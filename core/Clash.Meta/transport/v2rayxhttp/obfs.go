package v2rayxhttp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"sync"
)

// The Shanlian fork wraps every XHTTP TCP connection (below TLS) in a keyed
// stream obfuscation layer. The wire shape was recovered from the vendor core
// (`transport/v2rayxhttp/obfs.go` in `lightningx-windows-amd64.exe`), which is
// not part of upstream sing-box:
//
//	key  = SHA-256(obfs_key)[:16]                       // AES-128
//	once: IV(16 random bytes) || AES-CTR(key, IV)(0^4)   // "tag", 4 bytes
//	then: AES-CTR(key, IV) continues over the payload, tag included in the
//	      keystream offset, so the peer decrypts tag + payload with one stream.
//
// The receiver reads the 20-byte preamble, decrypts the 4-byte tag with the
// CTR stream and requires it to be four zero bytes; anything else is reported
// as "obfs key mismatch" exactly like the vendor implementation.
const (
	obfsIVLength    = aes.BlockSize
	obfsTagLength   = 4
	obfsPreamble    = obfsIVLength + obfsTagLength
	obfsKeyLength   = 16
	obfsKeyMismatch = "obfs key mismatch"
)

type obfsConn struct {
	net.Conn
	key [obfsKeyLength]byte

	readMu     sync.Mutex
	readStream cipher.Stream

	writeMu     sync.Mutex
	writeStream cipher.Stream
}

// newObfsConn wraps conn with the vendor obfs layer when obfsKey is not empty.
func newObfsConn(conn net.Conn, obfsKey string) net.Conn {
	if obfsKey == "" {
		return conn
	}
	sum := sha256.Sum256([]byte(obfsKey))
	c := &obfsConn{Conn: conn}
	copy(c.key[:], sum[:obfsKeyLength])
	return c
}

func (c *obfsConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readStream == nil {
		if err := c.initRead(); err != nil {
			return 0, err
		}
	}
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.readStream.XORKeyStream(b[:n], b[:n])
	}
	return n, err
}

func (c *obfsConn) initRead() error {
	var preamble [obfsPreamble]byte
	if _, err := io.ReadFull(c.Conn, preamble[:]); err != nil {
		return err
	}
	stream, err := newObfsStream(c.key[:], preamble[:obfsIVLength])
	if err != nil {
		return err
	}
	var tag [obfsTagLength]byte
	stream.XORKeyStream(tag[:], preamble[obfsIVLength:])
	for _, v := range tag {
		if v != 0 {
			return errors.New(obfsKeyMismatch)
		}
	}
	c.readStream = stream
	return nil
}

func (c *obfsConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeStream == nil {
		var iv [obfsIVLength]byte
		if _, err := rand.Read(iv[:]); err != nil {
			return 0, err
		}
		stream, err := newObfsStream(c.key[:], iv[:])
		if err != nil {
			return 0, err
		}
		// tag = keystream(0^4); payload is encrypted with the continuation of
		// the same stream, so tag and payload travel as one write.
		preamble := make([]byte, 0, obfsPreamble+len(b))
		preamble = append(preamble, iv[:]...)
		tag := make([]byte, obfsTagLength)
		stream.XORKeyStream(tag, tag)
		preamble = append(preamble, tag...)
		payload := make([]byte, len(b))
		stream.XORKeyStream(payload, b)
		preamble = append(preamble, payload...)
		if err := writeFull(c.Conn, preamble); err != nil {
			return 0, err
		}
		c.writeStream = stream
		return len(b), nil
	}
	payload := make([]byte, len(b))
	c.writeStream.XORKeyStream(payload, b)
	if err := writeFull(c.Conn, payload); err != nil {
		return 0, err
	}
	return len(b), nil
}

func newObfsStream(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
