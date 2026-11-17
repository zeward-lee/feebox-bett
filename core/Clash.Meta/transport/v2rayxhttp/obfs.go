package v2rayxhttp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"sync"
)

// The Shanlian fork wraps the XHTTP HTTP stream bodies in a keyed stream
// obfuscation layer. The layer sits on the HTTP body of a request/response, not
// below TLS: the vendor core exposes `obfsReader` (downstream response body) and
// `obfsWriter` (upstream request body) rather than a connection wrapper, and the
// dedicated line endpoints complete a plain TLS 1.3 handshake and answer a plain
// HTTP/1.1 request. Wrapping the TCP conn instead breaks the handshake (the
// server sees the 20-byte obfs preamble where it expects a TLS record and drops
// the connection), so do not move these wrappers back below `StreamTLSConn`.
//
// The wire shape was recovered from the vendor core
// (`transport/v2rayxhttp/obfs.go` in `lightningx-windows-amd64.exe`), which is
// not part of upstream sing-box:
//
//	key  = SHA-256(obfs_key)[:16]                       // AES-128
//	once: IV(16 random bytes) || AES-CTR(key, IV)(0^4)   // "tag", 4 bytes
//	then: AES-CTR(key, IV) continues over the payload, tag included in the
//	      keystream offset, so the peer decrypts tag + payload with one stream.
//
// The key derivation is a bare SHA-256 truncated to 16 bytes, byte-for-byte
// identical to the vendor core. Do NOT add a domain separator, prefix, salt or
// HKDF step, and do not widen the truncation: the peer derives the key the same
// way, so any change makes it reject the 4-byte tag with "obfs key mismatch"
// and the node looks unreachable. TestObfsKeyDerivation pins the mapping for a
// known obfs key to keep that contract from drifting.
//
// The receiver reads the 20-byte preamble, decrypts the 4-byte tag with the
// CTR stream and requires it to be four zero bytes; anything else is reported
// as "obfs key mismatch" exactly like the vendor implementation. A failed
// preamble is sticky: the stream can never be decrypted again, so every later
// Read keeps returning the same error and the body is closed (fail-closed)
// instead of hanging until the session times out.
const (
	obfsIVLength    = aes.BlockSize
	obfsTagLength   = 4
	obfsPreamble    = obfsIVLength + obfsTagLength
	obfsKeyLength   = 16
	obfsKeyMismatch = "obfs key mismatch"
)

type obfsAESKey [obfsKeyLength]byte

func deriveObfsKey(obfsKey string) obfsAESKey {
	sum := sha256.Sum256([]byte(obfsKey))
	var key obfsAESKey
	copy(key[:], sum[:obfsKeyLength])
	return key
}

// obfsWriter obfuscates the bytes of one upstream HTTP request body. Each
// direction has its own wrapper (and therefore its own IV/preamble), matching
// the vendor `obfsWriter`.
type obfsWriter struct {
	w   io.Writer
	key obfsAESKey

	mu     sync.Mutex
	stream cipher.Stream
	// err is sticky: a partial preamble/payload write leaves the CTR stream
	// out of sync with the peer, so the body can never be resumed. Returning
	// the same error keeps the upload failure visible instead of silently
	// sending undecryptable bytes.
	err error
}

// wrapObfsWriter wraps w with the vendor obfs layer when obfsKey is not empty.
// Config.Validate rejects a missing key, so an empty obfsKey only reaches here
// when the node explicitly disabled obfs (`obfs-key: ""`).
func wrapObfsWriter(w io.Writer, obfsKey string) io.Writer {
	if obfsKey == "" {
		return w
	}
	return &obfsWriter{w: w, key: deriveObfsKey(obfsKey)}
}

func (w *obfsWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	if w.stream == nil {
		var iv [obfsIVLength]byte
		if _, err := rand.Read(iv[:]); err != nil {
			w.err = err
			return 0, err
		}
		stream, err := newObfsStream(w.key[:], iv[:])
		if err != nil {
			w.err = err
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
		if err := writeFull(w.w, preamble); err != nil {
			w.err = err
			return 0, err
		}
		w.stream = stream
		return len(b), nil
	}
	payload := make([]byte, len(b))
	w.stream.XORKeyStream(payload, b)
	if err := writeFull(w.w, payload); err != nil {
		w.err = err
		return 0, err
	}
	return len(b), nil
}

// obfsReader deobfuscates one downstream HTTP response body, matching the
// vendor `obfsReader`.
type obfsReader struct {
	r   io.Reader
	key obfsAESKey

	mu     sync.Mutex
	stream cipher.Stream
	err    error
}

func (r *obfsReader) Read(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return 0, r.err
	}
	if r.stream == nil {
		if err := r.initRead(); err != nil {
			// A bad preamble (or a short read) leaves the key stream unusable.
			// Record it so neither half can keep retrying a stream that can
			// never be decrypted.
			r.err = err
			return 0, err
		}
	}
	n, err := r.r.Read(b)
	if n > 0 {
		r.stream.XORKeyStream(b[:n], b[:n])
	}
	return n, err
}

func (r *obfsReader) initRead() error {
	var preamble [obfsPreamble]byte
	if _, err := io.ReadFull(r.r, preamble[:]); err != nil {
		return err
	}
	stream, err := newObfsStream(r.key[:], preamble[:obfsIVLength])
	if err != nil {
		return err
	}
	var tag [obfsTagLength]byte
	stream.XORKeyStream(tag[:], preamble[obfsIVLength:])
	// Constant-time tag check: OR the four bytes together and compare once, so
	// the tag check does not leak how many leading bytes matched (a timing
	// oracle on a keyed preamble is a bad habit even on a stream body).
	diff := tag[0] | tag[1] | tag[2] | tag[3]
	if subtle.ConstantTimeByteEq(diff, 0) != 1 {
		return errors.New(obfsKeyMismatch)
	}
	r.stream = stream
	return nil
}

// obfsReadCloser is the response-body wrapper handed to the stream reader. A
// failed read closes the body so a corrupted obfs stream tears the HTTP stream
// down immediately (fail-closed) instead of lingering.
type obfsReadCloser struct {
	*obfsReader
	closer io.Closer
}

func (r *obfsReadCloser) Read(b []byte) (int, error) {
	n, err := r.obfsReader.Read(b)
	if err != nil {
		_ = r.closer.Close()
	}
	return n, err
}

func (r *obfsReadCloser) Close() error {
	return r.closer.Close()
}

// wrapObfsReader wraps r with the vendor obfs layer when obfsKey is not empty.
func wrapObfsReader(r io.ReadCloser, obfsKey string) io.ReadCloser {
	if obfsKey == "" {
		return r
	}
	return &obfsReadCloser{obfsReader: &obfsReader{r: r, key: deriveObfsKey(obfsKey)}, closer: r}
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
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
