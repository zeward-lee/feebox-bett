package sntp_eclipse

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

var (
	randReader = rand.Reader

	// maxRecordBody caps the advertised body ciphertext length. It is the
	// largest value the BE16 header can carry; anything bigger is a protocol
	// violation and is rejected before allocating.
	maxRecordBody = 0xffff

	// maxPayloadPerRecord is the payload chunk we put in one record. The
	// vendor client pads to bucket sizes <= 1280 and our reference client used
	// 4000 byte chunks, both accepted by the server (§13.1 / §13.4).
	maxPayloadPerRecord = 4000
)

// Conn is the framed, encrypted tunnel connection. One Conn maps to one
// upstream record stream; Read/Write serialise whole records so a caller may
// use it from multiple goroutines like any net.Conn.
type Conn struct {
	net.Conn

	writeHdr  cipher.AEAD
	writeBody cipher.AEAD
	readHdr   cipher.AEAD
	readBody  cipher.AEAD

	writeMu    sync.Mutex
	readMu     sync.Mutex
	writeCtr   uint64
	readCtr    uint64
	readBuffer []byte
	closed     bool
}

// Dial performs the hello exchange on an already connected TCP socket and
// returns the framed tunnel. The caller owns rawConn: on error it is closed.
func Dial(rawConn net.Conn, cfg ClientConfig, target Target) (*Conn, error) {
	return dial(rawConn, cfg, target, time.Now())
}

func dial(rawConn net.Conn, cfg ClientConfig, target Target, now time.Time) (*Conn, error) {
	if err := cfg.validate(); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	if target.Host == "" {
		_ = rawConn.Close()
		return nil, errors.New("sntp-eclipse: target host is required")
	}
	serverPub, err := DecodeServerPublicKey(cfg.ServerPublicKey)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	uuidASCII, err := DecodeUUID(cfg.UUID)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	if deadline := now.Add(cfg.timeout()); !deadline.IsZero() {
		_ = rawConn.SetDeadline(deadline)
	}
	defer func() {
		// Handshake only: the tunnel inherits the caller's deadlines afterwards.
		_ = rawConn.SetDeadline(time.Time{})
	}()

	priv, pub, err := generateKeyPair()
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	var clientNonce [16]byte
	if _, err = io.ReadFull(randReader, clientNonce[:]); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("sntp-eclipse: client nonce: %w", err)
	}
	prefix := make([]byte, 0, keySize+len(clientNonce))
	prefix = append(prefix, pub[:]...)
	prefix = append(prefix, clientNonce[:]...)

	s1, err := x25519(priv, serverPub)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	handshakeKeys, err := handshakeKDF(s1, clientNonce[:], cfg.mode())
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	frame, transcript, err := buildHello(prefix, handshakeKeys, target, uuidASCII, now)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	if _, err = writeFull(rawConn, frame); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("sntp-eclipse: send hello: %w", err)
	}

	reply, err := readHelloReply(rawConn, handshakeKeys, transcript)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	s2, err := x25519(priv, reply.ServerEph)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	trafficKeys, err := trafficKDF(s1, s2, transcript, reply.ServerEph, cfg.mode())
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	writeHdr, err := newAEAD(trafficKeys[0])
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	writeBody, err := newAEAD(trafficKeys[1])
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	readHdr, err := newAEAD(trafficKeys[2])
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	readBody, err := newAEAD(trafficKeys[3])
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	return &Conn{
		Conn:      rawConn,
		writeHdr:  writeHdr,
		writeBody: writeBody,
		readHdr:   readHdr,
		readBody:  readBody,
	}, nil
}

// newTunnelConn builds a Conn from explicit traffic keys, bypassing the
// handshake. It exists for the golden tests (captured sessions) and must not
// be used in production paths.
func newTunnelConn(rawConn net.Conn, keys [4][keySize]byte) (*Conn, error) {
	writeHdr, err := newAEAD(keys[0])
	if err != nil {
		return nil, err
	}
	writeBody, err := newAEAD(keys[1])
	if err != nil {
		return nil, err
	}
	readHdr, err := newAEAD(keys[2])
	if err != nil {
		return nil, err
	}
	readBody, err := newAEAD(keys[3])
	if err != nil {
		return nil, err
	}
	return &Conn{Conn: rawConn, writeHdr: writeHdr, writeBody: writeBody, readHdr: readHdr, readBody: readBody}, nil
}

func (c *Conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.readBuffer) == 0 {
		payload, err := c.readRecord()
		if err != nil {
			return 0, err
		}
		if len(payload) == 0 {
			// Padding-only record: the peer sent no payload, keep reading.
			continue
		}
		c.readBuffer = payload
	}
	n := copy(b, c.readBuffer)
	c.readBuffer = c.readBuffer[n:]
	return n, nil
}

// readRecord reads and authenticates one record (§13.1):
//
//	hdr18   = Seal(tkH, nonce=00*16||BE64(ctr), aad="", pt=BE16(len(body_ct)))
//	body_ct = Seal(tkB, nonce=ctr, aad=hdr18, pt=BE16(payload_len)||payload||pad)
func (c *Conn) readRecord() ([]byte, error) {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return nil, err
	}
	bodyLen, err := openHeader(c.readHdr, c.readCtr, nil, header)
	if err != nil {
		return nil, err
	}
	if bodyLen < 2+chachaOverhead || bodyLen > maxRecordBody {
		return nil, fmt.Errorf("sntp-eclipse: record body length %d out of range", bodyLen)
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(c.Conn, body); err != nil {
		return nil, err
	}
	plain, err := openBody(c.readBody, c.readCtr, nil, header, body)
	if err != nil {
		return nil, err
	}
	c.readCtr++
	payloadLen := int(binary.BigEndian.Uint16(plain[0:2]))
	if payloadLen > len(plain)-2 {
		return nil, fmt.Errorf("sntp-eclipse: record payload length %d exceeds body %d", payloadLen, len(plain)-2)
	}
	return plain[2 : 2+payloadLen], nil
}

func (c *Conn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	written := 0
	for written < len(b) {
		end := written + maxPayloadPerRecord
		if end > len(b) {
			end = len(b)
		}
		payload := b[written:end]
		plain := make([]byte, 2, 2+len(payload))
		binary.BigEndian.PutUint16(plain, uint16(len(payload)))
		plain = append(plain, payload...)

		record := sealRecord(c.writeHdr, c.writeBody, c.writeCtr, nil, plain)
		if _, err := writeFull(c.Conn, record); err != nil {
			return written, err
		}
		c.writeCtr++
		written = end
	}
	return written, nil
}

func (c *Conn) Close() error {
	c.writeMu.Lock()
	c.closed = true
	c.writeMu.Unlock()
	return c.Conn.Close()
}

// writeFull writes the whole buffer; net.Conn.Write may return short writes.
func writeFull(w io.Writer, buf []byte) (int, error) {
	written := 0
	for written < len(buf) {
		n, err := w.Write(buf[written:])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

// DialContext dials the node through the supplied dial function and performs
// the handshake. It exists so adapters do not have to duplicate the dial +
// handshake ordering.
func DialContext(ctx context.Context, dialFn func(ctx context.Context, network, addr string) (net.Conn, error), addr string, cfg ClientConfig, target Target) (*Conn, error) {
	rawConn, err := dialFn(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if ctx.Done() != nil {
		go func() {
			<-ctx.Done()
			_ = rawConn.Close()
		}()
	}
	return Dial(rawConn, cfg, target)
}
