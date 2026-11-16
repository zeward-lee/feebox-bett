package xhttpstream

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	bufSize = 2048

	// handshakeReadTimeout bounds the read of the server preamble, the echoed
	// token and the read IV. The relay's own deadlines do not cover it until the
	// reader is built, so a server that accepts the TCP connect and then goes
	// silent would otherwise pin the first read forever.
	handshakeReadTimeout = 10 * time.Second
)

// Writer is an encrypted io.Writer. It keeps one buffer so a plain Write does
// not allocate, exactly like the shadowsocks stream writer the vendor forked.
type Writer struct {
	io.Writer
	cipher.Stream
	buf [bufSize]byte

	access sync.Mutex
}

// NewWriter wraps an io.Writer with stream cipher encryption.
func NewWriter(w io.Writer, s cipher.Stream) *Writer {
	return &Writer{Writer: w, Stream: s}
}

func (w *Writer) Write(p []byte) (n int, err error) {
	w.access.Lock()
	defer w.access.Unlock()
	buf := w.buf[:]
	for nw := 0; n < len(p) && err == nil; n += nw {
		end := n + len(buf)
		if end > len(p) {
			end = len(p)
		}
		w.XORKeyStream(buf, p[n:end])
		nw, err = w.Writer.Write(buf[:end-n])
	}
	return
}

func (w *Writer) ReadFrom(r io.Reader) (n int64, err error) {
	w.access.Lock()
	defer w.access.Unlock()
	buf := w.buf[:]
	for {
		nr, er := r.Read(buf)
		n += int64(nr)
		b := buf[:nr]
		w.XORKeyStream(b, b)
		if _, err = w.Writer.Write(b); err != nil {
			return
		}
		if er != nil {
			if er != io.EOF { // ignore EOF as per io.ReaderFrom contract
				err = er
			}
			return
		}
	}
}

// Reader is an encrypted io.Reader.
//
// The stream cipher is stateful, so Read and WriteTo (the io.WriterTo fast path
// io.Copy uses) must not run concurrently: access serialises them. A caller that
// shares a Conn between a reader and a writer goroutine therefore only ever
// touches one cipher stream per direction.
type Reader struct {
	io.Reader
	cipher.Stream
	buf [bufSize]byte

	access sync.Mutex
}

// NewReader wraps an io.Reader with stream cipher decryption.
func NewReader(r io.Reader, s cipher.Stream) *Reader {
	return &Reader{Reader: r, Stream: s}
}

func (r *Reader) Read(p []byte) (n int, err error) {
	r.access.Lock()
	defer r.access.Unlock()
	n, err = r.Reader.Read(p)
	if err != nil {
		return 0, err
	}
	r.XORKeyStream(p, p[:n])
	return
}

func (r *Reader) WriteTo(w io.Writer) (n int64, err error) {
	r.access.Lock()
	defer r.access.Unlock()
	buf := r.buf[:]
	for {
		nr, er := r.Reader.Read(buf)
		if nr > 0 {
			r.XORKeyStream(buf, buf[:nr])
			nw, ew := w.Write(buf[:nr])
			n += int64(nw)
			if ew != nil {
				err = ew
				return
			}
		}
		if er != nil {
			if er != io.EOF { // ignore EOF as per io.Copy contract
				err = er
			}
			return
		}
	}
}

// Conn is an xhttp transport stream.
//
// Wire format, client to server (confirmed against the vendor build):
//
//	[128]  forged prefix: hex(fake-net["tcp"]) followed by random bytes
//	[16]   token, md5(secret + "do not hack this protocol please")
//	[H]    hmac key, hex decoded from the second half of the password
//	[1]    IV length, 0x10 for AES-CTR
//	[IV]   random write IV
//	[..]   AES-CTR(SOCKS address of the first target)
//	[..]   AES-CTR(payload)
//
// Server to client (reconstructed; the three layouts the two client
// implementations disagree on are all accepted, see handshake.go):
//
//	[128]  forged prefix
//	[16]   the same token, echoed back (mismatch => ErrInvalidToken)
//	[..]   preamble: [1]N[N], or an hmac sized echo followed by <=10 pad bytes
//	[1]    IV length, 0x10 for AES-CTR
//	[IV]   read IV
//
// The header and the destination form one write: the vendor server starts
// decrypting the stream right after the IV, so a destination sent as a second
// write would leave a window where a half-written handshake is on the wire.
type Conn struct {
	net.Conn
	Cipher
	r       *Reader
	w       *Writer
	readIV  []byte
	writeIV []byte

	// Destination is the SOCKS address written as the first encrypted bytes.
	Destination []byte
	token       []byte
	hmac        []byte
	paddingLen  int
	fakeNet     map[string]string

	// readMu guards the reader side (r and its cipher stream), writeMu the
	// writer side (w, writeIV and the handshake). Read and WriteTo share
	// readMu; Write and ReadFrom share writeMu, so the four io paths never
	// touch one cipher stream concurrently.
	readMu  sync.Mutex
	writeMu sync.Mutex

	// writeErr makes a failed handshake sticky: the CTR keystream has advanced,
	// so retrying would emit a corrupt header.
	writeErr          error
	handshakeDeadline time.Time
}

func (c *Conn) initReader() error {
	if c.r != nil {
		return nil
	}
	deadline := time.Now().Add(handshakeReadTimeout)
	if !c.handshakeDeadline.IsZero() && c.handshakeDeadline.Before(deadline) {
		deadline = c.handshakeDeadline
	}
	// Bounded handshake read: the echoed token is validated here, so a wrong
	// password fails fast instead of hanging on a silent server. The deadline is
	// cleared once the reader owns the connection again.
	_ = c.Conn.SetReadDeadline(deadline)
	defer func() { _ = c.Conn.SetReadDeadline(time.Time{}) }()
	// Discard the server's forged prefix.
	if _, err := io.CopyN(io.Discard, c.Conn, FakePrefixLen); err != nil {
		return err
	}
	if len(c.token) > 0 {
		serverToken := make([]byte, len(c.token))
		if _, err := io.ReadFull(c.Conn, serverToken); err != nil {
			return err
		}
		if !tokenEqual(serverToken, c.token) {
			return ErrInvalidToken
		}
	}
	// The server preamble (length prefixed padding, and in the second generation
	// layout an hmac echo) sits between the token and the IV length byte.
	// resolveServerPreamble accepts every known layout and returns a reader
	// positioned right after the IV length byte.
	reader, preamble, _, err := resolveServerPreamble(c.Conn, len(c.hmac), c.IVSize())
	if err != nil {
		return fmt.Errorf("xhttp: server preamble (%s): %w", describePreamble(preamble), err)
	}
	iv := make([]byte, c.IVSize())
	if _, err := io.ReadFull(reader, iv); err != nil {
		return fmt.Errorf("xhttp: read server IV: %w", err)
	}
	c.readIV = iv
	c.r = NewReader(c.Conn, c.Decrypter(iv))
	return nil
}

func (c *Conn) initWriter() error {
	if c.w != nil {
		return nil
	}
	if c.writeErr != nil {
		return c.writeErr
	}
	iv, err := c.ObtainWriteIV()
	if err != nil {
		return err
	}
	fake, err := DecodeFakeNet(c.fakeNet, "tcp")
	if err != nil {
		return err
	}
	header := make([]byte, FakePrefixLen+len(c.token)+len(c.hmac)+1+len(iv))
	copied := copy(header[:FakePrefixLen], fake)
	if copied < FakePrefixLen {
		if _, err := rand.Read(header[copied:FakePrefixLen]); err != nil {
			return err
		}
	}
	offset := FakePrefixLen
	offset += copy(header[offset:], c.token)
	offset += copy(header[offset:], c.hmac)
	header[offset] = byte(len(iv))
	offset++
	copy(header[offset:], iv)
	// Header and destination go out in one write. The destination continues the
	// same CTR keystream the payload will use, so the encrypter is created once
	// and handed to the writer only after the write succeeded.
	enc := c.Encrypter(iv)
	frame := header
	if len(c.Destination) > 0 {
		start := len(frame)
		frame = append(frame, c.Destination...)
		enc.XORKeyStream(frame[start:], frame[start:])
	}
	if _, err := c.Conn.Write(frame); err != nil {
		c.writeErr = fmt.Errorf("xhttp: write client handshake: %w", err)
		return c.writeErr
	}
	c.w = NewWriter(c.Conn, enc)
	return nil
}

// Read implements net.Conn.
func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

// Write implements net.Conn. A zero length write only forces the handshake,
// which is the mihomo EarlyConn convention for proxies that defer it.
func (c *Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
		if len(b) == 0 {
			return 0, nil
		}
	}
	return c.w.Write(b)
}

// WriteTo implements io.WriterTo.
func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.WriteTo(w)
}

// ReadFrom implements io.ReaderFrom.
func (c *Conn) ReadFrom(r io.Reader) (int64, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.ReadFrom(r)
}

// NeedHandshake implements sing's network.EarlyConn, so callers that know the
// convention can force the handshake with a zero length write.
func (c *Conn) NeedHandshake() bool {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.w == nil
}

// SetHandshakeDeadline records the dial context deadline, so the handshake read
// cannot outlive it. It must be called before the conn is used.
func (c *Conn) SetHandshakeDeadline(deadline time.Time) {
	c.handshakeDeadline = deadline
}

// ObtainWriteIV returns the cached write IV, generating it on first use.
func (c *Conn) ObtainWriteIV() ([]byte, error) {
	if len(c.writeIV) == c.IVSize() {
		return c.writeIV, nil
	}
	iv := make([]byte, c.IVSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	c.writeIV = iv
	return iv, nil
}

// ObtainReadIV reads size bytes of IV from the connection, caching the result.
func (c *Conn) ObtainReadIV(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("xhttp: empty read IV")
	}
	if len(c.readIV) == size {
		return c.readIV, nil
	}
	iv := make([]byte, size)
	if _, err := io.ReadFull(c.Conn, iv); err != nil {
		return nil, err
	}
	c.readIV = iv
	return iv, nil
}

// SetPaddingLen records the configured padding range. The vendor build parses
// `padding-len` but never uses it on the client side; it is kept here so the
// option is not silently dropped.
func (c *Conn) SetPaddingLen(paddingLen int) {
	c.paddingLen = paddingLen
}

func readLengthByte(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

// ParsePaddingLen accepts the vendor form "<min>-<max>" (for example "8-64"),
// a bare "<max>" or an empty string. Surrounding whitespace (a YAML quirk or a
// hand-edited node) is ignored. The values are parsed for validation and kept on
// the connection; this build does not pad the client stream.
func ParsePaddingLen(value string) (minLen, maxLen int, err error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, 0, nil
	}
	parse := func(s string) (int, error) {
		s = strings.TrimSpace(s)
		var n int
		if _, scanErr := fmt.Sscanf(s, "%d", &n); scanErr != nil {
			return 0, fmt.Errorf("xhttp: invalid padding-len %q", value)
		}
		return n, nil
	}
	for i := 0; i < len(value); i++ {
		if value[i] != '-' {
			continue
		}
		if minLen, err = parse(value[:i]); err != nil {
			return 0, 0, err
		}
		if maxLen, err = parse(value[i+1:]); err != nil {
			return 0, 0, err
		}
		if minLen < 0 || maxLen < minLen || maxLen > 1<<16 {
			return 0, 0, fmt.Errorf("xhttp: padding-len out of range %q", value)
		}
		return minLen, maxLen, nil
	}
	if maxLen, err = parse(value); err != nil {
		return 0, 0, err
	}
	if maxLen < 0 || maxLen > 1<<16 {
		return 0, 0, fmt.Errorf("xhttp: padding-len out of range %q", value)
	}
	return 0, maxLen, nil
}
