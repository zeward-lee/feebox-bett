package ninja

import (
	"bufio"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"sync"
	"time"
)

// On the wire a ninja tunnel looks like this (both directions are symmetric):
//
//	+----------------+  KeyLen random bytes, plain text
//	|     salt       |
//	+----------------+  16 bytes, plain text, AES-ECB(tokenKey) of the psk digest
//	|     token      |
//	+----------------+  12 byte meta record, AEAD sealed (+16 tag)
//	|  meta (12+16)  |
//	+----------------+  meta[10:12] byte meta record, AEAD sealed (+16 tag)
//	| first block    |  addr || BE16(pad) || pad || payload
//	+----------------+
//	| chunk ...      |  hdr4 = BE16(payload+pad), BE16(pad), then body
//	+----------------+
//
// meta = [0]=0 | [1]=role (1=initiator, 2=responder) | [2:10]=BE64 unix ms | [10:12]=BE16 len(first block)
//
// Every Seal/Open consumes the 96 bit nonce, which starts at zero and is
// incremented as a little endian counter afterwards.

const (
	metaLen        = 12
	chunkHeaderLen = 4
	// maxChunkPayload keeps the sealed chunk small enough for a single flush.
	maxChunkPayload = 0x3fff
	// maxFirstBlock caps the in-band first block payload.
	maxFirstBlock = 0xffff - 64
)

// PaddingMode mirrors the reference padding strategies.
type PaddingMode string

const (
	PaddingMin       PaddingMode = "min"
	PaddingRandom    PaddingMode = "random"
	PaddingMinRandom PaddingMode = "min_random"
)

// PaddingConfig controls the amount of random padding written per record.
type PaddingConfig struct {
	Mode PaddingMode
	Min  int
	Max  int
}

func (p PaddingConfig) normalize() PaddingConfig {
	if p.Min < 0 {
		p.Min = 0
	}
	if p.Max <= 0 {
		p.Max = 128
	}
	switch p.Mode {
	case PaddingMin, PaddingRandom, PaddingMinRandom:
	default:
		p.Mode = PaddingRandom
	}
	return p
}

// PaddingLen returns the number of padding bytes to append for a payload of n bytes.
func (p PaddingConfig) PaddingLen(n int) int {
	p = p.normalize()
	switch p.Mode {
	case PaddingMin:
		if d := p.Min - n; d > 0 {
			return d
		}
		return 0
	case PaddingMinRandom:
		base := p.Min - n
		if base < 0 {
			base = 0
		}
		return base + mrand.Intn(p.Max+1)
	default:
		return mrand.Intn(p.Max + 1)
	}
}

// Config is the shared tunnel configuration.
type Config struct {
	Method   Method
	Password string
	// NodePassword only feeds the token wrapping key; the AEAD sub key comes
	// from Password. When empty it falls back to Password.
	NodePassword string
	Padding      PaddingConfig
}

// state holds the derived key material of one direction of one connection.
type state struct {
	cfg    *Config
	psk    []byte
	tokenPSK []byte
	salt   []byte
	aead   cipher.AEAD
	nonce  []byte
	role   byte
	banner []byte // token we send (initiator) / expect (responder)
}

func newState(cfg *Config, role byte) (*state, error) {
	if !cfg.Method.Valid() {
		return nil, fmt.Errorf("ninja: unsupported method %q", string(cfg.Method))
	}
	psk, err := cfg.Method.psk(cfg.Password)
	if err != nil {
		return nil, err
	}
	tokenPass := cfg.NodePassword
	if tokenPass == "" {
		tokenPass = cfg.Password
	}
	tokenPSK, err := cfg.Method.psk(tokenPass)
	if err != nil {
		return nil, err
	}
	return &state{cfg: cfg, psk: psk, tokenPSK: tokenPSK, role: role}, nil
}

// init generates a salt and derives the AEAD for it.
func (s *state) init() error {
	salt := make([]byte, s.cfg.Method.KeyLen())
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	s.salt = salt
	sub, err := s.cfg.Method.subKey(s.psk, salt)
	if err != nil {
		return err
	}
	aead, err := s.cfg.Method.NewAEAD(sub)
	if err != nil {
		return err
	}
	s.aead = aead
	s.nonce = make([]byte, aead.NonceSize())
	banner, err := s.cfg.Method.buildToken(s.psk, s.tokenPSK, salt)
	if err != nil {
		return err
	}
	s.banner = banner
	return nil
}

// adopt installs a peer supplied salt and derives the matching AEAD.
func (s *state) adopt(salt []byte) error {
	if len(salt) != s.cfg.Method.KeyLen() {
		return fmt.Errorf("ninja: bad salt length %d", len(salt))
	}
	s.salt = salt
	sub, err := s.cfg.Method.subKey(s.psk, salt)
	if err != nil {
		return err
	}
	aead, err := s.cfg.Method.NewAEAD(sub)
	if err != nil {
		return err
	}
	s.aead = aead
	s.nonce = make([]byte, aead.NonceSize())
	return nil
}

func (s *state) seal(dst, plaintext []byte) []byte {
	out := s.aead.Seal(dst, s.nonce, plaintext, nil)
	increment(s.nonce)
	return out
}

func (s *state) open(dst, ciphertext []byte) ([]byte, error) {
	out, err := s.aead.Open(dst, s.nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	increment(s.nonce)
	return out, nil
}

// Conn is an AEAD framed net.Conn.
//
// The first Write carries the tunnel header: salt, token, meta and a first block
// that already contains the destination address. Everything after that is sent
// as length prefixed chunks.
type Conn struct {
	net.Conn

	cfg  *Config
	st   *state
	br   *bufio.Reader
	lock sync.Mutex

	wroteHeader bool
	headerRead  bool

	// addr is the socks5 encoded destination carried by the first block.
	addr []byte
	// remoteAddr is the destination parsed from the peer first block (responder side).
	remoteAddr []byte
	// payload buffers the first block payload and the current chunk tail.
	payload []byte

	// read side scratch
	rerr error
}

// NewConn wraps raw, which must already carry a destination address in addr
// when used as an initiator. The caller owns raw.
func NewConn(raw net.Conn, cfg *Config, initiator bool) *Conn {
	role := byte(2)
	if initiator {
		role = 1
	}
	c := &Conn{Conn: raw, cfg: cfg, br: bufio.NewReaderSize(raw, 16*1024)}
	st, err := newState(cfg, role)
	if err != nil {
		c.rerr = err
		return c
	}
	c.st = st
	return c
}

func binBE16(b []byte, v uint16) { binary.BigEndian.PutUint16(b, v) }

// responderHeaderLen is the plaintext size of the responder's first record:
// role(1) || token(16) || unix ms(8) || total(2) || pad(2).
const responderHeaderLen = 1 + tokenLen + 8 + 2 + 2

// writeResponderHeader emits salt || sealed(header) || sealed(payload).
//
// The responder uses a self describing first record: its total length only
// depends on the method, so the initiator can read it in one shot.
func (c *Conn) writeResponderHeader(payload []byte) (int, error) {
	if err := c.st.init(); err != nil {
		return 0, err
	}
	pad := c.cfg.Padding.PaddingLen(len(payload))
	if pad < 0 {
		pad = 0
	}
	if pad > 0xffff {
		pad = 0xffff
	}
	hdr := make([]byte, responderHeaderLen)
	hdr[0] = c.st.role
	copy(hdr[1:1+tokenLen], c.st.banner)
	binary.BigEndian.PutUint64(hdr[1+tokenLen:9+tokenLen], uint64(time.Now().UnixMilli()))
	binBE16(hdr[9+tokenLen:11+tokenLen], uint16(len(payload)+pad))
	binBE16(hdr[11+tokenLen:], uint16(pad))

	body := make([]byte, 0, len(payload)+pad)
	body = append(body, payload...)
	if pad > 0 {
		p := make([]byte, pad)
		if _, err := rand.Read(p); err != nil {
			return 0, err
		}
		body = append(body, p...)
	}
	sealedHdr := c.st.seal(nil, hdr)
	sealedBody := c.st.seal(nil, body)
	out := make([]byte, 0, len(c.st.salt)+len(sealedHdr)+len(sealedBody))
	out = append(out, c.st.salt...)
	out = append(out, sealedHdr...)
	out = append(out, sealedBody...)
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(payload), nil
}

// writeHeader emits salt || token || sealed(meta) || sealed(firstBlock).
// dstAddr is the socks5 encoded destination; pass nil when responding.
func (c *Conn) writeHeader(dstAddr []byte, firstPayload []byte) error {
	if err := c.st.init(); err != nil {
		return err
	}
	pad := c.cfg.Padding.PaddingLen(len(firstPayload) + len(dstAddr) + 2)
	if pad < 0 {
		pad = 0
	}
	if pad > 0xffff {
		pad = 0xffff
	}
	first := make([]byte, 0, len(dstAddr)+2+pad+len(firstPayload))
	first = append(first, dstAddr...)
	var padLen [2]byte
	binBE16(padLen[:], uint16(pad))
	first = append(first, padLen[:]...)
	if pad > 0 {
		p := make([]byte, pad)
		if _, err := rand.Read(p); err != nil {
			return err
		}
		first = append(first, p...)
	}
	first = append(first, firstPayload...)

	meta := make([]byte, metaLen)
	meta[0] = 0
	meta[1] = c.st.role
	binary.BigEndian.PutUint64(meta[2:10], uint64(time.Now().UnixMilli()))
	binBE16(meta[10:12], uint16(len(first)))

	sealedMeta := c.st.seal(nil, meta)
	sealedFirst := c.st.seal(nil, first)

	out := make([]byte, 0, len(c.st.salt)+tokenLen+len(sealedMeta)+len(sealedFirst))
	out = append(out, c.st.salt...)
	out = append(out, c.st.banner...)
	out = append(out, sealedMeta...)
	out = append(out, sealedFirst...)
	_, err := c.Conn.Write(out)
	c.wroteHeader = true
	return err
}

// Write implements io.Writer. The first call establishes the tunnel header and
// carries dstAddr from the dialer.
func (c *Conn) Write(b []byte) (int, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.rerr != nil {
		return 0, c.rerr
	}
	if !c.wroteHeader {
		if c.st.role == 2 {
			// responder: carry the whole write inside the header record
			n, err := c.writeResponderHeader(b)
			c.wroteHeader = true
			return n, err
		}
		firstLen := len(b)
		if firstLen > maxFirstBlock {
			firstLen = maxFirstBlock
		}
		if err := c.writeHeader(c.addr, b[:firstLen]); err != nil {
			return 0, err
		}
		written := firstLen
		if written == len(b) {
			return written, nil
		}
		n, err := c.writeChunk(b[written:])
		return written + n, err
	}
	return c.writeChunk(b)
}

func (c *Conn) writeChunk(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		n := len(b)
		if n > maxChunkPayload {
			n = maxChunkPayload
		}
		if err := c.writeOneChunk(b[:n]); err != nil {
			return total, err
		}
		total += n
		b = b[n:]
	}
	return total, nil
}

func (c *Conn) writeOneChunk(payload []byte) error {
	pad := c.cfg.Padding.PaddingLen(len(payload))
	if pad < 0 {
		pad = 0
	}
	if pad > 0xffff {
		pad = 0xffff
	}
	hdr := make([]byte, chunkHeaderLen)
	binBE16(hdr[0:2], uint16(len(payload)+pad))
	binBE16(hdr[2:4], uint16(pad))
	body := make([]byte, 0, len(payload)+pad)
	body = append(body, payload...)
	if pad > 0 {
		p := make([]byte, pad)
		if _, err := rand.Read(p); err != nil {
			return err
		}
		body = append(body, p...)
	}
	sealedHdr := c.st.seal(nil, hdr)
	sealedBody := c.st.seal(nil, body)
	out := make([]byte, 0, len(sealedHdr)+len(sealedBody))
	out = append(out, sealedHdr...)
	out = append(out, sealedBody...)
	_, err := c.Conn.Write(out)
	return err
}

// SetAddr records the destination address for the tunnel header.
func (c *Conn) SetAddr(socksAddr []byte) { c.addr = socksAddr }

// readHeader consumes salt, token, meta and the first block.
func (c *Conn) readHeader() error {
	if c.headerRead {
		return nil
	}
	if c.st == nil {
		return c.rerr
	}
	salt := make([]byte, c.cfg.Method.KeyLen())
	if _, err := io.ReadFull(c.br, salt); err != nil {
		return err
	}
	if err := c.st.adopt(salt); err != nil {
		return err
	}
	if c.st.role == 1 {
		// initiator reads the responder header record
		rec := make([]byte, responderHeaderLen+c.cfg.Method.Overhead())
		if _, err := io.ReadFull(c.br, rec); err != nil {
			return err
		}
		plain, err := c.st.open(nil, rec)
		if err != nil {
			return fmt.Errorf("ninja: open response header: %w", err)
		}
		total := int(binary.BigEndian.Uint16(plain[9+tokenLen : 11+tokenLen]))
		pad := int(binary.BigEndian.Uint16(plain[11+tokenLen:]))
		if pad > total {
			return fmt.Errorf("ninja: bad response lengths tpl=%d pad=%d", total, pad)
		}
		bodyRec := make([]byte, total+c.cfg.Method.Overhead())
		if _, err := io.ReadFull(c.br, bodyRec); err != nil {
			return err
		}
		body, err := c.st.open(nil, bodyRec)
		if err != nil {
			return fmt.Errorf("ninja: open response body: %w", err)
		}
		c.payload = body[:total-pad]
		c.headerRead = true
		return nil
	}

	// token (plain text) + sealed meta
	first := make([]byte, tokenLen+metaLen+c.cfg.Method.Overhead())
	if _, err := io.ReadFull(c.br, first); err != nil {
		return err
	}
	token := first[:tokenLen]
	if !c.cfg.Method.verifyToken(c.st.psk, c.st.tokenPSK, salt, token) {
		return fmt.Errorf("ninja: bad peer token")
	}
	meta, err := c.st.open(nil, first[tokenLen:])
	if err != nil {
		return fmt.Errorf("ninja: open meta: %w", err)
	}
	if len(meta) != metaLen {
		return fmt.Errorf("ninja: bad meta length %d", len(meta))
	}
	firstLen := int(binary.BigEndian.Uint16(meta[10:12]))
	rec := make([]byte, firstLen+c.cfg.Method.Overhead())
	if _, err := io.ReadFull(c.br, rec); err != nil {
		return err
	}
	block, err := c.st.open(nil, rec)
	if err != nil {
		return fmt.Errorf("ninja: open first block: %w", err)
	}
	// The initiator sends the destination address inside its first block; the
	// responder's first block only carries padding and payload.
	if c.st.role == 2 {
		c.remoteAddr, c.payload, err = splitPayload(block)
	} else {
		c.remoteAddr, c.payload, err = splitPayloadNoAddr(block)
	}
	if err != nil {
		return err
	}
	c.headerRead = true
	return nil
}

// splitPayload parses addr || BE16(pad) || pad || payload.
func splitPayload(b []byte) (addr, payload []byte, err error) {
	if len(b) < 1 {
		return nil, nil, fmt.Errorf("ninja: short first block")
	}
	var addrLen int
	switch b[0] {
	case 1:
		addrLen = 1 + 4 + 2
	case 3:
		if len(b) < 2 {
			return nil, nil, fmt.Errorf("ninja: short domain address")
		}
		addrLen = 1 + 1 + int(b[1]) + 2
	case 4:
		addrLen = 1 + 16 + 2
	default:
		return nil, nil, fmt.Errorf("ninja: bad address type %d", b[0])
	}
	if len(b) < addrLen+2 {
		return nil, nil, fmt.Errorf("ninja: short first block (addr)")
	}
	pad := int(binary.BigEndian.Uint16(b[addrLen : addrLen+2]))
	if len(b) < addrLen+2+pad {
		return nil, nil, fmt.Errorf("ninja: bad response lengths tpl=%d pad=%d", len(b), pad)
	}
	return b[:addrLen], b[addrLen+2+pad:], nil
}

// splitPayloadNoAddr parses BE16(pad) || pad || payload.
func splitPayloadNoAddr(b []byte) (addr, payload []byte, err error) {
	if len(b) < 2 {
		return nil, nil, fmt.Errorf("ninja: short first block")
	}
	pad := int(binary.BigEndian.Uint16(b[:2]))
	if len(b) < 2+pad {
		return nil, nil, fmt.Errorf("ninja: bad response lengths tpl=%d pad=%d", len(b), pad)
	}
	return nil, b[2+pad:], nil
}

// Read implements io.Reader.
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !c.headerRead {
		if err := c.readHeader(); err != nil {
			return 0, err
		}
		if len(c.payload) > 0 {
			n := copy(p, c.payload)
			c.payload = c.payload[n:]
			return n, nil
		}
	}
	for {
		if len(c.payload) > 0 {
			n := copy(p, c.payload)
			c.payload = c.payload[n:]
			return n, nil
		}
		if err := c.readChunk(); err != nil {
			return 0, err
		}
	}
}

func (c *Conn) readChunk() error {
	hdr := make([]byte, chunkHeaderLen+c.cfg.Method.Overhead())
	if _, err := io.ReadFull(c.br, hdr); err != nil {
		return err
	}
	plain, err := c.st.open(nil, hdr)
	if err != nil {
		return fmt.Errorf("ninja: open chunk header: %w", err)
	}
	total := int(binary.BigEndian.Uint16(plain[0:2]))
	pad := int(binary.BigEndian.Uint16(plain[2:4]))
	if pad > total {
		return fmt.Errorf("ninja: bad chunk lengths dataLen=%d pad=%d", total, pad)
	}
	body := make([]byte, total+c.cfg.Method.Overhead())
	if _, err := io.ReadFull(c.br, body); err != nil {
		return err
	}
	plain, err = c.st.open(nil, body)
	if err != nil {
		return fmt.Errorf("ninja: open chunk body: %w", err)
	}
	c.payload = plain[:total-pad]
	return nil
}
