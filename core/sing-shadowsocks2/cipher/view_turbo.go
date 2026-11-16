package cipher

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"strings"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// The ViewTurbo variant of a shadowsocks node hides the real shadowsocks
// handshake behind a forged HTTP request:
//
//	<20-25 random letters>\r\n\r\n    forged request line and header end
//	<60 byte token block>             token, second byte inverted, ':' padded
//	<32 byte salt block>              first salt block, first byte inverted
//	<remainder of the first write>
//
// The node password carries the marker: "...#VT" (or a 34 byte password whose
// last two characters are "VT"). The marker is stripped before the wrapped
// method derives its key, and the real token travels in the header, so the
// underlying method runs with the vendor's fixed placeholder password.
//
// On the read side the server answers with a fake header of its own, which is
// located by the first "\r\n\r\n" and dropped together with anything the client
// already buffered from the real stream.

const (
	viewTurboMarker = "#VT"

	// viewTurboTokenBlock is the fixed 60 byte token block the vendor client
	// sends. The token is copied into it verbatim, so a token longer than 60
	// bytes is truncated by the copy below, exactly like the vendor build.
	viewTurboTokenBlock = 60

	// viewTurboSaltBlock is the fixed 32 byte salt block.
	viewTurboSaltBlock = 32

	// viewTurboPlaceholderPassword replaces the node password for the wrapped
	// method: the server derives the real key from the token in the header.
	viewTurboPlaceholderPassword = "password"

	// viewTurboMaxHeader bounds the forged response header the reader will
	// buffer before it gives up.
	viewTurboMaxHeader = 4096
)

// ParseViewTurboPassword strips the ViewTurbo marker off a node password. The
// marker is either the "#VT" suffix or, for a 34 byte password, a bare "VT"
// suffix (the vendor app's second form).
func ParseViewTurboPassword(password string) (string, bool) {
	upper := strings.ToUpper(password)
	if strings.HasSuffix(upper, viewTurboMarker) {
		return password[:len(password)-len(viewTurboMarker)], true
	}
	if len(password) == 34 && strings.HasSuffix(upper, "VT") {
		return password[:len(password)-2], true
	}
	return password, false
}

// ParseBlackstonePassword strips the "#BLACKSTONE" suffix off a node password.
// The suffix is case insensitive, matching the vendor client.
func ParseBlackstonePassword(password string) (string, bool) {
	const suffix = "#BLACKSTONE"
	if len(password) < len(suffix) || !strings.EqualFold(password[len(password)-len(suffix):], suffix) {
		return password, false
	}
	return password[:len(password)-len(suffix)], true
}

// viewTurboMethod wraps a method so its connections carry the forged header.
// Packet connections are not wrapped: the vendor client only uses the marker on
// the TCP path, and a wrapped UDP datagram would change the standard wire.
type viewTurboMethod struct {
	origMethod Method
	token      string
}

func (m *viewTurboMethod) DialConn(conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	return m.origMethod.DialConn(newViewTurboConn(conn, m.token), destination)
}

func (m *viewTurboMethod) DialEarlyConn(conn net.Conn, destination M.Socksaddr) net.Conn {
	return m.origMethod.DialEarlyConn(newViewTurboConn(conn, m.token), destination)
}

func (m *viewTurboMethod) DialPacketConn(conn net.Conn) N.NetPacketConn {
	return m.origMethod.DialPacketConn(conn)
}

// viewTurboConn writes the forged preamble in front of the first shadowsocks
// write and strips the forged header off the first read.
type viewTurboConn struct {
	net.Conn
	token      string
	firstWrite bool
	firstRead  bool
	// leftover holds real stream bytes that arrived in the same read as the
	// end of the forged header.
	leftover []byte
	random   *rand.Rand
}

func newViewTurboConn(c net.Conn, token string) net.Conn {
	return &viewTurboConn{
		Conn:       c,
		token:      token,
		firstWrite: true,
		firstRead:  true,
		random:     rand.New(rand.NewSource(randomSeed())),
	}
}

func randomSeed() int64 {
	var seed [8]byte
	if _, err := cryptorand.Read(seed[:]); err == nil {
		return int64(binary.LittleEndian.Uint64(seed[:]))
	}
	return int64(binary.LittleEndian.Uint64([]byte("ViewTurb")))
}

func (c *viewTurboConn) randomString(min, max int) string {
	length := min
	if max > min {
		length = c.random.Intn(max-min+1) + min
	}
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]rune, length)
	for i := range b {
		b[i] = rune(letters[c.random.Intn(len(letters))])
	}
	return string(b)
}

// Write sends the forged preamble in front of the first shadowsocks write. The
// first write is split into several TCP segments, which is what the vendor
// client's traffic looks like on the wire.
func (c *viewTurboConn) Write(b []byte) (int, error) {
	if !c.firstWrite || len(b) < viewTurboSaltBlock {
		return c.Conn.Write(b)
	}
	c.firstWrite = false

	fakeHeader := c.randomString(20, 25) + "\r\n\r\n"
	if _, err := c.Conn.Write([]byte(fakeHeader)); err != nil {
		return 0, err
	}

	tokenBlock := make([]byte, viewTurboTokenBlock)
	tokenBytes := []byte(c.token)
	copy(tokenBlock, tokenBytes)
	if len(tokenBytes) < viewTurboTokenBlock {
		tokenBlock[len(tokenBytes)] = ':'
	}
	tokenBlock[1] = ^tokenBlock[1]
	if _, err := c.Conn.Write(tokenBlock); err != nil {
		return 0, err
	}

	saltBlock := make([]byte, viewTurboSaltBlock)
	copy(saltBlock, b[:viewTurboSaltBlock])
	saltBlock[0] = ^saltBlock[0]
	if _, err := c.Conn.Write(saltBlock); err != nil {
		return 0, err
	}

	rem := b[viewTurboSaltBlock:]
	if len(rem) > 0 {
		splitSize := c.random.Intn(30) + 50
		if len(rem) < splitSize {
			splitSize = len(rem)
		}
		if _, err := c.Conn.Write(rem[:splitSize]); err != nil {
			return 0, err
		}
		if len(rem) > splitSize {
			if _, err := c.Conn.Write(rem[splitSize:]); err != nil {
				return 0, err
			}
		}
	}
	return len(b), nil
}

// Read drops the server's forged header on the first read. Bytes that arrived
// past the header end are kept in leftover and served before the connection is
// read again.
func (c *viewTurboConn) Read(b []byte) (int, error) {
	if c.firstRead {
		c.firstRead = false
		buf := make([]byte, 1024)
		var received []byte
		for {
			n, err := c.Conn.Read(buf)
			if err != nil {
				return 0, err
			}
			received = append(received, buf[:n]...)
			if idx := bytes.Index(received, []byte("\r\n\r\n")); idx != -1 {
				end := idx + 4
				if len(received) > end {
					c.leftover = append(c.leftover, received[end:]...)
				}
				break
			}
			if len(received) > viewTurboMaxHeader {
				return 0, io.ErrUnexpectedEOF
			}
		}
	}
	if len(c.leftover) > 0 {
		n := copy(b, c.leftover)
		c.leftover = c.leftover[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}
