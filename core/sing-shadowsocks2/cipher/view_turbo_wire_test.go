package cipher

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"net"
	"testing"
	"time"
)

type memoryConn struct {
	reader io.Reader
	writes bytes.Buffer
}

func (c *memoryConn) Read(p []byte) (int, error) {
	if c.reader == nil {
		return 0, io.EOF
	}
	return c.reader.Read(p)
}
func (c *memoryConn) Write(p []byte) (int, error)    { return c.writes.Write(p) }
func (*memoryConn) Close() error                     { return nil }
func (*memoryConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (*memoryConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (*memoryConn) SetDeadline(time.Time) error      { return nil }
func (*memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }

func TestViewTurboFirstWriteWire(t *testing.T) {
	underlying := &memoryConn{}
	conn := &viewTurboConn{
		Conn:       underlying,
		token:      "test-token",
		firstWrite: true,
		firstRead:  true,
		random:     rand.New(rand.NewSource(1)),
	}
	input := make([]byte, 100)
	for i := range input {
		input[i] = byte(i)
	}

	n, err := conn.Write(input)
	if err != nil || n != len(input) {
		t.Fatalf("Write() = %d, %v; want %d, nil", n, err, len(input))
	}
	wire := underlying.writes.Bytes()
	headerEnd := bytes.Index(wire, []byte("\r\n\r\n"))
	if headerEnd < viewTurboMinHeaderLength || headerEnd > viewTurboMaxHeaderLength {
		t.Fatalf("fake header length = %d; want %d..%d", headerEnd, viewTurboMinHeaderLength, viewTurboMaxHeaderLength)
	}
	for i, b := range wire[:headerEnd] {
		if b < 'A' || b > 'Z' && b < 'a' || b > 'z' {
			t.Fatalf("fake header byte %d = %#x; want ASCII letter", i, b)
		}
	}

	offset := headerEnd + 4
	if len(wire) != offset+60+len(input) {
		t.Fatalf("wire length = %d; want %d", len(wire), offset+60+len(input))
	}
	tokenBlock := wire[offset : offset+60]
	wantToken := []byte("test-token")
	for i, want := range wantToken {
		if i == 1 {
			want = ^want
		}
		if tokenBlock[i] != want {
			t.Fatalf("token byte %d = %#x; want %#x", i, tokenBlock[i], want)
		}
	}
	if tokenBlock[len(wantToken)] != ':' {
		t.Fatalf("token terminator = %#x; want ':'", tokenBlock[len(wantToken)])
	}

	offset += 60
	wantSalt := append([]byte(nil), input[:32]...)
	wantSalt[0] = ^wantSalt[0]
	if !bytes.Equal(wire[offset:offset+32], wantSalt) {
		t.Fatalf("salt block = %x; want %x", wire[offset:offset+32], wantSalt)
	}
	if !bytes.Equal(wire[offset+32:], input[32:]) {
		t.Fatalf("payload remainder changed: got %x want %x", wire[offset+32:], input[32:])
	}
}

func TestViewTurboReadStripsHeaderAndDrainsLeftover(t *testing.T) {
	payload := []byte("encrypted-response-payload")
	wire := append([]byte("camouflage\r\n\r\n"), payload...)
	underlying := &memoryConn{reader: bytes.NewReader(wire)}
	conn := &viewTurboConn{Conn: underlying, firstRead: true}

	first := make([]byte, 5)
	n, err := conn.Read(first)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first[:n], payload[:5]) {
		t.Fatalf("first Read = %q; want %q", first[:n], payload[:5])
	}
	if len(conn.leftover) != len(payload)-5 {
		t.Fatalf("leftover length = %d; want %d", len(conn.leftover), len(payload)-5)
	}

	second := make([]byte, len(payload))
	n, err = conn.Read(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second[:n], payload[5:]) {
		t.Fatalf("second Read = %q; want %q", second[:n], payload[5:])
	}
	if len(conn.leftover) != 0 {
		t.Fatalf("leftover not drained: %d bytes", len(conn.leftover))
	}
}

func TestViewTurboReadRejectsOverlongHeader(t *testing.T) {
	// One byte past the vendor's 64 KiB limit, with no "\r\n\r\n" in sight.
	overlong := bytes.Repeat([]byte{'x'}, viewTurboMaxHeader+1024)
	underlying := &memoryConn{reader: bytes.NewReader(overlong)}
	conn := &viewTurboConn{Conn: underlying, firstRead: true}

	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Read error = %v; want io.ErrUnexpectedEOF", err)
	}
}

// TestViewTurboReadAcceptsLargeHeader pins the read cap at the vendor's 64 KiB:
// an 8 KiB forged header (well past the old 4096 limit) must be stripped, not
// mistaken for EOF, and the payload behind it must survive.
func TestViewTurboReadAcceptsLargeHeader(t *testing.T) {
	payload := []byte("real-stream-bytes")
	wire := append(bytes.Repeat([]byte("X"), 8192), []byte("\r\n\r\n")...)
	wire = append(wire, payload...)
	underlying := &memoryConn{reader: bytes.NewReader(wire)}
	conn := &viewTurboConn{Conn: underlying, firstRead: true}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("Read = %v; want the payload after an 8 KiB header", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("payload = %q; want %q", buf, payload)
	}
}

// TestViewTurboFakeHeaderLengthRange pins the forged-header length window: the
// vendor randomizes it over 32..128 letters, and the fake request line must use
// the whole window (a fixed or narrow length is a fingerprint).
func TestViewTurboFakeHeaderLengthRange(t *testing.T) {
	conn := &viewTurboConn{random: rand.New(rand.NewSource(7))}
	minSeen, maxSeen := viewTurboMaxHeaderLength, viewTurboMinHeaderLength
	for i := 0; i < 500; i++ {
		n := len(conn.randomString(viewTurboMinHeaderLength, viewTurboMaxHeaderLength))
		if n < viewTurboMinHeaderLength || n > viewTurboMaxHeaderLength {
			t.Fatalf("length %d outside %d..%d", n, viewTurboMinHeaderLength, viewTurboMaxHeaderLength)
		}
		if n < minSeen {
			minSeen = n
		}
		if n > maxSeen {
			maxSeen = n
		}
	}
	if minSeen > viewTurboMinHeaderLength+8 {
		t.Errorf("min observed length = %d; want the window to reach %d", minSeen, viewTurboMinHeaderLength)
	}
	if maxSeen < viewTurboMaxHeaderLength-8 {
		t.Errorf("max observed length = %d; want the window to reach %d", maxSeen, viewTurboMaxHeaderLength)
	}
	if maxSeen-minSeen < (viewTurboMaxHeaderLength-viewTurboMinHeaderLength)*3/4 {
		t.Errorf("length only spans %d..%d; want the full 32..128 window", minSeen, maxSeen)
	}
}
