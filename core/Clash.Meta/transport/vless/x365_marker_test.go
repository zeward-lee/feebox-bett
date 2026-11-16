package vless

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
)

type x365MemoryConn struct {
	writes bytes.Buffer
	read   bytes.Reader
}

func (c *x365MemoryConn) Read(p []byte) (int, error)  { return c.read.Read(p) }
func (c *x365MemoryConn) Write(p []byte) (int, error) { return c.writes.Write(p) }
func (*x365MemoryConn) Close() error                  { return nil }
func (*x365MemoryConn) LocalAddr() net.Addr           { return testAddr("local") }
func (*x365MemoryConn) RemoteAddr() net.Addr          { return testAddr("remote") }
func (*x365MemoryConn) SetDeadline(time.Time) error   { return nil }
func (*x365MemoryConn) SetReadDeadline(time.Time) error {
	return nil
}
func (*x365MemoryConn) SetWriteDeadline(time.Time) error { return nil }

const x365TestUUID = "00112233-4455-6677-8899-aabbccddeeff"

// TestX365MarkerRequestWire pins the inline x365 request a `type: vless` node
// with a #x365 uuid sends: the marker switches the wire format and the request
// carries the bare 16 byte UUID.
func TestX365MarkerRequestWire(t *testing.T) {
	client, err := NewClient(x365TestUUID+"#x365", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !client.IsX365 {
		t.Fatal("client did not switch to the x365 wire")
	}
	wire := &x365MemoryConn{}
	dst := &DstAddr{
		AddrType: AtypDomainName,
		Addr:     append([]byte{11}, []byte("example.com")...),
		Port:     443,
	}
	conn, err := client.StreamConn(wire, dst)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(nil); err != nil {
		t.Fatal(err)
	}

	id := uuid.Must(uuid.FromString(x365TestUUID))
	want := append([]byte("X365"), 0x01, CommandTCP)
	want = append(want, id.Bytes()...)
	want = append(want, 0x01, 0xbb) // port 443
	want = append(want, AtypDomainName)
	want = append(want, 11)
	want = append(want, "example.com"...)
	if got := wire.writes.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("request = %x\nwant       %x", got, want)
	}
}

// TestX365MarkerResponseMagic keeps a wrong response magic an error, which is
// what turns a silent half-open tunnel into a log line.
func TestX365MarkerResponseMagic(t *testing.T) {
	client, err := NewClient(x365TestUUID+"#x365", nil)
	if err != nil {
		t.Fatal(err)
	}
	wire := &x365MemoryConn{}
	wire.read.Reset([]byte("HTTP/1.1 400\r\n"))
	conn, err := client.StreamConn(wire, &DstAddr{AddrType: AtypIPv4, Addr: []byte{1, 2, 3, 4}, Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 1)); err == nil {
		t.Fatal("a non x365 response prefix was accepted")
	}
}

// TestX365MarkerSuffixIsCaseSensitive pins the vendor comparison: only the exact
// lowercase marker switches the wire, so a name ending in "#X365" stays a plain
// vless node with an untouched uuid.
func TestX365MarkerSuffixIsCaseSensitive(t *testing.T) {
	client, err := NewClient(x365TestUUID+"#X365", nil)
	if err != nil {
		t.Fatal(err)
	}
	if client.IsX365 || client.mode != ModeStandard {
		t.Fatalf("IsX365=%v mode=%v, want a plain vless node", client.IsX365, client.mode)
	}
	clean, mode, err := parsePrivateUUID(x365TestUUID + "#x365")
	if err != nil || clean != x365TestUUID || mode != ModeX365 {
		t.Fatalf("parsePrivateUUID() = (%q, %v, %v)", clean, mode, err)
	}
	if got := hex.EncodeToString(client.uuid.Bytes()); got == "" {
		t.Fatal("uuid was lost")
	}
}
