package ninja

import (
	"bytes"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func testConfig() *Config {
	return &Config{
		Method:   MethodAES128GCM,
		Password: "testpass",
		Padding:  PaddingConfig{Mode: PaddingRandom, Min: 0, Max: 64},
	}
}

// TestRoundTrip checks that our own client and server agree on the framing.
func TestRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv, err := NewServer(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		host string
		port uint16
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			ch <- result{err: err}
			return
		}
		c, host, port, err := srv.Handshake(raw)
		ch <- result{host: host, port: port, conn: c, err: err}
	}()

	cli, err := NewClient(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := cli.StreamConn(raw, "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("hello ninja tunnel, this is a payload longer than one chunk boundary? no.")
	go func() {
		c.Write(payload)
		c.Write(bytes.Repeat([]byte("Z"), 1000))
	}()

	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	if r.host != "example.com" || r.port != 443 {
		t.Fatalf("server saw %s:%d", r.host, r.port)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(r.conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch:\n got %q\nwant %q", got, payload)
	}
	rest := make([]byte, 1000)
	if _, err := io.ReadFull(r.conn, rest); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, bytes.Repeat([]byte("Z"), 1000)) {
		t.Fatal("big payload mismatch")
	}
}

// TestInteropServer exposes a reference compatible server for black box testing
// against the original mihomo-ninja client binary.
//
//	NINJA_SRV=1 go test ./transport/ninja -run TestInteropServer -v
func TestInteropServer(t *testing.T) {
	if os.Getenv("NINJA_SRV") == "" {
		t.Skip("set NINJA_SRV=1 to run the interop server")
	}
	addr := os.Getenv("NINJA_SRV_ADDR")
	if addr == "" {
		addr = "127.0.0.1:19099"
	}
	pass := os.Getenv("NINJA_SRV_PASS")
	if pass == "" {
		pass = "testpass"
	}
	method := os.Getenv("NINJA_SRV_METHOD")
	if method == "" {
		method = string(MethodAES128GCM)
	}
	cfg := &Config{Method: Method(method), Password: pass, Padding: PaddingConfig{Mode: PaddingRandom, Max: 128}}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("interop server listening on %s (method=%s)", addr, method)
	for {
		raw, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		go func(raw net.Conn) {
			c, host, port, err := srv.Handshake(raw)
			if err != nil {
				t.Logf("handshake error from %s: %v", raw.RemoteAddr(), err)
				return
			}
			t.Logf("tunnel: %s -> %s:%d", raw.RemoteAddr(), host, port)
			target := net.JoinHostPort(host, itoa(int(port)))
			up, err := net.DialTimeout("tcp", target, 5*time.Second)
			if err != nil {
				t.Logf("dial %s: %v", target, err)
				c.Close()
				return
			}
			go func() { io.Copy(up, c); up.Close() }()
			io.Copy(c, up)
			c.Close()
		}(raw)
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
