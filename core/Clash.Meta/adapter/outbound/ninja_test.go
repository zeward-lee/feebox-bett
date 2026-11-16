package outbound

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/ninja"
)

// startNinjaEchoServer runs a minimal ninja responder that echoes everything
// back, so the outbound adapter can be exercised end to end.
func startNinjaEchoServer(t *testing.T, cfg *ninja.Config) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := ninja.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				c, _, _, err := srv.Handshake(raw)
				if err != nil {
					t.Logf("handshake: %v", err)
					return
				}
				io.Copy(c, c)
				c.Close()
			}(raw)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestNinjaOutboundEcho(t *testing.T) {
	cfg := &ninja.Config{
		Method:   ninja.MethodAES128GCM,
		Password: "testpass",
		Padding:  ninja.PaddingConfig{Mode: ninja.PaddingRandom, Max: 64},
	}
	addr, stop := startNinjaEchoServer(t, cfg)
	defer stop()

	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	proxy, err := NewNinja(NinjaOption{
		Name:         "n1",
		Server:       host,
		Port:         port,
		Password:     "testpass",
		NodePassword: "testpass",
		Method:       "aes-128-gcm",
	})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Type() != C.Ninja {
		t.Fatalf("type = %v", proxy.Type())
	}

	meta := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.SOCKS5,
		Host:    "example.org",
		DstPort: 8080,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, meta)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte("ninja"), 300)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echo mismatch")
	}
}
