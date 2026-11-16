package outbound

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/xhttpstream"
)

// TestXhttpStaticRelay drives the whole static path of the adapter against a
// local server that speaks the vendor handshake: DialContext must write the
// forged preamble, the token, the hmac and the destination, and the payload must
// round trip through the CTR streams. This is the endpoint level companion of the
// transport/xhttpstream tests (which only exercise the conn).
func TestXhttpStaticRelay(t *testing.T) {
	const (
		secret   = "relay-secret"
		hmacHex  = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
		fakeNet  = "16030100c5010000c10303"
		password = secret + ":" + hmacHex
	)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	defer listener.Close()

	token := xhttpstream.Token(secret)
	hmacKey, err := hex.DecodeString(hmacHex)
	if err != nil {
		t.Fatal(err)
	}
	key := xhttpstream.Kdf(secret, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		prefix := make([]byte, xhttpstream.FakePrefixLen)
		if _, err := io.ReadFull(conn, prefix); err != nil {
			serverErr <- err
			return
		}
		fake, _ := hex.DecodeString(fakeNet)
		if !bytes.HasPrefix(prefix, fake) {
			serverErr <- errString("forged prefix does not start with fake-net bytes")
			return
		}
		gotToken := make([]byte, len(token))
		if _, err := io.ReadFull(conn, gotToken); err != nil {
			serverErr <- err
			return
		}
		if !bytes.Equal(gotToken, token) {
			serverErr <- errString("token mismatch")
			return
		}
		gotHmac := make([]byte, len(hmacKey))
		if _, err := io.ReadFull(conn, gotHmac); err != nil {
			serverErr <- err
			return
		}
		if !bytes.Equal(gotHmac, hmacKey) {
			serverErr <- errString("hmac mismatch")
			return
		}
		ivLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, ivLen); err != nil {
			serverErr <- err
			return
		}
		if int(ivLen[0]) != block.BlockSize() {
			serverErr <- errString("unexpected write IV length")
			return
		}
		writeIV := make([]byte, block.BlockSize())
		if _, err := io.ReadFull(conn, writeIV); err != nil {
			serverErr <- err
			return
		}
		dec := xhttpstream.NewReader(conn, cipher.NewCTR(block, writeIV))

		// Reply in the runtime layout: prefix, echoed token, empty preamble, IV.
		serverPrefix := make([]byte, xhttpstream.FakePrefixLen)
		_, _ = rand.Read(serverPrefix)
		serverIV := make([]byte, block.BlockSize())
		_, _ = rand.Read(serverIV)
		header := append(serverPrefix, token...)
		header = append(header, 0x00, byte(len(serverIV)))
		header = append(header, serverIV...)
		if _, err := conn.Write(header); err != nil {
			serverErr <- err
			return
		}
		enc := xhttpstream.NewWriter(conn, cipher.NewCTR(block, serverIV))

		destination := make([]byte, 1+1+len("example.com")+2)
		destination[0] = 0x03
		destination[1] = byte(len("example.com"))
		copy(destination[2:], "example.com")
		destination[len(destination)-2] = 0x00
		destination[len(destination)-1] = 0x50
		gotDest := make([]byte, len(destination))
		if _, err := io.ReadFull(dec, gotDest); err != nil {
			serverErr <- err
			return
		}
		if !bytes.Equal(gotDest, destination) {
			serverErr <- errString("destination mismatch")
			return
		}
		payload := make([]byte, 4)
		if _, err := io.ReadFull(dec, payload); err != nil {
			serverErr <- err
			return
		}
		if string(payload) != "ping" {
			serverErr <- errString("payload mismatch: " + string(payload))
			return
		}
		if _, err := enc.Write([]byte("pong")); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	host, portStr, _ := net.SplitHostPort(listener.Addr().String())
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	x, err := NewXHttp(XHttpOption{
		Name:     "relay",
		Server:   host,
		Port:     port,
		Password: password,
		Cipher:   "aes-128-ctr",
		FakeNet:  map[string]string{"tcp": fakeNet},
		UDP:      false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := x.DialContext(ctx, &C.Metadata{
		NetWork: C.TCP,
		Type:    C.SOCKS5,
		Host:    "example.com",
		DstPort: 80,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "pong" {
		t.Fatalf("echo = %q, want pong", got)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
