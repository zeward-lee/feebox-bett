package v2rayxhttp

import (
	"crypto/sha256"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// TestObfsRoundTrip checks the symmetric obfs layer: the connector writes a
// 20-byte preamble (IV + tag) and both directions then speak AES-CTR.
func TestObfsRoundTrip(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	const key = "9uByRBBiCy"
	client := newObfsConn(clientSide, key)
	server := newObfsConn(serverSide, key)

	done := make(chan error, 2)
	go func() {
		_, err := client.Write([]byte("hello dedicated line"))
		done <- err
	}()
	go func() {
		buf := make([]byte, 64)
		n, err := server.Read(buf)
		if err == nil && string(buf[:n]) != "hello dedicated line" {
			t.Errorf("server read %q", buf[:n])
			err = io.ErrUnexpectedEOF
		}
		done <- err
	}()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("obfs round trip: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("obfs round trip timed out")
		}
	}

	// Reverse direction reuses the same wrapper with its own preamble.
	go func() {
		_, err := server.Write([]byte("pong"))
		done <- err
	}()
	go func() {
		buf := make([]byte, 16)
		n, err := client.Read(buf)
		if err == nil && string(buf[:n]) != "pong" {
			t.Errorf("client read %q", buf[:n])
			err = io.ErrUnexpectedEOF
		}
		done <- err
	}()
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatalf("obfs reverse round trip: %v", err)
		}
	}
}

// TestObfsHandshakePreamble pins the vendor wire format: the first 20 bytes are
// a random 16-byte IV followed by AES-CTR(key, IV) applied to four zero bytes,
// with key = SHA-256(obfs_key)[:16].
func TestObfsHandshakePreamble(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	obfs := newObfsConn(conn, "9uByRBBiCy")
	go func() {
		_, _ = obfs.Write([]byte{0x16, 0x03, 0x01}) // fake TLS record header
	}()

	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer accepted.Close()
	_ = accepted.SetReadDeadline(time.Now().Add(5 * time.Second))
	preamble := make([]byte, obfsPreamble+3)
	if _, err := io.ReadFull(accepted, preamble); err != nil {
		t.Fatalf("read preamble: %v", err)
	}
	sum := sha256.Sum256([]byte("9uByRBBiCy"))
	stream, err := newObfsStream(sum[:obfsKeyLength], preamble[:obfsIVLength])
	if err != nil {
		t.Fatalf("new stream: %v", err)
	}
	decrypted := make([]byte, len(preamble)-obfsIVLength)
	stream.XORKeyStream(decrypted, preamble[obfsIVLength:])
	for i, v := range decrypted[:obfsTagLength] {
		if v != 0 {
			t.Fatalf("tag byte %d is %#x, want 0 (preamble %x)", i, v, preamble)
		}
	}
	payload := decrypted[obfsTagLength:]
	if string(payload) != string([]byte{0x16, 0x03, 0x01}) {
		t.Fatalf("payload decrypts to %x", payload)
	}
}

// TestObfsKeyMismatch mirrors the vendor error path: a preamble whose tag does
// not decrypt to zero means the peer used a different obfs key.
func TestObfsKeyMismatch(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	client := newObfsConn(clientSide, "wrong-key")
	server := newObfsConn(serverSide, "right-key")
	go func() {
		_, _ = client.Write([]byte("x"))
	}()
	_ = serverSide.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 8)
	_, err := server.Read(buf)
	if err == nil || !strings.Contains(err.Error(), "obfs key mismatch") {
		t.Fatalf("got error %v, want obfs key mismatch", err)
	}
}
