package v2rayxhttp

import (
	"crypto/sha256"
	"encoding/hex"
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

// TestObfsKeyDerivation locks the key schedule to the vendor wire format: the
// AES-128 key is the first 16 bytes of a bare SHA-256 of the obfs key. Adding a
// domain separator, a prefix or a different truncation silently breaks every
// dedicated line (the peer answers "obfs key mismatch"), so the mapping for a
// known vendor key is pinned here.
func TestObfsKeyDerivation(t *testing.T) {
	const obfsKey = "9uByRBBiCy"
	// hex of SHA-256("9uByRBBiCy")[:16], computed independently of this package.
	const wantHex = "a8a981e3a2d529f9ba745ade7c8c0094"
	sum := sha256.Sum256([]byte(obfsKey))
	got := hex.EncodeToString(sum[:obfsKeyLength])
	if got != wantHex {
		t.Fatalf("derived key = %s, want %s (vendor SDK-256[:16], no domain separation)", got, wantHex)
	}

	conn := newObfsConn(&deadConn{}, obfsKey).(*obfsConn)
	if key := hex.EncodeToString(conn.key[:]); key != wantHex {
		t.Fatalf("obfsConn key = %s, want %s", key, wantHex)
	}
	// An empty key returns the conn untouched: Validate rejects a missing key, so
	// only an explicit opt-out reaches this branch.
	plain := &deadConn{}
	if wrapped := newObfsConn(plain, ""); wrapped != net.Conn(plain) {
		t.Fatal("empty obfs key must pass the conn through unchanged")
	}
}

// TestObfsIVIsFreshAndFullLength checks the per-connection preamble: a fresh
// random 16-byte IV for every connection, never reused.
func TestObfsIVIsFreshAndFullLength(t *testing.T) {
	ivs := make(map[string]bool, 2)
	for i := 0; i < 2; i++ {
		iv := captureClientIV(t)
		if len(iv) != obfsIVLength {
			t.Fatalf("connection %d IV length = %d, want %d", i, len(iv), obfsIVLength)
		}
		if ivs[string(iv)] {
			t.Fatalf("connection %d reused IV %x", i, iv)
		}
		ivs[string(iv)] = true
	}
}

// captureClientIV dials a loopback listener, writes one payload through a fresh
// obfs conn and returns the IV of the preamble the peer received.
func captureClientIV(t *testing.T) []byte {
	t.Helper()
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
		_, _ = obfs.Write([]byte("iv probe"))
	}()

	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer accepted.Close()
	_ = accepted.SetReadDeadline(time.Now().Add(5 * time.Second))
	preamble := make([]byte, obfsPreamble)
	if _, err := io.ReadFull(accepted, preamble); err != nil {
		t.Fatalf("read preamble: %v", err)
	}
	iv := make([]byte, obfsIVLength)
	copy(iv, preamble[:obfsIVLength])
	return iv
}

// TestObfsBadPreambleClosesConn pins the review fix: a preamble that fails the
// tag check leaves the conn unusable, so the wrapper closes the socket instead
// of letting it linger until a read timeout.
func TestObfsBadPreambleClosesConn(t *testing.T) {
	clientSide, peer := net.Pipe()
	defer peer.Close()
	recorder := &closeRecorder{Conn: clientSide}
	obfs := newObfsConn(recorder, "right-key")

	go func() {
		// 16-byte IV and a 4-byte tag that decrypts to 89c6fea7 with this key,
		// i.e. a peer that used a different obfs key.
		_, _ = peer.Write(make([]byte, obfsPreamble))
	}()

	buf := make([]byte, 8)
	_, err := obfs.Read(buf)
	if err == nil || !strings.Contains(err.Error(), obfsKeyMismatch) {
		t.Fatalf("read error = %v, want obfs key mismatch", err)
	}
	if !recorder.closed {
		t.Error("underlying conn was not closed after a bad preamble")
	}
}

type closeRecorder struct {
	net.Conn
	closed bool
}

func (c *closeRecorder) Close() error {
	c.closed = true
	return c.Conn.Close()
}

// deadConn is a net.Conn that is never read or written; it only exists so the
// key-derivation test can build an obfsConn without a socket.
type deadConn struct{}

func (*deadConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (*deadConn) Write([]byte) (int, error)        { return 0, io.EOF }
func (*deadConn) Close() error                     { return nil }
func (*deadConn) LocalAddr() net.Addr              { return nil }
func (*deadConn) RemoteAddr() net.Addr             { return nil }
func (*deadConn) SetDeadline(time.Time) error      { return nil }
func (*deadConn) SetReadDeadline(time.Time) error  { return nil }
func (*deadConn) SetWriteDeadline(time.Time) error { return nil }

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
