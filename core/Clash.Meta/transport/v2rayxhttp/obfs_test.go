package v2rayxhttp

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// TestObfsRoundTrip checks the symmetric obfs layer: the writer sends a 20-byte
// preamble (IV + tag) and both directions then speak AES-CTR. The wrappers are
// stream-body wrappers (io.Writer / io.Reader), not net.Conn wrappers.
func TestObfsRoundTrip(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	const key = "9uByRBBiCy"
	clientWriter := wrapObfsWriter(clientSide, key)
	serverReader := &obfsReader{r: serverSide, key: deriveObfsKey(key)}
	serverWriter := wrapObfsWriter(serverSide, key)
	clientReader := &obfsReader{r: clientSide, key: deriveObfsKey(key)}

	done := make(chan error, 2)
	go func() {
		_, err := clientWriter.Write([]byte("hello dedicated line"))
		done <- err
	}()
	go func() {
		buf := make([]byte, 64)
		n, err := serverReader.Read(buf)
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

	// Reverse direction uses its own wrapper and IV, exactly like the vendor's
	// per-direction obfsReader/obfsWriter pair.
	go func() {
		_, err := serverWriter.Write([]byte("pong"))
		done <- err
	}()
	go func() {
		buf := make([]byte, 16)
		n, err := clientReader.Read(buf)
		if err == nil && string(buf[:n]) != "pong" {
			t.Errorf("client read %q", buf[:n])
			err = io.ErrUnexpectedEOF
		}
		done <- err
	}()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("obfs reverse round trip: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("obfs reverse round trip timed out")
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
	obfs := wrapObfsWriter(conn, "9uByRBBiCy")
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
		t.Fatalf("derived key = %s, want %s (vendor SHA-256[:16], no domain separation)", got, wantHex)
	}

	key := deriveObfsKey(obfsKey)
	if hex.EncodeToString(key[:]) != wantHex {
		t.Fatalf("obfs key = %s, want %s", hex.EncodeToString(key[:]), wantHex)
	}
	// An empty key returns the body untouched: Validate rejects a missing key,
	// so only an explicit opt-out reaches this branch.
	plain := &deadWriter{}
	if wrapped := wrapObfsWriter(plain, ""); wrapped != io.Writer(plain) {
		t.Fatal("empty obfs key must pass the writer through unchanged")
	}
}

// TestObfsIVIsFreshAndFullLength checks the per-body preamble: a fresh random
// 16-byte IV for every obfuscated stream, never reused.
func TestObfsIVIsFreshAndFullLength(t *testing.T) {
	ivs := make(map[string]bool, 2)
	for i := 0; i < 2; i++ {
		iv := captureClientIV(t)
		if len(iv) != obfsIVLength {
			t.Fatalf("stream %d IV length = %d, want %d", i, len(iv), obfsIVLength)
		}
		if ivs[string(iv)] {
			t.Fatalf("stream %d reused IV %x", i, iv)
		}
		ivs[string(iv)] = true
	}
}

// captureClientIV dials a loopback listener, writes one payload through a fresh
// obfs writer and returns the IV of the preamble the peer received.
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
	obfs := wrapObfsWriter(conn, "9uByRBBiCy")
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

// TestObfsBadPreambleClosesBody pins fail-closed behaviour: a preamble that
// fails the tag check leaves the stream unusable, so the body is closed and the
// error is sticky (a retry must not re-read the same garbage).
func TestObfsBadPreambleClosesBody(t *testing.T) {
	recorder := &closeRecorderReader{
		Reader: strings.NewReader(string(make([]byte, obfsPreamble))),
	}
	obfs := wrapObfsReader(recorder, "right-key")

	buf := make([]byte, 8)
	_, err := obfs.Read(buf)
	if err == nil || !strings.Contains(err.Error(), obfsKeyMismatch) {
		t.Fatalf("read error = %v, want obfs key mismatch", err)
	}
	if !recorder.closed {
		t.Error("underlying body was not closed after a bad preamble")
	}
	if _, err := obfs.Read(buf); err == nil || !strings.Contains(err.Error(), obfsKeyMismatch) {
		t.Fatalf("second read error = %v, want the sticky obfs key mismatch", err)
	}
}

type closeRecorderReader struct {
	io.Reader
	closed bool
}

func (r *closeRecorderReader) Close() error {
	r.closed = true
	return nil
}

// deadWriter is an io.Writer that is never written to; it only exists so the
// key-derivation test can build an obfs writer without a socket.
type deadWriter struct{}

func (*deadWriter) Write([]byte) (int, error) { return 0, io.EOF }

// TestObfsKeyMismatch mirrors the vendor error path: a preamble whose tag does
// not decrypt to zero means the peer used a different obfs key.
func TestObfsKeyMismatch(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	client := wrapObfsWriter(clientSide, "wrong-key")
	server := wrapObfsReader(&nopReadCloser{serverSide}, "right-key")
	go func() {
		_, _ = client.Write([]byte("x"))
	}()
	_ = serverSide.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 8)
	_, err := server.Read(buf)
	if err == nil || !strings.Contains(err.Error(), obfsKeyMismatch) {
		t.Fatalf("got error %v, want obfs key mismatch", err)
	}
}

type nopReadCloser struct {
	io.Reader
}

func (nopReadCloser) Close() error { return nil }

// TestObfsWriterErrorIsSticky pins the write half of fail-closed: once a write
// to the body fails, later writes keep reporting the same error instead of
// emitting bytes that continue a broken CTR stream.
func TestObfsWriterErrorIsSticky(t *testing.T) {
	writer := wrapObfsWriter(&failingWriter{}, "key")
	if _, err := writer.Write([]byte("boom")); err == nil {
		t.Fatal("first write should fail")
	} else if !errors.Is(err, errWriterBoom) {
		t.Fatalf("first write error = %v, want %v", err, errWriterBoom)
	}
	if _, err := writer.Write([]byte("again")); !errors.Is(err, errWriterBoom) {
		t.Fatalf("second write error = %v, want the sticky %v", err, errWriterBoom)
	}
}

var errWriterBoom = errors.New("writer boom")

type failingWriter struct{}

func (*failingWriter) Write([]byte) (int, error) { return 0, errWriterBoom }
