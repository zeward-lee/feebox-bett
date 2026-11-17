package anytls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// vendorHexPassword is the vendor's bare 32 hex character password form, the
// one the Shanlian subscription publishes without the "#sl" marker. It is not a
// literal secret: it hex-decodes to the 16 byte key used by the vendor
// credential derivation (see deriveHexPasswordCredential).
const vendorHexPassword = "720a437f4beb4fb9915f7f913d7bc9f7"

// defaultFirstPacketPadding is the padding length of the vendor default scheme
// entry `0=30-30`.
const defaultFirstPacketPadding = 30

// firstPacketPlaintextLen is the plaintext length of the first packet that
// official sing-anytls v0.0.11 emits: 32B credential + 2B padding length + 30B
// zero padding. The official capture shows 5/5 connections with this shape.
const firstPacketPlaintextLen = sha256.Size + 2 + defaultFirstPacketPadding

// firstPacketRecordLen is the TLS 1.3 application_data record payload length
// (the length field, i.e. what a capture prints as "23(81)"): plaintext plus
// the 1-byte inner content type and the 16-byte AEAD tag.
const firstPacketRecordLen = firstPacketPlaintextLen + 17

// TestFirstPacketVendorHexPasswordUsesDerivedCredential pins the vendor bare 32
// hex password form to the vendor credential derivation: the first 16 bytes are
// the decoded key (not sha256(password)) and the last 16 bytes are the time
// token XORed with that key, followed by the unchanged upstream padding suffix.
// The official client sends exactly this shape (capture-official-20261117, 5/5
// records were 23(81)).
func TestFirstPacketVendorHexPasswordUsesDerivedCredential(t *testing.T) {
	raw, err := hex.DecodeString(vendorHexPassword)
	if err != nil {
		t.Fatalf("decode vendor password: %v", err)
	}
	plaintext, appRecordLens := captureFirstPacket(t, vendorHexPassword)
	assertFirstPacketLayout(t, plaintext, appRecordLens)

	u := assertDerivedHexCredential(t, plaintext[:sha256.Size], raw)
	assertTimestampMillis(t, u)
}

// TestFirstPacketMarkerKeepsUpstreamPrefix pins the "#sl" variant: the 64 hex
// key is decoded and keeps the same 64 byte upstream layout, so the existing
// vendor marker path is unchanged.
func TestFirstPacketMarkerKeepsUpstreamPrefix(t *testing.T) {
	want, err := hex.DecodeString(shanlianFixture)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	assertUpstreamFirstPacket(t, shanlianFixture+"#sl", want)
}

// TestFirstPacketOrdinaryPasswordKeepsUpstreamPrefix pins that a standard
// anytls password (neither the 32 hex vendor form nor the "#sl" marker) keeps
// the upstream layout byte for byte, so upstream anytls nodes are unaffected.
func TestFirstPacketOrdinaryPasswordKeepsUpstreamPrefix(t *testing.T) {
	const password = "ordinary-password"
	want := sha256.Sum256([]byte(password))
	assertUpstreamFirstPacket(t, password, want[:])
}

// TestSkipTLSWritesHandshakeIntoPlainStream pins the vendor xhttp path: with
// SkipTLS the dialed stream must receive the anytls prefix as the very first
// bytes and must not contain a TLS record in front of them.
//
// The xhttp transport already runs inside TLS, and the vendor server reads the
// upload body as `credential || 2B padding length || padding` directly. If the
// anytls layer adds a second TLS handshake here, the first bytes become
// 0x16 0x03 ... and the server never answers (production symptom: "failed to
// create session: context deadline exceeded").
func TestSkipTLSWritesHandshakeIntoPlainStream(t *testing.T) {
	raw, err := hex.DecodeString(vendorHexPassword)
	if err != nil {
		t.Fatalf("decode vendor password: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := parsePort(portText)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	client, err := NewClient(context.Background(), ClientConfig{
		Password:                 vendorHexPassword,
		Server:                   M.ParseSocksaddrHostPort(host, port),
		Dialer:                   directDialer{},
		SkipTLS:                  true,
		IdleSessionCheckInterval: 30 * time.Second,
		IdleSessionTimeout:       30 * time.Second,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	dialErr := make(chan error, 1)
	go func() {
		conn, err := client.createOutboundTLSConnection(context.Background())
		if err != nil {
			dialErr <- err
			return
		}
		_ = conn.Close()
		dialErr <- nil
	}()

	rawConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer rawConn.Close()
	_ = rawConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	plaintext := make([]byte, 0, 128)
	buf := make([]byte, 128)
	for len(plaintext) < firstPacketPlaintextLen {
		n, readErr := rawConn.Read(buf)
		plaintext = append(plaintext, buf[:n]...)
		if readErr != nil {
			t.Fatalf("read first packet: %v (got %d bytes)", readErr, len(plaintext))
		}
	}

	if plaintext[0] == 0x16 && len(plaintext) > 2 && plaintext[1] == 0x03 {
		t.Fatalf("first bytes %x look like a TLS record, want the plain anytls prefix", plaintext[:3])
	}
	if len(plaintext) != firstPacketPlaintextLen {
		t.Fatalf("first packet = %d bytes (%x), want %d", len(plaintext), plaintext, firstPacketPlaintextLen)
	}
	if !bytes.Equal(plaintext[:hexPasswordKeySize], raw) {
		t.Fatalf("credential key half = %x, want %x", plaintext[:hexPasswordKeySize], raw)
	}
	assertDerivedHexCredential(t, plaintext[:sha256.Size], raw)
	if got := binary.BigEndian.Uint16(plaintext[sha256.Size : sha256.Size+2]); int(got) != defaultFirstPacketPadding {
		t.Fatalf("padding length = %d, want %d", got, defaultFirstPacketPadding)
	}
	for i, b := range plaintext[sha256.Size+2:] {
		if b != 0 {
			t.Fatalf("padding byte %d = %#x, want 0", i, b)
		}
	}

	select {
	case err := <-dialErr:
		if err != nil {
			t.Fatalf("create outbound connection: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("outbound connection was never established")
	}
}

// assertUpstreamFirstPacket captures the real first packet for password and
// asserts both the plaintext layout and the TLS record payload length.
func assertUpstreamFirstPacket(t *testing.T, password string, wantCredential []byte) {
	t.Helper()
	if len(wantCredential) != sha256.Size {
		t.Fatalf("credential fixture is %d bytes, want %d", len(wantCredential), sha256.Size)
	}
	plaintext, appRecordLens := captureFirstPacket(t, password)
	assertFirstPacketLayout(t, plaintext, appRecordLens)

	if !bytes.Equal(plaintext[:sha256.Size], wantCredential) {
		t.Fatalf("credential = %x, want %x", plaintext[:sha256.Size], wantCredential)
	}
}

// assertFirstPacketLayout checks the vendor 64 byte plaintext: 32 bytes of
// credential, the 2 byte big endian padding length 30 and 30 zero padding
// bytes, carried in a TLS application_data record with payload length 81.
func assertFirstPacketLayout(t *testing.T, plaintext []byte, appRecordLens []int) {
	t.Helper()
	if len(plaintext) != firstPacketPlaintextLen {
		t.Fatalf("first packet plaintext = %d bytes (%x), want %d bytes",
			len(plaintext), plaintext, firstPacketPlaintextLen)
	}
	if got := binary.BigEndian.Uint16(plaintext[sha256.Size : sha256.Size+2]); int(got) != defaultFirstPacketPadding {
		t.Fatalf("padding length = %d, want %d", got, defaultFirstPacketPadding)
	}
	for i, b := range plaintext[sha256.Size+2:] {
		if b != 0 {
			t.Fatalf("padding byte %d = %#x, want 0", i, b)
		}
	}
	if got := appRecordLens[len(appRecordLens)-1]; got != firstPacketRecordLen {
		t.Fatalf("first packet application_data record length = %d (all records %v), want %d",
			got, appRecordLens, firstPacketRecordLen)
	}
}

// assertDerivedHexCredential verifies that credential is `raw16 || (T16 XOR
// raw16)` for some time token T16 = BE64(u*10+1) || BE64(u), and returns u.
func assertDerivedHexCredential(t *testing.T, credential, raw []byte) int64 {
	t.Helper()
	if len(credential) != hexPasswordCredentialSize {
		t.Fatalf("credential is %d bytes, want %d", len(credential), hexPasswordCredentialSize)
	}
	if len(raw) != hexPasswordKeySize {
		t.Fatalf("key fixture is %d bytes, want %d", len(raw), hexPasswordKeySize)
	}
	if !bytes.Equal(credential[:hexPasswordKeySize], raw) {
		t.Fatalf("credential key half = %x, want the decoded key %x", credential[:hexPasswordKeySize], raw)
	}
	var token [hexPasswordKeySize]byte
	for i := range token {
		token[i] = credential[hexPasswordKeySize+i] ^ raw[i]
	}
	high := binary.BigEndian.Uint64(token[0:8])
	low := binary.BigEndian.Uint64(token[8:16])
	if high != low*10+1 {
		t.Fatalf("time token = %x: high=%d is not UnixMilli*10+1 for low=%d", token, high, low)
	}
	return int64(low)
}

// assertTimestampMillis pins the derived token to roughly the wall clock, which
// proves the credential is generated at connection time instead of being a
// fixed fixture or a cached value.
func assertTimestampMillis(t *testing.T, millis int64) {
	t.Helper()
	now := time.Now().UnixMilli()
	const slack = int64(60 * 1000)
	if millis < now-slack || millis > now+slack {
		t.Fatalf("credential timestamp = %d ms, wall clock = %d ms (diff %d ms)", millis, now, millis-now)
	}
}

// captureFirstPacket runs one real TLS handshake against a loopback server and
// returns the plaintext the server received within a short grace period, plus
// the payload length of every application_data record on the wire.
//
// The TLS 1.3 client Finished is itself an application_data record (69 bytes
// with a SHA-384 suite as in the capture, 53 with SHA-256 as negotiated against
// the test server), so the first packet is the last record captured here: the
// only thing this path writes after the handshake.
func captureFirstPacket(t *testing.T, password string) (plaintext []byte, appRecordLens []int) {
	t.Helper()
	serverTLS, serverName := testServerTLSConfig(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	client := newTestClient(t, password, listener, serverName)
	defer client.Close()

	return captureFirstPacketConn(t, client, listener, serverTLS)
}

// newTestClient builds an anytls client pointed at listener's loopback address.
func newTestClient(t *testing.T, password string, listener net.Listener, serverName string) *Client {
	t.Helper()
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := parsePort(portText)
	if err != nil {
		t.Fatalf("port: %v", err)
	}

	client, err := NewClient(context.Background(), ClientConfig{
		Password:                 password,
		Server:                   M.ParseSocksaddrHostPort(host, port),
		Dialer:                   directDialer{},
		TLSConfig:                clientTLSConfig(serverName),
		IdleSessionCheckInterval: 30 * time.Second,
		IdleSessionTimeout:       30 * time.Second,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return client
}

// captureFirstPacketConn opens one connection through client, accepts it on
// listener and returns the plaintext the server received plus the payload
// length of every application_data record on the wire.
func captureFirstPacketConn(t *testing.T, client *Client, listener net.Listener, serverTLS *tls.Config) (plaintext []byte, appRecordLens []int) {
	t.Helper()
	connReady := make(chan net.Conn, 1)
	dialErr := make(chan error, 1)
	go func() {
		conn, err := client.createOutboundTLSConnection(context.Background())
		if err != nil {
			dialErr <- err
			return
		}
		connReady <- conn
	}()

	raw, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer raw.Close()
	recorder := &recordingConn{Conn: raw}
	server := tls.Server(recorder, serverTLS)
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	if err := server.Handshake(); err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	// Grace window: read whatever plaintext arrives, then require a timeout so
	// "no more bytes" is distinguishable from "peer hung up".
	_ = server.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	buf := make([]byte, 512)
	for {
		n, readErr := server.Read(buf)
		if n > 0 {
			plaintext = append(plaintext, buf[:n]...)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			var netErr net.Error
			if errors.As(readErr, &netErr) && netErr.Timeout() {
				break
			}
			t.Fatalf("unexpected read error after first packet: %v", readErr)
		}
	}

	select {
	case conn := <-connReady:
		_ = conn.Close()
	case err := <-dialErr:
		t.Fatalf("create outbound connection: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("outbound connection was never established")
	}

	return plaintext, applicationDataRecordLens(t, recorder.bytes())
}

// applicationDataRecordLens parses the recorded TLS stream and returns the
// payload length (the length field a capture prints as "23(N)") of every
// application_data record in order.
func applicationDataRecordLens(t *testing.T, wire []byte) []int {
	t.Helper()
	var lens []int
	for i := 0; i+5 <= len(wire); {
		typ := wire[i]
		length := int(binary.BigEndian.Uint16(wire[i+3 : i+5]))
		if length > 18432 || i+5+length > len(wire) {
			break
		}
		if typ == 0x17 {
			lens = append(lens, length)
		}
		i += 5 + length
	}
	if len(lens) == 0 {
		t.Fatalf("no complete application_data record in %d recorded bytes: %x", len(wire), wire)
	}
	return lens
}

// recordingConn tees every byte read from the wire so the test can parse the
// TLS records that a tls.Conn consumed.
type recordingConn struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.buf = append(c.buf, p[:n]...)
		c.mu.Unlock()
	}
	return n, err
}

func (c *recordingConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...)
}

type directDialer struct{}

func (directDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", destination.String())
}

func (directDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("test: ListenPacket not supported")
}

var _ N.Dialer = directDialer{}

func parsePort(text string) (uint16, error) {
	var value int
	for _, r := range text {
		if r < '0' || r > '9' {
			return 0, errors.New("invalid port: " + text)
		}
		value = value*10 + int(r-'0')
	}
	return uint16(value), nil
}

func clientTLSConfig(serverName string) *vmess.TLSConfig {
	return &vmess.TLSConfig{Host: serverName, SkipCertVerify: true}
}

// testServerTLSConfig builds a throwaway self-signed certificate so the test
// can observe the bytes that follow a real TLS handshake.
func testServerTLSConfig(t *testing.T) (*tls.Config, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const serverName = "localhost"
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: serverName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{serverName},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, serverName
}
