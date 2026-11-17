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
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

const directAuthFixture = "720a437f4beb4fb9915f7f913d7bc9f7"

// TestFirstPacketDirectAuthIsBareHash pins the wire prefix of the vendor direct
// authentication form: exactly the 32-byte SHA-256 of the 32 hex character
// password, with no 2-byte padding length and no padding behind it. The live
// servers close the connection within ~0.1s when those extra bytes are present.
func TestFirstPacketDirectAuthIsBareHash(t *testing.T) {
	prefix, extra := captureFirstPacket(t, directAuthFixture)
	want := sha256.Sum256([]byte(directAuthFixture))
	if !bytes.Equal(prefix, want[:]) {
		t.Fatalf("first packet = %x, want %x", prefix, want)
	}
	if len(extra) != 0 {
		t.Fatalf("direct auth sent %d extra bytes after the bare hash: %x", len(extra), extra)
	}
}

// TestFirstPacketMarkerKeepsUpstreamPrefix pins the "#sl" variant: the 64 hex
// key is decoded and keeps the upstream `[2B padding length][padding]` suffix,
// so the existing vendor marker path is unchanged.
func TestFirstPacketMarkerKeepsUpstreamPrefix(t *testing.T) {
	password := shanlianFixture + "#sl"
	prefix, extra := captureFirstPacket(t, password)
	want, _ := hex.DecodeString(shanlianFixture)
	if !bytes.Equal(prefix, want) {
		t.Fatalf("first packet = %x, want %x", prefix, want)
	}
	if len(extra) < 2 {
		t.Fatalf("marker variant sent %d bytes total, want 32-byte hash + padding prefix", len(prefix)+len(extra))
	}
	wantLen := defaultFirstPacketPadding + 2
	if len(extra) != wantLen {
		t.Fatalf("marker variant suffix = %d bytes, want %d (2-byte length + padding)", len(extra), wantLen)
	}
	if got := binary.BigEndian.Uint16(extra[:2]); int(got) != defaultFirstPacketPadding {
		t.Fatalf("padding length = %d, want %d", got, defaultFirstPacketPadding)
	}
	for i, b := range extra[2:] {
		if b != 0 {
			t.Fatalf("padding byte %d = %#x, want 0", i, b)
		}
	}
}

// TestFirstPacketOrdinaryPasswordKeepsUpstreamPrefix pins that a standard
// anytls password (not the 32 hex vendor form) keeps the upstream prefix byte
// for byte, so upstream anytls nodes are unaffected.
func TestFirstPacketOrdinaryPasswordKeepsUpstreamPrefix(t *testing.T) {
	const password = "ordinary-password"
	prefix, extra := captureFirstPacket(t, password)
	want := sha256.Sum256([]byte(password))
	if !bytes.Equal(prefix, want[:]) {
		t.Fatalf("first packet = %x, want %x", prefix, want)
	}
	if len(extra) != defaultFirstPacketPadding+2 {
		t.Fatalf("suffix = %d bytes, want %d", len(extra), defaultFirstPacketPadding+2)
	}
	if got := binary.BigEndian.Uint16(extra[:2]); int(got) != defaultFirstPacketPadding {
		t.Fatalf("padding length = %d, want %d", got, defaultFirstPacketPadding)
	}
}

// TestDirectAuthPasswordShape pins the discriminator: only a bare 32 hex
// character key takes the direct authentication path.
func TestDirectAuthPasswordShape(t *testing.T) {
	cases := map[string]bool{
		directAuthFixture:                   true,
		"ABCDEF0123456789ABCDEF0123456789":  true,
		shanlianFixture + "#sl":             false,
		shanlianFixture + "#SL":             false,
		"short-password":                    false,
		"not-hex-at-all-but-32-chars-long!": false,
		directAuthFixture + "0":             false,
	}
	for password, want := range cases {
		if got := isDirectAuthPassword(password); got != want {
			t.Errorf("isDirectAuthPassword(%q) = %v, want %v", password, got, want)
		}
	}
}

// defaultFirstPacketPadding is the padding length of the vendor default scheme
// entry `0=30-30`.
const defaultFirstPacketPadding = 30

// captureFirstPacket runs one real TLS handshake against a loopback server and
// returns the first 32 bytes the server received plus whatever followed within
// a short grace period.
func captureFirstPacket(t *testing.T, password string) (prefix, extra []byte) {
	t.Helper()
	serverTLS, serverName := testServerTLSConfig(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
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
	defer client.Close()

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

	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer accepted.Close()
	_ = accepted.SetReadDeadline(time.Now().Add(5 * time.Second))
	prefix = make([]byte, sha256.Size)
	if _, err := readFull(accepted, prefix); err != nil {
		t.Fatalf("read first packet: %v", err)
	}
	// Grace window: nothing else may follow the prefix on the wire. The client
	// conn stays open until it is closed below, so a timeout means "no more
	// bytes", not "peer hung up".
	_ = accepted.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	buf := make([]byte, 512)
	n, err := accepted.Read(buf)
	if err == nil {
		extra = append(extra, buf[:n]...)
		// Drain whatever else is already buffered so the assertion is stable.
		for len(extra) < 512 {
			n, err = accepted.Read(buf)
			if err != nil {
				break
			}
			extra = append(extra, buf[:n]...)
		}
	} else {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("unexpected read error after first packet: %v", err)
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
	return prefix, extra
}

func readFull(r net.Conn, b []byte) (int, error) {
	done := 0
	for done < len(b) {
		n, err := r.Read(b[done:])
		done += n
		if err != nil {
			return done, err
		}
	}
	return done, nil
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
