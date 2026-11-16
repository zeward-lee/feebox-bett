package xhttpstream

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

const (
	testSecret = "Zx9-test-secret"
	testHmac   = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	testFake   = "16030100c5010000c10303"
)

func testCipher(t *testing.T) *StreamCipher {
	t.Helper()
	ciph, err := PickCipher("aes-128-ctr", nil, testSecret+":"+testHmac, map[string]string{"tcp": testFake, "udp": testFake})
	if err != nil {
		t.Fatalf("PickCipher: %v", err)
	}
	return ciph
}

// fakeServer speaks the client handshake described on Conn and echoes the
// payload back, so the test covers both directions of the format.
func fakeServer(t *testing.T, listener net.Listener, ciph *StreamCipher) {
	t.Helper()
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	key := Kdf(testSecret, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Errorf("server cipher: %v", err)
		return
	}
	prefix := make([]byte, FakePrefixLen)
	if _, err := io.ReadFull(conn, prefix); err != nil {
		t.Errorf("server read prefix: %v", err)
		return
	}
	fake, _ := hex.DecodeString(testFake)
	if !bytes.HasPrefix(prefix, fake) {
		t.Errorf("server prefix does not start with fake-net bytes: %x", prefix[:len(fake)])
	}
	hmacLen := len(ciph.hmac)
	token := make([]byte, 16)
	if _, err := io.ReadFull(conn, token); err != nil {
		t.Errorf("server read token: %v", err)
		return
	}
	if !bytes.Equal(token, ciph.token) {
		t.Errorf("server token mismatch")
		return
	}
	hmac := make([]byte, hmacLen)
	if _, err := io.ReadFull(conn, hmac); err != nil {
		t.Errorf("server read hmac: %v", err)
		return
	}
	if !bytes.Equal(hmac, ciph.hmac) {
		t.Errorf("server hmac mismatch")
		return
	}
	ivLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, ivLen); err != nil {
		t.Errorf("server read iv len: %v", err)
		return
	}
	if int(ivLen[0]) != 16 {
		t.Errorf("server iv len = %d, want 16", ivLen[0])
		return
	}
	writeIV := make([]byte, 16)
	if _, err := io.ReadFull(conn, writeIV); err != nil {
		t.Errorf("server read iv: %v", err)
		return
	}
	dec := NewReader(conn, cipher.NewCTR(block, writeIV))

	// Reply handshake: forged prefix, echoed token, empty preamble, IV length
	// and the read IV.
	serverPrefix := make([]byte, FakePrefixLen)
	if _, err := rand.Read(serverPrefix); err != nil {
		t.Errorf("server prefix: %v", err)
		return
	}
	serverIV := make([]byte, 16)
	if _, err := rand.Read(serverIV); err != nil {
		t.Errorf("server iv: %v", err)
		return
	}
	header := append(serverPrefix, ciph.token...)
	header = append(header, 0x00, byte(len(serverIV)))
	header = append(header, serverIV...)
	if _, err := conn.Write(header); err != nil {
		t.Errorf("server write header: %v", err)
		return
	}
	enc := NewWriter(conn, cipher.NewCTR(block, serverIV))

	// The first encrypted bytes are the SOCKS destination.
	dest := make([]byte, 1+1+len("example.com")+2)
	dest[0] = 0x03
	dest[1] = byte(len("example.com"))
	copy(dest[2:], "example.com")
	dest[len(dest)-2] = 0x01
	dest[len(dest)-1] = 0xbb
	gotDest := make([]byte, len(dest))
	if _, err := io.ReadFull(dec, gotDest); err != nil {
		t.Errorf("server read destination: %v", err)
		return
	}
	if !bytes.Equal(gotDest, dest) {
		t.Errorf("server destination = %x, want %x", gotDest, dest)
		return
	}
	payload := make([]byte, 5)
	if _, err := io.ReadFull(dec, payload); err != nil {
		t.Errorf("server read payload: %v", err)
		return
	}
	if string(payload) != "hello" {
		t.Errorf("server payload = %q", payload)
	}
	if _, err := enc.Write([]byte("world")); err != nil {
		t.Errorf("server write: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
}

func TestStreamHandshakeRoundTrip(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	defer listener.Close()
	ciph := testCipher(t)
	go fakeServer(t, listener, ciph)

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	destination := []byte{0x03, 0x0b}
	destination = append(destination, []byte("example.com")...)
	destination = append(destination, 0x01, 0xbb)
	stream := ciph.StreamConn(conn, destination)
	defer stream.Close()
	if handshaker, ok := stream.(interface{ NeedHandshake() bool }); !ok || !handshaker.NeedHandshake() {
		t.Fatal("fresh Conn should report NeedHandshake")
	}
	if _, err := stream.Write(nil); err != nil {
		t.Fatalf("force handshake: %v", err)
	}
	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 5)
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != "world" {
		t.Fatalf("echo = %q, want world", got)
	}
}

func TestReadRejectsForeignToken(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		prefix := make([]byte, FakePrefixLen)
		_, _ = rand.Read(prefix)
		wrongToken := bytes.Repeat([]byte{0xaa}, 16)
		_, _ = conn.Write(append(prefix, wrongToken...))
		// Drain the client handshake before closing. Closing a socket that
		// still holds unread inbound data makes Windows send an RST, which can
		// purge the wrong token we just wrote and surface as "connection
		// aborted" instead of ErrInvalidToken.
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.Copy(io.Discard, conn)
	}()

	ciph := testCipher(t)
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	stream := ciph.StreamConn(conn, nil)
	if _, err := stream.Write(nil); err != nil {
		t.Fatalf("force handshake: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := stream.Read(make([]byte, 1)); err != ErrInvalidToken {
		t.Fatalf("Read error = %v, want ErrInvalidToken", err)
	}
}

func TestPickCipherRejectsBadPassword(t *testing.T) {
	if _, err := PickCipher("aes-128-ctr", nil, "no-colon", nil); err == nil {
		t.Fatal("password without a hmac part should fail")
	}
	if _, err := PickCipher("aes-128-ctr", nil, "secret:zz", nil); err == nil {
		t.Fatal("non-hex hmac key should fail")
	}
	if _, err := PickCipher("chacha20", nil, testSecret+":"+testHmac, nil); err == nil {
		t.Fatal("unsupported cipher should fail")
	}
}

func TestTokenMatchesVendorFormula(t *testing.T) {
	// md5("<secret>" + "do not hack this protocol please")
	sum := md5.Sum([]byte("secret" + "do not hack this protocol please"))
	if !bytes.Equal(Token("secret"), sum[:]) {
		t.Fatalf("Token(secret) = %x, want %x", Token("secret"), sum)
	}
	if bytes.Equal(Token("secret"), Token("secret2")) {
		t.Fatal("different secrets produced the same token")
	}
}

// recordConn captures every Write so a test can prove the handshake is one
// write, and fails on demand to exercise the error path.
type recordConn struct {
	mu     sync.Mutex
	writes [][]byte
	err    error
}

func (c *recordConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *recordConn) Write(b []byte) (int, error)      { return c.record(b) }
func (c *recordConn) Close() error                     { return nil }
func (c *recordConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *recordConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *recordConn) SetDeadline(time.Time) error      { return nil }
func (c *recordConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordConn) SetWriteDeadline(time.Time) error { return nil }

func (c *recordConn) record(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return 0, c.err
	}
	copied := make([]byte, len(b))
	copy(copied, b)
	c.writes = append(c.writes, copied)
	return len(b), nil
}

// TestInitWriterSendsHeaderAndDestinationInOneWrite covers the P1 "半写死锁":
// the 128 byte prefix, token, HMAC, IV and the encrypted destination must leave
// as a single write, and the destination must continue the same CTR keystream
// the payload uses.
func TestInitWriterSendsHeaderAndDestinationInOneWrite(t *testing.T) {
	ciph := testCipher(t)
	conn := &recordConn{}
	destination := []byte{0x03, 0x0b}
	destination = append(destination, []byte("example.com")...)
	destination = append(destination, 0x01, 0xbb)
	stream := ciph.StreamConn(conn, destination).(*Conn)
	if _, err := stream.Write(nil); err != nil {
		t.Fatalf("force handshake: %v", err)
	}
	if len(conn.writes) != 1 {
		t.Fatalf("handshake used %d writes, want 1", len(conn.writes))
	}
	frame := conn.writes[0]
	headerLen := FakePrefixLen + len(ciph.token) + len(ciph.hmac) + 1 + 16
	if len(frame) != headerLen+len(destination) {
		t.Fatalf("frame length = %d, want %d", len(frame), headerLen+len(destination))
	}
	iv := frame[headerLen-16 : headerLen]
	if int(frame[headerLen-17]) != 16 {
		t.Fatalf("iv length byte = %d, want 16", frame[headerLen-17])
	}
	plain := make([]byte, len(destination))
	cipher.NewCTR(mustBlock(t), iv).XORKeyStream(plain, frame[headerLen:])
	if !bytes.Equal(plain, destination) {
		t.Fatalf("destination = %x, want %x", plain, destination)
	}
	// The payload continues the same keystream, so a payload written next must
	// decrypt to itself: force a known payload through the writer.
	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if len(conn.writes) != 2 {
		t.Fatalf("payload write count = %d, want 2 total", len(conn.writes))
	}
	payloadPlain := make([]byte, 5)
	// Continue the CTR stream: the destination consumed len(destination) bytes.
	stream2 := cipher.NewCTR(mustBlock(t), iv)
	stream2.XORKeyStream(make([]byte, len(destination)), make([]byte, len(destination)))
	stream2.XORKeyStream(payloadPlain, conn.writes[1])
	if string(payloadPlain) != "hello" {
		t.Fatalf("payload = %q, want hello", payloadPlain)
	}
}

func mustBlock(t *testing.T) cipher.Block {
	t.Helper()
	block, err := aes.NewCipher(Kdf(testSecret, 16))
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	return block
}

// TestInitWriterFailureIsSticky covers the second half of the same fix: a failed
// handshake write returns a clear error and is never retried, so a partial
// header can not be followed by a second (misaligned) one.
func TestInitWriterFailureIsSticky(t *testing.T) {
	ciph := testCipher(t)
	boom := errors.New("write refused")
	conn := &recordConn{err: boom}
	stream := ciph.StreamConn(conn, []byte{0x01, 0x01, 0x02, 0x03, 0x00, 0x35})
	if _, err := stream.Write(nil); !errors.Is(err, boom) {
		t.Fatalf("first write error = %v, want %v", err, boom)
	}
	conn.mu.Lock()
	conn.err = nil // a retry would now succeed if it were attempted
	conn.mu.Unlock()
	if _, err := stream.Write([]byte("hello")); err == nil {
		t.Fatal("a failed handshake was retried silently")
	}
	if len(conn.writes) != 0 {
		t.Fatalf("conn saw %d writes after a failed handshake, want 0", len(conn.writes))
	}
}

// TestHandshakeReadIsBounded covers the token check running under a deadline: a
// server that accepts the connection and stays silent must not hang the first
// read forever.
func TestHandshakeReadIsBounded(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		close(accepted)
		// Read the client handshake but never answer it.
		_, _ = io.Copy(io.Discard, conn)
		_ = conn.Close()
	}()

	ciph := testCipher(t)
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	stream := ciph.StreamConn(conn, nil).(*Conn)
	stream.SetHandshakeDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err := stream.Write(nil); err != nil {
		t.Fatalf("force handshake: %v", err)
	}
	<-accepted
	start := time.Now()
	_, err = stream.Read(make([]byte, 1))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Read against a silent server returned no error")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("handshake read took %v, the deadline was not applied", elapsed)
	}
}

// TestPacketConnRemoteAddrIsTheServer covers the plain UDP target semantics: the
// carrier is the configured server, never a metadata address.
func TestPacketConnRemoteAddrIsTheServer(t *testing.T) {
	ciph := testCipher(t)
	server := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 50775}
	pc := ciph.PacketConn(&recordConn{}, server).(*PacketConn)
	if pc.RemoteAddr() == nil || pc.RemoteAddr().String() != server.String() {
		t.Fatalf("RemoteAddr = %v, want %v", pc.RemoteAddr(), server)
	}
}

// TestPacketConnWriteToEncodesTarget walks one plain UDP frame back to its
// address and payload, including a SOCKS domain target (the case the udp relay
// hands over when the destination was never resolved).
func TestPacketConnWriteToEncodesTarget(t *testing.T) {
	ciph := testCipher(t)
	conn := &recordConn{}
	server := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 50775}
	pc := ciph.PacketConn(conn, server)
	target := &domainAddr{host: "dns.example", port: 53}
	n, err := pc.WriteTo([]byte("query"), target)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != 5 {
		t.Fatalf("WriteTo n = %d, want 5", n)
	}
	if len(conn.writes) != 1 {
		t.Fatalf("WriteTo used %d writes, want 1", len(conn.writes))
	}
	frame := conn.writes[0]
	offset := FakePrefixLen + len(ciph.token) + len(ciph.hmac)
	if offset+1 > len(frame) {
		t.Fatalf("short frame %d", len(frame))
	}
	ivLen := int(frame[offset])
	offset++
	if ivLen != 16 || offset+ivLen > len(frame) {
		t.Fatalf("iv length = %d", ivLen)
	}
	iv := frame[offset : offset+ivLen]
	offset += ivLen
	plain := make([]byte, len(frame)-offset)
	ciph.Decrypter(iv).XORKeyStream(plain, frame[offset:])
	addr, payload, err := decodeSocksAddr(plain)
	if err != nil {
		t.Fatalf("decodeSocksAddr: %v", err)
	}
	if addr.String() != target.String() {
		t.Fatalf("address = %s, want %s", addr, target)
	}
	if string(payload) != "query" {
		t.Fatalf("payload = %q", payload)
	}
}

func TestParsePaddingLenTrimsWhitespace(t *testing.T) {
	cases := map[string][2]int{
		" 8-64 ": {8, 64},
		" 16 ":   {0, 16},
		"8 - 64": {8, 64},
		"":       {0, 0},
	}
	for value, want := range cases {
		minLen, maxLen, err := ParsePaddingLen(value)
		if err != nil {
			t.Fatalf("ParsePaddingLen(%q): %v", value, err)
		}
		if minLen != want[0] || maxLen != want[1] {
			t.Fatalf("ParsePaddingLen(%q) = %d-%d, want %d-%d", value, minLen, maxLen, want[0], want[1])
		}
	}
	if _, _, err := ParsePaddingLen(" 64-8 "); err == nil {
		t.Fatal("inverted range accepted")
	}
}
