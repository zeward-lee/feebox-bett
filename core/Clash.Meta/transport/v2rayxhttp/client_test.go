package v2rayxhttp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
)

// testDialer dials the loopback test server directly; the transport under test
// never sees a proxy dialer here.
type testDialer struct{}

func (testDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", destination.String())
}

func (testDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("test: ListenPacket not supported")
}

// echoBroker implements the server half of stream-up: a GET holds the download
// stream open, a POST carries the upload bytes, and uploaded bytes are echoed
// back on the download stream of the same session.
type echoBroker struct {
	mu       sync.Mutex
	sessions map[string]*echoSession

	muRecord     sync.Mutex
	requests     []*http.Request
	contentTypes []string
}

type echoSession struct {
	chunks chan []byte
	once   sync.Once
}

func newEchoBroker() *echoBroker {
	return &echoBroker{sessions: make(map[string]*echoSession)}
}

func (b *echoBroker) session(id string) *echoSession {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.sessions[id]
	if !ok {
		s = &echoSession{chunks: make(chan []byte, 256)}
		b.sessions[id] = s
	}
	return s
}

func (b *echoBroker) record(r *http.Request) {
	b.muRecord.Lock()
	defer b.muRecord.Unlock()
	clone := r.Clone(context.Background())
	clone.Body = nil
	b.requests = append(b.requests, clone)
	b.contentTypes = append(b.contentTypes, r.Header.Get("Content-Type"))
}

func (b *echoBroker) recorded() ([]*http.Request, []string) {
	b.muRecord.Lock()
	defer b.muRecord.Unlock()
	return append([]*http.Request(nil), b.requests...), append([]string(nil), b.contentTypes...)
}

func (b *echoBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session := strings.TrimPrefix(r.URL.Path, "/rpcv2/")
	if session == "" || strings.Contains(session, "/") {
		http.NotFound(w, r)
		return
	}
	b.record(r)
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		if flusher != nil {
			flusher.Flush()
		}
		s := b.session(session)
		for {
			select {
			case chunk, ok := <-s.chunks:
				if !ok {
					return
				}
				if _, err := w.Write(chunk); err != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
			case <-r.Context().Done():
				return
			}
		}
	}
	// Upload stream: read everything and mirror it to the download half.
	buf := make([]byte, 4096)
	s := b.session(session)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			select {
			case s.chunks <- chunk:
			case <-r.Context().Done():
				return
			}
		}
		if err != nil {
			break
		}
	}
	w.WriteHeader(http.StatusOK)
}

func newEchoServer(t *testing.T, broker *echoBroker) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/rpcv2/", broker)
	server := httptest.NewUnstartedServer(mux)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func serverSocksaddr(t *testing.T, server *httptest.Server) M.Socksaddr {
	t.Helper()
	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	value, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return M.ParseSocksaddrHostPort(host, uint16(value))
}

func roundTrip(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte(payload))
		writeErr <- err
	}()
	readResult := make(chan []byte, 1)
	go func() {
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			readResult <- nil
			return
		}
		readResult <- buf
	}()
	select {
	case err := <-writeErr:
		if err != nil {
			t.Fatalf("write: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("write timed out")
	}
	select {
	case got := <-readResult:
		if string(got) != payload {
			t.Fatalf("read %q, want %q", got, payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("read timed out")
	}
}

func assertRequestMeta(t *testing.T, broker *echoBroker) {
	t.Helper()
	requests, contentTypes := broker.recorded()
	if len(requests) != 2 {
		t.Fatalf("server saw %d requests, want 2 (download GET + upload POST)", len(requests))
	}
	var sawGet, sawPost bool
	for i, request := range requests {
		session := strings.TrimPrefix(request.URL.Path, "/rpcv2/")
		if session == "" {
			t.Errorf("request %d path %q carries no session id", i, request.URL.Path)
		}
		referer, err := url.Parse(request.Header.Get("Referer"))
		if err != nil {
			t.Fatalf("referer %q: %v", request.Header.Get("Referer"), err)
		}
		padding := referer.Query().Get("x_padding")
		if len(padding) < 100 || len(padding) > 1000 {
			t.Errorf("request %d padding length %d out of range", i, len(padding))
		}
		switch request.Method {
		case http.MethodGet:
			sawGet = true
		case http.MethodPost:
			sawPost = true
			if contentTypes[i] != "application/grpc" {
				t.Errorf("upload content type = %q, want application/grpc", contentTypes[i])
			}
		default:
			t.Errorf("unexpected method %s", request.Method)
		}
	}
	if !sawGet || !sawPost {
		t.Errorf("missing streams: get=%v post=%v", sawGet, sawPost)
	}
}

func TestStreamUpRoundTrip(t *testing.T) {
	broker := newEchoBroker()
	server := newEchoServer(t, broker)
	config := &Config{
		Server: serverSocksaddr(t, server),
		TLS:    &vmess.TLSConfig{Host: "localhost", SkipCertVerify: true},
		Path:   "/rpcv2",
		Mode:   ModeStreamUp,
		Xmux:   &XmuxOptions{MaxConcurrency: Range{From: 2, To: 2}},
		Download: &DownloadOptions{
			Server: serverSocksaddr(t, server),
			TLS:    &vmess.TLSConfig{Host: "localhost", SkipCertVerify: true},
		},
	}
	client, err := NewClient(context.Background(), testDialer{}, config)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(dialCtx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	roundTrip(t, conn, "ping from anytls")
	assertRequestMeta(t, broker)
}

func TestStreamUpDownloadSplit(t *testing.T) {
	broker := newEchoBroker()
	uploadServer := newEchoServer(t, broker)
	downloadServer := newEchoServer(t, broker)
	config := &Config{
		Server: serverSocksaddr(t, uploadServer),
		TLS:    &vmess.TLSConfig{Host: "localhost", SkipCertVerify: true},
		Path:   "/rpcv2",
		Mode:   ModeStreamUp,
		Download: &DownloadOptions{
			Server: serverSocksaddr(t, downloadServer),
			TLS:    &vmess.TLSConfig{Host: "localhost", SkipCertVerify: true},
		},
	}
	client, err := NewClient(context.Background(), testDialer{}, config)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(dialCtx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	roundTrip(t, conn, "downstream split")
}

// streamOneHandler answers a single POST by echoing the request body, which is
// what mode stream-one expects (one bidirectional stream per conn).
func streamOneHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

func newStreamOneServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/rpcv2/", streamOneHandler)
	server := httptest.NewUnstartedServer(mux)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestStreamOneRoundTrip(t *testing.T) {
	server := newStreamOneServer(t)
	config := &Config{
		Server: serverSocksaddr(t, server),
		TLS:    &vmess.TLSConfig{Host: "localhost", SkipCertVerify: true},
		Path:   "/rpcv2",
		Mode:   ModeStreamOne,
	}
	client, err := NewClient(context.Background(), testDialer{}, config)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	conn, err := client.DialContext(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	roundTrip(t, conn, "single stream")
}

// TestTransportWrapsObfs pins the stack order: the obfs preamble precedes the
// TLS record, so the very first bytes a server sees are the 20-byte obfs
// preamble and not 0x16 0x03 (TLS handshake).
func TestTransportWrapsObfs(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	value, _ := strconv.Atoi(port)
	config := &Config{
		Server:  M.ParseSocksaddrHostPort(host, uint16(value)),
		TLS:     &vmess.TLSConfig{Host: "localhost", SkipCertVerify: true},
		Path:    "/rpcv2",
		Mode:    ModeStreamUp,
		ObfsKey: "9uByRBBiCy",
		Download: &DownloadOptions{
			Server: M.ParseSocksaddrHostPort(host, uint16(value)),
			TLS:    &vmess.TLSConfig{Host: "localhost", SkipCertVerify: true},
		},
	}
	client, err := NewClient(context.Background(), testDialer{}, config)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	dialErr := make(chan error, 1)
	go func() {
		conn, err := client.DialContext(context.Background())
		if err == nil {
			_ = conn.Close()
		}
		dialErr <- err
	}()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer accepted.Close()
	_ = accepted.SetReadDeadline(time.Now().Add(5 * time.Second))
	head := make([]byte, 3)
	if _, err := io.ReadFull(accepted, head); err != nil {
		t.Fatalf("read head: %v", err)
	}
	if head[0] == 0x16 && head[1] == 0x03 {
		t.Fatalf("first bytes look like a bare TLS record: %x (obfs layer missing)", head)
	}
	<-dialErr
}
