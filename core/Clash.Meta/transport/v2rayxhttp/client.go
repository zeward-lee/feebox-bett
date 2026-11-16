package v2rayxhttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/transport/vmess"

	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"golang.org/x/net/http2"
)

// Client is the client half of the vendor `transport/v2rayxhttp` (XHTTP)
// transport: a session id in the path, an upload stream (POST with an endless
// body) and, when `download` is configured, a separate downstream stream served
// by a different server/TLS identity.
type Client struct {
	config *Config
	upload *endpoint

	download *endpoint
}

// NewClient builds a transport client. dialer is the underlying TCP dialer
// (mihomo's proxy dialer); it is only ever asked for TCP connections.
func NewClient(ctx context.Context, dialer N.Dialer, config *Config) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	upload, err := newEndpoint(dialer, endpointOptions{
		dest:     config.Server,
		tls:      config.TLS,
		path:     config.Path,
		host:     config.Host,
		headers:  config.Headers,
		obfsKey:  config.ObfsKey,
		padding:  config.XPadding,
		xmux:     config.Xmux,
		method:   config.UplinkHTTPMethod,
		mode:     config.Mode,
		useHTTPS: true,
	})
	if err != nil {
		return nil, err
	}
	client := &Client{config: config, upload: upload}
	if config.Download != nil {
		d := config.Download
		client.download, err = newEndpoint(dialer, endpointOptions{
			dest:     d.Server,
			tls:      d.TLS,
			path:     d.Path,
			host:     d.Host,
			headers:  d.Headers,
			obfsKey:  d.ObfsKey,
			padding:  d.XPadding,
			xmux:     d.Xmux,
			method:   config.UplinkHTTPMethod,
			mode:     config.Mode,
			useHTTPS: true,
		})
		if err != nil {
			return nil, err
		}
	}
	return client, nil
}

// DialContext opens one proxied stream pair and returns it as a net.Conn. The
// anytls client dials through this conn exactly like it dials a TCP socket, so
// its TLS handshake and session multiplexing ride inside the XHTTP streams.
func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	session := sessionID()
	switch c.config.Mode {
	case ModeStreamOne:
		return c.dialStreamOne(ctx, session)
	case ModeStreamUp:
		return c.dialStreamUp(ctx, session)
	default:
		return nil, fmt.Errorf("v2rayxhttp: unsupported mode %q", c.config.Mode)
	}
}

func (c *Client) dialStreamUp(ctx context.Context, session string) (net.Conn, error) {
	// The downstream half is opened first so the server knows the session before
	// the upload body starts flowing (same order as the vendor client).
	reader, downloadEntry, err := c.download.openDownload(ctx, session)
	if err != nil {
		return nil, err
	}
	writer, uploadEntry, err := c.upload.openUpload(ctx, session)
	if err != nil {
		_ = reader.Close()
		if downloadEntry != nil {
			downloadEntry.release()
		}
		return nil, err
	}
	conn := &streamConn{
		reader:     reader,
		writer:     writer,
		remoteAddr: socksaddr(c.upload.dest),
		localAddr:  nil,
	}
	conn.onClose = func() {
		if downloadEntry != nil {
			downloadEntry.release()
		}
		if uploadEntry != nil {
			uploadEntry.release()
		}
	}
	return conn, nil
}

func (c *Client) dialStreamOne(ctx context.Context, session string) (net.Conn, error) {
	reader, writer, entry, err := c.upload.openSingleStream(ctx, session)
	if err != nil {
		return nil, err
	}
	conn := &streamConn{
		reader:     reader,
		writer:     writer,
		remoteAddr: socksaddr(c.upload.dest),
		localAddr:  nil,
	}
	if entry != nil {
		conn.onClose = entry.release
	}
	return conn, nil
}

// Config returns the normalized transport configuration.
func (c *Client) Config() *Config {
	return c.config
}

// Close releases every pooled HTTP connection.
func (c *Client) Close() error {
	c.upload.close()
	if c.download != nil {
		c.download.close()
	}
	return nil
}

// Dialer adapts Client to sing's N.Dialer so it can replace the dialer of an
// anytls client: every DialContext returns a fresh proxied stream instead of a
// TCP socket.
type Dialer struct {
	client *Client
}

func NewDialer(client *Client) *Dialer {
	return &Dialer{client: client}
}

func (d *Dialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkTCP {
		return nil, E.New("v2rayxhttp: unsupported network: ", network)
	}
	return d.client.DialContext(ctx)
}

func (d *Dialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("v2rayxhttp: ListenPacket not supported")
}

// endpoint owns one server/TLS/obfs tuple and its connection pool.
type endpoint struct {
	dest     M.Socksaddr
	tls      *vmess.TLSConfig
	path     string
	host     string
	headers  http.Header
	obfsKey  string
	padding  Range
	method   string
	mode     string
	useHTTPS bool

	base *url.URL
	mux  *muxManager
}

type endpointOptions struct {
	dest     M.Socksaddr
	tls      *vmess.TLSConfig
	path     string
	host     string
	headers  map[string]string
	obfsKey  string
	padding  Range
	xmux     *XmuxOptions
	method   string
	mode     string
	useHTTPS bool
}

func newEndpoint(dialer N.Dialer, options endpointOptions) (*endpoint, error) {
	e := &endpoint{
		dest:     options.dest,
		tls:      options.tls,
		path:     options.path,
		host:     options.host,
		headers:  defaultHeaders(),
		obfsKey:  options.obfsKey,
		padding:  options.padding,
		method:   options.method,
		mode:     options.mode,
		useHTTPS: options.useHTTPS,
	}
	for k, v := range options.headers {
		e.headers.Set(k, v)
	}
	scheme := "http"
	if options.useHTTPS {
		scheme = "https"
	}
	e.base = requestURL(scheme, e.host, e.path)
	e.mux = newMuxManager(options.xmux, func() (*http.Client, error) {
		return e.newHTTPClient(dialer)
	})
	return e, nil
}

// newHTTPClient builds an HTTP/2 client whose single connection is dialed
// through the proxy dialer, optionally obfuscated, then TLS-wrapped.
func (e *endpoint) newHTTPClient(dialer N.Dialer) (*http.Client, error) {
	transport := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, N.NetworkTCP, e.dest)
			if err != nil {
				return nil, err
			}
			conn = newObfsConn(conn, e.obfsKey)
			tlsConn, err := vmess.StreamTLSConn(ctx, conn, e.tls)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
		IdleConnTimeout: idleConnTimeout,
		ReadIdleTimeout: keepAlivePeriod,
	}
	return &http.Client{Transport: transport}, nil
}

func (e *endpoint) close() {
	e.mux.close()
}

// requestURL returns the stream URL for one session: the XHTTP session id
// travels in the path (the vendor leaves `session_placement` at its default).
func (e *endpoint) requestURL(session string) *url.URL {
	u := *e.base
	u.Path = e.path + session
	return &u
}

// requestHeaders applies the browser-like defaults, the user headers and the
// default `queryInHeader` X-Padding carrier (a Referer with x_padding). The
// vendor builds the padding from the base URL, before the session id is
// appended, so the Referer carries the bare path.
func (e *endpoint) requestHeaders(req *http.Request, session string) {
	for k, v := range e.headers {
		req.Header[k] = v
	}
	req.Header.Set("Referer", paddingValue(e.base, e.padding))
}

func (e *endpoint) openDownload(ctx context.Context, session string) (*waitReadCloser, *muxEntry, error) {
	client, entry, err := e.mux.acquire()
	if err != nil {
		return nil, nil, err
	}
	requestCtx, cancel := context.WithCancel(contextutils.WithoutCancel(ctx))
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, e.requestURL(session).String(), nil)
	if err != nil {
		cancel()
		entry.release()
		return nil, nil, err
	}
	e.requestHeaders(req, session)
	reader := newWaitReadCloser(cancel)
	go func() {
		resp, err := client.Do(req)
		if err != nil {
			reader.fail(err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			reader.fail(fmt.Errorf("v2rayxhttp: download stream returned %s", resp.Status))
			return
		}
		reader.set(resp.Body)
	}()
	return reader, entry, nil
}

func (e *endpoint) openUpload(ctx context.Context, session string) (io.WriteCloser, *muxEntry, error) {
	client, entry, err := e.mux.acquire()
	if err != nil {
		return nil, nil, err
	}
	requestCtx, cancel := context.WithCancel(contextutils.WithoutCancel(ctx))
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(requestCtx, e.method, e.requestURL(session).String(), pr)
	if err != nil {
		cancel()
		entry.release()
		return nil, nil, err
	}
	e.requestHeaders(req, session)
	req.Header.Set("Content-Type", "application/grpc")
	req.ContentLength = -1
	go func() {
		resp, err := client.Do(req)
		if err != nil {
			_ = pw.CloseWithError(err)
			cancel()
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			_ = pw.CloseWithError(fmt.Errorf("v2rayxhttp: upload stream returned %s", resp.Status))
		}
		cancel()
	}()
	return pw, entry, nil
}

// openSingleStream implements mode stream-one: a single POST whose response
// body is the downstream half.
func (e *endpoint) openSingleStream(ctx context.Context, session string) (io.ReadCloser, io.WriteCloser, *muxEntry, error) {
	client, entry, err := e.mux.acquire()
	if err != nil {
		return nil, nil, nil, err
	}
	requestCtx, cancel := context.WithCancel(contextutils.WithoutCancel(ctx))
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(requestCtx, e.method, e.requestURL(session).String(), pr)
	if err != nil {
		cancel()
		entry.release()
		return nil, nil, nil, err
	}
	e.requestHeaders(req, session)
	req.Header.Set("Content-Type", "application/grpc")
	req.ContentLength = -1
	reader := newWaitReadCloser(cancel)
	go func() {
		resp, err := client.Do(req)
		if err != nil {
			reader.fail(err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			reader.fail(fmt.Errorf("v2rayxhttp: stream returned %s", resp.Status))
			return
		}
		reader.set(resp.Body)
	}()
	return reader, pw, entry, nil
}

func defaultHeaders() http.Header {
	header := http.Header{}
	header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	header.Set("Accept", "*/*")
	header.Set("Accept-Language", "en-US,en;q=0.9")
	header.Set("Cache-Control", "no-cache")
	header.Set("Pragma", "no-cache")
	header.Set("Sec-Fetch-Mode", "cors")
	header.Set("Sec-Fetch-Dest", "empty")
	header.Set("Sec-Fetch-Site", "same-origin")
	header.Set("Priority", "u=1, i")
	return header
}

// waitReadCloser waits for the response body of a stream request without
// blocking the dialer: the vendor client returns a conn as soon as the request
// is on the wire and lets the first Read wait for the response headers.
type waitReadCloser struct {
	once   sync.Once
	ready  chan struct{}
	mu     sync.Mutex
	body   io.ReadCloser
	err    error
	closed bool
	cancel context.CancelFunc
}

func newWaitReadCloser(cancel context.CancelFunc) *waitReadCloser {
	return &waitReadCloser{ready: make(chan struct{}), cancel: cancel}
}

func (w *waitReadCloser) set(body io.ReadCloser) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		_ = body.Close()
		return
	}
	w.body = body
	w.mu.Unlock()
	w.once.Do(func() { close(w.ready) })
}

func (w *waitReadCloser) fail(err error) {
	w.mu.Lock()
	if w.err == nil {
		w.err = err
	}
	w.mu.Unlock()
	w.once.Do(func() { close(w.ready) })
}

func (w *waitReadCloser) Read(b []byte) (int, error) {
	<-w.ready
	w.mu.Lock()
	body, err, closed := w.body, w.err, w.closed
	w.mu.Unlock()
	if err != nil {
		return 0, err
	}
	if body == nil || closed {
		return 0, io.ErrClosedPipe
	}
	return body.Read(b)
}

func (w *waitReadCloser) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	body := w.body
	w.mu.Unlock()
	if w.cancel != nil {
		w.cancel()
	}
	if body != nil {
		return body.Close()
	}
	w.once.Do(func() { close(w.ready) })
	return nil
}

// streamConn is the net.Conn handed to the anytls client: reads come from the
// downstream stream, writes go to the upstream stream.
type streamConn struct {
	reader     io.ReadCloser
	writer     io.WriteCloser
	remoteAddr net.Addr
	localAddr  net.Addr
	onClose    func()
	closeOnce  sync.Once
}

func (c *streamConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *streamConn) Write(b []byte) (int, error) {
	return c.writer.Write(b)
}

func (c *streamConn) Close() error {
	var firstErr error
	c.closeOnce.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
		if err := c.writer.Close(); err != nil {
			firstErr = err
		}
		if err := c.reader.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	})
	return firstErr
}

func (c *streamConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *streamConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *streamConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *streamConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// socksaddr adapts a destination to net.Addr; sing's metadata.Socksaddr
// already implements the interface, so it is returned as is.
func socksaddr(dest M.Socksaddr) net.Addr {
	if dest.Fqdn == "" && !dest.Addr.IsValid() {
		return nil
	}
	return dest
}
