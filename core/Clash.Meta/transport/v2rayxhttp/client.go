package v2rayxhttp

import (
	"context"
	"crypto/tls"
	"errors"
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
		obfsKey:  config.ObfsKeyValue(),
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
			obfsKey:  d.ObfsKeyValue(),
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
	// Link the halves: the upload and the download are two independent HTTP
	// requests here, so a dead upload would otherwise leave the anytls session
	// blocked on a download read that never completes or fails. Failing the
	// reader with the upload error makes the failure visible to the session.
	writer.setOnFailure(func(err error) {
		reader.fail(err)
		_ = reader.Close()
	})
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

// newHTTPClient builds a client whose single connection is dialed through the
// proxy dialer and then TLS-wrapped. The ALPN list decides the protocol: h2 uses
// http2.Transport (one conn multiplexes streams), while a node that asked for
// something else gets an HTTP/1.1 transport, where every in-flight stream needs
// its own TCP connection.
//
// The obfs layer is NOT applied here: the vendor wraps the HTTP stream bodies
// (`obfsReader` on the response body, `obfsWriter` on the request body), so the
// TLS handshake travels unwrapped and the obfuscation is added per body in
// openUpload/openDownload/openSingleStream. Do not wrap `conn` again - a server
// that answers a plain TLS record will reject the 20-byte obfs preamble.
func (e *endpoint) newHTTPClient(dialer N.Dialer) (*http.Client, error) {
	dialConn := func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, N.NetworkTCP, e.dest)
		if err != nil {
			return nil, err
		}
		tlsConn, err := vmess.StreamTLSConn(ctx, conn, e.tls)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	var transport http.RoundTripper
	if e.usesHTTP2() {
		transport = &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return dialConn(ctx, network, addr)
			},
			IdleConnTimeout: idleConnTimeout,
			ReadIdleTimeout: keepAlivePeriod,
		}
	} else {
		// HTTP/1.1 fallback. ForceAttemptHTTP2 stays false so the transport can
		// never upgrade behind the negotiated ALPN; Proxy stays nil because the
		// node's own proxy chain already sits under the dialer.
		transport = &http.Transport{
			DialTLSContext:    dialConn,
			ForceAttemptHTTP2: false,
			IdleConnTimeout:   idleConnTimeout,
		}
	}
	return &http.Client{Transport: &nonReplayableTransport{base: transport}}, nil
}

// usesHTTP2 reports whether the configured ALPN list can negotiate h2. An empty
// list means "not configured" and Validate already defaulted it to h2.
func (e *endpoint) usesHTTP2() bool {
	if e.tls == nil || len(e.tls.NextProtos) == 0 {
		return true
	}
	for _, proto := range e.tls.NextProtos {
		if proto == ALPNH2 {
			return true
		}
	}
	return false
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
		// The vendor obfs layer belongs to the HTTP body: the downstream half
		// is deobfuscated as it is read, after TLS and dechunking.
		reader.set(wrapObfsReader(resp.Body, e.obfsKey))
	}()
	return reader, entry, nil
}

func (e *endpoint) openUpload(ctx context.Context, session string) (*pipeWriter, *muxEntry, error) {
	client, entry, err := e.mux.acquire()
	if err != nil {
		return nil, nil, err
	}
	// The upload body is a live io.Pipe: it can only be sent once, so redirects
	// must not replay it (a 307/308 would otherwise re-POST a truncated stream).
	uploadClient := *client
	uploadClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	requestCtx, cancel := context.WithCancel(contextutils.WithoutCancel(ctx))
	requestCtx = context.WithValue(requestCtx, uploadAttemptKey{}, &uploadAttempt{})
	pr, pw := io.Pipe()
	// The vendor obfs layer belongs to the HTTP body: the upstream half is
	// obfuscated between the stream writer and the request body pipe.
	writer := newPipeWriter(pw, e.obfsKey)
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
		resp, err := uploadClient.Do(req)
		if err != nil {
			// Record on the write path first (so the next Write returns it and
			// nothing is silently swallowed), then let the hook fail the read
			// half with the same cause.
			writer.fail(fmt.Errorf("v2rayxhttp: upload stream: %w", err))
			cancel()
			return
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			writer.fail(fmt.Errorf("v2rayxhttp: upload stream returned %s", resp.Status))
			cancel()
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		cancel()
	}()
	return writer, entry, nil
}

// openSingleStream implements mode stream-one: a single POST whose response
// body is the downstream half.
func (e *endpoint) openSingleStream(ctx context.Context, session string) (io.ReadCloser, *pipeWriter, *muxEntry, error) {
	client, entry, err := e.mux.acquire()
	if err != nil {
		return nil, nil, nil, err
	}
	requestCtx, cancel := context.WithCancel(contextutils.WithoutCancel(ctx))
	requestCtx = context.WithValue(requestCtx, uploadAttemptKey{}, &uploadAttempt{})
	pr, pw := io.Pipe()
	// Stream-one carries both directions on one HTTP exchange: the request
	// body is obfuscated on the write side, the response body on the read side.
	writer := newPipeWriter(pw, e.obfsKey)
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
	writer.setOnFailure(func(err error) {
		reader.fail(err)
		_ = reader.Close()
	})
	go func() {
		resp, err := client.Do(req)
		if err != nil {
			writer.fail(fmt.Errorf("v2rayxhttp: stream: %w", err))
			return
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			writer.fail(fmt.Errorf("v2rayxhttp: stream returned %s", resp.Status))
			return
		}
		reader.set(wrapObfsReader(resp.Body, e.obfsKey))
	}()
	return reader, writer, entry, nil
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
	n, err := body.Read(b)
	if err != nil {
		// A failure recorded while this read was blocked is the real cause (for
		// stream-up it is the upload half dying and aborting the stream), so
		// report it instead of the generic "response body closed" the aborted
		// read produces.
		w.mu.Lock()
		recorded := w.err
		w.mu.Unlock()
		if recorded != nil {
			return n, recorded
		}
	}
	return n, err
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

// pipeWriter is the upload half of a stream. It owns the io.PipeWriter feeding
// the request body and remembers the first transport-level failure, so a dead
// upload is reported on the write path instead of surfacing as a broken pipe
// with no cause, and (through onFailure) on the download half as well.
//
// out is the body source net/http reads: the obfs writer when the node has an
// obfs key, the pipe itself otherwise. Wrapping here keeps the vendor obfs at
// the HTTP body layer while the failure bookkeeping stays on the pipe.
type pipeWriter struct {
	pw *io.PipeWriter

	out io.Writer

	mu        sync.Mutex
	err       error
	onFailure func(error)
}

func newPipeWriter(pw *io.PipeWriter, obfsKey string) *pipeWriter {
	return &pipeWriter{pw: pw, out: wrapObfsWriter(pw, obfsKey)}
}

func (w *pipeWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	stored := w.err
	w.mu.Unlock()
	if stored != nil {
		return 0, stored
	}
	return w.out.Write(b)
}

func (w *pipeWriter) Close() error {
	return w.pw.Close()
}

// setOnFailure registers the read-side failure hook. It fires immediately when
// the upload already failed, so a failure racing the dialer cannot be missed.
// Hooks must be idempotent (the ones installed by this package are).
func (w *pipeWriter) setOnFailure(hook func(error)) {
	w.mu.Lock()
	w.onFailure = hook
	err := w.err
	w.mu.Unlock()
	if err != nil && hook != nil {
		hook(err)
	}
}

// fail records err (first one wins), unblocks a pending Write and then runs the
// hook. Repeated failures are no-ops.
func (w *pipeWriter) fail(err error) {
	if err == nil {
		return
	}
	w.mu.Lock()
	if w.err != nil {
		w.mu.Unlock()
		return
	}
	w.err = err
	hook := w.onFailure
	w.mu.Unlock()
	_ = w.pw.CloseWithError(err)
	if hook != nil {
		hook(err)
	}
}

// errUploadReplay is returned when the same one-shot upload stream is handed to
// the HTTP stack twice. An io.Pipe body cannot be replayed: the retry would
// either hang or send a truncated stream, both of which the server sees as a
// corrupted session.
var errUploadReplay = errors.New("v2rayxhttp: upload stream cannot be replayed")

// uploadAttempt counts how often one upload stream reached the transport. It
// travels in the request context.
type uploadAttempt struct {
	mu       sync.Mutex
	attempts int
}

type uploadAttemptKey struct{}

// nonReplayableTransport makes the one-shot nature of the upload body explicit.
// The request never carries GetBody, so net/http itself refuses to retry a
// request whose body was already read; this wrapper additionally rejects a
// second attempt for the same stream instead of silently replaying a consumed
// io.Pipe. The one internal retry net/http still performs (a connection that
// died before any byte was written) hands the untouched pipe back unchanged,
// which is safe.
type nonReplayableTransport struct {
	base http.RoundTripper
}

func (t *nonReplayableTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.GetBody != nil {
		return nil, errUploadReplay
	}
	attempt, ok := req.Context().Value(uploadAttemptKey{}).(*uploadAttempt)
	if !ok {
		return t.base.RoundTrip(req)
	}
	attempt.mu.Lock()
	attempt.attempts++
	replay := attempt.attempts > 1
	attempt.mu.Unlock()
	if replay {
		return nil, errUploadReplay
	}
	return t.base.RoundTrip(req)
}

// streamConn is the net.Conn handed to the anytls client: reads come from the
// downstream stream, writes go to the upstream stream.
type streamConn struct {
	reader     io.ReadCloser
	writer     *pipeWriter
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
