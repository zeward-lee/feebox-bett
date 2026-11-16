// Package v2rayxhttp implements the client half of the vendor
// `transport/v2rayxhttp` (XHTTP) transport: a session id in the request path,
// an upload stream with an endless body and, for `stream-up`, a separate
// downstream stream that may live on another server/TLS identity.
//
// ALPN: the stream layer speaks HTTP/2 and defaults to ALPN "h2". A node may
// override the protocol list (`alpn`); when the configured list cannot
// negotiate h2 the endpoint falls back to an HTTP/1.1 client. HTTP/1.1 has no
// stream multiplexing, so `xmux.max-concurrency` (streams per connection)
// cannot bound concurrency - every in-flight stream needs its own TCP
// connection - and `stream-one` loses its full-duplex guarantee. The dedicated
// lines must stay on h2; the h1 path only exists so a node that explicitly asks
// for `alpn: [http/1.1]` (e.g. behind a CDN that terminates h2 itself) still
// connects.
package v2rayxhttp

import (
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
)

// Mode constants of the XHTTP transport. Only the streaming modes are
// implemented: the Shanlian dedicated lines (the only vendor publishing this
// transport) run `mode: stream-up` with a split download endpoint.
const (
	ModeAuto       = "auto"
	ModePacketUp   = "packet-up"
	ModeStreamUp   = "stream-up"
	ModeStreamOne  = "stream-one"
	defaultPath    = "/"
	defaultPadding = 100
	maxPadding     = 1000
)

// ALPNH2 is the ALPN protocol of the HTTP/2 stream layer. The transport falls
// back to it when the node does not configure `alpn`; adapters should use the
// same constant so the default cannot drift.
const ALPNH2 = "h2"

// Range is an inclusive [From, To] interval. The vendor config writes single
// numbers ("max_concurrency": "8"); the Xray option surface allows ranges, so a
// zero To is treated as a single-value range.
type Range struct {
	From int
	To   int
}

func (r Range) Normalized() Range {
	if r.To < r.From {
		r.To = r.From
	}
	return r
}

// Rand returns a random value of the range, or From when the range is empty.
func (r Range) Rand() int {
	r = r.Normalized()
	if r.To <= r.From {
		return r.From
	}
	return r.From + rand.Intn(r.To-r.From+1)
}

// XmuxOptions bounds how many streams/conections a single HTTP client may
// carry before the transport dials another one.
//
// CMaxReuseTimes caps how often one pooled connection may be handed out again;
// once the budget is spent the entry is closed as soon as it goes idle and a
// fresh connection takes over, so no stream is ever cut.
type XmuxOptions struct {
	MaxConcurrency   Range
	MaxConnections   Range
	CMaxReuseTimes   Range
	HMaxRequestTimes Range
	HMaxReusableSecs Range
}

// DownloadOptions describes the split download endpoint (`download` in the
// vendor config): a second server, TLS identity and mux pool used only for the
// downstream half of a stream-up tunnel.
type DownloadOptions struct {
	Server  M.Socksaddr
	TLS     *vmess.TLSConfig
	Path    string
	Host    string
	Headers map[string]string
	// ObfsKey mirrors Config.ObfsKey: nil inherits the upload key, a pointer to
	// "" explicitly runs the download half without the obfs layer.
	ObfsKey  *string
	XPadding Range
	Xmux     *XmuxOptions
}

// Config is the normalized transport configuration.
type Config struct {
	Server  M.Socksaddr
	TLS     *vmess.TLSConfig
	Path    string
	Mode    string
	Host    string
	Headers map[string]string
	// ObfsKey is required: nil fails Validate ("obfs-key is required for
	// v2rayxhttp transport"), while a pointer to the empty string is the
	// explicit opt-out that runs the stream without the obfs preamble. The
	// pointer exists so a forgotten key cannot silently degrade to cleartext.
	ObfsKey  *string
	XPadding Range
	// UplinkHTTPMethod is the HTTP verb of the upstream stream ("POST" by
	// default, "GET" only valid in packet-up).
	UplinkHTTPMethod string
	Xmux             *XmuxOptions
	Download         *DownloadOptions
}

// ObfsKeyValue returns the configured obfs key. Validate guarantees ObfsKey is
// non-nil, so an empty result means the node explicitly disabled obfs.
func (c *Config) ObfsKeyValue() string {
	return obfsKeyValue(c.ObfsKey)
}

// ObfsKeyValue returns the download obfs key (Validate fills in the inherited
// upload key when the download block leaves it unset).
func (d *DownloadOptions) ObfsKeyValue() string {
	return obfsKeyValue(d.ObfsKey)
}

func obfsKeyValue(key *string) string {
	if key == nil {
		return ""
	}
	return *key
}

// Validate normalizes the configuration and rejects modes this port does not
// implement, so a misconfigured node fails at load time instead of silently
// degrading to a plain anytls dial.
func (c *Config) Validate() error {
	switch c.Mode {
	case "", ModeAuto:
		c.Mode = ModeAuto
	case ModeStreamUp, ModeStreamOne:
	case ModePacketUp:
		return errors.New("v2rayxhttp: mode packet-up is not implemented")
	default:
		return fmt.Errorf("v2rayxhttp: unsupported mode %q", c.Mode)
	}
	if c.Download != nil {
		if c.Mode == ModeStreamOne {
			return errors.New(`v2rayxhttp: download is not allowed when mode is "stream-one"`)
		}
		if c.Mode == ModeAuto {
			c.Mode = ModeStreamUp
		}
	} else if c.Mode == ModeAuto {
		c.Mode = ModeStreamOne
	}
	if c.Path == "" {
		c.Path = defaultPath
	}
	c.Path = normalizePath(c.Path)
	if c.UplinkHTTPMethod == "" {
		c.UplinkHTTPMethod = "POST"
	}
	c.UplinkHTTPMethod = strings.ToUpper(c.UplinkHTTPMethod)
	if c.UplinkHTTPMethod == "GET" && c.Mode != ModePacketUp {
		return errors.New("v2rayxhttp: uplink_http_method can be GET only in packet-up mode")
	}
	if c.XPadding.From <= 0 && c.XPadding.To <= 0 {
		c.XPadding = Range{From: defaultPadding, To: maxPadding}
	}
	c.XPadding = c.XPadding.Normalized()
	if c.XPadding.From <= 0 {
		return errors.New("v2rayxhttp: x_padding_bytes cannot be disabled")
	}
	if c.Xmux != nil {
		if c.Xmux.MaxConnections.To > 0 && c.Xmux.MaxConcurrency.To > 0 {
			return errors.New("v2rayxhttp: max_connections cannot be specified together with max_concurrency")
		}
	}
	// Obfs is mandatory unless the node explicitly opts out. A node that forgot
	// `obfs-key` would otherwise send a bare TLS record to a server that expects
	// the 20-byte obfs preamble and the peer would drop the connection, leaving
	// the user with an unexplained timeout. Fail at construction time instead.
	if c.ObfsKey == nil {
		return errors.New(`v2rayxhttp: obfs-key is required for v2rayxhttp transport (write obfs-key: "" to explicitly disable the obfs layer)`)
	}
	if c.TLS == nil {
		return errors.New("v2rayxhttp: TLS is required")
	}
	// Never edit the caller's TLS config in place: the adapter may hand the same
	// pointer to several endpoints, and the download block inherits it below.
	c.TLS = cloneTLS(c.TLS)
	if c.TLS.Host == "" {
		c.TLS.Host = c.Server.Fqdn
	}
	if c.Host == "" {
		c.Host = c.TLS.Host
	}
	if len(c.TLS.NextProtos) == 0 {
		c.TLS.NextProtos = []string{ALPNH2}
	}
	if c.Download != nil {
		d := c.Download
		if d.Server.Fqdn == "" && !d.Server.Addr.IsValid() {
			return errors.New("v2rayxhttp: download.server is required")
		}
		if d.TLS == nil {
			d.TLS = cloneTLS(c.TLS)
		} else {
			d.TLS = cloneTLS(d.TLS)
		}
		if d.TLS.Host == "" {
			d.TLS.Host = d.Server.Fqdn
		}
		if len(d.TLS.NextProtos) == 0 {
			d.TLS.NextProtos = []string{ALPNH2}
		}
		if d.Path == "" {
			d.Path = c.Path
		}
		d.Path = normalizePath(d.Path)
		if d.Host == "" {
			d.Host = d.TLS.Host
		}
		if d.ObfsKey == nil {
			d.ObfsKey = c.ObfsKey
		}
		if d.XPadding.From <= 0 && d.XPadding.To <= 0 {
			d.XPadding = c.XPadding
		}
		d.XPadding = d.XPadding.Normalized()
		if d.Xmux != nil {
			if d.Xmux.MaxConnections.To > 0 && d.Xmux.MaxConcurrency.To > 0 {
				return errors.New("v2rayxhttp: download max_connections cannot be specified together with max_concurrency")
			}
		}
	}
	return nil
}

// cloneTLS returns a private copy of cfg, ALPN list included, so a validation
// pass can apply defaults without touching a config owned by the caller or
// shared with another endpoint.
func cloneTLS(cfg *vmess.TLSConfig) *vmess.TLSConfig {
	if cfg == nil {
		return nil
	}
	clone := *cfg
	clone.NextProtos = append([]string(nil), cfg.NextProtos...)
	return &clone
}

// normalizePath returns the request path with a leading slash and, because the
// session id is appended to the path, a trailing slash.
func normalizePath(path string) string {
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	if path == "" {
		path = defaultPath
	}
	if path[0] != '/' {
		path = "/" + path
	}
	if path[len(path)-1] != '/' {
		path += "/"
	}
	return path
}

// requestURL builds the base URL of a request stream (without the session id).
func requestURL(scheme, host, path string) *url.URL {
	return &url.URL{Scheme: scheme, Host: host, Path: path}
}

// sessionID returns a random UUIDv4, the default session id of the vendor
// client (its option surface leaves the session id length at zero).
func sessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// paddingValue is the default `queryInHeader` X-Padding carrier: the request URL
// with an `x_padding` query parameter holding N literal 'X' characters. The
// server validates 100 <= len <= 1000 unless configured otherwise.
func paddingValue(base *url.URL, r Range) string {
	n := r.Rand()
	u := *base
	u.RawQuery = "x_padding=" + strings.Repeat("X", n)
	return u.String()
}

const (
	keepAlivePeriod = 30 * time.Second
	idleConnTimeout = 90 * time.Second
)

// ParseRange parses the vendor's single-value ("8") or range ("8-16") numeric
// spelling used by the xmux and padding options.
func ParseRange(value string) (Range, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return Range{}, nil
	}
	if idx := strings.IndexByte(value, '-'); idx > 0 {
		from, err := strconv.Atoi(strings.TrimSpace(value[:idx]))
		if err != nil {
			return Range{}, fmt.Errorf("v2rayxhttp: invalid range %q: %w", value, err)
		}
		to, err := strconv.Atoi(strings.TrimSpace(value[idx+1:]))
		if err != nil {
			return Range{}, fmt.Errorf("v2rayxhttp: invalid range %q: %w", value, err)
		}
		return Range{From: from, To: to}.Normalized(), nil
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return Range{}, fmt.Errorf("v2rayxhttp: invalid number %q: %w", value, err)
	}
	return Range{From: n, To: n}, nil
}
