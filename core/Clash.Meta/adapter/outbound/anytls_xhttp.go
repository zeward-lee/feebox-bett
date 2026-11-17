package outbound

import (
	"context"
	"fmt"
	"strings"

	"github.com/metacubex/mihomo/transport/v2rayxhttp"
	"github.com/metacubex/mihomo/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// XHTTPTransportOptions is the `xhttp-opts` block of an anytls node whose
// traffic rides the vendor `transport/v2rayxhttp` (XHTTP) transport instead of
// a plain TCP socket. The option names mirror the vendor config so a node can be
// translated field by field:
//
//	transport: xhttp
//	xhttp-opts:
//	  path: /rpcv2
//	  mode: stream-up
//	  obfs-key: <vendor obfs key>
//	  xmux: {max-concurrency: 8}
//	  download: {server: ..., port: ..., sni: ..., xmux: {max-concurrency: 2}}
type XHTTPTransportOptions struct {
	Path    string            `proxy:"path,omitempty"`
	Host    string            `proxy:"host,omitempty"`
	Headers map[string]string `proxy:"headers,omitempty"`
	Mode    string            `proxy:"mode,omitempty"`
	// ObfsKey is required by the transport. A nil pointer (key absent from the
	// yaml) fails node construction with "obfs-key is required for v2rayxhttp
	// transport"; an explicit empty string (`obfs-key: ""`) is the opt-out that
	// runs the stream without the vendor obfs preamble.
	ObfsKey       *string               `proxy:"obfs-key,omitempty"`
	XPaddingBytes string                `proxy:"x-padding-bytes,omitempty"`
	UplinkMethod  string                `proxy:"uplink-http-method,omitempty"`
	Xmux          *XHTTPXmuxOptions     `proxy:"xmux,omitempty"`
	Download      *XHTTPDownloadOptions `proxy:"download,omitempty"`
}

// XHTTPXmuxOptions mirrors the vendor `xmux` block. Values accept the vendor's
// single-value ("8") or range ("8-16") spelling.
type XHTTPXmuxOptions struct {
	MaxConcurrency   string `proxy:"max-concurrency,omitempty"`
	MaxConnections   string `proxy:"max-connections,omitempty"`
	CMaxReuseTimes   string `proxy:"c-max-reuse-times,omitempty"`
	HMaxRequestTimes string `proxy:"h-max-request-times,omitempty"`
	HMaxReusableSecs string `proxy:"h-max-reusable-secs,omitempty"`
}

// XHTTPDownloadOptions is the split downstream endpoint of a stream-up tunnel.
type XHTTPDownloadOptions struct {
	Server         string            `proxy:"server"`
	Port           int               `proxy:"port"`
	SNI            string            `proxy:"sni,omitempty"`
	SkipCertVerify bool              `proxy:"skip-cert-verify,omitempty"`
	Path           string            `proxy:"path,omitempty"`
	Host           string            `proxy:"host,omitempty"`
	Headers        map[string]string `proxy:"headers,omitempty"`
	// ObfsKey follows the upload rule: absent inherits the upload key, an
	// explicit empty string disables obfs on the download half only.
	ObfsKey       *string           `proxy:"obfs-key,omitempty"`
	XPaddingBytes string            `proxy:"x-padding-bytes,omitempty"`
	Xmux          *XHTTPXmuxOptions `proxy:"xmux,omitempty"`
}

func (o *XHTTPXmuxOptions) build() (*v2rayxhttp.XmuxOptions, error) {
	if o == nil {
		return nil, nil
	}
	maxConcurrency, err := v2rayxhttp.ParseRange(o.MaxConcurrency)
	if err != nil {
		return nil, err
	}
	maxConnections, err := v2rayxhttp.ParseRange(o.MaxConnections)
	if err != nil {
		return nil, err
	}
	cMaxReuseTimes, err := v2rayxhttp.ParseRange(o.CMaxReuseTimes)
	if err != nil {
		return nil, err
	}
	hMaxRequestTimes, err := v2rayxhttp.ParseRange(o.HMaxRequestTimes)
	if err != nil {
		return nil, err
	}
	hMaxReusableSecs, err := v2rayxhttp.ParseRange(o.HMaxReusableSecs)
	if err != nil {
		return nil, err
	}
	return &v2rayxhttp.XmuxOptions{
		MaxConcurrency:   maxConcurrency,
		MaxConnections:   maxConnections,
		CMaxReuseTimes:   cMaxReuseTimes,
		HMaxRequestTimes: hMaxRequestTimes,
		HMaxReusableSecs: hMaxReusableSecs,
	}, nil
}

// newXHTTPTransport builds the XHTTP client that replaces the anytls dialer.
// The XHTTP stream pair already carries TLS (the transport handshake), so the
// anytls layer above it runs without a second TLS handshake: the credential and
// session frames are written straight into the upload stream, exactly like the
// vendor stack (TCP -> TLS -> HTTP/2 streams -> obfs -> anytls frames).
func newXHTTPTransport(option *AnyTLSOption, dialer N.Dialer) (*v2rayxhttp.Client, error) {
	opts := option.XHTTPOpts
	mode := strings.ToLower(strings.TrimSpace(opts.Mode))
	if mode == "" {
		mode = "auto"
	}
	padding, err := v2rayxhttp.ParseRange(opts.XPaddingBytes)
	if err != nil {
		return nil, err
	}
	xmux, err := opts.Xmux.build()
	if err != nil {
		return nil, err
	}
	config := &v2rayxhttp.Config{
		Server:           M.ParseSocksaddrHostPort(option.Server, uint16(option.Port)),
		TLS:              xhttpTLSConfig(option),
		Path:             opts.Path,
		Mode:             mode,
		Host:             opts.Host,
		Headers:          opts.Headers,
		ObfsKey:          opts.ObfsKey,
		XPadding:         padding,
		UplinkHTTPMethod: opts.UplinkMethod,
		Xmux:             xmux,
	}
	if d := opts.Download; d != nil {
		downloadPadding, err := v2rayxhttp.ParseRange(d.XPaddingBytes)
		if err != nil {
			return nil, err
		}
		downloadXmux, err := d.Xmux.build()
		if err != nil {
			return nil, err
		}
		config.Download = &v2rayxhttp.DownloadOptions{
			Server:   M.ParseSocksaddrHostPort(d.Server, uint16(d.Port)),
			TLS:      xhttpDownloadTLSConfig(option, d),
			Path:     d.Path,
			Host:     d.Host,
			Headers:  d.Headers,
			ObfsKey:  d.ObfsKey,
			XPadding: downloadPadding,
			Xmux:     downloadXmux,
		}
	}
	// The transport config validates itself (obfs key present, ALPN, mode), so a
	// misconfigured node fails here, at construction time, with the transport's
	// own error message instead of dialing and timing out later.
	client, err := v2rayxhttp.NewClient(context.Background(), dialer, config)
	if err != nil {
		return nil, fmt.Errorf("anytls: build xhttp transport: %w", err)
	}
	return client, nil
}

// xhttpTLSConfig derives a private TLS config for the transport connection. It
// must not share the anytls TLS config: the transport needs its own ALPN list
// while the inner anytls TLS handshake is left untouched.
//
// ALPN: `alpn` from the node wins; only when it is unset does the transport
// default to h2. An explicit list without h2 makes the transport fall back to
// HTTP/1.1, where one connection carries one stream at a time (so xmux
// max-concurrency cannot bound concurrency and stream-one loses its full-duplex
// guarantee). The dedicated lines run h2.
func xhttpTLSConfig(option *AnyTLSOption) *vmess.TLSConfig {
	alpn := option.ALPN
	if len(alpn) == 0 {
		alpn = []string{v2rayxhttp.ALPNH2}
	}
	return &vmess.TLSConfig{
		Host:              firstNonEmpty(option.SNI, option.Server),
		SkipCertVerify:    option.SkipCertVerify,
		NextProtos:        append([]string(nil), alpn...),
		FingerPrint:       option.Fingerprint,
		ClientFingerprint: option.ClientFingerprint,
		Certificate:       option.Certificate,
		PrivateKey:        option.PrivateKey,
	}
}

func xhttpDownloadTLSConfig(option *AnyTLSOption, download *XHTTPDownloadOptions) *vmess.TLSConfig {
	cfg := xhttpTLSConfig(option)
	if download.SNI != "" {
		cfg.Host = download.SNI
	}
	if download.SkipCertVerify {
		cfg.SkipCertVerify = true
	}
	return cfg
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
