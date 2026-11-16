package outbound

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/metacubex/mihomo/common/structure"

	M "github.com/metacubex/sing/common/metadata"
)

// shanlianXHTTPFixture is the parameter shape of a Shanlian dedicated line,
// copied field by field from the vendor config (password masked).
func shanlianXHTTPFixture() map[string]any {
	return map[string]any{
		"name":             "闪连 🇭🇰 专线",
		"type":             "anytls",
		"server":           "82.163.67.20",
		"port":             6504,
		"password":         "00000000000000000000000000000000",
		"udp":              true,
		"skip-cert-verify": true,
		"sni":              "v-mirror.byteimg.com",
		"transport":        "xhttp",
		"xhttp-opts": map[string]any{
			"path":     "/rpcv2",
			"mode":     "stream-up",
			"obfs-key": "9uByRBBiCy",
			"xmux": map[string]any{
				"max-concurrency": "8",
			},
			"download": map[string]any{
				"server":           "82.163.67.21",
				"port":             6504,
				"sni":              "d-mirror.surfonline.vip",
				"skip-cert-verify": true,
				"path":             "/rpcv2",
				"xmux": map[string]any{
					"max-concurrency": "2",
				},
			},
		},
	}
}

type noopDialer struct{}

func (noopDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("noop dialer")
}

func (noopDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("noop dialer")
}

func decodeAnyTLSOption(t *testing.T, mapping map[string]any) *AnyTLSOption {
	t.Helper()
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	option := &AnyTLSOption{}
	if err := decoder.Decode(mapping, option); err != nil {
		t.Fatalf("decode anytls options: %v", err)
	}
	return option
}

// TestXHTTPTransportOptionsDecode checks the yaml surface: `transport: xhttp`
// and the nested `xhttp-opts` block are decoded into the option table the
// vendor config describes.
func TestXHTTPTransportOptionsDecode(t *testing.T) {
	option := decodeAnyTLSOption(t, shanlianXHTTPFixture())
	if option.Transport != "xhttp" {
		t.Fatalf("transport = %q", option.Transport)
	}
	if option.XHTTPOpts.Mode != "stream-up" {
		t.Errorf("mode = %q", option.XHTTPOpts.Mode)
	}
	if option.XHTTPOpts.Path != "/rpcv2" {
		t.Errorf("path = %q", option.XHTTPOpts.Path)
	}
	if option.XHTTPOpts.ObfsKey != "9uByRBBiCy" {
		t.Errorf("obfs key = %q", option.XHTTPOpts.ObfsKey)
	}
	if option.XHTTPOpts.Xmux == nil || option.XHTTPOpts.Xmux.MaxConcurrency != "8" {
		t.Errorf("xmux = %+v", option.XHTTPOpts.Xmux)
	}
	download := option.XHTTPOpts.Download
	if download == nil {
		t.Fatal("download block missing")
	}
	if download.Server != "82.163.67.21" || download.Port != 6504 {
		t.Errorf("download endpoint = %s:%d", download.Server, download.Port)
	}
	if download.SNI != "d-mirror.surfonline.vip" {
		t.Errorf("download sni = %q", download.SNI)
	}
	if download.Xmux == nil || download.Xmux.MaxConcurrency != "2" {
		t.Errorf("download xmux = %+v", download.Xmux)
	}
}

// TestXHTTPTransportBuildsClient checks the translation from the yaml option
// table to the transport config.
func TestXHTTPTransportBuildsClient(t *testing.T) {
	option := decodeAnyTLSOption(t, shanlianXHTTPFixture())
	client, err := newXHTTPTransport(option, noopDialer{})
	if err != nil {
		t.Fatalf("build transport: %v", err)
	}
	defer client.Close()
	config := client.Config()
	if config.Mode != "stream-up" {
		t.Errorf("mode = %q", config.Mode)
	}
	if config.Path != "/rpcv2/" {
		t.Errorf("path = %q", config.Path)
	}
	if config.ObfsKey != "9uByRBBiCy" {
		t.Errorf("obfs key = %q", config.ObfsKey)
	}
	if config.Server.String() != "82.163.67.20:6504" {
		t.Errorf("server = %s", config.Server.String())
	}
	if config.Xmux == nil || config.Xmux.MaxConcurrency.From != 8 {
		t.Errorf("xmux = %+v", config.Xmux)
	}
	if config.Download == nil {
		t.Fatal("download endpoint missing")
	}
	if config.Download.Server.String() != "82.163.67.21:6504" {
		t.Errorf("download server = %s", config.Download.Server.String())
	}
	if config.Download.ObfsKey != "9uByRBBiCy" {
		t.Errorf("download obfs key = %q", config.Download.ObfsKey)
	}
	if config.Download.Xmux == nil || config.Download.Xmux.MaxConcurrency.From != 2 {
		t.Errorf("download xmux = %+v", config.Download.Xmux)
	}
	if config.TLS == nil || !config.TLS.SkipCertVerify || config.TLS.Host != "v-mirror.byteimg.com" {
		t.Errorf("transport TLS = %+v", config.TLS)
	}
	if config.Download.TLS.Host != "d-mirror.surfonline.vip" {
		t.Errorf("download TLS host = %q", config.Download.TLS.Host)
	}
}

// TestAnyTLSWithoutTransportIsUnchanged is the zero-impact guard: a node
// without a transport block builds the same plain anytls outbound as before.
func TestAnyTLSWithoutTransportIsUnchanged(t *testing.T) {
	mapping := shanlianXHTTPFixture()
	delete(mapping, "transport")
	delete(mapping, "xhttp-opts")
	option := decodeAnyTLSOption(t, mapping)
	if option.Transport != "" {
		t.Fatalf("transport = %q", option.Transport)
	}
	adapter, err := NewAnyTLS(*option)
	if err != nil {
		t.Fatalf("new anytls: %v", err)
	}
	defer adapter.Close()
	if adapter.xhttp != nil {
		t.Error("plain anytls node must not build an xhttp transport")
	}
}

func TestAnyTLSRejectsUnknownTransport(t *testing.T) {
	mapping := shanlianXHTTPFixture()
	mapping["transport"] = "grpc"
	option := decodeAnyTLSOption(t, mapping)
	if _, err := NewAnyTLS(*option); err == nil {
		t.Fatal("unknown transport should be rejected")
	}
}

func TestAnyTLSWithXHTTPTransport(t *testing.T) {
	option := decodeAnyTLSOption(t, shanlianXHTTPFixture())
	adapter, err := NewAnyTLS(*option)
	if err != nil {
		t.Fatalf("new anytls: %v", err)
	}
	defer adapter.Close()
	if adapter.xhttp == nil {
		t.Fatal("xhttp transport missing on a `transport: xhttp` node")
	}
	if adapter.xhttp.Config().Download == nil {
		t.Fatal("download endpoint missing")
	}
}
