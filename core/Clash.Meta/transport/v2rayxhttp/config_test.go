package v2rayxhttp

import (
	"net/url"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
)

func baseConfig() *Config {
	return &Config{
		Server: M.ParseSocksaddrHostPort("82.163.67.20", 6504),
		TLS:    &vmess.TLSConfig{Host: "v-mirror.byteimg.com", SkipCertVerify: true},
		Path:   "/rpcv2",
	}
}

func TestValidateStreamUpDefaults(t *testing.T) {
	config := baseConfig()
	config.Mode = "stream-up"
	config.Download = &DownloadOptions{
		Server: M.ParseSocksaddrHostPort("82.163.67.21", 6504),
		TLS:    &vmess.TLSConfig{Host: "d-mirror.surfonline.vip", SkipCertVerify: true},
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if config.Path != "/rpcv2/" {
		t.Errorf("path = %q, want /rpcv2/", config.Path)
	}
	if config.Download.Path != "/rpcv2/" {
		t.Errorf("download path = %q", config.Download.Path)
	}
	if config.XPadding.From != 100 || config.XPadding.To != 1000 {
		t.Errorf("default padding = %+v", config.XPadding)
	}
	if got := config.TLS.NextProtos; len(got) != 1 || got[0] != "h2" {
		t.Errorf("tls ALPN = %v, want [h2]", got)
	}
	if config.Download.ObfsKey != "" {
		t.Errorf("download obfs key should inherit the upload one")
	}
	// The download endpoint inherits path/padding/obfs from the base config.
	if config.Download.XPadding != config.XPadding {
		t.Errorf("download padding = %+v", config.Download.XPadding)
	}
}

func TestValidateModeSelection(t *testing.T) {
	// auto + download behaves like the vendor configuration: stream-up.
	config := baseConfig()
	config.Download = &DownloadOptions{Server: M.ParseSocksaddrHostPort("1.2.3.4", 443), TLS: &vmess.TLSConfig{Host: "d.example"}}
	if err := config.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if config.Mode != ModeStreamUp {
		t.Errorf("mode = %q, want stream-up", config.Mode)
	}
	// auto without download degrades to stream-one.
	config = baseConfig()
	if err := config.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if config.Mode != ModeStreamOne {
		t.Errorf("mode = %q, want stream-one", config.Mode)
	}
	// download is invalid for stream-one, packet-up is not implemented.
	config = baseConfig()
	config.Mode = ModeStreamOne
	config.Download = &DownloadOptions{Server: M.ParseSocksaddrHostPort("1.2.3.4", 443), TLS: &vmess.TLSConfig{Host: "d.example"}}
	if err := config.Validate(); err == nil {
		t.Error("stream-one with download should be rejected")
	}
	config = baseConfig()
	config.Mode = ModePacketUp
	if err := config.Validate(); err == nil {
		t.Error("packet-up should be rejected")
	}
	// max_connections and max_concurrency are mutually exclusive (vendor check).
	config = baseConfig()
	config.Mode = ModeStreamUp
	config.Xmux = &XmuxOptions{MaxConcurrency: Range{From: 8, To: 8}, MaxConnections: Range{From: 2, To: 2}}
	if err := config.Validate(); err == nil {
		t.Error("max_concurrency together with max_connections should be rejected")
	}
}

func TestValidateDownloadInheritsObfsKey(t *testing.T) {
	config := baseConfig()
	config.Mode = ModeStreamUp
	config.ObfsKey = "9uByRBBiCy"
	config.Download = &DownloadOptions{
		Server: M.ParseSocksaddrHostPort("82.163.67.21", 6504),
		TLS:    &vmess.TLSConfig{Host: "d-mirror.surfonline.vip"},
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if config.Download.ObfsKey != "9uByRBBiCy" {
		t.Errorf("download obfs key = %q", config.Download.ObfsKey)
	}
	if config.Download.Host != "d-mirror.surfonline.vip" {
		t.Errorf("download host = %q", config.Download.Host)
	}
}

func TestParseRange(t *testing.T) {
	cases := map[string]Range{
		"":      {},
		"8":     {From: 8, To: 8},
		"2":     {From: 2, To: 2},
		"8-16":  {From: 8, To: 16},
		" 8-16": {From: 8, To: 16},
	}
	for input, want := range cases {
		got, err := ParseRange(input)
		if err != nil {
			t.Fatalf("ParseRange(%q): %v", input, err)
		}
		if got != want {
			t.Errorf("ParseRange(%q) = %+v, want %+v", input, got, want)
		}
	}
	if _, err := ParseRange("x"); err == nil {
		t.Error("ParseRange(x) should fail")
	}
}

func TestPaddingValue(t *testing.T) {
	base := requestURL("https", "v-mirror.byteimg.com", "/rpcv2/")
	for i := 0; i < 32; i++ {
		value := paddingValue(base, Range{From: 100, To: 1000})
		parsed, err := url.Parse(value)
		if err != nil {
			t.Fatalf("padding value %q: %v", value, err)
		}
		padding := parsed.Query().Get("x_padding")
		if len(padding) < 100 || len(padding) > 1000 {
			t.Fatalf("padding length %d out of range", len(padding))
		}
		if strings.Trim(padding, "X") != "" {
			t.Fatalf("padding is not repeat-x: %q", padding)
		}
	}
}
