package v2rayxhttp

import (
	"net/url"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
)

// obfsPtr is the pointer spelling of an obfs key: nil means "not configured"
// (rejected by Validate), a pointer to "" means "explicitly disabled".
func obfsPtr(value string) *string {
	return &value
}

func baseConfig() *Config {
	return &Config{
		Server:  M.ParseSocksaddrHostPort("82.163.67.20", 6504),
		TLS:     &vmess.TLSConfig{Host: "v-mirror.byteimg.com", SkipCertVerify: true},
		Path:    "/rpcv2",
		ObfsKey: obfsPtr("9uByRBBiCy"),
	}
}

// TestValidateRequiresObfsKey pins the fail-closed rule from the review: a node
// that forgets `obfs-key` must be rejected at construction time instead of
// silently dialing the server in cleartext.
func TestValidateRequiresObfsKey(t *testing.T) {
	config := baseConfig()
	config.ObfsKey = nil
	err := config.Validate()
	if err == nil {
		t.Fatal("missing obfs-key should fail validation")
	}
	if want := "obfs-key is required for v2rayxhttp transport"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want it to contain %q", err, want)
	}

	// An explicit empty string is the documented opt-out.
	config = baseConfig()
	config.ObfsKey = obfsPtr("")
	if err := config.Validate(); err != nil {
		t.Fatalf("explicit obfs opt-out should validate: %v", err)
	}
	if got := config.ObfsKeyValue(); got != "" {
		t.Errorf("obfs key = %q, want empty", got)
	}
}

// TestValidateDownloadObfsKeyInheritance keeps the two opt-out levels separate:
// an unset download key inherits the upload one, while an explicit empty string
// disables obfs on the download half only.
func TestValidateDownloadObfsKeyInheritance(t *testing.T) {
	config := baseConfig()
	config.Download = &DownloadOptions{Server: M.ParseSocksaddrHostPort("82.163.67.21", 6504)}
	if err := config.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := config.Download.ObfsKeyValue(); got != "9uByRBBiCy" {
		t.Errorf("download obfs key = %q, want the inherited upload key", got)
	}

	config = baseConfig()
	config.Download = &DownloadOptions{
		Server:  M.ParseSocksaddrHostPort("82.163.67.21", 6504),
		ObfsKey: obfsPtr(""),
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := config.Download.ObfsKeyValue(); got != "" {
		t.Errorf("download obfs key = %q, want the explicit opt-out", got)
	}
	if got := config.ObfsKeyValue(); got != "9uByRBBiCy" {
		t.Errorf("upload obfs key = %q, must not follow the download opt-out", got)
	}
}

// TestValidateKeepsTLSConfigPrivate pins that normalization never edits the
// caller's TLS config and never lets the download endpoint share the upload
// pointer: the adapter can hand one struct to both halves.
func TestValidateKeepsTLSConfigPrivate(t *testing.T) {
	shared := &vmess.TLSConfig{Host: "v-mirror.byteimg.com", SkipCertVerify: true}
	config := baseConfig()
	config.TLS = shared
	config.Download = &DownloadOptions{Server: M.ParseSocksaddrHostPort("82.163.67.21", 6504)}
	if err := config.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(shared.NextProtos) != 0 {
		t.Errorf("caller TLS config was mutated: NextProtos = %v", shared.NextProtos)
	}
	if config.TLS == shared {
		t.Error("config kept the caller's TLS pointer")
	}
	if config.Download.TLS == config.TLS {
		t.Error("download shares the upload TLS config pointer")
	}
	if got := config.Download.TLS.NextProtos; len(got) != 1 || got[0] != ALPNH2 {
		t.Errorf("download ALPN = %v, want [%s]", got, ALPNH2)
	}
	config.Download.TLS.Host = "d-mirror.example"
	if config.TLS.Host != "v-mirror.byteimg.com" {
		t.Errorf("upload TLS host changed to %q through the download config", config.TLS.Host)
	}
}

// TestValidateHonoursConfiguredALPN pins that a node-level `alpn` list survives
// normalization instead of being overwritten with h2.
func TestValidateHonoursConfiguredALPN(t *testing.T) {
	config := baseConfig()
	config.TLS.NextProtos = []string{"http/1.1"}
	if err := config.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := config.TLS.NextProtos; len(got) != 1 || got[0] != "http/1.1" {
		t.Errorf("ALPN = %v, want [http/1.1]", got)
	}

	config = baseConfig()
	config.TLS.NextProtos = []string{ALPNH2, "http/1.1"}
	if err := config.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := config.TLS.NextProtos; len(got) != 2 || got[0] != ALPNH2 || got[1] != "http/1.1" {
		t.Errorf("ALPN = %v, want [h2 http/1.1]", got)
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
	if got := config.TLS.NextProtos; len(got) != 1 || got[0] != ALPNH2 {
		t.Errorf("tls ALPN = %v, want [%s]", got, ALPNH2)
	}
	if config.Download.ObfsKeyValue() != "9uByRBBiCy" {
		t.Errorf("download obfs key should inherit the upload one, got %q", config.Download.ObfsKeyValue())
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
	config.ObfsKey = obfsPtr("9uByRBBiCy")
	config.Download = &DownloadOptions{
		Server: M.ParseSocksaddrHostPort("82.163.67.21", 6504),
		TLS:    &vmess.TLSConfig{Host: "d-mirror.surfonline.vip"},
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := config.Download.ObfsKeyValue(); got != "9uByRBBiCy" {
		t.Errorf("download obfs key = %q", got)
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
