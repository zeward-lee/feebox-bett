package outbound

import (
	"strings"
	"testing"
)

// TestAnyTLSPasswordModeOptionDecodesFromYAML pins the yaml surface of the
// credential scheme selector: `password-mode: raw16` lands in
// AnyTLSOption.PasswordMode and an ordinary node leaves it empty (standard
// anytls).
func TestAnyTLSPasswordModeOptionDecodesFromYAML(t *testing.T) {
	mapping := shanlianXHTTPFixture()
	if got := decodeAnyTLSOption(t, mapping).PasswordMode; got != "" {
		t.Fatalf("password-mode without the field = %q, want empty", got)
	}
	mapping["password-mode"] = ShanlianPasswordMode
	if got := decodeAnyTLSOption(t, mapping).PasswordMode; got != ShanlianPasswordMode {
		t.Fatalf("password-mode = %q, want %q", got, ShanlianPasswordMode)
	}
}

// TestAnyTLSPasswordModeReachesClient proves the option is wired into the
// transport instead of being decoded and dropped: an unsupported value must fail
// construction with the transport's own error, and the supported value builds.
func TestAnyTLSPasswordModeReachesClient(t *testing.T) {
	option := decodeAnyTLSOption(t, shanlianXHTTPFixture())
	option.PasswordMode = "shanlian-hex"
	if _, err := NewAnyTLS(*option); err == nil || !strings.Contains(err.Error(), "unsupported password-mode") {
		t.Fatalf("NewAnyTLS(password-mode=shanlian-hex) error = %v, want unsupported password-mode", err)
	}

	option.PasswordMode = ShanlianPasswordMode
	adapter, err := NewAnyTLS(*option)
	if err != nil {
		t.Fatalf("new anytls with %q: %v", ShanlianPasswordMode, err)
	}
	adapter.Close()
}

// TestPlainAnyTLS32HexPasswordWithoutModeIsStandard is the reverse-verification
// guard at the adapter level: a plain anytls node (no transport, no
// password-mode) whose password happens to be 32 hex characters must build as a
// standard node. The vendor derivation is only selected by the explicit marker.
func TestPlainAnyTLS32HexPasswordWithoutModeIsStandard(t *testing.T) {
	mapping := map[string]any{
		"name":     "ordinary anytls with a hex-looking password",
		"type":     "anytls",
		"server":   "node.example",
		"port":     443,
		"password": "720a437f4beb4fb9915f7f913d7bc9f7",
	}
	option := decodeAnyTLSOption(t, mapping)
	if option.PasswordMode != "" {
		t.Fatalf("password-mode = %q, want empty for an ordinary node", option.PasswordMode)
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

// TestApplyShanlianTypeDefaults pins the `type: shanlian` translation: the
// vendor type implies both the "#sl" password form and the vendor credential
// scheme, while an explicit `password-mode:` in the node wins.
func TestApplyShanlianTypeDefaults(t *testing.T) {
	option := &AnyTLSOption{Password: "720a437f4beb4fb9915f7f913d7bc9f7"}
	option.ApplyShanlianTypeDefaults()
	if option.PasswordMode != ShanlianPasswordMode {
		t.Fatalf("password-mode = %q, want %q", option.PasswordMode, ShanlianPasswordMode)
	}
	if !strings.HasSuffix(option.Password, "#sl") {
		t.Fatalf("password = %q, want the #sl marker appended", option.Password)
	}

	explicit := &AnyTLSOption{Password: shanlianKey64() + "#SL", PasswordMode: "custom"}
	explicit.ApplyShanlianTypeDefaults()
	if explicit.PasswordMode != "custom" {
		t.Fatalf("explicit password-mode was overwritten: %q", explicit.PasswordMode)
	}
	if explicit.Password != shanlianKey64()+"#SL" {
		t.Fatalf("password marker was rewritten: %q", explicit.Password)
	}
}

func shanlianKey64() string {
	return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
