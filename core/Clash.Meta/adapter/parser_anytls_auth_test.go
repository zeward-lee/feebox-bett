package adapter

import (
	"strings"
	"testing"
)

// plainHexPasswordFixture is the vendor bare 32 hex password form: it
// hex-decodes to a 16 byte key. It is not a real secret.
const plainHexPasswordFixture = "720a437f4beb4fb9915f7f913d7bc9f7"

// TestParsePlainAnyTLS32HexPasswordStaysStandard is the parser-level reverse
// verification for the confirmed P1: an ordinary `type: anytls` node whose
// password happens to be 32 hex characters must stay a standard anytls node.
// It must parse without error (the vendor derivation used to fire silently),
// and it must not be forced into the vendor scheme.
func TestParsePlainAnyTLS32HexPasswordStaysStandard(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "ordinary anytls with hex-looking password",
		"type":     "anytls",
		"server":   "node.example",
		"port":     443,
		"password": plainHexPasswordFixture,
	})
	if err != nil {
		t.Fatalf("plain anytls node with a 32 hex password was rejected: %v", err)
	}
	proxy.Close()

	// A typo in the selector must fail closed at config load instead of falling
	// back to standard anytls (which would hide the misconfiguration).
	_, err = ParseProxy(map[string]any{
		"name":          "bad password-mode",
		"type":          "anytls",
		"server":        "node.example",
		"port":          443,
		"password":      plainHexPasswordFixture,
		"password-mode": "standard",
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported password-mode") {
		t.Fatalf("ParseProxy(password-mode=standard) error = %v, want unsupported password-mode", err)
	}

	// The explicit marker keeps working on a plain anytls node (the generator
	// spelling the profile uses).
	marked, err := ParseProxy(map[string]any{
		"name":          "marked anytls",
		"type":          "anytls",
		"server":        "node.example",
		"port":          443,
		"password":      plainHexPasswordFixture,
		"password-mode": "raw16",
	})
	if err != nil {
		t.Fatalf("anytls node with password-mode: raw16 was rejected: %v", err)
	}
	marked.Close()
}

// TestParseShanlianTypeKeepsExplicitPasswordMode pins that `type: shanlian`
// still honors an explicit `password-mode:` value instead of overwriting it (so
// a hand-written node can opt out), while an unknown value is rejected rather
// than ignored.
func TestParseShanlianTypeKeepsExplicitPasswordMode(t *testing.T) {
	if _, err := ParseProxy(map[string]any{
		"name":          "shanlian with explicit unknown mode",
		"type":          "shanlian",
		"server":        "node.example",
		"port":          443,
		"password":      fixtureShanlianKey,
		"password-mode": "standard",
	}); err == nil || !strings.Contains(err.Error(), "unsupported password-mode") {
		t.Fatalf("shanlian node with password-mode=standard error = %v, want unsupported password-mode", err)
	}
}
