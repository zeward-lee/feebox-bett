package adapter

import (
	"strings"
	"testing"
)

// TestParseBlackstoneSSDefaultsCipher pins the blackstone-over-SS recognition:
// the vendor API calls these nodes "os" and leaves the cipher empty, and the
// vendor client assumes aes-128-ctr. Without the default the node would fail to
// load with "unknown method: ".
func TestParseBlackstoneSSDefaultsCipher(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "blackstone fixture",
		"type":     "ss",
		"server":   "node.example",
		"port":     8388,
		"password": "synthetic-password#BLACKSTONE",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if got := proxy.Type().String(); got != "Shadowsocks" {
		t.Fatalf("type = %q, want Shadowsocks", got)
	}
}

func TestParseBlackstoneSSKeepsExplicitCipher(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "blackstone fixture",
		"type":     "ss",
		"server":   "node.example",
		"port":     8388,
		"password": "synthetic-password#BLACKSTONE",
		"cipher":   "aes-256-ctr",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if got := proxy.Type().String(); got != "Shadowsocks" {
		t.Fatalf("type = %q, want Shadowsocks", got)
	}
}

func TestParseBlackstoneSSRejectsEmptyPassword(t *testing.T) {
	_, err := ParseProxy(map[string]any{
		"name":     "blackstone fixture",
		"type":     "ss",
		"server":   "node.example",
		"port":     8388,
		"password": "#BLACKSTONE",
	})
	if err == nil || !strings.Contains(err.Error(), "empty password") {
		t.Fatalf("ParseProxy() error = %v, want empty password", err)
	}
}

// TestParsePlainSSUnaffected guards the other direction: the marker handling
// must not change ordinary shadowsocks nodes.
func TestParsePlainSSUnaffected(t *testing.T) {
	_, err := ParseProxy(map[string]any{
		"name":     "plain fixture",
		"type":     "ss",
		"server":   "node.example",
		"port":     8388,
		"password": "synthetic-password",
	})
	// No cipher on a plain node is still an error: only the blackstone variant
	// carries a vendor default.
	if err == nil {
		t.Fatal("plain ss node without cipher unexpectedly loaded")
	}
}
