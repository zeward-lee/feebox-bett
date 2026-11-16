package adapter

import (
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// 64 hex characters: the Shanlian direct-authentication key.
const fixtureShanlianKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestParseShanlianTypeIdentity(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "Shanlian fixture",
		"type":     "shanlian",
		"server":   "node.example",
		"port":     443,
		"password": fixtureShanlianKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	if got := proxy.Type(); got != C.Shanlian {
		t.Fatalf("type = %v, want %v", got, C.Shanlian)
	}
	raw, err := proxy.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"type":"Shanlian"`) {
		t.Fatalf("API identity = %s, want the Shanlian type", raw)
	}
}

func TestParseShanlianTypeAcceptsMarker(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "Shanlian marker fixture",
		"type":     "shanlian",
		"server":   "node.example",
		"port":     443,
		"password": fixtureShanlianKey + "#SL",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if got := proxy.Type(); got != C.Shanlian {
		t.Fatalf("type = %v, want %v", got, C.Shanlian)
	}
}

func TestParseShanlianTypeFailsClosedOnMalformedKey(t *testing.T) {
	_, err := ParseProxy(map[string]any{
		"name":     "Shanlian broken fixture",
		"type":     "shanlian",
		"server":   "node.example",
		"port":     443,
		"password": "not-a-hex-key",
	})
	if err == nil {
		t.Fatal("malformed Shanlian key was accepted")
	}
	if !strings.Contains(err.Error(), "Shanlian") {
		t.Fatalf("error = %v, want the Shanlian validation error", err)
	}
}

func TestParseFastupTypeIdentity(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "Fastup fixture",
		"type":     "fastup",
		"server":   "node.example",
		"port":     443,
		"password": "synthetic-password",
		"sni":      "www.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	if got := proxy.Type(); got != C.Fastup {
		t.Fatalf("type = %v, want %v", got, C.Fastup)
	}
	if !proxy.ProxyInfo().SMUX {
		t.Fatal("Fastup type was not wrapped with sing-mux")
	}
	raw, err := proxy.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"type":"Fastup"`) {
		t.Fatalf("API identity = %s, want the Fastup type", raw)
	}
}

func TestParseFastupTypeAcceptsMarker(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "Fastup marker fixture",
		"type":     "fastup",
		"server":   "node.example",
		"port":     443,
		"password": "synthetic-password#fastup",
		"mpw":      "rotated-mpw",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if got := proxy.Type(); got != C.Fastup {
		t.Fatalf("type = %v, want %v", got, C.Fastup)
	}
	if !proxy.ProxyInfo().SMUX {
		t.Fatal("Fastup type was not wrapped with sing-mux")
	}
}

func TestParseOldFormsKeepBaseIdentity(t *testing.T) {
	anytlsProxy, err := ParseProxy(map[string]any{
		"name":     "Old anytls fixture",
		"type":     "anytls",
		"server":   "node.example",
		"port":     443,
		"password": fixtureShanlianKey + "#SL",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer anytlsProxy.Close()
	if got := anytlsProxy.Type(); got != C.AnyTLS {
		t.Fatalf("legacy anytls type = %v, want %v", got, C.AnyTLS)
	}

	trojanProxy, err := ParseProxy(map[string]any{
		"name":     "Old trojan fixture",
		"type":     "trojan",
		"server":   "node.example",
		"port":     443,
		"password": "synthetic-password#fastup",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer trojanProxy.Close()
	if got := trojanProxy.Type(); got != C.Trojan {
		t.Fatalf("legacy trojan type = %v, want %v", got, C.Trojan)
	}
}
