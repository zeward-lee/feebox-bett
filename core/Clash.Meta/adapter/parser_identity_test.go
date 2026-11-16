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

// The old spellings (`type: trojan` + password#fastup, `type: anytls` +
// password#SL) keep working and now report the vendor identity, so a node
// generated before the generator emitted `type: fastup` still shows FastUP.
func TestParseMarkerFormsReportVendorIdentity(t *testing.T) {
	trojanProxy, err := ParseProxy(map[string]any{
		"name":     "Marker trojan fixture",
		"type":     "trojan",
		"server":   "node.example",
		"port":     443,
		"password": "synthetic-password#fastup",
		"sni":      "www.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer trojanProxy.Close()
	if got := trojanProxy.Type(); got != C.Fastup {
		t.Fatalf("marker trojan type = %v, want %v", got, C.Fastup)
	}
	if !trojanProxy.ProxyInfo().SMUX {
		t.Fatal("marker trojan was not wrapped with sing-mux")
	}
	raw, err := trojanProxy.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"type":"Fastup"`) {
		t.Fatalf("API identity = %s, want the Fastup type", raw)
	}

	anytlsProxy, err := ParseProxy(map[string]any{
		"name":     "Marker anytls fixture",
		"type":     "anytls",
		"server":   "node.example",
		"port":     443,
		"password": fixtureShanlianKey + "#SL",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer anytlsProxy.Close()
	if got := anytlsProxy.Type(); got != C.Shanlian {
		t.Fatalf("marker anytls type = %v, want %v", got, C.Shanlian)
	}
	raw, err = anytlsProxy.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"type":"Shanlian"`) {
		t.Fatalf("API identity = %s, want the Shanlian type", raw)
	}
}

// A node without the marker keeps the base protocol identity and is not forced
// into sing-mux: only the Fastup marker means the variant.
func TestParseUnmarkedNodesKeepBaseIdentity(t *testing.T) {
	anytlsProxy, err := ParseProxy(map[string]any{
		"name":     "Plain anytls fixture",
		"type":     "anytls",
		"server":   "node.example",
		"port":     443,
		"password": "ordinary-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer anytlsProxy.Close()
	if got := anytlsProxy.Type(); got != C.AnyTLS {
		t.Fatalf("plain anytls type = %v, want %v", got, C.AnyTLS)
	}

	trojanProxy, err := ParseProxy(map[string]any{
		"name":     "Plain trojan fixture",
		"type":     "trojan",
		"server":   "node.example",
		"port":     443,
		"password": "ordinary-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer trojanProxy.Close()
	if got := trojanProxy.Type(); got != C.Trojan {
		t.Fatalf("plain trojan type = %v, want %v", got, C.Trojan)
	}
	if trojanProxy.ProxyInfo().SMUX {
		t.Fatal("plain trojan was wrapped with sing-mux")
	}
}

// The borrow-shell identities: every vendor variant that reuses another
// protocol's wire but carries its own name must report that name, because the
// UI maps the reported type to the protocol's own label (ViewTurbo、黑石、OIX、
// X365、Juzi、Pure).
func TestParseBorrowShellIdentities(t *testing.T) {
	cases := []struct {
		name    string
		mapping map[string]any
		want    C.AdapterType
	}{
		{
			// ss + password ending in #VT is the ViewTurbo variant.
			name: "ss viewturbo",
			mapping: map[string]any{
				"name":     "ViewTurbo fixture",
				"type":     "ss",
				"server":   "node.example",
				"port":     8388,
				"password": "synthetic-token#VT",
				"cipher":   "chacha20-ietf-poly1305",
			},
			want: C.ViewTurbo,
		},
		{
			// ss + password ending in #BLACKSTONE is the blackstone variant; the
			// parser also defaults its cipher, so the marker alone is enough.
			name: "ss blackstone",
			mapping: map[string]any{
				"name":     "Blackstone fixture",
				"type":     "ss",
				"server":   "node.example",
				"port":     8388,
				"password": "synthetic-password#BLACKSTONE",
			},
			want: C.Blackstone,
		},
		{
			// snell + psk ending in #oix is the OIX variant.
			name: "snell oix",
			mapping: map[string]any{
				"name":   "OIX fixture",
				"type":   "snell",
				"server": "node.example",
				"port":   8388,
				"psk":    "synthetic-psk#oix",
			},
			want: C.OIX,
		},
		{
			// vless + uuid ending in #x365 selects the x365 request format.
			name: "vless x365",
			mapping: map[string]any{
				"name":   "X365 fixture",
				"type":   "vless",
				"server": "node.example",
				"port":   443,
				"uuid":   "00112233-4455-6677-8899-aabbccddeeff#x365",
			},
			want: C.X365,
		},
		{
			// vless + uuid ending in #juzi adds the 8 byte HMAC tag; the tag of
			// this fixture uuid is cadf5ab2d76ecb6c.
			name: "vless juzi",
			mapping: map[string]any{
				"name":   "Juzi fixture",
				"type":   "vless",
				"server": "node.example",
				"port":   443,
				"uuid":   "6ac24745-6118-1ce8-57da-1aab6a9b7b56#juzi",
			},
			want: C.Juzi,
		},
		{
			// vless + uuid ending in #pure replaces the request entirely; a Pure
			// node is TLS WebSocket only.
			name: "vless pure",
			mapping: map[string]any{
				"name":    "Pure fixture",
				"type":    "vless",
				"server":  "node.example",
				"port":    443,
				"uuid":    "00112233-4455-6677-8899-aabbccddeeff#pure",
				"tls":     true,
				"network": "ws",
			},
			want: C.Pure,
		},
		{
			// A node without a marker keeps the base protocol identity.
			name: "plain ss",
			mapping: map[string]any{
				"name":     "Plain ss fixture",
				"type":     "ss",
				"server":   "node.example",
				"port":     8388,
				"password": "ordinary-password",
				"cipher":   "aes-128-gcm",
			},
			want: C.Shadowsocks,
		},
		{
			name: "plain snell",
			mapping: map[string]any{
				"name":   "Plain snell fixture",
				"type":   "snell",
				"server": "node.example",
				"port":   8388,
				"psk":    "ordinary-psk",
			},
			want: C.Snell,
		},
		{
			name: "plain vless",
			mapping: map[string]any{
				"name":   "Plain vless fixture",
				"type":   "vless",
				"server": "node.example",
				"port":   443,
				"uuid":   "00112233-4455-6677-8899-aabbccddeeff",
			},
			want: C.Vless,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxy, err := ParseProxy(tc.mapping)
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			if got := proxy.Type(); got != tc.want {
				t.Fatalf("type = %v, want %v", got, tc.want)
			}
			raw, err := proxy.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			wantJSON := `"type":"` + tc.want.String() + `"`
			if !strings.Contains(string(raw), wantJSON) {
				t.Fatalf("API identity = %s, want %s", raw, wantJSON)
			}
		})
	}
}
