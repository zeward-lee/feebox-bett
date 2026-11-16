package adapter

import (
	"testing"

	"github.com/metacubex/mihomo/common/yaml"
	C "github.com/metacubex/mihomo/constant"
)

func TestParseFastupTrojanForcesH2Mux(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "Fastup fixture",
		"type":     "trojan",
		"server":   "node.example",
		"port":     443,
		"password": "synthetic-password#fastup",
		"mpw":      "rotated-mpw",
		"sni":      "www.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if !proxy.ProxyInfo().SMUX {
		t.Fatal("Fastup Trojan was not wrapped with sing-mux")
	}
}

func TestParseStandardTrojanDoesNotForceMux(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "Standard fixture",
		"type":     "trojan",
		"server":   "node.example",
		"port":     443,
		"password": "ordinary-password",
		"mpw":      "must-be-ignored",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if proxy.ProxyInfo().SMUX {
		t.Fatal("standard Trojan was forced into sing-mux")
	}
}

// A Fastup node that turns the per-proxy smux block off must ride the plain
// trojan wire while still reporting the vendor identity: MTProto breaks behind
// the forced h2mux on some servers and this is the escape hatch.
func TestParseFastupTrojanMuxOptOut(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "Fastup opt-out fixture",
		"type":     "trojan",
		"server":   "node.example",
		"port":     443,
		"password": "synthetic-password#fastup",
		"mpw":      "rotated-mpw",
		"smux": map[string]any{
			"enabled": false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if proxy.ProxyInfo().SMUX {
		t.Fatal("opt-out Fastup Trojan was still wrapped with sing-mux")
	}
	if got := proxy.Type(); got != C.Fastup {
		t.Fatalf("type = %v, want %v", got, C.Fastup)
	}
}

func TestParseFastupTypeMuxOptOut(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "Fastup type opt-out fixture",
		"type":     "fastup",
		"server":   "node.example",
		"port":     443,
		"password": "synthetic-password",
		"mpw":      "rotated-mpw",
		"smux": map[string]any{
			"enabled": false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if proxy.ProxyInfo().SMUX {
		t.Fatal("opt-out type: fastup node was still wrapped with sing-mux")
	}
	if got := proxy.Type(); got != C.Fastup {
		t.Fatalf("type = %v, want %v", got, C.Fastup)
	}
}

// `mux: false` is the Fastup-only shorthand for the same opt-out.
func TestParseFastupTypeMuxShorthandOptOut(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "Fastup mux shorthand fixture",
		"type":     "fastup",
		"server":   "node.example",
		"port":     443,
		"password": "synthetic-password",
		"mpw":      "rotated-mpw",
		"mux":      false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if proxy.ProxyInfo().SMUX {
		t.Fatal("mux: false did not opt the Fastup node out of sing-mux")
	}
	if got := proxy.Type(); got != C.Fastup {
		t.Fatalf("type = %v, want %v", got, C.Fastup)
	}
}

// The API exposes ProxyInfo.SMUX as `smux: <bool>`; a profile built from that
// JSON must keep the opt-out instead of silently regaining the forced session.
func TestParseFastupTypeMuxOptOutFromBoolSmux(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "Fastup bool smux fixture",
		"type":     "fastup",
		"server":   "node.example",
		"port":     443,
		"password": "synthetic-password",
		"mpw":      "rotated-mpw",
		"smux":     false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if proxy.ProxyInfo().SMUX {
		t.Fatal("smux: false did not opt the Fastup node out of sing-mux")
	}
	if got := proxy.Type(); got != C.Fastup {
		t.Fatalf("type = %v, want %v", got, C.Fastup)
	}
}

// The switch has to survive the real config path: RawConfig keeps `proxies` as
// []map[string]any decoded by common/yaml, so the nested smux block must still
// arrive as a map and not as a string or bool.
func TestParseFastupMuxOptOutFromYAML(t *testing.T) {
	var nodes []map[string]any
	err := yaml.Unmarshal([]byte(`
- name: "Fastup HK opt-out"
  type: fastup
  server: node.example
  port: 443
  password: synthetic-password
  mpw: rotated-mpw
  sni: www.example.com
  smux:
    enabled: false
`), &nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("decoded %d nodes, want 1", len(nodes))
	}
	proxy, err := ParseProxy(nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if proxy.ProxyInfo().SMUX {
		t.Fatal("YAML-configured Fastup node ignored its smux opt-out")
	}
	if got := proxy.Type(); got != C.Fastup {
		t.Fatalf("type = %v, want %v", got, C.Fastup)
	}
}

// Default behaviour stays vendor-faithful: type: fastup with no opt-out key
// keeps the forced h2mux session, and a smux block that merely enables mux does
// not replace it with a second wrapper.
func TestParseFastupTypeDefaultsToForcedMux(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "Fastup default fixture",
		"type":     "fastup",
		"server":   "node.example",
		"port":     443,
		"password": "synthetic-password",
		"mpw":      "rotated-mpw",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if !proxy.ProxyInfo().SMUX {
		t.Fatal("type: fastup lost its forced sing-mux session")
	}
	if got := proxy.Type(); got != C.Fastup {
		t.Fatalf("type = %v, want %v", got, C.Fastup)
	}
}

func TestParseFastupTypeIgnoresEnabledSmuxBlock(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "Fastup enabled smux fixture",
		"type":     "fastup",
		"server":   "node.example",
		"port":     443,
		"password": "synthetic-password",
		"mpw":      "rotated-mpw",
		"smux": map[string]any{
			"enabled":  true,
			"protocol": "smux",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if !proxy.ProxyInfo().SMUX {
		t.Fatal("type: fastup with an enabled smux block lost its mux session")
	}
}
