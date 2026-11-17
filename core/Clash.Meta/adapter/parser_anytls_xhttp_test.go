package adapter

import (
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// shanlianDedicatedNode is the yaml shape the Shanlian generator emits for a
// dedicated line (`_xhttp_` node): anytls plus the vendor xhttp transport. The
// password is masked; the remaining values are the vendor's parameter shape.
func shanlianDedicatedNode() map[string]any {
	return map[string]any{
		"name":             "闪连 🇭🇰 专线",
		"type":             "anytls",
		"server":           "82.163.67.20",
		"port":             6504,
		"password":         "00000000000000000000000000000000",
		"udp":              true,
		"sni":              "v-mirror.byteimg.com",
		"skip-cert-verify": true,
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

func TestParseAnyTLSWithXHTTPTransport(t *testing.T) {
	proxy, err := ParseProxy(shanlianDedicatedNode())
	if err != nil {
		t.Fatalf("parse dedicated node: %v", err)
	}
	defer proxy.Close()
	if proxy.Type() != C.Shanlian {
		t.Fatalf("adapter type = %v, want Shanlian", proxy.Type())
	}
	raw, err := proxy.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"type":"Shanlian"`) {
		t.Fatalf("API identity = %s, want the Shanlian type", raw)
	}
	if proxy.Addr() != "82.163.67.20:6504" {
		t.Errorf("addr = %q", proxy.Addr())
	}
}

// TestParseAnyTLSWithV2RayXHTTPTransportSpelling pins the second spelling of
// the same transport option: the wire is identical, so the identity is too.
func TestParseAnyTLSWithV2RayXHTTPTransportSpelling(t *testing.T) {
	node := shanlianDedicatedNode()
	node["transport"] = "v2rayxhttp"
	proxy, err := ParseProxy(node)
	if err != nil {
		t.Fatalf("parse dedicated node: %v", err)
	}
	defer proxy.Close()
	if proxy.Type() != C.Shanlian {
		t.Fatalf("adapter type = %v, want Shanlian", proxy.Type())
	}
}

// TestParseAnyTLSWithoutTransportStillWorks guards the zero-impact requirement
// for ordinary Shanlian nodes: no transport block, same adapter as before. The
// password is the vendor's 32 hex key with no "#sl" marker, which must stay
// AnyTLS — only the dedicated-line shape reports the Shanlian identity.
func TestParseAnyTLSWithoutTransportStillWorks(t *testing.T) {
	node := shanlianDedicatedNode()
	delete(node, "transport")
	delete(node, "xhttp-opts")
	proxy, err := ParseProxy(node)
	if err != nil {
		t.Fatalf("parse plain dedicated node: %v", err)
	}
	defer proxy.Close()
	if proxy.Type() != C.AnyTLS {
		t.Errorf("adapter type = %v, want AnyTLS", proxy.Type())
	}
	raw, err := proxy.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"type":"AnyTLS"`) {
		t.Errorf("API identity = %s, want the AnyTLS type", raw)
	}
}

func TestParseAnyTLSRejectsUnknownTransport(t *testing.T) {
	node := shanlianDedicatedNode()
	node["transport"] = "grpc"
	if _, err := ParseProxy(node); err == nil {
		t.Fatal("unknown transport should fail at parse time")
	}
}

// TestParseAnyTLSXHTTPRequiresObfsKey pins the fail-closed contract on the yaml
// surface: a dedicated line without `obfs-key` must be refused when the profile
// is parsed, never silently dialed in cleartext. An explicit `obfs-key: ""` is
// the documented opt-out and must still parse.
func TestParseAnyTLSXHTTPRequiresObfsKey(t *testing.T) {
	node := shanlianDedicatedNode()
	opts := node["xhttp-opts"].(map[string]any)
	delete(opts, "obfs-key")
	if _, err := ParseProxy(node); err == nil || !strings.Contains(err.Error(), "obfs-key is required for v2rayxhttp transport") {
		t.Fatalf("parse error = %v, want the obfs-key required error", err)
	}

	node = shanlianDedicatedNode()
	node["xhttp-opts"].(map[string]any)["obfs-key"] = ""
	proxy, err := ParseProxy(node)
	if err != nil {
		t.Fatalf("explicit obfs opt-out should parse: %v", err)
	}
	proxy.Close()
}
