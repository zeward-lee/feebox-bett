package adapter

import (
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
	if proxy.Type() != C.AnyTLS {
		t.Fatalf("adapter type = %v, want AnyTLS", proxy.Type())
	}
	if proxy.Addr() != "82.163.67.20:6504" {
		t.Errorf("addr = %q", proxy.Addr())
	}
}

// TestParseAnyTLSWithoutTransportStillWorks guards the zero-impact requirement
// for ordinary Shanlian nodes: no transport block, same adapter as before.
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
}

func TestParseAnyTLSRejectsUnknownTransport(t *testing.T) {
	node := shanlianDedicatedNode()
	node["transport"] = "grpc"
	if _, err := ParseProxy(node); err == nil {
		t.Fatal("unknown transport should fail at parse time")
	}
}
