package config

import "testing"

// TestProcessNinjaObfuscationKeepsNodeOnDecodeFailure guards the regression
// where a plaintext "type: ninja" node (marked tls: true by the provider) lost
// its tls flag because restoreNinjaNode failed and the caller deleted it.
func TestProcessNinjaObfuscationKeepsNodeOnDecodeFailure(t *testing.T) {
	proxies := []map[string]any{
		{
			"type":          "ninja",
			"name":          "plain-node",
			"server":        "plain.example.com",
			"port":          23011,
			"tls":           true,
			"password":      "6ccdeec2-be60-4195-8740-a3661cd087a1",
			"node-password": "BRYjC2p2nj8eEMy5",
		},
	}
	// The label before the first dot is shorter than the 8 byte minimum, so
	// restoreNinjaNode must fail deterministically.
	if err := restoreNinjaNode(proxies[0]); err == nil {
		t.Fatal("expected restoreNinjaNode to fail on a plaintext node")
	}
	ProcessNinjaObfuscation(proxies, nil)

	p := proxies[0]
	tls, _ := p["tls"].(bool)
	if !tls {
		t.Fatal("tls flag was dropped when decoding failed")
	}
	if got := ninjaStr(p, "server"); got != "plain.example.com" {
		t.Fatalf("server changed to %q", got)
	}
	if got := ninjaStr(p, "node-password"); got != "BRYjC2p2nj8eEMy5" {
		t.Fatalf("node-password changed to %q", got)
	}
	if port, ok := ninjaInt(p, "port"); !ok || port != 23011 {
		t.Fatalf("port changed to %v (ok=%v)", port, ok)
	}
}
