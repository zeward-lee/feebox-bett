package adapter

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// TestParseX365ProxyUDPFlag covers the subscription shape of the flclash-private
// x365 nodes: type/server/port/uuid/servername/client-fingerprint/reality-opts/
// xhttp-opts plus an explicit `udp` flag. Every node in the live subscription
// sets `udp: false`, so the parser must keep UDP off unless it is turned on.
func TestParseX365ProxyUDPFlag(t *testing.T) {
	for _, test := range []struct {
		name    string
		udp     any
		wantUDP bool
	}{
		{"udp false", false, false},
		{"udp true", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			proxy, err := ParseProxy(map[string]any{
				"name":               "x365 fixture",
				"type":               "x365",
				"server":             "bgp01.example",
				"port":               443,
				"uuid":               "c5f1a574-20a8-4f06-8880-2ae7a4af2f7e",
				"servername":         "updates.example",
				"client-fingerprint": "chrome",
				"udp":                test.udp,
				"reality-opts": map[string]any{
					"public-key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
					"short-id":   "0123abcd",
				},
				"xhttp-opts": map[string]any{"host": "updates.example", "path": "/hk", "mode": "stream-one"},
			})
			if err != nil {
				t.Fatalf("ParseProxy: %v", err)
			}
			defer proxy.Close()

			if proxy.Type() != C.X365 {
				t.Fatalf("type = %v, want %v", proxy.Type(), C.X365)
			}
			if proxy.SupportUDP() != test.wantUDP {
				t.Fatalf("SupportUDP = %v, want %v", proxy.SupportUDP(), test.wantUDP)
			}
			if !proxy.SupportUOT() {
				t.Fatal("SupportUOT should be true for x365")
			}
		})
	}
}
