package adapter

import (
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// heysocks masks: the fixtures below follow the two real HeySocks node shapes on
// this machine, with the credential replaced by a synthetic transport password.
//
//   - the app-side / memory-extracted node JSON: `clover: <gateway>` plus
//     `encryption: fake-net`;
//   - the downloadable subscription: `gateway: <host:port>` plus `sess`/`auth`
//     (the 82 HeySocks nodes in profiles/1794900000005.yaml are all this shape
//     and none of them carries `clover`).
//
// Both carry `cipher: aes-128-ctr`, `fake-net.tcp` and `padding-len: 8-64`.
const (
	fixtureHeySocksPassword = "synthetic-secret:0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	fixtureHeySocksFakeNet  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// heysocksCloverNode is the app-extracted shape.
func heysocksCloverNode() map[string]any {
	return map[string]any{
		"name":        "HeySocks clover fixture",
		"type":        "xhttp",
		"server":      "edge.example",
		"port":        10007,
		"password":    fixtureHeySocksPassword,
		"cipher":      "aes-128-ctr",
		"padding-len": "8-64",
		"udp":         false,
		"clover":      "203.0.113.7",
		"encryption":  "fake-net",
		"fake-net": map[string]any{
			"tcp": fixtureHeySocksFakeNet,
		},
	}
}

// heysocksSubscriptionNode is the downloadable-subscription shape.
func heysocksSubscriptionNode() map[string]any {
	return map[string]any{
		"name":        "HeySocks subscription fixture",
		"type":        "xhttp",
		"server":      "edge.example",
		"port":        10025,
		"password":    fixtureHeySocksPassword,
		"auth":        "synthetic-auth-token",
		"cipher":      "aes-128-ctr",
		"padding-len": "8-64",
		"udp":         false,
		"gateway":     "edge.example:10025",
		"sess":        fixtureHeySocksFakeNet,
		"fake-net": map[string]any{
			"tcp": fixtureHeySocksFakeNet,
		},
	}
}

// plainXhttpNode is an ordinary `type: xhttp` node: no gateway marker of either
// spelling.
func plainXhttpNode() map[string]any {
	return map[string]any{
		"name":     "Plain xhttp fixture",
		"type":     "xhttp",
		"server":   "edge.example",
		"port":     443,
		"password": fixtureHeySocksPassword,
		"cipher":   "aes-128-ctr",
	}
}

func TestParseHeysocksIdentity(t *testing.T) {
	cases := []struct {
		name    string
		mapping map[string]any
		want    C.AdapterType
	}{
		// Heysocks: both real shapes report the site identity.
		{name: "clover app shape", mapping: heysocksCloverNode(), want: C.Heysocks},
		{name: "gateway subscription shape", mapping: heysocksSubscriptionNode(), want: C.Heysocks},
		// The encryption tag alone is the documented auxiliary marker.
		{
			name: "encryption fake-net only",
			mapping: map[string]any{
				"name":       "HeySocks encryption fixture",
				"type":       "xhttp",
				"server":     "edge.example",
				"port":       443,
				"password":   fixtureHeySocksPassword,
				"cipher":     "aes-128-ctr",
				"encryption": "fake-net",
			},
			want: C.Heysocks,
		},
		// Plain xhttp keeps the plain identity, even when the transport itself
		// carries a fake-net block: that layout is not an identity marker.
		{name: "plain xhttp", mapping: plainXhttpNode(), want: C.XHttp},
		{
			name: "plain xhttp with fake-net",
			mapping: map[string]any{
				"name":        "Plain xhttp fake-net fixture",
				"type":        "xhttp",
				"server":      "edge.example",
				"port":        443,
				"password":    fixtureHeySocksPassword,
				"cipher":      "aes-128-ctr",
				"padding-len": "8-64",
				"fake-net": map[string]any{
					"tcp": fixtureHeySocksFakeNet,
				},
			},
			want: C.XHttp,
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

// TestHeysocksAndXhttpAreDistinctIdentities is the anti-merge guard: the two
// types must have different names and different enum values, so the API never
// conflates the site identity with the generic protocol name.
func TestHeysocksAndXhttpAreDistinctIdentities(t *testing.T) {
	if C.Heysocks == C.XHttp {
		t.Fatal("Heysocks and XHttp must not be the same AdapterType value")
	}
	if got := C.Heysocks.String(); got != "Heysocks" {
		t.Fatalf("C.Heysocks.String() = %q, want Heysocks", got)
	}
	if got := C.XHttp.String(); got != "XHttp" {
		t.Fatalf("C.XHttp.String() = %q, want XHttp", got)
	}
}
