package outbound

import (
	"reflect"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// TestXhttpModeSelection pins which of the two protocol generations a node
// selects: a config blob or a transport password is static, a `node-id` node is
// dynamic (its password is the API token).
func TestXhttpModeSelection(t *testing.T) {
	static, err := NewXHttp(XHttpOption{
		Name:     "static",
		Server:   "192.0.2.10",
		Port:     443,
		Password: "secret:0f1e2d3c4b5a69788796a5b4c3d2e1f0",
	})
	if err != nil {
		t.Fatalf("static node: %v", err)
	}
	if static.IsDynamic() {
		t.Fatal("transport password node reported as dynamic")
	}
	if static.cipher == nil {
		t.Fatal("static node has no transport cipher")
	}

	dynamic, err := NewXHttp(XHttpOption{
		Name:     "dynamic",
		Server:   "192.0.2.11",
		Port:     8443,
		Password: "api-token",
		NodeID:   "node-42",
	})
	if err != nil {
		t.Fatalf("dynamic node: %v", err)
	}
	if !dynamic.IsDynamic() {
		t.Fatal("node-id node reported as static")
	}
	if dynamic.cipher != nil {
		t.Fatal("dynamic node built a static cipher before resolving the API")
	}
	if dynamic.addr != "192.0.2.11:8443" {
		t.Fatalf("dynamic addr = %q, want the configured address", dynamic.addr)
	}
	if dynamic.SupportUOT() {
		t.Fatal("dynamic node claimed UOT support")
	}
}

func TestXhttpRejectsBadNodes(t *testing.T) {
	cases := []struct {
		name   string
		option XHttpOption
		want   string
	}{
		{
			name:   "no colon in transport password",
			option: XHttpOption{Server: "192.0.2.10", Port: 443, Password: "not-a-password"},
			want:   "password",
		},
		{
			name:   "missing server",
			option: XHttpOption{Port: 443, Password: "secret:0f1e2d3c"},
			want:   "server is required",
		},
		{
			name:   "port out of range",
			option: XHttpOption{Server: "192.0.2.10", Port: 70000, Password: "secret:0f1e2d3c"},
			want:   "invalid port",
		},
		{
			name:   "dynamic node without token",
			option: XHttpOption{Server: "192.0.2.10", Port: 443, NodeID: "node-42"},
			want:   "API token",
		},
		{
			name:   "malformed config blob",
			option: XHttpOption{Server: "192.0.2.10", Port: 443, Password: "prefix\nnot*base64"},
			want:   "config",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewXHttp(tc.option); err == nil {
				t.Fatalf("NewXHttp accepted a bad node")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to mention %q", err.Error(), tc.want)
			}
		})
	}
}

// TestXhttpOptionTableKeepsVendorKeys guards the option table against an
// accidental rename: the vendor subscription hands these keys straight through.
func TestXhttpOptionTableKeepsVendorKeys(t *testing.T) {
	want := []string{"name", "server", "port", "password", "node-id", "cipher", "udp", "udp-over-tcp", "udp-over-tcp-version", "padding-len", "fake-net"}
	seen := map[string]bool{}
	typ := reflect.TypeOf(XHttpOption{})
	for i := 0; i < typ.NumField(); i++ {
		if tag := proxyTag(typ.Field(i)); tag != "" {
			seen[tag] = true
		}
	}
	for _, key := range want {
		if !seen[key] {
			t.Errorf("XHttpOption is missing proxy key %q", key)
		}
	}
}

func TestXhttpAdapterType(t *testing.T) {
	x, err := NewXHttp(XHttpOption{
		Name:     "typed",
		Server:   "192.0.2.10",
		Port:     443,
		Password: "secret:0f1e2d3c4b5a69788796a5b4c3d2e1f0",
	})
	if err != nil {
		t.Fatalf("NewXHttp: %v", err)
	}
	if x.Type() != C.XHttp {
		t.Fatalf("type = %v, want C.XHttp", x.Type())
	}
	if got := C.XHttp.String(); got != "XHttp" {
		t.Fatalf("C.XHttp.String() = %q, want XHttp", got)
	}
}

// TestXhttpHeySocksIdentity pins the site identity at the constructor, which is
// the single place the marker is read: Type() and MarshalJSON must agree because
// both read Base.tp.
func TestXhttpHeySocksIdentity(t *testing.T) {
	cases := []struct {
		name string
		opt  XHttpOption
		want C.AdapterType
	}{
		{
			// App-extracted node shape: clover + encryption: fake-net.
			name: "clover",
			opt: XHttpOption{
				Name:       "heysocks clover",
				Server:     "192.0.2.10",
				Port:       10007,
				Password:   "secret:0f1e2d3c4b5a69788796a5b4c3d2e1f0",
				Cipher:     "aes-128-ctr",
				Clover:     "203.0.113.7",
				Encryption: "fake-net",
			},
			want: C.Heysocks,
		},
		{
			// Subscription node shape: gateway + sess/auth, no clover.
			name: "gateway",
			opt: XHttpOption{
				Name:     "heysocks subscription",
				Server:   "192.0.2.10",
				Port:     10025,
				Password: "secret:0f1e2d3c4b5a69788796a5b4c3d2e1f0",
				Cipher:   "aes-128-ctr",
				Gateway:  "192.0.2.10:10025",
			},
			want: C.Heysocks,
		},
		{
			name: "plain xhttp",
			opt: XHttpOption{
				Name:     "plain",
				Server:   "192.0.2.10",
				Port:     443,
				Password: "secret:0f1e2d3c4b5a69788796a5b4c3d2e1f0",
			},
			want: C.XHttp,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x, err := NewXHttp(tc.opt)
			if err != nil {
				t.Fatalf("NewXHttp: %v", err)
			}
			if got := x.Type(); got != tc.want {
				t.Fatalf("type = %v, want %v", got, tc.want)
			}
			raw, err := x.MarshalJSON()
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
