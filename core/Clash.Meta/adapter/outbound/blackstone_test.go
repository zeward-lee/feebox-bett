package outbound

import (
	"testing"

	"github.com/metacubex/sing-shadowsocks2/shadowaead_2022"
	"github.com/metacubex/sing-shadowsocks2/shadowstream"
)

// TestSupportsBlackstoneCipherFollowsTheFork pins the guard against drift: every
// method the fork implements a blackstone wire for must be accepted, and the
// classic AEAD family (which has none) must be rejected.
func TestSupportsBlackstoneCipherFollowsTheFork(t *testing.T) {
	for _, name := range shadowstream.MethodList {
		if !SupportsBlackstoneCipher(name) {
			t.Errorf("stream method %q is not accepted", name)
		}
	}
	for _, name := range shadowaead_2022.MethodList {
		if !SupportsBlackstoneCipher(name) {
			t.Errorf("2022 method %q is not accepted", name)
		}
	}
	for _, name := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-unknown"} {
		if SupportsBlackstoneCipher(name) {
			t.Errorf("method %q without a blackstone wire is accepted", name)
		}
	}
}
