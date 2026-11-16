package outbound

import (
	"strings"

	"github.com/metacubex/sing-shadowsocks2/shadowaead_2022"
	"github.com/metacubex/sing-shadowsocks2/shadowstream"
)

// blackstoneCiphers lists the shadowsocks methods the blackstone-over-SS
// variant implements: the 2022 AEAD family (magic code injected after the fixed
// length request header) and the legacy stream family (35 byte plaintext header
// instead of a bare salt). The classic AEAD family (aes-*-gcm,
// chacha20-ietf-poly1305) has no blackstone wire, so a marker on such a node
// would derive the key from a password that still contains "#BLACKSTONE" and
// fail authentication on the server with no local error.
//
// The lists are taken from the fork itself so they cannot drift.
func blackstoneCiphers() map[string]struct{} {
	methods := make(map[string]struct{}, len(blackstone2022Methods)+len(blackstoneStreamMethods))
	for _, name := range blackstone2022Methods {
		methods[name] = struct{}{}
	}
	for _, name := range blackstoneStreamMethods {
		methods[name] = struct{}{}
	}
	return methods
}

var (
	blackstone2022Methods   = shadowaead_2022.MethodList
	blackstoneStreamMethods = shadowstream.MethodList
)

// SupportsBlackstoneCipher reports whether a cipher has a blackstone wire in the
// sing-shadowsocks2 fork. Method names are case insensitive, matching the
// registry lookup.
func SupportsBlackstoneCipher(name string) bool {
	_, ok := blackstoneCiphers()[strings.ToLower(name)]
	return ok
}
