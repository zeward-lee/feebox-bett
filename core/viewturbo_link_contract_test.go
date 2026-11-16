package main

// ViewTurbo (`#VT`) and blackstone (`#BLACKSTONE`) are implemented as a local
// fork of sing-shadowsocks2 that lives at core/sing-shadowsocks2.
//
// A replace directive in the DEPENDENCY's go.mod is ignored: only the main
// module's replaces apply. The module compiled into the shipped library is
// `core`, not `core/Clash.Meta`, so core/go.mod must carry
//     replace github.com/metacubex/sing-shadowsocks2 => ./sing-shadowsocks2
// This contract fails loudly if that replace is ever dropped: without it every
// ViewTurbo node silently falls back to a plain shadowsocks handshake (no fake
// HTTP header, no token block, no salt inversion), the server rejects the
// stream, and the node carries no traffic.

import (
	"fmt"
	"strings"
	"testing"

	shadowsocks "github.com/metacubex/sing-shadowsocks2"
)

// viewTurboCipher matches the cipher ViewTurbo subscriptions ship.
const viewTurboCipher = "chacha20-ietf-poly1305"

// TestViewTurboWrapperIsLinkedIntoCoreModule asserts that the ViewTurbo method
// wrapper is reachable from the `core` main module.
func TestViewTurboWrapperIsLinkedIntoCoreModule(t *testing.T) {
	method, err := shadowsocks.CreateMethod(viewTurboCipher, shadowsocks.MethodOptions{
		Password: "contract-token#VT",
	})
	if err != nil {
		t.Fatalf("CreateMethod(%s) with a #VT password failed: %v", viewTurboCipher, err)
	}
	if typeName := fmt.Sprintf("%T", method); !strings.Contains(typeName, "viewTurbo") {
		t.Fatalf(
			"ViewTurbo wrapper is NOT linked into the core module: CreateMethod returned %s.\n"+
				"The core module resolves github.com/metacubex/sing-shadowsocks2 to the upstream\n"+
				"proxy cache instead of ./sing-shadowsocks2. core/go.mod must contain:\n"+
				"    replace github.com/metacubex/sing-shadowsocks2 => ./sing-shadowsocks2",
			typeName,
		)
	}
}

// TestNonViewTurboPasswordKeepsUpstreamMethod guards the other direction: the
// wrapper must not swallow ordinary Shadowsocks nodes.
func TestNonViewTurboPasswordKeepsUpstreamMethod(t *testing.T) {
	method, err := shadowsocks.CreateMethod(viewTurboCipher, shadowsocks.MethodOptions{
		Password: "an-ordinary-shadowsocks-password",
	})
	if err != nil {
		t.Fatalf("CreateMethod(%s) with a plain password failed: %v", viewTurboCipher, err)
	}
	if typeName := fmt.Sprintf("%T", method); strings.Contains(typeName, "viewTurbo") {
		t.Fatalf("plain Shadowsocks nodes must not be wrapped in the ViewTurbo transport, got %s", typeName)
	}
}

// TestBlackstonePasswordReachesTheFork key material is decoded from the password
// with the marker stripped; if the fork is not linked the marker would end up in
// the key and the node would fail authentication.
func TestBlackstonePasswordReachesTheFork(t *testing.T) {
	if _, err := shadowsocks.CreateMethod("2022-blake3-aes-128-gcm", shadowsocks.MethodOptions{
		Password: "MDEyMzQ1Njc4OWFiY2RlZg==#BLACKSTONE",
	}); err != nil {
		t.Fatalf("CreateMethod with a #BLACKSTONE password failed: %v", err)
	}
}
