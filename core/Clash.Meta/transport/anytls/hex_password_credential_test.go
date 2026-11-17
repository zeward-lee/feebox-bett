package anytls

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

// officialCapturedCredential is a credential the live Shanlian endpoint
// (tx01.swdzzl.com:6504) accepted during the reverse engineering round: the
// token was recovered from an accepted first packet and matches
// BE64(u*10+1) || BE64(u) for u=1794887296188 (report-lightningx-credential.md
// §3). It is kept here as a byte-for-byte vector for
// deriveHexPasswordCredential, i.e. the Go implementation must reproduce the
// bytes the vendor applyAnyTLSHexPassword (landing_apply.go) writes.
const (
	officialCredentialMillis   = 1794887296188
	officialCredentialHex      = "720a437f4beb4fb9915f7f913d7bc9f7720a532c47d920e0915f7e30dae56d4b"
	officialIndependentMillis  = 1700000000123
	officialIndependentCredHex = "720a437f4beb4fb9915f7f913d7bc9f7720a4c09551d5b76915f7e1af29ea18c"
)

func TestDeriveHexPasswordCredentialMatchesOfficialVector(t *testing.T) {
	raw, err := hex.DecodeString(vendorHexPassword)
	if err != nil {
		t.Fatalf("decode password: %v", err)
	}
	want, err := hex.DecodeString(officialCredentialHex)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	got := deriveHexPasswordCredential(raw, officialCredentialMillis)
	if len(got) != hexPasswordCredentialSize {
		t.Fatalf("credential = %d bytes (%x), want %d", len(got), got, hexPasswordCredentialSize)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("credential = %x, want %x", got, want)
	}
}

// TestDeriveHexPasswordCredentialMatchesIndependentVector pins a second vector
// that was computed by an independent implementation of landing_apply.go, so a
// byte order or offset mistake cannot pass both tests by accident.
func TestDeriveHexPasswordCredentialMatchesIndependentVector(t *testing.T) {
	raw, err := hex.DecodeString(vendorHexPassword)
	if err != nil {
		t.Fatalf("decode password: %v", err)
	}
	want, err := hex.DecodeString(officialIndependentCredHex)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	got := deriveHexPasswordCredential(raw, officialIndependentMillis)
	if !bytes.Equal(got, want) {
		t.Fatalf("credential = %x, want %x", got, want)
	}
}

func TestDeriveHexPasswordCredentialRejectsMalformedKey(t *testing.T) {
	for _, raw := range [][]byte{nil, {}, make([]byte, 15), make([]byte, 17), make([]byte, 32)} {
		if got := deriveHexPasswordCredential(raw, officialCredentialMillis); got != nil {
			t.Fatalf("derive(%d byte key) = %x, want nil", len(raw), got)
		}
	}
}

// TestDeriveHexPasswordCredentialAcceptsAnyTimestamp documents that the server
// only rejects tokens too far in the future, so no local timestamp validation is
// applied and extreme values must not panic.
func TestDeriveHexPasswordCredentialAcceptsAnyTimestamp(t *testing.T) {
	raw, err := hex.DecodeString(vendorHexPassword)
	if err != nil {
		t.Fatalf("decode password: %v", err)
	}
	for _, u := range []int64{0, 1, -1, -1 << 62, 1 << 62} {
		if got := deriveHexPasswordCredential(raw, u); len(got) != hexPasswordCredentialSize {
			t.Fatalf("derive(u=%d) = %x, want %d bytes", u, got, hexPasswordCredentialSize)
		}
	}
}

func TestDecodeHexPasswordKeyFormSelection(t *testing.T) {
	raw, err := hex.DecodeString(vendorHexPassword)
	if err != nil {
		t.Fatalf("decode password: %v", err)
	}
	for _, password := range []string{
		vendorHexPassword,
		"720A437F4BEB4FB9915F7F913D7BC9F7",
	} {
		got, ok := decodeHexPasswordKey(password)
		if !ok {
			t.Fatalf("decodeHexPasswordKey(%q) not accepted", password)
		}
		if !bytes.Equal(got, raw) {
			t.Fatalf("decodeHexPasswordKey(%q) = %x, want %x", password, got, raw)
		}
	}

	notHexPasswords := []string{
		"",                                  // empty
		"720a437f4beb4fb9915f7f913d7bc9f",   // 31 chars
		"720a437f4beb4fb9915f7f913d7bc9f77", // 33 chars
		shanlianFixture,                     // 64 hex chars without the marker
		shanlianFixture + "#sl",             // marker variant
		"720a437f4beb4fb9915f7f913d7bc9fg",  // 32 chars but not hex
		"ordinary-password",
	}
	for _, password := range notHexPasswords {
		if got, ok := decodeHexPasswordKey(password); ok {
			t.Fatalf("decodeHexPasswordKey(%q) = %x, want rejected", password, got)
		}
	}
}

// TestFirstPacketLongHexWithoutMarkerKeepsUpstreamPrefix guards the boundary:
// only the bare 32 hex form switches to the vendor credential, the 64 hex form
// without "#sl" stays an ordinary anytls password (sha256 of the literal).
func TestFirstPacketLongHexWithoutMarkerKeepsUpstreamPrefix(t *testing.T) {
	want := sha256.Sum256([]byte(shanlianFixture))
	assertUpstreamFirstPacket(t, shanlianFixture, want[:])
}

// TestFirstPacketHexPasswordIsRecomputedPerConnection proves that the token is
// derived for every new connection instead of being frozen on the client: two
// connections through the same client, separated by more than a millisecond,
// must carry different tokens both close to the wall clock.
func TestFirstPacketHexPasswordIsRecomputedPerConnection(t *testing.T) {
	raw, err := hex.DecodeString(vendorHexPassword)
	if err != nil {
		t.Fatalf("decode password: %v", err)
	}
	serverTLS, serverName := testServerTLSConfig(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	client := newTestClient(t, vendorHexPassword, listener, serverName)
	defer client.Close()

	first, firstRecords := captureFirstPacketConn(t, client, listener, serverTLS)
	assertFirstPacketLayout(t, first, firstRecords)
	firstMillis := assertDerivedHexCredential(t, first[:sha256.Size], raw)
	assertTimestampMillis(t, firstMillis)

	time.Sleep(25 * time.Millisecond)

	second, secondRecords := captureFirstPacketConn(t, client, listener, serverTLS)
	assertFirstPacketLayout(t, second, secondRecords)
	secondMillis := assertDerivedHexCredential(t, second[:sha256.Size], raw)
	assertTimestampMillis(t, secondMillis)

	if secondMillis <= firstMillis {
		t.Fatalf("credential token not recomputed per connection: first=%d ms, second=%d ms",
			firstMillis, secondMillis)
	}
	if bytes.Equal(first[:sha256.Size], second[:sha256.Size]) {
		t.Fatalf("credential reused across connections: %x", first[:sha256.Size])
	}
}
