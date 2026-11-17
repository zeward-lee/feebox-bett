package sntp_eclipse

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// NativeV3Mode is the only wire dialect the Eclipse transport speaks. The
// string is load bearing: the vendor derives both HKDF info strings from it
// ("<mode>/handshake", "<mode>/traffic"), so aliasing it silently breaks the
// key schedule. See report-sntp-eclipse.md §11.1 / §13.2.
const NativeV3Mode = "sntp-eclipse-v3-native-1"

const (
	// helloOuterLen is the outer u16 of the hello record. The vendor client
	// sends 574 while the sealed plaintext is padded to 672 bytes; the server
	// does not cross-check the two (§11.4), so the constant is kept for byte
	// compatibility with the official client.
	helloOuterLen = 574
	// helloPlaintextLen is the fixed plaintext size of the first record.
	helloPlaintextLen = 672
	// helloVersion / helloCmdConnect are the hello version byte and the
	// CONNECT command. cmd=2 exists in the binary but has never been observed
	// (UDP is not implemented by this transport, see adapter note).
	helloVersion    = 3
	helloCmdConnect = 1
	// defaultHandshakeTimeout bounds the hello exchange only.
	defaultHandshakeTimeout = 10 * time.Second
)

// ClientConfig carries the per-node secrets. Everything else (ephemeral
// X25519 pair, nonces, handshake/traffic keys, counters) is derived per
// connection and never stored.
type ClientConfig struct {
	// Mode must stay NativeV3Mode when set.
	Mode string
	// ServerPublicKey is the node's static X25519 public key, base64url
	// (43 chars, no padding) or standard base64.
	ServerPublicKey string
	// UUID is the 32 hex characters sent verbatim as the hello "meta" field.
	UUID string
	// HandshakeTimeout defaults to 10s when zero.
	HandshakeTimeout time.Duration
}

// Target is the address the tunnel should connect to. It is only known at
// dial time (one connection per target).
type Target struct {
	Host string
	Port uint16
}

func (c ClientConfig) timeout() time.Duration {
	if c.HandshakeTimeout > 0 {
		return c.HandshakeTimeout
	}
	return defaultHandshakeTimeout
}

func (c ClientConfig) mode() string {
	if c.Mode == "" {
		return NativeV3Mode
	}
	return c.Mode
}

func (c ClientConfig) validate() error {
	if c.mode() != NativeV3Mode {
		return fmt.Errorf("sntp-eclipse: unsupported mode %q (only %q is implemented)", c.Mode, NativeV3Mode)
	}
	if _, err := DecodeServerPublicKey(c.ServerPublicKey); err != nil {
		return err
	}
	if _, err := DecodeUUID(c.UUID); err != nil {
		return err
	}
	return nil
}

// DecodeServerPublicKey accepts the vendor's base64url spelling (43 chars,
// unpadded) as well as padded/standard base64 of the same 32 raw bytes.
func DecodeServerPublicKey(s string) ([32]byte, error) {
	var out [32]byte
	key := strings.TrimSpace(s)
	if key == "" {
		return out, errors.New("sntp-eclipse: server-public-key is empty")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(key, "="))
	if err != nil {
		raw, err = base64.StdEncoding.DecodeString(key)
	}
	if err != nil {
		return out, fmt.Errorf("sntp-eclipse: server-public-key is not base64url: %w", err)
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("sntp-eclipse: server-public-key must decode to 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// DecodeUUID returns the 32 ASCII bytes of the uuid hex string. The vendor
// sends the *text* form inside hello's meta field (§10.4), not the 16 raw
// bytes, so a 32 hex string is required (a dashed UUID or a 16 byte value is
// rejected rather than silently mangled).
func DecodeUUID(s string) ([32]byte, error) {
	var out [32]byte
	id := strings.TrimSpace(s)
	if len(id) != 32 {
		return out, fmt.Errorf("sntp-eclipse: uuid must be 32 hex characters, got %d", len(id))
	}
	if _, err := hex.DecodeString(id); err != nil {
		return out, fmt.Errorf("sntp-eclipse: uuid is not hex: %w", err)
	}
	copy(out[:], id)
	return out, nil
}
