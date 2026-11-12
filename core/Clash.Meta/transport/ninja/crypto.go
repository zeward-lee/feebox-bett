package ninja

import (
	"crypto/aes"
	"crypto/subtle"
	"fmt"

	"github.com/metacubex/blake3"
)

// Derivation contexts of the ninja tunnel. These are BLAKE3 derive-key
// "context" strings; the reference core keeps them as 32 byte hex literals and
// they are application specific, so they must match exactly.
const (
	// ctxPSK turns the configured passphrase into the tunnel pre-shared key.
	ctxPSK = "de6dbaddc4e0dbaaeb65778b44e6fdac"
	// ctxSubKey mixes the connection salt into the per-connection AEAD key.
	ctxSubKey = "52386811679ea908c4a2b02f367c472c"
	// ctxTokenKey derives the key that protects the 16 byte session token.
	ctxTokenKey = "e14d197ae519bdd2d9a75ae94df7e208"
)

// tokenLen is the length of the plaintext session token exchanged in the clear.
const tokenLen = 16

// psk derives the pre-shared key from the passphrase.
//
//	psk = BLAKE3-derive-key(ctxPSK, passphrase)  [KeyLen]
func (m Method) psk(passphrase string) ([]byte, error) {
	keyLen := m.KeyLen()
	if keyLen == 0 {
		return nil, fmt.Errorf("ninja: unsupported method %q", string(m))
	}
	if passphrase == "" {
		return nil, fmt.Errorf("ninja: empty password")
	}
	out := make([]byte, keyLen)
	blake3.DeriveKey(out, ctxPSK, []byte(passphrase))
	return out, nil
}

// subKey derives the per connection AEAD key.
//
//	subKey = BLAKE3-derive-key(ctxSubKey, psk || salt)  [KeyLen]
func (m Method) subKey(psk, salt []byte) ([]byte, error) {
	keyLen := m.KeyLen()
	if keyLen == 0 {
		return nil, fmt.Errorf("ninja: unsupported method %q", string(m))
	}
	if len(salt) != keyLen {
		return nil, fmt.Errorf("ninja: bad salt length %d (method %s needs %d)", len(salt), string(m), keyLen)
	}
	buf := make([]byte, 0, len(psk)+len(salt))
	buf = append(buf, psk...)
	buf = append(buf, salt...)
	out := make([]byte, keyLen)
	blake3.DeriveKey(out, ctxSubKey, buf)
	zero(buf)
	return out, nil
}

// tokenKey derives the AES key that wraps the session token.
//
//	tokenKey = BLAKE3-derive-key(ctxTokenKey, psk || salt)  [KeyLen]
func (m Method) tokenKey(psk, salt []byte) ([]byte, error) {
	keyLen := m.KeyLen()
	if keyLen == 0 {
		return nil, fmt.Errorf("ninja: unsupported method %q", string(m))
	}
	buf := make([]byte, 0, len(psk)+len(salt))
	buf = append(buf, psk...)
	buf = append(buf, salt...)
	out := make([]byte, keyLen)
	blake3.DeriveKey(out, ctxTokenKey, buf)
	zero(buf)
	return out, nil
}

// buildToken returns the on-wire session token:
//
//	plain = BLAKE3-Sum512(psk)[:16]
//	wire  = AES-ECB-Encrypt(tokenKey, plain)
//
// The token is written in clear text but is only reproducible by a peer that
// knows the passphrase, so the responder can authenticate the initiator before
// any payload is accepted.
func (m Method) buildToken(psk, salt []byte) ([]byte, error) {
	if len(psk) != 16 && len(psk) != 24 && len(psk) != 32 {
		return nil, fmt.Errorf("ninja: bad psk length %d", len(psk))
	}
	sum := blake3.Sum512(psk)
	tk, err := m.tokenKey(psk, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(tk)
	if err != nil {
		return nil, err
	}
	out := make([]byte, tokenLen)
	block.Encrypt(out, sum[:tokenLen])
	return out, nil
}

// verifyToken re-computes the expected token and compares in constant time.
func (m Method) verifyToken(psk, salt, got []byte) bool {
	want, err := m.buildToken(psk, salt)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(want, got) == 1
}

// zero wipes sensitive key material (go1.20 compatible clear).
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// increment advances the 96 bit AEAD nonce as a little endian counter.
// A fresh connection starts at all-zero and increments after every Seal/Open.
func increment(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}
