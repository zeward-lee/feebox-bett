package ninja

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Method is the name of the AEAD suite used by the ninja tunnel.
//
// Four suites are accepted on the wire (exactly the ones the reference
// implementation understands):
//
//	aes-128-gcm             key = 16 bytes
//	aes-192-gcm             key = 24 bytes
//	aes-256-gcm             key = 32 bytes
//	chacha20-ietf-poly1305  key = 32 bytes
type Method string

const (
	MethodAES128GCM          Method = "aes-128-gcm"
	MethodAES192GCM          Method = "aes-192-gcm"
	MethodAES256GCM          Method = "aes-256-gcm"
	MethodChacha20Poly1305   Method = "chacha20-ietf-poly1305"
)

// KeyLen returns the AEAD key length (and the on-wire salt length) of the method.
func (m Method) KeyLen() int {
	switch m {
	case MethodAES128GCM:
		return 16
	case MethodAES192GCM:
		return 24
	case MethodAES256GCM, MethodChacha20Poly1305:
		return 32
	}
	return 0
}

// Overhead is the running AEAD tag size; every ninja record carries a 16 byte tag.
func (m Method) Overhead() int { return 16 }

// Valid reports whether the method is understood.
func (m Method) Valid() bool { return m.KeyLen() != 0 }

// NewAEAD builds the AEAD instance for a derived sub key.
func (m Method) NewAEAD(key []byte) (cipher.AEAD, error) {
	if !m.Valid() {
		return nil, fmt.Errorf("ninja: unsupported method %q", string(m))
	}
	if len(key) != m.KeyLen() {
		return nil, fmt.Errorf("ninja: bad key length %d for method %s", len(key), string(m))
	}
	switch m {
	case MethodChacha20Poly1305:
		return chacha20poly1305.New(key)
	default:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
}
