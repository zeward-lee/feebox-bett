package sntp_eclipse

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	keySize = 32
	// nonceSize is XChaCha20-Poly1305's 24 byte nonce. The vendor builds it as
	// 16 zero bytes followed by a big-endian uint64 record counter (§11.3).
	nonceSize = chacha20poly1305.NonceSizeX
	// chachaOverhead is the Poly1305 tag size.
	chachaOverhead = chacha20poly1305.Overhead
	// headerSize is the on-wire size of the sealed record header (BE16 length
	// + 16 byte Poly1305 tag). The body ciphertext length is carried inside it.
	headerSize = 2 + chachaOverhead
	// keyMaterialLen is the HKDF output length: four 32 byte keys.
	keyMaterialLen = 4 * keySize
)

// trafficKeys is the handshake and traffic key schedule. handshake keys are
// k0..k3 of the "<mode>/handshake" expansion; traffic keys are tk0..tk3 of the
// "<mode>/traffic" expansion. Direction mapping (verified against the vendor
// client, §13.1): C→S header=tk0, body=tk1; S→C header=tk2, body=tk3.
type trafficKeys struct {
	handshake [4][keySize]byte
	traffic   [4][keySize]byte
}

func recordNonce(counter uint64) []byte {
	var n [nonceSize]byte
	binary.BigEndian.PutUint64(n[nonceSize-8:], counter)
	return n[:]
}

func generateKeyPair() (priv, pub [keySize]byte, err error) {
	if _, err = rand.Read(priv[:]); err != nil {
		return priv, pub, fmt.Errorf("sntp-eclipse: generate ephemeral key: %w", err)
	}
	// X25519 clamps internally; curve25519.X25519Base does the same for the
	// public half.
	if pub, err = x25519(priv, basepoint); err != nil {
		return priv, pub, err
	}
	return priv, pub, nil
}

// basepoint is curve25519.Basepoint spelled out so x25519 stays a pure
// multiply helper in tests.
var basepoint = [keySize]byte{9}

func x25519(priv [keySize]byte, peerPub [keySize]byte) ([keySize]byte, error) {
	var out [keySize]byte
	shared, err := curve25519.X25519(priv[:], peerPub[:])
	if err != nil {
		return out, fmt.Errorf("sntp-eclipse: x25519: %w", err)
	}
	if isZero(shared) {
		return out, errors.New("sntp-eclipse: x25519 produced the all-zero shared secret")
	}
	copy(out[:], shared)
	return out, nil
}

func isZero(b []byte) bool {
	var acc byte
	for _, v := range b {
		acc |= v
	}
	return acc == 0
}

func hkdfSHA256(secret, salt, info []byte, length int) ([]byte, error) {
	out := make([]byte, length)
	r := hkdf.New(sha256.New, secret, salt, info)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("sntp-eclipse: hkdf: %w", err)
	}
	return out, nil
}

// handshakeKDF is s1 -> k0..k3 with salt=client_nonce and
// info="<mode>/handshake" (§11.2).
func handshakeKDF(shared [keySize]byte, clientNonce []byte, mode string) ([4][keySize]byte, error) {
	var keys [4][keySize]byte
	okm, err := hkdfSHA256(shared[:], clientNonce, []byte(mode+"/handshake"), keyMaterialLen)
	if err != nil {
		return keys, err
	}
	for i := range keys {
		copy(keys[i][:], okm[i*keySize:(i+1)*keySize])
	}
	return keys, nil
}

// trafficKDF is (§13.2):
//
//	ikm  = s1 || s2
//	salt = SHA256(transcript32 || server_eph32)
//	info = "<mode>/traffic", L = 128
func trafficKDF(s1, s2 [keySize]byte, transcript, serverEph [keySize]byte, mode string) ([4][keySize]byte, error) {
	var keys [4][keySize]byte
	saltInput := make([]byte, 0, len(transcript)+len(serverEph))
	saltInput = append(saltInput, transcript[:]...)
	saltInput = append(saltInput, serverEph[:]...)
	salt := sha256.Sum256(saltInput)

	ikm := make([]byte, 0, 2*keySize)
	ikm = append(ikm, s1[:]...)
	ikm = append(ikm, s2[:]...)

	okm, err := hkdfSHA256(ikm, salt[:], []byte(mode+"/traffic"), keyMaterialLen)
	if err != nil {
		return keys, err
	}
	for i := range keys {
		copy(keys[i][:], okm[i*keySize:(i+1)*keySize])
	}
	return keys, nil
}

func newAEAD(key [keySize]byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key[:])
}

// sealRecord produces hdr18||body_ct for one record.
//
//	cfg  hdr  = Seal(keyH, nonce(ctr), BE16(len(pt)+16), aad)
//	body = Seal(keyB, nonce(ctr), pt,              aad||hdr18)
//
// The header and the body of a single record share the counter; the caller
// advances the counter once per record (§13.1).
func sealRecord(hdrAEAD, bodyAEAD cipher.AEAD, counter uint64, aad, plaintext []byte) []byte {
	nonce := recordNonce(counter)
	lengthField := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthField, uint16(len(plaintext)+chacha20poly1305.Overhead))
	header := hdrAEAD.Seal(nil, nonce, lengthField, aad)

	bodyAD := make([]byte, 0, len(aad)+len(header))
	bodyAD = append(bodyAD, aad...)
	bodyAD = append(bodyAD, header...)
	body := bodyAEAD.Seal(nil, nonce, plaintext, bodyAD)

	out := make([]byte, 0, len(header)+len(body))
	out = append(out, header...)
	out = append(out, body...)
	return out
}

// openHeader decrypts the 18 byte record header and returns the advertised
// body ciphertext length.
func openHeader(hdrAEAD cipher.AEAD, counter uint64, aad, header []byte) (int, error) {
	if len(header) != headerSize {
		return 0, fmt.Errorf("sntp-eclipse: record header must be %d bytes, got %d", headerSize, len(header))
	}
	plain, err := hdrAEAD.Open(nil, recordNonce(counter), header, aad)
	if err != nil {
		return 0, fmt.Errorf("sntp-eclipse: open record header (counter=%d): %w", counter, err)
	}
	if len(plain) != 2 {
		return 0, fmt.Errorf("sntp-eclipse: record header plaintext must be 2 bytes, got %d", len(plain))
	}
	return int(binary.BigEndian.Uint16(plain)), nil
}

// openBody decrypts the record body; aad must be the header prefix the peer
// used (hello: prefix48; data records: only hdr18).
func openBody(bodyAEAD cipher.AEAD, counter uint64, aad, header, body []byte) ([]byte, error) {
	bodyAD := make([]byte, 0, len(aad)+len(header))
	bodyAD = append(bodyAD, aad...)
	bodyAD = append(bodyAD, header...)
	plain, err := bodyAEAD.Open(nil, recordNonce(counter), body, bodyAD)
	if err != nil {
		return nil, fmt.Errorf("sntp-eclipse: open record body (counter=%d): %w", counter, err)
	}
	return plain, nil
}
