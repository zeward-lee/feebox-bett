package xhttpstream

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// kdfLabel is the VMess AEAD KDF label the vendor uses to derive the
	// ChaCha20-Poly1305 key of a node config blob.
	kdfLabel = "CHACHA 20 POLY 1305"

	// blobSeparator splits the vendor node `password` into a short prefix and
	// the base64 body. The vendor core joins everything after the first
	// separator back together before decoding.
	blobSeparator = "\n"

	// maxChunks bounds the chunk table of a config blob so a corrupted or
	// hostile blob cannot make us allocate absurdly.
	maxChunks = 15
)

var (
	// ErrNotConfigBlob reports that a password is not a vendor config blob.
	ErrNotConfigBlob = errors.New("xhttp: password is not a node config blob")

	// ErrBadConfigBlob reports a blob whose bytes do not decode.
	ErrBadConfigBlob = errors.New("xhttp: malformed node config blob")
)

// DecodeFakeNet hex-decodes fake-net[key]. A missing key is not an error: the
// vendor core hands an empty prefix to the random filler in that case.
func DecodeFakeNet(fakeNet map[string]string, key string) ([]byte, error) {
	if len(fakeNet) == 0 {
		return nil, nil
	}
	value := fakeNet[key]
	if value == "" {
		return nil, nil
	}
	decoded, err := hex.DecodeString(strings.Join(strings.Fields(value), ""))
	if err != nil {
		return nil, fmt.Errorf("xhttp: fake-net[%s] is not hex: %w", key, err)
	}
	return decoded, nil
}

// LooksLikeConfigBlob reports whether a password has the vendor blob shape:
// a short prefix, a newline, then base64.
func LooksLikeConfigBlob(password string) bool {
	_, rest, found := strings.Cut(password, blobSeparator)
	if !found {
		return false
	}
	rest = strings.TrimSpace(strings.ReplaceAll(rest, blobSeparator, ""))
	if len(rest) < 8 {
		return false
	}
	_, err := decodeBase64(rest)
	return err == nil
}

// DecodeConfigBlob unwraps a vendor node `password` value into the option map
// the core would otherwise receive over its encrypted channel.
//
// The vendor app hands the core one opaque string:
//
//	"<prefix>\n<base64(blackstone-payload)>"
//
// where the payload is the ChaCha20-Poly1305 chunk format below. The second
// return value is false (and the error nil) when the password is an ordinary
// "<secret>:<hmac-hex>" transport password.
func DecodeConfigBlob(password string) (map[string]any, bool, error) {
	_, rest, found := strings.Cut(password, blobSeparator)
	if !found {
		return nil, false, nil
	}
	body := strings.TrimSpace(strings.ReplaceAll(rest, blobSeparator, ""))
	if len(body) < 8 {
		return nil, false, nil
	}
	raw, err := decodeBase64(body)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrBadConfigBlob, err)
	}
	plain, err := DecryptBlackstonePayload(raw)
	if err != nil {
		return nil, true, fmt.Errorf("%w: %w", ErrBadConfigBlob, err)
	}
	var optionMap map[string]any
	if err := json.Unmarshal(plain, &optionMap); err != nil {
		return nil, true, fmt.Errorf("%w: %w", ErrBadConfigBlob, err)
	}
	if len(optionMap) == 0 {
		return nil, true, ErrBadConfigBlob
	}
	return optionMap, true, nil
}

// DecryptBlackstonePayload decrypts the vendor chunked ChaCha20-Poly1305
// payload:
//
//	[1]            chunk count
//	[count*8]      (start, end) big endian uint32 offsets into the payload
//	[..]           payload; the bytes covered by the table are the key seed,
//	               everything else is nonce (12 bytes) followed by ciphertext
//
// The key is VMess-AEAD KDF(seed, "CHACHA 20 POLY 1305"). A plaintext that
// starts with the gzip magic is decompressed, matching the vendor build.
func DecryptBlackstonePayload(raw []byte) ([]byte, error) {
	if len(raw) < 1 {
		return nil, errors.New("xhttp: config blob is empty")
	}
	chunkCount := int(raw[0])
	if chunkCount < 1 || chunkCount > maxChunks {
		return nil, fmt.Errorf("xhttp: config blob chunk count %d out of range", chunkCount)
	}
	headerSize := 1 + chunkCount*8
	if len(raw) < headerSize {
		return nil, errors.New("xhttp: config blob header is truncated")
	}
	type offset struct{ start, end uint32 }
	table := make([]offset, chunkCount)
	for i := 0; i < chunkCount; i++ {
		ptr := 1 + i*8
		start := binary.BigEndian.Uint32(raw[ptr : ptr+4])
		end := binary.BigEndian.Uint32(raw[ptr+4 : ptr+8])
		if end < start {
			return nil, errors.New("xhttp: config blob chunk range is inverted")
		}
		table[i] = offset{start: start, end: end}
	}
	payload := raw[headerSize:]
	isKey := make([]bool, len(payload))
	for _, off := range table {
		for i := uint32(0); i < off.end-off.start; i++ {
			index := off.start + i
			if int(index) < len(isKey) {
				isKey[index] = true
			}
		}
	}
	var keySeed, ciphertext []byte
	for i, b := range payload {
		if isKey[i] {
			keySeed = append(keySeed, b)
		} else {
			ciphertext = append(ciphertext, b)
		}
	}
	secret, err := hex.DecodeString(string(keySeed))
	if err != nil {
		secret = keySeed
	}
	derivedKey := vmessKDF(secret, kdfLabel)
	if len(ciphertext) < 12 {
		return nil, errors.New("xhttp: config blob ciphertext is truncated")
	}
	aead, err := chacha20poly1305.New(derivedKey)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, ciphertext[:12], ciphertext[12:], nil)
	if err != nil {
		return nil, fmt.Errorf("xhttp: config blob decrypt: %w", err)
	}
	if bytes.HasPrefix(plaintext, []byte("\x1f\x8b")) {
		reader, gzipErr := gzip.NewReader(bytes.NewReader(plaintext))
		if gzipErr == nil {
			defer reader.Close()
			return io.ReadAll(reader)
		}
	}
	return plaintext, nil
}

// vmessKDF is the VMess AEAD KDF, reused by the vendor for config blobs.
func vmessKDF(secret []byte, paths ...string) []byte {
	creator := func() hash.Hash { return hmac.New(sha256.New, []byte("VMess AEAD KDF")) }
	for _, path := range paths {
		c := creator
		pBytes := []byte(path)
		creator = func() hash.Hash { return hmac.New(c, pBytes) }
	}
	hashVal := creator()
	hashVal.Write(secret)
	return hashVal.Sum(nil)
}

func decodeBase64(value string) ([]byte, error) {
	if pad := len(value) % 4; pad != 0 {
		value += strings.Repeat("=", 4-pad)
	}
	return base64.StdEncoding.DecodeString(value)
}
