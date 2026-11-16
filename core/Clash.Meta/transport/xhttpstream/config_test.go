package xhttpstream

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// buildBlobWithSeed encodes plaintext in the vendor's chunked
// ChaCha20-Poly1305 format with a single key chunk, which is the shape the
// decoder must read. payloadSeed is written into the chunk table verbatim while
// kdfSeed is the key material the AEAD key is derived from; the two differ when
// the seed is a hex string that DecryptBlackstonePayload hex-decodes.
func buildBlobWithSeed(t *testing.T, plaintext, payloadSeed, kdfSeed []byte) []byte {
	t.Helper()
	aead, err := chacha20poly1305.New(vmessKDF(kdfSeed, kdfLabel))
	if err != nil {
		t.Fatalf("chacha20poly1305: %v", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	ciphertext := append(nonce, aead.Seal(nil, nonce, plaintext, nil)...)
	payload := append(append([]byte{}, payloadSeed...), ciphertext...)
	raw := make([]byte, 1+8+len(payload))
	raw[0] = 1
	binary.BigEndian.PutUint32(raw[1:5], 0)
	binary.BigEndian.PutUint32(raw[5:9], uint32(len(payloadSeed)))
	copy(raw[9:], payload)
	return raw
}

// buildBlob uses a non-hex seed, so the decoder takes its raw-seed path.
func buildBlob(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	seed := []byte("transport-secret")
	return buildBlobWithSeed(t, plaintext, seed, seed)
}

// buildHexSeedBlob writes a hex-looking seed, which the decoder hex-decodes
// before deriving the key.
func buildHexSeedBlob(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	payloadSeed := []byte("00112233445566778899aabbccddeeff")
	rawSeed, err := hex.DecodeString(string(payloadSeed))
	if err != nil {
		t.Fatalf("hex seed: %v", err)
	}
	return buildBlobWithSeed(t, plaintext, payloadSeed, rawSeed)
}

func TestDecryptBlackstonePayload(t *testing.T) {
	plaintext := []byte(`{"server":"203.0.113.9","port":443}`)
	got, err := DecryptBlackstonePayload(buildBlob(t, plaintext))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted = %q, want %q", got, plaintext)
	}
}

func TestDecryptBlackstonePayloadHexSeed(t *testing.T) {
	plaintext := []byte(`{"server":"203.0.113.9","port":443}`)
	got, err := DecryptBlackstonePayload(buildHexSeedBlob(t, plaintext))
	if err != nil {
		t.Fatalf("decrypt with hex seed: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted = %q, want %q", got, plaintext)
	}
}

func TestDecryptBlackstonePayloadGzip(t *testing.T) {
	plaintext := []byte(`{"server":"203.0.113.9"}`)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	got, err := DecryptBlackstonePayload(buildBlob(t, compressed.Bytes()))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted = %q, want %q", got, plaintext)
	}
}

func TestDecodeConfigBlob(t *testing.T) {
	optionMap := map[string]any{
		"server":      "203.0.113.9",
		"port":        float64(443),
		"password":    "transport-secret:0011223344556677",
		"cipher":      "aes-128-ctr",
		"udp":         true,
		"padding-len": "8-64",
		"fake-net":    map[string]any{"tcp": "1603"},
	}
	plaintext, err := json.Marshal(optionMap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	password := "v3\n" + base64.StdEncoding.EncodeToString(buildBlob(t, plaintext))
	got, isBlob, err := DecodeConfigBlob(password)
	if err != nil {
		t.Fatalf("DecodeConfigBlob: %v", err)
	}
	if !isBlob {
		t.Fatal("DecodeConfigBlob did not recognise the blob")
	}
	if got["server"] != "203.0.113.9" {
		t.Fatalf("server = %v", got["server"])
	}
	if _, ok := got["password"]; !ok {
		t.Fatal("blob lost the transport password")
	}
}

func TestDecodeConfigBlobRejectsOrdinaryPassword(t *testing.T) {
	if _, isBlob, err := DecodeConfigBlob("transport-secret:0011223344556677"); err != nil || isBlob {
		t.Fatalf("plain password: isBlob=%v err=%v", isBlob, err)
	}
	if LooksLikeConfigBlob("transport-secret:0011223344556677") {
		t.Fatal("plain password looks like a blob")
	}
	// The body must survive DecodeConfigBlob's "too short to be a blob" guard
	// (>= 8 base64 chars) so the corrupted chunk table is actually parsed.
	corrupted := "v3\n" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x09}, 16))
	if _, isBlob, err := DecodeConfigBlob(corrupted); err == nil || !isBlob {
		t.Fatalf("corrupted blob: isBlob=%v err=%v", isBlob, err)
	}
}

func TestParsePaddingLen(t *testing.T) {
	if minLen, maxLen, err := ParsePaddingLen("8-64"); err != nil || minLen != 8 || maxLen != 64 {
		t.Fatalf("8-64 => %d,%d,%v", minLen, maxLen, err)
	}
	if minLen, maxLen, err := ParsePaddingLen("32"); err != nil || minLen != 0 || maxLen != 32 {
		t.Fatalf("32 => %d,%d,%v", minLen, maxLen, err)
	}
	if minLen, maxLen, err := ParsePaddingLen(""); err != nil || minLen != 0 || maxLen != 0 {
		t.Fatalf("empty => %d,%d,%v", minLen, maxLen, err)
	}
	if _, _, err := ParsePaddingLen("8-"); err == nil {
		t.Fatal("8- accepted")
	}
	if _, _, err := ParsePaddingLen("64-8"); err == nil {
		t.Fatal("reversed range accepted")
	}
}

func TestDecodeFakeNet(t *testing.T) {
	got, err := DecodeFakeNet(map[string]string{"tcp": "1603 0100"}, "tcp")
	if err != nil {
		t.Fatalf("DecodeFakeNet: %v", err)
	}
	if !bytes.Equal(got, []byte{0x16, 0x03, 0x01, 0x00}) {
		t.Fatalf("fake net = %x", got)
	}
	if _, err := DecodeFakeNet(map[string]string{"tcp": "zz"}, "tcp"); err == nil {
		t.Fatal("non-hex fake-net accepted")
	}
	if got, err := DecodeFakeNet(nil, "tcp"); err != nil || got != nil {
		t.Fatalf("nil fake net = %x, %v", got, err)
	}
}
