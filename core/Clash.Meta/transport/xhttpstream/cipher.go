package xhttpstream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
)

const (
	// FakePrefixLen is the length of the forged HTTP/TLS prefix that fronts
	// every client handshake and every UDP datagram. The vendor build always
	// fills exactly this many bytes: the hex blob from fake-net first, random
	// bytes for the remainder.
	FakePrefixLen = 128

	// tokenSuffix is appended to the first half of the password before it is
	// hashed into the 16 byte handshake token. Kept byte-identical to the
	// upstream build ("do not hack this protocol please").
	tokenSuffix = "do not hack this protocol please"

	// DefaultCipher is what the vendor falls back to when `cipher` is unset.
	DefaultCipher = "aes-128-ctr"
)

var (
	// ErrInvalidToken is returned when the server does not echo the handshake
	// token. It means the password (or the server) is wrong.
	ErrInvalidToken = errors.New("xhttp: invalid token")

	// ErrInvalidPassword is returned when the transport password is not in the
	// "<secret>:<hmac-hex>" form the handshake needs.
	ErrInvalidPassword = errors.New("xhttp: password must be <secret>:<hmac-hex>")

	// ErrCipherNotSupported is returned by PickCipher for unknown cipher names.
	ErrCipherNotSupported = errors.New("xhttp: cipher not supported")
)

// Kdf derives a key from password with the shadowsocks MD5 KDF. It is the same
// derivation the vendor core uses (its transport keeps a copy of the
// shadowsocks core package).
func Kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}

// Cipher generates a pair of stream ciphers for encryption and decryption.
type Cipher interface {
	IVSize() int
	Encrypter(iv []byte) cipher.Stream
	Decrypter(iv []byte) cipher.Stream
}

// KeySizeError reports a key whose length does not fit the cipher.
type KeySizeError int

func (e KeySizeError) Error() string {
	return "key size error: need " + strconv.Itoa(int(e)) + " bytes"
}

// ctrStream is the AES-CTR mode, the only mode the vendor build ships.
type ctrStream struct{ cipher.Block }

func (b *ctrStream) IVSize() int                       { return b.BlockSize() }
func (b *ctrStream) Decrypter(iv []byte) cipher.Stream { return cipher.NewCTR(b.Block, iv) }
func (b *ctrStream) Encrypter(iv []byte) cipher.Stream { return cipher.NewCTR(b.Block, iv) }

// AESCTR builds a CTR cipher. Every key length AES accepts is allowed; the
// vendor advertises the three CTR names below.
func AESCTR(key []byte) (Cipher, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &ctrStream{blk}, nil
}

// cipherList is the cipher table the vendor core keeps. Names are matched case
// insensitively, exactly like its PickCipher.
var cipherList = map[string]struct {
	KeySize int
	New     func([]byte) (Cipher, error)
}{
	"AES-128-CTR": {16, AESCTR},
	"AES-192-CTR": {24, AESCTR},
	"AES-256-CTR": {32, AESCTR},
}

// ListCipher reports the cipher names the transport accepts, in table order.
func ListCipher() []string {
	names := make([]string, 0, len(cipherList))
	for name := range cipherList {
		names = append(names, strings.ToLower(name))
	}
	return names
}

// StreamCipher is the xhttp transport cipher. It carries the three values the
// handshake needs on top of a normal stream cipher: the token, the HMAC key and
// the fake-net header map.
type StreamCipher struct {
	Cipher
	Key      []byte
	token    []byte
	hmac     []byte
	password string
	fakeNet  map[string]string

	// mu guards the lazy HMAC assignment, mirroring the upstream SetHmac.
	mu sync.Mutex
}

// SplitTransportPassword splits "<secret>:<hmac-hex>". The vendor core splits
// on every ':' and keeps the first two parts, so anything after a second colon
// is not part of the HMAC key.
func SplitTransportPassword(password string) (secret string, hmacKey []byte, err error) {
	secret, rest, found := strings.Cut(password, ":")
	if !found {
		return "", nil, ErrInvalidPassword
	}
	hmacKey, err = hex.DecodeString(rest)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", ErrInvalidPassword, err)
	}
	if len(hmacKey) == 0 {
		return "", nil, fmt.Errorf("%w: empty hmac key", ErrInvalidPassword)
	}
	return secret, hmacKey, nil
}

// Token derives the handshake token from the first half of the password.
func Token(secret string) []byte {
	sum := md5.Sum([]byte(secret + tokenSuffix))
	return sum[:]
}

// PickCipher builds the transport cipher for a cipher name and a
// "<secret>:<hmac-hex>" password. An empty name selects DefaultCipher; a nil
// key derives one from the secret with Kdf, like the vendor PickCipher.
func PickCipher(name string, key []byte, password string, fakeNet map[string]string) (*StreamCipher, error) {
	if name == "" {
		name = DefaultCipher
	}
	choice, ok := cipherList[strings.ToUpper(name)]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrCipherNotSupported, name)
	}
	secret, hmacKey, err := SplitTransportPassword(password)
	if err != nil {
		return nil, err
	}
	if len(key) == 0 {
		key = Kdf(secret, choice.KeySize)
	}
	if len(key) != choice.KeySize {
		return nil, KeySizeError(choice.KeySize)
	}
	ciph, err := choice.New(key)
	if err != nil {
		return nil, err
	}
	return &StreamCipher{
		Cipher:   ciph,
		Key:      key,
		token:    Token(secret),
		hmac:     hmacKey,
		password: secret,
		fakeNet:  fakeNet,
	}, nil
}

// SetHmac replaces the HMAC key, mirroring the upstream SetHmac helper.
func (c *StreamCipher) SetHmac(hmacKey []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hmac = hmacKey
}

// StreamConn wraps a stream connection. destination is the SOCKS address of the
// first target and is sent as the first encrypted bytes of the stream.
func (c *StreamCipher) StreamConn(conn net.Conn, destination []byte) net.Conn {
	return &Conn{
		Conn:        conn,
		Cipher:      c,
		Destination: destination,
		token:       c.token,
		hmac:        c.hmac,
		fakeNet:     c.fakeNet,
	}
}

// PacketConn wraps a datagram carrier for the plain (non UOT) UDP mode. The
// carrier must already be bound to the configured server (server/port from the
// node or its config blob); remote is kept so the conn reports it as
// RemoteAddr, while the destination inside each frame stays per datagram.
func (c *StreamCipher) PacketConn(conn net.Conn, remote net.Addr) net.PacketConn {
	return &PacketConn{
		Conn:    conn,
		Cipher:  c,
		remote:  remote,
		token:   c.token,
		hmac:    c.hmac,
		fakeNet: c.fakeNet,
	}
}

// tokenEqual is a constant time comparison, so a wrong password leaks nothing
// about how many bytes matched.
func tokenEqual(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}
