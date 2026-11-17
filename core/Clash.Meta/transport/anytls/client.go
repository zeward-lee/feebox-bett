package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/session"
	"github.com/metacubex/mihomo/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type ClientConfig struct {
	Password                 string
	ClientMetadata           string
	IdleSessionCheckInterval time.Duration
	IdleSessionTimeout       time.Duration
	MinIdleSession           int
	DisableReuse             bool
	Server                   M.Socksaddr
	Dialer                   N.Dialer
	TLSConfig                *vmess.TLSConfig
	// SkipTLS dials the underlying transport as a plain byte stream and writes
	// the anytls handshake (credential + padding + frames) directly into it.
	//
	// It is required by the vendor `transport/v2rayxhttp` (XHTTP) transport: the
	// XHTTP stream pair already runs inside TLS (one handshake per endpoint,
	// configured on the transport), and the vendor server expects the anytls
	// credential as the very first bytes of the upload body. Adding a second TLS
	// handshake there makes the server read a TLS ClientHello as the credential
	// and never answer, which is exactly the "failed to create session: context
	// deadline exceeded" failure the dedicated lines showed. Plain anytls nodes
	// keep TLSConfig and this flag false.
	SkipTLS bool
}

type Client struct {
	passwordSha256 []byte
	// hexPasswordKey is set only when Password is the vendor bare 32 hex form:
	// the key decoded from it is combined with a per-connection time token (see
	// deriveHexPasswordCredential) instead of sending passwordSha256.
	hexPasswordKey []byte
	tlsConfig      *vmess.TLSConfig
	skipTLS        bool
	dialer         N.Dialer
	server         M.Socksaddr
	sessionClient  *session.Client
	padding        atomic.Pointer[padding.PaddingFactory]
}

const (
	// hexPasswordKeySize is the decoded size of the vendor bare hex password.
	hexPasswordKeySize = 16
	// hexPasswordCredentialSize is the first packet credential size: the 16 byte
	// key followed by the 16 byte time token XORed with that key.
	hexPasswordCredentialSize = 32
)

// hexPasswordPattern matches the vendor bare password form: 32 hex characters,
// i.e. the hexadecimal encoding of the 16 byte shared key.
var hexPasswordPattern = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

// decodeHexPasswordKey returns the 16 byte shared key encoded by password when
// it is exactly 32 hex characters. ok is false for every other form (the "#sl"
// marker variant, ordinary anytls passwords, wrong lengths, invalid hex), which
// keep their existing decoding untouched.
func decodeHexPasswordKey(password string) (key []byte, ok bool) {
	if !hexPasswordPattern.MatchString(password) {
		return nil, false
	}
	decoded, err := hex.DecodeString(password)
	if err != nil || len(decoded) != hexPasswordKeySize {
		return nil, false
	}
	return decoded, true
}

// deriveHexPasswordCredential reproduces the vendor client's 32 byte first
// packet credential (applyAnyTLSHexPassword in the official fork):
//
//	cred = raw16 || (T16 XOR raw16)
//	T16  = BE64(u*10+1) || BE64(u)
//
// raw16 is the decoded 16 byte key and u is Unix time in milliseconds. It
// returns nil for a malformed key so callers fall back to passwordSha256
// instead of panicking.
func deriveHexPasswordCredential(raw []byte, u int64) []byte {
	if len(raw) != hexPasswordKeySize {
		return nil
	}
	millis := uint64(u)
	var token [hexPasswordKeySize]byte
	binary.BigEndian.PutUint64(token[0:8], millis*10+1)
	binary.BigEndian.PutUint64(token[8:16], millis)

	credential := make([]byte, hexPasswordCredentialSize)
	copy(credential, raw)
	for i := range token {
		credential[hexPasswordKeySize+i] = token[i] ^ raw[i]
	}
	return credential
}

// ShanlianPasswordMarker is the suffix the vendor client puts on a Shanlian
// node's password: the part before it is the raw 32-byte key in hex and is used
// directly as passwordSha256 instead of hashing the literal string.
const ShanlianPasswordMarker = "#sl"

// IsShanlianPassword reports whether password carries the Shanlian marker. The
// marker match is case-insensitive.
func IsShanlianPassword(password string) bool {
	return strings.HasSuffix(strings.ToLower(password), ShanlianPasswordMarker)
}

func decodeClientPassword(password string) ([]byte, error) {
	if IsShanlianPassword(password) {
		raw := password[:len(password)-len(ShanlianPasswordMarker)]
		if len(raw) != sha256.Size*2 {
			return nil, errors.New("anytls: Shanlian password must be 64 hexadecimal characters before #sl")
		}
		decoded, err := hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("anytls: invalid Shanlian hexadecimal password: %w", err)
		}
		return decoded, nil
	}
	hash := sha256.Sum256([]byte(password))
	return hash[:], nil
}

func NewClient(ctx context.Context, config ClientConfig) (*Client, error) {
	password, err := decodeClientPassword(config.Password)
	if err != nil {
		return nil, err
	}
	c := &Client{
		passwordSha256: password,
		tlsConfig:      config.TLSConfig,
		skipTLS:        config.SkipTLS,
		dialer:         config.Dialer,
		server:         config.Server,
	}
	if key, ok := decodeHexPasswordKey(config.Password); ok {
		c.hexPasswordKey = key
	}
	// Initialize the padding state of this client
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &c.padding)
	c.sessionClient = session.NewClient(ctx, c.createOutboundTLSConnection, &c.padding, config.ClientMetadata, config.IdleSessionCheckInterval, config.IdleSessionTimeout, config.MinIdleSession, config.DisableReuse)
	return c, nil
}

func (c *Client) CreateProxy(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.sessionClient.CreateStream(ctx)
	if err != nil {
		return nil, err
	}
	err = M.SocksaddrSerializer.WriteAddrPort(conn, destination)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) createOutboundTLSConnection(ctx context.Context) (net.Conn, error) {
	conn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.server)
	if err != nil {
		return nil, err
	}

	// XHTTP already carries the stream inside its own TLS; layering anytls TLS on
	// top would make the vendor server parse the ClientHello as a credential and
	// stay silent. The handshake prefix therefore goes straight into the stream.
	if c.skipTLS {
		if _, err = c.writeFirstPacket(conn); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}

	tlsConn, err := vmess.StreamTLSConn(ctx, conn, c.tlsConfig)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if _, err = c.writeFirstPacket(tlsConn); err != nil {
		tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// writeFirstPacket writes the anytls handshake prefix that precedes the first
// frame (the session client sends the settings frame right after this returns).
//
// The prefix is `[32B credential][2B big endian padding length][padding]`,
// i.e. the upstream sing-anytls v0.0.11 layout. The vendor client embeds
// sing-anytls v0.0.11 with the default padding scheme `0=30-30`, so its first
// packet is always 64 bytes plaintext (32 + 2 + 30) and the matching TLS record
// carries a payload length of 81 (64 + 1 inner content type + 16 AEAD tag).
// The official capture (capture-official-20261117, 5/5 connections) confirms
// that exact shape for the bare 32 hex character password as well, so this
// vendor form must not skip the padding suffix.
//
// The 32 byte credential itself is passwordSha256 for ordinary passwords, but
// the vendor bare 32 hex form sends a time based credential derived on every
// new connection (see hexPasswordCredential).
func (c *Client) writeFirstPacket(w io.Writer) (int64, error) {
	b := buf.NewPacket()
	defer b.Release()

	credential := c.hexPasswordCredential()
	if credential == nil {
		credential = c.passwordSha256
	}
	b.Write(credential)
	var paddingLen int
	if pad := c.padding.Load().GenerateRecordPayloadSizes(0); len(pad) > 0 {
		paddingLen = pad[0]
	}
	binary.BigEndian.PutUint16(b.Extend(2), uint16(paddingLen))
	if paddingLen > 0 {
		b.WriteZeroN(paddingLen)
	}
	return b.WriteTo(w)
}

// hexPasswordCredential derives the credential for a connection that is being
// established now. The vendor token embeds the wall clock, so it is recomputed
// per connection instead of being cached on the client; that is accepted by the
// server just like the official client's token frozen at client creation, since
// the server only rejects tokens too far in the future.
//
// It returns nil when the password is not the vendor bare hex form or the key is
// malformed, in which case writeFirstPacket keeps the upstream behavior.
func (c *Client) hexPasswordCredential() []byte {
	if len(c.hexPasswordKey) != hexPasswordKeySize {
		return nil
	}
	return deriveHexPasswordCredential(c.hexPasswordKey, time.Now().UnixMilli())
}

func (h *Client) Close() error {
	return h.sessionClient.Close()
}
