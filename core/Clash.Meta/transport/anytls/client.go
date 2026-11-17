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
}

type Client struct {
	passwordSha256 []byte
	tlsConfig      *vmess.TLSConfig
	dialer         N.Dialer
	server         M.Socksaddr
	sessionClient  *session.Client
	padding        atomic.Pointer[padding.PaddingFactory]
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
		dialer:         config.Dialer,
		server:         config.Server,
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
// The prefix is `[32B sha256(password)][2B big endian padding length][padding]`,
// i.e. the upstream sing-anytls v0.0.11 layout. The vendor client embeds
// sing-anytls v0.0.11 with the default padding scheme `0=30-30`, so its first
// packet is always 64 bytes plaintext (32 + 2 + 30) and the matching TLS record
// carries a payload length of 81 (64 + 1 inner content type + 16 AEAD tag).
// The official capture (capture-official-20261117, 5/5 connections) confirms
// that exact shape for the bare 32 hex character password as well, so this
// vendor form must not skip the padding suffix.
func (c *Client) writeFirstPacket(w io.Writer) (int64, error) {
	b := buf.NewPacket()
	defer b.Release()

	b.Write(c.passwordSha256)
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

func (h *Client) Close() error {
	return h.sessionClient.Close()
}
