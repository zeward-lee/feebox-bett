package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/ninja"
)

// Ninja is the ninja tunnel outbound. The wire protocol is a BLAKE3 derived
// AEAD stream carried over plain TCP (or TLS/WebSocket when configured) and was
// reconstructed from the mihomo-ninja reference core.
type Ninja struct {
	*Base
	option *NinjaOption
	client *ninja.Client
}

// NinjaPassOptions controls the AEAD suite and the padding profile.
type NinjaPassOptions struct {
	PassVersion int    `proxy:"passversion,omitempty"`
	PaddingMode string `proxy:"padding-mode,omitempty"`
	PaddingMin  int    `proxy:"padding-min,omitempty"`
	PaddingMax  int    `proxy:"padding-max,omitempty"`
}

type NinjaOption struct {
	BasicOption
	Name         string           `proxy:"name"`
	Server       string           `proxy:"server"`
	Port         int              `proxy:"port"`
	Password     string           `proxy:"password,omitempty"`
	NodePassword string           `proxy:"node-password"`
	Method       string           `proxy:"method"`
	UDP          bool             `proxy:"udp,omitempty"`
	PassOptions  NinjaPassOptions `proxy:",squash"`
}

// DialContext implements C.ProxyAdapter
func (n *Ninja) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := n.dialer.DialContext(ctx, "tcp", n.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", n.addr, err)
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	host := metadata.Host
	if host == "" {
		host = metadata.DstIP.String()
	} else if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	port := metadata.DstPort
	stream, err := n.client.StreamConn(c, host, port)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", n.addr, err)
	}
	return NewConn(stream, n), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (n *Ninja) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	return n.Base.ListenPacketContext(ctx, metadata)
}

// SupportUDP implements C.ProxyAdapter
func (n *Ninja) SupportUDP() bool { return false }

// SupportUOT implements C.ProxyAdapter
func (n *Ninja) SupportUOT() bool { return false }

// ProxyInfo implements C.ProxyAdapter
func (n *Ninja) ProxyInfo() C.ProxyInfo {
	info := n.Base.ProxyInfo()
	info.DialerProxy = n.option.DialerProxy
	return info
}

// NewNinja builds the outbound from its option block.
func NewNinja(option NinjaOption) (*Ninja, error) {
	method := ninja.Method(option.Method)
	if !method.Valid() {
		return nil, fmt.Errorf("ninja %s: unsupported method %s", option.Name, option.Method)
	}
	if option.NodePassword == "" {
		return nil, fmt.Errorf("ninja %s: empty node-password", option.Name)
	}
	cfg := &ninja.Config{
		Method:   method,
		Password: option.NodePassword,
		Padding: ninja.PaddingConfig{
			Mode: ninja.PaddingMode(option.PassOptions.PaddingMode),
			Min:  option.PassOptions.PaddingMin,
			Max:  option.PassOptions.PaddingMax,
		},
	}
	client, err := ninja.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	n := &Ninja{
		Base:   NewBase(BaseOption{Type: C.Ninja, Name: option.Name, Addr: addr, UDP: false}),
		option: &option,
		client: client,
	}
	n.dialer = option.NewDialer(n.DialOptions())
	return n, nil
}

var _ C.ProxyAdapter = (*Ninja)(nil)
