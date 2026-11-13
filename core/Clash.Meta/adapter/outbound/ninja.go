package outbound

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/ninja"
)

// Ninja is the ninja tunnel outbound.
//
// Wire stack (as implemented by the reference client):
//
//	TCP -> TLS(SNI) -> WebSocket(path) -> pass layer -> core layer -> payload
type Ninja struct {
	*Base
	option *NinjaOption
	cfg    *ninja.Config
	pass   *ninja.PassConfig
	ws     *NinjaWSOptions
}

// NinjaWSConfig mirrors the ws-opts block.
type NinjaWSConfig struct {
	Path    string            `proxy:"path,omitempty"`
	Headers map[string]string `proxy:"headers,omitempty"`
}

// NinjaWSConfig is aliased below.

// NinjaPassOptions controls the pass layer.
type NinjaPassOptions struct {
	Method      string `proxy:"method,omitempty"`
	Password    string `proxy:"password,omitempty"`
	PaddingMode string `proxy:"padding_mode,omitempty"`
	PaddingMin  int    `proxy:"padding_min,omitempty"`
	PaddingMax  int    `proxy:"padding_random_max,omitempty"`
}

// NinjaWSOptions mirrors ws-opts.
type NinjaWSOptions struct {
	Path    string            `proxy:"path,omitempty"`
	Headers map[string]string `proxy:"headers,omitempty"`
}

type NinjaOption struct {
	BasicOption
	Name             string            `proxy:"name"`
	Server           string            `proxy:"server"`
	Port             int               `proxy:"port"`
	Password         string            `proxy:"password,omitempty"`
	NodePassword     string            `proxy:"node-password"`
	Method           string            `proxy:"method"`
	UDP              bool              `proxy:"udp,omitempty"`
	TLS              bool              `proxy:"tls,omitempty"`
	Servername       string            `proxy:"servername,omitempty"`
	SNI              string            `proxy:"sni,omitempty"`
	SkipCertVerify   bool              `proxy:"skip-cert-verify,omitempty"`
	Network          string            `proxy:"network,omitempty"`
	WSOpts           NinjaWSOptions    `proxy:"ws-opts,omitempty"`
	Pass             bool              `proxy:"pass,omitempty"`
	PassOpts         NinjaPassOptions  `proxy:"pass-opts,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (n *Ninja) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := n.dialer.DialContext(ctx, "tcp", n.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", n.addr, err)
	}
	defer func(c net.Conn) {
		if err != nil {
			_ = c.Close()
		}
	}(c)

	conn := c
	if n.option.TLS {
		sni := n.option.Servername
		if sni == "" {
			sni = n.option.SNI
		}
		if sni == "" {
			sni = n.option.Server
		}
		tc := tls.Client(conn, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: n.option.SkipCertVerify,
			NextProtos:         []string{"http/1.1"},
		})
		if err = tc.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("%s tls error: %w", n.addr, err)
		}
		conn = tc
	}
	if strings.EqualFold(n.option.Network, "ws") {
		host := n.option.Servername
		if v, ok := n.option.WSOpts.Headers["Host"]; ok && v != "" {
			host = v
		}
		if host == "" {
			host = n.option.Server
		}
		path := n.option.WSOpts.Path
		if path == "" {
			path = "/"
		}
		conn, err = NewNinjaWSConn(conn, host, path)
		if err != nil {
			return nil, fmt.Errorf("%s ws error: %w", n.addr, err)
		}
	}
	if n.pass != nil {
		conn = ninja.NewPassConn(conn, n.pass, nil)
	}

	host := metadata.Host
	if host == "" {
		host = metadata.DstIP.String()
	} else if h, _, e := net.SplitHostPort(host); e == nil {
		host = h
	}
	stream := ninja.NewConn(conn, n.cfg, true)
	addr, err := ninja.EncodeSocksAddr(host, metadata.DstPort)
	if err != nil {
		return nil, err
	}
	stream.SetAddr(addr)
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
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	n := &Ninja{
		Base:   NewBase(BaseOption{Type: C.Ninja, Name: option.Name, Addr: addr, UDP: false}),
		option: &option,
	}
	n.cfg = &ninja.Config{
		Method:       method,
		Password:     option.Password,
		NodePassword: option.NodePassword,
	}
	n.dialer = option.NewDialer(n.DialOptions())

	if option.Pass && option.PassOpts.Password != "" {
		passMethod := ninja.Method(option.PassOpts.Method)
		if passMethod == "" {
			passMethod = method
		}
		pc, err := ninja.NewPassConfig(passMethod, option.PassOpts.Password)
		if err != nil {
			return nil, fmt.Errorf("ninja %s: pass config: %w", option.Name, err)
		}
		pc.Padding = ninja.PaddingConfig{
			Mode: ninja.PaddingMode(option.PassOpts.PaddingMode),
			Min:  option.PassOpts.PaddingMin,
			Max:  option.PassOpts.PaddingMax,
		}
		n.pass = pc
	}
	return n, nil
}

var _ C.ProxyAdapter = (*Ninja)(nil)
