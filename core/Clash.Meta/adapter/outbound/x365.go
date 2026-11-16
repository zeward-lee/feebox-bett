package outbound

import (
	"context"
	"fmt"
	"net"
	"strings"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/x365"
)

// X365 carries the X365 request header over the same REALITY + xhttp
// stack as VLESS, so it reuses the VLESS transport and only replaces the
// protocol layer.
type X365 struct {
	*Vless
	client *x365.Client
}

type X365Option struct {
	BasicOption
	Name              string         `proxy:"name"`
	Server            string         `proxy:"server"`
	Port              int            `proxy:"port"`
	UUID              string         `proxy:"uuid"`
	UDP               bool           `proxy:"udp,omitempty"`
	ALPN              []string       `proxy:"alpn,omitempty"`
	ServerName        string         `proxy:"servername,omitempty"`
	ClientFingerprint string         `proxy:"client-fingerprint,omitempty"`
	RealityOpts       RealityOptions `proxy:"reality-opts,omitempty"`
	XHTTPOpts         XHTTPOptions   `proxy:"xhttp-opts,omitempty"`
}

// StreamConnContext implements C.ProxyAdapter
func (x *X365) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	return x.client.StreamConn(c, parseX365Addr(metadata)), nil
}

// DialContext implements C.ProxyAdapter
func (x *X365) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := x.dialContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %s", x.addr, err.Error())
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = x.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %s", x.addr, err.Error())
	}
	return NewConn(c, x), err
}

// ListenPacketContext implements C.ProxyAdapter
//
// UDP keeps the VLESS/xhttp transport but replaces the TCP header with one
// x365 UDP request frame per datagram (command 0x02, see transport/x365
// PacketConn). The public x365-core reference implementation documents the
// command but has not implemented it; the flclash-private core has, and that
// is the framing this adapter follows. The `udp` yaml key still gates it, so
// subscriptions that set `udp: false` keep the proxy TCP only.
func (x *X365) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = x.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	c, err := x.dialContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %s", x.addr, err.Error())
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	// x365 only allows xhttp mode stream-one, so dialContext already returns
	// the REALITY + xhttp full-duplex stream; the xhttp client owns the TLS
	// handshake and there is no extra TLS layer to add here.
	return NewPacketConn(N.NewThreadSafePacketConn(x.client.PacketConn(c, parseX365UDPAddr(metadata))), x), nil
}

// SupportUOT implements C.ProxyAdapter
//
// The flclash-private core reports UOT support for x365; UDP datagrams travel
// over the same TCP/TLS/xhttp stream either way.
func (x *X365) SupportUOT() bool {
	return true
}

func parseX365Addr(metadata *C.Metadata) *x365.DstAddr {
	var addrType byte
	var addr []byte
	switch metadata.AddrType() {
	case C.AtypIPv4:
		addrType = x365.AtypIPv4
		addr = metadata.DstIP.AsSlice()
	case C.AtypIPv6:
		addrType = x365.AtypIPv6
		addr = metadata.DstIP.AsSlice()
	case C.AtypDomainName:
		addrType = x365.AtypDomainName
		addr = make([]byte, len(metadata.Host)+1)
		addr[0] = byte(len(metadata.Host))
		copy(addr[1:], metadata.Host)
	}

	return &x365.DstAddr{
		AddrType: addrType,
		Addr:     addr,
		Port:     metadata.DstPort,
	}
}

// parseX365UDPAddr builds the per-datagram destination. ListenPacketContext has
// already resolved the host, and the private core sends the resolved IP rather
// than a domain, so prefer DstIP and only fall back to the domain when
// resolution produced nothing.
func parseX365UDPAddr(metadata *C.Metadata) *x365.DstAddr {
	dst := &x365.DstAddr{Port: metadata.DstPort}
	ip := metadata.DstIP
	if ip.IsValid() {
		ip = ip.Unmap()
	}
	switch {
	case ip.Is4():
		dst.AddrType = x365.AtypIPv4
		dst.Addr = ip.AsSlice()
	case ip.Is6():
		dst.AddrType = x365.AtypIPv6
		dst.Addr = ip.AsSlice()
	default:
		dst.AddrType = x365.AtypDomainName
		dst.Addr = make([]byte, len(metadata.Host)+1)
		dst.Addr[0] = byte(len(metadata.Host))
		copy(dst.Addr[1:], metadata.Host)
	}
	return dst
}

func NewX365(option X365Option) (*X365, error) {
	// Subscriptions written for the public `type: vless` flavour carry the
	// protocol marker in the uuid (`uuid: <uuid>#x365`) instead of switching
	// the type. Strip it here as well as in x365.NewClient so the VLESS stack
	// built below and the X365 request header share one clean UUID.
	option.UUID = x365.TrimUUIDSuffix(option.UUID)
	switch option.XHTTPOpts.Mode {
	case "", "auto":
		option.XHTTPOpts.Mode = "stream-one"
	case "stream-one":
	default:
		return nil, fmt.Errorf("x365 only supports xhttp mode stream-one, not %s", option.XHTTPOpts.Mode)
	}
	headers := make(map[string]string, len(option.XHTTPOpts.Headers)+1)
	hasUserAgent := false
	for key, value := range option.XHTTPOpts.Headers {
		headers[key] = value
		if strings.EqualFold(key, "User-Agent") {
			hasUserAgent = true
		}
	}
	if !hasUserAgent {
		headers["User-Agent"] = x365.UserAgent
	}
	option.XHTTPOpts.Headers = headers

	v, err := NewVless(VlessOption{
		BasicOption:       option.BasicOption,
		Name:              option.Name,
		Server:            option.Server,
		Port:              option.Port,
		UUID:              option.UUID,
		UDP:               option.UDP,
		TLS:               true,
		ALPN:              option.ALPN,
		Network:           "xhttp",
		RealityOpts:       option.RealityOpts,
		XHTTPOpts:         option.XHTTPOpts,
		ServerName:        option.ServerName,
		ClientFingerprint: option.ClientFingerprint,
	})
	if err != nil {
		return nil, err
	}
	v.tp = C.X365
	// XUDP is the Xray Mux.Cool wrapper; x365 has no such command, so keep it
	// off. SupportUDP comes from the `udp` yaml key through NewBase.
	v.xudp = false

	return &X365{
		Vless:  v,
		client: x365.NewClient(option.UUID),
	}, nil
}
