package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/sntp_eclipse"
)

// SNTPEclipse is the "守候网络 / SNTP 封端" private protocol
// (sntp-eclipse-v3-native-1): X25519 handshake, HKDF-SHA256 key schedule and
// length-framed XChaCha20-Poly1305 records over plain TCP.
//
// Wire spec: scratch/flclash-ipc/report-sntp-eclipse.md §11 and §13.
// Reference client: scratch/flclash-ipc/re-sntp/client_final.py.
//
// UDP: the hello command byte has a second value (cmd=2) that the vendor
// binary accepts, but neither the UDP payload framing nor a single accepted
// UDP datagram was ever observed (§13.5). Implementing an invented
// udp-over-tcp shape would silently blackhole UDP instead of failing loudly,
// so this transport is TCP-only: Base.UDP is false and SupportUOT is false.
// The extractor therefore writes `udp: false` for these nodes even when the
// vendor config says `udp: true`.
type SNTPEclipse struct {
	*Base
	option *SNTPEclipseOption
	config sntp_eclipse.ClientConfig
}

type SNTPEclipseOption struct {
	BasicOption
	Name string `proxy:"name"`
	// Server is the pre-pool IP (or hostname) the vendor config ships; the
	// extractor rewrites it to the IP resolved through the private DoH.
	Server string `proxy:"server"`
	Port   int    `proxy:"port"`
	// UUID is the 32 hex characters sent verbatim as hello's meta field.
	UUID string `proxy:"uuid"`
	// ServerPublicKey is the node's static X25519 public key, base64url.
	ServerPublicKey string `proxy:"server-public-key"`
	// Mode must stay "sntp-eclipse-v3-native-1"; it is also the HKDF info
	// prefix, so aliasing it breaks the key schedule.
	Mode string `proxy:"mode,omitempty"`
	// UDP is accepted for config compatibility but ignored: see the type doc.
	UDP bool `proxy:"udp,omitempty"`
	// SNTPReportScope is stored only. It never appears in the handshake
	// (§10.4 / §11.1); the vendor uses it for its own reporting channel.
	SNTPReportScope string `proxy:"sntp-report-scope,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (s *SNTPEclipse) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	host, port, err := s.sntpEclipseTarget(metadata)
	if err != nil {
		return nil, err
	}

	rawConn, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(rawConn)

	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, rawConn)
		defer done(&err)
	}

	conn, err := sntp_eclipse.Dial(rawConn, s.config, sntp_eclipse.Target{Host: host, Port: port})
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
	}
	return NewConn(conn, s), nil
}

// ListenPacketContext implements C.ProxyAdapter.
//
// The wire dialect only has a verified CONNECT command, so UDP is refused
// explicitly instead of being wrapped in an unverified frame.
func (s *SNTPEclipse) ListenPacketContext(_ context.Context, _ *C.Metadata) (C.PacketConn, error) {
	return nil, fmt.Errorf("sntp-eclipse: UDP is not supported by this transport (only cmd=1 CONNECT is verified)")
}

// SupportUOT implements C.ProxyAdapter
func (s *SNTPEclipse) SupportUOT() bool {
	return false
}

// ProxyInfo implements C.ProxyAdapter
func (s *SNTPEclipse) ProxyInfo() C.ProxyInfo {
	info := s.Base.ProxyInfo()
	info.DialerProxy = s.option.DialerProxy
	return info
}

func (s *SNTPEclipse) sntpEclipseTarget(metadata *C.Metadata) (string, uint16, error) {
	if metadata == nil || metadata.DstPort == 0 || !metadata.Valid() {
		return "", 0, fmt.Errorf("invalid metadata for sntp-eclipse outbound")
	}
	host := metadata.Host
	if host == "" && metadata.DstIP.IsValid() {
		host = metadata.DstIP.Unmap().String()
	}
	if host == "" {
		return "", 0, fmt.Errorf("sntp-eclipse: target host is empty")
	}
	return host, metadata.DstPort, nil
}

func NewSNTPEclipse(option SNTPEclipseOption) (*SNTPEclipse, error) {
	if option.Server == "" {
		return nil, fmt.Errorf("sntp-eclipse: server is required")
	}
	if option.Port <= 0 || option.Port > 65535 {
		return nil, fmt.Errorf("sntp-eclipse: invalid port: %d", option.Port)
	}
	if option.ServerPublicKey == "" {
		return nil, fmt.Errorf("sntp-eclipse: server-public-key is required")
	}
	if _, err := sntp_eclipse.DecodeServerPublicKey(option.ServerPublicKey); err != nil {
		return nil, err
	}
	if _, err := sntp_eclipse.DecodeUUID(option.UUID); err != nil {
		return nil, err
	}
	mode := option.Mode
	if mode == "" {
		mode = sntp_eclipse.NativeV3Mode
	}
	if mode != sntp_eclipse.NativeV3Mode {
		return nil, fmt.Errorf("sntp-eclipse: unsupported mode %q", option.Mode)
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &SNTPEclipse{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.SNTPEclipse,
			ProviderName: option.ProviderName,
			// TCP only: see the type doc for why UDP is refused.
			UDP:         false,
			TFO:         option.TFO,
			MPTCP:       option.MPTCP,
			Interface:   option.Interface,
			RoutingMark: option.RoutingMark,
			Prefer:      option.IPVersion,
		}),
		option: &option,
		config: sntp_eclipse.ClientConfig{
			Mode:            mode,
			ServerPublicKey: option.ServerPublicKey,
			UUID:            option.UUID,
		},
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}
