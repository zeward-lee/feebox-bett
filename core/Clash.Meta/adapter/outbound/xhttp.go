package outbound

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/xhttpstream"
	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
	"go.yaml.in/yaml/v3"
)

// xhttpHandshakeTimeout bounds the client handshake (header write and the read
// of the echoed token) so a silent or hostile server cannot pin a relay
// goroutine forever. It is clamped by the dial context deadline.
const xhttpHandshakeTimeout = 10 * time.Second

// The dynamic (second generation) mode of the protocol asks the vendor's API for
// the real node list. The two keys are the static XOR envelope keys of that API,
// byte identical to the published client; they are protocol constants, not
// per-node credentials.
var (
	xhttpPrivKey = []byte("NiKNssxJcXp7Mh4yjjFGdrcFoC66wcVu5j1LgBevGCm8utV4qg089xdb20tAKu")
	xhttpPubKey  = []byte("jMJaXZXGc1CbTri1UnRdvJ3izp8f0jGhXGr2jjr9nMkBKUZDoh3Avoijc4jQUw")
)

const (
	xhttpAPIHost             = "g.just4test.xyz"
	xhttpAPIIP               = "104.21.41.69"
	xhttpMaxAPIResponseBytes = 8 << 20
	xhttpMaxPlaintextBytes   = 16 << 20

	// xhttpBlackstoneSuffix marks the shadowsocks password of a dynamic node as
	// blackstone-over-SS: the cipher registry and the ss parser strip it.
	xhttpBlackstoneSuffix = "#BLACKSTONE"
)

// xhttpRealConfig is one node resolved from the vendor API, in the shape both
// downstream modes need.
type xhttpRealConfig struct {
	Name     string
	Type     string
	Server   string
	Port     string
	Password string
	Cipher   string
	TcpFake  string
}

// XHttpOption is the `type: xhttp` node.
//
// The first block is exactly the option table the vendor core reads: name,
// server, port, password, cipher, udp, udp-over-tcp, udp-over-tcp-version,
// padding-len and fake-net, plus `node-id` for the dynamic mode. `password` is
// the transport password in "<secret>:<hmac-hex>" form, the vendor's encrypted
// node config blob (see xhttpstream.DecodeConfigBlob), in which case the blob
// supplies the values the YAML leaves out, or the API token of a dynamic node
// (`node-id` set), in which case the real server is resolved at first use.
//
// The second block is what a vendor subscription node carries on top. The
// vendor app strips those keys before it hands the node to its core; they are
// accepted here (and marked omitempty) so a node can be pasted from a
// subscription as-is. `uuid` is deliberately not part of the table: the
// protocol has no UUID, and keeping it out keeps the custom-proxy form's
// credential list honest.
type XHttpOption struct {
	BasicOption
	Name              string            `proxy:"name"`
	Server            string            `proxy:"server"`
	Port              int               `proxy:"port"`
	Password          string            `proxy:"password"`
	NodeID            string            `proxy:"node-id,omitempty"`
	Cipher            string            `proxy:"cipher,omitempty"`
	UDP               bool              `proxy:"udp,omitempty"`
	UDPOverTCP        bool              `proxy:"udp-over-tcp,omitempty"`
	UDPOverTCPVersion int               `proxy:"udp-over-tcp-version,omitempty"`
	PaddingLen        string            `proxy:"padding-len,omitempty"`
	FakeNet           map[string]string `proxy:"fake-net,omitempty"`

	Network           string       `proxy:"network,omitempty"`
	TLS               bool         `proxy:"tls,omitempty"`
	ServerName        string       `proxy:"servername,omitempty"`
	SNI               string       `proxy:"sni,omitempty"`
	ALPN              []string     `proxy:"alpn,omitempty"`
	SkipCertVerify    bool         `proxy:"skip-cert-verify,omitempty"`
	Certificate       string       `proxy:"certificate,omitempty"`
	PrivateKey        string       `proxy:"private-key,omitempty"`
	ClientFingerprint string       `proxy:"client-fingerprint,omitempty"`
	XHTTPOpts         XHTTPOptions `proxy:"xhttp-opts,omitempty"`
	Clover            string       `proxy:"clover,omitempty"`
	Encryption        string       `proxy:"encryption,omitempty"`
	// Gateway is the vendor subscription's spelling of the same gateway endpoint
	// Clover carries in the app-side node JSON (see isHeySocksXHttp). It is read
	// only as an identity marker; the transport does not use it.
	Gateway   string `proxy:"gateway,omitempty"`
	UpSpeed   string `proxy:"up-speed,omitempty"`
	DownSpeed string `proxy:"down-speed,omitempty"`
}

// XHttp is the private xhttp outbound.
//
// It runs in one of two modes, picked once at load time:
//
//   - static: the node carries a transport password ("<secret>:<hmac-hex>") or
//     a vendor config blob. The outbound is a forged 128 byte prefix around an
//     AES-CTR stream, with the destination sent as the first encrypted bytes.
//   - dynamic: the node carries an API token and a `node-id`. The real node list
//     is fetched, decoded and raced on first use; the winner is either a
//     shadowsocks node (blackstone-over-SS) or another xhttp hop.
type XHttp struct {
	*Base
	option *XHttpOption
	// static mode
	cipher *xhttpstream.StreamCipher
	// dynamic mode
	dynamic    bool
	initMu     sync.Mutex
	isInit     bool
	initErr    error
	bestCfg    xhttpRealConfig
	lastFetch  time.Time
	ssOutbound C.ProxyAdapter
	ssUDP      atomic.Bool
}

// proxyTag reports the `proxy` tag name of a struct field, or "" when the field
// is not part of the option table.
func proxyTag(field reflect.StructField) string {
	tag := field.Tag.Get("proxy")
	if tag == "" || tag == "-" {
		return ""
	}
	for i := 0; i < len(tag); i++ {
		if tag[i] == ',' {
			return tag[:i]
		}
	}
	return tag
}

// explicitKeys records the keys the YAML side actually set, before the blob is
// merged in. A key is "set" when its field is non-zero: the YAML decode has
// already collapsed absent keys to their zero value, so a key that is present
// but set to its zero value is indistinguishable from an absent one. That is
// the intended reading for a node table (an explicit `udp: false` and no `udp`
// mean the same thing).
func explicitKeys(option *XHttpOption) map[string]bool {
	keys := make(map[string]bool)
	value := reflect.ValueOf(option).Elem()
	typ := value.Type()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Anonymous {
			continue
		}
		name := proxyTag(field)
		if name == "" {
			continue
		}
		if !value.Field(i).IsZero() {
			keys[name] = true
		}
	}
	return keys
}

// fillMissing copies every non-zero blob field into an option field the YAML
// left unset. `name` is never taken from the blob, and nested option tables
// (xhttp-opts) are treated as one value, mirroring how the vendor core reads
// them.
func fillMissing(option *XHttpOption, fromBlob XHttpOption, explicit map[string]bool) {
	dst := reflect.ValueOf(option).Elem()
	src := reflect.ValueOf(fromBlob)
	typ := dst.Type()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Anonymous {
			continue
		}
		name := proxyTag(field)
		if name == "" || name == "name" || name == "fake-net" {
			// name belongs to the YAML node; fake-net is merged per key below.
			continue
		}
		if explicit[name] {
			continue
		}
		if !dst.Field(i).CanSet() || src.Field(i).IsZero() {
			continue
		}
		dst.Field(i).Set(src.Field(i))
	}
}

// applyConfigBlob fills the option values the YAML left out from the vendor
// node config blob when `password` is one. YAML always wins: the blob only
// supplies defaults, so an operator can override a node without re-encoding the
// blob. A server/port conflict is logged because it is the one clash that
// silently sends traffic to the wrong host.
func applyConfigBlob(option *XHttpOption) error {
	blob, isBlob, err := xhttpstream.DecodeConfigBlob(option.Password)
	if err != nil {
		return fmt.Errorf("xhttp: decode node config: %w", err)
	}
	if !isBlob {
		return nil
	}
	var fromBlob XHttpOption
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	if err := decoder.Decode(blob, &fromBlob); err != nil {
		return fmt.Errorf("xhttp: decode node config fields: %w", err)
	}
	explicit := explicitKeys(option)
	if option.Server != "" && fromBlob.Server != "" && option.Server != fromBlob.Server {
		log.Warnln("[XHttp](%s) config server %q overrides node blob server %q", option.Name, option.Server, fromBlob.Server)
	}
	if option.Port != 0 && fromBlob.Port != 0 && option.Port != fromBlob.Port {
		log.Warnln("[XHttp](%s) config port %d overrides node blob port %d", option.Name, option.Port, fromBlob.Port)
	}
	fillMissing(option, fromBlob, explicit)
	// fake-net is a map of per-transport prefixes: fill the keys the YAML does
	// not name, keep the ones it does.
	if len(fromBlob.FakeNet) > 0 {
		if option.FakeNet == nil {
			option.FakeNet = make(map[string]string, len(fromBlob.FakeNet))
		}
		for key, value := range fromBlob.FakeNet {
			if _, ok := option.FakeNet[key]; !ok {
				option.FakeNet[key] = value
			}
		}
	}
	// The blob is a wrapper, not a credential: the transport password always
	// comes from inside it.
	if fromBlob.Password != "" {
		option.Password = fromBlob.Password
	}
	return nil
}

// isHeySocksXHttp reports whether the node is the vendor's own xhttp flavour,
// which publishes the site identity `Heysocks` instead of the plain `Xhttp`.
//
// The marker is the node's gateway endpoint, written by the vendor client on
// every one of its nodes:
//
//   - the app-side / memory-extracted node JSON spells it `clover: <gateway>`
//     and tags the wire `encryption: fake-net`;
//   - the downloadable subscription (the HeySocks profile on this machine)
//     spells the same gateway `gateway: <host:port>` and carries `sess`/`auth`
//     next to it.
//
// Any of the three keys is enough. `fake-net` on its own is deliberately not a
// marker: the transport uses that frame layout on both flavours, so keying on it
// would merge the Heysocks identity back into Xhttp — the two identities must
// stay separate. A plain `type: xhttp` node carries none of these keys and keeps
// reporting Xhttp.
func isHeySocksXHttp(option *XHttpOption) bool {
	if strings.TrimSpace(option.Clover) != "" {
		return true
	}
	if strings.TrimSpace(option.Gateway) != "" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(option.Encryption), "fake-net")
}

// NewXHttp builds the adapter and resolves every static option up front, so a
// bad node fails at load time instead of on the first connection.
//
// A node with `node-id` is dynamic: its password is the API token, not a
// transport password, so nothing is validated here and the real server is
// resolved on first use. Every other node is static: an optional config blob is
// unwrapped first, then the transport password is parsed.
func NewXHttp(option XHttpOption) (*XHttp, error) {
	if option.NodeID != "" {
		return newDynamicXHttp(option)
	}
	if err := applyConfigBlob(&option); err != nil {
		return nil, err
	}
	if option.Server == "" {
		return nil, fmt.Errorf("xhttp: server is required")
	}
	if option.Port < 1 || option.Port > 65535 {
		return nil, fmt.Errorf("xhttp: invalid port %d", option.Port)
	}
	if _, _, err := xhttpstream.SplitTransportPassword(option.Password); err != nil {
		return nil, err
	}
	if _, _, err := xhttpstream.ParsePaddingLen(option.PaddingLen); err != nil {
		return nil, err
	}
	switch option.UDPOverTCPVersion {
	case uot.Version, uot.LegacyVersion:
	case 0:
		option.UDPOverTCPVersion = uot.LegacyVersion
	default:
		return nil, fmt.Errorf("xhttp: unknown udp-over-tcp-version %d", option.UDPOverTCPVersion)
	}
	if option.UDP && !option.UDPOverTCP {
		// The plain UDP frame layout is reconstructed, not yet validated
		// against a live server. Keep the path (the vendor nodes carry `udp`
		// without `udp-over-tcp`) but say so once per node.
		log.Warnln("[XHttp](%s) udp: true without udp-over-tcp uses the unverified plain UDP framing; prefer udp-over-tcp: true", option.Name)
	}
	ciph, err := xhttpstream.PickCipher(option.Cipher, nil, option.Password, option.FakeNet)
	if err != nil {
		return nil, fmt.Errorf("xhttp: initialize cipher: %w", err)
	}
	x := &XHttp{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			Type:         C.XHttp,
			ProviderName: option.ProviderName,
			UDP:          option.UDP || option.UDPOverTCP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
		cipher: ciph,
	}
	x.dialer = option.NewDialer(x.DialOptions())
	// The identity is decided from the resolved option table (after the config
	// blob merge), and Type()/MarshalJSON both read Base.tp, so the API and the
	// UI see Heysocks for the vendor's own nodes and Xhttp for plain ones.
	if isHeySocksXHttp(&option) {
		x.SetAdapterType(C.Heysocks)
	}
	return x, nil
}

// newDynamicXHttp builds the adapter for an API backed node. The YAML address is
// the address a URLTest pings; traffic goes to whichever node the API returns.
func newDynamicXHttp(option XHttpOption) (*XHttp, error) {
	if option.Server == "" {
		return nil, fmt.Errorf("xhttp: server is required")
	}
	if option.Port < 1 || option.Port > 65535 {
		return nil, fmt.Errorf("xhttp: invalid port %d", option.Port)
	}
	if option.Password == "" {
		return nil, fmt.Errorf("xhttp: dynamic xhttp node requires a password (API token)")
	}
	x := &XHttp{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			Type:         C.XHttp,
			ProviderName: option.ProviderName,
			UDP:          true,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:  &option,
		dynamic: true,
	}
	x.dialer = option.NewDialer(x.DialOptions())
	if isHeySocksXHttp(&option) {
		x.SetAdapterType(C.Heysocks)
	}
	return x, nil
}

// IsDynamic reports whether the real node is resolved through the vendor API.
func (x *XHttp) IsDynamic() bool { return x.dynamic }

// snapshotDynamic returns the resolved node and its shadowsocks outbound under
// the init lock, so a refresh that swaps them cannot race a dial.
func (x *XHttp) snapshotDynamic() (xhttpRealConfig, C.ProxyAdapter) {
	x.initMu.Lock()
	defer x.initMu.Unlock()
	return x.bestCfg, x.ssOutbound
}

// XHttpProxyWrapper overrides URLTest for the dynamic mode.
//
// A dynamic node's YAML address is a front, not the address a connection goes
// to, so a real URL test would either pay for a full API round trip or measure a
// host that carries no traffic. The test therefore only pings the configured TCP
// address, which is what the vendor client shows in its latency column.
type XHttpProxyWrapper struct {
	C.Proxy
	adapter *XHttp
}

func (p *XHttpProxyWrapper) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	start := time.Now()

	conn, err := p.adapter.dialer.DialContext(ctx, "tcp", p.adapter.addr)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()

	return uint16(time.Since(start).Milliseconds()), nil
}

// NewXHttpProxyWrapper wraps a built proxy so its URL test pings the configured
// address instead of resolving the dynamic node.
func NewXHttpProxyWrapper(baseProxy C.Proxy, adapter *XHttp) C.Proxy {
	return &XHttpProxyWrapper{Proxy: baseProxy, adapter: adapter}
}

// pingRace returns the first of configs whose TCP address accepts a connection.
// Each attempt is bounded so an unreachable node cannot stretch the dial.
func (x *XHttp) pingRace(ctx context.Context, configs []xhttpRealConfig) (xhttpRealConfig, error) {
	if len(configs) == 1 {
		return configs[0], nil
	}
	type raceResult struct {
		cfg xhttpRealConfig
		err error
	}
	resCh := make(chan raceResult, len(configs))
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for _, cfg := range configs {
		wg.Add(1)
		go func(c xhttpRealConfig) {
			defer wg.Done()
			addr := net.JoinHostPort(c.Server, c.Port)
			dialCtx, dialCancel := context.WithTimeout(raceCtx, 3*time.Second)
			defer dialCancel()

			conn, err := x.dialer.DialContext(dialCtx, "tcp", addr)
			if err == nil {
				_ = conn.Close()
				cancel()
			}
			resCh <- raceResult{cfg: c, err: err}
		}(cfg)
	}

	go func() { wg.Wait(); close(resCh) }()

	var firstErr error
	for res := range resCh {
		if res.err == nil {
			return res.cfg, nil
		}
		if firstErr == nil {
			firstErr = res.err
		}
	}
	return xhttpRealConfig{}, fmt.Errorf("all dynamic nodes failed tcp ping: %v", firstErr)
}

// lazyInit resolves the real node on first use and re-resolves it after an hour.
func (x *XHttp) lazyInit(ctx context.Context) error {
	x.initMu.Lock()
	defer x.initMu.Unlock()

	if x.isInit {
		if time.Since(x.lastFetch) < 1*time.Hour {
			return x.initErr
		}
		x.isInit = false
	}

	// The API call is deliberately independent of the dial context: a cancelled
	// dial must not poison the cached node for the next connection.
	apiCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	allConfigs, err := x.fetchDynamicConfig(apiCtx, x.option.NodeID, x.option.Password)
	if err != nil {
		x.initErr = err
		return err
	}

	var matchedConfigs []xhttpRealConfig
	isSingleNode := len(allConfigs) == 1

	for _, cfg := range allConfigs {
		if !isSingleNode && x.option.Name != "" {
			cleanNodeName := strings.ReplaceAll(x.option.Name, "#", " ")
			cleanNodeName = strings.ReplaceAll(cleanNodeName, "-", " ")
			cleanNodeName = strings.ReplaceAll(cleanNodeName, "|", " ")
			keywords := strings.Fields(cleanNodeName)

			isMatch := true
			for _, kw := range keywords {
				if !strings.Contains(cfg.Name, kw) {
					isMatch = false
					break
				}
			}
			if !isMatch {
				continue
			}
		}
		matchedConfigs = append(matchedConfigs, cfg)
	}

	if len(matchedConfigs) == 0 {
		x.initErr = fmt.Errorf("no target node matched for name: %s", x.option.Name)
		return x.initErr
	}

	best, err := x.pingRace(apiCtx, matchedConfigs)
	if err != nil {
		x.initErr = err
		return err
	}

	x.bestCfg = best
	x.ssOutbound = nil
	x.ssUDP.Store(false)
	if best.Type == "ss" {
		portInt, convErr := strconv.Atoi(best.Port)
		if convErr != nil {
			x.initErr = fmt.Errorf("dynamic ss node port %q: %w", best.Port, convErr)
			return x.initErr
		}
		ssOpt := ShadowSocksOption{
			BasicOption: x.option.BasicOption,
			Name:        x.option.Name + "_ss",
			Server:      best.Server,
			Port:        portInt,
			Password:    best.Password + xhttpBlackstoneSuffix,
			Cipher:      best.Cipher,
		}
		x.ssOutbound, x.initErr = NewShadowSocks(ssOpt)
		if x.initErr != nil {
			return x.initErr
		}
		x.ssUDP.Store(true)
	}

	x.isInit = true
	x.initErr = nil
	x.lastFetch = time.Now()
	return nil
}

// handshakeDeadline is min(now + xhttpHandshakeTimeout, ctx deadline).
func handshakeDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(xhttpHandshakeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return deadline
}

// dialStream dials the server and hands the xhttp handshake to the relay phase
// with the mihomo EarlyConn convention: the forged prefix, token, HMAC and IV
// are written on the first read/write of the returned conn instead of inside
// DialContext. A failure therefore surfaces as an I/O error of the relay (which
// closes the connection) and never blocks the dial path, while the token echo
// is validated on the first read under a deadline.
func (x *XHttp) dialStream(ctx context.Context, destination []byte) (net.Conn, error) {
	conn, err := x.dialer.DialContext(ctx, "tcp", x.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", x.addr, err)
	}
	streamConn := x.cipher.StreamConn(conn, destination)
	if setter, ok := streamConn.(interface{ SetHandshakeDeadline(time.Time) }); ok {
		setter.SetHandshakeDeadline(handshakeDeadline(ctx))
	}
	if !N.NeedHandshake(streamConn) {
		return streamConn, nil
	}
	return N.NewEarlyConn(streamConn, func() error {
		deadline := handshakeDeadline(ctx)
		_ = streamConn.SetWriteDeadline(deadline)
		_, err := streamConn.Write(nil)
		_ = streamConn.SetWriteDeadline(time.Time{})
		if err != nil {
			// The dial already succeeded; a half-open conn here would leak a
			// socket until the relay notices, so close it now.
			_ = conn.Close()
			return fmt.Errorf("%s xhttp handshake error: %w", x.addr, err)
		}
		return nil
	}), nil
}

// DialContext implements C.ProxyAdapter.
func (x *XHttp) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if x.dynamic {
		return x.dynamicDial(ctx, metadata)
	}
	if metadata.NetWork == C.UDP {
		pc, err := x.ListenPacketContext(ctx, metadata)
		if err != nil {
			return nil, err
		}
		return NewConn(N.NewBindPacketConn(pc, metadata.UDPAddr()), x), nil
	}
	conn, err := x.dialStream(ctx, serializesSocksAddr(metadata))
	if err != nil {
		return nil, err
	}
	return NewConn(conn, x), nil
}

// dynamicDial resolves the real node and dials it: a shadowsocks node reuses the
// ss outbound (which carries the blackstone-over-SS marker), an xhttp node runs
// the same static transport against the resolved address.
func (x *XHttp) dynamicDial(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := x.lazyInit(ctx); err != nil {
		return nil, err
	}
	bestCfg, ssOutbound := x.snapshotDynamic()
	if ssOutbound != nil {
		return ssOutbound.DialContext(ctx, metadata)
	}
	addr := net.JoinHostPort(bestCfg.Server, bestCfg.Port)
	rawConn, err := x.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", addr, err)
	}
	fakeNet := map[string]string{}
	if bestCfg.TcpFake != "" {
		fakeNet["tcp"] = bestCfg.TcpFake
	}
	ciph, err := xhttpstream.PickCipher(x.option.Cipher, nil, bestCfg.Password, fakeNet)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("xhttp: dynamic node cipher: %w", err)
	}
	streamConn := ciph.StreamConn(rawConn, serializesSocksAddr(metadata))
	if setter, ok := streamConn.(interface{ SetHandshakeDeadline(time.Time) }); ok {
		setter.SetHandshakeDeadline(handshakeDeadline(ctx))
	}
	if !N.NeedHandshake(streamConn) {
		return NewConn(streamConn, x), nil
	}
	return NewConn(N.NewEarlyConn(streamConn, func() error {
		deadline := handshakeDeadline(ctx)
		_ = streamConn.SetWriteDeadline(deadline)
		_, err := streamConn.Write(nil)
		_ = streamConn.SetWriteDeadline(time.Time{})
		if err != nil {
			_ = rawConn.Close()
			return fmt.Errorf("%s xhttp handshake error: %w", addr, err)
		}
		return nil
	}), x), nil
}

// listenPacketContext opens the plain UDP carrier the same way shadowsocks does:
// resolve the server address, ask the dialer for an unconnected socket, then
// bind it to the server with bufio.NewBindPacketConn so interface/routing-mark
// options and the resolved address actually apply.
func (x *XHttp) listenPacketContext(ctx context.Context) (net.PacketConn, net.Addr, error) {
	addr, err := resolveUDPAddr(ctx, "udp", x.addr, x.option.IPVersion)
	if err != nil {
		return nil, nil, err
	}
	pc, err := x.dialer.ListenPacket(ctx, "udp", "", addr.AddrPort())
	if err != nil {
		return nil, nil, fmt.Errorf("%s udp listen error: %w", x.addr, err)
	}
	return pc, addr, nil
}

// ListenPacketContext implements C.ProxyAdapter. UDP runs over the same stream
// with the sing-box UOT framing when udp-over-tcp is on, and over a UDP socket
// with per-datagram frames otherwise. A dynamic xhttp node has no UDP path; a
// dynamic ss node delegates.
func (x *XHttp) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if x.dynamic {
		if err := x.lazyInit(ctx); err != nil {
			return nil, err
		}
		_, ssOutbound := x.snapshotDynamic()
		if ssOutbound != nil {
			return ssOutbound.ListenPacketContext(ctx, metadata)
		}
		return nil, C.ErrNotSupport
	}
	if err := x.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	if x.option.UDPOverTCP {
		uotDestination := uot.RequestDestination(uint8(x.option.UDPOverTCPVersion))
		uotMetadata := *metadata
		uotMetadata.Host = uotDestination.Fqdn
		uotMetadata.DstPort = uotDestination.Port
		conn, err := x.dialStream(ctx, serializesSocksAddr(&uotMetadata))
		if err != nil {
			return nil, err
		}
		destination := M.SocksaddrFromNet(metadata.UDPAddr())
		if x.option.UDPOverTCPVersion == uot.LegacyVersion {
			return NewPacketConn(N.NewThreadSafePacketConn(uot.NewConn(conn, uot.Request{Destination: destination})), x), nil
		}
		return NewPacketConn(N.NewThreadSafePacketConn(uot.NewLazyConn(conn, uot.Request{Destination: destination})), x), nil
	}
	pc, serverAddr, err := x.listenPacketContext(ctx)
	if err != nil {
		return nil, err
	}
	// The socket is bound to the configured server (server/port from the node or
	// its config blob); the destination inside each datagram frame is the
	// per-packet SOCKS address the caller passes to WriteTo.
	carrier := bufio.NewBindPacketConn(pc, serverAddr)
	return NewPacketConn(x.cipher.PacketConn(carrier, serverAddr), x), nil
}

// SupportUDP implements C.ProxyAdapter.
func (x *XHttp) SupportUDP() bool {
	if x.dynamic {
		// Only the shadowsocks arm of a dynamic node can carry UDP. The flag is
		// read without the init lock so a relay decision never waits on an API
		// round trip.
		return x.ssUDP.Load()
	}
	return x.option.UDP || x.option.UDPOverTCP
}

// SupportUOT implements C.ProxyAdapter.
func (x *XHttp) SupportUOT() bool { return !x.dynamic && x.option.UDPOverTCP }

// ProxyInfo implements C.ProxyAdapter.
func (x *XHttp) ProxyInfo() C.ProxyInfo {
	info := x.Base.ProxyInfo()
	info.DialerProxy = x.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter. The transport holds no shared state.
func (x *XHttp) Close() error { return nil }

// readLimited reads at most limit bytes and reports a payload that would exceed
// it instead of buffering it.
func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	limited := io.LimitReader(reader, limit+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("payload exceeds %d bytes", limit)
	}
	return data, nil
}

func gunzipLimited(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return readLimited(reader, xhttpMaxPlaintextBytes)
}

// xhttpAPITransport builds the API client transport: TLS with the vendor SNI,
// verified against the system roots, and dialed through the node's dialer so
// interface/proxy options apply to the API call too.
func xhttpAPITransport(dialer C.Dialer) *http.Transport {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{ServerName: xhttpAPIHost},
		ForceAttemptHTTP2: true,
	}
	if dialer != nil {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", addr)
		}
	}
	return transport
}

// fetchDynamicConfig asks the vendor API for the node list of an API token.
func (x *XHttp) fetchDynamicConfig(ctx context.Context, nodeID, token string) ([]xhttpRealConfig, error) {
	url := fmt.Sprintf("https://%s/api/v3/proxy/config", xhttpAPIIP)

	reqMap := map[string]interface{}{
		"fastest_ping": map[string]interface{}{},
		"energy":       false,
		"id":           nodeID,
		"strategy":     "smart",
	}
	reqJson, _ := json.Marshal(reqMap)
	encryptedReq := x.encryptRequestData(string(reqJson))

	payloadMap := map[string]string{"data": encryptedReq}
	payloadJson, _ := json.Marshal(payloadMap)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payloadJson))
	if err != nil {
		return nil, fmt.Errorf("create api request: %w", err)
	}
	req.Host = xhttpAPIHost
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-version", "520")
	req.Header.Set("x-platform", "android")
	req.Header.Set("user-agent", "okhttp/4.9.2")
	req.Header.Set("x-header", x.buildXHeader(token))

	client := &http.Client{Transport: xhttpAPITransport(x.dialer)}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api request failed: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := readLimited(resp.Body, xhttpMaxAPIResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("read api response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api returned status: %d", resp.StatusCode)
	}

	var jsonResp map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &jsonResp); err != nil {
		encryptedB64 := strings.Trim(string(bodyBytes), "\"'\n\r\t ")
		return x.processApiData(encryptedB64)
	}
	encryptedB64, ok := jsonResp["data"].(string)
	if !ok || encryptedB64 == "" {
		return nil, errors.New("api data field must be a non-empty string")
	}
	return x.processApiData(encryptedB64)
}

// processApiData unwraps the two API envelopes (XOR base64, then the chunked
// ChaCha20-Poly1305 payload) and turns the YAML node list into real configs.
func (x *XHttp) processApiData(encryptedB64 string) ([]xhttpRealConfig, error) {
	if pad := len(encryptedB64) % 4; pad != 0 {
		encryptedB64 += strings.Repeat("=", 4-pad)
	}

	rawB64, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		return nil, err
	}
	for i := range rawB64 {
		rawB64[i] ^= xhttpPrivKey[i%len(xhttpPrivKey)]
	}
	if bytes.HasPrefix(rawB64, []byte("\x1f\x8b")) {
		rawB64, err = gunzipLimited(rawB64)
		if err != nil {
			return nil, fmt.Errorf("decompress api envelope: %w", err)
		}
	}

	var layer1 struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(rawB64, &layer1); err != nil {
		return nil, fmt.Errorf("decode api envelope: %w", err)
	}
	if layer1.Data == nil {
		return nil, errors.New("decrypted data field is missing")
	}
	smartB64, ok := layer1.Data["smart"].(string)
	if !ok || smartB64 == "" {
		return nil, errors.New("smart field must be a non-empty string")
	}

	smartRaw, err := base64.StdEncoding.DecodeString(smartB64)
	if err != nil {
		return nil, fmt.Errorf("decode smart payload: %w", err)
	}
	smartPlain, err := xhttpstream.DecryptBlackstonePayload(smartRaw)
	if err != nil {
		return nil, fmt.Errorf("decrypt smart payload: %w", err)
	}
	if len(smartPlain) > xhttpMaxPlaintextBytes {
		return nil, fmt.Errorf("plaintext exceeds %d bytes", xhttpMaxPlaintextBytes)
	}

	var smartData struct {
		Proxies []map[string]interface{} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(smartPlain, &smartData); err != nil {
		return nil, fmt.Errorf("decode smart config: %w", err)
	}

	var realConfigs []xhttpRealConfig
	for _, proxy := range smartData.Proxies {
		pName, _ := proxy["name"].(string)
		pType, _ := proxy["type"].(string)

		if pType == "ss" || pType == "os" {
			cipherStr, _ := proxy["cipher"].(string)
			if cipherStr == "" || cipherStr == "<nil>" {
				if pType == "os" {
					cipherStr = "aes-128-ctr"
				} else {
					cipherStr = "2022-blake3-aes-128-gcm"
				}
			}

			realConfigs = append(realConfigs, xhttpRealConfig{
				Name:     pName,
				Type:     "ss",
				Server:   fmt.Sprintf("%v", proxy["server"]),
				Port:     fmt.Sprintf("%v", proxy["port"]),
				Password: fmt.Sprintf("%v", proxy["password"]),
				Cipher:   cipherStr,
			})
		} else if pType == "xhttp" {
			certStr, _ := proxy["certificate"].(string)
			if certStr != "" {
				realCfg, certErr := x.crackCertificate(certStr)
				if certErr == nil {
					realCfg.Name = pName
					realConfigs = append(realConfigs, realCfg)
				}
			} else {
				cfg := xhttpRealConfig{
					Name:     pName,
					Type:     "xhttp",
					Server:   fmt.Sprintf("%v", proxy["server"]),
					Port:     fmt.Sprintf("%v", proxy["port"]),
					Password: fmt.Sprintf("%v", proxy["password"]),
				}
				if fakeNet, ok := proxy["fake-net"].(map[string]interface{}); ok {
					cfg.TcpFake, _ = fakeNet["tcp"].(string)
				}
				realConfigs = append(realConfigs, cfg)
			}
		}
	}

	if len(realConfigs) == 0 {
		return nil, errors.New("api returned no valid nodes")
	}

	return realConfigs, nil
}

// crackCertificate recovers an xhttp node that the API smuggled in as a
// certificate: the DER body is hashed into a chunked payload, and the ASN.1
// offsets below are the ones the vendor client tries.
func (x *XHttp) crackCertificate(certPem string) (xhttpRealConfig, error) {
	re := regexp.MustCompile(`-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+`)
	b64Data := re.ReplaceAllString(certPem, "")
	if pad := len(b64Data) % 4; pad != 0 {
		b64Data += strings.Repeat("=", 4-pad)
	}

	raw, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return xhttpRealConfig{}, err
	}

	offsets := []int{48, 52, 56, 64}
	for _, offset := range offsets {
		if offset >= len(raw) {
			continue
		}
		plain, err := xhttpstream.DecryptBlackstonePayload(raw[offset:])
		if err == nil {
			var innerData map[string]interface{}
			if json.Unmarshal(plain, &innerData) == nil {
				cfg := xhttpRealConfig{
					Type:     "xhttp",
					Server:   fmt.Sprintf("%v", innerData["server"]),
					Port:     fmt.Sprintf("%v", innerData["port"]),
					Password: fmt.Sprintf("%v", innerData["password"]),
				}
				if fakeNet, ok := innerData["fake-net"].(map[string]interface{}); ok {
					cfg.TcpFake, _ = fakeNet["tcp"].(string)
				}
				return cfg, nil
			}
		}
	}
	return xhttpRealConfig{}, errors.New("all asn.1 offsets failed")
}

// buildXHeader builds the encrypted device header the API expects.
func (x *XHttp) buildXHeader(token string) string {
	headerMap := map[string]interface{}{
		"X-DEVICE-NAME":  "Lenovo - Lenovo TB-J606F",
		"X-IDENTIFIER":   "ed7295e154b50905",
		"X-TOKEN":        token,
		"X-TIMESTAMP":    "1779367490",
		"X-CHECK-MOBILE": `{"isRoot":true,"isEmulator":false,"bundleID":"com.heysocks.android"}`,
		"X-OS-VERSION":   "30",
	}
	headerJson, _ := json.Marshal(headerMap)
	return x.encryptRequestData(string(headerJson))
}

// encryptRequestData applies the static XOR envelope and base64.
func (x *XHttp) encryptRequestData(dataStr string) string {
	rawBytes := []byte(dataStr)
	res := make([]byte, len(rawBytes))
	for i := 0; i < len(rawBytes); i++ {
		res[i] = rawBytes[i] ^ xhttpPubKey[i%len(xhttpPubKey)]
	}
	return base64.StdEncoding.EncodeToString(res)
}

var _ C.ProxyAdapter = (*XHttp)(nil)
