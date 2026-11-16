package vless

import (
	"net"

	"github.com/metacubex/mihomo/common/utils"

	"github.com/gofrs/uuid/v5"
)

const (
	XRO = "xtls-rprx-origin"
	XRD = "xtls-rprx-direct"
	XRS = "xtls-rprx-splice"
	XRV = "xtls-rprx-vision"

	Version byte = 0 // protocol version. preview version is 0
)

// Command types
const (
	CommandTCP byte = 1
	CommandUDP byte = 2
	CommandMux byte = 3
)

// Addr types
const (
	AtypIPv4       byte = 1
	AtypDomainName byte = 2
	AtypIPv6       byte = 3
)

// DstAddr store destination address
type DstAddr struct {
	UDP      bool
	AddrType byte
	Addr     []byte
	Port     uint16
	Mux      bool // currently used for XUDP only
}

// Client is vless connection generator
type Client struct {
	uuid   uuid.UUID
	Addons *Addons
	// IsX365 selects the x365 request format for a `type: vless` node whose uuid
	// carries the #x365 marker. The standalone `type: x365` outbound keeps its own
	// transport; this flag only covers a node pasted with the marker.
	IsX365 bool
	// mode selects the private wire format. ModeStandard is the upstream vless
	// request; ModeJuzi adds an HMAC tag to it; ModeX365 replaces it with the
	// x365 request; ModePure replaces it entirely.
	mode PrivateMode
}

// PrivateMode reports the private wire format the uuid markers of this client
// selected: ModeX365 for the "#x365" suffix, ModeJuzi for "#juzi", ModePure for
// "#pure", and ModeStandard for a node without a marker. The outbound adapter
// publishes the vendor identity from it, so one node string drives both the
// wire and the name the API/UI show.
func (c *Client) PrivateMode() PrivateMode {
	return c.mode
}

// StreamConn return a Conn with net.Conn and DstAddr
func (c *Client) StreamConn(conn net.Conn, dst *DstAddr) (net.Conn, error) {
	if c.mode == ModePure {
		return c.dialPure(conn, dst)
	}
	return newConn(conn, c, dst)
}

func (c *Client) PacketConn(conn net.Conn, rAddr net.Addr) net.PacketConn {
	if c.mode == ModePure {
		return &purePacketReject{}
	}
	return &PacketConn{conn, rAddr}
}

// NewClient return Client instance
//
// A UUID may carry a private protocol marker as its suffix (#juzi, #pure). The
// marker is stripped here and recorded as the client mode, so one node string
// drives one wire format.
func NewClient(uuidStr string, addons *Addons) (*Client, error) {
	cleanID, mode, err := parsePrivateUUID(uuidStr)
	if err != nil {
		return nil, err
	}
	if mode == ModePure {
		key, _, err := pureIdentity(uuidStr)
		if err != nil {
			return nil, err
		}
		return &Client{uuid: key, Addons: addons, mode: mode}, nil
	}
	uid := utils.UUIDMap(cleanID)
	return &Client{
		uuid:   uid,
		Addons: addons,
		mode:   mode,
		IsX365: mode == ModeX365,
	}, nil
}
