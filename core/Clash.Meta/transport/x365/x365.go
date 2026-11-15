package x365

import (
	"net"
	"strings"

	"github.com/metacubex/mihomo/common/utils"

	"github.com/gofrs/uuid/v5"
)

// Magic prefixes every request header and the server's response.
var Magic = [4]byte{'X', '3', '6', '5'}

const (
	Version byte = 1

	CommandTCP byte = 1

	StatusOK byte = 0

	// UserAgent is the exact user agent X365 servers expect on the tunnel
	// request; any other value is rejected with 403.
	UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

// Addr types
const (
	AtypIPv4       byte = 1
	AtypDomainName byte = 2
	AtypIPv6       byte = 3
)

// DstAddr store destination address
type DstAddr struct {
	AddrType byte
	Addr     []byte
	Port     uint16
}

// Client is x365 connection generator
type Client struct {
	uuid uuid.UUID
}

// StreamConn return a Conn with net.Conn and DstAddr
func (c *Client) StreamConn(conn net.Conn, dst *DstAddr) net.Conn {
	return newConn(conn, c, dst)
}

// uuidSuffix is the marker subscriptions built for the public `type: vless`
// flavour append to the uuid instead of switching the type to `x365`. The
// flclash-private configs carry the same suffix on `type: x365` nodes, so the
// adapter and this client both drop it before parsing.
const uuidSuffix = "#x365"

// TrimUUIDSuffix removes a trailing `#x365` marker from a uuid so the value
// parses as a plain UUID. The match is case-insensitive and surrounding
// whitespace is ignored, matching mihomo's `parseVlessUUIDMode`. A uuid without
// the marker is returned unchanged.
func TrimUUIDSuffix(uuidStr string) string {
	trimmed := strings.TrimSpace(uuidStr)
	if len(trimmed) >= len(uuidSuffix) && strings.EqualFold(trimmed[len(trimmed)-len(uuidSuffix):], uuidSuffix) {
		return strings.TrimSpace(trimmed[:len(trimmed)-len(uuidSuffix)])
	}
	return trimmed
}

// NewClient return Client instance
func NewClient(uuidStr string) *Client {
	return &Client{
		uuid: utils.UUIDMap(TrimUUIDSuffix(uuidStr)),
	}
}
