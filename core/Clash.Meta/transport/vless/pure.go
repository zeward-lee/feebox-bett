package vless

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// PrivateMode keeps the private wire formats of the vless transport mutually
// exclusive: a node marks its flavour with a suffix on the UUID, and a UUID that
// carries two markers is rejected instead of silently picking one.
type PrivateMode uint8

const (
	ModeStandard PrivateMode = iota
	ModeX365
	ModeJuzi
	ModePure
)

// parsePrivateUUID splits the private marker off a UUID. The marker must be the
// one exact suffix: a marker in the middle of the string, or two markers, is an
// error rather than a guess.
func parsePrivateUUID(value string) (id string, mode PrivateMode, err error) {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "#pure") {
		rest := value[:strings.LastIndex(lower, "#pure")]
		if !strings.HasSuffix(lower, "#pure") ||
			strings.Contains(strings.ToLower(rest), "#juzi") || strings.Contains(rest, "#x365") {
			return "", ModePure, fmt.Errorf("private protocol markers must be one exact suffix")
		}
		id = rest
		if !canonicalUUID(id) {
			return "", ModePure, fmt.Errorf("Pure: canonical UUID required")
		}
		return id, ModePure, nil
	}
	if strings.Contains(lower, "#juzi") {
		if !strings.HasSuffix(lower, "#juzi") {
			return "", ModeJuzi, fmt.Errorf("private protocol markers must be one exact suffix")
		}
		rest := value[:strings.LastIndex(lower, "#juzi")]
		if strings.Contains(strings.ToLower(rest), "#pure") || strings.Contains(rest, "#x365") {
			return "", ModeJuzi, fmt.Errorf("private protocol markers must be one exact suffix")
		}
		// Juzi only tags the upstream request, so the id keeps going through
		// utils.UUIDMap and may be a bare 32 hex digit UUID.
		return rest, ModeJuzi, nil
	}
	// The x365 marker is case sensitive on purpose: "#X365" is plain text, which
	// keeps a node name that happens to end that way from switching the wire.
	if strings.Contains(value, "#x365") {
		if !strings.HasSuffix(value, "#x365") {
			return "", ModeX365, fmt.Errorf("private protocol markers must be one exact suffix")
		}
		rest := value[:len(value)-len("#x365")]
		if strings.Contains(strings.ToLower(rest), "#pure") || strings.Contains(strings.ToLower(rest), "#juzi") {
			return "", ModeX365, fmt.Errorf("private protocol markers must be one exact suffix")
		}
		return rest, ModeX365, nil
	}
	return value, ModeStandard, nil
}

// canonicalUUID reports whether value is a dashed 36 character UUID. Pure needs
// it because the id is decoded into a fixed 16 byte array; the other modes go
// through utils.UUIDMap, which also accepts a bare 32 hex digit id.
func canonicalUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil
}

// pureIdentity returns the 16 byte UUID of a Pure node.
func pureIdentity(value string) ([16]byte, bool, error) {
	id, mode, err := parsePrivateUUID(value)
	if err != nil {
		return [16]byte{}, mode == ModePure, err
	}
	if mode != ModePure {
		return [16]byte{}, false, nil
	}
	decoded, _ := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	var key [16]byte
	copy(key[:], decoded)
	return key, true, nil
}

// pureHeader builds the Pure request:
//
//	[0xa1][uuid 16][0x00][command TCP][port 2][atyp][addr]
//
// Pure is TCP only: it has no UDP and no mux framing, and the destination cannot
// be IPv6.
func pureHeader(key [16]byte, dst *DstAddr) ([]byte, error) {
	if dst == nil || dst.Port == 0 || dst.UDP || dst.Mux {
		return nil, fmt.Errorf("Pure: TCP-only destination required")
	}
	if dst.AddrType == AtypIPv6 {
		return nil, fmt.Errorf("Pure: IPv6 destination unsupported")
	}
	if dst.AddrType != AtypIPv4 && dst.AddrType != AtypDomainName {
		return nil, fmt.Errorf("Pure: invalid destination type")
	}
	if dst.AddrType == AtypIPv4 && len(dst.Addr) != 4 {
		return nil, fmt.Errorf("Pure: invalid IPv4 destination")
	}
	if dst.AddrType == AtypDomainName {
		if len(dst.Addr) < 2 || int(dst.Addr[0]) != len(dst.Addr)-1 {
			return nil, fmt.Errorf("Pure: invalid destination domain")
		}
	}
	b := append([]byte{0xa1}, key[:]...)
	b = append(b, 0, CommandTCP, byte(dst.Port>>8), byte(dst.Port))
	b = append(b, dst.AddrType)
	return append(b, dst.Addr...), nil
}

// pureConn validates the Pure response prefix (0xa1 0x00) on the first read. A
// short or wrong prefix is sticky: the stream cannot be resynchronised, so every
// later read returns the same error.
type pureConn struct {
	net.Conn
	ready       bool
	responseErr error
}

func (c *pureConn) NeedAdditionalReadDeadline() bool { return true }

func (c *pureConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.responseErr != nil {
		return 0, c.responseErr
	}
	if !c.ready {
		var header [2]byte
		_, err := io.ReadFull(c.Conn, header[:])
		if err == nil && header != [2]byte{0xa1, 0} {
			err = fmt.Errorf("Pure response prefix invalid")
		}
		if err != nil {
			c.responseErr = err
			return 0, err
		}
		c.ready = true
	}
	return c.Conn.Read(p)
}

// dialPure writes the Pure request and returns the response validating conn.
func (c *Client) dialPure(conn net.Conn, dst *DstAddr) (net.Conn, error) {
	wire, err := pureHeader(c.uuid, dst)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	n, err := conn.Write(wire)
	if err == nil && n != len(wire) {
		err = io.ErrShortWrite
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &pureConn{Conn: conn}, nil
}

// purePacketReject is the UDP carrier of a Pure node: the protocol has no UDP
// path, so the adapter reports it instead of pretending to send datagrams.
type purePacketReject struct{}

func (*purePacketReject) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, fmt.Errorf("Pure: UDP/XUDP unsupported")
}
func (*purePacketReject) WriteTo([]byte, net.Addr) (int, error) {
	return 0, fmt.Errorf("Pure: UDP/XUDP unsupported")
}
func (*purePacketReject) Close() error                     { return nil }
func (*purePacketReject) LocalAddr() net.Addr              { return nil }
func (*purePacketReject) SetDeadline(time.Time) error      { return nil }
func (*purePacketReject) SetReadDeadline(time.Time) error  { return nil }
func (*purePacketReject) SetWriteDeadline(time.Time) error { return nil }
