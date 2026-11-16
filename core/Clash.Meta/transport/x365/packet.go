package x365

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	M "github.com/metacubex/sing/common/metadata"

	"github.com/gofrs/uuid/v5"
)

// maxUDPPayload is the largest datagram the two-byte length prefix can carry.
const maxUDPPayload = math.MaxUint16

// PacketConn carries UDP datagrams over an x365 stream.
//
// Wire format, as implemented by the flclash-private core:
//
//	request datagram:  header(22+addr) | length(2, big endian) | payload
//	                    header = magic(4) | version(1) | command(0x02) |
//	                             uuid(16) | port(2) | atyp(1) | addr
//	response stream:   magic(4) | status(1) once, then length(2) | payload
//	                    per datagram
//
// The public x365-core reference implementation documents 0x02/0x03 as UDP
// commands but does not implement them; the framing above follows the
// flclash-private binary, which does (transport/x365.PacketConn, WritePacket,
// ReadPacket, writeRequest). Address fields are written like the TCP header
// (port, atyp, addr) so both paths share one decoder on the server side.
type PacketConn struct {
	N.ExtendedConn
	id       uuid.UUID
	dst      *DstAddr
	rAddr    net.Addr
	writeMu  sync.Mutex
	received bool
	sent     bool
}

func newPacketConn(conn net.Conn, client *Client, dst *DstAddr) *PacketConn {
	return &PacketConn{
		ExtendedConn: N.NewExtendedConn(conn),
		id:           client.uuid,
		dst:          dst,
		rAddr:        dst.socksaddr(),
	}
}

// socksaddr converts the wire destination to the net.Addr reported by ReadFrom.
func (d *DstAddr) socksaddr() net.Addr {
	addr := M.Socksaddr{Port: d.Port}
	switch d.AddrType {
	case AtypIPv4, AtypIPv6:
		if parsed, ok := netip.AddrFromSlice(d.Addr); ok {
			addr.Addr = parsed.Unmap()
		}
	case AtypDomainName:
		// DstAddr keeps the one-byte domain length in Addr, matching the
		// wire format; tolerate a bare domain for hand-built destinations.
		if len(d.Addr) > 0 && int(d.Addr[0]) == len(d.Addr)-1 {
			addr.Fqdn = string(d.Addr[1:])
		} else {
			addr.Fqdn = string(d.Addr)
		}
	}
	return addr
}

// Read implements net.Conn by returning one datagram. The destination address
// is not carried in the response, so callers use ReadFrom/RemoteAddr instead.
func (c *PacketConn) Read(b []byte) (int, error) {
	if err := c.recvResponse(); err != nil {
		return 0, err
	}
	return readDatagram(c.ExtendedConn, b)
}

func (c *PacketConn) ReadBuffer(buffer *buf.Buffer) error {
	if err := c.recvResponse(); err != nil {
		return err
	}
	var length uint16
	if err := binary.Read(c.ExtendedConn, binary.BigEndian, &length); err != nil {
		return err
	}
	_, err := buffer.ReadFullFrom(c.ExtendedConn, int(length))
	return err
}

func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	if err != nil {
		return 0, nil, err
	}
	return n, c.rAddr, nil
}

// Write implements net.Conn for a fixed destination: the first datagram
// carries the full request header, later datagrams only the length prefix.
func (c *PacketConn) Write(b []byte) (int, error) {
	if len(b) > maxUDPPayload {
		return 0, fmt.Errorf("x365: udp payload too large: %d bytes", len(b))
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if !c.sent {
		if err := c.writeRequest(b); err != nil {
			return 0, err
		}
		c.sent = true
		return len(b), nil
	}

	frame := buf.NewSize(2 + len(b))
	defer frame.Release()
	binary.BigEndian.PutUint16(frame.Extend(2), uint16(len(b)))
	buf.Must(buf.Error(frame.Write(b)))

	_, err := c.ExtendedConn.Write(frame.Bytes())
	return len(b), err
}

func (c *PacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return c.Write(b)
}

// WritePacket sends one datagram as a complete request frame, so a single
// stream can address a destination per datagram.
func (c *PacketConn) WritePacket(b []byte) (int, error) {
	if len(b) > maxUDPPayload {
		return 0, fmt.Errorf("x365: udp payload too large: %d bytes", len(b))
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.writeRequest(b); err != nil {
		return 0, err
	}
	c.sent = true
	return len(b), nil
}

// writeRequest writes header | length(2) | payload. The caller holds writeMu.
func (c *PacketConn) writeRequest(p []byte) error {
	requestLen := len(Magic)
	requestLen += 1  // version
	requestLen += 1  // command
	requestLen += 16 // UUID
	requestLen += 2  // port
	requestLen += 1  // addr type
	requestLen += len(c.dst.Addr)
	requestLen += 2 // payload length
	requestLen += len(p)

	frame := buf.NewSize(requestLen)
	defer frame.Release()

	writeRequestHeader(frame, CommandUDP, c.id, c.dst)
	binary.BigEndian.PutUint16(frame.Extend(2), uint16(len(p)))
	buf.Must(buf.Error(frame.Write(p)))

	_, err := c.ExtendedConn.Write(frame.Bytes())
	return err
}

func (c *PacketConn) recvResponse() error {
	if c.received {
		return nil
	}
	if err := readResponse(c.ExtendedConn); err != nil {
		return err
	}
	c.received = true
	return nil
}

func (c *PacketConn) Upstream() any {
	return c.ExtendedConn
}

func (c *PacketConn) ReaderReplaceable() bool {
	return false
}

func (c *PacketConn) WriterReplaceable() bool {
	return false
}

// readDatagram reads length(2) | payload, the per-datagram response framing.
func readDatagram(r io.Reader, b []byte) (int, error) {
	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return 0, err
	}
	if int(length) > len(b) {
		return 0, io.ErrShortBuffer
	}
	return io.ReadFull(r, b[:length])
}

var _ net.PacketConn = (*PacketConn)(nil)
var _ net.Conn = (*PacketConn)(nil)
