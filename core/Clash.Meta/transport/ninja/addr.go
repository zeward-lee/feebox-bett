package ninja

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
)

// Socks5 address types as used by the tunnel first block.
const (
	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4
)

// EncodeSocksAddr serialises host:port the same way the reference core does
// (socks5 address: ATYP + address + big endian port).
func EncodeSocksAddr(host string, port uint16) ([]byte, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			b := make([]byte, 0, 7)
			b = append(b, atypIPv4)
			a := ip.As4()
			b = append(b, a[:]...)
			var p [2]byte
			binary.BigEndian.PutUint16(p[:], port)
			return append(b, p[:]...), nil
		}
		b := make([]byte, 0, 19)
		b = append(b, atypIPv6)
		a := ip.As16()
		b = append(b, a[:]...)
		var p [2]byte
		binary.BigEndian.PutUint16(p[:], port)
		return append(b, p[:]...), nil
	}
	if len(host) == 0 || len(host) > 255 {
		return nil, fmt.Errorf("ninja: bad host %q", host)
	}
	b := make([]byte, 0, 4+len(host))
	b = append(b, atypDomain, byte(len(host)))
	b = append(b, host...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	return append(b, p[:]...), nil
}

// DecodeSocksAddr parses a socks5 address back into host and port.
func DecodeSocksAddr(b []byte) (host string, port uint16, rest []byte, err error) {
	if len(b) < 1 {
		return "", 0, nil, fmt.Errorf("ninja: short address")
	}
	switch b[0] {
	case atypIPv4:
		if len(b) < 7 {
			return "", 0, nil, fmt.Errorf("ninja: short IPv4 address")
		}
		host = net.IP(b[1:5]).String()
		port = binary.BigEndian.Uint16(b[5:7])
		return host, port, b[7:], nil
	case atypIPv6:
		if len(b) < 19 {
			return "", 0, nil, fmt.Errorf("ninja: short IPv6 address")
		}
		host = net.IP(b[1:17]).String()
		port = binary.BigEndian.Uint16(b[17:19])
		return host, port, b[19:], nil
	case atypDomain:
		if len(b) < 2 || len(b) < 2+int(b[1])+2 {
			return "", 0, nil, fmt.Errorf("ninja: short domain address")
		}
		l := int(b[1])
		host = string(b[2 : 2+l])
		port = binary.BigEndian.Uint16(b[2+l : 4+l])
		return host, port, b[4+l:], nil
	}
	return "", 0, nil, fmt.Errorf("ninja: bad address type %d", b[0])
}
