package xhttpstream

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
)

// PacketConn is the plain (non UOT) UDP mode: one forged-and-encrypted frame
// per datagram on a UDP socket bound to the configured server.
//
// Frame layout, reconstructed from the vendor build's Pack/Unpack helpers:
//
//	[128]  forged prefix: hex(fake-net["udp"]) padded with random bytes
//	[16]   token
//	[H]    hmac key
//	[1]    IV length
//	[IV]   random per-packet IV
//	[..]   AES-CTR( SOCKS address || payload )
//
// The socket always talks to the server named by the node (server/port, or the
// values inside its config blob); the SOCKS address inside the frame is the
// per-datagram target the caller passes to WriteTo. remote is kept explicit so
// RemoteAddr reports the configured server and never a metadata address.
//
// This path is not covered by a live test yet; see the report's 联调 list.
type PacketConn struct {
	net.Conn
	Cipher
	remote  net.Addr
	token   []byte
	hmac    []byte
	fakeNet map[string]string

	writeMu sync.Mutex
	readMu  sync.Mutex
}

// RemoteAddr reports the configured xhttp server, not the datagram target.
func (c *PacketConn) RemoteAddr() net.Addr { return c.remote }

// WriteTo encrypts one datagram to addr.
func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	destination, err := encodeSocksAddr(addr)
	if err != nil {
		return 0, err
	}
	iv, err := c.newIV()
	if err != nil {
		return 0, err
	}
	fake, err := DecodeFakeNet(c.fakeNet, "udp")
	if err != nil {
		return 0, err
	}
	plaintext := make([]byte, 0, len(destination)+len(b))
	plaintext = append(plaintext, destination...)
	plaintext = append(plaintext, b...)
	frame := make([]byte, FakePrefixLen+len(c.token)+len(c.hmac)+1+len(iv)+len(plaintext))
	copied := copy(frame[:FakePrefixLen], fake)
	if copied < FakePrefixLen {
		if _, err := rand.Read(frame[copied:FakePrefixLen]); err != nil {
			return 0, err
		}
	}
	offset := FakePrefixLen
	offset += copy(frame[offset:], c.token)
	offset += copy(frame[offset:], c.hmac)
	frame[offset] = byte(len(iv))
	offset++
	offset += copy(frame[offset:], iv)
	c.Encrypter(iv).XORKeyStream(frame[offset:], plaintext)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := c.Conn.Write(frame); err != nil {
		return 0, err
	}
	return len(b), nil
}

// ReadFrom decrypts one datagram and reports the address it came from.
func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	raw := make([]byte, 64*1024)
	if n, err := c.Conn.Read(raw); err == nil {
		raw = raw[:n]
	} else {
		return 0, nil, err
	}
	if len(raw) < FakePrefixLen+len(c.token) {
		return 0, nil, errors.New("xhttp: short UDP frame")
	}
	offset := FakePrefixLen
	if !tokenEqual(raw[offset:offset+len(c.token)], c.token) {
		return 0, nil, ErrInvalidToken
	}
	offset += len(c.token)
	offset += len(c.hmac)
	if offset+1 > len(raw) {
		return 0, nil, errors.New("xhttp: short UDP frame")
	}
	ivLen := int(raw[offset])
	offset++
	if ivLen != c.IVSize() || offset+ivLen > len(raw) {
		return 0, nil, fmt.Errorf("xhttp: unexpected UDP IV length %d", ivLen)
	}
	iv := raw[offset : offset+ivLen]
	offset += ivLen
	plaintext := make([]byte, len(raw)-offset)
	c.Decrypter(iv).XORKeyStream(plaintext, raw[offset:])
	addr, payload, err := decodeSocksAddr(plaintext)
	if err != nil {
		return 0, nil, err
	}
	n := copy(b, payload)
	return n, addr, nil
}

func (c *PacketConn) newIV() ([]byte, error) {
	iv := make([]byte, c.IVSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	return iv, nil
}

// encodeSocksAddr serializes a net.Addr the way the vendor core serializes the
// first destination of a stream.
func encodeSocksAddr(addr net.Addr) ([]byte, error) {
	if addr == nil {
		return nil, errors.New("xhttp: missing UDP destination")
	}
	switch a := addr.(type) {
	case *net.UDPAddr:
		if a.IP == nil {
			return nil, fmt.Errorf("xhttp: UDP address %s has no IP", a)
		}
		port := a.Port
		if ip4 := a.IP.To4(); ip4 != nil {
			return append(append([]byte{0x01}, ip4...), byte(port>>8), byte(port)), nil
		}
		return append(append([]byte{0x04}, a.IP.To16()...), byte(port>>8), byte(port)), nil
	case *net.TCPAddr:
		return encodeSocksAddr(&net.UDPAddr{IP: a.IP, Port: a.Port})
	default:
		// A SOCKS domain destination (what the udp relay hands over when the
		// target was never resolved) and any other host:port address.
		host, portString, err := net.SplitHostPort(addr.String())
		if err != nil {
			return nil, fmt.Errorf("xhttp: unsupported UDP address %s", addr)
		}
		port, err := strconv.Atoi(portString)
		if err != nil || port < 0 || port > 65535 {
			return nil, fmt.Errorf("xhttp: bad UDP port in %s", addr)
		}
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("xhttp: bad UDP domain length in %s", addr)
		}
		encoded := make([]byte, 0, 2+len(host)+2)
		encoded = append(encoded, 0x03, byte(len(host)))
		encoded = append(encoded, host...)
		return append(encoded, byte(port>>8), byte(port)), nil
	}
}

// decodeSocksAddr splits a SOCKS address off a decrypted datagram.
func decodeSocksAddr(payload []byte) (net.Addr, []byte, error) {
	if len(payload) < 1 {
		return nil, nil, errors.New("xhttp: empty UDP payload")
	}
	switch payload[0] {
	case 0x01: // IPv4
		if len(payload) < 7 {
			return nil, nil, errors.New("xhttp: truncated IPv4 UDP header")
		}
		ip := net.IP(payload[1:5])
		port := int(binary.BigEndian.Uint16(payload[5:7]))
		return &net.UDPAddr{IP: ip, Port: port}, payload[7:], nil
	case 0x03: // domain
		if len(payload) < 2 {
			return nil, nil, errors.New("xhttp: truncated domain UDP header")
		}
		length := int(payload[1])
		if len(payload) < 2+length+2 {
			return nil, nil, errors.New("xhttp: truncated domain UDP header")
		}
		host := string(payload[2 : 2+length])
		port := int(binary.BigEndian.Uint16(payload[2+length : 2+length+2]))
		return &domainAddr{host: host, port: port}, payload[2+length+2:], nil
	case 0x04: // IPv6
		if len(payload) < 19 {
			return nil, nil, errors.New("xhttp: truncated IPv6 UDP header")
		}
		ip := net.IP(payload[1:17])
		port := int(binary.BigEndian.Uint16(payload[17:19]))
		return &net.UDPAddr{IP: ip, Port: port}, payload[19:], nil
	default:
		return nil, nil, fmt.Errorf("xhttp: unsupported UDP address type %d", payload[0])
	}
}

// domainAddr is a SOCKS domain destination, used because net.UDPAddr cannot
// carry a host name.
type domainAddr struct {
	host string
	port int
}

func (a *domainAddr) Network() string { return "udp" }
func (a *domainAddr) String() string {
	return net.JoinHostPort(a.host, strconv.Itoa(a.port))
}
