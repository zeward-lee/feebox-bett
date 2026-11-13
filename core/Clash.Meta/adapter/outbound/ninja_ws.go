package outbound

// Minimal RFC6455 client used by the ninja outbound: the reference server only
// accepts a handshake that looks exactly like the official client's, so the
// request is written byte for byte (duplicate Host header, no extra headers).

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

type ninjaWSConn struct {
	net.Conn
	br  *bufio.Reader
	buf []byte
}

// NewNinjaWSConn performs the websocket handshake on conn.
func NewNinjaWSConn(conn net.Conn, host, path string) (net.Conn, error) {
	if path == "" {
		path = "/"
	}
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key) + "\r\n" +
		"Host: " + host + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.Contains(status, "101") {
		return nil, fmt.Errorf("ninja ws: unexpected status %q", strings.TrimSpace(status))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return &ninjaWSConn{Conn: conn, br: br}, nil
}

func (c *ninjaWSConn) Read(p []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	for {
		payload, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		if len(payload) == 0 {
			continue
		}
		n := copy(p, payload)
		c.buf = payload[n:]
		return n, nil
	}
}

func (c *ninjaWSConn) readFrame() ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c.br, hdr); err != nil {
		return nil, err
	}
	op := hdr[0] & 0x0f
	masked := hdr[1]&0x80 != 0
	ln := int(hdr[1] & 0x7f)
	switch ln {
	case 126:
		e := make([]byte, 2)
		if _, err := io.ReadFull(c.br, e); err != nil {
			return nil, err
		}
		ln = int(binary.BigEndian.Uint16(e))
	case 127:
		e := make([]byte, 8)
		if _, err := io.ReadFull(c.br, e); err != nil {
			return nil, err
		}
		ln = int(binary.BigEndian.Uint64(e))
	}
	var mask []byte
	if masked {
		mask = make([]byte, 4)
		if _, err := io.ReadFull(c.br, mask); err != nil {
			return nil, err
		}
	}
	payload := make([]byte, ln)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i&3]
		}
	}
	if op == 0x8 {
		return nil, io.EOF
	}
	return payload, nil
}

func (c *ninjaWSConn) Write(p []byte) (int, error) {
	hdr := []byte{0x82}
	n := len(p)
	switch {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	case n < 65536:
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 0x80|127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		hdr = append(hdr, ext[:]...)
	}
	mask := make([]byte, 4)
	if _, err := rand.Read(mask); err != nil {
		return 0, err
	}
	hdr = append(hdr, mask...)
	body := make([]byte, n)
	for i := 0; i < n; i++ {
		body[i] = p[i] ^ mask[i&3]
	}
	if _, err := c.Conn.Write(hdr); err != nil {
		return 0, err
	}
	if _, err := c.Conn.Write(body); err != nil {
		return 0, err
	}
	return n, nil
}

var _ http.Header = nil
