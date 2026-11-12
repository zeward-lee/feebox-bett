package ninja

import (
	"fmt"
	"net"
)

// Client dials through a ninja server over an already established transport
// (plain TCP, or TLS/WebSocket when configured by the caller).
type Client struct {
	cfg *Config
}

// NewClient validates cfg and returns a dialer.
func NewClient(cfg *Config) (*Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("ninja: nil config")
	}
	if !cfg.Method.Valid() {
		return nil, fmt.Errorf("ninja: unsupported method %q", string(cfg.Method))
	}
	if cfg.Password == "" {
		return nil, fmt.Errorf("ninja: empty password")
	}
	return &Client{cfg: cfg}, nil
}

// StreamConn wraps raw and performs the ninja handshake on the first write.
// host/port is the final destination the server should dial.
func (c *Client) StreamConn(raw net.Conn, host string, port uint16) (net.Conn, error) {
	addr, err := EncodeSocksAddr(host, port)
	if err != nil {
		raw.Close()
		return nil, err
	}
	conn := NewConn(raw, c.cfg, true)
	conn.SetAddr(addr)
	return conn, nil
}
