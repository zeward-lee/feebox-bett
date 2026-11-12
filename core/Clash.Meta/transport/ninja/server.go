package ninja

import (
	"fmt"
	"net"
)

// Server accepts ninja tunnels on an already established transport.
type Server struct {
	cfg *Config
}

// NewServer validates cfg and returns a server.
func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("ninja: nil config")
	}
	if !cfg.Method.Valid() {
		return nil, fmt.Errorf("ninja: unsupported method %q", string(cfg.Method))
	}
	if cfg.Password == "" {
		return nil, fmt.Errorf("ninja: empty password")
	}
	return &Server{cfg: cfg}, nil
}

// Handshake reads the client tunnel header and returns a Conn positioned at the
// destination address and any payload that arrived with the first block.
func (s *Server) Handshake(raw net.Conn) (net.Conn, string, uint16, error) {
	conn := NewConn(raw, s.cfg, false)
	if err := conn.readHeader(); err != nil {
		raw.Close()
		return nil, "", 0, err
	}
	host, port, _, err := DecodeSocksAddr(conn.remoteAddr)
	if err != nil {
		raw.Close()
		return nil, "", 0, err
	}
	return conn, host, port, nil
}
