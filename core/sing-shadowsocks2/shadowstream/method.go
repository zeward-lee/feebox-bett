package shadowstream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"io"
	"net"
	"os"

	C "github.com/metacubex/sing-shadowsocks2/cipher"
	"github.com/metacubex/sing-shadowsocks2/internal/legacykey"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	"github.com/metacubex/chacha"
)

var MethodList = []string{
	"aes-128-ctr",
	"aes-192-ctr",
	"aes-256-ctr",
	"aes-128-cfb",
	"aes-192-cfb",
	"aes-256-cfb",
	"rc4-md5",
	"chacha20-ietf",
	"xchacha20",
	"chacha20",
}

func init() {
	C.RegisterMethod(MethodList, NewMethod)
}

type Method struct {
	keyLength          int
	saltLength         int
	encryptConstructor func(key []byte, salt []byte) (cipher.Stream, error)
	decryptConstructor func(key []byte, salt []byte) (cipher.Stream, error)
	key                []byte
	// password is the node password with the marker stripped; the blackstone
	// header token is derived from it.
	password string
	// blackstone marks a node whose first write is the vendor's 35 byte
	// plaintext header instead of a bare salt.
	blackstone bool
}

func NewMethod(methodName string, options C.MethodOptions) (C.Method, error) {
	cleanPassword, blackstone := C.ParseBlackstonePassword(options.Password)
	m := &Method{
		password:   cleanPassword,
		blackstone: blackstone,
	}
	switch methodName {
	case "aes-128-ctr":
		m.keyLength = 16
		m.saltLength = aes.BlockSize
		m.encryptConstructor = blockStream(aes.NewCipher, cipher.NewCTR)
		m.decryptConstructor = blockStream(aes.NewCipher, cipher.NewCTR)
	case "aes-192-ctr":
		m.keyLength = 24
		m.saltLength = aes.BlockSize
		m.encryptConstructor = blockStream(aes.NewCipher, cipher.NewCTR)
		m.decryptConstructor = blockStream(aes.NewCipher, cipher.NewCTR)
	case "aes-256-ctr":
		m.keyLength = 32
		m.saltLength = aes.BlockSize
		m.encryptConstructor = blockStream(aes.NewCipher, cipher.NewCTR)
		m.decryptConstructor = blockStream(aes.NewCipher, cipher.NewCTR)
	case "aes-128-cfb":
		m.keyLength = 16
		m.saltLength = aes.BlockSize
		m.encryptConstructor = blockStream(aes.NewCipher, cipher.NewCFBEncrypter)
		m.decryptConstructor = blockStream(aes.NewCipher, cipher.NewCFBDecrypter)
	case "aes-192-cfb":
		m.keyLength = 24
		m.saltLength = aes.BlockSize
		m.encryptConstructor = blockStream(aes.NewCipher, cipher.NewCFBEncrypter)
		m.decryptConstructor = blockStream(aes.NewCipher, cipher.NewCFBDecrypter)
	case "aes-256-cfb":
		m.keyLength = 32
		m.saltLength = aes.BlockSize
		m.encryptConstructor = blockStream(aes.NewCipher, cipher.NewCFBEncrypter)
		m.decryptConstructor = blockStream(aes.NewCipher, cipher.NewCFBDecrypter)
	case "rc4-md5":
		m.keyLength = 16
		m.saltLength = 16
		m.encryptConstructor = func(key []byte, salt []byte) (cipher.Stream, error) {
			h := md5.New()
			h.Write(key)
			h.Write(salt)
			return rc4.NewCipher(h.Sum(nil))
		}
		m.decryptConstructor = func(key []byte, salt []byte) (cipher.Stream, error) {
			h := md5.New()
			h.Write(key)
			h.Write(salt)
			return rc4.NewCipher(h.Sum(nil))
		}
	case "chacha20-ietf":
		m.keyLength = chacha.KeySize
		m.saltLength = chacha.INonceSize
		m.encryptConstructor = func(key []byte, salt []byte) (cipher.Stream, error) {
			return chacha.NewChaCha20IgnoreCounterOverflow(salt, key)
		}
		m.decryptConstructor = func(key []byte, salt []byte) (cipher.Stream, error) {
			return chacha.NewChaCha20IgnoreCounterOverflow(salt, key)
		}
	case "xchacha20":
		m.keyLength = chacha.KeySize
		m.saltLength = chacha.XNonceSize
		m.encryptConstructor = func(key []byte, salt []byte) (cipher.Stream, error) {
			return chacha.NewChaCha20IgnoreCounterOverflow(salt, key)
		}
		m.decryptConstructor = func(key []byte, salt []byte) (cipher.Stream, error) {
			return chacha.NewChaCha20IgnoreCounterOverflow(salt, key)
		}
	case "chacha20":
		m.keyLength = chacha.KeySize
		m.saltLength = chacha.NonceSize
		m.encryptConstructor = func(key []byte, salt []byte) (cipher.Stream, error) {
			return chacha.NewChaCha20IgnoreCounterOverflow(salt, key)
		}
		m.decryptConstructor = func(key []byte, salt []byte) (cipher.Stream, error) {
			return chacha.NewChaCha20IgnoreCounterOverflow(salt, key)
		}
	default:
		return nil, os.ErrInvalid
	}
	if len(options.Key) == m.keyLength {
		m.key = options.Key
	} else if len(options.Key) > 0 {
		return nil, E.New("bad key length, required ", m.keyLength, ", got ", len(options.Key))
	} else if cleanPassword != "" {
		m.key = legacykey.Key([]byte(cleanPassword), m.keyLength)
	} else {
		return nil, C.ErrMissingPassword
	}
	return m, nil
}

func blockStream(blockCreator func(key []byte) (cipher.Block, error), streamCreator func(block cipher.Block, iv []byte) cipher.Stream) func([]byte, []byte) (cipher.Stream, error) {
	return func(key []byte, iv []byte) (cipher.Stream, error) {
		block, err := blockCreator(key)
		if err != nil {
			return nil, err
		}
		return streamCreator(block, iv), err
	}
}

func (m *Method) DialConn(conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	ssConn := &clientConn{
		ExtendedConn: bufio.NewExtendedConn(conn),
		method:       m,
		destination:  destination,
	}
	return ssConn, common.Error(ssConn.Write(nil))
}

func (m *Method) DialEarlyConn(conn net.Conn, destination M.Socksaddr) net.Conn {
	return &clientConn{
		ExtendedConn: bufio.NewExtendedConn(conn),
		method:       m,
		destination:  destination,
	}
}

func (m *Method) DialPacketConn(conn net.Conn) N.NetPacketConn {
	return &clientPacketConn{
		ExtendedConn: bufio.NewExtendedConn(conn),
		method:       m,
	}
}

type clientConn struct {
	N.ExtendedConn
	method      *Method
	destination M.Socksaddr
	readStream  cipher.Stream
	writeStream cipher.Stream
}

// blackstoneRandReader is a variable so tests can make the salt deterministic.
var blackstoneRandReader io.Reader = rand.Reader

// writeBlackstoneHeader writes the plaintext 35 byte header a #BLACKSTONE stream
// node expects before the encrypted address and payload:
//
//	[0x01][0x00][md5(password + "_onesocks") 16][0x10][salt]
func (c *clientConn) writeBlackstoneHeader(payload []byte) (cipher.Stream, error) {
	token := md5.Sum([]byte(c.method.password + "_onesocks"))

	salt := make([]byte, c.method.saltLength)
	if _, err := io.ReadFull(blackstoneRandReader, salt); err != nil {
		return nil, err
	}

	header := make([]byte, 35)
	header[0] = 0x01
	header[1] = 0x00
	copy(header[2:18], token[:])
	header[18] = 0x10
	copy(header[19:35], salt)

	if _, err := c.ExtendedConn.Write(header); err != nil {
		return nil, err
	}
	return c.method.encryptConstructor(c.method.key, salt)
}

func (c *clientConn) readResponse() error {
	if c.readStream != nil {
		return nil
	}
	if c.method.blackstone {
		magic := make([]byte, 2)
		if _, err := io.ReadFull(c.ExtendedConn, magic); err != nil {
			return err
		}
		if magic[0] != 0x01 {
			return E.New("invalid BLACKSTONE response magic: ", magic[0])
		}
		if padLen := int(magic[1]); padLen > 0 {
			if _, err := io.CopyN(io.Discard, c.ExtendedConn, int64(padLen)); err != nil {
				return err
			}
		}
		// The response header carries a 17 byte token; the client does not
		// verify it, matching the vendor build.
		if _, err := io.CopyN(io.Discard, c.ExtendedConn, 17); err != nil {
			return err
		}
		salt := make([]byte, c.method.saltLength)
		if _, err := io.ReadFull(c.ExtendedConn, salt); err != nil {
			return err
		}
		var err error
		c.readStream, err = c.method.decryptConstructor(c.method.key, salt)
		return err
	}
	saltBuffer := buf.NewSize(c.method.saltLength)
	defer saltBuffer.Release()
	_, err := saltBuffer.ReadFullFrom(c.ExtendedConn, c.method.saltLength)
	if err != nil {
		return err
	}
	c.readStream, err = c.method.decryptConstructor(c.method.key, saltBuffer.Bytes())
	return err
}

func (c *clientConn) Read(p []byte) (n int, err error) {
	if c.readStream == nil {
		err = c.readResponse()
		if err != nil {
			return
		}
	}
	n, err = c.ExtendedConn.Read(p)
	if err != nil {
		return
	}
	c.readStream.XORKeyStream(p[:n], p[:n])
	return
}

func (c *clientConn) Write(p []byte) (n int, err error) {
	if c.writeStream == nil {
		if c.method.blackstone {
			c.writeStream, err = c.writeBlackstoneHeader(p)
			if err != nil {
				return
			}
			buffer := buf.NewSize(M.SocksaddrSerializer.AddrPortLen(c.destination) + len(p))
			defer buffer.Release()
			err = M.SocksaddrSerializer.WriteAddrPort(buffer, c.destination)
			if err != nil {
				return
			}
			if len(p) > 0 {
				_, _ = buffer.Write(p)
			}
			c.writeStream.XORKeyStream(buffer.Bytes(), buffer.Bytes())
			_, err = c.ExtendedConn.Write(buffer.Bytes())
			if err == nil {
				n = len(p)
			}
			return
		}
		buffer := buf.NewSize(c.method.saltLength + M.SocksaddrSerializer.AddrPortLen(c.destination) + len(p))
		defer buffer.Release()
		buffer.WriteRandom(c.method.saltLength)
		err = M.SocksaddrSerializer.WriteAddrPort(buffer, c.destination)
		if err != nil {
			return
		}
		common.Must1(buffer.Write(p))
		c.writeStream, err = c.method.encryptConstructor(c.method.key, buffer.To(c.method.saltLength))
		if err != nil {
			return
		}
		c.writeStream.XORKeyStream(buffer.From(c.method.saltLength), buffer.From(c.method.saltLength))
		_, err = c.ExtendedConn.Write(buffer.Bytes())
		if err == nil {
			n = len(p)
		}
		return
	}
	c.writeStream.XORKeyStream(p, p)
	return c.ExtendedConn.Write(p)
}

func (c *clientConn) ReadBuffer(buffer *buf.Buffer) error {
	if c.readStream == nil {
		err := c.readResponse()
		if err != nil {
			return err
		}
	}
	err := c.ExtendedConn.ReadBuffer(buffer)
	if err != nil {
		return err
	}
	c.readStream.XORKeyStream(buffer.Bytes(), buffer.Bytes())
	return nil
}

func (c *clientConn) WriteBuffer(buffer *buf.Buffer) error {
	if c.writeStream == nil {
		if c.method.blackstone {
			var err error
			c.writeStream, err = c.writeBlackstoneHeader(nil)
			if err != nil {
				return err
			}
			addrHeader := buf.With(buffer.ExtendHeader(M.SocksaddrSerializer.AddrPortLen(c.destination)))
			if err := M.SocksaddrSerializer.WriteAddrPort(addrHeader, c.destination); err != nil {
				return err
			}
			c.writeStream.XORKeyStream(buffer.Bytes(), buffer.Bytes())
			return c.ExtendedConn.WriteBuffer(buffer)
		}
		header := buf.With(buffer.ExtendHeader(c.method.saltLength + M.SocksaddrSerializer.AddrPortLen(c.destination)))
		header.WriteRandom(c.method.saltLength)
		err := M.SocksaddrSerializer.WriteAddrPort(header, c.destination)
		if err != nil {
			return err
		}
		c.writeStream, err = c.method.encryptConstructor(c.method.key, header.To(c.method.saltLength))
		if err != nil {
			return err
		}
		c.writeStream.XORKeyStream(buffer.From(c.method.saltLength), buffer.From(c.method.saltLength))
	} else {
		c.writeStream.XORKeyStream(buffer.Bytes(), buffer.Bytes())
	}
	return c.ExtendedConn.WriteBuffer(buffer)
}

func (c *clientConn) FrontHeadroom() int {
	if c.writeStream == nil {
		if c.method.blackstone {
			return M.SocksaddrSerializer.AddrPortLen(c.destination)
		}
		return c.method.saltLength + M.SocksaddrSerializer.AddrPortLen(c.destination)
	}
	return 0
}

func (c *clientConn) NeedHandshake() bool {
	return c.writeStream == nil
}

func (c *clientConn) Upstream() any {
	return c.ExtendedConn
}

type clientPacketConn struct {
	N.ExtendedConn
	method *Method
}

func (c *clientPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	err = c.ReadBuffer(buffer)
	if err != nil {
		return
	}
	stream, err := c.method.decryptConstructor(c.method.key, buffer.To(c.method.saltLength))
	if err != nil {
		return
	}
	stream.XORKeyStream(buffer.From(c.method.saltLength), buffer.From(c.method.saltLength))
	buffer.Advance(c.method.saltLength)
	destination, err = M.SocksaddrSerializer.ReadAddrPort(buffer)
	if err != nil {
		return
	}
	return destination.Unwrap(), nil
}

func (c *clientPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	header := buf.With(buffer.ExtendHeader(c.method.saltLength + M.SocksaddrSerializer.AddrPortLen(destination)))
	header.WriteRandom(c.method.saltLength)
	err := M.SocksaddrSerializer.WriteAddrPort(header, destination)
	if err != nil {
		return err
	}
	stream, err := c.method.encryptConstructor(c.method.key, buffer.To(c.method.saltLength))
	if err != nil {
		return err
	}
	stream.XORKeyStream(buffer.From(c.method.saltLength), buffer.From(c.method.saltLength))
	return c.ExtendedConn.WriteBuffer(buffer)
}

func (c *clientPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.ExtendedConn.Read(p)
	if err != nil {
		return
	}
	// A short datagram cannot carry a salt; without this bound the slice below
	// panics on a hostile or truncated packet.
	if n < c.method.saltLength {
		return 0, nil, E.New("shadowstream: packet shorter than salt")
	}
	stream, err := c.method.decryptConstructor(c.method.key, p[:c.method.saltLength])
	if err != nil {
		return
	}
	buffer := buf.As(p[c.method.saltLength:n])
	stream.XORKeyStream(buffer.Bytes(), buffer.Bytes())
	destination, err := M.SocksaddrSerializer.ReadAddrPort(buffer)
	if err != nil {
		return
	}
	if destination.IsFqdn() {
		addr = destination
	} else {
		addr = destination.UDPAddr()
	}
	n = copy(p, buffer.Bytes())
	return
}

func (c *clientPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	destination := M.SocksaddrFromNet(addr)
	buffer := buf.NewSize(c.method.saltLength + M.SocksaddrSerializer.AddrPortLen(destination) + len(p))
	defer buffer.Release()
	buffer.WriteRandom(c.method.saltLength)
	err = M.SocksaddrSerializer.WriteAddrPort(buffer, destination)
	if err != nil {
		return
	}
	stream, err := c.method.encryptConstructor(c.method.key, buffer.To(c.method.saltLength))
	if err != nil {
		return
	}
	stream.XORKeyStream(buffer.From(c.method.saltLength), buffer.From(c.method.saltLength))
	stream.XORKeyStream(buffer.Extend(len(p)), p)
	_, err = c.ExtendedConn.Write(buffer.Bytes())
	if err == nil {
		n = len(p)
	}
	return
}

func (c *clientPacketConn) FrontHeadroom() int {
	return c.method.saltLength + M.MaxSocksaddrLength
}

func (c *clientPacketConn) Upstream() any {
	return c.ExtendedConn
}
