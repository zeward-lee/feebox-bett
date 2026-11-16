package x365

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func udpTestDst() *DstAddr {
	return &DstAddr{
		AddrType: AtypIPv4,
		Addr:     []byte{1, 2, 3, 4},
		Port:     53,
	}
}

// udpRequestHeader is the fixed part every x365 UDP datagram request starts
// with: magic | version | command(0x02) | uuid | port.
func udpRequestHeader(t *testing.T, id uuid.UUID, port uint16) []byte {
	t.Helper()
	want := []byte("X365")
	want = append(want, 0x01, CommandUDP)
	want = append(want, id.Bytes()...)
	want = append(want, byte(port>>8), byte(port))
	return want
}

func TestPacketConnWritePacketCarriesHeaderPerDatagram(t *testing.T) {
	id := uuid.FromStringOrNil(testUUID)
	dst := &DstAddr{AddrType: AtypDomainName, Addr: append([]byte{11}, "example.com"...), Port: 443}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	pc := NewClient(testUUID).PacketConn(client, dst)
	payload := []byte("datagram")

	go func() {
		_, _ = pc.WritePacket(payload)
	}()

	want := udpRequestHeader(t, id, 443)
	want = append(want, AtypDomainName, 11)
	want = append(want, "example.com"...)
	want = append(want, byte(len(payload)>>8), byte(len(payload)))
	want = append(want, payload...)

	got := make([]byte, len(want))
	_, err := io.ReadFull(server, got)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestPacketConnWriteFramesHeaderOnce(t *testing.T) {
	id := uuid.FromStringOrNil(testUUID)
	dst := udpTestDst()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	pc := NewClient(testUUID).PacketConn(client, dst)

	first := []byte("one")
	second := []byte("two")
	go func() {
		_, _ = pc.Write(first)
		_, _ = pc.Write(second)
	}()

	wantFirst := udpRequestHeader(t, id, dst.Port)
	wantFirst = append(wantFirst, AtypIPv4, 1, 2, 3, 4)
	wantFirst = append(wantFirst, byte(len(first)>>8), byte(len(first)))
	wantFirst = append(wantFirst, first...)

	gotFirst := make([]byte, len(wantFirst))
	_, err := io.ReadFull(server, gotFirst)
	require.NoError(t, err)
	assert.Equal(t, wantFirst, gotFirst)

	wantSecond := []byte{byte(len(second) >> 8), byte(len(second))}
	wantSecond = append(wantSecond, second...)
	gotSecond := make([]byte, len(wantSecond))
	_, err = io.ReadFull(server, gotSecond)
	require.NoError(t, err)
	assert.Equal(t, wantSecond, gotSecond)
}

func TestPacketConnReadDatagrams(t *testing.T) {
	dst := udpTestDst()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	pc := NewClient(testUUID).PacketConn(client, dst)

	go func() {
		// One response header for the stream, then length-prefixed payloads.
		_, _ = server.Write([]byte("X365\x00"))
		_, _ = server.Write([]byte{0x00, 0x04, 'p', 'i', 'n', 'g'})
		_, _ = server.Write([]byte{0x00, 0x04, 'p', 'o', 'n', 'g'})
	}()

	buffer := make([]byte, 16)
	n, err := pc.Read(buffer)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buffer[:n]))

	n, addr, err := pc.ReadFrom(buffer)
	require.NoError(t, err)
	assert.Equal(t, "pong", string(buffer[:n]))
	require.NotNil(t, addr)
	assert.Equal(t, "1.2.3.4:53", addr.String())
}

func TestPacketConnResponseRejectsInvalidMagic(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	pc := NewClient(testUUID).PacketConn(client, udpTestDst())
	go func() {
		_, _ = server.Write([]byte("X366\x00"))
	}()

	_, err := pc.Read(make([]byte, 16))
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "unexpected response magic"), err.Error())
}

func TestPacketConnReadShortBuffer(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	pc := NewClient(testUUID).PacketConn(client, udpTestDst())
	go func() {
		_, _ = server.Write([]byte("X365\x00"))
		_, _ = server.Write([]byte{0x00, 0x0a})
		_, _ = server.Write([]byte("0123456789"))
	}()

	_, err := pc.Read(make([]byte, 4))
	assert.ErrorIs(t, err, io.ErrShortBuffer)
}

func TestPacketConnRejectsOversizedPayload(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	pc := NewClient(testUUID).PacketConn(client, udpTestDst())
	_, err := pc.WritePacket(make([]byte, maxUDPPayload+1))
	require.Error(t, err)
}

func TestPacketConnTCPHeaderUnchanged(t *testing.T) {
	// The shared header helper must not change the TCP command byte or layout.
	id := uuid.FromStringOrNil(testUUID)
	dst := udpTestDst()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn := NewClient(testUUID).StreamConn(client, dst)
	go func() {
		_, _ = conn.Write([]byte("x"))
	}()

	want := []byte("X365")
	want = append(want, 0x01, CommandTCP)
	want = append(want, id.Bytes()...)
	want = append(want, 0x00, 0x35)
	want = append(want, AtypIPv4, 1, 2, 3, 4)
	want = append(want, 'x')

	got := make([]byte, len(want))
	_, err := io.ReadFull(server, got)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(want, got), "tcp frame changed: %x", got)
}
