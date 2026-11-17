package sntp_eclipse

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// helloRecord is the parsed form of the first (C→S) record's plaintext.
// Layout (§11.4):
//
//	BE16 outer_len (574) || BE16 hello_len (74) || hello || random padding
//	hello = ver(3) cmd(1) BE64 unix_seconds || nonce16 || u8 meta_len(32)
//	        || meta(32 ASCII uuid) || BE16 host_len || host || BE16 port
type helloRecord struct {
	OuterLen   uint16
	HelloLen   uint16
	Version    byte
	Cmd        byte
	Timestamp  uint64
	Nonce      [16]byte
	Meta       []byte
	Host       string
	Port       uint16
	PaddingLen int
}

// buildHello seals the first record and returns the full on-wire frame
// (prefix48 || hdr18 || body_ct) together with its transcript hash, which the
// server reply's AAD is bound to (§12.1).
func buildHello(prefix []byte, keys [4][keySize]byte, target Target, uuidASCII [32]byte, now time.Time) ([]byte, [32]byte, error) {
	var transcript [32]byte

	hdrAEAD, err := newAEAD(keys[0])
	if err != nil {
		return nil, transcript, err
	}
	bodyAEAD, err := newAEAD(keys[1])
	if err != nil {
		return nil, transcript, err
	}

	var innerNonce [16]byte
	if _, err := io.ReadFull(randReader, innerNonce[:]); err != nil {
		return nil, transcript, fmt.Errorf("sntp-eclipse: hello nonce: %w", err)
	}

	inner := make([]byte, 0, 96)
	inner = append(inner, helloVersion, helloCmdConnect)
	inner = binary.BigEndian.AppendUint64(inner, uint64(now.Unix()))
	inner = append(inner, innerNonce[:]...)
	inner = append(inner, byte(len(uuidASCII)))
	inner = append(inner, uuidASCII[:]...)
	if len(target.Host) > 0xffff {
		return nil, transcript, errors.New("sntp-eclipse: target host is too long")
	}
	inner = binary.BigEndian.AppendUint16(inner, uint16(len(target.Host)))
	inner = append(inner, target.Host...)
	inner = binary.BigEndian.AppendUint16(inner, target.Port)

	plain := make([]byte, 0, helloPlaintextLen)
	plain = binary.BigEndian.AppendUint16(plain, helloOuterLen)
	plain = binary.BigEndian.AppendUint16(plain, uint16(len(inner)))
	plain = append(plain, inner...)
	if len(plain) < helloPlaintextLen {
		padding := make([]byte, helloPlaintextLen-len(plain))
		if _, err := io.ReadFull(randReader, padding); err != nil {
			return nil, transcript, fmt.Errorf("sntp-eclipse: hello padding: %w", err)
		}
		plain = append(plain, padding...)
	}

	frame := make([]byte, 0, len(prefix)+headerSize+len(plain)+chachaOverhead)
	frame = append(frame, prefix...)
	frame = append(frame, sealRecord(hdrAEAD, bodyAEAD, 0, prefix, plain)...)
	transcript = sha256.Sum256(frame)
	return frame, transcript, nil
}

// parseHello decodes a hello plaintext (only used to verify captured traffic
// and to fail closed on malformed peers).
func parseHello(plain []byte) (helloRecord, error) {
	var rec helloRecord
	if len(plain) < 4 {
		return rec, errors.New("sntp-eclipse: hello plaintext truncated")
	}
	rec.OuterLen = binary.BigEndian.Uint16(plain[0:2])
	rec.HelloLen = binary.BigEndian.Uint16(plain[2:4])
	body := plain[4:]
	if len(body) < 10+16+1 {
		return rec, errors.New("sntp-eclipse: hello body truncated")
	}
	rec.Version = body[0]
	rec.Cmd = body[1]
	rec.Timestamp = binary.BigEndian.Uint64(body[2:10])
	copy(rec.Nonce[:], body[10:26])
	offset := 26
	metaLen := int(body[offset])
	offset++
	if len(body) < offset+metaLen+2 {
		return rec, errors.New("sntp-eclipse: hello meta truncated")
	}
	rec.Meta = append([]byte(nil), body[offset:offset+metaLen]...)
	offset += metaLen
	hostLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if len(body) < offset+hostLen+2 {
		return rec, errors.New("sntp-eclipse: hello host truncated")
	}
	rec.Host = string(body[offset : offset+hostLen])
	offset += hostLen
	rec.Port = binary.BigEndian.Uint16(body[offset : offset+2])
	offset += 2
	if len(body) > offset {
		rec.PaddingLen = len(body) - offset
	}
	// The official client writes the exact hello length here; only reject
	// values that cannot describe this buffer at all.
	if int(rec.HelloLen) > len(body) {
		return rec, fmt.Errorf("sntp-eclipse: hello length %d exceeds body %d", rec.HelloLen, len(body))
	}
	return rec, nil
}

// serverHello is the parsed S→C handshake reply (§12.1):
//
//	BE16 valid_len (34) || ver(3) || cmd(1) || server_eph32 || padding
type serverHello struct {
	ValidLen  uint16
	Version   byte
	Cmd       byte
	ServerEph [keySize]byte
}

func parseServerHello(plain []byte) (serverHello, error) {
	var out serverHello
	if len(plain) < 4+2+keySize {
		return out, fmt.Errorf("sntp-eclipse: server hello truncated (%d bytes)", len(plain))
	}
	out.ValidLen = binary.BigEndian.Uint16(plain[0:2])
	out.Version = plain[2]
	out.Cmd = plain[3]
	if out.Version != helloVersion {
		return out, fmt.Errorf("sntp-eclipse: server hello version %d (want %d)", out.Version, helloVersion)
	}
	if int(out.ValidLen) > len(plain)-4 {
		return out, fmt.Errorf("sntp-eclipse: server hello length %d exceeds body %d", out.ValidLen, len(plain)-4)
	}
	copy(out.ServerEph[:], plain[4:4+keySize])
	return out, nil
}

// readHelloReply reads the single S→C handshake record and binds it to the
// transcript hash (its AAD), then returns the server ephemeral key.
func readHelloReply(conn net.Conn, keys [4][keySize]byte, transcript [32]byte) (serverHello, error) {
	var out serverHello
	hdrAEAD, err := newAEAD(keys[2])
	if err != nil {
		return out, err
	}
	bodyAEAD, err := newAEAD(keys[3])
	if err != nil {
		return out, err
	}
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return out, fmt.Errorf("sntp-eclipse: read server hello header: %w", err)
	}
	bodyLen, err := openHeader(hdrAEAD, 0, transcript[:], header)
	if err != nil {
		return out, err
	}
	if bodyLen < 2+chachaOverhead || bodyLen > maxRecordBody {
		return out, fmt.Errorf("sntp-eclipse: server hello body length %d out of range", bodyLen)
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return out, fmt.Errorf("sntp-eclipse: read server hello body: %w", err)
	}
	plain, err := openBody(bodyAEAD, 0, transcript[:], header, body)
	if err != nil {
		return out, err
	}
	return parseServerHello(plain)
}
