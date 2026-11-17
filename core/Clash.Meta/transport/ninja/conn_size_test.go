package ninja

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// captureConn records everything the tunnel writes so tests can decode the
// records without a peer.
type captureConn struct {
	buf bytes.Buffer
}

func (c *captureConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Write(p []byte) (int, error)      { return c.buf.Write(p) }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4zero} }
func (c *captureConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4zero} }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

// TestPlanFirstBlock pins the reference size model: pad is drawn from
// 1..min(900, 877-addrLen), payload gets the rest of the 877 byte budget and
// an exhausted budget still yields a 1 byte pad with no payload.
func TestPlanFirstBlock(t *testing.T) {
	tests := []struct {
		name    string
		addrLen int
		limit   int
		exhaust bool
	}{
		{name: "domain example.com", addrLen: 15, limit: 862},
		{name: "ipv4", addrLen: 7, limit: 870},
		{name: "ipv6", addrLen: 19, limit: 858},
		{name: "zero address", addrLen: 0, limit: 877},
		{name: "only one byte left", addrLen: 876, limit: 1},
		{name: "exact budget", addrLen: 877, exhaust: true},
		{name: "over budget", addrLen: 878, exhaust: true},
		{name: "large", addrLen: 900, exhaust: true},
		{name: "former 64k cap", addrLen: 65471, exhaust: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 500; i++ {
				pad, payload := planFirstBlock(tc.addrLen)
				if tc.exhaust {
					if pad != 1 || payload != 0 {
						t.Fatalf("addrLen=%d: got pad=%d payload=%d, want 1/0", tc.addrLen, pad, payload)
					}
					continue
				}
				if pad < 1 {
					t.Fatalf("addrLen=%d: pad=%d, padding must be at least 1", tc.addrLen, pad)
				}
				if pad > tc.limit {
					t.Fatalf("addrLen=%d: pad=%d exceeds limit %d", tc.addrLen, pad, tc.limit)
				}
				if payload < 0 {
					t.Fatalf("addrLen=%d: negative payload %d", tc.addrLen, payload)
				}
				if got := pad + payload; got != tc.limit {
					t.Fatalf("addrLen=%d: pad+payload=%d, want %d", tc.addrLen, got, tc.limit)
				}
			}
		})
	}

	// The 900 clamp only caps the random draw; the payload budget still comes
	// from the raw 877-S formula. Only a negative address length can reach
	// this branch, but keep it exercised so a refactor cannot drop the clamp.
	for i := 0; i < 200; i++ {
		pad, payload := planFirstBlock(-30)
		if pad < 1 || pad > paddingRandMax {
			t.Fatalf("clamped pad=%d out of 1..%d", pad, paddingRandMax)
		}
		if pad+payload != firstBlockBudget+30 {
			t.Fatalf("clamped pad+payload=%d, want %d", pad+payload, firstBlockBudget+30)
		}
	}
}

// decodeRecord opens one sealed record at off and returns it with the next
// offset.
func decodeRecord(t *testing.T, st *state, raw []byte, off, plainLen int) ([]byte, int) {
	t.Helper()
	end := off + plainLen + st.aead.Overhead()
	if end > len(raw) {
		t.Fatalf("record at %d: want %d bytes, only %d left", off, plainLen+st.aead.Overhead(), len(raw)-off)
	}
	plain, err := st.open(nil, raw[off:end])
	if err != nil {
		t.Fatalf("open record at %d: %v", off, err)
	}
	if len(plain) != plainLen {
		t.Fatalf("record at %d: plaintext len %d, want %d", off, len(plain), plainLen)
	}
	return plain, end
}

// TestFirstBlockOnWire checks the emitted first block and chunk against the
// reference budget: addr || BE16(pad) || pad || payload stays <= 879 bytes and
// the leftover data is chunk framed with 1..900 padding bytes.
func TestFirstBlockOnWire(t *testing.T) {
	for _, payloadLen := range []int{1, 100, 314, 876, 877, 900, 5000} {
		t.Run(itoa(payloadLen)+"B", func(t *testing.T) {
			cfg := testConfig()
			addr, err := EncodeSocksAddr("example.com", 443)
			if err != nil {
				t.Fatal(err)
			}
			cc := &captureConn{}
			c := NewConn(cc, cfg, true)
			c.SetAddr(addr)
			payload := bytes.Repeat([]byte{0x5a}, payloadLen)
			if _, err := c.Write(payload); err != nil {
				t.Fatalf("write: %v", err)
			}

			raw := cc.buf.Bytes()
			keyLen := cfg.Method.KeyLen()
			salt := raw[:keyLen]
			off := keyLen + tokenLen

			st, err := newState(cfg, 2)
			if err != nil {
				t.Fatal(err)
			}
			if err := st.adopt(salt); err != nil {
				t.Fatal(err)
			}

			meta, off := decodeRecord(t, st, raw, off, metaLen)
			firstLen := int(binary.BigEndian.Uint16(meta[10:12]))
			block, off := decodeRecord(t, st, raw, off, firstLen)

			addrLen := len(addr)
			if len(block) < addrLen+2 {
				t.Fatalf("first block too short: %d", len(block))
			}
			pad := int(binary.BigEndian.Uint16(block[addrLen : addrLen+2]))
			firstPayload := len(block) - addrLen - 2 - pad
			if firstPayload < 0 {
				t.Fatalf("pad=%d does not fit in block of %d", pad, len(block))
			}
			if pad < 1 || pad > firstBlockBudget-addrLen {
				t.Fatalf("first block pad=%d outside 1..%d", pad, firstBlockBudget-addrLen)
			}
			if len(block) > firstBlockBudget+2 {
				t.Fatalf("first block is %d bytes, budget allows %d", len(block), firstBlockBudget+2)
			}
			if want := firstBlockBudget - addrLen - pad; firstPayload > want {
				t.Fatalf("first payload %d exceeds budget %d", firstPayload, want)
			}

			got := append([]byte{}, block[addrLen+2+pad:]...)
			for {
				if len(got) >= payloadLen {
					break
				}
				hdr, next := decodeRecord(t, st, raw, off, chunkHeaderLen)
				off = next
				total := int(binary.BigEndian.Uint16(hdr[0:2]))
				chunkPad := int(binary.BigEndian.Uint16(hdr[2:4]))
				if chunkPad < 1 || chunkPad > paddingRandMax {
					t.Fatalf("chunk pad=%d outside 1..%d", chunkPad, paddingRandMax)
				}
				if chunkPad > total {
					t.Fatalf("chunk pad=%d exceeds total %d", chunkPad, total)
				}
				if total > maxChunkPayload+paddingRandMax {
					t.Fatalf("chunk total %d too large", total)
				}
				body, next := decodeRecord(t, st, raw, off, total)
				off = next
				got = append(got, body[:total-chunkPad]...)
			}
			if off != len(raw) {
				t.Fatalf("%d trailing bytes after last chunk", len(raw)-off)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
			}
		})
	}
}

// TestSplitPayloadPaddingRange makes sure the read side accepts the whole
// reference padding range 0..900 and does not hardcode the old 128 ceiling.
func TestSplitPayloadPaddingRange(t *testing.T) {
	addr, err := EncodeSocksAddr("example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	for _, pad := range []int{0, 1, 128, 129, 877, 900} {
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(pad))
		block := append([]byte{}, addr...)
		block = append(block, l[:]...)
		block = append(block, bytes.Repeat([]byte{0xee}, pad)...)
		want := []byte("hello-after-padding")
		block = append(block, want...)

		gotAddr, gotPayload, err := splitPayload(block)
		if err != nil {
			t.Fatalf("pad=%d: %v", pad, err)
		}
		if !bytes.Equal(gotAddr, addr) {
			t.Fatalf("pad=%d: address mismatch", pad)
		}
		if !bytes.Equal(gotPayload, want) {
			t.Fatalf("pad=%d: payload mismatch %q", pad, gotPayload)
		}

		hdr := append([]byte{}, l[:]...)
		hdr = append(hdr, bytes.Repeat([]byte{0xee}, pad)...)
		hdr = append(hdr, want...)
		if _, got, err := splitPayloadNoAddr(hdr); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("pad=%d: no-addr parse err=%v payload=%q", pad, err, got)
		}
	}
}

// TestWriteAfterReadKeepsOwnCipherState guards the shared-cipher-state bug:
// readHeader used to adopt the peer salt into the same AEAD/nonce the writer
// used, so every chunk written after the first read was sealed with the peer
// key and an advanced nonce. Plain HTTP put the whole request in the first
// block and worked; TLS broke right after the handshake. A session must stay
// usable when writes and reads interleave.
func TestWriteAfterReadKeepsOwnCipherState(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv, err := NewServer(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	type sres struct {
		c   net.Conn
		err error
	}
	ch := make(chan sres, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			ch <- sres{err: err}
			return
		}
		c, _, _, err := srv.Handshake(raw)
		ch <- sres{c: c, err: err}
	}()

	cli, err := NewClient(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := cli.StreamConn(raw, "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}

	// 1) first write is carried by the tunnel header
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	s := <-ch
	if s.err != nil {
		t.Fatalf("handshake: %v", s.err)
	}
	defer s.c.Close()
	got := make([]byte, 4)
	if _, err := io.ReadFull(s.c, got); err != nil || string(got) != "ping" {
		t.Fatalf("server first read: %q err=%v", got, err)
	}

	// 2) the server sends two records; the client reads only the first one
	if _, err := s.c.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.c.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, got[:3]); err != nil || string(got[:3]) != "one" {
		t.Fatalf("client read one: %q err=%v", got[:3], err)
	}

	// 3) client writes after reading; must still use its own key and nonce
	if _, err := c.Write([]byte("after")); err != nil {
		t.Fatalf("write after read: %v", err)
	}
	want := make([]byte, 5)
	if _, err := io.ReadFull(s.c, want); err != nil || string(want) != "after" {
		t.Fatalf("server read after response: %q err=%v", want, err)
	}

	// 4) the pending second record is still readable, so neither direction
	// consumed the other's nonce
	if _, err := io.ReadFull(c, got[:3]); err != nil || string(got[:3]) != "two" {
		t.Fatalf("client read two: %q err=%v", got[:3], err)
	}
}
