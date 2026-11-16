package xhttpstream

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

// TestPickPreambleMarker pins the three server preamble shapes the client
// accepts. The strict, length prefixed shapes must win over the loose scan so a
// padding byte that happens to be 0x10 cannot steal the marker.
func TestPickPreambleMarker(t *testing.T) {
	const hmacLen = 4
	const ivSize = 16
	cases := []struct {
		name string
		buf  []byte
		want int
	}{
		{"runtime, empty preamble", []byte{0x00, 0x10}, 1},
		{"runtime, 3 byte preamble", []byte{0x03, 0xaa, 0xbb, 0xcc, 0x10}, 4},
		{"runtime, marker still missing", []byte{0x03, 0xaa, 0xbb}, -1},
		{"hmac plus length prefixed", []byte{0x0f, 0x1e, 0x2d, 0x3c, 0x02, 0xaa, 0xbb, 0x10}, 7},
		{"second generation hmac echo", []byte{0x0f, 0x1e, 0x2d, 0x3c, 0xaa, 0xbb, 0x10}, 6},
		{"second generation no pad", []byte{0x0f, 0x1e, 0x2d, 0x3c, 0x10}, 4},
		{"nothing usable yet", []byte{0x0f}, -1},
	}
	for _, tc := range cases {
		if got := pickPreambleMarker(tc.buf, hmacLen, ivSize); got != tc.want {
			t.Errorf("%s: marker = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// testServerPreamble is the server half of one handshake layout: it writes the
// 128 byte prefix, the echoed token, layout specific preamble bytes, the IV
// length and a CTR encrypted message.
type testServerPreamble struct {
	name     string
	preamble func(ciph *StreamCipher, ivSize int) []byte
}

func serverPrefixAndToken(t *testing.T, conn net.Conn, ciph *StreamCipher) {
	t.Helper()
	prefix := make([]byte, FakePrefixLen)
	if _, err := rand.Read(prefix); err != nil {
		t.Errorf("prefix: %v", err)
		return
	}
	if _, err := conn.Write(append(prefix, ciph.token...)); err != nil {
		t.Errorf("write prefix and token: %v", err)
	}
}

// TestServerPreambleLayouts drives Conn.initReader against each server layout
// and checks the payload that follows decrypts, which only holds when the
// marker was found at the right offset.
func TestServerPreambleLayouts(t *testing.T) {
	layouts := []testServerPreamble{
		{
			name: "runtime length prefixed",
			preamble: func(ciph *StreamCipher, ivSize int) []byte {
				return []byte{0x02, 0xaa, 0xbb, byte(ivSize)}
			},
		},
		{
			name: "hmac echo plus length prefixed",
			preamble: func(ciph *StreamCipher, ivSize int) []byte {
				out := append([]byte{}, ciph.hmac...)
				return append(out, 0x02, 0xaa, 0xbb, byte(ivSize))
			},
		},
		{
			name: "second generation hmac echo and pad",
			preamble: func(ciph *StreamCipher, ivSize int) []byte {
				out := append([]byte{}, ciph.hmac...)
				return append(out, 0xaa, 0xbb, 0xcc, byte(ivSize))
			},
		},
	}
	for _, layout := range layouts {
		t.Run(layout.name, func(t *testing.T) {
			ciph := testCipher(t)
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()

			iv := make([]byte, ciph.IVSize())
			if _, err := rand.Read(iv); err != nil {
				t.Fatalf("iv: %v", err)
			}
			block, err := aes.NewCipher(Kdf(testSecret, 16))
			if err != nil {
				t.Fatalf("server cipher: %v", err)
			}
			go func() {
				serverPrefixAndToken(t, server, ciph)
				header := append(layout.preamble(ciph, ciph.IVSize()), iv...)
				if _, err := server.Write(header); err != nil {
					return
				}
				enc := NewWriter(server, cipher.NewCTR(block, iv))
				_, _ = enc.Write([]byte("pong"))
			}()

			stream := ciph.StreamConn(client, nil)
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			got := make([]byte, 4)
			if _, err := io.ReadFull(stream, got); err != nil {
				t.Fatalf("read payload: %v", err)
			}
			if !bytes.Equal(got, []byte("pong")) {
				t.Fatalf("payload = %q, want pong", got)
			}
		})
	}
}

// TestServerPreambleRejectsGarbage makes sure a preamble that never announces a
// sane IV length fails instead of reading forever.
func TestServerPreambleRejectsGarbage(t *testing.T) {
	ciph := testCipher(t)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		serverPrefixAndToken(t, server, ciph)
		junk := make([]byte, 64)
		for i := range junk {
			junk[i] = 0xaa
		}
		_, _ = server.Write(junk)
	}()
	stream := ciph.StreamConn(client, nil)
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(stream, make([]byte, 1)); err == nil {
		t.Fatal("garbage preamble handshake succeeded")
	}
}

// TestServerPreambleTokenMismatch keeps the echoed token check in force for
// every layout: a wrong password must not fall through to the payload.
func TestServerPreambleTokenMismatch(t *testing.T) {
	ciph := testCipher(t)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		prefix := make([]byte, FakePrefixLen)
		_, _ = server.Write(append(prefix, bytes.Repeat([]byte{0xff}, 16)...))
		_, _ = server.Write([]byte{0x00, 0x10})
		_, _ = server.Write(make([]byte, 16))
	}()
	stream := ciph.StreamConn(client, nil)
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(stream, make([]byte, 1)); err != ErrInvalidToken {
		t.Fatalf("error = %v, want ErrInvalidToken", err)
	}
}
