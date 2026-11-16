package xhttpstream

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// The server side of the handshake is not fully pinned down by the two client
// implementations this package is built from:
//
//   - the vendor runtime disassembly reads a length prefixed preamble after the
//     echoed token and then the IV length byte
//     ([128][token][1]N[N][1]len[IV]);
//   - the published second generation client skips a fixed hmac sized region
//     after the token and then scans forward for the IV length marker
//     ([128][token][hmac][pad<=10][0x10][IV]).
//
// Both shapes differ only in how many bytes sit between the echoed token and
// the IV length byte, so the client can resolve the layout while reading: it
// buffers bytes one at a time, tests the strict layouts first, and falls back to
// the scan. The client handshake is identical for every layout, so tolerating
// all of them costs nothing on the wire.
const (
	// maxScanBytes bounds the layout search so a hostile or silent server
	// cannot make the client read without end. The vendor preamble is at most
	// one length prefixed blob, so 1 KiB is far above any real header.
	maxScanBytes = 1024

	// maxPadScan is the window the second generation client scans after the
	// hmac echo.
	maxPadScan = 10
)

var errPreambleTooLarge = errors.New("xhttp: server preamble is longer than the scan budget")

// resolveServerPreamble consumes the bytes between the echoed token and the IV
// length byte and returns a reader positioned right after the IV length byte
// merged with the connection, so the caller reads the IV without losing a
// buffered byte.
//
// hmacLen is len(StreamCipher.hmac): the hmac echo size of the second generation
// layout. ivSize is the IV length the marker must announce.
func resolveServerPreamble(conn io.Reader, hmacLen, ivSize int) (io.Reader, []byte, int, error) {
	buf := make([]byte, 0, 64)
	var one [1]byte
	for {
		if len(buf) >= maxScanBytes {
			return nil, nil, 0, errPreambleTooLarge
		}
		if _, err := io.ReadFull(conn, one[:]); err != nil {
			return nil, nil, 0, err
		}
		buf = append(buf, one[0])
		if marker := pickPreambleMarker(buf, hmacLen, ivSize); marker >= 0 {
			// Everything from marker+1 on is the IV (and the payload). The
			// resolver stops at the read that decided the layout, so no byte
			// past the marker is buffered.
			reader := io.MultiReader(bytes.NewReader(buf[marker+1:]), conn)
			return reader, buf[:marker+1], marker + 1, nil
		}
	}
}

// pickPreambleMarker reports the index of the IV length byte in buf, or -1 when
// the buffered prefix is still ambiguous. The strict, length prefixed layouts
// are tested before the scan so a random 0x10 inside a preamble cannot win over
// a header that actually parses.
func pickPreambleMarker(buf []byte, hmacLen, ivSize int) int {
	if len(buf) >= 1 {
		// Runtime layout: [N][N preamble bytes][ivSize].
		n := int(buf[0])
		if len(buf) >= 2+n && int(buf[1+n]) == ivSize {
			return 1 + n
		}
	}
	if hmacLen > 0 && len(buf) >= hmacLen+1 {
		// Hmac echo plus length prefixed preamble: [hmac][N][N][ivSize].
		n := int(buf[hmacLen])
		if len(buf) >= hmacLen+2+n && int(buf[hmacLen+1+n]) == ivSize {
			return hmacLen + 1 + n
		}
	}
	if hmacLen > 0 && len(buf) >= hmacLen+1 {
		// Second generation client: [hmac][pad][ivSize], pad <= maxPadScan.
		for p := hmacLen; p <= hmacLen+maxPadScan && p < len(buf); p++ {
			if int(buf[p]) == ivSize {
				return p
			}
		}
	}
	return -1
}

// describePreamble renders the resolved header for logs and tests; the bytes
// themselves are not secrets (padding), but keeping them out of error text keeps
// a hostile server from reflecting arbitrary bytes into the log.
func describePreamble(preamble []byte) string {
	return fmt.Sprintf("%d byte preamble", len(preamble))
}
