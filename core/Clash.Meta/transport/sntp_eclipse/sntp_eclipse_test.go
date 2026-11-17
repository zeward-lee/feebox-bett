package sntp_eclipse

// Golden tests for the sntp-eclipse wire format.
//
// The vectors in testdata/vectors.json come from real captures, not from this
// implementation:
//
//   - "hello" / "record": the vendor client's own session, harvested from
//     re-sntp/cap/streams6/s06 (report-sntp-eclipse.md §10.4 / §13.1). The
//     handshake keys k0/k1 and traffic keys tk0/tk1 were recovered from the
//     same process' memory (cap/keys_live*.txt). The uuid inside the hello
//     plaintext is a vendor credential, so that one field was replaced with
//     "000102030405060708090a0b0c0d0e0f" and the record re-sealed with the
//     captured keys; every other byte (timestamp, lengths, padding, host,
//     port) is the captured value.
//   - "c2s_records" / "s2c_records": live sessions against the production
//     server with our reference client (re-sntp/client_final.py framing),
//     captured with their traffic keys.
//   - "hkdf" / "traffic_kdf": key-schedule inputs and outputs of the same
//     captured sessions.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type keyVec struct {
	S1         string   `json:"s1"`
	Salt       string   `json:"salt,omitempty"`
	S2         string   `json:"s2,omitempty"`
	Transcript string   `json:"transcript,omitempty"`
	ServerEph  string   `json:"server_eph,omitempty"`
	Keys       []string `json:"keys"`
}

type helloVec struct {
	Prefix string `json:"prefix"`
	Header string `json:"header"`
	Body   string `json:"body"`
	K0     string `json:"k0"`
	K1     string `json:"k1"`
	Expect struct {
		OuterLen     int    `json:"outer_len"`
		HelloLen     int    `json:"hello_len"`
		Version      int    `json:"version"`
		Cmd          int    `json:"cmd"`
		Timestamp    uint64 `json:"timestamp"`
		UUID         string `json:"uuid"`
		Host         string `json:"host"`
		Port         int    `json:"port"`
		PaddingLen   int    `json:"padding_len"`
		PlaintextLen int    `json:"plaintext_len"`
	} `json:"expect"`
}

type recordVec struct {
	Header  string `json:"header"`
	Body    string `json:"body"`
	Tk0     string `json:"tk0"`
	Tk1     string `json:"tk1"`
	Ctr     uint64 `json:"ctr"`
	Payload string `json:"payload"`
	PadLen  int    `json:"pad_len"`
}

type recordList struct {
	Tk      []string `json:"tk"`
	Records []struct {
		Ctr     uint64 `json:"ctr"`
		Record  string `json:"record"`
		Payload string `json:"payload"`
	} `json:"records"`
	KeptCtrs             []uint64 `json:"kept_ctrs"`
	SessionRecordCount   int      `json:"session_record_count"`
	SessionTotalBytes    int      `json:"session_total_bytes"`
	SessionPayloadSHA256 string   `json:"session_payload_sha256"`
}

type vectors struct {
	HKDF    keyVec     `json:"hkdf"`
	Traffic keyVec     `json:"traffic_kdf"`
	Hello   helloVec   `json:"hello"`
	Record  recordVec  `json:"record"`
	C2S     recordList `json:"c2s_records"`
	S2C     recordList `json:"s2c_records"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	path := filepath.Join("testdata", "vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func mustKey(t *testing.T, s string) [keySize]byte {
	t.Helper()
	var out [keySize]byte
	b := mustHex(t, s)
	if len(b) != keySize {
		t.Fatalf("key must be %d bytes, got %d", keySize, len(b))
	}
	copy(out[:], b)
	return out
}

func TestHandshakeKDFAgainstCapturedSession(t *testing.T) {
	v := loadVectors(t)
	s1 := mustKey(t, v.HKDF.S1)
	nonce := mustHex(t, v.HKDF.Salt)
	keys, err := handshakeKDF(s1, nonce, NativeV3Mode)
	if err != nil {
		t.Fatalf("handshakeKDF: %v", err)
	}
	for i, want := range v.HKDF.Keys {
		if got := hex.EncodeToString(keys[i][:]); got != want {
			t.Fatalf("handshake key k%d mismatch\n got  %s\n want %s", i, got, want)
		}
	}
}

func TestTrafficKDFAgainstCapturedSession(t *testing.T) {
	v := loadVectors(t)
	s1 := mustKey(t, v.Traffic.S1)
	s2 := mustKey(t, v.Traffic.S2)
	var transcript, serverEph [keySize]byte
	copy(transcript[:], mustHex(t, v.Traffic.Transcript))
	copy(serverEph[:], mustHex(t, v.Traffic.ServerEph))

	keys, err := trafficKDF(s1, s2, transcript, serverEph, NativeV3Mode)
	if err != nil {
		t.Fatalf("trafficKDF: %v", err)
	}
	for i, want := range v.Traffic.Keys {
		if got := hex.EncodeToString(keys[i][:]); got != want {
			t.Fatalf("traffic key tk%d mismatch\n got  %s\n want %s", i, got, want)
		}
	}
}

func TestOfficialHelloGolden(t *testing.T) {
	v := loadVectors(t)
	prefix := mustHex(t, v.Hello.Prefix)
	header := mustHex(t, v.Hello.Header)
	body := mustHex(t, v.Hello.Body)

	hdrAEAD, err := newAEAD(mustKey(t, v.Hello.K0))
	if err != nil {
		t.Fatal(err)
	}
	bodyAEAD, err := newAEAD(mustKey(t, v.Hello.K1))
	if err != nil {
		t.Fatal(err)
	}

	bodyLen, err := openHeader(hdrAEAD, 0, prefix, header)
	if err != nil {
		t.Fatalf("open official hello header: %v", err)
	}
	if bodyLen != len(body) {
		t.Fatalf("header advertises %d body bytes, capture has %d", bodyLen, len(body))
	}
	plain, err := openBody(bodyAEAD, 0, prefix, header, body)
	if err != nil {
		t.Fatalf("open official hello body: %v", err)
	}

	rec, err := parseHello(plain)
	if err != nil {
		t.Fatalf("parse official hello: %v", err)
	}
	w := v.Hello.Expect
	if len(plain) != w.PlaintextLen {
		t.Errorf("plaintext len = %d, want %d", len(plain), w.PlaintextLen)
	}
	if int(rec.OuterLen) != w.OuterLen {
		t.Errorf("outer len = %d, want %d", rec.OuterLen, w.OuterLen)
	}
	if int(rec.HelloLen) != w.HelloLen {
		t.Errorf("hello len = %d, want %d", rec.HelloLen, w.HelloLen)
	}
	if rec.Version != helloVersion || rec.Cmd != helloCmdConnect {
		t.Errorf("ver/cmd = %d/%d, want %d/%d", rec.Version, rec.Cmd, helloVersion, helloCmdConnect)
	}
	if rec.Timestamp != w.Timestamp {
		t.Errorf("timestamp = %d, want %d", rec.Timestamp, w.Timestamp)
	}
	if string(rec.Meta) != w.UUID {
		t.Errorf("meta = %q, want %q", rec.Meta, w.UUID)
	}
	if rec.Host != w.Host || int(rec.Port) != w.Port {
		t.Errorf("target = %s:%d, want %s:%d", rec.Host, rec.Port, w.Host, w.Port)
	}
	if rec.PaddingLen != w.PaddingLen {
		t.Errorf("padding = %d, want %d", rec.PaddingLen, w.PaddingLen)
	}

	// Re-sealing the captured plaintext must reproduce the captured bytes
	// exactly: same keys, same nonce (counter 0), same chained AAD.
	resealed := sealRecord(hdrAEAD, bodyAEAD, 0, prefix, plain)
	if !bytes.Equal(resealed, append(append([]byte{}, header...), body...)) {
		t.Fatalf("re-seal mismatch\n got  %x\n want %x", resealed, append(append([]byte{}, header...), body...))
	}
}

func TestOfficialDataRecordGolden(t *testing.T) {
	v := loadVectors(t)
	header := mustHex(t, v.Record.Header)
	body := mustHex(t, v.Record.Body)
	hdrAEAD, err := newAEAD(mustKey(t, v.Record.Tk0))
	if err != nil {
		t.Fatal(err)
	}
	bodyAEAD, err := newAEAD(mustKey(t, v.Record.Tk1))
	if err != nil {
		t.Fatal(err)
	}

	bodyLen, err := openHeader(hdrAEAD, v.Record.Ctr, nil, header)
	if err != nil {
		t.Fatalf("open data record header: %v", err)
	}
	if bodyLen != len(body) {
		t.Fatalf("header advertises %d bytes, capture has %d", bodyLen, len(body))
	}
	plain, err := openBody(bodyAEAD, v.Record.Ctr, nil, header, body)
	if err != nil {
		t.Fatalf("open data record body: %v", err)
	}
	payloadLen := int(plain[0])<<8 | int(plain[1])
	wantPayload := mustHex(t, v.Record.Payload)
	if payloadLen != len(wantPayload) {
		t.Fatalf("payload len = %d, want %d", payloadLen, len(wantPayload))
	}
	if !bytes.Equal(plain[2:2+payloadLen], wantPayload) {
		t.Fatalf("payload mismatch\n got  %q\n want %q", plain[2:2+payloadLen], wantPayload)
	}
	if got := len(plain) - 2 - payloadLen; got != v.Record.PadLen {
		t.Errorf("padding len = %d, want %d", got, v.Record.PadLen)
	}
	if !bytes.HasPrefix(wantPayload, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n")) {
		t.Fatalf("unexpected captured payload: %q", wantPayload)
	}

	// Byte-exact re-seal with the same counter and empty header AAD.
	if got := sealRecord(hdrAEAD, bodyAEAD, v.Record.Ctr, nil, plain); !bytes.Equal(got, append(append([]byte{}, header...), body...)) {
		t.Fatalf("re-seal mismatch\n got  %x\n want %x", got, append(append([]byte{}, header...), body...))
	}

	// Wrong counter must fail authentication (fail-closed).
	if _, err := openHeader(hdrAEAD, v.Record.Ctr+1, nil, header); err == nil {
		t.Fatal("opening the record with counter+1 must fail")
	}
	// Data records do not use the hello AAD prefix.
	if _, err := openHeader(hdrAEAD, v.Record.Ctr, mustHex(t, v.Hello.Prefix), header); err == nil {
		t.Fatal("opening a data record with the hello AAD prefix must fail")
	}
}

// swapped reorders traffic keys into newTunnelConn's layout for the peer side:
// the peer writes with tk2/tk3 and reads with tk0/tk1.
func swapped(keys [4][keySize]byte) [4][keySize]byte {
	return [4][keySize]byte{keys[2], keys[3], keys[0], keys[1]}
}

func TestRecordListsGolden(t *testing.T) {
	v := loadVectors(t)

	// C→S: two real records from one live session (counters 0 and 1).
	c2sHdr, err := newAEAD(mustKey(t, v.C2S.Tk[0]))
	if err != nil {
		t.Fatal(err)
	}
	c2sBody, err := newAEAD(mustKey(t, v.C2S.Tk[1]))
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range v.C2S.Records {
		raw := mustHex(t, rec.Record)
		bodyLen, err := openHeader(c2sHdr, rec.Ctr, nil, raw[:headerSize])
		if err != nil {
			t.Fatalf("c2s ctr=%d header: %v", rec.Ctr, err)
		}
		plain, err := openBody(c2sBody, rec.Ctr, nil, raw[:headerSize], raw[headerSize:headerSize+bodyLen])
		if err != nil {
			t.Fatalf("c2s ctr=%d body: %v", rec.Ctr, err)
		}
		want := mustHex(t, rec.Payload)
		payloadLen := int(plain[0])<<8 | int(plain[1])
		if !bytes.Equal(plain[2:2+payloadLen], want) {
			t.Fatalf("c2s ctr=%d payload mismatch", rec.Ctr)
		}
		if rec.Ctr > 0 {
			// A record sealed at counter N must not open at N-1: the counter is
			// part of the nonce, so miscounting breaks every later record.
			if _, err := openHeader(c2sHdr, rec.Ctr-1, nil, raw[:headerSize]); err == nil {
				t.Fatalf("c2s ctr=%d opened with counter-1", rec.Ctr)
			}
		}
	}
	if len(v.C2S.Records) != 2 {
		t.Fatalf("expected 2 captured c2s records, got %d", len(v.C2S.Records))
	}
	// The two captured payloads must reassemble the original request.
	joined := append(mustHex(t, v.C2S.Records[0].Payload), mustHex(t, v.C2S.Records[1].Payload)...)
	if !bytes.HasSuffix(joined, []byte("\r\n\r\n")) || !bytes.HasPrefix(joined, []byte("GET / HTTP/1.1")) {
		t.Fatalf("c2s payloads do not reassemble the request: %q", joined)
	}

	// S→C: real response records, including the last one of the session, which
	// proves counters above 8 (we keep ctr 0..7 plus the final record).
	s2cHdr, err := newAEAD(mustKey(t, v.S2C.Tk[0]))
	if err != nil {
		t.Fatal(err)
	}
	s2cBody, err := newAEAD(mustKey(t, v.S2C.Tk[1]))
	if err != nil {
		t.Fatal(err)
	}
	var firstPayload []byte
	for _, rec := range v.S2C.Records {
		raw := mustHex(t, rec.Record)
		bodyLen, err := openHeader(s2cHdr, rec.Ctr, nil, raw[:headerSize])
		if err != nil {
			t.Fatalf("s2c ctr=%d header: %v", rec.Ctr, err)
		}
		plain, err := openBody(s2cBody, rec.Ctr, nil, raw[:headerSize], raw[headerSize:headerSize+bodyLen])
		if err != nil {
			t.Fatalf("s2c ctr=%d body: %v", rec.Ctr, err)
		}
		payloadLen := int(plain[0])<<8 | int(plain[1])
		want := mustHex(t, rec.Payload)
		if !bytes.Equal(plain[2:2+payloadLen], want) {
			t.Fatalf("s2c ctr=%d payload mismatch", rec.Ctr)
		}
		if rec.Ctr == 0 {
			firstPayload = want
		}
	}
	if !bytes.HasPrefix(firstPayload, []byte("HTTP/1.1 200 OK\r\n")) {
		t.Fatalf("first s2c payload is not the HTTP response head: %q", firstPayload[:32])
	}
	if v.S2C.SessionRecordCount < len(v.S2C.Records) {
		t.Fatalf("capture metadata inconsistent: %d kept of %d records",
			len(v.S2C.Records), v.S2C.SessionRecordCount)
	}
	if len(v.S2C.SessionPayloadSHA256) != 64 {
		t.Fatalf("missing session payload digest")
	}
}

func TestConnReadWrite(t *testing.T) {
	keys := [4][keySize]byte{}
	for i := range keys {
		keys[i][i] = byte(i + 1)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	writer, err := newTunnelConn(left, keys)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := newTunnelConn(right, swapped(keys))
	if err != nil {
		t.Fatal(err)
	}

	payloads := [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		bytes.Repeat([]byte("a"), 12345), // spans multiple records
		[]byte("tail"),
	}
	for _, p := range payloads {
		want := p
		done := make(chan error, 1)
		go func() {
			_, err := writer.Write(want)
			done <- err
		}()
		got := make([]byte, len(want))
		if _, err := io.ReadFull(reader, got); err != nil {
			t.Fatalf("read: %v", err)
		}
		if err := <-done; err != nil {
			t.Fatalf("write: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("round trip mismatch: got %d bytes want %d", len(got), len(want))
		}
	}
	// 33 + 4 (12345 = 4000*3+345) + 1 = 8 records; one counter step per record.
	const wantRecords = 1 + 4 + 1
	if writer.writeCtr != wantRecords {
		t.Fatalf("writer counter = %d, want %d", writer.writeCtr, wantRecords)
	}
	if reader.readCtr != writer.writeCtr {
		t.Fatalf("reader counter %d != writer counter %d", reader.readCtr, writer.writeCtr)
	}
}

func TestShortFrameFailsClosed(t *testing.T) {
	keys := [4][keySize]byte{}
	aead, err := newAEAD(keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openHeader(aead, 0, nil, make([]byte, headerSize-1)); err == nil {
		t.Fatal("short header must fail")
	}
	if _, err := openHeader(aead, 0, nil, make([]byte, headerSize)); err == nil {
		t.Fatal("zeroed header must fail authentication")
	}

	peer, self := net.Pipe()
	defer peer.Close()
	conn, err := newTunnelConn(self, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	go func() {
		// header that advertises 60000 body bytes, then EOF
		badHdrAEAD, _ := newAEAD(keys[2])
		nonce := recordNonce(0)
		header := badHdrAEAD.Seal(nil, nonce, []byte{0xea, 0x60}, nil)
		_, _ = peer.Write(header)
		_ = peer.Close()
	}()
	if _, err := conn.Read(make([]byte, 16)); err == nil {
		t.Fatal("truncated record body must fail")
	}
}

func TestParseHelloRejectsTruncated(t *testing.T) {
	if _, err := parseHello([]byte{0, 1, 0, 2}); err == nil {
		t.Fatal("truncated hello must fail")
	}
	// valid prefix but a host length larger than the buffer
	plain := make([]byte, 40)
	plain[2], plain[3] = 0, 10
	plain[4], plain[5] = 3, 1
	plain[4+26] = 0 // meta len 0
	plain[4+27], plain[4+28] = 0xff, 0xff
	if _, err := parseHello(plain); err == nil {
		t.Fatal("impossible host length must fail")
	}
}

func TestParseServerHello(t *testing.T) {
	plain := make([]byte, 4+32+4)
	plain[0], plain[1] = 0, 34
	plain[2], plain[3] = 3, 1
	for i := 0; i < 32; i++ {
		plain[4+i] = byte(i)
	}
	got, err := parseServerHello(plain)
	if err != nil {
		t.Fatalf("parseServerHello: %v", err)
	}
	if got.ServerEph[0] != 0 || got.ServerEph[31] != 31 {
		t.Fatalf("server eph parsed wrong: %x", got.ServerEph[:])
	}
	if _, err := parseServerHello(plain[:10]); err == nil {
		t.Fatal("truncated server hello must fail")
	}
	bad := append([]byte{}, plain...)
	bad[2] = 4
	if _, err := parseServerHello(bad); err == nil {
		t.Fatal("wrong server hello version must fail")
	}
}

func TestDecodeConfigFields(t *testing.T) {
	// 32 hex characters: accepted, ASCII bytes are what hello carries.
	id, err := DecodeUUID("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("DecodeUUID: %v", err)
	}
	if string(id[:]) != "000102030405060708090a0b0c0d0e0f" {
		t.Fatalf("uuid bytes = %q", id)
	}
	if _, err := DecodeUUID("00010203-0405-0607-0809-0a0b0c0d0e0f"); err == nil {
		t.Fatal("dashed uuid must be rejected")
	}
	if _, err := DecodeUUID("zz0102030405060708090a0b0c0d0e0f"); err == nil {
		t.Fatal("non-hex uuid must be rejected")
	}

	// base64url (unpadded) and padded spellings of the same 32 bytes.
	raw := bytes.Repeat([]byte{0xab}, 32)
	url := b64url(raw)
	if got, err := DecodeServerPublicKey(url); err != nil || !bytes.Equal(got[:], raw) {
		t.Fatalf("base64url key: %v", err)
	}
	if got, err := DecodeServerPublicKey(url + "="); err != nil || !bytes.Equal(got[:], raw) {
		t.Fatalf("padded key: %v", err)
	}
	if _, err := DecodeServerPublicKey("short"); err == nil {
		t.Fatal("short key must be rejected")
	}
}

func b64url(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var out []byte
	for i := 0; i < len(b); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], b[i:])
		out = append(out, alphabet[chunk[0]>>2])
		out = append(out, alphabet[(chunk[0]&0x03)<<4|chunk[1]>>4])
		if n > 1 {
			out = append(out, alphabet[(chunk[1]&0x0f)<<2|chunk[2]>>6])
		}
		if n > 2 {
			out = append(out, alphabet[chunk[2]&0x3f])
		}
	}
	return string(out)
}

func TestBuildHelloFrameLayout(t *testing.T) {
	// Deterministic hex reader: the ephemeral nonces must be sourced from it.
	saved := randReader
	defer func() { randReader = saved }()
	randReader = bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096))

	keys := [4][keySize]byte{}
	for i := range keys {
		keys[i][i] = 0x10 + byte(i)
	}
	var prefix [48]byte
	for i := range prefix {
		prefix[i] = byte(i)
	}
	var uuid [32]byte
	copy(uuid[:], "00112233445566778899aabbccddeeff")

	frame, transcript, err := buildHello(prefix[:], keys, Target{Host: "example.com", Port: 80}, uuid, time.Unix(1794891190, 0))
	if err != nil {
		t.Fatalf("buildHello: %v", err)
	}
	if len(frame) != len(prefix)+headerSize+helloPlaintextLen+chachaOverhead {
		t.Fatalf("frame length = %d", len(frame))
	}
	if transcript != sha256.Sum256(frame) {
		t.Fatal("transcript must be SHA256 of the whole hello frame")
	}

	hdrAEAD, _ := newAEAD(keys[0])
	bodyAEAD, _ := newAEAD(keys[1])
	bodyLen, err := openHeader(hdrAEAD, 0, prefix[:], frame[len(prefix):len(prefix)+headerSize])
	if err != nil {
		t.Fatalf("open own hello header: %v", err)
	}
	plain, err := openBody(bodyAEAD, 0, prefix[:], frame[len(prefix):len(prefix)+headerSize],
		frame[len(prefix)+headerSize:len(prefix)+headerSize+bodyLen])
	if err != nil {
		t.Fatalf("open own hello body: %v", err)
	}
	rec, err := parseHello(plain)
	if err != nil {
		t.Fatalf("parse own hello: %v", err)
	}
	if rec.OuterLen != helloOuterLen || rec.HelloLen != 74 {
		t.Fatalf("outer/hello len = %d/%d", rec.OuterLen, rec.HelloLen)
	}
	if rec.Host != "example.com" || rec.Port != 80 || rec.Timestamp != 1794891190 {
		t.Fatalf("target/timestamp = %s:%d %d", rec.Host, rec.Port, rec.Timestamp)
	}
	if string(rec.Meta) != string(uuid[:]) {
		t.Fatalf("meta = %q", rec.Meta)
	}
	if len(plain) != helloPlaintextLen {
		t.Fatalf("plaintext len = %d, want %d", len(plain), helloPlaintextLen)
	}
	// The hello nonce inside the payload must differ from the prefix nonce by
	// construction (independent randomness).
	if bytes.Equal(rec.Nonce[:], prefix[32:]) {
		t.Fatal("hello nonce must be independent from the prefix nonce")
	}
}

func TestDialRejectsBadConfig(t *testing.T) {
	peer, self := net.Pipe()
	defer peer.Close()
	_, err := dial(self, ClientConfig{Mode: "something-else", ServerPublicKey: "x", UUID: "y"}, Target{Host: "example.com"}, time.Now())
	if err == nil {
		t.Fatal("unsupported mode must be rejected")
	}
	self2, peer2 := net.Pipe()
	defer self2.Close()
	defer peer2.Close()
	if _, err := Dial(self2, ClientConfig{Mode: NativeV3Mode, ServerPublicKey: "not-base64!", UUID: "x"}, Target{Host: "example.com"}); err == nil {
		t.Fatal("bad server-public-key must be rejected")
	}
}
