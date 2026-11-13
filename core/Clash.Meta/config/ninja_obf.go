package config

// ninja subscription deobfuscation, reconstructed from the reference core:
//
//   restoreNinjaNode: decode server/port/node_password of every "type: ninja"
//   proxy marked with "tls: true" (the marker is dropped afterwards), then
//   inject the fields carried by the "#!PASS-INFO" comment (set/replace).

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"sort"
	"strconv"
	"strings"
)

const (
	ninjaAlpha36 = "0123456789abcdefghijklmnopqrstuvwxyz"
	ninjaAlpha69 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@#$%^&*"
	ninjaPassKey = "ninja-pass-info"
)

func ninjaSaltShuffle(alpha, salt string) []byte {
	type pair struct {
		ch  byte
		sum [32]byte
	}
	ps := make([]pair, 0, len(alpha))
	for i := 0; i < len(alpha); i++ {
		ps = append(ps, pair{ch: alpha[i], sum: sha256.Sum256([]byte(salt + "|" + string(alpha[i])))})
	}
	sort.SliceStable(ps, func(i, j int) bool { return bytes.Compare(ps[i].sum[:], ps[j].sum[:]) < 0 })
	out := make([]byte, len(ps))
	for i, p := range ps {
		out[i] = p.ch
	}
	return out
}

// ninjaBaseNDecode decodes s as a big endian integer over alpha.
func ninjaBaseNDecode(s string, alpha []byte) []byte {
	idx := make(map[byte]int, len(alpha))
	for i, c := range alpha {
		idx[c] = i
	}
	n := len(alpha)
	acc := []byte{0}
	for i := 0; i < len(s); i++ {
		d, ok := idx[s[i]]
		if !ok {
			return nil
		}
		carry := d
		for j := 0; j < len(acc); j++ {
			v := int(acc[j])*n + carry
			acc[j] = byte(v & 0xff)
			carry = v >> 8
		}
		for carry > 0 {
			acc = append(acc, byte(carry&0xff))
			carry >>= 8
		}
	}
	for len(acc) > 1 && acc[len(acc)-1] == 0 {
		acc = acc[:len(acc)-1]
	}
	out := make([]byte, len(acc))
	for i := range acc {
		out[i] = acc[len(acc)-1-i]
	}
	return out
}

func ninjaStrXor(data []byte, key string) []byte {
	k := sha256.Sum256([]byte(key))
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ k[i&0x1f]
	}
	return out
}

func ninjaInflate(b []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(b))
	defer r.Close()
	return io.ReadAll(r)
}

func ninjaUnmapPort(port int, salt string, lo, hi, mul int) int {
	crc := int(crc32.ChecksumIEEE([]byte(salt)))
	if lo > hi {
		lo, hi = hi, lo
	}
	span := hi - lo + 1
	v := span*mul + (port - lo) - crc
	if v < 0 {
		v = 0
	}
	if v > 0xffff {
		v &= 0xffff
	}
	return v
}

func ninjaStr(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func ninjaInt(m map[string]any, key string) (int, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case string:
		i, err := strconv.Atoi(n)
		if err != nil {
			return 0, false
		}
		return i, true
	}
	return 0, false
}

func ninjaBool(m map[string]any, key string) bool {
	v, ok := m[key]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

func ninjaDecodeHost(tag, cand string, a36 []byte, xorKey string, pwd string, rawPort int) (string, error) {
	switch tag {
	case "01a", "01b":
		return string(ninjaStrXor(ninjaBaseNDecode(cand, a36), xorKey)), nil
	case "01c":
		h, err := ninjaInflate(ninjaStrXor(ninjaBaseNDecode(cand, a36), xorKey))
		if err != nil {
			return "", err
		}
		return string(h), nil
	case "02a":
		b := ninjaBaseNDecode(cand, a36)
		if len(b) != 4 {
			return "", fmt.Errorf("bad ipv4 payload")
		}
		v := binary.BigEndian.Uint32(b) ^ crc32.ChecksumIEEE([]byte(pwd)) ^ uint32(rawPort)
		return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v)), nil
	case "02b", "02c":
		return strings.ToLower(string(ninjaStrXor(ninjaBaseNDecode(cand, a36), xorKey))), nil
	}
	return "", fmt.Errorf("bad id")
}

// restoreNinjaNode decodes one obfuscated proxy map in place.
func restoreNinjaNode(m map[string]any) error {
	pwd := ninjaStr(m, "password")
	server := ninjaStr(m, "server")
	if server == "" {
		return fmt.Errorf("missing server")
	}
	rawPort, ok := ninjaInt(m, "port")
	if !ok {
		return fmt.Errorf("missing port")
	}
	dot := strings.IndexByte(server, '.')
	if dot < 0 {
		return fmt.Errorf("bad label format")
	}
	label, rest := server[:dot], server[dot+1:]
	if len(label) < 8 {
		return fmt.Errorf("bad label format")
	}
	dash := strings.IndexByte(label, '-')
	if dash < 0 {
		return fmt.Errorf("bad label format")
	}
	key := label[dash+1:]
	tag := label[4:7]

	a36 := ninjaSaltShuffle(ninjaAlpha36, pwd)
	a69 := ninjaSaltShuffle(ninjaAlpha69, pwd)

	pt, err := ninjaInflate(ninjaStrXor(ninjaBaseNDecode(ninjaStr(m, "node_password"), a69), key))
	if err != nil {
		return fmt.Errorf("inflate: %w", err)
	}
	i := bytes.IndexByte(pt, 0x1f)
	if i < 0 {
		return fmt.Errorf("empty payload")
	}
	newPwd := string(pt[:i])
	rest2 := pt[i+1:]
	field2, tail := string(rest2), ""
	if j := bytes.IndexByte(rest2, '#'); j >= 0 {
		field2, tail = string(rest2[:j]), string(rest2[j+1:])
	}
	mul, _ := strconv.Atoi(field2)
	xorKey := pwd + ":" + strconv.Itoa(rawPort)

	host, err := ninjaDecodeHost(tag, key+tail, a36, xorKey, pwd, rawPort)
	if err != nil {
		return err
	}
	if rest != "" {
		host = host + "." + rest
	}
	m["server"] = strings.ToLower(host)
	m["port"] = ninjaUnmapPort(rawPort, pwd, 10000, 20000, mul)
	m["node_password"] = newPwd
	delete(m, "tls")
	return nil
}

type ninjaPassInfo struct {
	Set     map[string]any   `json:"set"`
	Replace []map[string]any `json:"replace"`
}

func extractNinjaPassInfo(raw []byte) (*ninjaPassInfo, bool) {
	for _, line := range strings.Split(string(raw), "\n") {
		idx := strings.Index(line, "#!PASS-INFO")
		if idx < 0 {
			continue
		}
		payload := strings.TrimSpace(line[idx+len("#!PASS-INFO"):])
		if payload == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			continue
		}
		var info ninjaPassInfo
		if err := json.Unmarshal(ninjaStrXor(decoded, ninjaPassKey), &info); err != nil {
			continue
		}
		return &info, true
	}
	return nil, false
}

// ProcessNinjaObfuscation restores obfuscated ninja proxies and injects the
// pass settings carried by the subscription comment.
func ProcessNinjaObfuscation(proxies []map[string]any, raw []byte) {
	for _, p := range proxies {
		if ninjaStr(p, "type") != "ninja" {
			continue
		}
		if !ninjaBool(p, "tls") {
			continue
		}
		if err := restoreNinjaNode(p); err != nil {
			delete(p, "tls")
		}
	}
	info, ok := extractNinjaPassInfo(raw)
	if !ok {
		return
	}
	for _, p := range proxies {
		if ninjaStr(p, "type") != "ninja" {
			continue
		}
		for k, v := range info.Set {
			p[k] = v
		}
		for _, r := range info.Replace {
			match, _ := r["match"].(map[string]any)
			repl, _ := r["replace"].(map[string]any)
			if match == nil || repl == nil {
				continue
			}
			if ninjaStr(p, "server") != ninjaStr(match, "server") {
				continue
			}
			for k, v := range repl {
				p[k] = v
			}
		}
	}
}
