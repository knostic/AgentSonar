//go:build darwin

package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

type ClientHello struct {
	Version           uint16
	CipherSuites      []uint16
	Extensions        []uint16
	SNI               string
	ALPN              []string
	SignatureAlgs     []uint16
	SupportedVersions []uint16
}

func (ch *ClientHello) JA4() string {
	proto := "t"

	version := ch.Version
	for _, v := range ch.SupportedVersions {
		if v > version {
			version = v
		}
	}
	var verStr string
	switch version {
	case 0x0304:
		verStr = "13"
	case 0x0303:
		verStr = "12"
	case 0x0302:
		verStr = "11"
	case 0x0301:
		verStr = "10"
	default:
		verStr = "00"
	}

	sni := "i"
	if ch.SNI != "" && !isIP(ch.SNI) {
		sni = "d"
	}

	cipherCount := countNonGREASE(ch.CipherSuites)
	extCount := countNonGREASE(ch.Extensions)
	if cipherCount > 99 {
		cipherCount = 99
	}
	if extCount > 99 {
		extCount = 99
	}

	alpn := "00"
	if len(ch.ALPN) > 0 {
		alpn = normalizeALPN(ch.ALPN[0])
	}

	sectionA := fmt.Sprintf("%s%s%s%02d%02d%s", proto, verStr, sni, cipherCount, extCount, alpn)

	ciphers := filterGREASE(ch.CipherSuites)
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	cipherStrs := make([]string, len(ciphers))
	for i, c := range ciphers {
		cipherStrs[i] = fmt.Sprintf("%04x", c)
	}
	sectionB := truncatedHash(strings.Join(cipherStrs, ","))

	exts := filterGREASE(ch.Extensions)
	var filteredExts []uint16
	for _, e := range exts {
		if e != 0x0000 && e != 0x0010 {
			filteredExts = append(filteredExts, e)
		}
	}
	sort.Slice(filteredExts, func(i, j int) bool { return filteredExts[i] < filteredExts[j] })
	extStrs := make([]string, len(filteredExts))
	for i, e := range filteredExts {
		extStrs[i] = fmt.Sprintf("%04x", e)
	}

	sigAlgs := filterGREASE(ch.SignatureAlgs)
	sort.Slice(sigAlgs, func(i, j int) bool { return sigAlgs[i] < sigAlgs[j] })
	sigStrs := make([]string, len(sigAlgs))
	for i, s := range sigAlgs {
		sigStrs[i] = fmt.Sprintf("%04x", s)
	}

	hashInput := strings.Join(extStrs, ",") + "_" + strings.Join(sigStrs, ",")
	sectionC := truncatedHash(hashInput)

	return sectionA + "_" + sectionB + "_" + sectionC
}

func ParseClientHello(data []byte) *ClientHello {
	const (
		tlsHandshake   = 0x16
		tlsClientHello = 0x01
	)

	if len(data) < 5 || data[0] != tlsHandshake {
		return nil
	}

	recordLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recordLen {
		return nil
	}
	handshake := data[5 : 5+recordLen]

	if len(handshake) < 4 || handshake[0] != tlsClientHello {
		return nil
	}

	helloLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+helloLen {
		return nil
	}
	hello := handshake[4 : 4+helloLen]

	if len(hello) < 35 {
		return nil
	}

	ch := &ClientHello{
		Version: uint16(hello[0])<<8 | uint16(hello[1]),
	}

	pos := 34

	if pos >= len(hello) {
		return nil
	}
	sessionIDLen := int(hello[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(hello) {
		return nil
	}

	cipherLen := int(hello[pos])<<8 | int(hello[pos+1])
	pos += 2
	if pos+cipherLen > len(hello) {
		return nil
	}
	for i := 0; i < cipherLen; i += 2 {
		cipher := uint16(hello[pos+i])<<8 | uint16(hello[pos+i+1])
		ch.CipherSuites = append(ch.CipherSuites, cipher)
	}
	pos += cipherLen

	if pos >= len(hello) {
		return nil
	}
	compLen := int(hello[pos])
	pos += 1 + compLen
	if pos+2 > len(hello) {
		return ch
	}

	extLen := int(hello[pos])<<8 | int(hello[pos+1])
	pos += 2
	if pos+extLen > len(hello) {
		return ch
	}
	extensions := hello[pos : pos+extLen]

	for len(extensions) >= 4 {
		extType := uint16(extensions[0])<<8 | uint16(extensions[1])
		extDataLen := int(extensions[2])<<8 | int(extensions[3])
		if 4+extDataLen > len(extensions) {
			break
		}
		extData := extensions[4 : 4+extDataLen]

		ch.Extensions = append(ch.Extensions, extType)

		switch extType {
		case 0x0000:
			ch.SNI = parseSNIExtension(extData)
		case 0x0010:
			ch.ALPN = parseALPNExtension(extData)
		case 0x000d:
			ch.SignatureAlgs = parseSignatureAlgorithms(extData)
		case 0x002b:
			ch.SupportedVersions = parseSupportedVersions(extData)
		}

		extensions = extensions[4+extDataLen:]
	}

	return ch
}

func parseSNIExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	nameLen := int(data[3])<<8 | int(data[4])
	if 5+nameLen > len(data) {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

func parseALPNExtension(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	if 2+listLen > len(data) {
		return nil
	}
	var alpns []string
	pos := 2
	for pos < 2+listLen {
		if pos >= len(data) {
			break
		}
		strLen := int(data[pos])
		pos++
		if pos+strLen > len(data) {
			break
		}
		alpns = append(alpns, string(data[pos:pos+strLen]))
		pos += strLen
	}
	return alpns
}

func parseSignatureAlgorithms(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	if 2+listLen > len(data) {
		return nil
	}
	var algs []uint16
	for i := 2; i < 2+listLen; i += 2 {
		alg := uint16(data[i])<<8 | uint16(data[i+1])
		algs = append(algs, alg)
	}
	return algs
}

func parseSupportedVersions(data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	if 1+listLen > len(data) {
		return nil
	}
	var versions []uint16
	for i := 1; i < 1+listLen; i += 2 {
		ver := uint16(data[i])<<8 | uint16(data[i+1])
		versions = append(versions, ver)
	}
	return versions
}

func isGREASE(val uint16) bool {
	return val&0x0f0f == 0x0a0a
}

func filterGREASE(vals []uint16) []uint16 {
	var out []uint16
	for _, v := range vals {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func countNonGREASE(vals []uint16) int {
	count := 0
	for _, v := range vals {
		if !isGREASE(v) {
			count++
		}
	}
	return count
}

func truncatedHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:12]
}

func normalizeALPN(alpn string) string {
	switch alpn {
	case "h2":
		return "h2"
	case "http/1.1", "http/1.0":
		return "h1"
	default:
		if len(alpn) >= 2 {
			return alpn[:2]
		}
		return "00"
	}
}

func isIP(s string) bool {
	for _, c := range s {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func (ch *ClientHello) IsLikelyProgrammatic() (bool, string) {
	if len(ch.CipherSuites) == countNonGREASE(ch.CipherSuites) {
		return true, "no_grease"
	}
	if countNonGREASE(ch.CipherSuites) < 5 {
		return true, "few_ciphers"
	}
	if countNonGREASE(ch.Extensions) < 8 {
		return true, "few_extensions"
	}
	return false, ""
}
