package sai

import (
	"path/filepath"
	"testing"
	"time"
)

func makeEvent(process, domain, source string) Event {
	return Event{
		Timestamp: time.Now(),
		PID:       1234,
		Process:   process,
		Domain:    domain,
		Source:    source,
	}
}

func makeEventWithExtras(process, domain string, extras map[string]string) Event {
	return Event{
		Timestamp: time.Now(),
		PID:       1234,
		Process:   process,
		Domain:    domain,
		Source:    "tls",
		Extras:    extras,
	}
}

func makeStatsInput(bytesIn, bytesOut int64, packetsIn, packetsOut int, durationMs int64, sources map[string]int) *PairStats {
	return &PairStats{
		TotalBytesIn:    bytesIn,
		TotalBytesOut:   bytesOut,
		TotalPacketsIn:  packetsIn,
		TotalPacketsOut: packetsOut,
		TotalDurationMs: durationMs,
		Sources:         sources,
	}
}

func withTempFilterSet(t *testing.T, fn func(fs *FilterSet, path string)) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "filters.bin")
	fs := NewFilterSet()
	fn(fs, path)
}

func makeDNSQueryPacket(domain string) []byte {
	pkt := make([]byte, 12)
	pkt[4] = 0
	pkt[5] = 1
	pkt = append(pkt, encodeDNSName(domain)...)
	pkt = append(pkt, 0, 1, 0, 1)
	return pkt
}

func makeDNSResponsePacket(domain string, ips []string) []byte {
	pkt := make([]byte, 12)
	pkt[2] = 0x80
	pkt[4] = 0
	pkt[5] = 1
	pkt[6] = 0
	pkt[7] = byte(len(ips))

	pkt = append(pkt, encodeDNSName(domain)...)
	pkt = append(pkt, 0, 1, 0, 1)

	for _, ip := range ips {
		pkt = append(pkt, 0xc0, 0x0c)
		pkt = append(pkt, 0, 1)
		pkt = append(pkt, 0, 1)
		pkt = append(pkt, 0, 0, 0, 60)
		pkt = append(pkt, 0, 4)
		pkt = append(pkt, parseIPv4(ip)...)
	}
	return pkt
}

func encodeDNSName(domain string) []byte {
	var result []byte
	labels := splitLabels(domain)
	for _, label := range labels {
		result = append(result, byte(len(label)))
		result = append(result, []byte(label)...)
	}
	result = append(result, 0)
	return result
}

func splitLabels(domain string) []string {
	var labels []string
	start := 0
	for i := 0; i <= len(domain); i++ {
		if i == len(domain) || domain[i] == '.' {
			if i > start {
				labels = append(labels, domain[start:i])
			}
			start = i + 1
		}
	}
	return labels
}

func parseIPv4(ip string) []byte {
	result := make([]byte, 4)
	var octet byte
	idx := 0
	for i := 0; i <= len(ip); i++ {
		if i == len(ip) || ip[i] == '.' {
			result[idx] = octet
			idx++
			octet = 0
		} else {
			octet = octet*10 + (ip[i] - '0')
		}
	}
	return result
}

func makeClientHelloWithALPN(sni string, ciphers, extensions []uint16, alpn string) []byte {
	hello := make([]byte, 0, 512)

	hello = append(hello, 0x03, 0x03)
	hello = append(hello, make([]byte, 32)...)
	hello = append(hello, 0)

	cipherLen := len(ciphers) * 2
	hello = append(hello, byte(cipherLen>>8), byte(cipherLen))
	for _, c := range ciphers {
		hello = append(hello, byte(c>>8), byte(c))
	}

	hello = append(hello, 1, 0)

	var extData []byte
	for _, ext := range extensions {
		switch ext {
		case 0x0000:
			sniData := buildSNIExtension(sni)
			extData = append(extData, 0, 0)
			extData = append(extData, byte(len(sniData)>>8), byte(len(sniData)))
			extData = append(extData, sniData...)
		case 0x0010:
			alpnData := buildALPNExtension(alpn)
			extData = append(extData, 0, 0x10)
			extData = append(extData, byte(len(alpnData)>>8), byte(len(alpnData)))
			extData = append(extData, alpnData...)
		default:
			extData = append(extData, byte(ext>>8), byte(ext))
			extData = append(extData, 0, 0)
		}
	}

	extLen := len(extData)
	hello = append(hello, byte(extLen>>8), byte(extLen))
	hello = append(hello, extData...)

	handshake := make([]byte, 4)
	handshake[0] = 0x01
	helloLen := len(hello)
	handshake[1] = byte(helloLen >> 16)
	handshake[2] = byte(helloLen >> 8)
	handshake[3] = byte(helloLen)
	handshake = append(handshake, hello...)

	record := make([]byte, 5)
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x01
	recordLen := len(handshake)
	record[3] = byte(recordLen >> 8)
	record[4] = byte(recordLen)
	record = append(record, handshake...)

	return record
}

func buildSNIExtension(sni string) []byte {
	nameBytes := []byte(sni)
	listLen := 3 + len(nameBytes)

	data := make([]byte, 2+listLen)
	data[0] = byte(listLen >> 8)
	data[1] = byte(listLen)
	data[2] = 0
	data[3] = byte(len(nameBytes) >> 8)
	data[4] = byte(len(nameBytes))
	copy(data[5:], nameBytes)
	return data
}

func buildALPNExtension(alpn string) []byte {
	alpnBytes := []byte(alpn)
	listLen := 1 + len(alpnBytes)

	data := make([]byte, 2+listLen)
	data[0] = byte(listLen >> 8)
	data[1] = byte(listLen)
	data[2] = byte(len(alpnBytes))
	copy(data[3:], alpnBytes)
	return data
}

