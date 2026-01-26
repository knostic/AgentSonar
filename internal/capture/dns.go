//go:build darwin || linux

package capture

import "fmt"

func ParseDNSQuery(data []byte) string {
	if len(data) < 12 {
		return ""
	}

	if data[2]&0x80 != 0 {
		return ""
	}

	qdcount := int(data[4])<<8 | int(data[5])
	if qdcount == 0 {
		return ""
	}

	return parseDNSName(data, 12)
}

func ParseDNSResponseIPs(data []byte) (string, []string) {
	if len(data) < 12 {
		return "", nil
	}

	if data[2]&0x80 == 0 {
		return "", nil
	}

	qdcount := int(data[4])<<8 | int(data[5])
	ancount := int(data[6])<<8 | int(data[7])

	if qdcount == 0 || ancount == 0 {
		return "", nil
	}

	domain := parseDNSName(data, 12)
	if domain == "" {
		return "", nil
	}

	pos := 12
	for i := 0; i < qdcount; i++ {
		for pos < len(data) {
			if data[pos]&0xc0 == 0xc0 {
				pos += 2
				break
			}
			if data[pos] == 0 {
				pos++
				break
			}
			pos += int(data[pos]) + 1
		}
		pos += 4
	}

	var ips []string
	for i := 0; i < ancount && pos < len(data); i++ {
		if pos >= len(data) {
			break
		}
		if data[pos]&0xc0 == 0xc0 {
			pos += 2
		} else {
			for pos < len(data) && data[pos] != 0 {
				pos += int(data[pos]) + 1
			}
			pos++
		}

		if pos+10 > len(data) {
			break
		}

		rtype := int(data[pos])<<8 | int(data[pos+1])
		pos += 2
		pos += 2 // RCLASS
		pos += 4 // TTL
		rdlen := int(data[pos])<<8 | int(data[pos+1])
		pos += 2

		if pos+rdlen > len(data) {
			break
		}

		if rtype == 1 && rdlen == 4 {
			ip := fmt.Sprintf("%d.%d.%d.%d", data[pos], data[pos+1], data[pos+2], data[pos+3])
			ips = append(ips, ip)
		}

		pos += rdlen
	}

	return domain, ips
}

func parseDNSName(data []byte, offset int) string {
	var name []byte
	pos := offset
	maxJumps := 10

	for i := 0; i < maxJumps; i++ {
		if pos >= len(data) {
			break
		}

		length := int(data[pos])

		if length&0xc0 == 0xc0 {
			if pos+1 >= len(data) {
				break
			}
			ptr := int(data[pos]&0x3f)<<8 | int(data[pos+1])
			pos = ptr
			continue
		}

		if length == 0 {
			break
		}

		pos++
		if pos+length > len(data) {
			break
		}

		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, data[pos:pos+length]...)
		pos += length
	}

	return string(name)
}
