//go:build darwin

package capture

import (
	"testing"
)

func TestParseDNSQuery(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{"simple", "example.com"},
		{"subdomain", "api.example.com"},
		{"deep_subdomain", "a.b.c.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := makeDNSQueryPacket(tt.domain)
			got := ParseDNSQuery(pkt)
			if got != tt.domain {
				t.Errorf("ParseDNSQuery() = %q, want %q", got, tt.domain)
			}
		})
	}
}

func TestParseDNSResponse(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		ips    []string
	}{
		{"single_ip", "example.com", []string{"93.184.216.34"}},
		{"multiple_ips", "api.example.com", []string{"1.2.3.4", "5.6.7.8"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := makeDNSResponsePacket(tt.domain, tt.ips)
			domain, ips := ParseDNSResponseIPs(pkt)
			if domain != tt.domain {
				t.Errorf("domain = %q, want %q", domain, tt.domain)
			}
			if len(ips) != len(tt.ips) {
				t.Errorf("got %d IPs, want %d", len(ips), len(tt.ips))
			}
			for i, ip := range ips {
				if ip != tt.ips[i] {
					t.Errorf("ip[%d] = %q, want %q", i, ip, tt.ips[i])
				}
			}
		})
	}
}

func TestDNSNameCompression(t *testing.T) {
	pkt := []byte{
		0x00, 0x00,
		0x80, 0x00,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01,
		0x00, 0x01,
		0xc0, 0x0c,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04,
		0x01, 0x02, 0x03, 0x04,
	}

	domain, ips := ParseDNSResponseIPs(pkt)
	if domain != "example.com" {
		t.Errorf("domain = %q, want %q", domain, "example.com")
	}
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Errorf("ips = %v, want [1.2.3.4]", ips)
	}
}

func TestMalformedDNSReturnsEmpty(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too_short", []byte{0x00, 0x00, 0x00}},
		{"truncated_header", make([]byte, 10)},
		{"zero_questions", func() []byte {
			pkt := make([]byte, 12)
			return pkt
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("ParseDNSQuery panicked: %v", r)
				}
			}()
			got := ParseDNSQuery(tt.data)
			if got != "" {
				t.Errorf("ParseDNSQuery(%v) = %q, want empty", tt.data, got)
			}
		})
	}
}

func TestQueryVsResponseDistinction(t *testing.T) {
	queryPkt := makeDNSQueryPacket("example.com")

	queryPkt[2] = queryPkt[2] &^ 0x80
	if domain := ParseDNSQuery(queryPkt); domain == "" {
		t.Error("ParseDNSQuery should parse query packet")
	}
	if domain, _ := ParseDNSResponseIPs(queryPkt); domain != "" {
		t.Error("ParseDNSResponseIPs should not parse query packet")
	}

	responsePkt := makeDNSResponsePacket("example.com", []string{"1.2.3.4"})
	if domain := ParseDNSQuery(responsePkt); domain != "" {
		t.Error("ParseDNSQuery should not parse response packet")
	}
	if domain, _ := ParseDNSResponseIPs(responsePkt); domain == "" {
		t.Error("ParseDNSResponseIPs should parse response packet")
	}
}
