//go:build darwin

package sai

import (
	"strings"
	"testing"
)

func TestParseClientHello(t *testing.T) {
	ciphers := []uint16{0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b}
	extensions := []uint16{0x0000, 0x000b, 0x000a, 0x0023}
	pkt := makeClientHelloPacket("example.com", ciphers, extensions)

	ch := ParseClientHello(pkt)
	if ch == nil {
		t.Fatal("ParseClientHello returned nil")
	}

	if ch.SNI != "example.com" {
		t.Errorf("SNI = %q, want %q", ch.SNI, "example.com")
	}

	if len(ch.CipherSuites) != len(ciphers) {
		t.Errorf("got %d cipher suites, want %d", len(ch.CipherSuites), len(ciphers))
	}

	if len(ch.Extensions) != len(extensions) {
		t.Errorf("got %d extensions, want %d", len(ch.Extensions), len(extensions))
	}
}

func TestJA4Format(t *testing.T) {
	ciphers := []uint16{0x1301, 0x1302, 0x1303}
	extensions := []uint16{0x0000, 0x0010, 0x000b, 0x000a}
	pkt := makeClientHelloWithALPN("example.com", ciphers, extensions, "h2")

	ch := ParseClientHello(pkt)
	if ch == nil {
		t.Fatal("ParseClientHello returned nil")
	}

	ja4 := ch.JA4()

	parts := strings.Split(ja4, "_")
	if len(parts) != 3 {
		t.Errorf("JA4 should have 3 parts separated by _, got %d: %s", len(parts), ja4)
	}

	if !strings.HasPrefix(parts[0], "t") {
		t.Errorf("JA4 section A should start with 't', got %s", parts[0])
	}

	if len(parts[1]) != 12 {
		t.Errorf("JA4 section B should be 12 chars, got %d: %s", len(parts[1]), parts[1])
	}

	if len(parts[2]) != 12 {
		t.Errorf("JA4 section C should be 12 chars, got %d: %s", len(parts[2]), parts[2])
	}
}

func TestGREASEFiltering(t *testing.T) {
	greaseValues := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a}
	normalCiphers := []uint16{0x1301, 0x1302}
	allCiphers := append(greaseValues, normalCiphers...)

	count := countNonGREASE(allCiphers)
	if count != len(normalCiphers) {
		t.Errorf("countNonGREASE = %d, want %d (should exclude GREASE)", count, len(normalCiphers))
	}

	filtered := filterGREASE(allCiphers)
	if len(filtered) != len(normalCiphers) {
		t.Errorf("filterGREASE returned %d values, want %d", len(filtered), len(normalCiphers))
	}

	for _, v := range filtered {
		if isGREASE(v) {
			t.Errorf("filterGREASE did not remove GREASE value %04x", v)
		}
	}
}

func TestIsLikelyProgrammatic(t *testing.T) {
	tests := []struct {
		name       string
		ciphers    []uint16
		extensions []uint16
		wantProg   bool
		wantReason string
	}{
		{
			name:       "no_grease",
			ciphers:    []uint16{0x1301, 0x1302, 0x1303, 0x1304, 0x1305},
			extensions: []uint16{0x0000, 0x000b, 0x000a, 0x0023, 0x0010, 0x000d, 0x002b, 0x002d},
			wantProg:   true,
			wantReason: "no_grease",
		},
		{
			name:       "few_ciphers",
			ciphers:    []uint16{0x0a0a, 0x1301, 0x1302},
			extensions: []uint16{0x0a0a, 0x0000, 0x000b, 0x000a, 0x0023, 0x0010, 0x000d, 0x002b, 0x002d},
			wantProg:   true,
			wantReason: "few_ciphers",
		},
		{
			name:       "few_extensions",
			ciphers:    []uint16{0x0a0a, 0x1301, 0x1302, 0x1303, 0x1304, 0x1305},
			extensions: []uint16{0x0a0a, 0x0000, 0x000b},
			wantProg:   true,
			wantReason: "few_extensions",
		},
		{
			name:       "normal_browser",
			ciphers:    []uint16{0x0a0a, 0x1301, 0x1302, 0x1303, 0x1304, 0x1305, 0xc02c},
			extensions: []uint16{0x0a0a, 0x0000, 0x000b, 0x000a, 0x0023, 0x0010, 0x000d, 0x002b, 0x002d, 0x0033},
			wantProg:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := &ClientHello{
				CipherSuites: tt.ciphers,
				Extensions:   tt.extensions,
			}
			isProg, reason := ch.IsLikelyProgrammatic()
			if isProg != tt.wantProg {
				t.Errorf("IsLikelyProgrammatic() = %v, want %v", isProg, tt.wantProg)
			}
			if tt.wantProg && tt.wantReason != "" && reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestMalformedClientHelloReturnsNil(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too_short", []byte{0x16, 0x03, 0x01}},
		{"wrong_type", []byte{0x17, 0x03, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"truncated_record", func() []byte {
			pkt := []byte{0x16, 0x03, 0x01, 0x00, 0x10}
			pkt = append(pkt, make([]byte, 5)...)
			return pkt
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("ParseClientHello panicked: %v", r)
				}
			}()
			ch := ParseClientHello(tt.data)
			if ch != nil {
				t.Errorf("ParseClientHello(%v) should return nil", tt.data)
			}
		})
	}
}

func TestSupportedVersionsOverridesRecordVersion(t *testing.T) {
	ciphers := []uint16{0x1301, 0x1302}
	versions := []uint16{0x0304, 0x0303}
	pkt := makeClientHelloWithSupportedVersions("example.com", ciphers, versions)

	ch := ParseClientHello(pkt)
	if ch == nil {
		t.Fatal("ParseClientHello returned nil")
	}

	if ch.Version != 0x0303 {
		t.Errorf("record version = %04x, want 0x0303", ch.Version)
	}

	if len(ch.SupportedVersions) != 2 {
		t.Fatalf("expected 2 supported versions, got %d", len(ch.SupportedVersions))
	}

	ja4 := ch.JA4()
	if !strings.HasPrefix(ja4, "t13") {
		t.Errorf("JA4 should use TLS 1.3 (13) from supported_versions, got %s", ja4[:4])
	}
}

func TestJA4SNIIndicator(t *testing.T) {
	ciphers := []uint16{0x1301, 0x1302}

	withSNI := makeClientHelloPacket("example.com", ciphers, []uint16{0x0000})
	chWithSNI := ParseClientHello(withSNI)
	ja4WithSNI := chWithSNI.JA4()

	noSNI := &ClientHello{
		Version:      0x0303,
		CipherSuites: ciphers,
		Extensions:   []uint16{0x000b},
	}
	ja4NoSNI := noSNI.JA4()

	if ja4WithSNI[3] != 'd' {
		t.Errorf("JA4 with domain SNI should have 'd' indicator, got %c", ja4WithSNI[3])
	}
	if ja4NoSNI[3] != 'i' {
		t.Errorf("JA4 without SNI should have 'i' indicator, got %c", ja4NoSNI[3])
	}
}
