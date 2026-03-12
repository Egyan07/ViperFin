package tls

import (
	"strings"
	"testing"
)

func TestComputeKnownHash(t *testing.T) {
	// Construct a minimal ClientHello with known values and verify the hash.
	hello := &ClientHello{
		Version:          0x0303, // TLS 1.2
		CipherSuites:     []uint16{0xC02B, 0xC02F, 0x009C},
		Extensions:       []uint16{0, 10, 11, 13, 23},
		EllipticCurves:   []uint16{23, 24, 25},
		EllipticCurvesPF: []uint8{0},
	}

	result := Compute(hello)
	if result == nil {
		t.Fatal("Compute returned nil")
	}
	if result.Hash == "" {
		t.Error("expected non-empty hash")
	}
	if len(result.Hash) != 32 {
		t.Errorf("expected 32-char MD5 hex, got %d chars: %s", len(result.Hash), result.Hash)
	}
	// Verify raw string format: version,ciphers,extensions,curves,pointfmts
	parts := strings.Split(result.RawString, ",")
	if len(parts) != 5 {
		t.Errorf("expected 5 comma-separated fields, got %d: %s", len(parts), result.RawString)
	}
}

func TestComputeFiltersGREASE(t *testing.T) {
	hello := &ClientHello{
		Version:          0x0303,
		CipherSuites:     []uint16{0x0a0a, 0xC02B}, // 0x0a0a is GREASE
		Extensions:       []uint16{0x2a2a, 0},       // 0x2a2a is GREASE
		EllipticCurves:   []uint16{0xdada, 23},       // 0xdada is GREASE
		EllipticCurvesPF: []uint8{0},
	}

	result := Compute(hello)
	// GREASE values must not appear in the raw string
	if strings.Contains(result.RawString, "2730") { // 0x0a0a = 2730
		t.Errorf("GREASE value 0x0a0a found in raw string: %s", result.RawString)
	}
	if len(result.Ciphers) != 1 || result.Ciphers[0] != 0xC02B {
		t.Errorf("expected 1 cipher after GREASE filter, got %v", result.Ciphers)
	}
	if len(result.Extensions) != 1 || result.Extensions[0] != 0 {
		t.Errorf("expected 1 extension after GREASE filter, got %v", result.Extensions)
	}
	if len(result.Curves) != 1 || result.Curves[0] != 23 {
		t.Errorf("expected 1 curve after GREASE filter, got %v", result.Curves)
	}
}

func TestComputeJA3S(t *testing.T) {
	hello := &ServerHello{
		Version:     0x0303,
		CipherSuite: 0xC02B,
		Extensions:  []uint16{0, 23},
	}

	result := ComputeJA3S(hello)
	if result == nil {
		t.Fatal("ComputeJA3S returned nil")
	}
	if len(result.Hash) != 32 {
		t.Errorf("expected 32-char MD5 hex, got %d: %s", len(result.Hash), result.Hash)
	}
	// JA3S raw format: version,cipher,extensions
	parts := strings.Split(result.RawString, ",")
	if len(parts) != 3 {
		t.Errorf("expected 3 fields in JA3S raw string, got %d: %s", len(parts), result.RawString)
	}
}

func TestComputeDeterministic(t *testing.T) {
	hello := &ClientHello{
		Version:          0x0303,
		CipherSuites:     []uint16{0xC02B, 0xC02F},
		Extensions:       []uint16{0, 10},
		EllipticCurves:   []uint16{23},
		EllipticCurvesPF: []uint8{0},
	}
	r1 := Compute(hello)
	r2 := Compute(hello)
	if r1.Hash != r2.Hash {
		t.Errorf("Compute is not deterministic: %s != %s", r1.Hash, r2.Hash)
	}
}

func TestTLSVersionName(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{0x0301, "TLS 1.0"},
		{0x0302, "TLS 1.1"},
		{0x0303, "TLS 1.2"},
		{0x0304, "TLS 1.3"},
		{0x9999, "Unknown(0x9999)"},
	}
	for _, tc := range tests {
		got := TLSVersionName(tc.version)
		if got != tc.want {
			t.Errorf("TLSVersionName(0x%04X) = %q, want %q", tc.version, got, tc.want)
		}
	}
}
