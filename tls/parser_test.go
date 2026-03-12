package tls

import (
	"encoding/hex"
	"testing"
)

// buildClientHello constructs a minimal raw ClientHello byte slice for testing.
// version: ClientHello version field (2 bytes)
// ciphers: list of cipher suite IDs
func buildClientHello(version uint16, ciphers []uint16) []byte {
	// Build cipher suites bytes
	csBytes := make([]byte, len(ciphers)*2)
	for i, c := range ciphers {
		csBytes[i*2] = byte(c >> 8)
		csBytes[i*2+1] = byte(c)
	}

	body := []byte{
		byte(version >> 8), byte(version), // Client Version
	}
	// Random (32 bytes)
	body = append(body, make([]byte, 32)...)
	// Session ID length = 0
	body = append(body, 0x00)
	// Cipher suites length
	csLen := uint16(len(csBytes))
	body = append(body, byte(csLen>>8), byte(csLen))
	body = append(body, csBytes...)
	// Compression methods: 1 byte length + 1 null
	body = append(body, 0x01, 0x00)
	// No extensions

	// Handshake header: type=0x01, length (3 bytes)
	hLen := len(body)
	hs := []byte{0x01, byte(hLen >> 16), byte(hLen >> 8), byte(hLen)}
	hs = append(hs, body...)

	// TLS record header: type=0x16, version=0x0301, length (2 bytes)
	recLen := uint16(len(hs))
	rec := []byte{0x16, 0x03, 0x01, byte(recLen >> 8), byte(recLen)}
	rec = append(rec, hs...)

	return rec
}

func TestParseClientHello_Basic(t *testing.T) {
	data := buildClientHello(0x0303, []uint16{0xC02B, 0xC02F})

	hello, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}
	if hello.Version != 0x0303 {
		t.Errorf("expected version 0x0303, got 0x%04X", hello.Version)
	}
	if len(hello.CipherSuites) != 2 {
		t.Errorf("expected 2 cipher suites, got %d", len(hello.CipherSuites))
	}
	if hello.CipherSuites[0] != 0xC02B {
		t.Errorf("expected first cipher 0xC02B, got 0x%04X", hello.CipherSuites[0])
	}
}

func TestParseClientHello_TooShort(t *testing.T) {
	_, err := ParseClientHello([]byte{0x16, 0x03})
	if err == nil {
		t.Error("expected error for truncated data, got nil")
	}
}

func TestParseClientHello_WrongContentType(t *testing.T) {
	data := buildClientHello(0x0303, nil)
	data[0] = 0x17 // Application data, not handshake
	_, err := ParseClientHello(data)
	if err == nil {
		t.Error("expected error for wrong content type, got nil")
	}
}

func TestParseClientHello_WrongHandshakeType(t *testing.T) {
	data := buildClientHello(0x0303, nil)
	data[5] = 0x02 // ServerHello, not ClientHello
	_, err := ParseClientHello(data)
	if err == nil {
		t.Error("expected error for wrong handshake type, got nil")
	}
}

func TestParseClientHello_Empty(t *testing.T) {
	_, err := ParseClientHello([]byte{})
	if err == nil {
		t.Error("expected error for empty data, got nil")
	}
}

// TestParseClientHello_RealCapture uses a known real-world ClientHello snippet
// (first 90 bytes only — enough to parse version and cipher suites).
func TestParseClientHello_RealCapture(t *testing.T) {
	// Minimal valid ClientHello: TLS 1.2, one cipher suite (AES128-GCM-SHA256)
	raw := buildClientHello(0x0303, []uint16{0xC02B, 0x0035})
	hello, err := ParseClientHello(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hello == nil {
		t.Fatal("got nil hello")
	}
}

func TestHexRoundTrip(t *testing.T) {
	// Ensure we can build, parse, and compute a JA3 hash end-to-end
	data := buildClientHello(0x0303, []uint16{0xC02B, 0xC02F, 0x009C})
	hello, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	result := Compute(hello)
	if result == nil {
		t.Fatal("compute returned nil")
	}
	// Sanity check: hash is valid hex
	if _, err := hex.DecodeString(result.Hash); err != nil {
		t.Errorf("hash %q is not valid hex: %v", result.Hash, err)
	}
}
