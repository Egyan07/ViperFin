package db

import (
	"testing"
)

func TestCountNonZero(t *testing.T) {
	n := Count()
	if n == 0 {
		t.Error("expected at least one signature in database, got 0")
	}
}

func TestLookupKnownHash(t *testing.T) {
	// Cobalt Strike default beacon — must be in the database
	sig := Lookup("6bea65232d17d4884c427918d6c3abf0")
	if sig == nil {
		t.Fatal("expected to find Cobalt Strike hash, got nil")
	}
	if sig.ThreatLevel != ThreatMalicious {
		t.Errorf("expected threat_level malicious, got %s", sig.ThreatLevel)
	}
}

func TestLookupCaseInsensitive(t *testing.T) {
	lower := Lookup("6bea65232d17d4884c427918d6c3abf0")
	upper := Lookup("6BEA65232D17D4884C427918D6C3ABF0")
	mixed := Lookup("6Bea65232d17D4884c427918D6c3abf0")
	if lower == nil || upper == nil || mixed == nil {
		t.Error("Lookup must be case-insensitive")
	}
	if lower != upper || lower != mixed {
		t.Error("expected same result regardless of case")
	}
}

func TestLookupUnknown(t *testing.T) {
	sig := Lookup("00000000000000000000000000000000")
	if sig != nil {
		t.Errorf("expected nil for unknown hash, got %+v", sig)
	}
}

func TestAllReturnsAllSignatures(t *testing.T) {
	all := All()
	if len(all) != Count() {
		t.Errorf("All() returned %d entries, Count() says %d", len(all), Count())
	}
	for _, sig := range all {
		if sig == nil {
			t.Error("All() returned a nil signature pointer")
		}
	}
}

func TestThreatColor(t *testing.T) {
	tests := []struct {
		level string
		want  string
	}{
		{ThreatBenign, "\033[32m"},
		{ThreatInfo, "\033[36m"},
		{ThreatSuspicious, "\033[33m"},
		{ThreatMalicious, "\033[31m"},
		{"unknown_level", "\033[37m"},
	}
	for _, tc := range tests {
		got := ThreatColor(tc.level)
		if got != tc.want {
			t.Errorf("ThreatColor(%q) = %q, want %q", tc.level, got, tc.want)
		}
	}
}

func TestThreatIcon(t *testing.T) {
	if ThreatIcon(ThreatBenign) != "✓" {
		t.Error("expected ✓ for benign")
	}
	if ThreatIcon(ThreatMalicious) != "✗" {
		t.Error("expected ✗ for malicious")
	}
	if ThreatIcon("bogus") != "?" {
		t.Error("expected ? for unknown level")
	}
}
