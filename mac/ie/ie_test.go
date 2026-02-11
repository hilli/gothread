// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package ie_test

import (
	"bytes"
	"testing"

	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/mac/ie"
)

// --- Header IE encode/decode round-trip ------------------------------------

func TestHeaderIERoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		elementID uint8
		content   []byte
	}{
		{"empty", 0x42, nil},
		{"one_byte", 0x01, []byte{0xAA}},
		{"csl_sized", ie.IECsl, []byte{0x01, 0x02, 0x03, 0x04}},
		{"max_id", 0xFF, []byte{0xBE, 0xEF}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := ie.AppendHeaderIE(nil, tt.elementID, tt.content)
			ies, consumed, err := ie.ParseHeaderIEs(buf)
			if err != nil {
				t.Fatalf("ParseHeaderIEs() error = %v", err)
			}
			if consumed != len(buf) {
				t.Errorf("consumed = %d, want %d", consumed, len(buf))
			}
			if len(ies) != 1 {
				t.Fatalf("got %d IEs, want 1", len(ies))
			}
			got := ies[0]
			if got.ElementID != tt.elementID {
				t.Errorf("ElementID = 0x%02X, want 0x%02X", got.ElementID, tt.elementID)
			}
			wantLen := 0
			if tt.content != nil {
				wantLen = len(tt.content)
			}
			if int(got.Length) != wantLen {
				t.Errorf("Length = %d, want %d", got.Length, wantLen)
			}
			if !bytes.Equal(got.Content, tt.content) {
				t.Errorf("Content = %v, want %v", got.Content, tt.content)
			}
		})
	}
}

// --- Header IE bit layout --------------------------------------------------

func TestHeaderIEBitLayout(t *testing.T) {
	// Build a CSL IE (ID=0x1A, length=4) and verify the raw 2-byte header.
	// Expected: length=4 in bits 0-6, ID=0x1A in bits 7-14, type=0 in bit 15.
	// Bits 0-6:  0000100 (4)
	// Bits 7-14: 00011010 (0x1A)
	// Bit 15:    0
	// As uint16 LE: bits = 0_00011010_0000100 = 0x0D04
	content := []byte{0x01, 0x02, 0x03, 0x04}
	buf := ie.AppendHeaderIE(nil, ie.IECsl, content)

	if len(buf) < 2 {
		t.Fatalf("buffer too short: %d bytes", len(buf))
	}
	hdr := encoding.LittleEndianReadUint16(buf[0:2])

	wantLength := uint16(4)
	gotLength := hdr & 0x007F
	if gotLength != wantLength {
		t.Errorf("header length field = %d, want %d", gotLength, wantLength)
	}

	wantID := uint8(0x1A)
	gotID := uint8((hdr >> 7) & 0xFF)
	if gotID != wantID {
		t.Errorf("header ID field = 0x%02X, want 0x%02X", gotID, wantID)
	}

	wantType := uint16(0) // Header IE type bit = 0
	gotType := (hdr >> 15) & 1
	if gotType != wantType {
		t.Errorf("header type bit = %d, want %d", gotType, wantType)
	}
}

// --- Termination IEs -------------------------------------------------------

func TestTerminationIEs(t *testing.T) {
	t.Run("termination1", func(t *testing.T) {
		buf := ie.AppendTermination1(nil)
		ies, consumed, err := ie.ParseHeaderIEs(buf)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if consumed != 2 {
			t.Errorf("consumed = %d, want 2", consumed)
		}
		if len(ies) != 1 {
			t.Fatalf("got %d IEs, want 1", len(ies))
		}
		if ies[0].ElementID != ie.IEHeaderTermination1 {
			t.Errorf("ElementID = 0x%02X, want 0x%02X", ies[0].ElementID, ie.IEHeaderTermination1)
		}
		if ies[0].Length != 0 {
			t.Errorf("Length = %d, want 0", ies[0].Length)
		}
	})

	t.Run("termination2", func(t *testing.T) {
		buf := ie.AppendTermination2(nil)
		ies, consumed, err := ie.ParseHeaderIEs(buf)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if consumed != 2 {
			t.Errorf("consumed = %d, want 2", consumed)
		}
		if len(ies) != 1 {
			t.Fatalf("got %d IEs, want 1", len(ies))
		}
		if ies[0].ElementID != ie.IEHeaderTermination2 {
			t.Errorf("ElementID = 0x%02X, want 0x%02X", ies[0].ElementID, ie.IEHeaderTermination2)
		}
	})
}

// --- Multiple IEs with termination -----------------------------------------

func TestMultipleIEsWithTermination(t *testing.T) {
	// Build: CSL IE + a custom IE + Termination1.
	var buf []byte
	buf = ie.AppendCslIE(buf, 320, 160)
	buf = ie.AppendHeaderIE(buf, 0x42, []byte{0xDE, 0xAD})
	buf = ie.AppendTermination1(buf)

	// Append extra garbage after termination (should not be consumed).
	buf = append(buf, 0xFF, 0xFF, 0xFF)

	ies, consumed, err := ie.ParseHeaderIEs(buf)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// Should have 3 IEs: CSL, custom, termination.
	if len(ies) != 3 {
		t.Fatalf("got %d IEs, want 3", len(ies))
	}
	// Consumed should be: 2+4 + 2+2 + 2 = 12.
	if consumed != 12 {
		t.Errorf("consumed = %d, want 12", consumed)
	}

	// Verify CSL IE.
	if ies[0].ElementID != ie.IECsl {
		t.Errorf("IE[0] ElementID = 0x%02X, want 0x%02X", ies[0].ElementID, ie.IECsl)
	}
	if ies[0].Length != 4 {
		t.Errorf("IE[0] Length = %d, want 4", ies[0].Length)
	}

	// Verify custom IE.
	if ies[1].ElementID != 0x42 {
		t.Errorf("IE[1] ElementID = 0x%02X, want 0x42", ies[1].ElementID)
	}

	// Verify termination.
	if ies[2].ElementID != ie.IEHeaderTermination1 {
		t.Errorf("IE[2] ElementID = 0x%02X, want 0x%02X", ies[2].ElementID, ie.IEHeaderTermination1)
	}
}

// --- CSL IE ---------------------------------------------------------------

func TestCslIERoundTrip(t *testing.T) {
	original := ie.CslIE{Period: 320, Phase: 160}
	data := original.Marshal()
	if len(data) != ie.CslIEContentSize {
		t.Fatalf("Marshal() len = %d, want %d", len(data), ie.CslIEContentSize)
	}

	parsed, err := ie.ParseCslIE(data)
	if err != nil {
		t.Fatalf("ParseCslIE() error = %v", err)
	}
	if parsed.Period != original.Period {
		t.Errorf("Period = %d, want %d", parsed.Period, original.Period)
	}
	if parsed.Phase != original.Phase {
		t.Errorf("Phase = %d, want %d", parsed.Phase, original.Phase)
	}
}

func TestCslIEWireFormat(t *testing.T) {
	// Verify exact wire bytes for known values.
	csl := ie.CslIE{Period: 0x0140, Phase: 0x00A0} // 320, 160
	data := csl.Marshal()

	// Phase first (LE): 0xA0, 0x00
	// Period second (LE): 0x40, 0x01
	want := []byte{0xA0, 0x00, 0x40, 0x01}
	if !bytes.Equal(data, want) {
		t.Errorf("Marshal() = %v, want %v", data, want)
	}
}

func TestCslIEParseTooShort(t *testing.T) {
	_, err := ie.ParseCslIE([]byte{0x01, 0x02})
	if err == nil {
		t.Error("expected error for short data")
	}
}

// --- AppendCslIE integration -----------------------------------------------

func TestAppendCslIE(t *testing.T) {
	buf := ie.AppendCslIE(nil, 320, 160)
	ies, _, err := ie.ParseHeaderIEs(buf)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(ies) != 1 {
		t.Fatalf("got %d IEs, want 1", len(ies))
	}
	if ies[0].ElementID != ie.IECsl {
		t.Errorf("ElementID = 0x%02X, want 0x%02X", ies[0].ElementID, ie.IECsl)
	}

	csl, err := ie.ParseCslIE(ies[0].Content)
	if err != nil {
		t.Fatalf("ParseCslIE() error = %v", err)
	}
	if csl.Period != 320 || csl.Phase != 160 {
		t.Errorf("CSL = {Period:%d, Phase:%d}, want {320, 160}", csl.Period, csl.Phase)
	}
}

// --- Time Sync IE ----------------------------------------------------------

func TestTimeSyncIERoundTrip(t *testing.T) {
	original := ie.TimeSyncIE{Sequence: 42, Time: -123456789}
	data := original.Marshal()
	if len(data) != ie.TimeSyncIEContentSize {
		t.Fatalf("Marshal() len = %d, want %d", len(data), ie.TimeSyncIEContentSize)
	}

	parsed, err := ie.ParseTimeSyncIE(data)
	if err != nil {
		t.Fatalf("ParseTimeSyncIE() error = %v", err)
	}
	if parsed.Sequence != original.Sequence {
		t.Errorf("Sequence = %d, want %d", parsed.Sequence, original.Sequence)
	}
	if parsed.Time != original.Time {
		t.Errorf("Time = %d, want %d", parsed.Time, original.Time)
	}
}

func TestTimeSyncIEParseTooShort(t *testing.T) {
	_, err := ie.ParseTimeSyncIE([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Error("expected error for short data")
	}
}

// --- FindHeaderIE ----------------------------------------------------------

func TestFindHeaderIE(t *testing.T) {
	var buf []byte
	buf = ie.AppendCslIE(buf, 100, 50)
	buf = ie.AppendHeaderIE(buf, 0x42, []byte{0xBE, 0xEF})
	buf = ie.AppendTermination1(buf)

	ies, _, err := ie.ParseHeaderIEs(buf)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	t.Run("found", func(t *testing.T) {
		got, ok := ie.FindHeaderIE(ies, ie.IECsl)
		if !ok {
			t.Fatal("expected to find CSL IE")
		}
		if got.ElementID != ie.IECsl {
			t.Errorf("ElementID = 0x%02X, want 0x%02X", got.ElementID, ie.IECsl)
		}
	})

	t.Run("found_custom", func(t *testing.T) {
		got, ok := ie.FindHeaderIE(ies, 0x42)
		if !ok {
			t.Fatal("expected to find custom IE 0x42")
		}
		if !bytes.Equal(got.Content, []byte{0xBE, 0xEF}) {
			t.Errorf("Content = %v, want [0xBE, 0xEF]", got.Content)
		}
	})

	t.Run("not_found", func(t *testing.T) {
		_, ok := ie.FindHeaderIE(ies, 0x99)
		if ok {
			t.Error("expected not to find IE 0x99")
		}
	})
}

// --- Empty and edge cases --------------------------------------------------

func TestParseEmptyData(t *testing.T) {
	ies, consumed, err := ie.ParseHeaderIEs(nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(ies) != 0 {
		t.Errorf("got %d IEs, want 0", len(ies))
	}
	if consumed != 0 {
		t.Errorf("consumed = %d, want 0", consumed)
	}
}

func TestParseSingleByte(t *testing.T) {
	// Only 1 byte — not enough for an IE header.
	ies, consumed, err := ie.ParseHeaderIEs([]byte{0xFF})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(ies) != 0 {
		t.Errorf("got %d IEs, want 0", len(ies))
	}
	if consumed != 0 {
		t.Errorf("consumed = %d, want 0", consumed)
	}
}

func TestParseTruncatedContent(t *testing.T) {
	// Build a valid CSL IE header but truncate the content.
	buf := ie.AppendCslIE(nil, 100, 50)
	// IE header (2) + content (4) = 6 bytes. Truncate to 4.
	_, _, err := ie.ParseHeaderIEs(buf[:4])
	if err == nil {
		t.Error("expected error for truncated content")
	}
}

func TestFindHeaderIEEmptyList(t *testing.T) {
	_, ok := ie.FindHeaderIE(nil, ie.IECsl)
	if ok {
		t.Error("expected not found on nil list")
	}
}

// --- Constants -------------------------------------------------------------

func TestConstants(t *testing.T) {
	if ie.IEVendorSpecific != 0x00 {
		t.Errorf("IEVendorSpecific = 0x%02X, want 0x00", ie.IEVendorSpecific)
	}
	if ie.IECsl != 0x1A {
		t.Errorf("IECsl = 0x%02X, want 0x1A", ie.IECsl)
	}
	if ie.IEHeaderTermination1 != 0x7E {
		t.Errorf("IEHeaderTermination1 = 0x%02X, want 0x7E", ie.IEHeaderTermination1)
	}
	if ie.IEHeaderTermination2 != 0x7F {
		t.Errorf("IEHeaderTermination2 = 0x%02X, want 0x7F", ie.IEHeaderTermination2)
	}
	if ie.ThreadVendorOUI != 0xEAB89B {
		t.Errorf("ThreadVendorOUI = 0x%06X, want 0xEAB89B", ie.ThreadVendorOUI)
	}
}
