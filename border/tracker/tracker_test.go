// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tracker

import (
	"slices"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildPrefixTlv builds a Prefix TLV with a Border Router sub-TLV.
//
//	Format: [type=1, length, domainID=0, prefixLenBits, prefix..., sub-TLVs...]
func buildPrefixTlv(prefix [16]byte, prefixLen uint8, subTlvs []byte) []byte {
	prefixBytes := int((prefixLen + 7) / 8)
	value := make([]byte, 0, 2+prefixBytes+len(subTlvs))
	value = append(value, 0, prefixLen) // Domain ID, then prefix length in bits.
	value = append(value, prefix[:prefixBytes]...)
	value = append(value, subTlvs...)

	tlv := make([]byte, 0, 2+len(value))
	tlv = append(tlv, tlvTypePrefix, byte(len(value)))
	tlv = append(tlv, value...)
	return tlv
}

// buildBorderRouterSubTlv builds a Border Router sub-TLV entry.
// flags: bit5=O(on-link), bits7-6=preference
func buildBorderRouterSubTlv(rloc16 uint16, onLink bool, pref uint8) []byte {
	var flags uint16
	if onLink {
		flags |= 0x0020 // O flag
	}
	flags |= uint16(pref&0x03) << 6

	entry := []byte{
		byte(rloc16 >> 8), byte(rloc16),
		byte(flags >> 8), byte(flags),
	}

	return []byte{
		tlvTypeBorderRouter, byte(len(entry)),
		entry[0], entry[1], entry[2], entry[3],
	}
}

// buildHasRouteSubTlv builds a Has Route sub-TLV entry.
func buildHasRouteSubTlv(rloc16 uint16, pref uint8) []byte {
	flags := (pref & 0x03) << 6
	entry := []byte{
		byte(rloc16 >> 8), byte(rloc16),
		flags,
	}
	return []byte{
		tlvTypeHasRoute, byte(len(entry)),
		entry[0], entry[1], entry[2],
	}
}

// ---------------------------------------------------------------------------
// Tests: Basic
// ---------------------------------------------------------------------------

func TestNewTracker(t *testing.T) {
	tr := NewTracker()
	if tr.GetBorderRouterCount() != 0 {
		t.Fatalf("new tracker border router count = %d, want 0", tr.GetBorderRouterCount())
	}
	if tr.GetPrefixes() != nil {
		t.Fatal("new tracker should have no prefixes")
	}
}

func TestClear(t *testing.T) {
	tr := NewTracker()

	prefix := [16]byte{0xfd, 0x00, 0x00, 0x01}
	subTlv := buildBorderRouterSubTlv(0x0400, false, prefMedium)
	data := buildPrefixTlv(prefix, 64, subTlv)
	tr.HandleNetworkDataChanged(data)

	if tr.GetBorderRouterCount() == 0 {
		t.Fatal("expected border routers after parse")
	}

	tr.Clear()
	if tr.GetBorderRouterCount() != 0 {
		t.Fatalf("border router count after Clear = %d, want 0", tr.GetBorderRouterCount())
	}
	if tr.GetPrefixes() != nil {
		t.Fatal("prefixes after Clear should be nil")
	}
}

// ---------------------------------------------------------------------------
// Tests: Prefix parsing
// ---------------------------------------------------------------------------

func TestParseSingleOmrPrefix(t *testing.T) {
	tr := NewTracker()

	prefix := [16]byte{0xfd, 0x00, 0x00, 0x01}
	subTlv := buildBorderRouterSubTlv(0x0400, false, prefMedium)
	data := buildPrefixTlv(prefix, 64, subTlv)

	tr.HandleNetworkDataChanged(data)

	if tr.GetBorderRouterCount() != 1 {
		t.Fatalf("border router count = %d, want 1", tr.GetBorderRouterCount())
	}

	if !tr.HasOmrPrefix(prefix, 64) {
		t.Fatal("expected OMR prefix to be found")
	}
	if tr.HasOnLinkPrefix(prefix, 64) {
		t.Fatal("OMR prefix should not be an on-link prefix")
	}
}

func TestParseSingleOnLinkPrefix(t *testing.T) {
	tr := NewTracker()

	prefix := [16]byte{0x20, 0x01, 0x0d, 0xb8}
	subTlv := buildBorderRouterSubTlv(0x0800, true, prefMedium)
	data := buildPrefixTlv(prefix, 64, subTlv)

	tr.HandleNetworkDataChanged(data)

	if !tr.HasOnLinkPrefix(prefix, 64) {
		t.Fatal("expected on-link prefix to be found")
	}
	if tr.HasOmrPrefix(prefix, 64) {
		t.Fatal("on-link prefix should not be an OMR prefix")
	}
}

func TestParseHasRoute(t *testing.T) {
	tr := NewTracker()

	prefix := [16]byte{0xfd, 0xab, 0xcd}
	subTlv := buildHasRouteSubTlv(0x1000, prefHigh)
	data := buildPrefixTlv(prefix, 48, subTlv)

	tr.HandleNetworkDataChanged(data)

	if tr.GetBorderRouterCount() != 1 {
		t.Fatalf("border router count = %d, want 1", tr.GetBorderRouterCount())
	}

	if !tr.HasOmrPrefix(prefix, 48) {
		t.Fatal("expected OMR prefix from Has Route")
	}
}

func TestParseMultiplePrefixes(t *testing.T) {
	tr := NewTracker()

	// Two prefix TLVs concatenated.
	prefix1 := [16]byte{0xfd, 0x01}
	sub1 := buildBorderRouterSubTlv(0x0400, false, prefMedium)
	tlv1 := buildPrefixTlv(prefix1, 64, sub1)

	prefix2 := [16]byte{0xfd, 0x02}
	sub2 := buildBorderRouterSubTlv(0x0800, false, prefHigh)
	tlv2 := buildPrefixTlv(prefix2, 64, sub2)

	data := slices.Concat(tlv1, tlv2)
	tr.HandleNetworkDataChanged(data)

	if tr.GetBorderRouterCount() != 2 {
		t.Fatalf("border router count = %d, want 2", tr.GetBorderRouterCount())
	}

	if !tr.HasOmrPrefix(prefix1, 64) {
		t.Fatal("expected prefix1")
	}
	if !tr.HasOmrPrefix(prefix2, 64) {
		t.Fatal("expected prefix2")
	}
}

func TestParseDuplicateBorderRouter(t *testing.T) {
	tr := NewTracker()

	// Two prefix TLVs from the same border router (same RLOC16, same router ID).
	prefix1 := [16]byte{0xfd, 0x01}
	sub1 := buildBorderRouterSubTlv(0x0400, false, prefMedium)
	tlv1 := buildPrefixTlv(prefix1, 64, sub1)

	prefix2 := [16]byte{0xfd, 0x02}
	sub2 := buildBorderRouterSubTlv(0x0400, true, prefMedium) // same RLOC
	tlv2 := buildPrefixTlv(prefix2, 64, sub2)

	data := slices.Concat(tlv1, tlv2)
	tr.HandleNetworkDataChanged(data)

	// Should deduplicate border routers by router ID.
	if tr.GetBorderRouterCount() != 1 {
		t.Fatalf("border router count = %d, want 1", tr.GetBorderRouterCount())
	}

	prefixes := tr.GetPrefixes()
	if len(prefixes) != 2 {
		t.Fatalf("prefix count = %d, want 2", len(prefixes))
	}
}

// ---------------------------------------------------------------------------
// Tests: Prefix not found
// ---------------------------------------------------------------------------

func TestHasPrefixNotFound(t *testing.T) {
	tr := NewTracker()

	prefix := [16]byte{0xfd, 0x01}
	subTlv := buildBorderRouterSubTlv(0x0400, false, prefMedium)
	data := buildPrefixTlv(prefix, 64, subTlv)
	tr.HandleNetworkDataChanged(data)

	// Different prefix.
	other := [16]byte{0xfd, 0x99}
	if tr.HasOmrPrefix(other, 64) {
		t.Fatal("should not find a non-existent prefix")
	}

	// Same prefix, different length.
	if tr.HasOmrPrefix(prefix, 48) {
		t.Fatal("should not find prefix with different length")
	}
}

// ---------------------------------------------------------------------------
// Tests: GetFavoredOmrPrefix
// ---------------------------------------------------------------------------

func TestGetFavoredOmrPrefixEmpty(t *testing.T) {
	tr := NewTracker()
	_, _, _, found := tr.GetFavoredOmrPrefix()
	if found {
		t.Fatal("should not find favored OMR prefix when empty")
	}
}

func TestGetFavoredOmrPrefixSingle(t *testing.T) {
	tr := NewTracker()

	prefix := [16]byte{0xfd, 0xab}
	subTlv := buildBorderRouterSubTlv(0x0400, false, prefHigh)
	data := buildPrefixTlv(prefix, 64, subTlv)
	tr.HandleNetworkDataChanged(data)

	p, l, pref, found := tr.GetFavoredOmrPrefix()
	if !found {
		t.Fatal("should find favored OMR prefix")
	}
	if !matchPrefix(p, prefix, 64) {
		t.Fatal("prefix mismatch")
	}
	if l != 64 {
		t.Fatalf("length = %d, want 64", l)
	}
	if pref != prefHigh {
		t.Fatalf("preference = %d, want %d", pref, prefHigh)
	}
}

func TestGetFavoredOmrPrefixByPreference(t *testing.T) {
	tr := NewTracker()

	prefix1 := [16]byte{0xfd, 0x01}
	sub1 := buildBorderRouterSubTlv(0x0400, false, prefLow)
	tlv1 := buildPrefixTlv(prefix1, 64, sub1)

	prefix2 := [16]byte{0xfd, 0x02}
	sub2 := buildBorderRouterSubTlv(0x0800, false, prefHigh)
	tlv2 := buildPrefixTlv(prefix2, 64, sub2)

	data := slices.Concat(tlv1, tlv2)
	tr.HandleNetworkDataChanged(data)

	p, _, pref, found := tr.GetFavoredOmrPrefix()
	if !found {
		t.Fatal("should find favored OMR prefix")
	}
	if pref != prefHigh {
		t.Fatalf("preference = %d, want %d (high)", pref, prefHigh)
	}
	if !matchPrefix(p, prefix2, 64) {
		t.Fatal("expected prefix2 (high pref) to be favored")
	}
}

func TestGetFavoredOmrPrefixTiebreak(t *testing.T) {
	tr := NewTracker()

	prefix1 := [16]byte{0xfd, 0x02}
	sub1 := buildBorderRouterSubTlv(0x0400, false, prefMedium)
	tlv1 := buildPrefixTlv(prefix1, 64, sub1)

	prefix2 := [16]byte{0xfd, 0x01}
	sub2 := buildBorderRouterSubTlv(0x0800, false, prefMedium)
	tlv2 := buildPrefixTlv(prefix2, 64, sub2)

	data := slices.Concat(tlv1, tlv2)
	tr.HandleNetworkDataChanged(data)

	p, _, _, found := tr.GetFavoredOmrPrefix()
	if !found {
		t.Fatal("should find favored OMR prefix")
	}
	// Lexicographically smaller prefix wins: fd01 < fd02.
	if !matchPrefix(p, prefix2, 64) {
		t.Fatal("expected prefix2 (fd01, smaller) to be favored")
	}
}

func TestGetFavoredOmrPrefixSkipsOnLink(t *testing.T) {
	tr := NewTracker()

	// On-link prefix should not be considered as OMR.
	prefix := [16]byte{0x20, 0x01, 0x0d, 0xb8}
	subTlv := buildBorderRouterSubTlv(0x0400, true, prefHigh)
	data := buildPrefixTlv(prefix, 64, subTlv)
	tr.HandleNetworkDataChanged(data)

	_, _, _, found := tr.GetFavoredOmrPrefix()
	if found {
		t.Fatal("should not find OMR prefix when only on-link exists")
	}
}

// ---------------------------------------------------------------------------
// Tests: HandleNetworkDataChanged replaces old data
// ---------------------------------------------------------------------------

func TestHandleNetworkDataChangedReplacesOld(t *testing.T) {
	tr := NewTracker()

	prefix1 := [16]byte{0xfd, 0x01}
	sub1 := buildBorderRouterSubTlv(0x0400, false, prefMedium)
	data1 := buildPrefixTlv(prefix1, 64, sub1)
	tr.HandleNetworkDataChanged(data1)

	if !tr.HasOmrPrefix(prefix1, 64) {
		t.Fatal("expected prefix1")
	}

	// New data replaces the old.
	prefix2 := [16]byte{0xfd, 0x02}
	sub2 := buildBorderRouterSubTlv(0x0800, false, prefHigh)
	data2 := buildPrefixTlv(prefix2, 64, sub2)
	tr.HandleNetworkDataChanged(data2)

	if tr.HasOmrPrefix(prefix1, 64) {
		t.Fatal("prefix1 should be gone after new data")
	}
	if !tr.HasOmrPrefix(prefix2, 64) {
		t.Fatal("expected prefix2")
	}
}

// ---------------------------------------------------------------------------
// Tests: Empty / malformed data
// ---------------------------------------------------------------------------

func TestEmptyData(t *testing.T) {
	tr := NewTracker()
	tr.HandleNetworkDataChanged(nil)
	if tr.GetBorderRouterCount() != 0 {
		t.Fatal("empty data should yield no border routers")
	}

	tr.HandleNetworkDataChanged([]byte{})
	if tr.GetBorderRouterCount() != 0 {
		t.Fatal("empty data should yield no border routers")
	}
}

func TestTruncatedTlv(t *testing.T) {
	tr := NewTracker()
	// TLV header says length=10 but only 2 bytes of data.
	tr.HandleNetworkDataChanged([]byte{tlvTypePrefix, 10, 0, 0})
	if tr.GetBorderRouterCount() != 0 {
		t.Fatal("truncated TLV should yield no results")
	}
}

// ---------------------------------------------------------------------------
// Tests: matchPrefix helper
// ---------------------------------------------------------------------------

func TestMatchPrefix(t *testing.T) {
	tests := []struct {
		name string
		a    [16]byte
		b    [16]byte
		bits uint8
		want bool
	}{
		{
			name: "identical /64",
			a:    [16]byte{0xfd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			b:    [16]byte{0xfd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			bits: 64,
			want: true,
		},
		{
			name: "differ in IID but same /64",
			a:    [16]byte{0xfd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xaa},
			b:    [16]byte{0xfd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xbb},
			bits: 64,
			want: true,
		},
		{
			name: "differ within /64",
			a:    [16]byte{0xfd, 0x01},
			b:    [16]byte{0xfd, 0x02},
			bits: 64,
			want: false,
		},
		{
			name: "partial byte match /12",
			a:    [16]byte{0xfd, 0x10},
			b:    [16]byte{0xfd, 0x1f},
			bits: 12,
			want: true,
		},
		{
			name: "partial byte mismatch /12",
			a:    [16]byte{0xfd, 0x10},
			b:    [16]byte{0xfd, 0x20},
			bits: 12,
			want: false,
		},
		{
			name: "zero bits",
			a:    [16]byte{0xfd},
			b:    [16]byte{0x20},
			bits: 0,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchPrefix(tt.a, tt.b, tt.bits); got != tt.want {
				t.Errorf("matchPrefix = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: Border router entries
// ---------------------------------------------------------------------------

func TestGetBorderRouters(t *testing.T) {
	tr := NewTracker()

	prefix := [16]byte{0xfd, 0x01}
	subTlv := buildBorderRouterSubTlv(0x0400, false, prefMedium)
	data := buildPrefixTlv(prefix, 64, subTlv)
	tr.HandleNetworkDataChanged(data)

	brs := tr.GetBorderRouters()
	if len(brs) != 1 {
		t.Fatalf("border routers = %d, want 1", len(brs))
	}
	if brs[0].Rloc16 != 0x0400 {
		t.Fatalf("RLOC16 = %04x, want 0400", brs[0].Rloc16)
	}
	// Router ID = RLOC16 >> 10 = 0x0400 >> 10 = 1
	if brs[0].RouterID != 1 {
		t.Fatalf("RouterID = %d, want 1", brs[0].RouterID)
	}
}
