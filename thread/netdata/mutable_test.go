// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package netdata

import (
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Basic operations
// ---------------------------------------------------------------------------

func TestMutableNetworkDataNew(t *testing.T) {
	t.Parallel()
	data := []byte{0x01, 0x02, 0x03}
	m := NewMutableNetworkData(data)
	if m.Len() != 3 {
		t.Fatalf("Len() = %d, want 3", m.Len())
	}
	got := m.Data()
	if !bytesEqual(got, data) {
		t.Fatalf("Data() = %v, want %v", got, data)
	}
}

func TestMutableNetworkDataClear(t *testing.T) {
	t.Parallel()
	m := NewMutableNetworkData([]byte{0x01, 0x02})
	m.Clear()
	if m.Len() != 0 {
		t.Fatalf("Len() = %d after Clear(), want 0", m.Len())
	}
}

func TestMutableNetworkDataCanInsert(t *testing.T) {
	t.Parallel()
	m := NewMutableNetworkData(nil)
	if !m.CanInsert(MaxSize) {
		t.Fatal("should be able to insert MaxSize into empty buffer")
	}
	if m.CanInsert(MaxSize + 1) {
		t.Fatal("should not be able to insert MaxSize+1 into empty buffer")
	}
	m = NewMutableNetworkData(make([]byte, MaxSize))
	if m.CanInsert(1) {
		t.Fatal("should not be able to insert into full buffer")
	}
}

// ---------------------------------------------------------------------------
// Insert / Remove / Append
// ---------------------------------------------------------------------------

func TestMutableNetworkDataInsert(t *testing.T) {
	t.Parallel()
	m := NewMutableNetworkData([]byte{0xAA, 0xBB, 0xCC})

	// Insert 2 bytes at offset 1.
	if err := m.Insert(1, 2); err != nil {
		t.Fatalf("Insert(1,2) error: %v", err)
	}
	if m.Len() != 5 {
		t.Fatalf("Len() = %d, want 5", m.Len())
	}
	want := []byte{0xAA, 0x00, 0x00, 0xBB, 0xCC}
	if !bytesEqual(m.Data(), want) {
		t.Fatalf("Data() = %v, want %v", m.Data(), want)
	}
}

func TestMutableNetworkDataInsertAtEnd(t *testing.T) {
	t.Parallel()
	m := NewMutableNetworkData([]byte{0xAA})
	if err := m.Insert(1, 2); err != nil {
		t.Fatalf("Insert at end error: %v", err)
	}
	want := []byte{0xAA, 0x00, 0x00}
	if !bytesEqual(m.Data(), want) {
		t.Fatalf("Data() = %v, want %v", m.Data(), want)
	}
}

func TestMutableNetworkDataInsertOverflow(t *testing.T) {
	t.Parallel()
	m := NewMutableNetworkData(make([]byte, MaxSize))
	err := m.Insert(0, 1)
	if err != goterrors.ErrNoBufs {
		t.Fatalf("Insert into full buffer: got %v, want ErrNoBufs", err)
	}
}

func TestMutableNetworkDataInsertBadOffset(t *testing.T) {
	t.Parallel()
	m := NewMutableNetworkData([]byte{0x01})
	err := m.Insert(5, 1)
	if err != goterrors.ErrParse {
		t.Fatalf("Insert with bad offset: got %v, want ErrParse", err)
	}
}

func TestMutableNetworkDataRemove(t *testing.T) {
	t.Parallel()
	m := NewMutableNetworkData([]byte{0xAA, 0xBB, 0xCC, 0xDD})

	// Remove 2 bytes at offset 1.
	if err := m.Remove(1, 2); err != nil {
		t.Fatalf("Remove(1,2) error: %v", err)
	}
	if m.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", m.Len())
	}
	want := []byte{0xAA, 0xDD}
	if !bytesEqual(m.Data(), want) {
		t.Fatalf("Data() = %v, want %v", m.Data(), want)
	}
}

func TestMutableNetworkDataRemoveOutOfBounds(t *testing.T) {
	t.Parallel()
	m := NewMutableNetworkData([]byte{0x01, 0x02})
	err := m.Remove(1, 5)
	if err != goterrors.ErrParse {
		t.Fatalf("Remove out of bounds: got %v, want ErrParse", err)
	}
}

func TestMutableNetworkDataAppend(t *testing.T) {
	t.Parallel()
	m := NewMutableNetworkData([]byte{0xAA})
	if err := m.Append([]byte{0xBB, 0xCC}); err != nil {
		t.Fatalf("Append error: %v", err)
	}
	want := []byte{0xAA, 0xBB, 0xCC}
	if !bytesEqual(m.Data(), want) {
		t.Fatalf("Data() = %v, want %v", m.Data(), want)
	}
}

func TestMutableNetworkDataAppendOverflow(t *testing.T) {
	t.Parallel()
	m := NewMutableNetworkData(make([]byte, MaxSize))
	err := m.Append([]byte{0x01})
	if err != goterrors.ErrNoBufs {
		t.Fatalf("Append to full buffer: got %v, want ErrNoBufs", err)
	}
}

// ---------------------------------------------------------------------------
// TLV accessors
// ---------------------------------------------------------------------------

func TestTLVLengthAndSet(t *testing.T) {
	t.Parallel()
	// Build a simple TLV: type=Prefix, stable, length=3, value=0x00 0x00 0x00
	m := NewMutableNetworkData(nil)
	buf := AppendTLVHeader(nil, TLVTypePrefix, true, 3)
	buf = append(buf, 0x00, 0x00, 0x00)
	_ = m.Append(buf)

	l, err := m.TLVLength(0)
	if err != nil {
		t.Fatalf("TLVLength error: %v", err)
	}
	if l != 3 {
		t.Fatalf("TLVLength = %d, want 3", l)
	}

	if err := m.SetTLVLength(0, 2); err != nil {
		t.Fatalf("SetTLVLength error: %v", err)
	}
	l2, _ := m.TLVLength(0)
	if l2 != 2 {
		t.Fatalf("TLVLength after set = %d, want 2", l2)
	}
}

func TestTLVType(t *testing.T) {
	t.Parallel()
	buf := AppendTLVHeader(nil, TLVTypeService, false, 0)
	m := NewMutableNetworkData(buf)

	typ, stable, err := m.TLVType(0)
	if err != nil {
		t.Fatalf("TLVType error: %v", err)
	}
	if typ != TLVTypeService {
		t.Fatalf("TLVType = %d, want %d", typ, TLVTypeService)
	}
	if stable {
		t.Fatal("expected stable=false")
	}
}

func TestTLVSize(t *testing.T) {
	t.Parallel()
	buf := AppendTLV(nil, TLVTypeHasRoute, true, []byte{0x01, 0x02, 0x03})
	m := NewMutableNetworkData(buf)
	size, err := m.TLVSize(0)
	if err != nil {
		t.Fatalf("TLVSize error: %v", err)
	}
	if size != 5 { // 2-byte header + 3-byte value
		t.Fatalf("TLVSize = %d, want 5", size)
	}
}

func TestRemoveTLV(t *testing.T) {
	t.Parallel()
	// Two TLVs: HasRoute(3 bytes value) + Context(2 bytes value).
	var buf []byte
	buf = AppendTLV(buf, TLVTypeHasRoute, true, []byte{0x01, 0x02, 0x03})
	buf = AppendContextTLV(buf, true, ContextInfo{ContextID: 1, Compress: true, ContextLength: 64})
	m := NewMutableNetworkData(buf)

	origLen := m.Len()

	// Remove the first TLV (5 bytes).
	if err := m.RemoveTLV(0); err != nil {
		t.Fatalf("RemoveTLV error: %v", err)
	}
	if m.Len() != origLen-5 {
		t.Fatalf("Len() = %d, want %d", m.Len(), origLen-5)
	}

	// The remaining data should be just the Context TLV.
	typ, stable, err := m.TLVType(0)
	if err != nil {
		t.Fatalf("TLVType after remove error: %v", err)
	}
	if typ != TLVTypeContext || !stable {
		t.Fatalf("remaining TLV: type=%d stable=%v, want Context/true", typ, stable)
	}
}

func TestAppendTLVSpace(t *testing.T) {
	t.Parallel()
	m := NewMutableNetworkData(nil)
	off, err := m.AppendTLVSpace(5)
	if err != nil {
		t.Fatalf("AppendTLVSpace error: %v", err)
	}
	if off != 0 {
		t.Fatalf("offset = %d, want 0", off)
	}
	if m.Len() != 5 {
		t.Fatalf("Len() = %d, want 5", m.Len())
	}
}

// ---------------------------------------------------------------------------
// Find operations
// ---------------------------------------------------------------------------

func TestFindTLV(t *testing.T) {
	t.Parallel()
	var buf []byte
	buf = AppendTLV(buf, TLVTypeHasRoute, true, []byte{0x01})
	buf = AppendTLV(buf, TLVTypePrefix, false, []byte{0x02, 0x03})
	buf = AppendTLV(buf, TLVTypePrefix, true, []byte{0x04})
	m := NewMutableNetworkData(buf)

	tests := []struct {
		name   string
		typ    TLVType
		stable bool
		want   int
	}{
		{"HasRoute stable", TLVTypeHasRoute, true, 0},
		{"Prefix unstable", TLVTypePrefix, false, 3},
		{"Prefix stable", TLVTypePrefix, true, 7},
		{"not found", TLVTypeService, true, -1},
	}
	for _, tc := range tests {
		got := m.FindTLV(tc.typ, tc.stable)
		if got != tc.want {
			t.Errorf("%s: FindTLV = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// buildPrefixTLV is a test helper that builds a complete Prefix TLV with
// sub-TLVs already included.
func buildPrefixTLV(prefix ip6.Prefix, stable bool, subTLVs []byte) []byte {
	info := PrefixTLVInfo{
		DomainID:    0,
		Prefix:      prefix,
		SubTLVsData: subTLVs,
		Stable:      stable,
	}
	value := AppendPrefixValue(nil, info)
	return AppendTLV(nil, TLVTypePrefix, stable, value)
}

func TestFindPrefix(t *testing.T) {
	t.Parallel()
	prefix1 := makePrefix([16]byte{0x20, 0x01, 0x0d, 0xb8}, 32)
	prefix2 := makePrefix([16]byte{0xfd, 0x00}, 16)

	var buf []byte
	buf = append(buf, buildPrefixTLV(prefix1, true, nil)...)
	secondOffset := len(buf)
	buf = append(buf, buildPrefixTLV(prefix2, true, nil)...)

	m := NewMutableNetworkData(buf)

	off := m.FindPrefix(prefix1)
	if off != 0 {
		t.Fatalf("FindPrefix(prefix1) = %d, want 0", off)
	}

	off = m.FindPrefix(prefix2)
	if off != secondOffset {
		t.Fatalf("FindPrefix(prefix2) = %d, want %d", off, secondOffset)
	}

	notFound := makePrefix([16]byte{0xfc, 0x00}, 16)
	off = m.FindPrefix(notFound)
	if off != -1 {
		t.Fatalf("FindPrefix(not-found) = %d, want -1", off)
	}
}

func buildServiceTLV(enterprise uint32, serviceData []byte, stable bool, subTLVs []byte) []byte {
	info := ServiceTLVInfo{
		ServiceID:        0,
		EnterpriseNumber: enterprise,
		ServiceData:      serviceData,
		SubTLVsData:      subTLVs,
		Stable:           stable,
	}
	value := AppendServiceValue(nil, info)
	return AppendTLV(nil, TLVTypeService, stable, value)
}

func TestFindService(t *testing.T) {
	t.Parallel()
	sd1 := []byte{0x01}
	sd2 := []byte{0x02, 0x03}

	var buf []byte
	buf = append(buf, buildServiceTLV(ThreadEnterpriseNumber, sd1, true, nil)...)
	secondOffset := len(buf)
	buf = append(buf, buildServiceTLV(12345, sd2, true, nil)...)

	m := NewMutableNetworkData(buf)

	off := m.FindService(ThreadEnterpriseNumber, sd1)
	if off != 0 {
		t.Fatalf("FindService(Thread, sd1) = %d, want 0", off)
	}

	off = m.FindService(12345, sd2)
	if off != secondOffset {
		t.Fatalf("FindService(12345, sd2) = %d, want %d", off, secondOffset)
	}

	off = m.FindService(ThreadEnterpriseNumber, []byte{0xFF})
	if off != -1 {
		t.Fatalf("FindService(not found) = %d, want -1", off)
	}
}

func TestFindSubTLV(t *testing.T) {
	t.Parallel()
	// Build a Prefix TLV with a HasRoute sub-TLV and a BorderRouter sub-TLV.
	prefix := makePrefix([16]byte{0x20, 0x01, 0x0d, 0xb8}, 32)
	var subTLVs []byte
	subTLVs = AppendHasRouteTLV(subTLVs, true, []HasRouteEntry{
		{RLOC16: 0x1000, Preference: RoutePreferenceMedium},
	})
	subTLVs = AppendBorderRouterTLV(subTLVs, true, []BorderRouterEntry{
		{RLOC16: 0x2000, OnMesh: true},
	})

	buf := buildPrefixTLV(prefix, true, subTLVs)
	m := NewMutableNetworkData(buf)

	hrOff := m.FindSubTLV(0, TLVTypeHasRoute)
	if hrOff == -1 {
		t.Fatal("FindSubTLV(HasRoute) returned -1")
	}
	typ, _, err := m.TLVType(hrOff)
	if err != nil {
		t.Fatalf("TLVType at HasRoute offset error: %v", err)
	}
	if typ != TLVTypeHasRoute {
		t.Fatalf("TLV type at HasRoute offset = %d, want %d", typ, TLVTypeHasRoute)
	}

	brOff := m.FindSubTLV(0, TLVTypeBorderRouter)
	if brOff == -1 {
		t.Fatal("FindSubTLV(BorderRouter) returned -1")
	}
	if brOff <= hrOff {
		t.Fatalf("BorderRouter offset %d should be > HasRoute offset %d", brOff, hrOff)
	}

	ctxOff := m.FindSubTLV(0, TLVTypeContext)
	if ctxOff != -1 {
		t.Fatalf("FindSubTLV(Context) = %d, want -1", ctxOff)
	}
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"empty", nil, false},
		{"valid single TLV", AppendTLV(nil, TLVTypeHasRoute, true, []byte{0x01}), false},
		{
			"valid two TLVs",
			append(
				AppendTLV(nil, TLVTypeHasRoute, true, []byte{0x01}),
				AppendTLV(nil, TLVTypePrefix, false, []byte{0x02})...,
			),
			false,
		},
		{"truncated header", []byte{0x03}, true},
		{"length exceeds data", []byte{0x03, 0x10, 0x01}, true},
		{"trailing byte", append(AppendTLV(nil, TLVTypeHasRoute, true, []byte{0x01}), 0xFF), true},
	}
	for _, tc := range tests {
		m := NewMutableNetworkData(tc.data)
		err := m.Validate()
		if tc.wantErr && err == nil {
			t.Errorf("%s: Validate() = nil, want error", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: Validate() = %v, want nil", tc.name, err)
		}
	}
}

// ---------------------------------------------------------------------------
// CopyFrom
// ---------------------------------------------------------------------------

func TestCopyFrom(t *testing.T) {
	t.Parallel()

	// Build source with one stable and one unstable TLV.
	var buf []byte
	buf = AppendTLV(buf, TLVTypeHasRoute, true, []byte{0x01, 0x02})
	buf = AppendTLV(buf, TLVTypePrefix, false, []byte{0x03})
	buf = AppendTLV(buf, TLVTypeService, true, []byte{0x04})
	src := NewMutableNetworkData(buf)

	t.Run("all", func(t *testing.T) {
		t.Parallel()
		dst := NewMutableNetworkData(nil)
		dst.CopyFrom(src, false)
		if !bytesEqual(dst.Data(), src.Data()) {
			t.Fatalf("CopyFrom(all): data mismatch")
		}
	})

	t.Run("stable only", func(t *testing.T) {
		t.Parallel()
		dst := NewMutableNetworkData(nil)
		dst.CopyFrom(src, true)

		// Should contain only the two stable TLVs.
		tlvs := ParseTLVs(dst.Data())
		if len(tlvs) != 2 {
			t.Fatalf("CopyFrom(stable): got %d TLVs, want 2", len(tlvs))
		}
		for _, tlv := range tlvs {
			if !tlv.Stable {
				t.Errorf("CopyFrom(stable): got unstable TLV type %d", tlv.Type)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// InsertTLVSpace
// ---------------------------------------------------------------------------

func TestInsertTLVSpace(t *testing.T) {
	t.Parallel()
	// Build a Prefix TLV with one HasRoute sub-TLV.
	prefix := makePrefix([16]byte{0x20, 0x01, 0x0d, 0xb8}, 32)
	var subTLVs []byte
	subTLVs = AppendHasRouteTLV(subTLVs, true, []HasRouteEntry{
		{RLOC16: 0x1000, Preference: RoutePreferenceMedium},
	})
	buf := buildPrefixTLV(prefix, true, subTLVs)
	m := NewMutableNetworkData(buf)

	origPLen, _ := m.TLVLength(0)
	origTotal := m.Len()

	// Insert 3 bytes at the end of the parent value (for a new HasRoute entry).
	insertAt := TLVHeaderSize + int(origPLen)
	if err := m.InsertTLVSpace(0, insertAt, HasRouteEntrySize); err != nil {
		t.Fatalf("InsertTLVSpace error: %v", err)
	}

	newPLen, _ := m.TLVLength(0)
	if int(newPLen) != int(origPLen)+HasRouteEntrySize {
		t.Fatalf("parent length: got %d, want %d", newPLen, int(origPLen)+HasRouteEntrySize)
	}
	if m.Len() != origTotal+HasRouteEntrySize {
		t.Fatalf("total length: got %d, want %d", m.Len(), origTotal+HasRouteEntrySize)
	}
}

// ---------------------------------------------------------------------------
// ContainsEntriesFrom
// ---------------------------------------------------------------------------

func TestContainsEntriesFrom(t *testing.T) {
	t.Parallel()
	prefix := makePrefix([16]byte{0x20, 0x01, 0x0d, 0xb8}, 32)
	var subTLVs []byte
	subTLVs = AppendHasRouteTLV(subTLVs, true, []HasRouteEntry{
		{RLOC16: 0x1000, Preference: RoutePreferenceMedium},
		{RLOC16: 0x2000, Preference: RoutePreferenceHigh},
	})
	subTLVs = AppendServerTLV(subTLVs, true, ServerEntry{Server16: 0x3000})

	buf := buildPrefixTLV(prefix, true, subTLVs)
	m := NewMutableNetworkData(buf)

	if !m.ContainsEntriesFrom(0, 0x1000) {
		t.Error("should find RLOC16 0x1000 in HasRoute entries")
	}
	if !m.ContainsEntriesFrom(0, 0x2000) {
		t.Error("should find RLOC16 0x2000 in HasRoute entries")
	}
	if !m.ContainsEntriesFrom(0, 0x3000) {
		t.Error("should find Server16 0x3000 in Server sub-TLV")
	}
	if m.ContainsEntriesFrom(0, 0x9999) {
		t.Error("should not find RLOC16 0x9999")
	}
}

// ---------------------------------------------------------------------------
// RemoveRLOC16Entries
// ---------------------------------------------------------------------------

func TestRemoveRLOC16EntriesExact(t *testing.T) {
	t.Parallel()
	prefix := makePrefix([16]byte{0x20, 0x01, 0x0d, 0xb8}, 32)
	var subTLVs []byte
	subTLVs = AppendHasRouteTLV(subTLVs, true, []HasRouteEntry{
		{RLOC16: 0x1000, Preference: RoutePreferenceMedium},
		{RLOC16: 0x2000, Preference: RoutePreferenceHigh},
	})

	buf := buildPrefixTLV(prefix, true, subTLVs)
	m := NewMutableNetworkData(buf)

	m.RemoveRLOC16Entries(0x1000, MatchModeRLOC16)

	// Prefix TLV should still exist, with one HasRoute entry remaining.
	if m.Len() == 0 {
		t.Fatal("buffer should not be empty")
	}
	if m.ContainsEntriesFrom(0, 0x1000) {
		t.Error("RLOC16 0x1000 should have been removed")
	}
	if !m.ContainsEntriesFrom(0, 0x2000) {
		t.Error("RLOC16 0x2000 should still be present")
	}
}

func TestRemoveRLOC16EntriesRemovesEmptyParent(t *testing.T) {
	t.Parallel()
	prefix := makePrefix([16]byte{0x20, 0x01, 0x0d, 0xb8}, 32)
	var subTLVs []byte
	subTLVs = AppendHasRouteTLV(subTLVs, true, []HasRouteEntry{
		{RLOC16: 0x1000, Preference: RoutePreferenceMedium},
	})

	buf := buildPrefixTLV(prefix, true, subTLVs)
	m := NewMutableNetworkData(buf)

	m.RemoveRLOC16Entries(0x1000, MatchModeRLOC16)

	// The entire Prefix TLV should be removed since it has no sub-TLVs left.
	if m.Len() != 0 {
		t.Fatalf("buffer should be empty after removing only entry, got Len()=%d", m.Len())
	}
}

func TestRemoveRLOC16EntriesRouterIDMode(t *testing.T) {
	t.Parallel()
	prefix := makePrefix([16]byte{0x20, 0x01, 0x0d, 0xb8}, 32)
	// Router ID 4 = RLOC16 0x1000..0x13FF
	var subTLVs []byte
	subTLVs = AppendHasRouteTLV(subTLVs, true, []HasRouteEntry{
		{RLOC16: 0x1000, Preference: RoutePreferenceMedium}, // Router ID 4
		{RLOC16: 0x1001, Preference: RoutePreferenceHigh},   // Router ID 4, child 1
		{RLOC16: 0x2000, Preference: RoutePreferenceLow},    // Router ID 8
	})

	buf := buildPrefixTLV(prefix, true, subTLVs)
	m := NewMutableNetworkData(buf)

	// Remove all entries with Router ID 4.
	m.RemoveRLOC16Entries(0x1000, MatchModeRouterID)

	if m.ContainsEntriesFrom(0, 0x1000) {
		t.Error("RLOC16 0x1000 should have been removed")
	}
	if m.ContainsEntriesFrom(0, 0x1001) {
		t.Error("RLOC16 0x1001 should have been removed")
	}
	if !m.ContainsEntriesFrom(0, 0x2000) {
		t.Error("RLOC16 0x2000 should still be present")
	}
}

func TestRemoveRLOC16EntriesServerSubTLV(t *testing.T) {
	t.Parallel()
	// Build a Service TLV with two Server sub-TLVs.
	var subTLVs []byte
	subTLVs = AppendServerTLV(subTLVs, true, ServerEntry{Server16: 0x1000, ServerData: []byte{0xAA}})
	subTLVs = AppendServerTLV(subTLVs, true, ServerEntry{Server16: 0x2000, ServerData: []byte{0xBB}})

	buf := buildServiceTLV(ThreadEnterpriseNumber, []byte{0x01}, true, subTLVs)
	m := NewMutableNetworkData(buf)

	m.RemoveRLOC16Entries(0x1000, MatchModeRLOC16)

	// Service TLV should still exist with the 0x2000 Server.
	if m.Len() == 0 {
		t.Fatal("buffer should not be empty")
	}
	off := m.FindService(ThreadEnterpriseNumber, []byte{0x01})
	if off == -1 {
		t.Fatal("Service TLV should still exist")
	}
	if m.ContainsEntriesFrom(off, 0x1000) {
		t.Error("Server16 0x1000 should have been removed")
	}
	if !m.ContainsEntriesFrom(off, 0x2000) {
		t.Error("Server16 0x2000 should still be present")
	}
}

// ---------------------------------------------------------------------------
// rloc16Matches
// ---------------------------------------------------------------------------

func TestRloc16Matches(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		candidate uint16
		target    uint16
		mode      MatchMode
		want      bool
	}{
		{"exact match", 0x1000, 0x1000, MatchModeRLOC16, true},
		{"exact mismatch", 0x1000, 0x1001, MatchModeRLOC16, false},
		{"routerID match same router", 0x1000, 0x1001, MatchModeRouterID, true},
		{"routerID match different child", 0x1000, 0x13FF, MatchModeRouterID, true},
		{"routerID mismatch", 0x1000, 0x2000, MatchModeRouterID, false},
	}
	for _, tc := range tests {
		got := rloc16Matches(tc.candidate, tc.target, tc.mode)
		if got != tc.want {
			t.Errorf("%s: rloc16Matches(%04x, %04x, %d) = %v, want %v",
				tc.name, tc.candidate, tc.target, tc.mode, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Vector3 integration test
// ---------------------------------------------------------------------------

func TestMutableNetworkDataVector3(t *testing.T) {
	t.Parallel()
	data := networkDataVector3()
	m := NewMutableNetworkData(data)

	// Validate parses cleanly.
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate on vector3 failed: %v", err)
	}

	// Find two of the three Prefix TLVs in vector3.
	// The prefixes are: fd00:beef:cafe::/64, fd00:2222::/64, fd00:3333::/64
	p1 := makePrefix([16]byte{0xfd, 0x00, 0xbe, 0xef, 0xca, 0xfe, 0x00, 0x00}, 64)
	p2 := makePrefix([16]byte{0xfd, 0x00, 0x22, 0x22, 0x00, 0x00, 0x00, 0x00}, 64)

	off1 := m.FindPrefix(p1)
	if off1 == -1 {
		t.Fatal("FindPrefix(p1) returned -1")
	}
	off2 := m.FindPrefix(p2)
	if off2 == -1 {
		t.Fatal("FindPrefix(p2) returned -1")
	}
	if off2 <= off1 {
		t.Fatalf("prefix2 offset (%d) should be > prefix1 offset (%d)", off2, off1)
	}

	// Check sub-TLV finding within first prefix (has BorderRouter and Context).
	brOff := m.FindSubTLV(off1, TLVTypeBorderRouter)
	if brOff == -1 {
		t.Fatal("FindSubTLV(BorderRouter) in prefix1 returned -1")
	}
	ctxOff := m.FindSubTLV(off1, TLVTypeContext)
	if ctxOff == -1 {
		t.Fatal("FindSubTLV(Context) in prefix1 returned -1")
	}
	if ctxOff <= brOff {
		t.Fatalf("Context offset (%d) should be > BorderRouter offset (%d)", ctxOff, brOff)
	}

	// Third prefix (fd00:3333::/64) has a HasRoute sub-TLV.
	p3 := makePrefix([16]byte{0xfd, 0x00, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00}, 64)
	off3 := m.FindPrefix(p3)
	if off3 == -1 {
		t.Fatal("FindPrefix(p3) returned -1")
	}
	hrOff := m.FindSubTLV(off3, TLVTypeHasRoute)
	if hrOff == -1 {
		t.Fatal("FindSubTLV(HasRoute) in prefix3 returned -1")
	}

	// CopyFrom round-trip.
	dst := NewMutableNetworkData(nil)
	dst.CopyFrom(m, false)
	if !bytesEqual(dst.Data(), m.Data()) {
		t.Fatal("CopyFrom round-trip mismatch")
	}
}

// ---------------------------------------------------------------------------
// FindSubTLVStable
// ---------------------------------------------------------------------------

func TestFindSubTLVStable(t *testing.T) {
	t.Parallel()
	prefix := makePrefix([16]byte{0x20, 0x01, 0x0d, 0xb8}, 32)
	var subTLVs []byte
	subTLVs = AppendHasRouteTLV(subTLVs, false, []HasRouteEntry{
		{RLOC16: 0x1000},
	})
	subTLVs = AppendHasRouteTLV(subTLVs, true, []HasRouteEntry{
		{RLOC16: 0x2000},
	})

	buf := buildPrefixTLV(prefix, true, subTLVs)
	m := NewMutableNetworkData(buf)

	// Find unstable HasRoute.
	off := m.FindSubTLVStable(0, TLVTypeHasRoute, false)
	if off == -1 {
		t.Fatal("FindSubTLVStable(HasRoute, false) returned -1")
	}

	// Find stable HasRoute — should be at a different offset.
	off2 := m.FindSubTLVStable(0, TLVTypeHasRoute, true)
	if off2 == -1 {
		t.Fatal("FindSubTLVStable(HasRoute, true) returned -1")
	}
	if off == off2 {
		t.Fatalf("stable and unstable HasRoute should be at different offsets, both at %d", off)
	}

	// Not found.
	off3 := m.FindSubTLVStable(0, TLVTypeContext, true)
	if off3 != -1 {
		t.Fatalf("FindSubTLVStable(Context, true) = %d, want -1", off3)
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestNewMutableNetworkDataTruncatesLargeInput(t *testing.T) {
	t.Parallel()
	big := make([]byte, MaxSize+100)
	for i := range big {
		big[i] = byte(i & 0xFF)
	}
	m := NewMutableNetworkData(big)
	if m.Len() != MaxSize {
		t.Fatalf("Len() = %d, want %d", m.Len(), MaxSize)
	}
}

func TestTLVAccessorsOnEmpty(t *testing.T) {
	t.Parallel()
	m := NewMutableNetworkData(nil)

	_, err := m.TLVLength(0)
	if err != goterrors.ErrParse {
		t.Fatalf("TLVLength on empty: got %v, want ErrParse", err)
	}

	_, _, err = m.TLVType(0)
	if err != goterrors.ErrParse {
		t.Fatalf("TLVType on empty: got %v, want ErrParse", err)
	}

	err = m.SetTLVLength(0, 5)
	if err != goterrors.ErrParse {
		t.Fatalf("SetTLVLength on empty: got %v, want ErrParse", err)
	}
}

func TestRemoveRLOC16EntriesBorderRouter(t *testing.T) {
	t.Parallel()
	prefix := makePrefix([16]byte{0x20, 0x01, 0x0d, 0xb8}, 32)
	var subTLVs []byte
	subTLVs = AppendBorderRouterTLV(subTLVs, true, []BorderRouterEntry{
		{RLOC16: 0x1000, OnMesh: true},
		{RLOC16: 0x2000, OnMesh: true, DHCP: true},
	})

	buf := buildPrefixTLV(prefix, true, subTLVs)
	m := NewMutableNetworkData(buf)

	m.RemoveRLOC16Entries(0x1000, MatchModeRLOC16)

	if m.ContainsEntriesFrom(0, 0x1000) {
		t.Error("RLOC16 0x1000 should have been removed from BorderRouter entries")
	}
	if !m.ContainsEntriesFrom(0, 0x2000) {
		t.Error("RLOC16 0x2000 should still be present in BorderRouter entries")
	}
}
