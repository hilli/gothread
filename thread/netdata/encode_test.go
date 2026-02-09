// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package netdata

import (
	"bytes"
	"testing"
)

// ---------------------------------------------------------------------------
// TLV Header encoding
// ---------------------------------------------------------------------------

func TestEncodeTLVHeaderRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		typ    TLVType
		stable bool
		length uint8
	}{
		{"HasRoute unstable", TLVTypeHasRoute, false, 3},
		{"HasRoute stable", TLVTypeHasRoute, true, 6},
		{"Prefix stable", TLVTypePrefix, true, 0x14},
		{"BorderRouter stable", TLVTypeBorderRouter, true, 0x0c},
		{"Context stable", TLVTypeContext, true, 2},
		{"CommissioningData unstable", TLVTypeCommissioningData, false, 4},
		{"Service stable", TLVTypeService, true, 10},
		{"Server stable", TLVTypeServer, true, 5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf [TLVHeaderSize]byte
			EncodeTLVHeader(buf[:], tc.typ, tc.stable, tc.length)

			gotTyp, gotStable, gotLen, err := ParseTLVHeader(buf[:])
			if err != nil {
				t.Fatalf("ParseTLVHeader: %v", err)
			}
			if gotTyp != tc.typ {
				t.Errorf("type = %d, want %d", gotTyp, tc.typ)
			}
			if gotStable != tc.stable {
				t.Errorf("stable = %v, want %v", gotStable, tc.stable)
			}
			if gotLen != tc.length {
				t.Errorf("length = %d, want %d", gotLen, tc.length)
			}
		})
	}
}

func TestEncodeTLVHeaderKnownBytes(t *testing.T) {
	t.Parallel()
	// Prefix TLV, stable, length 0x14 -> byte0 = (1<<1)|1 = 0x03, byte1 = 0x14.
	var buf [TLVHeaderSize]byte
	EncodeTLVHeader(buf[:], TLVTypePrefix, true, 0x14)
	if buf[0] != 0x03 || buf[1] != 0x14 {
		t.Errorf("bytes = %02x %02x, want 03 14", buf[0], buf[1])
	}

	// HasRoute, not stable, length 3 -> byte0 = (0<<1)|0 = 0x00.
	EncodeTLVHeader(buf[:], TLVTypeHasRoute, false, 3)
	if buf[0] != 0x00 || buf[1] != 0x03 {
		t.Errorf("bytes = %02x %02x, want 00 03", buf[0], buf[1])
	}
}

// ---------------------------------------------------------------------------
// HasRouteEntry encoding
// ---------------------------------------------------------------------------

func TestEncodeHasRouteEntryRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		entry HasRouteEntry
	}{
		{"high pref", HasRouteEntry{RLOC16: 0xC800, Preference: RoutePreferenceHigh}},
		{"medium pref NAT64", HasRouteEntry{RLOC16: 0x1000, Preference: RoutePreferenceMedium, NAT64: true}},
		{"low pref AdvPio", HasRouteEntry{RLOC16: 0x5400, Preference: RoutePreferenceLow, AdvPio: true}},
		{"all flags", HasRouteEntry{RLOC16: 0x0401, Preference: RoutePreferenceHigh, NAT64: true, AdvPio: true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf [HasRouteEntrySize]byte
			EncodeHasRouteEntry(buf[:], tc.entry)

			got, err := ParseHasRouteEntry(buf[:])
			if err != nil {
				t.Fatalf("ParseHasRouteEntry: %v", err)
			}
			if got != tc.entry {
				t.Errorf("got %+v, want %+v", got, tc.entry)
			}
		})
	}
}

func TestEncodeHasRouteEntryKnownBytes(t *testing.T) {
	t.Parallel()
	// RLOC=0xC800, pref=High -> flags = 0x40.
	var buf [HasRouteEntrySize]byte
	EncodeHasRouteEntry(buf[:], HasRouteEntry{RLOC16: 0xC800, Preference: RoutePreferenceHigh})
	want := []byte{0xC8, 0x00, 0x40}
	if !bytes.Equal(buf[:], want) {
		t.Errorf("bytes = %x, want %x", buf[:], want)
	}

	// RLOC=0x1000, pref=Medium, NAT64=true -> flags = 0x20.
	EncodeHasRouteEntry(buf[:], HasRouteEntry{RLOC16: 0x1000, Preference: RoutePreferenceMedium, NAT64: true})
	want2 := []byte{0x10, 0x00, 0x20}
	if !bytes.Equal(buf[:], want2) {
		t.Errorf("bytes = %x, want %x", buf[:], want2)
	}
}

// ---------------------------------------------------------------------------
// BorderRouterEntry encoding
// ---------------------------------------------------------------------------

func TestEncodeBorderRouterEntryRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		entry BorderRouterEntry
	}{
		{
			"medium all on",
			BorderRouterEntry{
				RLOC16: 0x2800, Preference: RoutePreferenceMedium,
				Preferred: true, SLAAC: true, DHCP: true, Configure: true,
				DefaultRoute: true, OnMesh: true, NdDNS: true, Dp: true,
			},
		},
		{
			"high basic",
			BorderRouterEntry{
				RLOC16: 0x4c00, Preference: RoutePreferenceHigh,
				Preferred: true, SLAAC: true, OnMesh: true,
			},
		},
		{
			"low DHCP only",
			BorderRouterEntry{
				RLOC16: 0x1000, Preference: RoutePreferenceLow,
				DHCP: true, OnMesh: true,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf [BorderRouterEntrySize]byte
			EncodeBorderRouterEntry(buf[:], tc.entry)

			got, err := ParseBorderRouterEntry(buf[:])
			if err != nil {
				t.Fatalf("ParseBorderRouterEntry: %v", err)
			}
			if got != tc.entry {
				t.Errorf("got %+v, want %+v", got, tc.entry)
			}
		})
	}
}

func TestEncodeBorderRouterEntryKnownBytes(t *testing.T) {
	t.Parallel()
	// flags=0x3300: Pref=Med(00), Preferred(1), SLAAC(1), DefaultRoute(1), OnMesh(1).
	// 0x3300 = 0011_0011_0000_0000
	entry := BorderRouterEntry{
		RLOC16: 0x2800, Preference: RoutePreferenceMedium,
		Preferred: true, SLAAC: true, DefaultRoute: true, OnMesh: true,
	}
	var buf [BorderRouterEntrySize]byte
	EncodeBorderRouterEntry(buf[:], entry)
	want := []byte{0x28, 0x00, 0x33, 0x00}
	if !bytes.Equal(buf[:], want) {
		t.Errorf("bytes = %x, want %x", buf[:], want)
	}

	// flags=0x7300: Pref=High(01), Preferred(1), SLAAC(1), DefaultRoute(1), OnMesh(1).
	// 01_11_0011_0000_0000 = 0x7300
	entry2 := BorderRouterEntry{
		RLOC16: 0x2800, Preference: RoutePreferenceHigh,
		Preferred: true, SLAAC: true, DefaultRoute: true, OnMesh: true,
	}
	EncodeBorderRouterEntry(buf[:], entry2)
	want2 := []byte{0x28, 0x00, 0x73, 0x00}
	if !bytes.Equal(buf[:], want2) {
		t.Errorf("bytes = %x, want %x", buf[:], want2)
	}
}

// ---------------------------------------------------------------------------
// ContextInfo encoding
// ---------------------------------------------------------------------------

func TestEncodeContextValueRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		info ContextInfo
	}{
		{"basic", ContextInfo{ContextID: 1, Compress: true, ContextLength: 64}},
		{"no compress", ContextInfo{ContextID: 5, Compress: false, ContextLength: 48}},
		{"max ID", ContextInfo{ContextID: 15, Compress: true, ContextLength: 128}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf [ContextValueSize]byte
			EncodeContextValue(buf[:], tc.info)

			got, err := ParseContextValue(buf[:])
			if err != nil {
				t.Fatalf("ParseContextValue: %v", err)
			}
			if got != tc.info {
				t.Errorf("got %+v, want %+v", got, tc.info)
			}
		})
	}
}

func TestEncodeContextValueKnownBytes(t *testing.T) {
	t.Parallel()
	// ContextID=1, Compress=true -> flags=0x11, ContextLength=64 -> 0x40.
	var buf [ContextValueSize]byte
	EncodeContextValue(buf[:], ContextInfo{ContextID: 1, Compress: true, ContextLength: 64})
	if buf[0] != 0x11 || buf[1] != 0x40 {
		t.Errorf("bytes = %02x %02x, want 11 40", buf[0], buf[1])
	}
}

// ---------------------------------------------------------------------------
// ServerEntry encoding
// ---------------------------------------------------------------------------

func TestEncodeServerValueRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		entry ServerEntry
	}{
		{"no data", ServerEntry{Server16: 0x5400}},
		{"with data", ServerEntry{Server16: 0x2800, ServerData: []byte{0xAB, 0xCD}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			buf := AppendServerValue(nil, tc.entry)

			got, err := ParseServerValue(buf)
			if err != nil {
				t.Fatalf("ParseServerValue: %v", err)
			}
			if got.Server16 != tc.entry.Server16 {
				t.Errorf("Server16 = 0x%04x, want 0x%04x", got.Server16, tc.entry.Server16)
			}
			if !bytes.Equal(got.ServerData, tc.entry.ServerData) {
				t.Errorf("ServerData = %x, want %x", got.ServerData, tc.entry.ServerData)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ServiceTLV value encoding
// ---------------------------------------------------------------------------

func TestAppendServiceValueRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		info ServiceTLVInfo
	}{
		{
			"Thread enterprise",
			ServiceTLVInfo{
				ServiceID:        2,
				EnterpriseNumber: ThreadEnterpriseNumber,
				ServiceData:      []byte{0xAB},
			},
		},
		{
			"custom enterprise",
			ServiceTLVInfo{
				ServiceID:        3,
				EnterpriseNumber: 12345,
				ServiceData:      []byte{0x01, 0x02},
			},
		},
		{
			"with sub-TLVs",
			ServiceTLVInfo{
				ServiceID:        1,
				EnterpriseNumber: ThreadEnterpriseNumber,
				ServiceData:      []byte{0xFF},
				SubTLVsData:      []byte{0x0D, 0x02, 0x54, 0x00}, // Server sub-TLV
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			buf := AppendServiceValue(nil, tc.info)

			got, err := ParseServiceValue(buf, tc.info.Stable)
			if err != nil {
				t.Fatalf("ParseServiceValue: %v", err)
			}
			if got.ServiceID != tc.info.ServiceID {
				t.Errorf("ServiceID = %d, want %d", got.ServiceID, tc.info.ServiceID)
			}
			if got.EnterpriseNumber != tc.info.EnterpriseNumber {
				t.Errorf("EnterpriseNumber = %d, want %d", got.EnterpriseNumber, tc.info.EnterpriseNumber)
			}
			if !bytes.Equal(got.ServiceData, tc.info.ServiceData) {
				t.Errorf("ServiceData = %x, want %x", got.ServiceData, tc.info.ServiceData)
			}
			if !bytes.Equal(got.SubTLVsData, tc.info.SubTLVsData) {
				t.Errorf("SubTLVsData = %x, want %x", got.SubTLVsData, tc.info.SubTLVsData)
			}
		})
	}
}

func TestAppendServiceValueKnownBytes(t *testing.T) {
	t.Parallel()
	// Thread enterprise, serviceID=2, serviceData=[0xab] -> {0x82, 0x01, 0xab}.
	info := ServiceTLVInfo{
		ServiceID:        2,
		EnterpriseNumber: ThreadEnterpriseNumber,
		ServiceData:      []byte{0xAB},
	}
	buf := AppendServiceValue(nil, info)
	want := []byte{0x82, 0x01, 0xAB}
	if !bytes.Equal(buf, want) {
		t.Errorf("bytes = %x, want %x", buf, want)
	}
}

// ---------------------------------------------------------------------------
// PrefixTLV value encoding
// ---------------------------------------------------------------------------

func TestAppendPrefixValueRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		info PrefixTLVInfo
	}{
		{
			"64-bit prefix no sub-TLVs",
			PrefixTLVInfo{
				DomainID: 0,
				Prefix:   makePrefix([16]byte{0xFD, 0x00, 0x12, 0x34}, 64),
			},
		},
		{
			"32-bit prefix",
			PrefixTLVInfo{
				DomainID: 0,
				Prefix:   makePrefix([16]byte{0xFD, 0x00, 0xAB, 0xBA}, 32),
			},
		},
		{
			"with sub-TLVs",
			PrefixTLVInfo{
				DomainID:    0,
				Prefix:      makePrefix([16]byte{0xFD, 0x00, 0xBE, 0xEF, 0xCA, 0xFE}, 64),
				SubTLVsData: []byte{0x01, 0x03, 0xEC, 0x00, 0x00}, // HasRoute stable sub-TLV
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			buf := AppendPrefixValue(nil, tc.info)

			got, err := ParsePrefixValue(buf, tc.info.Stable)
			if err != nil {
				t.Fatalf("ParsePrefixValue: %v", err)
			}
			if got.DomainID != tc.info.DomainID {
				t.Errorf("DomainID = %d, want %d", got.DomainID, tc.info.DomainID)
			}
			if got.Prefix.GetLength() != tc.info.Prefix.GetLength() {
				t.Errorf("PrefixLength = %d, want %d", got.Prefix.GetLength(), tc.info.Prefix.GetLength())
			}
			gotBytes := got.Prefix.GetBytes()
			wantBytes := tc.info.Prefix.GetBytes()
			pbs := prefixByteSize(tc.info.Prefix.GetLength())
			for i := 0; i < pbs; i++ {
				if gotBytes[i] != wantBytes[i] {
					t.Errorf("Prefix byte[%d] = 0x%02x, want 0x%02x", i, gotBytes[i], wantBytes[i])
				}
			}
			if !bytes.Equal(got.SubTLVsData, tc.info.SubTLVsData) {
				t.Errorf("SubTLVsData = %x, want %x", got.SubTLVsData, tc.info.SubTLVsData)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Full TLV encoding helpers
// ---------------------------------------------------------------------------

func TestAppendTLVRoundTrip(t *testing.T) {
	t.Parallel()
	value := []byte{0x0B, 0x02, 0x36, 0xCC}
	buf := AppendTLV(nil, TLVTypeCommissioningData, false, value)

	tlvs := ParseTLVs(buf)
	if len(tlvs) != 1 {
		t.Fatalf("ParseTLVs returned %d, want 1", len(tlvs))
	}
	if tlvs[0].Type != TLVTypeCommissioningData {
		t.Errorf("Type = %d, want %d", tlvs[0].Type, TLVTypeCommissioningData)
	}
	if tlvs[0].Stable {
		t.Error("Stable = true, want false")
	}
	if !bytes.Equal(tlvs[0].Value, value) {
		t.Errorf("Value = %x, want %x", tlvs[0].Value, value)
	}
}

func TestAppendHasRouteTLVRoundTrip(t *testing.T) {
	t.Parallel()
	entries := []HasRouteEntry{
		{RLOC16: 0xEC00, Preference: RoutePreferenceMedium},
		{RLOC16: 0x2801, Preference: RoutePreferenceLow},
	}
	buf := AppendHasRouteTLV(nil, true, entries)

	// Parse the header.
	typ, stable, length, err := ParseTLVHeader(buf)
	if err != nil {
		t.Fatalf("ParseTLVHeader: %v", err)
	}
	if typ != TLVTypeHasRoute {
		t.Errorf("type = %d, want %d", typ, TLVTypeHasRoute)
	}
	if !stable {
		t.Error("stable = false, want true")
	}
	if length != uint8(len(entries)*HasRouteEntrySize) {
		t.Errorf("length = %d, want %d", length, len(entries)*HasRouteEntrySize)
	}

	// Parse entries.
	value := buf[TLVHeaderSize:]
	for i, want := range entries {
		got, parseErr := ParseHasRouteEntry(value[i*HasRouteEntrySize:])
		if parseErr != nil {
			t.Fatalf("entry[%d]: %v", i, parseErr)
		}
		if got != want {
			t.Errorf("entry[%d] = %+v, want %+v", i, got, want)
		}
	}
}

func TestAppendBorderRouterTLVRoundTrip(t *testing.T) {
	t.Parallel()
	entries := []BorderRouterEntry{
		{
			RLOC16: 0x2800, Preference: RoutePreferenceMedium,
			Preferred: true, SLAAC: true, DefaultRoute: true, OnMesh: true,
		},
		{
			RLOC16: 0x4C00, Preference: RoutePreferenceMedium,
			Preferred: true, SLAAC: true, OnMesh: true,
		},
	}
	buf := AppendBorderRouterTLV(nil, true, entries)

	typ, stable, length, err := ParseTLVHeader(buf)
	if err != nil {
		t.Fatalf("ParseTLVHeader: %v", err)
	}
	if typ != TLVTypeBorderRouter {
		t.Errorf("type = %d, want %d", typ, TLVTypeBorderRouter)
	}
	if !stable {
		t.Error("stable = false, want true")
	}
	if length != uint8(len(entries)*BorderRouterEntrySize) {
		t.Errorf("length = %d, want %d", length, len(entries)*BorderRouterEntrySize)
	}

	value := buf[TLVHeaderSize:]
	for i, want := range entries {
		got, parseErr := ParseBorderRouterEntry(value[i*BorderRouterEntrySize:])
		if parseErr != nil {
			t.Fatalf("entry[%d]: %v", i, parseErr)
		}
		if got != want {
			t.Errorf("entry[%d] = %+v, want %+v", i, got, want)
		}
	}
}

func TestAppendContextTLVRoundTrip(t *testing.T) {
	t.Parallel()
	c := ContextInfo{ContextID: 2, Compress: true, ContextLength: 64}
	buf := AppendContextTLV(nil, true, c)

	typ, stable, length, err := ParseTLVHeader(buf)
	if err != nil {
		t.Fatalf("ParseTLVHeader: %v", err)
	}
	if typ != TLVTypeContext {
		t.Errorf("type = %d, want %d", typ, TLVTypeContext)
	}
	if !stable {
		t.Error("stable = false, want true")
	}
	if length != ContextValueSize {
		t.Errorf("length = %d, want %d", length, ContextValueSize)
	}

	got, parseErr := ParseContextValue(buf[TLVHeaderSize:])
	if parseErr != nil {
		t.Fatalf("ParseContextValue: %v", parseErr)
	}
	if got != c {
		t.Errorf("got %+v, want %+v", got, c)
	}
}

func TestAppendServerTLVRoundTrip(t *testing.T) {
	t.Parallel()
	s := ServerEntry{Server16: 0x5400, ServerData: []byte{0xDE, 0xAD}}
	buf := AppendServerTLV(nil, true, s)

	typ, stable, length, err := ParseTLVHeader(buf)
	if err != nil {
		t.Fatalf("ParseTLVHeader: %v", err)
	}
	if typ != TLVTypeServer {
		t.Errorf("type = %d, want %d", typ, TLVTypeServer)
	}
	if !stable {
		t.Error("stable = false, want true")
	}
	if length != uint8(2+len(s.ServerData)) {
		t.Errorf("length = %d, want %d", length, 2+len(s.ServerData))
	}

	got, parseErr := ParseServerValue(buf[TLVHeaderSize:])
	if parseErr != nil {
		t.Fatalf("ParseServerValue: %v", parseErr)
	}
	if got.Server16 != s.Server16 {
		t.Errorf("Server16 = 0x%04x, want 0x%04x", got.Server16, s.Server16)
	}
	if !bytes.Equal(got.ServerData, s.ServerData) {
		t.Errorf("ServerData = %x, want %x", got.ServerData, s.ServerData)
	}
}

// ---------------------------------------------------------------------------
// Integration: rebuild test vector 3 from structs and verify byte equality
// ---------------------------------------------------------------------------

func TestEncodeVector3Partial(t *testing.T) {
	t.Parallel()

	// Rebuild the last Prefix TLV from vector 3:
	// fd00:3333::/64 with stable HasRoute sub-TLV containing 2 entries.
	//
	// Wire bytes from networkDataVector3() offset 62:
	//   03 12 00 40 fd 00 33 33 00 00 00 00
	//   01 06 ec 00 00 28 01 c0
	entries := []HasRouteEntry{
		{RLOC16: 0xEC00, Preference: RoutePreferenceMedium},
		{RLOC16: 0x2801, Preference: RoutePreferenceLow},
	}

	// Build sub-TLVs.
	subTLVs := AppendHasRouteTLV(nil, true, entries)

	// Build prefix value.
	prefixInfo := PrefixTLVInfo{
		DomainID:    0,
		Prefix:      makePrefix([16]byte{0xFD, 0x00, 0x33, 0x33}, 64),
		SubTLVsData: subTLVs,
	}
	prefixValue := AppendPrefixValue(nil, prefixInfo)

	// Build complete TLV.
	tlvBytes := AppendTLV(nil, TLVTypePrefix, true, prefixValue)

	want := []byte{
		0x03, 0x12, 0x00, 0x40, 0xFD, 0x00, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x06, 0xEC, 0x00, 0x00, 0x28, 0x01, 0xC0,
	}
	if !bytes.Equal(tlvBytes, want) {
		t.Errorf("encoded bytes:\n  got  %x\n  want %x", tlvBytes, want)
	}
}

func TestServiceValueSize(t *testing.T) {
	t.Parallel()
	// Thread enterprise: 1(flags) + 0(no enterprise) + 1(sdLen) + 1(sd) = 3.
	info := ServiceTLVInfo{
		ServiceID:        2,
		EnterpriseNumber: ThreadEnterpriseNumber,
		ServiceData:      []byte{0xAB},
	}
	if got := ServiceValueSize(info); got != 3 {
		t.Errorf("ServiceValueSize = %d, want 3", got)
	}

	// Custom enterprise: 1 + 4 + 1 + 2 = 8.
	info2 := ServiceTLVInfo{
		ServiceID:        3,
		EnterpriseNumber: 12345,
		ServiceData:      []byte{0x01, 0x02},
	}
	if got := ServiceValueSize(info2); got != 8 {
		t.Errorf("ServiceValueSize = %d, want 8", got)
	}
}

func TestPrefixValueSize(t *testing.T) {
	t.Parallel()
	// 64-bit prefix: 2 (domainID + prefixLen) + 8 (prefix bytes) = 10.
	info := PrefixTLVInfo{Prefix: makePrefix([16]byte{0xFD}, 64)}
	if got := PrefixValueSize(info); got != 10 {
		t.Errorf("PrefixValueSize = %d, want 10", got)
	}

	// 32-bit prefix: 2 + 4 = 6.
	info2 := PrefixTLVInfo{Prefix: makePrefix([16]byte{0xFD}, 32)}
	if got := PrefixValueSize(info2); got != 6 {
		t.Errorf("PrefixValueSize = %d, want 6", got)
	}

	// With sub-TLVs: 10 + 8.
	info3 := PrefixTLVInfo{
		Prefix:      makePrefix([16]byte{0xFD}, 64),
		SubTLVsData: make([]byte, 8),
	}
	if got := PrefixValueSize(info3); got != 18 {
		t.Errorf("PrefixValueSize = %d, want 18", got)
	}
}
