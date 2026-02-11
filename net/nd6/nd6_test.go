// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package nd6

import (
	"bytes"
	"testing"

	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func mustAddr(s string) ip6.Address {
	a, err := ip6.AddressFromString(s)
	if err != nil {
		panic("bad test address: " + s)
	}
	return a
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

func TestTypeConstants(t *testing.T) {
	if TypeRouterSolicit != 133 {
		t.Errorf("TypeRouterSolicit = %d, want 133", TypeRouterSolicit)
	}
	if TypeRouterAdvert != 134 {
		t.Errorf("TypeRouterAdvert = %d, want 134", TypeRouterAdvert)
	}
	if TypeNeighborSolicit != 135 {
		t.Errorf("TypeNeighborSolicit = %d, want 135", TypeNeighborSolicit)
	}
	if TypeNeighborAdvert != 136 {
		t.Errorf("TypeNeighborAdvert = %d, want 136", TypeNeighborAdvert)
	}
}

func TestOptionTypeConstants(t *testing.T) {
	if OptionTypeSourceLinkLayerAddress != 1 {
		t.Error("OptionTypeSourceLinkLayerAddress")
	}
	if OptionTypeTargetLinkLayerAddress != 2 {
		t.Error("OptionTypeTargetLinkLayerAddress")
	}
	if OptionTypePrefixInfo != 3 {
		t.Error("OptionTypePrefixInfo")
	}
	if OptionTypeRouteInfo != 24 {
		t.Error("OptionTypeRouteInfo")
	}
	if OptionTypeRaDnsServer != 25 {
		t.Error("OptionTypeRaDnsServer")
	}
	if OptionTypeRaFlagsExtension != 26 {
		t.Error("OptionTypeRaFlagsExtension")
	}
	if OptionTypeNat64Prefix != 38 {
		t.Error("OptionTypeNat64Prefix")
	}
}

// ---------------------------------------------------------------------------
// Option (base header)
// ---------------------------------------------------------------------------

func TestOptionMarshalUnmarshal(t *testing.T) {
	o := Option{Type: 3, Length: 4}
	buf := o.Marshal()
	if buf != [2]byte{3, 4} {
		t.Errorf("Marshal = %v, want [3 4]", buf)
	}
	if o.GetTotalSize() != 32 {
		t.Errorf("GetTotalSize = %d, want 32", o.GetTotalSize())
	}

	var o2 Option
	if err := o2.Unmarshal(buf[:]); err != nil {
		t.Fatal(err)
	}
	if o2.Type != 3 || o2.Length != 4 {
		t.Errorf("Unmarshal: Type=%d Length=%d", o2.Type, o2.Length)
	}
}

func TestOptionUnmarshalTooShort(t *testing.T) {
	var o Option
	if err := o.Unmarshal([]byte{0}); err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// PrefixInfoOption
// ---------------------------------------------------------------------------

func TestPrefixInfoOptionRoundTrip(t *testing.T) {
	prefix := mustAddr("2001:db8:1::")
	var pio PrefixInfoOption
	pio.SetPrefixLength(64)
	pio.SetOnLinkFlag()
	pio.SetAutoAddrConfigFlag()
	pio.SetValidLifetime(3600)
	pio.SetPreferredLifetime(1800)
	pio.SetPrefix(prefix)

	buf := pio.Marshal()
	if len(buf) != PrefixInfoOptionSize {
		t.Fatalf("Marshal len = %d, want %d", len(buf), PrefixInfoOptionSize)
	}
	if buf[0] != OptionTypePrefixInfo {
		t.Errorf("type = %d, want %d", buf[0], OptionTypePrefixInfo)
	}
	if buf[1] != 4 {
		t.Errorf("length = %d, want 4", buf[1])
	}

	var pio2 PrefixInfoOption
	if err := pio2.Unmarshal(buf[:]); err != nil {
		t.Fatal(err)
	}
	if pio2.GetPrefixLength() != 64 {
		t.Errorf("PrefixLength = %d, want 64", pio2.GetPrefixLength())
	}
	if !pio2.IsOnLinkFlagSet() {
		t.Error("OnLink flag not set")
	}
	if !pio2.IsAutoAddrConfigFlagSet() {
		t.Error("AutoAddrConfig flag not set")
	}
	if pio2.IsRouterFlagSet() {
		t.Error("Router flag should not be set")
	}
	if pio2.GetValidLifetime() != 3600 {
		t.Errorf("ValidLifetime = %d, want 3600", pio2.GetValidLifetime())
	}
	if pio2.GetPreferredLifetime() != 1800 {
		t.Errorf("PreferredLifetime = %d, want 1800", pio2.GetPreferredLifetime())
	}
	if pio2.GetPrefix() != prefix {
		t.Errorf("Prefix mismatch")
	}
}

func TestPrefixInfoOptionAllFlags(t *testing.T) {
	tests := []struct {
		name string
		set  func(*PrefixInfoOption)
		chk  func(*PrefixInfoOption) bool
	}{
		{"OnLink", func(p *PrefixInfoOption) { p.SetOnLinkFlag() }, func(p *PrefixInfoOption) bool { return p.IsOnLinkFlagSet() }},
		{"AutoAddrConfig", func(p *PrefixInfoOption) { p.SetAutoAddrConfigFlag() }, func(p *PrefixInfoOption) bool { return p.IsAutoAddrConfigFlagSet() }},
		{"Router", func(p *PrefixInfoOption) { p.SetRouterFlag() }, func(p *PrefixInfoOption) bool { return p.IsRouterFlagSet() }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pio PrefixInfoOption
			if tt.chk(&pio) {
				t.Error("flag should not be set initially")
			}
			tt.set(&pio)
			if !tt.chk(&pio) {
				t.Error("flag should be set after Set")
			}
			// Round-trip
			buf := pio.Marshal()
			var pio2 PrefixInfoOption
			if err := pio2.Unmarshal(buf[:]); err != nil {
				t.Fatal(err)
			}
			if !tt.chk(&pio2) {
				t.Error("flag lost after round-trip")
			}
		})
	}
}

func TestPrefixInfoOptionCombinedFlags(t *testing.T) {
	var pio PrefixInfoOption
	pio.SetOnLinkFlag()
	pio.SetAutoAddrConfigFlag()
	pio.SetRouterFlag()
	if pio.Flags != 0xe0 {
		t.Errorf("combined flags = 0x%02x, want 0xe0", pio.Flags)
	}
	if !pio.IsOnLinkFlagSet() || !pio.IsAutoAddrConfigFlagSet() || !pio.IsRouterFlagSet() {
		t.Error("one or more flags not set")
	}
}

func TestPrefixInfoOptionUnmarshalTooShort(t *testing.T) {
	var pio PrefixInfoOption
	if err := pio.Unmarshal(make([]byte, 31)); err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// RouteInfoOption
// ---------------------------------------------------------------------------

func TestRouteInfoOptionZeroPrefix(t *testing.T) {
	var rio RouteInfoOption
	rio.SetPrefixLength(0)
	rio.SetRoutePreference(RoutePrefHigh)
	rio.SetRouteLifetime(7200)

	buf := rio.Marshal()
	if len(buf) != 8 {
		t.Fatalf("Marshal len = %d, want 8 for /0 prefix", len(buf))
	}
	if buf[0] != OptionTypeRouteInfo || buf[1] != 1 {
		t.Errorf("header = [%d %d], want [%d 1]", buf[0], buf[1], OptionTypeRouteInfo)
	}

	var rio2 RouteInfoOption
	if err := rio2.Unmarshal(buf); err != nil {
		t.Fatal(err)
	}
	if rio2.GetPrefixLength() != 0 {
		t.Errorf("PrefixLength = %d", rio2.GetPrefixLength())
	}
	if rio2.GetRoutePreference() != RoutePrefHigh {
		t.Errorf("RoutePreference = %d", rio2.GetRoutePreference())
	}
	if rio2.GetRouteLifetime() != 7200 {
		t.Errorf("RouteLifetime = %d", rio2.GetRouteLifetime())
	}
}

func TestRouteInfoOptionShortPrefix(t *testing.T) {
	prefix := mustAddr("2001:db8::")
	var rio RouteInfoOption
	rio.SetPrefixLength(48)
	rio.SetRoutePreference(RoutePrefMedium)
	rio.SetRouteLifetime(1800)
	rio.SetPrefix(prefix)

	buf := rio.Marshal()
	if len(buf) != 16 {
		t.Fatalf("Marshal len = %d, want 16 for /48 prefix", len(buf))
	}
	if buf[1] != 2 {
		t.Errorf("length field = %d, want 2", buf[1])
	}

	var rio2 RouteInfoOption
	if err := rio2.Unmarshal(buf); err != nil {
		t.Fatal(err)
	}
	if rio2.GetPrefixLength() != 48 {
		t.Errorf("PrefixLength = %d", rio2.GetPrefixLength())
	}
	if rio2.GetRoutePreference() != RoutePrefMedium {
		t.Errorf("RoutePreference = %d", rio2.GetRoutePreference())
	}
	// Check first 8 bytes of prefix
	got := rio2.GetPrefix()
	if !bytes.Equal(got[:6], prefix[:6]) {
		t.Errorf("Prefix mismatch")
	}
}

func TestRouteInfoOptionLongPrefix(t *testing.T) {
	prefix := mustAddr("2001:db8:1:2:3:4:5:6")
	var rio RouteInfoOption
	rio.SetPrefixLength(128)
	rio.SetRoutePreference(RoutePrefLow)
	rio.SetRouteLifetime(600)
	rio.SetPrefix(prefix)

	buf := rio.Marshal()
	if len(buf) != 24 {
		t.Fatalf("Marshal len = %d, want 24 for /128 prefix", len(buf))
	}
	if buf[1] != 3 {
		t.Errorf("length field = %d, want 3", buf[1])
	}

	var rio2 RouteInfoOption
	if err := rio2.Unmarshal(buf); err != nil {
		t.Fatal(err)
	}
	if rio2.GetPrefixLength() != 128 {
		t.Errorf("PrefixLength = %d", rio2.GetPrefixLength())
	}
	if rio2.GetRoutePreference() != RoutePrefLow {
		t.Errorf("RoutePreference = %d, want %d", rio2.GetRoutePreference(), RoutePrefLow)
	}
	if rio2.GetPrefix() != prefix {
		t.Errorf("Prefix mismatch")
	}
}

func TestRouteInfoOptionPreferenceValues(t *testing.T) {
	prefs := []RoutePreference{RoutePrefHigh, RoutePrefMedium, RoutePrefLow}
	for _, pref := range prefs {
		var rio RouteInfoOption
		rio.SetRoutePreference(pref)
		if rio.GetRoutePreference() != pref {
			t.Errorf("pref %d: got %d", pref, rio.GetRoutePreference())
		}
		buf := rio.Marshal()
		var rio2 RouteInfoOption
		if err := rio2.Unmarshal(buf); err != nil {
			t.Fatal(err)
		}
		if rio2.GetRoutePreference() != pref {
			t.Errorf("pref %d: after round-trip got %d", pref, rio2.GetRoutePreference())
		}
	}
}

func TestRouteInfoOptionTotalSize(t *testing.T) {
	tests := []struct {
		prefixLen uint8
		wantSize  int
	}{
		{0, 8},
		{1, 16},
		{32, 16},
		{64, 16},
		{65, 24},
		{128, 24},
	}
	for _, tt := range tests {
		var rio RouteInfoOption
		rio.SetPrefixLength(tt.prefixLen)
		if rio.TotalSize() != tt.wantSize {
			t.Errorf("prefixLen=%d: TotalSize=%d, want %d", tt.prefixLen, rio.TotalSize(), tt.wantSize)
		}
	}
}

func TestRouteInfoOptionUnmarshalTooShort(t *testing.T) {
	var rio RouteInfoOption
	if err := rio.Unmarshal(make([]byte, 7)); err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// RouterAdvertHeader
// ---------------------------------------------------------------------------

func TestRouterAdvertHeaderRoundTrip(t *testing.T) {
	var h RouterAdvertHeader
	h.CurHopLimit = 64
	h.SetManagedAddrConfigFlag()
	h.SetOtherConfigFlag()
	h.SetDefaultRouterPreference(RoutePrefHigh)
	h.SetRouterLifetime(1800)
	h.SetReachableTime(30000)
	h.SetRetransTimer(1000)

	buf := h.Marshal()
	if buf[0] != 64 {
		t.Errorf("CurHopLimit = %d", buf[0])
	}

	var h2 RouterAdvertHeader
	if err := h2.Unmarshal(buf[:]); err != nil {
		t.Fatal(err)
	}
	if h2.CurHopLimit != 64 {
		t.Errorf("CurHopLimit = %d", h2.CurHopLimit)
	}
	if !h2.IsManagedAddrConfigFlagSet() {
		t.Error("M flag not set")
	}
	if !h2.IsOtherConfigFlagSet() {
		t.Error("O flag not set")
	}
	if h2.GetDefaultRouterPreference() != RoutePrefHigh {
		t.Errorf("preference = %d", h2.GetDefaultRouterPreference())
	}
	if h2.GetRouterLifetime() != 1800 {
		t.Errorf("RouterLifetime = %d", h2.GetRouterLifetime())
	}
	if h2.GetReachableTime() != 30000 {
		t.Errorf("ReachableTime = %d", h2.GetReachableTime())
	}
	if h2.GetRetransTimer() != 1000 {
		t.Errorf("RetransTimer = %d", h2.GetRetransTimer())
	}
}

func TestRouterAdvertHeaderPreferences(t *testing.T) {
	prefs := []RoutePreference{RoutePrefHigh, RoutePrefMedium, RoutePrefLow}
	for _, pref := range prefs {
		var h RouterAdvertHeader
		h.SetDefaultRouterPreference(pref)
		if h.GetDefaultRouterPreference() != pref {
			t.Errorf("pref %d: got %d", pref, h.GetDefaultRouterPreference())
		}
	}
}

func TestRouterAdvertHeaderFlags(t *testing.T) {
	var h RouterAdvertHeader

	if h.IsManagedAddrConfigFlagSet() {
		t.Error("M should not be set initially")
	}
	h.SetManagedAddrConfigFlag()
	if !h.IsManagedAddrConfigFlagSet() {
		t.Error("M should be set")
	}

	if h.IsOtherConfigFlagSet() {
		t.Error("O should not be set initially")
	}
	h.SetOtherConfigFlag()
	if !h.IsOtherConfigFlagSet() {
		t.Error("O should be set")
	}
}

func TestRouterAdvertHeaderUnmarshalTooShort(t *testing.T) {
	var h RouterAdvertHeader
	if err := h.Unmarshal(make([]byte, 11)); err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// NeighborSolicitHeader
// ---------------------------------------------------------------------------

func TestNeighborSolicitHeaderRoundTrip(t *testing.T) {
	addr := mustAddr("fe80::1")
	var ns NeighborSolicitHeader
	ns.SetTargetAddress(addr)

	buf := ns.Marshal()
	if len(buf) != NeighborSolicitHeaderSize {
		t.Fatalf("Marshal len = %d", len(buf))
	}
	// First 4 bytes should be zero (reserved)
	if buf[0] != 0 || buf[1] != 0 || buf[2] != 0 || buf[3] != 0 {
		t.Error("Reserved bytes not zero")
	}

	var ns2 NeighborSolicitHeader
	if err := ns2.Unmarshal(buf[:]); err != nil {
		t.Fatal(err)
	}
	if ns2.GetTargetAddress() != addr {
		t.Error("TargetAddress mismatch")
	}
}

func TestNeighborSolicitHeaderUnmarshalTooShort(t *testing.T) {
	var ns NeighborSolicitHeader
	if err := ns.Unmarshal(make([]byte, 19)); err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// NeighborAdvertHeader
// ---------------------------------------------------------------------------

func TestNeighborAdvertHeaderRoundTrip(t *testing.T) {
	addr := mustAddr("fe80::2")
	var na NeighborAdvertHeader
	na.SetRouterFlag()
	na.SetSolicitedFlag()
	na.SetOverrideFlag()
	na.SetTargetAddress(addr)

	buf := na.Marshal()
	if len(buf) != NeighborAdvertHeaderSize {
		t.Fatalf("Marshal len = %d", len(buf))
	}

	var na2 NeighborAdvertHeader
	if err := na2.Unmarshal(buf[:]); err != nil {
		t.Fatal(err)
	}
	if !na2.IsRouterFlagSet() {
		t.Error("Router flag not set")
	}
	if !na2.IsSolicitedFlagSet() {
		t.Error("Solicited flag not set")
	}
	if !na2.IsOverrideFlagSet() {
		t.Error("Override flag not set")
	}
	if na2.GetTargetAddress() != addr {
		t.Error("TargetAddress mismatch")
	}
}

func TestNeighborAdvertHeaderIndividualFlags(t *testing.T) {
	tests := []struct {
		name string
		set  func(*NeighborAdvertHeader)
		chk  func(*NeighborAdvertHeader) bool
	}{
		{"Router", func(h *NeighborAdvertHeader) { h.SetRouterFlag() }, func(h *NeighborAdvertHeader) bool { return h.IsRouterFlagSet() }},
		{"Solicited", func(h *NeighborAdvertHeader) { h.SetSolicitedFlag() }, func(h *NeighborAdvertHeader) bool { return h.IsSolicitedFlagSet() }},
		{"Override", func(h *NeighborAdvertHeader) { h.SetOverrideFlag() }, func(h *NeighborAdvertHeader) bool { return h.IsOverrideFlagSet() }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var na NeighborAdvertHeader
			if tt.chk(&na) {
				t.Error("flag should not be set initially")
			}
			tt.set(&na)
			if !tt.chk(&na) {
				t.Error("flag should be set after Set")
			}
			// Round-trip
			buf := na.Marshal()
			var na2 NeighborAdvertHeader
			if err := na2.Unmarshal(buf[:]); err != nil {
				t.Fatal(err)
			}
			if !tt.chk(&na2) {
				t.Error("flag lost after round-trip")
			}
		})
	}
}

func TestNeighborAdvertHeaderUnmarshalTooShort(t *testing.T) {
	var na NeighborAdvertHeader
	if err := na.Unmarshal(make([]byte, 19)); err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Nat64PrefixOption
// ---------------------------------------------------------------------------

func TestNat64PrefixOptionPLCMapping(t *testing.T) {
	// PLC 0→96, 1→64, 2→56, 3→48, 4→40, 5→32
	expected := []uint8{96, 64, 56, 48, 40, 32}
	for plc, want := range expected {
		var n Nat64PrefixOption
		n.prefixAttr = uint16(plc) // set PLC directly
		got := n.GetPrefixLength()
		if got != want {
			t.Errorf("PLC %d: GetPrefixLength = %d, want %d", plc, got, want)
		}
	}
}

func TestNat64PrefixOptionSetPrefixLength(t *testing.T) {
	validLengths := []uint8{96, 64, 56, 48, 40, 32}
	for _, pl := range validLengths {
		var n Nat64PrefixOption
		if err := n.SetPrefixLength(pl); err != nil {
			t.Errorf("SetPrefixLength(%d) failed: %v", pl, err)
		}
		if n.GetPrefixLength() != pl {
			t.Errorf("SetPrefixLength(%d): got %d", pl, n.GetPrefixLength())
		}
	}

	// Invalid prefix length
	var n Nat64PrefixOption
	if err := n.SetPrefixLength(100); err != ErrInvalidPrefixLength {
		t.Errorf("expected ErrInvalidPrefixLength, got %v", err)
	}
}

func TestNat64PrefixOptionLifetime(t *testing.T) {
	var n Nat64PrefixOption
	n.SetLifetime(600) // 600 / 8 = 75 scaled
	if n.GetLifetime() != 600 {
		t.Errorf("GetLifetime = %d, want 600", n.GetLifetime())
	}

	// Non-multiple of 8 gets truncated
	n.SetLifetime(601) // 601 / 8 = 75, * 8 = 600
	if n.GetLifetime() != 600 {
		t.Errorf("GetLifetime = %d, want 600 (truncated)", n.GetLifetime())
	}
}

func TestNat64PrefixOptionRoundTrip(t *testing.T) {
	validLengths := []uint8{96, 64, 56, 48, 40, 32}
	for _, pl := range validLengths {
		t.Run("prefix_"+string(rune('0'+pl/10))+string(rune('0'+pl%10)), func(t *testing.T) {
			prefix := mustAddr("64:ff9b::")
			var n Nat64PrefixOption
			if err := n.SetPrefixLength(pl); err != nil {
				t.Fatal(err)
			}
			n.SetLifetime(480)
			n.SetPrefix(prefix)

			buf := n.Marshal()
			if buf[0] != OptionTypeNat64Prefix {
				t.Errorf("type = %d", buf[0])
			}
			if buf[1] != 2 {
				t.Errorf("length = %d, want 2", buf[1])
			}

			var n2 Nat64PrefixOption
			if err := n2.Unmarshal(buf); err != nil {
				t.Fatal(err)
			}
			if n2.GetPrefixLength() != pl {
				t.Errorf("PrefixLength = %d, want %d", n2.GetPrefixLength(), pl)
			}
			if n2.GetLifetime() != 480 {
				t.Errorf("Lifetime = %d, want 480", n2.GetLifetime())
			}
			// Check prefix (only first 12 bytes stored)
			p1 := n.GetPrefix()
			p2 := n2.GetPrefix()
			if !bytes.Equal(p1[:12], p2[:12]) {
				t.Error("Prefix mismatch")
			}
		})
	}
}

func TestNat64PrefixOptionUnmarshalTooShort(t *testing.T) {
	var n Nat64PrefixOption
	if err := n.Unmarshal(make([]byte, 3)); err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

func TestNat64PrefixOptionLifetimeAndPLCIndependent(t *testing.T) {
	// Verify that setting lifetime doesn't clobber PLC and vice versa
	var n Nat64PrefixOption
	if err := n.SetPrefixLength(64); err != nil {
		t.Fatal(err)
	}
	n.SetLifetime(800)
	if n.GetPrefixLength() != 64 {
		t.Errorf("PLC clobbered by SetLifetime: got %d", n.GetPrefixLength())
	}
	if n.GetLifetime() != 800 {
		t.Errorf("Lifetime = %d, want 800", n.GetLifetime())
	}

	if err := n.SetPrefixLength(96); err != nil {
		t.Fatal(err)
	}
	if n.GetLifetime() != 800 {
		t.Errorf("Lifetime clobbered by SetPrefixLength: got %d", n.GetLifetime())
	}
}

// ---------------------------------------------------------------------------
// RaDnsServerOption
// ---------------------------------------------------------------------------

func TestRaDnsServerOptionRoundTrip(t *testing.T) {
	addr1 := mustAddr("2001:4860:4860::8888")
	addr2 := mustAddr("2001:4860:4860::8844")

	var rdnss RaDnsServerOption
	rdnss.SetLifetime(3600)
	rdnss.Addresses = []ip6.Address{addr1, addr2}

	buf := rdnss.Marshal()
	// header(2) + reserved(2) + lifetime(4) + 2*16 = 40 bytes
	// 40 / 8 = 5
	if buf[0] != OptionTypeRaDnsServer {
		t.Errorf("type = %d", buf[0])
	}
	if buf[1] != 5 {
		t.Errorf("length = %d, want 5", buf[1])
	}
	if len(buf) != 40 {
		t.Fatalf("Marshal len = %d, want 40", len(buf))
	}

	var rdnss2 RaDnsServerOption
	if err := rdnss2.Unmarshal(buf); err != nil {
		t.Fatal(err)
	}
	if rdnss2.GetLifetime() != 3600 {
		t.Errorf("Lifetime = %d", rdnss2.GetLifetime())
	}
	addrs := rdnss2.GetAddresses()
	if len(addrs) != 2 {
		t.Fatalf("NumAddresses = %d, want 2", len(addrs))
	}
	if addrs[0] != addr1 {
		t.Error("Address[0] mismatch")
	}
	if addrs[1] != addr2 {
		t.Error("Address[1] mismatch")
	}
}

func TestRaDnsServerOptionSingleAddress(t *testing.T) {
	addr := mustAddr("::1")
	var rdnss RaDnsServerOption
	rdnss.SetLifetime(600)
	rdnss.Addresses = []ip6.Address{addr}

	buf := rdnss.Marshal()
	// 8 + 16 = 24 bytes, 24/8 = 3
	if buf[1] != 3 {
		t.Errorf("length = %d, want 3", buf[1])
	}

	var rdnss2 RaDnsServerOption
	if err := rdnss2.Unmarshal(buf); err != nil {
		t.Fatal(err)
	}
	addrs := rdnss2.GetAddresses()
	if len(addrs) != 1 {
		t.Fatalf("NumAddresses = %d", len(addrs))
	}
	if addrs[0] != addr {
		t.Error("Address mismatch")
	}
}

func TestRaDnsServerOptionEmpty(t *testing.T) {
	var rdnss RaDnsServerOption
	rdnss.SetLifetime(100)

	buf := rdnss.Marshal()
	// 8 bytes, length = 1
	if buf[1] != 1 {
		t.Errorf("length = %d, want 1", buf[1])
	}

	var rdnss2 RaDnsServerOption
	if err := rdnss2.Unmarshal(buf); err != nil {
		t.Fatal(err)
	}
	if len(rdnss2.GetAddresses()) != 0 {
		t.Error("expected no addresses")
	}
}

func TestRaDnsServerOptionUnmarshalTooShort(t *testing.T) {
	var rdnss RaDnsServerOption
	if err := rdnss.Unmarshal(make([]byte, 7)); err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// RaFlagsExtOption
// ---------------------------------------------------------------------------

func TestRaFlagsExtOptionRoundTrip(t *testing.T) {
	var fe RaFlagsExtOption
	fe.SetFlag(0)  // MSB of Flags[0]
	fe.SetFlag(7)  // LSB of Flags[0]
	fe.SetFlag(47) // LSB of Flags[5]

	if !fe.IsFlagSet(0) {
		t.Error("bit 0 not set")
	}
	if !fe.IsFlagSet(7) {
		t.Error("bit 7 not set")
	}
	if !fe.IsFlagSet(47) {
		t.Error("bit 47 not set")
	}
	if fe.IsFlagSet(1) {
		t.Error("bit 1 should not be set")
	}

	buf := fe.Marshal()
	if buf[0] != OptionTypeRaFlagsExtension {
		t.Errorf("type = %d", buf[0])
	}
	if buf[1] != 1 {
		t.Errorf("length = %d", buf[1])
	}

	var fe2 RaFlagsExtOption
	if err := fe2.Unmarshal(buf[:]); err != nil {
		t.Fatal(err)
	}
	if !fe2.IsFlagSet(0) || !fe2.IsFlagSet(7) || !fe2.IsFlagSet(47) {
		t.Error("flags lost after round-trip")
	}
}

func TestRaFlagsExtOptionClearFlag(t *testing.T) {
	var fe RaFlagsExtOption
	fe.SetFlag(10)
	if !fe.IsFlagSet(10) {
		t.Error("bit 10 not set")
	}
	fe.ClearFlag(10)
	if fe.IsFlagSet(10) {
		t.Error("bit 10 still set after clear")
	}
}

func TestRaFlagsExtOptionOutOfRange(t *testing.T) {
	var fe RaFlagsExtOption
	// Should not panic
	fe.SetFlag(48)
	fe.SetFlag(100)
	if fe.IsFlagSet(48) {
		t.Error("out-of-range bit should not be set")
	}
	fe.ClearFlag(48)
}

func TestRaFlagsExtOptionUnmarshalTooShort(t *testing.T) {
	var fe RaFlagsExtOption
	if err := fe.Unmarshal(make([]byte, 7)); err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// RaMessage
// ---------------------------------------------------------------------------

func TestRaMessageMarshalUnmarshal(t *testing.T) {
	var h RouterAdvertHeader
	h.CurHopLimit = 64
	h.SetRouterLifetime(1800)
	h.SetReachableTime(0)
	h.SetRetransTimer(0)

	msg := RaMessage{Header: h}
	buf := msg.Marshal()
	if len(buf) != 12 {
		t.Fatalf("Marshal len = %d, want 12", len(buf))
	}

	var msg2 RaMessage
	if err := msg2.Unmarshal(buf); err != nil {
		t.Fatal(err)
	}
	if msg2.Header.CurHopLimit != 64 {
		t.Errorf("CurHopLimit = %d", msg2.Header.CurHopLimit)
	}
	if msg2.Header.GetRouterLifetime() != 1800 {
		t.Errorf("RouterLifetime = %d", msg2.Header.GetRouterLifetime())
	}
}

func TestRaMessageWithOptions(t *testing.T) {
	// Build an RA with a PIO and a RIO
	var h RouterAdvertHeader
	h.CurHopLimit = 64
	h.SetRouterLifetime(1800)

	prefix := mustAddr("2001:db8::")
	var pio PrefixInfoOption
	pio.SetPrefixLength(64)
	pio.SetOnLinkFlag()
	pio.SetAutoAddrConfigFlag()
	pio.SetValidLifetime(3600)
	pio.SetPreferredLifetime(1800)
	pio.SetPrefix(prefix)
	pioBuf := pio.Marshal()

	var rio RouteInfoOption
	rio.SetPrefixLength(48)
	rio.SetRoutePreference(RoutePrefHigh)
	rio.SetRouteLifetime(7200)
	rio.SetPrefix(prefix)
	rioBuf := rio.Marshal()

	var opts []byte
	opts = append(opts, pioBuf[:]...)
	opts = append(opts, rioBuf...)

	msg := RaMessage{Header: h, Options: opts}

	// Parse options
	parsedOpts, err := msg.ParseOptions()
	if err != nil {
		t.Fatal(err)
	}
	if len(parsedOpts) != 2 {
		t.Fatalf("ParseOptions: len = %d, want 2", len(parsedOpts))
	}
	if parsedOpts[0].Type != OptionTypePrefixInfo {
		t.Errorf("opt[0].Type = %d", parsedOpts[0].Type)
	}
	if parsedOpts[1].Type != OptionTypeRouteInfo {
		t.Errorf("opt[1].Type = %d", parsedOpts[1].Type)
	}

	// Find PIO options
	pios := msg.FindPrefixInfoOptions()
	if len(pios) != 1 {
		t.Fatalf("FindPrefixInfoOptions: len = %d", len(pios))
	}
	if pios[0].GetPrefixLength() != 64 {
		t.Errorf("PIO PrefixLength = %d", pios[0].GetPrefixLength())
	}
	if !pios[0].IsOnLinkFlagSet() {
		t.Error("PIO OnLink flag not set")
	}

	// Find RIO options
	rios := msg.FindRouteInfoOptions()
	if len(rios) != 1 {
		t.Fatalf("FindRouteInfoOptions: len = %d", len(rios))
	}
	if rios[0].GetPrefixLength() != 48 {
		t.Errorf("RIO PrefixLength = %d", rios[0].GetPrefixLength())
	}
	if rios[0].GetRoutePreference() != RoutePrefHigh {
		t.Errorf("RIO RoutePreference = %d", rios[0].GetRoutePreference())
	}
}

func TestRaMessageMultipleOptions(t *testing.T) {
	// Build RA with 2 PIOs and 1 RIO
	var opts []byte

	prefix1 := mustAddr("2001:db8:1::")
	var pio1 PrefixInfoOption
	pio1.SetPrefixLength(64)
	pio1.SetOnLinkFlag()
	pio1.SetValidLifetime(3600)
	pio1.SetPreferredLifetime(1800)
	pio1.SetPrefix(prefix1)
	buf1 := pio1.Marshal()
	opts = append(opts, buf1[:]...)

	prefix2 := mustAddr("2001:db8:2::")
	var pio2 PrefixInfoOption
	pio2.SetPrefixLength(48)
	pio2.SetAutoAddrConfigFlag()
	pio2.SetValidLifetime(7200)
	pio2.SetPreferredLifetime(3600)
	pio2.SetPrefix(prefix2)
	buf2 := pio2.Marshal()
	opts = append(opts, buf2[:]...)

	var rio RouteInfoOption
	rio.SetPrefixLength(0)
	rio.SetRoutePreference(RoutePrefLow)
	rio.SetRouteLifetime(600)
	rioBuf := rio.Marshal()
	opts = append(opts, rioBuf...)

	var h RouterAdvertHeader
	h.CurHopLimit = 128
	msg := RaMessage{Header: h, Options: opts}

	pios := msg.FindPrefixInfoOptions()
	if len(pios) != 2 {
		t.Fatalf("expected 2 PIOs, got %d", len(pios))
	}
	if pios[0].GetPrefix() != prefix1 {
		t.Error("PIO[0] prefix mismatch")
	}
	if pios[1].GetPrefix() != prefix2 {
		t.Error("PIO[1] prefix mismatch")
	}

	rios := msg.FindRouteInfoOptions()
	if len(rios) != 1 {
		t.Fatalf("expected 1 RIO, got %d", len(rios))
	}
	if rios[0].GetRoutePreference() != RoutePrefLow {
		t.Errorf("RIO preference = %d", rios[0].GetRoutePreference())
	}
}

func TestRaMessageRoundTrip(t *testing.T) {
	var h RouterAdvertHeader
	h.CurHopLimit = 64
	h.SetManagedAddrConfigFlag()
	h.SetRouterLifetime(900)
	h.SetReachableTime(5000)
	h.SetRetransTimer(2000)

	// Add a PIO
	var pio PrefixInfoOption
	pio.SetPrefixLength(64)
	pio.SetOnLinkFlag()
	pio.SetValidLifetime(3600)
	pio.SetPreferredLifetime(1800)
	pio.SetPrefix(mustAddr("2001:db8::"))
	pioBuf := pio.Marshal()

	msg := RaMessage{Header: h, Options: pioBuf[:]}
	buf := msg.Marshal()

	var msg2 RaMessage
	if err := msg2.Unmarshal(buf); err != nil {
		t.Fatal(err)
	}
	if msg2.Header.CurHopLimit != 64 {
		t.Error("CurHopLimit mismatch")
	}
	if !msg2.Header.IsManagedAddrConfigFlagSet() {
		t.Error("M flag lost")
	}
	if msg2.Header.GetRouterLifetime() != 900 {
		t.Error("RouterLifetime mismatch")
	}

	pios := msg2.FindPrefixInfoOptions()
	if len(pios) != 1 {
		t.Fatalf("expected 1 PIO, got %d", len(pios))
	}
	if pios[0].GetValidLifetime() != 3600 {
		t.Error("PIO ValidLifetime mismatch")
	}
}

func TestRaMessageParseOptionsInvalidLength(t *testing.T) {
	// Option with Length=0 should be an error
	opts := []byte{3, 0, 0, 0, 0, 0, 0, 0}
	msg := RaMessage{Options: opts}
	_, err := msg.ParseOptions()
	if err != ErrInvalidLength {
		t.Errorf("expected ErrInvalidLength, got %v", err)
	}
}

func TestRaMessageUnmarshalTooShort(t *testing.T) {
	var msg RaMessage
	if err := msg.Unmarshal(make([]byte, 11)); err != ErrTooShort {
		t.Errorf("expected ErrTooShort, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Edge cases and additional coverage
// ---------------------------------------------------------------------------

func TestPrefixInfoOptionMaxLifetimes(t *testing.T) {
	var pio PrefixInfoOption
	pio.SetValidLifetime(0xFFFFFFFF)
	pio.SetPreferredLifetime(0xFFFFFFFF)
	buf := pio.Marshal()

	var pio2 PrefixInfoOption
	if err := pio2.Unmarshal(buf[:]); err != nil {
		t.Fatal(err)
	}
	if pio2.GetValidLifetime() != 0xFFFFFFFF {
		t.Errorf("ValidLifetime = %d", pio2.GetValidLifetime())
	}
	if pio2.GetPreferredLifetime() != 0xFFFFFFFF {
		t.Errorf("PreferredLifetime = %d", pio2.GetPreferredLifetime())
	}
}

func TestRouterAdvertHeaderZeroValues(t *testing.T) {
	var h RouterAdvertHeader
	buf := h.Marshal()
	var h2 RouterAdvertHeader
	if err := h2.Unmarshal(buf[:]); err != nil {
		t.Fatal(err)
	}
	if h2.CurHopLimit != 0 || h2.GetRouterLifetime() != 0 ||
		h2.GetReachableTime() != 0 || h2.GetRetransTimer() != 0 {
		t.Error("zero values not preserved")
	}
}

func TestNeighborAdvertHeaderNoFlags(t *testing.T) {
	addr := mustAddr("2001:db8::1")
	var na NeighborAdvertHeader
	na.SetTargetAddress(addr)
	buf := na.Marshal()

	var na2 NeighborAdvertHeader
	if err := na2.Unmarshal(buf[:]); err != nil {
		t.Fatal(err)
	}
	if na2.IsRouterFlagSet() || na2.IsSolicitedFlagSet() || na2.IsOverrideFlagSet() {
		t.Error("no flags should be set")
	}
	if na2.GetTargetAddress() != addr {
		t.Error("TargetAddress mismatch")
	}
}

func TestRaMessageNoOptions(t *testing.T) {
	msg := RaMessage{}
	pios := msg.FindPrefixInfoOptions()
	if len(pios) != 0 {
		t.Error("expected no PIOs")
	}
	rios := msg.FindRouteInfoOptions()
	if len(rios) != 0 {
		t.Error("expected no RIOs")
	}
	opts, err := msg.ParseOptions()
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) != 0 {
		t.Error("expected no options")
	}
}

func TestRouteInfoOption64BitBoundary(t *testing.T) {
	// PrefixLength = 64 should use Length=2 (16 bytes)
	var rio RouteInfoOption
	rio.SetPrefixLength(64)
	rio.SetRouteLifetime(100)
	prefix := mustAddr("2001:db8:abcd:ef01::")
	rio.SetPrefix(prefix)

	buf := rio.Marshal()
	if len(buf) != 16 {
		t.Fatalf("Marshal len = %d, want 16", len(buf))
	}

	var rio2 RouteInfoOption
	if err := rio2.Unmarshal(buf); err != nil {
		t.Fatal(err)
	}
	got := rio2.GetPrefix()
	// First 8 bytes should match
	if !bytes.Equal(got[:8], prefix[:8]) {
		t.Error("Prefix first 8 bytes mismatch")
	}
}

func TestRouteInfoOption65BitBoundary(t *testing.T) {
	// PrefixLength = 65 should use Length=3 (24 bytes)
	var rio RouteInfoOption
	rio.SetPrefixLength(65)
	if rio.TotalSize() != 24 {
		t.Errorf("TotalSize = %d, want 24", rio.TotalSize())
	}
	buf := rio.Marshal()
	if len(buf) != 24 {
		t.Fatalf("Marshal len = %d, want 24", len(buf))
	}
}

func TestNat64PrefixOptionInvalidPLC(t *testing.T) {
	var n Nat64PrefixOption
	n.prefixAttr = 6 // PLC = 6, which is invalid
	if n.GetPrefixLength() != 0 {
		t.Errorf("expected 0 for invalid PLC, got %d", n.GetPrefixLength())
	}
}

func TestRaFlagsExtOptionAllBits(t *testing.T) {
	var fe RaFlagsExtOption
	// Set all 48 bits
	for i := uint(0); i < 48; i++ {
		fe.SetFlag(i)
	}
	for i := uint(0); i < 48; i++ {
		if !fe.IsFlagSet(i) {
			t.Errorf("bit %d not set", i)
		}
	}
	// Clear all
	for i := uint(0); i < 48; i++ {
		fe.ClearFlag(i)
	}
	for i := uint(0); i < 48; i++ {
		if fe.IsFlagSet(i) {
			t.Errorf("bit %d still set after clear", i)
		}
	}
}

func TestRaDnsServerOptionThreeAddresses(t *testing.T) {
	addrs := []ip6.Address{
		mustAddr("2001:4860:4860::8888"),
		mustAddr("2001:4860:4860::8844"),
		mustAddr("2606:4700:4700::1111"),
	}

	var rdnss RaDnsServerOption
	rdnss.SetLifetime(1200)
	rdnss.Addresses = addrs

	buf := rdnss.Marshal()
	// 8 + 3*16 = 56 bytes, 56/8 = 7
	if buf[1] != 7 {
		t.Errorf("length = %d, want 7", buf[1])
	}

	var rdnss2 RaDnsServerOption
	if err := rdnss2.Unmarshal(buf); err != nil {
		t.Fatal(err)
	}
	got := rdnss2.GetAddresses()
	if len(got) != 3 {
		t.Fatalf("NumAddresses = %d", len(got))
	}
	for i, want := range addrs {
		if got[i] != want {
			t.Errorf("Address[%d] mismatch", i)
		}
	}
}
