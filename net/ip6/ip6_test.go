// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package ip6_test

import (
	"testing"

	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// TestDscpToPriority
// ---------------------------------------------------------------------------

func TestDscpToPriority(t *testing.T) {
	tests := []struct {
		name     string
		dscp     ip6.Dscp
		expected ip6.Priority
	}{
		// Class Selector values
		{"CS0", ip6.DscpCs0, ip6.PriorityNormal},
		{"CS1", ip6.DscpCs1, ip6.PriorityLow},
		{"CS2", ip6.DscpCs2, ip6.PriorityLow},
		{"CS3", ip6.DscpCs3, ip6.PriorityNormal},
		{"CS4", ip6.DscpCs4, ip6.PriorityHigh},
		{"CS5", ip6.DscpCs5, ip6.PriorityHigh},
		{"CS6", ip6.DscpCs6, ip6.PriorityHigh},
		{"CS7", ip6.DscpCs7, ip6.PriorityHigh},
		// Non-CS DSCP values (low bits set) — CS is extracted via mask.
		{"AF11 (10)", ip6.Dscp(10), ip6.PriorityLow},    // CS bits = CS1
		{"AF21 (18)", ip6.Dscp(18), ip6.PriorityLow},    // CS bits = CS2
		{"AF31 (26)", ip6.Dscp(26), ip6.PriorityNormal}, // CS bits = CS3
		{"AF41 (34)", ip6.Dscp(34), ip6.PriorityHigh},   // CS bits = CS4
		{"EF (46)", ip6.Dscp(46), ip6.PriorityHigh},     // CS bits = CS5
		// Thread-specific DSCP values
		{"TmfNet (7)", ip6.DscpTmfNetPriority, ip6.PriorityNormal},     // CS bits = CS0
		{"TmfNormal (15)", ip6.DscpTmfNormalPriority, ip6.PriorityLow}, // CS bits = CS1
		{"TmfLow (23)", ip6.DscpTmfLowPriority, ip6.PriorityLow},       // CS bits = 23 & 0x38 = 16 = CS2 → Low
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ip6.DscpToPriority(tc.dscp)
			if got != tc.expected {
				t.Errorf("DscpToPriority(%d) = %d, want %d", tc.dscp, got, tc.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestPriorityToDscp
// ---------------------------------------------------------------------------

func TestPriorityToDscp(t *testing.T) {
	tests := []struct {
		name     string
		priority ip6.Priority
		expected ip6.Dscp
	}{
		{"Low", ip6.PriorityLow, ip6.DscpCs1},
		{"Normal", ip6.PriorityNormal, ip6.DscpCs0},
		{"High", ip6.PriorityHigh, ip6.DscpCs4},
		{"Net", ip6.PriorityNet, ip6.DscpCs0},
		{"OutOfRange", ip6.Priority(99), ip6.DscpCs0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ip6.PriorityToDscp(tc.priority)
			if got != tc.expected {
				t.Errorf("PriorityToDscp(%d) = %d, want %d", tc.priority, got, tc.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestIpProtoToString
// ---------------------------------------------------------------------------

func TestIPProtoToString(t *testing.T) {
	tests := []struct {
		proto    uint8
		expected string
	}{
		{ip6.ProtoHopOpts, "HopOpts"},
		{ip6.ProtoTCP, "TCP"},
		{ip6.ProtoUDP, "UDP"},
		{ip6.ProtoIPv6, "IP6"},
		{ip6.ProtoRouting, "Routing"},
		{ip6.ProtoFragment, "Frag"},
		{ip6.ProtoICMPv6, "ICMP6"},
		{ip6.ProtoNone, "None"},
		{ip6.ProtoDstOpts, "DstOpts"},
		{255, "Unknown"},
		{99, "Unknown"},
	}

	for _, tc := range tests {
		got := ip6.IPProtoToString(tc.proto)
		if got != tc.expected {
			t.Errorf("IpProtoToString(%d) = %q, want %q", tc.proto, got, tc.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// TestEcnToString
// ---------------------------------------------------------------------------

func TestEcnToString(t *testing.T) {
	tests := []struct {
		ecn      ip6.Ecn
		expected string
	}{
		{ip6.EcnNotCapable, "no"},
		{ip6.EcnCapable0, "e0"},
		{ip6.EcnCapable1, "e1"},
		{ip6.EcnMarked, "ce"},
		{ip6.Ecn(99), "Unknown"},
	}

	for _, tc := range tests {
		got := ip6.EcnToString(tc.ecn)
		if got != tc.expected {
			t.Errorf("EcnToString(%d) = %q, want %q", tc.ecn, got, tc.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// TestPriorityConstants
// ---------------------------------------------------------------------------

func TestPriorityConstants(t *testing.T) {
	if ip6.PriorityLow >= ip6.PriorityNormal {
		t.Error("expected PriorityLow < PriorityNormal")
	}
	if ip6.PriorityNormal >= ip6.PriorityHigh {
		t.Error("expected PriorityNormal < PriorityHigh")
	}
	if ip6.PriorityHigh >= ip6.PriorityNet {
		t.Error("expected PriorityHigh < PriorityNet")
	}
}

// ---------------------------------------------------------------------------
// TestSelectSourceAddress
// ---------------------------------------------------------------------------

// helper to create a unicast address entry.
func makeUnicast(addr ip6.Address, prefixLen uint8, preferred bool) ip6.UnicastAddress {
	return ip6.UnicastAddress{
		Address:      addr,
		PrefixLength: prefixLen,
		Preferred:    preferred,
		Valid:        true,
	}
}

// helper to create a unicast address with scope override.
func makeUnicastScoped(addr ip6.Address, prefixLen uint8, preferred bool, scope uint8) ip6.UnicastAddress {
	return ip6.UnicastAddress{
		Address:            addr,
		PrefixLength:       prefixLen,
		Preferred:          preferred,
		Valid:              true,
		ScopeOverride:      scope,
		ScopeOverrideValid: true,
	}
}

func mustAddr(s string) ip6.Address {
	a, err := ip6.AddressFromString(s)
	if err != nil {
		panic("bad test address: " + s + ": " + err.Error())
	}
	return a
}

func TestSelectSourceAddress(t *testing.T) {
	t.Run("NoAddresses", func(t *testing.T) {
		netif := ip6.NewNetif()
		dest := mustAddr("2001:db8::1")
		result := ip6.SelectSourceAddress(netif, dest)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("SingleAddress", func(t *testing.T) {
		netif := ip6.NewNetif()
		src := mustAddr("2001:db8::10")
		ua := makeUnicast(src, 64, true)
		netif.AddUnicastAddress(&ua)

		dest := mustAddr("2001:db8::1")
		result := ip6.SelectSourceAddress(netif, dest)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if *result != src {
			t.Errorf("got %v, want %v", result.ToString(), src.ToString())
		}
	})

	t.Run("ExactMatch", func(t *testing.T) {
		netif := ip6.NewNetif()
		addr1 := mustAddr("2001:db8::10")
		addr2 := mustAddr("2001:db8::20")
		dest := mustAddr("2001:db8::20")

		ua1 := makeUnicast(addr1, 64, true)
		ua2 := makeUnicast(addr2, 64, true)
		netif.AddUnicastAddress(&ua1)
		netif.AddUnicastAddress(&ua2)

		result := ip6.SelectSourceAddress(netif, dest)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if *result != dest {
			t.Errorf("got %v, want exact match %v", result.ToString(), dest.ToString())
		}
	})

	t.Run("PreferAppropriateScope", func(t *testing.T) {
		netif := ip6.NewNetif()
		// Link-local source
		linkLocal := mustAddr("fe80::1")
		// Global source
		global := mustAddr("2001:db8::1")
		// Link-local destination — prefer link-local source
		dest := mustAddr("fe80::99")

		ua1 := makeUnicast(global, 64, true)
		ua2 := makeUnicast(linkLocal, 64, true)
		netif.AddUnicastAddress(&ua1)
		netif.AddUnicastAddress(&ua2)

		result := ip6.SelectSourceAddress(netif, dest)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if *result != linkLocal {
			t.Errorf("got %v, want link-local %v", result.ToString(), linkLocal.ToString())
		}
	})

	t.Run("PreferNonDeprecated", func(t *testing.T) {
		netif := ip6.NewNetif()
		deprecated := mustAddr("2001:db8::1")
		preferred := mustAddr("2001:db8::2")
		dest := mustAddr("2001:db8::99")

		ua1 := makeUnicast(deprecated, 64, false) // deprecated
		ua2 := makeUnicast(preferred, 64, true)   // preferred
		netif.AddUnicastAddress(&ua1)
		netif.AddUnicastAddress(&ua2)

		result := ip6.SelectSourceAddress(netif, dest)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if *result != preferred {
			t.Errorf("got %v, want preferred %v", result.ToString(), preferred.ToString())
		}
	})

	t.Run("PreferLongestPrefixMatch", func(t *testing.T) {
		netif := ip6.NewNetif()
		// addr1 shares a /64 with dest, addr2 shares nothing.
		addr1 := mustAddr("2001:db8:1::10")
		addr2 := mustAddr("2001:db8:2::10")
		dest := mustAddr("2001:db8:1::99")

		ua1 := makeUnicast(addr1, 64, true)
		ua2 := makeUnicast(addr2, 64, true)
		netif.AddUnicastAddress(&ua1)
		netif.AddUnicastAddress(&ua2)

		result := ip6.SelectSourceAddress(netif, dest)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if *result != addr1 {
			t.Errorf("got %v, want %v (longest prefix match)", result.ToString(), addr1.ToString())
		}
	})

	t.Run("PreferRlocForRlocDest", func(t *testing.T) {
		netif := ip6.NewNetif()
		// RLOC IID pattern: 0000:00ff:fe00:xxxx where byte[6] < 0xfc
		// Build an RLOC address: fd00:db8:0:0:0:ff:fe00:1000
		rlocAddr := mustAddr("fd00:db8::ff:fe00:1000")
		normalAddr := mustAddr("fd00:db8::1")
		// RLOC destination
		dest := mustAddr("fd00:db8::ff:fe00:2000")

		uaRloc := makeUnicastScoped(rlocAddr, 64, true, ip6.ScopeRealmLocal)
		uaNormal := makeUnicastScoped(normalAddr, 64, true, ip6.ScopeRealmLocal)
		netif.AddUnicastAddress(&uaNormal)
		netif.AddUnicastAddress(&uaRloc)

		result := ip6.SelectSourceAddress(netif, dest)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if *result != rlocAddr {
			t.Errorf("got %v, want RLOC %v", result.ToString(), rlocAddr.ToString())
		}
	})
}
