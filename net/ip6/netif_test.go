// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package ip6

import (
	"errors"
	"testing"

	oterrors "github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// UnicastAddress helpers
// ---------------------------------------------------------------------------

func TestUnicastAddressGetScope(t *testing.T) {
	t.Parallel()

	t.Run("from address", func(t *testing.T) {
		t.Parallel()
		u := UnicastAddress{Address: Address{0: 0xfe, 1: 0x80}} // link-local
		if got := u.GetScope(); got != ScopeLinkLocal {
			t.Errorf("GetScope() = %d, want %d", got, ScopeLinkLocal)
		}
	})

	t.Run("scope override", func(t *testing.T) {
		t.Parallel()
		u := UnicastAddress{
			Address:            Address{0: 0xfe, 1: 0x80},
			ScopeOverride:      ScopeRealmLocal,
			ScopeOverrideValid: true,
		}
		if got := u.GetScope(); got != ScopeRealmLocal {
			t.Errorf("GetScope() with override = %d, want %d", got, ScopeRealmLocal)
		}
	})
}

func TestUnicastAddressHasPrefix(t *testing.T) {
	t.Parallel()

	prefix, err := PrefixFromString("fd00:db8::/64")
	if err != nil {
		t.Fatal(err)
	}
	u := UnicastAddress{
		Address:      Address{0: 0xfd, 1: 0x00, 2: 0x0d, 3: 0xb8},
		PrefixLength: 64,
	}
	if !u.HasPrefix(prefix) {
		t.Error("HasPrefix should be true for matching prefix")
	}

	mismatch, _ := PrefixFromString("2001:db8::/64")
	if u.HasPrefix(mismatch) {
		t.Error("HasPrefix should be false for non-matching prefix")
	}
}

func TestUnicastAddressInitAsThreadOrigin(t *testing.T) {
	t.Parallel()
	var u UnicastAddress
	u.InitAsThreadOrigin()
	if u.PrefixLength != NetworkPrefixLength {
		t.Errorf("PrefixLength = %d, want %d", u.PrefixLength, NetworkPrefixLength)
	}
	if u.Origin != OriginThread {
		t.Error("Origin should be OriginThread")
	}
	if !u.Preferred || !u.Valid {
		t.Error("should be preferred and valid")
	}
}

func TestUnicastAddressInitAsThreadOriginMeshLocal(t *testing.T) {
	t.Parallel()
	var u UnicastAddress
	u.InitAsThreadOriginMeshLocal()
	if !u.ScopeOverrideValid || u.ScopeOverride != ScopeRealmLocal {
		t.Error("should have realm-local scope override")
	}
	if !u.MeshLocal {
		t.Error("should be mesh-local")
	}
}

func TestUnicastAddressInitAsThreadOriginGlobalScope(t *testing.T) {
	t.Parallel()
	var u UnicastAddress
	u.InitAsThreadOriginGlobalScope()
	if !u.ScopeOverrideValid || u.ScopeOverride != ScopeGlobal {
		t.Error("should have global scope override")
	}
	if u.Preferred {
		t.Error("should not be preferred")
	}
	if !u.Valid {
		t.Error("should be valid")
	}
}

func TestUnicastAddressInitAsSLAACOrigin(t *testing.T) {
	t.Parallel()
	var u UnicastAddress
	u.InitAsSLAACOrigin(48, true)
	if u.PrefixLength != 48 {
		t.Errorf("PrefixLength = %d, want 48", u.PrefixLength)
	}
	if u.Origin != OriginSLAAC {
		t.Error("Origin should be OriginSLAAC")
	}
	if !u.Preferred || !u.Valid {
		t.Error("should be preferred and valid")
	}
}

// ---------------------------------------------------------------------------
// Netif — unicast
// ---------------------------------------------------------------------------

func TestNetifAddRemoveUnicastAddress(t *testing.T) {
	t.Parallel()
	n := NewNetif()
	addr := &UnicastAddress{Address: Address{15: 1}}

	n.AddUnicastAddress(addr)
	if !n.HasUnicastAddress(addr.Address) {
		t.Fatal("address should be present after add")
	}
	if len(n.GetUnicastAddresses()) != 1 {
		t.Fatal("expected 1 unicast address")
	}

	// Adding again should be no-op.
	n.AddUnicastAddress(addr)
	if len(n.GetUnicastAddresses()) != 1 {
		t.Fatal("duplicate add should be no-op")
	}

	n.RemoveUnicastAddress(addr)
	if n.HasUnicastAddress(addr.Address) {
		t.Fatal("address should not be present after remove")
	}
}

func TestNetifUpdatePreferredFlagOn(t *testing.T) {
	t.Parallel()
	n := NewNetif()

	var events []AddressEvent
	n.SetAddressCallback(func(_ AddressInfo, event AddressEvent) {
		events = append(events, event)
	})

	addr := &UnicastAddress{Address: Address{15: 1}, Preferred: true, Valid: true}
	n.AddUnicastAddress(addr)
	events = nil // Reset after add.

	n.UpdatePreferredFlagOn(addr.Address, false)
	if len(events) != 2 {
		t.Fatalf("expected 2 events (remove+add), got %d", len(events))
	}
	if events[0] != AddressRemoved || events[1] != AddressAdded {
		t.Error("expected remove then add event")
	}

	addrs := n.GetUnicastAddresses()
	if addrs[0].Preferred {
		t.Error("preferred flag should be false")
	}

	// Same value should be no-op.
	events = nil
	n.UpdatePreferredFlagOn(addr.Address, false)
	if len(events) != 0 {
		t.Error("same value should not trigger events")
	}
}

func TestNetifAddressCallback(t *testing.T) {
	t.Parallel()
	n := NewNetif()

	var infos []AddressInfo
	var evts []AddressEvent
	n.SetAddressCallback(func(info AddressInfo, event AddressEvent) {
		infos = append(infos, info)
		evts = append(evts, event)
	})

	addr := &UnicastAddress{
		Address:      Address{0: 0x20, 1: 0x01, 15: 0x01},
		PrefixLength: 64,
		Preferred:    true,
		Valid:        true,
	}
	n.AddUnicastAddress(addr)

	if len(evts) != 1 || evts[0] != AddressAdded {
		t.Fatal("expected one AddressAdded event")
	}
	if infos[0].Address != addr.Address {
		t.Error("callback address mismatch")
	}
	if infos[0].PrefixLength != 64 {
		t.Error("callback prefix length mismatch")
	}
}

// ---------------------------------------------------------------------------
// Netif — external unicast
// ---------------------------------------------------------------------------

func TestNetifExternalUnicastAddress(t *testing.T) {
	t.Parallel()
	n := NewNetif()

	ext := &UnicastAddress{
		Address:      Address{0: 0x20, 1: 0x01, 15: 0x01},
		PrefixLength: 64,
		Origin:       OriginManual,
		Preferred:    true,
		Valid:        true,
	}

	if err := n.AddExternalUnicastAddress(ext); err != nil {
		t.Fatalf("AddExternalUnicastAddress: %v", err)
	}
	if !n.HasUnicastAddress(ext.Address) {
		t.Fatal("external address should be present")
	}
	if !n.IsUnicastAddressExternal(ext.Address) {
		t.Fatal("should be marked as external")
	}

	// Update existing.
	ext2 := *ext
	ext2.Preferred = false
	if err := n.AddExternalUnicastAddress(&ext2); err != nil {
		t.Fatalf("update external: %v", err)
	}
	addrs := n.GetUnicastAddresses()
	if addrs[0].Preferred {
		t.Error("preferred should be updated to false")
	}

	// Remove.
	if err := n.RemoveExternalUnicastAddress(ext.Address); err != nil {
		t.Fatalf("RemoveExternalUnicastAddress: %v", err)
	}
	if n.HasUnicastAddress(ext.Address) {
		t.Fatal("address should be removed")
	}
}

func TestNetifExternalUnicastRejectMulticast(t *testing.T) {
	t.Parallel()
	n := NewNetif()
	ext := &UnicastAddress{Address: Address{0: 0xff, 1: 0x02, 15: 0x01}}
	if err := n.AddExternalUnicastAddress(ext); !errors.Is(err, oterrors.ErrInvalidArgs) {
		t.Errorf("expected ErrInvalidArgs for multicast, got %v", err)
	}
}

func TestNetifExternalUnicastRejectLinkLocal(t *testing.T) {
	t.Parallel()
	n := NewNetif()
	ext := &UnicastAddress{Address: Address{0: 0xfe, 1: 0x80, 15: 0x01}}
	if err := n.AddExternalUnicastAddress(ext); !errors.Is(err, oterrors.ErrInvalidArgs) {
		t.Errorf("expected ErrInvalidArgs for link-local, got %v", err)
	}
}

func TestNetifExternalUnicastPoolExhaustion(t *testing.T) {
	t.Parallel()
	n := NewNetif()
	for i := 0; i < MaxExternalUnicastAddresses; i++ {
		addr := &UnicastAddress{
			Address: Address{0: 0x20, 1: 0x01, 15: byte(i + 1)},
			Valid:   true,
		}
		if err := n.AddExternalUnicastAddress(addr); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	overflow := &UnicastAddress{
		Address: Address{0: 0x20, 1: 0x01, 15: 0xff},
		Valid:   true,
	}
	if err := n.AddExternalUnicastAddress(overflow); !errors.Is(err, oterrors.ErrNoBufs) {
		t.Errorf("expected ErrNoBufs, got %v", err)
	}
}

func TestNetifRemoveAllExternalUnicastAddresses(t *testing.T) {
	t.Parallel()
	n := NewNetif()

	// Add an internal address.
	internal := &UnicastAddress{Address: Address{15: 1}, Valid: true}
	n.AddUnicastAddress(internal)

	// Add external addresses.
	for i := 0; i < 3; i++ {
		ext := &UnicastAddress{
			Address: Address{0: 0x20, 1: 0x01, 15: byte(i + 10)},
			Valid:   true,
		}
		if err := n.AddExternalUnicastAddress(ext); err != nil {
			t.Fatal(err)
		}
	}

	if len(n.GetUnicastAddresses()) != 4 {
		t.Fatalf("expected 4 addresses, got %d", len(n.GetUnicastAddresses()))
	}

	n.RemoveAllExternalUnicastAddresses()
	if len(n.GetUnicastAddresses()) != 1 {
		t.Fatalf("expected 1 address remaining, got %d", len(n.GetUnicastAddresses()))
	}
	if !n.HasUnicastAddress(internal.Address) {
		t.Error("internal address should remain")
	}
}

// ---------------------------------------------------------------------------
// Netif — multicast
// ---------------------------------------------------------------------------

func TestNetifSubscribeUnsubscribeMulticast(t *testing.T) {
	t.Parallel()
	n := NewNetif()
	addr := Address{0: 0xff, 1: 0x02, 15: 0x42}

	n.SubscribeMulticast(addr)
	if !n.IsMulticastSubscribed(addr) {
		t.Fatal("should be subscribed")
	}

	// Subscribe again should be no-op.
	n.SubscribeMulticast(addr)
	if len(n.GetMulticastAddresses()) != 1 {
		t.Fatal("duplicate subscribe should be no-op")
	}

	n.UnsubscribeMulticast(addr)
	if n.IsMulticastSubscribed(addr) {
		t.Fatal("should not be subscribed after unsubscribe")
	}
}

func TestNetifSubscribeAllNodesMulticast(t *testing.T) {
	t.Parallel()
	n := NewNetif()

	n.SubscribeAllNodesMulticast()
	if !n.IsMulticastSubscribed(MulticastLinkLocalAllNodes) {
		t.Error("should be subscribed to link-local all nodes")
	}
	if !n.IsMulticastSubscribed(MulticastRealmLocalAllNodes) {
		t.Error("should be subscribed to realm-local all nodes")
	}
	if !n.IsMulticastSubscribed(MulticastRealmLocalAllMPLForwarders) {
		t.Error("should be subscribed to realm-local all MPL forwarders")
	}

	// Second call should be no-op.
	before := len(n.GetMulticastAddresses())
	n.SubscribeAllNodesMulticast()
	if len(n.GetMulticastAddresses()) != before {
		t.Error("second SubscribeAllNodesMulticast should be no-op")
	}

	n.UnsubscribeAllNodesMulticast()
	if n.IsMulticastSubscribed(MulticastLinkLocalAllNodes) {
		t.Error("should not be subscribed after unsubscribe all nodes")
	}
}

func TestNetifSubscribeAllRoutersMulticast(t *testing.T) {
	t.Parallel()
	n := NewNetif()

	n.SubscribeAllNodesMulticast()
	n.SubscribeAllRoutersMulticast()

	if !n.IsMulticastSubscribed(MulticastLinkLocalAllRouters) {
		t.Error("should be subscribed to link-local all routers")
	}
	if !n.IsMulticastSubscribed(MulticastRealmLocalAllRouters) {
		t.Error("should be subscribed to realm-local all routers")
	}

	n.UnsubscribeAllRoutersMulticast()
	if n.IsMulticastSubscribed(MulticastLinkLocalAllRouters) {
		t.Error("should not be subscribed to all routers after unsubscribe")
	}
	// All nodes should still be subscribed.
	if !n.IsMulticastSubscribed(MulticastLinkLocalAllNodes) {
		t.Error("all nodes should still be subscribed")
	}
}

func TestNetifExternalMulticast(t *testing.T) {
	t.Parallel()
	n := NewNetif()
	addr := Address{0: 0xff, 1: 0x05, 15: 0x42}

	if err := n.SubscribeExternalMulticast(addr); err != nil {
		t.Fatalf("SubscribeExternalMulticast: %v", err)
	}
	if !n.IsMulticastSubscribed(addr) {
		t.Fatal("should be subscribed")
	}
	if !n.IsMulticastAddressExternal(addr) {
		t.Fatal("should be external")
	}

	// Subscribe again returns ErrAlready.
	if err := n.SubscribeExternalMulticast(addr); !errors.Is(err, oterrors.ErrAlready) {
		t.Errorf("expected ErrAlready, got %v", err)
	}

	if err := n.UnsubscribeExternalMulticast(addr); err != nil {
		t.Fatalf("UnsubscribeExternalMulticast: %v", err)
	}
	if n.IsMulticastSubscribed(addr) {
		t.Fatal("should not be subscribed after unsubscribe")
	}
}

func TestNetifExternalMulticastRejectNonMulticast(t *testing.T) {
	t.Parallel()
	n := NewNetif()
	if err := n.SubscribeExternalMulticast(Address{0: 0x20, 15: 1}); !errors.Is(err, oterrors.ErrInvalidArgs) {
		t.Errorf("expected ErrInvalidArgs for non-multicast, got %v", err)
	}
}

func TestNetifExternalMulticastRejectFixed(t *testing.T) {
	t.Parallel()
	n := NewNetif()
	if err := n.SubscribeExternalMulticast(MulticastLinkLocalAllNodes); !errors.Is(err, oterrors.ErrRejected) {
		t.Errorf("expected ErrRejected for fixed address, got %v", err)
	}
}

func TestNetifExternalMulticastPoolExhaustion(t *testing.T) {
	t.Parallel()
	n := NewNetif()
	for i := 0; i < MaxExternalMulticastAddresses; i++ {
		addr := Address{0: 0xff, 1: 0x05, 15: byte(i + 1)}
		if err := n.SubscribeExternalMulticast(addr); err != nil {
			t.Fatalf("subscribe %d: %v", i, err)
		}
	}
	overflow := Address{0: 0xff, 1: 0x05, 15: 0xff}
	if err := n.SubscribeExternalMulticast(overflow); !errors.Is(err, oterrors.ErrNoBufs) {
		t.Errorf("expected ErrNoBufs, got %v", err)
	}
}

func TestNetifUnsubscribeAllExternalMulticast(t *testing.T) {
	t.Parallel()
	n := NewNetif()

	// Subscribe internal.
	n.SubscribeMulticast(Address{0: 0xff, 1: 0x02, 15: 0xAA})

	// Subscribe external.
	for i := 0; i < 3; i++ {
		addr := Address{0: 0xff, 1: 0x05, 15: byte(i + 1)}
		if err := n.SubscribeExternalMulticast(addr); err != nil {
			t.Fatal(err)
		}
	}

	if len(n.GetMulticastAddresses()) != 4 {
		t.Fatalf("expected 4, got %d", len(n.GetMulticastAddresses()))
	}

	n.UnsubscribeAllExternalMulticastAddresses()
	if len(n.GetMulticastAddresses()) != 1 {
		t.Fatalf("expected 1 remaining, got %d", len(n.GetMulticastAddresses()))
	}
}

func TestNetifMulticastCallbackFired(t *testing.T) {
	t.Parallel()
	n := NewNetif()

	var events []AddressEvent
	n.SetAddressCallback(func(_ AddressInfo, event AddressEvent) {
		events = append(events, event)
	})

	n.SubscribeMulticast(Address{0: 0xff, 1: 0x02, 15: 0x42})
	n.UnsubscribeMulticast(Address{0: 0xff, 1: 0x02, 15: 0x42})

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0] != AddressAdded || events[1] != AddressRemoved {
		t.Error("expected add then remove event")
	}
}

// ---------------------------------------------------------------------------
// Well-known multicast addresses
// ---------------------------------------------------------------------------

func TestWellKnownMulticastAddresses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr Address
		str  string
	}{
		{"AllMPLForwarders", MulticastRealmLocalAllMPLForwarders, "ff03:0:0:0:0:0:0:fc"},
		{"LinkLocalAllNodes", MulticastLinkLocalAllNodes, "ff02:0:0:0:0:0:0:1"},
		{"RealmLocalAllNodes", MulticastRealmLocalAllNodes, "ff03:0:0:0:0:0:0:1"},
		{"LinkLocalAllRouters", MulticastLinkLocalAllRouters, "ff02:0:0:0:0:0:0:2"},
		{"RealmLocalAllRouters", MulticastRealmLocalAllRouters, "ff03:0:0:0:0:0:0:2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !tt.addr.IsMulticast() {
				t.Error("should be multicast")
			}
			if got := tt.addr.ToString(); got != tt.str {
				t.Errorf("ToString() = %q, want %q", got, tt.str)
			}
		})
	}
}
