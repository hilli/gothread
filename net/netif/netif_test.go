// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package netif

import (
	"testing"

	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func linkLocal1() [16]byte { return [16]byte{0: 0xfe, 1: 0x80, 15: 0x01} }
func linkLocal2() [16]byte { return [16]byte{0: 0xfe, 1: 0x80, 15: 0x02} }
func global1() [16]byte    { return [16]byte{0: 0x20, 1: 0x01, 15: 0x01} }

// ---------------------------------------------------------------------------
// Unicast address management
// ---------------------------------------------------------------------------

func TestAddUnicastAddress(t *testing.T) {
	t.Parallel()

	n := NewNetIf()
	addr := UnicastAddress{Address: linkLocal1(), PrefixLength: 64, Origin: OriginThread}

	if err := n.AddUnicastAddress(addr); err != nil {
		t.Fatalf("AddUnicastAddress: %v", err)
	}
	if !n.HasUnicastAddress(linkLocal1()) {
		t.Error("address should be present after add")
	}
}

func TestAddUnicastAddressDuplicate(t *testing.T) {
	t.Parallel()

	n := NewNetIf()
	addr := UnicastAddress{Address: linkLocal1(), PrefixLength: 64}
	_ = n.AddUnicastAddress(addr)

	if err := n.AddUnicastAddress(addr); err != errors.ErrAlready {
		t.Errorf("duplicate add: got %v, want ErrAlready", err)
	}
}

func TestRemoveUnicastAddress(t *testing.T) {
	t.Parallel()

	n := NewNetIf()
	addr := UnicastAddress{Address: linkLocal1(), PrefixLength: 64}
	_ = n.AddUnicastAddress(addr)

	if err := n.RemoveUnicastAddress(linkLocal1()); err != nil {
		t.Fatalf("RemoveUnicastAddress: %v", err)
	}
	if n.HasUnicastAddress(linkLocal1()) {
		t.Error("address should not be present after remove")
	}
}

func TestRemoveUnicastAddressNotFound(t *testing.T) {
	t.Parallel()

	n := NewNetIf()
	if err := n.RemoveUnicastAddress(linkLocal1()); err != errors.ErrNotFound {
		t.Errorf("remove non-existent: got %v, want ErrNotFound", err)
	}
}

func TestGetUnicastAddresses(t *testing.T) {
	t.Parallel()

	n := NewNetIf()
	_ = n.AddUnicastAddress(UnicastAddress{Address: linkLocal1()})
	_ = n.AddUnicastAddress(UnicastAddress{Address: linkLocal2()})

	addrs := n.GetUnicastAddresses()
	if len(addrs) != 2 {
		t.Fatalf("GetUnicastAddresses: got %d, want 2", len(addrs))
	}
}

func TestFindUnicastAddress(t *testing.T) {
	t.Parallel()

	n := NewNetIf()
	_ = n.AddUnicastAddress(UnicastAddress{
		Address:      linkLocal1(),
		PrefixLength: 64,
		Origin:       OriginSlaac,
		MeshLocal:    true,
	})

	found := n.FindUnicastAddress(linkLocal1())
	if found == nil {
		t.Fatal("FindUnicastAddress returned nil for existing address")
	}
	if found.Origin != OriginSlaac {
		t.Errorf("Origin = %d, want OriginSlaac", found.Origin)
	}
	if !found.MeshLocal {
		t.Error("MeshLocal should be true")
	}

	if n.FindUnicastAddress(linkLocal2()) != nil {
		t.Error("FindUnicastAddress should return nil for missing address")
	}
}

// ---------------------------------------------------------------------------
// Multicast address management
// ---------------------------------------------------------------------------

func TestAddMulticastAddress(t *testing.T) {
	t.Parallel()

	n := NewNetIf()
	maddr := MulticastAddress{Address: AllNodesLinkLocal, Origin: OriginThread}

	if err := n.AddMulticastAddress(maddr); err != nil {
		t.Fatalf("AddMulticastAddress: %v", err)
	}
	if !n.HasMulticastAddress(AllNodesLinkLocal) {
		t.Error("multicast address should be present after add")
	}
}

func TestAddMulticastAddressDuplicate(t *testing.T) {
	t.Parallel()

	n := NewNetIf()
	maddr := MulticastAddress{Address: AllNodesLinkLocal, Origin: OriginThread}
	_ = n.AddMulticastAddress(maddr)

	if err := n.AddMulticastAddress(maddr); err != errors.ErrAlready {
		t.Errorf("duplicate add: got %v, want ErrAlready", err)
	}
}

func TestAddMulticastAddressInvalid(t *testing.T) {
	t.Parallel()

	n := NewNetIf()
	bad := MulticastAddress{Address: linkLocal1()} // not multicast (not ff...)

	if err := n.AddMulticastAddress(bad); err != errors.ErrInvalidArgs {
		t.Errorf("non-multicast add: got %v, want ErrInvalidArgs", err)
	}
}

func TestRemoveMulticastAddress(t *testing.T) {
	t.Parallel()

	n := NewNetIf()
	_ = n.AddMulticastAddress(MulticastAddress{Address: AllNodesLinkLocal})

	if err := n.RemoveMulticastAddress(AllNodesLinkLocal); err != nil {
		t.Fatalf("RemoveMulticastAddress: %v", err)
	}
	if n.HasMulticastAddress(AllNodesLinkLocal) {
		t.Error("multicast address should not be present after remove")
	}
}

func TestRemoveMulticastAddressNotFound(t *testing.T) {
	t.Parallel()

	n := NewNetIf()
	if err := n.RemoveMulticastAddress(AllNodesLinkLocal); err != errors.ErrNotFound {
		t.Errorf("remove non-existent: got %v, want ErrNotFound", err)
	}
}

func TestIsMulticastSubscribed(t *testing.T) {
	t.Parallel()

	n := NewNetIf()
	_ = n.AddMulticastAddress(MulticastAddress{Address: AllRoutersLinkLocal})

	if !n.IsMulticastSubscribed(AllRoutersLinkLocal) {
		t.Error("IsMulticastSubscribed should return true")
	}
	if n.IsMulticastSubscribed(AllNodesLinkLocal) {
		t.Error("IsMulticastSubscribed should return false for unsubscribed")
	}
}

// ---------------------------------------------------------------------------
// Well-known multicast addresses
// ---------------------------------------------------------------------------

func TestWellKnownMulticastAddresses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr [16]byte
		last byte
	}{
		{"AllNodesLinkLocal", AllNodesLinkLocal, 0x01},
		{"AllRoutersLinkLocal", AllRoutersLinkLocal, 0x02},
		{"AllNodesRealmLocal", AllNodesRealmLocal, 0x01},
		{"AllRoutersRealmLocal", AllRoutersRealmLocal, 0x02},
		{"AllMLENodesLinkLocal", AllMLENodesLinkLocal, 0xfc},
		{"AllMLENodesRealmLocal", AllMLENodesRealmLocal, 0xfc},
		{"AllMLDv2Routers", AllMLDv2Routers, 0x16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.addr[0] != 0xff {
				t.Errorf("first byte = 0x%02x, want 0xff", tt.addr[0])
			}
			if tt.addr[15] != tt.last {
				t.Errorf("last byte = 0x%02x, want 0x%02x", tt.addr[15], tt.last)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Subscribe / unsubscribe all-nodes / all-routers
// ---------------------------------------------------------------------------

func TestSubscribeAllNodesMulticast(t *testing.T) {
	t.Parallel()

	n := NewNetIf()
	n.SubscribeAllNodesMulticast()

	if !n.HasMulticastAddress(AllNodesLinkLocal) {
		t.Error("should be subscribed to AllNodesLinkLocal")
	}
	if !n.HasMulticastAddress(AllNodesRealmLocal) {
		t.Error("should be subscribed to AllNodesRealmLocal")
	}

	// Idempotent — calling again should not duplicate.
	countBefore := len(n.GetMulticastAddresses())
	n.SubscribeAllNodesMulticast()
	if len(n.GetMulticastAddresses()) != countBefore {
		t.Error("double subscribe should not add duplicates")
	}
}

func TestSubscribeAllRoutersMulticast(t *testing.T) {
	t.Parallel()

	n := NewNetIf()
	n.SubscribeAllRoutersMulticast()

	if !n.HasMulticastAddress(AllRoutersLinkLocal) {
		t.Error("should be subscribed to AllRoutersLinkLocal")
	}
	if !n.HasMulticastAddress(AllRoutersRealmLocal) {
		t.Error("should be subscribed to AllRoutersRealmLocal")
	}
}

func TestUnsubscribeAllRoutersMulticast(t *testing.T) {
	t.Parallel()

	n := NewNetIf()
	n.SubscribeAllRoutersMulticast()
	n.UnsubscribeAllRoutersMulticast()

	if n.HasMulticastAddress(AllRoutersLinkLocal) {
		t.Error("should not be subscribed to AllRoutersLinkLocal")
	}
	if n.HasMulticastAddress(AllRoutersRealmLocal) {
		t.Error("should not be subscribed to AllRoutersRealmLocal")
	}

	// Unsubscribe again should be no-op.
	n.UnsubscribeAllRoutersMulticast()
}

// ---------------------------------------------------------------------------
// State changed callback
// ---------------------------------------------------------------------------

func TestStateChangedCallback(t *testing.T) {
	t.Parallel()

	n := NewNetIf()
	callCount := 0
	n.SetStateChangedCallback(func() { callCount++ })

	_ = n.AddUnicastAddress(UnicastAddress{Address: linkLocal1()})
	if callCount != 1 {
		t.Errorf("callCount after add unicast = %d, want 1", callCount)
	}

	_ = n.RemoveUnicastAddress(linkLocal1())
	if callCount != 2 {
		t.Errorf("callCount after remove unicast = %d, want 2", callCount)
	}

	_ = n.AddMulticastAddress(MulticastAddress{Address: AllNodesLinkLocal})
	if callCount != 3 {
		t.Errorf("callCount after add multicast = %d, want 3", callCount)
	}

	_ = n.RemoveMulticastAddress(AllNodesLinkLocal)
	if callCount != 4 {
		t.Errorf("callCount after remove multicast = %d, want 4", callCount)
	}

	n.SubscribeAllNodesMulticast()
	if callCount != 5 {
		t.Errorf("callCount after subscribe all nodes = %d, want 5", callCount)
	}
}

func TestNoCallbackOnError(t *testing.T) {
	t.Parallel()

	n := NewNetIf()
	callCount := 0
	n.SetStateChangedCallback(func() { callCount++ })

	// Remove non-existent should not trigger callback.
	_ = n.RemoveUnicastAddress(linkLocal1())
	if callCount != 0 {
		t.Errorf("callCount after failed remove = %d, want 0", callCount)
	}

	// Duplicate add should not trigger callback.
	_ = n.AddUnicastAddress(UnicastAddress{Address: linkLocal1()})
	callCount = 0
	_ = n.AddUnicastAddress(UnicastAddress{Address: linkLocal1()})
	if callCount != 0 {
		t.Errorf("callCount after duplicate add = %d, want 0", callCount)
	}
}

// ---------------------------------------------------------------------------
// GetLinkLocalAddress
// ---------------------------------------------------------------------------

func TestGetLinkLocalAddress(t *testing.T) {
	t.Parallel()

	n := NewNetIf()

	// No addresses — should return zero.
	if n.GetLinkLocalAddress() != ([16]byte{}) {
		t.Error("expected zero address when no link-local present")
	}

	// Add a global, then a link-local.
	_ = n.AddUnicastAddress(UnicastAddress{Address: global1()})
	_ = n.AddUnicastAddress(UnicastAddress{Address: linkLocal1()})

	got := n.GetLinkLocalAddress()
	if got != linkLocal1() {
		t.Errorf("GetLinkLocalAddress = %v, want %v", got, linkLocal1())
	}
}

// ---------------------------------------------------------------------------
// GetAddressCount
// ---------------------------------------------------------------------------

func TestGetAddressCount(t *testing.T) {
	t.Parallel()

	n := NewNetIf()
	if n.GetAddressCount() != 0 {
		t.Errorf("empty interface count = %d, want 0", n.GetAddressCount())
	}

	_ = n.AddUnicastAddress(UnicastAddress{Address: linkLocal1()})
	_ = n.AddUnicastAddress(UnicastAddress{Address: linkLocal2()})
	_ = n.AddMulticastAddress(MulticastAddress{Address: AllNodesLinkLocal})

	if n.GetAddressCount() != 3 {
		t.Errorf("count = %d, want 3", n.GetAddressCount())
	}

	_ = n.RemoveUnicastAddress(linkLocal1())
	if n.GetAddressCount() != 2 {
		t.Errorf("count after remove = %d, want 2", n.GetAddressCount())
	}
}

// ---------------------------------------------------------------------------
// Origin filtering
// ---------------------------------------------------------------------------

func TestOriginFiltering(t *testing.T) {
	t.Parallel()

	n := NewNetIf()
	_ = n.AddUnicastAddress(UnicastAddress{Address: linkLocal1(), Origin: OriginThread})
	_ = n.AddUnicastAddress(UnicastAddress{Address: linkLocal2(), Origin: OriginSlaac})
	_ = n.AddUnicastAddress(UnicastAddress{Address: global1(), Origin: OriginManual})

	addrs := n.GetUnicastAddresses()
	originCounts := map[AddressOrigin]int{}
	for _, a := range addrs {
		originCounts[a.Origin]++
	}

	if originCounts[OriginThread] != 1 {
		t.Errorf("Thread count = %d, want 1", originCounts[OriginThread])
	}
	if originCounts[OriginSlaac] != 1 {
		t.Errorf("Slaac count = %d, want 1", originCounts[OriginSlaac])
	}
	if originCounts[OriginManual] != 1 {
		t.Errorf("Manual count = %d, want 1", originCounts[OriginManual])
	}
}
