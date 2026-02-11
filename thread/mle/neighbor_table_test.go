// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"testing"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
)

func TestNewNeighborTable(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()
	if nt == nil {
		t.Fatal("NewNeighborTable returned nil")
	}
	if nt.GetChildCount() != 0 {
		t.Errorf("GetChildCount = %d, want 0", nt.GetChildCount())
	}
	if nt.GetActiveRouterCount() != 0 {
		t.Errorf("GetActiveRouterCount = %d, want 0", nt.GetActiveRouterCount())
	}
}

func TestNeighborTable_ChildOperations(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()
	addr := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	child := nt.GetNewChild()
	if child == nil {
		t.Fatal("GetNewChild returned nil")
	}
	child.MacAddr = addr
	child.State = StateValid
	child.RLOC16 = 0x0401

	if nt.GetChildCount() != 1 {
		t.Errorf("GetChildCount = %d, want 1", nt.GetChildCount())
	}
	if nt.GetValidChildCount() != 1 {
		t.Errorf("GetValidChildCount = %d, want 1", nt.GetValidChildCount())
	}
}

func TestNeighborTable_FindChildByExtAddress(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()
	addr := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}

	if nt.FindChildByExtAddress(addr) != nil {
		t.Error("expected nil for empty table")
	}

	child := nt.GetNewChild()
	child.MacAddr = addr
	child.State = StateValid

	found := nt.FindChildByExtAddress(addr)
	if found == nil {
		t.Fatal("FindChildByExtAddress returned nil for known address")
	}
	if found.MacAddr != addr {
		t.Errorf("got %v, want %v", found.MacAddr, addr)
	}
}

func TestNeighborTable_FindChildByRLOC16(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	child := nt.GetNewChild()
	child.State = StateValid
	child.RLOC16 = 0x0403

	found := nt.FindChildByRLOC16(0x0403)
	if found == nil {
		t.Fatal("FindChildByRLOC16 returned nil")
	}
	if found.RLOC16 != 0x0403 {
		t.Errorf("RLOC16 = 0x%04X, want 0x0403", found.RLOC16)
	}

	if nt.FindChildByRLOC16(0x0404) != nil {
		t.Error("expected nil for unknown RLOC16")
	}
}

func TestNeighborTable_FindChildByIP6Address(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	child := nt.GetNewChild()
	child.State = StateValid
	child.MacAddr = types.ExtAddress{0x01}
	addr := ip6.Address{0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	child.AddIP6Address(addr)

	found := nt.FindChildByIP6Address(addr)
	if found == nil {
		t.Fatal("FindChildByIP6Address returned nil")
	}
	if found.MacAddr != child.MacAddr {
		t.Errorf("wrong child returned")
	}

	other := ip6.Address{0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x99}
	if nt.FindChildByIP6Address(other) != nil {
		t.Error("expected nil for unknown address")
	}
}

func TestNeighborTable_FindChildByMeshLocalIID(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	child := nt.GetNewChild()
	child.State = StateValid
	child.MacAddr = types.ExtAddress{0x01}
	child.MeshLocalIID = ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	found := nt.FindChildByMeshLocalIID(child.MeshLocalIID)
	if found == nil {
		t.Fatal("FindChildByMeshLocalIID returned nil")
	}
	if found.MacAddr != child.MacAddr {
		t.Errorf("wrong child returned")
	}

	other := ip6.InterfaceIdentifier{0xFF}
	if nt.FindChildByMeshLocalIID(other) != nil {
		t.Error("expected nil for unknown IID")
	}
}

func TestNeighborTable_RemoveChild(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	var events []NeighborTableEvent
	nt.RegisterCallback(func(event NeighborTableEvent, _ *Neighbor) {
		events = append(events, event)
	})

	child := nt.GetNewChild()
	child.MacAddr = types.ExtAddress{0x01}
	child.State = StateValid

	nt.RemoveChild(child)

	if child.State != StateInvalid {
		t.Errorf("child state = %v, want StateInvalid", child.State)
	}
	if nt.GetChildCount() != 0 {
		t.Errorf("GetChildCount = %d, want 0", nt.GetChildCount())
	}
	if len(events) != 1 || events[0] != NeighborTableEventChildRemoved {
		t.Errorf("events = %v, want [ChildRemoved]", events)
	}
}

func TestNeighborTable_SignalChildAdded(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	var events []NeighborTableEvent
	nt.RegisterCallback(func(event NeighborTableEvent, _ *Neighbor) {
		events = append(events, event)
	})

	child := nt.GetNewChild()
	child.MacAddr = types.ExtAddress{0x01}
	child.State = StateValid
	nt.SignalChildAdded(child)

	if len(events) != 1 || events[0] != NeighborTableEventChildAdded {
		t.Errorf("events = %v, want [ChildAdded]", events)
	}
}

func TestNeighborTable_SignalChildModeChanged(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	var events []NeighborTableEvent
	nt.RegisterCallback(func(event NeighborTableEvent, _ *Neighbor) {
		events = append(events, event)
	})

	child := nt.GetNewChild()
	child.MacAddr = types.ExtAddress{0x01}
	child.State = StateValid
	nt.SignalChildModeChanged(child)

	if len(events) != 1 || events[0] != NeighborTableEventChildModeChanged {
		t.Errorf("events = %v, want [ChildModeChanged]", events)
	}
}

func TestNeighborTable_RouterOperations(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	// GetRouter with valid ID.
	r := nt.GetRouter(5)
	if r == nil {
		t.Fatal("GetRouter(5) returned nil")
	}
	if r.State != StateInvalid {
		t.Errorf("router state = %v, want StateInvalid", r.State)
	}

	// GetRouter with invalid ID.
	if nt.GetRouter(InvalidRouterID) != nil {
		t.Error("GetRouter(InvalidRouterID) should return nil")
	}
	if nt.GetRouter(MaxRouterID+1) != nil {
		t.Error("GetRouter(64) should return nil")
	}
}

func TestNeighborTable_AllocateRouter(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	r := nt.AllocateRouter(10)
	if r == nil {
		t.Fatal("AllocateRouter returned nil")
	}
	expectedRLOC := RLOC16FromRouterID(10)
	if r.RLOC16 != expectedRLOC {
		t.Errorf("RLOC16 = 0x%04X, want 0x%04X", r.RLOC16, expectedRLOC)
	}

	// Set state so it becomes active.
	r.State = StateValid
	r.MacAddr = types.ExtAddress{0x10}

	if nt.GetActiveRouterCount() != 1 {
		t.Errorf("GetActiveRouterCount = %d, want 1", nt.GetActiveRouterCount())
	}

	// Invalid router ID.
	if nt.AllocateRouter(InvalidRouterID) != nil {
		t.Error("AllocateRouter with InvalidRouterID should return nil")
	}
}

func TestNeighborTable_SignalRouterAdded(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	var events []NeighborTableEvent
	nt.RegisterCallback(func(event NeighborTableEvent, _ *Neighbor) {
		events = append(events, event)
	})

	r := nt.AllocateRouter(5)
	r.State = StateValid
	r.MacAddr = types.ExtAddress{0x05}
	nt.SignalRouterAdded(r)

	if len(events) != 1 || events[0] != NeighborTableEventRouterAdded {
		t.Errorf("events = %v, want [RouterAdded]", events)
	}
}

func TestNeighborTable_ReleaseRouter(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	var events []NeighborTableEvent
	nt.RegisterCallback(func(event NeighborTableEvent, _ *Neighbor) {
		events = append(events, event)
	})

	r := nt.AllocateRouter(7)
	r.State = StateValid
	r.MacAddr = types.ExtAddress{0x07}

	nt.ReleaseRouter(7)

	released := nt.GetRouter(7)
	if released.State != StateInvalid {
		t.Errorf("router state = %v, want StateInvalid", released.State)
	}
	if nt.GetActiveRouterCount() != 0 {
		t.Errorf("GetActiveRouterCount = %d, want 0", nt.GetActiveRouterCount())
	}
	if len(events) != 1 || events[0] != NeighborTableEventRouterRemoved {
		t.Errorf("events = %v, want [RouterRemoved]", events)
	}
}

func TestNeighborTable_ReleaseRouter_Invalid(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	var events []NeighborTableEvent
	nt.RegisterCallback(func(event NeighborTableEvent, _ *Neighbor) {
		events = append(events, event)
	})

	// Releasing an already-invalid router should be a no-op.
	nt.ReleaseRouter(7)
	if len(events) != 0 {
		t.Errorf("events = %v, want empty", events)
	}

	// Releasing out-of-range should be a no-op.
	nt.ReleaseRouter(InvalidRouterID)
	if len(events) != 0 {
		t.Errorf("events = %v, want empty", events)
	}
}

func TestNeighborTable_GetRouterByRLOC16(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	r := nt.AllocateRouter(3)
	r.State = StateValid
	rloc := RLOC16FromRouterID(3)

	found := nt.GetRouterByRLOC16(rloc)
	if found == nil {
		t.Fatal("GetRouterByRLOC16 returned nil")
	}
	if found != r {
		t.Error("returned different router")
	}

	// Child RLOC16 should return nil.
	if nt.GetRouterByRLOC16(rloc|0x01) != nil {
		t.Error("GetRouterByRLOC16 should return nil for child RLOC16")
	}

	// Unknown router.
	if nt.GetRouterByRLOC16(RLOC16FromRouterID(50)) != nil {
		t.Error("GetRouterByRLOC16 should return nil for unknown router")
	}
}

func TestNeighborTable_FindRouterByExtAddress(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()
	addr := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}

	if nt.FindRouterByExtAddress(addr) != nil {
		t.Error("expected nil for empty table")
	}

	r := nt.AllocateRouter(20)
	r.State = StateValid
	r.MacAddr = addr

	found := nt.FindRouterByExtAddress(addr)
	if found == nil {
		t.Fatal("FindRouterByExtAddress returned nil")
	}
	if found.MacAddr != addr {
		t.Errorf("got %v, want %v", found.MacAddr, addr)
	}
}

func TestNeighborTable_GetValidRouterCount(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	r1 := nt.AllocateRouter(1)
	r1.State = StateValid

	r2 := nt.AllocateRouter(2)
	r2.State = StateLinkRequest // not valid

	r3 := nt.AllocateRouter(3)
	r3.State = StateValid

	if nt.GetActiveRouterCount() != 3 {
		t.Errorf("GetActiveRouterCount = %d, want 3", nt.GetActiveRouterCount())
	}
	if nt.GetValidRouterCount() != 2 {
		t.Errorf("GetValidRouterCount = %d, want 2", nt.GetValidRouterCount())
	}
}

func TestNeighborTable_ForEachRouter(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	r1 := nt.AllocateRouter(5)
	r1.State = StateValid

	r2 := nt.AllocateRouter(10)
	r2.State = StateValid

	count := 0
	nt.ForEachRouter(func(_ *Router) bool {
		count++
		return true
	})
	if count != 2 {
		t.Errorf("ForEachRouter visited %d routers, want 2", count)
	}

	// Early stop.
	count = 0
	nt.ForEachRouter(func(_ *Router) bool {
		count++
		return false
	})
	if count != 1 {
		t.Errorf("ForEachRouter with early stop visited %d routers, want 1", count)
	}
}

func TestNeighborTable_FindNeighborByExtAddress_Child(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()
	addr := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	child := nt.GetNewChild()
	child.MacAddr = addr
	child.State = StateValid

	found := nt.FindNeighborByExtAddress(addr)
	if found == nil {
		t.Fatal("FindNeighborByExtAddress returned nil")
	}
	if found.MacAddr != addr {
		t.Errorf("got %v, want %v", found.MacAddr, addr)
	}
}

func TestNeighborTable_FindNeighborByExtAddress_Router(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()
	addr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	r := nt.AllocateRouter(15)
	r.State = StateValid
	r.MacAddr = addr

	found := nt.FindNeighborByExtAddress(addr)
	if found == nil {
		t.Fatal("FindNeighborByExtAddress returned nil for router")
	}
	if found.MacAddr != addr {
		t.Errorf("got %v, want %v", found.MacAddr, addr)
	}
}

func TestNeighborTable_FindNeighborByExtAddress_NotFound(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()
	addr := types.ExtAddress{0xFF}

	if nt.FindNeighborByExtAddress(addr) != nil {
		t.Error("expected nil for unknown address")
	}
}

func TestNeighborTable_FindNeighborByRLOC16_Child(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	child := nt.GetNewChild()
	child.State = StateValid
	child.RLOC16 = 0x0401

	found := nt.FindNeighborByRLOC16(0x0401)
	if found == nil {
		t.Fatal("FindNeighborByRLOC16 returned nil for child")
	}
	if found.RLOC16 != 0x0401 {
		t.Errorf("RLOC16 = 0x%04X, want 0x0401", found.RLOC16)
	}
}

func TestNeighborTable_FindNeighborByRLOC16_Router(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	r := nt.AllocateRouter(4)
	r.State = StateValid

	rloc := RLOC16FromRouterID(4)
	found := nt.FindNeighborByRLOC16(rloc)
	if found == nil {
		t.Fatal("FindNeighborByRLOC16 returned nil for router")
	}
	if found.RLOC16 != rloc {
		t.Errorf("RLOC16 = 0x%04X, want 0x%04X", found.RLOC16, rloc)
	}
}

func TestNeighborTable_FindNeighborByRLOC16_NotFound(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	if nt.FindNeighborByRLOC16(0x9999) != nil {
		t.Error("expected nil for unknown RLOC16")
	}
}

func TestNeighborTable_Clear(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	// Add a child.
	child := nt.GetNewChild()
	child.MacAddr = types.ExtAddress{0x01}
	child.State = StateValid

	// Add a router.
	r := nt.AllocateRouter(5)
	r.State = StateValid
	r.MacAddr = types.ExtAddress{0x05}

	nt.Clear()

	if nt.GetChildCount() != 0 {
		t.Errorf("GetChildCount = %d, want 0 after Clear", nt.GetChildCount())
	}
	if nt.GetActiveRouterCount() != 0 {
		t.Errorf("GetActiveRouterCount = %d, want 0 after Clear", nt.GetActiveRouterCount())
	}
}

func TestNeighborTable_ClearRouters(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	// Add a child and a router.
	child := nt.GetNewChild()
	child.MacAddr = types.ExtAddress{0x01}
	child.State = StateValid

	r := nt.AllocateRouter(5)
	r.State = StateValid

	nt.ClearRouters()

	// Child should remain.
	if nt.GetChildCount() != 1 {
		t.Errorf("GetChildCount = %d, want 1 after ClearRouters", nt.GetChildCount())
	}
	// Routers should be gone.
	if nt.GetActiveRouterCount() != 0 {
		t.Errorf("GetActiveRouterCount = %d, want 0 after ClearRouters", nt.GetActiveRouterCount())
	}
}

func TestNeighborTable_CallbackNil(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	// No callback registered; these should not panic.
	child := nt.GetNewChild()
	child.State = StateValid
	child.MacAddr = types.ExtAddress{0x01}
	nt.SignalChildAdded(child)
	nt.SignalChildModeChanged(child)
	nt.RemoveChild(child)

	r := nt.AllocateRouter(1)
	r.State = StateValid
	nt.SignalRouterAdded(r)
	nt.ReleaseRouter(1)
}

func TestNeighborTable_GetChildTable(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	ct := nt.GetChildTable()
	if ct == nil {
		t.Fatal("GetChildTable returned nil")
	}

	// Operations through the returned ChildTable should be reflected.
	child := ct.GetNewChild()
	child.State = StateValid
	child.MacAddr = types.ExtAddress{0x01}

	if nt.GetChildCount() != 1 {
		t.Errorf("GetChildCount = %d, want 1", nt.GetChildCount())
	}
}

func TestNeighborTable_ChildPrefersOverRouter(t *testing.T) {
	t.Parallel()
	nt := NewNeighborTable()

	// When the same ext address exists as both child and router,
	// the unified lookup should return the child (searched first).
	addr := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}

	child := nt.GetNewChild()
	child.MacAddr = addr
	child.State = StateValid
	child.RLOC16 = 0x0401

	r := nt.AllocateRouter(20)
	r.State = StateValid
	r.MacAddr = addr

	found := nt.FindNeighborByExtAddress(addr)
	if found == nil {
		t.Fatal("FindNeighborByExtAddress returned nil")
	}
	// Should be the child's neighbor (child RLOC16).
	if found.RLOC16 != 0x0401 {
		t.Errorf("RLOC16 = 0x%04X, want 0x0401 (child)", found.RLOC16)
	}
}
