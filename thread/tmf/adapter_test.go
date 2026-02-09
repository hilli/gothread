// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tmf

import (
	"testing"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/routing"
)

// ---------------------------------------------------------------------------
// Compile-time interface check
// ---------------------------------------------------------------------------

var _ LeaderRouterTable = (*RouterTableAdapter)(nil)

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func newAdapter() *RouterTableAdapter {
	return NewRouterTableAdapter(routing.NewRouterTable())
}

// ---------------------------------------------------------------------------
// RouterTableOps base methods
// ---------------------------------------------------------------------------

func TestAdapterClear(t *testing.T) {
	t.Parallel()
	a := newAdapter()

	_, _ = a.AllocateWithID(3)
	a.Clear()

	set := a.GetRouterIDSet()
	if set.Contains(3) {
		t.Error("router ID 3 should not be present after Clear")
	}
}

func TestAdapterAllocateWithID(t *testing.T) {
	t.Parallel()
	a := newAdapter()

	rloc16, err := a.AllocateWithID(5)
	if err != nil {
		t.Fatalf("AllocateWithID(5) error: %v", err)
	}
	want := mle.RLOC16FromRouterID(5)
	if rloc16 != want {
		t.Errorf("rloc16 = 0x%04x, want 0x%04x", rloc16, want)
	}

	// Duplicate should fail.
	_, err = a.AllocateWithID(5)
	if err == nil {
		t.Error("duplicate AllocateWithID(5) should fail")
	}
}

func TestAdapterAllocate(t *testing.T) {
	t.Parallel()
	a := newAdapter()

	routerID, rloc16, err := a.Allocate()
	if err != nil {
		t.Fatalf("Allocate error: %v", err)
	}
	want := mle.RLOC16FromRouterID(routerID)
	if rloc16 != want {
		t.Errorf("rloc16 = 0x%04x, want 0x%04x", rloc16, want)
	}
	idSet := a.GetRouterIDSet()
	if !idSet.Contains(routerID) {
		t.Errorf("router ID %d should be in the set", routerID)
	}
}

func TestAdapterGetActiveRouterCount(t *testing.T) {
	t.Parallel()
	a := newAdapter()

	if a.GetActiveRouterCount() != 0 {
		t.Errorf("initial active count = %d, want 0", a.GetActiveRouterCount())
	}

	// AllocateWithID creates a router in StateInvalid, so the active count
	// should remain 0 — active means StateValid.
	_, _ = a.AllocateWithID(1)
	if a.GetActiveRouterCount() != 0 {
		t.Errorf("after allocate, active count = %d, want 0 (new routers are StateInvalid)", a.GetActiveRouterCount())
	}
}

func TestAdapterGetRouterIDSet(t *testing.T) {
	t.Parallel()
	a := newAdapter()

	_, _ = a.AllocateWithID(2)
	_, _ = a.AllocateWithID(10)

	set := a.GetRouterIDSet()
	if !set.Contains(2) {
		t.Error("set should contain router ID 2")
	}
	if !set.Contains(10) {
		t.Error("set should contain router ID 10")
	}
	if set.Contains(5) {
		t.Error("set should not contain router ID 5")
	}
}

func TestAdapterGetRouterIDSequence(t *testing.T) {
	t.Parallel()
	a := newAdapter()

	seq0 := a.GetRouterIDSequence()
	_, _ = a.AllocateWithID(1)
	seq1 := a.GetRouterIDSequence()

	if seq1 <= seq0 {
		t.Errorf("sequence should increment after allocation: before=%d, after=%d", seq0, seq1)
	}
}

// ---------------------------------------------------------------------------
// LeaderRouterTable extension methods
// ---------------------------------------------------------------------------

func TestAdapterAllocateWithIDForRouter(t *testing.T) {
	t.Parallel()
	a := newAdapter()

	extAddr := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	rloc16, err := a.AllocateWithIDForRouter(7, extAddr)
	if err != nil {
		t.Fatalf("AllocateWithIDForRouter error: %v", err)
	}
	want := mle.RLOC16FromRouterID(7)
	if rloc16 != want {
		t.Errorf("rloc16 = 0x%04x, want 0x%04x", rloc16, want)
	}

	// The ext address should be findable.
	found, ok := a.FindRLOC16ByExtAddress(extAddr)
	if !ok {
		t.Fatal("FindRLOC16ByExtAddress should find the router")
	}
	if found != rloc16 {
		t.Errorf("found rloc16 = 0x%04x, want 0x%04x", found, rloc16)
	}
}

func TestAdapterAllocateWithIDForRouterDuplicate(t *testing.T) {
	t.Parallel()
	a := newAdapter()

	extAddr := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	_, _ = a.AllocateWithIDForRouter(3, extAddr)

	_, err := a.AllocateWithIDForRouter(3, types.ExtAddress{0xFF})
	if err == nil {
		t.Error("duplicate AllocateWithIDForRouter should fail")
	}
}

func TestAdapterAllocateForRouter(t *testing.T) {
	t.Parallel()
	a := newAdapter()

	extAddr := types.ExtAddress{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00, 0x01}
	routerID, rloc16, err := a.AllocateForRouter(extAddr)
	if err != nil {
		t.Fatalf("AllocateForRouter error: %v", err)
	}
	want := mle.RLOC16FromRouterID(routerID)
	if rloc16 != want {
		t.Errorf("rloc16 = 0x%04x, want 0x%04x", rloc16, want)
	}

	// Ext address should be findable.
	found, ok := a.FindRLOC16ByExtAddress(extAddr)
	if !ok {
		t.Fatal("FindRLOC16ByExtAddress should find the router")
	}
	if found != rloc16 {
		t.Errorf("found rloc16 = 0x%04x, want 0x%04x", found, rloc16)
	}
}

func TestAdapterFindRLOC16ByExtAddressNotFound(t *testing.T) {
	t.Parallel()
	a := newAdapter()

	_, ok := a.FindRLOC16ByExtAddress(types.ExtAddress{0xFF})
	if ok {
		t.Error("FindRLOC16ByExtAddress should return false for empty table")
	}
}

func TestAdapterRelease(t *testing.T) {
	t.Parallel()
	a := newAdapter()

	_, _ = a.AllocateWithIDForRouter(10, types.ExtAddress{0x01})

	err := a.Release(10)
	if err != nil {
		t.Fatalf("Release error: %v", err)
	}

	set := a.GetRouterIDSet()
	if set.Contains(10) {
		t.Error("router ID 10 should not be in set after Release")
	}
}

func TestAdapterReleaseNonExistent(t *testing.T) {
	t.Parallel()
	a := newAdapter()

	err := a.Release(42)
	if err == nil {
		t.Error("Release of non-existent router should fail")
	}
}

func TestAdapterValidateOwnership(t *testing.T) {
	t.Parallel()
	a := newAdapter()

	extAddr := types.ExtAddress{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00, 0x01}
	rloc16, _ := a.AllocateWithIDForRouter(5, extAddr)

	if !a.ValidateOwnership(rloc16, extAddr) {
		t.Error("ValidateOwnership should return true for matching address")
	}

	wrongAddr := types.ExtAddress{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	if a.ValidateOwnership(rloc16, wrongAddr) {
		t.Error("ValidateOwnership should return false for non-matching address")
	}
}

func TestAdapterValidateOwnershipNotFound(t *testing.T) {
	t.Parallel()
	a := newAdapter()

	if a.ValidateOwnership(0x0400, types.ExtAddress{0x01}) {
		t.Error("ValidateOwnership should return false for non-existent router")
	}
}

// ---------------------------------------------------------------------------
// Integration: adapter with LeaderService
// ---------------------------------------------------------------------------

func TestAdapterWithLeaderServiceRoundtrip(t *testing.T) {
	t.Parallel()

	// Create a real routing.RouterTable, wrap it with the adapter, and use
	// it with a LeaderService to verify the full integration path.
	a := newAdapter()

	engine, _ := newLoopbackEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, a, 32)
	defer ls.Stop()

	// Allocate via the adapter directly and verify LeaderService can
	// respond to clients using the same table.
	extAddr := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	rloc16, err := a.AllocateWithIDForRouter(5, extAddr)
	if err != nil {
		t.Fatalf("AllocateWithIDForRouter error: %v", err)
	}

	// The router should be findable.
	found, ok := a.FindRLOC16ByExtAddress(extAddr)
	if !ok || found != rloc16 {
		t.Fatalf("FindRLOC16ByExtAddress = (%d, %v), want (%d, true)", found, ok, rloc16)
	}

	// Validate ownership.
	if !a.ValidateOwnership(rloc16, extAddr) {
		t.Error("ValidateOwnership should return true")
	}

	// Release and verify.
	if err := a.Release(5); err != nil {
		t.Fatalf("Release error: %v", err)
	}
	_, ok = a.FindRLOC16ByExtAddress(extAddr)
	if ok {
		t.Error("FindRLOC16ByExtAddress should return false after Release")
	}
}
