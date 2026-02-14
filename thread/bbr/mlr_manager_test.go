// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package bbr

import (
	"testing"

	"github.com/hilli/gothread/backbone"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Constructor tests
// ---------------------------------------------------------------------------

func TestNewMlrManager(t *testing.T) {
	mm := NewMlrManager()

	if entries := mm.GetEntries(); len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
	if reg := mm.GetRegisteredAddresses(); len(reg) != 0 {
		t.Fatalf("expected 0 registered addresses, got %d", len(reg))
	}
	// Default max entries should allow at least defaultMaxMlrEntries additions.
	for i := byte(0); i < defaultMaxMlrEntries; i++ {
		if err := mm.AddAddress(testMulticastAddr(i + 1)); err != nil {
			t.Fatalf("AddAddress(%d) failed unexpectedly: %v", i+1, err)
		}
	}
	if len(mm.GetEntries()) != defaultMaxMlrEntries {
		t.Fatalf("expected %d entries, got %d", defaultMaxMlrEntries, len(mm.GetEntries()))
	}
}

func TestMlrManagerWithOptions(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(
		WithMaxEntries(3),
		WithMlrLeaderProvider(leader),
	)

	// Verify max entries is respected.
	for i := byte(0); i < 3; i++ {
		if err := mm.AddAddress(testMulticastAddr(i + 1)); err != nil {
			t.Fatalf("AddAddress(%d) failed: %v", i+1, err)
		}
	}
	if err := mm.AddAddress(testMulticastAddr(4)); err == nil {
		t.Fatal("expected error when exceeding max entries")
	}

	// Verify leader provider is set (timeout should come from config).
	entries := mm.GetEntries()
	for _, e := range entries {
		if e.Timeout != leader.config.MlrTimeout {
			t.Fatalf("expected timeout %d from leader config, got %d", leader.config.MlrTimeout, e.Timeout)
		}
	}
}

func TestMlrManagerWithMaxEntries_ZeroIgnored(t *testing.T) {
	mm := NewMlrManager(WithMaxEntries(0))

	// Zero should be ignored, keeping the default.
	for i := byte(0); i < defaultMaxMlrEntries; i++ {
		if err := mm.AddAddress(testMulticastAddr(i + 1)); err != nil {
			t.Fatalf("AddAddress(%d) failed: %v", i+1, err)
		}
	}
}

func TestMlrManagerWithMaxEntries_NegativeIgnored(t *testing.T) {
	mm := NewMlrManager(WithMaxEntries(-5))

	// Negative should be ignored, keeping the default.
	if err := mm.AddAddress(testMulticastAddr(1)); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// AddAddress without a leader provider (nil leader, zero timeout)
// ---------------------------------------------------------------------------

func TestMlrManager_AddAddress_NilLeader(t *testing.T) {
	mm := NewMlrManager()

	if err := mm.AddAddress(testMulticastAddr(1)); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}
	entries := mm.GetEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Timeout != 0 {
		t.Fatalf("expected timeout 0 with nil leader, got %d", entries[0].Timeout)
	}
	if entries[0].State != MlrStateToRegister {
		t.Fatalf("expected MlrStateToRegister, got %s", entries[0].State)
	}
}

// ---------------------------------------------------------------------------
// UpdateRegistration with nil leader
// ---------------------------------------------------------------------------

func TestMlrManager_UpdateRegistration_NilLeader(t *testing.T) {
	mm := NewMlrManager()
	_ = mm.AddAddress(testMulticastAddr(1))

	addrs := mm.UpdateRegistration()
	if addrs != nil {
		t.Fatal("expected nil from UpdateRegistration with nil leader")
	}
}

// ---------------------------------------------------------------------------
// RegisterMulticastListeners with nil leader
// ---------------------------------------------------------------------------

func TestMlrManager_RegisterMulticastListeners_NilLeader(t *testing.T) {
	mm := NewMlrManager()
	_ = mm.AddAddress(testMulticastAddr(1))

	err := mm.RegisterMulticastListeners([][16]byte{testMulticastAddr(1)})
	if err == nil {
		t.Fatal("expected error with nil leader")
	}
}

// ---------------------------------------------------------------------------
// HandleMlrResponse updates timeout from leader
// ---------------------------------------------------------------------------

func TestMlrManager_HandleMlrResponse_UpdatesTimeout(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	_ = mm.AddAddress(testMulticastAddr(1))
	mm.UpdateRegistration()

	// Change the leader config timeout before response.
	leader.config.MlrTimeout = 7200
	mm.HandleMlrResponse(MlrStatusSuccess, nil)

	entries := mm.GetEntries()
	if entries[0].Timeout != 7200 {
		t.Fatalf("expected updated timeout 7200, got %d", entries[0].Timeout)
	}
}

// ---------------------------------------------------------------------------
// HandleBackboneRouterPrimaryUpdate with LeaderStateAdded
// ---------------------------------------------------------------------------

func TestMlrManager_HandleBackboneRouterPrimaryUpdate_Added(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	_ = mm.AddAddress(testMulticastAddr(1))
	mm.UpdateRegistration()
	mm.HandleMlrResponse(MlrStatusSuccess, nil)

	mm.HandleBackboneRouterPrimaryUpdate(backbone.LeaderStateAdded)

	for _, e := range mm.GetEntries() {
		if e.State != MlrStateToRegister {
			t.Fatalf("expected MlrStateToRegister after LeaderStateAdded, got %s", e.State)
		}
	}
}

// ---------------------------------------------------------------------------
// HandleBackboneRouterPrimaryUpdate does not affect non-registered entries
// ---------------------------------------------------------------------------

func TestMlrManager_HandleBackboneRouterPrimaryUpdate_OnlyRegistered(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	// addr1 will be registered, addr2 stays in ToRegister.
	_ = mm.AddAddress(testMulticastAddr(1))
	mm.UpdateRegistration()
	mm.HandleMlrResponse(MlrStatusSuccess, nil)

	_ = mm.AddAddress(testMulticastAddr(2))
	// addr2 is in ToRegister state.

	mm.HandleBackboneRouterPrimaryUpdate(backbone.LeaderStateAdded)

	entries := mm.GetEntries()
	for _, e := range entries {
		if e.State != MlrStateToRegister {
			t.Fatalf("all entries should be ToRegister, got %s for %x", e.State, e.Address)
		}
	}
}

// ---------------------------------------------------------------------------
// Timer re-registration marks entries for re-registration
// ---------------------------------------------------------------------------

func TestMlrManager_HandleTimer_ReregistrationMarksEntries(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	_ = mm.AddAddress(testMulticastAddr(1))
	_ = mm.AddAddress(testMulticastAddr(2))
	mm.UpdateRegistration()

	// Successful registration first.
	mm.HandleMlrResponse(MlrStatusSuccess, nil)
	for _, e := range mm.GetEntries() {
		if e.State != MlrStateRegistered {
			t.Fatalf("expected MlrStateRegistered, got %s", e.State)
		}
	}

	// Trigger re-registration via BBR update.
	mm.HandleBackboneRouterPrimaryUpdate(backbone.LeaderStateToTriggerRereg)

	// Tick until timer fires.
	fired := false
	for i := 0; i < 100; i++ {
		if mm.HandleTimer() {
			fired = true
			break
		}
	}
	if !fired {
		t.Fatal("expected timer to fire")
	}
}

// ---------------------------------------------------------------------------
// FTD: AddChildMulticast respects max entries limit
// ---------------------------------------------------------------------------

func TestMlrManager_AddChildMulticast_MaxEntries(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader), WithMaxEntries(1))

	addr1 := ip6.Address(testMulticastAddr(1))
	addr2 := ip6.Address(testMulticastAddr(2))

	mm.AddChildMulticast(0x0401, []ip6.Address{addr1, addr2})

	entries := mm.GetEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (max entries=1), got %d", len(entries))
	}
	if entries[0].Address != addr1 {
		t.Fatalf("expected first address to be added, got %x", entries[0].Address)
	}
}

// ---------------------------------------------------------------------------
// FTD: RemoveChildMulticast for non-existent child
// ---------------------------------------------------------------------------

func TestMlrManager_RemoveChildMulticast_NotFound(t *testing.T) {
	mm := NewMlrManager()
	// Should not panic.
	mm.RemoveChildMulticast(0xFFFF)
}
