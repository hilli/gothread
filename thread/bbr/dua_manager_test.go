// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package bbr

import (
	"testing"

	"github.com/hilli/gothread/backbone"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Constructor & Option Tests
// ---------------------------------------------------------------------------

func TestNewDuaManager(t *testing.T) {
	dm := NewDuaManager()

	if dm.GetState() != DuaStateIdle {
		t.Fatalf("expected DuaStateIdle, got %s", dm.GetState())
	}
	if _, ok := dm.GetDuaAddress(); ok {
		t.Fatal("expected no DUA configured on new manager")
	}
}

func TestDuaManagerWithOptions(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}}

	dm := NewDuaManager(
		WithLeaderProvider(leader),
		WithIIDGenerator(gen),
		WithMaxDadCounter(5),
	)

	// Verify leader and generator are wired by generating a DUA.
	dm.UpdateDomainUnicastAddress()
	if dm.GetState() != DuaStateToRegister {
		t.Fatalf("expected DuaStateToRegister, got %s", dm.GetState())
	}
	addr, ok := dm.GetDuaAddress()
	if !ok {
		t.Fatal("expected DUA to be configured with options")
	}

	// Verify the generated IID came from our mock generator.
	a := ip6.Address(addr)
	iid := a.GetIid()
	if iid[0] != 0x01 || iid[6] != 0x07 {
		t.Fatalf("unexpected IID: %x", iid)
	}

	// Verify WithMaxDadCounter by exhausting DAD collisions.
	// dadCounter starts at 0, max is 5, so 6 duplicates should exhaust.
	for i := 0; i < 6; i++ {
		_ = dm.Register()
		dm.HandleDuaResponse(DuaStatusDuplicate)
	}
	if dm.GetState() != DuaStateIdle {
		t.Fatalf("expected DuaStateIdle after exhausting maxDadCounter=5, got %s", dm.GetState())
	}
}

// ---------------------------------------------------------------------------
// IID Generator Error Handling
// ---------------------------------------------------------------------------

func TestDuaManager_IIDGeneratorError(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{err: errors.ErrFailed}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	dm.UpdateDomainUnicastAddress()

	// IID generation failed, so no DUA should be configured.
	if _, ok := dm.GetDuaAddress(); ok {
		t.Fatal("expected no DUA when IID generation fails")
	}
	if dm.GetState() != DuaStateIdle {
		t.Fatalf("expected DuaStateIdle, got %s", dm.GetState())
	}
}

func TestDuaManager_ClearFixedIID_GeneratorError(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	fixedIID := ip6.InterfaceIdentifier{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	dm.UpdateDomainUnicastAddress()
	_ = dm.SetFixedIID(fixedIID)

	// Make generator fail, then clear fixed IID.
	gen.err = errors.ErrFailed
	dm.ClearFixedIID()

	// DUA should be removed since regeneration failed.
	if _, ok := dm.GetDuaAddress(); ok {
		t.Fatal("expected no DUA when IID regeneration fails on clear")
	}
	if dm.GetState() != DuaStateIdle {
		t.Fatalf("expected DuaStateIdle, got %s", dm.GetState())
	}
}

// ---------------------------------------------------------------------------
// SetFixedIID / ClearFixedIID Edge Cases
// ---------------------------------------------------------------------------

func TestDuaManager_SetFixedIID_BeforeDua(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	fixedIID := ip6.InterfaceIdentifier{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}

	// Set fixed IID before generating a DUA.
	if err := dm.SetFixedIID(fixedIID); err != nil {
		t.Fatalf("SetFixedIID failed: %v", err)
	}

	// Now generate the DUA — it should use the fixed IID.
	dm.UpdateDomainUnicastAddress()
	addr, ok := dm.GetDuaAddress()
	if !ok {
		t.Fatal("expected DUA to be configured")
	}
	a := ip6.Address(addr)
	if a.GetIid() != fixedIID {
		t.Fatalf("IID mismatch: got %x, want %x", a.GetIid(), fixedIID)
	}
}

func TestDuaManager_SetFixedIID_Overwrites(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	iid1 := ip6.InterfaceIdentifier{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	iid2 := ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x99}

	dm.UpdateDomainUnicastAddress()
	_ = dm.SetFixedIID(iid1)
	_ = dm.SetFixedIID(iid2)

	addr, ok := dm.GetDuaAddress()
	if !ok {
		t.Fatal("expected DUA to be configured")
	}
	a := ip6.Address(addr)
	if a.GetIid() != iid2 {
		t.Fatalf("IID mismatch: got %x, want %x", a.GetIid(), iid2)
	}
}

func TestDuaManager_ClearFixedIID_WhenNotSet(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	dm.UpdateDomainUnicastAddress()
	addrBefore, _ := dm.GetDuaAddress()

	// Clearing when no fixed IID is set should be a no-op.
	dm.ClearFixedIID()

	addrAfter, ok := dm.GetDuaAddress()
	if !ok {
		t.Fatal("expected DUA to remain configured")
	}
	if addrBefore != addrAfter {
		t.Fatal("DUA should not change when clearing unset fixed IID")
	}
}

func TestDuaManager_ClearFixedIID_NoLeader(t *testing.T) {
	dm := NewDuaManager()

	fixedIID := ip6.InterfaceIdentifier{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	_ = dm.SetFixedIID(fixedIID)

	// Should not panic with nil leader.
	dm.ClearFixedIID()
}

func TestDuaManager_ClearFixedIID_NoDomainPrefix(t *testing.T) {
	leader := &mockLeader{hasPrimary: true, hasPrefix: false}
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	// Generate DUA with prefix, then remove prefix.
	leader.hasPrefix = true
	leader.prefix = testDomainPrefix()
	dm.UpdateDomainUnicastAddress()

	fixedIID := ip6.InterfaceIdentifier{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	_ = dm.SetFixedIID(fixedIID)

	leader.hasPrefix = false
	dm.ClearFixedIID()

	// DUA should be removed since domain prefix is no longer available.
	if _, ok := dm.GetDuaAddress(); ok {
		t.Fatal("expected no DUA when domain prefix is gone")
	}
	if dm.GetState() != DuaStateIdle {
		t.Fatalf("expected DuaStateIdle, got %s", dm.GetState())
	}
}

// ---------------------------------------------------------------------------
// Register Edge Cases
// ---------------------------------------------------------------------------

func TestDuaManager_Register_WithRegistrationDelay(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	dm.UpdateDomainUnicastAddress()

	// Manually set a registration delay via the internal field.
	dm.mu.Lock()
	dm.registrationDelay = 5
	dm.mu.Unlock()

	err := dm.Register()
	if err != errors.ErrBusy {
		t.Fatalf("expected ErrBusy with active registration delay, got %v", err)
	}
}

func TestDuaManager_Register_NilLeader(t *testing.T) {
	dm := NewDuaManager()

	// Force hasDua without leader to test nil leader guard.
	dm.mu.Lock()
	dm.hasDua = true
	dm.state = DuaStateToRegister
	dm.mu.Unlock()

	if err := dm.Register(); err == nil {
		t.Fatal("expected error when leader is nil")
	}
}

// ---------------------------------------------------------------------------
// HandleDuaResponse Edge Cases
// ---------------------------------------------------------------------------

func TestDuaManager_HandleDuaResponse_Duplicate_Regenerates(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(
		WithLeaderProvider(leader),
		WithIIDGenerator(gen),
		WithMaxDadCounter(3),
	)

	dm.UpdateDomainUnicastAddress()
	_ = dm.Register()
	initialCallCount := gen.callCount

	dm.HandleDuaResponse(DuaStatusDuplicate)

	// Generator should have been called again for regeneration.
	if gen.callCount <= initialCallCount {
		t.Fatal("expected IID generator to be called on DAD collision")
	}
	if dm.GetState() != DuaStateToRegister {
		t.Fatalf("expected DuaStateToRegister after regeneration, got %s", dm.GetState())
	}
}

func TestDuaManager_HandleDuaResponse_Duplicate_NoLeader(t *testing.T) {
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	leader := testLeader()
	dm := NewDuaManager(
		WithLeaderProvider(leader),
		WithIIDGenerator(gen),
		WithMaxDadCounter(3),
	)

	dm.UpdateDomainUnicastAddress()
	_ = dm.Register()

	// Remove leader before handling duplicate.
	dm.mu.Lock()
	dm.leader = nil
	dm.mu.Unlock()

	dm.HandleDuaResponse(DuaStatusDuplicate)

	// Without leader, regeneration should fail and remove DUA.
	if dm.GetState() != DuaStateIdle {
		t.Fatalf("expected DuaStateIdle when no leader during regeneration, got %s", dm.GetState())
	}
}

func TestDuaManager_HandleDuaResponse_Duplicate_NoDomainPrefix(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(
		WithLeaderProvider(leader),
		WithIIDGenerator(gen),
		WithMaxDadCounter(3),
	)

	dm.UpdateDomainUnicastAddress()
	_ = dm.Register()

	// Remove domain prefix before handling duplicate.
	leader.hasPrefix = false

	dm.HandleDuaResponse(DuaStatusDuplicate)

	// Without domain prefix, regeneration should fail and remove DUA.
	if dm.GetState() != DuaStateIdle {
		t.Fatalf("expected DuaStateIdle when no prefix during regeneration, got %s", dm.GetState())
	}
}

func TestDuaManager_HandleDuaResponse_ReRegister_NoDua(t *testing.T) {
	dm := NewDuaManager()

	// ReRegister with no DUA configured should not change state.
	dm.HandleDuaResponse(DuaStatusReRegister)
	if dm.GetState() != DuaStateIdle {
		t.Fatalf("expected DuaStateIdle, got %s", dm.GetState())
	}
}

// ---------------------------------------------------------------------------
// Domain Prefix Event Tests
// ---------------------------------------------------------------------------

func TestDuaManager_HandleDomainPrefixUpdate_Refreshed(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	dm.HandleDomainPrefixUpdate(backbone.DomainPrefixAdded)
	addrBefore, _ := dm.GetDuaAddress()

	// Refresh should clear and regenerate.
	dm.HandleDomainPrefixUpdate(backbone.DomainPrefixRefreshed)
	if dm.GetState() != DuaStateToRegister {
		t.Fatalf("expected DuaStateToRegister after refresh, got %s", dm.GetState())
	}
	addrAfter, ok := dm.GetDuaAddress()
	if !ok {
		t.Fatal("expected DUA after refresh")
	}
	// Address may differ because DUA was removed and regenerated.
	_ = addrBefore
	_ = addrAfter
}

func TestDuaManager_HandleDomainPrefixUpdate_Unchanged(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	dm.HandleDomainPrefixUpdate(backbone.DomainPrefixUnchanged)
	if dm.GetState() != DuaStateToRegister {
		t.Fatalf("expected DuaStateToRegister after unchanged event, got %s", dm.GetState())
	}
	if _, ok := dm.GetDuaAddress(); !ok {
		t.Fatal("expected DUA after unchanged event")
	}
}

func TestDuaManager_HandleDomainPrefixUpdate_WithFixedIID(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	fixedIID := ip6.InterfaceIdentifier{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	_ = dm.SetFixedIID(fixedIID)

	dm.HandleDomainPrefixUpdate(backbone.DomainPrefixAdded)

	addr, ok := dm.GetDuaAddress()
	if !ok {
		t.Fatal("expected DUA after prefix added with fixed IID")
	}
	a := ip6.Address(addr)
	if a.GetIid() != fixedIID {
		t.Fatalf("IID mismatch: got %x, want %x", a.GetIid(), fixedIID)
	}
}

func TestDuaManager_HandleDomainPrefixUpdate_NilLeader(t *testing.T) {
	dm := NewDuaManager()

	// Should not panic with nil leader.
	dm.HandleDomainPrefixUpdate(backbone.DomainPrefixAdded)
	dm.HandleDomainPrefixUpdate(backbone.DomainPrefixRemoved)
	dm.HandleDomainPrefixUpdate(backbone.DomainPrefixRefreshed)
	dm.HandleDomainPrefixUpdate(backbone.DomainPrefixUnchanged)
}

func TestDuaManager_HandleDomainPrefixUpdate_GeneratorError(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{err: errors.ErrFailed}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	dm.HandleDomainPrefixUpdate(backbone.DomainPrefixAdded)

	// IID generation failed, so no DUA should be created.
	if _, ok := dm.GetDuaAddress(); ok {
		t.Fatal("expected no DUA when IID generation fails during prefix update")
	}
}

// ---------------------------------------------------------------------------
// HandleBackboneRouterPrimaryUpdate Edge Cases
// ---------------------------------------------------------------------------

func TestDuaManager_HandleBackboneRouterPrimaryUpdate_Unchanged(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	dm.UpdateDomainUnicastAddress()
	_ = dm.Register()
	dm.HandleDuaResponse(DuaStatusSuccess)

	// LeaderStateUnchanged should not trigger reregistration.
	dm.HandleBackboneRouterPrimaryUpdate(backbone.LeaderStateUnchanged)

	// State should remain Registered.
	if dm.GetState() != DuaStateRegistered {
		t.Fatalf("expected DuaStateRegistered after unchanged update, got %s", dm.GetState())
	}
}

func TestDuaManager_HandleBackboneRouterPrimaryUpdate_ToTriggerRereg(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	dm.UpdateDomainUnicastAddress()
	_ = dm.Register()
	dm.HandleDuaResponse(DuaStatusSuccess)

	dm.HandleBackboneRouterPrimaryUpdate(backbone.LeaderStateToTriggerRereg)

	// Tick until reregistration fires.
	fired := false
	for i := 0; i < 100; i++ {
		if dm.HandleTimer() {
			fired = true
			break
		}
	}
	if !fired {
		t.Fatal("expected timer to fire after ToTriggerRereg")
	}
	if dm.GetState() != DuaStateToRegister {
		t.Fatalf("expected DuaStateToRegister after rereg timer, got %s", dm.GetState())
	}
}

// ---------------------------------------------------------------------------
// Timer Tests
// ---------------------------------------------------------------------------

func TestDuaManager_HandleTimer_NoDelays(t *testing.T) {
	dm := NewDuaManager()

	// Should return false and not panic.
	if dm.HandleTimer() {
		t.Fatal("expected false when no delays are active")
	}
}

func TestDuaManager_HandleTimer_ElapsedTracking(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	dm.UpdateDomainUnicastAddress()

	// Tick several times; elapsed should increase.
	for i := 0; i < 10; i++ {
		dm.HandleTimer()
	}

	dm.mu.Lock()
	elapsed := dm.elapsedSinceAdd
	dm.mu.Unlock()

	if elapsed != 10 {
		t.Fatalf("expected elapsedSinceAdd=10, got %d", elapsed)
	}
}

func TestDuaManager_HandleTimer_MultipleDelays(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	dm.UpdateDomainUnicastAddress()

	// Set multiple internal delays.
	dm.mu.Lock()
	dm.registrationDelay = 3
	dm.checkDelay = 5
	dm.mu.Unlock()

	// Tick until registration delay fires.
	fireCount := 0
	for i := 0; i < 10; i++ {
		if dm.HandleTimer() {
			fireCount++
		}
	}
	// Both delays should have fired within 10 ticks.
	if fireCount < 2 {
		t.Fatalf("expected at least 2 timer fires, got %d", fireCount)
	}
}

// ---------------------------------------------------------------------------
// Status Constants
// ---------------------------------------------------------------------------

func TestDuaStatusConstants(t *testing.T) {
	tests := []struct {
		name   string
		status uint8
		want   uint8
	}{
		{"Success", DuaStatusSuccess, 0},
		{"ReRegister", DuaStatusReRegister, 1},
		{"Invalid", DuaStatusInvalid, 2},
		{"Duplicate", DuaStatusDuplicate, 3},
		{"NoResources", DuaStatusNoResources, 4},
		{"NotPrimary", DuaStatusNotPrimary, 5},
		{"GeneralFailure", DuaStatusGeneralFailure, 6},
	}
	for _, tc := range tests {
		if tc.status != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, tc.status, tc.want)
		}
	}
}
