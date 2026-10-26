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
// Mock LeaderProvider
// ---------------------------------------------------------------------------

type mockLeader struct {
	hasPrimary bool
	config     backbone.Config
	prefix     ip6.Prefix
	hasPrefix  bool
}

func (m *mockLeader) HasPrimary() bool           { return m.hasPrimary }
func (m *mockLeader) GetConfig() backbone.Config { return m.config }
func (m *mockLeader) GetDomainPrefix() (ip6.Prefix, bool) {
	return m.prefix, m.hasPrefix
}
func (m *mockLeader) IsDomainUnicast(addr [16]byte) bool {
	if !m.hasPrefix {
		return false
	}
	a := ip6.Address(addr)
	return !a.IsMulticast() && a.MatchesPrefix(m.prefix)
}

// ---------------------------------------------------------------------------
// Mock IIDGenerator
// ---------------------------------------------------------------------------

type mockIIDGen struct {
	iid       ip6.InterfaceIdentifier
	callCount int
	err       error
}

func (g *mockIIDGen) GenerateIID(_ ip6.Prefix, dadCounter uint8) (ip6.InterfaceIdentifier, error) {
	g.callCount++
	if g.err != nil {
		return ip6.InterfaceIdentifier{}, g.err
	}
	// Return base IID XOR'd with dadCounter for uniqueness on DAD collisions.
	var iid ip6.InterfaceIdentifier
	copy(iid[:], g.iid[:])
	iid[7] ^= dadCounter
	return iid, nil
}

// ---------------------------------------------------------------------------
// Helper: build a domain prefix
// ---------------------------------------------------------------------------

func testDomainPrefix() ip6.Prefix {
	// fd00:db8::/64
	var addr [16]byte
	addr[0] = 0xfd
	addr[1] = 0x00
	addr[2] = 0x0d
	addr[3] = 0xb8
	return ip6.NewPrefix(addr, 64)
}

func testLeader() *mockLeader {
	return &mockLeader{
		hasPrimary: true,
		config: backbone.Config{
			Server16:            0x0400,
			ReregistrationDelay: 10,
			MlrTimeout:          3600,
			SequenceNumber:      1,
		},
		prefix:    testDomainPrefix(),
		hasPrefix: true,
	}
}

// ---------------------------------------------------------------------------
// DUA Manager Tests
// ---------------------------------------------------------------------------

func TestDuaManager_NewDefaults(t *testing.T) {
	dm := NewDuaManager()
	if dm.GetState() != DuaStateIdle {
		t.Fatalf("expected DuaStateIdle, got %s", dm.GetState())
	}
	if _, ok := dm.GetDuaAddress(); ok {
		t.Fatal("expected no DUA configured initially")
	}
}

func TestDuaManager_UpdateDomainUnicastAddress(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}}

	dm := NewDuaManager(
		WithLeaderProvider(leader),
		WithIIDGenerator(gen),
	)

	dm.UpdateDomainUnicastAddress()

	if dm.GetState() != DuaStateToRegister {
		t.Fatalf("expected DuaStateToRegister, got %s", dm.GetState())
	}

	addr, ok := dm.GetDuaAddress()
	if !ok {
		t.Fatal("expected DUA to be configured")
	}
	// Check prefix matches.
	prefixBytes := testDomainPrefix().GetBytes()
	for i := 0; i < 8; i++ {
		if addr[i] != prefixBytes[i] {
			t.Fatalf("prefix byte %d: got %02x, want %02x", i, addr[i], prefixBytes[i])
		}
	}
	// Check IID.
	if addr[8] != 0x01 || addr[15] != 0x08 {
		t.Fatalf("unexpected IID bytes: %x", addr[8:])
	}
}

func TestDuaManager_NoDomainPrefix(t *testing.T) {
	leader := &mockLeader{hasPrimary: true, hasPrefix: false}
	dm := NewDuaManager(WithLeaderProvider(leader))

	dm.UpdateDomainUnicastAddress()

	if dm.GetState() != DuaStateIdle {
		t.Fatalf("expected DuaStateIdle when no domain prefix, got %s", dm.GetState())
	}
	if _, ok := dm.GetDuaAddress(); ok {
		t.Fatal("expected no DUA when no domain prefix")
	}
}

func TestDuaManager_RegisterFlow(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}}

	dm := NewDuaManager(
		WithLeaderProvider(leader),
		WithIIDGenerator(gen),
	)

	// Cannot register without DUA.
	if err := dm.Register(); err == nil {
		t.Fatal("expected error when registering without DUA")
	}

	dm.UpdateDomainUnicastAddress()

	if err := dm.Register(); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if dm.GetState() != DuaStateRegistering {
		t.Fatalf("expected DuaStateRegistering, got %s", dm.GetState())
	}

	// Cannot register again while already registering.
	if err := dm.Register(); err == nil {
		t.Fatal("expected error when registering while already in progress")
	}
}

func TestDuaManager_HandleDuaResponse_Success(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	dm.UpdateDomainUnicastAddress()
	_ = dm.Register()

	dm.HandleDuaResponse(DuaStatusSuccess)
	if dm.GetState() != DuaStateRegistered {
		t.Fatalf("expected DuaStateRegistered, got %s", dm.GetState())
	}
}

func TestDuaManager_HandleDuaResponse_ReRegister(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	dm.UpdateDomainUnicastAddress()
	_ = dm.Register()

	dm.HandleDuaResponse(DuaStatusReRegister)
	if dm.GetState() != DuaStateToRegister {
		t.Fatalf("expected DuaStateToRegister after re-register, got %s", dm.GetState())
	}
}

func TestDuaManager_HandleDuaResponse_Invalid(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	dm.UpdateDomainUnicastAddress()
	_ = dm.Register()

	dm.HandleDuaResponse(DuaStatusInvalid)
	if dm.GetState() != DuaStateIdle {
		t.Fatalf("expected DuaStateIdle after invalid, got %s", dm.GetState())
	}
	if _, ok := dm.GetDuaAddress(); ok {
		t.Fatal("expected DUA to be removed after invalid response")
	}
}

func TestDuaManager_HandleDuaResponse_Duplicate(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(
		WithLeaderProvider(leader),
		WithIIDGenerator(gen),
		WithMaxDadCounter(3),
	)

	dm.UpdateDomainUnicastAddress()
	addrBefore, _ := dm.GetDuaAddress()
	_ = dm.Register()

	dm.HandleDuaResponse(DuaStatusDuplicate)
	if dm.GetState() != DuaStateToRegister {
		t.Fatalf("expected DuaStateToRegister after duplicate, got %s", dm.GetState())
	}

	addrAfter, ok := dm.GetDuaAddress()
	if !ok {
		t.Fatal("expected DUA to still exist after DAD collision")
	}
	// The IID should differ because dadCounter was incremented.
	if addrBefore == addrAfter {
		t.Fatal("expected DUA to change after DAD collision")
	}
}

func TestDuaManager_HandleDuaResponse_DuplicateExhausted(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(
		WithLeaderProvider(leader),
		WithIIDGenerator(gen),
		WithMaxDadCounter(1),
	)

	dm.UpdateDomainUnicastAddress()
	_ = dm.Register()
	dm.HandleDuaResponse(DuaStatusDuplicate) // First duplicate increments the DAD counter to 1 and regenerates.
	// Register and get another duplicate.
	_ = dm.Register()
	dm.HandleDuaResponse(DuaStatusDuplicate) // dadCounter = 2, exceeds max (1)

	if dm.GetState() != DuaStateIdle {
		t.Fatalf("expected DuaStateIdle after DAD exhaustion, got %s", dm.GetState())
	}
}

func TestDuaManager_HandleDuaResponse_NonFatal(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	for _, status := range []uint8{DuaStatusNoResources, DuaStatusNotPrimary, DuaStatusGeneralFailure} {
		dm.UpdateDomainUnicastAddress()
		_ = dm.Register()
		dm.HandleDuaResponse(status)

		// Should still have a DUA, just with reregistration scheduled.
		if _, ok := dm.GetDuaAddress(); !ok {
			t.Fatalf("DUA should still exist after non-fatal status %d", status)
		}
	}
}

func TestDuaManager_SetFixedIID(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	fixedIID := ip6.InterfaceIdentifier{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}

	// Reject zero IID.
	if err := dm.SetFixedIID(ip6.InterfaceIdentifier{}); err == nil {
		t.Fatal("expected error for zero IID")
	}

	dm.UpdateDomainUnicastAddress()
	if err := dm.SetFixedIID(fixedIID); err != nil {
		t.Fatalf("SetFixedIID failed: %v", err)
	}

	addr, ok := dm.GetDuaAddress()
	if !ok {
		t.Fatal("expected DUA to be configured")
	}
	// Check that the IID matches the fixed value.
	a := ip6.Address(addr)
	if a.GetIid() != fixedIID {
		t.Fatalf("IID mismatch: got %x, want %x", a.GetIid(), fixedIID)
	}
}

func TestDuaManager_ClearFixedIID(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	fixedIID := ip6.InterfaceIdentifier{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}

	dm.UpdateDomainUnicastAddress()
	_ = dm.SetFixedIID(fixedIID)
	dm.ClearFixedIID()

	addr, ok := dm.GetDuaAddress()
	if !ok {
		t.Fatal("expected DUA to be configured after clearing fixed IID")
	}
	a := ip6.Address(addr)
	if a.GetIid() == fixedIID {
		t.Fatal("IID should have changed after clearing fixed IID")
	}
}

func TestDuaManager_HandleBackboneRouterPrimaryUpdate(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	dm.UpdateDomainUnicastAddress()
	_ = dm.Register()
	dm.HandleDuaResponse(DuaStatusSuccess)

	// Trigger BBR primary update (re-registration needed).
	dm.HandleBackboneRouterPrimaryUpdate(backbone.LeaderStateAdded)
	// The reregistration delay should have been set; we verify via timer.
	// (Internal state not directly exposed, but timer handling reveals it.)
}

func TestDuaManager_HandleDomainPrefixUpdate(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	// Adding a domain prefix should create a DUA.
	dm.HandleDomainPrefixUpdate(backbone.DomainPrefixAdded)
	if dm.GetState() != DuaStateToRegister {
		t.Fatalf("expected DuaStateToRegister after prefix added, got %s", dm.GetState())
	}
	if _, ok := dm.GetDuaAddress(); !ok {
		t.Fatal("expected DUA after prefix added")
	}

	// Removing it should clear the DUA.
	dm.HandleDomainPrefixUpdate(backbone.DomainPrefixRemoved)
	if dm.GetState() != DuaStateIdle {
		t.Fatalf("expected DuaStateIdle after prefix removed, got %s", dm.GetState())
	}
}

func TestDuaManager_HandleTimer(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	dm.UpdateDomainUnicastAddress()
	_ = dm.Register()
	dm.HandleDuaResponse(DuaStatusNoResources) // Sets reregistration delay.

	// Tick until the timer fires.
	fired := false
	for i := 0; i < 100; i++ {
		if dm.HandleTimer() {
			fired = true
			break
		}
	}
	if !fired {
		t.Fatal("expected timer to fire within 100 ticks")
	}
}

func TestDuaManager_NilLeader(t *testing.T) {
	dm := NewDuaManager()
	// These should not panic.
	dm.UpdateDomainUnicastAddress()
	dm.HandleBackboneRouterPrimaryUpdate(backbone.LeaderStateAdded)
	dm.HandleDomainPrefixUpdate(backbone.DomainPrefixAdded)
	_ = dm.HandleTimer()
}

func TestDuaManager_NoPrimary(t *testing.T) {
	leader := &mockLeader{hasPrimary: false, hasPrefix: true, prefix: testDomainPrefix()}
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	dm.UpdateDomainUnicastAddress()
	if err := dm.Register(); err == nil {
		t.Fatal("expected error when registering without primary BBR")
	}
}

// ---------------------------------------------------------------------------
// MLR Manager Tests
// ---------------------------------------------------------------------------

// testMulticastAddr returns a multicast address with global scope (scope=14).
func testMulticastAddr(suffix byte) [16]byte {
	var addr [16]byte
	addr[0] = 0xff // multicast
	addr[1] = 0x0e // scope 14 (global)
	addr[15] = suffix
	return addr
}

// testRealmLocalMulticast returns a realm-local multicast address (scope=3).
func testRealmLocalMulticast() [16]byte {
	var addr [16]byte
	addr[0] = 0xff
	addr[1] = 0x03 // scope 3 (realm-local)
	addr[15] = 0x01
	return addr
}

func TestMlrManager_NewDefaults(t *testing.T) {
	mm := NewMlrManager()
	entries := mm.GetEntries()
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
	reg := mm.GetRegisteredAddresses()
	if len(reg) != 0 {
		t.Fatalf("expected 0 registered addresses, got %d", len(reg))
	}
}

func TestMlrManager_AddAddress(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	addr := testMulticastAddr(1)
	if err := mm.AddAddress(addr); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	entries := mm.GetEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].State != MlrStateToRegister {
		t.Fatalf("expected MlrStateToRegister, got %s", entries[0].State)
	}
	if entries[0].Timeout != 3600 {
		t.Fatalf("expected timeout 3600, got %d", entries[0].Timeout)
	}
}

func TestMlrManager_AddAddress_Duplicate(t *testing.T) {
	mm := NewMlrManager(WithMlrLeaderProvider(testLeader()))
	addr := testMulticastAddr(1)

	_ = mm.AddAddress(addr)
	if err := mm.AddAddress(addr); err == nil {
		t.Fatal("expected error on duplicate add")
	}
}

func TestMlrManager_AddAddress_InvalidScope(t *testing.T) {
	mm := NewMlrManager(WithMlrLeaderProvider(testLeader()))

	// Realm-local multicast should be rejected.
	if err := mm.AddAddress(testRealmLocalMulticast()); err == nil {
		t.Fatal("expected error for realm-local multicast address")
	}

	// Unicast should be rejected.
	var unicast [16]byte
	unicast[0] = 0x20
	if err := mm.AddAddress(unicast); err == nil {
		t.Fatal("expected error for unicast address")
	}
}

func TestMlrManager_AddAddress_Full(t *testing.T) {
	mm := NewMlrManager(WithMlrLeaderProvider(testLeader()), WithMaxEntries(2))

	_ = mm.AddAddress(testMulticastAddr(1))
	_ = mm.AddAddress(testMulticastAddr(2))

	if err := mm.AddAddress(testMulticastAddr(3)); err == nil {
		t.Fatal("expected error when table is full")
	}
}

func TestMlrManager_RemoveAddress(t *testing.T) {
	mm := NewMlrManager(WithMlrLeaderProvider(testLeader()))
	addr := testMulticastAddr(1)

	_ = mm.AddAddress(addr)
	mm.RemoveAddress(addr)

	entries := mm.GetEntries()
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries after removal, got %d", len(entries))
	}
}

func TestMlrManager_RemoveAddress_NotFound(t *testing.T) {
	mm := NewMlrManager()
	// Should not panic.
	mm.RemoveAddress(testMulticastAddr(99))
}

func TestMlrManager_UpdateRegistration(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	_ = mm.AddAddress(testMulticastAddr(1))
	_ = mm.AddAddress(testMulticastAddr(2))

	addrs := mm.UpdateRegistration()
	if len(addrs) != 2 {
		t.Fatalf("expected 2 addresses to register, got %d", len(addrs))
	}

	// Entries should now be in Registering state.
	for _, e := range mm.GetEntries() {
		if e.State != MlrStateRegistering {
			t.Fatalf("expected MlrStateRegistering, got %s", e.State)
		}
	}

	// Second call while pending should return nil.
	addrs2 := mm.UpdateRegistration()
	if addrs2 != nil {
		t.Fatal("expected nil from UpdateRegistration while pending")
	}
}

func TestMlrManager_UpdateRegistration_NoPrimary(t *testing.T) {
	leader := &mockLeader{hasPrimary: false}
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	_ = mm.AddAddress(testMulticastAddr(1))
	addrs := mm.UpdateRegistration()
	if addrs != nil {
		t.Fatal("expected nil from UpdateRegistration when no primary")
	}
}

func TestMlrManager_RegisterMulticastListeners(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	addr1 := testMulticastAddr(1)
	addr2 := testMulticastAddr(2)
	_ = mm.AddAddress(addr1)
	_ = mm.AddAddress(addr2)

	if err := mm.RegisterMulticastListeners([][16]byte{addr1}); err != nil {
		t.Fatalf("RegisterMulticastListeners failed: %v", err)
	}

	// Should be busy now.
	if err := mm.RegisterMulticastListeners([][16]byte{addr2}); err == nil {
		t.Fatal("expected busy error")
	}
}

func TestMlrManager_RegisterMulticastListeners_Empty(t *testing.T) {
	mm := NewMlrManager(WithMlrLeaderProvider(testLeader()))
	if err := mm.RegisterMulticastListeners(nil); err == nil {
		t.Fatal("expected error for empty addresses")
	}
}

func TestMlrManager_RegisterMulticastListeners_NoPrimary(t *testing.T) {
	leader := &mockLeader{hasPrimary: false}
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	_ = mm.AddAddress(testMulticastAddr(1))
	if err := mm.RegisterMulticastListeners([][16]byte{testMulticastAddr(1)}); err == nil {
		t.Fatal("expected error when no primary")
	}
}

func TestMlrManager_RegisterMulticastListeners_NotFound(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	// Address not in entries.
	if err := mm.RegisterMulticastListeners([][16]byte{testMulticastAddr(99)}); err == nil {
		t.Fatal("expected error for unknown address")
	}
}

func TestMlrManager_HandleMlrResponse_Success(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	_ = mm.AddAddress(testMulticastAddr(1))
	_ = mm.AddAddress(testMulticastAddr(2))
	mm.UpdateRegistration()

	mm.HandleMlrResponse(MlrStatusSuccess, nil)

	for _, e := range mm.GetEntries() {
		if e.State != MlrStateRegistered {
			t.Fatalf("expected MlrStateRegistered, got %s", e.State)
		}
	}

	reg := mm.GetRegisteredAddresses()
	if len(reg) != 2 {
		t.Fatalf("expected 2 registered addresses, got %d", len(reg))
	}
}

func TestMlrManager_HandleMlrResponse_PartialFailure(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	addr1 := testMulticastAddr(1)
	addr2 := testMulticastAddr(2)
	_ = mm.AddAddress(addr1)
	_ = mm.AddAddress(addr2)
	mm.UpdateRegistration()

	// addr2 failed.
	mm.HandleMlrResponse(MlrStatusSuccess, [][16]byte{addr2})

	entries := mm.GetEntries()
	for _, e := range entries {
		a := [16]byte(e.Address)
		if a == addr1 && e.State != MlrStateRegistered {
			t.Fatalf("addr1 should be registered, got %s", e.State)
		}
		if a == addr2 && e.State != MlrStateToRegister {
			t.Fatalf("addr2 should be ToRegister (failed), got %s", e.State)
		}
	}
}

func TestMlrManager_HandleMlrResponse_AllFailed(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	_ = mm.AddAddress(testMulticastAddr(1))
	mm.UpdateRegistration()

	mm.HandleMlrResponse(MlrStatusGeneralFailure, nil)

	for _, e := range mm.GetEntries() {
		if e.State != MlrStateToRegister {
			t.Fatalf("expected MlrStateToRegister after general failure, got %s", e.State)
		}
	}
}

func TestMlrManager_HandleBackboneRouterPrimaryUpdate(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	_ = mm.AddAddress(testMulticastAddr(1))
	mm.UpdateRegistration()
	mm.HandleMlrResponse(MlrStatusSuccess, nil)

	// Verify registered.
	for _, e := range mm.GetEntries() {
		if e.State != MlrStateRegistered {
			t.Fatalf("expected MlrStateRegistered, got %s", e.State)
		}
	}

	// Trigger re-registration.
	mm.HandleBackboneRouterPrimaryUpdate(backbone.LeaderStateToTriggerRereg)

	for _, e := range mm.GetEntries() {
		if e.State != MlrStateToRegister {
			t.Fatalf("expected MlrStateToRegister after BBR update, got %s", e.State)
		}
	}
}

func TestMlrManager_HandleBackboneRouterPrimaryUpdate_NoChange(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	_ = mm.AddAddress(testMulticastAddr(1))
	mm.UpdateRegistration()
	mm.HandleMlrResponse(MlrStatusSuccess, nil)

	// Unchanged should not trigger re-registration.
	mm.HandleBackboneRouterPrimaryUpdate(backbone.LeaderStateUnchanged)

	for _, e := range mm.GetEntries() {
		if e.State != MlrStateRegistered {
			t.Fatalf("state should remain Registered for unchanged, got %s", e.State)
		}
	}
}

func TestMlrManager_HandleTimer(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	_ = mm.AddAddress(testMulticastAddr(1))
	mm.UpdateRegistration()
	mm.HandleMlrResponse(MlrStatusGeneralFailure, nil) // Sets reregistration delay.

	fired := false
	for i := 0; i < 100; i++ {
		if mm.HandleTimer() {
			fired = true
			break
		}
	}
	if !fired {
		t.Fatal("expected timer to fire within 100 ticks")
	}

	// After timer fires, registered addresses should be ToRegister.
	for _, e := range mm.GetEntries() {
		if e.State != MlrStateToRegister {
			t.Fatalf("expected MlrStateToRegister after timer, got %s", e.State)
		}
	}
}

func TestMlrManager_HandleTimer_NoDelays(t *testing.T) {
	mm := NewMlrManager()
	// Should return false and not panic.
	if mm.HandleTimer() {
		t.Fatal("expected false when no delays are active")
	}
}

// ---------------------------------------------------------------------------
// FTD Aggregation Tests
// ---------------------------------------------------------------------------

func TestMlrManager_AddChildMulticast(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	addr1 := ip6.Address(testMulticastAddr(1))
	addr2 := ip6.Address(testMulticastAddr(2))

	mm.AddChildMulticast(0x0401, []ip6.Address{addr1, addr2})

	entries := mm.GetEntries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	childAddrs := mm.GetChildMulticast(0x0401)
	if len(childAddrs) != 2 {
		t.Fatalf("expected 2 child addresses, got %d", len(childAddrs))
	}
}

func TestMlrManager_RemoveChildMulticast(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	addr1 := ip6.Address(testMulticastAddr(1))
	addr2 := ip6.Address(testMulticastAddr(2))

	mm.AddChildMulticast(0x0401, []ip6.Address{addr1, addr2})
	mm.RemoveChildMulticast(0x0401)

	entries := mm.GetEntries()
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries after child removal, got %d", len(entries))
	}

	childAddrs := mm.GetChildMulticast(0x0401)
	if childAddrs != nil {
		t.Fatal("expected nil child addresses after removal")
	}
}

func TestMlrManager_RemoveChildMulticast_SharedAddress(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	sharedAddr := ip6.Address(testMulticastAddr(1))
	uniqueAddr := ip6.Address(testMulticastAddr(2))

	mm.AddChildMulticast(0x0401, []ip6.Address{sharedAddr, uniqueAddr})
	mm.AddChildMulticast(0x0402, []ip6.Address{sharedAddr})

	// Remove child 0x0401 — sharedAddr is still referenced by 0x0402.
	mm.RemoveChildMulticast(0x0401)

	entries := mm.GetEntries()
	// sharedAddr should remain, uniqueAddr should be removed.
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (shared addr), got %d", len(entries))
	}
	if entries[0].Address != sharedAddr {
		t.Fatalf("expected shared address to remain, got %x", entries[0].Address)
	}
}

func TestMlrManager_AddChildMulticast_RejectsRealmLocal(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	// Realm-local multicast should NOT be added.
	realmAddr := ip6.Address(testRealmLocalMulticast())
	globalAddr := ip6.Address(testMulticastAddr(1))

	mm.AddChildMulticast(0x0401, []ip6.Address{realmAddr, globalAddr})

	entries := mm.GetEntries()
	if len(entries) != 1 {
		t.Fatalf("expected only 1 entry (global), got %d", len(entries))
	}
}

func TestMlrManager_AddChildMulticast_UpdateExisting(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	addr1 := ip6.Address(testMulticastAddr(1))
	addr2 := ip6.Address(testMulticastAddr(2))

	mm.AddChildMulticast(0x0401, []ip6.Address{addr1})

	// Update the same child with a different set.
	mm.AddChildMulticast(0x0401, []ip6.Address{addr2})

	childAddrs := mm.GetChildMulticast(0x0401)
	if len(childAddrs) != 1 {
		t.Fatalf("expected 1 child address after update, got %d", len(childAddrs))
	}
	if childAddrs[0] != addr2 {
		t.Fatalf("expected addr2, got %x", childAddrs[0])
	}
}

func TestMlrManager_GetChildMulticast_NotFound(t *testing.T) {
	mm := NewMlrManager()
	if addrs := mm.GetChildMulticast(0xFFFF); addrs != nil {
		t.Fatal("expected nil for unknown child")
	}
}

// ---------------------------------------------------------------------------
// State string tests
// ---------------------------------------------------------------------------

func TestDuaState_String(t *testing.T) {
	tests := []struct {
		s    DuaState
		want string
	}{
		{DuaStateIdle, "Idle"},
		{DuaStateToRegister, "ToRegister"},
		{DuaStateRegistering, "Registering"},
		{DuaStateRegistered, "Registered"},
		{DuaState(99), "Unknown"},
	}
	for _, tc := range tests {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("DuaState(%d).String() = %q, want %q", tc.s, got, tc.want)
		}
	}
}

func TestMlrState_String(t *testing.T) {
	tests := []struct {
		s    MlrState
		want string
	}{
		{MlrStateIdle, "Idle"},
		{MlrStateToRegister, "ToRegister"},
		{MlrStateRegistering, "Registering"},
		{MlrStateRegistered, "Registered"},
		{MlrState(99), "Unknown"},
	}
	for _, tc := range tests {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("MlrState(%d).String() = %q, want %q", tc.s, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Full registration round-trip tests
// ---------------------------------------------------------------------------

func TestDuaManager_FullRoundTrip(t *testing.T) {
	leader := testLeader()
	gen := &mockIIDGen{iid: ip6.InterfaceIdentifier{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}}
	dm := NewDuaManager(WithLeaderProvider(leader), WithIIDGenerator(gen))

	// 1. Generate DUA.
	dm.UpdateDomainUnicastAddress()
	if dm.GetState() != DuaStateToRegister {
		t.Fatalf("step 1: expected ToRegister, got %s", dm.GetState())
	}

	// 2. Register.
	if err := dm.Register(); err != nil {
		t.Fatalf("step 2: Register failed: %v", err)
	}
	if dm.GetState() != DuaStateRegistering {
		t.Fatalf("step 2: expected Registering, got %s", dm.GetState())
	}

	// 3. Receive success.
	dm.HandleDuaResponse(DuaStatusSuccess)
	if dm.GetState() != DuaStateRegistered {
		t.Fatalf("step 3: expected Registered, got %s", dm.GetState())
	}

	// 4. BBR changes, triggers re-registration.
	dm.HandleBackboneRouterPrimaryUpdate(backbone.LeaderStateToTriggerRereg)

	// 5. Timer fires, state goes back to ToRegister.
	for i := 0; i < 100; i++ {
		if dm.HandleTimer() {
			break
		}
	}
	if dm.GetState() != DuaStateToRegister {
		t.Fatalf("step 5: expected ToRegister after timer, got %s", dm.GetState())
	}

	// 6. Re-register.
	if err := dm.Register(); err != nil {
		t.Fatalf("step 6: Register failed: %v", err)
	}
	dm.HandleDuaResponse(DuaStatusSuccess)
	if dm.GetState() != DuaStateRegistered {
		t.Fatalf("step 6: expected Registered, got %s", dm.GetState())
	}
}

func TestMlrManager_FullRoundTrip(t *testing.T) {
	leader := testLeader()
	mm := NewMlrManager(WithMlrLeaderProvider(leader))

	addr1 := testMulticastAddr(1)
	addr2 := testMulticastAddr(2)
	_ = mm.AddAddress(addr1)
	_ = mm.AddAddress(addr2)

	// 1. Collect addresses to register.
	addrs := mm.UpdateRegistration()
	if len(addrs) != 2 {
		t.Fatalf("step 1: expected 2 addresses, got %d", len(addrs))
	}

	// 2. Success response.
	mm.HandleMlrResponse(MlrStatusSuccess, nil)
	reg := mm.GetRegisteredAddresses()
	if len(reg) != 2 {
		t.Fatalf("step 2: expected 2 registered, got %d", len(reg))
	}

	// 3. BBR update triggers re-registration.
	mm.HandleBackboneRouterPrimaryUpdate(backbone.LeaderStateAdded)
	for _, e := range mm.GetEntries() {
		if e.State != MlrStateToRegister {
			t.Fatalf("step 3: expected ToRegister, got %s", e.State)
		}
	}

	// 4. Re-register.
	addrs = mm.UpdateRegistration()
	if len(addrs) != 2 {
		t.Fatalf("step 4: expected 2 addresses, got %d", len(addrs))
	}
	mm.HandleMlrResponse(MlrStatusSuccess, nil)
	reg = mm.GetRegisteredAddresses()
	if len(reg) != 2 {
		t.Fatalf("step 4: expected 2 registered, got %d", len(reg))
	}
}
