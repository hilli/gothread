// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package backbone

import (
	"testing"

	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

type mockManagerDeps struct {
	rloc16       uint16
	isPrimary    bool
	domainPrefix *ip6.Prefix
}

func (d *mockManagerDeps) GetRloc16() uint16 { return d.rloc16 }
func (d *mockManagerDeps) IsPrimary() bool   { return d.isPrimary }
func (d *mockManagerDeps) GetDomainPrefix() (ip6.Prefix, bool) {
	if d.domainPrefix == nil {
		return ip6.Prefix{}, false
	}
	return *d.domainPrefix, true
}

// mcastAddr creates a site-local multicast address distinguished by the last byte.
func mcastAddr(n byte) [16]byte {
	var addr [16]byte
	addr[0] = 0xff
	addr[1] = 0x05
	addr[15] = n
	return addr
}

// ---------------------------------------------------------------------------
// NewManager — sub-components created
// ---------------------------------------------------------------------------

func TestManager_NewCreatesSubComponents(t *testing.T) {
	deps := &mockManagerDeps{rloc16: 0x0400, isPrimary: true}
	m := NewManager(deps)

	if m.GetLeader() == nil {
		t.Fatal("Leader is nil")
	}
	if m.GetLocal() == nil {
		t.Fatal("Local is nil")
	}
	if m.GetMulticastListenersTable() == nil {
		t.Fatal("MulticastListenersTable is nil")
	}
	if m.GetNdProxyTable() == nil {
		t.Fatal("NdProxyTable is nil")
	}
}

func TestManager_NewWithCallbacks(t *testing.T) {
	deps := &mockManagerDeps{}
	var leaderCBCalled bool
	lcb := &testLeaderCB{onPrimary: func(LeaderState, Config) { leaderCBCalled = true }}

	m := NewManager(deps, WithManagerLeaderCallbacks(lcb))

	cfg := Config{Server16: 0x0400, MlrTimeout: 3600}
	m.GetLeader().UpdatePrimary(&cfg)
	if !leaderCBCalled {
		t.Fatal("expected leader callback to be invoked")
	}
}

type testLeaderCB struct {
	onPrimary func(LeaderState, Config)
}

func (cb *testLeaderCB) OnPrimaryUpdated(s LeaderState, c Config) {
	if cb.onPrimary != nil {
		cb.onPrimary(s, c)
	}
}
func (cb *testLeaderCB) OnDomainPrefixUpdated(DomainPrefixEvent, ip6.Prefix) {}

// ---------------------------------------------------------------------------
// Start / Stop lifecycle
// ---------------------------------------------------------------------------

func TestManager_StartStop(t *testing.T) {
	deps := &mockManagerDeps{rloc16: 0x0400, isPrimary: true}
	m := NewManager(deps)

	if m.IsRunning() {
		t.Fatal("expected not running before Start")
	}

	m.Start()
	if !m.IsRunning() {
		t.Fatal("expected running after Start")
	}
	if !m.GetLocal().IsEnabled() {
		t.Fatal("expected local enabled after Start")
	}

	m.Stop()
	if m.IsRunning() {
		t.Fatal("expected not running after Stop")
	}
	if m.GetLocal().IsEnabled() {
		t.Fatal("expected local disabled after Stop")
	}
}

func TestManager_StartIdempotent(t *testing.T) {
	deps := &mockManagerDeps{}
	m := NewManager(deps)
	m.Start()
	m.Start() // should not panic
	if !m.IsRunning() {
		t.Fatal("expected running")
	}
}

func TestManager_StopIdempotent(t *testing.T) {
	deps := &mockManagerDeps{}
	m := NewManager(deps)
	m.Stop() // not running, should not panic
}

func TestManager_StopClearsTables(t *testing.T) {
	deps := &mockManagerDeps{isPrimary: true}
	m := NewManager(deps)
	m.Start()

	// Add some data.
	m.GetMulticastListenersTable().Add(mcastAddr(1), 10000)
	m.GetNdProxyTable().Register(iid(1), iid(0xA0), 0x0400, nil, 1000)

	m.Stop()

	if m.GetMulticastListenersTable().Count() != 0 {
		t.Fatalf("listeners count = %d, want 0", m.GetMulticastListenersTable().Count())
	}
	if m.GetNdProxyTable().Count() != 0 {
		t.Fatalf("ndproxy count = %d, want 0", m.GetNdProxyTable().Count())
	}
}

// ---------------------------------------------------------------------------
// HandleTimer
// ---------------------------------------------------------------------------

func TestManager_HandleTimer_ExpiresListeners(t *testing.T) {
	deps := &mockManagerDeps{isPrimary: true}
	m := NewManager(deps)

	_ = m.GetMulticastListenersTable().Add(mcastAddr(1), 100)
	_ = m.GetMulticastListenersTable().Add(mcastAddr(2), 200)
	_ = m.GetMulticastListenersTable().Add(mcastAddr(3), 500)

	m.HandleTimer(250)

	if m.GetMulticastListenersTable().Count() != 1 {
		t.Fatalf("listeners count = %d, want 1 after expire", m.GetMulticastListenersTable().Count())
	}
}

func TestManager_HandleTimer_ProgressesDad(t *testing.T) {
	deps := &mockManagerDeps{isPrimary: true}
	var dadSends int
	m := NewManager(deps, WithManagerNdProxyOptions(
		WithDadSendCallback(func(_ [8]byte) { dadSends++ }),
	))

	_ = m.GetNdProxyTable().Register(iid(1), iid(0xA0), 0x0400, nil, 1000)
	m.HandleTimer(1000)

	if dadSends != 1 {
		t.Fatalf("dadSends = %d, want 1", dadSends)
	}
}

// ---------------------------------------------------------------------------
// HandleMulticastListenerRegistration
// ---------------------------------------------------------------------------

func TestManager_MLR_Success(t *testing.T) {
	deps := &mockManagerDeps{isPrimary: true}
	m := NewManager(deps)

	addrs := [][16]byte{mcastAddr(1), mcastAddr(2)}
	failed, status := m.HandleMulticastListenerRegistration(addrs, 3600, 1000)

	if status != MlrStatusSuccess {
		t.Fatalf("status = %d, want MlrStatusSuccess", status)
	}
	if len(failed) != 0 {
		t.Fatalf("failed = %d, want 0", len(failed))
	}
	if m.GetMulticastListenersTable().Count() != 2 {
		t.Fatalf("listeners = %d, want 2", m.GetMulticastListenersTable().Count())
	}
}

func TestManager_MLR_NotPrimary(t *testing.T) {
	deps := &mockManagerDeps{isPrimary: false}
	m := NewManager(deps)

	addrs := [][16]byte{mcastAddr(1)}
	failed, status := m.HandleMulticastListenerRegistration(addrs, 3600, 1000)

	if status != MlrStatusNotPrimary {
		t.Fatalf("status = %d, want MlrStatusNotPrimary", status)
	}
	if len(failed) != 1 {
		t.Fatalf("failed = %d, want 1", len(failed))
	}
}

func TestManager_MLR_EmptyAddresses(t *testing.T) {
	deps := &mockManagerDeps{isPrimary: true}
	m := NewManager(deps)

	failed, status := m.HandleMulticastListenerRegistration(nil, 3600, 1000)

	if status != MlrStatusInvalid {
		t.Fatalf("status = %d, want MlrStatusInvalid", status)
	}
	if failed != nil {
		t.Fatalf("failed = %v, want nil", failed)
	}
}

func TestManager_MLR_RemoveWithZeroTimeout(t *testing.T) {
	deps := &mockManagerDeps{isPrimary: true}
	m := NewManager(deps)

	// Add first.
	addrs := [][16]byte{mcastAddr(1)}
	m.HandleMulticastListenerRegistration(addrs, 3600, 1000)

	// Remove with timeout=0.
	_, status := m.HandleMulticastListenerRegistration(addrs, 0, 2000)
	if status != MlrStatusSuccess {
		t.Fatalf("status = %d, want MlrStatusSuccess", status)
	}
	if m.GetMulticastListenersTable().Count() != 0 {
		t.Fatalf("listeners = %d, want 0", m.GetMulticastListenersTable().Count())
	}
}

func TestManager_MLR_TableFull(t *testing.T) {
	deps := &mockManagerDeps{isPrimary: true}
	m := NewManager(deps, WithManagerListenerOptions(WithMaxListeners(1)))

	addrs := [][16]byte{mcastAddr(1), mcastAddr(2)}
	failed, status := m.HandleMulticastListenerRegistration(addrs, 3600, 1000)

	if status != MlrStatusNoResources {
		t.Fatalf("status = %d, want MlrStatusNoResources", status)
	}
	if len(failed) != 1 {
		t.Fatalf("failed = %d, want 1", len(failed))
	}
}

// ---------------------------------------------------------------------------
// HandleDuaRegistration
// ---------------------------------------------------------------------------

func TestManager_DUA_Success(t *testing.T) {
	deps := &mockManagerDeps{isPrimary: true}
	m := NewManager(deps)

	status := m.HandleDuaRegistration(iid(1), iid(0xA0), 0x0400, nil, 1000)
	if status != DuaStatusSuccess {
		t.Fatalf("status = %d, want DuaStatusSuccess", status)
	}
	if m.GetNdProxyTable().Count() != 1 {
		t.Fatalf("ndproxy count = %d, want 1", m.GetNdProxyTable().Count())
	}
}

func TestManager_DUA_NotPrimary(t *testing.T) {
	deps := &mockManagerDeps{isPrimary: false}
	m := NewManager(deps)

	status := m.HandleDuaRegistration(iid(1), iid(0xA0), 0x0400, nil, 1000)
	if status != DuaStatusNotPrimary {
		t.Fatalf("status = %d, want DuaStatusNotPrimary", status)
	}
}

func TestManager_DUA_Duplicate(t *testing.T) {
	deps := &mockManagerDeps{isPrimary: true}
	m := NewManager(deps)

	m.HandleDuaRegistration(iid(1), iid(0xA0), 0x0400, nil, 1000)
	// Same address IID, different mesh-local IID → duplicate.
	status := m.HandleDuaRegistration(iid(1), iid(0xB0), 0x0800, nil, 2000)
	if status != DuaStatusDuplicateAddress {
		t.Fatalf("status = %d, want DuaStatusDuplicateAddress", status)
	}
}

func TestManager_DUA_NoResources(t *testing.T) {
	deps := &mockManagerDeps{isPrimary: true}
	m := NewManager(deps, WithManagerNdProxyOptions(WithMaxNdProxies(1)))

	m.HandleDuaRegistration(iid(1), iid(0xA0), 0x0400, nil, 1000)
	status := m.HandleDuaRegistration(iid(2), iid(0xB0), 0x0800, nil, 2000)
	if status != DuaStatusNoResources {
		t.Fatalf("status = %d, want DuaStatusNoResources", status)
	}
}

// ---------------------------------------------------------------------------
// HandleBackboneQuery
// ---------------------------------------------------------------------------

func TestManager_BackboneQuery_Found(t *testing.T) {
	deps := &mockManagerDeps{isPrimary: true}
	m := NewManager(deps)

	// Register and complete DAD.
	m.HandleDuaRegistration(iid(1), iid(0xA0), 0x0400, nil, 1000)
	for i := 0; i < int(DuaDadRepeats)+1; i++ {
		m.GetNdProxyTable().HandleTimer(1000)
	}

	answer := m.HandleBackboneQuery(iid(1))
	if answer == nil {
		t.Fatal("expected non-nil answer")
	}
	if answer.MeshLocalIid != iid(0xA0) {
		t.Fatalf("MeshLocalIid = %v, want %v", answer.MeshLocalIid, iid(0xA0))
	}
	if answer.Rloc16 != 0x0400 {
		t.Fatalf("Rloc16 = 0x%04x, want 0x0400", answer.Rloc16)
	}
}

func TestManager_BackboneQuery_NotFound(t *testing.T) {
	deps := &mockManagerDeps{isPrimary: true}
	m := NewManager(deps)

	answer := m.HandleBackboneQuery(iid(99))
	if answer != nil {
		t.Fatal("expected nil answer for non-existent entry")
	}
}

func TestManager_BackboneQuery_DadInProgress(t *testing.T) {
	deps := &mockManagerDeps{isPrimary: true}
	m := NewManager(deps)

	m.HandleDuaRegistration(iid(1), iid(0xA0), 0x0400, nil, 1000)
	// DAD not completed — ResolveDua returns nil.
	answer := m.HandleBackboneQuery(iid(1))
	if answer != nil {
		t.Fatal("expected nil answer while DAD in progress")
	}
}

// ---------------------------------------------------------------------------
// HandleBackboneAnswer
// ---------------------------------------------------------------------------

func TestManager_BackboneAnswer_DuplicateRemovesProxy(t *testing.T) {
	deps := &mockManagerDeps{isPrimary: true}
	var removedCount int
	m := NewManager(deps, WithManagerNdProxyOptions(
		WithNdProxyCallback(func(e NdProxyEvent, _ [8]byte) {
			if e == NdProxyRemoved {
				removedCount++
			}
		}),
	))

	m.HandleDuaRegistration(iid(1), iid(0xA0), 0x0400, nil, 1000)
	// Backbone answer for same IID → marks as duplicated.
	m.HandleBackboneAnswer(iid(1), iid(0xB0), nil, 0, 2000)

	if m.GetNdProxyTable().Count() != 0 {
		t.Fatalf("ndproxy count = %d, want 0", m.GetNdProxyTable().Count())
	}
	if removedCount != 1 {
		t.Fatalf("removedCount = %d, want 1", removedCount)
	}
}

func TestManager_BackboneAnswer_ProactiveRegistration(t *testing.T) {
	deps := &mockManagerDeps{isPrimary: true}
	m := NewManager(deps)

	rloc := uint16(0x0800)
	m.HandleBackboneAnswer(iid(5), iid(0xC0), &rloc, 60, 5000)

	if m.GetNdProxyTable().Count() != 1 {
		t.Fatalf("ndproxy count = %d, want 1", m.GetNdProxyTable().Count())
	}
}

func TestManager_BackboneAnswer_UnknownIid_NoRloc(t *testing.T) {
	deps := &mockManagerDeps{isPrimary: true}
	m := NewManager(deps)

	// Unknown IID, no RLOC — should be a no-op.
	m.HandleBackboneAnswer(iid(99), iid(0xD0), nil, 0, 1000)

	if m.GetNdProxyTable().Count() != 0 {
		t.Fatalf("ndproxy count = %d, want 0", m.GetNdProxyTable().Count())
	}
}

// ---------------------------------------------------------------------------
// Status code constants
// ---------------------------------------------------------------------------

func TestManager_MlrStatusValues(t *testing.T) {
	if MlrStatusSuccess != 0 {
		t.Fatalf("MlrStatusSuccess = %d, want 0", MlrStatusSuccess)
	}
	if MlrStatusInvalid != 2 {
		t.Fatalf("MlrStatusInvalid = %d, want 2", MlrStatusInvalid)
	}
	if MlrStatusNoResources != 4 {
		t.Fatalf("MlrStatusNoResources = %d, want 4", MlrStatusNoResources)
	}
	if MlrStatusNotPrimary != 5 {
		t.Fatalf("MlrStatusNotPrimary = %d, want 5", MlrStatusNotPrimary)
	}
	if MlrStatusGeneralFailure != 6 {
		t.Fatalf("MlrStatusGeneralFailure = %d, want 6", MlrStatusGeneralFailure)
	}
}

func TestManager_DuaStatusValues(t *testing.T) {
	if DuaStatusSuccess != 0 {
		t.Fatalf("DuaStatusSuccess = %d, want 0", DuaStatusSuccess)
	}
	if DuaStatusReregistration != 1 {
		t.Fatalf("DuaStatusReregistration = %d, want 1", DuaStatusReregistration)
	}
	if DuaStatusInvalid != 2 {
		t.Fatalf("DuaStatusInvalid = %d, want 2", DuaStatusInvalid)
	}
	if DuaStatusDuplicateAddress != 3 {
		t.Fatalf("DuaStatusDuplicateAddress = %d, want 3", DuaStatusDuplicateAddress)
	}
	if DuaStatusNoResources != 4 {
		t.Fatalf("DuaStatusNoResources = %d, want 4", DuaStatusNoResources)
	}
	if DuaStatusNotPrimary != 5 {
		t.Fatalf("DuaStatusNotPrimary = %d, want 5", DuaStatusNotPrimary)
	}
	if DuaStatusGeneralFailure != 6 {
		t.Fatalf("DuaStatusGeneralFailure = %d, want 6", DuaStatusGeneralFailure)
	}
}
