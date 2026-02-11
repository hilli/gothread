// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"testing"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/routing"
)

// --------------------------------------------------------------------------
// Tier 1 — Module creation and wiring
// --------------------------------------------------------------------------

func TestWireModules_Tier1_ModulesCreated(t *testing.T) {
	inst := New(Config{})

	if inst.MessagePool() == nil {
		t.Error("MessagePool should be created")
	}
	if inst.KeyManager() == nil {
		t.Error("KeyManager should be created")
	}
	if inst.SubMac() == nil {
		t.Error("SubMac should be created")
	}
	if inst.Mac() == nil {
		t.Error("Mac should be created")
	}
}

func TestWireModules_Tier1_SettingsWithNilPlatform(t *testing.T) {
	inst := New(Config{})

	// With no platform settings, stackSettings should be nil.
	if inst.stackSettings != nil {
		t.Error("stackSettings should be nil when no platform.Settings provided")
	}
}

func TestWireModules_Tier1_SettingsWithPlatform(t *testing.T) {
	ms := &mockSettings{}
	inst := New(Config{Settings: ms})

	if inst.stackSettings == nil {
		t.Error("stackSettings should be created when platform.Settings provided")
	}
}

func TestWireModules_Tier1_MacCallbacksInterface(t *testing.T) {
	inst := New(Config{})

	// Instance should satisfy mac.Callbacks via HandleFrameRequest,
	// HandleSentFrame, HandleReceivedFrame.
	frame := &radio.Frame{PSDU: make([]byte, 10)}

	// These should not panic with nil modules.
	got := inst.HandleFrameRequest(frame)
	if got {
		t.Error("HandleFrameRequest should return false (stub)")
	}

	inst.HandleSentFrame(frame, nil)
	inst.HandleReceivedFrame(frame)
}

func TestWireModules_Tier1_SubmacCallbackBridge(t *testing.T) {
	bridge := &submacCallbackBridge{}

	// All methods should be safe to call with nil target.
	frame := &radio.Frame{PSDU: make([]byte, 10)}
	bridge.ReceiveDone(frame, nil)
	bridge.TransmitDone(frame, nil, nil)
	bridge.RecordFrameTransmitStatus(frame, nil, 0, false)
	bridge.RecordCcaStatus(true, 11)
	bridge.EnergyScanDone(-50)
	bridge.FrameCounterUsed(42)
}

// --------------------------------------------------------------------------
// Tier 1 — KeyProvider delegation
// --------------------------------------------------------------------------

func TestWireModules_Tier1_KeyProviderDelegation(t *testing.T) {
	inst := New(Config{})

	// Key manager starts at sequence 0.
	if seq := inst.GetCurrentKeySequence(); seq != 0 {
		t.Errorf("GetCurrentKeySequence() = %d, want 0", seq)
	}

	// Set and verify.
	inst.SetCurrentKeySequence(42, key.ForceUpdate)
	if seq := inst.GetCurrentKeySequence(); seq != 42 {
		t.Errorf("after set, GetCurrentKeySequence() = %d, want 42", seq)
	}

	// Frame counter should start at 0.
	if fc := inst.GetMleFrameCounter(); fc != 0 {
		t.Errorf("GetMleFrameCounter() = %d, want 0", fc)
	}

	inst.IncrementMleFrameCounter()
	if fc := inst.GetMleFrameCounter(); fc != 1 {
		t.Errorf("after increment, GetMleFrameCounter() = %d, want 1", fc)
	}

	// MLE key should be non-panicking (may be all zeros with no network key set).
	_ = inst.GetCurrentMleKey()
	_ = inst.GetTemporaryMleKey(0)
	_ = inst.GetMacFrameCounter()
}

// --------------------------------------------------------------------------
// Tier 2 — Module creation and wiring
// --------------------------------------------------------------------------

func TestWireModules_Tier2_ModulesCreated(t *testing.T) {
	inst := New(Config{})

	if inst.RouterTable() == nil {
		t.Error("RouterTable should be created")
	}
	if inst.ChildTable() == nil {
		t.Error("ChildTable should be created")
	}
	if inst.NeighborTable() == nil {
		t.Error("NeighborTable should be created")
	}
	if inst.MleService() == nil {
		t.Error("MleService should be created")
	}
	if inst.Netif() == nil {
		t.Error("Netif should be created")
	}
	if inst.UDPManager() == nil {
		t.Error("UDPManager should be created")
	}
}

func TestWireModules_Tier2_TransportInterface(t *testing.T) {
	inst := New(Config{})

	// SendMLE should not panic.
	err := inst.SendMLE([]byte{0x01}, ip6.Address{})
	if err != nil {
		t.Errorf("SendMLE() error: %v", err)
	}

	// GetExtAddress should return zero address (no MAC configured).
	ext := inst.GetExtAddress()
	if ext != (types.ExtAddress{}) {
		t.Errorf("GetExtAddress() = %v, want zero", ext)
	}

	// GetLinkLocalAllRoutersMulticast should return ff02::2.
	allRouters := inst.GetLinkLocalAllRoutersMulticast()
	if allRouters[0] != 0xff || allRouters[1] != 0x02 || allRouters[15] != 0x02 {
		t.Errorf("GetLinkLocalAllRoutersMulticast() = %v, want ff02::2", allRouters)
	}
}

func TestWireModules_Tier2_RouterLookup(t *testing.T) {
	inst := New(Config{})

	// With no routers allocated, lookups should return nil.
	r := inst.FindRouterByRLOC16(0x0400)
	if r != nil {
		t.Error("FindRouterByRLOC16 should return nil for empty table")
	}

	r = inst.FindRouterByExtAddress(types.ExtAddress{1, 2, 3, 4, 5, 6, 7, 8})
	if r != nil {
		t.Error("FindRouterByExtAddress should return nil for empty table")
	}

	r = inst.FindRouterByID(1)
	if r != nil {
		t.Error("FindRouterByID should return nil for empty table")
	}
}

func TestWireModules_Tier2_AdvertisementRouterOps(t *testing.T) {
	inst := New(Config{})

	// With an empty table, active router count should be 0.
	if n := inst.GetActiveRouterCount(); n != 0 {
		t.Errorf("GetActiveRouterCount() = %d, want 0", n)
	}

	if n := inst.GetNeighborCount(1); n != 0 {
		t.Errorf("GetNeighborCount(1) = %d, want 0", n)
	}

	if inst.IsAllocated(0) {
		t.Error("IsAllocated(0) should be false for empty table")
	}

	// GetRouterIDSequence should be 0 initially.
	if seq := inst.GetRouterIDSequence(); seq != 0 {
		t.Errorf("GetRouterIDSequence() = %d, want 0", seq)
	}

	// UpdateRouterIDSet should work.
	var idSet mle.RouterIDSet
	idSet.Add(1)
	idSet.Add(5)
	changed := inst.UpdateRouterIDSet(1, idSet, 1000)
	if !changed {
		t.Error("UpdateRouterIDSet should return true when set changes")
	}

	if !inst.IsAllocated(1) {
		t.Error("Router ID 1 should be allocated after UpdateRouterIDSet")
	}
	if !inst.IsAllocated(5) {
		t.Error("Router ID 5 should be allocated after UpdateRouterIDSet")
	}

	// GetActiveRouterCount counts routers with StateValid, not just
	// allocated IDs. After UpdateRouterIDSet, routers are allocated
	// but not yet in StateValid, so count remains 0.
	if n := inst.GetActiveRouterCount(); n != 0 {
		t.Errorf("GetActiveRouterCount() = %d, want 0 (allocated but not valid)", n)
	}

	// Verify router ID sequence was updated.
	if seq := inst.GetRouterIDSequence(); seq != 1 {
		t.Errorf("GetRouterIDSequence() = %d, want 1", seq)
	}
}

func TestWireModules_Tier2_RouteDataProvider(t *testing.T) {
	inst := New(Config{})

	// Allocate a couple of routers first.
	var idSet mle.RouterIDSet
	idSet.Add(0)
	idSet.Add(3)
	inst.UpdateRouterIDSet(1, idSet, 1000)

	// Get route data.
	seq, mask, entries := inst.GetRouteData(0, 0)
	if seq != 1 {
		t.Errorf("sequence = %d, want 1", seq)
	}
	if !mask.Contains(0) || !mask.Contains(3) {
		t.Error("mask should contain router IDs 0 and 3")
	}
	if len(entries) != 2 {
		t.Errorf("len(entries) = %d, want 2", len(entries))
	}
}

func TestWireModules_Tier2_ConnectivityProvider(t *testing.T) {
	inst := New(Config{})

	tlv := inst.GetConnectivityTLV()
	if tlv.ActiveRouters != 0 {
		t.Errorf("ActiveRouters = %d, want 0", tlv.ActiveRouters)
	}
}

func TestWireModules_Tier2_NetworkInfoProvider(t *testing.T) {
	inst := New(Config{})

	if name := inst.GetNetworkName(); name != "" {
		t.Errorf("GetNetworkName() = %q, want empty", name)
	}

	if epid := inst.GetExtendedPanID(); epid != ([8]byte{}) {
		t.Errorf("GetExtendedPanID() = %v, want zero", epid)
	}

	if sd := inst.GetSteeringData(); sd != nil {
		t.Errorf("GetSteeringData() = %v, want nil", sd)
	}

	if inst.IsNativeCommissioner() {
		t.Error("IsNativeCommissioner() should be false by default")
	}
}

func TestWireModules_Tier2_RemoveRouterLink(t *testing.T) {
	inst := New(Config{})

	// Should not panic with nil.
	inst.RemoveRouterLink(nil)

	// Should not panic with a router not in the table.
	inst.RemoveRouterLink(&mle.Router{
		Neighbor: mle.Neighbor{
			MacAddr: types.ExtAddress{9, 9, 9, 9, 9, 9, 9, 9},
		},
	})
}

// --------------------------------------------------------------------------
// Tier 3 — Module creation and wiring
// --------------------------------------------------------------------------

func TestWireModules_Tier3_ModulesCreated(t *testing.T) {
	inst := New(Config{})

	if inst.CoapEngine() == nil {
		t.Error("CoapEngine should be created")
	}
	if inst.TmfAgent() == nil {
		t.Error("TmfAgent should be created")
	}
	if inst.NetdataLeader() == nil {
		t.Error("NetdataLeader should be created")
	}
	if inst.Forwarder() == nil {
		t.Error("Forwarder should be created")
	}
}

func TestWireModules_Tier3_RouterCheckerAdapter(t *testing.T) {
	inst := New(Config{})

	// Allocate a router and verify the netdata leader can check it
	// through the routerCheckerAdapter.
	var idSet mle.RouterIDSet
	idSet.Add(7)
	inst.UpdateRouterIDSet(1, idSet, 1000)

	// The routerCheckerAdapter delegates to the routing table.
	adapter := &routerCheckerAdapter{rt: inst.routerTable}
	if !adapter.IsRouterIDAllocated(7) {
		t.Error("Router ID 7 should be allocated")
	}
	if adapter.IsRouterIDAllocated(8) {
		t.Error("Router ID 8 should not be allocated")
	}
}

// --------------------------------------------------------------------------
// Adapter unit tests
// --------------------------------------------------------------------------

func TestSettingsDriverAdapter(t *testing.T) {
	ms := &mockSettings{store: make(map[uint16][]byte)}
	adapter := &settingsDriverAdapter{ps: ms}

	if err := adapter.Init(); err != nil {
		t.Errorf("Init() error: %v", err)
	}

	if err := adapter.Set(1, []byte{0xAA}); err != nil {
		t.Errorf("Set() error: %v", err)
	}

	data, err := adapter.Get(1, 0)
	if err != nil {
		t.Errorf("Get() error: %v", err)
	}
	if len(data) != 1 || data[0] != 0xAA {
		t.Errorf("Get() = %v, want [0xAA]", data)
	}

	if err := adapter.Add(2, []byte{0xBB}); err != nil {
		t.Errorf("Add() error: %v", err)
	}

	if err := adapter.Delete(1, 0); err != nil {
		t.Errorf("Delete() error: %v", err)
	}

	if _, err := adapter.Get(1, 0); err == nil {
		t.Error("Get() should error after Delete()")
	}

	if err := adapter.Wipe(); err != nil {
		t.Errorf("Wipe() error: %v", err)
	}

	adapter.Deinit()
}

func TestNeighborToMLE(t *testing.T) {
	// nil input should return nil.
	if neighborToMLE(nil) != nil {
		t.Error("neighborToMLE(nil) should return nil")
	}

	// Convert a routing neighbor.
	rn := &routing.Neighbor{
		ExtAddress:       types.ExtAddress{1, 2, 3, 4, 5, 6, 7, 8},
		LastHeard:        5000,
		KeySequence:      10,
		RLOC16:           0x0400,
		Mode:             mle.NewDeviceMode(0x0F),
		LinkFailures:     2,
		Version:          4,
		LinkFrameCounter: 100,
		MleFrameCounter:  200,
	}

	mn := neighborToMLE(rn)
	if mn == nil {
		t.Fatal("neighborToMLE returned nil")
	}
	if mn.MacAddr != rn.ExtAddress {
		t.Error("MacAddr mismatch")
	}
	if mn.RLOC16 != 0x0400 {
		t.Errorf("RLOC16 = %#04x, want 0x0400", mn.RLOC16)
	}
	if mn.KeySequence != 10 {
		t.Errorf("KeySequence = %d, want 10", mn.KeySequence)
	}
	if mn.Counters.LinkFrameCounter != 100 {
		t.Errorf("LinkFrameCounter = %d, want 100", mn.Counters.LinkFrameCounter)
	}
	if mn.Counters.MleFrameCounter != 200 {
		t.Errorf("MleFrameCounter = %d, want 200", mn.Counters.MleFrameCounter)
	}
}

func TestRouterToMLE(t *testing.T) {
	if routerToMLE(nil) != nil {
		t.Error("routerToMLE(nil) should return nil")
	}
}

func TestScheduleTimerDirect(t *testing.T) {
	inst := New(Config{})

	called := false
	inst.scheduleTimerDirect(0, func() { called = true })

	if inst.timers.count() != 1 {
		t.Errorf("timers.count() = %d, want 1", inst.timers.count())
	}

	inst.timers.processExpired()
	if !called {
		t.Error("timer should have fired")
	}
}

func TestSendCoAP(t *testing.T) {
	inst := New(Config{})
	// sendCoAP is a stub — should not error.
	err := inst.sendCoAP([]byte{0x01}, coap.MessageInfo{})
	if err != nil {
		t.Errorf("sendCoAP() error: %v", err)
	}
}

// --------------------------------------------------------------------------
// Mock types
// --------------------------------------------------------------------------

// mockSettings implements platform.Settings for testing.
type mockSettings struct {
	store map[uint16][]byte
}

func (ms *mockSettings) Get(key platform.SettingsKey) ([]byte, error) {
	k := uint16(key)
	if ms.store == nil {
		return nil, errNotFound
	}
	data, ok := ms.store[k]
	if !ok {
		return nil, errNotFound
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	return cp, nil
}

func (ms *mockSettings) Set(key platform.SettingsKey, value []byte) error {
	if ms.store == nil {
		ms.store = make(map[uint16][]byte)
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	ms.store[uint16(key)] = cp
	return nil
}

func (ms *mockSettings) Add(key platform.SettingsKey, value []byte) error {
	return ms.Set(key, value)
}

func (ms *mockSettings) Delete(key platform.SettingsKey) error {
	if ms.store != nil {
		delete(ms.store, uint16(key))
	}
	return nil
}

func (ms *mockSettings) Wipe() error {
	ms.store = make(map[uint16][]byte)
	return nil
}

var errNotFound = &instanceError{msg: "not found"}
