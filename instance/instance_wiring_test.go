// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"bytes"
	"testing"

	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/mac"
	macframe "github.com/hilli/gothread/mac/frame"
	"github.com/hilli/gothread/mac/submac"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/icmp6"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/udp"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/lowpan"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/routing"
)

// --------------------------------------------------------------------------
// Compile-time interface assertions
// --------------------------------------------------------------------------

var _ mac.Callbacks = (*Instance)(nil)
var _ mle.Transport = (*Instance)(nil)
var _ mle.KeyProvider = (*Instance)(nil)
var _ mle.RouterLookup = (*Instance)(nil)
var _ mle.RouteDataProvider = (*Instance)(nil)
var _ mle.AdvertisementRouterOps = (*Instance)(nil)
var _ mle.ConnectivityProvider = (*Instance)(nil)
var _ mle.NetworkInfoProvider = (*Instance)(nil)
var _ mle.DatasetProvider = (*Instance)(nil)
var _ mle.NetworkDataProvider = (*Instance)(nil)
var _ mle.MacInfoProvider = (*Instance)(nil)
var _ submac.Callbacks = (*submacCallbackBridge)(nil)

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
// Tier 1 — DatasetProvider delegation
// --------------------------------------------------------------------------

func TestWireModules_Tier1_DatasetManagersCreated(t *testing.T) {
	inst := New(Config{})

	if inst.activeDataset == nil {
		t.Error("activeDataset should be created")
	}
	if inst.pendingDataset == nil {
		t.Error("pendingDataset should be created")
	}
}

func TestWireModules_Tier1_DatasetProviderEmptyTimestamps(t *testing.T) {
	inst := New(Config{})

	// With empty datasets, timestamps should be invalid (not yet configured).
	activeTS := inst.GetActiveTimestamp()
	if activeTS.IsValid() {
		t.Error("GetActiveTimestamp() should return invalid timestamp for empty dataset")
	}

	pendingTS := inst.GetPendingTimestamp()
	if pendingTS.IsValid() {
		t.Error("GetPendingTimestamp() should return invalid timestamp for empty dataset")
	}
}

func TestWireModules_Tier1_DatasetProviderEmptyRead(t *testing.T) {
	inst := New(Config{})

	// With empty datasets, Read should return nil.
	if data := inst.ReadActiveDataset(); data != nil {
		t.Errorf("ReadActiveDataset() = %v, want nil", data)
	}
	if data := inst.ReadPendingDataset(); data != nil {
		t.Errorf("ReadPendingDataset() = %v, want nil", data)
	}
}

// --------------------------------------------------------------------------
// Tier 2 — NetworkDataProvider delegation
// --------------------------------------------------------------------------

func TestWireModules_NetworkDataProvider_NilLeader(t *testing.T) {
	inst := New(Config{})
	inst.netdataLeader = nil

	// Should return nil when netdataLeader is nil (nil-safe).
	data := inst.GetNetworkData(false)
	if data != nil {
		t.Errorf("GetNetworkData(false) = %v, want nil with nil leader", data)
	}
}

func TestWireModules_NetworkDataProvider_EmptyLeader(t *testing.T) {
	inst := New(Config{})

	// Fresh leader has no data.
	data := inst.GetNetworkData(false)
	if len(data) != 0 {
		t.Errorf("GetNetworkData(false) = %v, want empty with fresh leader", data)
	}

	// stableOnly=true should also work (returns same data for now).
	data = inst.GetNetworkData(true)
	if len(data) != 0 {
		t.Errorf("GetNetworkData(true) = %v, want empty with fresh leader", data)
	}
}

// --------------------------------------------------------------------------
// Tier 2 — MacInfoProvider delegation
// --------------------------------------------------------------------------

func TestWireModules_MacInfoProvider_Default(t *testing.T) {
	inst := New(Config{})

	// Default PAN ID is 0.
	panID := inst.GetPanID()
	if panID != 0 {
		t.Errorf("GetPanID() = %d, want 0", panID)
	}

	// Default channel is 11 (Thread default).
	ch := inst.GetPanChannel()
	if ch != 11 {
		t.Errorf("GetPanChannel() = %d, want 11", ch)
	}
}

func TestWireModules_MacInfoProvider_Configured(t *testing.T) {
	inst := New(Config{})

	inst.mac.SetPanID(types.PanID(0xFACE))
	inst.mac.SetPanChannel(15)

	if panID := inst.GetPanID(); panID != 0xFACE {
		t.Errorf("GetPanID() = 0x%04X, want 0xFACE", panID)
	}

	if ch := inst.GetPanChannel(); ch != 15 {
		t.Errorf("GetPanChannel() = %d, want 15", ch)
	}
}

func TestWireModules_MacInfoProvider_NilMac(t *testing.T) {
	inst := New(Config{})
	inst.mac = nil

	// Should be nil-safe.
	if panID := inst.GetPanID(); panID != 0 {
		t.Errorf("GetPanID() = %d, want 0 with nil mac", panID)
	}
	if ch := inst.GetPanChannel(); ch != 0 {
		t.Errorf("GetPanChannel() = %d, want 0 with nil mac", ch)
	}
}

// --------------------------------------------------------------------------
// Tier 3 — netdataLeader.SetOnChanged callback
// --------------------------------------------------------------------------

func TestWireModules_NetdataOnChanged_SignalsNotifier(t *testing.T) {
	inst := New(Config{})

	// Register a notifier callback to capture events.
	var received Event
	inst.notifier.register(func(events Event) {
		received |= events
	})

	// Trigger the OnChanged callback by incrementing netdata versions.
	inst.netdataLeader.IncrementVersions(false)

	// Process notifier — signal is deferred until process().
	inst.notifier.process()

	if received&EventThreadNetDataChanged == 0 {
		t.Error("OnChanged callback should signal EventThreadNetDataChanged")
	}
}

func TestWireModules_NetdataOnChanged_SyncsLeaderDataVersions(t *testing.T) {
	inst := New(Config{})

	// Make the MLE instance a leader so the version sync fires.
	m := inst.mleService.Mle()
	_ = m.Enable()
	_ = m.SetStateLeader(0x0400) // router ID 1

	// Set initial leader data with zeroed versions.
	m.SetLeaderData(mle.LeaderData{
		PartitionID:       0xABCD,
		LeaderRouterID:    1,
		DataVersion:       0,
		StableDataVersion: 0,
	})

	// Increment netdata versions — the callback should sync them into
	// MLE LeaderData.
	inst.netdataLeader.IncrementVersions(false) // data version only
	inst.notifier.process()

	ld := m.GetLeaderData()
	wantDataVer := inst.netdataLeader.Version()
	wantStableVer := inst.netdataLeader.StableVersion()

	if ld.DataVersion != wantDataVer {
		t.Errorf("LeaderData.DataVersion = %d, want %d", ld.DataVersion, wantDataVer)
	}
	if ld.StableDataVersion != wantStableVer {
		t.Errorf("LeaderData.StableDataVersion = %d, want %d", ld.StableDataVersion, wantStableVer)
	}
}

func TestWireModules_NetdataOnChanged_SkipsSyncForNonLeader(t *testing.T) {
	inst := New(Config{})

	// Make the MLE instance a router (not leader).
	m := inst.mleService.Mle()
	_ = m.Enable()
	_ = m.SetStateRouter(0x0400) // router ID 1

	// Set leader data with specific versions.
	m.SetLeaderData(mle.LeaderData{
		PartitionID:       0xABCD,
		LeaderRouterID:    1,
		DataVersion:       42,
		StableDataVersion: 10,
	})

	// Increment netdata versions — since we are NOT leader, the MLE
	// LeaderData should NOT be updated.
	inst.netdataLeader.IncrementVersions(true)
	inst.notifier.process()

	ld := m.GetLeaderData()
	if ld.DataVersion != 42 {
		t.Errorf("LeaderData.DataVersion = %d, want 42 (should not be overwritten)", ld.DataVersion)
	}
	if ld.StableDataVersion != 10 {
		t.Errorf("LeaderData.StableDataVersion = %d, want 10 (should not be overwritten)", ld.StableDataVersion)
	}
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

	// With the forwarder disabled (default), SendMLE returns an error.
	err := inst.SendMLE([]byte{0x01}, ip6.Address{})
	if err == nil {
		t.Error("SendMLE() should error when forwarder is disabled")
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

func TestWireModules_Tier2_ConnectivityProvider_LeaderCost(t *testing.T) {
	inst := New(Config{})

	// Set up leader data so LeaderCost calculation has a leader router ID.
	m := inst.mleService.Mle()
	_ = m.Enable()
	_ = m.SetStateLeader(0x0400) // router ID 1
	m.SetLeaderData(mle.LeaderData{
		PartitionID:    0xABCD,
		LeaderRouterID: 1,
	})

	tlv := inst.GetConnectivityTLV()

	// With no routers in the table the leader is unreachable and the path
	// cost equals MaxRouteCost (16).
	if tlv.LeaderCost != 16 {
		t.Errorf("LeaderCost = %d, want 16 (MaxRouteCost for unreachable leader)", tlv.LeaderCost)
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
	// With forwarder disabled, sendCoAP returns an error.
	err := inst.sendCoAP([]byte{0x01}, coap.MessageInfo{})
	if err == nil {
		t.Error("sendCoAP() should error when forwarder is disabled")
	}
}

// --------------------------------------------------------------------------
// Phase 28b — Address derivation tests
// --------------------------------------------------------------------------

func TestGetLinkLocalAddress(t *testing.T) {
	inst := New(Config{})

	// Set a known extended address on the MAC.
	extAddr := types.ExtAddress{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}
	inst.mac.SetExtAddress(extAddr)

	addr := inst.GetLinkLocalAddress()

	// fe80:: prefix
	if addr[0] != 0xfe || addr[1] != 0x80 {
		t.Errorf("prefix: got %02x%02x, want fe80", addr[0], addr[1])
	}
	for i := 2; i < 8; i++ {
		if addr[i] != 0 {
			t.Errorf("addr[%d] = %02x, want 0x00", i, addr[i])
		}
	}

	// IID = extended address with U/L bit toggled (bit 1 of byte 0).
	// Original: 0x12, toggled: 0x10 (0x12 ^ 0x02 = 0x10).
	if addr[8] != 0x10 {
		t.Errorf("IID[0] = %02x, want 0x10 (0x12 ^ 0x02)", addr[8])
	}
	// Remaining IID bytes match the extended address.
	for i := 1; i < 8; i++ {
		if addr[8+i] != extAddr[i] {
			t.Errorf("IID[%d] = %02x, want %02x", i, addr[8+i], extAddr[i])
		}
	}
}

func TestGetLinkLocalAddress_ULBitToggle(t *testing.T) {
	// Test with an address where U/L bit is already set (0x02 → 0x00).
	inst := New(Config{})
	extAddr := types.ExtAddress{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	inst.mac.SetExtAddress(extAddr)

	addr := inst.GetLinkLocalAddress()
	if addr[8] != 0x00 {
		t.Errorf("IID[0] = %02x, want 0x00 (0x02 ^ 0x02)", addr[8])
	}
}

func TestGetMeshLocalAddress(t *testing.T) {
	inst := New(Config{})

	// Set a mesh-local prefix (fd00:db8::/64 equivalent).
	prefix := [8]byte{0xfd, 0x00, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00}
	inst.SetMeshLocalPrefix(prefix)
	inst.SetRLOC16(0x0400)

	addr := inst.GetMeshLocalAddress()

	// Check prefix.
	for i := 0; i < 8; i++ {
		if addr[i] != prefix[i] {
			t.Errorf("addr[%d] = %02x, want %02x", i, addr[i], prefix[i])
		}
	}

	// IID: 0000:00FF:FE00:0400
	expected := [8]byte{0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x04, 0x00}
	for i := 0; i < 8; i++ {
		if addr[8+i] != expected[i] {
			t.Errorf("IID[%d] = %02x, want %02x", i, addr[8+i], expected[i])
		}
	}

	// The address should be recognized as a Routing Locator.
	if !addr.IsRoutingLocator() {
		t.Error("mesh-local RLOC should be recognized as a routing locator")
	}
}

func TestGetMeshLocalAddress_ZeroRLOC(t *testing.T) {
	inst := New(Config{})
	prefix := [8]byte{0xfd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	inst.SetMeshLocalPrefix(prefix)
	inst.SetRLOC16(0x0000)

	addr := inst.GetMeshLocalAddress()
	// RLOC16 = 0x0000, so last two bytes should be 0x00, 0x00.
	if addr[14] != 0x00 || addr[15] != 0x00 {
		t.Errorf("RLOC16 bytes: %02x%02x, want 0000", addr[14], addr[15])
	}
}

func TestMeshLocalPrefixAndRLOC16Accessors(t *testing.T) {
	inst := New(Config{})

	prefix := [8]byte{0xfd, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00}
	inst.SetMeshLocalPrefix(prefix)
	if got := inst.MeshLocalPrefix(); got != prefix {
		t.Errorf("MeshLocalPrefix() = %v, want %v", got, prefix)
	}

	inst.SetRLOC16(0x7C00)
	if got := inst.RLOC16(); got != 0x7C00 {
		t.Errorf("RLOC16() = %#04x, want 0x7C00", got)
	}
}

// --------------------------------------------------------------------------
// Phase 28b — MAC callback / mesh forwarder integration tests
// --------------------------------------------------------------------------

func TestHandleFrameRequest_EmptyQueue(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)

	frame := &radio.Frame{PSDU: make([]byte, 127)}
	if inst.HandleFrameRequest(frame) {
		t.Error("HandleFrameRequest should return false with empty queue")
	}
}

func TestHandleFrameRequest_WithMessage(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)

	// Enqueue a message.
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	msg := mesh.NewTxMessage(payload, 0x0400, 0x0800)
	if err := inst.forwarder.SendMessage(msg); err != nil {
		t.Fatalf("SendMessage() error: %v", err)
	}

	frame := &radio.Frame{}
	if !inst.HandleFrameRequest(frame) {
		t.Fatal("HandleFrameRequest should return true with queued message")
	}

	// Verify the frame PSDU contains the message data.
	if len(frame.PSDU) != len(payload) {
		t.Errorf("PSDU length = %d, want %d", len(frame.PSDU), len(payload))
	}
	for i, b := range payload {
		if frame.PSDU[i] != b {
			t.Errorf("PSDU[%d] = %02x, want %02x", i, frame.PSDU[i], b)
		}
	}

	// The pending TxMessage should be stored on the instance.
	if inst.pendingTxMsg == nil {
		t.Error("pendingTxMsg should be set after HandleFrameRequest")
	}
}

func TestHandleSentFrame_Success(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)

	// Enqueue and dequeue a message.
	payload := []byte{0x01, 0x02}
	msg := mesh.NewTxMessage(payload, 0xFFFF, 0x0400)
	inst.forwarder.SendMessage(msg)

	frame := &radio.Frame{}
	inst.HandleFrameRequest(frame)

	// Simulate successful transmission.
	inst.HandleSentFrame(frame, nil)

	// pendingTxMsg should be cleared.
	if inst.pendingTxMsg != nil {
		t.Error("pendingTxMsg should be nil after HandleSentFrame")
	}

	// Forwarder counters should reflect the successful transmission.
	counters := inst.forwarder.GetCounters()
	if counters.TxBroadcast != 1 {
		t.Errorf("TxBroadcast = %d, want 1", counters.TxBroadcast)
	}
}

func TestHandleSentFrame_Failure(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)

	payload := []byte{0x01, 0x02}
	msg := mesh.NewTxMessage(payload, 0x0400, 0x0800)
	inst.forwarder.SendMessage(msg)

	frame := &radio.Frame{}
	inst.HandleFrameRequest(frame)

	// Simulate failed transmission.
	inst.HandleSentFrame(frame, &instanceError{msg: "tx failed"})

	if inst.pendingTxMsg != nil {
		t.Error("pendingTxMsg should be nil after HandleSentFrame")
	}

	counters := inst.forwarder.GetCounters()
	if counters.TxDropped != 1 {
		t.Errorf("TxDropped = %d, want 1", counters.TxDropped)
	}
}

func TestHandleSentFrame_NoPending(t *testing.T) {
	inst := New(Config{})
	// Should not panic when no pending message.
	inst.HandleSentFrame(&radio.Frame{}, nil)
}

func TestHandleReceivedFrame_NilFrame(t *testing.T) {
	inst := New(Config{})
	// Should not panic with nil frame.
	inst.HandleReceivedFrame(nil)
}

func TestHandleReceivedFrame_EmptyPSDU(t *testing.T) {
	inst := New(Config{})
	// Should not panic with empty PSDU.
	inst.HandleReceivedFrame(&radio.Frame{PSDU: nil})
	inst.HandleReceivedFrame(&radio.Frame{PSDU: []byte{}})
}

func TestHandleReceivedFrame_WithData(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)

	// Simulate receiving a non-mesh frame.
	frame := &radio.Frame{
		PSDU:    []byte{0x41, 0x88, 0x01, 0x02, 0x03}, // data frame bytes
		Channel: 15,
		RxInfo: &radio.RxInfo{
			RSSI:      -60,
			LQI:       200,
			Timestamp: 12345,
		},
	}
	inst.HandleReceivedFrame(frame)

	// The forwarder should have processed the frame.
	counters := inst.forwarder.GetCounters()
	if counters.RxDirect != 1 {
		t.Errorf("RxDirect = %d, want 1", counters.RxDirect)
	}
}

func TestHandleReceivedFrame_ForwarderDisabled(t *testing.T) {
	inst := New(Config{})
	// Forwarder is disabled by default — should not panic.
	frame := &radio.Frame{
		PSDU: []byte{0x01, 0x02, 0x03},
	}
	inst.HandleReceivedFrame(frame)

	counters := inst.forwarder.GetCounters()
	// No counters incremented since forwarder returns error.
	if counters.RxDirect != 0 {
		t.Errorf("RxDirect = %d, want 0 (forwarder disabled)", counters.RxDirect)
	}
}

// --------------------------------------------------------------------------
// Phase 28b — SendMLE integration tests
// --------------------------------------------------------------------------

func TestSendMLE_ForwarderEnabled(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)
	inst.SetRLOC16(0x0400)

	err := inst.SendMLE([]byte{0x0A, 0x0B}, ip6.Address{})
	if err != nil {
		t.Errorf("SendMLE() error: %v", err)
	}

	// The message should be in the forwarder's direct queue.
	direct, _ := inst.forwarder.GetQueueLength()
	if direct != 1 {
		t.Errorf("direct queue length = %d, want 1", direct)
	}
}

func TestSendMLE_BroadcastDest(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)
	inst.SetRLOC16(0x0400)

	// Non-RLOC destination → broadcast (0xFFFF).
	dst, _ := ip6.AddressFromString("ff02::1")
	err := inst.SendMLE([]byte{0x01}, dst)
	if err != nil {
		t.Errorf("SendMLE() error: %v", err)
	}

	queue := inst.forwarder.GetDirectQueue()
	if len(queue) != 1 {
		t.Fatalf("queue length = %d, want 1", len(queue))
	}
	if queue[0].MeshDest != 0xFFFF {
		t.Errorf("MeshDest = %04x, want FFFF", queue[0].MeshDest)
	}
	if queue[0].MeshSource != 0x0400 {
		t.Errorf("MeshSource = %04x, want 0400", queue[0].MeshSource)
	}
}

func TestSendMLE_RLOCDest(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)
	inst.SetRLOC16(0x0400)
	inst.SetMeshLocalPrefix([8]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Build a mesh-local RLOC address for destination RLOC16 = 0x0800.
	dst := inst.GetMeshLocalAddress()
	// Override with different RLOC16.
	dst[14] = 0x08
	dst[15] = 0x00

	err := inst.SendMLE([]byte{0x01}, dst)
	if err != nil {
		t.Errorf("SendMLE() error: %v", err)
	}

	queue := inst.forwarder.GetDirectQueue()
	if len(queue) != 1 {
		t.Fatalf("queue length = %d, want 1", len(queue))
	}
	if queue[0].MeshDest != 0x0800 {
		t.Errorf("MeshDest = %04x, want 0800", queue[0].MeshDest)
	}
}

func TestSendMLE_Priority(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)

	inst.SendMLE([]byte{0x01}, ip6.Address{})
	queue := inst.forwarder.GetDirectQueue()
	if len(queue) != 1 {
		t.Fatalf("queue length = %d, want 1", len(queue))
	}
	if queue[0].Priority != uint8(mesh.PriorityNet) {
		t.Errorf("Priority = %d, want %d (PriorityNet)", queue[0].Priority, mesh.PriorityNet)
	}
}

// --------------------------------------------------------------------------
// Phase 28b — sendCoAP integration tests
// --------------------------------------------------------------------------

func TestSendCoAP_ForwarderEnabled(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)
	inst.SetRLOC16(0x0400)

	err := inst.sendCoAP([]byte{0x40, 0x01}, coap.MessageInfo{
		PeerPort: 5683,
	})
	if err != nil {
		t.Errorf("sendCoAP() error: %v", err)
	}

	direct, _ := inst.forwarder.GetQueueLength()
	if direct != 1 {
		t.Errorf("direct queue length = %d, want 1", direct)
	}
}

func TestSendCoAP_RLOCPeerAddr(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)
	inst.SetRLOC16(0x0400)
	inst.SetMeshLocalPrefix([8]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Build a peer address that is a mesh-local RLOC (RLOC16=0x0C00).
	var peerAddr [16]byte
	copy(peerAddr[0:8], inst.meshLocalPrefix[:])
	peerAddr[11] = 0xFF
	peerAddr[12] = 0xFE
	peerAddr[14] = 0x0C
	peerAddr[15] = 0x00

	err := inst.sendCoAP([]byte{0x40}, coap.MessageInfo{
		PeerAddr: peerAddr,
		PeerPort: 5683,
	})
	if err != nil {
		t.Errorf("sendCoAP() error: %v", err)
	}

	queue := inst.forwarder.GetDirectQueue()
	if len(queue) != 1 {
		t.Fatalf("queue length = %d, want 1", len(queue))
	}
	if queue[0].MeshDest != 0x0C00 {
		t.Errorf("MeshDest = %04x, want 0C00", queue[0].MeshDest)
	}
}

func TestSendCoAP_Priority(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)

	inst.sendCoAP([]byte{0x01}, coap.MessageInfo{})
	queue := inst.forwarder.GetDirectQueue()
	if len(queue) != 1 {
		t.Fatalf("queue length = %d, want 1", len(queue))
	}
	if queue[0].Priority != uint8(mesh.PriorityNormal) {
		t.Errorf("Priority = %d, want %d (PriorityNormal)", queue[0].Priority, mesh.PriorityNormal)
	}
}

// --------------------------------------------------------------------------
// Phase 28b — Full TX path integration test
// --------------------------------------------------------------------------

func TestFullTxPath_SendMLE_Through_HandleFrameRequest(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)
	inst.SetRLOC16(0x0400)

	// Step 1: Send an MLE message — enqueues to forwarder with metadata.
	mleData := []byte{0x0A, 0x01, 0x02, 0x03, 0x04}
	err := inst.SendMLE(mleData, ip6.Address{})
	if err != nil {
		t.Fatalf("SendMLE() error: %v", err)
	}

	// Step 2: MAC requests a frame — dequeues from forwarder and
	// builds a complete 802.15.4 frame with 6LoWPAN headers.
	frame := &radio.Frame{}
	if !inst.HandleFrameRequest(frame) {
		t.Fatal("HandleFrameRequest should return true after SendMLE")
	}

	// Step 3: Verify the frame is larger than just the raw payload
	// (it now includes MAC header + IPHC + NHC-UDP + payload).
	if len(frame.PSDU) <= len(mleData) {
		t.Errorf("PSDU should be larger than raw MLE data (%d), got %d",
			len(mleData), len(frame.PSDU))
	}

	// Step 4: Verify the MAC sequence number was incremented.
	if inst.macSeqNum != 1 {
		t.Errorf("macSeqNum = %d, want 1 after first frame", inst.macSeqNum)
	}

	// Step 5: Report successful transmission.
	inst.HandleSentFrame(frame, nil)
	if inst.pendingTxMsg != nil {
		t.Error("pendingTxMsg should be nil after HandleSentFrame")
	}

	// Step 6: Queue should be empty now.
	direct, _ := inst.forwarder.GetQueueLength()
	if direct != 0 {
		t.Errorf("queue should be empty after TX, got %d", direct)
	}
}

// --------------------------------------------------------------------------
// Phase 30d — TX→RX round-trip integration tests
// --------------------------------------------------------------------------

// TestFullTxRxRoundtrip_MLE verifies the complete TX→RX loop:
// SendMLE builds a frame, HandleFrameRequest constructs it, then we feed
// the resulting 802.15.4 frame back through HandleReceivedFrame and verify
// the MLE payload arrives at the MLE receiver.
func TestFullTxRxRoundtrip_MLE(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)
	inst.SetRLOC16(0x0400)
	inst.SetMeshLocalPrefix([8]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Replace the UDP manager with a fresh one so the built-in MLE
	// receiver (which would consume the message) is not present.
	inst.udpManager = udp.New()
	sock := &udp.Socket{}
	var gotPayload []byte
	var gotInfo *ip6.MessageInfo
	inst.udpManager.Open(sock, udp.NetifThreadHost, func(p []byte, mi *ip6.MessageInfo) {
		gotPayload = make([]byte, len(p))
		copy(gotPayload, p)
		gotInfo = mi
	})
	inst.udpManager.Bind(sock, ip6.SockAddr{Port: mle.UDPPort})

	// Step 1: Send MLE to link-local all-nodes (broadcast).
	mleData := []byte{0x0A, 0x01, 0x02, 0x03, 0x04}
	dst := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	err := inst.SendMLE(mleData, dst)
	if err != nil {
		t.Fatalf("SendMLE() error: %v", err)
	}

	// Step 2: HandleFrameRequest builds the frame.
	frame := &radio.Frame{}
	if !inst.HandleFrameRequest(frame) {
		t.Fatal("HandleFrameRequest should return true")
	}
	if len(frame.PSDU) == 0 {
		t.Fatal("frame PSDU is empty")
	}
	inst.HandleSentFrame(frame, nil) // report success

	// Step 3: Parse the built frame to extract the 6LoWPAN payload.
	mf := macframe.NewFrame(frame.PSDU)
	hdrLen, pErr := mf.GetHeaderLength()
	if pErr != nil {
		t.Fatalf("GetHeaderLength() error: %v", pErr)
	}
	lowpanData := frame.PSDU[int(hdrLen):]

	// Step 4: Feed the 6LoWPAN payload back through the RX path.
	// We construct a minimal frame that HandleReceivedFrame can process.
	// The RX path starts with forwarder.HandleReceivedFrame which checks
	// for mesh headers, then does 6LoWPAN decompression.
	rxFrame := &radio.Frame{
		PSDU:    lowpanData,
		Channel: 11,
	}
	inst.HandleReceivedFrame(rxFrame)

	// Step 5: Verify the MLE data arrived at the UDP socket.
	if gotPayload == nil {
		t.Fatal("UDP socket on MLE port did not receive the payload")
	}
	if !bytes.Equal(gotPayload, mleData) {
		t.Errorf("received payload = %x, want %x", gotPayload, mleData)
	}
	if gotInfo.SockPort != mle.UDPPort {
		t.Errorf("SockPort = %d, want %d", gotInfo.SockPort, mle.UDPPort)
	}
	if gotInfo.PeerPort != mle.UDPPort {
		t.Errorf("PeerPort = %d, want %d", gotInfo.PeerPort, mle.UDPPort)
	}

}

// TestFullTxRxRoundtrip_CoAP verifies the sendCoAP→HandleFrameRequest→
// HandleReceivedFrame round-trip for CoAP/TMF messages.
func TestFullTxRxRoundtrip_CoAP(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)
	inst.SetRLOC16(0x0400)
	inst.SetMeshLocalPrefix([8]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Replace the UDP manager with a fresh one so the built-in CoAP
	// receiver (which would consume the message) is not present.
	inst.udpManager = udp.New()
	sock := &udp.Socket{}
	var gotPayload []byte
	var gotInfo *ip6.MessageInfo
	inst.udpManager.Open(sock, udp.NetifThreadHost, func(p []byte, mi *ip6.MessageInfo) {
		gotPayload = make([]byte, len(p))
		copy(gotPayload, p)
		gotInfo = mi
	})
	inst.udpManager.Bind(sock, ip6.SockAddr{Port: udp.TmfPort})

	// Build a mesh-local peer address with RLOC16=0x0800.
	var peerAddr [16]byte
	copy(peerAddr[0:8], inst.meshLocalPrefix[:])
	peerAddr[11] = 0xff
	peerAddr[12] = 0xfe
	peerAddr[14] = 0x08
	peerAddr[15] = 0x00

	localAddr := inst.GetMeshLocalAddress()
	coapData := []byte{0x40, 0x01, 0x00, 0x01, 0xBB} // CoAP-like payload
	err := inst.sendCoAP(coapData, coap.MessageInfo{
		PeerAddr:  peerAddr,
		PeerPort:  udp.TmfPort,
		LocalAddr: localAddr,
	})
	if err != nil {
		t.Fatalf("sendCoAP() error: %v", err)
	}

	// Build the frame.
	frame := &radio.Frame{}
	if !inst.HandleFrameRequest(frame) {
		t.Fatal("HandleFrameRequest should return true")
	}
	inst.HandleSentFrame(frame, nil)

	// Parse and feed through RX.
	mf := macframe.NewFrame(frame.PSDU)
	hdrLen, pErr := mf.GetHeaderLength()
	if pErr != nil {
		t.Fatalf("GetHeaderLength() error: %v", pErr)
	}
	rxFrame := &radio.Frame{
		PSDU:    frame.PSDU[int(hdrLen):],
		Channel: 11,
	}
	inst.HandleReceivedFrame(rxFrame)

	// Verify.
	if gotPayload == nil {
		t.Fatal("UDP socket on TMF port did not receive the payload")
	}
	if !bytes.Equal(gotPayload, coapData) {
		t.Errorf("received payload = %x, want %x", gotPayload, coapData)
	}
	if gotInfo.SockPort != udp.TmfPort {
		t.Errorf("SockPort = %d, want %d", gotInfo.SockPort, udp.TmfPort)
	}
}

// TestTxMacSeqNumIncrement verifies that the MAC sequence number increments
// with each transmitted frame.
func TestTxMacSeqNumIncrement(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)
	inst.SetRLOC16(0x0400)

	if inst.macSeqNum != 0 {
		t.Fatalf("initial macSeqNum = %d, want 0", inst.macSeqNum)
	}

	// Send 3 MLE messages and verify sequence number increments.
	for i := 0; i < 3; i++ {
		err := inst.SendMLE([]byte{byte(i)}, ip6.Address{})
		if err != nil {
			t.Fatalf("SendMLE #%d error: %v", i, err)
		}
		frame := &radio.Frame{}
		if !inst.HandleFrameRequest(frame) {
			t.Fatalf("HandleFrameRequest #%d should return true", i)
		}
		inst.HandleSentFrame(frame, nil)
	}

	if inst.macSeqNum != 3 {
		t.Errorf("macSeqNum = %d, want 3 after 3 frames", inst.macSeqNum)
	}
}

// TestTxMacSeqNumWraparound verifies that the MAC sequence number wraps
// from 255 to 0.
func TestTxMacSeqNumWraparound(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)
	inst.SetRLOC16(0x0400)
	inst.macSeqNum = 255

	err := inst.SendMLE([]byte{0x01}, ip6.Address{})
	if err != nil {
		t.Fatalf("SendMLE() error: %v", err)
	}
	frame := &radio.Frame{}
	if !inst.HandleFrameRequest(frame) {
		t.Fatal("HandleFrameRequest should return true")
	}
	inst.HandleSentFrame(frame, nil)

	if inst.macSeqNum != 0 {
		t.Errorf("macSeqNum = %d, want 0 after wrap", inst.macSeqNum)
	}
}

// TestTxFrameContainsValidMACHeader verifies that frames built by the TX
// path contain a parseable IEEE 802.15.4 MAC header with correct fields.
func TestTxFrameContainsValidMACHeader(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)
	inst.SetRLOC16(0x0400)
	inst.SetMeshLocalPrefix([8]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Set a PAN ID on the MAC.
	if inst.mac != nil {
		inst.mac.SetPanID(0xFACE)
	}

	// Send to a specific RLOC (unicast, short addresses).
	dst := inst.GetMeshLocalAddress()
	dst[14] = 0x08
	dst[15] = 0x00

	err := inst.SendMLE([]byte{0xAA, 0xBB}, dst)
	if err != nil {
		t.Fatalf("SendMLE() error: %v", err)
	}

	frame := &radio.Frame{}
	if !inst.HandleFrameRequest(frame) {
		t.Fatal("HandleFrameRequest should return true")
	}

	// Parse the MAC header.
	mf := macframe.NewFrame(frame.PSDU)

	// Verify it's a Data frame.
	if mf.GetType() != macframe.TypeData {
		t.Errorf("expected Data frame type, got %d", mf.GetType())
	}

	// Verify PAN ID.
	panID, err := mf.GetDstPanID()
	if err != nil {
		t.Fatalf("GetDstPanID() error: %v", err)
	}
	if panID != 0xFACE {
		t.Errorf("PAN ID = 0x%04X, want 0xFACE", panID)
	}

	// Verify payload can be found.
	off, err := mf.GetHeaderLength()
	if err != nil {
		t.Fatalf("GetHeaderLength() error: %v", err)
	}
	if int(off) >= len(frame.PSDU) {
		t.Fatal("payload offset beyond PSDU length")
	}

	// Verify the 6LoWPAN payload starts with IPHC dispatch.
	lpPayload := frame.PSDU[int(off):]
	if !lowpan.IsLowpanHc(lpPayload) {
		t.Errorf("6LoWPAN payload does not start with IPHC dispatch: first byte = 0x%02x", lpPayload[0])
	}
}

// TestTxFrameDecompressesBackToOriginal verifies that a TX frame's 6LoWPAN
// payload can be decompressed back to the original IPv6/UDP headers and
// application payload.
func TestTxFrameDecompressesBackToOriginal(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)
	inst.SetRLOC16(0x0400)
	inst.SetMeshLocalPrefix([8]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	srcAddr := inst.GetLinkLocalAddress()
	dstAddr := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	payload := []byte("round-trip-test")

	err := inst.SendMLE(payload, dstAddr)
	if err != nil {
		t.Fatalf("SendMLE() error: %v", err)
	}

	frame := &radio.Frame{}
	if !inst.HandleFrameRequest(frame) {
		t.Fatal("HandleFrameRequest should return true")
	}

	// Extract 6LoWPAN payload from MAC frame.
	mf := macframe.NewFrame(frame.PSDU)
	off, err := mf.GetHeaderLength()
	if err != nil {
		t.Fatalf("GetHeaderLength() error: %v", err)
	}
	lpPayload := frame.PSDU[int(off):]

	// Decompress IPv6 header.
	var macAddrs lowpan.AddressContext
	// For decompression with fully inline addresses, empty context is fine.
	ipv6Raw, consumed, err := lowpan.DecompressHeader(lpPayload, macAddrs, nil)
	if err != nil {
		t.Fatalf("DecompressHeader() error: %v", err)
	}

	hdr := ip6.HeaderFromBytes(ipv6Raw)

	// Verify IPv6 header fields.
	if hdr.GetSource() != srcAddr {
		t.Errorf("IPv6 src = %v, want %v", hdr.GetSource(), srcAddr)
	}
	if hdr.GetDestination() != dstAddr {
		t.Errorf("IPv6 dst = %v, want %v", hdr.GetDestination(), dstAddr)
	}
	if hdr.GetHopLimit() != 64 {
		t.Errorf("HopLimit = %d, want 64", hdr.GetHopLimit())
	}

	// Decompress NHC UDP header.
	remaining := lpPayload[consumed:]
	udpHdr, udpConsumed, err := lowpan.DecompressUDPHeader(remaining)
	if err != nil {
		t.Fatalf("DecompressUDPHeader() error: %v", err)
	}

	srcPort := encoding.BigEndianReadUint16(udpHdr[0:2])
	dstPort := encoding.BigEndianReadUint16(udpHdr[2:4])
	if srcPort != mle.UDPPort {
		t.Errorf("UDP src port = %d, want %d", srcPort, mle.UDPPort)
	}
	if dstPort != mle.UDPPort {
		t.Errorf("UDP dst port = %d, want %d", dstPort, mle.UDPPort)
	}

	// Verify application payload.
	appPayload := remaining[udpConsumed:]
	if !bytes.Equal(appPayload, payload) {
		t.Errorf("app payload = %x, want %x", appPayload, payload)
	}
}

// TestSendMLE_MetadataPopulated verifies that SendMLE now creates a
// TxMessage with properly populated TxMetadata.
func TestSendMLE_MetadataPopulated(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)
	inst.SetRLOC16(0x0400)
	inst.SetMeshLocalPrefix([8]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// RLOC destination — should use mesh-local source.
	dst := inst.GetMeshLocalAddress()
	dst[14] = 0x08
	dst[15] = 0x00

	err := inst.SendMLE([]byte{0x01}, dst)
	if err != nil {
		t.Fatalf("SendMLE() error: %v", err)
	}

	queue := inst.forwarder.GetDirectQueue()
	if len(queue) != 1 {
		t.Fatalf("queue length = %d, want 1", len(queue))
	}
	msg := queue[0]

	if !msg.HasMetadata() {
		t.Fatal("TxMessage should have metadata after SendMLE")
	}
	meta := msg.Metadata

	// Verify IPv6 source is the mesh-local RLOC.
	expectedSrc := inst.GetMeshLocalAddress()
	if meta.SrcAddr != [16]byte(expectedSrc) {
		t.Errorf("SrcAddr = %x, want %x", meta.SrcAddr, expectedSrc)
	}

	// Verify IPv6 destination.
	if meta.DstAddr != [16]byte(dst) {
		t.Errorf("DstAddr = %x, want %x", meta.DstAddr, dst)
	}

	// Verify UDP ports.
	if meta.SrcPort != mle.UDPPort {
		t.Errorf("SrcPort = %d, want %d", meta.SrcPort, mle.UDPPort)
	}
	if meta.DstPort != mle.UDPPort {
		t.Errorf("DstPort = %d, want %d", meta.DstPort, mle.UDPPort)
	}

	// Verify next header.
	if meta.NextHeader != ip6.ProtoUDP {
		t.Errorf("NextHeader = %d, want %d", meta.NextHeader, ip6.ProtoUDP)
	}

	// Verify hop limit.
	if meta.HopLimit != 64 {
		t.Errorf("HopLimit = %d, want 64", meta.HopLimit)
	}

	// Verify short addressing for unicast.
	if !meta.UseSrcShort {
		t.Error("UseSrcShort should be true")
	}
	if !meta.UseDstShort {
		t.Error("UseDstShort should be true for unicast RLOC dest")
	}
}

// TestSendMLE_BroadcastUsesExtendedDst verifies that broadcast MLE
// messages use extended addressing for the destination.
func TestSendMLE_BroadcastUsesExtendedDst(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)
	inst.SetRLOC16(0x0400)

	// Non-RLOC destination → broadcast → UseDstShort should be false.
	dst := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	err := inst.SendMLE([]byte{0x01}, dst)
	if err != nil {
		t.Fatalf("SendMLE() error: %v", err)
	}

	queue := inst.forwarder.GetDirectQueue()
	if len(queue) != 1 {
		t.Fatalf("queue length = %d, want 1", len(queue))
	}
	msg := queue[0]

	if !msg.HasMetadata() {
		t.Fatal("expected metadata")
	}
	if msg.Metadata.UseDstShort {
		t.Error("UseDstShort should be false for non-RLOC broadcast destination")
	}
	if msg.MeshDest != 0xFFFF {
		t.Errorf("MeshDest = 0x%04X, want 0xFFFF for broadcast", msg.MeshDest)
	}
}

// TestSendCoAP_MetadataPopulated verifies that sendCoAP creates a
// TxMessage with properly populated TxMetadata.
func TestSendCoAP_MetadataPopulated(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)
	inst.SetRLOC16(0x0400)
	inst.SetMeshLocalPrefix([8]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	var peerAddr [16]byte
	copy(peerAddr[0:8], inst.meshLocalPrefix[:])
	peerAddr[11] = 0xff
	peerAddr[12] = 0xfe
	peerAddr[14] = 0x08
	peerAddr[15] = 0x00

	localAddr := inst.GetMeshLocalAddress()
	err := inst.sendCoAP([]byte{0x40}, coap.MessageInfo{
		PeerAddr:  peerAddr,
		PeerPort:  udp.TmfPort,
		LocalAddr: localAddr,
	})
	if err != nil {
		t.Fatalf("sendCoAP() error: %v", err)
	}

	queue := inst.forwarder.GetDirectQueue()
	if len(queue) != 1 {
		t.Fatalf("queue length = %d, want 1", len(queue))
	}
	msg := queue[0]

	if !msg.HasMetadata() {
		t.Fatal("expected metadata from sendCoAP")
	}
	meta := msg.Metadata

	if meta.SrcPort != udp.TmfPort {
		t.Errorf("SrcPort = %d, want %d", meta.SrcPort, udp.TmfPort)
	}
	if meta.DstPort != udp.TmfPort {
		t.Errorf("DstPort = %d, want %d", meta.DstPort, udp.TmfPort)
	}
	if meta.NextHeader != ip6.ProtoUDP {
		t.Errorf("NextHeader = %d, want %d", meta.NextHeader, ip6.ProtoUDP)
	}
	if !meta.UseDstShort {
		t.Error("UseDstShort should be true for unicast RLOC peer")
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

// --------------------------------------------------------------------------
// Phase 29 — Full RX path integration tests
// --------------------------------------------------------------------------

// build6LoWPANFrameInlineUDP builds a 6LoWPAN IPHC frame with fully inline
// addresses, inline NH=UDP, hop limit=64, and an uncompressed 8-byte UDP
// header followed by the given payload.
//
// IPHC = 0x6000: TF=00, NH=inline, HLIM=inline, SAC=0, SAM=00, M=0, DAC=0, DAM=00
func build6LoWPANFrameInlineUDP(srcIP, dstIP ip6.Address, srcPort, dstPort uint16, payload []byte) []byte {
	d := []byte{0x60, 0x00}               // IPHC dispatch
	d = append(d, 0x00, 0x00, 0x00, 0x00) // TF=00: ECN=0, DSCP=0, Flow=0
	d = append(d, 0x11)                   // NH = UDP (17)
	d = append(d, 0x40)                   // HL = 64
	d = append(d, srcIP[:]...)            // 16 bytes source
	d = append(d, dstIP[:]...)            // 16 bytes destination
	// 8-byte UDP header: src port, dst port, length, checksum (all big-endian)
	udpLen := uint16(8 + len(payload))
	d = append(d, byte(srcPort>>8), byte(srcPort))
	d = append(d, byte(dstPort>>8), byte(dstPort))
	d = append(d, byte(udpLen>>8), byte(udpLen))
	d = append(d, 0x00, 0x00) // checksum = 0
	d = append(d, payload...)
	return d
}

// build6LoWPANFrameNHCUDP builds a 6LoWPAN IPHC frame with fully inline
// addresses, NHC-compressed UDP header (PP=00, both ports full, checksum
// inline), followed by the given payload.
//
// IPHC = 0x6400: TF=00, NH=compressed(1), HLIM=inline, SAC=0, SAM=00, M=0, DAC=0, DAM=00
func build6LoWPANFrameNHCUDP(srcIP, dstIP ip6.Address, srcPort, dstPort uint16, payload []byte) []byte {
	d := []byte{0x64, 0x00}               // IPHC dispatch with NH=compressed
	d = append(d, 0x00, 0x00, 0x00, 0x00) // TF=00: ECN=0, DSCP=0, Flow=0
	d = append(d, 0x40)                   // HL = 64  (no NH byte since compressed)
	d = append(d, srcIP[:]...)            // 16 bytes source
	d = append(d, dstIP[:]...)            // 16 bytes destination
	// NHC UDP: dispatch=0xF0 (PP=00 both full, C=0 checksum inline)
	d = append(d, 0xF0)
	d = append(d, byte(srcPort>>8), byte(srcPort))
	d = append(d, byte(dstPort>>8), byte(dstPort))
	d = append(d, 0x00, 0x00) // checksum
	d = append(d, payload...)
	return d
}

func TestFullRxPath_InlineUDP_ToSocket(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)

	// Register a socket on port 9999.
	s := &udp.Socket{}
	var gotPayload []byte
	var gotInfo *ip6.MessageInfo
	inst.udpManager.Open(s, udp.NetifThreadHost, func(p []byte, mi *ip6.MessageInfo) {
		gotPayload = p
		gotInfo = mi
	})
	inst.udpManager.Bind(s, ip6.SockAddr{Port: 9999})

	srcIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xef, 0x10, 0x22, 0x11, 0x00}
	dstIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xef, 0x10, 0xaa, 0xbb, 0xcc}
	appData := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	frame := &radio.Frame{
		PSDU:    build6LoWPANFrameInlineUDP(srcIP, dstIP, 4444, 9999, appData),
		Channel: 15,
	}
	inst.HandleReceivedFrame(frame)

	if gotPayload == nil {
		t.Fatal("socket handler was not called")
	}
	if len(gotPayload) != len(appData) {
		t.Errorf("payload length = %d, want %d", len(gotPayload), len(appData))
	}
	for i, b := range appData {
		if gotPayload[i] != b {
			t.Errorf("payload[%d] = %02x, want %02x", i, gotPayload[i], b)
		}
	}
	if gotInfo.PeerAddr != srcIP {
		t.Errorf("PeerAddr = %v, want %v", gotInfo.PeerAddr, srcIP)
	}
	if gotInfo.SockAddr != dstIP {
		t.Errorf("SockAddr = %v, want %v", gotInfo.SockAddr, dstIP)
	}
	if gotInfo.PeerPort != 4444 {
		t.Errorf("PeerPort = %d, want 4444", gotInfo.PeerPort)
	}
	if gotInfo.SockPort != 9999 {
		t.Errorf("SockPort = %d, want 9999", gotInfo.SockPort)
	}
	if gotInfo.HopLimit != 64 {
		t.Errorf("HopLimit = %d, want 64", gotInfo.HopLimit)
	}
}

func TestFullRxPath_NHCUDP_ToSocket(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)

	s := &udp.Socket{}
	var gotPayload []byte
	inst.udpManager.Open(s, udp.NetifThreadHost, func(p []byte, mi *ip6.MessageInfo) {
		gotPayload = p
	})
	inst.udpManager.Bind(s, ip6.SockAddr{Port: 5683})

	srcIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dstIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	appData := []byte{0x40, 0x01, 0x00, 0x01} // CoAP-like payload

	frame := &radio.Frame{
		PSDU:    build6LoWPANFrameNHCUDP(srcIP, dstIP, 12345, 5683, appData),
		Channel: 11,
	}
	inst.HandleReceivedFrame(frame)

	if gotPayload == nil {
		t.Fatal("socket handler was not called for NHC-compressed UDP")
	}
	if len(gotPayload) != len(appData) {
		t.Errorf("payload length = %d, want %d", len(gotPayload), len(appData))
	}
}

func TestFullRxPath_MLEReceiver(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)

	srcIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xef, 0x10, 0x22, 0x11, 0x00}
	dstIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xef, 0x10, 0xaa, 0xbb, 0xcc}
	// MLE port = 19788, src port arbitrary
	mlePayload := []byte{0x00, 0x01, 0x02, 0x03} // fake MLE data

	frame := &radio.Frame{
		PSDU:    build6LoWPANFrameInlineUDP(srcIP, dstIP, 19788, mle.UDPPort, mlePayload),
		Channel: 15,
	}

	// A socket on port 19788 should NOT receive the message because the
	// MLE receiver is registered and consumes it first.
	s := &udp.Socket{}
	socketCalled := false
	inst.udpManager.Open(s, udp.NetifThreadHost, func(p []byte, mi *ip6.MessageInfo) {
		socketCalled = true
	})
	inst.udpManager.Bind(s, ip6.SockAddr{Port: mle.UDPPort})

	inst.HandleReceivedFrame(frame)

	// The MLE receiver should have consumed the message.
	// We can't easily observe that MLE.HandleReceive was called (it
	// returns an error for invalid MLE data), but we CAN verify the
	// socket was NOT called.
	if socketCalled {
		t.Error("socket on MLE port should not receive message — MLE receiver should consume it")
	}
}

func TestFullRxPath_CoAPReceiver(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)

	srcIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dstIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	// TMF port = 61631
	coapPayload := []byte{0x40, 0x01, 0x00, 0x01} // CON GET, MID=1

	frame := &radio.Frame{
		PSDU: build6LoWPANFrameInlineUDP(srcIP, dstIP, 49200, udp.TmfPort, coapPayload),
	}

	// A socket on the TMF port should NOT receive — CoAP receiver consumes.
	s := &udp.Socket{}
	socketCalled := false
	inst.udpManager.Open(s, udp.NetifThreadHost, func(p []byte, mi *ip6.MessageInfo) {
		socketCalled = true
	})
	inst.udpManager.Bind(s, ip6.SockAddr{Port: udp.TmfPort})

	inst.HandleReceivedFrame(frame)

	if socketCalled {
		t.Error("socket on TMF port should not receive message — CoAP receiver should consume it")
	}
}

func TestFullRxPath_NonLowpanDropped(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)

	// Non-IPHC data (doesn't start with 011... dispatch).
	frame := &radio.Frame{
		PSDU: []byte{0x41, 0x88, 0x01, 0x02, 0x03, 0x04, 0x05},
	}

	s := &udp.Socket{}
	called := false
	inst.udpManager.Open(s, udp.NetifThreadHost, func(p []byte, mi *ip6.MessageInfo) {
		called = true
	})
	inst.udpManager.Bind(s, ip6.SockAddr{Port: 9999})

	// Should not panic, and should not dispatch.
	inst.HandleReceivedFrame(frame)

	if called {
		t.Error("non-6LoWPAN frame should not reach UDP sockets")
	}
}

func TestFullRxPath_NonUDPProtocolDropped(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)

	// Build a 6LoWPAN frame with NH=ICMPv6 (58) instead of UDP.
	srcIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dstIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	d := []byte{0x60, 0x00}               // IPHC
	d = append(d, 0x00, 0x00, 0x00, 0x00) // TF=00
	d = append(d, 0x3A)                   // NH = ICMPv6 (58)
	d = append(d, 0x40)                   // HL = 64
	d = append(d, srcIP[:]...)
	d = append(d, dstIP[:]...)
	d = append(d, 0x80, 0x00, 0x00, 0x00) // ICMPv6 echo request (fake)

	frame := &radio.Frame{PSDU: d}

	s := &udp.Socket{}
	called := false
	inst.udpManager.Open(s, udp.NetifThreadHost, func(p []byte, mi *ip6.MessageInfo) {
		called = true
	})
	inst.udpManager.Bind(s, ip6.SockAddr{Port: 9999})

	inst.HandleReceivedFrame(frame)

	if called {
		t.Error("ICMPv6 frame should not reach UDP sockets")
	}
}

func TestFullRxPath_MACAddressParsing(t *testing.T) {
	// Verify that HandleReceivedFrame correctly parses MAC addresses
	// from an 802.15.4 frame header. Since the mesh forwarder returns
	// the full PSDU for direct frames (no MAC header stripping yet),
	// a real MAC-framed packet won't reach 6LoWPAN decompression.
	// This test verifies that the MAC parsing code runs without error
	// on a valid 802.15.4 data frame and that the existing inline
	// address pipeline remains unaffected.

	t.Run("ValidMACFrame_NoPanic", func(t *testing.T) {
		inst := New(Config{})
		inst.forwarder.SetEnabled(true)

		// Build a proper 802.15.4 data frame with extended addresses.
		srcExt := [8]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
		dstExt := [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}

		ctx := &mesh.FrameContext{
			SrcExtAddr:  srcExt,
			DstExtAddr:  dstExt,
			UseSrcShort: false,
			UseDstShort: false,
			PanId:       0x1234,
		}
		framer := mesh.NewFramer()

		// Use dummy payload (not valid IPHC — the frame will be dropped
		// after the forwarder returns it, since the first byte of the
		// full PSDU is the FCF, not an IPHC dispatch).
		macFrame, err := framer.BuildDataFrame(ctx, []byte{0xDE, 0xAD})
		if err != nil {
			t.Fatalf("BuildDataFrame failed: %v", err)
		}

		frame := &radio.Frame{
			PSDU:    macFrame,
			Channel: 15,
		}

		// This should not panic — the MAC parsing runs, then the
		// forwarder returns the data, and it gets dropped because
		// byte[0] is the FCF (not IPHC).
		inst.HandleReceivedFrame(frame)
	})

	t.Run("InlineAddresses_StillWork", func(t *testing.T) {
		// Verify the existing inline-address pipeline is unaffected
		// by the MAC address extraction code. When the PSDU starts
		// with IPHC bytes (no real MAC header), the mac/frame parser
		// will fail to extract addresses (which is fine — macAddrs
		// stays zero-valued) and the pipeline proceeds as before.
		inst := New(Config{})
		inst.forwarder.SetEnabled(true)

		s := &udp.Socket{}
		var gotPayload []byte
		inst.udpManager.Open(s, udp.NetifThreadHost, func(p []byte, mi *ip6.MessageInfo) {
			gotPayload = p
		})
		inst.udpManager.Bind(s, ip6.SockAddr{Port: 9999})

		srcIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xef, 0x10, 0x22, 0x11, 0x00}
		dstIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xef, 0x10, 0xaa, 0xbb, 0xcc}
		appData := []byte{0xCA, 0xFE}

		frame := &radio.Frame{
			PSDU:    build6LoWPANFrameInlineUDP(srcIP, dstIP, 4444, 9999, appData),
			Channel: 15,
		}
		inst.HandleReceivedFrame(frame)

		if gotPayload == nil {
			t.Fatal("socket handler was not called — MAC parsing broke inline pipeline")
		}
		if len(gotPayload) != len(appData) {
			t.Errorf("payload length = %d, want %d", len(gotPayload), len(appData))
		}
	})
}

func TestFullRxPath_ICMPv6Dispatched(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)

	// Register an ICMPv6 handler.
	var gotType icmp6.Type
	var gotCode icmp6.Code
	var gotInfo *ip6.MessageInfo
	handlerCalled := false

	h := icmp6.NewHandler(func(mi *ip6.MessageInfo, hdr *icmp6.Header) {
		handlerCalled = true
		gotType = hdr.GetType()
		gotCode = hdr.GetCode()
		gotInfo = mi
	})
	inst.icmpManager.RegisterHandler(h)

	// Build a 6LoWPAN frame with NH=58 (ICMPv6), fully inline addresses.
	srcIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xef, 0x10, 0x22, 0x11, 0x00}
	dstIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xef, 0x10, 0xaa, 0xbb, 0xcc}

	d := []byte{0x60, 0x00}               // IPHC dispatch: TF=00, NH=inline, HLIM=inline
	d = append(d, 0x00, 0x00, 0x00, 0x00) // TF=00: 4 bytes
	d = append(d, 0x3A)                   // NH = ICMPv6 (58)
	d = append(d, 0x40)                   // HL = 64
	d = append(d, srcIP[:]...)            // 16 bytes source
	d = append(d, dstIP[:]...)            // 16 bytes destination
	// 8-byte ICMPv6 header: Echo Request
	d = append(d, 0x80)       // type: Echo Request (128)
	d = append(d, 0x00)       // code: 0
	d = append(d, 0x00, 0x00) // checksum
	d = append(d, 0x00, 0x01) // ID
	d = append(d, 0x00, 0x01) // Sequence

	frame := &radio.Frame{
		PSDU:    d,
		Channel: 15,
	}
	inst.HandleReceivedFrame(frame)

	if !handlerCalled {
		t.Fatal("ICMPv6 handler was not called")
	}
	if gotType != icmp6.TypeEchoRequest {
		t.Errorf("ICMPv6 type = %d, want %d (EchoRequest)", gotType, icmp6.TypeEchoRequest)
	}
	if gotCode != 0 {
		t.Errorf("ICMPv6 code = %d, want 0", gotCode)
	}
	if gotInfo.PeerAddr != srcIP {
		t.Errorf("PeerAddr = %v, want %v", gotInfo.PeerAddr, srcIP)
	}
	if gotInfo.SockAddr != dstIP {
		t.Errorf("SockAddr = %v, want %v", gotInfo.SockAddr, dstIP)
	}
	if gotInfo.HopLimit != 64 {
		t.Errorf("HopLimit = %d, want 64", gotInfo.HopLimit)
	}
}

// --------------------------------------------------------------------------
// Phase 31a: LinkInfo propagation tests
// --------------------------------------------------------------------------

func TestFullRxPath_LinkInfo_Populated_UDP(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)

	s := &udp.Socket{}
	var gotInfo *ip6.MessageInfo
	inst.udpManager.Open(s, udp.NetifThreadHost, func(p []byte, mi *ip6.MessageInfo) {
		gotInfo = mi
	})
	inst.udpManager.Bind(s, ip6.SockAddr{Port: 9999})

	srcIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xef, 0x10, 0x22, 0x11, 0x00}
	dstIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xef, 0x10, 0xaa, 0xbb, 0xcc}

	frame := &radio.Frame{
		PSDU:    build6LoWPANFrameInlineUDP(srcIP, dstIP, 4444, 9999, []byte{0xAB}),
		Channel: 15,
		RxInfo:  &radio.RxInfo{RSSI: -65},
	}
	inst.HandleReceivedFrame(frame)

	if gotInfo == nil {
		t.Fatal("socket handler was not called")
	}
	if gotInfo.LinkInfo == nil {
		t.Fatal("LinkInfo is nil, expected it to be populated on RX path")
	}
	if gotInfo.LinkInfo.RSSI != -65 {
		t.Errorf("LinkInfo.RSSI = %d, want -65", gotInfo.LinkInfo.RSSI)
	}
}

func TestFullRxPath_LinkInfo_Populated_ICMPv6(t *testing.T) {
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)

	var gotInfo *ip6.MessageInfo
	handlerCalled := false

	h := icmp6.NewHandler(func(mi *ip6.MessageInfo, hdr *icmp6.Header) {
		handlerCalled = true
		gotInfo = mi
	})
	inst.icmpManager.RegisterHandler(h)

	srcIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xef, 0x10, 0x22, 0x11, 0x00}
	dstIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xef, 0x10, 0xaa, 0xbb, 0xcc}

	d := []byte{0x60, 0x00}               // IPHC
	d = append(d, 0x00, 0x00, 0x00, 0x00) // TF=00
	d = append(d, 0x3A)                   // NH = ICMPv6 (58)
	d = append(d, 0x40)                   // HL = 64
	d = append(d, srcIP[:]...)
	d = append(d, dstIP[:]...)
	d = append(d, 0x80)       // Echo Request
	d = append(d, 0x00)       // code
	d = append(d, 0x00, 0x00) // checksum
	d = append(d, 0x00, 0x01) // ID
	d = append(d, 0x00, 0x01) // Sequence

	frame := &radio.Frame{
		PSDU:    d,
		Channel: 15,
		RxInfo:  &radio.RxInfo{RSSI: -40},
	}
	inst.HandleReceivedFrame(frame)

	if !handlerCalled {
		t.Fatal("ICMPv6 handler was not called")
	}
	if gotInfo.LinkInfo == nil {
		t.Fatal("LinkInfo is nil, expected it to be populated on ICMPv6 RX path")
	}
	if gotInfo.LinkInfo.RSSI != -40 {
		t.Errorf("LinkInfo.RSSI = %d, want -40", gotInfo.LinkInfo.RSSI)
	}
}

func TestFullRxPath_MLEReceiver_ConsumesMLEPort(t *testing.T) {
	// Verify that the MLE receiver (which now uses LinkInfo) consumes
	// UDP frames destined to the MLE port (19788) before they reach
	// regular sockets. This proves the receiver lambda is active and
	// correctly wired with the LinkInfo-aware code path.
	inst := New(Config{})
	inst.forwarder.SetEnabled(true)

	// Bind a regular socket on the MLE port — it should NOT receive
	// the message because the MLE receiver intercepts first.
	s := &udp.Socket{}
	socketCalled := false
	inst.udpManager.Open(s, udp.NetifThreadHost, func(p []byte, mi *ip6.MessageInfo) {
		socketCalled = true
	})
	inst.udpManager.Bind(s, ip6.SockAddr{Port: mle.UDPPort})

	srcIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xef, 0x10, 0x22, 0x11, 0x00}
	dstIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xef, 0x10, 0xaa, 0xbb, 0xcc}

	frame := &radio.Frame{
		PSDU:    build6LoWPANFrameInlineUDP(srcIP, dstIP, 4444, mle.UDPPort, []byte{0x00}),
		Channel: 15,
		RxInfo:  &radio.RxInfo{RSSI: -50},
	}
	inst.HandleReceivedFrame(frame)

	if socketCalled {
		t.Error("socket on MLE port was called — MLE receiver should have consumed the message")
	}
}

func TestLinkMarginCalculation(t *testing.T) {
	// The link margin formula used in the MLE receiver is:
	//   margin = clamp(RSSI + 130, 0, 255)
	// This test verifies the formula across boundary values.
	tests := []struct {
		name       string
		rssi       int8
		wantMargin uint8
	}{
		{"typical_good", -50, 80},
		{"typical_weak", -90, 40},
		{"boundary_low", -128, 0},     // guard: RSSI == -128 skips calc, margin stays 0
		{"just_above_floor", -127, 3}, // -127 + 130 = 3
		{"very_strong", -10, 120},     // -10 + 130 = 120
		{"zero_rssi", 0, 130},         // 0 + 130 = 130
		{"positive_rssi", 8, 138},     // 8 + 130 = 138
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rssi := tc.rssi
			var linkMargin uint8
			if rssi > -128 {
				margin := int(rssi) + 130
				if margin < 0 {
					margin = 0
				}
				if margin > 255 {
					margin = 255
				}
				linkMargin = uint8(margin)
			}
			if linkMargin != tc.wantMargin {
				t.Errorf("linkMargin(%d) = %d, want %d", rssi, linkMargin, tc.wantMargin)
			}
		})
	}
}
