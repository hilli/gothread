// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"testing"

	"github.com/hilli/gothread/mac"
	"github.com/hilli/gothread/mac/submac"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/key"
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

	// Step 1: Send an MLE message — enqueues to forwarder.
	mleData := []byte{0x0A, 0x01, 0x02, 0x03, 0x04}
	err := inst.SendMLE(mleData, ip6.Address{})
	if err != nil {
		t.Fatalf("SendMLE() error: %v", err)
	}

	// Step 2: MAC requests a frame — dequeues from forwarder.
	frame := &radio.Frame{}
	if !inst.HandleFrameRequest(frame) {
		t.Fatal("HandleFrameRequest should return true after SendMLE")
	}

	// Step 3: Verify the frame carries the MLE data.
	if len(frame.PSDU) != len(mleData) {
		t.Errorf("PSDU length = %d, want %d", len(frame.PSDU), len(mleData))
	}

	// Step 4: Report successful transmission.
	inst.HandleSentFrame(frame, nil)
	if inst.pendingTxMsg != nil {
		t.Error("pendingTxMsg should be nil after HandleSentFrame")
	}

	// Step 5: Queue should be empty now.
	direct, _ := inst.forwarder.GetQueueLength()
	if direct != 0 {
		t.Errorf("queue should be empty after TX, got %d", direct)
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
