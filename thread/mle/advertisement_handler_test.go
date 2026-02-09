// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"errors"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
)

// --- mock AdvertisementRouterOps ---

type mockAdvRouterOps struct {
	mockRouterLookup
	activeRouterCount              int
	neighborCount                  int
	routerIDSequence               uint8
	isRouteTlvIDSequenceMoreRecent bool
	allocatedIDs                   RouterIDSet
	routersByID                    map[uint8]*Router

	// Tracking calls.
	updateRouterIDSetCalled   bool
	updateRouterIDSetSequence uint8
	updateRouterIDSetMask     RouterIDSet
	updateRoutesCalled        bool
	updateRoutesSequence      uint8
	updateRoutesNeighborID    uint8
	updateRouterOnFtdCalled   bool
	updateRouterOnFtdParentID uint8
	removeRouterLinkCalled    bool
	removeRouterLinkRouter    *Router
}

func newMockAdvRouterOps() *mockAdvRouterOps {
	return &mockAdvRouterOps{
		mockRouterLookup: mockRouterLookup{
			routersByRLOC16:  make(map[uint16]*Router),
			routersByExtAddr: make(map[types.ExtAddress]*Router),
		},
		routersByID: make(map[uint8]*Router),
	}
}

func (m *mockAdvRouterOps) GetActiveRouterCount() int       { return m.activeRouterCount }
func (m *mockAdvRouterOps) GetNeighborCount(_ uint8) int    { return m.neighborCount }
func (m *mockAdvRouterOps) IsAllocated(routerID uint8) bool { return m.allocatedIDs.Contains(routerID) }
func (m *mockAdvRouterOps) GetRouterIDSequence() uint8      { return m.routerIDSequence }
func (m *mockAdvRouterOps) IsRouteTlvIDSequenceMoreRecent(_ uint8) bool {
	return m.isRouteTlvIDSequenceMoreRecent
}

func (m *mockAdvRouterOps) UpdateRouterIDSet(sequence uint8, idSet RouterIDSet, _ uint32) bool {
	m.updateRouterIDSetCalled = true
	m.updateRouterIDSetSequence = sequence
	m.updateRouterIDSetMask = idSet
	return true
}

func (m *mockAdvRouterOps) UpdateRoutes(sequence uint8, _ RouterIDSet, _ []Route64Entry, neighborID uint8, _ uint8) bool {
	m.updateRoutesCalled = true
	m.updateRoutesSequence = sequence
	m.updateRoutesNeighborID = neighborID
	return true
}

func (m *mockAdvRouterOps) UpdateRouterOnFtdChild(_ uint8, _ RouterIDSet, _ []Route64Entry, parentID uint8) {
	m.updateRouterOnFtdCalled = true
	m.updateRouterOnFtdParentID = parentID
}

func (m *mockAdvRouterOps) FindRouterByID(routerID uint8) *Router {
	return m.routersByID[routerID]
}

func (m *mockAdvRouterOps) RemoveRouterLink(router *Router) {
	m.removeRouterLinkCalled = true
	m.removeRouterLinkRouter = router
}

// --- test helpers ---

const (
	testRouterID1   uint8  = 5
	testRouterID2   uint8  = 10
	testRouterRLOC1 uint16 = 0x1400 // RouterID 5
	testRouterRLOC2 uint16 = 0x2800 // RouterID 10
)

var testLeaderData = LeaderData{
	PartitionID:       0xABCD0001,
	Weighting:         64,
	DataVersion:       20,
	StableDataVersion: 15,
	LeaderRouterID:    testRouterID1,
}

// makeRoute64TLVValue builds a Route64 TLV value from components.
func makeRoute64TLVValue(sequence uint8, mask RouterIDSet, entries []Route64Entry) []byte {
	buf := make([]byte, 1+8+len(entries))
	buf[0] = sequence
	copy(buf[1:9], mask[:])
	for i, e := range entries {
		b := (e.LinkQualityOut & 0x03) << Route64EntryLinkQualityOutShift
		b |= (e.LinkQualityIn & 0x03) << Route64EntryLinkQualityInShift
		b |= e.Cost & Route64EntryCostMask
		buf[9+i] = b
	}
	return buf
}

// newAdvHandlerTestSetup creates an FtdAdvertisementHandler with an MLE in
// the specified role (child/router/leader) and mocks.
func newAdvHandlerTestSetup(role DeviceRole, routerID uint8) (
	*FtdAdvertisementHandler, *Mle, *mockAdvRouterOps,
) {
	m := NewMle()
	_ = m.Enable()

	transport := &mockTransport{
		extAddr: types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		linkLocal: ip6.Address{
			0xfe, 0x80, 0, 0, 0, 0, 0, 0,
			0x03, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		},
	}

	keyMgr := &mockKeyProvider{
		currentSeq:      1,
		mleFrameCounter: 100,
		macFrameCounter: 200,
	}

	d := NewDispatcher(m, keyMgr, transport)

	ops := newMockAdvRouterOps()

	switch role {
	case RoleChild:
		_ = m.SetStateChild(childRLOC16)
		m.SetLeaderData(testLeaderData)
		parent := m.GetParent()
		parent.MacAddr = parentExtAddr
		parent.RLOC16 = parentRLOC16
		parent.State = StateValid
		parent.LastHeard = time.Now().Add(-1 * time.Minute)
	case RoleRouter, RoleLeader:
		m.mu.Lock()
		m.role = role
		m.rloc16 = RLOC16FromRouterID(routerID)
		m.ftd.routerID = routerID
		m.leaderData = testLeaderData
		m.mu.Unlock()
	}

	h := NewFtdAdvertisementHandler(m, d, ops)
	return h, m, ops
}

// advRxInfoFromParent creates an RxInfo appearing to come from the parent.
func advRxInfoFromParent(m *Mle, tlvs []TLV, linkMargin uint8) *RxInfo {
	parentIP := parentLinkLocalIP(parentExtAddr)
	return &RxInfo{
		SrcAddr:       parentExtAddr,
		SrcIP:         parentIP,
		Neighbor:      &m.GetParent().Neighbor,
		TLVs:          tlvs,
		LinkMarginRaw: linkMargin,
		Command:       CommandAdvertisement,
	}
}

// advRxInfoFromRouter creates an RxInfo from a valid router neighbor.
func advRxInfoFromRouter(neighbor *Neighbor, tlvs []TLV, linkMargin uint8) *RxInfo {
	srcIP := linkLocalIPFromExtAddress(neighbor.MacAddr)
	return &RxInfo{
		SrcAddr:       neighbor.MacAddr,
		SrcIP:         srcIP,
		Neighbor:      neighbor,
		TLVs:          tlvs,
		LinkMarginRaw: linkMargin,
		Command:       CommandAdvertisement,
	}
}

// advRxInfoFromUnknown creates an RxInfo with nil Neighbor.
func advRxInfoFromUnknown(srcAddr types.ExtAddress, tlvs []TLV, linkMargin uint8) *RxInfo {
	srcIP := linkLocalIPFromExtAddress(srcAddr)
	return &RxInfo{
		SrcAddr:       srcAddr,
		SrcIP:         srcIP,
		Neighbor:      nil,
		TLVs:          tlvs,
		LinkMarginRaw: linkMargin,
		Command:       CommandAdvertisement,
	}
}

// standardAdvTLVs returns SourceAddress + LeaderData TLVs.
func standardAdvTLVs(rloc16 uint16, ld LeaderData) []TLV {
	return []TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(rloc16)},
		{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(ld)},
	}
}

// standardAdvTLVsWithRoute returns SourceAddress + LeaderData + Route64.
func standardAdvTLVsWithRoute(rloc16 uint16, ld LeaderData, seq uint8, mask RouterIDSet, entries []Route64Entry) []TLV {
	return []TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(rloc16)},
		{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(ld)},
		{Type: TLVRoute64, Value: makeRoute64TLVValue(seq, mask, entries)},
	}
}

// --- Registration Test ---

func TestNewFtdAdvertisementHandler_RegistersHandler(t *testing.T) {
	t.Parallel()
	m := NewMle()
	_ = m.Enable()
	transport := &mockTransport{
		extAddr: types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}
	keyMgr := &mockKeyProvider{currentSeq: 1}
	d := NewDispatcher(m, keyMgr, transport)
	ops := newMockAdvRouterOps()

	_ = NewFtdAdvertisementHandler(m, d, ops)

	if _, ok := d.handlers[CommandAdvertisement]; !ok {
		t.Error("expected CommandAdvertisement handler to be registered")
	}
}

// --- HandleAdvertisement: not attached ---

func TestHandleAdvertisement_NotAttached_Error(t *testing.T) {
	t.Parallel()
	m := NewMle()
	_ = m.Enable()
	// State is RoleDetached — not attached.
	transport := &mockTransport{
		extAddr: types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}
	keyMgr := &mockKeyProvider{currentSeq: 1}
	d := NewDispatcher(m, keyMgr, transport)
	ops := newMockAdvRouterOps()
	h := NewFtdAdvertisementHandler(m, d, ops)

	rxInfo := advRxInfoFromUnknown(parentExtAddr, standardAdvTLVs(parentRLOC16, testLeaderData), 30)
	err := h.HandleAdvertisement(rxInfo)
	if err == nil {
		t.Fatal("expected error when not attached")
	}
}

// --- HandleAdvertisement: missing TLVs ---

func TestHandleAdvertisement_MissingSourceAddress_Error(t *testing.T) {
	t.Parallel()
	h, m, _ := newAdvHandlerTestSetup(RoleChild, 0)

	tlvs := []TLV{
		{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(testLeaderData)},
	}
	rxInfo := advRxInfoFromParent(m, tlvs, 30)

	err := h.HandleAdvertisement(rxInfo)
	if err == nil {
		t.Fatal("expected error for missing SourceAddress TLV")
	}
}

func TestHandleAdvertisement_MissingLeaderData_Error(t *testing.T) {
	t.Parallel()
	h, m, _ := newAdvHandlerTestSetup(RoleChild, 0)

	tlvs := []TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
	}
	rxInfo := advRxInfoFromParent(m, tlvs, 30)

	err := h.HandleAdvertisement(rxInfo)
	if err == nil {
		t.Fatal("expected error for missing LeaderData TLV")
	}
}

// --- Child path: non-FTD receives from parent ---

func TestHandleAdvertisement_ChildFromParent_SamePartition_UpdatesLastHeard(t *testing.T) {
	t.Parallel()
	h, m, _ := newAdvHandlerTestSetup(RoleChild, 0)

	before := m.GetParent().LastHeard
	rxInfo := advRxInfoFromParent(m, standardAdvTLVs(parentRLOC16, testLeaderData), 30)

	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	after := m.GetParent().LastHeard
	if !after.After(before) {
		t.Error("expected LastHeard to be updated")
	}
}

func TestHandleAdvertisement_ChildFromParent_RLOC16Mismatch_Detaches(t *testing.T) {
	t.Parallel()
	h, m, _ := newAdvHandlerTestSetup(RoleChild, 0)

	// Parent advertises a different RLOC16 than what we have stored.
	wrongRLOC := uint16(0x0C00)
	rxInfo := advRxInfoFromParent(m, standardAdvTLVs(wrongRLOC, testLeaderData), 30)

	_ = h.HandleAdvertisement(rxInfo)

	if m.Role() != RoleDetached {
		t.Errorf("expected detached, got %v", m.Role())
	}
}

func TestHandleAdvertisement_ChildFromParent_PartitionChange_SetsRetrieveNewData(t *testing.T) {
	t.Parallel()
	h, m, _ := newAdvHandlerTestSetup(RoleChild, 0)

	changedLD := testLeaderData
	changedLD.PartitionID = 0xDEAD0002 // Different partition.
	// Also need the FTD path to not fail for partition mismatch.
	// For a child that is FTD, partition mismatch triggers better-partition attach
	// via the FTD path, but let's make the link margin below threshold so it drops
	// via ErrDrop first, then the child code won't run. Actually — the FTD path
	// returns ErrDrop before the child path runs. We need to test non-FTD child here.
	m.SetDeviceMode(NewDeviceMode(ModeRxOnWhenIdle | ModeFullNetworkData)) // Non-FTD.

	rxInfo := advRxInfoFromParent(m, standardAdvTLVs(parentRLOC16, changedLD), 30)

	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !m.NeedsNewNetworkData() {
		t.Error("expected NeedsNewNetworkData to be true after partition change")
	}
}

func TestHandleAdvertisement_ChildFromParent_DataVersionChange_SetsRetrieveNewData(t *testing.T) {
	t.Parallel()
	h, m, _ := newAdvHandlerTestSetup(RoleChild, 0)
	m.SetDeviceMode(NewDeviceMode(ModeRxOnWhenIdle | ModeFullNetworkData)) // Non-FTD.

	changedLD := testLeaderData
	changedLD.DataVersion = testLeaderData.DataVersion + 1

	rxInfo := advRxInfoFromParent(m, standardAdvTLVs(parentRLOC16, changedLD), 30)

	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !m.NeedsNewNetworkData() {
		t.Error("expected NeedsNewNetworkData after data version change")
	}
}

func TestHandleAdvertisement_ChildFromNonParent_Ignored(t *testing.T) {
	t.Parallel()
	h, m, _ := newAdvHandlerTestSetup(RoleChild, 0)
	m.SetDeviceMode(NewDeviceMode(ModeRxOnWhenIdle | ModeFullNetworkData)) // Non-FTD.

	strangerAddr := types.ExtAddress{0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22}
	stranger := &Neighbor{
		MacAddr: strangerAddr,
		RLOC16:  0x0800,
		State:   StateValid,
	}
	rxInfo := advRxInfoFromRouter(stranger, standardAdvTLVs(0x0800, testLeaderData), 30)

	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No crash, no error — silently ignored for non-FTD child.
}

// --- Router/Leader path: valid neighbor ---

func TestHandleAdvertisement_RouterFromValidNeighbor_UpdatesLastHeardAndRoutes(t *testing.T) {
	t.Parallel()
	h, _, ops := newAdvHandlerTestSetup(RoleRouter, testRouterID1)

	neighborRouter := &Router{}
	neighborRouter.MacAddr = extAddressForRouterID(testRouterID2)
	neighborRouter.RLOC16 = testRouterRLOC2
	neighborRouter.State = StateValid
	neighborRouter.LastHeard = time.Now().Add(-5 * time.Minute)

	ops.routersByID[testRouterID2] = neighborRouter
	ops.routersByRLOC16[testRouterRLOC2] = neighborRouter

	routeMask := RouterIDSet{}
	routeMask.Add(testRouterID1)
	routeMask.Add(testRouterID2)
	entries := []Route64Entry{
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 1},
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
	}

	tlvs := standardAdvTLVsWithRoute(testRouterRLOC2, testLeaderData, 5, routeMask, entries)
	rxInfo := advRxInfoFromRouter(&neighborRouter.Neighbor, tlvs, 30)

	before := neighborRouter.LastHeard
	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// LastHeard updated (via the router/leader path at the end of HandleAdvertisement).
	if !neighborRouter.LastHeard.After(before) {
		t.Error("expected LastHeard to be updated")
	}

	// UpdateRoutes should have been called.
	if !ops.updateRoutesCalled {
		t.Error("expected UpdateRoutes to be called")
	}
	if ops.updateRoutesNeighborID != testRouterID2 {
		t.Errorf("UpdateRoutes neighborID = %d, want %d", ops.updateRoutesNeighborID, testRouterID2)
	}
}

// --- Partition ID mismatch ---

func TestHandleAdvertisement_Router_PartitionMismatch_BetterPartition_Attaches(t *testing.T) {
	t.Parallel()
	h, m, _ := newAdvHandlerTestSetup(RoleRouter, testRouterID1)

	// Peer has a better partition (higher partition ID wins when weighting equal).
	betterLD := testLeaderData
	betterLD.PartitionID = testLeaderData.PartitionID + 1000

	routeMask := RouterIDSet{}
	routeMask.Add(testRouterID2)
	routeMask.Add(3)
	entries := []Route64Entry{
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 1},
	}

	tlvs := standardAdvTLVsWithRoute(testRouterRLOC2, betterLD, 5, routeMask, entries)
	neighbor := &Neighbor{
		MacAddr: extAddressForRouterID(testRouterID2),
		RLOC16:  testRouterRLOC2,
		State:   StateValid,
	}
	rxInfo := advRxInfoFromRouter(neighbor, tlvs, PartitionMergeMinMargin+1)

	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have triggered attach for better partition.
	if m.Role() == RoleRouter {
		// After StartAttach, the attach state should change.
		m.mu.RLock()
		attachState := m.attachState
		m.mu.RUnlock()
		if attachState == AttachStateIdle {
			t.Error("expected attach to be started for better partition")
		}
	}
}

func TestHandleAdvertisement_Router_PartitionMismatch_WorsePartition_Drops(t *testing.T) {
	t.Parallel()
	h, _, _ := newAdvHandlerTestSetup(RoleRouter, testRouterID1)

	// Peer has a worse partition (lower partition ID).
	worseLD := testLeaderData
	worseLD.PartitionID = testLeaderData.PartitionID - 1000

	routeMask := RouterIDSet{}
	routeMask.Add(testRouterID2)
	entries := []Route64Entry{
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
	}

	tlvs := standardAdvTLVsWithRoute(testRouterRLOC2, worseLD, 5, routeMask, entries)
	neighbor := &Neighbor{
		MacAddr: extAddressForRouterID(testRouterID2),
		RLOC16:  testRouterRLOC2,
		State:   StateValid,
	}
	rxInfo := advRxInfoFromRouter(neighbor, tlvs, PartitionMergeMinMargin+1)

	err := h.HandleAdvertisement(rxInfo)
	if !errors.Is(err, goterrors.ErrDrop) {
		t.Errorf("expected ErrDrop for worse partition, got %v", err)
	}
}

func TestHandleAdvertisement_Router_PartitionMismatch_LowLinkMargin_Drops(t *testing.T) {
	t.Parallel()
	h, _, _ := newAdvHandlerTestSetup(RoleRouter, testRouterID1)

	betterLD := testLeaderData
	betterLD.PartitionID = testLeaderData.PartitionID + 1000

	tlvs := standardAdvTLVs(testRouterRLOC2, betterLD)
	neighbor := &Neighbor{
		MacAddr: extAddressForRouterID(testRouterID2),
		RLOC16:  testRouterRLOC2,
		State:   StateValid,
	}
	// Link margin below threshold.
	rxInfo := advRxInfoFromRouter(neighbor, tlvs, PartitionMergeMinMargin-1)

	err := h.HandleAdvertisement(rxInfo)
	if !errors.Is(err, goterrors.ErrDrop) {
		t.Errorf("expected ErrDrop for low link margin, got %v", err)
	}
}

func TestHandleAdvertisement_Router_PreviousPartitionLoop_Drops(t *testing.T) {
	t.Parallel()
	h, m, _ := newAdvHandlerTestSetup(RoleRouter, testRouterID1)

	// Set up previous partition info that matches the peer.
	prevMask := RouterIDSet{}
	prevMask.Add(testRouterID2)
	prevMask.Add(3)
	prevSeq := uint8(42)

	m.mu.Lock()
	m.ftd.previousPartitionID = testLeaderData.PartitionID + 500
	m.ftd.previousPartitionRouterIDSequence = prevSeq
	m.ftd.previousPartitionRouterIDSet = prevMask
	m.mu.Unlock()

	peerLD := testLeaderData
	peerLD.PartitionID = testLeaderData.PartitionID + 500 // Matches previous.

	entries := []Route64Entry{
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 1},
	}

	tlvs := standardAdvTLVsWithRoute(testRouterRLOC2, peerLD, prevSeq, prevMask, entries)
	neighbor := &Neighbor{
		MacAddr: extAddressForRouterID(testRouterID2),
		RLOC16:  testRouterRLOC2,
		State:   StateValid,
	}
	rxInfo := advRxInfoFromRouter(neighbor, tlvs, PartitionMergeMinMargin+1)

	err := h.HandleAdvertisement(rxInfo)
	if !errors.Is(err, goterrors.ErrDrop) {
		t.Errorf("expected ErrDrop for previous partition loop, got %v", err)
	}
}

// --- Leader Router ID mismatch ---

func TestHandleAdvertisement_Router_LeaderIDMismatch_Detaches(t *testing.T) {
	t.Parallel()
	h, m, _ := newAdvHandlerTestSetup(RoleRouter, testRouterID1)

	// Same partition, different leader.
	mismatchLD := testLeaderData
	mismatchLD.LeaderRouterID = testRouterID1 + 5

	routeMask := RouterIDSet{}
	routeMask.Add(testRouterID2)
	entries := []Route64Entry{
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
	}

	tlvs := standardAdvTLVsWithRoute(testRouterRLOC2, mismatchLD, 5, routeMask, entries)
	neighbor := &Neighbor{
		MacAddr: extAddressForRouterID(testRouterID2),
		RLOC16:  testRouterRLOC2,
		State:   StateValid,
	}
	rxInfo := advRxInfoFromRouter(neighbor, tlvs, 30)

	_ = h.HandleAdvertisement(rxInfo)
	if m.Role() != RoleDetached {
		t.Errorf("expected detached after leader ID mismatch, got %v", m.Role())
	}
}

func TestHandleAdvertisement_Child_LeaderIDMismatch_Ignored(t *testing.T) {
	t.Parallel()
	h, m, _ := newAdvHandlerTestSetup(RoleChild, 0)

	mismatchLD := testLeaderData
	mismatchLD.LeaderRouterID = testLeaderData.LeaderRouterID + 5

	// From a non-parent stranger (the child path will just return nil).
	strangerAddr := types.ExtAddress{0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22}
	stranger := &Neighbor{
		MacAddr: strangerAddr,
		RLOC16:  0x2000,
		State:   StateValid,
	}
	// For FTD child, leader ID mismatch returns nil (not an error).
	rxInfo := advRxInfoFromRouter(stranger, standardAdvTLVs(0x2000, mismatchLD), 30)

	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("expected nil for child with leader ID mismatch, got %v", err)
	}
	if m.Role() != RoleChild {
		t.Errorf("expected child to remain in child role, got %v", m.Role())
	}
}

// --- Router receives from unknown router: Link Request scheduling ---

func TestHandleAdvertisement_Router_UnknownRouter_GoodMargin_SchedulesLinkRequest(t *testing.T) {
	t.Parallel()
	h, _, ops := newAdvHandlerTestSetup(RoleRouter, testRouterID1)

	unknownRouterID := uint8(15)
	unknownRLOC := RLOC16FromRouterID(unknownRouterID)
	unknownRouter := &Router{}
	unknownRouter.RLOC16 = unknownRLOC
	unknownRouter.State = StateInvalid
	ops.routersByRLOC16[unknownRLOC] = unknownRouter

	routeMask := RouterIDSet{}
	routeMask.Add(testRouterID1)
	routeMask.Add(unknownRouterID)
	entries := []Route64Entry{
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
	}

	tlvs := standardAdvTLVsWithRoute(unknownRLOC, testLeaderData, 5, routeMask, entries)
	rxInfo := advRxInfoFromUnknown(extAddressForRouterID(unknownRouterID), tlvs, LinkRequestMinMargin+1)

	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if unknownRouter.RemainingLinkRequestAttempts != LinkRequestAttempts {
		t.Errorf("expected link request attempts = %d, got %d",
			LinkRequestAttempts, unknownRouter.RemainingLinkRequestAttempts)
	}
}

func TestHandleAdvertisement_Router_UnknownRouter_LowMargin_NoLinkRequest(t *testing.T) {
	t.Parallel()
	h, _, ops := newAdvHandlerTestSetup(RoleRouter, testRouterID1)

	unknownRouterID := uint8(15)
	unknownRLOC := RLOC16FromRouterID(unknownRouterID)
	unknownRouter := &Router{}
	unknownRouter.RLOC16 = unknownRLOC
	unknownRouter.State = StateInvalid
	ops.routersByRLOC16[unknownRLOC] = unknownRouter

	routeMask := RouterIDSet{}
	routeMask.Add(testRouterID1)
	routeMask.Add(unknownRouterID)
	entries := []Route64Entry{
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
	}

	tlvs := standardAdvTLVsWithRoute(unknownRLOC, testLeaderData, 5, routeMask, entries)
	rxInfo := advRxInfoFromUnknown(extAddressForRouterID(unknownRouterID), tlvs, LinkRequestMinMargin-1)

	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if unknownRouter.RemainingLinkRequestAttempts != 0 {
		t.Errorf("expected no link request scheduling, got attempts=%d",
			unknownRouter.RemainingLinkRequestAttempts)
	}
}

// --- ShouldDowngrade ---

func TestShouldDowngrade_BelowThreshold_False(t *testing.T) {
	t.Parallel()
	h, _, ops := newAdvHandlerTestSetup(RoleRouter, testRouterID1)

	ops.activeRouterCount = 10
	// Default downgrade threshold is 23.
	ops.neighborCount = 10

	routeMask := RouterIDSet{}
	entries := []Route64Entry{}

	got := h.shouldDowngrade(testRouterID2, 5, routeMask, entries)
	if got {
		t.Error("expected shouldDowngrade=false when active routers below threshold")
	}
}

func TestShouldDowngrade_AboveThresholdFewNeighbors_False(t *testing.T) {
	t.Parallel()
	h, _, ops := newAdvHandlerTestSetup(RoleRouter, testRouterID1)

	ops.activeRouterCount = 30 // Above default threshold (23).
	ops.neighborCount = 3      // Below MinDowngradeNeighbors (7).

	routeMask := RouterIDSet{}
	entries := []Route64Entry{}

	got := h.shouldDowngrade(testRouterID2, 5, routeMask, entries)
	if got {
		t.Error("expected shouldDowngrade=false when neighbor count too low")
	}
}

func TestShouldDowngrade_AboveThresholdGoodNeighbors_True(t *testing.T) {
	t.Parallel()
	h, _, ops := newAdvHandlerTestSetup(RoleRouter, testRouterID1)

	ops.activeRouterCount = 30 // Above default threshold (23).
	ops.neighborCount = 10     // Above MinDowngradeNeighbors (7).

	// Build a route with many reachable routers.
	routeMask := RouterIDSet{}
	var entries []Route64Entry
	for i := uint8(0); i < 20; i++ {
		routeMask.Add(i)
		entries = append(entries, Route64Entry{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 1})
	}

	got := h.shouldDowngrade(testRouterID2, 5, routeMask, entries)
	if !got {
		t.Error("expected shouldDowngrade=true when conditions met")
	}
}

// --- FTD Child: upgrade timer ---

func TestHandleAdvertisement_FtdChild_BelowUpgradeThreshold_StartsUpgradeTimer(t *testing.T) {
	t.Parallel()
	h, m, ops := newAdvHandlerTestSetup(RoleChild, 0)

	// Active router count below upgrade threshold triggers timer.
	ops.activeRouterCount = 5 // Default upgrade threshold is 16.

	routeMask := RouterIDSet{}
	routeMask.Add(RouterIDFromRLOC16(parentRLOC16))
	entries := []Route64Entry{
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
	}

	tlvs := standardAdvTLVsWithRoute(parentRLOC16, testLeaderData, 5, routeMask, entries)
	rxInfo := advRxInfoFromParent(m, tlvs, 30)

	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	transition := m.GetRouterRoleTransition()
	if !transition.IsPending() {
		t.Error("expected router role transition to be pending (upgrade timer started)")
	}
}

func TestHandleAdvertisement_FtdChild_AboveUpgradeThreshold_NoTimer(t *testing.T) {
	t.Parallel()
	h, m, ops := newAdvHandlerTestSetup(RoleChild, 0)

	// Active router count above upgrade threshold.
	ops.activeRouterCount = 20

	routeMask := RouterIDSet{}
	routeMask.Add(RouterIDFromRLOC16(parentRLOC16))
	entries := []Route64Entry{
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
	}

	tlvs := standardAdvTLVsWithRoute(parentRLOC16, testLeaderData, 5, routeMask, entries)
	rxInfo := advRxInfoFromParent(m, tlvs, 30)

	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	transition := m.GetRouterRoleTransition()
	if transition.IsPending() {
		t.Error("expected no upgrade timer when above threshold")
	}
}

// --- Route TLV processing ---

func TestHandleAdvertisement_Router_MoreRecentIDSequence_UpdatesRouterIDSet(t *testing.T) {
	t.Parallel()
	h, _, ops := newAdvHandlerTestSetup(RoleRouter, testRouterID1)

	ops.isRouteTlvIDSequenceMoreRecent = true

	neighborRouter := &Router{}
	neighborRouter.MacAddr = extAddressForRouterID(testRouterID2)
	neighborRouter.RLOC16 = testRouterRLOC2
	neighborRouter.State = StateValid
	ops.routersByID[testRouterID2] = neighborRouter
	ops.routersByRLOC16[testRouterRLOC2] = neighborRouter

	routeMask := RouterIDSet{}
	routeMask.Add(testRouterID1) // Our ID must be present.
	routeMask.Add(testRouterID2)
	entries := []Route64Entry{
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
	}

	tlvs := standardAdvTLVsWithRoute(testRouterRLOC2, testLeaderData, 10, routeMask, entries)
	rxInfo := advRxInfoFromRouter(&neighborRouter.Neighbor, tlvs, 30)

	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !ops.updateRouterIDSetCalled {
		t.Error("expected UpdateRouterIDSet to be called for more recent sequence")
	}
	if ops.updateRouterIDSetSequence != 10 {
		t.Errorf("sequence = %d, want 10", ops.updateRouterIDSetSequence)
	}
}

func TestHandleAdvertisement_Router_OwnIDRemovedFromSet_Detaches(t *testing.T) {
	t.Parallel()
	h, m, ops := newAdvHandlerTestSetup(RoleRouter, testRouterID1)

	ops.isRouteTlvIDSequenceMoreRecent = true

	neighborRouter := &Router{}
	neighborRouter.MacAddr = extAddressForRouterID(testRouterID2)
	neighborRouter.RLOC16 = testRouterRLOC2
	neighborRouter.State = StateValid
	ops.routersByID[testRouterID2] = neighborRouter

	// Route mask does NOT contain our router ID.
	routeMask := RouterIDSet{}
	routeMask.Add(testRouterID2) // Only peer, not us.
	entries := []Route64Entry{
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
	}

	tlvs := standardAdvTLVsWithRoute(testRouterRLOC2, testLeaderData, 10, routeMask, entries)
	rxInfo := advRxInfoFromRouter(&neighborRouter.Neighbor, tlvs, 30)

	_ = h.HandleAdvertisement(rxInfo)

	if m.Role() != RoleDetached {
		t.Errorf("expected detached when own ID removed from route set, got %v", m.Role())
	}
}

// --- Route64 TLV absent ---

func TestHandleAdvertisement_Router_NoRoute64TLV_Handled(t *testing.T) {
	t.Parallel()
	h, _, ops := newAdvHandlerTestSetup(RoleRouter, testRouterID1)

	// Source is a router RLOC, but no Route64 TLV — should return nil
	// without calling UpdateRoutes.
	neighbor := &Neighbor{
		MacAddr: extAddressForRouterID(testRouterID2),
		RLOC16:  testRouterRLOC2,
		State:   StateValid,
	}
	tlvs := standardAdvTLVs(testRouterRLOC2, testLeaderData)
	rxInfo := advRxInfoFromRouter(neighbor, tlvs, 30)

	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ops.updateRoutesCalled {
		t.Error("expected UpdateRoutes NOT to be called without Route64 TLV")
	}
}

// --- FTD child: UpdateRouterOnFtdChild ---

func TestHandleAdvertisement_FtdChild_FromParent_UpdatesRouterOnFtdChild(t *testing.T) {
	t.Parallel()
	h, m, ops := newAdvHandlerTestSetup(RoleChild, 0)

	ops.activeRouterCount = 30 // Above threshold, no upgrade timer.

	routeMask := RouterIDSet{}
	routeMask.Add(RouterIDFromRLOC16(parentRLOC16))
	entries := []Route64Entry{
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
	}

	tlvs := standardAdvTLVsWithRoute(parentRLOC16, testLeaderData, 5, routeMask, entries)
	rxInfo := advRxInfoFromParent(m, tlvs, 30)

	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !ops.updateRouterOnFtdCalled {
		t.Error("expected UpdateRouterOnFtdChild to be called")
	}
	expectedParentID := RouterIDFromRLOC16(parentRLOC16)
	if ops.updateRouterOnFtdParentID != expectedParentID {
		t.Errorf("UpdateRouterOnFtdChild parentID = %d, want %d",
			ops.updateRouterOnFtdParentID, expectedParentID)
	}
}

// --- FTD child: establish router link from non-parent ---

func TestHandleAdvertisement_FtdChild_FromNonParent_GoodMargin_SchedulesLink(t *testing.T) {
	t.Parallel()
	h, _, ops := newAdvHandlerTestSetup(RoleChild, 0)

	ops.neighborCount = 0 // No existing router links.

	nonParentRouterID := uint8(20)
	nonParentRLOC := RLOC16FromRouterID(nonParentRouterID)

	nonParentRouter := &Router{}
	nonParentRouter.RLOC16 = nonParentRLOC
	nonParentRouter.State = StateInvalid
	ops.routersByID[nonParentRouterID] = nonParentRouter

	routeMask := RouterIDSet{}
	routeMask.Add(nonParentRouterID)
	entries := []Route64Entry{
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
	}

	strangerAddr := extAddressForRouterID(nonParentRouterID)
	stranger := &Neighbor{
		MacAddr: strangerAddr,
		RLOC16:  nonParentRLOC,
		State:   StateValid,
	}

	tlvs := standardAdvTLVsWithRoute(nonParentRLOC, testLeaderData, 5, routeMask, entries)
	rxInfo := advRxInfoFromRouter(stranger, tlvs, LinkRequestMinMargin+5)

	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if nonParentRouter.RemainingLinkRequestAttempts != LinkRequestAttempts {
		t.Errorf("expected link request attempts = %d, got %d",
			LinkRequestAttempts, nonParentRouter.RemainingLinkRequestAttempts)
	}
}

func TestHandleAdvertisement_FtdChild_FromNonParent_LowMargin_NoLink(t *testing.T) {
	t.Parallel()
	h, _, ops := newAdvHandlerTestSetup(RoleChild, 0)

	ops.neighborCount = 0

	nonParentRouterID := uint8(20)
	nonParentRLOC := RLOC16FromRouterID(nonParentRouterID)

	nonParentRouter := &Router{}
	nonParentRouter.RLOC16 = nonParentRLOC
	nonParentRouter.State = StateInvalid
	ops.routersByID[nonParentRouterID] = nonParentRouter

	routeMask := RouterIDSet{}
	routeMask.Add(nonParentRouterID)
	entries := []Route64Entry{
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
	}

	strangerAddr := extAddressForRouterID(nonParentRouterID)
	stranger := &Neighbor{
		MacAddr: strangerAddr,
		RLOC16:  nonParentRLOC,
		State:   StateValid,
	}

	tlvs := standardAdvTLVsWithRoute(nonParentRLOC, testLeaderData, 5, routeMask, entries)
	rxInfo := advRxInfoFromRouter(stranger, tlvs, LinkRequestMinMargin-1)

	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if nonParentRouter.RemainingLinkRequestAttempts != 0 {
		t.Errorf("expected no link request for low margin, got attempts=%d",
			nonParentRouter.RemainingLinkRequestAttempts)
	}
}

// --- Stale RLOC16 cleanup ---

func TestHandleAdvertisement_Router_StaleRLOC16_RemovesLink(t *testing.T) {
	t.Parallel()
	h, _, ops := newAdvHandlerTestSetup(RoleRouter, testRouterID1)

	// The rxInfo neighbor has a different RLOC16 than the source address.
	neighborRouter := &Router{}
	neighborRouter.MacAddr = extAddressForRouterID(testRouterID2)
	neighborRouter.RLOC16 = testRouterRLOC2
	neighborRouter.State = StateValid
	ops.routersByID[testRouterID2] = neighborRouter
	ops.routersByRLOC16[testRouterRLOC2] = neighborRouter

	// The neighbor's RLOC16 in rxInfo differs from the source address.
	staleRLOC := uint16(0x3000)
	staleRouter := &Router{}
	staleRouter.RLOC16 = staleRLOC
	staleRouter.State = StateValid
	ops.routersByRLOC16[staleRLOC] = staleRouter

	neighborWithStaleRLOC := &Neighbor{
		MacAddr: extAddressForRouterID(testRouterID2),
		RLOC16:  staleRLOC, // Stale — doesn't match source.
		State:   StateValid,
	}

	routeMask := RouterIDSet{}
	routeMask.Add(testRouterID1)
	routeMask.Add(testRouterID2)
	entries := []Route64Entry{
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
	}

	tlvs := standardAdvTLVsWithRoute(testRouterRLOC2, testLeaderData, 5, routeMask, entries)
	rxInfo := advRxInfoFromRouter(neighborWithStaleRLOC, tlvs, 30)

	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !ops.removeRouterLinkCalled {
		t.Error("expected RemoveRouterLink to be called for stale RLOC16")
	}
	if ops.removeRouterLinkRouter != staleRouter {
		t.Error("expected RemoveRouterLink to be called with the stale router")
	}
}

// --- Source not a router RLOC16 ---

func TestHandleAdvertisement_Router_SourceNotRouterRLOC_Ignored(t *testing.T) {
	t.Parallel()
	h, _, ops := newAdvHandlerTestSetup(RoleRouter, testRouterID1)

	// Source is a child RLOC16, not a router RLOC.
	childRLOCSource := uint16(0x2801) // Router ID 10, child ID 1.
	neighbor := &Neighbor{
		MacAddr: extAddressForRouterID(testRouterID2),
		RLOC16:  childRLOCSource,
		State:   StateValid,
	}
	tlvs := standardAdvTLVs(childRLOCSource, testLeaderData)
	rxInfo := advRxInfoFromRouter(neighbor, tlvs, 30)

	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ops.updateRoutesCalled {
		t.Error("expected UpdateRoutes NOT to be called for non-router RLOC16")
	}
}

// --- Router with known but invalid neighbor ---

func TestHandleAdvertisement_Router_KnownInvalidNeighbor_GoodMargin_SchedulesLink(t *testing.T) {
	t.Parallel()
	h, _, ops := newAdvHandlerTestSetup(RoleRouter, testRouterID1)

	// Known router but not in valid state.
	knownRouter := &Router{}
	knownRouter.MacAddr = extAddressForRouterID(testRouterID2)
	knownRouter.RLOC16 = testRouterRLOC2
	knownRouter.State = StateInvalid
	ops.routersByID[testRouterID2] = knownRouter
	ops.routersByRLOC16[testRouterRLOC2] = knownRouter

	routeMask := RouterIDSet{}
	routeMask.Add(testRouterID1)
	routeMask.Add(testRouterID2)
	entries := []Route64Entry{
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
	}

	neighbor := &Neighbor{
		MacAddr: extAddressForRouterID(testRouterID2),
		RLOC16:  testRouterRLOC2,
		State:   StateValid,
	}
	tlvs := standardAdvTLVsWithRoute(testRouterRLOC2, testLeaderData, 5, routeMask, entries)
	rxInfo := advRxInfoFromRouter(neighbor, tlvs, LinkRequestMinMargin+5)

	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if knownRouter.RemainingLinkRequestAttempts != LinkRequestAttempts {
		t.Errorf("expected link request attempts = %d for known invalid neighbor, got %d",
			LinkRequestAttempts, knownRouter.RemainingLinkRequestAttempts)
	}
}

// --- Router/Leader: nil or invalid neighbor ---

func TestHandleAdvertisement_Router_NilNeighbor_UpdatesLastHeardSkipped(t *testing.T) {
	t.Parallel()
	h, _, _ := newAdvHandlerTestSetup(RoleRouter, testRouterID1)

	routeMask := RouterIDSet{}
	routeMask.Add(testRouterID1)
	routeMask.Add(testRouterID2)
	entries := []Route64Entry{
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
		{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0},
	}

	// nil neighbor — the router/leader last-heard path should not crash.
	tlvs := standardAdvTLVsWithRoute(testRouterRLOC2, testLeaderData, 5, routeMask, entries)
	rxInfo := advRxInfoFromUnknown(extAddressForRouterID(testRouterID2), tlvs, 30)

	err := h.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No crash is the assertion.
}

// --- extAddressForRouterID helper ---

func TestExtAddressForRouterID(t *testing.T) {
	t.Parallel()
	addr := extAddressForRouterID(42)
	expected := types.ExtAddress{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 42}
	if addr != expected {
		t.Errorf("extAddressForRouterID(42) = %v, want %v", addr, expected)
	}
}
