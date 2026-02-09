// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"testing"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/key"
)

// --- mock RouteDataProvider ---

type mockRouteDataProvider struct {
	sequence uint8
	mask     RouterIDSet
	entries  []Route64Entry
	calls    []routeDataCall
}

type routeDataCall struct {
	selfRouterID   uint8
	leaderRouterID uint8
}

func (m *mockRouteDataProvider) GetRouteData(selfRouterID, leaderRouterID uint8) (uint8, RouterIDSet, []Route64Entry) {
	m.calls = append(m.calls, routeDataCall{
		selfRouterID:   selfRouterID,
		leaderRouterID: leaderRouterID,
	})
	return m.sequence, m.mask, m.entries
}

// --- BuildAdvertisement tests ---

func TestBuildAdvertisement(t *testing.T) {
	t.Parallel()

	rloc16 := uint16(0x1800) // Router ID 6

	leaderData := LeaderData{
		PartitionID:       0xDEADBEEF,
		Weighting:         64,
		DataVersion:       10,
		StableDataVersion: 5,
		LeaderRouterID:    6,
	}

	var mask RouterIDSet
	mask.Add(6)
	mask.Add(10)

	entries := []Route64Entry{
		{LinkQualityOut: 0, LinkQualityIn: 0, Cost: 1}, // self (router 6)
		{LinkQualityOut: 3, LinkQualityIn: 2, Cost: 0}, // neighbor (router 10)
	}

	msg := BuildAdvertisement(rloc16, leaderData, 42, mask, entries)

	if msg == nil {
		t.Fatal("BuildAdvertisement returned nil")
	}

	if msg.Command() != CommandAdvertisement {
		t.Errorf("command = %d, want %d", msg.Command(), CommandAdvertisement)
	}

	// Parse the TLVs from the payload.
	payload := msg.Payload()
	if len(payload) < 2 {
		t.Fatalf("payload too short: %d", len(payload))
	}

	// Skip the command byte.
	tlvs, err := ParseTLVs(payload[1:])
	if err != nil {
		t.Fatalf("ParseTLVs: %v", err)
	}

	// Verify Source Address TLV.
	srcVal, ok := FindTLV(tlvs, TLVSourceAddress)
	if !ok {
		t.Fatal("missing Source Address TLV")
	}
	srcRLOC, err := ReadSourceAddressTLV(srcVal)
	if err != nil {
		t.Fatalf("ReadSourceAddressTLV: %v", err)
	}
	if srcRLOC != 0x1800 {
		t.Errorf("Source Address RLOC16 = 0x%04X, want 0x1800", srcRLOC)
	}

	// Verify Leader Data TLV.
	ldVal, ok := FindTLV(tlvs, TLVLeaderData)
	if !ok {
		t.Fatal("missing Leader Data TLV")
	}
	ld, err := ReadLeaderDataTLV(ldVal)
	if err != nil {
		t.Fatalf("ReadLeaderDataTLV: %v", err)
	}
	if ld.PartitionID != 0xDEADBEEF {
		t.Errorf("PartitionID = 0x%08X, want 0xDEADBEEF", ld.PartitionID)
	}
	if ld.Weighting != 64 {
		t.Errorf("Weighting = %d, want 64", ld.Weighting)
	}
	if ld.DataVersion != 10 {
		t.Errorf("DataVersion = %d, want 10", ld.DataVersion)
	}
	if ld.StableDataVersion != 5 {
		t.Errorf("StableDataVersion = %d, want 5", ld.StableDataVersion)
	}
	if ld.LeaderRouterID != 6 {
		t.Errorf("LeaderRouterID = %d, want 6", ld.LeaderRouterID)
	}

	// Verify Route64 TLV.
	routeVal, ok := FindTLV(tlvs, TLVRoute64)
	if !ok {
		t.Fatal("missing Route64 TLV")
	}
	seq, parsedMask, parsedEntries, err := ReadRoute64TLV(routeVal)
	if err != nil {
		t.Fatalf("ReadRoute64TLV: %v", err)
	}
	if seq != 42 {
		t.Errorf("sequence = %d, want 42", seq)
	}
	if !parsedMask.Contains(6) || !parsedMask.Contains(10) {
		t.Errorf("mask does not contain expected router IDs 6 and 10")
	}
	if len(parsedEntries) != 2 {
		t.Fatalf("entry count = %d, want 2", len(parsedEntries))
	}
	if parsedEntries[0].Cost != 1 {
		t.Errorf("entry[0].Cost = %d, want 1", parsedEntries[0].Cost)
	}
	if parsedEntries[1].LinkQualityOut != 3 || parsedEntries[1].LinkQualityIn != 2 {
		t.Errorf("entry[1] LQ = out:%d in:%d, want out:3 in:2",
			parsedEntries[1].LinkQualityOut, parsedEntries[1].LinkQualityIn)
	}
}

func TestBuildAdvertisement_EmptyRouteTable(t *testing.T) {
	t.Parallel()

	rloc16 := uint16(0x0C00) // Router ID 3
	leaderData := LeaderData{
		PartitionID:    1234,
		LeaderRouterID: 3,
	}

	var mask RouterIDSet
	mask.Add(3)
	entries := []Route64Entry{
		{Cost: 1}, // self only
	}

	msg := BuildAdvertisement(rloc16, leaderData, 1, mask, entries)

	payload := msg.Payload()
	tlvs, err := ParseTLVs(payload[1:])
	if err != nil {
		t.Fatalf("ParseTLVs: %v", err)
	}

	routeVal, ok := FindTLV(tlvs, TLVRoute64)
	if !ok {
		t.Fatal("missing Route64 TLV")
	}
	_, parsedMask, parsedEntries, err := ReadRoute64TLV(routeVal)
	if err != nil {
		t.Fatalf("ReadRoute64TLV: %v", err)
	}
	if parsedMask.GetAllocatedCount() != 1 {
		t.Errorf("mask count = %d, want 1", parsedMask.GetAllocatedCount())
	}
	if len(parsedEntries) != 1 {
		t.Errorf("entry count = %d, want 1", len(parsedEntries))
	}
}

// --- SendAdvertisement tests ---

// newAdvertisementTestSetup creates test fixtures for SendAdvertisement.
func newAdvertisementTestSetup(role DeviceRole, routerID uint8) (*Mle, *Dispatcher, *mockTransport, *mockRouteDataProvider) {
	m := NewMle()
	_ = m.Enable()

	// Set up the role and FTD state directly.
	m.mu.Lock()
	m.role = role
	m.rloc16 = RLOC16FromRouterID(routerID)
	m.ftd.routerID = routerID
	m.leaderData = LeaderData{
		PartitionID:    0xCAFE0001,
		Weighting:      64,
		DataVersion:    3,
		LeaderRouterID: routerID,
	}
	m.mu.Unlock()

	allRouters := ip6.Address{
		0xff, 0x02, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0x02,
	}

	transport := &mockTransport{
		extAddr: types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		linkLocal: ip6.Address{
			0xfe, 0x80, 0, 0, 0, 0, 0, 0,
			0x13, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		},
		allRouters: allRouters,
	}

	keyMgr := &mockKeyProvider{
		currentSeq: 5,
		currentKey: key.MleKey{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
	}

	d := NewDispatcher(m, keyMgr, transport)

	var mask RouterIDSet
	mask.Add(routerID)

	routeProvider := &mockRouteDataProvider{
		sequence: 7,
		mask:     mask,
		entries: []Route64Entry{
			{Cost: 1}, // self
		},
	}

	return m, d, transport, routeProvider
}

func TestSendAdvertisement_Router(t *testing.T) {
	t.Parallel()

	m, d, transport, routeProvider := newAdvertisementTestSetup(RoleRouter, 5)

	err := SendAdvertisement(m, d, transport, routeProvider)
	if err != nil {
		t.Fatalf("SendAdvertisement: %v", err)
	}

	// Verify a message was sent.
	if len(transport.sentMessages) != 1 {
		t.Fatalf("sent %d messages, want 1", len(transport.sentMessages))
	}

	// Verify destination is all-routers multicast.
	expectedDst := ip6.Address{
		0xff, 0x02, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0x02,
	}
	if transport.sentMessages[0].dst != expectedDst {
		t.Errorf("dst = %v, want %v", transport.sentMessages[0].dst, expectedDst)
	}

	// Verify the RouteDataProvider was called with correct args.
	if len(routeProvider.calls) != 1 {
		t.Fatalf("RouteDataProvider called %d times, want 1", len(routeProvider.calls))
	}
	if routeProvider.calls[0].selfRouterID != 5 {
		t.Errorf("selfRouterID = %d, want 5", routeProvider.calls[0].selfRouterID)
	}
	if routeProvider.calls[0].leaderRouterID != 5 {
		t.Errorf("leaderRouterID = %d, want 5", routeProvider.calls[0].leaderRouterID)
	}
}

func TestSendAdvertisement_Leader(t *testing.T) {
	t.Parallel()

	m, d, transport, routeProvider := newAdvertisementTestSetup(RoleLeader, 10)

	err := SendAdvertisement(m, d, transport, routeProvider)
	if err != nil {
		t.Fatalf("SendAdvertisement: %v", err)
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("sent %d messages, want 1", len(transport.sentMessages))
	}

	if routeProvider.calls[0].selfRouterID != 10 {
		t.Errorf("selfRouterID = %d, want 10", routeProvider.calls[0].selfRouterID)
	}
}

func TestSendAdvertisement_WrongRole_Child(t *testing.T) {
	t.Parallel()

	m, d, transport, routeProvider := newAdvertisementTestSetup(RoleChild, 5)

	// Override role to Child.
	m.mu.Lock()
	m.role = RoleChild
	m.mu.Unlock()

	err := SendAdvertisement(m, d, transport, routeProvider)
	if err == nil {
		t.Fatal("expected error for Child role")
	}

	if len(transport.sentMessages) != 0 {
		t.Errorf("sent %d messages, want 0", len(transport.sentMessages))
	}
}

func TestSendAdvertisement_WrongRole_Detached(t *testing.T) {
	t.Parallel()

	m, d, transport, routeProvider := newAdvertisementTestSetup(RoleDetached, 5)

	m.mu.Lock()
	m.role = RoleDetached
	m.mu.Unlock()

	err := SendAdvertisement(m, d, transport, routeProvider)
	if err == nil {
		t.Fatal("expected error for Detached role")
	}
}

func TestSendAdvertisement_InvalidRouterID(t *testing.T) {
	t.Parallel()

	m, d, transport, routeProvider := newAdvertisementTestSetup(RoleRouter, InvalidRouterID)

	err := SendAdvertisement(m, d, transport, routeProvider)
	if err == nil {
		t.Fatal("expected error for invalid router ID")
	}

	if len(transport.sentMessages) != 0 {
		t.Errorf("sent %d messages, want 0", len(transport.sentMessages))
	}
}

func TestSendAdvertisement_WithMultipleRouters(t *testing.T) {
	t.Parallel()

	m, d, transport, _ := newAdvertisementTestSetup(RoleRouter, 2)

	// Set leader to a different router.
	m.mu.Lock()
	m.leaderData.LeaderRouterID = 0
	m.mu.Unlock()

	var mask RouterIDSet
	mask.Add(0) // leader
	mask.Add(2) // self
	mask.Add(5) // neighbor

	routeProvider := &mockRouteDataProvider{
		sequence: 15,
		mask:     mask,
		entries: []Route64Entry{
			{LinkQualityOut: 0, LinkQualityIn: 0, Cost: 3}, // router 0 (leader)
			{LinkQualityOut: 0, LinkQualityIn: 0, Cost: 1}, // router 2 (self)
			{LinkQualityOut: 3, LinkQualityIn: 3, Cost: 0}, // router 5 (neighbor)
		},
	}

	err := SendAdvertisement(m, d, transport, routeProvider)
	if err != nil {
		t.Fatalf("SendAdvertisement: %v", err)
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("sent %d messages, want 1", len(transport.sentMessages))
	}

	// Verify provider was called with correct router IDs.
	if routeProvider.calls[0].selfRouterID != 2 {
		t.Errorf("selfRouterID = %d, want 2", routeProvider.calls[0].selfRouterID)
	}
	if routeProvider.calls[0].leaderRouterID != 0 {
		t.Errorf("leaderRouterID = %d, want 0", routeProvider.calls[0].leaderRouterID)
	}
}

func TestRouteDataProvider_Interface(t *testing.T) {
	t.Parallel()

	// Verify the interface is satisfiable.
	var provider RouteDataProvider = &mockRouteDataProvider{
		sequence: 1,
		mask:     RouterIDSet{},
		entries:  nil,
	}

	seq, mask, entries := provider.GetRouteData(0, 0)
	if seq != 1 {
		t.Errorf("sequence = %d, want 1", seq)
	}
	if mask.GetAllocatedCount() != 0 {
		t.Errorf("mask count = %d, want 0", mask.GetAllocatedCount())
	}
	if entries != nil {
		t.Errorf("entries = %v, want nil", entries)
	}
}
