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

// --- linkLocalIPFromExtAddress tests ---

func TestLinkLocalIPFromExtAddress(t *testing.T) {
	t.Parallel()

	mac := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	got := linkLocalIPFromExtAddress(mac)

	expected := ip6.Address{
		0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		0x13, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // Toggle the U/L bit: XOR 0x11 with 0x02 to obtain 0x13.
	}

	if got != expected {
		t.Errorf("linkLocalIPFromExtAddress(%v) = %v, want %v", mac, got, expected)
	}
}

// --- BuildLinkRequest tests ---

func TestBuildLinkRequest_Detached(t *testing.T) {
	t.Parallel()

	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44}
	msg := BuildLinkRequest(RoleDetached, 0xFFFE, LeaderData{}, challenge, false)

	if msg.Command() != CommandLinkRequest {
		t.Errorf("command = %d, want %d", msg.Command(), CommandLinkRequest)
	}

	tlvs, err := ParseTLVs(msg.Payload()[1:])
	if err != nil {
		t.Fatalf("ParseTLVs: %v", err)
	}

	// Should have Version.
	verVal, ok := FindTLV(tlvs, TLVVersion)
	if !ok {
		t.Fatal("missing Version TLV")
	}
	ver, err := ReadVersionTLV(verVal)
	if err != nil {
		t.Fatalf("ReadVersionTLV: %v", err)
	}
	if ver != ThreadVersion {
		t.Errorf("version = %d, want %d", ver, ThreadVersion)
	}

	// Should have Challenge.
	chalVal, ok := FindTLV(tlvs, TLVChallenge)
	if !ok {
		t.Fatal("missing Challenge TLV")
	}
	chal, err := ReadChallengeTLV(chalVal)
	if err != nil {
		t.Fatalf("ReadChallengeTLV: %v", err)
	}
	if chal != challenge {
		t.Errorf("challenge = %v, want %v", chal, challenge)
	}

	// Should have TLV Request with Address16 and Route64.
	reqVal, ok := FindTLV(tlvs, TLVTLVRequest)
	if !ok {
		t.Fatal("missing TLV Request")
	}
	if len(reqVal) != 2 || reqVal[0] != TLVAddress16 || reqVal[1] != TLVRoute64 {
		t.Errorf("TLV Request = %v, want [%d, %d]", reqVal, TLVAddress16, TLVRoute64)
	}

	// Should NOT have Source Address or Leader Data.
	if _, ok := FindTLV(tlvs, TLVSourceAddress); ok {
		t.Error("detached Link Request should not include Source Address TLV")
	}
	if _, ok := FindTLV(tlvs, TLVLeaderData); ok {
		t.Error("detached Link Request should not include Leader Data TLV")
	}
}

func TestBuildLinkRequest_Child(t *testing.T) {
	t.Parallel()

	challenge := Challenge{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	leaderData := LeaderData{
		PartitionID:    0x12345678,
		LeaderRouterID: 5,
	}

	msg := BuildLinkRequest(RoleChild, 0x1401, leaderData, challenge, false)

	tlvs, err := ParseTLVs(msg.Payload()[1:])
	if err != nil {
		t.Fatalf("ParseTLVs: %v", err)
	}

	// Should have Version, Source Address, Leader Data, Challenge.
	if _, ok := FindTLV(tlvs, TLVVersion); !ok {
		t.Error("missing Version TLV")
	}

	srcVal, ok := FindTLV(tlvs, TLVSourceAddress)
	if !ok {
		t.Fatal("missing Source Address TLV")
	}
	srcRLOC, err := ReadSourceAddressTLV(srcVal)
	if err != nil {
		t.Fatalf("ReadSourceAddressTLV: %v", err)
	}
	if srcRLOC != 0x1401 {
		t.Errorf("Source Address = 0x%04X, want 0x1401", srcRLOC)
	}

	ldVal, ok := FindTLV(tlvs, TLVLeaderData)
	if !ok {
		t.Fatal("missing Leader Data TLV")
	}
	ld, err := ReadLeaderDataTLV(ldVal)
	if err != nil {
		t.Fatalf("ReadLeaderDataTLV: %v", err)
	}
	if ld.PartitionID != 0x12345678 {
		t.Errorf("PartitionID = 0x%08X, want 0x12345678", ld.PartitionID)
	}

	if _, ok := FindTLV(tlvs, TLVChallenge); !ok {
		t.Error("missing Challenge TLV")
	}

	// Should NOT have TLV Request (child doesn't send one).
	if _, ok := FindTLV(tlvs, TLVTLVRequest); ok {
		t.Error("child Link Request should not include TLV Request")
	}
}

func TestBuildLinkRequest_RouterUnknownNeighbor(t *testing.T) {
	t.Parallel()

	challenge := Challenge{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	leaderData := LeaderData{PartitionID: 99, LeaderRouterID: 0}

	msg := BuildLinkRequest(RoleRouter, 0x0800, leaderData, challenge, false)

	tlvs, err := ParseTLVs(msg.Payload()[1:])
	if err != nil {
		t.Fatalf("ParseTLVs: %v", err)
	}

	// Should have Version, Source Address, Leader Data, Challenge, TLV Request(LinkMargin).
	if _, ok := FindTLV(tlvs, TLVVersion); !ok {
		t.Error("missing Version TLV")
	}
	if _, ok := FindTLV(tlvs, TLVSourceAddress); !ok {
		t.Error("missing Source Address TLV")
	}
	if _, ok := FindTLV(tlvs, TLVLeaderData); !ok {
		t.Error("missing Leader Data TLV")
	}
	if _, ok := FindTLV(tlvs, TLVChallenge); !ok {
		t.Error("missing Challenge TLV")
	}

	reqVal, ok := FindTLV(tlvs, TLVTLVRequest)
	if !ok {
		t.Fatal("missing TLV Request")
	}
	if len(reqVal) != 1 || reqVal[0] != TLVLinkMargin {
		t.Errorf("TLV Request = %v, want [%d]", reqVal, TLVLinkMargin)
	}
}

func TestBuildLinkRequest_RouterValidNeighbor(t *testing.T) {
	t.Parallel()

	challenge := Challenge{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	leaderData := LeaderData{PartitionID: 42, LeaderRouterID: 1}

	msg := BuildLinkRequest(RoleRouter, 0x0400, leaderData, challenge, true)

	tlvs, err := ParseTLVs(msg.Payload()[1:])
	if err != nil {
		t.Fatalf("ParseTLVs: %v", err)
	}

	// TLV Request should include both LinkMargin and Route64.
	reqVal, ok := FindTLV(tlvs, TLVTLVRequest)
	if !ok {
		t.Fatal("missing TLV Request")
	}
	if len(reqVal) != 2 || reqVal[0] != TLVLinkMargin || reqVal[1] != TLVRoute64 {
		t.Errorf("TLV Request = %v, want [%d, %d]", reqVal, TLVLinkMargin, TLVRoute64)
	}
}

func TestBuildLinkRequest_Leader(t *testing.T) {
	t.Parallel()

	challenge := Challenge{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88}
	leaderData := LeaderData{PartitionID: 1000, LeaderRouterID: 0}

	msg := BuildLinkRequest(RoleLeader, 0x0000, leaderData, challenge, false)

	tlvs, err := ParseTLVs(msg.Payload()[1:])
	if err != nil {
		t.Fatalf("ParseTLVs: %v", err)
	}

	// Leader uses same TLV structure as Router.
	if _, ok := FindTLV(tlvs, TLVSourceAddress); !ok {
		t.Error("missing Source Address TLV")
	}
	if _, ok := FindTLV(tlvs, TLVLeaderData); !ok {
		t.Error("missing Leader Data TLV")
	}

	reqVal, ok := FindTLV(tlvs, TLVTLVRequest)
	if !ok {
		t.Fatal("missing TLV Request")
	}
	// Unknown neighbor: only LinkMargin.
	if len(reqVal) != 1 || reqVal[0] != TLVLinkMargin {
		t.Errorf("TLV Request = %v, want [%d]", reqVal, TLVLinkMargin)
	}
}

// --- SendLinkRequest tests ---

func newLinkRequestTestSetup(role DeviceRole, routerID uint8) (*Mle, *Dispatcher, *mockTransport) {
	m := NewMle()
	_ = m.Enable()

	m.mu.Lock()
	m.role = role
	m.rloc16 = RLOC16FromRouterID(routerID)
	m.ftd.routerID = routerID
	m.leaderData = LeaderData{
		PartitionID:    0xBEEF0001,
		LeaderRouterID: routerID,
	}
	m.mu.Unlock()

	allRouters := ip6.Address{
		0xff, 0x02, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0x02,
	}

	transport := &mockTransport{
		extAddr: types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11},
		linkLocal: ip6.Address{
			0xfe, 0x80, 0, 0, 0, 0, 0, 0,
			0xA8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		},
		allRouters: allRouters,
	}

	keyMgr := &mockKeyProvider{
		currentSeq: 3,
		currentKey: key.MleKey{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
			0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00},
	}

	d := NewDispatcher(m, keyMgr, transport)
	return m, d, transport
}

func TestSendLinkRequest_Multicast(t *testing.T) {
	t.Parallel()

	m, d, transport := newLinkRequestTestSetup(RoleRouter, 5)

	challenge, err := SendLinkRequest(m, d, transport, nil)
	if err != nil {
		t.Fatalf("SendLinkRequest: %v", err)
	}

	// Challenge should be non-zero (randomly generated).
	if challenge == (Challenge{}) {
		t.Error("challenge should be non-zero")
	}

	// Should have sent one message.
	if len(transport.sentMessages) != 1 {
		t.Fatalf("sent %d messages, want 1", len(transport.sentMessages))
	}

	// Destination should be all-routers multicast.
	expectedDst := ip6.Address{
		0xff, 0x02, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0x02,
	}
	if transport.sentMessages[0].dst != expectedDst {
		t.Errorf("dst = %v, want %v", transport.sentMessages[0].dst, expectedDst)
	}
}

func TestSendLinkRequest_UnicastUnknownNeighbor(t *testing.T) {
	t.Parallel()

	m, d, transport := newLinkRequestTestSetup(RoleRouter, 5)

	router := &Router{
		Neighbor: Neighbor{
			MacAddr: types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
			RLOC16:  0x2800,
			State:   StateRestored,
		},
	}

	challenge, err := SendLinkRequest(m, d, transport, router)
	if err != nil {
		t.Fatalf("SendLinkRequest: %v", err)
	}

	// Challenge should be stored on the router.
	if router.PendingChallenge != challenge {
		t.Error("challenge not stored on router")
	}

	// Link accept countdown should be restarted.
	if router.LinkAcceptCountdown != LinkAcceptTimeout {
		t.Errorf("LinkAcceptCountdown = %d, want %d", router.LinkAcceptCountdown, LinkAcceptTimeout)
	}

	// Destination should be the router's link-local address.
	expectedDst := linkLocalIPFromExtAddress(router.MacAddr)
	if len(transport.sentMessages) != 1 {
		t.Fatalf("sent %d messages, want 1", len(transport.sentMessages))
	}
	if transport.sentMessages[0].dst != expectedDst {
		t.Errorf("dst = %v, want %v", transport.sentMessages[0].dst, expectedDst)
	}
}

func TestSendLinkRequest_UnicastValidNeighbor(t *testing.T) {
	t.Parallel()

	m, d, transport := newLinkRequestTestSetup(RoleRouter, 5)

	router := &Router{
		Neighbor: Neighbor{
			MacAddr: types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22},
			RLOC16:  0x2800,
			State:   StateValid,
		},
	}

	originalChallenge := router.PendingChallenge

	challenge, err := SendLinkRequest(m, d, transport, router)
	if err != nil {
		t.Fatalf("SendLinkRequest: %v", err)
	}

	// For a valid neighbor, challenge should NOT be stored on the router.
	if router.PendingChallenge != originalChallenge {
		t.Error("challenge should not be stored on valid neighbor's router entry")
	}

	// But the returned challenge should still be non-zero.
	if challenge == (Challenge{}) {
		t.Error("returned challenge should be non-zero")
	}

	// Link accept countdown should NOT be restarted for valid neighbors.
	if router.LinkAcceptCountdown != 0 {
		t.Errorf("LinkAcceptCountdown = %d, want 0", router.LinkAcceptCountdown)
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("sent %d messages, want 1", len(transport.sentMessages))
	}
}

func TestSendLinkRequest_Disabled(t *testing.T) {
	t.Parallel()

	m, d, transport := newLinkRequestTestSetup(RoleDisabled, 0)
	m.mu.Lock()
	m.role = RoleDisabled
	m.mu.Unlock()

	_, err := SendLinkRequest(m, d, transport, nil)
	if err == nil {
		t.Fatal("expected error for disabled state")
	}

	if len(transport.sentMessages) != 0 {
		t.Errorf("sent %d messages, want 0", len(transport.sentMessages))
	}
}

func TestSendLinkRequest_Detached(t *testing.T) {
	t.Parallel()

	m, d, transport := newLinkRequestTestSetup(RoleDetached, 0)
	m.mu.Lock()
	m.role = RoleDetached
	m.mu.Unlock()

	_, err := SendLinkRequest(m, d, transport, nil)
	if err != nil {
		t.Fatalf("SendLinkRequest: %v", err)
	}

	// Detached is allowed (for restoring previous role).
	if len(transport.sentMessages) != 1 {
		t.Fatalf("sent %d messages, want 1", len(transport.sentMessages))
	}
}

func TestSendLinkRequest_Child(t *testing.T) {
	t.Parallel()

	m, d, transport := newLinkRequestTestSetup(RoleChild, 0)
	m.mu.Lock()
	m.role = RoleChild
	m.rloc16 = 0x1401 // Child RLOC16
	m.mu.Unlock()

	router := &Router{
		Neighbor: Neighbor{
			MacAddr: types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
			RLOC16:  0x2800,
			State:   StateRestored,
		},
	}

	_, err := SendLinkRequest(m, d, transport, router)
	if err != nil {
		t.Fatalf("SendLinkRequest: %v", err)
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("sent %d messages, want 1", len(transport.sentMessages))
	}
}
