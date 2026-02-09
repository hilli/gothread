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

// --- BuildLinkAccept tests ---

func TestBuildLinkAccept_Basic(t *testing.T) {
	t.Parallel()

	response := Challenge{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	msg := BuildLinkAccept(
		false,    // not accept-and-request
		0x0800,   // rloc16
		response, // response (echo of challenge)
		100,      // link frame counter
		200,      // mle frame counter
		32,       // link margin
		&LeaderData{ // leader data
			PartitionID:    0xCAFE,
			LeaderRouterID: 2,
		},
		nil, // no requested TLVs
		InvalidRLOC16,
		0, RouterIDSet{}, nil, // no route data
		Challenge{}, // no challenge (not accept-and-request)
	)

	if msg.Command() != CommandLinkAccept {
		t.Errorf("command = %d, want %d", msg.Command(), CommandLinkAccept)
	}

	tlvs, err := ParseTLVs(msg.Payload()[1:])
	if err != nil {
		t.Fatalf("ParseTLVs: %v", err)
	}

	// Verify Version.
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

	// Verify Source Address.
	srcVal, ok := FindTLV(tlvs, TLVSourceAddress)
	if !ok {
		t.Fatal("missing Source Address TLV")
	}
	srcRLOC, err := ReadSourceAddressTLV(srcVal)
	if err != nil {
		t.Fatalf("ReadSourceAddressTLV: %v", err)
	}
	if srcRLOC != 0x0800 {
		t.Errorf("Source Address = 0x%04X, want 0x0800", srcRLOC)
	}

	// Verify Response.
	respVal, ok := FindTLV(tlvs, TLVResponse)
	if !ok {
		t.Fatal("missing Response TLV")
	}
	if len(respVal) != ChallengeSize {
		t.Fatalf("Response length = %d, want %d", len(respVal), ChallengeSize)
	}
	var gotResp Challenge
	copy(gotResp[:], respVal)
	if gotResp != response {
		t.Errorf("Response = %v, want %v", gotResp, response)
	}

	// Verify Link Frame Counter.
	lfcVal, ok := FindTLV(tlvs, TLVLinkFrameCounter)
	if !ok {
		t.Fatal("missing Link Frame Counter TLV")
	}
	lfc, err := ReadLinkFrameCounterTLV(lfcVal)
	if err != nil {
		t.Fatalf("ReadLinkFrameCounterTLV: %v", err)
	}
	if lfc != 100 {
		t.Errorf("Link Frame Counter = %d, want 100", lfc)
	}

	// Verify MLE Frame Counter.
	mfcVal, ok := FindTLV(tlvs, TLVMleFrameCounter)
	if !ok {
		t.Fatal("missing MLE Frame Counter TLV")
	}
	mfc, err := ReadMleFrameCounterTLV(mfcVal)
	if err != nil {
		t.Fatalf("ReadMleFrameCounterTLV: %v", err)
	}
	if mfc != 200 {
		t.Errorf("MLE Frame Counter = %d, want 200", mfc)
	}

	// Verify Link Margin.
	lmVal, ok := FindTLV(tlvs, TLVLinkMargin)
	if !ok {
		t.Fatal("missing Link Margin TLV")
	}
	lm, err := ReadLinkMarginTLV(lmVal)
	if err != nil {
		t.Fatalf("ReadLinkMarginTLV: %v", err)
	}
	if lm != 32 {
		t.Errorf("Link Margin = %d, want 32", lm)
	}

	// Verify Leader Data.
	ldVal, ok := FindTLV(tlvs, TLVLeaderData)
	if !ok {
		t.Fatal("missing Leader Data TLV")
	}
	ld, err := ReadLeaderDataTLV(ldVal)
	if err != nil {
		t.Fatalf("ReadLeaderDataTLV: %v", err)
	}
	if ld.PartitionID != 0xCAFE {
		t.Errorf("PartitionID = 0x%04X, want 0xCAFE", ld.PartitionID)
	}

	// Should NOT have Challenge (not accept-and-request).
	if _, ok := FindTLV(tlvs, TLVChallenge); ok {
		t.Error("plain Link Accept should not include Challenge TLV")
	}
}

func TestBuildLinkAccept_AcceptAndRequest(t *testing.T) {
	t.Parallel()

	response := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	challenge := Challenge{0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22}

	msg := BuildLinkAccept(
		true,   // accept-and-request
		0x1400, // rloc16
		response,
		50, 60, // frame counters
		20,  // link margin
		nil, // no leader data
		nil, // no requested TLVs
		InvalidRLOC16,
		0, RouterIDSet{}, nil,
		challenge,
	)

	if msg.Command() != CommandLinkAcceptAndRequest {
		t.Errorf("command = %d, want %d", msg.Command(), CommandLinkAcceptAndRequest)
	}

	tlvs, err := ParseTLVs(msg.Payload()[1:])
	if err != nil {
		t.Fatalf("ParseTLVs: %v", err)
	}

	// Should have Challenge.
	chalVal, ok := FindTLV(tlvs, TLVChallenge)
	if !ok {
		t.Fatal("missing Challenge TLV in Accept And Request")
	}
	chal, err := ReadChallengeTLV(chalVal)
	if err != nil {
		t.Fatalf("ReadChallengeTLV: %v", err)
	}
	if chal != challenge {
		t.Errorf("Challenge = %v, want %v", chal, challenge)
	}

	// Should have TLV Request with LinkMargin.
	reqVal, ok := FindTLV(tlvs, TLVTLVRequest)
	if !ok {
		t.Fatal("missing TLV Request in Accept And Request")
	}
	if len(reqVal) != 1 || reqVal[0] != TLVLinkMargin {
		t.Errorf("TLV Request = %v, want [%d]", reqVal, TLVLinkMargin)
	}

	// Should NOT have Leader Data (passed nil).
	if _, ok := FindTLV(tlvs, TLVLeaderData); ok {
		t.Error("should not include Leader Data when nil")
	}
}

func TestBuildLinkAccept_WithRequestedRoute64(t *testing.T) {
	t.Parallel()

	response := Challenge{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	var mask RouterIDSet
	mask.Add(2)
	mask.Add(5)

	entries := []Route64Entry{
		{LinkQualityOut: 0, LinkQualityIn: 0, Cost: 1},
		{LinkQualityOut: 3, LinkQualityIn: 2, Cost: 0},
	}

	msg := BuildLinkAccept(
		false,
		0x0800,
		response,
		10, 20,
		25,
		&LeaderData{PartitionID: 42},
		[]uint8{TLVRoute64}, // request Route64
		InvalidRLOC16,
		7, // route sequence
		mask,
		entries,
		Challenge{},
	)

	tlvs, err := ParseTLVs(msg.Payload()[1:])
	if err != nil {
		t.Fatalf("ParseTLVs: %v", err)
	}

	// Should have Route64.
	routeVal, ok := FindTLV(tlvs, TLVRoute64)
	if !ok {
		t.Fatal("missing Route64 TLV")
	}
	seq, parsedMask, parsedEntries, err := ReadRoute64TLV(routeVal)
	if err != nil {
		t.Fatalf("ReadRoute64TLV: %v", err)
	}
	if seq != 7 {
		t.Errorf("sequence = %d, want 7", seq)
	}
	if !parsedMask.Contains(2) || !parsedMask.Contains(5) {
		t.Error("mask missing expected router IDs")
	}
	if len(parsedEntries) != 2 {
		t.Fatalf("entry count = %d, want 2", len(parsedEntries))
	}
}

func TestBuildLinkAccept_WithRequestedAddress16(t *testing.T) {
	t.Parallel()

	response := Challenge{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	msg := BuildLinkAccept(
		false,
		0x0800,
		response,
		10, 20,
		25,
		nil,
		[]uint8{TLVAddress16}, // request Address16
		0x2800,                // router RLOC16
		0, RouterIDSet{}, nil,
		Challenge{},
	)

	tlvs, err := ParseTLVs(msg.Payload()[1:])
	if err != nil {
		t.Fatalf("ParseTLVs: %v", err)
	}

	// Should have Address16.
	a16Val, ok := FindTLV(tlvs, TLVAddress16)
	if !ok {
		t.Fatal("missing Address16 TLV")
	}
	rloc, err := ReadAddress16TLV(a16Val)
	if err != nil {
		t.Fatalf("ReadAddress16TLV: %v", err)
	}
	if rloc != 0x2800 {
		t.Errorf("Address16 = 0x%04X, want 0x2800", rloc)
	}
}

func TestBuildLinkAccept_Address16OmittedWhenInvalid(t *testing.T) {
	t.Parallel()

	response := Challenge{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	msg := BuildLinkAccept(
		false,
		0x0800,
		response,
		10, 20,
		25,
		nil,
		[]uint8{TLVAddress16},
		InvalidRLOC16, // should omit Address16
		0, RouterIDSet{}, nil,
		Challenge{},
	)

	tlvs, err := ParseTLVs(msg.Payload()[1:])
	if err != nil {
		t.Fatalf("ParseTLVs: %v", err)
	}

	// Should NOT have Address16 when routerRLOC16 is InvalidRLOC16.
	if _, ok := FindTLV(tlvs, TLVAddress16); ok {
		t.Error("should not include Address16 when routerRLOC16 is InvalidRLOC16")
	}
}

// --- SendLinkAccept tests ---

func newLinkAcceptTestSetup(role DeviceRole, routerID uint8) (*Mle, *Dispatcher, *mockTransport, *mockKeyProvider) {
	m := NewMle()
	_ = m.Enable()

	m.mu.Lock()
	m.role = role
	m.rloc16 = RLOC16FromRouterID(routerID)
	m.ftd.routerID = routerID
	m.leaderData = LeaderData{
		PartitionID:    0xDEAD0001,
		LeaderRouterID: routerID,
	}
	m.mu.Unlock()

	transport := &mockTransport{
		extAddr: types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11},
		linkLocal: ip6.Address{
			0xfe, 0x80, 0, 0, 0, 0, 0, 0,
			0xA8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		},
	}

	keyMgr := &mockKeyProvider{
		currentSeq:      5,
		currentKey:      key.MleKey{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
		macFrameCounter: 1000,
		mleFrameCounter: 2000,
	}

	d := NewDispatcher(m, keyMgr, transport)
	return m, d, transport, keyMgr
}

func TestSendLinkAccept_RouterToValidRouter(t *testing.T) {
	t.Parallel()

	m, d, transport, keyMgr := newLinkAcceptTestSetup(RoleRouter, 5)

	peerAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	info := &LinkAcceptInfo{
		ExtAddress:    peerAddr,
		RequestedTLVs: []uint8{TLVLinkMargin},
		RxChallenge:   Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22},
		LinkMargin:    40,
	}

	router := &Router{
		Neighbor: Neighbor{
			MacAddr: peerAddr,
			RLOC16:  0x2800,
			State:   StateValid,
		},
	}

	err := SendLinkAccept(m, d, keyMgr, info, router, nil)
	if err != nil {
		t.Fatalf("SendLinkAccept: %v", err)
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("sent %d messages, want 1", len(transport.sentMessages))
	}

	// Destination should be the peer's link-local address.
	expectedDst := linkLocalIPFromExtAddress(peerAddr)
	if transport.sentMessages[0].dst != expectedDst {
		t.Errorf("dst = %v, want %v", transport.sentMessages[0].dst, expectedDst)
	}
}

func TestSendLinkAccept_AcceptAndRequestForLinkRequestState(t *testing.T) {
	t.Parallel()

	m, d, transport, keyMgr := newLinkAcceptTestSetup(RoleRouter, 5)

	peerAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	info := &LinkAcceptInfo{
		ExtAddress:  peerAddr,
		RxChallenge: Challenge{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE},
		LinkMargin:  35,
	}

	router := &Router{
		Neighbor: Neighbor{
			MacAddr: peerAddr,
			RLOC16:  0x2800,
			State:   StateLinkRequest, // We also sent a Link Request
		},
	}

	err := SendLinkAccept(m, d, keyMgr, info, router, nil)
	if err != nil {
		t.Fatalf("SendLinkAccept: %v", err)
	}

	// Router should now have a generated challenge stored.
	if router.PendingChallenge == (Challenge{}) {
		t.Error("challenge should be generated and stored on router for Accept And Request")
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("sent %d messages, want 1", len(transport.sentMessages))
	}
}

func TestSendLinkAccept_WithRouteData(t *testing.T) {
	t.Parallel()

	m, d, transport, keyMgr := newLinkAcceptTestSetup(RoleRouter, 5)

	peerAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	info := &LinkAcceptInfo{
		ExtAddress:    peerAddr,
		RequestedTLVs: []uint8{TLVRoute64, TLVAddress16},
		RxChallenge:   Challenge{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		LinkMargin:    30,
	}

	router := &Router{
		Neighbor: Neighbor{
			MacAddr: peerAddr,
			RLOC16:  0x2800,
			State:   StateValid,
		},
	}

	var mask RouterIDSet
	mask.Add(5)
	mask.Add(10)

	routeProvider := &mockRouteDataProvider{
		sequence: 15,
		mask:     mask,
		entries: []Route64Entry{
			{Cost: 1},
			{LinkQualityOut: 3, LinkQualityIn: 2, Cost: 0},
		},
	}

	err := SendLinkAccept(m, d, keyMgr, info, router, routeProvider)
	if err != nil {
		t.Fatalf("SendLinkAccept: %v", err)
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("sent %d messages, want 1", len(transport.sentMessages))
	}

	// Verify route data provider was called.
	if len(routeProvider.calls) != 1 {
		t.Fatalf("route data provider called %d times, want 1", len(routeProvider.calls))
	}
	if routeProvider.calls[0].selfRouterID != 5 {
		t.Errorf("selfRouterID = %d, want 5", routeProvider.calls[0].selfRouterID)
	}
}

func TestSendLinkAccept_NilRouter(t *testing.T) {
	t.Parallel()

	m, d, transport, keyMgr := newLinkAcceptTestSetup(RoleRouter, 5)

	peerAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	info := &LinkAcceptInfo{
		ExtAddress:  peerAddr,
		RxChallenge: Challenge{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		LinkMargin:  25,
	}

	err := SendLinkAccept(m, d, keyMgr, info, nil, nil)
	if err != nil {
		t.Fatalf("SendLinkAccept: %v", err)
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("sent %d messages, want 1", len(transport.sentMessages))
	}

	// Destination should still use the info's ext address.
	expectedDst := linkLocalIPFromExtAddress(peerAddr)
	if transport.sentMessages[0].dst != expectedDst {
		t.Errorf("dst = %v, want %v", transport.sentMessages[0].dst, expectedDst)
	}
}

func TestSendLinkAccept_WrongRole_Detached(t *testing.T) {
	t.Parallel()

	m, d, _, keyMgr := newLinkAcceptTestSetup(RoleDetached, 5)
	m.mu.Lock()
	m.role = RoleDetached
	m.mu.Unlock()

	info := &LinkAcceptInfo{
		ExtAddress:  types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		RxChallenge: Challenge{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		LinkMargin:  20,
	}

	err := SendLinkAccept(m, d, keyMgr, info, nil, nil)
	if err == nil {
		t.Fatal("expected error for detached role")
	}
}

func TestSendLinkAccept_Leader(t *testing.T) {
	t.Parallel()

	m, d, transport, keyMgr := newLinkAcceptTestSetup(RoleLeader, 0)

	peerAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	info := &LinkAcceptInfo{
		ExtAddress:  peerAddr,
		RxChallenge: Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22},
		LinkMargin:  45,
	}

	router := &Router{
		Neighbor: Neighbor{
			MacAddr: peerAddr,
			RLOC16:  0x2800,
			State:   StateValid,
		},
	}

	err := SendLinkAccept(m, d, keyMgr, info, router, nil)
	if err != nil {
		t.Fatalf("SendLinkAccept: %v", err)
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("sent %d messages, want 1", len(transport.sentMessages))
	}
}

// --- containsTLVType tests ---

func TestContainsTLVType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		types  []uint8
		target uint8
		want   bool
	}{
		{"found", []uint8{TLVLinkMargin, TLVRoute64}, TLVRoute64, true},
		{"not found", []uint8{TLVLinkMargin}, TLVRoute64, false},
		{"empty", nil, TLVRoute64, false},
		{"single match", []uint8{TLVAddress16}, TLVAddress16, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := containsTLVType(tt.types, tt.target)
			if got != tt.want {
				t.Errorf("containsTLVType(%v, %d) = %v, want %v", tt.types, tt.target, got, tt.want)
			}
		})
	}
}
