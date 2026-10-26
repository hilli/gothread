// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"testing"

	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/key"
)

// newTestAttacher sets up a complete Attacher with mock dependencies.
func newTestAttacher() (*Attacher, *Dispatcher, *mockTransport, *mockKeyProvider) {
	d, transport, keyMgr := newTestDispatcher()
	attacher := NewAttacher(d.mle, d)
	return attacher, d, transport, keyMgr
}

func TestNewAttacher(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()
	if a == nil {
		t.Fatal("NewAttacher returned nil")
	}
	if a.hasCandidate {
		t.Error("new attacher should not have a candidate")
	}
}

func TestAttacherStart(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()

	err := a.Start(AttachAnyPartition)
	if err != nil {
		t.Fatalf("Start error: %v", err)
	}

	if a.mle.GetAttachState() != AttachStateStart {
		t.Errorf("attach state = %s, want Start", a.mle.GetAttachState())
	}

	if a.NextTimerDelay == 0 {
		t.Error("timer should be armed after Start")
	}

	// Challenge should be generated (non-zero).
	allZero := true
	for _, b := range a.challenge {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("challenge should be generated (non-zero)")
	}
}

func TestAttacherStart_AlreadyAttaching(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()

	_ = a.Start(AttachAnyPartition)
	err := a.Start(AttachAnyPartition)
	if err == nil {
		t.Error("second Start should fail when already attaching")
	}
}

func TestAttacherHandleTimer_Start(t *testing.T) {
	t.Parallel()

	a, _, transport, _ := newTestAttacher()
	_ = a.Start(AttachAnyPartition)

	// First timer fire transitions from Start to ParentRequest.
	err := a.HandleTimer()
	if err != nil {
		t.Fatalf("HandleTimer error: %v", err)
	}

	if a.mle.GetAttachState() != AttachStateParentRequest {
		t.Errorf("attach state = %s, want ParentRequest", a.mle.GetAttachState())
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
	}

	if a.NextTimerDelay == 0 {
		t.Error("timer should be armed for Parent Request timeout")
	}
}

func TestAttacherHandleTimer_ExhaustedNoCandidate(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()
	_ = a.Start(AttachAnyPartition)

	// Fire timer multiple times to exhaust all parent requests.
	var lastErr error
	for i := 0; i < 10; i++ {
		lastErr = a.HandleTimer()
		if a.mle.GetAttachState() == AttachStateIdle {
			break
		}
	}

	if lastErr == nil {
		t.Error("should get an error when attach fails")
	}

	if a.mle.GetAttachState() != AttachStateIdle {
		t.Errorf("attach state = %s, want Idle after exhaustion", a.mle.GetAttachState())
	}
}

func TestAttacherHandleTimer_ChildIDTimeout(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()
	_ = a.Start(AttachAnyPartition)

	// Simulate direct transition to ChildIDRequest state.
	a.mle.SetAttachState(AttachStateChildIDRequest)

	err := a.HandleTimer()
	if err == nil {
		t.Error("should get error on Child ID Response timeout")
	}

	if a.mle.GetAttachState() != AttachStateIdle {
		t.Errorf("attach state = %s, want Idle after timeout", a.mle.GetAttachState())
	}
}

func TestAttacherHandleTimer_AnnounceState(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()
	_ = a.Start(AttachAnyPartition)

	// Simulate transition to Announce state (as if processAnnounce set it).
	a.mle.SetAttachState(AttachStateAnnounce)

	err := a.HandleTimer()
	if err != nil {
		t.Fatalf("HandleTimer returned error: %v", err)
	}

	// After processing Announce, the attacher should begin a fresh attach
	// (state transitions through Start → ParentRequest).
	state := a.mle.GetAttachState()
	if state == AttachStateAnnounce || state == AttachStateIdle {
		t.Errorf("attach state = %s, want transition away from Announce/Idle", state)
	}
}

// buildParentResponseTLVs creates TLV bytes for a Parent Response.
func buildParentResponseTLVs(
	challenge Challenge,
	sourceRLOC16 uint16,
	version uint16,
	leaderData LeaderData,
	linkMargin uint8,
	connectivity ConnectivityTLV,
	linkFrameCounter uint32,
	parentChallenge Challenge,
) []TLV {
	var tlvs []TLV

	// SourceAddress
	var srcVal [2]byte
	encoding.BigEndianWriteUint16(sourceRLOC16, srcVal[:])
	tlvs = append(tlvs, TLV{Type: TLVSourceAddress, Value: srcVal[:]})

	// Version
	var verVal [2]byte
	encoding.BigEndianWriteUint16(version, verVal[:])
	tlvs = append(tlvs,
		TLV{Type: TLVVersion, Value: verVal[:]},
		// Response (echo our challenge)
		TLV{Type: TLVResponse, Value: challenge[:]},
	)

	// LeaderData
	var ldVal [LeaderDataTLVSize]byte
	encoding.BigEndianWriteUint32(leaderData.PartitionID, ldVal[0:4])
	ldVal[4] = leaderData.Weighting
	ldVal[5] = leaderData.DataVersion
	ldVal[6] = leaderData.StableDataVersion
	ldVal[7] = leaderData.LeaderRouterID
	tlvs = append(tlvs,
		TLV{Type: TLVLeaderData, Value: ldVal[:]},
		// LinkMargin
		TLV{Type: TLVLinkMargin, Value: []byte{linkMargin}},
	)

	// Connectivity
	connVal := make([]byte, ConnectivityTLVMinSize)
	connVal[0] = connectivity.Flags
	connVal[1] = connectivity.LinkQuality3
	connVal[2] = connectivity.LinkQuality2
	connVal[3] = connectivity.LinkQuality1
	connVal[4] = connectivity.LeaderCost
	connVal[5] = connectivity.IDSequence
	connVal[6] = connectivity.ActiveRouters
	tlvs = append(tlvs, TLV{Type: TLVConnectivity, Value: connVal})

	// LinkFrameCounter
	var fcVal [4]byte
	encoding.BigEndianWriteUint32(linkFrameCounter, fcVal[:])
	tlvs = append(tlvs,
		TLV{Type: TLVLinkFrameCounter, Value: fcVal[:]},
		// Challenge (parent's challenge)
		TLV{Type: TLVChallenge, Value: parentChallenge[:]},
	)

	return tlvs
}

func TestAttacherHandleParentResponse(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()
	_ = a.Start(AttachAnyPartition)
	_ = a.HandleTimer() // Transition to ParentRequest

	parentChallenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	routerRLOC := uint16(1 << RouterIDOffset)

	tlvs := buildParentResponseTLVs(
		a.challenge, routerRLOC, ThreadVersion,
		LeaderData{PartitionID: 1, Weighting: 64, LeaderRouterID: 1},
		25, // Good link margin
		ConnectivityTLV{LinkQuality3: 3, ActiveRouters: 5},
		100, parentChallenge,
	)

	rxInfo := &RxInfo{
		SrcAddr: types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11},
		SrcIP: ip6.Address{
			0xfe, 0x80, 0, 0, 0, 0, 0, 0,
			0xA8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		},
		LinkMarginRaw: 30,
		TLVs:          tlvs,
		IsSecured:     true,
		KeySequence:   1,
	}

	err := a.HandleParentResponse(rxInfo)
	if err != nil {
		t.Fatalf("HandleParentResponse error: %v", err)
	}

	if !a.hasCandidate {
		t.Error("should have a candidate after Parent Response")
	}

	if a.candidate.RLOC16 != routerRLOC {
		t.Errorf("candidate RLOC16 = %04X, want %04X", a.candidate.RLOC16, routerRLOC)
	}

	if a.candidate.RxChallenge != parentChallenge {
		t.Error("candidate RxChallenge not set correctly")
	}

	// Link margin should be min(30, 25) = 25.
	if a.candidate.LinkMargin != 25 {
		t.Errorf("candidate LinkMargin = %d, want 25", a.candidate.LinkMargin)
	}
}

func TestAttacherHandleParentResponse_ChallengeMismatch(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()
	_ = a.Start(AttachAnyPartition)
	_ = a.HandleTimer()

	wrongChallenge := Challenge{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	routerRLOC := uint16(1 << RouterIDOffset)

	tlvs := buildParentResponseTLVs(
		wrongChallenge, routerRLOC, ThreadVersion,
		LeaderData{}, 20, ConnectivityTLV{}, 100,
		Challenge{},
	)

	rxInfo := &RxInfo{
		SrcAddr:       types.ExtAddress{0xAA},
		LinkMarginRaw: 30,
		TLVs:          tlvs,
	}

	err := a.HandleParentResponse(rxInfo)
	if err == nil {
		t.Error("should reject parent response with wrong challenge")
	}
}

func TestAttacherHandleParentResponse_BetterCandidateReplaces(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()
	_ = a.Start(AttachAnyPartition)
	_ = a.HandleTimer()

	routerRLOC := uint16(1 << RouterIDOffset)
	parentChallenge := Challenge{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	// First: weak candidate.
	tlvs1 := buildParentResponseTLVs(
		a.challenge, routerRLOC, ThreadVersion,
		LeaderData{PartitionID: 1}, 5, // Low margin -> LQ1
		ConnectivityTLV{}, 100, parentChallenge,
	)
	rxInfo1 := &RxInfo{
		SrcAddr:       types.ExtAddress{0x01},
		LinkMarginRaw: 5,
		TLVs:          tlvs1,
		KeySequence:   1,
	}
	_ = a.HandleParentResponse(rxInfo1)

	// Second: strong candidate.
	parentChallenge2 := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	tlvs2 := buildParentResponseTLVs(
		a.challenge, routerRLOC+uint16(1<<RouterIDOffset), ThreadVersion,
		LeaderData{PartitionID: 1}, 25, // High margin -> LQ3
		ConnectivityTLV{LinkQuality3: 5}, 200, parentChallenge2,
	)
	rxInfo2 := &RxInfo{
		SrcAddr:       types.ExtAddress{0x02},
		LinkMarginRaw: 30,
		TLVs:          tlvs2,
		KeySequence:   1,
	}
	err := a.HandleParentResponse(rxInfo2)
	if err != nil {
		t.Fatalf("HandleParentResponse (better) error: %v", err)
	}

	if a.candidate.MacAddr != (types.ExtAddress{0x02}) {
		t.Error("better candidate should have replaced the weaker one")
	}
}

func TestAttacherHandleParentResponse_WorseCandidateIgnored(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()
	_ = a.Start(AttachAnyPartition)
	_ = a.HandleTimer()

	routerRLOC := uint16(1 << RouterIDOffset)
	parentChallenge := Challenge{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	// First: strong candidate.
	tlvs1 := buildParentResponseTLVs(
		a.challenge, routerRLOC, ThreadVersion,
		LeaderData{PartitionID: 1}, 25, // High margin
		ConnectivityTLV{LinkQuality3: 5}, 100, parentChallenge,
	)
	rxInfo1 := &RxInfo{
		SrcAddr:       types.ExtAddress{0x01},
		LinkMarginRaw: 30,
		TLVs:          tlvs1,
		KeySequence:   1,
	}
	_ = a.HandleParentResponse(rxInfo1)

	// Second: weak candidate.
	tlvs2 := buildParentResponseTLVs(
		a.challenge, routerRLOC, ThreadVersion,
		LeaderData{PartitionID: 1}, 3, // Low margin
		ConnectivityTLV{}, 200, Challenge{},
	)
	rxInfo2 := &RxInfo{
		SrcAddr:       types.ExtAddress{0x02},
		LinkMarginRaw: 3,
		TLVs:          tlvs2,
		KeySequence:   1,
	}
	_ = a.HandleParentResponse(rxInfo2)

	if a.candidate.MacAddr != (types.ExtAddress{0x01}) {
		t.Error("worse candidate should not replace the stronger one")
	}
}

func TestAttacherHandleParentResponse_WrongState(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()
	// Don't start attach — stays in Idle.

	rxInfo := &RxInfo{
		TLVs: []TLV{},
	}

	err := a.HandleParentResponse(rxInfo)
	if err == nil {
		t.Error("should reject parent response in wrong state")
	}
}

// buildChildIDResponseTLVs creates TLVs for a Child ID Response.
func buildChildIDResponseTLVs(
	sourceRLOC16 uint16,
	assignedRLOC16 uint16,
	leaderData LeaderData,
) []TLV {
	var tlvs []TLV

	// SourceAddress
	var srcVal [2]byte
	encoding.BigEndianWriteUint16(sourceRLOC16, srcVal[:])
	tlvs = append(tlvs, TLV{Type: TLVSourceAddress, Value: srcVal[:]})

	// Address16
	var addrVal [2]byte
	encoding.BigEndianWriteUint16(assignedRLOC16, addrVal[:])
	tlvs = append(tlvs, TLV{Type: TLVAddress16, Value: addrVal[:]})

	// LeaderData
	var ldVal [LeaderDataTLVSize]byte
	encoding.BigEndianWriteUint32(leaderData.PartitionID, ldVal[0:4])
	ldVal[4] = leaderData.Weighting
	ldVal[5] = leaderData.DataVersion
	ldVal[6] = leaderData.StableDataVersion
	ldVal[7] = leaderData.LeaderRouterID
	tlvs = append(tlvs,
		TLV{Type: TLVLeaderData, Value: ldVal[:]},
		// NetworkData (present but empty for testing)
		TLV{Type: TLVNetworkData, Value: []byte{}},
	)

	return tlvs
}

func TestAttacherFullFlow(t *testing.T) {
	t.Parallel()

	a, _, transport, _ := newTestAttacher()

	// Step 1: Start attach.
	if err := a.Start(AttachAnyPartition); err != nil {
		t.Fatalf("Start error: %v", err)
	}

	// Step 2: Timer fires -> sends ParentRequest.
	if err := a.HandleTimer(); err != nil {
		t.Fatalf("HandleTimer (start) error: %v", err)
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("expected 1 sent message after first timer, got %d", len(transport.sentMessages))
	}

	// Step 3: Receive Parent Response.
	routerRLOC := uint16(1 << RouterIDOffset)
	parentChallenge := Challenge{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	parentExtAddr := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}

	tlvs := buildParentResponseTLVs(
		a.challenge, routerRLOC, ThreadVersion,
		LeaderData{PartitionID: 42, Weighting: 64, LeaderRouterID: 1},
		25, ConnectivityTLV{LinkQuality3: 3, ActiveRouters: 5},
		100, parentChallenge,
	)

	rxInfo := &RxInfo{
		SrcAddr:       parentExtAddr,
		LinkMarginRaw: 30,
		TLVs:          tlvs,
		IsSecured:     true,
		KeySequence:   1,
	}

	if err := a.HandleParentResponse(rxInfo); err != nil {
		t.Fatalf("HandleParentResponse error: %v", err)
	}

	if !a.hasCandidate {
		t.Fatal("expected candidate after Parent Response")
	}

	// Step 4: Timer fires -> has acceptable candidate -> sends ChildIDRequest.
	prevSent := len(transport.sentMessages)
	if err := a.HandleTimer(); err != nil {
		t.Fatalf("HandleTimer (child ID) error: %v", err)
	}

	if a.mle.GetAttachState() != AttachStateChildIDRequest {
		t.Errorf("attach state = %s, want ChildIDRequest", a.mle.GetAttachState())
	}

	if len(transport.sentMessages) <= prevSent {
		t.Error("expected Child ID Request to be sent")
	}

	// Step 5: Receive Child ID Response.
	assignedRLOC := routerRLOC | 5 // Child ID = 5
	cidTLVs := buildChildIDResponseTLVs(
		routerRLOC, assignedRLOC,
		LeaderData{PartitionID: 42, Weighting: 64, LeaderRouterID: 1},
	)

	cidRxInfo := &RxInfo{
		SrcAddr:       parentExtAddr,
		LinkMarginRaw: 30,
		TLVs:          cidTLVs,
		IsSecured:     true,
		KeySequence:   1,
	}

	if err := a.HandleChildIDResponse(cidRxInfo); err != nil {
		t.Fatalf("HandleChildIDResponse error: %v", err)
	}

	// Verify final state.
	if !a.mle.IsChild() {
		t.Errorf("role = %s, want Child", a.mle.Role())
	}

	if a.mle.RLOC16() != assignedRLOC {
		t.Errorf("RLOC16 = %04X, want %04X", a.mle.RLOC16(), assignedRLOC)
	}

	// Parent should be set.
	parent := a.mle.GetParent()
	if parent.State != StateValid {
		t.Errorf("parent state = %s, want Valid", parent.State)
	}

	if parent.RLOC16 != routerRLOC {
		t.Errorf("parent RLOC16 = %04X, want %04X", parent.RLOC16, routerRLOC)
	}
}

func TestAttacherHandleChildIDResponse_WrongState(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()

	rxInfo := &RxInfo{TLVs: []TLV{}}
	err := a.HandleChildIDResponse(rxInfo)
	if err == nil {
		t.Error("should reject Child ID Response in wrong state")
	}
}

func TestAttacherHandleChildIDResponse_RouterIDMismatch(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()
	_ = a.Start(AttachAnyPartition)
	a.mle.SetAttachState(AttachStateChildIDRequest)
	a.hasCandidate = true

	// Source is router 1, but assigned address belongs to router 2.
	router1RLOC := uint16(1 << RouterIDOffset)
	router2RLOC := uint16(2<<RouterIDOffset) | 3

	cidTLVs := buildChildIDResponseTLVs(
		router1RLOC, router2RLOC,
		LeaderData{},
	)

	rxInfo := &RxInfo{TLVs: cidTLVs}
	err := a.HandleChildIDResponse(rxInfo)
	if err == nil {
		t.Error("should reject Child ID Response with router ID mismatch")
	}
}

func TestAttacherParentIP(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()
	a.candidate.MacAddr = types.ExtAddress{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}

	ip := a.parentIP()

	// Link-local prefix.
	if ip[0] != 0xfe || ip[1] != 0x80 {
		t.Errorf("parentIP prefix = %02X%02X, want FE80", ip[0], ip[1])
	}

	// U/L bit toggled: 0x02 ^ 0x02 = 0x00.
	if ip[8] != 0x00 {
		t.Errorf("parentIP IID[0] = %02X, want 00 (U/L toggled from 0x02)", ip[8])
	}

	// Last byte.
	if ip[15] != 0x01 {
		t.Errorf("parentIP IID[7] = %02X, want 01", ip[15])
	}
}

func TestAttacherVerifyResponse(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()
	a.challenge = Challenge{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Correct response.
	if !a.verifyResponse(a.challenge[:]) {
		t.Error("verifyResponse should accept matching challenge")
	}

	// Wrong response.
	wrong := []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8}
	if a.verifyResponse(wrong) {
		t.Error("verifyResponse should reject wrong challenge")
	}

	// Too short.
	if a.verifyResponse([]byte{0x01, 0x02}) {
		t.Error("verifyResponse should reject short response")
	}
}

func TestDetermineParentRequestType_SelectedParent(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()
	_ = a.Start(AttachSelectedParent)

	// First request.
	a.parentRequestCounter = 1
	reqType, ok := a.determineParentRequestType()
	if !ok {
		t.Fatal("should allow first request")
	}
	if reqType != parentRequestRouters {
		t.Errorf("reqType = %d, want parentRequestRouters", reqType)
	}

	// Second request should be exhausted.
	a.parentRequestCounter = 2
	_, ok = a.determineParentRequestType()
	if ok {
		t.Error("should exhaust after 1 request for SelectedParent")
	}
}

func TestDetermineParentRequestType_FirstCycle(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()
	_ = a.Start(AttachAnyPartition)

	// First request: routers only.
	a.parentRequestCounter = 1
	reqType, ok := a.determineParentRequestType()
	if !ok || reqType != parentRequestRouters {
		t.Errorf("first request: type=%d, ok=%v, want routers", reqType, ok)
	}

	// Second request: routers + REEDs.
	a.parentRequestCounter = 2
	reqType, ok = a.determineParentRequestType()
	if !ok || reqType != parentRequestRoutersAndREEDs {
		t.Errorf("second request: type=%d, ok=%v, want routers+REEDs", reqType, ok)
	}

	// Third request: routers + REEDs.
	a.parentRequestCounter = 3
	reqType, ok = a.determineParentRequestType()
	if !ok || reqType != parentRequestRoutersAndREEDs {
		t.Errorf("third request: type=%d, ok=%v, want routers+REEDs", reqType, ok)
	}

	// Fourth: exhausted.
	a.parentRequestCounter = 4
	_, ok = a.determineParentRequestType()
	if ok {
		t.Error("should exhaust after 3 requests in first cycle")
	}
}

func TestDetermineParentRequestType_SamePartition(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()
	_ = a.Start(AttachSamePartition)

	// SamePartition always includes REEDs.
	a.parentRequestCounter = 1
	reqType, ok := a.determineParentRequestType()
	if !ok || reqType != parentRequestRoutersAndREEDs {
		t.Errorf("SamePartition: type=%d, ok=%v, want routers+REEDs", reqType, ok)
	}
}

func TestGetCandidate(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()

	_, has := a.GetCandidate()
	if has {
		t.Error("should not have candidate initially")
	}

	a.hasCandidate = true
	_, has = a.GetCandidate()
	if !has {
		t.Error("should have candidate when set")
	}
}

// Verify that HandleTimer in Idle state does nothing harmful.
func TestAttacherHandleTimer_Idle(t *testing.T) {
	t.Parallel()

	a, _, _, _ := newTestAttacher()
	// Mle starts Detached, manually set to Idle attach state.

	err := a.HandleTimer()
	if err != nil {
		t.Errorf("HandleTimer in Idle should not error: %v", err)
	}
}

// Verify unused import guard - ensure key package is exercised.
func TestMockKeyProvider_ImplementsKeyProvider(t *testing.T) {
	t.Parallel()

	var _ KeyProvider = (*mockKeyProvider)(nil)
	// Also verify real Manager satisfies KeyProvider.
	var _ KeyProvider = (*key.Manager)(nil)
}
