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

// --- test setup ---

// newChildIDHandlerTestSetup creates a ChildIDHandler with a fully initialized
// Mle (router state) and Dispatcher mocks.
func newChildIDHandlerTestSetup(role DeviceRole, routerID uint8) (handler *ChildIDHandler, mleInstance *Mle, dispatcher *Dispatcher, sender *mockTransport, table *ChildTable) {
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
	childTable := NewChildTable()

	h := NewChildIDHandler(m, d, keyMgr, childTable, nil, nil, nil)
	return h, m, d, transport, childTable
}

// buildChildIDRequestRxInfo creates an RxInfo simulating a received Child ID
// Request with configurable TLVs. Pass nil for any TLV to omit it.
func buildChildIDRequestRxInfo(
	srcAddr types.ExtAddress,
	response []byte,
	version *uint16,
	linkFrameCounter *uint32,
	mleFrameCounter *uint32,
	mode *DeviceMode,
	timeout *uint32,
	tlvRequest []uint8,
) *RxInfo {
	var tlvs []TLV

	if response != nil {
		tlvs = append(tlvs, TLV{Type: TLVResponse, Value: response})
	}
	if version != nil {
		tlvs = append(tlvs, TLV{Type: TLVVersion, Value: makeVersionTLVValue(*version)})
	}
	if linkFrameCounter != nil {
		tlvs = append(tlvs, TLV{Type: TLVLinkFrameCounter, Value: makeLinkFrameCounterTLVValue(*linkFrameCounter)})
	}
	if mleFrameCounter != nil {
		tlvs = append(tlvs, TLV{Type: TLVMleFrameCounter, Value: makeMleFrameCounterTLVValue(*mleFrameCounter)})
	}
	if mode != nil {
		tlvs = append(tlvs, TLV{Type: TLVMode, Value: makeModeTLVValue(*mode)})
	}
	if timeout != nil {
		tlvs = append(tlvs, TLV{Type: TLVTimeout, Value: makeTimeoutTLVValue(*timeout)})
	}
	if len(tlvRequest) > 0 {
		tlvs = append(tlvs, TLV{Type: TLVTLVRequest, Value: tlvRequest})
	}

	srcIP := ip6.Address(linkLocalIPFromExtAddress(srcAddr))
	return &RxInfo{
		SrcAddr:       srcAddr,
		SrcIP:         srcIP,
		DstIP:         ip6.Address{0xfe, 0x80},
		LinkMarginRaw: 25,
		KeySequence:   5,
		FrameCounter:  100,
		Command:       CommandChildIDRequest,
		TLVs:          tlvs,
		IsSecured:     true,
	}
}

// challengeToResponse converts a Challenge to the []byte form expected by
// makeResponseTLVValue.
func challengeToResponse(ch Challenge) []byte {
	return makeResponseTLVValue(ch[:])
}

// --- NewChildIDHandler tests ---

func TestNewChildIDHandler_RegistersHandler(t *testing.T) {
	t.Parallel()

	h, _, d, _, _ := newChildIDHandlerTestSetup(RoleRouter, 2)

	if h == nil {
		t.Fatal("NewChildIDHandler returned nil")
	}

	if _, ok := d.handlers[CommandChildIDRequest]; !ok {
		t.Error("handler for CommandChildIDRequest not registered")
	}
}

// --- HandleChildIDRequest tests ---

func TestHandleChildIDRequest(t *testing.T) {
	t.Parallel()

	childAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	pendingChallenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)
	linkCounter := uint32(500)
	mleCounter := uint32(600)
	mode := NewDeviceMode(ModeRxOnWhenIdle | ModeFullThreadDevice)
	timeout := uint32(300)

	tests := []struct {
		name      string
		role      DeviceRole
		routerID  uint8
		setup     func(*ChildIDHandler, *Mle, *ChildTable)
		buildInfo func() *RxInfo
		wantErr   bool
		verify    func(*testing.T, *ChildIDHandler, *ChildTable, *mockTransport)
	}{
		{
			name:     "rejects when not router-eligible",
			role:     RoleChild,
			routerID: 1,
			buildInfo: func() *RxInfo {
				return buildChildIDRequestRxInfo(childAddr, challengeToResponse(pendingChallenge),
					&version, &linkCounter, &mleCounter, &mode, &timeout, nil)
			},
			wantErr: true,
		},
		{
			name:     "rejects when not attached",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *ChildIDHandler, m *Mle, _ *ChildTable) {
				m.mu.Lock()
				m.role = RoleDetached
				m.mu.Unlock()
			},
			buildInfo: func() *RxInfo {
				return buildChildIDRequestRxInfo(childAddr, challengeToResponse(pendingChallenge),
					&version, &linkCounter, &mleCounter, &mode, &timeout, nil)
			},
			wantErr: true,
		},
		{
			name:     "rejects missing Response TLV",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *ChildIDHandler, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateParentResponse
				c.PendingChallenge = pendingChallenge
			},
			buildInfo: func() *RxInfo {
				return buildChildIDRequestRxInfo(childAddr, nil,
					&version, &linkCounter, &mleCounter, &mode, &timeout, nil)
			},
			wantErr: true,
		},
		{
			name:     "rejects missing Version TLV",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *ChildIDHandler, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateParentResponse
				c.PendingChallenge = pendingChallenge
			},
			buildInfo: func() *RxInfo {
				return buildChildIDRequestRxInfo(childAddr, challengeToResponse(pendingChallenge),
					nil, &linkCounter, &mleCounter, &mode, &timeout, nil)
			},
			wantErr: true,
		},
		{
			name:     "rejects missing LinkFrameCounter TLV",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *ChildIDHandler, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateParentResponse
				c.PendingChallenge = pendingChallenge
			},
			buildInfo: func() *RxInfo {
				return buildChildIDRequestRxInfo(childAddr, challengeToResponse(pendingChallenge),
					&version, nil, &mleCounter, &mode, &timeout, nil)
			},
			wantErr: true,
		},
		{
			name:     "rejects missing Mode TLV",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *ChildIDHandler, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateParentResponse
				c.PendingChallenge = pendingChallenge
			},
			buildInfo: func() *RxInfo {
				return buildChildIDRequestRxInfo(childAddr, challengeToResponse(pendingChallenge),
					&version, &linkCounter, &mleCounter, nil, &timeout, nil)
			},
			wantErr: true,
		},
		{
			name:     "rejects missing Timeout TLV",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *ChildIDHandler, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateParentResponse
				c.PendingChallenge = pendingChallenge
			},
			buildInfo: func() *RxInfo {
				return buildChildIDRequestRxInfo(childAddr, challengeToResponse(pendingChallenge),
					&version, &linkCounter, &mleCounter, &mode, nil, nil)
			},
			wantErr: true,
		},
		{
			name:     "rejects unknown child (not in table)",
			role:     RoleRouter,
			routerID: 2,
			// No setup — child table is empty.
			buildInfo: func() *RxInfo {
				return buildChildIDRequestRxInfo(childAddr, challengeToResponse(pendingChallenge),
					&version, &linkCounter, &mleCounter, &mode, &timeout, nil)
			},
			wantErr: true,
		},
		{
			name:     "rejects response mismatch",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *ChildIDHandler, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateParentResponse
				c.PendingChallenge = pendingChallenge
			},
			buildInfo: func() *RxInfo {
				wrongChallenge := Challenge{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8}
				return buildChildIDRequestRxInfo(childAddr, challengeToResponse(wrongChallenge),
					&version, &linkCounter, &mleCounter, &mode, &timeout, nil)
			},
			wantErr: true,
		},
		{
			name:     "successful handling as router",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *ChildIDHandler, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateParentResponse
				c.PendingChallenge = pendingChallenge
			},
			buildInfo: func() *RxInfo {
				return buildChildIDRequestRxInfo(childAddr, challengeToResponse(pendingChallenge),
					&version, &linkCounter, &mleCounter, &mode, &timeout, nil)
			},
			wantErr: false,
			verify: func(t *testing.T, _ *ChildIDHandler, ct *ChildTable, transport *mockTransport) {
				t.Helper()
				child := ct.FindChild(childAddr)
				if child == nil {
					t.Fatal("child should still be in table")
				}
				// State should be StateValid after SendChildIDResponse.
				if child.State != StateValid {
					t.Errorf("child state = %v, want StateValid", child.State)
				}
				// Frame counters should be set.
				if child.Counters.LinkFrameCounter != linkCounter {
					t.Errorf("link frame counter = %d, want %d", child.Counters.LinkFrameCounter, linkCounter)
				}
				if child.Counters.MleFrameCounter != mleCounter {
					t.Errorf("mle frame counter = %d, want %d", child.Counters.MleFrameCounter, mleCounter)
				}
				// Mode, timeout, version should be updated.
				if child.Mode != mode {
					t.Errorf("mode = %v, want %v", child.Mode, mode)
				}
				if child.Timeout != timeout {
					t.Errorf("timeout = %d, want %d", child.Timeout, timeout)
				}
				if child.Version != version {
					t.Errorf("version = %d, want %d", child.Version, version)
				}
				// RLOC16 should be allocated with correct router ID.
				routerRLOC16 := RLOC16FromRouterID(2)
				if !RouterIDMatch(child.RLOC16, routerRLOC16) {
					t.Errorf("child RLOC16 = 0x%04X, does not match router base 0x%04X",
						child.RLOC16, routerRLOC16)
				}
				if ChildIDFromRLOC16(child.RLOC16) < MinChildID {
					t.Errorf("child ID from RLOC16 = %d, want >= %d",
						ChildIDFromRLOC16(child.RLOC16), MinChildID)
				}
				// A response message should have been sent.
				if len(transport.sentMessages) < 1 {
					t.Fatal("no response message sent")
				}
				expectedDst := ip6.Address(linkLocalIPFromExtAddress(childAddr))
				if transport.sentMessages[0].dst != expectedDst {
					t.Errorf("response dst = %v, want %v", transport.sentMessages[0].dst, expectedDst)
				}
			},
		},
		{
			name:     "successful handling as leader",
			role:     RoleLeader,
			routerID: 5,
			setup: func(_ *ChildIDHandler, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateParentResponse
				c.PendingChallenge = pendingChallenge
			},
			buildInfo: func() *RxInfo {
				return buildChildIDRequestRxInfo(childAddr, challengeToResponse(pendingChallenge),
					&version, &linkCounter, &mleCounter, &mode, &timeout, nil)
			},
			wantErr: false,
			verify: func(t *testing.T, _ *ChildIDHandler, ct *ChildTable, transport *mockTransport) {
				t.Helper()
				child := ct.FindChild(childAddr)
				if child == nil {
					t.Fatal("child should still be in table")
				}
				if child.State != StateValid {
					t.Errorf("child state = %v, want StateValid", child.State)
				}
				routerRLOC16 := RLOC16FromRouterID(5)
				if !RouterIDMatch(child.RLOC16, routerRLOC16) {
					t.Errorf("child RLOC16 = 0x%04X, does not match router base 0x%04X",
						child.RLOC16, routerRLOC16)
				}
				if len(transport.sentMessages) < 1 {
					t.Fatal("no response message sent")
				}
			},
		},
		{
			name:     "MleFrameCounter defaults to LinkFrameCounter when absent",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *ChildIDHandler, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateParentResponse
				c.PendingChallenge = pendingChallenge
			},
			buildInfo: func() *RxInfo {
				// No MLE frame counter — should default to linkCounter.
				return buildChildIDRequestRxInfo(childAddr, challengeToResponse(pendingChallenge),
					&version, &linkCounter, nil, &mode, &timeout, nil)
			},
			wantErr: false,
			verify: func(t *testing.T, _ *ChildIDHandler, ct *ChildTable, _ *mockTransport) {
				t.Helper()
				child := ct.FindChild(childAddr)
				if child == nil {
					t.Fatal("child should still be in table")
				}
				if child.Counters.LinkFrameCounter != linkCounter {
					t.Errorf("link frame counter = %d, want %d", child.Counters.LinkFrameCounter, linkCounter)
				}
				if child.Counters.MleFrameCounter != linkCounter {
					t.Errorf("mle frame counter = %d, want %d (should default to link counter)",
						child.Counters.MleFrameCounter, linkCounter)
				}
			},
		},
		{
			name:     "TLV request types are stored on child",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *ChildIDHandler, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateParentResponse
				c.PendingChallenge = pendingChallenge
			},
			buildInfo: func() *RxInfo {
				return buildChildIDRequestRxInfo(childAddr, challengeToResponse(pendingChallenge),
					&version, &linkCounter, &mleCounter, &mode, &timeout,
					[]uint8{TLVNetworkData, TLVSupervisionInterval})
			},
			wantErr: false,
			verify: func(t *testing.T, _ *ChildIDHandler, ct *ChildTable, _ *mockTransport) {
				t.Helper()
				child := ct.FindChild(childAddr)
				if child == nil {
					t.Fatal("child should still be in table")
				}
				requestTLVs := child.GetRequestTLVs()
				if len(requestTLVs) != 2 {
					t.Fatalf("request TLV count = %d, want 2", len(requestTLVs))
				}
				if requestTLVs[0] != TLVNetworkData {
					t.Errorf("request TLV[0] = %d, want TLVNetworkData (%d)", requestTLVs[0], TLVNetworkData)
				}
				if requestTLVs[1] != TLVSupervisionInterval {
					t.Errorf("request TLV[1] = %d, want TLVSupervisionInterval (%d)", requestTLVs[1], TLVSupervisionInterval)
				}
			},
		},
		{
			name:     "key sequence updated on child",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *ChildIDHandler, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateParentResponse
				c.PendingChallenge = pendingChallenge
			},
			buildInfo: func() *RxInfo {
				rxInfo := buildChildIDRequestRxInfo(childAddr, challengeToResponse(pendingChallenge),
					&version, &linkCounter, &mleCounter, &mode, &timeout, nil)
				rxInfo.KeySequence = 42
				return rxInfo
			},
			wantErr: false,
			verify: func(t *testing.T, _ *ChildIDHandler, ct *ChildTable, _ *mockTransport) {
				t.Helper()
				child := ct.FindChild(childAddr)
				if child == nil {
					t.Fatal("child should still be in table")
				}
				if child.KeySequence != 42 {
					t.Errorf("key sequence = %d, want 42", child.KeySequence)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h, m, _, transport, ct := newChildIDHandlerTestSetup(tt.role, tt.routerID)

			if tt.setup != nil {
				tt.setup(h, m, ct)
			}

			rxInfo := tt.buildInfo()
			err := h.HandleChildIDRequest(rxInfo)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.verify != nil {
				tt.verify(t, h, ct, transport)
			}
		})
	}
}

// --- RLOC16 allocation tests ---

func TestHandleChildIDRequest_RLOC16Allocation(t *testing.T) {
	t.Parallel()

	routerID := uint8(3)
	routerRLOC16 := RLOC16FromRouterID(routerID)

	version := uint16(ThreadVersion)
	linkCounter := uint32(100)
	mode := NewDeviceMode(ModeRxOnWhenIdle | ModeFullThreadDevice)
	timeout := uint32(240)

	h, _, _, _, ct := newChildIDHandlerTestSetup(RoleRouter, routerID)

	// Attach two children sequentially and verify they get different RLOC16s.
	child1Addr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x01}
	child2Addr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x02}

	challenge1 := Challenge{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	challenge2 := Challenge{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}

	// Add child 1.
	c1 := ct.GetNewChild()
	c1.MacAddr = child1Addr
	c1.State = StateParentResponse
	c1.PendingChallenge = challenge1

	rxInfo1 := buildChildIDRequestRxInfo(child1Addr, challengeToResponse(challenge1),
		&version, &linkCounter, nil, &mode, &timeout, nil)
	if err := h.HandleChildIDRequest(rxInfo1); err != nil {
		t.Fatalf("child 1: %v", err)
	}

	// Add child 2.
	c2 := ct.GetNewChild()
	c2.MacAddr = child2Addr
	c2.State = StateParentResponse
	c2.PendingChallenge = challenge2

	rxInfo2 := buildChildIDRequestRxInfo(child2Addr, challengeToResponse(challenge2),
		&version, &linkCounter, nil, &mode, &timeout, nil)
	if err := h.HandleChildIDRequest(rxInfo2); err != nil {
		t.Fatalf("child 2: %v", err)
	}

	// Both should be valid.
	child1 := ct.FindChild(child1Addr)
	child2 := ct.FindChild(child2Addr)

	if child1 == nil || child2 == nil {
		t.Fatal("both children should be in the table")
	}

	// Both should share the same router ID.
	if !RouterIDMatch(child1.RLOC16, routerRLOC16) {
		t.Errorf("child1 RLOC16 = 0x%04X, does not match router base", child1.RLOC16)
	}
	if !RouterIDMatch(child2.RLOC16, routerRLOC16) {
		t.Errorf("child2 RLOC16 = 0x%04X, does not match router base", child2.RLOC16)
	}

	// But they should have different child IDs.
	if child1.RLOC16 == child2.RLOC16 {
		t.Errorf("children have same RLOC16: 0x%04X", child1.RLOC16)
	}
}

// --- Response TLV too short ---

func TestHandleChildIDRequest_ResponseTLVTooShort(t *testing.T) {
	t.Parallel()

	childAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	pendingChallenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)
	linkCounter := uint32(500)
	mode := NewDeviceMode(ModeRxOnWhenIdle | ModeFullThreadDevice)
	timeout := uint32(300)

	h, _, _, _, ct := newChildIDHandlerTestSetup(RoleRouter, 2)

	c := ct.GetNewChild()
	c.MacAddr = childAddr
	c.State = StateParentResponse
	c.PendingChallenge = pendingChallenge

	// Build RxInfo with a too-short response (only 4 bytes instead of ChallengeSize).
	shortResponse := pendingChallenge[:4]
	rxInfo := buildChildIDRequestRxInfo(childAddr, shortResponse,
		&version, &linkCounter, nil, &mode, &timeout, nil)

	err := h.HandleChildIDRequest(rxInfo)
	if err == nil {
		t.Fatal("expected error for too-short Response TLV, got nil")
	}
}

// --- SendChildIDResponse tests ---

func TestSendChildIDResponse_AllocatesRLOC16(t *testing.T) {
	t.Parallel()

	h, _, _, transport, ct := newChildIDHandlerTestSetup(RoleRouter, 2)

	childAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	c := ct.GetNewChild()
	c.MacAddr = childAddr
	c.State = StateChildIDRequest
	c.RLOC16 = 0 // No RLOC16 assigned yet.

	err := h.SendChildIDResponse(c)
	if err != nil {
		t.Fatalf("SendChildIDResponse: %v", err)
	}

	routerRLOC16 := RLOC16FromRouterID(2)
	if !RouterIDMatch(c.RLOC16, routerRLOC16) {
		t.Errorf("child RLOC16 = 0x%04X, does not match router base 0x%04X", c.RLOC16, routerRLOC16)
	}

	if c.State != StateValid {
		t.Errorf("child state = %v, want StateValid", c.State)
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
	}

	expectedDst := ip6.Address(linkLocalIPFromExtAddress(childAddr))
	if transport.sentMessages[0].dst != expectedDst {
		t.Errorf("response dst = %v, want %v", transport.sentMessages[0].dst, expectedDst)
	}
}

func TestSendChildIDResponse_PreservesExistingMatchingRLOC16(t *testing.T) {
	t.Parallel()

	routerID := uint8(2)
	h, _, _, _, ct := newChildIDHandlerTestSetup(RoleRouter, routerID)

	childAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	c := ct.GetNewChild()
	c.MacAddr = childAddr
	c.State = StateChildIDRequest

	// Pre-assign an RLOC16 that matches the router.
	existingRLOC16 := RLOC16FromRouterID(routerID) | 0x0005
	c.RLOC16 = existingRLOC16

	err := h.SendChildIDResponse(c)
	if err != nil {
		t.Fatalf("SendChildIDResponse: %v", err)
	}

	// RLOC16 should be preserved (not re-allocated).
	if c.RLOC16 != existingRLOC16 {
		t.Errorf("child RLOC16 = 0x%04X, want preserved 0x%04X", c.RLOC16, existingRLOC16)
	}
}

func TestSendChildIDResponse_ReallocatesWhenRouterIDMismatch(t *testing.T) {
	t.Parallel()

	h, _, _, _, ct := newChildIDHandlerTestSetup(RoleRouter, 2)

	childAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	c := ct.GetNewChild()
	c.MacAddr = childAddr
	c.State = StateChildIDRequest

	// Pre-assign an RLOC16 with a different router ID.
	c.RLOC16 = RLOC16FromRouterID(5) | 0x0003

	err := h.SendChildIDResponse(c)
	if err != nil {
		t.Fatalf("SendChildIDResponse: %v", err)
	}

	// RLOC16 should be re-allocated to match router ID 2.
	routerRLOC16 := RLOC16FromRouterID(2)
	if !RouterIDMatch(c.RLOC16, routerRLOC16) {
		t.Errorf("child RLOC16 = 0x%04X, should match router base 0x%04X", c.RLOC16, routerRLOC16)
	}
}

// --- AllocateChildRLOC16 tests ---

func TestAllocateChildRLOC16_Basic(t *testing.T) {
	t.Parallel()

	ct := NewChildTable()
	routerRLOC16 := RLOC16FromRouterID(1)

	rloc16, ok := ct.AllocateChildRLOC16(routerRLOC16)
	if !ok {
		t.Fatal("AllocateChildRLOC16 returned false for empty table")
	}

	expectedBase := routerRLOC16 & ^uint16(MaxChildID)
	if rloc16&^uint16(MaxChildID) != expectedBase {
		t.Errorf("RLOC16 base = 0x%04X, want 0x%04X", rloc16&^uint16(MaxChildID), expectedBase)
	}

	childID := ChildIDFromRLOC16(rloc16)
	if childID < MinChildID || childID > MaxChildID {
		t.Errorf("child ID = %d, want [%d, %d]", childID, MinChildID, MaxChildID)
	}
}

func TestAllocateChildRLOC16_SkipsUsed(t *testing.T) {
	t.Parallel()

	ct := NewChildTable()
	routerRLOC16 := RLOC16FromRouterID(1)
	routerBase := routerRLOC16 & ^uint16(MaxChildID)

	// Occupy child ID 1.
	c := ct.GetNewChild()
	c.State = StateValid
	c.RLOC16 = routerBase | MinChildID

	rloc16, ok := ct.AllocateChildRLOC16(routerRLOC16)
	if !ok {
		t.Fatal("AllocateChildRLOC16 returned false")
	}

	// Should have skipped ID 1 and returned ID 2.
	if ChildIDFromRLOC16(rloc16) != MinChildID+1 {
		t.Errorf("child ID = %d, want %d", ChildIDFromRLOC16(rloc16), MinChildID+1)
	}
}

// --- Attaching state rejection ---

func TestHandleChildIDRequest_RejectsWhenAttaching(t *testing.T) {
	t.Parallel()

	childAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	pendingChallenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)
	linkCounter := uint32(500)
	mode := NewDeviceMode(ModeRxOnWhenIdle | ModeFullThreadDevice)
	timeout := uint32(300)

	h, m, _, _, ct := newChildIDHandlerTestSetup(RoleRouter, 2)

	// Put MLE into attaching state.
	m.mu.Lock()
	m.attachState = AttachStateAnnounce
	m.mu.Unlock()

	c := ct.GetNewChild()
	c.MacAddr = childAddr
	c.State = StateParentResponse
	c.PendingChallenge = pendingChallenge

	rxInfo := buildChildIDRequestRxInfo(childAddr, challengeToResponse(pendingChallenge),
		&version, &linkCounter, nil, &mode, &timeout, nil)

	err := h.HandleChildIDRequest(rxInfo)
	if err == nil {
		t.Fatal("expected error when attaching, got nil")
	}
}
