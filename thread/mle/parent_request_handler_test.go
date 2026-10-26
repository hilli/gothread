// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"testing"
	"time"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/key"
)

// --- mock ConnectivityProvider ---

type mockConnectivityProvider struct {
	connectivity ConnectivityTLV
}

func (m *mockConnectivityProvider) GetConnectivityTLV() ConnectivityTLV {
	return m.connectivity
}

// --- test setup ---

func newParentRequestHandlerTestSetup(role DeviceRole, routerID uint8) (handler *ParentRequestHandler, mleInstance *Mle, dispatcher *Dispatcher, sender *mockTransport, table *ChildTable) {
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

	connectivity := &mockConnectivityProvider{
		connectivity: ConnectivityTLV{
			Flags:            1,
			LinkQuality3:     2,
			LinkQuality2:     3,
			LinkQuality1:     4,
			LeaderCost:       5,
			IDSequence:       6,
			ActiveRouters:    7,
			SEDBufferSize:    512,
			SEDDatagramCount: 10,
		},
	}

	h := NewParentRequestHandler(m, d, keyMgr, childTable, connectivity)
	return h, m, d, transport, childTable
}

// buildParentRequestRxInfo creates an RxInfo simulating a received Parent Request.
func buildParentRequestRxInfo(
	srcAddr types.ExtAddress,
	challenge *Challenge,
	version *uint16,
	scanMask *uint8,
) *RxInfo {
	var tlvs []TLV

	if version != nil {
		tlvs = append(tlvs, TLV{Type: TLVVersion, Value: makeVersionTLVValue(*version)})
	}
	if scanMask != nil {
		tlvs = append(tlvs, TLV{Type: TLVScanMask, Value: []byte{*scanMask}})
	}
	if challenge != nil {
		tlvs = append(tlvs, TLV{Type: TLVChallenge, Value: challenge[:]})
	}

	srcIP := ip6.Address(linkLocalIPFromExtAddress(srcAddr))
	return &RxInfo{
		SrcAddr:       srcAddr,
		SrcIP:         srcIP,
		DstIP:         ip6.Address{0xfe, 0x80},
		LinkMarginRaw: 25,
		KeySequence:   5,
		FrameCounter:  100,
		Command:       CommandParentRequest,
		TLVs:          tlvs,
		IsSecured:     true,
	}
}

// --- NewParentRequestHandler tests ---

func TestNewParentRequestHandler_RegistersHandler(t *testing.T) {
	t.Parallel()

	h, _, d, _, _ := newParentRequestHandlerTestSetup(RoleRouter, 2)

	if h == nil {
		t.Fatal("NewParentRequestHandler returned nil")
	}

	if _, ok := d.handlers[CommandParentRequest]; !ok {
		t.Error("handler for CommandParentRequest not registered")
	}
}

// --- HandleParentRequest tests ---

func TestHandleParentRequest(t *testing.T) {
	t.Parallel()

	childAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)
	scanMaskRouters := uint8(ScanMaskRouterFlag)
	scanMaskAll := uint8(ScanMaskRouterFlag | ScanMaskEndDeviceFlag)
	scanMaskEndDeviceOnly := uint8(ScanMaskEndDeviceFlag)

	tests := []struct {
		name      string
		role      DeviceRole
		routerID  uint8
		setup     func(*ParentRequestHandler, *Mle)
		buildInfo func() *RxInfo
		wantErr   bool
		verify    func(*testing.T, *ParentRequestHandler, *ChildTable, *mockTransport)
	}{
		{
			name:     "rejects when role is child",
			role:     RoleChild,
			routerID: 1,
			buildInfo: func() *RxInfo {
				return buildParentRequestRxInfo(childAddr, &challenge, &version, &scanMaskRouters)
			},
			wantErr: true,
		},
		{
			name:     "rejects when role is detached",
			role:     RoleDetached,
			routerID: 1,
			buildInfo: func() *RxInfo {
				return buildParentRequestRxInfo(childAddr, &challenge, &version, &scanMaskRouters)
			},
			wantErr: true,
		},
		{
			name:     "rejects when attaching",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *ParentRequestHandler, m *Mle) {
				m.mu.Lock()
				m.attachState = AttachStateAnnounce
				m.mu.Unlock()
			},
			buildInfo: func() *RxInfo {
				return buildParentRequestRxInfo(childAddr, &challenge, &version, &scanMaskRouters)
			},
			wantErr: true,
		},
		{
			name:     "rejects missing Version TLV",
			role:     RoleRouter,
			routerID: 2,
			buildInfo: func() *RxInfo {
				return buildParentRequestRxInfo(childAddr, &challenge, nil, &scanMaskRouters)
			},
			wantErr: true,
		},
		{
			name:     "rejects missing ScanMask TLV",
			role:     RoleRouter,
			routerID: 2,
			buildInfo: func() *RxInfo {
				return buildParentRequestRxInfo(childAddr, &challenge, &version, nil)
			},
			wantErr: true,
		},
		{
			name:     "rejects missing Challenge TLV",
			role:     RoleRouter,
			routerID: 2,
			buildInfo: func() *RxInfo {
				return buildParentRequestRxInfo(childAddr, nil, &version, &scanMaskRouters)
			},
			wantErr: true,
		},
		{
			name:     "rejects scan mask without router flag",
			role:     RoleRouter,
			routerID: 2,
			buildInfo: func() *RxInfo {
				return buildParentRequestRxInfo(childAddr, &challenge, &version, &scanMaskEndDeviceOnly)
			},
			wantErr: true,
		},
		{
			name:     "accepts valid parent request from router role",
			role:     RoleRouter,
			routerID: 2,
			buildInfo: func() *RxInfo {
				return buildParentRequestRxInfo(childAddr, &challenge, &version, &scanMaskRouters)
			},
			wantErr: false,
			verify: func(t *testing.T, h *ParentRequestHandler, ct *ChildTable, _ *mockTransport) {
				t.Helper()
				child := ct.FindChild(childAddr)
				if child == nil {
					t.Fatal("child not added to table")
				}
				if child.State != StateParentRequest {
					t.Errorf("child state = %v, want StateParentRequest", child.State)
				}
				if child.MacAddr != childAddr {
					t.Errorf("child MacAddr = %v, want %v", child.MacAddr, childAddr)
				}
				if child.Version != version {
					t.Errorf("child version = %d, want %d", child.Version, version)
				}
				if child.PendingChallenge != challenge {
					t.Error("child PendingChallenge not set correctly")
				}
				if h.PendingResponseCount() != 1 {
					t.Errorf("pending responses = %d, want 1", h.PendingResponseCount())
				}
			},
		},
		{
			name:     "accepts valid parent request from leader role",
			role:     RoleLeader,
			routerID: 5,
			buildInfo: func() *RxInfo {
				return buildParentRequestRxInfo(childAddr, &challenge, &version, &scanMaskRouters)
			},
			wantErr: false,
			verify: func(t *testing.T, h *ParentRequestHandler, ct *ChildTable, _ *mockTransport) {
				t.Helper()
				if ct.GetChildCount() != 1 {
					t.Errorf("child count = %d, want 1", ct.GetChildCount())
				}
				if h.PendingResponseCount() != 1 {
					t.Errorf("pending responses = %d, want 1", h.PendingResponseCount())
				}
			},
		},
		{
			name:     "accepts scan mask with both router and end device flags",
			role:     RoleRouter,
			routerID: 2,
			buildInfo: func() *RxInfo {
				return buildParentRequestRxInfo(childAddr, &challenge, &version, &scanMaskAll)
			},
			wantErr: false,
			verify: func(t *testing.T, _ *ParentRequestHandler, ct *ChildTable, _ *mockTransport) {
				t.Helper()
				if ct.GetChildCount() != 1 {
					t.Errorf("child count = %d, want 1", ct.GetChildCount())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h, m, _, transport, ct := newParentRequestHandlerTestSetup(tt.role, tt.routerID)

			if tt.setup != nil {
				tt.setup(h, m)
			}

			rxInfo := tt.buildInfo()
			err := h.HandleParentRequest(rxInfo)

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

// --- Duplicate suppression test ---

func TestHandleParentRequest_DuplicateSuppression(t *testing.T) {
	t.Parallel()

	h, _, _, _, ct := newParentRequestHandlerTestSetup(RoleRouter, 2)

	childAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)
	scanMask := uint8(ScanMaskRouterFlag)

	// First request succeeds and allocates a child.
	rxInfo := buildParentRequestRxInfo(childAddr, &challenge, &version, &scanMask)
	err := h.HandleParentRequest(rxInfo)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}

	if ct.GetChildCount() != 1 {
		t.Fatalf("child count after first request = %d, want 1", ct.GetChildCount())
	}
	if h.PendingResponseCount() != 1 {
		t.Fatalf("pending responses after first = %d, want 1", h.PendingResponseCount())
	}

	// Second immediate request should be suppressed (returns nil, no new pending).
	rxInfo2 := buildParentRequestRxInfo(childAddr, &challenge, &version, &scanMask)
	err = h.HandleParentRequest(rxInfo2)
	if err != nil {
		t.Fatalf("duplicate request should return nil, got: %v", err)
	}

	// Still only 1 pending response.
	if h.PendingResponseCount() != 1 {
		t.Errorf("pending responses after duplicate = %d, want 1", h.PendingResponseCount())
	}
}

// --- Duplicate suppression timeout expiry test ---

func TestHandleParentRequest_DuplicateAfterTimeout(t *testing.T) {
	t.Parallel()

	h, _, _, _, ct := newParentRequestHandlerTestSetup(RoleRouter, 2)

	childAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)
	scanMask := uint8(ScanMaskRouterFlag)

	// First request.
	rxInfo := buildParentRequestRxInfo(childAddr, &challenge, &version, &scanMask)
	err := h.HandleParentRequest(rxInfo)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}

	// Simulate time passing beyond the duplicate timeout by backdating LastHeard.
	child := ct.FindChild(childAddr)
	if child == nil {
		t.Fatal("child not found after first request")
	}
	child.LastHeard = time.Now().Add(-ParentRequestDuplicateTimeout - time.Millisecond)

	// Second request should now be processed.
	rxInfo2 := buildParentRequestRxInfo(childAddr, &challenge, &version, &scanMask)
	err = h.HandleParentRequest(rxInfo2)
	if err != nil {
		t.Fatalf("request after timeout: %v", err)
	}

	// Should now have 2 pending responses (one from each accepted request).
	if h.PendingResponseCount() != 2 {
		t.Errorf("pending responses = %d, want 2", h.PendingResponseCount())
	}
}

// --- Child table full test ---

func TestHandleParentRequest_TableFull(t *testing.T) {
	t.Parallel()

	h, _, _, _, ct := newParentRequestHandlerTestSetup(RoleRouter, 2)

	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)
	scanMask := uint8(ScanMaskRouterFlag)

	// Fill the child table.
	for i := 0; i < MaxChildren; i++ {
		c := ct.GetNewChild()
		c.State = StateValid
		c.MacAddr = types.ExtAddress{byte(i + 0x80)}
	}

	// New parent request should fail with table full.
	newChild := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	rxInfo := buildParentRequestRxInfo(newChild, &challenge, &version, &scanMask)
	err := h.HandleParentRequest(rxInfo)
	if err == nil {
		t.Fatal("expected error for full child table, got nil")
	}
}

// --- SendParentResponse tests ---

func TestSendParentResponse(t *testing.T) {
	t.Parallel()

	h, _, _, transport, ct := newParentRequestHandlerTestSetup(RoleRouter, 2)

	childAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	rxChallenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}

	// Add a child in StateParentRequest.
	c := ct.GetNewChild()
	c.MacAddr = childAddr
	c.State = StateParentRequest
	c.Version = ThreadVersion

	info := ParentResponseInfo{
		ChildExtAddress: childAddr,
		RxChallenge:     rxChallenge,
	}

	dstIP := ip6.Address(linkLocalIPFromExtAddress(childAddr))

	err := h.SendParentResponse(info, dstIP)
	if err != nil {
		t.Fatalf("SendParentResponse: %v", err)
	}

	if len(transport.sentMessages) < 1 {
		t.Fatal("no messages sent")
	}

	// Verify destination address.
	if transport.sentMessages[0].dst != dstIP {
		t.Errorf("dst = %v, want %v", transport.sentMessages[0].dst, dstIP)
	}

	// Verify that the child now has a PendingChallenge set (our challenge,
	// not the rx challenge).
	child := ct.FindChild(childAddr)
	if child == nil {
		t.Fatal("child not found after SendParentResponse")
	}
	if child.PendingChallenge == rxChallenge {
		t.Error("child PendingChallenge should have been replaced with new challenge")
	}
	// Challenge should not be all zeros (generated random).
	if child.PendingChallenge == (Challenge{}) {
		t.Error("child PendingChallenge should not be zero after SendParentResponse")
	}
}

func TestSendParentResponse_ChildNotFound(t *testing.T) {
	t.Parallel()

	h, _, _, _, _ := newParentRequestHandlerTestSetup(RoleRouter, 2)

	unknownAddr := types.ExtAddress{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8}
	info := ParentResponseInfo{
		ChildExtAddress: unknownAddr,
	}

	dstIP := ip6.Address(linkLocalIPFromExtAddress(unknownAddr))

	err := h.SendParentResponse(info, dstIP)
	if err == nil {
		t.Fatal("expected error for unknown child, got nil")
	}
}

// --- SendAllPendingResponses tests ---

func TestSendAllPendingResponses(t *testing.T) {
	t.Parallel()

	h, _, _, transport, ct := newParentRequestHandlerTestSetup(RoleRouter, 2)

	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)
	scanMask := uint8(ScanMaskRouterFlag)

	// Send a parent request to create a pending response.
	childAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	rxInfo := buildParentRequestRxInfo(childAddr, &challenge, &version, &scanMask)
	err := h.HandleParentRequest(rxInfo)
	if err != nil {
		t.Fatalf("HandleParentRequest: %v", err)
	}

	if h.PendingResponseCount() != 1 {
		t.Fatalf("pending responses = %d, want 1", h.PendingResponseCount())
	}

	// No messages sent yet (pending).
	if len(transport.sentMessages) != 0 {
		t.Fatalf("expected 0 sent messages, got %d", len(transport.sentMessages))
	}

	// Flush all pending responses immediately.
	sent, err := h.SendAllPendingResponses()
	if err != nil {
		t.Fatalf("SendAllPendingResponses: %v", err)
	}
	if sent != 1 {
		t.Errorf("sent = %d, want 1", sent)
	}

	if h.PendingResponseCount() != 0 {
		t.Errorf("pending after flush = %d, want 0", h.PendingResponseCount())
	}

	if len(transport.sentMessages) != 1 {
		t.Errorf("sent messages = %d, want 1", len(transport.sentMessages))
	}

	// Verify child is still in the table.
	child := ct.FindChild(childAddr)
	if child == nil {
		t.Fatal("child should still be in table after response")
	}
}

// --- FlushPendingResponses tests ---

func TestFlushPendingResponses_TimeBased(t *testing.T) {
	t.Parallel()

	h, _, _, transport, _ := newParentRequestHandlerTestSetup(RoleRouter, 2)

	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)
	scanMask := uint8(ScanMaskRouterFlag)

	childAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	rxInfo := buildParentRequestRxInfo(childAddr, &challenge, &version, &scanMask)
	err := h.HandleParentRequest(rxInfo)
	if err != nil {
		t.Fatalf("HandleParentRequest: %v", err)
	}

	// The response has a random delay. Backdate the pending response to make
	// it ready for sending.
	if len(h.pendingResponses) > 0 {
		h.pendingResponses[0].sendAt = time.Now().Add(-time.Millisecond)
	}

	sent, err := h.FlushPendingResponses()
	if err != nil {
		t.Fatalf("FlushPendingResponses: %v", err)
	}
	if sent != 1 {
		t.Errorf("sent = %d, want 1", sent)
	}
	if len(transport.sentMessages) != 1 {
		t.Errorf("sent messages = %d, want 1", len(transport.sentMessages))
	}
	if h.PendingResponseCount() != 0 {
		t.Errorf("remaining pending = %d, want 0", h.PendingResponseCount())
	}
}

func TestFlushPendingResponses_NotReady(t *testing.T) {
	t.Parallel()

	h, _, _, transport, _ := newParentRequestHandlerTestSetup(RoleRouter, 2)

	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)
	scanMask := uint8(ScanMaskRouterFlag)

	childAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	rxInfo := buildParentRequestRxInfo(childAddr, &challenge, &version, &scanMask)
	err := h.HandleParentRequest(rxInfo)
	if err != nil {
		t.Fatalf("HandleParentRequest: %v", err)
	}

	// Set the pending response far in the future.
	if len(h.pendingResponses) > 0 {
		h.pendingResponses[0].sendAt = time.Now().Add(10 * time.Second)
	}

	sent, err := h.FlushPendingResponses()
	if err != nil {
		t.Fatalf("FlushPendingResponses: %v", err)
	}
	if sent != 0 {
		t.Errorf("sent = %d, want 0 (not ready yet)", sent)
	}
	if len(transport.sentMessages) != 0 {
		t.Errorf("sent messages = %d, want 0", len(transport.sentMessages))
	}
	if h.PendingResponseCount() != 1 {
		t.Errorf("remaining pending = %d, want 1", h.PendingResponseCount())
	}
}

// --- Integration: HandleParentRequest + SendAllPendingResponses ---

func TestHandleParentRequest_EndToEnd(t *testing.T) {
	t.Parallel()

	h, _, _, transport, ct := newParentRequestHandlerTestSetup(RoleRouter, 2)

	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)
	scanMask := uint8(ScanMaskRouterFlag)

	childAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	rxInfo := buildParentRequestRxInfo(childAddr, &challenge, &version, &scanMask)

	// Handle the parent request.
	err := h.HandleParentRequest(rxInfo)
	if err != nil {
		t.Fatalf("HandleParentRequest: %v", err)
	}

	// Verify child was added.
	child := ct.FindChild(childAddr)
	if child == nil {
		t.Fatal("child not found")
	}
	if child.State != StateParentRequest {
		t.Errorf("child state = %v, want StateParentRequest", child.State)
	}

	// Send all pending responses.
	sent, err := h.SendAllPendingResponses()
	if err != nil {
		t.Fatalf("SendAllPendingResponses: %v", err)
	}
	if sent != 1 {
		t.Errorf("sent = %d, want 1", sent)
	}

	// Verify a message was sent.
	if len(transport.sentMessages) != 1 {
		t.Fatalf("sent messages = %d, want 1", len(transport.sentMessages))
	}

	// Verify destination.
	expectedDst := ip6.Address(linkLocalIPFromExtAddress(childAddr))
	if transport.sentMessages[0].dst != expectedDst {
		t.Errorf("dst = %v, want %v", transport.sentMessages[0].dst, expectedDst)
	}

	// Verify no more pending responses.
	if h.PendingResponseCount() != 0 {
		t.Errorf("remaining pending = %d, want 0", h.PendingResponseCount())
	}
}

// --- Multiple children test ---

func TestHandleParentRequest_MultipleChildren(t *testing.T) {
	t.Parallel()

	h, _, _, transport, ct := newParentRequestHandlerTestSetup(RoleRouter, 2)

	version := uint16(ThreadVersion)
	scanMask := uint8(ScanMaskRouterFlag)

	// Two different children send parent requests.
	child1Addr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	child2Addr := types.ExtAddress{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28}

	challenge1 := Challenge{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	challenge2 := Challenge{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}

	rxInfo1 := buildParentRequestRxInfo(child1Addr, &challenge1, &version, &scanMask)
	err := h.HandleParentRequest(rxInfo1)
	if err != nil {
		t.Fatalf("first child: %v", err)
	}

	rxInfo2 := buildParentRequestRxInfo(child2Addr, &challenge2, &version, &scanMask)
	err = h.HandleParentRequest(rxInfo2)
	if err != nil {
		t.Fatalf("second child: %v", err)
	}

	if ct.GetChildCount() != 2 {
		t.Errorf("child count = %d, want 2", ct.GetChildCount())
	}
	if h.PendingResponseCount() != 2 {
		t.Errorf("pending responses = %d, want 2", h.PendingResponseCount())
	}

	// Send all.
	sent, err := h.SendAllPendingResponses()
	if err != nil {
		t.Fatalf("SendAllPendingResponses: %v", err)
	}
	if sent != 2 {
		t.Errorf("sent = %d, want 2", sent)
	}
	if len(transport.sentMessages) != 2 {
		t.Errorf("sent messages = %d, want 2", len(transport.sentMessages))
	}
}

// --- SendParentResponse with nil connectivity provider ---

func TestSendParentResponse_NilConnectivity(t *testing.T) {
	t.Parallel()

	h, _, _, transport, ct := newParentRequestHandlerTestSetup(RoleRouter, 2)

	// Set connectivity to nil.
	h.connectivity = nil

	childAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	c := ct.GetNewChild()
	c.MacAddr = childAddr
	c.State = StateParentRequest

	info := ParentResponseInfo{
		ChildExtAddress: childAddr,
		RxChallenge:     Challenge{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}

	dstIP := ip6.Address(linkLocalIPFromExtAddress(childAddr))
	err := h.SendParentResponse(info, dstIP)
	if err != nil {
		t.Fatalf("SendParentResponse with nil connectivity: %v", err)
	}

	if len(transport.sentMessages) != 1 {
		t.Errorf("sent messages = %d, want 1", len(transport.sentMessages))
	}
}
