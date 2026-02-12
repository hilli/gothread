// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"testing"
	"time"

	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/key"
)

// --- mock RouterLookup ---

type mockRouterLookup struct {
	routersByRLOC16  map[uint16]*Router
	routersByExtAddr map[types.ExtAddress]*Router
}

func (m *mockRouterLookup) FindRouterByRLOC16(rloc16 uint16) *Router {
	return m.routersByRLOC16[rloc16]
}

func (m *mockRouterLookup) FindRouterByExtAddress(addr types.ExtAddress) *Router {
	return m.routersByExtAddr[addr]
}

// --- test setup ---

func newLinkRequestHandlerTestSetup(role DeviceRole, routerID uint8) (
	*FtdLinkHandlers, *Mle, *Dispatcher, *mockTransport, *mockKeyProvider,
	*mockRouterLookup, *mockRouteDataProvider,
) {
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

	routerLookup := &mockRouterLookup{
		routersByRLOC16:  make(map[uint16]*Router),
		routersByExtAddr: make(map[types.ExtAddress]*Router),
	}

	routeData := &mockRouteDataProvider{
		sequence: 7,
		mask:     RouterIDSet{},
		entries:  nil,
	}

	h := NewFtdLinkHandlers(m, d, keyMgr, routerLookup, routeData)
	return h, m, d, transport, keyMgr, routerLookup, routeData
}

func makeVersionTLVValue(version uint16) []byte {
	val := make([]byte, 2)
	encoding.BigEndianWriteUint16(version, val)
	return val
}

// buildLinkRequestRxInfo creates an RxInfo simulating a received Link Request.
func buildLinkRequestRxInfo(
	srcAddr types.ExtAddress,
	challenge *Challenge,
	version *uint16,
	sourceRLOC16 *uint16,
	leaderData *LeaderData,
) *RxInfo {
	var tlvs []TLV

	if challenge != nil {
		tlvs = append(tlvs, TLV{Type: TLVChallenge, Value: challenge[:]})
	}
	if version != nil {
		tlvs = append(tlvs, TLV{Type: TLVVersion, Value: makeVersionTLVValue(*version)})
	}
	if sourceRLOC16 != nil {
		tlvs = append(tlvs, TLV{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(*sourceRLOC16)})
	}
	if leaderData != nil {
		tlvs = append(tlvs, TLV{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(*leaderData)})
	}

	srcIP := linkLocalIPFromExtAddress(srcAddr)
	return &RxInfo{
		SrcAddr:       srcAddr,
		SrcIP:         srcIP,
		DstIP:         ip6.Address{0xfe, 0x80}, // unicast
		LinkMarginRaw: 30,
		KeySequence:   5,
		FrameCounter:  100,
		Command:       CommandLinkRequest,
		TLVs:          tlvs,
		IsSecured:     true,
	}
}

// --- HandleLinkRequest tests ---

func TestHandleLinkRequest(t *testing.T) {
	t.Parallel()

	peerAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)

	tests := []struct {
		name      string
		role      DeviceRole
		routerID  uint8
		setup     func(*FtdLinkHandlers, *mockRouterLookup, *RxInfo)
		buildInfo func() *RxInfo
		wantErr   bool
		verify    func(*testing.T, *FtdLinkHandlers, *mockTransport, *mockRouterLookup)
	}{
		{
			name:     "rejects when not router or leader",
			role:     RoleChild,
			routerID: 1,
			buildInfo: func() *RxInfo {
				rloc := uint16(0x0800)
				return buildLinkRequestRxInfo(peerAddr, &challenge, &version, &rloc, nil)
			},
			wantErr: true,
		},
		{
			name:     "rejects missing challenge TLV",
			role:     RoleRouter,
			routerID: 2,
			buildInfo: func() *RxInfo {
				rloc := uint16(0x0800)
				return buildLinkRequestRxInfo(peerAddr, nil, &version, &rloc, nil)
			},
			wantErr: true,
		},
		{
			name:     "rejects missing version TLV",
			role:     RoleRouter,
			routerID: 2,
			buildInfo: func() *RxInfo {
				return buildLinkRequestRxInfo(peerAddr, &challenge, nil, nil, nil)
			},
			wantErr: true,
		},
		{
			name:     "rejects partition ID mismatch",
			role:     RoleRouter,
			routerID: 2,
			buildInfo: func() *RxInfo {
				rloc := uint16(0x0800)
				ld := LeaderData{PartitionID: 0x99999999}
				return buildLinkRequestRxInfo(peerAddr, &challenge, &version, &rloc, &ld)
			},
			wantErr: true,
		},
		{
			name:     "rejects non-router source address",
			role:     RoleRouter,
			routerID: 2,
			buildInfo: func() *RxInfo {
				childRLOC := uint16(0x0401) // child RLOC16
				return buildLinkRequestRxInfo(peerAddr, &challenge, &version, &childRLOC, nil)
			},
			wantErr: true,
		},
		{
			name:     "rejects unknown router RLOC16",
			role:     RoleRouter,
			routerID: 2,
			buildInfo: func() *RxInfo {
				rloc := uint16(0x0800) // router RLOC16, but not in lookup
				return buildLinkRequestRxInfo(peerAddr, &challenge, &version, &rloc, nil)
			},
			wantErr: true,
		},
		{
			name:     "initializes neighbor for unvalidated router",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *FtdLinkHandlers, rl *mockRouterLookup, _ *RxInfo) {
				r := &Router{
					Neighbor: Neighbor{
						RLOC16: 0x0800,
						State:  StateRestored,
					},
				}
				rl.routersByRLOC16[0x0800] = r
			},
			buildInfo: func() *RxInfo {
				rloc := uint16(0x0800)
				return buildLinkRequestRxInfo(peerAddr, &challenge, &version, &rloc, nil)
			},
			wantErr: false,
			verify: func(t *testing.T, _ *FtdLinkHandlers, transport *mockTransport, rl *mockRouterLookup) {
				t.Helper()
				r := rl.routersByRLOC16[0x0800]
				if r.State != StateLinkRequest {
					t.Errorf("router state = %v, want StateLinkRequest", r.State)
				}
				if r.MacAddr != peerAddr {
					t.Errorf("router MacAddr = %v, want %v", r.MacAddr, peerAddr)
				}
				if len(transport.sentMessages) < 1 {
					t.Error("expected at least 1 sent message (link accept)")
				}
			},
		},
		{
			name:     "accepts valid router",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *FtdLinkHandlers, rl *mockRouterLookup, _ *RxInfo) {
				r := &Router{
					Neighbor: Neighbor{
						MacAddr: peerAddr,
						RLOC16:  0x0800,
						State:   StateValid,
					},
				}
				rl.routersByRLOC16[0x0800] = r
			},
			buildInfo: func() *RxInfo {
				rloc := uint16(0x0800)
				return buildLinkRequestRxInfo(peerAddr, &challenge, &version, &rloc, nil)
			},
			wantErr: false,
			verify: func(t *testing.T, _ *FtdLinkHandlers, transport *mockTransport, _ *mockRouterLookup) {
				t.Helper()
				if len(transport.sentMessages) < 1 {
					t.Error("expected at least 1 sent message (link accept)")
				}
			},
		},
		{
			name:     "rejects MAC mismatch for valid router",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *FtdLinkHandlers, rl *mockRouterLookup, _ *RxInfo) {
				differentAddr := types.ExtAddress{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8}
				r := &Router{
					Neighbor: Neighbor{
						MacAddr: differentAddr,
						RLOC16:  0x0800,
						State:   StateValid,
					},
				}
				rl.routersByRLOC16[0x0800] = r
			},
			buildInfo: func() *RxInfo {
				rloc := uint16(0x0800)
				return buildLinkRequestRxInfo(peerAddr, &challenge, &version, &rloc, nil)
			},
			wantErr: true,
		},
		{
			name:     "rejects no source address and nil neighbor",
			role:     RoleRouter,
			routerID: 2,
			buildInfo: func() *RxInfo {
				rxInfo := buildLinkRequestRxInfo(peerAddr, &challenge, &version, nil, nil)
				rxInfo.Neighbor = nil
				return rxInfo
			},
			wantErr: true,
		},
		{
			name:     "rejects no source address from non-router neighbor",
			role:     RoleRouter,
			routerID: 2,
			buildInfo: func() *RxInfo {
				rxInfo := buildLinkRequestRxInfo(peerAddr, &challenge, &version, nil, nil)
				rxInfo.Neighbor = &Neighbor{
					MacAddr: peerAddr,
					RLOC16:  0x0401, // child RLOC16
					State:   StateValid,
				}
				return rxInfo
			},
			wantErr: true,
		},
		{
			name:     "accepts no source address from router neighbor",
			role:     RoleRouter,
			routerID: 2,
			buildInfo: func() *RxInfo {
				rxInfo := buildLinkRequestRxInfo(peerAddr, &challenge, &version, nil, nil)
				rxInfo.Neighbor = &Neighbor{
					MacAddr: peerAddr,
					RLOC16:  0x0800, // router RLOC16
					State:   StateValid,
				}
				return rxInfo
			},
			wantErr: false,
			verify: func(t *testing.T, _ *FtdLinkHandlers, transport *mockTransport, _ *mockRouterLookup) {
				t.Helper()
				if len(transport.sentMessages) < 1 {
					t.Error("expected at least 1 sent message (link accept)")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h, _, _, transport, _, rl, _ := newLinkRequestHandlerTestSetup(tt.role, tt.routerID)

			rxInfo := tt.buildInfo()

			if tt.setup != nil {
				tt.setup(h, rl, rxInfo)
			}

			err := h.HandleLinkRequest(rxInfo)

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
				tt.verify(t, h, transport, rl)
			}
		})
	}
}

// --- HandleLinkRequest leader role test ---

func TestHandleLinkRequest_Leader(t *testing.T) {
	t.Parallel()

	h, _, _, transport, _, rl, _ := newLinkRequestHandlerTestSetup(RoleLeader, 5)

	peerAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)
	rloc := uint16(0x0800)

	r := &Router{
		Neighbor: Neighbor{
			MacAddr: peerAddr,
			RLOC16:  0x0800,
			State:   StateValid,
		},
	}
	rl.routersByRLOC16[0x0800] = r

	rxInfo := buildLinkRequestRxInfo(peerAddr, &challenge, &version, &rloc, nil)

	err := h.HandleLinkRequest(rxInfo)
	if err != nil {
		t.Fatalf("HandleLinkRequest as leader: %v", err)
	}

	if len(transport.sentMessages) < 1 {
		t.Error("expected at least 1 sent message")
	}
}

// --- HandleLinkRequest with matching partition ID ---

func TestHandleLinkRequest_MatchingPartitionID(t *testing.T) {
	t.Parallel()

	h, _, _, transport, _, rl, _ := newLinkRequestHandlerTestSetup(RoleRouter, 2)

	peerAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)
	rloc := uint16(0x0800)

	r := &Router{
		Neighbor: Neighbor{
			MacAddr: peerAddr,
			RLOC16:  0x0800,
			State:   StateValid,
		},
	}
	rl.routersByRLOC16[0x0800] = r

	// Matching partition ID.
	ld := LeaderData{PartitionID: 0xDEAD0001}
	rxInfo := buildLinkRequestRxInfo(peerAddr, &challenge, &version, &rloc, &ld)

	err := h.HandleLinkRequest(rxInfo)
	if err != nil {
		t.Fatalf("HandleLinkRequest with matching partition: %v", err)
	}

	if len(transport.sentMessages) < 1 {
		t.Error("expected at least 1 sent message")
	}
}

// --- initNeighbor tests ---

func TestInitNeighbor(t *testing.T) {
	t.Parallel()

	srcAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	srcIP := linkLocalIPFromExtAddress(srcAddr)

	rxInfo := &RxInfo{
		SrcAddr:      srcAddr,
		SrcIP:        srcIP,
		KeySequence:  42,
		FrameCounter: 1000,
	}

	n := &Neighbor{
		State:        StateValid,
		LinkFailures: 5,
	}

	before := time.Now()
	initNeighbor(n, rxInfo)
	after := time.Now()

	if n.MacAddr != srcAddr {
		t.Errorf("MacAddr = %v, want %v", n.MacAddr, srcAddr)
	}
	if n.State != StateInvalid {
		t.Errorf("State = %v, want StateInvalid", n.State)
	}
	if n.KeySequence != 42 {
		t.Errorf("KeySequence = %d, want 42", n.KeySequence)
	}
	if n.Counters.MleFrameCounter != 1000 {
		t.Errorf("MleFrameCounter = %d, want 1000", n.Counters.MleFrameCounter)
	}
	if n.Counters.LinkFrameCounter != 0 {
		t.Errorf("LinkFrameCounter = %d, want 0", n.Counters.LinkFrameCounter)
	}
	if n.LinkFailures != 0 {
		t.Errorf("LinkFailures = %d, want 0", n.LinkFailures)
	}
	if n.LastHeard.Before(before) || n.LastHeard.After(after) {
		t.Errorf("LastHeard = %v, want between %v and %v", n.LastHeard, before, after)
	}
}

// --- NewFtdLinkHandlers registration test ---

func TestNewFtdLinkHandlers_RegistersHandler(t *testing.T) {
	t.Parallel()

	h, _, d, _, _, _, _ := newLinkRequestHandlerTestSetup(RoleRouter, 2)

	if h == nil {
		t.Fatal("NewFtdLinkHandlers returned nil")
	}

	if _, ok := d.handlers[CommandLinkRequest]; !ok {
		t.Error("handler for CommandLinkRequest not registered")
	}
}

// --- Delayed Link Accept for multicast tests (Phase 31ab) ---

// buildMulticastLinkRequestRxInfo creates an RxInfo with a multicast DstIP.
func buildMulticastLinkRequestRxInfo(
	srcAddr types.ExtAddress,
	challenge *Challenge,
	version *uint16,
	sourceRLOC16 *uint16,
) *RxInfo {
	rxInfo := buildLinkRequestRxInfo(srcAddr, challenge, version, sourceRLOC16, nil)
	// Set DstIP to an all-routers multicast address.
	rxInfo.DstIP = ip6.Address{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	return rxInfo
}

func TestHandleLinkRequest_MulticastQueuesDelayedAccept(t *testing.T) {
	t.Parallel()

	h, _, _, transport, _, rl, _ := newLinkRequestHandlerTestSetup(RoleRouter, 2)

	peerAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)
	rloc := uint16(0x0800)

	r := &Router{
		Neighbor: Neighbor{
			MacAddr: peerAddr,
			RLOC16:  0x0800,
			State:   StateValid,
		},
	}
	rl.routersByRLOC16[0x0800] = r

	rxInfo := buildMulticastLinkRequestRxInfo(peerAddr, &challenge, &version, &rloc)

	err := h.HandleLinkRequest(rxInfo)
	if err != nil {
		t.Fatalf("HandleLinkRequest (multicast): %v", err)
	}

	// Should NOT have sent immediately.
	if len(transport.sentMessages) != 0 {
		t.Errorf("sent %d messages immediately, want 0 (should be delayed)", len(transport.sentMessages))
	}

	// Should have 1 pending accept.
	if h.PendingAcceptCount() != 1 {
		t.Errorf("pending accepts = %d, want 1", h.PendingAcceptCount())
	}
}

func TestHandleLinkRequest_UnicastSendsImmediately(t *testing.T) {
	t.Parallel()

	h, _, _, transport, _, rl, _ := newLinkRequestHandlerTestSetup(RoleRouter, 2)

	peerAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)
	rloc := uint16(0x0800)

	r := &Router{
		Neighbor: Neighbor{
			MacAddr: peerAddr,
			RLOC16:  0x0800,
			State:   StateValid,
		},
	}
	rl.routersByRLOC16[0x0800] = r

	rxInfo := buildLinkRequestRxInfo(peerAddr, &challenge, &version, &rloc, nil)
	// DstIP is already unicast (0xfe80...) from buildLinkRequestRxInfo.

	err := h.HandleLinkRequest(rxInfo)
	if err != nil {
		t.Fatalf("HandleLinkRequest (unicast): %v", err)
	}

	if len(transport.sentMessages) < 1 {
		t.Error("expected immediate send for unicast Link Request")
	}
	if h.PendingAcceptCount() != 0 {
		t.Errorf("pending accepts = %d, want 0 for unicast", h.PendingAcceptCount())
	}
}

func TestFlushPendingAccepts_SendsWhenDue(t *testing.T) {
	t.Parallel()

	h, _, _, transport, _, rl, _ := newLinkRequestHandlerTestSetup(RoleRouter, 2)

	peerAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)
	rloc := uint16(0x0800)

	r := &Router{
		Neighbor: Neighbor{
			MacAddr: peerAddr,
			RLOC16:  0x0800,
			State:   StateValid,
		},
	}
	rl.routersByRLOC16[0x0800] = r

	rxInfo := buildMulticastLinkRequestRxInfo(peerAddr, &challenge, &version, &rloc)
	if err := h.HandleLinkRequest(rxInfo); err != nil {
		t.Fatalf("HandleLinkRequest: %v", err)
	}

	// Force the pending accept to be due now.
	if len(h.pendingAccepts) > 0 {
		h.pendingAccepts[0].sendAt = time.Now().Add(-time.Millisecond)
	}

	sent, err := h.FlushPendingAccepts()
	if err != nil {
		t.Fatalf("FlushPendingAccepts: %v", err)
	}
	if sent != 1 {
		t.Errorf("sent = %d, want 1", sent)
	}
	if len(transport.sentMessages) < 1 {
		t.Error("expected message to be sent after flush")
	}
	if h.PendingAcceptCount() != 0 {
		t.Errorf("remaining pending = %d, want 0", h.PendingAcceptCount())
	}
}

func TestFlushPendingAccepts_KeepsNotYetDue(t *testing.T) {
	t.Parallel()

	h, _, _, transport, _, rl, _ := newLinkRequestHandlerTestSetup(RoleRouter, 2)

	peerAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)
	rloc := uint16(0x0800)

	r := &Router{
		Neighbor: Neighbor{
			MacAddr: peerAddr,
			RLOC16:  0x0800,
			State:   StateValid,
		},
	}
	rl.routersByRLOC16[0x0800] = r

	rxInfo := buildMulticastLinkRequestRxInfo(peerAddr, &challenge, &version, &rloc)
	if err := h.HandleLinkRequest(rxInfo); err != nil {
		t.Fatalf("HandleLinkRequest: %v", err)
	}

	// Set sendAt far in the future.
	if len(h.pendingAccepts) > 0 {
		h.pendingAccepts[0].sendAt = time.Now().Add(10 * time.Second)
	}

	sent, err := h.FlushPendingAccepts()
	if err != nil {
		t.Fatalf("FlushPendingAccepts: %v", err)
	}
	if sent != 0 {
		t.Errorf("sent = %d, want 0 (not yet due)", sent)
	}
	if len(transport.sentMessages) != 0 {
		t.Errorf("sent messages = %d, want 0", len(transport.sentMessages))
	}
	if h.PendingAcceptCount() != 1 {
		t.Errorf("remaining pending = %d, want 1", h.PendingAcceptCount())
	}
}

func TestSendAllPendingAccepts(t *testing.T) {
	t.Parallel()

	h, _, _, transport, _, rl, _ := newLinkRequestHandlerTestSetup(RoleRouter, 2)

	peerAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)
	rloc := uint16(0x0800)

	r := &Router{
		Neighbor: Neighbor{
			MacAddr: peerAddr,
			RLOC16:  0x0800,
			State:   StateValid,
		},
	}
	rl.routersByRLOC16[0x0800] = r

	// Queue two multicast requests.
	for i := 0; i < 2; i++ {
		rxInfo := buildMulticastLinkRequestRxInfo(peerAddr, &challenge, &version, &rloc)
		if err := h.HandleLinkRequest(rxInfo); err != nil {
			t.Fatalf("HandleLinkRequest #%d: %v", i, err)
		}
	}

	if h.PendingAcceptCount() != 2 {
		t.Fatalf("pending = %d, want 2", h.PendingAcceptCount())
	}

	sent, err := h.SendAllPendingAccepts()
	if err != nil {
		t.Fatalf("SendAllPendingAccepts: %v", err)
	}
	if sent != 2 {
		t.Errorf("sent = %d, want 2", sent)
	}
	if len(transport.sentMessages) != 2 {
		t.Errorf("transport messages = %d, want 2", len(transport.sentMessages))
	}
	if h.PendingAcceptCount() != 0 {
		t.Errorf("remaining = %d, want 0", h.PendingAcceptCount())
	}
}

func TestFlushPendingAccepts_RouterRemovedBetweenQueueAndFlush(t *testing.T) {
	t.Parallel()

	h, _, _, _, _, rl, _ := newLinkRequestHandlerTestSetup(RoleRouter, 2)

	peerAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	version := uint16(ThreadVersion)
	rloc := uint16(0x0800)

	r := &Router{
		Neighbor: Neighbor{
			MacAddr: peerAddr,
			RLOC16:  0x0800,
			State:   StateValid,
		},
	}
	rl.routersByRLOC16[0x0800] = r

	rxInfo := buildMulticastLinkRequestRxInfo(peerAddr, &challenge, &version, &rloc)
	if err := h.HandleLinkRequest(rxInfo); err != nil {
		t.Fatalf("HandleLinkRequest: %v", err)
	}

	// Remove the router from the lookup to simulate it being evicted.
	delete(rl.routersByRLOC16, 0x0800)

	// Force due.
	if len(h.pendingAccepts) > 0 {
		h.pendingAccepts[0].sendAt = time.Now().Add(-time.Millisecond)
	}

	// Should still succeed — SendLinkAccept handles nil router gracefully.
	sent, err := h.FlushPendingAccepts()
	if err != nil {
		t.Fatalf("FlushPendingAccepts with removed router: %v", err)
	}
	if sent != 1 {
		t.Errorf("sent = %d, want 1", sent)
	}
	if h.PendingAcceptCount() != 0 {
		t.Errorf("remaining = %d, want 0", h.PendingAcceptCount())
	}
}
