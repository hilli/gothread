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

// newChildUpdateRouterTestSetup creates a ChildUpdateRouter with a fully
// initialized Mle (router state) and Dispatcher mocks.
func newChildUpdateRouterTestSetup(role DeviceRole, routerID uint8) (handler *ChildUpdateRouter, mleInstance *Mle, dispatcher *Dispatcher, sender *mockTransport, table *ChildTable) {
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

	h := NewChildUpdateRouter(m, d, keyMgr, childTable)
	return h, m, d, transport, childTable
}

// buildChildUpdateRequestRxInfo creates an RxInfo simulating a received Child
// Update Request with configurable TLVs. Pass nil for optional TLVs to omit.
func buildChildUpdateRequestRxInfo(
	srcAddr types.ExtAddress,
	mode *DeviceMode,
	challenge []byte,
	timeout *uint32,
	tlvRequest []uint8,
) *RxInfo {
	var tlvs []TLV

	if mode != nil {
		tlvs = append(tlvs, TLV{Type: TLVMode, Value: makeModeTLVValue(*mode)})
	}
	if challenge != nil {
		tlvs = append(tlvs, TLV{Type: TLVChallenge, Value: challenge})
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
		Command:       CommandChildUpdateRequest,
		TLVs:          tlvs,
		IsSecured:     true,
	}
}

// --- NewChildUpdateRouter tests ---

func TestNewChildUpdateRouter_DoesNotRegister(t *testing.T) {
	t.Parallel()

	h, _, d, _, _ := newChildUpdateRouterTestSetup(RoleRouter, 2)

	if h == nil {
		t.Fatal("NewChildUpdateRouter returned nil")
	}

	// The handler must NOT register on the dispatcher — child_handlers.go
	// already does that.
	if _, ok := d.handlers[CommandChildUpdateRequest]; ok {
		t.Error("ChildUpdateRouter should not register for CommandChildUpdateRequest")
	}
	if _, ok := d.handlers[CommandChildUpdateResponse]; ok {
		t.Error("ChildUpdateRouter should not register for CommandChildUpdateResponse")
	}
}

// --- HandleChildUpdateRequest tests ---

func TestHandleChildUpdateRequest_Router(t *testing.T) {
	t.Parallel()

	childAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	mode := NewDeviceMode(ModeRxOnWhenIdle | ModeFullThreadDevice)
	timeout := uint32(300)
	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}

	tests := []struct {
		name      string
		role      DeviceRole
		routerID  uint8
		setup     func(*ChildUpdateRouter, *Mle, *ChildTable)
		buildInfo func() *RxInfo
		wantErr   bool
		verify    func(*testing.T, *ChildUpdateRouter, *ChildTable, *mockTransport)
	}{
		{
			name:     "rejects when not router or leader",
			role:     RoleChild,
			routerID: 1,
			buildInfo: func() *RxInfo {
				return buildChildUpdateRequestRxInfo(childAddr, &mode, nil, &timeout, nil)
			},
			wantErr: true,
		},
		{
			name:     "rejects missing Mode TLV",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *ChildUpdateRouter, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateValid
				c.RLOC16 = RLOC16FromRouterID(2) | 0x0001
			},
			buildInfo: func() *RxInfo {
				// No mode TLV
				return buildChildUpdateRequestRxInfo(childAddr, nil, nil, &timeout, nil)
			},
			wantErr: true,
		},
		{
			name:     "unknown child with challenge sends error status",
			role:     RoleRouter,
			routerID: 2,
			// No setup — child table is empty.
			buildInfo: func() *RxInfo {
				return buildChildUpdateRequestRxInfo(childAddr, &mode, challenge[:], &timeout, nil)
			},
			wantErr: false,
			verify: func(t *testing.T, _ *ChildUpdateRouter, _ *ChildTable, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) < 1 {
					t.Fatal("expected an error status response to be sent")
				}
				// The response should be sent to the source IP of the request.
				expectedDst := ip6.Address(linkLocalIPFromExtAddress(childAddr))
				if transport.sentMessages[0].dst != expectedDst {
					t.Errorf("response dst = %v, want %v", transport.sentMessages[0].dst, expectedDst)
				}
			},
		},
		{
			name:     "unknown child without challenge returns error",
			role:     RoleRouter,
			routerID: 2,
			// No setup — child table is empty.
			buildInfo: func() *RxInfo {
				return buildChildUpdateRequestRxInfo(childAddr, &mode, nil, &timeout, nil)
			},
			wantErr: true,
		},
		{
			name:     "known child not StateValid returns error",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *ChildUpdateRouter, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateChildIDRequest // Not StateValid
				c.RLOC16 = RLOC16FromRouterID(2) | 0x0001
			},
			buildInfo: func() *RxInfo {
				return buildChildUpdateRequestRxInfo(childAddr, &mode, nil, &timeout, nil)
			},
			wantErr: true,
		},
		{
			name:     "valid child update updates mode timeout and last heard",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *ChildUpdateRouter, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateValid
				c.RLOC16 = RLOC16FromRouterID(2) | 0x0001
				c.Mode = NewDeviceMode(0) // Different initial mode.
				c.Timeout = 100           // Different initial timeout.
			},
			buildInfo: func() *RxInfo {
				return buildChildUpdateRequestRxInfo(childAddr, &mode, nil, &timeout, nil)
			},
			wantErr: false,
			verify: func(t *testing.T, _ *ChildUpdateRouter, ct *ChildTable, transport *mockTransport) {
				t.Helper()
				child := ct.FindChild(childAddr)
				if child == nil {
					t.Fatal("child should still be in table")
				}
				// Mode should be updated.
				if child.Mode != mode {
					t.Errorf("mode = %v, want %v", child.Mode, mode)
				}
				// Timeout should be updated.
				if child.Timeout != timeout {
					t.Errorf("timeout = %d, want %d", child.Timeout, timeout)
				}
				// LastHeard should be recently set (not zero).
				if child.LastHeard.IsZero() {
					t.Error("LastHeard should have been updated")
				}
				// KeySequence should match the rxInfo.
				if child.KeySequence != 5 {
					t.Errorf("key sequence = %d, want 5", child.KeySequence)
				}
				// A response should have been sent.
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
			name:     "valid child with challenge sends response",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *ChildUpdateRouter, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateValid
				c.RLOC16 = RLOC16FromRouterID(2) | 0x0001
			},
			buildInfo: func() *RxInfo {
				return buildChildUpdateRequestRxInfo(childAddr, &mode, challenge[:], &timeout, nil)
			},
			wantErr: false,
			verify: func(t *testing.T, _ *ChildUpdateRouter, _ *ChildTable, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) < 1 {
					t.Fatal("no response message sent")
				}
				expectedDst := ip6.Address(linkLocalIPFromExtAddress(childAddr))
				if transport.sentMessages[0].dst != expectedDst {
					t.Errorf("response dst = %v, want %v", transport.sentMessages[0].dst, expectedDst)
				}
				// The sent data should be non-empty (contains the encrypted response).
				if len(transport.sentMessages[0].data) == 0 {
					t.Error("response message data is empty")
				}
			},
		},
		{
			name:     "requested TLVs forwarded to response",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *ChildUpdateRouter, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateValid
				c.RLOC16 = RLOC16FromRouterID(2) | 0x0001
				c.Timeout = 300
			},
			buildInfo: func() *RxInfo {
				return buildChildUpdateRequestRxInfo(childAddr, &mode, nil, &timeout,
					[]uint8{TLVTimeout})
			},
			wantErr: false,
			verify: func(t *testing.T, _ *ChildUpdateRouter, _ *ChildTable, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) < 1 {
					t.Fatal("no response message sent")
				}
				// Verify the response was sent to the child.
				expectedDst := ip6.Address(linkLocalIPFromExtAddress(childAddr))
				if transport.sentMessages[0].dst != expectedDst {
					t.Errorf("response dst = %v, want %v", transport.sentMessages[0].dst, expectedDst)
				}
			},
		},
		{
			name:     "valid child update as leader",
			role:     RoleLeader,
			routerID: 5,
			setup: func(_ *ChildUpdateRouter, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateValid
				c.RLOC16 = RLOC16FromRouterID(5) | 0x0001
			},
			buildInfo: func() *RxInfo {
				return buildChildUpdateRequestRxInfo(childAddr, &mode, nil, &timeout, nil)
			},
			wantErr: false,
			verify: func(t *testing.T, _ *ChildUpdateRouter, _ *ChildTable, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) < 1 {
					t.Fatal("no response message sent")
				}
			},
		},
		{
			name:     "timeout not updated when TLV absent",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *ChildUpdateRouter, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateValid
				c.RLOC16 = RLOC16FromRouterID(2) | 0x0001
				c.Timeout = 999 // Should remain unchanged.
			},
			buildInfo: func() *RxInfo {
				// No Timeout TLV.
				return buildChildUpdateRequestRxInfo(childAddr, &mode, nil, nil, nil)
			},
			wantErr: false,
			verify: func(t *testing.T, _ *ChildUpdateRouter, ct *ChildTable, _ *mockTransport) {
				t.Helper()
				child := ct.FindChild(childAddr)
				if child == nil {
					t.Fatal("child should still be in table")
				}
				if child.Timeout != 999 {
					t.Errorf("timeout = %d, want 999 (should not be updated)", child.Timeout)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h, m, _, transport, ct := newChildUpdateRouterTestSetup(tt.role, tt.routerID)

			if tt.setup != nil {
				tt.setup(h, m, ct)
			}

			rxInfo := tt.buildInfo()
			err := h.HandleChildUpdateRequest(rxInfo)

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
