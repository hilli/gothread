// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"testing"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/key"
)

// --- test setup ---

// newDataRequestHandlerTestSetup creates a DataRequestHandler with a fully
// initialized Mle (router state) and Dispatcher mocks.
func newDataRequestHandlerTestSetup(role DeviceRole, routerID uint8) (
	*DataRequestHandler, *Mle, *Dispatcher, *mockTransport,
	*mockKeyProvider, *ChildTable,
) {
	m := NewMle()
	_ = m.Enable()

	m.mu.Lock()
	m.role = role
	m.rloc16 = RLOC16FromRouterID(routerID)
	m.ftd.routerID = routerID
	m.leaderData = LeaderData{
		PartitionID:    0xDEAD0002,
		LeaderRouterID: routerID,
	}
	m.mu.Unlock()

	transport := &mockTransport{
		extAddr: types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x22},
		linkLocal: ip6.Address{
			0xfe, 0x80, 0, 0, 0, 0, 0, 0,
			0xA8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x22,
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

	h := NewDataRequestHandler(m, d, keyMgr, childTable, nil)
	return h, m, d, transport, keyMgr, childTable
}

// makeActiveTimestampTLVValue creates a serialized Active Timestamp TLV value
// from a meshcop.Timestamp.
func makeActiveTimestampTLVValue(ts *meshcop.Timestamp) []byte {
	data, _ := ts.MarshalBinary()
	return data
}

// makePendingTimestampTLVValue creates a serialized Pending Timestamp TLV
// value from a meshcop.Timestamp.
func makePendingTimestampTLVValue(ts *meshcop.Timestamp) []byte {
	data, _ := ts.MarshalBinary()
	return data
}

// buildDataRequestRxInfo creates an RxInfo simulating a received Data Request
// with configurable TLVs.
func buildDataRequestRxInfo(
	srcAddr types.ExtAddress,
	tlvRequest []uint8,
	activeTimestamp *meshcop.Timestamp,
	pendingTimestamp *meshcop.Timestamp,
) *RxInfo {
	var tlvs []TLV

	if len(tlvRequest) > 0 {
		tlvs = append(tlvs, TLV{Type: TLVTLVRequest, Value: tlvRequest})
	}
	if activeTimestamp != nil {
		tlvs = append(tlvs, TLV{Type: TLVActiveTimestamp, Value: makeActiveTimestampTLVValue(activeTimestamp)})
	}
	if pendingTimestamp != nil {
		tlvs = append(tlvs, TLV{Type: TLVPendingTimestamp, Value: makePendingTimestampTLVValue(pendingTimestamp)})
	}

	srcIP := ip6.Address(linkLocalIPFromExtAddress(srcAddr))
	return &RxInfo{
		SrcAddr:       srcAddr,
		SrcIP:         srcIP,
		DstIP:         ip6.Address{0xfe, 0x80},
		LinkMarginRaw: 25,
		KeySequence:   5,
		FrameCounter:  100,
		Command:       CommandDataRequest,
		TLVs:          tlvs,
		IsSecured:     true,
	}
}

// --- NewDataRequestHandler tests ---

func TestNewDataRequestHandler_RegistersOnDispatcher(t *testing.T) {
	t.Parallel()

	h, _, d, _, _, _ := newDataRequestHandlerTestSetup(RoleRouter, 2)

	if h == nil {
		t.Fatal("NewDataRequestHandler returned nil")
	}

	// The handler must register for CommandDataRequest.
	if _, ok := d.handlers[CommandDataRequest]; !ok {
		t.Error("DataRequestHandler should register for CommandDataRequest")
	}
}

// --- HandleDataRequest tests ---

func TestHandleDataRequest(t *testing.T) {
	t.Parallel()

	childAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x99}

	tests := []struct {
		name     string
		role     DeviceRole
		routerID uint8
		setup    func(*DataRequestHandler, *Mle, *ChildTable)
		buildRx  func() *RxInfo
		wantErr  bool
		verify   func(*testing.T, *DataRequestHandler, *ChildTable, *mockTransport)
	}{
		{
			name:     "rejects when not router or leader",
			role:     RoleChild,
			routerID: 1,
			buildRx: func() *RxInfo {
				return buildDataRequestRxInfo(childAddr, []uint8{TLVNetworkData}, nil, nil)
			},
			wantErr: true,
		},
		{
			name:     "rejects unknown child",
			role:     RoleRouter,
			routerID: 2,
			// No setup — child table is empty.
			buildRx: func() *RxInfo {
				return buildDataRequestRxInfo(childAddr, []uint8{TLVNetworkData}, nil, nil)
			},
			wantErr: true,
		},
		{
			name:     "rejects child not in StateValid",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *DataRequestHandler, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateChildIDRequest // Not StateValid
				c.RLOC16 = RLOC16FromRouterID(2) | 0x0001
			},
			buildRx: func() *RxInfo {
				return buildDataRequestRxInfo(childAddr, []uint8{TLVNetworkData}, nil, nil)
			},
			wantErr: true,
		},
		{
			name:     "rejects missing TLV Request TLV",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *DataRequestHandler, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateValid
				c.RLOC16 = RLOC16FromRouterID(2) | 0x0001
			},
			buildRx: func() *RxInfo {
				// No TLV Request TLV.
				return buildDataRequestRxInfo(childAddr, nil, nil, nil)
			},
			wantErr: true,
		},
		{
			name:     "successful data request with network data",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *DataRequestHandler, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateValid
				c.RLOC16 = RLOC16FromRouterID(2) | 0x0001
			},
			buildRx: func() *RxInfo {
				// Include matching (zero) timestamps so datasets are not added.
				zeroTS := &meshcop.Timestamp{}
				return buildDataRequestRxInfo(childAddr,
					[]uint8{TLVNetworkData},
					zeroTS, zeroTS)
			},
			wantErr: false,
			verify: func(t *testing.T, _ *DataRequestHandler, _ *ChildTable, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) < 1 {
					t.Fatal("expected a data response to be sent")
				}
				expectedDst := ip6.Address(linkLocalIPFromExtAddress(childAddr))
				if transport.sentMessages[0].dst != expectedDst {
					t.Errorf("response dst = %v, want %v", transport.sentMessages[0].dst, expectedDst)
				}
				if len(transport.sentMessages[0].data) == 0 {
					t.Error("response message data is empty")
				}
			},
		},
		{
			name:     "adds active dataset when timestamp absent",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *DataRequestHandler, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateValid
				c.RLOC16 = RLOC16FromRouterID(2) | 0x0001
			},
			buildRx: func() *RxInfo {
				// No Active Timestamp TLV — should trigger ActiveDataset.
				// Include matching Pending Timestamp to isolate the test.
				zeroTS := &meshcop.Timestamp{}
				return buildDataRequestRxInfo(childAddr,
					[]uint8{TLVNetworkData},
					nil, zeroTS)
			},
			wantErr: false,
			verify: func(t *testing.T, _ *DataRequestHandler, _ *ChildTable, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) < 1 {
					t.Fatal("expected a data response to be sent")
				}
			},
		},
		{
			name:     "adds pending dataset when timestamp absent",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *DataRequestHandler, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateValid
				c.RLOC16 = RLOC16FromRouterID(2) | 0x0001
			},
			buildRx: func() *RxInfo {
				// No Pending Timestamp TLV — should trigger PendingDataset.
				// Include matching Active Timestamp to isolate the test.
				zeroTS := &meshcop.Timestamp{}
				return buildDataRequestRxInfo(childAddr,
					[]uint8{TLVNetworkData},
					zeroTS, nil)
			},
			wantErr: false,
			verify: func(t *testing.T, _ *DataRequestHandler, _ *ChildTable, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) < 1 {
					t.Fatal("expected a data response to be sent")
				}
			},
		},
		{
			name:     "adds active dataset when timestamp mismatches",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *DataRequestHandler, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateValid
				c.RLOC16 = RLOC16FromRouterID(2) | 0x0001
			},
			buildRx: func() *RxInfo {
				// Child has a non-zero Active Timestamp that won't match our
				// zero placeholder.
				nonZeroTS := &meshcop.Timestamp{}
				nonZeroTS.SetSeconds(42)
				zeroTS := &meshcop.Timestamp{}
				return buildDataRequestRxInfo(childAddr,
					[]uint8{TLVNetworkData},
					nonZeroTS, zeroTS)
			},
			wantErr: false,
			verify: func(t *testing.T, _ *DataRequestHandler, _ *ChildTable, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) < 1 {
					t.Fatal("expected a data response to be sent")
				}
			},
		},
		{
			name:     "suppresses response when waiting for new network data",
			role:     RoleRouter,
			routerID: 2,
			setup: func(_ *DataRequestHandler, m *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateValid
				c.RLOC16 = RLOC16FromRouterID(2) | 0x0001
				// Set the flag that suppresses data responses.
				m.SetRetrieveNewNetworkData(true)
			},
			buildRx: func() *RxInfo {
				zeroTS := &meshcop.Timestamp{}
				return buildDataRequestRxInfo(childAddr,
					[]uint8{TLVNetworkData},
					zeroTS, zeroTS)
			},
			wantErr: true,
			verify: func(t *testing.T, _ *DataRequestHandler, _ *ChildTable, transport *mockTransport) {
				t.Helper()
				// No message should be sent.
				if len(transport.sentMessages) != 0 {
					t.Errorf("expected no messages sent, got %d", len(transport.sentMessages))
				}
			},
		},
		{
			name:     "successful as leader",
			role:     RoleLeader,
			routerID: 5,
			setup: func(_ *DataRequestHandler, _ *Mle, ct *ChildTable) {
				c := ct.GetNewChild()
				c.MacAddr = childAddr
				c.State = StateValid
				c.RLOC16 = RLOC16FromRouterID(5) | 0x0001
			},
			buildRx: func() *RxInfo {
				zeroTS := &meshcop.Timestamp{}
				return buildDataRequestRxInfo(childAddr,
					[]uint8{TLVNetworkData},
					zeroTS, zeroTS)
			},
			wantErr: false,
			verify: func(t *testing.T, _ *DataRequestHandler, _ *ChildTable, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) < 1 {
					t.Fatal("expected a data response to be sent")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h, m, _, transport, _, ct := newDataRequestHandlerTestSetup(tt.role, tt.routerID)

			if tt.setup != nil {
				tt.setup(h, m, ct)
			}

			rxInfo := tt.buildRx()
			err := h.HandleDataRequest(rxInfo)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.verify != nil {
					tt.verify(t, h, ct, transport)
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

// --- appendIfMissing tests ---

func TestAppendIfMissing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  []uint8
		value  uint8
		wantN  int
		wantIn bool
	}{
		{
			name:   "appends to empty slice",
			input:  nil,
			value:  42,
			wantN:  1,
			wantIn: true,
		},
		{
			name:   "appends when not present",
			input:  []uint8{1, 2, 3},
			value:  4,
			wantN:  4,
			wantIn: true,
		},
		{
			name:   "does not duplicate",
			input:  []uint8{1, 2, 3},
			value:  2,
			wantN:  3,
			wantIn: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := appendIfMissing(tt.input, tt.value)
			if len(result) != tt.wantN {
				t.Errorf("len = %d, want %d", len(result), tt.wantN)
			}
			found := false
			for _, v := range result {
				if v == tt.value {
					found = true
					break
				}
			}
			if found != tt.wantIn {
				t.Errorf("found = %v, want %v", found, tt.wantIn)
			}
		})
	}
}
