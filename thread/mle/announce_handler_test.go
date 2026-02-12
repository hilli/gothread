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

// newAnnounceHandlerTestSetup creates an AnnounceHandler with a fully
// initialized Mle (at the given role) and Dispatcher mocks.
func newAnnounceHandlerTestSetup(role DeviceRole, routerID uint8) (
	*AnnounceHandler, *Mle, *Dispatcher, *mockTransport, *mockKeyProvider,
) {
	m := NewMle()
	_ = m.Enable()

	m.mu.Lock()
	m.role = role
	m.rloc16 = RLOC16FromRouterID(routerID)
	m.ftd.routerID = routerID
	m.routerEligible = true
	m.mu.Unlock()

	transport := &mockTransport{
		extAddr: types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x33},
		linkLocal: ip6.Address{
			0xfe, 0x80, 0, 0, 0, 0, 0, 0,
			0xA8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x33,
		},
	}

	keyMgr := &mockKeyProvider{
		currentSeq:      5,
		currentKey:      key.MleKey{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
		macFrameCounter: 1000,
		mleFrameCounter: 2000,
	}

	d := NewDispatcher(m, keyMgr, transport)
	h := NewAnnounceHandler(m, d, keyMgr, nil, nil)

	return h, m, d, transport, keyMgr
}

// buildAnnounceRxInfo creates an RxInfo simulating a received Announce
// message with configurable TLVs.
func buildAnnounceRxInfo(
	channel *uint16,
	panID *uint16,
	activeTimestamp *meshcop.Timestamp,
) *RxInfo {
	var tlvs []TLV

	if channel != nil {
		// Channel TLV: page(1) + channel(2) = 3 bytes.
		val := make([]byte, 3)
		val[0] = 0 // channel page 0
		val[1] = byte(*channel >> 8)
		val[2] = byte(*channel)
		tlvs = append(tlvs, TLV{Type: TLVChannel, Value: val})
	}

	if panID != nil {
		val := make([]byte, 2)
		val[0] = byte(*panID >> 8)
		val[1] = byte(*panID)
		tlvs = append(tlvs, TLV{Type: TLVPanID, Value: val})
	}

	if activeTimestamp != nil {
		tlvs = append(tlvs, TLV{Type: TLVActiveTimestamp, Value: makeActiveTimestampTLVValue(activeTimestamp)})
	}

	srcAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xAA}
	srcIP := ip6.Address(linkLocalIPFromExtAddress(srcAddr))

	return &RxInfo{
		SrcAddr:       srcAddr,
		SrcIP:         srcIP,
		DstIP:         ip6.Address(LinkLocalAllNodesMulticast),
		LinkMarginRaw: 20,
		KeySequence:   5,
		FrameCounter:  50,
		Command:       CommandAnnounce,
		TLVs:          tlvs,
		IsSecured:     true,
	}
}

// ptrUint16 returns a pointer to the given uint16 value.
func ptrUint16(v uint16) *uint16 {
	return &v
}

// --- NewAnnounceHandler tests ---

func TestNewAnnounceHandler_RegistersOnDispatcher(t *testing.T) {
	t.Parallel()

	h, _, d, _, _ := newAnnounceHandlerTestSetup(RoleRouter, 3)

	if h == nil {
		t.Fatal("NewAnnounceHandler returned nil")
	}

	// The handler must register for CommandAnnounce.
	if _, ok := d.handlers[CommandAnnounce]; !ok {
		t.Error("AnnounceHandler should register for CommandAnnounce")
	}
}

// --- HandleAnnounce tests ---

func TestHandleAnnounce(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		role     DeviceRole
		routerID uint8
		setup    func(*AnnounceHandler, *Mle)
		buildRx  func() *RxInfo
		wantErr  bool
		verify   func(*testing.T, *AnnounceHandler, *mockTransport)
	}{
		{
			name:     "rejects missing Channel TLV",
			role:     RoleRouter,
			routerID: 3,
			buildRx: func() *RxInfo {
				ts := &meshcop.Timestamp{}
				ts.SetSeconds(10)
				return buildAnnounceRxInfo(nil, ptrUint16(0x1234), ts)
			},
			wantErr: true,
		},
		{
			name:     "rejects missing PanID TLV",
			role:     RoleRouter,
			routerID: 3,
			buildRx: func() *RxInfo {
				ts := &meshcop.Timestamp{}
				ts.SetSeconds(10)
				return buildAnnounceRxInfo(ptrUint16(15), nil, ts)
			},
			wantErr: true,
		},
		{
			name:     "rejects missing ActiveTimestamp TLV",
			role:     RoleRouter,
			routerID: 3,
			buildRx: func() *RxInfo {
				return buildAnnounceRxInfo(ptrUint16(15), ptrUint16(0x1234), nil)
			},
			wantErr: true,
		},
		{
			name:     "ignores when not attached (detached)",
			role:     RoleDetached,
			routerID: 0,
			buildRx: func() *RxInfo {
				ts := &meshcop.Timestamp{}
				ts.SetSeconds(100)
				return buildAnnounceRxInfo(ptrUint16(15), ptrUint16(0x1234), ts)
			},
			wantErr: false,
			verify: func(t *testing.T, h *AnnounceHandler, transport *mockTransport) {
				t.Helper()
				if h.LastAction != AnnounceActionIgnore {
					t.Errorf("LastAction = %d, want AnnounceActionIgnore (%d)", h.LastAction, AnnounceActionIgnore)
				}
				if len(transport.sentMessages) != 0 {
					t.Errorf("expected no messages sent, got %d", len(transport.sentMessages))
				}
			},
		},
		{
			name:     "ignores orphan announce when not attached",
			role:     RoleDetached,
			routerID: 0,
			buildRx: func() *RxInfo {
				ts := &meshcop.Timestamp{}
				ts.SetToOrphanAnnounce()
				return buildAnnounceRxInfo(ptrUint16(15), ptrUint16(0x1234), ts)
			},
			wantErr: false,
			verify: func(t *testing.T, h *AnnounceHandler, transport *mockTransport) {
				t.Helper()
				if h.LastAction != AnnounceActionIgnore {
					t.Errorf("LastAction = %d, want AnnounceActionIgnore", h.LastAction)
				}
				if len(transport.sentMessages) != 0 {
					t.Errorf("expected no messages sent, got %d", len(transport.sentMessages))
				}
			},
		},
		{
			name:     "signals when received timestamp is newer",
			role:     RoleRouter,
			routerID: 3,
			buildRx: func() *RxInfo {
				ts := &meshcop.Timestamp{}
				ts.SetSeconds(100) // Newer than our zero-value local timestamp.
				return buildAnnounceRxInfo(ptrUint16(15), ptrUint16(0xABCD), ts)
			},
			wantErr: false,
			verify: func(t *testing.T, h *AnnounceHandler, transport *mockTransport) {
				t.Helper()
				if h.LastAction != AnnounceActionSignal {
					t.Errorf("LastAction = %d, want AnnounceActionSignal (%d)", h.LastAction, AnnounceActionSignal)
				}
				if h.LastReceivedChannel != 15 {
					t.Errorf("LastReceivedChannel = %d, want 15", h.LastReceivedChannel)
				}
				if h.LastReceivedPanID != 0xABCD {
					t.Errorf("LastReceivedPanID = 0x%04X, want 0xABCD", h.LastReceivedPanID)
				}
				// No message should be sent — we are the stale side.
				if len(transport.sentMessages) != 0 {
					t.Errorf("expected no messages sent, got %d", len(transport.sentMessages))
				}
			},
		},
		{
			name:     "signals when received timestamp equals local",
			role:     RoleRouter,
			routerID: 3,
			buildRx: func() *RxInfo {
				// Zero timestamp matches our local zero placeholder.
				ts := &meshcop.Timestamp{}
				return buildAnnounceRxInfo(ptrUint16(20), ptrUint16(0x5678), ts)
			},
			wantErr: false,
			verify: func(t *testing.T, h *AnnounceHandler, transport *mockTransport) {
				t.Helper()
				if h.LastAction != AnnounceActionSignal {
					t.Errorf("LastAction = %d, want AnnounceActionSignal", h.LastAction)
				}
				if len(transport.sentMessages) != 0 {
					t.Errorf("expected no messages sent, got %d", len(transport.sentMessages))
				}
			},
		},
		{
			name:     "sends announce back when local timestamp is newer on FTD router",
			role:     RoleRouter,
			routerID: 3,
			buildRx: func() *RxInfo {
				// Invalid timestamp compares as less than our zero-value
				// valid timestamp.
				ts := &meshcop.Timestamp{}
				ts.SetToInvalid()
				return buildAnnounceRxInfo(ptrUint16(25), ptrUint16(0x9999), ts)
			},
			wantErr: false,
			verify: func(t *testing.T, h *AnnounceHandler, transport *mockTransport) {
				t.Helper()
				if h.LastAction != AnnounceActionSendBack {
					t.Errorf("LastAction = %d, want AnnounceActionSendBack (%d)", h.LastAction, AnnounceActionSendBack)
				}
				if len(transport.sentMessages) < 1 {
					t.Fatal("expected an announce message to be sent")
				}
				if transport.sentMessages[0].dst != LinkLocalAllNodesMulticast {
					t.Errorf("sent dst = %v, want %v", transport.sentMessages[0].dst, LinkLocalAllNodesMulticast)
				}
			},
		},
		{
			name:     "sends announce back as leader",
			role:     RoleLeader,
			routerID: 5,
			buildRx: func() *RxInfo {
				ts := &meshcop.Timestamp{}
				ts.SetToInvalid()
				return buildAnnounceRxInfo(ptrUint16(11), ptrUint16(0x1111), ts)
			},
			wantErr: false,
			verify: func(t *testing.T, h *AnnounceHandler, transport *mockTransport) {
				t.Helper()
				if h.LastAction != AnnounceActionSendBack {
					t.Errorf("LastAction = %d, want AnnounceActionSendBack", h.LastAction)
				}
				if len(transport.sentMessages) < 1 {
					t.Fatal("expected an announce message to be sent")
				}
			},
		},
		{
			name:     "ignores when local is newer but device is child (not router/leader)",
			role:     RoleChild,
			routerID: 3,
			buildRx: func() *RxInfo {
				ts := &meshcop.Timestamp{}
				ts.SetToInvalid()
				return buildAnnounceRxInfo(ptrUint16(15), ptrUint16(0x2222), ts)
			},
			wantErr: false,
			verify: func(t *testing.T, h *AnnounceHandler, transport *mockTransport) {
				t.Helper()
				if h.LastAction != AnnounceActionIgnore {
					t.Errorf("LastAction = %d, want AnnounceActionIgnore", h.LastAction)
				}
				if len(transport.sentMessages) != 0 {
					t.Errorf("expected no messages sent, got %d", len(transport.sentMessages))
				}
			},
		},
		{
			name:     "ignores when local is newer but device is not router-eligible",
			role:     RoleRouter,
			routerID: 3,
			setup: func(_ *AnnounceHandler, m *Mle) {
				m.SetRouterEligible(false)
			},
			buildRx: func() *RxInfo {
				ts := &meshcop.Timestamp{}
				ts.SetToInvalid()
				return buildAnnounceRxInfo(ptrUint16(15), ptrUint16(0x3333), ts)
			},
			wantErr: false,
			verify: func(t *testing.T, h *AnnounceHandler, transport *mockTransport) {
				t.Helper()
				if h.LastAction != AnnounceActionIgnore {
					t.Errorf("LastAction = %d, want AnnounceActionIgnore", h.LastAction)
				}
				if len(transport.sentMessages) != 0 {
					t.Errorf("expected no messages sent, got %d", len(transport.sentMessages))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h, m, _, transport, _ := newAnnounceHandlerTestSetup(tt.role, tt.routerID)

			if tt.setup != nil {
				tt.setup(h, m)
			}

			rxInfo := tt.buildRx()
			err := h.HandleAnnounce(rxInfo)

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
				tt.verify(t, h, transport)
			}
		})
	}
}

// --- SendAnnounce tests ---

func TestSendAnnounce(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		channel uint16
		mode    AnnounceMode
		dst     ip6.Address
		wantErr bool
		verify  func(*testing.T, *mockTransport)
	}{
		{
			name:    "normal announce",
			channel: 15,
			mode:    AnnounceNormal,
			dst:     LinkLocalAllNodesMulticast,
			wantErr: false,
			verify: func(t *testing.T, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) != 1 {
					t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
				}
				if transport.sentMessages[0].dst != LinkLocalAllNodesMulticast {
					t.Errorf("dst = %v, want %v", transport.sentMessages[0].dst, LinkLocalAllNodesMulticast)
				}
				if len(transport.sentMessages[0].data) == 0 {
					t.Error("message data is empty")
				}
			},
		},
		{
			name:    "orphan announce",
			channel: 20,
			mode:    AnnounceOrphan,
			dst:     LinkLocalAllNodesMulticast,
			wantErr: false,
			verify: func(t *testing.T, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) != 1 {
					t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
				}
				if transport.sentMessages[0].dst != LinkLocalAllNodesMulticast {
					t.Errorf("dst = %v, want %v", transport.sentMessages[0].dst, LinkLocalAllNodesMulticast)
				}
			},
		},
		{
			name:    "unicast destination",
			channel: 11,
			mode:    AnnounceNormal,
			dst: ip6.Address{
				0xfe, 0x80, 0, 0, 0, 0, 0, 0,
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			},
			wantErr: false,
			verify: func(t *testing.T, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) != 1 {
					t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
				}
				expectedDst := ip6.Address{
					0xfe, 0x80, 0, 0, 0, 0, 0, 0,
					0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				}
				if transport.sentMessages[0].dst != expectedDst {
					t.Errorf("dst = %v, want %v", transport.sentMessages[0].dst, expectedDst)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h, _, _, transport, _ := newAnnounceHandlerTestSetup(RoleRouter, 3)

			err := h.SendAnnounce(tt.channel, tt.mode, tt.dst)

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
				tt.verify(t, transport)
			}
		})
	}
}
