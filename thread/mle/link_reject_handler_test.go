// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"testing"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
)

func newLinkRejectTestSetup(role DeviceRole) (*Mle, *Dispatcher, *mockTransport, *mockKeyProvider, *LinkRejectHandler) {
	m := NewMle()
	transport := &mockTransport{}
	keyProv := &mockKeyProvider{}
	dispatcher := NewDispatcher(m, keyProv, transport)

	switch role {
	case RoleChild:
		_ = m.Enable()
		_ = m.SetStateChild(0x0401)
	case RoleRouter:
		_ = m.Enable()
		_ = m.SetStateRouter(0x0400)
	case RoleLeader:
		_ = m.Enable()
		_ = m.SetStateLeader(0x0400)
	case RoleDetached:
		_ = m.Enable()
	case RoleDisabled:
		// leave as-is
	}

	h := NewLinkRejectHandler(m, dispatcher)
	return m, dispatcher, transport, keyProv, h
}

func TestNewLinkRejectHandler_RegistersOnDispatcher(t *testing.T) {
	t.Parallel()

	_, dispatcher, _, _, _ := newLinkRejectTestSetup(RoleRouter)

	if _, ok := dispatcher.handlers[CommandLinkReject]; !ok {
		t.Fatal("expected CommandLinkReject to be registered")
	}
}

func TestHandleLinkReject(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		role      DeviceRole
		neighbor  *Neighbor
		wantErr   bool
		wantState NeighborState
	}{
		{
			name:     "rejects when not attached (Disabled)",
			role:     RoleDisabled,
			neighbor: &Neighbor{State: StateValid},
			wantErr:  true,
		},
		{
			name:     "rejects when not attached (Detached)",
			role:     RoleDetached,
			neighbor: &Neighbor{State: StateValid},
			wantErr:  true,
		},
		{
			name:     "rejects from unknown neighbor (nil)",
			role:     RoleRouter,
			neighbor: nil,
			wantErr:  true,
		},
		{
			name: "invalidates valid neighbor as Child",
			role: RoleChild,
			neighbor: &Neighbor{
				State:   StateValid,
				RLOC16:  0x0800,
				MacAddr: types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			},
			wantErr:   false,
			wantState: StateInvalid,
		},
		{
			name: "invalidates valid neighbor as Router",
			role: RoleRouter,
			neighbor: &Neighbor{
				State:   StateValid,
				RLOC16:  0x0800,
				MacAddr: types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			},
			wantErr:   false,
			wantState: StateInvalid,
		},
		{
			name: "invalidates valid neighbor as Leader",
			role: RoleLeader,
			neighbor: &Neighbor{
				State:   StateValid,
				RLOC16:  0x0800,
				MacAddr: types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			},
			wantErr:   false,
			wantState: StateInvalid,
		},
		{
			name: "invalidates neighbor in LinkRequest state",
			role: RoleRouter,
			neighbor: &Neighbor{
				State:   StateLinkRequest,
				RLOC16:  0x0C00,
				MacAddr: types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11},
			},
			wantErr:   false,
			wantState: StateInvalid,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, _, _, _, h := newLinkRejectTestSetup(tc.role)

			rxInfo := &RxInfo{
				SrcAddr:  types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
				SrcIP:    ip6.Address{0xfe, 0x80},
				Neighbor: tc.neighbor,
			}

			err := h.HandleLinkReject(rxInfo)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.neighbor.State != tc.wantState {
				t.Fatalf("expected neighbor state %s, got %s", tc.wantState, tc.neighbor.State)
			}
		})
	}
}

func TestSendLinkReject(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dst  ip6.Address
	}{
		{
			name: "sends to unicast destination",
			dst: ip6.Address{
				0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x03, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			},
		},
		{
			name: "sends to another unicast destination",
			dst: ip6.Address{
				0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, _, transport, _, h := newLinkRejectTestSetup(RoleRouter)

			err := h.SendLinkReject(tc.dst)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(transport.sentMessages) != 1 {
				t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
			}

			sent := transport.sentMessages[0]

			// Verify destination.
			if sent.dst != tc.dst {
				t.Fatalf("expected dst %v, got %v", tc.dst, sent.dst)
			}

			// Parse the sent message to verify contents.
			pm, err := ParseMessage(sent.data)
			if err != nil {
				t.Fatalf("failed to parse sent message: %v", err)
			}

			// Should be a secured message.
			if pm.SecuritySuite != SecuritySuiteEncMic32 {
				t.Fatalf("expected secured message, got security suite 0x%02X", pm.SecuritySuite)
			}

			// Decrypt the payload to inspect contents.
			secHdrBytes := pm.SecHeader.Marshal()
			srcAddr := transport.GetExtAddress()
			srcIP := transport.GetLinkLocalAddress()

			keyProv := &mockKeyProvider{}
			mleKey := keyProv.GetCurrentMleKey()

			plaintext, err := pm.DecryptPayload(mleKey, srcAddr, srcIP, tc.dst, secHdrBytes)
			if err != nil {
				t.Fatalf("failed to decrypt: %v", err)
			}

			// First byte is the command.
			if len(plaintext) < 1 {
				t.Fatal("plaintext too short")
			}
			if Command(plaintext[0]) != CommandLinkReject {
				t.Fatalf("expected command %d (LinkReject), got %d", CommandLinkReject, plaintext[0])
			}

			// Parse TLVs from the rest.
			tlvs, err := ParseTLVs(plaintext[1:])
			if err != nil {
				t.Fatalf("failed to parse TLVs: %v", err)
			}

			// Should contain a Status TLV.
			statusVal, ok := FindTLV(tlvs, TLVStatus)
			if !ok {
				t.Fatal("expected Status TLV in Link Reject message")
			}

			status, err := ReadStatusTLV(statusVal)
			if err != nil {
				t.Fatalf("failed to read Status TLV: %v", err)
			}

			if status != StatusError {
				t.Fatalf("expected status %d (StatusError), got %d", StatusError, status)
			}
		})
	}
}
