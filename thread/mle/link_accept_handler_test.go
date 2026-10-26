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
	"github.com/hilli/gothread/thread/link"
)

// linkAcceptTestTLVs holds the configurable TLV fields for building a Link
// Accept RxInfo in tests.
type linkAcceptTestTLVs struct {
	sourceRLOC16     *uint16
	response         []byte
	version          *uint16
	linkFrameCounter *uint32
	mleFrameCounter  *uint32
	linkMargin       *uint8
	leaderData       *LeaderData
	challenge        *Challenge
	tlvRequest       []uint8
}

// makeLinkFrameCounterTLVValue encodes a 4-byte big-endian frame counter.
func makeLinkFrameCounterTLVValue(counter uint32) []byte {
	val := make([]byte, 4)
	encoding.BigEndianWriteUint32(counter, val)
	return val
}

// makeMleFrameCounterTLVValue encodes a 4-byte big-endian MLE frame counter.
func makeMleFrameCounterTLVValue(counter uint32) []byte {
	val := make([]byte, 4)
	encoding.BigEndianWriteUint32(counter, val)
	return val
}

// makeResponseTLVValue returns the raw response bytes (echo of a challenge).
func makeResponseTLVValue(response []byte) []byte {
	cp := make([]byte, len(response))
	copy(cp, response)
	return cp
}

// buildLinkAcceptRxInfo creates an RxInfo simulating a received Link Accept
// (or Link Accept And Request) message with the given TLVs.
func buildLinkAcceptRxInfo(
	srcAddr types.ExtAddress,
	cmd Command,
	opts *linkAcceptTestTLVs,
) *RxInfo {
	var tlvs []TLV

	if opts.sourceRLOC16 != nil {
		tlvs = append(tlvs, TLV{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(*opts.sourceRLOC16)})
	}
	if opts.response != nil {
		tlvs = append(tlvs, TLV{Type: TLVResponse, Value: makeResponseTLVValue(opts.response)})
	}
	if opts.version != nil {
		tlvs = append(tlvs, TLV{Type: TLVVersion, Value: makeVersionTLVValue(*opts.version)})
	}
	if opts.linkFrameCounter != nil {
		tlvs = append(tlvs, TLV{Type: TLVLinkFrameCounter, Value: makeLinkFrameCounterTLVValue(*opts.linkFrameCounter)})
	}
	if opts.mleFrameCounter != nil {
		tlvs = append(tlvs, TLV{Type: TLVMleFrameCounter, Value: makeMleFrameCounterTLVValue(*opts.mleFrameCounter)})
	}
	if opts.linkMargin != nil {
		tlvs = append(tlvs, TLV{Type: TLVLinkMargin, Value: []byte{*opts.linkMargin}})
	}
	if opts.leaderData != nil {
		tlvs = append(tlvs, TLV{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(*opts.leaderData)})
	}
	if opts.challenge != nil {
		tlvs = append(tlvs, TLV{Type: TLVChallenge, Value: opts.challenge[:]})
	}
	if opts.tlvRequest != nil {
		tlvs = append(tlvs, TLV{Type: TLVTLVRequest, Value: opts.tlvRequest})
	}

	srcIP := linkLocalIPFromExtAddress(srcAddr)
	return &RxInfo{
		SrcAddr:       srcAddr,
		SrcIP:         srcIP,
		DstIP:         ip6.Address{0xfe, 0x80},
		LinkMarginRaw: 30,
		KeySequence:   5,
		FrameCounter:  100,
		Command:       cmd,
		TLVs:          tlvs,
		IsSecured:     true,
	}
}

// TestHandleLinkAcceptVariant tests both HandleLinkAccept and
// HandleLinkAcceptAndRequest using a table-driven approach.
func TestHandleLinkAcceptVariant(t *testing.T) {
	t.Parallel()

	peerAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	version := uint16(ThreadVersion)
	linkFC := uint32(500)
	mleFC := uint32(600)
	pendingChallenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	peerChallenge := Challenge{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// routerRLOC is a router RLOC16 (Router ID 2, child ID 0).
	routerRLOC := uint16(0x0800)

	// validOpts returns a linkAcceptTestTLVs with all required TLVs present
	// and a response matching pendingChallenge.
	validOpts := func() linkAcceptTestTLVs {
		return linkAcceptTestTLVs{
			sourceRLOC16:     &routerRLOC,
			response:         pendingChallenge[:],
			version:          &version,
			linkFrameCounter: &linkFC,
		}
	}

	// handlers is the set of command variants under test.
	type handlerVariant struct {
		name    string
		cmd     Command
		handler func(*FtdLinkHandlers, *RxInfo) error
	}
	variants := []handlerVariant{
		{"LinkAccept", CommandLinkAccept, func(h *FtdLinkHandlers, rx *RxInfo) error { return h.HandleLinkAccept(rx) }},
		{"LinkAcceptAndRequest", CommandLinkAcceptAndRequest, func(h *FtdLinkHandlers, rx *RxInfo) error { return h.HandleLinkAcceptAndRequest(rx) }},
	}

	tests := []struct {
		name    string
		role    DeviceRole
		setup   func(*mockRouterLookup)
		opts    func() linkAcceptTestTLVs
		wantErr bool
		verify  func(*testing.T, *mockRouterLookup, *mockTransport)
	}{
		{
			name: "rejects when not router or leader",
			role: RoleChild,
			opts: func() linkAcceptTestTLVs {
				return validOpts()
			},
			wantErr: true,
		},
		{
			name: "rejects missing source address",
			role: RoleRouter,
			opts: func() linkAcceptTestTLVs {
				o := validOpts()
				o.sourceRLOC16 = nil
				return o
			},
			wantErr: true,
		},
		{
			name: "rejects non-router source address",
			role: RoleRouter,
			opts: func() linkAcceptTestTLVs {
				o := validOpts()
				childAddr := uint16(0x0801) // child RLOC16
				o.sourceRLOC16 = &childAddr
				return o
			},
			wantErr: true,
		},
		{
			name: "rejects missing response TLV",
			role: RoleRouter,
			opts: func() linkAcceptTestTLVs {
				o := validOpts()
				o.response = nil
				return o
			},
			wantErr: true,
		},
		{
			name: "rejects missing version TLV",
			role: RoleRouter,
			opts: func() linkAcceptTestTLVs {
				o := validOpts()
				o.version = nil
				return o
			},
			wantErr: true,
		},
		{
			name: "rejects missing link frame counter",
			role: RoleRouter,
			opts: func() linkAcceptTestTLVs {
				o := validOpts()
				o.linkFrameCounter = nil
				return o
			},
			wantErr: true,
		},
		{
			name: "rejects unknown router",
			role: RoleRouter,
			// No setup — router not in lookup.
			opts: func() linkAcceptTestTLVs {
				return validOpts()
			},
			wantErr: true,
		},
		{
			name: "rejects response mismatch in StateLinkRequest",
			role: RoleRouter,
			setup: func(rl *mockRouterLookup) {
				r := &Router{
					Neighbor: Neighbor{
						RLOC16:           routerRLOC,
						State:            StateLinkRequest,
						PendingChallenge: pendingChallenge,
					},
				}
				rl.routersByRLOC16[routerRLOC] = r
			},
			opts: func() linkAcceptTestTLVs {
				o := validOpts()
				// Wrong response — does not match pendingChallenge.
				o.response = []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8}
				return o
			},
			wantErr: true,
		},
		{
			name: "rejects unexpected router state",
			role: RoleRouter,
			setup: func(rl *mockRouterLookup) {
				r := &Router{
					Neighbor: Neighbor{
						RLOC16: routerRLOC,
						State:  StateRestored,
					},
				}
				rl.routersByRLOC16[routerRLOC] = r
			},
			opts: func() linkAcceptTestTLVs {
				return validOpts()
			},
			wantErr: true,
		},
		{
			name: "accepts StateLinkRequest with matching response",
			role: RoleRouter,
			setup: func(rl *mockRouterLookup) {
				r := &Router{
					Neighbor: Neighbor{
						RLOC16:           routerRLOC,
						State:            StateLinkRequest,
						PendingChallenge: pendingChallenge,
					},
				}
				rl.routersByRLOC16[routerRLOC] = r
			},
			opts: func() linkAcceptTestTLVs {
				o := validOpts()
				o.linkFrameCounter = &linkFC
				mleFCVal := mleFC
				o.mleFrameCounter = &mleFCVal
				return o
			},
			wantErr: false,
			verify: func(t *testing.T, rl *mockRouterLookup, _ *mockTransport) {
				t.Helper()
				r := rl.routersByRLOC16[routerRLOC]
				if r.State != StateValid {
					t.Errorf("router state = %v, want StateValid", r.State)
				}
				if r.RLOC16 != routerRLOC {
					t.Errorf("router RLOC16 = 0x%04X, want 0x%04X", r.RLOC16, routerRLOC)
				}
				if r.Counters.LinkFrameCounter != linkFC {
					t.Errorf("LinkFrameCounter = %d, want %d", r.Counters.LinkFrameCounter, linkFC)
				}
				if r.Counters.MleFrameCounter != mleFC {
					t.Errorf("MleFrameCounter = %d, want %d", r.Counters.MleFrameCounter, mleFC)
				}
				if r.Version != version {
					t.Errorf("Version = %d, want %d", r.Version, version)
				}
				expectedMode := NewDeviceMode(ModeRxOnWhenIdle | ModeFullThreadDevice | ModeFullNetworkData)
				if r.Mode != expectedMode {
					t.Errorf("Mode = %v, want %v", r.Mode, expectedMode)
				}
			},
		},
		{
			name: "accepts StateValid router (link refresh)",
			role: RoleRouter,
			setup: func(rl *mockRouterLookup) {
				r := &Router{
					Neighbor: Neighbor{
						MacAddr:  peerAddr,
						RLOC16:   routerRLOC,
						State:    StateValid,
						Counters: FrameCounters{LinkFrameCounter: 10, MleFrameCounter: 20},
					},
				}
				rl.routersByRLOC16[routerRLOC] = r
			},
			opts: func() linkAcceptTestTLVs {
				o := validOpts()
				o.linkFrameCounter = &linkFC
				mleFCVal := mleFC
				o.mleFrameCounter = &mleFCVal
				return o
			},
			wantErr: false,
			verify: func(t *testing.T, rl *mockRouterLookup, _ *mockTransport) {
				t.Helper()
				r := rl.routersByRLOC16[routerRLOC]
				if r.State != StateValid {
					t.Errorf("router state = %v, want StateValid", r.State)
				}
				if r.Counters.LinkFrameCounter != linkFC {
					t.Errorf("LinkFrameCounter = %d, want %d", r.Counters.LinkFrameCounter, linkFC)
				}
				if r.Counters.MleFrameCounter != mleFC {
					t.Errorf("MleFrameCounter = %d, want %d", r.Counters.MleFrameCounter, mleFC)
				}
			},
		},
		{
			name: "MLE frame counter defaults to link frame counter",
			role: RoleRouter,
			setup: func(rl *mockRouterLookup) {
				r := &Router{
					Neighbor: Neighbor{
						RLOC16:           routerRLOC,
						State:            StateLinkRequest,
						PendingChallenge: pendingChallenge,
					},
				}
				rl.routersByRLOC16[routerRLOC] = r
			},
			opts: func() linkAcceptTestTLVs {
				o := validOpts()
				// Omit MLE Frame Counter — should default to linkFrameCounter.
				o.mleFrameCounter = nil
				return o
			},
			wantErr: false,
			verify: func(t *testing.T, rl *mockRouterLookup, _ *mockTransport) {
				t.Helper()
				r := rl.routersByRLOC16[routerRLOC]
				if r.Counters.LinkFrameCounter != linkFC {
					t.Errorf("LinkFrameCounter = %d, want %d", r.Counters.LinkFrameCounter, linkFC)
				}
				if r.Counters.MleFrameCounter != linkFC {
					t.Errorf("MleFrameCounter = %d, want %d (should default to LinkFrameCounter)",
						r.Counters.MleFrameCounter, linkFC)
				}
			},
		},
		{
			name: "link margin sets quality out",
			role: RoleRouter,
			setup: func(rl *mockRouterLookup) {
				r := &Router{
					Neighbor: Neighbor{
						RLOC16:           routerRLOC,
						State:            StateLinkRequest,
						PendingChallenge: pendingChallenge,
					},
				}
				rl.routersByRLOC16[routerRLOC] = r
			},
			opts: func() linkAcceptTestTLVs {
				o := validOpts()
				margin := uint8(25) // Should map to a non-zero quality level.
				o.linkMargin = &margin
				return o
			},
			wantErr: false,
			verify: func(t *testing.T, rl *mockRouterLookup, _ *mockTransport) {
				t.Helper()
				r := rl.routersByRLOC16[routerRLOC]
				expectedQuality := link.QualityForLinkMargin(25)
				got := r.LinkInfo.GetQualityOut()
				if got != expectedQuality {
					t.Errorf("QualityOut = %d, want %d (from link margin 25)", got, expectedQuality)
				}
			},
		},
		{
			name: "accept and request sends reply",
			role: RoleRouter,
			setup: func(rl *mockRouterLookup) {
				r := &Router{
					Neighbor: Neighbor{
						RLOC16:           routerRLOC,
						State:            StateLinkRequest,
						PendingChallenge: pendingChallenge,
					},
				}
				rl.routersByRLOC16[routerRLOC] = r
			},
			opts: func() linkAcceptTestTLVs {
				o := validOpts()
				o.challenge = &peerChallenge
				return o
			},
			wantErr: false,
			verify: func(t *testing.T, _ *mockRouterLookup, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) < 1 {
					t.Error("expected at least 1 sent message (link accept reply)")
				}
			},
		},
	}

	for _, variant := range variants {
		for _, tt := range tests {
			// The "accept and request sends reply" case only applies to
			// HandleLinkAcceptAndRequest; for plain HandleLinkAccept the
			// challenge TLV is ignored (and should still succeed).
			testName := variant.name + "/" + tt.name

			t.Run(testName, func(t *testing.T) {
				t.Parallel()

				h, _, _, transport, rl := newLinkRequestHandlerTestSetup(tt.role, 1)

				if tt.setup != nil {
					tt.setup(rl)
				}

				opts := tt.opts()
				// LinkAcceptAndRequest always requires a Challenge TLV;
				// inject one when the test case doesn't explicitly set it.
				if variant.cmd == CommandLinkAcceptAndRequest && opts.challenge == nil {
					opts.challenge = &peerChallenge
				}
				rxInfo := buildLinkAcceptRxInfo(peerAddr, variant.cmd, &opts)

				err := variant.handler(h, rxInfo)

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
					// For the "accept and request sends reply" test, only
					// verify the sent message for the AcceptAndRequest variant.
					if tt.name == "accept and request sends reply" && variant.cmd == CommandLinkAccept {
						// Plain LinkAccept does not send a reply, so skip
						// the "sent message" verification.
						return
					}
					tt.verify(t, rl, transport)
				}
			})
		}
	}
}

// TestHandleLinkAcceptTimestamps verifies that a successful Link Accept
// updates the router's LastHeard, KeySequence, and clears the
// LinkAcceptCountdown.
func TestHandleLinkAcceptTimestamps(t *testing.T) {
	t.Parallel()

	peerAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	routerRLOC := uint16(0x0800)
	version := uint16(ThreadVersion)
	linkFC := uint32(500)
	pendingChallenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}

	h, _, _, _, rl := newLinkRequestHandlerTestSetup(RoleRouter, 1)

	r := &Router{
		Neighbor: Neighbor{
			RLOC16:           routerRLOC,
			State:            StateLinkRequest,
			PendingChallenge: pendingChallenge,
		},
		LinkAcceptCountdown: 3, // Non-zero to verify it gets cleared.
	}
	rl.routersByRLOC16[routerRLOC] = r

	before := time.Now()

	rxInfo := buildLinkAcceptRxInfo(peerAddr, CommandLinkAccept, &linkAcceptTestTLVs{
		sourceRLOC16:     &routerRLOC,
		response:         pendingChallenge[:],
		version:          &version,
		linkFrameCounter: &linkFC,
	})

	err := h.HandleLinkAccept(rxInfo)
	after := time.Now()
	if err != nil {
		t.Fatalf("HandleLinkAccept: %v", err)
	}

	if r.LastHeard.Before(before) || r.LastHeard.After(after) {
		t.Errorf("LastHeard = %v, want between %v and %v", r.LastHeard, before, after)
	}
	if r.KeySequence != 5 {
		t.Errorf("KeySequence = %d, want 5", r.KeySequence)
	}
	if r.LinkAcceptCountdown != 0 {
		t.Errorf("LinkAcceptCountdown = %d, want 0", r.LinkAcceptCountdown)
	}
}
