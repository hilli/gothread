// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Link Request receive-side handler for MLE.
// Ported from OpenThread — Copyright (c) 2016, The OpenThread Authors.

package mle

import (
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/hilli/gothread/mac/types"
)

// RouterLookup abstracts router table lookups so the link request handler
// can locate router entries without importing the router table package.
type RouterLookup interface {
	// FindRouterByRLOC16 returns the Router entry for the given RLOC16,
	// or nil if no such router exists in the table.
	FindRouterByRLOC16(rloc16 uint16) *Router

	// FindRouterByExtAddress returns the Router entry for the given
	// extended MAC address, or nil if no such router exists.
	FindRouterByExtAddress(addr types.ExtAddress) *Router
}

// pendingLinkAccept holds a delayed Link Accept response scheduled for
// sending after a random delay. This is used for multicast-received Link
// Requests to avoid collisions when multiple routers respond simultaneously.
type pendingLinkAccept struct {
	info   LinkAcceptInfo
	rloc16 uint16 // RLOC16 for router re-lookup at send time (safer than storing *Router)
	sendAt time.Time
}

// FtdLinkHandlers implements MLE Link Request, Link Accept, and Link Accept
// And Request handlers for Full Thread Devices (routers and leaders).
//
// It follows the same structural pattern as ChildHandlers: the constructor
// registers command handlers with the Dispatcher, and incoming messages
// are dispatched to the appropriate method.
type FtdLinkHandlers struct {
	mle          *Mle
	dispatcher   *Dispatcher
	keyMgr       KeyProvider
	routerLookup RouterLookup
	routeData    RouteDataProvider

	// pendingAccepts holds delayed Link Accept messages for multicast-
	// received Link Requests. Flushed by FlushPendingAccepts each tick.
	pendingAccepts []pendingLinkAccept
}

// NewFtdLinkHandlers creates a new FtdLinkHandlers instance and registers
// the Link Request handler with the dispatcher.
func NewFtdLinkHandlers(
	mle *Mle,
	dispatcher *Dispatcher,
	keyMgr KeyProvider,
	routerLookup RouterLookup,
	routeData RouteDataProvider,
) *FtdLinkHandlers {
	h := &FtdLinkHandlers{
		mle:          mle,
		dispatcher:   dispatcher,
		keyMgr:       keyMgr,
		routerLookup: routerLookup,
		routeData:    routeData,
	}

	dispatcher.RegisterHandler(CommandLinkRequest, h.HandleLinkRequest)
	dispatcher.RegisterHandler(CommandLinkAccept, h.HandleLinkAccept)
	dispatcher.RegisterHandler(CommandLinkAcceptAndRequest, h.HandleLinkAcceptAndRequest)

	return h
}

// initNeighbor resets a Neighbor entry with initial values derived from
// the received message metadata. This is called when a router transitions
// from an invalid/restored state to the LinkRequest state.
func initNeighbor(n *Neighbor, rxInfo *RxInfo) {
	n.MacAddr = rxInfo.SrcAddr
	n.State = StateInvalid
	n.KeySequence = rxInfo.KeySequence
	n.Counters = FrameCounters{
		MleFrameCounter:  rxInfo.FrameCounter,
		LinkFrameCounter: 0,
	}
	n.LastHeard = time.Now()
	n.LinkInfo.Clear()
	n.LinkFailures = 0
}

// HandleLinkRequest processes a received MLE Link Request message.
//
// A Link Request is sent by peer routers/leaders to establish or
// re-verify a bidirectional link. On success, this handler sends a
// Link Accept (or Link Accept And Request) in reply.
//
// This is a Go port of OpenThread's Mle::HandleLinkRequest
// (src/core/thread/mle_ftd.cpp, lines 647-756).
func (h *FtdLinkHandlers) HandleLinkRequest(rxInfo *RxInfo) error {
	// 1. Role check: must be Router or Leader to process Link Requests.
	if !h.mle.IsRouterOrLeader() {
		return fmt.Errorf("mle: link request received while not router or leader (role=%s)",
			h.mle.Role())
	}

	// 2. Parse required TLVs.

	// Challenge — required.
	challengeVal, ok := FindTLV(rxInfo.TLVs, TLVChallenge)
	if !ok {
		return fmt.Errorf("mle: link request missing Challenge TLV")
	}
	challenge, err := ReadChallengeTLV(challengeVal)
	if err != nil {
		return fmt.Errorf("mle: link request: %w", err)
	}

	// Version — required.
	versionVal, ok := FindTLV(rxInfo.TLVs, TLVVersion)
	if !ok {
		return fmt.Errorf("mle: link request missing Version TLV")
	}
	_, err = ReadVersionTLV(versionVal)
	if err != nil {
		return fmt.Errorf("mle: link request: %w", err)
	}

	// 3. Parse optional TLVs.

	// Source Address — optional (present when sender has an allocated RLOC16).
	var sourceAddr uint16
	hasSourceAddr := false
	if srcAddrVal, ok := FindTLV(rxInfo.TLVs, TLVSourceAddress); ok {
		sourceAddr, err = ReadSourceAddressTLV(srcAddrVal)
		if err != nil {
			return fmt.Errorf("mle: link request: %w", err)
		}
		hasSourceAddr = true
	}

	// Leader Data — optional. If present, the partition ID must match ours.
	if leaderDataVal, ok := FindTLV(rxInfo.TLVs, TLVLeaderData); ok {
		leaderData, err := ReadLeaderDataTLV(leaderDataVal)
		if err != nil {
			return fmt.Errorf("mle: link request: %w", err)
		}
		localLeaderData := h.mle.GetLeaderData()
		if leaderData.PartitionID != localLeaderData.PartitionID {
			return fmt.Errorf("mle: link request partition ID mismatch: got %d, local %d",
				leaderData.PartitionID, localLeaderData.PartitionID)
		}
	}

	// TLV Request — optional raw bytes listing requested TLV types.
	var tlvRequestVal []uint8
	if reqVal, ok := FindTLV(rxInfo.TLVs, TLVTLVRequest); ok {
		tlvRequestVal = reqVal
	}

	// 4. Source Address handling — determines the router entry.
	var router *Router

	if hasSourceAddr {
		// Sender has an allocated RLOC16.
		if !IsRouterRLOC16(sourceAddr) {
			return fmt.Errorf("mle: link request source address 0x%04X is not a router RLOC16",
				sourceAddr)
		}

		router = h.routerLookup.FindRouterByRLOC16(sourceAddr)
		if router == nil {
			return fmt.Errorf("mle: link request from unknown router RLOC16 0x%04X",
				sourceAddr)
		}

		switch {
		case router.State != StateValid:
			// Router is not yet fully established — initialize and move
			// to the LinkRequest state.
			initNeighbor(&router.Neighbor, rxInfo)
			router.State = StateLinkRequest
			router.ClearLinkAcceptTimeout()
		case router.MacAddr != rxInfo.SrcAddr:
			// Router is already valid but the extended address does not match.
			return fmt.Errorf("mle: link request MAC address mismatch for router 0x%04X: "+
				"expected %v, got %v", sourceAddr, router.MacAddr, rxInfo.SrcAddr)
		}
	} else {
		// No Source Address — this is a recently-reset router that does not
		// yet have an RLOC16. It must be a known neighbor with a router RLOC16.
		if rxInfo.Neighbor == nil {
			return fmt.Errorf("mle: link request without source address from unknown neighbor")
		}
		if !IsRouterRLOC16(rxInfo.Neighbor.RLOC16) {
			return fmt.Errorf("mle: link request without source address from non-router RLOC16 0x%04X",
				rxInfo.Neighbor.RLOC16)
		}
	}

	// 5. Build the LinkAcceptInfo for the response.
	acceptInfo := LinkAcceptInfo{
		ExtAddress:    rxInfo.SrcAddr,
		RxChallenge:   challenge,
		RequestedTLVs: tlvRequestVal,
		LinkMargin:    rxInfo.LinkMarginRaw,
	}

	// 6. Send the Link Accept (or Link Accept And Request) reply.
	//
	// For multicast-received Link Requests, delay the response by a random
	// 0–MaxLinkAcceptDelay to avoid collisions when multiple routers reply.
	// For unicast requests, send immediately.

	if rxInfo.DstIP.IsMulticast() {
		delay := time.Duration(rand.IntN(int(MaxLinkAcceptDelay.Milliseconds()))) * time.Millisecond
		rloc16 := uint16(0)
		if router != nil {
			rloc16 = router.RLOC16
		}
		h.scheduleLinkAccept(acceptInfo, rloc16, delay)
		return nil
	}

	if err := SendLinkAccept(h.mle, h.dispatcher, h.keyMgr, &acceptInfo, router, h.routeData); err != nil {
		return fmt.Errorf("mle: link request: failed to send link accept: %w", err)
	}

	return nil
}

// scheduleLinkAccept queues a delayed Link Accept response.
func (h *FtdLinkHandlers) scheduleLinkAccept(info LinkAcceptInfo, rloc16 uint16, delay time.Duration) {
	h.pendingAccepts = append(h.pendingAccepts, pendingLinkAccept{
		info:   info,
		rloc16: rloc16,
		sendAt: time.Now().Add(delay),
	})
}

// FlushPendingAccepts sends any pending Link Accept messages whose
// scheduled delay has elapsed. Returns the number sent and the first
// error encountered, if any.
func (h *FtdLinkHandlers) FlushPendingAccepts() (int, error) {
	now := time.Now()
	sent := 0
	var remaining []pendingLinkAccept
	var firstErr error

	for _, pa := range h.pendingAccepts {
		if now.Before(pa.sendAt) {
			remaining = append(remaining, pa)
			continue
		}

		// Re-lookup router by RLOC16 at send time for safety — the
		// router entry may have changed between queue and flush.
		var router *Router
		if pa.rloc16 != 0 {
			router = h.routerLookup.FindRouterByRLOC16(pa.rloc16)
		}

		if err := SendLinkAccept(h.mle, h.dispatcher, h.keyMgr, &pa.info, router, h.routeData); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		} else {
			sent++
		}
	}

	h.pendingAccepts = remaining
	return sent, firstErr
}

// SendAllPendingAccepts immediately sends all pending Link Accepts,
// ignoring delays. This is primarily useful for testing.
func (h *FtdLinkHandlers) SendAllPendingAccepts() (int, error) {
	sent := 0
	var firstErr error

	for _, pa := range h.pendingAccepts {
		var router *Router
		if pa.rloc16 != 0 {
			router = h.routerLookup.FindRouterByRLOC16(pa.rloc16)
		}

		if err := SendLinkAccept(h.mle, h.dispatcher, h.keyMgr, &pa.info, router, h.routeData); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		} else {
			sent++
		}
	}

	h.pendingAccepts = nil
	return sent, firstErr
}

// PendingAcceptCount returns the number of unsent Link Accepts.
func (h *FtdLinkHandlers) PendingAcceptCount() int {
	return len(h.pendingAccepts)
}
