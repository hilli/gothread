// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file implements the router-side Parent Request handler and Parent
// Response sender for MLE.
//
// When a device (child) wants to attach to the Thread network, it sends a
// Parent Request. Routers and leaders that receive this message evaluate
// whether they can accept the child and schedule a Parent Response.
//
// This is a Go port of OpenThread's HandleParentRequest (mle_ftd.cpp:1411-1495)
// and SendParentResponse (mle_ftd.cpp:1769-1813).

package mle

import (
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
)

// Parent Request / Response timing constants from OpenThread mle.hpp.
const (
	// ParentRequestDuplicateTimeout is the minimum time between processing
	// duplicate Parent Requests from the same child (milliseconds).
	ParentRequestDuplicateTimeout = 700 * time.Millisecond

	// ParentResponseMaxDelayRouters is the maximum random delay for
	// sending a Parent Response when the scan mask does NOT include the
	// End Device flag (i.e., only routers respond).
	ParentResponseMaxDelayRouters = 500 * time.Millisecond

	// ParentResponseMaxDelayAll is the maximum random delay for
	// sending a Parent Response when the scan mask includes the
	// End Device flag (routers + REEDs respond).
	ParentResponseMaxDelayAll = 1000 * time.Millisecond

	// ChildIDRequestTimeout is the timeout waiting for a Child ID Request
	// after sending a Parent Response.
	ChildIDRequestTimeout = 5000 * time.Millisecond
)

// ParentResponseInfo carries the information needed to send a delayed
// Parent Response to a specific child.
type ParentResponseInfo struct {
	// ChildExtAddress is the extended MAC address of the child that
	// sent the Parent Request.
	ChildExtAddress types.ExtAddress

	// RxChallenge is the challenge received in the Parent Request,
	// which must be echoed in the Response TLV of the Parent Response.
	RxChallenge Challenge
}

// ConnectivityProvider supplies the connectivity data needed to build
// the Connectivity TLV in a Parent Response. This allows the handler to
// compute the TLV without importing the routing package.
type ConnectivityProvider interface {
	// GetConnectivityTLV returns the Connectivity TLV data reflecting
	// the current router state (link quality counts, leader cost,
	// active routers, etc.).
	GetConnectivityTLV() ConnectivityTLV
}

// ParentRequestHandler implements the router-side handling of MLE Parent
// Request messages and the sending of Parent Response messages.
type ParentRequestHandler struct {
	mle          *Mle
	dispatcher   *Dispatcher
	keyMgr       KeyProvider
	childTable   *ChildTable
	connectivity ConnectivityProvider

	// pendingResponses holds scheduled but not yet sent Parent Responses.
	// In a real implementation these would be dispatched after a random
	// delay by a timer. For now we store them and provide a method to
	// flush/send them.
	pendingResponses []pendingParentResponse
}

// pendingParentResponse holds a scheduled Parent Response with its send time.
type pendingParentResponse struct {
	info    ParentResponseInfo
	sendAt  time.Time
	dstAddr ip6.Address
}

// NewParentRequestHandler creates a new ParentRequestHandler and registers
// the CommandParentRequest handler with the dispatcher.
func NewParentRequestHandler(
	mle *Mle,
	dispatcher *Dispatcher,
	keyMgr KeyProvider,
	childTable *ChildTable,
	connectivity ConnectivityProvider,
) *ParentRequestHandler {
	h := &ParentRequestHandler{
		mle:          mle,
		dispatcher:   dispatcher,
		keyMgr:       keyMgr,
		childTable:   childTable,
		connectivity: connectivity,
	}

	dispatcher.RegisterHandler(CommandParentRequest, h.HandleParentRequest)

	return h
}

// HandleParentRequest processes a received MLE Parent Request message.
//
// Required TLVs: Version, ScanMask, Challenge.
//
// The handler validates that this device is eligible to respond (must be
// a router or leader, not detached/attaching, with a valid path to the
// leader), then looks up or allocates a child entry and schedules a
// delayed Parent Response.
//
// This is a Go port of OpenThread's Mle::HandleParentRequest
// (mle_ftd.cpp:1411-1495).
func (h *ParentRequestHandler) HandleParentRequest(rxInfo *RxInfo) error {
	// 1. Must be a router or leader to respond to Parent Requests.
	if !h.mle.IsRouterOrLeader() {
		return fmt.Errorf("mle: parent request received while not router or leader (role=%s)",
			h.mle.Role())
	}

	// 2. Must not be detached or in an attaching state.
	if h.mle.GetAttachState() != AttachStateIdle {
		return fmt.Errorf("mle: parent request received while attaching")
	}

	// 3. Parse required TLVs.

	// Version TLV.
	versionVal, ok := FindTLV(rxInfo.TLVs, TLVVersion)
	if !ok {
		return fmt.Errorf("mle: parent request missing Version TLV")
	}
	version, err := ReadVersionTLV(versionVal)
	if err != nil {
		return fmt.Errorf("mle: parent request: %w", err)
	}

	// ScanMask TLV.
	scanMaskVal, ok := FindTLV(rxInfo.TLVs, TLVScanMask)
	if !ok {
		return fmt.Errorf("mle: parent request missing ScanMask TLV")
	}
	scanMask, err := ReadScanMaskTLV(scanMaskVal)
	if err != nil {
		return fmt.Errorf("mle: parent request: %w", err)
	}

	// Challenge TLV.
	challengeVal, ok := FindTLV(rxInfo.TLVs, TLVChallenge)
	if !ok {
		return fmt.Errorf("mle: parent request missing Challenge TLV")
	}
	challenge, err := ReadChallengeTLV(challengeVal)
	if err != nil {
		return fmt.Errorf("mle: parent request: %w", err)
	}

	// 4. Validate scan mask against our role.
	//    If the child is scanning for routers only, we must be a Router or Leader.
	//    If the child is scanning for end devices (REEDs), we could be a REED
	//    (but since we only handle Router/Leader, this always passes).
	role := h.mle.Role()

	if role == RoleRouter || role == RoleLeader {
		// Check that the router flag is set in the scan mask.
		if scanMask&ScanMaskRouterFlag == 0 {
			return fmt.Errorf("mle: parent request scan mask does not include routers")
		}
	}

	// 5. Look up existing child entry by extended address.
	childExtAddr := rxInfo.SrcAddr
	child := h.childTable.FindChild(childExtAddr)

	if child != nil {
		// Existing child found. Check for duplicate Parent Request
		// (suppress if received too recently).
		if child.State == StateParentRequest {
			timeSinceLastHeard := time.Since(child.LastHeard)
			if timeSinceLastHeard < ParentRequestDuplicateTimeout {
				return nil // Suppress duplicate.
			}
		}
	} else {
		// Allocate a new child entry.
		child = h.childTable.GetNewChild()
		if child == nil {
			return fmt.Errorf("mle: parent request: child table full")
		}

		// Initialize the child entry.
		initNeighbor(&child.Neighbor, rxInfo)
	}

	// 6. Update child state.
	child.MacAddr = childExtAddr
	child.State = StateParentRequest
	child.Version = version
	child.PendingChallenge = challenge
	child.LastHeard = time.Now()
	child.KeySequence = rxInfo.KeySequence
	child.Counters = FrameCounters{
		MleFrameCounter: rxInfo.FrameCounter,
	}

	// 7. Schedule a delayed Parent Response.
	maxDelay := ParentResponseMaxDelayRouters
	if scanMask&ScanMaskEndDeviceFlag != 0 {
		maxDelay = ParentResponseMaxDelayAll
	}

	delay := time.Duration(rand.IntN(int(maxDelay.Milliseconds()))) * time.Millisecond

	info := ParentResponseInfo{
		ChildExtAddress: childExtAddr,
		RxChallenge:     challenge,
	}

	dstIP := ip6.Address(linkLocalIPFromExtAddress(childExtAddr))

	h.scheduleParentResponse(info, dstIP, delay)

	return nil
}

// SendParentResponse builds and sends a Parent Response message to a child.
//
// Required TLVs: SourceAddress, LeaderData, LinkFrameCounter,
// MleFrameCounter, Response, Challenge, LinkMargin, Connectivity, Version.
//
// This is a Go port of OpenThread's Mle::SendParentResponse
// (mle_ftd.cpp:1769-1813).
func (h *ParentRequestHandler) SendParentResponse(info ParentResponseInfo, dstIP ip6.Address) error {
	// Look up the child to verify it's still in our table.
	child := h.childTable.FindChild(info.ChildExtAddress)
	if child == nil {
		return fmt.Errorf("mle: send parent response: child not found")
	}

	// Build the message.
	msg := NewMessage(CommandParentResponse)

	// Source Address TLV — our RLOC16.
	msg.AppendSourceAddressTLV(h.mle.RLOC16())

	// Leader Data TLV.
	msg.AppendLeaderDataTLV(h.mle.GetLeaderData())

	// Link Frame Counter TLV.
	msg.AppendLinkFrameCounterTLV(h.keyMgr.GetMacFrameCounter())

	// MLE Frame Counter TLV.
	msg.AppendMleFrameCounterTLV(h.keyMgr.GetMleFrameCounter())

	// Response TLV — echo the child's challenge.
	msg.AppendResponseTLV(info.RxChallenge[:])

	// Challenge TLV — generate a new challenge for the child.
	var ourChallenge Challenge
	ourChallenge.GenerateChallenge()
	msg.AppendChallengeTLV(ourChallenge)

	// Store the challenge in the child's PendingChallenge so we can
	// verify the child's response in the Child ID Request.
	child.PendingChallenge = ourChallenge

	// Link Margin TLV — the received link margin from the child.
	msg.AppendLinkMarginTLV(child.LinkInfo.GetLinkMargin())

	// Connectivity TLV.
	if h.connectivity != nil {
		connectivity := h.connectivity.GetConnectivityTLV()
		msg.AppendConnectivityTLV(connectivity)
	}

	// Version TLV.
	msg.AppendVersionTLV(ThreadVersion)

	// Send the message.
	if err := h.dispatcher.SendMessage(msg, dstIP); err != nil {
		return fmt.Errorf("mle: send parent response: %w", err)
	}

	return nil
}

// scheduleParentResponse adds a Parent Response to the pending queue with
// the given delay. In a real implementation this would use a timer.
func (h *ParentRequestHandler) scheduleParentResponse(info ParentResponseInfo, dstIP ip6.Address, delay time.Duration) {
	h.pendingResponses = append(h.pendingResponses, pendingParentResponse{
		info:    info,
		sendAt:  time.Now().Add(delay),
		dstAddr: dstIP,
	})
}

// FlushPendingResponses sends any pending Parent Responses whose delay
// has elapsed. Returns the number of responses sent and any error from
// the first failure.
func (h *ParentRequestHandler) FlushPendingResponses() (int, error) {
	now := time.Now()
	sent := 0
	var remaining []pendingParentResponse
	var firstErr error

	for _, pr := range h.pendingResponses {
		if now.After(pr.sendAt) || now.Equal(pr.sendAt) {
			if err := h.SendParentResponse(pr.info, pr.dstAddr); err != nil {
				if firstErr == nil {
					firstErr = err
				}
			} else {
				sent++
			}
		} else {
			remaining = append(remaining, pr)
		}
	}

	h.pendingResponses = remaining
	return sent, firstErr
}

// SendAllPendingResponses immediately sends all pending Parent Responses,
// ignoring delays. This is primarily useful for testing.
func (h *ParentRequestHandler) SendAllPendingResponses() (int, error) {
	sent := 0
	var firstErr error

	for _, pr := range h.pendingResponses {
		if err := h.SendParentResponse(pr.info, pr.dstAddr); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		} else {
			sent++
		}
	}

	h.pendingResponses = nil
	return sent, firstErr
}

// PendingResponseCount returns the number of unsent Parent Responses.
func (h *ParentRequestHandler) PendingResponseCount() int {
	return len(h.pendingResponses)
}
