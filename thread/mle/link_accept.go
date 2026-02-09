// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file implements MLE Link Accept and Link Accept And Request message
// building and sending.
//
// A Link Accept is sent in response to a Link Request, confirming the
// bidirectional link. It always includes:
//
//   - Version TLV
//   - Source Address TLV
//   - Response TLV (echoing the Link Request's challenge)
//   - Link Frame Counter TLV
//   - MLE Frame Counter TLV
//   - Link Margin TLV
//
// Conditionally included:
//   - Leader Data TLV (if the router is known)
//   - Route64 TLV (if requested)
//   - Address16 TLV (if requested and router is known)
//
// If the local device also has a pending Link Request to the same peer
// (router is in StateLinkRequest), the command is upgraded to Link Accept
// And Request, which additionally includes:
//   - Challenge TLV (new challenge for the peer)
//   - TLV Request (LinkMargin)
//
// This is a Go port of the Link Accept logic from OpenThread's
// src/core/thread/mle_ftd.cpp (SendLinkAccept).

package mle

import (
	"fmt"

	"github.com/hilli/gothread/mac/types"
)

// LinkAcceptInfo holds the parameters extracted from a received Link Request
// that are needed to build a Link Accept response.
type LinkAcceptInfo struct {
	// ExtAddress is the extended MAC address of the Link Request sender.
	ExtAddress types.ExtAddress

	// RequestedTLVs is the list of TLV types requested in the Link Request.
	RequestedTLVs []uint8

	// RxChallenge is the challenge value from the received Link Request.
	RxChallenge Challenge

	// LinkMargin is the link margin of the received Link Request (dB).
	LinkMargin uint8
}

// BuildLinkAccept constructs an MLE Link Accept (or Link Accept And Request)
// message from the given parameters.
//
// If isAcceptAndRequest is true, the command is CommandLinkAcceptAndRequest
// and a Challenge TLV + TLV Request (LinkMargin) are appended for the
// piggybacked link request.
//
// The routerRLOC16 parameter is the RLOC16 to include in the Address16 TLV
// if it was requested. Set to InvalidRLOC16 to omit even if requested.
//
// The routeData parameters (sequence, mask, entries) are included only if
// TLVRoute64 appears in requestedTLVs.
func BuildLinkAccept(
	isAcceptAndRequest bool,
	rloc16 uint16,
	response Challenge,
	linkFrameCounter uint32,
	mleFrameCounter uint32,
	linkMargin uint8,
	leaderData *LeaderData,
	requestedTLVs []uint8,
	routerRLOC16 uint16,
	routeSequence uint8,
	routeMask RouterIDSet,
	routeEntries []Route64Entry,
	challenge Challenge,
) *Message {
	cmd := CommandLinkAccept
	if isAcceptAndRequest {
		cmd = CommandLinkAcceptAndRequest
	}

	msg := NewMessage(cmd)

	msg.AppendVersionTLV(ThreadVersion)
	msg.AppendSourceAddressTLV(rloc16)
	msg.AppendResponseTLV(response[:])
	msg.AppendLinkFrameCounterTLV(linkFrameCounter)
	msg.AppendMleFrameCounterTLV(mleFrameCounter)
	msg.AppendLinkMarginTLV(linkMargin)

	if leaderData != nil {
		msg.AppendLeaderDataTLV(*leaderData)
	}

	// Append requested TLVs.
	for _, tlvType := range requestedTLVs {
		switch tlvType {
		case TLVRoute64:
			msg.AppendRoute64TLV(routeSequence, routeMask, routeEntries)
		case TLVAddress16:
			if routerRLOC16 != InvalidRLOC16 {
				msg.AppendAddress16TLV(routerRLOC16)
			}
		}
	}

	// For Accept And Request, append our own challenge and TLV request.
	if isAcceptAndRequest {
		msg.AppendChallengeTLV(challenge)
		msg.AppendTLVRequestTLV([]uint8{TLVLinkMargin})
	}

	return msg
}

// SendLinkAccept builds and sends an MLE Link Accept (or Link Accept And
// Request) message in response to a received Link Request.
//
// The router parameter is the Router entry for the Link Request sender.
// If the router's state is StateLinkRequest (meaning we also have a pending
// Link Request to this peer), the command is upgraded to Link Accept And
// Request. In that case, a new challenge is generated and stored on the
// router entry.
//
// If router is nil, the message is sent using only the info's ExtAddress
// for the destination (for cases where the sender is not yet in the router
// table as a known router).
//
// The device must be attached (Child, Router, or Leader). Returns an error
// if the device is not attached or if sending fails.
func SendLinkAccept(
	m *Mle,
	dispatcher *Dispatcher,
	keyMgr KeyProvider,
	info *LinkAcceptInfo,
	router *Router,
	routeData RouteDataProvider,
) error {
	m.mu.RLock()
	role := m.role
	rloc16 := m.rloc16
	leaderData := m.leaderData
	routerID := m.ftd.routerID
	m.mu.RUnlock()

	if role != RoleChild && role != RoleRouter && role != RoleLeader {
		return fmt.Errorf("mle: cannot send link accept in role %s", role)
	}

	// Determine if this should be a combined Accept And Request.
	isAcceptAndRequest := false
	var challenge Challenge

	if router != nil && router.State == StateLinkRequest {
		isAcceptAndRequest = true
		challenge.GenerateChallenge()
		router.PendingChallenge = challenge
	}

	// Only include Leader Data if we know the router.
	var leaderDataPtr *LeaderData
	if router != nil {
		leaderDataPtr = &leaderData
	}

	// For Address16, use the router's RLOC16 if known.
	routerRLOC16 := uint16(InvalidRLOC16)
	if router != nil {
		routerRLOC16 = router.RLOC16
	}

	// Get route data if Route64 was requested.
	var routeSeq uint8
	var routeMask RouterIDSet
	var routeEntries []Route64Entry

	if routeData != nil && containsTLVType(info.RequestedTLVs, TLVRoute64) {
		routeSeq, routeMask, routeEntries = routeData.GetRouteData(routerID, leaderData.LeaderRouterID)
	}

	// Get frame counters.
	linkFC := keyMgr.GetMacFrameCounter()
	mleFC := keyMgr.GetMleFrameCounter()

	msg := BuildLinkAccept(
		isAcceptAndRequest,
		rloc16,
		info.RxChallenge,
		linkFC,
		mleFC,
		info.LinkMargin,
		leaderDataPtr,
		info.RequestedTLVs,
		routerRLOC16,
		routeSeq,
		routeMask,
		routeEntries,
		challenge,
	)

	dst := linkLocalIPFromExtAddress(info.ExtAddress)
	return dispatcher.SendMessage(msg, dst)
}

// containsTLVType checks whether a TLV type appears in a list.
func containsTLVType(types []uint8, target uint8) bool {
	for _, t := range types {
		if t == target {
			return true
		}
	}
	return false
}
