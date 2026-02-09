// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file implements the router-side Child Update Request handler and
// Child Update Response sender for MLE.
//
// When a child sends a Child Update Request to its parent (router/leader),
// the parent processes the request, updates the child entry, and replies
// with a Child Update Response containing the child's current state.
//
// This is the router/parent side counterpart to the child-side handlers
// in child_handlers.go. Note: this handler does NOT register on the
// dispatcher because child_handlers.go already registers handlers for
// CommandChildUpdateRequest and CommandChildUpdateResponse. The caller
// must route messages here directly.
//
// This is a Go port of OpenThread's HandleChildUpdateRequest (router side)
// from mle_ftd.cpp.

package mle

import (
	"fmt"
	"time"

	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/link"
)

// ChildUpdateRouter implements the router-side handling of MLE Child Update
// Request messages received from children, and the sending of Child Update
// Response messages back to those children.
type ChildUpdateRouter struct {
	mle        *Mle
	dispatcher *Dispatcher
	keyMgr     KeyProvider
	childTable *ChildTable
}

// NewChildUpdateRouter creates a new ChildUpdateRouter.
//
// Unlike other handlers, it does NOT register on the dispatcher because
// child_handlers.go already registers for CommandChildUpdateRequest and
// CommandChildUpdateResponse. The caller is responsible for routing
// received Child Update Requests to HandleChildUpdateRequest when
// operating as a router or leader.
func NewChildUpdateRouter(
	mle *Mle,
	dispatcher *Dispatcher,
	keyMgr KeyProvider,
	childTable *ChildTable,
) *ChildUpdateRouter {
	return &ChildUpdateRouter{
		mle:        mle,
		dispatcher: dispatcher,
		keyMgr:     keyMgr,
		childTable: childTable,
	}
}

// HandleChildUpdateRequest processes a Child Update Request received by a
// router or leader from one of its children.
//
// Required TLVs: Mode.
// Optional TLVs: Challenge, Source Address, Leader Data, Timeout,
// TLV Request, Address Registration.
//
// The handler verifies the sender is a known child in StateValid, updates
// the child entry, and sends a Child Update Response.
//
// If the child is not found but includes a Challenge TLV, a response with
// StatusError is sent to trigger the child to re-attach. If the child is
// not found and no Challenge is present, an error is returned.
func (h *ChildUpdateRouter) HandleChildUpdateRequest(rxInfo *RxInfo) error {
	// 1. Must be a router or leader.
	if !h.mle.IsRouterOrLeader() {
		return fmt.Errorf("mle: child update request received while not router or leader")
	}

	// 2. Parse required Mode TLV.
	modeVal, ok := FindTLV(rxInfo.TLVs, TLVMode)
	if !ok {
		return fmt.Errorf("mle: child update request missing Mode TLV")
	}
	mode, err := ReadModeTLV(modeVal)
	if err != nil {
		return fmt.Errorf("mle: child update request: %w", err)
	}

	// 3. Parse optional Challenge TLV.
	var challenge *Challenge
	if challengeVal, ok := FindTLV(rxInfo.TLVs, TLVChallenge); ok {
		ch, err := ReadChallengeTLV(challengeVal)
		if err != nil {
			return fmt.Errorf("mle: child update request: %w", err)
		}
		challenge = &ch
	}

	// 4. Parse optional Timeout TLV.
	var timeout *uint32
	if timeoutVal, ok := FindTLV(rxInfo.TLVs, TLVTimeout); ok {
		t, err := ReadTimeoutTLV(timeoutVal)
		if err != nil {
			return fmt.Errorf("mle: child update request: %w", err)
		}
		timeout = &t
	}

	// 5. Parse optional TLV Request TLV.
	var requestedTLVs []uint8
	if tlvRequestVal, ok := FindTLV(rxInfo.TLVs, TLVTLVRequest); ok {
		requestedTLVs = tlvRequestVal
	}

	// 6. Look up the child by extended address.
	child := h.childTable.FindChild(rxInfo.SrcAddr)

	if child == nil {
		// Unknown child — if Challenge is present, send an error status
		// response to trigger re-attach.
		if challenge != nil {
			return h.SendChildUpdateResponse(rxInfo, nil, challenge, ptrUint8(StatusError), nil)
		}
		return fmt.Errorf("mle: child update request from unknown child %v", rxInfo.SrcAddr)
	}

	// 7. Child must be in StateValid.
	if child.State != StateValid {
		return fmt.Errorf("mle: child update request from child in state %v, want StateValid", child.State)
	}

	// 8. Update child entry.
	child.Mode = mode
	child.LastHeard = time.Now()
	child.KeySequence = rxInfo.KeySequence

	if timeout != nil {
		child.Timeout = *timeout
	}

	// Update link quality from the received link margin.
	child.LinkInfo.SetQualityOut(link.QualityForLinkMargin(rxInfo.LinkMarginRaw))

	// 9. Send the response.
	return h.SendChildUpdateResponse(rxInfo, child, challenge, nil, requestedTLVs)
}

// SendChildUpdateResponse builds and sends a Child Update Response to a
// child.
//
// If child is nil (unknown child case), only Source Address and Status
// are included. If child is non-nil, the response includes Source Address,
// Mode, Leader Data, and optionally Response (if challenge), Status (if
// status), and any requested TLVs.
func (h *ChildUpdateRouter) SendChildUpdateResponse(
	rxInfo *RxInfo,
	child *Child,
	challenge *Challenge,
	status *uint8,
	requestedTLVs []uint8,
) error {
	msg := NewMessage(CommandChildUpdateResponse)

	// Always include our Source Address.
	msg.AppendSourceAddressTLV(h.mle.RLOC16())

	// If a challenge was present, include the Response TLV.
	if challenge != nil {
		msg.AppendResponseTLV(challenge[:])
	}

	// If a status is provided, include it.
	if status != nil {
		msg.AppendStatusTLV(*status)
	}

	// If the child is known, include Mode, Leader Data, and requested TLVs.
	if child != nil {
		msg.AppendModeTLV(child.Mode)
		msg.AppendLeaderDataTLV(h.mle.GetLeaderData())

		for _, tlvType := range requestedTLVs {
			h.appendRequestedTLV(msg, child, tlvType)
		}
	}

	// Determine destination IP.
	var dstIP ip6.Address
	if child != nil {
		dstIP = ip6.Address(linkLocalIPFromExtAddress(child.MacAddr))
	} else {
		dstIP = rxInfo.SrcIP
	}

	if err := h.dispatcher.SendMessage(msg, dstIP); err != nil {
		return fmt.Errorf("mle: send child update response: %w", err)
	}

	return nil
}

// appendRequestedTLV appends a single TLV to the response based on its
// type code. This handles TLV Request processing where the child asks
// for specific TLVs in the response.
func (h *ChildUpdateRouter) appendRequestedTLV(msg *Message, child *Child, tlvType uint8) {
	switch tlvType {
	case TLVTimeout:
		msg.AppendTimeoutTLV(child.Timeout)
	case TLVLinkMargin:
		// The link margin we report back is derived from the child's
		// incoming link quality.
		msg.AppendLinkMarginTLV(child.LinkInfo.GetLinkMargin())
	case TLVSourceAddress:
		msg.AppendSourceAddressTLV(h.mle.RLOC16())
	case TLVLeaderData:
		msg.AppendLeaderDataTLV(h.mle.GetLeaderData())
	case TLVMode:
		msg.AppendModeTLV(child.Mode)
	}
}

// ptrUint8 returns a pointer to the given uint8 value.
func ptrUint8(v uint8) *uint8 {
	return &v
}
