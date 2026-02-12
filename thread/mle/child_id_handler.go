// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file implements the router-side Child ID Request handler and Child ID
// Response sender for MLE.
//
// When a child has selected a parent (via Parent Request / Response), it
// sends a Child ID Request to complete the attachment. The router processes
// this request, allocates an RLOC16, and replies with a Child ID Response
// containing the assigned address and any requested TLVs.
//
// This is a Go port of OpenThread's HandleChildIdRequest (mle_ftd.cpp:2053-2212)
// and SendChildIdResponse (mle_ftd.cpp:2861-2935).

package mle

import (
	"fmt"
	"time"

	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/net/ip6"
)

// ChildIDHandler implements the router-side handling of MLE Child ID Request
// messages and the sending of Child ID Response messages.
type ChildIDHandler struct {
	mle         *Mle
	dispatcher  *Dispatcher
	keyMgr      KeyProvider
	childTable  *ChildTable
	datasets    DatasetProvider
	networkData NetworkDataProvider
}

// NewChildIDHandler creates a new ChildIDHandler and registers the
// CommandChildIDRequest handler with the dispatcher.
func NewChildIDHandler(
	mle *Mle,
	dispatcher *Dispatcher,
	keyMgr KeyProvider,
	childTable *ChildTable,
	datasets DatasetProvider,
	networkData NetworkDataProvider,
) *ChildIDHandler {
	h := &ChildIDHandler{
		mle:         mle,
		dispatcher:  dispatcher,
		keyMgr:      keyMgr,
		childTable:  childTable,
		datasets:    datasets,
		networkData: networkData,
	}

	dispatcher.RegisterHandler(CommandChildIDRequest, h.HandleChildIDRequest)

	return h
}

// HandleChildIDRequest processes a received MLE Child ID Request message.
//
// Required TLVs: Response, LinkFrameCounter, Mode, Timeout, Version.
// Optional TLVs: MleFrameCounter (defaults to LinkFrameCounter if absent),
// TLVRequest.
//
// The handler verifies the Response TLV matches the child's PendingChallenge
// from the Parent Response, updates the child entry, and sends a Child ID
// Response if the device is a router or leader.
//
// This is a Go port of OpenThread's Mle::HandleChildIdRequest
// (mle_ftd.cpp:2053-2212).
func (h *ChildIDHandler) HandleChildIDRequest(rxInfo *RxInfo) error {
	// 1. Must be router-eligible, attached, and not mid-attach.
	if !h.mle.IsRouterEligible() {
		return fmt.Errorf("mle: child id request received while not router-eligible")
	}
	if !h.mle.IsAttached() {
		return fmt.Errorf("mle: child id request received while not attached")
	}
	if h.mle.GetAttachState() != AttachStateIdle {
		return fmt.Errorf("mle: child id request received while attaching")
	}

	// 2. Parse required TLVs.

	// Response TLV.
	responseVal, ok := FindTLV(rxInfo.TLVs, TLVResponse)
	if !ok {
		return fmt.Errorf("mle: child id request missing Response TLV")
	}

	// Version TLV.
	versionVal, ok := FindTLV(rxInfo.TLVs, TLVVersion)
	if !ok {
		return fmt.Errorf("mle: child id request missing Version TLV")
	}
	version, err := ReadVersionTLV(versionVal)
	if err != nil {
		return fmt.Errorf("mle: child id request: %w", err)
	}

	// Link Frame Counter TLV.
	linkCounterVal, ok := FindTLV(rxInfo.TLVs, TLVLinkFrameCounter)
	if !ok {
		return fmt.Errorf("mle: child id request missing LinkFrameCounter TLV")
	}
	linkFrameCounter, err := ReadLinkFrameCounterTLV(linkCounterVal)
	if err != nil {
		return fmt.Errorf("mle: child id request: %w", err)
	}

	// MLE Frame Counter TLV (optional, defaults to LinkFrameCounter).
	mleFrameCounter := linkFrameCounter
	mleCounterVal, hasMle := FindTLV(rxInfo.TLVs, TLVMleFrameCounter)
	if hasMle {
		mleFrameCounter, err = ReadMleFrameCounterTLV(mleCounterVal)
		if err != nil {
			return fmt.Errorf("mle: child id request: %w", err)
		}
	}

	// Mode TLV.
	modeVal, ok := FindTLV(rxInfo.TLVs, TLVMode)
	if !ok {
		return fmt.Errorf("mle: child id request missing Mode TLV")
	}
	mode, err := ReadModeTLV(modeVal)
	if err != nil {
		return fmt.Errorf("mle: child id request: %w", err)
	}

	// Timeout TLV.
	timeoutVal, ok := FindTLV(rxInfo.TLVs, TLVTimeout)
	if !ok {
		return fmt.Errorf("mle: child id request missing Timeout TLV")
	}
	timeout, err := ReadTimeoutTLV(timeoutVal)
	if err != nil {
		return fmt.Errorf("mle: child id request: %w", err)
	}

	// TLV Request TLV (optional).
	var requestTLVTypes []uint8
	tlvRequestVal, hasRequest := FindTLV(rxInfo.TLVs, TLVTLVRequest)
	if hasRequest {
		requestTLVTypes = tlvRequestVal // Each byte is a requested TLV type.
	}

	// 3. Look up the child by extended address.
	child := h.childTable.FindChild(rxInfo.SrcAddr)
	if child == nil {
		return fmt.Errorf("mle: child id request from unknown child %v", rxInfo.SrcAddr)
	}

	// 4. Verify the Response TLV matches the child's PendingChallenge.
	if len(responseVal) < ChallengeSize {
		return fmt.Errorf("mle: child id request Response TLV too short: %d", len(responseVal))
	}
	var rxResponse Challenge
	copy(rxResponse[:], responseVal[:ChallengeSize])
	if rxResponse != child.PendingChallenge {
		return fmt.Errorf("mle: child id request response mismatch")
	}

	// 5. Update child entry.
	child.Counters = FrameCounters{
		LinkFrameCounter: linkFrameCounter,
		MleFrameCounter:  mleFrameCounter,
	}
	child.Mode = mode
	child.Timeout = timeout
	child.Version = version
	child.KeySequence = rxInfo.KeySequence
	child.LastHeard = time.Now()
	child.State = StateChildIDRequest

	// Store requested TLV types.
	child.SetRequestTLVs(requestTLVTypes)

	// 6. If we are a router or leader, send the Child ID Response immediately.
	if h.mle.IsRouterOrLeader() {
		return h.SendChildIDResponse(child)
	}

	return nil
}

// SendChildIDResponse builds and sends a Child ID Response message to the
// given child.
//
// It allocates an RLOC16 for the child, appends the required TLVs
// (SourceAddress, LeaderData, Address16), iterates over the child's
// requested TLVs to include optional data (NetworkData, Route64,
// ActiveTimestamp, PendingTimestamp, SupervisionInterval), and sets the
// child state to StateValid.
//
// This is a Go port of OpenThread's Mle::SendChildIdResponse
// (mle_ftd.cpp:2861-2935).
func (h *ChildIDHandler) SendChildIDResponse(child *Child) error {
	// Allocate an RLOC16 for the child if it doesn't already have one
	// with a matching router ID.
	routerRLOC16 := h.mle.RLOC16()
	if !RouterIDMatch(child.RLOC16, routerRLOC16) || child.RLOC16 == 0 {
		rloc16, ok := h.childTable.AllocateChildRLOC16(routerRLOC16)
		if !ok {
			return fmt.Errorf("mle: send child id response: no child ID available")
		}
		child.RLOC16 = rloc16
	}

	// Build the message.
	msg := NewMessage(CommandChildIDResponse)

	// Source Address TLV — our RLOC16.
	msg.AppendSourceAddressTLV(routerRLOC16)

	// Leader Data TLV.
	msg.AppendLeaderDataTLV(h.mle.GetLeaderData())

	// Address16 TLV — the child's assigned RLOC16.
	msg.AppendAddress16TLV(child.RLOC16)

	// Append requested TLVs.
	for _, tlvType := range child.GetRequestTLVs() {
		switch tlvType {
		case TLVNetworkData:
			msg.AppendNetworkDataTLV(h.getNetworkData())

		case TLVRoute64:
			// Route64 would be appended from the router table.
			// Omitted here — a real implementation fills it in.

		case TLVActiveTimestamp:
			ts := h.getActiveTimestamp()
			if ts.IsValid() {
				_ = msg.AppendActiveTimestampTLV(ts)
			}

		case TLVPendingTimestamp:
			ts := h.getPendingTimestamp()
			if ts.IsValid() {
				_ = msg.AppendPendingTimestampTLV(ts)
			}

		case TLVSupervisionInterval:
			msg.AppendSupervisionIntervalTLV(child.SupervisionInterval)
		}
	}

	// Set child state to Valid.
	child.State = StateValid

	// Send the message.
	dstIP := ip6.Address(linkLocalIPFromExtAddress(child.MacAddr))
	if err := h.dispatcher.SendMessage(msg, dstIP); err != nil {
		return fmt.Errorf("mle: send child id response: %w", err)
	}

	return nil
}

// --------------------------------------------------------------------------
// Dataset helper methods
// --------------------------------------------------------------------------

// getActiveTimestamp returns the local Active Timestamp from the dataset
// provider, or a zero-value Timestamp if no provider is configured.
func (h *ChildIDHandler) getActiveTimestamp() *meshcop.Timestamp {
	if h.datasets == nil {
		return &meshcop.Timestamp{}
	}
	ts := h.datasets.GetActiveTimestamp()
	return &ts
}

// getPendingTimestamp returns the local Pending Timestamp from the dataset
// provider, or a zero-value Timestamp if no provider is configured.
func (h *ChildIDHandler) getPendingTimestamp() *meshcop.Timestamp {
	if h.datasets == nil {
		return &meshcop.Timestamp{}
	}
	ts := h.datasets.GetPendingTimestamp()
	return &ts
}

// getNetworkData returns the current network data bytes from the provider,
// or nil if no provider is configured.
func (h *ChildIDHandler) getNetworkData() []byte {
	if h.networkData == nil {
		return nil
	}
	return h.networkData.GetNetworkData(false)
}
