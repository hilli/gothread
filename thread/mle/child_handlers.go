// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file implements MLE message handlers for the child role:
// Advertisement, Data Response, Child Update Request/Response.
//
// These are the common handlers used by both MTD and FTD devices
// when operating as a child. FTD-specific router/parent handlers
// (HandleDataRequest, HandleAdvertisementOnFtd, etc.) are not included
// and will be added in a future phase.
//
// This is a Go port of the child-side handlers from OpenThread's
// src/core/thread/mle.cpp.

package mle

import (
	"bytes"
	"fmt"
	"time"

	"github.com/hilli/gothread/thread/link"
)

// ChildHandlers implements MLE message handlers for the child role.
//
// It processes Advertisement, Data Response, and Child Update
// Request/Response messages received from the parent, and provides
// methods to send Data Requests and Child Update messages to the parent.
type ChildHandlers struct {
	mle         *Mle
	dispatcher  *Dispatcher
	datasets    DatasetProvider
	networkData NetworkDataProvider

	// pendingChallenge holds a challenge sent in a Child Update Request
	// (when re-establishing a link with the parent). If empty, no
	// challenge-response exchange is pending.
	pendingChallenge    Challenge
	hasPendingChallenge bool
}

// NewChildHandlers creates a new ChildHandlers instance and registers
// the handler functions with the dispatcher.
func NewChildHandlers(mle *Mle, dispatcher *Dispatcher, datasets DatasetProvider, networkData NetworkDataProvider) *ChildHandlers {
	ch := &ChildHandlers{
		mle:         mle,
		dispatcher:  dispatcher,
		datasets:    datasets,
		networkData: networkData,
	}

	dispatcher.RegisterHandler(CommandDataResponse, ch.HandleDataResponse)
	dispatcher.RegisterHandler(CommandChildUpdateRequest, ch.HandleChildUpdateRequest)
	dispatcher.RegisterHandler(CommandChildUpdateResponse, ch.HandleChildUpdateResponse)

	return ch
}

// --- HandleAdvertisement ---

// HandleAdvertisement processes a received MLE Advertisement.
//
// The child path validates that the advertisement is from the parent,
// checks for partition/leader changes, and schedules a Data Request
// if the network data version has changed.
//
// Required TLVs: SourceAddress, LeaderData.
func (ch *ChildHandlers) HandleAdvertisement(rxInfo *RxInfo) error {
	if !ch.mle.IsAttached() {
		return fmt.Errorf("mle: advertisement received while not attached")
	}

	// Parse required TLVs.
	srcAddrVal, ok := FindTLV(rxInfo.TLVs, TLVSourceAddress)
	if !ok {
		return fmt.Errorf("mle: advertisement missing SourceAddress TLV")
	}
	sourceAddress, err := ReadSourceAddressTLV(srcAddrVal)
	if err != nil {
		return err
	}

	leaderDataVal, ok := FindTLV(rxInfo.TLVs, TLVLeaderData)
	if !ok {
		return fmt.Errorf("mle: advertisement missing LeaderData TLV")
	}
	leaderData, err := ReadLeaderDataTLV(leaderDataVal)
	if err != nil {
		return err
	}

	// Child path: only process advertisements from our parent.
	if !ch.mle.IsChild() {
		// Router/Leader paths are handled in FtdAdvertisementHandler.
		return nil
	}

	parent := ch.mle.GetParent()

	// The advertisement must come from our parent.
	if rxInfo.Neighbor == nil || rxInfo.Neighbor != &parent.Neighbor {
		return nil // Silently ignore advertisements from non-parent.
	}

	// Validate that the parent's RLOC16 matches the advertised source.
	if parent.RLOC16 != sourceAddress {
		return ch.mle.BecomeDetached()
	}

	// Check for partition or leader changes.
	currentLeaderData := ch.mle.GetLeaderData()
	if leaderData.PartitionID != currentLeaderData.PartitionID ||
		leaderData.LeaderRouterID != currentLeaderData.LeaderRouterID {
		ch.mle.SetLeaderData(leaderData)
		ch.mle.SetRetrieveNewNetworkData(true)
	}

	// Check if network data version changed.
	if leaderData.DataVersion != currentLeaderData.DataVersion ||
		leaderData.StableDataVersion != currentLeaderData.StableDataVersion {
		ch.mle.SetLeaderData(leaderData)
		ch.mle.SetRetrieveNewNetworkData(true)
	}

	// Update last heard time.
	parent.LastHeard = time.Now()

	// Schedule a Data Request if needed.
	if ch.mle.NeedsNewNetworkData() {
		ch.mle.SetDataRequestPending(true)
	}

	return nil
}

// --- HandleDataResponse ---

// HandleDataResponse processes a received MLE Data Response.
//
// The child validates the sender, processes leader data and network
// data updates, and clears the pending data request flag.
//
// Required TLVs: LeaderData.
// Optional TLVs: NetworkData, ActiveTimestamp, PendingTimestamp.
func (ch *ChildHandlers) HandleDataResponse(rxInfo *RxInfo) error {
	// Must be from a valid neighbor.
	if rxInfo.Neighbor == nil || !rxInfo.Neighbor.IsStateValid() {
		return fmt.Errorf("mle: data response from unknown or invalid neighbor")
	}

	if !ch.mle.IsAttached() {
		return fmt.Errorf("mle: data response while not attached")
	}

	// Process leader data.
	if err := ch.handleLeaderData(rxInfo); err != nil {
		return err
	}

	return nil
}

// handleLeaderData processes the LeaderData TLV (and optional Network
// Data, timestamp TLVs) from a Data Response or Child Update message.
//
// If the partition ID or leader changed while we're a child, it flags
// that new network data is needed. If network data is present, it clears
// the pending flag.
func (ch *ChildHandlers) handleLeaderData(rxInfo *RxInfo) error {
	leaderDataVal, ok := FindTLV(rxInfo.TLVs, TLVLeaderData)
	if !ok {
		return fmt.Errorf("mle: message missing LeaderData TLV")
	}
	leaderData, err := ReadLeaderDataTLV(leaderDataVal)
	if err != nil {
		return err
	}

	currentLeaderData := ch.mle.GetLeaderData()

	// As a child, if the partition or leader changed, flag for new data.
	if ch.mle.IsChild() {
		if leaderData.PartitionID != currentLeaderData.PartitionID ||
			leaderData.Weighting != currentLeaderData.Weighting ||
			leaderData.LeaderRouterID != currentLeaderData.LeaderRouterID {
			ch.mle.SetLeaderData(leaderData)
			ch.mle.SetRetrieveNewNetworkData(true)
			return nil
		}
	}

	// Update leader data versions.
	ch.mle.SetLeaderData(leaderData)

	// If Network Data TLV is present, mark the data as received.
	if _, hasNetData := FindTLV(rxInfo.TLVs, TLVNetworkData); hasNetData {
		ch.mle.SetRetrieveNewNetworkData(false)
		ch.mle.SetDataRequestPending(false)
	} else if ch.mle.NeedsNewNetworkData() {
		// Network Data was not included — schedule another request.
		ch.mle.SetDataRequestPending(true)
	}

	return nil
}

// --- HandleChildUpdateRequest (child receiving from parent) ---

// HandleChildUpdateRequest processes an MLE Child Update Request
// received by a child from its parent.
//
// The parent sends this to check child liveness, push updated data,
// or request the child to re-register.
//
// Required TLVs: SourceAddress.
// Optional TLVs: Challenge, Status, LeaderData, LinkMargin, TlvRequest.
func (ch *ChildHandlers) HandleChildUpdateRequest(rxInfo *RxInfo) error {
	if !ch.mle.IsAttached() {
		return fmt.Errorf("mle: child update request while not attached")
	}

	// Parse required SourceAddress.
	srcAddrVal, ok := FindTLV(rxInfo.TLVs, TLVSourceAddress)
	if !ok {
		return fmt.Errorf("mle: child update request missing SourceAddress TLV")
	}
	sourceAddress, err := ReadSourceAddressTLV(srcAddrVal)
	if err != nil {
		return err
	}

	// Parse optional Challenge.
	var rxChallenge []byte
	if challengeVal, ok := FindTLV(rxInfo.TLVs, TLVChallenge); ok {
		rxChallenge = challengeVal
	}

	// Check if this is from our parent.
	parent := ch.mle.GetParent()

	if rxInfo.Neighbor == nil || rxInfo.Neighbor != &parent.Neighbor {
		// Not from our parent — send a reject response.
		return ch.sendChildUpdateReject(rxInfo)
	}

	// Check for Status TLV indicating error.
	if statusVal, ok := FindTLV(rxInfo.TLVs, TLVStatus); ok {
		status, err := ReadStatusTLV(statusVal)
		if err != nil {
			return err
		}
		if status == StatusError {
			return ch.mle.BecomeDetached()
		}
	}

	// Validate parent RLOC16.
	if parent.RLOC16 != sourceAddress {
		return ch.mle.BecomeDetached()
	}

	// Process optional LeaderData.
	if rxInfo.Neighbor.IsStateValid() {
		if _, ok := FindTLV(rxInfo.TLVs, TLVLeaderData); ok {
			if err := ch.handleLeaderData(rxInfo); err != nil {
				return err
			}
		}

		// Process optional LinkMargin.
		if linkMarginVal, ok := FindTLV(rxInfo.TLVs, TLVLinkMargin); ok {
			linkMargin, err := ReadLinkMarginTLV(linkMarginVal)
			if err != nil {
				return err
			}
			parent.LinkInfo.SetQualityOut(link.QualityForLinkMargin(linkMargin))
		}
	}

	// Build and send the response.
	return ch.sendChildUpdateResponse(rxInfo, rxChallenge)
}

// sendChildUpdateReject sends a Child Update Response with Status=Error
// to a sender that is not our parent. This tells the sender to remove
// us from its child table.
func (ch *ChildHandlers) sendChildUpdateReject(rxInfo *RxInfo) error {
	msg := NewMessage(CommandChildUpdateResponse)

	msg.AppendSourceAddressTLV(ch.mle.RLOC16())
	msg.AppendStatusTLV(StatusError)

	return ch.dispatcher.SendMessage(msg, rxInfo.SrcIP)
}

// sendChildUpdateResponse builds and sends a Child Update Response
// back to the parent in reply to a Child Update Request.
//
// If a challenge was included in the request, the response includes
// Response, MleFrameCounter, and LinkFrameCounter TLVs.
func (ch *ChildHandlers) sendChildUpdateResponse(rxInfo *RxInfo, rxChallenge []byte) error {
	msg := NewMessage(CommandChildUpdateResponse)

	// Always include SourceAddress and LeaderData.
	msg.AppendSourceAddressTLV(ch.mle.RLOC16())
	msg.AppendLeaderDataTLV(ch.mle.GetLeaderData())

	// If the parent sent a challenge, echo it back with frame counters.
	if len(rxChallenge) > 0 {
		msg.AppendResponseTLV(rxChallenge)
		msg.AppendMleFrameCounterTLV(ch.dispatcher.keyMgr.GetMleFrameCounter())
		msg.AppendLinkFrameCounterTLV(ch.dispatcher.keyMgr.GetMacFrameCounter())
	}

	// Include Mode.
	msg.AppendModeTLV(ch.mle.GetDeviceMode())

	// Include Timeout.
	msg.AppendTimeoutTLV(ch.mle.GetChildTimeout())

	// Process any TlvRequest from the parent.
	if tlvRequestVal, ok := FindTLV(rxInfo.TLVs, TLVTLVRequest); ok {
		for _, reqType := range tlvRequestVal {
			ch.appendRequestedTLV(msg, reqType)
		}
	}

	// Send unicast to parent.
	return ch.dispatcher.SendMessage(msg, rxInfo.SrcIP)
}

// --- HandleChildUpdateResponse (child receiving from parent) ---

// HandleChildUpdateResponse processes an MLE Child Update Response
// received by a child from its parent.
//
// This is the parent's reply to our Child Update Request.
//
// Required TLVs: Mode, SourceAddress (in child role).
// Optional TLVs: Response, Status, LeaderData, Timeout, LinkMargin,
//
//	LinkFrameCounter, MleFrameCounter.
func (ch *ChildHandlers) HandleChildUpdateResponse(rxInfo *RxInfo) error {
	if !ch.mle.IsChild() {
		return fmt.Errorf("mle: child update response while not a child")
	}

	// Parse optional Response TLV.
	var responseVal []byte
	if rv, ok := FindTLV(rxInfo.TLVs, TLVResponse); ok {
		responseVal = rv
	}

	// Must be from our parent and parent must be valid.
	parent := ch.mle.GetParent()
	if rxInfo.Neighbor == nil || rxInfo.Neighbor != &parent.Neighbor {
		return fmt.Errorf("mle: child update response not from parent")
	}
	if !parent.IsStateValid() {
		return fmt.Errorf("mle: child update response from parent in invalid state")
	}

	// If we sent a challenge, verify the response.
	if ch.hasPendingChallenge {
		if !bytes.Equal(responseVal, ch.pendingChallenge[:]) {
			return fmt.Errorf("mle: child update response challenge mismatch")
		}
		ch.hasPendingChallenge = false
	}

	// Check for Status TLV — any status causes detach.
	if _, ok := FindTLV(rxInfo.TLVs, TLVStatus); ok {
		return ch.mle.BecomeDetached()
	}

	// Parse required Mode TLV.
	modeVal, ok := FindTLV(rxInfo.TLVs, TLVMode)
	if !ok {
		return fmt.Errorf("mle: child update response missing Mode TLV")
	}
	mode, err := ReadModeTLV(modeVal)
	if err != nil {
		return err
	}

	// Mode must match our current mode.
	if mode.Get() != ch.mle.GetDeviceMode().Get() {
		return fmt.Errorf("mle: child update response mode mismatch: got %02X, want %02X",
			mode.Get(), ch.mle.GetDeviceMode().Get())
	}

	// Parse required SourceAddress.
	srcAddrVal, ok := FindTLV(rxInfo.TLVs, TLVSourceAddress)
	if !ok {
		return fmt.Errorf("mle: child update response missing SourceAddress TLV")
	}
	sourceAddress, err := ReadSourceAddressTLV(srcAddrVal)
	if err != nil {
		return err
	}

	// Source address must match the parent's router ID.
	if !RouterIDMatch(sourceAddress, parent.RLOC16) {
		return fmt.Errorf("mle: child update response source address mismatch")
	}

	// Process LeaderData.
	if _, ok := FindTLV(rxInfo.TLVs, TLVLeaderData); ok {
		if err := ch.handleLeaderData(rxInfo); err != nil {
			return err
		}
	}

	// Process optional Timeout.
	if timeoutVal, ok := FindTLV(rxInfo.TLVs, TLVTimeout); ok {
		timeout, err := ReadTimeoutTLV(timeoutVal)
		if err != nil {
			return err
		}
		ch.mle.SetChildTimeout(timeout)
	}

	// Process optional LinkMargin.
	if linkMarginVal, ok := FindTLV(rxInfo.TLVs, TLVLinkMargin); ok {
		linkMargin, err := ReadLinkMarginTLV(linkMarginVal)
		if err != nil {
			return err
		}
		parent.LinkInfo.SetQualityOut(link.QualityForLinkMargin(linkMargin))
	}

	return nil
}

// --- Send helpers ---

// MleMaxResponseDelay is the maximum random delay for Data Request scheduling.
const MleMaxResponseDelay = 1000 * time.Millisecond

// SendDataRequest constructs and sends an MLE Data Request to the parent.
//
// TLVs: TlvRequest[NetworkData], ActiveTimestamp, PendingTimestamp.
func (ch *ChildHandlers) SendDataRequest() error {
	if !ch.mle.IsAttached() {
		return fmt.Errorf("mle: cannot send data request while not attached")
	}

	parent := ch.mle.GetParent()
	if !parent.IsStateValid() {
		return fmt.Errorf("mle: cannot send data request: parent not valid")
	}

	msg := NewMessage(CommandDataRequest)

	// Request network data. FTDs also request Route64.
	requestedTLVs := []uint8{TLVNetworkData}
	if ch.mle.GetDeviceMode().IsFullThreadDevice() {
		requestedTLVs = append(requestedTLVs, TLVRoute64)
	}
	msg.AppendTLVRequestTLV(requestedTLVs)

	// Include our timestamps so the parent knows what versions we have.
	if ch.datasets != nil {
		ts := ch.datasets.GetActiveTimestamp()
		if ts.IsValid() {
			_ = msg.AppendActiveTimestampTLV(&ts)
		}
		pts := ch.datasets.GetPendingTimestamp()
		if pts.IsValid() {
			_ = msg.AppendPendingTimestampTLV(&pts)
		}
	}

	dstIP := parentLinkLocalIP(parent.MacAddr)
	return ch.dispatcher.SendMessage(msg, dstIP)
}

// ChildUpdateRequestMode controls what additional TLVs are included in
// a Child Update Request sent to the parent.
type ChildUpdateRequestMode uint8

const (
	// ChildUpdateNormal sends a normal Child Update Request.
	ChildUpdateNormal ChildUpdateRequestMode = 0
	// ChildUpdateAppendChallenge includes a Challenge TLV to re-establish
	// the link with the parent.
	ChildUpdateAppendChallenge ChildUpdateRequestMode = 1
	// ChildUpdateAppendZeroTimeout includes a Timeout of zero to
	// gracefully detach from the parent.
	ChildUpdateAppendZeroTimeout ChildUpdateRequestMode = 2
)

// SendChildUpdateRequest constructs and sends an MLE Child Update Request
// to the parent.
//
// TLVs: Mode, (Challenge), SourceAddress, LeaderData, Timeout.
func (ch *ChildHandlers) SendChildUpdateRequest(mode ChildUpdateRequestMode) error {
	if !ch.mle.IsChild() && mode != ChildUpdateAppendChallenge {
		return fmt.Errorf("mle: cannot send child update request while not a child")
	}

	msg := NewMessage(CommandChildUpdateRequest)

	// Always include Mode.
	msg.AppendModeTLV(ch.mle.GetDeviceMode())

	// Optionally include Challenge.
	if mode == ChildUpdateAppendChallenge {
		ch.pendingChallenge.GenerateChallenge()
		ch.hasPendingChallenge = true
		msg.AppendChallengeTLV(ch.pendingChallenge)
	}

	// Include SourceAddress and LeaderData when we're a child.
	if ch.mle.IsChild() {
		msg.AppendSourceAddressTLV(ch.mle.RLOC16())
		msg.AppendLeaderDataTLV(ch.mle.GetLeaderData())

		// Include Timeout (zero for graceful detach).
		switch mode {
		case ChildUpdateAppendZeroTimeout:
			msg.AppendTimeoutTLV(0)
		default:
			msg.AppendTimeoutTLV(ch.mle.GetChildTimeout())
		}
	}

	parent := ch.mle.GetParent()
	dstIP := parentLinkLocalIP(parent.MacAddr)
	return ch.dispatcher.SendMessage(msg, dstIP)
}

// appendRequestedTLV appends a single TLV to the message based on its
// type code. This handles TLV Request responses where the parent asks
// for specific TLVs in our response.
func (ch *ChildHandlers) appendRequestedTLV(msg *Message, tlvType uint8) {
	switch tlvType {
	case TLVMode:
		msg.AppendModeTLV(ch.mle.GetDeviceMode())
	case TLVTimeout:
		msg.AppendTimeoutTLV(ch.mle.GetChildTimeout())
	case TLVVersion:
		msg.AppendVersionTLV(ThreadVersion)
	case TLVSourceAddress:
		msg.AppendSourceAddressTLV(ch.mle.RLOC16())
	case TLVLeaderData:
		msg.AppendLeaderDataTLV(ch.mle.GetLeaderData())
	case TLVLinkFrameCounter:
		msg.AppendLinkFrameCounterTLV(ch.dispatcher.keyMgr.GetMacFrameCounter())
	case TLVMleFrameCounter:
		msg.AppendMleFrameCounterTLV(ch.dispatcher.keyMgr.GetMleFrameCounter())
	case TLVNetworkData:
		if ch.networkData != nil {
			msg.AppendNetworkDataTLV(ch.networkData.GetNetworkData(false))
		}
	case TLVActiveTimestamp:
		if ch.datasets != nil {
			ts := ch.datasets.GetActiveTimestamp()
			if ts.IsValid() {
				_ = msg.AppendActiveTimestampTLV(&ts)
			}
		}
	case TLVPendingTimestamp:
		if ch.datasets != nil {
			ts := ch.datasets.GetPendingTimestamp()
			if ts.IsValid() {
				_ = msg.AppendPendingTimestampTLV(&ts)
			}
		}
	}
}

// parentLinkLocalIP computes the link-local IPv6 address from an extended
// MAC address using the EUI-64 to modified EUI-64 conversion.
func parentLinkLocalIP(macAddr [8]byte) [16]byte {
	var addr [16]byte
	addr[0] = 0xfe
	addr[1] = 0x80
	addr[8] = macAddr[0] ^ 0x02 // Toggle U/L bit
	addr[9] = macAddr[1]
	addr[10] = macAddr[2]
	addr[11] = macAddr[3]
	addr[12] = macAddr[4]
	addr[13] = macAddr[5]
	addr[14] = macAddr[6]
	addr[15] = macAddr[7]
	return addr
}
