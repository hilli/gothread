// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file implements the router-side Data Request handler and Data Response
// sender for MLE.
//
// When a child sends a Data Request to its parent (router/leader), the parent
// processes the request, compares timestamps to determine what data the child
// needs, and replies with a Data Response containing the requested TLVs.
//
// This is a Go port of OpenThread's HandleDataRequest (mle_ftd.cpp:2579-2634)
// and SendDataResponse (mle_ftd.cpp:3115-3175).

package mle

import (
	"fmt"

	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/net/ip6"
)

// DataRequestHandler implements the router-side handling of MLE Data Request
// messages received from children, and the sending of Data Response messages.
type DataRequestHandler struct {
	mle        *Mle
	dispatcher *Dispatcher
	keyMgr     KeyProvider
	childTable *ChildTable
	datasets   DatasetProvider
}

// NewDataRequestHandler creates a new DataRequestHandler and registers the
// CommandDataRequest handler with the dispatcher.
func NewDataRequestHandler(
	mle *Mle,
	dispatcher *Dispatcher,
	keyMgr KeyProvider,
	childTable *ChildTable,
	datasets DatasetProvider,
) *DataRequestHandler {
	h := &DataRequestHandler{
		mle:        mle,
		dispatcher: dispatcher,
		keyMgr:     keyMgr,
		childTable: childTable,
		datasets:   datasets,
	}

	dispatcher.RegisterHandler(CommandDataRequest, h.HandleDataRequest)

	return h
}

// HandleDataRequest processes a Data Request received by a router or leader
// from one of its children.
//
// Required TLVs: TLV Request.
// Optional TLVs: Active Timestamp, Pending Timestamp.
//
// The handler verifies the sender is a known child in StateValid, reads the
// TLV Request TLV to determine what data the child needs, compares timestamp
// TLVs to determine whether dataset TLVs should be added, and sends a Data
// Response.
//
// This is a Go port of OpenThread's Mle::HandleDataRequest
// (mle_ftd.cpp:2579-2634).
func (h *DataRequestHandler) HandleDataRequest(rxInfo *RxInfo) error {
	// 1. Must be a router or leader.
	if !h.mle.IsRouterOrLeader() {
		return fmt.Errorf("mle: data request received while not router or leader")
	}

	// 2. Look up the child by extended address.
	child := h.childTable.FindChild(rxInfo.SrcAddr)
	if child == nil {
		return fmt.Errorf("mle: data request from unknown child %v", rxInfo.SrcAddr)
	}

	// 3. Child must be in StateValid.
	if child.State != StateValid {
		return fmt.Errorf("mle: data request from child in state %v, want StateValid", child.State)
	}

	// 4. Parse required TLV Request TLV — the list of TLV types the child
	// is requesting.
	tlvRequestVal, ok := FindTLV(rxInfo.TLVs, TLVTLVRequest)
	if !ok {
		return fmt.Errorf("mle: data request missing TLV Request TLV")
	}
	requestedTLVs := make([]uint8, len(tlvRequestVal))
	copy(requestedTLVs, tlvRequestVal)

	// 5. Check Active Timestamp: if the child's timestamp is absent or
	// doesn't match ours, add TLVActiveDataset to the response list.
	if activeVal, hasActive := FindTLV(rxInfo.TLVs, TLVActiveTimestamp); hasActive {
		childTS, err := ReadActiveTimestampTLV(activeVal)
		if err == nil {
			localTS := h.getActiveTimestamp()
			if meshcop.Compare(childTS, localTS) != 0 {
				requestedTLVs = appendIfMissing(requestedTLVs, TLVActiveDataset)
			}
		}
	} else {
		// Absent timestamp — child needs the dataset.
		requestedTLVs = appendIfMissing(requestedTLVs, TLVActiveDataset)
	}

	// 6. Check Pending Timestamp: same logic as Active Timestamp.
	if pendingVal, hasPending := FindTLV(rxInfo.TLVs, TLVPendingTimestamp); hasPending {
		childTS, err := ReadPendingTimestampTLV(pendingVal)
		if err == nil {
			localTS := h.getPendingTimestamp()
			if meshcop.Compare(childTS, localTS) != 0 {
				requestedTLVs = appendIfMissing(requestedTLVs, TLVPendingDataset)
			}
		}
	} else {
		// Absent timestamp — child needs the dataset.
		requestedTLVs = appendIfMissing(requestedTLVs, TLVPendingDataset)
	}

	// 7. Send the Data Response.
	dstIP := ip6.Address(linkLocalIPFromExtAddress(child.MacAddr))
	return h.SendDataResponse(dstIP, requestedTLVs)
}

// SendDataResponse builds and sends a Data Response message to the given
// destination with the specified TLVs.
//
// It always includes Source Address, Leader Data, Active Timestamp, and
// Pending Timestamp TLVs. For each entry in requestedTLVs, it appends the
// corresponding data: Network Data, Active Dataset, or Pending Dataset.
//
// If the device is not attached or is waiting for fresh network data
// (NeedsNewNetworkData), the response is suppressed.
//
// This is a Go port of OpenThread's Mle::SendDataResponse
// (mle_ftd.cpp:3115-3175).
func (h *DataRequestHandler) SendDataResponse(dstIP ip6.Address, requestedTLVs []uint8) error {
	// Suppress if not attached.
	if !h.mle.IsAttached() {
		return fmt.Errorf("mle: send data response: not attached")
	}

	// Suppress if waiting for new network data.
	if h.mle.NeedsNewNetworkData() {
		return fmt.Errorf("mle: send data response: waiting for new network data")
	}

	msg := NewMessage(CommandDataResponse)

	// Always include Source Address TLV.
	msg.AppendSourceAddressTLV(h.mle.RLOC16())

	// Always include Leader Data TLV.
	msg.AppendLeaderDataTLV(h.mle.GetLeaderData())

	// Always include Active Timestamp TLV.
	activeTS := h.getActiveTimestamp()
	if err := msg.AppendActiveTimestampTLV(activeTS); err != nil {
		return fmt.Errorf("mle: send data response: %w", err)
	}

	// Always include Pending Timestamp TLV.
	pendingTS := h.getPendingTimestamp()
	if err := msg.AppendPendingTimestampTLV(pendingTS); err != nil {
		return fmt.Errorf("mle: send data response: %w", err)
	}

	// Append each requested TLV.
	for _, tlvType := range requestedTLVs {
		switch tlvType {
		case TLVNetworkData:
			// Append empty network data placeholder. A real implementation
			// would include the leader's current network data, filtered by
			// the child's data type (full vs stable).
			msg.AppendNetworkDataTLV(nil)

		case TLVActiveDataset:
			msg.appendTLV(TLVActiveDataset, h.readActiveDataset())

		case TLVPendingDataset:
			msg.appendTLV(TLVPendingDataset, h.readPendingDataset())
		}
	}

	if err := h.dispatcher.SendMessage(msg, dstIP); err != nil {
		return fmt.Errorf("mle: send data response: %w", err)
	}

	return nil
}

// --------------------------------------------------------------------------
// Dataset helper methods
// --------------------------------------------------------------------------

// getActiveTimestamp returns the local Active Timestamp from the dataset
// provider, or a zero-value Timestamp if no provider is configured.
func (h *DataRequestHandler) getActiveTimestamp() *meshcop.Timestamp {
	if h.datasets == nil {
		return &meshcop.Timestamp{}
	}
	ts := h.datasets.GetActiveTimestamp()
	return &ts
}

// getPendingTimestamp returns the local Pending Timestamp from the dataset
// provider, or a zero-value Timestamp if no provider is configured.
func (h *DataRequestHandler) getPendingTimestamp() *meshcop.Timestamp {
	if h.datasets == nil {
		return &meshcop.Timestamp{}
	}
	ts := h.datasets.GetPendingTimestamp()
	return &ts
}

// readActiveDataset returns the serialised Active Dataset bytes from the
// dataset provider, or nil if no provider is configured.
func (h *DataRequestHandler) readActiveDataset() []byte {
	if h.datasets == nil {
		return nil
	}
	return h.datasets.ReadActiveDataset()
}

// readPendingDataset returns the serialised Pending Dataset bytes from the
// dataset provider, or nil if no provider is configured.
func (h *DataRequestHandler) readPendingDataset() []byte {
	if h.datasets == nil {
		return nil
	}
	return h.datasets.ReadPendingDataset()
}

// appendIfMissing appends v to the slice if it is not already present.
func appendIfMissing(s []uint8, v uint8) []uint8 {
	for _, existing := range s {
		if existing == v {
			return s
		}
	}
	return append(s, v)
}
