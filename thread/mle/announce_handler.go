// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file implements the MLE Announce handler and sender.
//
// When a Thread device receives an MLE Announce message, it compares the
// received Active Timestamp against its own. Depending on the result, the
// device may ignore the announce, send its own announce back (if its dataset
// is newer), or signal a channel/PAN-ID change (if the received dataset is
// newer).
//
// This is a Go port of OpenThread's HandleAnnounce (mle.cpp:5786-5927) and
// SendAnnounce (mle.cpp:1369-1411).

package mle

import (
	"fmt"

	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/net/ip6"
)

// AnnounceMode controls the type of MLE Announce message.
type AnnounceMode uint8

const (
	// AnnounceNormal is a regular Announce carrying the device's current
	// Active Timestamp, Channel, and PAN ID.
	AnnounceNormal AnnounceMode = 0

	// AnnounceOrphan is sent by an orphan device with a zero-value
	// timestamp to solicit an Announce response from attached devices.
	AnnounceOrphan AnnounceMode = 1
)

// LinkLocalAllNodesMulticast is the IPv6 link-local all-nodes multicast
// address (ff02::1). MLE Announce messages are sent to this address.
var LinkLocalAllNodesMulticast = ip6.Address{
	0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
}

// AnnounceAction describes what the handler decided to do after
// processing an incoming Announce message.
type AnnounceAction uint8

const (
	// AnnounceActionIgnore means the announce was ignored (e.g., orphan
	// announce on the same channel/PAN).
	AnnounceActionIgnore AnnounceAction = 0

	// AnnounceActionSendBack means the device will send its own
	// Announce back because the local dataset is newer.
	AnnounceActionSendBack AnnounceAction = 1

	// AnnounceActionSignal means the received dataset is newer or
	// equal, and the upper layer should be signaled (e.g., to trigger
	// a channel/PAN switch).
	AnnounceActionSignal AnnounceAction = 2
)

// AnnounceHandler implements the handling of MLE Announce messages and
// the sending of MLE Announce messages.
type AnnounceHandler struct {
	mle        *Mle
	dispatcher *Dispatcher
	keyMgr     KeyProvider
	datasets   DatasetProvider
	macInfo    MacInfoProvider

	// LastAction records the action taken by the most recent
	// HandleAnnounce call. Useful for testing and debugging.
	LastAction AnnounceAction

	// LastReceivedChannel records the channel from the most recently
	// received Announce.
	LastReceivedChannel uint16

	// LastReceivedPanID records the PAN ID from the most recently
	// received Announce.
	LastReceivedPanID uint16

	// OnSignal is an optional callback invoked when the handler
	// determines that the received Announce carries a newer (or equal)
	// timestamp and the upper layer should switch channel/PAN.
	// The callback receives the channel and PAN ID from the Announce.
	OnSignal func(channel uint16, panID uint16)
}

// NewAnnounceHandler creates a new AnnounceHandler and registers the
// CommandAnnounce handler with the dispatcher.
func NewAnnounceHandler(
	mle *Mle,
	dispatcher *Dispatcher,
	keyMgr KeyProvider,
	datasets DatasetProvider,
	macInfo MacInfoProvider,
) *AnnounceHandler {
	h := &AnnounceHandler{
		mle:        mle,
		dispatcher: dispatcher,
		keyMgr:     keyMgr,
		datasets:   datasets,
		macInfo:    macInfo,
	}

	dispatcher.RegisterHandler(CommandAnnounce, h.HandleAnnounce)

	return h
}

// HandleAnnounce processes a received MLE Announce message.
//
// Required TLVs: Channel, PAN ID, Active Timestamp.
//
// The handler compares the received Active Timestamp against the local
// reference timestamp and decides on one of three actions:
//
//   - Ignore: The announce is an orphan announce whose channel and PAN ID
//     match the local values, or the device is not attached.
//   - SendBack: The local dataset timestamp is strictly newer, and the
//     device is an FTD router-eligible node attached as Router or Leader.
//     The device sends its own Announce on the received channel.
//   - Signal: The received timestamp is newer than or equal to the local
//     one. The upper layer should handle the channel/PAN switch.
//
// This is a Go port of OpenThread's Mle::HandleAnnounce
// (mle.cpp:5786-5927).
func (h *AnnounceHandler) HandleAnnounce(rxInfo *RxInfo) error {
	// 1. Parse required Channel TLV.
	channelVal, ok := FindTLV(rxInfo.TLVs, TLVChannel)
	if !ok {
		return fmt.Errorf("mle: announce missing Channel TLV")
	}
	_, channel, err := ReadChannelTLV(channelVal)
	if err != nil {
		return fmt.Errorf("mle: announce: %w", err)
	}

	// 2. Parse required PAN ID TLV.
	panIDVal, ok := FindTLV(rxInfo.TLVs, TLVPanID)
	if !ok {
		return fmt.Errorf("mle: announce missing PanID TLV")
	}
	panID, err := ReadPanIDTLV(panIDVal)
	if err != nil {
		return fmt.Errorf("mle: announce: %w", err)
	}

	// 3. Parse required Active Timestamp TLV.
	activeVal, ok := FindTLV(rxInfo.TLVs, TLVActiveTimestamp)
	if !ok {
		return fmt.Errorf("mle: announce missing ActiveTimestamp TLV")
	}
	receivedTS, err := ReadActiveTimestampTLV(activeVal)
	if err != nil {
		return fmt.Errorf("mle: announce: %w", err)
	}

	// Record what we received.
	h.LastReceivedChannel = channel
	h.LastReceivedPanID = panID

	// 4. If the received timestamp is an Orphan Announce, check whether
	// the channel and PAN ID match. If they do, ignore.
	if receivedTS.IsOrphanAnnounce() {
		localChannel, localPanID := h.getMacInfo()
		if channel == localChannel && panID == localPanID {
			// Orphan on our same channel/PAN — ignore.
			h.LastAction = AnnounceActionIgnore
			return nil
		}
		// Orphan on a different channel/PAN. If not attached, ignore.
		if !h.mle.IsAttached() {
			h.LastAction = AnnounceActionIgnore
			return nil
		}
	}

	// 5. If not attached, ignore the announce.
	if !h.mle.IsAttached() {
		h.LastAction = AnnounceActionIgnore
		return nil
	}

	// 6. Compare the received timestamp against our local Active Timestamp.
	localTS := h.getActiveTimestamp()

	cmp := meshcop.Compare(receivedTS, localTS)

	switch {
	case cmp < 0:
		// Received timestamp is older than ours. If we are an FTD and
		// router-eligible (and operating as Router or Leader), send our
		// own Announce back on the received channel.
		if h.mle.IsRouterOrLeader() && h.mle.IsRouterEligible() &&
			h.mle.GetDeviceMode().IsFullThreadDevice() {
			h.LastAction = AnnounceActionSendBack
			return h.SendAnnounce(channel, AnnounceNormal, LinkLocalAllNodesMulticast)
		}
		// Non-FTD or non-router: ignore.
		h.LastAction = AnnounceActionIgnore
		return nil

	default:
		// Received timestamp is newer or equal — signal the upper layer
		// to trigger a channel/PAN switch via the OnSignal callback.
		h.LastAction = AnnounceActionSignal
		if h.OnSignal != nil {
			h.OnSignal(h.LastReceivedChannel, h.LastReceivedPanID)
		}
		return nil
	}
}

// SendAnnounce builds and sends an MLE Announce message on the given
// channel to the specified destination.
//
// The Announce message contains:
//   - Channel TLV (channel page 0 + channel)
//   - Active Timestamp TLV
//   - PAN ID TLV
//
// For AnnounceOrphan mode, the Active Timestamp is set to the orphan
// sentinel (seconds=0, ticks=0, authoritative=true).
//
// This is a Go port of OpenThread's Mle::SendAnnounce
// (mle.cpp:1369-1411).
func (h *AnnounceHandler) SendAnnounce(channel uint16, mode AnnounceMode, dst ip6.Address) error {
	msg := NewMessage(CommandAnnounce)

	// Channel TLV: page 0 + channel.
	msg.AppendChannelTLV(0, channel)

	// Active Timestamp TLV.
	var ts *meshcop.Timestamp
	if mode == AnnounceOrphan {
		ts = &meshcop.Timestamp{}
		ts.SetToOrphanAnnounce()
	} else {
		ts = h.getActiveTimestamp()
	}
	if err := msg.AppendActiveTimestampTLV(ts); err != nil {
		return fmt.Errorf("mle: send announce: %w", err)
	}

	// PAN ID TLV: use the current PAN ID from the MAC layer.
	_, localPanID := h.getMacInfo()
	msg.AppendPanIDTLV(localPanID)

	if err := h.dispatcher.SendMessage(msg, dst); err != nil {
		return fmt.Errorf("mle: send announce: %w", err)
	}

	return nil
}

// --------------------------------------------------------------------------
// Dataset helper methods
// --------------------------------------------------------------------------

// getActiveTimestamp returns the local Active Timestamp from the dataset
// provider, or a zero-value Timestamp if no provider is configured.
func (h *AnnounceHandler) getActiveTimestamp() *meshcop.Timestamp {
	if h.datasets == nil {
		return &meshcop.Timestamp{}
	}
	ts := h.datasets.GetActiveTimestamp()
	return &ts
}

// getMacInfo returns the current PAN channel and PAN ID from the MAC
// info provider. Returns (0, 0) if no provider is configured.
func (h *AnnounceHandler) getMacInfo() (channel, panID uint16) {
	if h.macInfo == nil {
		return 0, 0
	}
	return uint16(h.macInfo.GetPanChannel()), h.macInfo.GetPanID()
}
