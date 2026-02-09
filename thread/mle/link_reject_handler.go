// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Link Reject handler and sender for MLE.
//
// A Link Reject message indicates that a peer router has rejected the link
// establishment attempt. On receipt, the local device invalidates the
// neighbor entry for the sender.
//
// This is a Go port of OpenThread's HandleLinkReject (mle.cpp) and
// SendLinkReject (mle_ftd.cpp).

package mle

import (
	"fmt"

	"github.com/hilli/gothread/net/ip6"
)

// LinkRejectHandler handles received MLE Link Reject messages and provides
// the ability to send Link Reject messages.
type LinkRejectHandler struct {
	mle        *Mle
	dispatcher *Dispatcher
}

// NewLinkRejectHandler creates a new LinkRejectHandler and registers the
// CommandLinkReject handler with the dispatcher.
func NewLinkRejectHandler(
	mle *Mle,
	dispatcher *Dispatcher,
) *LinkRejectHandler {
	h := &LinkRejectHandler{
		mle:        mle,
		dispatcher: dispatcher,
	}

	dispatcher.RegisterHandler(CommandLinkReject, h.HandleLinkReject)

	return h
}

// HandleLinkReject processes a received MLE Link Reject message.
//
// The Link Reject is a simple message indicating the peer has rejected
// link establishment. The handler invalidates the neighbor entry of the
// sender so the link is torn down on the local side.
//
// Required: the sender must be a known neighbor (rxInfo.Neighbor != nil).
//
// This is a Go port of OpenThread's Mle::HandleLinkReject
// (src/core/thread/mle.cpp).
func (h *LinkRejectHandler) HandleLinkReject(rxInfo *RxInfo) error {
	// Must be attached to process link reject.
	if !h.mle.IsAttached() {
		return fmt.Errorf("mle: link reject received while not attached (role=%s)",
			h.mle.Role())
	}

	// The sender must be a known neighbor.
	if rxInfo.Neighbor == nil {
		return fmt.Errorf("mle: link reject from unknown neighbor")
	}

	// Invalidate the neighbor — the link is rejected.
	rxInfo.Neighbor.Invalidate()

	return nil
}

// SendLinkReject builds and sends an MLE Link Reject message to the
// specified destination.
//
// The Link Reject message contains only a Status TLV with StatusError.
//
// This is a Go port of OpenThread's Mle::SendLinkReject
// (src/core/thread/mle_ftd.cpp).
func (h *LinkRejectHandler) SendLinkReject(dst ip6.Address) error {
	msg := NewMessage(CommandLinkReject)
	msg.AppendStatusTLV(StatusError)

	if err := h.dispatcher.SendMessage(msg, dst); err != nil {
		return fmt.Errorf("mle: send link reject: %w", err)
	}

	return nil
}
