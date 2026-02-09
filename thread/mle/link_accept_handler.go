// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Link Accept and Link Accept And Request receive-side handlers for MLE.
// Ported from OpenThread — Copyright (c) 2016, The OpenThread Authors.

package mle

import (
	"bytes"
	"fmt"
	"time"

	"github.com/hilli/gothread/thread/link"
)

// HandleLinkAccept processes a received MLE Link Accept message.
func (h *FtdLinkHandlers) HandleLinkAccept(rxInfo *RxInfo) error {
	return h.handleLinkAcceptVariant(rxInfo, false)
}

// HandleLinkAcceptAndRequest processes a received MLE Link Accept And Request message.
func (h *FtdLinkHandlers) HandleLinkAcceptAndRequest(rxInfo *RxInfo) error {
	return h.handleLinkAcceptVariant(rxInfo, true)
}

// handleLinkAcceptVariant is the shared implementation for Link Accept and
// Link Accept And Request. It validates the incoming message, updates the
// router entry, and optionally sends a Link Accept reply when the incoming
// message is a Link Accept And Request.
//
// This is a Go port of OpenThread's Mle::HandleLinkAccept
// (src/core/thread/mle_ftd.cpp, lines 849-1054).
func (h *FtdLinkHandlers) handleLinkAcceptVariant(rxInfo *RxInfo, isAcceptAndRequest bool) error {
	cmdName := "link accept"
	if isAcceptAndRequest {
		cmdName = "link accept and request"
	}

	// 1. Role check: must be Router or Leader.
	if !h.mle.IsRouterOrLeader() {
		return fmt.Errorf("mle: %s received while not router or leader (role=%s)",
			cmdName, h.mle.Role())
	}

	// 2. Parse required TLVs.

	// Source Address — required, must be a router RLOC16.
	srcAddrVal, ok := FindTLV(rxInfo.TLVs, TLVSourceAddress)
	if !ok {
		return fmt.Errorf("mle: %s missing Source Address TLV", cmdName)
	}
	sourceAddr, err := ReadSourceAddressTLV(srcAddrVal)
	if err != nil {
		return fmt.Errorf("mle: %s: %w", cmdName, err)
	}
	if !IsRouterRLOC16(sourceAddr) {
		return fmt.Errorf("mle: %s source address 0x%04X is not a router RLOC16",
			cmdName, sourceAddr)
	}

	// Response — required (raw bytes echoing our challenge).
	responseVal, ok := FindTLV(rxInfo.TLVs, TLVResponse)
	if !ok {
		return fmt.Errorf("mle: %s missing Response TLV", cmdName)
	}

	// Version — required.
	versionVal, ok := FindTLV(rxInfo.TLVs, TLVVersion)
	if !ok {
		return fmt.Errorf("mle: %s missing Version TLV", cmdName)
	}
	version, err := ReadVersionTLV(versionVal)
	if err != nil {
		return fmt.Errorf("mle: %s: %w", cmdName, err)
	}

	// Link Frame Counter — required.
	linkFCVal, ok := FindTLV(rxInfo.TLVs, TLVLinkFrameCounter)
	if !ok {
		return fmt.Errorf("mle: %s missing Link Frame Counter TLV", cmdName)
	}
	linkFrameCounter, err := ReadLinkFrameCounterTLV(linkFCVal)
	if err != nil {
		return fmt.Errorf("mle: %s: %w", cmdName, err)
	}

	// MLE Frame Counter — optional; defaults to Link Frame Counter if absent.
	mleFrameCounter := linkFrameCounter
	if mleFCVal, ok := FindTLV(rxInfo.TLVs, TLVMleFrameCounter); ok {
		mleFrameCounter, err = ReadMleFrameCounterTLV(mleFCVal)
		if err != nil {
			return fmt.Errorf("mle: %s: %w", cmdName, err)
		}
	}

	// 3. Look up the router by source address.
	router := h.routerLookup.FindRouterByRLOC16(sourceAddr)
	if router == nil {
		return fmt.Errorf("mle: %s from unknown router RLOC16 0x%04X",
			cmdName, sourceAddr)
	}

	// 4. Challenge verification — critical security gate.
	switch router.State {
	case StateLinkRequest:
		// We sent a Link Request to this router; the Response TLV must match
		// the challenge we stored on the router entry.
		if !bytes.Equal(responseVal, router.PendingChallenge[:]) {
			return fmt.Errorf("mle: %s response mismatch for router 0x%04X",
				cmdName, sourceAddr)
		}

	case StateValid:
		// Already-valid link — this is a link refresh/rekey. Accept it.

	default:
		return fmt.Errorf("mle: %s unexpected router state %s for router 0x%04X",
			cmdName, router.State, sourceAddr)
	}

	// 5. Parse conditional TLVs.

	// Link Margin — optional.
	var linkMargin uint8
	hasLinkMargin := false
	if lmVal, ok := FindTLV(rxInfo.TLVs, TLVLinkMargin); ok {
		linkMargin, err = ReadLinkMarginTLV(lmVal)
		if err != nil {
			return fmt.Errorf("mle: %s: %w", cmdName, err)
		}
		hasLinkMargin = true
	}

	// Leader Data — optional. Parsed but not currently acted upon beyond
	// the initial link establishment.
	if ldVal, ok := FindTLV(rxInfo.TLVs, TLVLeaderData); ok {
		_, err = ReadLeaderDataTLV(ldVal)
		if err != nil {
			return fmt.Errorf("mle: %s: %w", cmdName, err)
		}
	}

	// Route64 — optional.
	if r64Val, ok := FindTLV(rxInfo.TLVs, TLVRoute64); ok {
		_, _, _, err = ReadRoute64TLV(r64Val)
		if err != nil {
			return fmt.Errorf("mle: %s: %w", cmdName, err)
		}
	}

	// Address16 — optional.
	if a16Val, ok := FindTLV(rxInfo.TLVs, TLVAddress16); ok {
		_, err = ReadAddress16TLV(a16Val)
		if err != nil {
			return fmt.Errorf("mle: %s: %w", cmdName, err)
		}
	}

	// 6. Finalize router state.
	router.RLOC16 = sourceAddr
	router.Counters.LinkFrameCounter = linkFrameCounter
	router.Counters.MleFrameCounter = mleFrameCounter
	router.Version = version
	router.Mode = NewDeviceMode(ModeRxOnWhenIdle | ModeFullThreadDevice | ModeFullNetworkData)

	if hasLinkMargin {
		router.LinkInfo.SetQualityOut(link.QualityForLinkMargin(linkMargin))
	}

	router.State = StateValid
	router.KeySequence = rxInfo.KeySequence
	router.ClearLinkAcceptTimeout()
	router.LastHeard = time.Now()

	// 7. If this is an Accept And Request, send a Link Accept reply.
	if isAcceptAndRequest {
		// Challenge TLV — required for Accept And Request.
		challengeVal, ok := FindTLV(rxInfo.TLVs, TLVChallenge)
		if !ok {
			return fmt.Errorf("mle: %s missing Challenge TLV", cmdName)
		}
		challenge, err := ReadChallengeTLV(challengeVal)
		if err != nil {
			return fmt.Errorf("mle: %s: %w", cmdName, err)
		}

		// TLV Request — optional list of TLV types the peer wants in the reply.
		var tlvRequestVal []uint8
		if reqVal, ok := FindTLV(rxInfo.TLVs, TLVTLVRequest); ok {
			tlvRequestVal = reqVal
		}

		acceptInfo := LinkAcceptInfo{
			ExtAddress:    rxInfo.SrcAddr,
			RxChallenge:   challenge,
			RequestedTLVs: tlvRequestVal,
			LinkMargin:    rxInfo.LinkMarginRaw,
		}

		if err := SendLinkAccept(h.mle, h.dispatcher, h.keyMgr, &acceptInfo, router, h.routeData); err != nil {
			return fmt.Errorf("mle: %s: failed to send link accept reply: %w", cmdName, err)
		}
	}

	return nil
}
