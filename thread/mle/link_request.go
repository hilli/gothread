// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file implements MLE Link Request message building and sending.
//
// A Link Request is sent by routers/leaders to establish or re-verify a
// bidirectional link with a peer router. It can be sent unicast to a
// specific router, or multicast to all routers (e.g., when restoring a
// previous router role after reboot).
//
// The TLVs included depend on the sender's role:
//
//   - Detached: Version, Challenge, TLV Request (Address16, Route)
//   - Child: Version, Source Address, Leader Data, Challenge
//   - Router/Leader (unknown neighbor): Version, Source Address, Leader Data,
//     Challenge, TLV Request (LinkMargin)
//   - Router/Leader (valid neighbor): Version, Source Address, Leader Data,
//     Challenge, TLV Request (LinkMargin, Route)
//
// This is a Go port of the Link Request logic from OpenThread's
// src/core/thread/mle_ftd.cpp (SendLinkRequest).

package mle

import (
	"fmt"

	"github.com/hilli/gothread/mac/types"
)

// linkLocalIPFromExtAddress computes the link-local IPv6 address from an
// extended MAC address using the modified EUI-64 conversion (toggle U/L bit).
func linkLocalIPFromExtAddress(macAddr types.ExtAddress) [16]byte {
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

// BuildLinkRequest constructs an MLE Link Request message.
//
// The TLVs included depend on the sender's role and whether the target
// neighbor is already in a valid state:
//
//   - Detached: Version + Challenge + TLV Request (Address16, Route)
//   - Child: Version + Source Address + Leader Data + Challenge
//   - Router/Leader with unknown neighbor: Version + Source Address +
//     Leader Data + Challenge + TLV Request (LinkMargin)
//   - Router/Leader with valid neighbor: Version + Source Address +
//     Leader Data + Challenge + TLV Request (LinkMargin, Route)
//
// The returned Message is not yet encrypted; the caller should pass it
// to Dispatcher.SendMessage() for security framing and transmission.
func BuildLinkRequest(role DeviceRole, rloc16 uint16, leaderData LeaderData, challenge Challenge, neighborValid bool) *Message {
	msg := NewMessage(CommandLinkRequest)

	msg.AppendVersionTLV(ThreadVersion)

	switch role {
	case RoleDetached:
		msg.AppendChallengeTLV(challenge)
		msg.AppendTLVRequestTLV([]uint8{TLVAddress16, TLVRoute64})

	case RoleChild:
		msg.AppendSourceAddressTLV(rloc16)
		msg.AppendLeaderDataTLV(leaderData)
		msg.AppendChallengeTLV(challenge)

	case RoleRouter, RoleLeader:
		msg.AppendSourceAddressTLV(rloc16)
		msg.AppendLeaderDataTLV(leaderData)
		msg.AppendChallengeTLV(challenge)

		if neighborValid {
			msg.AppendTLVRequestTLV([]uint8{TLVLinkMargin, TLVRoute64})
		} else {
			msg.AppendTLVRequestTLV([]uint8{TLVLinkMargin})
		}
	}

	return msg
}

// SendLinkRequest builds and sends an MLE Link Request message.
//
// If router is nil, the request is sent as multicast to the link-local
// all-routers address (ff02::2). The challenge is generated fresh and
// returned so the caller can store it for matching the response.
//
// If router is non-nil, the request is sent unicast to the router's
// link-local address derived from its extended MAC address. The challenge
// is stored on the router's PendingChallenge field and the link accept
// countdown is restarted.
//
// The device must not be in the Disabled state. Returns the generated
// challenge and any error.
func SendLinkRequest(m *Mle, dispatcher *Dispatcher, transport Transport, router *Router) (Challenge, error) {
	m.mu.RLock()
	role := m.role
	rloc16 := m.rloc16
	leaderData := m.leaderData
	m.mu.RUnlock()

	if role == RoleDisabled {
		return Challenge{}, fmt.Errorf("mle: cannot send link request in disabled state")
	}

	// Generate a fresh challenge.
	var challenge Challenge
	challenge.GenerateChallenge()

	neighborValid := false
	if router != nil {
		neighborValid = router.IsStateValid()
		if !neighborValid {
			// Store challenge on the router for matching the Link Accept.
			router.PendingChallenge = challenge
			router.RestartLinkAcceptTimeout()
		}
	}

	msg := BuildLinkRequest(role, rloc16, leaderData, challenge, neighborValid)

	if router != nil {
		// Unicast to the router's link-local address.
		dst := linkLocalIPFromExtAddress(router.MacAddr)
		return challenge, dispatcher.SendMessage(msg, dst)
	}

	// Multicast to all routers.
	dst := transport.GetLinkLocalAllRoutersMulticast()
	return challenge, dispatcher.SendMessage(msg, dst)
}
