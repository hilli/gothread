// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file implements MLE Advertisement message building and sending.
//
// An MLE Advertisement message contains:
//   - Source Address TLV (device RLOC16)
//   - Leader Data TLV (partition info)
//   - Route64 TLV (routing table data)
//
// Advertisements are sent to the link-local all-routers multicast address
// (ff02::2) and are scheduled by a Trickle timer (RFC 6206).
//
// This is a Go port of the advertisement logic from OpenThread's
// src/core/thread/mle.cpp (SendAdvertisement).

package mle

import "fmt"

// RouteDataProvider supplies route information for building MLE
// Advertisement messages without importing the routing package.
//
// This interface breaks the circular dependency: mle defines the
// interface, and the routing package provides an implementation that
// wraps RouterTable.FillRouteTlv().
type RouteDataProvider interface {
	// GetRouteData returns the route data for inclusion in an Advertisement.
	// selfRouterID and leaderRouterID identify the local device and the
	// leader in the partition.
	//
	// Returns the router ID sequence number, the router ID bitmask, and
	// the per-router Route64 entries (one per set bit in the mask, in
	// ascending router ID order).
	GetRouteData(selfRouterID, leaderRouterID uint8) (sequence uint8, mask RouterIDSet, entries []Route64Entry)
}

// BuildAdvertisement constructs an MLE Advertisement message from the
// given parameters. The returned Message is not yet encrypted; the caller
// should pass it to Dispatcher.SendMessage() for security framing and
// transmission.
//
// The message contains:
//   - Source Address TLV (rloc16)
//   - Leader Data TLV (leaderData)
//   - Route64 TLV (sequence, mask, entries)
func BuildAdvertisement(rloc16 uint16, leaderData LeaderData, sequence uint8, mask RouterIDSet, entries []Route64Entry) *Message {
	msg := NewMessage(CommandAdvertisement)
	msg.AppendSourceAddressTLV(rloc16)
	msg.AppendLeaderDataTLV(leaderData)
	msg.AppendRoute64TLV(sequence, mask, entries)
	return msg
}

// SendAdvertisement builds and sends an MLE Advertisement message.
//
// It retrieves the current MLE state (RLOC16, leader data, router ID)
// from the Mle instance, obtains route data from the RouteDataProvider,
// builds the Advertisement message, and sends it to the link-local
// all-routers multicast address via the Dispatcher.
//
// The device must be in the Router or Leader role. Returns an error if
// the device is not in an appropriate role or if sending fails.
func SendAdvertisement(m *Mle, dispatcher *Dispatcher, transport Transport, routeData RouteDataProvider) error {
	m.mu.RLock()
	role := m.role
	rloc16 := m.rloc16
	leaderData := m.leaderData
	routerID := m.ftd.routerID
	m.mu.RUnlock()

	if role != RoleRouter && role != RoleLeader {
		return fmt.Errorf("mle: cannot send advertisement in role %s", role)
	}

	if routerID > MaxRouterID {
		return fmt.Errorf("mle: invalid router ID %d for advertisement", routerID)
	}

	sequence, mask, entries := routeData.GetRouteData(routerID, leaderData.LeaderRouterID)
	msg := BuildAdvertisement(rloc16, leaderData, sequence, mask, entries)

	dst := transport.GetLinkLocalAllRoutersMulticast()
	return dispatcher.SendMessage(msg, dst)
}
