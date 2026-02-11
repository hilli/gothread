// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package ndagent implements an IPv6 Neighbor Discovery proxy agent for
// Thread border routers.
//
// When a border router receives a Neighbor Solicitation (NS) on the
// infrastructure link for a target address that belongs to a Thread device,
// the ND Agent responds with a Neighbor Advertisement (NA) on behalf of
// that device. This is a Go port of OpenThread's ND Agent functionality
// adapted for the border router's infrastructure-side ND proxying role.
//
// See RFC 4861 sections 4.3 (NS) and 4.4 (NA).
package ndagent

import (
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Well-known addresses
// ---------------------------------------------------------------------------

// allNodesMulticast is the link-local all-nodes multicast address (ff02::1).
var allNodesMulticast = ip6.Address{
	0xff, 0x02, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0x01,
}

// unspecified is the all-zeros address (::).
var unspecified = ip6.Address{}

// ---------------------------------------------------------------------------
// Dependency interfaces
// ---------------------------------------------------------------------------

// AddressChecker determines whether a given IPv6 address belongs to a Thread
// device reachable through the Thread mesh.
type AddressChecker interface {
	// HasAddress returns true if the target address belongs to a Thread
	// device that this border router should proxy ND for.
	HasAddress(addr ip6.Address) bool
}

// NaSender sends Neighbor Advertisement messages on the infrastructure link.
type NaSender interface {
	// SendNeighborAdvert sends an NA for the given target address to the
	// specified destination address on the infrastructure link.
	SendNeighborAdvert(target ip6.Address, destination ip6.Address) error
}

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

// Agent proxies IPv6 Neighbor Discovery for Thread devices on the
// infrastructure link. It responds to Neighbor Solicitations with Neighbor
// Advertisements on behalf of Thread devices whose addresses are reachable
// through the mesh.
type Agent struct {
	checker AddressChecker
	sender  NaSender
	enabled bool
}

// NewAgent creates a new ND Agent with the given address checker and NA
// sender. The agent starts in the disabled state.
func NewAgent(checker AddressChecker, sender NaSender) *Agent {
	return &Agent{
		checker: checker,
		sender:  sender,
	}
}

// Enable activates the agent so it will process incoming NS messages.
func (a *Agent) Enable() {
	a.enabled = true
}

// Disable deactivates the agent. While disabled, all NS messages are ignored.
func (a *Agent) Disable() {
	a.enabled = false
}

// IsEnabled reports whether the agent is currently active.
func (a *Agent) IsEnabled() bool {
	return a.enabled
}

// HandleNeighborSolicitation processes a Neighbor Solicitation received on
// the infrastructure link.
//
// If the agent is disabled, it returns ErrInvalidState. If the target address
// does not belong to a Thread device, it returns ErrDrop. Otherwise it sends
// a Neighbor Advertisement back on the infrastructure link with:
//   - Target = the solicited address
//   - Destination = source of the NS, or all-nodes multicast (ff02::1)
//     if the NS source was the unspecified address (DAD case)
func (a *Agent) HandleNeighborSolicitation(target ip6.Address, source ip6.Address) error {
	if !a.enabled {
		return errors.ErrInvalidState
	}

	if !a.checker.HasAddress(target) {
		return errors.ErrDrop
	}

	// Determine the NA destination per RFC 4861 section 7.2.4:
	// If the source of the NS is the unspecified address (DAD), the NA
	// is sent to the all-nodes multicast address. Otherwise it is
	// unicast back to the NS source.
	dest := source
	if source == unspecified {
		dest = allNodesMulticast
	}

	return a.sender.SendNeighborAdvert(target, dest)
}

// HandleNeighborAdvertisement processes a Neighbor Advertisement received on
// the infrastructure link. This can be used for DAD conflict detection or
// tracking purposes. The current implementation is a no-op placeholder for
// future extension.
func (a *Agent) HandleNeighborAdvertisement(_ ip6.Address, _ ip6.Address) {
	// Reserved for future DAD conflict detection.
}
