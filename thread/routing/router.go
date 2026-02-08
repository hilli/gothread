// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package routing

import (
	"github.com/hilli/gothread/thread/link"
)

// Router ID and routing constants.
const (
	// InvalidRouterID is the sentinel value for an unassigned or invalid router ID.
	InvalidRouterID uint8 = 63
	// MaxRouterID is the maximum valid router ID.
	MaxRouterID uint8 = 62
	// MaxRouters is the maximum number of routers in a Thread network.
	MaxRouters uint8 = 32
	// MaxRouteCost is the maximum path cost for Thread routing.
	MaxRouteCost uint8 = 16
	// DefaultLinkRequestAttempts is the default number of link request attempts.
	DefaultLinkRequestAttempts uint8 = 3
	// DefaultLinkAcceptTimeout is the default link accept timeout in seconds.
	DefaultLinkAcceptTimeout uint8 = 3
)

// Router represents a Thread router neighbor.
type Router struct {
	Neighbor
	NextHop             uint8 // Router ID of next hop
	Cost                uint8 // Path cost
	LinkQualityOut      uint8 // Outgoing link quality (0-3)
	LinkRequestAttempts uint8
	LinkAcceptTimeout   uint8
}

// GetTwoWayLinkQuality returns the minimum of the incoming and outgoing
// link quality, representing the bidirectional link quality.
func (r *Router) GetTwoWayLinkQuality() uint8 {
	qualityIn := r.LinkInfo.GetQualityIn()
	if qualityIn < r.LinkQualityOut {
		return qualityIn
	}
	return r.LinkQualityOut
}

// SetNextHopAndCost sets the next hop router ID and path cost.
// Returns true if either value changed.
func (r *Router) SetNextHopAndCost(nextHop, cost uint8) bool {
	changed := r.NextHop != nextHop || r.Cost != cost
	r.NextHop = nextHop
	r.Cost = cost
	return changed
}

// SetNextHopToInvalid sets the next hop to InvalidRouterID and cost to zero.
// Returns true if the next hop was previously valid.
func (r *Router) SetNextHopToInvalid() bool {
	wasValid := r.NextHop != InvalidRouterID
	r.NextHop = InvalidRouterID
	r.Cost = 0
	return wasValid
}

// HasRemainingLinkRequestAttempts returns true if there are remaining link
// request attempts.
func (r *Router) HasRemainingLinkRequestAttempts() bool {
	return r.LinkRequestAttempts > 0
}

// DecrementLinkRequestAttempts decrements the link request attempt counter.
func (r *Router) DecrementLinkRequestAttempts() {
	if r.LinkRequestAttempts > 0 {
		r.LinkRequestAttempts--
	}
}

// RestartLinkAcceptTimeout resets the link accept timeout to its default value.
func (r *Router) RestartLinkAcceptTimeout() {
	r.LinkAcceptTimeout = DefaultLinkAcceptTimeout
}

// IsWaitingForLinkAccept returns true if the router is waiting for a link
// accept response.
func (r *Router) IsWaitingForLinkAccept() bool {
	return r.LinkAcceptTimeout > 0
}

// DecrementLinkAcceptTimeout decrements the link accept timeout counter.
func (r *Router) DecrementLinkAcceptTimeout() {
	if r.LinkAcceptTimeout > 0 {
		r.LinkAcceptTimeout--
	}
}

// GetLinkCostToRouter computes the link cost based on the two-way link quality.
func (r *Router) GetLinkCostToRouter() uint8 {
	return link.CostForQuality(r.GetTwoWayLinkQuality())
}

// Parent extends Router with leader cost information.
type Parent struct {
	Router
	LeaderCost uint8
}
