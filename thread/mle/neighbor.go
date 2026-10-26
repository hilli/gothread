// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file defines Neighbor, Router, Parent, and Child types for MLE state
// tracking.
//
// This is a Go port of the neighbor/router/child types defined in OpenThread's
// src/core/thread/neighbor.hpp, src/core/thread/router.hpp, and
// src/core/thread/child.hpp.

package mle

import (
	"crypto/rand"
	"time"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/link"
)

// NeighborState represents the connection state of a Thread neighbor.
type NeighborState uint8

const (
	// StateInvalid indicates the neighbor entry is unused or invalid.
	StateInvalid NeighborState = 0
	// StateRestored indicates the neighbor was restored from non-volatile storage.
	StateRestored NeighborState = 1
	// StateParentRequest indicates a Parent Request was received from this neighbor.
	StateParentRequest NeighborState = 2
	// StateParentResponse indicates a Parent Response was received from this neighbor.
	StateParentResponse NeighborState = 3
	// StateChildIDRequest indicates a Child ID Request was received from this neighbor.
	StateChildIDRequest NeighborState = 4
	// StateLinkRequest indicates a Link Request was sent to this neighbor.
	StateLinkRequest NeighborState = 5
	// StateChildUpdateRequest indicates a Child Update Request was sent (restoring).
	StateChildUpdateRequest NeighborState = 6
	// StateValid indicates the link to this neighbor is fully established.
	StateValid NeighborState = 7
)

// String returns a human-readable name for the neighbor state.
func (s NeighborState) String() string {
	switch s {
	case StateInvalid:
		return "Invalid"
	case StateRestored:
		return "Restored"
	case StateParentRequest:
		return "ParentRequest"
	case StateParentResponse:
		return "ParentResponse"
	case StateChildIDRequest:
		return "ChildIDRequest"
	case StateLinkRequest:
		return "LinkRequest"
	case StateChildUpdateRequest:
		return "ChildUpdateRequest"
	case StateValid:
		return "Valid"
	default:
		return "Unknown"
	}
}

// ChallengeSize is the size of an MLE challenge in bytes.
const ChallengeSize = 8

// Challenge is a random value used in the MLE handshake.
type Challenge [ChallengeSize]byte

// GenerateChallenge fills the challenge with random bytes.
func (c *Challenge) GenerateChallenge() {
	_, _ = rand.Read(c[:])
}

// FrameCounters holds the link and MLE frame counters for a neighbor.
type FrameCounters struct {
	// LinkFrameCounter is the 802.15.4 MAC frame counter.
	LinkFrameCounter uint32
	// MleFrameCounter is the MLE frame counter.
	MleFrameCounter uint32
}

// Neighbor represents a Thread neighbor with link state tracking.
//
// This is the base type used for all neighbor entries — children, routers,
// and the parent.
type Neighbor struct {
	// MacAddr is the extended (EUI-64) MAC address.
	MacAddr types.ExtAddress
	// RLOC16 is the short address.
	RLOC16 uint16
	// State is the current neighbor connection state.
	State NeighborState
	// Mode is the device mode flags.
	Mode DeviceMode
	// Version is the MLE protocol version.
	Version uint16
	// KeySequence is the current key sequence number.
	KeySequence uint32
	// LastHeard is the timestamp when a message was last received.
	LastHeard time.Time
	// LinkInfo tracks RSS, LQI, and link quality metrics.
	LinkInfo link.QualityInfo
	// LinkFailures counts consecutive link failures.
	LinkFailures uint8

	// Counters holds frame counters when state is StateValid.
	Counters FrameCounters
	// Challenge holds the pending challenge when state is not yet valid.
	PendingChallenge Challenge
}

// IsStateValid reports whether the neighbor link is fully established.
func (n *Neighbor) IsStateValid() bool {
	return n.State == StateValid
}

// IsStateRestoring reports whether the neighbor is being restored from storage.
func (n *Neighbor) IsStateRestoring() bool {
	return n.State == StateRestored || n.State == StateChildUpdateRequest
}

// IsStateValidOrRestoring reports whether the neighbor is valid or restoring.
func (n *Neighbor) IsStateValidOrRestoring() bool {
	return n.IsStateValid() || n.IsStateRestoring()
}

// IsStateValidOrAttaching reports whether the neighbor is valid or in an
// attaching state (ParentRequest through ChildIDRequest, plus LinkRequest).
func (n *Neighbor) IsStateValidOrAttaching() bool {
	switch n.State {
	case StateParentRequest, StateParentResponse, StateChildIDRequest,
		StateLinkRequest, StateChildUpdateRequest, StateValid:
		return true
	default:
		return false
	}
}

// IsStateAnyExceptInvalid reports whether the neighbor is in any state
// other than Invalid.
func (n *Neighbor) IsStateAnyExceptInvalid() bool {
	return n.State != StateInvalid
}

// IsRxOnWhenIdle returns true if the neighbor keeps its receiver on when idle.
func (n *Neighbor) IsRxOnWhenIdle() bool {
	return n.Mode.IsRxOnWhenIdle()
}

// IsFullThreadDevice returns true if the neighbor is a Full Thread Device.
func (n *Neighbor) IsFullThreadDevice() bool {
	return n.Mode.IsFullThreadDevice()
}

// GetDeviceMode returns the neighbor's device mode.
func (n *Neighbor) GetDeviceMode() DeviceMode {
	return n.Mode
}

// GenerateChallenge fills the pending challenge with random data.
func (n *Neighbor) GenerateChallenge() {
	n.PendingChallenge.GenerateChallenge()
}

// GetLinkQualityIn returns the incoming link quality (0-3).
func (n *Neighbor) GetLinkQualityIn() uint8 {
	return n.LinkInfo.GetQualityIn()
}

// Invalidate marks the neighbor entry as invalid.
func (n *Neighbor) Invalidate() {
	n.State = StateInvalid
}

// LinkRequestAttempts is the maximum number of Link Request attempts.
const LinkRequestAttempts uint8 = 3

// LinkAcceptTimeout is the timeout in seconds waiting for a Link Accept.
const LinkAcceptTimeout uint8 = 3

// Router represents a Thread Router entry in the routing table.
//
// It extends Neighbor with routing-specific fields.
type Router struct {
	Neighbor
	// NextHop is the router ID of the next hop toward this router.
	// InvalidRouterID means no route is known.
	NextHop uint8
	// Cost is the path cost to reach this router.
	Cost uint8
	// LinkQualityOut is the outgoing link quality to this router.
	LinkQualityOut uint8
	// LinkRequestAttempts is the remaining Link Request retry count.
	RemainingLinkRequestAttempts uint8
	// LinkAcceptCountdown is the remaining seconds waiting for Link Accept.
	LinkAcceptCountdown uint8
}

// NewRouter returns a Router with default values and no route.
func NewRouter() Router {
	return Router{
		NextHop: InvalidRouterID,
	}
}

// HasRoute reports whether a route to this router is known.
func (r *Router) HasRoute() bool {
	return r.NextHop != InvalidRouterID
}

// SetNextHopAndCost sets the next hop and cost for routing to this router.
func (r *Router) SetNextHopAndCost(nextHop, cost uint8) {
	r.NextHop = nextHop
	r.Cost = cost
}

// SetNextHopToInvalid clears the route to this router.
func (r *Router) SetNextHopToInvalid() {
	r.NextHop = InvalidRouterID
	r.Cost = 0
}

// GetTwoWayLinkQuality returns the minimum of in and out link quality.
func (r *Router) GetTwoWayLinkQuality() uint8 {
	inQ := r.GetLinkQualityIn()
	if r.LinkQualityOut < inQ {
		return r.LinkQualityOut
	}
	return inQ
}

// IsWaitingForLinkAccept reports whether a Link Accept is pending.
func (r *Router) IsWaitingForLinkAccept() bool {
	return r.LinkAcceptCountdown > 0
}

// RestartLinkAcceptTimeout resets the Link Accept countdown.
func (r *Router) RestartLinkAcceptTimeout() {
	r.LinkAcceptCountdown = LinkAcceptTimeout
}

// ClearLinkAcceptTimeout cancels the Link Accept wait.
func (r *Router) ClearLinkAcceptTimeout() {
	r.LinkAcceptCountdown = 0
}

// DecrementLinkAcceptTimeout decrements the countdown by one second.
// Returns true if the timer has expired (reached zero).
func (r *Router) DecrementLinkAcceptTimeout() bool {
	if r.LinkAcceptCountdown > 0 {
		r.LinkAcceptCountdown--
	}
	return r.LinkAcceptCountdown == 0
}

// HasRemainingLinkRequestAttempts reports whether retries remain.
func (r *Router) HasRemainingLinkRequestAttempts() bool {
	return r.RemainingLinkRequestAttempts > 0
}

// SetLinkRequestAttemptsToMax resets the Link Request retry count.
func (r *Router) SetLinkRequestAttemptsToMax() {
	r.RemainingLinkRequestAttempts = LinkRequestAttempts
}

// DecrementLinkRequestAttempts decrements the remaining attempts.
func (r *Router) DecrementLinkRequestAttempts() {
	if r.RemainingLinkRequestAttempts > 0 {
		r.RemainingLinkRequestAttempts--
	}
}

// Parent represents the parent of a child device. It extends Router with
// leader-cost and CSL accuracy.
type Parent struct {
	Router
	// LeaderCost is the route cost from the parent to the leader.
	LeaderCost uint8
}

// MaxRequestTLVs is the maximum number of TLV types a child can request
// in its Child ID Request's TLV Request TLV.
const MaxRequestTLVs = 5

// MaxChildIPAddresses is the maximum number of IPv6 addresses a child can
// register with its parent (excluding the mesh-local EID).
const MaxChildIPAddresses = 5

// Child represents a Thread child maintained by a router or leader.
type Child struct {
	Neighbor
	// Timeout is the child's keep-alive timeout in seconds.
	Timeout uint32
	// MeshLocalIID is the child's mesh-local interface identifier.
	MeshLocalIID ip6.InterfaceIdentifier
	// IP6Addresses holds the child's registered IPv6 addresses
	// (excluding the mesh-local EID).
	IP6Addresses [MaxChildIPAddresses]ip6.Address
	// IP6AddressCount is the number of valid entries in IP6Addresses.
	IP6AddressCount uint8
	// NetworkDataVersion is the version of network data the child has.
	NetworkDataVersion uint8
	// SupervisionInterval is the child supervision interval in seconds.
	SupervisionInterval uint16
	// SecondsSinceSupervision is seconds since the last supervision message.
	SecondsSinceSupervision uint16
	// RequestTLVs stores the TLV types requested by the child in its
	// Child ID Request. Up to MaxRequestTLVs entries are stored.
	RequestTLVs [MaxRequestTLVs]uint8
	// RequestTLVCount is the number of valid entries in RequestTLVs.
	RequestTLVCount uint8
	// CSLPeriod is the CSL (Coordinated Sampled Listening) period in units
	// of 10 symbols.
	CSLPeriod uint16
	// CSLPhase is the CSL phase in units of 10 symbols.
	CSLPhase uint16
}

// AddIP6Address adds an IPv6 address to the child's registration list.
// Returns false if the list is full.
func (c *Child) AddIP6Address(addr ip6.Address) bool {
	if c.IP6AddressCount >= MaxChildIPAddresses {
		return false
	}
	c.IP6Addresses[c.IP6AddressCount] = addr
	c.IP6AddressCount++
	return true
}

// HasIP6Address reports whether the child has the given IPv6 address registered.
func (c *Child) HasIP6Address(addr ip6.Address) bool {
	for i := uint8(0); i < c.IP6AddressCount; i++ {
		if c.IP6Addresses[i] == addr {
			return true
		}
	}
	return false
}

// ClearIP6Addresses removes all registered IPv6 addresses.
func (c *Child) ClearIP6Addresses() {
	c.IP6AddressCount = 0
	c.IP6Addresses = [MaxChildIPAddresses]ip6.Address{}
}

// ClearRequestTLVs removes all stored request TLV types.
func (c *Child) ClearRequestTLVs() {
	c.RequestTLVCount = 0
	c.RequestTLVs = [MaxRequestTLVs]uint8{}
}

// SetRequestTLVs stores the TLV types from a TLV Request TLV value.
// At most MaxRequestTLVs types are stored; the rest are silently dropped.
func (c *Child) SetRequestTLVs(tlvTypes []uint8) {
	c.ClearRequestTLVs()
	n := len(tlvTypes)
	if n > MaxRequestTLVs {
		n = MaxRequestTLVs
	}
	for i := 0; i < n; i++ {
		c.RequestTLVs[i] = tlvTypes[i]
	}
	c.RequestTLVCount = uint8(n)
}

// GetRequestTLVs returns a slice of the stored request TLV types.
func (c *Child) GetRequestTLVs() []uint8 {
	return c.RequestTLVs[:c.RequestTLVCount]
}

// GetMeshLocalIP6Address constructs the child's mesh-local IPv6 address from
// the given mesh-local prefix and the child's IID.
func (c *Child) GetMeshLocalIP6Address(prefix ip6.NetworkPrefix) ip6.Address {
	var addr ip6.Address
	copy(addr[:8], prefix[:])
	iid := c.MeshLocalIID
	copy(addr[8:], iid[:])
	return addr
}
