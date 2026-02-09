// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file implements FTD (Full Thread Device) specific MLE functionality
// including router link establishment, advertisement, and role transitions.
//
// This is a Go port of the FTD-specific MLE logic defined in OpenThread's
// src/core/thread/mle_ftd.cpp and the FTD portions of mle.hpp.

package mle

import "time"

// FTD advertisement timing constants.
const (
	// AdvIntervalMin is the Trickle timer minimum interval for
	// MLE Advertisements (milliseconds).
	AdvIntervalMin = 1000 * time.Millisecond

	// AdvIntervalNeighborMultiplier is multiplied by (neighbor_count + 1)
	// to compute the Trickle I_MAX (milliseconds).
	AdvIntervalNeighborMultiplier = 4000 * time.Millisecond

	// AdvIntervalMaxLowerBound is the minimum allowed I_MAX for the
	// advertisement Trickle timer (milliseconds).
	AdvIntervalMaxLowerBound = 12000 * time.Millisecond

	// AdvIntervalMaxUpperBound is the maximum allowed I_MAX for the
	// advertisement Trickle timer (milliseconds).
	AdvIntervalMaxUpperBound = 32000 * time.Millisecond
)

// REED (Router-Eligible End Device) timing constants.
const (
	// ReedAdvIntervalMin is the minimum interval for REED advertisements
	// (milliseconds).
	ReedAdvIntervalMin = 570000 * time.Millisecond

	// ReedAdvIntervalMax is the maximum interval for REED advertisements
	// (milliseconds).
	ReedAdvIntervalMax = 630000 * time.Millisecond
)

// FTD link establishment timing constants.
const (
	// MaxLinkRequestDelayOnRouter is the maximum random delay before
	// sending a Link Request on a router (milliseconds).
	MaxLinkRequestDelayOnRouter = 1000 * time.Millisecond

	// MinLinkRequestDelayOnChild is the minimum delay before sending a
	// Link Request when operating as an FTD child (milliseconds).
	MinLinkRequestDelayOnChild = 1500 * time.Millisecond

	// MaxLinkRequestDelayOnChild is the maximum delay before sending a
	// Link Request when operating as an FTD child (milliseconds).
	MaxLinkRequestDelayOnChild = 3000 * time.Millisecond

	// MaxLinkAcceptDelay is the maximum delay before sending a Link
	// Accept in response to a multicast Link Request (milliseconds).
	MaxLinkAcceptDelay = 1000 * time.Millisecond

	// LinkRequestTimeout is the maximum time to wait for a Link Accept
	// after sending a Link Request (milliseconds).
	LinkRequestTimeout = 2000 * time.Millisecond
)

// FTD neighbor aging constants.
const (
	// MaxNeighborAge is the maximum age of a router neighbor before it
	// is considered stale (milliseconds).
	MaxNeighborAge = 100000 * time.Millisecond

	// MaxNeighborAgeOnChild is the maximum age of a router neighbor
	// when operating as an FTD child (milliseconds).
	MaxNeighborAgeOnChild = 150000 * time.Millisecond
)

// Router selection and threshold constants.
const (
	// RouterSelectionJitter is the jitter window in seconds for router
	// upgrade/downgrade decisions.
	RouterSelectionJitter uint8 = 120

	// DefaultRouterUpgradeThreshold is the default number of active
	// routers below which an FTD child should upgrade to router.
	DefaultRouterUpgradeThreshold uint8 = 16

	// DefaultRouterDowngradeThreshold is the default number of active
	// routers above which a router should consider downgrading.
	DefaultRouterDowngradeThreshold uint8 = 23

	// MinDowngradeNeighbors is the minimum number of good neighbors
	// required before a router considers downgrading.
	MinDowngradeNeighbors uint8 = 7

	// LeaderDowngradeExtraDelay is the additional timeout in seconds
	// the leader waits before downgrading.
	LeaderDowngradeExtraDelay uint8 = 10

	// NetworkIDTimeout is the leader age threshold in seconds before
	// the device considers re-attaching to a different partition.
	NetworkIDTimeout uint8 = 120

	// ChildRouterLinks is the target number of router links when
	// operating as an FTD child.
	ChildRouterLinks uint8 = 3
)

// RouterUpgradeReason indicates why a router upgrade was requested.
type RouterUpgradeReason uint8

const (
	// UpgradeReasonTooFewRouters indicates upgrade because the active
	// router count is below the upgrade threshold.
	UpgradeReasonTooFewRouters RouterUpgradeReason = 2

	// UpgradeReasonHaveChildIDRequest indicates upgrade because a
	// Child ID Request was received (the device needs to act as a router).
	UpgradeReasonHaveChildIDRequest RouterUpgradeReason = 3

	// UpgradeReasonParentPartitionChange indicates upgrade because the
	// parent's partition changed.
	UpgradeReasonParentPartitionChange RouterUpgradeReason = 4

	// UpgradeReasonBorderRouterRequest indicates upgrade because a
	// Border Router service requires router capability.
	UpgradeReasonBorderRouterRequest RouterUpgradeReason = 5
)

// RouterRoleTransition manages the countdown timer for router role
// upgrade/downgrade decisions.
type RouterRoleTransition struct {
	timeout uint8 // countdown in seconds, 0 = not pending
	jitter  uint8 // jitter window (default = RouterSelectionJitter)
}

// NewRouterRoleTransition creates a RouterRoleTransition with the default
// jitter value.
func NewRouterRoleTransition() RouterRoleTransition {
	return RouterRoleTransition{
		jitter: RouterSelectionJitter,
	}
}

// IsPending reports whether a role transition is pending.
func (t *RouterRoleTransition) IsPending() bool {
	return t.timeout > 0
}

// GetTimeout returns the current countdown value in seconds.
func (t *RouterRoleTransition) GetTimeout() uint8 {
	return t.timeout
}

// GetJitter returns the configured jitter window in seconds.
func (t *RouterRoleTransition) GetJitter() uint8 {
	return t.jitter
}

// SetJitter sets the jitter window in seconds.
func (t *RouterRoleTransition) SetJitter(jitter uint8) {
	t.jitter = jitter
}

// StartTimeout begins a new countdown with a random value in [0, jitter).
// If jitter is 0 or 1 the timeout is set to 1.
func (t *RouterRoleTransition) StartTimeout(randFn func(n int) int) {
	if t.jitter <= 1 {
		t.timeout = 1
		return
	}
	t.timeout = uint8(randFn(int(t.jitter)))
	if t.timeout == 0 {
		t.timeout = 1
	}
}

// StopTimeout cancels any pending transition.
func (t *RouterRoleTransition) StopTimeout() {
	t.timeout = 0
}

// IncreaseTimeout adds delta seconds to the current timeout, capping at
// the jitter window.
func (t *RouterRoleTransition) IncreaseTimeout(delta uint8) {
	newTimeout := uint16(t.timeout) + uint16(delta)
	if newTimeout > uint16(t.jitter) {
		newTimeout = uint16(t.jitter)
	}
	t.timeout = uint8(newTimeout)
}

// HandleTimeTick decrements the countdown by one second. Returns true
// if the timer just expired (reached zero from a non-zero value).
func (t *RouterRoleTransition) HandleTimeTick() bool {
	if t.timeout == 0 {
		return false
	}
	t.timeout--
	return t.timeout == 0
}

// FtdState holds the FTD-specific fields for the Mle state machine.
// These are separated into their own struct for clarity, but are embedded
// in Mle.
type FtdState struct {
	// routerID is the device's allocated Router ID (0-62).
	// InvalidRouterID (63) means no router ID is allocated.
	routerID uint8

	// addressSolicitPending indicates an Address Solicit CoAP request
	// is in flight.
	addressSolicitPending bool

	// addressSolicitRejected indicates the last Address Solicit was
	// rejected by the leader.
	addressSolicitRejected bool

	// networkIDTimeout is the leader age threshold in seconds before
	// re-attaching.
	networkIDTimeout uint8

	// routerUpgradeThreshold is the active router count below which
	// the device should upgrade to router.
	routerUpgradeThreshold uint8

	// routerDowngradeThreshold is the active router count above which
	// a router should consider downgrading.
	routerDowngradeThreshold uint8

	// leaderWeight is the partition weight this device contributes
	// when it becomes the leader.
	leaderWeight uint8

	// childRouterLinks is the target number of router links when
	// operating as an FTD child.
	childRouterLinks uint8

	// previousPartitionID stores the partition ID before the last
	// partition change (for merge detection).
	previousPartitionID uint32

	// previousPartitionRouterIDSequence stores the router ID sequence
	// of the previous partition.
	previousPartitionRouterIDSequence uint8

	// previousPartitionRouterIDSet stores the router ID set of the
	// previous partition.
	previousPartitionRouterIDSet RouterIDSet

	// routerRoleTransition manages the jitter timer for upgrade/downgrade.
	routerRoleTransition RouterRoleTransition
}

// newFtdState creates FtdState with default values.
func newFtdState() FtdState {
	return FtdState{
		routerID:                 InvalidRouterID,
		networkIDTimeout:         NetworkIDTimeout,
		routerUpgradeThreshold:   DefaultRouterUpgradeThreshold,
		routerDowngradeThreshold: DefaultRouterDowngradeThreshold,
		leaderWeight:             64, // Default leader weight
		childRouterLinks:         ChildRouterLinks,
		routerRoleTransition:     NewRouterRoleTransition(),
	}
}

// --- FTD accessors on Mle ---

// GetRouterID returns the device's allocated Router ID.
// Returns InvalidRouterID if no router ID is allocated.
func (m *Mle) GetRouterID() uint8 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ftd.routerID
}

// SetRouterID sets the device's allocated Router ID.
func (m *Mle) SetRouterID(id uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ftd.routerID = id
}

// IsAddressSolicitPending reports whether an Address Solicit request is
// in flight.
func (m *Mle) IsAddressSolicitPending() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ftd.addressSolicitPending
}

// SetAddressSolicitPending sets whether an Address Solicit request is
// in flight.
func (m *Mle) SetAddressSolicitPending(pending bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ftd.addressSolicitPending = pending
}

// IsAddressSolicitRejected reports whether the last Address Solicit was
// rejected.
func (m *Mle) IsAddressSolicitRejected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ftd.addressSolicitRejected
}

// SetAddressSolicitRejected sets whether the last Address Solicit was
// rejected.
func (m *Mle) SetAddressSolicitRejected(rejected bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ftd.addressSolicitRejected = rejected
}

// GetNetworkIDTimeout returns the leader age threshold in seconds.
func (m *Mle) GetNetworkIDTimeout() uint8 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ftd.networkIDTimeout
}

// SetNetworkIDTimeout sets the leader age threshold in seconds.
func (m *Mle) SetNetworkIDTimeout(timeout uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ftd.networkIDTimeout = timeout
}

// GetRouterUpgradeThreshold returns the active router count threshold
// for upgrade.
func (m *Mle) GetRouterUpgradeThreshold() uint8 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ftd.routerUpgradeThreshold
}

// SetRouterUpgradeThreshold sets the active router count threshold for
// upgrade.
func (m *Mle) SetRouterUpgradeThreshold(threshold uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ftd.routerUpgradeThreshold = threshold
}

// GetRouterDowngradeThreshold returns the active router count threshold
// for downgrade.
func (m *Mle) GetRouterDowngradeThreshold() uint8 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ftd.routerDowngradeThreshold
}

// SetRouterDowngradeThreshold sets the active router count threshold for
// downgrade.
func (m *Mle) SetRouterDowngradeThreshold(threshold uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ftd.routerDowngradeThreshold = threshold
}

// GetLeaderWeight returns the partition weight for this device.
func (m *Mle) GetLeaderWeight() uint8 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ftd.leaderWeight
}

// SetLeaderWeight sets the partition weight for this device.
func (m *Mle) SetLeaderWeight(weight uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ftd.leaderWeight = weight
}

// GetChildRouterLinks returns the target number of router links as an
// FTD child.
func (m *Mle) GetChildRouterLinks() uint8 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ftd.childRouterLinks
}

// SetChildRouterLinks sets the target number of router links as an FTD
// child.
func (m *Mle) SetChildRouterLinks(count uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ftd.childRouterLinks = count
}

// GetPreviousPartitionID returns the previous partition ID.
func (m *Mle) GetPreviousPartitionID() uint32 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ftd.previousPartitionID
}

// SetPreviousPartitionID sets the previous partition ID.
func (m *Mle) SetPreviousPartitionID(id uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ftd.previousPartitionID = id
}

// GetPreviousPartitionRouterIDSequence returns the router ID sequence of
// the previous partition.
func (m *Mle) GetPreviousPartitionRouterIDSequence() uint8 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ftd.previousPartitionRouterIDSequence
}

// SetPreviousPartitionRouterIDSequence sets the router ID sequence of the
// previous partition.
func (m *Mle) SetPreviousPartitionRouterIDSequence(seq uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ftd.previousPartitionRouterIDSequence = seq
}

// GetPreviousPartitionRouterIDSet returns a copy of the previous
// partition's router ID set.
func (m *Mle) GetPreviousPartitionRouterIDSet() RouterIDSet {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ftd.previousPartitionRouterIDSet
}

// SetPreviousPartitionRouterIDSet sets the previous partition's router
// ID set.
func (m *Mle) SetPreviousPartitionRouterIDSet(set RouterIDSet) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ftd.previousPartitionRouterIDSet = set
}

// GetRouterRoleTransition returns a pointer to the router role transition
// timer. The caller must hold the Mle lock if concurrent access is possible.
func (m *Mle) GetRouterRoleTransition() *RouterRoleTransition {
	return &m.ftd.routerRoleTransition
}

// SavePreviousPartitionInfo records the current partition information
// for later merge detection. Must be called before switching partitions.
func (m *Mle) SavePreviousPartitionInfo(routerIDSequence uint8, routerIDSet RouterIDSet) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ftd.previousPartitionID = m.leaderData.PartitionID
	m.ftd.previousPartitionRouterIDSequence = routerIDSequence
	m.ftd.previousPartitionRouterIDSet = routerIDSet
}

// IsFullThreadDevice reports whether the device mode includes FTD capability.
func (m *Mle) IsFullThreadDevice() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.deviceMode.IsFullThreadDevice()
}

// DetermineAdvertiseIntervalMax computes the Trickle I_MAX for advertisements
// based on the number of link-quality-2+ neighbors. The formula is:
//
//	iMax = (lq2Neighbors + 1) * AdvIntervalNeighborMultiplier
//
// clamped to [AdvIntervalMaxLowerBound, AdvIntervalMaxUpperBound].
func DetermineAdvertiseIntervalMax(lq2Neighbors int) time.Duration {
	iMax := time.Duration(lq2Neighbors+1) * AdvIntervalNeighborMultiplier
	if iMax < AdvIntervalMaxLowerBound {
		iMax = AdvIntervalMaxLowerBound
	}
	if iMax > AdvIntervalMaxUpperBound {
		iMax = AdvIntervalMaxUpperBound
	}
	return iMax
}
