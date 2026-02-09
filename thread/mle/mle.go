// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file implements the core MLE (Mesh Link Establishment) state machine
// for Thread networking.
//
// The Mle type manages device role transitions (Disabled -> Detached -> Child
// -> Router -> Leader) and tracks the associated state for each role.
//
// This is a Go port of the MLE state machine defined in OpenThread's
// src/core/thread/mle.hpp and src/core/thread/mle.cpp.

package mle

import (
	"sync"
	"time"

	goterrors "github.com/hilli/gothread/errors"
)

// AttachMode controls the type of partition the device will try to join.
type AttachMode uint8

const (
	// AttachAnyPartition attempts to attach to any Thread partition.
	AttachAnyPartition AttachMode = 0
	// AttachSamePartition attempts to re-attach to the same partition.
	AttachSamePartition AttachMode = 1
	// AttachBetterPartition looks for a partition with better parameters.
	AttachBetterPartition AttachMode = 2
	// AttachSamePartitionRetry retries attachment to the same partition.
	AttachSamePartitionRetry AttachMode = 3
	// AttachBetterParent searches for a better parent within the same partition.
	AttachBetterParent AttachMode = 4
	// AttachSelectedParent attaches to a specific pre-selected parent.
	AttachSelectedParent AttachMode = 5
)

// String returns a human-readable name for the attach mode.
func (m AttachMode) String() string {
	switch m {
	case AttachAnyPartition:
		return "AnyPartition"
	case AttachSamePartition:
		return "SamePartition"
	case AttachBetterPartition:
		return "BetterPartition"
	case AttachSamePartitionRetry:
		return "SamePartitionRetry"
	case AttachBetterParent:
		return "BetterParent"
	case AttachSelectedParent:
		return "SelectedParent"
	default:
		return "Unknown"
	}
}

// AttachState represents the sub-state of the attach process.
type AttachState uint8

const (
	// AttachStateIdle means no attach is in progress.
	AttachStateIdle AttachState = 0
	// AttachStateStart means an attach was requested and is starting.
	AttachStateStart AttachState = 1
	// AttachStateParentRequest means a Parent Request has been sent.
	AttachStateParentRequest AttachState = 2
	// AttachStateAnnounce means an Announce message is being processed.
	AttachStateAnnounce AttachState = 3
	// AttachStateChildIDRequest means a Child ID Request has been sent.
	AttachStateChildIDRequest AttachState = 4
)

// String returns a human-readable name for the attach state.
func (s AttachState) String() string {
	switch s {
	case AttachStateIdle:
		return "Idle"
	case AttachStateStart:
		return "Start"
	case AttachStateParentRequest:
		return "ParentRequest"
	case AttachStateAnnounce:
		return "Announce"
	case AttachStateChildIDRequest:
		return "ChildIDRequest"
	default:
		return "Unknown"
	}
}

// MLE timing constants from the Thread specification.
const (
	// ParentRequestRouterTimeout is the timeout for Parent Requests to routers.
	ParentRequestRouterTimeout = 750 * time.Millisecond
	// ParentRequestReedTimeout is the timeout for Parent Requests including REEDs.
	ParentRequestReedTimeout = 1250 * time.Millisecond
	// ChildIDResponseTimeout is the timeout waiting for a Child ID Response.
	ChildIDResponseTimeout = 1250 * time.Millisecond
	// AttachStartJitter is the maximum random jitter before starting attach.
	AttachStartJitter = 50 * time.Millisecond
	// UnicastRetxDelay is the delay before retransmitting a unicast MLE message.
	UnicastRetxDelay = 1 * time.Second
	// MinTimeout is the minimum child timeout value.
	MinTimeout = 1 * time.Second
	// MaxTimeout is the maximum child timeout value (8 hours).
	MaxTimeout = 8 * time.Hour
)

// ThreadVersion is the MLE protocol version for Thread 1.4.
const ThreadVersion uint16 = 4

// RoleChangeCallback is called when the device role changes.
type RoleChangeCallback func(oldRole, newRole DeviceRole)

// RoleCounters tracks the number of transitions to each role.
type RoleCounters struct {
	// DisabledCount is the number of transitions to Disabled.
	DisabledCount uint32
	// DetachedCount is the number of transitions to Detached.
	DetachedCount uint32
	// ChildCount is the number of transitions to Child.
	ChildCount uint32
	// RouterCount is the number of transitions to Router.
	RouterCount uint32
	// LeaderCount is the number of transitions to Leader.
	LeaderCount uint32
	// AttachAttempts is the total number of attach attempts.
	AttachAttempts uint32
	// ParentChanges is the number of times the parent changed.
	ParentChanges uint32
}

// Mle is the core MLE state machine. It manages the device's role in a
// Thread network and tracks associated state for each role.
//
// The zero value is not usable; create instances with NewMle.
type Mle struct {
	mu sync.RWMutex

	// role is the current device role.
	role DeviceRole
	// previousRole is the role before the last transition.
	previousRole DeviceRole

	// rloc16 is the device's current RLOC16 short address.
	rloc16 uint16

	// deviceMode is the MLE device mode flags.
	deviceMode DeviceMode

	// leaderData contains the current leader information.
	leaderData LeaderData

	// parent is the parent of this device (when role is Child).
	parent Parent

	// parentCandidate is a candidate parent during the attach process.
	parentCandidate Parent

	// attachMode is the current attach mode.
	attachMode AttachMode
	// attachState is the current sub-state of the attach process.
	attachState AttachState

	// childTimeout is the child timeout value in seconds.
	childTimeout uint32

	// routerEligible indicates whether the device can become a router.
	routerEligible bool

	// lastAttachTime records when the device last attached.
	lastAttachTime time.Time
	// roleStartTime records when the current role was entered.
	roleStartTime time.Time

	// counters tracks role transition statistics.
	counters RoleCounters

	// onRoleChange is called when the device role changes.
	onRoleChange RoleChangeCallback

	// previousRouterID stores the last router ID (for reconnection).
	previousRouterID uint8

	// retrieveNewNetworkData is set when the child needs to request
	// fresh network data from its parent via a Data Request.
	retrieveNewNetworkData bool

	// dataRequestPending indicates a Data Request should be sent to
	// the parent (scheduled by HandleAdvertisement or HandleDataResponse).
	dataRequestPending bool

	// ftd holds FTD-specific state (router ID, thresholds, etc.).
	ftd FtdState
}

// NewMle creates a new MLE state machine in the Disabled state.
func NewMle() *Mle {
	m := &Mle{
		role:             RoleDisabled,
		rloc16:           InvalidRLOC16,
		childTimeout:     240, // Default 240 seconds
		routerEligible:   true,
		previousRouterID: InvalidRouterID,
		ftd:              newFtdState(),
	}
	m.deviceMode.Set(ModeRxOnWhenIdle | ModeFullThreadDevice | ModeFullNetworkData)
	return m
}

// Role returns the current device role.
func (m *Mle) Role() DeviceRole {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.role
}

// RLOC16 returns the current RLOC16 short address.
func (m *Mle) RLOC16() uint16 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rloc16
}

// IsDisabled reports whether the MLE interface is disabled.
func (m *Mle) IsDisabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.role == RoleDisabled
}

// IsDetached reports whether the device is detached from any network.
func (m *Mle) IsDetached() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.role == RoleDetached
}

// IsChild reports whether the device is a child.
func (m *Mle) IsChild() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.role == RoleChild
}

// IsRouter reports whether the device is a router.
func (m *Mle) IsRouter() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.role == RoleRouter
}

// IsLeader reports whether the device is the leader.
func (m *Mle) IsLeader() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.role == RoleLeader
}

// IsAttached reports whether the device is attached (Child, Router, or Leader).
func (m *Mle) IsAttached() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.role >= RoleChild
}

// IsRouterOrLeader reports whether the device is a Router or Leader.
func (m *Mle) IsRouterOrLeader() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.role >= RoleRouter
}

// GetDeviceMode returns the current device mode.
func (m *Mle) GetDeviceMode() DeviceMode {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.deviceMode
}

// SetDeviceMode updates the device mode.
func (m *Mle) SetDeviceMode(mode DeviceMode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deviceMode = mode
}

// GetLeaderData returns a copy of the current leader data.
func (m *Mle) GetLeaderData() LeaderData {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.leaderData
}

// SetLeaderData updates the leader data.
func (m *Mle) SetLeaderData(data LeaderData) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.leaderData = data
}

// GetParent returns a pointer to the parent entry.
func (m *Mle) GetParent() *Parent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return &m.parent
}

// GetParentCandidate returns a pointer to the parent candidate.
func (m *Mle) GetParentCandidate() *Parent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return &m.parentCandidate
}

// GetChildTimeout returns the child timeout in seconds.
func (m *Mle) GetChildTimeout() uint32 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.childTimeout
}

// SetChildTimeout sets the child timeout in seconds.
func (m *Mle) SetChildTimeout(timeout uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.childTimeout = timeout
}

// IsRouterEligible reports whether the device can become a router.
func (m *Mle) IsRouterEligible() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.routerEligible
}

// SetRouterEligible sets whether the device can become a router.
func (m *Mle) SetRouterEligible(eligible bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routerEligible = eligible
}

// GetCounters returns a copy of the role transition counters.
func (m *Mle) GetCounters() RoleCounters {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.counters
}

// SetRoleChangeCallback sets a callback invoked on every role change.
func (m *Mle) SetRoleChangeCallback(cb RoleChangeCallback) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onRoleChange = cb
}

// GetAttachMode returns the current attach mode.
func (m *Mle) GetAttachMode() AttachMode {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.attachMode
}

// GetAttachState returns the current attach sub-state.
func (m *Mle) GetAttachState() AttachState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.attachState
}

// LastAttachTime returns the time of the last successful attach.
func (m *Mle) LastAttachTime() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastAttachTime
}

// RoleStartTime returns the time when the current role was entered.
func (m *Mle) RoleStartTime() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.roleStartTime
}

// --- State transitions ---

// Enable transitions the device from Disabled to Detached.
func (m *Mle) Enable() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.role != RoleDisabled {
		return goterrors.ErrAlready
	}

	m.setRole(RoleDetached)
	return nil
}

// Disable transitions the device to Disabled, clearing all state.
func (m *Mle) Disable() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.role == RoleDisabled {
		return goterrors.ErrAlready
	}

	m.setStateDisabled()
	return nil
}

// BecomeDetached transitions to the Detached state and invalidates the parent.
// This is the entry point for initiating a new attach process.
func (m *Mle) BecomeDetached() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.role == RoleDisabled {
		return goterrors.ErrInvalidState
	}

	m.setStateDetached()
	m.parent.Invalidate()
	m.rloc16 = InvalidRLOC16
	return nil
}

// SetStateChild transitions the device to the Child role with the given RLOC16.
// This is called when the attach process completes successfully.
func (m *Mle) SetStateChild(rloc16 uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.role == RoleDisabled {
		return goterrors.ErrInvalidState
	}

	oldParentRLOC := ParentRLOC16ForRLOC16(m.rloc16)
	newParentRLOC := ParentRLOC16ForRLOC16(rloc16)

	m.rloc16 = rloc16
	m.setRole(RoleChild)
	m.attachState = AttachStateIdle

	if oldParentRLOC != newParentRLOC {
		m.counters.ParentChanges++
	}

	return nil
}

// SetStateRouter transitions the device to the Router role with the given RLOC16.
// Only valid from the Child role on a Full Thread Device.
func (m *Mle) SetStateRouter(rloc16 uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.role == RoleDisabled {
		return goterrors.ErrInvalidState
	}

	m.rloc16 = rloc16
	m.setRole(RoleRouter)
	m.attachState = AttachStateIdle
	return nil
}

// SetStateLeader transitions the device to the Leader role with the given RLOC16.
func (m *Mle) SetStateLeader(rloc16 uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.role == RoleDisabled {
		return goterrors.ErrInvalidState
	}

	m.rloc16 = rloc16
	m.setRole(RoleLeader)
	m.attachState = AttachStateIdle
	return nil
}

// BecomeRouter initiates a transition from Child to Router.
// The actual role change happens asynchronously when the Address Solicit
// response is received. This method validates preconditions.
func (m *Mle) BecomeRouter() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch m.role {
	case RoleDisabled, RoleDetached:
		return goterrors.ErrInvalidState
	case RoleRouter, RoleLeader:
		return nil // Already a router or leader
	case RoleChild:
		if !m.routerEligible {
			return goterrors.ErrNotCapable
		}
		// In a real implementation, this would send an Address Solicit.
		// The role change happens when the response arrives.
		return nil
	default:
		return goterrors.ErrInvalidState
	}
}

// BecomeLeader creates a new partition with this device as Leader.
func (m *Mle) BecomeLeader() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.role == RoleDisabled {
		return goterrors.ErrInvalidState
	}
	if m.role == RoleLeader {
		return goterrors.ErrAlready
	}
	if !m.routerEligible {
		return goterrors.ErrNotCapable
	}

	// In a real implementation this would set up the leader data,
	// allocate a router ID, and call setRole(RoleLeader).
	return nil
}

// StartAttach begins the attach process with the given mode.
func (m *Mle) StartAttach(mode AttachMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.role == RoleDisabled {
		return goterrors.ErrInvalidState
	}
	if m.attachState != AttachStateIdle {
		return goterrors.ErrBusy
	}

	m.attachMode = mode
	m.attachState = AttachStateStart
	m.counters.AttachAttempts++
	return nil
}

// SetAttachState updates the attach sub-state. This is used by the attach
// process implementation to advance through the attach flow.
func (m *Mle) SetAttachState(state AttachState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attachState = state
}

// --- Internal helpers (must be called with mu held) ---

// setRole updates the role, fires the callback, and updates counters.
func (m *Mle) setRole(newRole DeviceRole) {
	if m.role == newRole {
		return
	}

	oldRole := m.role
	m.previousRole = oldRole
	m.role = newRole
	m.roleStartTime = time.Now()

	// Record attach time when transitioning from Detached to an attached role.
	if oldRole == RoleDetached && newRole >= RoleChild {
		m.lastAttachTime = time.Now()
	}

	// Update counters.
	switch newRole {
	case RoleDisabled:
		m.counters.DisabledCount++
	case RoleDetached:
		m.counters.DetachedCount++
	case RoleChild:
		m.counters.ChildCount++
	case RoleRouter:
		m.counters.RouterCount++
	case RoleLeader:
		m.counters.LeaderCount++
	}

	// If no longer a Child, invalidate the parent.
	if newRole != RoleChild && oldRole != RoleDisabled {
		m.parent.Invalidate()
	}

	if m.onRoleChange != nil {
		m.onRoleChange(oldRole, newRole)
	}
}

// setStateDisabled performs the full teardown for the Disabled state.
func (m *Mle) setStateDisabled() {
	m.setRole(RoleDisabled)
	m.attachState = AttachStateIdle
	m.rloc16 = InvalidRLOC16
	m.parent.Invalidate()
	m.parentCandidate.Invalidate()
}

// setStateDetached performs the full teardown for the Detached state.
func (m *Mle) setStateDetached() {
	m.setRole(RoleDetached)
	m.attachState = AttachStateIdle
}

// PreviousRole returns the role prior to the last transition.
func (m *Mle) PreviousRole() DeviceRole {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.previousRole
}

// NeedsNewNetworkData reports whether the child needs to request fresh
// network data from its parent.
func (m *Mle) NeedsNewNetworkData() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.retrieveNewNetworkData
}

// SetRetrieveNewNetworkData sets whether the child needs fresh network data.
func (m *Mle) SetRetrieveNewNetworkData(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.retrieveNewNetworkData = v
}

// IsDataRequestPending reports whether a Data Request is scheduled.
func (m *Mle) IsDataRequestPending() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.dataRequestPending
}

// SetDataRequestPending sets whether a Data Request should be sent.
func (m *Mle) SetDataRequestPending(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dataRequestPending = v
}
