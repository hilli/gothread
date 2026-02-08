// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package routing implements Thread mesh routing table management and neighbor
// tracking.
//
// This is a Go port of the routing types and tables from OpenThread's
// src/core/thread/neighbor.hpp, src/core/thread/router.hpp,
// src/core/thread/child.hpp, src/core/thread/router_table.hpp,
// src/core/thread/child_table.hpp, and src/core/thread/neighbor_table.hpp.
package routing

import (
	"fmt"

	mac_types "github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/thread/link"
	"github.com/hilli/gothread/thread/mle"
)

// State represents the state of a neighbor.
type State uint8

const (
	// StateInvalid indicates an invalid or uninitialized neighbor entry.
	StateInvalid State = 0
	// StateRestored indicates a neighbor restored from non-volatile storage.
	StateRestored State = 1
	// StateParentRequest indicates a parent request has been sent.
	StateParentRequest State = 2
	// StateParentResponse indicates a parent response has been received.
	StateParentResponse State = 3
	// StateChildIDRequest indicates a Child ID Request has been sent.
	StateChildIDRequest State = 4
	// StateLinkRequest indicates a link request has been sent.
	StateLinkRequest State = 5
	// StateChildUpdateRequest indicates a Child Update Request has been sent.
	StateChildUpdateRequest State = 6
	// StateValid indicates the neighbor is in a fully valid state.
	StateValid State = 7
)

// String returns a human-readable name for the State.
func (s State) String() string {
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
		return fmt.Sprintf("Unknown(%d)", s)
	}
}

// StateFilter is used to filter neighbors by state.
type StateFilter uint8

const (
	// FilterValid matches only StateValid.
	FilterValid StateFilter = 0
	// FilterValidOrRestoring matches StateValid or StateRestored.
	FilterValidOrRestoring StateFilter = 1
	// FilterChildIDRequest matches only StateChildIDRequest.
	FilterChildIDRequest StateFilter = 2
	// FilterValidOrAttaching matches StateValid, StateChildIDRequest,
	// or StateChildUpdateRequest.
	FilterValidOrAttaching StateFilter = 3
	// FilterInvalid matches only StateInvalid.
	FilterInvalid StateFilter = 4
	// FilterAnyExceptInvalid matches any state except StateInvalid.
	FilterAnyExceptInvalid StateFilter = 5
	// FilterAnyExceptValidOrRestoring matches any state except StateValid and StateRestored.
	FilterAnyExceptValidOrRestoring StateFilter = 6
	// FilterAny matches all states.
	FilterAny StateFilter = 7
	// FilterLinkRequest matches only StateLinkRequest.
	FilterLinkRequest StateFilter = 8
)

// String returns a human-readable name for the StateFilter.
func (f StateFilter) String() string {
	switch f {
	case FilterValid:
		return "Valid"
	case FilterValidOrRestoring:
		return "ValidOrRestoring"
	case FilterChildIDRequest:
		return "ChildIDRequest"
	case FilterValidOrAttaching:
		return "ValidOrAttaching"
	case FilterInvalid:
		return "Invalid"
	case FilterAnyExceptInvalid:
		return "AnyExceptInvalid"
	case FilterAnyExceptValidOrRestoring:
		return "AnyExceptValidOrRestoring"
	case FilterAny:
		return "Any"
	case FilterLinkRequest:
		return "LinkRequest"
	default:
		return fmt.Sprintf("Unknown(%d)", f)
	}
}

// MatchesFilter returns whether the given state matches the filter.
func (s State) MatchesFilter(f StateFilter) bool {
	switch f {
	case FilterValid:
		return s == StateValid
	case FilterValidOrRestoring:
		return s == StateValid || s == StateRestored
	case FilterChildIDRequest:
		return s == StateChildIDRequest
	case FilterValidOrAttaching:
		return s == StateValid ||
			s == StateChildIDRequest || s == StateChildUpdateRequest
	case FilterInvalid:
		return s == StateInvalid
	case FilterAnyExceptInvalid:
		return s != StateInvalid
	case FilterAnyExceptValidOrRestoring:
		return s != StateValid && s != StateRestored
	case FilterAny:
		return true
	case FilterLinkRequest:
		return s == StateLinkRequest
	default:
		return false
	}
}

// Neighbor represents a Thread mesh neighbor (base for Router and Child).
type Neighbor struct {
	ExtAddress       mac_types.ExtAddress
	LastHeard        uint32 // millisecond timestamp
	KeySequence      uint32
	RLOC16           uint16
	State            State
	Mode             mle.DeviceMode
	LinkFailures     uint8
	Version          uint16
	LinkInfo         link.QualityInfo
	LinkFrameCounter uint32
	MleFrameCounter  uint32
	Challenge        [8]byte
}

// IsStateValid returns true if the neighbor is in StateValid.
func (n *Neighbor) IsStateValid() bool {
	return n.State == StateValid
}

// IsStateRestoring returns true if the neighbor is in StateRestored.
func (n *Neighbor) IsStateRestoring() bool {
	return n.State == StateRestored
}

// IsStateValidOrRestoring returns true if the neighbor is in StateValid
// or StateRestored.
func (n *Neighbor) IsStateValidOrRestoring() bool {
	return n.State == StateValid || n.State == StateRestored
}

// IsStateValidOrAttaching returns true if the neighbor is in StateValid,
// StateChildIDRequest, or StateChildUpdateRequest.
func (n *Neighbor) IsStateValidOrAttaching() bool {
	return n.State == StateValid ||
		n.State == StateChildIDRequest || n.State == StateChildUpdateRequest
}

// GetRouterID extracts the router ID from the neighbor's RLOC16.
func (n *Neighbor) GetRouterID() uint8 {
	return mle.RouterIDFromRLOC16(n.RLOC16)
}

// IncrementLinkFailures increments the link failure counter, capping at 255.
func (n *Neighbor) IncrementLinkFailures() {
	if n.LinkFailures < 255 {
		n.LinkFailures++
	}
}

// ResetLinkFailures resets the link failure counter to zero.
func (n *Neighbor) ResetLinkFailures() {
	n.LinkFailures = 0
}
