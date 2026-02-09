// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package netdata

import "github.com/hilli/gothread/errors"

// ---------------------------------------------------------------------------
// Context ID Manager
// ---------------------------------------------------------------------------

// ContextIDState represents the state of a 6LoWPAN context ID.
type ContextIDState uint8

const (
	// ContextIDUnallocated indicates the context ID is free.
	ContextIDUnallocated ContextIDState = iota
	// ContextIDInUse indicates the context ID is actively assigned.
	ContextIDInUse
	// ContextIDScheduledToRemove indicates the context ID is pending removal
	// after the reuse delay expires.
	ContextIDScheduledToRemove
)

const (
	// minContextID is the smallest allocatable 6LoWPAN context ID.
	minContextID = 1
	// maxContextID is the largest allocatable 6LoWPAN context ID.
	maxContextID = 15
	// contextIDCount is the number of allocatable context IDs (1-15).
	contextIDCount = maxContextID - minContextID + 1
)

// DefaultContextIDReuseDelay is the default time (in milliseconds) to wait
// before a released context ID may be re-allocated. Per the Thread
// specification this is 5 minutes (300 seconds).
const DefaultContextIDReuseDelay uint32 = 5 * 60 * 1000 // 300_000 ms

// contextIDUnallocatedSentinel is the stored timestamp value meaning "free".
const contextIDUnallocatedSentinel uint32 = 0

// contextIDInUseSentinel is the stored timestamp value meaning "in use".
const contextIDInUseSentinel uint32 = 1

// InvalidContextID is returned when no context ID is available.
const InvalidContextID uint8 = 0xFF

// ContextIDManager tracks 6LoWPAN context IDs 1 through 15 with three
// states: Unallocated, InUse, and ScheduledToRemove. It mirrors OpenThread's
// Leader::ContextIds class from src/core/thread/network_data_leader.hpp.
//
// Time is represented as millisecond timestamps (uint32). The caller is
// responsible for providing the current time via HandleTimer and
// ScheduleToRemove.
type ContextIDManager struct {
	// removeTimes stores per-ID state. Values:
	//   0 = unallocated
	//   1 = in use
	//   other = absolute millisecond timestamp when ID should be freed
	removeTimes [contextIDCount]uint32
	reuseDelay  uint32
}

// NewContextIDManager creates a ContextIDManager with the default reuse delay.
func NewContextIDManager() *ContextIDManager {
	return &ContextIDManager{reuseDelay: DefaultContextIDReuseDelay}
}

// Clear marks all context IDs as unallocated.
func (c *ContextIDManager) Clear() {
	for i := range c.removeTimes {
		c.removeTimes[i] = contextIDUnallocatedSentinel
	}
}

// ReuseDelay returns the current reuse delay in milliseconds.
func (c *ContextIDManager) ReuseDelay() uint32 {
	return c.reuseDelay
}

// SetReuseDelay sets the reuse delay in milliseconds.
func (c *ContextIDManager) SetReuseDelay(delay uint32) {
	c.reuseDelay = delay
}

// State returns the state of the given context ID (1-15).
func (c *ContextIDManager) State(id uint8) ContextIDState {
	if id < minContextID || id > maxContextID {
		return ContextIDUnallocated
	}
	v := c.removeTimes[id-minContextID]
	switch v {
	case contextIDUnallocatedSentinel:
		return ContextIDUnallocated
	case contextIDInUseSentinel:
		return ContextIDInUse
	default:
		return ContextIDScheduledToRemove
	}
}

// GetUnallocatedID returns the first available context ID (1-15), or
// errors.ErrNotFound if none are available. The returned ID is NOT marked as
// in-use; the caller must call MarkAsInUse separately.
func (c *ContextIDManager) GetUnallocatedID() (uint8, error) {
	for id := uint8(minContextID); id <= maxContextID; id++ {
		if c.removeTimes[id-minContextID] == contextIDUnallocatedSentinel {
			return id, nil
		}
	}
	return InvalidContextID, errors.ErrNotFound
}

// MarkAsInUse transitions the context ID to the InUse state.
func (c *ContextIDManager) MarkAsInUse(id uint8) {
	if id >= minContextID && id <= maxContextID {
		c.removeTimes[id-minContextID] = contextIDInUseSentinel
	}
}

// MarkAsUnallocated transitions the context ID to the Unallocated state.
func (c *ContextIDManager) MarkAsUnallocated(id uint8) {
	if id >= minContextID && id <= maxContextID {
		c.removeTimes[id-minContextID] = contextIDUnallocatedSentinel
	}
}

// ScheduleToRemove transitions the context ID from InUse to
// ScheduledToRemove. The nowMs parameter is the current time in milliseconds.
// The ID will become re-allocatable after nowMs + reuseDelay. Returns the
// earliest next timer firing time (in ms) that the caller should schedule, or
// 0 if no timer is needed.
//
// If the ID is not currently InUse, this is a no-op and returns 0.
func (c *ContextIDManager) ScheduleToRemove(id uint8, nowMs uint32) uint32 {
	if id < minContextID || id > maxContextID {
		return 0
	}
	if c.removeTimes[id-minContextID] != contextIDInUseSentinel {
		return 0
	}
	removeTime := nowMs + c.reuseDelay
	// Avoid collision with sentinel values.
	for removeTime == contextIDUnallocatedSentinel || removeTime == contextIDInUseSentinel {
		removeTime++
	}
	c.removeTimes[id-minContextID] = removeTime
	return removeTime
}

// HandleTimer processes pending removals. The nowMs parameter is the current
// time in milliseconds. For each context ID in the ScheduledToRemove state
// whose removal time has passed, the provided callback is invoked with the
// context ID so the caller can remove the corresponding ContextTLV from
// network data.
//
// Returns the earliest next timer firing time (in ms) for IDs still pending,
// or 0 if no timers remain.
func (c *ContextIDManager) HandleTimer(nowMs uint32, onExpired func(id uint8)) uint32 {
	var nextFireTime uint32
	hasNext := false

	for id := uint8(minContextID); id <= maxContextID; id++ {
		v := c.removeTimes[id-minContextID]
		if v == contextIDUnallocatedSentinel || v == contextIDInUseSentinel {
			continue
		}
		// ScheduledToRemove state: v is the absolute removal timestamp.
		if timeMsGe(nowMs, v) {
			c.removeTimes[id-minContextID] = contextIDUnallocatedSentinel
			if onExpired != nil {
				onExpired(id)
			}
		} else if !hasNext || timeMsBefore(v, nextFireTime) {
			nextFireTime = v
			hasNext = true
		}
	}
	if hasNext {
		return nextFireTime
	}
	return 0
}

// PendingTimerIDs returns the context IDs currently in the ScheduledToRemove
// state. This is useful for inspecting state in tests.
func (c *ContextIDManager) PendingTimerIDs() []uint8 {
	var ids []uint8
	for id := uint8(minContextID); id <= maxContextID; id++ {
		if c.State(id) == ContextIDScheduledToRemove {
			ids = append(ids, id)
		}
	}
	return ids
}

// timeMsGe reports whether a >= b using uint32 millisecond wrapping arithmetic.
// This handles the case where the millisecond counter wraps around 2^32.
func timeMsGe(a, b uint32) bool {
	return int32(a-b) >= 0
}

// timeMsBefore reports whether a < b using uint32 millisecond wrapping arithmetic.
func timeMsBefore(a, b uint32) bool {
	return int32(a-b) < 0
}
