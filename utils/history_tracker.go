// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package utils implements OpenThread utility modules including event history
// tracking, ICMPv6 ping sending, and mesh topology diagnostics.
//
// This is a Go port of the utilities in OpenThread's
// src/core/utils/history_tracker.cpp, src/core/utils/ping_sender.cpp,
// and src/core/utils/mesh_diag.cpp.
package utils

import "sync"

// ---------------------------------------------------------------------------
// EventType
// ---------------------------------------------------------------------------

// EventType identifies the type of tracked event.
type EventType uint8

const (
	// EventTypeNetworkInfo tracks network info changes.
	EventTypeNetworkInfo EventType = iota
	// EventTypeUnicastAddr tracks unicast address additions/removals.
	EventTypeUnicastAddr
	// EventTypeMulticastAddr tracks multicast address additions/removals.
	EventTypeMulticastAddr
	// EventTypeRxMessage tracks received messages.
	EventTypeRxMessage
	// EventTypeTxMessage tracks transmitted messages.
	EventTypeTxMessage
	// EventTypeNeighborChanged tracks neighbor add/remove/state changes.
	EventTypeNeighborChanged
	// EventTypeRouterInfo tracks router table changes.
	EventTypeRouterInfo
	// EventTypeExternalRoute tracks external route changes.
	EventTypeExternalRoute
)

// ---------------------------------------------------------------------------
// Event data types
// ---------------------------------------------------------------------------

// Event is a tracked event entry.
type Event struct {
	Type      EventType
	Timestamp uint32      // milliseconds since boot
	Data      interface{} // type-specific data
}

// NetworkInfoEvent holds data for EventTypeNetworkInfo events.
type NetworkInfoEvent struct {
	Role        uint8
	Mode        uint8
	Rloc16      uint16
	PartitionID uint32
}

// MessageEvent holds data for EventTypeRxMessage and EventTypeTxMessage events.
type MessageEvent struct {
	Source      [16]byte
	Destination [16]byte
	Length      uint16
	Checksum    uint16
	Type        uint8 // IPv6 next header
	Security    bool
}

// NeighborEvent holds data for EventTypeNeighborChanged events.
type NeighborEvent struct {
	ExtAddress [8]byte
	Rloc16     uint16
	IsChild    bool
	IsRouter   bool
	Event      string // "added", "removed", "changed"
}

// ---------------------------------------------------------------------------
// TrackerOption
// ---------------------------------------------------------------------------

// DefaultMaxEvents is the default maximum number of events in a Tracker.
const DefaultMaxEvents = 64

// TrackerOption configures a Tracker.
type TrackerOption func(*Tracker)

// WithMaxEvents sets the maximum number of events in the circular buffer.
func WithMaxEvents(n int) TrackerOption {
	return func(t *Tracker) {
		if n > 0 {
			t.maxEvents = n
		}
	}
}

// ---------------------------------------------------------------------------
// Tracker
// ---------------------------------------------------------------------------

// Tracker maintains a circular buffer of events for debugging purposes.
type Tracker struct {
	mu         sync.Mutex
	events     []Event
	maxEvents  int
	writeIndex int
	count      int
	enabled    bool
	timestamp  uint32 // monotonic timestamp counter (ms)
}

// NewTracker creates a new Tracker with the given options.
func NewTracker(opts ...TrackerOption) *Tracker {
	t := &Tracker{
		maxEvents: DefaultMaxEvents,
		enabled:   true,
	}
	for _, o := range opts {
		o(t)
	}
	t.events = make([]Event, t.maxEvents)
	return t
}

// RecordEvent records an event of the given type with associated data.
// If the tracker is disabled, the event is silently dropped.
func (t *Tracker) RecordEvent(eventType EventType, data interface{}) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.enabled {
		return
	}

	t.events[t.writeIndex] = Event{
		Type:      eventType,
		Timestamp: t.timestamp,
		Data:      data,
	}
	t.timestamp++
	t.writeIndex = (t.writeIndex + 1) % t.maxEvents
	if t.count < t.maxEvents {
		t.count++
	}
}

// GetEvents returns events filtered by type, ordered newest first.
func (t *Tracker) GetEvents(eventType EventType) []Event {
	t.mu.Lock()
	defer t.mu.Unlock()

	result := make([]Event, 0)
	for i := 0; i < t.count; i++ {
		// Walk backwards from the most recently written entry.
		idx := (t.writeIndex - 1 - i + t.maxEvents) % t.maxEvents
		if t.events[idx].Type == eventType {
			result = append(result, t.events[idx])
		}
	}
	return result
}

// GetAllEvents returns all events ordered newest first.
func (t *Tracker) GetAllEvents() []Event {
	t.mu.Lock()
	defer t.mu.Unlock()

	result := make([]Event, 0, t.count)
	for i := 0; i < t.count; i++ {
		idx := (t.writeIndex - 1 - i + t.maxEvents) % t.maxEvents
		result = append(result, t.events[idx])
	}
	return result
}

// GetEventCount returns the number of stored events of the given type.
func (t *Tracker) GetEventCount(eventType EventType) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	n := 0
	for i := 0; i < t.count; i++ {
		idx := (t.writeIndex - 1 - i + t.maxEvents) % t.maxEvents
		if t.events[idx].Type == eventType {
			n++
		}
	}
	return n
}

// Clear removes all recorded events.
func (t *Tracker) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.events = make([]Event, t.maxEvents)
	t.writeIndex = 0
	t.count = 0
}

// Enable enables event recording.
func (t *Tracker) Enable() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.enabled = true
}

// Disable disables event recording. Existing events are retained.
func (t *Tracker) Disable() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.enabled = false
}

// IsEnabled reports whether event recording is enabled.
func (t *Tracker) IsEnabled() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.enabled
}
