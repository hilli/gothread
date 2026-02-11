// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package timesync implements Thread network time synchronization.
//
// The Time Sync Service distributes a common time reference through the
// mesh network using the Time Sync IE (Information Element) carried in
// MLE messages. Each node maintains a local estimate of the network time
// and periodically synchronizes with the time source.
//
// This is a Go port of the time sync logic in OpenThread's
// src/core/thread/time_sync_service.hpp and time_sync_service.cpp.
package timesync

import "sync"

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

// Status represents the time synchronization status.
type Status uint8

const (
	// StatusUnsynchronized indicates the node has not yet synchronized
	// with the network time source, or that synchronization was lost.
	StatusUnsynchronized Status = iota
	// StatusSynchronized indicates the node's network time is valid.
	StatusSynchronized
)

// String returns a human-readable representation of a Status.
func (s Status) String() string {
	switch s {
	case StatusUnsynchronized:
		return "Unsynchronized"
	case StatusSynchronized:
		return "Synchronized"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// TimeSyncCallback
// ---------------------------------------------------------------------------

// TimeSyncCallback is called when the network time is updated.
// The argument is the new network time in microseconds.
type TimeSyncCallback func(networkTime int64)

// ---------------------------------------------------------------------------
// Constants and defaults
// ---------------------------------------------------------------------------

const (
	// defaultPeriod is the default time sync period in seconds.
	defaultPeriod uint32 = 30
	// defaultThreshold is the default time (in seconds) before the node
	// considers synchronization lost.
	defaultThreshold uint32 = 120
)

// ---------------------------------------------------------------------------
// Functional options
// ---------------------------------------------------------------------------

// Option configures a Service.
type Option func(*Service)

// WithPeriod sets the time sync period in seconds. This controls how often
// this node initiates a time sync request.
func WithPeriod(seconds uint32) Option {
	return func(s *Service) {
		if seconds > 0 {
			s.period = seconds
		}
	}
}

// WithThreshold sets the time (in seconds) before the node considers
// synchronization lost if no Time Sync IE is received.
func WithThreshold(seconds uint32) Option {
	return func(s *Service) {
		if seconds > 0 {
			s.threshold = seconds
		}
	}
}

// WithCallback sets the callback invoked when network time is updated.
func WithCallback(cb TimeSyncCallback) Option {
	return func(s *Service) {
		s.callback = cb
	}
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// Service manages Thread network time synchronization.
//
// The service maintains the current network time estimate and processes
// received Time Sync IEs to update it. It uses serial-number arithmetic
// for sequence comparison so that wraparound is handled correctly.
type Service struct {
	mu                 sync.Mutex
	enabled            bool
	status             Status
	networkTime        int64  // microseconds since some epoch
	lastSyncTime       uint32 // local time (ms) of last sync
	sequence           uint8  // time sync sequence number
	period             uint32 // sync period in seconds
	threshold          uint32 // sync loss threshold in seconds
	isTimeSyncRequired bool
	callback           TimeSyncCallback
}

// NewService creates a new time sync Service. By default the service is
// disabled, unsynchronized, and uses the default period (30 s) and
// threshold (120 s).
func NewService(opts ...Option) *Service {
	s := &Service{
		status:    StatusUnsynchronized,
		period:    defaultPeriod,
		threshold: defaultThreshold,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Enable enables the time sync service.
func (s *Service) Enable() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = true
}

// Disable disables the time sync service and resets state.
func (s *Service) Disable() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = false
	s.status = StatusUnsynchronized
	s.isTimeSyncRequired = false
}

// GetStatus returns the current synchronization status.
func (s *Service) GetStatus() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// GetNetworkTime returns the current network time estimate in microseconds
// and the synchronization status. If the node is not synchronized the
// returned time is stale.
func (s *Service) GetNetworkTime() (int64, Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.networkTime, s.status
}

// GetSequence returns the current time sync sequence number.
func (s *Service) GetSequence() uint8 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sequence
}

// IncrementSequence increments the time sync sequence number (with
// wraparound).
func (s *Service) IncrementSequence() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sequence++
}

// SetTimeSyncRequired marks whether a time sync is required. The MLE layer
// checks this flag to decide whether to include a Time Sync IE in outgoing
// messages.
func (s *Service) SetTimeSyncRequired(required bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isTimeSyncRequired = required
}

// IsTimeSyncRequired reports whether a time sync request is pending.
func (s *Service) IsTimeSyncRequired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isTimeSyncRequired
}

// GetPeriod returns the sync period in seconds.
func (s *Service) GetPeriod() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.period
}

// GetThreshold returns the sync loss threshold in seconds.
func (s *Service) GetThreshold() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.threshold
}

// HandleTimeSyncIE processes a received Time Sync IE from a neighbor.
//
// The parameters are:
//   - sequence:    the sequence number from the received IE
//   - networkTime: the network time value from the received IE (µs)
//   - localRxTime: the local time (ms) when the message was received
//
// The network time is updated only if the received sequence number is
// newer than the current one (using serial-number comparison per RFC 1982).
func (s *Service) HandleTimeSyncIE(sequence uint8, networkTime int64, localRxTime uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.enabled {
		return
	}

	if !serialGreater(sequence, s.sequence) {
		return
	}

	s.sequence = sequence
	s.networkTime = networkTime
	s.lastSyncTime = localRxTime
	s.status = StatusSynchronized
	s.isTimeSyncRequired = false

	if s.callback != nil {
		// Invoke callback without holding the lock to avoid deadlock if
		// the callback calls back into the service.
		cb := s.callback
		nt := s.networkTime
		s.mu.Unlock()
		cb(nt)
		s.mu.Lock()
	}
}

// HandleTimer should be called periodically (at least once per second) with
// the current local time in milliseconds. It checks whether synchronization
// has been lost and whether a new sync request should be initiated.
func (s *Service) HandleTimer(localTime uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.enabled {
		return
	}

	if s.status == StatusUnsynchronized {
		return
	}

	elapsed := elapsedMs(s.lastSyncTime, localTime)

	// Check if synchronization is lost.
	if elapsed >= s.threshold*1000 {
		s.status = StatusUnsynchronized
		return
	}

	// Check if it's time to initiate a new sync.
	if elapsed >= s.period*1000 {
		s.isTimeSyncRequired = true
	}
}

// GetTimeSyncIEData returns the data needed to build a Time Sync IE for
// inclusion in an outgoing MLE message: the current sequence number and
// network time.
func (s *Service) GetTimeSyncIEData() (sequence uint8, networkTime int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sequence, s.networkTime
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// serialGreater performs serial-number comparison (RFC 1982) for 8-bit
// sequence numbers. It returns true if a > b in the serial-number sense.
func serialGreater(a, b uint8) bool {
	diff := int8(a - b)
	return diff > 0
}

// elapsedMs computes the elapsed time in milliseconds between start and
// now, handling 32-bit wraparound.
func elapsedMs(start, now uint32) uint32 {
	return now - start
}
