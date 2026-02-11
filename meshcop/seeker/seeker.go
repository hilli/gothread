// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package seeker implements the MeshCoP Seeker, which discovers and connects
// to Thread networks for joining via an external commissioner.
//
// Reference: Thread specification, MeshCoP Discovery and Join flow.
package seeker

import (
	"fmt"
	"sync"

	goterrors "github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

// State represents the seeker's operating state.
type State uint8

const (
	// StateStopped means the seeker is idle.
	StateStopped State = iota
	// StateDiscover means the seeker is scanning for Thread networks.
	StateDiscover
	// StateConnect means the seeker is connecting to a discovered network.
	StateConnect
)

// String returns a human-readable state name.
func (s State) String() string {
	switch s {
	case StateStopped:
		return "Stopped"
	case StateDiscover:
		return "Discover"
	case StateConnect:
		return "Connect"
	default:
		return fmt.Sprintf("State(%d)", s)
	}
}

// ---------------------------------------------------------------------------
// Discovery and join results
// ---------------------------------------------------------------------------

// DiscoverResult holds information about a discovered Thread network.
type DiscoverResult struct {
	// NetworkName is the Thread network name.
	NetworkName string
	// ExtPanID is the extended PAN ID.
	ExtPanID [8]byte
	// PanID is the IEEE 802.15.4 PAN ID.
	PanID uint16
	// Channel is the IEEE 802.15.4 channel.
	Channel uint8
	// RSSI is the received signal strength indicator.
	RSSI int8
	// LQI is the link quality indicator.
	LQI uint8
}

// JoinResult holds the outcome of a join attempt.
type JoinResult struct {
	// NetworkName is the network that was joined (or attempted).
	NetworkName string
	// ExtPanID is the extended PAN ID of the network.
	ExtPanID [8]byte
	// PanID is the PAN ID of the network.
	PanID uint16
	// Channel is the channel of the network.
	Channel uint8
	// Error is nil on success, or the join error.
	Error error
}

// ---------------------------------------------------------------------------
// Scanner interface
// ---------------------------------------------------------------------------

// Scanner abstracts MLE Discovery for the Seeker.
type Scanner interface {
	// StartScan begins a MeshCoP Discovery scan.
	// The callback is invoked for each result; nil signals scan complete.
	StartScan(callback func(result *DiscoverResult)) error
	// StopScan stops an active scan.
	StopScan()
}

// ---------------------------------------------------------------------------
// Seeker
// ---------------------------------------------------------------------------

// Seeker discovers Thread networks and connects to them for commissioning.
type Seeker struct {
	mu sync.Mutex

	state   State
	scanner Scanner

	// Discovered results collected during scanning.
	results []DiscoverResult

	// Callback invoked when discovery or join completes.
	discoverCB func(results []DiscoverResult)
	joinCB     func(result JoinResult)
}

// NewSeeker creates a new Seeker with the given scanner dependency.
func NewSeeker(scanner Scanner) *Seeker {
	return &Seeker{
		state:   StateStopped,
		scanner: scanner,
	}
}

// GetState returns the seeker's current state.
func (s *Seeker) GetState() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Start begins a network discovery scan. The callback is invoked with
// all discovered results when the scan completes.
func (s *Seeker) Start(cb func(results []DiscoverResult)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != StateStopped {
		return goterrors.ErrInvalidState
	}

	s.discoverCB = cb
	s.results = nil
	s.state = StateDiscover

	if err := s.scanner.StartScan(s.handleDiscoverResult); err != nil {
		s.state = StateStopped
		s.discoverCB = nil
		return err
	}

	return nil
}

// Stop stops the seeker. If a scan is in progress it is cancelled.
func (s *Seeker) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == StateStopped {
		return goterrors.ErrInvalidState
	}

	s.scanner.StopScan()
	s.state = StateStopped
	s.results = nil
	s.discoverCB = nil
	s.joinCB = nil
	return nil
}

// HandleDiscoverResult processes a single discovery result. A nil result
// signals that the scan is complete.
func (s *Seeker) HandleDiscoverResult(result *DiscoverResult) {
	s.handleDiscoverResult(result)
}

func (s *Seeker) handleDiscoverResult(result *DiscoverResult) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != StateDiscover {
		return
	}

	if result == nil {
		// Scan complete.
		s.state = StateStopped
		cb := s.discoverCB
		results := make([]DiscoverResult, len(s.results))
		copy(results, s.results)
		s.discoverCB = nil

		if cb != nil {
			s.mu.Unlock()
			cb(results)
			s.mu.Lock()
		}
		return
	}

	s.results = append(s.results, *result)
}

// GetResults returns a copy of the discovered results collected so far.
func (s *Seeker) GetResults() []DiscoverResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	results := make([]DiscoverResult, len(s.results))
	copy(results, s.results)
	return results
}
