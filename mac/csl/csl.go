// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package csl implements CSL (Coordinated Sampled Listening) TX
// scheduling for the parent side. It tracks CSL-synchronized children
// and calculates the next transmission window based on the child's
// CSL period and phase.
//
// This is a Go port of the CSL TX scheduler in OpenThread's
// src/core/thread/csl_tx_scheduler.hpp and csl_tx_scheduler.cpp.
package csl

import (
	"errors"
	"time"

	"github.com/hilli/gothread/mac/types"
)

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

const (
	// UsPerTenSymbols is the duration of 10 IEEE 802.15.4 symbols in
	// microseconds (10 * 16 µs = 160 µs). CSL period and phase are
	// expressed in units of 10 symbols.
	UsPerTenSymbols uint64 = 160

	// MaxCslTriggeredTxAttempts is the maximum number of CSL-triggered
	// transmission attempts before the child is considered out of sync.
	MaxCslTriggeredTxAttempts uint8 = 4

	// FramePreparationGuardInterval is a guard time in microseconds
	// added when checking delay while preparing a CSL frame for TX.
	FramePreparationGuardInterval uint32 = 1500
)

// --------------------------------------------------------------------------
// Error sentinels
// --------------------------------------------------------------------------

var (
	// ErrNotFound indicates the neighbor was not found in the scheduler.
	ErrNotFound = errors.New("csl: neighbor not found")
	// ErrAlreadyExists indicates the neighbor already exists.
	ErrAlreadyExists = errors.New("csl: neighbor already exists")
	// ErrNotSynchronized indicates the neighbor is not CSL-synchronized.
	ErrNotSynchronized = errors.New("csl: neighbor not synchronized")
)

// --------------------------------------------------------------------------
// NeighborInfo — per-child CSL state
// --------------------------------------------------------------------------

// NeighborInfo holds the CSL scheduling information for a single
// CSL-synchronized neighbor (child). It corresponds to
// CslTxScheduler::NeighborInfo in the C++ code.
type NeighborInfo struct {
	// CslTxAttempts is the number of CSL-triggered TX attempts.
	CslTxAttempts uint8

	// CslSynchronized indicates whether the child is CSL synchronized.
	CslSynchronized bool

	// CslChannel is the channel the child listens on (0 = use PAN channel).
	CslChannel uint8

	// CslTimeout is the CSL synchronization timeout in seconds.
	CslTimeout uint32

	// CslPeriod is the CSL sampled listening period in units of 10 symbols
	// (160 µs each).
	CslPeriod uint16

	// CslPhase is the time in units of 10 symbols from the first symbol
	// of the frame containing the CSL IE to the next channel sample.
	CslPhase uint16

	// CslLastHeard is the wall-clock time when the last frame containing
	// a CSL IE was heard.
	CslLastHeard time.Time

	// LastRxTimestamp is the radio clock time (in microseconds) when the
	// last frame containing a CSL IE was received.
	LastRxTimestamp uint64

	// ExtAddr is the extended address of this neighbor, used as a key.
	ExtAddr types.ExtAddress
}

// IsCslSynchronized reports whether this neighbor is CSL-synchronized.
// A neighbor is synchronized when CslSynchronized is true and CslPeriod
// is greater than zero.
func (n *NeighborInfo) IsCslSynchronized() bool {
	return n.CslSynchronized && n.CslPeriod > 0
}

// IncrementCslTxAttempts increments the CSL TX attempt counter by one.
func (n *NeighborInfo) IncrementCslTxAttempts() {
	n.CslTxAttempts++
}

// ResetCslTxAttempts resets the CSL TX attempt counter to zero.
func (n *NeighborInfo) ResetCslTxAttempts() {
	n.CslTxAttempts = 0
}

// --------------------------------------------------------------------------
// Scheduler — manages multiple CSL neighbors
// --------------------------------------------------------------------------

// Scheduler tracks CSL-synchronized neighbors and provides delay
// calculations for CSL frame transmission.
type Scheduler struct {
	neighbors map[types.ExtAddress]*NeighborInfo
}

// NewScheduler creates a new CSL TX scheduler.
func NewScheduler() *Scheduler {
	return &Scheduler{
		neighbors: make(map[types.ExtAddress]*NeighborInfo),
	}
}

// Add adds a neighbor to the scheduler. Returns ErrAlreadyExists if the
// neighbor (identified by ExtAddr) is already tracked.
func (s *Scheduler) Add(info *NeighborInfo) error {
	if _, ok := s.neighbors[info.ExtAddr]; ok {
		return ErrAlreadyExists
	}
	s.neighbors[info.ExtAddr] = info
	return nil
}

// Remove removes a neighbor from the scheduler. Returns ErrNotFound if
// the neighbor is not tracked.
func (s *Scheduler) Remove(addr types.ExtAddress) error {
	if _, ok := s.neighbors[addr]; !ok {
		return ErrNotFound
	}
	delete(s.neighbors, addr)
	return nil
}

// Update updates an existing neighbor's info. Returns ErrNotFound if
// the neighbor is not tracked.
func (s *Scheduler) Update(info *NeighborInfo) error {
	if _, ok := s.neighbors[info.ExtAddr]; !ok {
		return ErrNotFound
	}
	s.neighbors[info.ExtAddr] = info
	return nil
}

// Get returns the NeighborInfo for the given address. Returns nil if
// not found.
func (s *Scheduler) Get(addr types.ExtAddress) *NeighborInfo {
	return s.neighbors[addr]
}

// Clear removes all neighbors from the scheduler.
func (s *Scheduler) Clear() {
	for k := range s.neighbors {
		delete(s.neighbors, k)
	}
}

// Count returns the number of tracked neighbors.
func (s *Scheduler) Count() int {
	return len(s.neighbors)
}

// --------------------------------------------------------------------------
// CSL delay calculation
// --------------------------------------------------------------------------

// GetNextTransmissionDelay calculates the delay (in microseconds) from
// radioNowUs to the next CSL transmission window for the given neighbor,
// minus aheadUs preparation time.
//
// The calculation follows the CSL spec:
//
//	firstTxWindow = LastRxTimestamp + CslPhase * UsPerTenSymbols
//	periodInUs    = CslPeriod * UsPerTenSymbols
//	nextTxWindow  = radioNow aligned to periodInUs + (firstTxWindow % periodInUs)
//
// The function advances nextTxWindow until it is at least radioNowUs + aheadUs,
// then returns (nextTxWindow - radioNowUs - aheadUs).
//
// Also returns delayFromLastRx = nextTxWindow - LastRxTimestamp.
//
// Returns ErrNotSynchronized if the neighbor is not CSL-synchronized.
func GetNextTransmissionDelay(info *NeighborInfo, radioNowUs uint64, aheadUs uint32) (delayUs, delayFromLastRx uint32, err error) {
	if !info.IsCslSynchronized() {
		return 0, 0, ErrNotSynchronized
	}

	periodInUs := uint64(info.CslPeriod) * UsPerTenSymbols
	if periodInUs == 0 {
		return 0, 0, ErrNotSynchronized
	}

	firstTxWindow := info.LastRxTimestamp + uint64(info.CslPhase)*UsPerTenSymbols
	nextTxWindow := radioNowUs - (radioNowUs % periodInUs) + (firstTxWindow % periodInUs)

	ahead64 := uint64(aheadUs)
	for nextTxWindow < radioNowUs+ahead64 {
		nextTxWindow += periodInUs
	}

	delayFromLastRx = uint32(nextTxWindow - info.LastRxTimestamp)
	delayUs = uint32(nextTxWindow - radioNowUs - ahead64)
	return delayUs, delayFromLastRx, nil
}
