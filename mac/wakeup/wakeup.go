// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package wakeup implements the wake-up frame TX scheduler for Thread
// wake-up coordinators. It manages the timing of consecutive wake-up
// frame transmissions during a wake-up sequence.
//
// This is a Go port of the wake-up TX scheduler in OpenThread's
// src/core/mac/wakeup_tx_scheduler.hpp and wakeup_tx_scheduler.cpp.
package wakeup

import "errors"

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

const (
	// DefaultConnectionRetryInterval is the default number of wake-up
	// frame intervals to wait between connection retries.
	DefaultConnectionRetryInterval uint8 = 4

	// DefaultConnectionRetryCount is the default number of connection
	// retry attempts.
	DefaultConnectionRetryCount uint8 = 3

	// WakeupFrameLength is the length of a wake-up frame in bytes,
	// including the SHR.
	WakeupFrameLength uint32 = 54
)

// --------------------------------------------------------------------------
// Error sentinels
// --------------------------------------------------------------------------

var (
	// ErrInvalidState indicates the scheduler is not in the right state
	// for the requested operation.
	ErrInvalidState = errors.New("wakeup: invalid state")
	// ErrInvalidConfig indicates the configuration is invalid.
	ErrInvalidConfig = errors.New("wakeup: invalid config")
)

// --------------------------------------------------------------------------
// Config — wake-up sequence configuration
// --------------------------------------------------------------------------

// Config holds the configuration for a wake-up sequence.
type Config struct {
	// IntervalUs is the interval between consecutive wake-up frames in
	// microseconds.
	IntervalUs uint16

	// DurationMs is the total duration of the wake-up sequence in
	// milliseconds.
	DurationMs uint16
}

// Validate checks that the configuration is valid. IntervalUs must be
// greater than zero.
func (c *Config) Validate() error {
	if c.IntervalUs == 0 {
		return ErrInvalidConfig
	}
	return nil
}

// --------------------------------------------------------------------------
// Scheduler — wake-up frame TX timing
// --------------------------------------------------------------------------

// Scheduler manages the timing of wake-up frame transmissions within a
// wake-up sequence. It tracks when the next frame should be sent and
// when the sequence is over.
type Scheduler struct {
	isRunning               bool
	intervalUs              uint16
	txTimeUs                uint64
	txEndTimeUs             uint64
	connectionRetryInterval uint8
	connectionRetryCount    uint8
}

// NewScheduler creates a new wake-up TX scheduler with the given
// connection retry parameters.
func NewScheduler(retryInterval, retryCount uint8) *Scheduler {
	return &Scheduler{
		connectionRetryInterval: retryInterval,
		connectionRetryCount:    retryCount,
	}
}

// NewDefaultScheduler creates a new wake-up TX scheduler with default
// connection retry parameters.
func NewDefaultScheduler() *Scheduler {
	return NewScheduler(DefaultConnectionRetryInterval, DefaultConnectionRetryCount)
}

// Start begins a wake-up sequence. intervalUs is the interval between
// consecutive wake-up frames. durationMs is the total duration of the
// sequence. nowUs is the current radio time in microseconds.
//
// Returns ErrInvalidState if a sequence is already running.
func (s *Scheduler) Start(intervalUs, durationMs uint16, nowUs uint64) error {
	if s.isRunning {
		return ErrInvalidState
	}
	if intervalUs == 0 {
		return ErrInvalidConfig
	}
	s.intervalUs = intervalUs
	s.txTimeUs = nowUs
	// End time = now + duration_in_us + one interval
	// (matches C++: mTxEndTimeUs = mTxTimeUs + aDurationMs * 1000 + aIntervalUs)
	s.txEndTimeUs = nowUs + uint64(durationMs)*1000 + uint64(intervalUs)
	s.isRunning = true
	return nil
}

// Stop stops the current wake-up sequence.
func (s *Scheduler) Stop() {
	s.isRunning = false
}

// IsRunning reports whether a wake-up sequence is currently active.
func (s *Scheduler) IsRunning() bool {
	return s.isRunning
}

// GetConnectionWindowUs returns the connection window in microseconds.
// This is the amount of time the device waits for an initial link
// establishment message after sending the last wake-up frame.
//
// connectionWindow = intervalUs * retryInterval * retryCount
func (s *Scheduler) GetConnectionWindowUs() uint32 {
	return uint32(s.intervalUs) * uint32(s.connectionRetryInterval) * uint32(s.connectionRetryCount)
}

// GetTxEndTimeUs returns the end time of the wake-up sequence in
// microseconds.
func (s *Scheduler) GetTxEndTimeUs() uint64 {
	return s.txEndTimeUs
}

// GetIntervalUs returns the interval between consecutive wake-up frames.
func (s *Scheduler) GetIntervalUs() uint16 {
	return s.intervalUs
}

// ScheduleNext calculates the delay to the next wake-up frame
// transmission. Returns the delay in microseconds and true if another
// frame should be sent, or 0 and false if the sequence is over.
//
// Each call advances the internal TX time by intervalUs. If the
// sequence has ended (txTime >= txEndTime), the scheduler is stopped
// and (0, false) is returned.
func (s *Scheduler) ScheduleNext(nowUs uint64) (delayUs uint64, ok bool) {
	if !s.isRunning {
		return 0, false
	}

	// Advance to the next TX time.
	nextTx := s.txTimeUs + uint64(s.intervalUs)

	// If the next frame would be sent in the past, move it forward.
	if nextTx < nowUs {
		nextTx = nowUs
	}

	// Check if the sequence is over.
	if nextTx >= s.txEndTimeUs {
		s.isRunning = false
		return 0, false
	}

	s.txTimeUs = nextTx
	delay := nextTx - nowUs
	return delay, true
}
