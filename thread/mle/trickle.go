// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file implements a Trickle timer (RFC 6206) used to schedule MLE
// Advertisement transmissions.
//
// This is a Go port of the Trickle timer logic used in OpenThread's
// src/core/common/trickle_timer.cpp.

package mle

import "time"

// TrickleMode indicates whether the Trickle timer operates in normal
// (RFC 6206) mode or plain periodic mode.
type TrickleMode uint8

const (
	// TrickleModeTrickle is the standard RFC 6206 Trickle algorithm.
	TrickleModeTrickle TrickleMode = 0

	// TrickleModePlainTimer is a simple periodic timer with random jitter
	// (no consistency counter or doubling).
	TrickleModePlainTimer TrickleMode = 1
)

// TrickleTimer implements the Trickle algorithm defined in RFC 6206.
//
// The timer manages a current interval I in [iMin, iMax]. At the start of
// each interval:
//   - A random transmission time t is chosen in [I/2, I).
//   - A consistency counter c is reset to 0.
//
// When the timer fires at time t, transmission occurs only if c < k (the
// redundancy constant). After each interval, I is doubled (up to iMax).
//
// Calling Reset() sets I back to iMin, which is the correct response to
// "inconsistent" information (e.g., changed routes, new neighbor links).
type TrickleTimer struct {
	iMin     time.Duration // minimum interval
	iMax     time.Duration // maximum interval
	interval time.Duration // current interval I
	phase    time.Duration // time within current interval
	txTime   time.Duration // random t in [I/2, I)
	counter  int           // consistency counter c
	k        int           // redundancy constant (0 = infinite)
	mode     TrickleMode
	running  bool

	// randFn returns a random duration in [0, n).
	// Injected for deterministic testing.
	randFn func(n time.Duration) time.Duration
}

// TrickleTimerConfig holds the configuration for creating a TrickleTimer.
type TrickleTimerConfig struct {
	// IMin is the minimum interval (Trickle I_min).
	IMin time.Duration

	// IMax is the maximum interval (Trickle I_max).
	IMax time.Duration

	// K is the redundancy constant. 0 means infinite (always transmit).
	K int

	// Mode selects the timer algorithm.
	Mode TrickleMode

	// RandFn returns a random duration in [0, n). If nil, a default
	// implementation is not provided — the caller must supply one.
	RandFn func(n time.Duration) time.Duration
}

// NewTrickleTimer creates a new TrickleTimer with the given configuration.
// The timer starts in the stopped state; call Start() to begin.
func NewTrickleTimer(cfg TrickleTimerConfig) *TrickleTimer {
	return &TrickleTimer{
		iMin:   cfg.IMin,
		iMax:   cfg.IMax,
		k:      cfg.K,
		mode:   cfg.Mode,
		randFn: cfg.RandFn,
	}
}

// IsRunning reports whether the timer is currently running.
func (t *TrickleTimer) IsRunning() bool {
	return t.running
}

// GetInterval returns the current interval I.
func (t *TrickleTimer) GetInterval() time.Duration {
	return t.interval
}

// SetIntervalMax updates the maximum interval. If the current interval
// exceeds the new maximum, it is clamped.
func (t *TrickleTimer) SetIntervalMax(iMax time.Duration) {
	t.iMax = iMax
	if t.running && t.interval > t.iMax {
		t.interval = t.iMax
	}
}

// Start begins the Trickle timer. The interval is set to iMin and a
// new period is started.
func (t *TrickleTimer) Start() {
	t.interval = t.iMin
	t.running = true
	t.startNewPeriod()
}

// Stop halts the Trickle timer.
func (t *TrickleTimer) Stop() {
	t.running = false
}

// Reset is the Trickle "inconsistency" signal. It resets the interval
// to iMin and starts a new period. If the timer is not running, this
// is a no-op.
func (t *TrickleTimer) Reset() {
	if !t.running {
		return
	}
	t.interval = t.iMin
	t.startNewPeriod()
}

// IndicateConsistent increments the consistency counter c. In Trickle
// mode, if c >= k the timer suppresses transmission.
func (t *TrickleTimer) IndicateConsistent() {
	t.counter++
}

// HandleTimeTick advances the timer by the given elapsed duration.
// Returns true if a transmission should occur at this tick.
//
// The caller is responsible for calling this periodically (e.g., every
// second). When it returns true, the caller should transmit the
// Advertisement and then call HandleTimeTick again on subsequent ticks.
func (t *TrickleTimer) HandleTimeTick(elapsed time.Duration) bool {
	if !t.running {
		return false
	}

	prevPhase := t.phase
	t.phase += elapsed

	// Check if we crossed the transmission time.
	transmit := false
	if prevPhase < t.txTime && t.phase >= t.txTime {
		transmit = t.shouldTransmit()
	}

	// Check if the interval expired.
	if t.phase >= t.interval {
		t.endInterval()
	}

	return transmit
}

// shouldTransmit returns true if transmission should occur at time t.
// In Trickle mode, this is true when c < k (or k == 0 meaning infinite).
// In plain timer mode, it always returns true.
func (t *TrickleTimer) shouldTransmit() bool {
	switch t.mode {
	case TrickleModePlainTimer:
		return true
	default:
		// Trickle: transmit if c < k, or k == 0 (no suppression).
		return t.k == 0 || t.counter < t.k
	}
}

// endInterval doubles the interval (up to iMax) and starts a new period.
// In plain timer mode the interval stays at iMin.
func (t *TrickleTimer) endInterval() {
	switch t.mode {
	case TrickleModePlainTimer:
		t.interval = t.iMin
	default:
		t.interval *= 2
		if t.interval > t.iMax {
			t.interval = t.iMax
		}
	}
	t.startNewPeriod()
}

// startNewPeriod resets the phase and consistency counter, and picks
// a new random transmission time t in [I/2, I).
func (t *TrickleTimer) startNewPeriod() {
	t.phase = 0
	t.counter = 0

	halfInterval := t.interval / 2
	if halfInterval <= 0 {
		// If the interval is very small, transmit at 0.
		t.txTime = 0
		return
	}

	t.txTime = halfInterval + t.randFn(halfInterval)
}
