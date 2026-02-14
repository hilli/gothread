// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package simulation

import (
	"sync"
	"time"

	"github.com/hilli/gothread/platform"
)

// Compile-time interface check.
var _ platform.Alarm = (*SimAlarm)(nil)

// SimAlarm implements platform.Alarm using Go's time package.
type SimAlarm struct {
	mu      sync.Mutex
	start   time.Time
	target  uint32
	running bool
}

// NewSimAlarm creates a new SimAlarm with the monotonic clock starting now.
func NewSimAlarm() *SimAlarm {
	return &SimAlarm{start: time.Now()}
}

// Start schedules an alarm to fire at t0+dt milliseconds.
func (a *SimAlarm) Start(t0, dt uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.target = t0 + dt
	a.running = true
}

// Stop cancels any pending alarm.
func (a *SimAlarm) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.running = false
}

// GetNow returns the current platform time in milliseconds since creation.
func (a *SimAlarm) GetNow() uint32 {
	return uint32(time.Since(a.start).Milliseconds())
}
