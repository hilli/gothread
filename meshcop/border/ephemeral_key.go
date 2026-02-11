// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package border

import (
	"sync"
	"time"

	goterrors "github.com/hilli/gothread/errors"
)

// Ephemeral key constants.
const (
	// MaxKeyLength is the maximum ephemeral key length in bytes.
	MaxKeyLength = 32
	// MinKeyLength is the minimum ephemeral key length in bytes.
	MinKeyLength = 6
	// DefaultTimeout is the default duration an ephemeral key remains valid.
	DefaultTimeout = 120 * time.Second
)

// EphemeralKeyManager manages short-lived PSK credentials for Border Agent
// commissioner sessions. An ephemeral key can be activated for a limited
// time window, after which it automatically expires.
//
// Reference: openthread/src/core/meshcop/border_agent_ephemeral_key.cpp
type EphemeralKeyManager struct {
	mu sync.Mutex

	active  bool
	key     string
	port    uint16
	timeout time.Duration

	// Timer for automatic expiration. Uses the border.Timer interface
	// already defined in agent.go.
	timer Timer

	// Timer injection for testing.
	afterFunc func(d time.Duration, f func()) Timer

	// Callback invoked when the key expires or is stopped.
	stoppedCB func()
}

// NewEphemeralKeyManager creates a new EphemeralKeyManager.
func NewEphemeralKeyManager() *EphemeralKeyManager {
	return &EphemeralKeyManager{
		timeout: DefaultTimeout,
		afterFunc: func(d time.Duration, f func()) Timer {
			return time.AfterFunc(d, f)
		},
	}
}

// Start activates an ephemeral key for the given duration. The key must be
// between MinKeyLength and MaxKeyLength characters. If timeout is zero,
// DefaultTimeout is used.
func (m *EphemeralKeyManager) Start(key string, port uint16, timeout time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.active {
		return goterrors.ErrAlready
	}

	if len(key) < MinKeyLength || len(key) > MaxKeyLength {
		return goterrors.ErrInvalidArgs
	}

	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	m.key = key
	m.port = port
	m.timeout = timeout
	m.active = true

	m.timer = m.afterFunc(timeout, func() {
		m.handleTimeout()
	})

	return nil
}

// Stop deactivates the ephemeral key.
func (m *EphemeralKeyManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.stopLocked()
}

func (m *EphemeralKeyManager) stopLocked() {
	if !m.active {
		return
	}

	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}

	m.active = false
	m.key = ""

	cb := m.stoppedCB
	if cb != nil {
		m.mu.Unlock()
		cb()
		m.mu.Lock()
	}
}

// IsActive reports whether an ephemeral key is currently active.
func (m *EphemeralKeyManager) IsActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

// GetPort returns the port associated with the active ephemeral key.
// Returns 0 if no key is active.
func (m *EphemeralKeyManager) GetPort() uint16 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active {
		return 0
	}
	return m.port
}

// GetKey returns the current ephemeral key. Returns an empty string
// if no key is active.
func (m *EphemeralKeyManager) GetKey() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active {
		return ""
	}
	return m.key
}

// SetStoppedCallback sets a callback that is invoked when the ephemeral
// key expires or is stopped.
func (m *EphemeralKeyManager) SetStoppedCallback(cb func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stoppedCB = cb
}

// HandleTimeout is called when the ephemeral key timer expires.
func (m *EphemeralKeyManager) HandleTimeout() {
	m.handleTimeout()
}

func (m *EphemeralKeyManager) handleTimeout() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.timer != nil {
		m.timer = nil // Timer already fired.
	}

	m.active = false
	m.key = ""

	cb := m.stoppedCB
	if cb != nil {
		m.mu.Unlock()
		cb()
		m.mu.Lock()
	}
}
