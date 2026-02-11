// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package border

import (
	"fmt"
	"sync"
)

// ---------------------------------------------------------------------------
// Tracker state
// ---------------------------------------------------------------------------

// TrackerState represents the Border Agent connection state.
type TrackerState uint8

const (
	// StateDisconnected means no commissioner is connected.
	StateDisconnected TrackerState = iota
	// StateConnecting means a DTLS handshake is in progress.
	StateConnecting
	// StateConnected means a commissioner session is active.
	StateConnected
)

// String returns a human-readable name for the tracker state.
func (s TrackerState) String() string {
	switch s {
	case StateDisconnected:
		return "Disconnected"
	case StateConnecting:
		return "Connecting"
	case StateConnected:
		return "Connected"
	default:
		return fmt.Sprintf("TrackerState(%d)", s)
	}
}

// ---------------------------------------------------------------------------
// Tracker
// ---------------------------------------------------------------------------

// Tracker monitors the Border Agent's connection state and peer address.
// It provides a simple state-change callback mechanism for observers.
type Tracker struct {
	mu sync.Mutex

	state    TrackerState
	peerAddr [16]byte

	stateCallback func(state TrackerState)
}

// NewTracker creates a new Tracker in the Disconnected state.
func NewTracker() *Tracker {
	return &Tracker{
		state: StateDisconnected,
	}
}

// GetState returns the current tracker state.
func (tr *Tracker) GetState() TrackerState {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.state
}

// GetPeerAddress returns the IPv6 address of the connected commissioner.
// Returns a zero address if not connected.
func (tr *Tracker) GetPeerAddress() [16]byte {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.peerAddr
}

// SetStateCallback sets the callback invoked when the state changes.
func (tr *Tracker) SetStateCallback(cb func(state TrackerState)) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.stateCallback = cb
}

// HandleConnecting transitions to StateConnecting.
func (tr *Tracker) HandleConnecting(peerAddr [16]byte) {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	tr.state = StateConnecting
	tr.peerAddr = peerAddr
	tr.notifyLocked()
}

// HandleConnected transitions to StateConnected.
func (tr *Tracker) HandleConnected(peerAddr [16]byte) {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	tr.state = StateConnected
	tr.peerAddr = peerAddr
	tr.notifyLocked()
}

// HandleDisconnected transitions to StateDisconnected and clears the
// peer address.
func (tr *Tracker) HandleDisconnected() {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	tr.state = StateDisconnected
	tr.peerAddr = [16]byte{}
	tr.notifyLocked()
}

// notifyLocked invokes the state callback if set. Must be called with
// tr.mu held. The callback is invoked with the lock released to avoid
// potential deadlocks.
func (tr *Tracker) notifyLocked() {
	cb := tr.stateCallback
	if cb == nil {
		return
	}
	state := tr.state
	tr.mu.Unlock()
	cb(state)
	tr.mu.Lock()
}
