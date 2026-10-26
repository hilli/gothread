// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"math/rand/v2"
	"sync"
	"time"
)

// leaderSessionTimeout is the leader's commissioner session timeout.
const leaderSessionTimeout = 50 * time.Second

// LeaderCommissioner manages the commissioner state on the Thread Leader.
// It handles petition and keep-alive requests from commissioners, maintaining
// at most one active commissioner session at a time.
//
// This is a Go port of OpenThread's src/core/meshcop/meshcop_leader.hpp/cpp.
type LeaderCommissioner struct {
	mu sync.Mutex

	commissionerID  string
	sessionID       uint16
	hasCommissioner bool
	expiryTimer     *time.Timer

	// afterFunc allows tests to inject timer scheduling.
	afterFunc func(d time.Duration, f func()) *time.Timer

	// onResign is called when the commissioner session expires or resigns.
	onResign func()
}

// NewLeaderCommissioner creates a new LeaderCommissioner.
// onResign is called when the commissioner session expires or is resigned
// (may be nil).
func NewLeaderCommissioner(onResign func()) *LeaderCommissioner {
	return &LeaderCommissioner{
		onResign:  onResign,
		afterFunc: time.AfterFunc,
	}
}

// HandlePetition processes a LEAD_PETITION request from a commissioner.
// Returns the session ID and state (StateAccept or StateReject).
//
// Accept conditions:
//   - No active commissioner, OR
//   - Same commissioner ID (refresh)
//
// If accepted, a new session ID is generated and the session timeout is started.
func (lc *LeaderCommissioner) HandlePetition(commissionerID string) (sessionID uint16, state uint8) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if lc.hasCommissioner && lc.commissionerID != commissionerID {
		// Another commissioner is already active — reject.
		return 0, StateReject
	}

	// Accept the petition.
	lc.commissionerID = commissionerID
	lc.sessionID = uint16(rand.IntN(0x10000)) //nolint:gosec // non-crypto random, matching OpenThread
	lc.hasCommissioner = true

	lc.resetExpiryTimer()

	return lc.sessionID, StateAccept
}

// HandleKeepAlive processes a LEAD_KEEP_ALIVE request.
// Returns the response state (StateAccept or StateReject).
//
// If the incoming state is StateAccept, the session timeout is refreshed.
// If the incoming state is StateReject (resign), the session is cleared.
// If the session ID does not match, StateReject is returned.
func (lc *LeaderCommissioner) HandleKeepAlive(sessionID uint16, state uint8) uint8 {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if !lc.hasCommissioner || sessionID != lc.sessionID {
		return StateReject
	}

	if state == StateReject {
		// Commissioner is resigning.
		lc.resignLocked()
		return StateAccept
	}

	// Refresh the session.
	lc.resetExpiryTimer()
	return StateAccept
}

// GetSessionID returns the current commissioner session ID.
// Returns 0 if no commissioner is active.
func (lc *LeaderCommissioner) GetSessionID() uint16 {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.sessionID
}

// GetCommissionerID returns the current commissioner's identity string.
// Returns empty string if no commissioner is active.
func (lc *LeaderCommissioner) GetCommissionerID() string {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if !lc.hasCommissioner {
		return ""
	}
	return lc.commissionerID
}

// HasCommissioner reports whether there is an active commissioner.
func (lc *LeaderCommissioner) HasCommissioner() bool {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.hasCommissioner
}

// Resign forcefully removes the active commissioner.
func (lc *LeaderCommissioner) Resign() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.resignLocked()
}

// resignLocked clears the commissioner session. Must be called with lc.mu held.
func (lc *LeaderCommissioner) resignLocked() {
	lc.stopExpiryTimer()
	lc.hasCommissioner = false
	lc.commissionerID = ""
	lc.sessionID = 0

	if lc.onResign != nil {
		lc.onResign()
	}
}

// resetExpiryTimer resets the session expiry timer. Must be called with lc.mu held.
func (lc *LeaderCommissioner) resetExpiryTimer() {
	lc.stopExpiryTimer()
	lc.expiryTimer = lc.afterFunc(leaderSessionTimeout, func() {
		lc.mu.Lock()
		defer lc.mu.Unlock()
		if lc.hasCommissioner {
			lc.resignLocked()
		}
	})
}

// stopExpiryTimer stops the expiry timer if running. Must be called with lc.mu held.
func (lc *LeaderCommissioner) stopExpiryTimer() {
	if lc.expiryTimer != nil {
		lc.expiryTimer.Stop()
		lc.expiryTimer = nil
	}
}
