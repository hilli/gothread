// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package netdata

import (
	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Notifier delays (milliseconds)
// ---------------------------------------------------------------------------

const (
	// NotifierDelayNoBufs is the retry delay when buffer exhaustion occurs.
	NotifierDelayNoBufs = 1000 // 1 second

	// NotifierDelayRemoveStaleChildren is the delay for stale child cleanup.
	NotifierDelayRemoveStaleChildren = 5000 // 5 seconds

	// NotifierDelaySynchronize is the general re-sync interval.
	NotifierDelaySynchronize = 300000 // 5 minutes

	// NotifierRouterUpgradeMaxTimeout is the maximum random delay for router
	// upgrade notifications.
	NotifierRouterUpgradeMaxTimeout = 10000 // 10 seconds
)

// ---------------------------------------------------------------------------
// SyncCallback
// ---------------------------------------------------------------------------

// SyncCallback is called when the Notifier wants to send SVR_DATA.ntf to the
// Leader. The callback receives the old RLOC16 (so the Leader can remove
// stale entries for a previous address) and the current local network data
// TLV bytes. It returns nil on success, or an error (e.g., errors.ErrNoBufs)
// to trigger a retry.
type SyncCallback func(oldRloc16 uint16, data []byte) error

// ---------------------------------------------------------------------------
// Notifier
// ---------------------------------------------------------------------------

// Notifier manages synchronization of local Network Data with the Leader.
// It is a Go port of OpenThread's NetworkData::Notifier
// (src/core/thread/network_data_notifier.hpp / .cpp).
//
// The Notifier acts as a state machine that decides WHEN to sync local
// network data and tracks the synchronization state. Since we don't have a
// full CoAP stack wired up, the actual send is delegated to a SyncCallback.
type Notifier struct {
	local              *Local
	syncCallback       SyncCallback
	oldRloc16          uint16
	nextDelay          uint32 // milliseconds, 0 means sync immediately
	waitingForResponse bool
	needsSync          bool
	timerRunning       bool
	timerRemaining     uint32 // ms remaining on current timer
}

// NewNotifier creates a Notifier bound to the given Local network data store.
func NewNotifier(local *Local) *Notifier {
	return &Notifier{
		local: local,
	}
}

// SetSyncCallback sets the function called when synchronization with the
// Leader is needed.
func (n *Notifier) SetSyncCallback(cb SyncCallback) {
	n.syncCallback = cb
}

// HandleServerDataUpdated signals that local server data has been updated and
// needs to be synchronized with the Leader. This resets the delay to 0
// (immediate sync) and clears any pending response wait.
func (n *Notifier) HandleServerDataUpdated() {
	n.nextDelay = 0
	n.needsSync = true
	n.waitingForResponse = false
}

// SynchronizeServerData attempts to sync local data with the Leader. This
// should be called from the event loop when needsSync is true.
//
// It returns the delay (in milliseconds) until the next sync attempt should
// be scheduled, or 0 if no further sync is needed at this time.
func (n *Notifier) SynchronizeServerData() uint32 {
	if n.waitingForResponse {
		return 0
	}

	if !n.needsSync {
		return 0
	}

	// Re-encode local entries with the current RLOC16.
	n.local.UpdateRloc()

	// Check if local data actually differs from what was last synced.
	if !n.local.HasChanged() {
		n.needsSync = false
		return 0
	}

	// Attempt to send via the callback.
	if n.syncCallback == nil {
		// No callback registered; nothing we can do.
		return NotifierDelaySynchronize
	}

	err := n.syncCallback(n.oldRloc16, n.local.Data())
	if err == nil {
		// Successfully sent; wait for response.
		n.waitingForResponse = true
		n.local.ClearChanged()
		return n.nextDelay
	}

	// Handle specific error codes.
	if err == errors.ErrNoBufs {
		return NotifierDelayNoBufs
	}

	// Any other error: schedule a general re-sync.
	return NotifierDelaySynchronize
}

// HandleSyncResponse should be called when a response to SVR_DATA.ntf is
// received from the Leader. If success is true the Leader accepted the data;
// otherwise the sync will be retried immediately.
func (n *Notifier) HandleSyncResponse(success bool) {
	n.waitingForResponse = false

	if success {
		n.nextDelay = NotifierDelaySynchronize
		// Schedule periodic re-sync timer.
		n.timerRunning = true
		n.timerRemaining = NotifierDelaySynchronize
	} else {
		// Retry immediately.
		n.needsSync = true
		n.nextDelay = 0
	}
}

// NeedsSync reports whether a synchronization with the Leader is pending.
func (n *Notifier) NeedsSync() bool {
	return n.needsSync
}

// IsWaitingForResponse reports whether we are waiting for a response to a
// previously sent SVR_DATA.ntf message.
func (n *Notifier) IsWaitingForResponse() bool {
	return n.waitingForResponse
}

// SetOldRloc16 sets the old RLOC16 value that is sent in SVR_DATA.ntf so
// the Leader can remove stale entries from a previous address.
func (n *Notifier) SetOldRloc16(rloc16 uint16) {
	n.oldRloc16 = rloc16
}

// HandleTimerFired should be called when the sync timer expires. It triggers
// a new synchronization attempt.
func (n *Notifier) HandleTimerFired() {
	n.needsSync = true
	n.timerRunning = false
}

// IsLocalDataConsistent checks if local data matches what has been
// synchronized with the Leader. This is a simplified version that checks
// whether local data has changed since the last successful sync.
func (n *Notifier) IsLocalDataConsistent() bool {
	return !n.local.HasChanged() && !n.needsSync
}

// IsTimerRunning reports whether the periodic re-sync timer is active.
func (n *Notifier) IsTimerRunning() bool {
	return n.timerRunning
}

// TimerRemaining returns the remaining time (in milliseconds) on the
// periodic re-sync timer, or 0 if no timer is running.
func (n *Notifier) TimerRemaining() uint32 {
	if !n.timerRunning {
		return 0
	}
	return n.timerRemaining
}
