// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"sync"
	"time"

	goterrors "github.com/hilli/gothread/errors"
)

// datasetUpdaterRetryDelay is the delay before retrying a failed dataset update.
const datasetUpdaterRetryDelay = 1 * time.Second

// DatasetUpdater manages delayed dataset updates. It stores a requested
// dataset change, saves it as a Pending dataset with appropriate timestamps
// and delay, and monitors for dataset changes to detect success or conflict.
//
// This is a Go port of OpenThread's src/core/meshcop/dataset_updater.hpp/cpp.
type DatasetUpdater struct {
	mu sync.Mutex

	updatePending bool
	requestedInfo Info
	callback      func(error)

	activeManager  *ActiveDatasetManager
	pendingManager *PendingDatasetManager
	store          DatasetStore

	retryTimer *time.Timer

	// afterFunc allows tests to inject timer scheduling.
	afterFunc func(d time.Duration, f func()) *time.Timer
}

// NewDatasetUpdater creates a new DatasetUpdater.
func NewDatasetUpdater(
	activeManager *ActiveDatasetManager,
	pendingManager *PendingDatasetManager,
	store DatasetStore,
) *DatasetUpdater {
	return &DatasetUpdater{
		activeManager:  activeManager,
		pendingManager: pendingManager,
		store:          store,
		afterFunc:      time.AfterFunc,
	}
}

// IsUpdatePending reports whether an update request is currently in progress.
func (du *DatasetUpdater) IsUpdatePending() bool {
	du.mu.Lock()
	defer du.mu.Unlock()
	return du.updatePending
}

// CancelUpdate cancels any pending update request. If there was a pending
// update, the callback is invoked with ErrAlready.
func (du *DatasetUpdater) CancelUpdate() {
	du.mu.Lock()
	defer du.mu.Unlock()

	if !du.updatePending {
		return
	}

	du.stopRetryTimer()
	cb := du.callback
	du.updatePending = false
	du.callback = nil

	if cb != nil {
		cb(goterrors.ErrAlready)
	}
}

// RequestUpdate requests a dataset update. The provided Info contains the
// fields to change. The callback is invoked when the update succeeds, fails,
// or is cancelled.
//
// Returns ErrInvalidState if no active dataset exists, ErrBusy if another
// update is already pending.
func (du *DatasetUpdater) RequestUpdate(dataset *Info, cb func(error)) error {
	du.mu.Lock()
	defer du.mu.Unlock()

	if du.updatePending {
		return goterrors.ErrBusy
	}

	du.requestedInfo = *dataset
	du.callback = cb
	du.updatePending = true

	err := du.applyUpdate()
	if err != nil {
		du.updatePending = false
		du.callback = nil
		return err
	}

	return nil
}

// applyUpdate reads the current active dataset, prepares timestamps and
// delay, and saves the result as a pending dataset. Must be called with
// du.mu held.
func (du *DatasetUpdater) applyUpdate() error {
	// Read current active dataset.
	activeDS, err := du.store.ReadDataset(DatasetActive)
	if err != nil {
		return goterrors.ErrInvalidState
	}

	activeInfo := activeDS.ConvertToInfo()

	// Build the update dataset starting from the requested changes.
	updateInfo := du.requestedInfo

	// Set Active Timestamp: take current and advance.
	updateInfo.ActiveTimestamp = activeInfo.ActiveTimestamp
	updateInfo.ActiveTimestamp.AdvanceRandomTicks()
	updateInfo.Components.ActiveTimestamp = true

	// Set Pending Timestamp: take current (if exists) and advance, else
	// create from active timestamp.
	if activeInfo.Components.PendingTimestamp {
		updateInfo.PendingTimestamp = activeInfo.PendingTimestamp
	} else {
		updateInfo.PendingTimestamp = activeInfo.ActiveTimestamp
	}
	updateInfo.PendingTimestamp.AdvanceRandomTicks()
	updateInfo.Components.PendingTimestamp = true

	// Set default delay timer.
	updateInfo.Delay = DelayTimerDefault
	updateInfo.Components.Delay = true

	// Convert to a dataset with the requested TLVs.
	updateDS := InfoToDataset(&updateInfo)

	// Merge onto the current active dataset to fill in any missing fields.
	mergedDS := &Dataset{}
	if copyErr := mergedDS.SetFrom(activeDS.Bytes()); copyErr != nil {
		return copyErr
	}
	if mergeErr := mergedDS.WriteTLVsFrom(updateDS); mergeErr != nil {
		return mergeErr
	}

	// Save as pending dataset.
	return du.store.SaveDataset(DatasetPending, mergedDS)
}

// HandleDatasetChanged should be called when the active dataset changes.
// It checks whether the requested changes have been applied (subset check)
// and invokes the callback accordingly.
func (du *DatasetUpdater) HandleDatasetChanged() {
	du.mu.Lock()
	defer du.mu.Unlock()

	if !du.updatePending {
		return
	}

	// Read current active dataset.
	activeDS, err := du.store.ReadDataset(DatasetActive)
	if err != nil {
		// Active dataset disappeared — retry.
		du.scheduleRetry()
		return
	}

	// Build a dataset from only the requested changes (excluding timestamps/delay).
	requestedDS := InfoToDataset(&du.requestedInfo)

	// Check if all requested changes are now present in the active dataset.
	if requestedDS.IsSubsetOf(activeDS) {
		// Success.
		du.stopRetryTimer()
		cb := du.callback
		du.updatePending = false
		du.callback = nil
		if cb != nil {
			cb(nil)
		}
		return
	}

	// Not yet applied — could be a conflict. Retry.
	du.scheduleRetry()
}

// scheduleRetry schedules a retry of the update after a delay.
// Must be called with du.mu held.
func (du *DatasetUpdater) scheduleRetry() {
	du.stopRetryTimer()
	du.retryTimer = du.afterFunc(datasetUpdaterRetryDelay, func() {
		du.mu.Lock()
		defer du.mu.Unlock()

		if !du.updatePending {
			return
		}

		if err := du.applyUpdate(); err != nil {
			// If apply fails, invoke callback with error.
			cb := du.callback
			du.updatePending = false
			du.callback = nil
			if cb != nil {
				cb(err)
			}
		}
	})
}

// stopRetryTimer stops the retry timer if running. Must be called with du.mu held.
func (du *DatasetUpdater) stopRetryTimer() {
	if du.retryTimer != nil {
		du.retryTimer.Stop()
		du.retryTimer = nil
	}
}
