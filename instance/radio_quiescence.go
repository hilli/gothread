// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"sync"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac"
	"github.com/hilli/gothread/mac/submac"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/radio"
)

type radioLoopOwner struct {
	mu           sync.Mutex
	enabled      bool
	pending      uint64
	closed       bool
	interrupted  bool
	failure      error
	receiveError error
	stopQueued   bool
	stopError    error
	prepared     bool
	restored     bool
	generation   chan struct{}
	discovery    *nativeDiscovery
	discoveryID  uint64
	lease        *mac.DiscoveryRadioLease
	home         radioHomeOwnership
	pan          uint16
	channel      uint8
	state        submac.State
	identity     types.ExtAddress
}

type radioHomeOwnership uint8

const (
	radioHomeUnprepared radioHomeOwnership = iota
	radioHomeLeased
	radioHomeDisabledMAC
	radioHomeDisabledResource
)

// RadioReceiveRestorationError reports the first actual Receive restoration
// error from ordinary transmit finalization after callback ownership was
// enabled, including unsubmitted cleanup. Safe to
// read outside the loop and after Stop. The actual transmitted-packet outcome
// and completed Join/Stop/Restore milestones are unchanged; callers must retain
// this separate cause for final cleanup aggregation, even after restoration.
// This is not a health/Ready flag or every later receive/operation error.
func (inst *Instance) RadioReceiveRestorationError() error {
	inst.radioOwner.mu.Lock()
	defer inst.radioOwner.mu.Unlock()
	return inst.radioOwner.receiveError
}

func (inst *Instance) retainPostTransmitReceiveError(_ *radio.Frame, cause error) {
	if cause == nil {
		return
	}
	inst.radioOwner.mu.Lock()
	defer inst.radioOwner.mu.Unlock()
	if inst.radioOwner.enabled && inst.radioOwner.receiveError == nil {
		inst.radioOwner.receiveError = cause
	}
}

type radioRestoreScope struct {
	owner     *radioLoopOwner
	discovery *nativeDiscovery
	lease     *mac.DiscoveryRadioLease
	panDone   bool
	restorer  interface {
		RestorePanID(uint16) error
		RestoreReceive(uint8) error
		RestoreSleep() error
	}
}

// PostRadioCallback publishes a DRIVER callback, not an ordinary SDK task.
// The bound radio worker calls this outside the SDK loop, exactly as PostTask;
// publication is owned before the existing bounded queue can block that worker.
func (inst *Instance) PostRadioCallback(fn func()) {
	if fn == nil {
		inst.failRadioPublication(goterrors.ErrInvalidArgs)
		return
	}
	task, admitted := inst.ownRadioWork(fn, true)
	if !admitted {
		return
	}
	// No early driver acknowledgement or callback-owned defer completes this
	// obligation. The dispatcher retires it after the ORIGINAL fn RETURNS.
	inst.taskCh <- task
}

func (inst *Instance) failRadioPublication(cause error) {
	inst.radioOwner.mu.Lock()
	if inst.radioOwner.failure == nil {
		inst.radioOwner.failure = cause
	}
	inst.radioOwner.mu.Unlock()
	inst.logOwnedControlError(cause)
}

// ownRadioWork is used only at explicit callback/derived-maintenance sites.
// It does not infer a task's origin from an ambient "currently in callback" bit.
func (inst *Instance) ownRadioWork(fn func(), enable bool) (loopTask, bool) {
	owner := &inst.radioOwner
	owner.mu.Lock()
	if enable {
		owner.enabled = true
	}
	// Required SDK maintenance can precede the first driver publication,
	// e.g. a synchronous radio rejection. Book it before opt-in too; Join
	// must not overlook a still-running continuation when first called.
	if owner.closed || owner.pending == ^uint64(0) {
		cause := goterrors.ErrInvalidState
		if !owner.closed {
			cause = goterrors.ErrNoBufs
		}
		if owner.failure == nil {
			owner.failure = cause
		}
		owner.mu.Unlock()
		inst.logOwnedControlError(cause)
		return loopTask{}, false
	}
	owner.pending++
	owner.mu.Unlock()
	return loopTask{fn: fn, owner: inst}, true
}

func (inst *Instance) deferRadioMaintenance(fn func()) {
	task, admitted := inst.ownRadioWork(fn, false)
	if admitted {
		inst.timers.scheduleTask(0, task)
	}
}

func (inst *Instance) postRadioMaintenance(fn func()) bool {
	task, admitted := inst.ownRadioWork(fn, false)
	if !admitted {
		return false
	}
	select {
	case inst.taskCh <- task:
		return true
	default:
		inst.retireRadioWork() // Refund only the obligation NOT admitted to a dispatcher.
		return false
	}
}

// JoinRadioCallbacks is a bounded, retryable observation of actual driver
// returns AND explicitly owned completion/RX maintenance. It never waits on the
// loop, steals tasks, checks queue length, or equates a driver ack with return.
// Nil is a resource milestone, NEVER healthy/Ready or networking authority.
func (inst *Instance) JoinRadioCallbacks() error {
	owner := &inst.radioOwner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	owner.enabled = true
	if owner.failure != nil {
		return owner.failure
	}
	if owner.pending != 0 {
		return goterrors.ErrBusy
	}
	return nil
}

// StopRadioQuiescent permanently closes normal admission, then requests the
// genuine loop's named stop. Busy means retry this SAME owner: nil requires
// actual generation completion, never running=false or a timeout. Nil does
// not clear SecurityError/PersistenceError or claim final Runtime.Close. It is
// nonblocking even when invoked from an SDK loop callback.
func (inst *Instance) StopRadioQuiescent() error {
	if err := inst.JoinRadioCallbacks(); err != nil {
		return err
	}
	inst.runningMu.Lock()
	owner := &inst.radioOwner
	owner.mu.Lock()
	inst.radioStopRequested = true
	if owner.prepared {
		done := owner.generation
		owner.mu.Unlock()
		inst.runningMu.Unlock()
		select {
		case <-done:
			return inst.JoinRadioCallbacks()
		default:
			return goterrors.ErrBusy
		}
	}
	if owner.stopQueued {
		owner.mu.Unlock()
		inst.runningMu.Unlock()
		return goterrors.ErrBusy
	}
	if inst.stopping {
		owner.mu.Unlock()
		inst.runningMu.Unlock()
		return goterrors.ErrBusy
	}
	if !inst.running {
		select {
		case <-inst.doneCh:
			owner.mu.Unlock()
			inst.runningMu.Unlock()
			return inst.prepareStoppedRadioOwner()
		default:
			owner.mu.Unlock()
			inst.runningMu.Unlock()
			return goterrors.ErrInvalidState
		}
	}
	owner.stopQueued = true
	previous := owner.stopError
	owner.mu.Unlock()
	select {
	case inst.taskCh <- loopTask{fn: inst.prepareRadioStop}:
		inst.runningMu.Unlock()
		if previous != nil {
			return previous
		}
		return goterrors.ErrBusy
	default:
		owner.mu.Lock()
		owner.stopQueued = false
		owner.mu.Unlock()
		inst.runningMu.Unlock()
		return goterrors.ErrBusy
	}
}

func (inst *Instance) prepareRadioHome() error {
	owner := &inst.radioOwner
	if owner.home != radioHomeUnprepared {
		return goterrors.ErrInvalidState
	}
	if inst.subMac == nil || inst.mac == nil || inst.radioBridge == nil {
		return goterrors.ErrNotCapable
	}
	if inst.subMac.IsTransmittingOrScanning() {
		return goterrors.ErrBusy
	}
	if scan := inst.nativeDiscovery; scan != nil && scan.lease != nil {
		if scan.transmitting {
			return goterrors.ErrBusy
		}
		owner.discovery, owner.lease = scan, scan.lease
		owner.home = radioHomeLeased
		owner.discoveryID = scan.id
		owner.pan, owner.channel, owner.state = scan.homePAN, scan.homeChannel, scan.homeState
	} else if !inst.mac.IsEnabled() {
		home := radioHomeDisabledMAC
		if inst.radioBridge.GetState() == radio.StateDisabled {
			home = radioHomeDisabledResource
		}
		if owner.lease != nil || owner.discovery != nil || !inst.disabledMACRadioHome(home) {
			return goterrors.ErrInvalidState
		}
		owner.home = home
		owner.pan, owner.channel, owner.state = inst.subMac.GetPanID(), inst.mac.GetPanChannelSnapshot(), inst.subMac.GetState()
	} else {
		lease, err := inst.mac.AcquireDiscoveryRadio()
		if err != nil {
			return err
		}
		owner.lease = lease
		owner.home = radioHomeLeased
		owner.pan, owner.channel, owner.state = inst.subMac.GetPanID(), inst.mac.GetPanChannelSnapshot(), inst.subMac.GetState()
	}
	owner.generation = inst.doneCh
	owner.identity = inst.subMac.GetExtAddress()
	owner.prepared = true
	return nil
}

func (inst *Instance) prepareRadioStop() {
	owner := &inst.radioOwner
	inst.runningMu.Lock()
	owner.mu.Lock()
	owner.stopQueued = false
	if owner.pending != 0 || owner.prepared {
		owner.mu.Unlock()
		inst.runningMu.Unlock()
		return
	}
	if err := inst.prepareRadioHome(); err != nil {
		// Busy/error does not release the permanent admission fence or the
		// radio's owner. Current SDK causes remain separately observable.
		owner.stopError = err
		owner.mu.Unlock()
		inst.runningMu.Unlock()
		return
	}
	owner.stopError = nil
	if !inst.stopping {
		inst.stopping = true
		close(inst.stopCh)
	}
	owner.mu.Unlock()
	inst.runningMu.Unlock()
}

func (inst *Instance) prepareStoppedRadioOwner() error {
	inst.runningMu.Lock()
	defer inst.runningMu.Unlock()
	if inst.running || inst.stopping || inst.discoveryCleanupOnly {
		return goterrors.ErrBusy
	}
	owner := &inst.radioOwner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.pending != 0 {
		return goterrors.ErrBusy
	}
	if owner.prepared {
		return nil
	}
	if err := inst.prepareRadioHome(); err != nil {
		return err
	}
	if owner.home == radioHomeDisabledMAC || owner.home == radioHomeDisabledResource {
		owner.closed = true // The captured real loop generation already returned.
	}
	return nil
}

// Called only by the genuine event loop. Once stop was requested, publication
// remains open until ALL admitted callbacks and their owned continuations ran.
func (inst *Instance) finishRadioLoop(done chan struct{}) {
	for {
		inst.radioOwner.mu.Lock()
		pending := inst.radioOwner.pending
		waitAccepted := inst.radioOwner.enabled && !inst.radioOwner.prepared
		interrupted := inst.radioOwner.interrupted
		inst.radioOwner.mu.Unlock()
		if waitAccepted && inst.subMac != nil {
			waitAccepted = inst.subMac.IsTransmittingOrScanning()
		} else {
			waitAccepted = false
		}
		if !interrupted && (pending != 0 || waitAccepted) {
			inst.timers.processExpired()
			inst.radioOwner.mu.Lock()
			remaining := inst.radioOwner.pending
			inst.radioOwner.mu.Unlock()
			if remaining == 0 && (inst.subMac == nil || !inst.subMac.IsTransmittingOrScanning()) {
				continue
			}
			var timerCh <-chan time.Time
			if delay, ok := inst.timers.nextDeadline(); ok {
				timerCh = time.After(delay)
			}
			select {
			case task := <-inst.taskCh:
				dispatchLoopTask(task)
			case <-timerCh:
				inst.timers.processExpired()
			}
			continue
		}
		inst.runningMu.Lock()
		inst.radioOwner.mu.Lock()
		if !inst.radioOwner.interrupted && inst.radioOwner.pending != 0 {
			inst.radioOwner.mu.Unlock()
			inst.runningMu.Unlock()
			continue
		}
		if inst.radioOwner.enabled || inst.radioOwner.interrupted {
			inst.radioOwner.closed = true
			inst.radioStopRequested = true
		}
		inst.radioOwner.mu.Unlock()
		inst.running, inst.stopping = false, false
		close(done)
		inst.runningMu.Unlock()
		return
	}
}

func (inst *Instance) validRadioRestore(scope *radioRestoreScope) bool {
	if scope == nil || !scope.panDone || inst.radioRestore != scope || !inst.discoveryCleanupOnly ||
		scope.owner != &inst.radioOwner || !scope.owner.prepared || scope.owner.restored ||
		scope.owner.lease != scope.lease || scope.owner.discovery != scope.discovery ||
		!inst.radioHomeIdentity(scope.owner) {
		return false
	}
	if scope.discovery != nil {
		return inst.nativeDiscovery == scope.discovery && scope.discovery.lease == scope.lease &&
			scope.discovery.terminal && !scope.discovery.transmitting
	}
	return inst.nativeDiscovery == nil
}

func (inst *Instance) radioHomeIdentity(owner *radioLoopOwner) bool {
	if inst.subMac == nil || inst.mac == nil ||
		inst.subMac.GetPanID() != owner.pan || inst.mac.GetPanChannelSnapshot() != owner.channel ||
		inst.subMac.GetExtAddress() != owner.identity {
		return false
	}
	switch owner.home {
	case radioHomeLeased:
		if owner.lease == nil || (owner.state != submac.StateReceive && owner.state != submac.StateSleep) {
			return false
		}
	case radioHomeDisabledMAC, radioHomeDisabledResource:
		if owner.lease != nil || owner.discovery != nil || inst.subMac.GetState() != owner.state ||
			!inst.disabledMACRadioHome(owner.home) {
			return false
		}
	default:
		return false
	}
	if scan := owner.discovery; scan != nil {
		return inst.nativeDiscovery == scan && scan.id == owner.discoveryID && scan.lease == owner.lease &&
			scan.homePAN == owner.pan && scan.homeChannel == owner.channel && scan.homeState == owner.state &&
			scan.identity == owner.identity && !scan.transmitting
	}
	return inst.nativeDiscovery == nil
}

func (inst *Instance) disabledMACRadioHome(home radioHomeOwnership) bool {
	if inst.subMac == nil || inst.mac == nil || inst.radioBridge == nil ||
		inst.ifConfigUp || inst.threadEnabled || inst.nativeDiscovery != nil ||
		inst.mac.IsEnabled() || inst.mac.GetCurrentOperation() != mac.OperationIdle ||
		inst.mac.GetPendingOperations() != 0 {
		return false
	}
	state := inst.subMac.GetState()
	physical := inst.radioBridge.GetState()
	if state != submac.StateDisabled && state != submac.StateSleep && state != submac.StateReceive {
		return false
	}
	switch home {
	case radioHomeDisabledMAC:
		return physical == radio.StateSleep || physical == radio.StateReceive
	case radioHomeDisabledResource:
		// SDK intent eligibility only. The actual token must attest native retirement.
		return physical == radio.StateDisabled
	default:
		return false
	}
}

// RestoreRadioQuiescent performs WHOLE named stopped SDK restoration. Its
// unnamed interface is identical to a radio module's alias, without importing
// that module. A successful hardware mode alone is not SDK cleanup success.
// Nil reports only WHOLE cleanup completion, never health recovery or Ready.
func (inst *Instance) RestoreRadioQuiescent(restorer interface {
	RestorePanID(uint16) error
	RestoreReceive(uint8) error
	RestoreSleep() error
}) error {
	if restorer == nil {
		return goterrors.ErrInvalidArgs
	}
	inst.runningMu.Lock()
	owner := &inst.radioOwner
	owner.mu.Lock()
	if inst.running || inst.stopping || !inst.radioStopRequested || !owner.prepared ||
		owner.generation != inst.doneCh || owner.restored {
		owner.mu.Unlock()
		inst.runningMu.Unlock()
		return goterrors.ErrInvalidState
	}
	if inst.discoveryCleanupOnly {
		owner.mu.Unlock()
		inst.runningMu.Unlock()
		return goterrors.ErrBusy
	}
	select {
	case <-owner.generation:
	default:
		owner.mu.Unlock()
		inst.runningMu.Unlock()
		return goterrors.ErrBusy
	}
	if !inst.radioHomeIdentity(owner) {
		owner.mu.Unlock()
		inst.runningMu.Unlock()
		return goterrors.ErrInvalidState
	}
	if owner.pending != 0 || owner.failure != nil {
		err := owner.failure
		if err == nil {
			err = goterrors.ErrBusy
		}
		owner.mu.Unlock()
		inst.runningMu.Unlock()
		return err
	}
	scope := &radioRestoreScope{owner: owner, discovery: owner.discovery, lease: owner.lease, restorer: restorer}
	inst.discoveryCleanupOnly = true
	inst.radioRestore = scope
	owner.mu.Unlock()
	inst.runningMu.Unlock()
	defer func() {
		inst.runningMu.Lock()
		inst.radioRestore = nil
		inst.discoveryCleanupOnly = false
		inst.runningMu.Unlock()
	}()
	if owner.home == radioHomeDisabledResource {
		disabled, ok := restorer.(interface{ RestoreDisabled() error })
		if !ok {
			return goterrors.ErrNotCapable
		}
		if err := disabled.RestoreDisabled(); err != nil {
			return err
		}
		return inst.finishDisabledRadioRestore(scope)
	}
	if err := restorer.RestorePanID(owner.pan); err != nil {
		return err
	}
	scope.panDone = true
	var err error
	if scope.discovery != nil {
		if inst.nativeDiscovery != scope.discovery || scope.discovery.lease != scope.lease ||
			!scope.discovery.terminal {
			return goterrors.ErrInvalidState
		}
		err = inst.discoveryScanner.RetryCleanup(scope.discovery.id)
		if err == nil && inst.nativeDiscovery != nil {
			return goterrors.ErrInvalidState
		}
	} else {
		if inst.nativeDiscovery != nil {
			return goterrors.ErrInvalidState
		}
		if owner.home == radioHomeDisabledMAC {
			if !inst.validRadioRestore(scope) {
				return goterrors.ErrInvalidState
			}
			switch owner.state {
			case submac.StateDisabled:
				// Restore physical sleep without enabling the disabled SubMac.
				err = restorer.RestoreSleep()
				if err == nil && (inst.radioBridge.GetState() != radio.StateSleep ||
					!inst.validRadioRestore(scope)) {
					return goterrors.ErrInvalidState
				}
			case submac.StateSleep:
				err = inst.subMac.Sleep()
			case submac.StateReceive:
				err = inst.subMac.Receive(owner.channel)
			default:
				return goterrors.ErrInvalidState
			}
			if err == nil && !inst.radioHomeIdentity(owner) {
				return goterrors.ErrInvalidState
			}
		} else {
			err = scope.lease.RestoreStopped()
		}
	}
	if err != nil {
		return err
	}
	owner.mu.Lock()
	owner.lease, owner.discovery = nil, nil
	owner.restored = true
	owner.mu.Unlock()
	return nil
}

func (inst *Instance) finishDisabledRadioRestore(scope *radioRestoreScope) error {
	inst.runningMu.Lock()
	defer inst.runningMu.Unlock()
	owner := &inst.radioOwner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.failure != nil {
		return owner.failure
	}
	if owner.pending != 0 {
		return goterrors.ErrBusy
	}
	if inst.running || inst.stopping || !inst.radioStopRequested || !inst.discoveryCleanupOnly ||
		inst.radioRestore != scope || scope.owner != owner || !owner.prepared || owner.restored ||
		owner.home != radioHomeDisabledResource || owner.generation != inst.doneCh ||
		owner.lease != nil || owner.discovery != nil || scope.lease != nil || scope.discovery != nil ||
		!inst.radioHomeIdentity(owner) {
		return goterrors.ErrInvalidState
	}
	select {
	case <-owner.generation:
	default:
		return goterrors.ErrBusy
	}
	owner.lease, owner.discovery = nil, nil
	owner.restored = true
	return nil
}
