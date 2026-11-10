// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/slaac"
	"github.com/hilli/gothread/platform"
)

// SourceLifetimeCapacity is a separate lease bound equal to the existing
// manager's four address slots. Retired/failed leases occupy slots until release;
// this never reduces manager, filter, membership or namespace capacities.
const SourceLifetimeCapacity = slaac.DefaultMaxAddresses

// ThreadSourceLifetime is a value-only opaque lease. Copies alias the same
// lease, not extra ownership; release invalidates every copy permanently.
type ThreadSourceLifetime struct {
	inst    *Instance
	attempt *ThreadAttachAttempt
	id      uint64
	slot    uint8
}

// ThreadSourceLifetimeState distinguishes observed retirement from failure.
// Zero is never a successful disposition.
type ThreadSourceLifetimeState uint8

// Source lifetime states distinguish current authority, retirement and failure.
const (
	ThreadSourceCurrent ThreadSourceLifetimeState = iota + 1
	ThreadSourceRetired
	ThreadSourceFailed
)

// ThreadSourceRetirement records only a specific accepted authenticated event.
type ThreadSourceRetirement uint8

// Retirement reasons require an accepted authenticated source event.
const (
	ThreadSourceNoRetirement ThreadSourceRetirement = iota
	ThreadSourceAuthenticatedWithdrawal
	ThreadSourceAuthenticatedDeprecation
)

// ThreadSourceFailure is the first retained SDK-visible genuine failure.
type ThreadSourceFailure uint8

// Failure reasons retain the first genuine SDK-visible source failure.
const (
	ThreadSourceNoFailure ThreadSourceFailure = iota
	ThreadSourceManualRemoval
	ThreadSourceRoleLost
	ThreadSourceStopped
	ThreadSourceNetworkDataInvalidated
	ThreadSourceBackendFailure
	ThreadSourceHealthFailure
	ThreadSourceIdentityInvalid
	ThreadSourceInterfaceDown
)

// ThreadSourceDisposition describes THIS leased generation, not current G2.
// Retirement is not absence-of-fault proof: failure and late latched errors
// dominate State, and consumers still retain child/drain/health/exclusive leases.
type ThreadSourceDisposition struct {
	State            ThreadSourceLifetimeState
	Retirement       ThreadSourceRetirement
	Failure          ThreadSourceFailure
	Cause            error
	HealthError      error
	PersistenceError error
	Source           ip6.Address
	Epoch            uint64
	SourceGeneration uint64
}

type sourceLifetimeRecord struct {
	id         uint64
	attempt    *ThreadAttachAttempt
	proof      ownedSourceProof
	epoch      uint64
	retirement ThreadSourceRetirement
	failure    ThreadSourceFailure
	cause      error
}

// AcquireSourceLifetime is LOOP-ONLY and succeeds only while the exact opaque
// attempt's generated source is genuinely current. DTOs cannot acquire G1 later.
func (attempt *ThreadAttachAttempt) AcquireSourceLifetime(source ip6.Address) (ThreadSourceLifetime, error) {
	var token ThreadSourceLifetime
	if _, err := attempt.ObserveAttachment(source); err != nil {
		return token, err
	}
	inst := attempt.inst
	proof, err := inst.currentOwnedSource(source)
	if err != nil {
		return token, err
	}
	if proof.generation == 0 {
		return token, goterrors.ErrNotCapable
	}
	inst.sourceLifetimeMu.Lock()
	defer inst.sourceLifetimeMu.Unlock()
	if failure := inst.securityFailure.Load(); failure != nil {
		return token, failure.cause
	}
	if inst.sourceLifetimeNext == ^uint64(0) {
		return token, goterrors.ErrNoBufs
	}
	for i := range inst.sourceLifetimes {
		if inst.sourceLifetimes[i].id != 0 {
			continue
		}
		inst.sourceLifetimeNext++
		id := inst.sourceLifetimeNext
		inst.sourceLifetimes[i] = sourceLifetimeRecord{id: id, attempt: attempt, proof: proof, epoch: attempt.epoch}
		return ThreadSourceLifetime{inst: inst, attempt: attempt, id: id, slot: uint8(i)}, nil
	}
	return token, goterrors.ErrNoBufs
}

func (attempt *ThreadAttachAttempt) sourceLifetimeRecord(token ThreadSourceLifetime) (sourceLifetimeRecord, error) {
	var record sourceLifetimeRecord
	if attempt == nil || attempt.inst == nil || token.inst != attempt.inst || token.attempt != attempt ||
		token.id == 0 || int(token.slot) >= SourceLifetimeCapacity {
		return record, goterrors.ErrInvalidState
	}
	inst := attempt.inst
	inst.sourceLifetimeMu.Lock()
	record = inst.sourceLifetimes[token.slot]
	inst.sourceLifetimeMu.Unlock()
	if record.id != token.id || record.attempt != attempt {
		return sourceLifetimeRecord{}, goterrors.ErrInvalidState
	}
	return record, nil
}

// ObserveSourceLifetime is read-only and LOOP-ONLY while running. After Stop
// returns it may read the retained terminal record without restarting a failed
// instance. It performs no Fill/Settings I/O/counter/latch/fence mutation.
func (attempt *ThreadAttachAttempt) ObserveSourceLifetime(token ThreadSourceLifetime) (ThreadSourceDisposition, error) {
	var result ThreadSourceDisposition
	record, err := attempt.sourceLifetimeRecord(token)
	if err != nil {
		return result, err
	}
	inst := attempt.inst
	result = ThreadSourceDisposition{State: ThreadSourceCurrent, Retirement: record.retirement,
		Failure: record.failure, Cause: record.cause, Source: record.proof.source,
		Epoch: record.epoch, SourceGeneration: record.proof.generation}
	if record.retirement != ThreadSourceNoRetirement {
		result.State = ThreadSourceRetired
	}
	if record.failure != ThreadSourceNoFailure {
		result.State = ThreadSourceFailed
	}
	if failure := inst.securityFailure.Load(); failure != nil {
		result.HealthError = failure.cause
	} else if health, ok := inst.entropy.(platform.EntropyHealth); ok {
		result.HealthError = health.Err()
	} else {
		result.HealthError = goterrors.ErrNotCapable
	}
	result.PersistenceError = inst.PersistenceError()
	if result.HealthError != nil {
		result.State = ThreadSourceFailed
		if result.Cause == nil {
			result.Cause, result.Failure = result.HealthError, ThreadSourceHealthFailure
		}
	}
	if result.PersistenceError != nil {
		result.State = ThreadSourceFailed
		if result.Cause == nil {
			result.Cause, result.Failure = result.PersistenceError, ThreadSourceBackendFailure
		}
	}
	if result.State == ThreadSourceCurrent {
		current, err := inst.currentOwnedSource(record.proof.source)
		if err != nil || current != record.proof || inst.threadEpoch != record.epoch {
			result.State, result.Failure = ThreadSourceFailed, ThreadSourceIdentityInvalid
			result.Cause = err
			if result.Cause == nil {
				result.Cause = goterrors.ErrInvalidState
			}
		}
	}
	return result, nil
}

// ReleaseSourceLifetime releases only its named lease. LOOP-ONLY while running;
// also allowed after Stop has returned. No protocol state or hardware is touched.
func (attempt *ThreadAttachAttempt) ReleaseSourceLifetime(token ThreadSourceLifetime) error {
	if _, err := attempt.sourceLifetimeRecord(token); err != nil {
		return err
	}
	inst := attempt.inst
	inst.sourceLifetimeMu.Lock()
	defer inst.sourceLifetimeMu.Unlock()
	if inst.sourceLifetimes[token.slot].id != token.id {
		return goterrors.ErrInvalidState
	}
	inst.sourceLifetimes[token.slot] = sourceLifetimeRecord{}
	return nil
}

// No protocol/provider getter is called with sourceLifetimeMu held; the role
// callback may hold MLE.mu, and health may be reported outside the owner loop.
func (inst *Instance) failSourceLifetimes(attachment *ownedThreadAttachment, reason ThreadSourceFailure, cause error) {
	if cause == nil {
		cause = goterrors.ErrInvalidState
	}
	inst.sourceLifetimeMu.Lock()
	defer inst.sourceLifetimeMu.Unlock()
	for i := range inst.sourceLifetimes {
		record := &inst.sourceLifetimes[i]
		if record.id == 0 || attachment != nil && record.proof.attachment != attachment ||
			record.failure != ThreadSourceNoFailure {
			continue
		}
		record.failure, record.cause = reason, cause
	}
}

func (inst *Instance) failSourceLifetime(proof ownedSourceProof, reason ThreadSourceFailure, cause error) {
	inst.sourceLifetimeMu.Lock()
	defer inst.sourceLifetimeMu.Unlock()
	for i := range inst.sourceLifetimes {
		record := &inst.sourceLifetimes[i]
		if record.id != 0 && record.proof == proof && record.failure == ThreadSourceNoFailure {
			record.failure, record.cause = reason, cause
		}
	}
}

func (inst *Instance) retireSourceLifetime(proof ownedSourceProof, reason ThreadSourceRetirement) {
	inst.sourceLifetimeMu.Lock()
	defer inst.sourceLifetimeMu.Unlock()
	for i := range inst.sourceLifetimes {
		record := &inst.sourceLifetimes[i]
		if record.id != 0 && record.proof == proof && record.failure == ThreadSourceNoFailure &&
			record.retirement == ThreadSourceNoRetirement {
			record.retirement = reason
		}
	}
}
