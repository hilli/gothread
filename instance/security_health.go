// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"errors"
	"fmt"

	csettings "github.com/hilli/gothread/common/settings"
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/platform"
)

// SecurityError reports the first configured entropy/health failure without
// clearing persistence state. The provider's Err must satisfy EntropyHealth's
// readonly/nonblocking contract. Safe from frame callbacks and outside the loop.
func (inst *Instance) SecurityError() error {
	if failure := inst.securityFailure.Load(); failure != nil {
		return failure.cause
	}
	if health, ok := inst.entropy.(platform.EntropyHealth); ok {
		if err := health.Err(); err != nil {
			inst.latchSecurityError(err)
		}
	}
	if failure := inst.securityFailure.Load(); failure != nil {
		return failure.cause
	}
	return nil
}

type securityFailure struct{ cause error }

func (inst *Instance) requireNativeSecurity() error {
	if _, ok := inst.entropy.(platform.EntropyHealth); !ok {
		return goterrors.ErrNotCapable
	}
	return inst.SecurityError()
}

func (inst *Instance) latchSecurityError(err error) {
	if err == nil || inst.securityFailure.Load() != nil {
		return
	}
	if inst.securityFailure.CompareAndSwap(nil, &securityFailure{cause: err}) {
		inst.failSourceLifetimes(nil, ThreadSourceHealthFailure, err)
		inst.securityFenceRequested.Store(true)
	}
}

// Called only by the loop, outside MAC/provider locks. Every producer also
// checks the latched cause synchronously, so queue saturation cannot bypass it.
func (inst *Instance) processSecurityFence() {
	if inst.securityFenceRequested.Swap(false) {
		inst.fenceSecurityFailure()
	}
}

func (inst *Instance) fenceSecurityFailure() {
	failure := inst.securityFailure.Load()
	if failure == nil {
		return
	}
	err := failure.cause
	inst.finishThreadAttach(&ThreadAttachResult{Err: err})
	if inst.srpBinding != nil {
		inst.srpBinding.close(err)
	}
	if inst.threadEnabled {
		_ = inst.ThreadStop()
	}
	inst.abortFragmentedTraffic()
}

type nativeEntropyReader struct{ inst *Instance }

func (reader nativeEntropyReader) Read(destination []byte) (int, error) {
	inst := reader.inst
	if err := inst.SecurityError(); err != nil {
		return 0, err
	}

	if inst.entropy == nil {
		return 0, goterrors.ErrInvalidState
	}
	// Commit neither partial challenge nor partial signing randomness.
	temporary := make([]byte, len(destination))
	if err := inst.entropy.Fill(temporary); err != nil {
		inst.latchSecurityError(err)
		return 0, err
	}
	if err := inst.SecurityError(); err != nil {
		return 0, err
	}
	copy(destination, temporary)
	return len(destination), nil
}

func (inst *Instance) readOrCreateSLAACSecret() [32]byte {
	var secret [32]byte
	if inst.stackSettings == nil || inst.SecurityError() != nil {
		return secret // Legacy no-settings use remains distinct from native admission.
	}
	stored, err := inst.stackSettings.ReadSlaacIidSecretKey()
	if err == nil {
		if len(stored) != len(secret) {
			inst.restoreErr = errors.Join(inst.restoreErr, fmt.Errorf("instance: corrupt SLAAC secret: %w", goterrors.ErrParse))
			return secret
		}
		copy(secret[:], stored)
		return secret
	}
	if !errors.Is(err, csettings.ErrNotFound) {
		inst.restoreErr = errors.Join(inst.restoreErr, fmt.Errorf("instance: read SLAAC secret: %w", err))
		return secret
	}
	if inst.entropy == nil {
		return secret // No weak value is persisted; qualified native profiles reject missing entropy.
	}
	if _, err := (nativeEntropyReader{inst: inst}).Read(secret[:]); err != nil {
		return [32]byte{}
	}
	if err := inst.stackSettings.WriteSlaacIidSecretKey(secret[:]); err != nil {
		inst.restoreErr = errors.Join(inst.restoreErr, fmt.Errorf("instance: persist SLAAC secret: %w", err))
	}
	return secret
}
