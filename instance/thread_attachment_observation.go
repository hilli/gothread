// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/thread/mle"
)

// ThreadAttachmentObservation is descriptive data returned by a live opaque
// attempt, never an authority token accepted by transmit/membership APIs.
// Epoch identifies the owned attachment, not its changing key/Primary state.
type ThreadAttachmentObservation struct {
	Profile          ThreadAttachProfile
	Role             mle.DeviceRole
	Source           ip6.Address
	LocalExtAddress  types.ExtAddress
	RLOC16           uint16
	ParentExtAddress types.ExtAddress
	ParentRLOC16     uint16
	Epoch            uint64
	// SourceGeneration is zero for the original caller-owned mesh EID and
	// changes when an authenticated owned SLAAC assignment is replaced.
	SourceGeneration uint64
}

// ObserveAttachment is LOOP-ONLY. It validates the exact attempt's successfully
// authenticated lifetime and the selected caller mesh EID or currently
// authenticated owned SLAAC assignment.
// It performs no sends, entropy reads, Settings access, counter allocation or
// state mutation. Normal key rotation/Primary refresh does not change Epoch.
// A successful observation is not a BBR/MLR/EID-return-path/native-ready claim.
func (attempt *ThreadAttachAttempt) ObserveAttachment(source ip6.Address) (ThreadAttachmentObservation, error) {
	var observation ThreadAttachmentObservation
	if attempt == nil || attempt.inst == nil || !attempt.done || attempt.attachment == nil {
		return observation, goterrors.ErrInvalidState
	}
	inst, attachment := attempt.inst, attempt.attachment
	inst.runningMu.Lock()
	running := inst.running && !inst.stopping
	inst.runningMu.Unlock()
	if !running || !inst.ifConfigUp || !inst.threadEnabled || inst.ownedAttachment != attachment ||
		inst.threadEpoch != attempt.epoch || attachment.epoch != attempt.epoch {
		return observation, goterrors.ErrInvalidState
	}
	// SecurityError intentionally latches/fences a newly observed provider
	// failure. This read-only API must report that cause without doing either.
	if failure := inst.securityFailure.Load(); failure != nil {
		return observation, failure.cause
	}
	health, ok := inst.entropy.(platform.EntropyHealth)
	if !ok {
		return observation, goterrors.ErrNotCapable
	}
	if err := health.Err(); err != nil {
		return observation, err
	}
	if err := inst.PersistenceError(); err != nil {
		return observation, err
	}
	if err := inst.validateOwnedProfile(); err != nil {
		return observation, err
	}
	if inst.rloc16 != attachment.rloc || uint16(inst.subMac.GetShortAddress()) != attachment.rloc ||
		inst.mac.GetPanChannelSnapshot() != attachment.channel || !inst.hasOwnedRLOCAddress() {
		return observation, goterrors.ErrInvalidState
	}
	proof, err := inst.currentOwnedSource(source)
	if err != nil {
		return observation, err
	}
	return ThreadAttachmentObservation{
		Profile: attachment.profile, Role: inst.mleService.Mle().Role(), Source: source,
		LocalExtAddress: attachment.identity, RLOC16: attachment.rloc,
		ParentExtAddress: attachment.parentExt, ParentRLOC16: attachment.parentRLOC, Epoch: attachment.epoch,
		SourceGeneration: proof.generation,
	}, nil
}
