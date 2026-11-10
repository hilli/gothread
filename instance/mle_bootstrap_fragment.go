// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"encoding/binary"
	"time"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
)

// Initial ParentResponse and selected-parent ChildIDResponse share ONE
// quarantine in the EXISTING pool. Source/PAN/header alone never authenticates
// an initial candidate or permits ordinary unsecured UDP.
type initialMLEFragment struct {
	key              mesh.FragmentKey
	epoch            uint64
	state            mle.AttachState
	until            time.Time
	complete, queued bool
	cancelExpiry     func()
	expected         *ownedMLEResponse
	responses        [2]*ownedMLEResponse
}

func (inst *Instance) retireInitialMLEFragment() {
	if candidate := inst.initialMLEFragment; candidate != nil {
		inst.initialMLEFragment = nil
		if candidate.cancelExpiry != nil {
			candidate.cancelExpiry()
		}
		if !candidate.complete {
			inst.forwarder.RejectFragment(candidate.key)
		}
	}
}

func (inst *Instance) initialMLEEnvelope(packet []byte, size uint16, key mesh.FragmentKey) bool {
	attempt := inst.threadAttach
	if attempt == nil {
		return inst.expectedMLEEnvelope(packet, size, key) != nil
	}
	if attempt == nil || len(packet) < 48+1+mle.SecurityHeaderSize || size < 48+1+mle.SecurityHeaderSize+1+mle.SecurityTagSize ||
		size > mesh.IPv6MTU || packet[0]>>4 != 6 || packet[6] != ip6.ProtoUDP ||
		packet[7] != mle.ControlHopLimit || binary.BigEndian.Uint16(packet[4:6]) != size-40 ||
		binary.BigEndian.Uint16(packet[40:42]) != mle.UDPPort || binary.BigEndian.Uint16(packet[42:44]) != mle.UDPPort ||
		binary.BigEndian.Uint16(packet[44:46]) != size-40 || binary.BigEndian.Uint16(packet[46:48]) == 0 ||
		packet[48] != mle.SecuritySuiteEncMic32 {
		return false
	}
	var source, destination ip6.Address
	copy(source[:], packet[8:24])
	copy(destination[:], packet[24:40])
	if source != linkLocalAddress(types.ExtAddress(key.Scope.Source)) ||
		destination != linkLocalAddress(attempt.identity) {
		return false
	}
	var security mle.SecurityHeader
	if security.Unmarshal(packet[49:]) != nil ||
		security.KeyIndex != mle.KeyIndexFromSequence(security.KeySource) {
		return false
	}
	switch inst.mleService.Mle().GetAttachState() {
	case mle.AttachStateParentRequest:
		current := inst.keyManager.GetCurrentKeySequence()
		knownSequence := security.KeySource == current || current > 0 && security.KeySource == current-1 ||
			current < ^uint32(0) && security.KeySource == current+1
		if !knownSequence && security.KeySource <= current {
			return false
		}
	case mle.AttachStateChildIDRequest:
		if !attempt.parentAuthenticated || key.Scope.Source != [8]byte(attempt.parentExt) ||
			security.KeySource != attempt.parentSequence || security.FrameCounter <= attempt.parentCounter {
			return false
		}
	default:
		return false
	}
	// This header remains UNAUTHENTICATED quarantine data. No sequence,
	// neighbor, role or address is changed until the full MLE MIC/handler.
	return true
}

func (inst *Instance) admitInitialMLEFragment(key mesh.FragmentKey, first bool, expanded []byte) bool {
	attempt := inst.threadAttach
	if attempt == nil {
		return inst.admitExpectedMLEFragment(key, first, expanded)
	}
	source := types.ExtAddress(key.Scope.Source)
	if attempt == nil || attempt.done || attempt.epoch != inst.threadEpoch ||
		!inst.threadEnabled || !inst.ifConfigUp ||
		key.Scope.Secured || source == (types.ExtAddress{}) || source.IsGroup() || source == attempt.identity ||
		key.Scope.Destination != [8]byte(attempt.identity) ||
		key.Scope.PanID != uint16(attempt.pan) || key.Scope.Channel != attempt.channel ||
		inst.subMac.GetExtAddress() != attempt.identity || inst.subMac.GetPanID() != uint16(attempt.pan) ||
		inst.keyManager.GetNetworkKey() != attempt.networkKey || inst.meshLocalPrefix != attempt.prefix ||
		inst.SecurityError() != nil || inst.PersistenceError() != nil {
		return false
	}
	state := inst.mleService.Mle().GetAttachState()
	if state != mle.AttachStateParentRequest &&
		(state != mle.AttachStateChildIDRequest || !attempt.parentAuthenticated || source != attempt.parentExt) {
		return false
	}
	now := inst.timers.nowTime()
	if candidate := inst.initialMLEFragment; candidate != nil &&
		(candidate.epoch != attempt.epoch || candidate.state != state || !now.Before(candidate.until)) {
		inst.retireInitialMLEFragment()
	}
	if !now.Before(attempt.deadlineAt) {
		return false
	}
	if candidate := inst.initialMLEFragment; candidate != nil && candidate.key.Scope == key.Scope &&
		candidate.key.Tag == key.Tag && candidate.key.Size != key.Size {
		inst.retireInitialMLEFragment()
		return false
	}
	if first {
		if candidate := inst.initialMLEFragment; candidate != nil &&
			(candidate.complete || candidate.key != key && state == mle.AttachStateParentRequest) {
			return false // Never grow/replace an active untrusted candidate.
		}
		if !inst.initialMLEEnvelope(expanded, key.Size, key) {
			if candidate := inst.initialMLEFragment; candidate != nil && candidate.key == key {
				inst.retireInitialMLEFragment()
			}
			return false
		}
		if candidate := inst.initialMLEFragment; candidate != nil && candidate.key != key {
			// A retransmitted first fragment can replace only this same
			// expected-parent control quarantine, never grow a second pool.
			inst.retireInitialMLEFragment()
		}
		if inst.initialMLEFragment == nil {
			until := now.Add(mesh.FragReassemblyTimeoutSec * time.Second)
			if attempt.deadlineAt.Before(until) {
				until = attempt.deadlineAt
			}
			inst.beginMLEFragment(key, attempt.epoch, state, until, nil)
		}
		return true
	}
	// FRAGN before a validated FRAG1 has no owned tuple/header and is dropped.
	return inst.initialMLEFragment != nil && !inst.initialMLEFragment.complete && inst.initialMLEFragment.key == key
}

func (inst *Instance) beginMLEFragment(key mesh.FragmentKey, epoch uint64, state mle.AttachState, until time.Time, expected *ownedMLEResponse) {
	candidate := &initialMLEFragment{key: key, epoch: epoch, state: state, until: until, expected: expected}
	inst.initialMLEFragment = candidate
	candidate.cancelExpiry = inst.timers.scheduleWithCancel(until.Sub(inst.timers.nowTime()), func() {
		if inst.initialMLEFragment == candidate {
			inst.retireInitialMLEFragment()
		}
	})
}
