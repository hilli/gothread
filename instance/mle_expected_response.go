// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"bytes"
	"encoding/binary"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
)

// This is an admission window, not a claim that the protocol retransmits or
// received an ACK. Data and Child Update may each own one pending response.
const ownedMLEResponseWindow = 5 * time.Second

type ownedMLEResponse struct {
	command           mle.Command
	epoch             uint64
	counter, sequence uint32
	until             time.Time
	challenge         []byte
	cancel            func()
	peer              *ownedControlPeer
	peerGeneration    uint64
}

func expectedMLESlot(command mle.Command) int {
	switch command {
	case mle.CommandDataResponse:
		return 0
	case mle.CommandChildUpdateResponse:
		return 1
	default:
		return -1
	}
}

func (inst *Instance) currentExpectedMLE(expected *ownedMLEResponse) bool {
	if expected == nil {
		return false
	}
	if expected.epoch != inst.threadEpoch || inst.ownedAttachment == nil || !inst.threadEnabled ||
		!inst.mleService.Mle().IsChild() || !inst.timers.nowTime().Before(expected.until) {
		return false
	}
	if peer := expected.peer; peer != nil {
		return inst.ownedAttachment.profile == ThreadAttachAwakeFTDChild &&
			inst.ownedPeerByAddress(peer.router.MacAddr) == peer && peer.expected == expected &&
			peer.generation == expected.peerGeneration && peer.awaiting
	}
	slot := expectedMLESlot(expected.command)
	return slot >= 0 && inst.expectedMLE[slot] == expected
}

func (inst *Instance) retireExpectedMLE(expected *ownedMLEResponse) {
	if expected == nil {
		return
	}
	if peer := expected.peer; peer != nil {
		if peer.expected != expected {
			return
		}
		peer.expected = nil
	} else {
		slot := expectedMLESlot(expected.command)
		if slot < 0 || inst.expectedMLE[slot] != expected {
			return
		}
		inst.expectedMLE[slot] = nil
	}
	if expected.cancel != nil {
		expected.cancel()
	}
	if candidate := inst.initialMLEFragment; candidate != nil {
		if candidate.expected == expected {
			inst.retireInitialMLEFragment()
			return
		}
		for _, owned := range candidate.responses {
			if owned == expected {
				inst.retireInitialMLEFragment()
				break
			}
		}
	}
}

func (inst *Instance) armExpectedMLE(command mle.Command, records []mle.TLV) {
	if inst.ownedAttachment == nil {
		return
	}
	var response mle.Command
	switch command {
	case mle.CommandDataRequest:
		response = mle.CommandDataResponse
	case mle.CommandChildUpdateRequest:
		response = mle.CommandChildUpdateResponse
	default:
		return
	}
	parent := inst.mleService.Mle().GetParent()
	expected := &ownedMLEResponse{command: response, epoch: inst.threadEpoch,
		counter: parent.Counters.MleFrameCounter, sequence: parent.KeySequence,
		until: inst.timers.nowTime().Add(ownedMLEResponseWindow)}
	if challenge, ok := mle.FindTLV(records, mle.TLVChallenge); ok {
		expected.challenge = append([]byte(nil), challenge...)
	}
	slot := expectedMLESlot(response)
	inst.retireExpectedMLE(inst.expectedMLE[slot])
	inst.expectedMLE[slot] = expected
	expected.cancel = inst.timers.scheduleWithCancel(ownedMLEResponseWindow, func() { inst.retireExpectedMLE(expected) })
}

func (inst *Instance) expectedMLEEnvelope(packet []byte, size uint16, key mesh.FragmentKey) *ownedMLEResponse {
	attachment := inst.ownedAttachment
	if attachment == nil || inst.validateOwnedProfile() != nil || inst.SecurityError() != nil || inst.PersistenceError() != nil ||
		key.Scope.Secured || key.Scope.Destination != [8]byte(attachment.identity) ||
		key.Scope.PanID != uint16(attachment.pan) || key.Scope.Channel != attachment.channel ||
		len(packet) < 59 || size < 64 || size > mesh.IPv6MTU || packet[0]>>4 != 6 || packet[6] != ip6.ProtoUDP ||
		packet[7] != mle.ControlHopLimit || binary.BigEndian.Uint16(packet[4:6]) != size-40 ||
		binary.BigEndian.Uint16(packet[40:42]) != mle.UDPPort || binary.BigEndian.Uint16(packet[42:44]) != mle.UDPPort ||
		binary.BigEndian.Uint16(packet[44:46]) != size-40 || binary.BigEndian.Uint16(packet[46:48]) == 0 ||
		packet[48] != mle.SecuritySuiteEncMic32 {
		return nil
	}
	var source, destination ip6.Address
	copy(source[:], packet[8:24])
	copy(destination[:], packet[24:40])
	if destination != linkLocalAddress(attachment.identity) {
		return nil
	}
	var security mle.SecurityHeader
	if security.Unmarshal(packet[49:]) != nil || security.KeyIndex != mle.KeyIndexFromSequence(security.KeySource) {
		return nil
	}
	if key.Scope.Source == [8]byte(attachment.parentExt) && source == linkLocalAddress(attachment.parentExt) {
		for _, expected := range inst.expectedMLE {
			if inst.currentExpectedMLE(expected) && security.KeySource == expected.sequence && security.FrameCounter > expected.counter {
				return expected
			}
		}
	}
	if attachment.profile == ThreadAttachAwakeFTDChild {
		for _, peer := range inst.ownedControlPeers {
			if peer != nil && key.Scope.Source == [8]byte(peer.router.MacAddr) && source == linkLocalAddress(peer.router.MacAddr) &&
				inst.currentExpectedMLE(peer.expected) && security.KeySource == peer.expected.sequence && security.FrameCounter > peer.expected.counter {
				return peer.expected
			}
		}
	}
	return nil
}

func (inst *Instance) validateExpectedMLE(info *mle.RxInfo, expected *ownedMLEResponse) error {
	commandMatches := expected != nil && (info.Command == expected.command ||
		expected.peer != nil && info.Command == mle.CommandLinkAcceptAndRequest)
	if !inst.currentExpectedMLE(expected) || !commandMatches || info.KeySequence != expected.sequence ||
		info.FrameCounter <= expected.counter {
		return goterrors.ErrDrop
	}
	if len(expected.challenge) > 0 {
		value, ok := mle.FindTLV(info.TLVs, mle.TLVResponse)
		if !ok || !bytes.Equal(value, expected.challenge) {
			return goterrors.ErrDrop
		}
	}
	return nil
}

func (inst *Instance) admitExpectedMLEFragment(key mesh.FragmentKey, first bool, packet []byte) bool {
	if inst.ownedAttachment == nil || inst.validateOwnedProfile() != nil || inst.SecurityError() != nil || inst.PersistenceError() != nil {
		return false
	}
	if candidate := inst.initialMLEFragment; candidate != nil {
		if !inst.currentExpectedMLE(candidate.expected) || !inst.timers.nowTime().Before(candidate.until) {
			inst.retireInitialMLEFragment()
		} else if candidate.key != key || candidate.complete {
			return false
		}
	}
	if !first {
		return inst.initialMLEFragment != nil && inst.initialMLEFragment.key == key
	}
	expected := inst.expectedMLEEnvelope(packet, key.Size, key)
	if expected == nil {
		if candidate := inst.initialMLEFragment; candidate != nil && candidate.key == key {
			inst.retireInitialMLEFragment()
		}
		return false
	}
	if inst.initialMLEFragment == nil {
		inst.beginMLEFragment(key, inst.threadEpoch, inst.mleService.Mle().GetAttachState(), expected.until, expected)
		inst.initialMLEFragment.responses = inst.expectedMLE
	}
	return true
}
