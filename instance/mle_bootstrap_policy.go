// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/mle"
)

func (inst *Instance) allowOwnedInitialKeyCandidate(source types.ExtAddress, sourceIP, destinationIP ip6.Address, sequence uint32) bool {
	attempt := inst.threadAttach
	return attempt != nil && !attempt.done && attempt.epoch == inst.threadEpoch && inst.threadEnabled &&
		inst.mleService.Mle().GetAttachState() == mle.AttachStateParentRequest &&
		sequence > inst.keyManager.GetCurrentKeySequence() && inst.SecurityError() == nil && inst.PersistenceError() == nil &&
		inst.keyManager.GetNetworkKey() == attempt.networkKey && inst.meshLocalPrefix == attempt.prefix &&
		inst.GetExtAddress() == attempt.identity && inst.mac.GetPanID() == attempt.pan && inst.mac.GetPanChannel() == attempt.channel &&
		source != (types.ExtAddress{}) && !source.IsGroup() && source != attempt.identity &&
		sourceIP == linkLocalAddress(source) && destinationIP == inst.GetLinkLocalAddress()
}

func (inst *Instance) validateOwnedAttachMessage(info *mle.RxInfo) error {
	attempt := inst.threadAttach
	if attempt == nil {
		if attachment := inst.ownedAttachment; attachment != nil {
			if !info.IsSecured && !ownedStatelessDiscovery(info) {
				return goterrors.ErrDrop
			}
			if attachment.profile == ThreadAttachAwakeFTDChild {
				if peer := inst.ownedPeerByAddress(info.SrcAddr); peer != nil {
					if err := inst.validateOwnedControlLink(info, info.Command != mle.CommandAdvertisement); err != nil {
						return err
					}
					info.Neighbor = &peer.router.Neighbor
				}
			}
		}
		if candidate := inst.activeMLEFragment; candidate != nil && candidate.expected != nil {
			if candidate.expected.peer != nil {
				return inst.validateExpectedMLE(info, candidate.expected)
			}
			slot := expectedMLESlot(info.Command)
			if slot < 0 {
				return goterrors.ErrDrop
			}
			return inst.validateExpectedMLE(info, candidate.responses[slot])
		}
		return nil
	}
	if attempt.done || attempt.epoch != inst.threadEpoch || !inst.threadEnabled || !info.IsSecured ||
		info.SrcAddr == (types.ExtAddress{}) || info.SrcAddr.IsGroup() || info.SrcAddr == attempt.identity ||
		info.SrcIP != linkLocalAddress(info.SrcAddr) || info.DstIP != linkLocalAddress(attempt.identity) {
		return goterrors.ErrDrop
	}
	switch inst.mleService.Mle().GetAttachState() {
	case mle.AttachStateParentRequest:
		if info.Command != mle.CommandParentResponse {
			return goterrors.ErrDrop
		}
	case mle.AttachStateChildIDRequest:
		if info.Command != mle.CommandChildIDResponse || !attempt.parentAuthenticated || info.SrcAddr != attempt.parentExt ||
			info.KeySequence != attempt.parentSequence || info.FrameCounter <= attempt.parentCounter {
			return goterrors.ErrDrop
		}
	default:
		return goterrors.ErrDrop
	}
	return nil
}
