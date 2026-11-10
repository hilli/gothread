// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"bytes"
	"math/rand/v2"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/routing"
)

// These are MLE CONTROL peers, not new application data routes or routers.
// The parent is separate; the default target remains three total router links.
const maxOwnedControlPeers = 3

type ownedControlPeer struct {
	router                     mle.Router
	epoch                      uint64
	counterFloor               uint32
	sequence                   uint32
	generation                 uint64
	admitting, awaiting        bool
	cancelSend, cancelDeadline func()
	lastHeard                  time.Time
	attempts                   uint8
	expected                   *ownedMLEResponse
}

func (inst *Instance) ownedPeerByRLOC(rloc uint16) *ownedControlPeer {
	for _, peer := range inst.ownedControlPeers {
		if peer != nil && peer.epoch == inst.threadEpoch && peer.router.RLOC16 == rloc {
			return peer
		}
	}
	return nil
}

func (inst *Instance) ownedPeerByAddress(address types.ExtAddress) *ownedControlPeer {
	for _, peer := range inst.ownedControlPeers {
		if peer != nil && peer.epoch == inst.threadEpoch && peer.router.MacAddr == address {
			return peer
		}
	}
	return nil
}

func (inst *Instance) retireOwnedPeer(peer *ownedControlPeer) {
	if peer.cancelSend != nil {
		peer.cancelSend()
	}
	if peer.cancelDeadline != nil {
		peer.cancelDeadline()
	}
	inst.retireExpectedMLE(peer.expected)
	peer.generation++
	peer.awaiting, peer.admitting = false, false
	if router := inst.routerTable.FindRouterByRLOC16(peer.router.RLOC16); router != nil && router.ExtAddress == peer.router.MacAddr {
		router.State = routing.StateInvalid
	}
	for i, current := range inst.ownedControlPeers {
		if current == peer {
			inst.ownedControlPeers[i] = nil
		}
	}
}

func (inst *Instance) releaseOwnedControlPeers() {
	for _, peer := range inst.ownedControlPeers {
		if peer != nil {
			inst.retireOwnedPeer(peer)
		}
	}
}

func (inst *Instance) syncOwnedPeer(peer *ownedControlPeer) error {
	target := inst.routerTable.FindRouterByRLOC16(peer.router.RLOC16)
	if target == nil {
		return goterrors.ErrNoRoute
	}
	source := &peer.router
	target.ExtAddress, target.RLOC16 = source.MacAddr, source.RLOC16
	target.State, target.Mode = routing.State(source.State), source.Mode
	target.Version, target.KeySequence = source.Version, source.KeySequence
	target.LinkFrameCounter, target.MleFrameCounter = source.Counters.LinkFrameCounter, source.Counters.MleFrameCounter
	target.Challenge = [8]byte(source.PendingChallenge)
	target.LinkInfo = source.LinkInfo
	target.LastHeard = uint32(time.Now().UnixMilli())
	target.LinkQualityOut = source.LinkQualityOut
	return nil
}

func (inst *Instance) syncOwnedParentRouter() error {
	attachment := inst.ownedAttachment
	if attachment == nil || attachment.profile != ThreadAttachAwakeFTDChild {
		return nil
	}
	router := inst.routerTable.FindRouterByRLOC16(attachment.parentRLOC)
	if router == nil {
		var err error
		router, err = inst.routerTable.AllocateWithID(uint8(attachment.parentRLOC >> 10))
		if err != nil {
			return err
		}
	}
	parent := inst.mleService.Mle().GetParent()
	router.ExtAddress, router.RLOC16 = parent.MacAddr, parent.RLOC16
	router.State, router.Mode = routing.StateValid, parent.Mode
	router.Version, router.KeySequence = parent.Version, parent.KeySequence
	router.MleFrameCounter, router.LinkFrameCounter = parent.Counters.MleFrameCounter, parent.Counters.LinkFrameCounter
	router.LinkInfo = parent.LinkInfo
	router.LastHeard = uint32(time.Now().UnixMilli())
	return nil
}

func (inst *Instance) scheduleOwnedPeer(peer *ownedControlPeer) {
	if peer.awaiting || peer.admitting || peer.cancelSend != nil || peer.router.IsStateValid() {
		return
	}
	peer.generation++
	generation, epoch := peer.generation, inst.threadEpoch
	delay := mle.MinLinkRequestDelayOnChild
	if span := mle.MaxLinkRequestDelayOnChild - delay; span > 0 {
		delay += time.Duration(rand.Int64N(int64(span)))
	}
	peer.cancelSend = inst.timers.scheduleWithCancel(delay, func() {
		peer.cancelSend = nil
		if peer.epoch != epoch || peer.generation != generation || inst.ownedPeerByRLOC(peer.router.RLOC16) != peer {
			return
		}
		if err := inst.validateOwnedProfile(); err != nil {
			inst.retireOwnedPeer(peer)
			return
		}
		if err := inst.SecurityError(); err != nil {
			inst.retireOwnedPeer(peer)
			return
		}
		if !inst.routerTable.IsAllocated(uint8(peer.router.RLOC16>>10)) ||
			inst.timers.nowTime().Sub(peer.lastHeard) > mle.MaxNeighborAgeOnChild {
			inst.retireOwnedPeer(peer)
			return
		}
		peer.admitting = true
		_, err := mle.SendLinkRequest(inst.mleService.Mle(), inst.mleService.Dispatcher(), inst, &peer.router)
		peer.admitting = false
		if err != nil {
			inst.logOwnedControlError(err)
			inst.retireOwnedPeer(peer)
			return
		}
		peer.awaiting = true
		peer.attempts++
		peer.router.State = mle.StateLinkRequest
		peer.cancelDeadline = inst.timers.scheduleWithCancel(mle.LinkRequestTimeout, func() {
			if peer.generation == generation && peer.awaiting && inst.ownedPeerByRLOC(peer.router.RLOC16) == peer {
				inst.logOwnedControlError(goterrors.ErrResponseTimeout)
				peer.awaiting = false
				inst.retireExpectedMLE(peer.expected)
				if peer.attempts < mle.LinkRequestAttempts {
					peer.router.State = mle.StateInvalid
					inst.scheduleOwnedPeer(peer)
				} else {
					inst.retireOwnedPeer(peer)
				}
			}

		})
	})
}

func (inst *Instance) logOwnedControlError(err error) {
	if inst.logger != nil {
		inst.logger.Log(platform.LogLevelWarn, platform.LogRegionMLE, "FTD child control: "+err.Error())
	}
}

func (inst *Instance) wireOwnedChildControlHandlers() {
	dispatcher := inst.mleService.Dispatcher()
	dispatcher.RegisterHandler(mle.CommandAdvertisement, func(info *mle.RxInfo) error {
		attachment := inst.ownedAttachment
		if attachment == nil || attachment.profile != ThreadAttachAwakeFTDChild {
			return inst.mleService.AdvertisementHandler.HandleAdvertisement(info)
		}
		if err := inst.validateOwnedProfile(); err != nil {
			return err
		}
		if err := inst.validateOwnedControlLink(info, false); err != nil {
			return err
		}
		if !info.IsSecured || info.SrcAddr == (types.ExtAddress{}) || info.SrcAddr.IsGroup() ||
			info.SrcIP != linkLocalAddress(info.SrcAddr) {
			return goterrors.ErrDrop
		}
		value, ok := mle.FindTLV(info.TLVs, mle.TLVSourceAddress)
		rloc, err := mle.ReadSourceAddressTLV(value)
		if !ok || err != nil || rloc >= 0xfc00 || rloc&0x03ff != 0 {
			return goterrors.ErrParse
		}
		value, ok = mle.FindTLV(info.TLVs, mle.TLVLeaderData)
		leader, err := mle.ReadLeaderDataTLV(value)
		current := inst.mleService.Mle().GetLeaderData()
		if !ok || err != nil || leader.PartitionID != current.PartitionID || leader.LeaderRouterID != current.LeaderRouterID {
			return goterrors.ErrDrop
		}
		route, hasRoute := mle.FindTLV(info.TLVs, mle.TLVRoute64)
		if hasRoute {
			if err := validateOwnedChildRoute(route, rloc); err != nil {
				return err
			}
		}
		if info.SrcAddr == attachment.parentExt {
			if rloc != attachment.parentRLOC {
				return goterrors.ErrDrop
			}
			return inst.mleService.AdvertisementHandler.HandleAdvertisement(info)
		}
		if !hasRoute || !inst.routerTable.IsAllocated(uint8(rloc>>10)) || rloc == attachment.parentRLOC || info.LinkMarginRaw < mle.LinkRequestMinMargin {
			return goterrors.ErrDrop
		}
		target := int(inst.mleService.Mle().GetChildRouterLinks())
		if target < 1 || target > maxOwnedControlPeers+1 {
			return goterrors.ErrNotCapable
		}
		established := 1 // Actual authenticated current parent.
		for _, peer := range inst.ownedControlPeers {
			if peer != nil {
				established++
			}
		}
		peer := inst.ownedPeerByRLOC(rloc)
		if peer != nil {
			if peer.router.MacAddr != info.SrcAddr {
				return goterrors.ErrDrop
			}
			if info.KeySequence < peer.sequence || info.KeySequence == peer.sequence && info.FrameCounter <= peer.counterFloor {
				return goterrors.ErrDrop
			}
			if peer.awaiting && info.KeySequence != peer.sequence {
				inst.retireOwnedPeer(peer)
				return goterrors.ErrDrop
			}
			peer.counterFloor, peer.sequence = info.FrameCounter, info.KeySequence
			if peer.expected != nil {
				peer.expected.counter = info.FrameCounter
			}
			peer.lastHeard = inst.timers.nowTime()
			inst.scheduleOwnedPeer(peer)
			return nil
		}
		if established >= target {
			return nil
		}
		slot := -1
		for i, entry := range inst.ownedControlPeers {
			if entry == nil {
				slot = i
				break
			}
		}
		if slot < 0 {
			return goterrors.ErrNoBufs
		}
		// Only the authenticated same-partition advertisement supplies identity.
		peer = &ownedControlPeer{epoch: inst.threadEpoch, counterFloor: info.FrameCounter, sequence: info.KeySequence, lastHeard: inst.timers.nowTime()}
		peer.router.Counters.MleFrameCounter = info.FrameCounter
		peer.router.KeySequence = info.KeySequence
		peer.router.MacAddr, peer.router.RLOC16 = info.SrcAddr, rloc
		peer.router.State = mle.StateInvalid
		peer.router.Mode = mle.NewDeviceMode(mle.ModeRxOnWhenIdle | mle.ModeFullThreadDevice | mle.ModeFullNetworkData)
		inst.ownedControlPeers[slot] = peer
		inst.scheduleOwnedPeer(peer)
		return nil
	})
	for _, entry := range []struct {
		command    mle.Command
		andRequest bool
	}{
		{mle.CommandLinkAccept, false}, {mle.CommandLinkAcceptAndRequest, true},
	} {
		andRequest := entry.andRequest
		dispatcher.RegisterHandler(entry.command, func(info *mle.RxInfo) error {
			attachment := inst.ownedAttachment
			if attachment == nil || attachment.profile != ThreadAttachAwakeFTDChild {
				if andRequest {
					return inst.mleService.LinkHandlers.HandleLinkAcceptAndRequest(info)
				}
				return inst.mleService.LinkHandlers.HandleLinkAccept(info)
			}
			if err := inst.validateOwnedProfile(); err != nil {
				return err
			}
			if err := inst.validateOwnedControlLink(info, true); err != nil {
				return err
			}
			peer := inst.ownedPeerByAddress(info.SrcAddr)
			if peer == nil || !inst.currentExpectedMLE(peer.expected) || !info.IsSecured || info.SrcIP != linkLocalAddress(peer.router.MacAddr) ||
				info.DstIP != inst.GetLinkLocalAddress() || info.KeySequence != peer.sequence || info.FrameCounter <= peer.counterFloor {
				return goterrors.ErrDrop
			}
			response, ok := mle.FindTLV(info.TLVs, mle.TLVResponse)
			if !ok || !bytes.Equal(response, peer.router.PendingChallenge[:]) {
				return goterrors.ErrDrop
			}
			if value, ok := mle.FindTLV(info.TLVs, mle.TLVSourceAddress); !ok {
				return goterrors.ErrParse
			} else if rloc, err := mle.ReadSourceAddressTLV(value); err != nil || rloc != peer.router.RLOC16 {
				return goterrors.ErrDrop
			}
			if value, ok := mle.FindTLV(info.TLVs, mle.TLVLeaderData); ok {
				leader, err := mle.ReadLeaderDataTLV(value)
				current := inst.mleService.Mle().GetLeaderData()
				if err != nil || leader.PartitionID != current.PartitionID || leader.LeaderRouterID != current.LeaderRouterID {
					return goterrors.ErrDrop
				}
			}
			if route, ok := mle.FindTLV(info.TLVs, mle.TLVRoute64); ok {
				if err := validateOwnedChildRoute(route, peer.router.RLOC16); err != nil {
					return err
				}
			}
			var err error
			if andRequest {
				err = inst.mleService.LinkHandlers.HandleChildLinkAcceptAndRequest(info)
			} else {
				err = inst.mleService.LinkHandlers.HandleChildLinkAccept(info)
			}
			if err != nil {
				inst.retireOwnedPeer(peer)
				return err
			}
			peer.awaiting = false
			inst.retireExpectedMLE(peer.expected)
			peer.lastHeard = inst.timers.nowTime()
			if peer.cancelDeadline != nil {
				peer.cancelDeadline()
				peer.cancelDeadline = nil
			}
			if peer.router.Counters.MleFrameCounter < info.FrameCounter {
				peer.router.Counters.MleFrameCounter = info.FrameCounter
			}
			return inst.syncOwnedPeer(peer)
		})
	}
}
