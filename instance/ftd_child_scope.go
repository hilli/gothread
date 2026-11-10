// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
)

type nativeMLELink struct {
	realmQueryMPL                                  bool
	scope                                          mesh.FragmentScope
	valid, extendedSource, localUnicast, broadcast bool
}

func (inst *Instance) ageOwnedControlPeers() {
	now := inst.timers.nowTime()
	for _, peer := range inst.ownedControlPeers {
		if peer != nil && (!inst.routerTable.IsAllocated(uint8(peer.router.RLOC16>>10)) ||
			now.Sub(peer.lastHeard) >= mle.MaxNeighborAgeOnChild) {
			inst.retireOwnedPeer(peer)
		}
	}
}

// Called only after inner authentication on the owner loop, never under MAC RX.
func (inst *Instance) validateOwnedControlLink(info *mle.RxInfo, unicast bool) error {
	attachment, link := inst.ownedAttachment, inst.activeMLELink
	if attachment == nil || attachment.profile != ThreadAttachAwakeFTDChild || !link.valid || !link.extendedSource ||
		link.scope.Source != [8]byte(info.SrcAddr) || link.scope.PanID != uint16(attachment.pan) ||
		link.scope.Channel != attachment.channel || inst.mac.GetPanChannel() != attachment.channel ||
		inst.GetExtAddress() != attachment.identity || !info.IsSecured ||
		info.SrcIP != linkLocalAddress(info.SrcAddr) {
		return goterrors.ErrDrop
	}
	switch {
	case unicast:
		if !link.localUnicast || info.DstIP != linkLocalAddress(attachment.identity) {
			return goterrors.ErrDrop
		}
	case info.DstIP == ip6.MulticastLinkLocalAllNodes || info.DstIP == inst.GetLinkLocalAllRoutersMulticast():
		if !link.broadcast {
			return goterrors.ErrDrop
		}
	default:
		if !link.localUnicast || info.DstIP != linkLocalAddress(attachment.identity) {
			return goterrors.ErrDrop
		}
	}
	return nil
}
