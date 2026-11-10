// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import "github.com/hilli/gothread/net/ip6"

// Two copied application datagrams, separate from the unchanged reassembly
// pool. Their callbacks run on the owner loop after the MAC RX lock is released.
const maxOwnedSiteReceives = 2

func (owner *ownedSiteGroups) receiveUDP(payload []byte, metadata *ip6.MessageInfo) {
	if owner.stopped || !owner.readyAddress(metadata.SockAddr) || len(payload) > MaxSiteMulticastPayload ||
		owner.pendingRx >= maxOwnedSiteReceives {
		owner.inst.forwarder.RecordReceiveError(false)
		return
	}
	owned, info := append([]byte(nil), payload...), *metadata
	if metadata.LinkInfo != nil {
		link := *metadata.LinkInfo
		info.LinkInfo = &link
	}
	epoch := owner.inst.threadEpoch
	keySequence := owner.inst.keyManager.GetCurrentKeySequence()
	primary := owner.client.primary
	sourceRevision := owner.inst.ownedSourceRevision()
	owner.pendingRx++
	if !owner.inst.postRadioMaintenance(func() {
		owner.pendingRx--
		if owner.stopped || owner.inst.siteGroups != owner || owner.inst.threadEpoch != epoch ||
			owner.inst.keyManager.GetCurrentKeySequence() != keySequence || owner.client.primary != primary ||
			owner.inst.ownedSourceRevision() != sourceRevision ||
			!owner.readyAddress(info.SockAddr) {
			return
		}
		owner.inst.udpManager.HandleMessage(owned, &info)
	}) {
		owner.pendingRx--
		owner.inst.forwarder.RecordReceiveError(false)
	}
}
