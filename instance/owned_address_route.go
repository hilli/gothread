// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/tmf"
)

type ownedAddressProof struct {
	attachment                    *ownedThreadAttachment
	epoch                         uint64
	target, meshEID, source, peer ip6.Address
	parentExt                     [8]byte
	parentRLOC                    uint16
	keySequence                   uint32
	dataVersion                   uint8
	targetSource                  ownedSourceProof
}

func (inst *Instance) currentOwnedAddressProof(target, peer ip6.Address) (ownedAddressProof, error) {
	var proof ownedAddressProof
	attachment := inst.ownedAttachment
	if attachment == nil || attachment.profile != ThreadAttachAwakeFTDChild {
		return proof, goterrors.ErrNotCapable
	}
	if err := inst.validateOwnedProfile(); err != nil {
		return proof, err
	}
	if err := inst.SecurityError(); err != nil {
		return proof, err
	}
	if err := inst.PersistenceError(); err != nil {
		return proof, err
	}
	if !inst.ifConfigUp || !inst.threadEnabled || !inst.hasOwnedRLOCAddress() ||
		inst.mac.GetPanChannelSnapshot() != attachment.channel {
		return proof, goterrors.ErrInvalidState
	}
	if target.IsIidReserved() || !udpUnicastAddress(target) || target.IsLinkLocal() ||
		peer.GetPrefix() != ip6.NetworkPrefix(attachment.prefix) || !peer.IsRoutingLocator() {
		return proof, goterrors.ErrInvalidArgs
	}
	peerRLOC := peer.GetIid().GetLocator()
	if peerRLOC >= 0xfc00 || peerRLOC == attachment.rloc ||
		!mle.IsRouterRLOC16(peerRLOC) && (!mle.IsChildRLOC16(peerRLOC) || peerRLOC&0x0200 != 0) {
		return proof, goterrors.ErrNoRoute
	}
	originRouter := peerRLOC & 0xfc00
	if originRouter != attachment.parentRLOC {
		route := inst.routerTable.FindRouterByRLOC16(originRouter)
		if route == nil || route.Cost == 0 || uint16(route.NextHop) != attachment.parentRLOC>>10 {
			return proof, goterrors.ErrNoRoute
		}
	}
	targetSource, err := inst.currentOwnedSource(target)
	if err != nil {
		return proof, err
	}
	proof.targetSource = targetSource
	for _, selected := range attachment.addresses {
		if selected.IsIidReserved() || !inst.hasNonLinkLocalUDPSource(selected) {
			continue
		}
		if proof.meshEID.IsUnspecified() && selected.GetPrefix() == ip6.NetworkPrefix(attachment.prefix) {
			proof.meshEID = selected
		}
	}
	if proof.meshEID.IsUnspecified() {
		return proof, goterrors.ErrInvalidSourceAddress
	}
	proof.attachment, proof.epoch = attachment, inst.threadEpoch
	proof.target, proof.peer = target, peer
	proof.source = meshLocator(attachment.prefix, attachment.rloc)
	proof.parentExt, proof.parentRLOC = [8]byte(attachment.parentExt), attachment.parentRLOC
	proof.keySequence = inst.keyManager.GetCurrentKeySequence()
	proof.dataVersion = attachment.networkDataVersion
	return proof, nil
}

func (inst *Instance) sendOwnedAddressNotification(data []byte, proof *ownedAddressProof) error {
	expected := *proof
	current, err := inst.currentOwnedAddressProof(expected.target, expected.peer)
	if err != nil {
		return err
	}
	if current != expected {
		return goterrors.ErrAbort
	}
	if len(data) > 260 {
		return goterrors.ErrNoBufs
	}
	message := inst.newUDPMessage(data, ip6.MessageInfo{SockAddr: expected.source, PeerAddr: expected.peer,
		SockPort: tmf.Port, PeerPort: tmf.Port, HopLimit: 64})
	message.MeshDest = expected.parentRLOC
	message.Metadata.UseSrcShort, message.Metadata.UseDstShort = false, false
	message.Metadata.DstExtAddr = expected.parentExt
	message.ValidateFrame = func() error {
		current, err := inst.currentOwnedAddressProof(expected.target, expected.peer)
		if err != nil {
			return err
		}
		if current != expected {
			return goterrors.ErrAbort
		}
		return nil
	}
	return inst.sendViaForwarder(message)
}
