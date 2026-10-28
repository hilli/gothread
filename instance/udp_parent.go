// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/submac"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/mle"
)

// This is an immutable admission prerequisite snapshot, not an EID/next-hop
// table. No IPv6 destination is rewritten and no remote reachability is inferred.
type udpParentRoute struct {
	localExt, parentExt   types.ExtAddress
	localRLOC, parentRLOC uint16
	panID                 uint16
	prefix                [8]byte
	networkKey            key.NetworkKey
}

// currentUDPParentRoute can run from Mac's frame-request callback with its mutex
// held. It reads only loop-owned Instance/SubMac/Netif state and MLE getters.
func (inst *Instance) currentUDPParentRoute(info ip6.MessageInfo) (udpParentRoute, error) {
	var snapshot udpParentRoute
	if !inst.ifConfigUp || !inst.threadEnabled || inst.subMac.GetState() == submac.StateDisabled {
		return snapshot, goterrors.ErrInvalidState
	}
	m := inst.mleService.Mle()
	if !m.IsAttached() {
		return snapshot, goterrors.ErrDetached
	}
	if !m.IsChild() || !m.GetDeviceMode().IsMinimalEndDevice() || !inst.subMac.GetRxOnWhenIdle() {
		return snapshot, goterrors.ErrNoRoute
	}
	rloc := m.RLOC16()
	if rloc >= 0xfc00 || rloc&0x0200 != 0 || !mle.IsChildRLOC16(rloc) ||
		inst.rloc16 != rloc || uint16(inst.subMac.GetShortAddress()) != rloc {
		return snapshot, goterrors.ErrNoRoute
	}
	parent := m.GetParent()
	ext := inst.subMac.GetExtAddress()
	if !parent.IsStateValid() || !parent.Mode.IsRxOnWhenIdle() || !parent.Mode.IsFullThreadDevice() ||
		parent.RLOC16 >= 0xfc00 || parent.RLOC16&0x03ff != 0 ||
		parent.RLOC16 != mle.ParentRLOC16ForRLOC16(rloc) ||
		parent.MacAddr == (types.ExtAddress{}) || parent.MacAddr.IsGroup() || parent.MacAddr == ext ||
		inst.subMac.GetPanID() == uint16(types.BroadcastPanID) || inst.meshLocalPrefix == ([8]byte{}) ||
		!ip6.NetworkPrefix(inst.meshLocalPrefix).IsUla() {
		return snapshot, goterrors.ErrNoRoute
	}
	if ext == (types.ExtAddress{}) || ext.IsGroup() {
		return snapshot, goterrors.ErrSecurity
	}
	if !inst.hasNonLinkLocalUDPSource(info.SockAddr) {
		return snapshot, goterrors.ErrInvalidSourceAddress
	}
	// A mesh-local address is not a routable off-mesh source. Netif provides
	// assignment and prefix metadata, not proof of an advertised external route.
	// Require an explicitly assigned non-mesh address for that qualified local
	// handoff and leave actual route/provisioning correctness to its owner.
	if info.PeerAddr.GetPrefix() != ip6.NetworkPrefix(inst.meshLocalPrefix) {
		if !inst.assignedOffMeshUDPSource(info.SockAddr) {
			return snapshot, goterrors.ErrInvalidSourceAddress
		}
	}
	return udpParentRoute{
		localExt: ext, parentExt: parent.MacAddr,
		localRLOC: rloc, parentRLOC: parent.RLOC16,
		panID: inst.subMac.GetPanID(), prefix: inst.meshLocalPrefix,
		networkKey: inst.keyManager.GetNetworkKey(),
	}, nil
}

func (inst *Instance) assignedOffMeshUDPSource(source ip6.Address) bool {
	if inst.netif == nil || source.GetPrefix() == ip6.NetworkPrefix(inst.meshLocalPrefix) || !udpUnicastAddress(source) ||
		source.IsLinkLocal() || source.IsIidReserved() {
		return false
	}
	for _, assigned := range inst.netif.GetUnicastAddresses() {
		if assigned.Address == source && assigned.Valid && !assigned.MeshLocal && !assigned.RLOC &&
			assigned.PrefixLength > 0 && assigned.PrefixLength <= 128 && assigned.GetScope() == ip6.ScopeGlobal {
			return true
		}
	}
	return false
}
