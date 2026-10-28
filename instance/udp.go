// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/routing"
)

// SendUDP accepts a datagram into the bounded, secured outbound forwarding
// queue and requests MAC work. It is LOOP-ONLY; external callers use
// inst.Do(ctx, func() error { return inst.SendUDP(payload, info) }).
// It never dispatches to local UDP receivers.
//
// The interface and Thread must be up and attached, with a usable radio and
// network key. The source must be explicitly assigned; both ports are nonzero.
// Direct valid awake neighbors use canonical EUI-64 link-local or same-prefix
// RLOC addresses. An attached always-on MTD child can additionally hand
// supported non-link-local unicast to its established awake router parent.
// This selects only the MAC next hop, preserving the final IPv6 tuple; it is
// not proof that the parent can subsequently route the packet. Off-mesh final
// peers require an explicitly assigned non-mesh source whose routability the
// caller has verified. FTD/general routing, sleepy delivery, multicast and
// discovery remain unsupported by this fallback (errors.ErrNoRoute/NotCapable).
//
// HopLimit zero defaults to 64; other nonzero values are honored. All other
// MessageInfo options must be zero/nil, otherwise errors.ErrNotCapable is
// returned. UDP payload is at most 1232 bytes (IPv6 MTU 1280). Standard
// RFC 4944/6282 fragmentation is owned by the shared forwarder; empty payloads
// remain valid and small datagrams remain unfragmented.
//
// Payload and retained metadata are copied before success. Nil means QUEUED,
// not transmitted or received. Later counter/encryption/radio errors remain
// asynchronous: observe Forwarder().GetCounters(), MAC counters, logs, and
// PersistenceError. Do not wait for radio completion on the event loop.
// Changed parent/role/address prerequisites retire a parent-handoff datagram
// before its next frame/counter or delayed radio attempt rather than retargeting
// its accepted tuple. A frame already handed to a radio cannot be retracted.
func (inst *Instance) SendUDP(payload []byte, info ip6.MessageInfo) error {
	msg, err := inst.prepareUDPMessage(payload, info)
	if err != nil {
		return err
	}
	// Forwarder owns the single transactional preparation/admission step.
	return inst.sendViaForwarder(msg)
}

// prepareUDPMessage qualifies the exact tuple/route without submitting frames
// or reserving counters. The SRP binding uses it before socket/key side effects.
func (inst *Instance) prepareUDPMessage(payload []byte, info ip6.MessageInfo) (*mesh.TxMessage, error) {
	if err := inst.PersistenceError(); err != nil {
		return nil, err
	}
	inst.runningMu.Lock()
	running := inst.running && !inst.stopping
	inst.runningMu.Unlock()
	if !running || !inst.ifConfigUp || !inst.threadEnabled || inst.forwarder == nil ||
		inst.platRadio == nil || inst.mac == nil || !inst.mac.IsEnabled() || inst.subMac.GetTransmitFrame() == nil {
		return nil, goterrors.ErrInvalidState
	}
	if !inst.forwarder.IsEnabled() {
		return nil, mesh.ErrForwarderDisabled
	}
	if !inst.mleService.Mle().IsAttached() {
		return nil, goterrors.ErrDetached
	}
	if info.SockPort == 0 || info.PeerPort == 0 || info.SockAddr.IsUnspecified() ||
		info.PeerAddr.IsUnspecified() || info.SockAddr.IsMulticast() || info.SockAddr.IsLoopback() ||
		info.PeerAddr.IsLoopback() {
		return nil, goterrors.ErrInvalidArgs
	}
	if info.Ecn != ip6.EcnNotCapable || info.MulticastLoop || info.IsHostInterface ||
		info.AllowZeroHopLimit || info.LinkInfo != nil || info.PeerAddr.IsMulticast() {
		return nil, goterrors.ErrNotCapable
	}
	if !udpUnicastAddress(info.SockAddr) {
		return nil, goterrors.ErrInvalidSourceAddress
	}
	ext := inst.GetExtAddress()
	if ext == (types.ExtAddress{}) || ext.IsGroup() ||
		inst.keyManager.GetCurrentMacKey() == ([16]byte{}) {
		return nil, goterrors.ErrSecurity
	}
	if !inst.hasUDPSource(info.SockAddr) {
		return nil, goterrors.ErrInvalidSourceAddress
	}
	if info.SockAddr.IsLinkLocal() != info.PeerAddr.IsLinkLocal() || inst.hasUDPSource(info.PeerAddr) {
		return nil, goterrors.ErrNoRoute
	}
	neighbor := inst.udpNeighbor(info.PeerAddr)
	var parentRoute *udpParentRoute
	if neighbor == nil && !info.PeerAddr.IsLinkLocal() {
		if !udpUnicastAddress(info.PeerAddr) || info.PeerAddr.IsIidReserved() {
			return nil, goterrors.ErrNoRoute
		}
		parent, err := inst.currentUDPParentRoute(info)
		if err != nil {
			return nil, err
		}
		parentRoute = &parent
		neighbor = &routing.Neighbor{ExtAddress: parent.parentExt, RLOC16: parent.parentRLOC, Mode: inst.mleService.Mle().GetParent().Mode}
	}
	if neighbor == nil || !neighbor.Mode.IsRxOnWhenIdle() || neighbor.RLOC16 >= 0xfc00 ||
		neighbor.ExtAddress == (types.ExtAddress{}) ||
		neighbor.ExtAddress.IsGroup() || neighbor.ExtAddress == ext {
		return nil, goterrors.ErrNoRoute
	}
	if len(payload) > mesh.IPv6MTU-ip6.HeaderSize-ip6.UDPHeaderSize {
		return nil, goterrors.ErrNoBufs
	}
	msg := inst.newUDPMessage(payload, info)
	msg.MeshDest = neighbor.RLOC16
	// Extended MAC addresses keep nonce identity and elided IPv6 IIDs explicit
	// on this direct-link path without relying on unimplemented next-hop logic.
	msg.Metadata.UseSrcShort = false
	msg.Metadata.UseDstShort = false
	msg.Metadata.DstExtAddr = neighbor.ExtAddress
	if parentRoute != nil {
		if parentRoute.localExt != ext || parentRoute.panID != msg.Metadata.PanId {
			return nil, goterrors.ErrInvalidState
		}
		// Preserve the final IPv6 tuple; only the MAC next hop is the parent.
		snapshot := *parentRoute
		msg.ValidateFrame = func() error {
			current, err := inst.currentUDPParentRoute(info)
			if err != nil {
				return err
			}
			if current != snapshot {
				return goterrors.ErrNoRoute
			}
			return nil
		}
	}
	return msg, nil
}

func udpUnicastAddress(addr ip6.Address) bool {
	prefix := addr.GetPrefix()
	return addr.IsLinkLocalUnicast() || prefix.IsUla() || addr[0]&0xe0 == 0x20
}

func (inst *Instance) hasUDPSource(addr ip6.Address) bool {
	if addr == inst.GetLinkLocalAddress() {
		return true
	}
	return inst.hasNonLinkLocalUDPSource(addr)
}

func (inst *Instance) hasNonLinkLocalUDPSource(addr ip6.Address) bool {
	if inst.meshLocalPrefix != ([8]byte{}) && inst.rloc16 != mle.InvalidRLOC16 &&
		inst.rloc16 == inst.mleService.Mle().RLOC16() && addr == inst.GetMeshLocalAddress() {
		return true
	}
	if inst.netif != nil {
		for _, assigned := range inst.netif.GetUnicastAddresses() {
			if assigned.Valid && assigned.Address == addr && !addr.IsIidReserved() {
				return true
			}
		}
	}
	return false
}

func (inst *Instance) udpNeighbor(addr ip6.Address) *routing.Neighbor {
	var neighbor *routing.Neighbor
	m := inst.mleService.Mle()
	parent := m.GetParent()
	switch {
	case addr.IsLinkLocal():
		ext := types.ExtAddress(addr.GetIid())
		ext.ToggleLocal()
		if addr != linkLocalAddress(ext) {
			return nil
		}
		neighbor = inst.neighborTable.FindNeighborByExtAddress(ext, routing.FilterValid)
		if neighbor == nil && m.IsChild() && parent.IsStateValid() && parent.MacAddr == ext {
			return &routing.Neighbor{ExtAddress: parent.MacAddr, RLOC16: parent.RLOC16, Mode: parent.Mode}
		}
	case inst.meshLocalPrefix != ([8]byte{}) && addr.GetPrefix() == ip6.NetworkPrefix(inst.meshLocalPrefix) && addr.IsRoutingLocator():
		iid := addr.GetIid()
		rloc := iid.GetLocator()
		neighbor = inst.neighborTable.FindNeighborByShortAddress(rloc, routing.FilterValid)
		if neighbor == nil && m.IsChild() && parent.IsStateValid() && parent.RLOC16 == rloc {
			return &routing.Neighbor{ExtAddress: parent.MacAddr, RLOC16: parent.RLOC16, Mode: parent.Mode}
		}
	}
	return neighbor
}

func linkLocalAddress(ext types.ExtAddress) ip6.Address {
	addr := ip6.Address{0xfe, 0x80}
	copy(addr[8:], ext[:])
	addr[8] ^= 0x02
	return addr
}
