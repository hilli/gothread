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
// Only direct, valid, rx-on-when-idle neighbors are supported, addressed by
// their canonical EUI-64 link-local address or same-mesh-prefix RLOC.
// Other EIDs, multi-hop/off-mesh routes, multicast, and fragmentation are not
// implemented by this boundary. Unsupported routes return errors.ErrNoRoute.
//
// HopLimit zero defaults to 64; other nonzero values are honored. All other
// MessageInfo options must be zero/nil, otherwise errors.ErrNotCapable is
// returned. Actual compressed/security overhead determines the single-frame
// size limit (errors.ErrNoBufs); zero-length payloads are valid.
//
// Payload and retained metadata are copied before success. Nil means QUEUED,
// not transmitted or received. Later counter/encryption/radio errors remain
// asynchronous: observe Forwarder().GetCounters(), MAC counters, logs, and
// PersistenceError. Do not wait for radio completion on the event loop.
func (inst *Instance) SendUDP(payload []byte, info ip6.MessageInfo) error {
	if err := inst.PersistenceError(); err != nil {
		return err
	}
	inst.runningMu.Lock()
	running := inst.running && !inst.stopping
	inst.runningMu.Unlock()
	if !running || !inst.ifConfigUp || !inst.threadEnabled || inst.forwarder == nil ||
		inst.platRadio == nil || inst.mac == nil || !inst.mac.IsEnabled() || inst.subMac.GetTransmitFrame() == nil {
		return goterrors.ErrInvalidState
	}
	if !inst.forwarder.IsEnabled() {
		return mesh.ErrForwarderDisabled
	}
	if !inst.mleService.Mle().IsAttached() {
		return goterrors.ErrDetached
	}
	if info.SockPort == 0 || info.PeerPort == 0 || info.SockAddr.IsUnspecified() ||
		info.PeerAddr.IsUnspecified() || info.SockAddr.IsMulticast() || info.SockAddr.IsLoopback() ||
		info.PeerAddr.IsLoopback() {
		return goterrors.ErrInvalidArgs
	}
	if info.Ecn != ip6.EcnNotCapable || info.MulticastLoop || info.IsHostInterface ||
		info.AllowZeroHopLimit || info.LinkInfo != nil || info.PeerAddr.IsMulticast() {
		return goterrors.ErrNotCapable
	}
	if !udpUnicastAddress(info.SockAddr) {
		return goterrors.ErrInvalidSourceAddress
	}
	ext := inst.GetExtAddress()
	if ext == (types.ExtAddress{}) || ext.IsGroup() ||
		inst.keyManager.GetCurrentMacKey() == ([16]byte{}) {
		return goterrors.ErrSecurity
	}
	if !inst.hasUDPSource(info.SockAddr) {
		return goterrors.ErrInvalidSourceAddress
	}
	if info.SockAddr.IsLinkLocal() != info.PeerAddr.IsLinkLocal() || inst.hasUDPSource(info.PeerAddr) {
		return goterrors.ErrNoRoute
	}
	neighbor := inst.udpNeighbor(info.PeerAddr)
	if neighbor == nil || !neighbor.Mode.IsRxOnWhenIdle() || neighbor.RLOC16 >= 0xfc00 ||
		neighbor.ExtAddress == (types.ExtAddress{}) ||
		neighbor.ExtAddress.IsGroup() || neighbor.ExtAddress == ext {
		return goterrors.ErrNoRoute
	}
	// Bound copying before building the exact compressed representation.
	if len(payload) > mesh.MaxPsduSize-mesh.FCSSize {
		return goterrors.ErrNoBufs
	}
	msg := inst.newUDPMessage(payload, info)
	msg.MeshDest = neighbor.RLOC16
	// Extended MAC addresses keep nonce identity and elided IPv6 IIDs explicit
	// on this direct-link path without relying on unimplemented next-hop logic.
	msg.Metadata.UseSrcShort = false
	msg.Metadata.UseDstShort = false
	msg.Metadata.DstExtAddr = neighbor.ExtAddress
	if err := mesh.ValidateTxFrame(msg); err != nil {
		return err
	}
	return inst.sendViaForwarder(msg)
}

func udpUnicastAddress(addr ip6.Address) bool {
	prefix := addr.GetPrefix()
	return addr.IsLinkLocalUnicast() || prefix.IsUla() || addr[0]&0xe0 == 0x20
}

func (inst *Instance) hasUDPSource(addr ip6.Address) bool {
	if addr == inst.GetLinkLocalAddress() {
		return true
	}
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
