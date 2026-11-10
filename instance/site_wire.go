// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"encoding/binary"

	"github.com/hilli/gothread/checksum"
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// MaxSiteMulticastPayload leaves96 bytes for outer IPv6/MPL and inner IPv6/UDP.
const MaxSiteMulticastPayload = 1184

var realmMplForwarders = ip6.Address{0xff, 0x03, 15: 0xfc}

func nativeUDPSum(packet []byte) checksum.Checksum {
	var sum checksum.Checksum
	sum.AddData(packet[8:40])
	sum.AddUint16(0)
	sum.AddUint16(uint16(len(packet) - 40))
	sum.AddUint16(0)
	sum.AddUint16(uint16(ip6.ProtoUDP))
	sum.AddData(packet[40:])
	return sum
}

func validNativeUDP(packet []byte) bool {
	if len(packet) < 48 || len(packet) > 1280 || packet[0]>>4 != 6 || packet[6] != ip6.ProtoUDP ||
		binary.BigEndian.Uint16(packet[4:6]) != uint16(len(packet)-40) ||
		binary.BigEndian.Uint16(packet[44:46]) != uint16(len(packet)-40) ||
		binary.BigEndian.Uint16(packet[46:48]) == 0 {
		return false
	}
	sum := nativeUDPSum(packet)
	return sum.Value() == 0xffff
}

func encodeSiteTunnel(payload []byte, info ip6.MessageInfo, outerSource ip6.Address, seed uint16, sequence uint8) ([]byte, error) {
	if len(payload) > MaxSiteMulticastPayload {
		return nil, goterrors.ErrNoBufs
	}
	if !supportedSiteGroup(info.PeerAddr) || info.PeerPort != 5540 || info.SockPort == 0 ||
		!udpUnicastAddress(info.SockAddr) || info.SockAddr.IsMulticast() || seed >= 0xfc00 {
		return nil, goterrors.ErrInvalidArgs
	}
	hop := info.HopLimit
	if hop == 0 {
		hop = 64
	}
	innerHeader := ip6.NewHeader(info.SockAddr, info.PeerAddr, ip6.ProtoUDP, hop, uint16(8+len(payload)))
	raw := innerHeader.Bytes()
	inner := make([]byte, 48+len(payload))
	copy(inner, raw[:])
	binary.BigEndian.PutUint16(inner[40:42], info.SockPort)
	binary.BigEndian.PutUint16(inner[42:44], info.PeerPort)
	binary.BigEndian.PutUint16(inner[44:46], uint16(8+len(payload)))
	copy(inner[48:], payload)
	sum := nativeUDPSum(inner)
	binary.BigEndian.PutUint16(inner[46:48], sum.Finalize())
	outerHeader := ip6.NewHeader(outerSource, realmMplForwarders, 0, 64, uint16(8+len(inner)))
	outer := outerHeader.Bytes()
	packet := make([]byte, 48+len(inner))
	copy(packet, outer[:])
	var option ip6.MPLOption
	option.Init(ip6.MPLSeedIDLength2)
	option.SetSeedID(seed)
	option.SetSequence(sequence)
	copy(packet[40:48], []byte{41, 0, option.GetType(), option.GetLength(), byte(option.GetSeedIDLength()), option.GetSequence(), 0, 0})
	binary.BigEndian.PutUint16(packet[46:48], option.GetSeedID())
	copy(packet[48:], inner)
	return packet, nil
}

func decodeSiteTunnel(packet []byte, prefix [8]byte) (inner []byte, seed uint16, sequence uint8, err error) {
	if len(packet) < 96 || len(packet) > 1280 || packet[0]>>4 != 6 || packet[6] != 0 || packet[7] == 0 ||
		binary.BigEndian.Uint16(packet[4:6]) != uint16(len(packet)-40) ||
		packet[40] != 41 || packet[41] != 0 || packet[42] != ip6.MPLOptionType || packet[43] != 4 ||
		packet[44]&0xdf != byte(ip6.MPLSeedIDLength2) {
		return nil, 0, 0, goterrors.ErrParse
	}
	var source, destination ip6.Address
	copy(source[:], packet[8:24])
	copy(destination[:], packet[24:40])
	seed = binary.BigEndian.Uint16(packet[46:48])
	if destination != realmMplForwarders || source.GetPrefix() != ip6.NetworkPrefix(prefix) ||
		!source.IsRoutingLocator() || source.GetIid().GetLocator() != seed || seed >= 0xfc00 {
		return nil, 0, 0, goterrors.ErrNoRoute
	}
	inner = packet[48:]
	if !validNativeUDP(inner) || inner[7] == 0 || binary.BigEndian.Uint16(inner[42:44]) != 5540 {
		return nil, 0, 0, goterrors.ErrParse
	}
	copy(source[:], inner[8:24])
	copy(destination[:], inner[24:40])
	if !udpUnicastAddress(source) || !supportedSiteGroup(destination) {
		return nil, 0, 0, goterrors.ErrParse
	}
	return inner, seed, packet[45], nil
}

func (owner *ownedSiteGroups) readyAddress(address ip6.Address) bool {
	if owner == nil || owner.stopped {
		return false
	}
	proof, err := owner.inst.currentOwnedPrimaryBBR()
	if err != nil || proof != owner.client.primary {
		return false
	}
	for _, entry := range &owner.entries {
		if entry != nil && entry.address == address && entry.refs > 0 && entry.accepted && owner.inst.timers.nowTime().Before(entry.leaseUntil) {
			return true
		}
	}
	return false
}

// SendUDP emits a real MPL/IP-in-IP site datagram via the current parent.
// The original inner tuple is retained;1185 rejects before tags/counters/queue.
func (membership *MulticastMembership) SendUDP(payload []byte, info ip6.MessageInfo) error {
	if len(payload) > MaxSiteMulticastPayload {
		return goterrors.ErrNoBufs
	}
	if membership == nil || !membership.active {
		return goterrors.ErrInvalidState
	}
	owner, entry := membership.owner, membership.entry
	if !owner.readyAddress(entry.address) {
		return goterrors.ErrInvalidState
	}
	inst := owner.inst
	proof, err := inst.currentOwnedPrimaryBBR()
	if err != nil {
		return err
	}
	source, err := inst.currentOwnedSource(info.SockAddr)
	if err != nil {
		return err
	}
	if info.PeerAddr != entry.address || info.LinkInfo != nil ||
		info.Ecn != ip6.EcnNotCapable || info.MulticastLoop || info.IsHostInterface || info.AllowZeroHopLimit {
		return goterrors.ErrNotCapable
	}
	attachment := inst.ownedAttachment
	outerSource := meshLocator(attachment.prefix, attachment.rloc)
	if !inst.hasOwnedRLOCAddress() {
		return goterrors.ErrInvalidSourceAddress
	}
	packet, err := encodeSiteTunnel(payload, info, outerSource, attachment.rloc, owner.mpl.GetSequence())
	if err != nil {
		return err
	}
	message := inst.newUDPMessage(packet[40:], ip6.MessageInfo{SockAddr: outerSource, PeerAddr: realmMplForwarders, HopLimit: 64})
	message.Metadata.NextHeader = 0
	message.Metadata.UseSrcShort, message.Metadata.UseDstShort = false, false
	message.Metadata.DstExtAddr = proof.parentExt
	message.MeshDest = proof.parentRLOC
	message.ValidateFrame = func() error {
		if !membership.active || inst.siteGroups != owner || !owner.readyAddress(entry.address) {
			return goterrors.ErrAbort
		}
		current, err := inst.currentOwnedPrimaryBBR()
		if err != nil {
			return err
		}
		if current != proof {
			return goterrors.ErrNoRoute
		}
		currentSource, err := inst.currentOwnedSource(info.SockAddr)
		if err != nil {
			return err
		}
		if currentSource != source {
			return goterrors.ErrAbort
		}
		return nil
	}
	if err := inst.sendViaForwarder(message); err != nil {
		return err
	}
	owner.mpl.IncrementSequence()
	return nil
}
