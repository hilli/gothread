// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"encoding/binary"

	goterrors "github.com/hilli/gothread/errors"
	macframe "github.com/hilli/gothread/mac/frame"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/lowpan"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
)

// Discovery RX is a purpose-bound stateless catalogue path. It never feeds
// discovered data into parent/key/dataset/role/address processing.
func (inst *Instance) receiveDiscoveryFrame(frame *radio.Frame, receiveErr error) bool {
	if inst.discoveryCleanupOnly {
		return true
	} // Stopped cleanup cannot admit ordinary RX callbacks.
	owner := inst.nativeDiscovery
	if owner == nil || owner.lease == nil {
		return false
	}
	if owner.restoring || owner.terminal {
		return true
	}
	if receiveErr != nil {
		inst.discoveryScanner.Fail(owner.id, receiveErr)
		return true
	}
	if frame == nil || len(frame.PSDU) > radio.FrameMaxSize-radio.FrameFCSSize {
		return false
	}
	headerFrame := macframe.NewFrame(frame.PSDU)
	if headerFrame.GetType() != macframe.TypeData {
		return false
	}
	context, offset, err := mesh.NewFramer().ParseFrameHeader(frame.PSDU)
	if err != nil || context.SecurityEnabled || offset >= len(frame.PSDU) {
		return false
	}
	addresses := lowpan.AddressContext{SrcExtAddr: context.SrcExtAddr, DstExtAddr: context.DstExtAddr,
		SrcShort: types.ShortAddress(context.SrcShortAddr), DstShort: types.ShortAddress(context.DstShortAddr),
		SrcShortValid: context.UseSrcShort, DstShortValid: context.UseDstShort}
	payload := frame.PSDU[offset:]
	if lowpan.IsFragment(payload) {
		header, count, err := lowpan.ParseFragmentHeader(payload)
		if err == nil && header.IsFirst {
			partial, err := lowpan.DecompressDatagram(payload[count:], addresses, header.DatagramSize)
			if err == nil && discoveryResponsePacket(partial) {
				if uint16(frame.Channel) != owner.channel {
					return true
				}
				inst.discoveryScanner.Fail(owner.id, goterrors.ErrNotCapable)
				return true // No new unsecured fragment/reassembly exception.
			}
		}
		return false
	}
	packet, err := lowpan.DecompressDatagram(payload, addresses, 0)
	if err != nil || !discoveryResponsePacket(packet) {
		return false
	}
	// Identified discovery rejected by the live channel owner is consumed,
	// never re-entered through metadata-free ordinary MLE delivery.
	if uint16(frame.Channel) != owner.channel {
		return true
	}
	if err := owner.validate(); err != nil {
		inst.discoveryScanner.Fail(owner.id, err)
		return true
	}
	var source, destination ip6.Address
	copy(source[:], packet[8:24])
	copy(destination[:], packet[24:40])
	local := linkLocalAddress(owner.identity)
	if context.UseSrcShort || context.SrcExtAddr == ([8]byte{}) || context.SrcExtAddr[0]&1 != 0 ||
		source != linkLocalAddress(types.ExtAddress(context.SrcExtAddr)) ||
		(destination != local && destination != mle.LinkLocalAllNodesMulticast) ||
		packet[7] != mle.ControlHopLimit || !validNativeUDP(packet) || frame.RxInfo == nil ||
		(!context.UseDstShort && context.DstExtAddr != [8]byte(owner.identity)) ||
		(context.UseDstShort && context.DstShortAddr != 0xffff) {
		inst.discoveryScanner.Fail(owner.id, goterrors.ErrParse)
		return true
	}
	macPacket := macframe.NewFrame(frame.PSDU)
	pan, err := macPacket.GetSrcPanID()
	if err != nil {
		if len(frame.PSDU) < 2 || frame.PSDU[0]&0x40 == 0 {
			inst.discoveryScanner.Fail(owner.id, err)
			return true
		}
		pan = types.PanID(context.PanId)
	}
	if uint16(pan) == 0xffff || owner.pan != 0xffff && owner.pan != uint16(pan) {
		return true
	}
	// Decompression may return a view for an uncompressed dispatch. Own the
	// bounded MLE payload before the driver's buffer can be reused.
	ownedPayload := append([]byte(nil), packet[48:]...)
	message, err := mle.ParseMessage(ownedPayload)
	if err != nil {
		inst.discoveryScanner.Fail(owner.id, err)
		return true
	}
	records, err := mle.ParseTLVs(message.Payload[1:])
	if err != nil || len(records) != 1 || records[0].Type != mle.TLVDiscovery {
		inst.discoveryScanner.Fail(owner.id, goterrors.ErrParse)
		return true
	}
	info := &mle.RxInfo{SrcAddr: types.ExtAddress(context.SrcExtAddr), SrcIP: source, DstIP: destination,
		Command: mle.CommandDiscoveryResponse, TLVs: records}
	metadata := mle.DiscoveryLinkInfo{Channel: uint16(frame.Channel), PanID: uint16(pan),
		RSSI: frame.RxInfo.RSSI, LQI: frame.RxInfo.LQI}
	// Parsed TLVs reference the bounded decompressed packet owned by this
	// callback, not the driver's reusable RX buffer. Retain the admitted scan
	// and channel ticket across the existing owner queue.
	if owner.pendingRX == 2 {
		inst.discoveryScanner.Fail(owner.id, goterrors.ErrNoBufs)
		return true
	}
	id, ticket := owner.id, owner.ticket
	owner.pendingRX++
	if !inst.postRadioMaintenance(func() {
		owner.pendingRX--
		if inst.nativeDiscovery != owner || owner.id != id || owner.ticket != ticket || owner.terminal {
			return
		}
		if err := owner.validate(); err != nil {
			inst.discoveryScanner.Fail(id, err)
			return
		}
		if err := inst.mleService.DiscoveryHandler.HandleDiscoveryResponseFor(id, info, metadata); err != nil {
			inst.discoveryScanner.Fail(id, err)
		}
	}) {
		owner.pendingRX--
		inst.discoveryScanner.Fail(id, goterrors.ErrNoBufs)
	}
	return true
}

func discoveryResponsePacket(packet []byte) bool {
	return len(packet) >= 50 && packet[0]>>4 == 6 && packet[6] == ip6.ProtoUDP &&
		binary.BigEndian.Uint16(packet[40:42]) == mle.UDPPort &&
		binary.BigEndian.Uint16(packet[42:44]) == mle.UDPPort &&
		packet[48] == mle.SecuritySuiteNone && mle.Command(packet[49]) == mle.CommandDiscoveryResponse
}
