// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import (
	"encoding/binary"

	"github.com/hilli/gothread/checksum"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/lowpan"
)

// IPv6MTU is the uncompressed IPv6 link MTU. UDP application payload is at
// most IPv6MTU - 40 - 8 = 1232 bytes.
const IPv6MTU = lowpan.IPv6MTU

type transmitState struct {
	packet     []byte
	header     []byte
	headerSize int // represented, uncompressed header bytes
	maxPayload int
	offset     int // always in uncompressed IPv6 bytes
	frameEnd   int
	fragments  int
	remaining  int
	tag        uint16
}

func frameContext(msg *TxMessage) *FrameContext {
	meta := msg.Metadata
	return &FrameContext{
		SrcShortAddr: msg.MeshSource, DstShortAddr: msg.MeshDest,
		SrcExtAddr: meta.SrcExtAddr, DstExtAddr: meta.DstExtAddr,
		UseSrcShort: meta.UseSrcShort, UseDstShort: meta.UseDstShort,
		PanId: meta.PanId, SecurityEnabled: meta.SecurityEnabled,
		Security: meta.Security, AckRequest: msg.AckRequired,
	}
}

func prepareTransmit(msg *TxMessage) (*transmitState, error) {
	if msg == nil || msg.Metadata == nil {
		return nil, errors.ErrInvalidArgs
	}
	meta := msg.Metadata
	headerSize := ip6.HeaderSize
	if meta.NextHeader == ip6.ProtoUDP {
		headerSize += ip6.UDPHeaderSize
	}
	if len(msg.Data) > IPv6MTU-headerSize {
		return nil, errors.ErrNoBufs
	}
	packet := make([]byte, headerSize+len(msg.Data))
	hdr := ip6.NewHeader(meta.SrcAddr, meta.DstAddr, meta.NextHeader, meta.HopLimit, uint16(len(packet)-ip6.HeaderSize))
	raw := hdr.Bytes()
	copy(packet, raw[:])
	copy(packet[headerSize:], msg.Data)
	header, err := lowpan.CompressHeader(raw, lowpan.AddressContext{
		SrcExtAddr: types.ExtAddress(meta.SrcExtAddr), DstExtAddr: types.ExtAddress(meta.DstExtAddr),
		SrcShort: types.ShortAddress(msg.MeshSource), DstShort: types.ShortAddress(msg.MeshDest),
		SrcShortValid: meta.UseSrcShort, DstShortValid: meta.UseDstShort,
	}, nil)
	if err != nil {
		return nil, err
	}
	if meta.NextHeader == ip6.ProtoUDP {
		udpHeader := packet[ip6.HeaderSize:headerSize]
		binary.BigEndian.PutUint16(udpHeader[:2], meta.SrcPort)
		binary.BigEndian.PutUint16(udpHeader[2:4], meta.DstPort)
		binary.BigEndian.PutUint16(udpHeader[4:6], uint16(len(packet)-ip6.HeaderSize))
		var sum checksum.Checksum
		sum.AddData(packet[8:40])
		sum.AddUint16(0)
		sum.AddUint16(uint16(len(packet) - ip6.HeaderSize))
		sum.AddUint16(0)
		sum.AddUint16(uint16(ip6.ProtoUDP))
		sum.AddData(packet[ip6.HeaderSize:])
		binary.BigEndian.PutUint16(udpHeader[6:8], sum.Finalize())
		var udp [ip6.UDPHeaderSize]byte
		copy(udp[:], udpHeader)
		compressed, compressErr := lowpan.CompressUDPHeader(udp)
		if compressErr != nil {
			return nil, compressErr
		}
		header = append(header, compressed...)
	}
	state := &transmitState{
		packet: packet, header: header, headerSize: headerSize,
		maxPayload: NewFramer().GetMaxPayloadSize(frameContext(msg)),
	}
	if len(header)+len(msg.Data) <= state.maxPayload {
		state.fragments, state.remaining = 1, 1
		return state, nil
	}
	// Routing/address selection belongs to the caller. Fragmentation never
	// invents a mesh route or an indirect delivery path.
	if !msg.Direct {
		return nil, errors.ErrNoBufs
	}
	for offset := 0; offset < len(packet); {
		end, endErr := state.nextEnd(offset)
		if endErr != nil {
			return nil, endErr
		}
		state.fragments++
		offset = end
	}
	state.remaining = state.fragments
	return state, nil
}

func (s *transmitState) nextEnd(offset int) (int, error) {
	start, capacity := offset, s.maxPayload-lowpan.FragSubsequentHeaderLen
	if offset == 0 {
		start = s.headerSize
		capacity = s.maxPayload - lowpan.FragFirstHeaderLen - len(s.header)
	}
	if capacity < 0 {
		return 0, errors.ErrNoBufs
	}
	end := start + capacity
	if end >= len(s.packet) {
		return len(s.packet), nil
	}
	end &^= 7
	if end <= offset || end < start {
		return 0, errors.ErrNoBufs
	}
	return end, nil
}

func (s *transmitState) payload() ([]byte, error) {
	if s.fragments == 1 {
		s.frameEnd = len(s.packet)
		data := append([]byte(nil), s.header...)
		return append(data, s.packet[s.headerSize:]...), nil
	}
	end, err := s.nextEnd(s.offset)
	if err != nil {
		return nil, err
	}
	data, err := lowpan.AppendFragmentHeader(nil, uint16(len(s.packet)), s.tag, uint16(s.offset))
	if err != nil {
		return nil, err
	}
	start := s.offset
	if start == 0 {
		data = append(data, s.header...)
		start = s.headerSize
	}
	s.frameEnd = end
	return append(data, s.packet[start:end]...), nil
}

// BuildTxFrame constructs the current secured MAC frame. Queued datagrams carry
// an owned transmit plan; only successful MAC completion advances its ORIGINAL
// IPv6 offset. SubMac retries the same prepared frame without rebuilding it.
func BuildTxFrame(msg *TxMessage, sequenceNumber uint8) ([]byte, error) {
	if msg == nil || msg.Metadata == nil {
		return nil, errors.ErrInvalidArgs
	}
	state := msg.transmit
	if state == nil {
		var err error
		state, err = prepareTransmit(msg)
		if err != nil {
			return nil, err
		}
		if state.fragments != 1 {
			return nil, errors.ErrNoBufs // Tag/admission must be owned by Forwarder.
		}
	}
	payload, err := state.payload()
	if err != nil {
		return nil, err
	}
	ctx := frameContext(msg)
	ctx.SequenceNumber = sequenceNumber
	return NewFramer().BuildDataFrame(ctx, payload)
}

// ValidateTxFrame checks a single-frame representation without consuming
// security material. Use ValidateTxDatagram for the integrated fragment path.
func ValidateTxFrame(msg *TxMessage) error {
	state, err := prepareTransmit(msg)
	if err == nil && state.fragments != 1 {
		err = errors.ErrNoBufs
	}
	return err
}

// ValidateTxDatagram validates an IPv6-MTU datagram and its actual per-fragment
// budgets without assigning a tag, admitting resources, encrypting, or taking
// a security counter.
func ValidateTxDatagram(msg *TxMessage) error {
	_, err := prepareTransmit(msg)
	return err
}

// BuildUDPMetadata creates UDP transmit metadata.
func BuildUDPMetadata(srcAddr, dstAddr [16]byte, srcPort, dstPort uint16, hopLimit uint8) *TxMetadata {
	return &TxMetadata{
		SrcAddr: srcAddr, DstAddr: dstAddr, SrcPort: srcPort, DstPort: dstPort,
		NextHeader: ip6.ProtoUDP, HopLimit: hopLimit,
	}
}
