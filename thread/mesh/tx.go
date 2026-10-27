// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import (
	"github.com/hilli/gothread/checksum"
	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/lowpan"
)

// BuildTxFrame constructs a complete IEEE 802.15.4 MAC frame from a
// TxMessage that has IPv6/transport metadata. The frame construction
// pipeline is:
//
//  1. Build 40-byte IPv6 header from metadata
//  2. Compress IPv6 header via 6LoWPAN IPHC
//  3. If UDP: build and compress UDP header via NHC
//  4. Concatenate: compressed_IPHC + (compressed_NHC_UDP) + payload
//  5. Build 802.15.4 MAC data frame around the 6LoWPAN payload
//
// The sequenceNumber parameter is the MAC-layer sequence number to use.
// Returns the complete MAC frame (without FCS, as radio hardware appends it).
func BuildTxFrame(msg *TxMessage, sequenceNumber uint8) ([]byte, error) {
	ctx, payload, err := prepareTxFrame(msg)
	if err != nil {
		return nil, err
	}
	ctx.SequenceNumber = sequenceNumber
	return NewFramer().BuildDataFrame(ctx, payload)
}

// ValidateTxFrame checks the actual compressed headers, security overhead, and
// payload against the single-frame limit without encrypting or using a counter.
// The instance TX path does not currently integrate outbound fragmentation.
func ValidateTxFrame(msg *TxMessage) error {
	ctx, payload, err := prepareTxFrame(msg)
	if err != nil {
		return err
	}
	if len(payload) > NewFramer().GetMaxPayloadSize(ctx) {
		return errors.ErrNoBufs
	}
	return nil
}

func prepareTxFrame(msg *TxMessage) (*FrameContext, []byte, error) {
	if msg == nil || msg.Metadata == nil {
		return nil, nil, errors.ErrInvalidArgs
	}
	// No single frame can carry this much application data, regardless of
	// compression. Reject before length conversion or allocating a datagram.
	if len(msg.Data) > MaxPsduSize-FCSSize {
		return nil, nil, errors.ErrNoBufs
	}
	meta := msg.Metadata

	// --- Step 1: Build IPv6 header ---
	var srcAddr, dstAddr ip6.Address
	copy(srcAddr[:], meta.SrcAddr[:])
	copy(dstAddr[:], meta.DstAddr[:])

	// Payload length: for UDP, it includes the 8-byte UDP header + data.
	// For other protocols (ICMPv6, etc.), it's just the data length.
	var payloadLen uint16
	if meta.NextHeader == ip6.ProtoUDP {
		payloadLen = uint16(8 + len(msg.Data)) // UDP header + payload
	} else {
		payloadLen = uint16(len(msg.Data))
	}

	ipv6Hdr := ip6.NewHeader(srcAddr, dstAddr, meta.NextHeader, meta.HopLimit, payloadLen)
	ipv6Raw := ipv6Hdr.Bytes()

	// --- Step 2: Build MAC address context for IPHC compression ---
	macAddrs := lowpan.AddressContext{
		SrcExtAddr: meta.SrcExtAddr,
		DstExtAddr: meta.DstExtAddr,
		SrcShort:   types.ShortAddress(msg.MeshSource),
		DstShort:   types.ShortAddress(msg.MeshDest),
	}

	// --- Step 3: Compress IPv6 header ---
	compressedIPHC, err := lowpan.CompressHeader(ipv6Raw, macAddrs, nil)
	if err != nil {
		return nil, nil, err
	}

	// --- Step 4: Build the 6LoWPAN payload ---
	// Start with the compressed IPHC header.
	var lowpanPayload []byte
	lowpanPayload = append(lowpanPayload, compressedIPHC...)

	if meta.NextHeader == ip6.ProtoUDP {
		// Build the 8-byte UDP header and compress it.
		var udpHdr [8]byte
		encoding.BigEndianWriteUint16(meta.SrcPort, udpHdr[0:2])
		encoding.BigEndianWriteUint16(meta.DstPort, udpHdr[2:4])
		encoding.BigEndianWriteUint16(payloadLen, udpHdr[4:6])
		var sum checksum.Checksum
		sum.AddData(srcAddr[:])
		sum.AddData(dstAddr[:])
		sum.AddUint16(0) // Upper-layer length, high word.
		sum.AddUint16(payloadLen)
		sum.AddUint16(0)
		sum.AddUint16(uint16(ip6.ProtoUDP))
		sum.AddData(udpHdr[:])
		sum.AddData(msg.Data)
		encoding.BigEndianWriteUint16(sum.Finalize(), udpHdr[6:8])

		compressedUDP, err := lowpan.CompressUDPHeader(udpHdr)
		if err != nil {
			return nil, nil, err
		}
		lowpanPayload = append(lowpanPayload, compressedUDP...)
	}

	// Append the application-layer payload.
	lowpanPayload = append(lowpanPayload, msg.Data...)

	// --- Step 5: Build the 802.15.4 MAC frame ---
	frameCtx := &FrameContext{
		SrcShortAddr:    msg.MeshSource,
		SrcExtAddr:      meta.SrcExtAddr,
		DstShortAddr:    msg.MeshDest,
		DstExtAddr:      meta.DstExtAddr,
		UseSrcShort:     meta.UseSrcShort,
		UseDstShort:     meta.UseDstShort,
		PanId:           meta.PanId,
		SecurityEnabled: meta.SecurityEnabled,
		Security:        meta.Security,
		AckRequest:      msg.AckRequired,
	}
	return frameCtx, lowpanPayload, nil
}

// BuildUDPMetadata is a convenience function that creates a TxMetadata
// populated for UDP transmission. This covers the common case of MLE
// and CoAP messages.
func BuildUDPMetadata(srcAddr, dstAddr [16]byte, srcPort, dstPort uint16, hopLimit uint8) *TxMetadata {
	return &TxMetadata{
		SrcAddr:    srcAddr,
		DstAddr:    dstAddr,
		SrcPort:    srcPort,
		DstPort:    dstPort,
		NextHeader: ip6.ProtoUDP,
		HopLimit:   hopLimit,
	}
}
