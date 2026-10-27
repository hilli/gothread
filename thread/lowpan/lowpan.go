// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package lowpan implements 6LoWPAN IPHC header compression and decompression
// as defined in RFC 6282.
//
// This is a Go port of the compression logic in OpenThread's
// src/core/thread/lowpan.hpp and src/core/thread/lowpan.cpp.
package lowpan

import (
	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
)

// ---------------------------------------------------------------------------
// IPHC dispatch constants (2-byte, big-endian)
// ---------------------------------------------------------------------------

const (
	// HcDispatch is the 3-bit dispatch value for IPHC (011).
	HcDispatch uint16 = 0x6000
	// HcDispatchMask masks the top 3 bits of the IPHC dispatch.
	HcDispatchMask uint16 = 0xE000

	// HcTfMask is the bitmask for Traffic Class / Flow Label compression modes (bits 11-12).
	HcTfMask uint16 = 0x1800
	// HcTfFullInline selects ECN+DSCP+4-byte-Flow inline.
	HcTfFullInline uint16 = 0x0000
	// HcTfEcnFlowInline selects ECN+2-byte-Flow inline, DSCP elided.
	HcTfEcnFlowInline uint16 = 0x0800
	// HcTfEcnInline selects ECN only, Flow+DSCP elided.
	HcTfEcnInline uint16 = 0x1000
	// HcTfElided indicates all Traffic Class and Flow Label fields are elided.
	HcTfElided uint16 = 0x1800

	// HcNextHeader indicates the Next Header is compressed (bit 10).
	HcNextHeader uint16 = 0x0400

	// HcHopLimitMask is the bitmask for Hop Limit modes (bits 8-9).
	HcHopLimitMask uint16 = 0x0300
	// HcHopLimitInline selects hop limit carried inline.
	HcHopLimitInline uint16 = 0x0000
	// HcHopLimit1 selects a hop limit of 1.
	HcHopLimit1 uint16 = 0x0100
	// HcHopLimit64 selects a hop limit of 64.
	HcHopLimit64 uint16 = 0x0200
	// HcHopLimit255 selects a hop limit of 255.
	HcHopLimit255 uint16 = 0x0300

	// HcContextID is the Context Identifier Extension flag (bit 7).
	HcContextID uint16 = 0x0080

	// HcSrcAddrContext indicates stateful source address compression (bit 6).
	HcSrcAddrContext uint16 = 0x0040
	// HcSrcAddrMask is the bitmask for source address mode (bits 4-5).
	HcSrcAddrMask uint16 = 0x0030
	// HcSrcAddr128 selects full 128-bit source address inline.
	HcSrcAddr128 uint16 = 0x0000
	// HcSrcAddr64 selects 64-bit source IID inline.
	HcSrcAddr64 uint16 = 0x0010
	// HcSrcAddr16 selects 16-bit source address inline.
	HcSrcAddr16 uint16 = 0x0020
	// HcSrcAddrElided indicates the source address is fully elided.
	HcSrcAddrElided uint16 = 0x0030

	// HcMulticast is the multicast destination flag (bit 3).
	HcMulticast uint16 = 0x0008
	// HcDstAddrContext indicates stateful destination address compression (bit 2).
	HcDstAddrContext uint16 = 0x0004
	// HcDstAddrMask is the bitmask for destination address mode (bits 0-1).
	HcDstAddrMask uint16 = 0x0003
	// HcDstAddr128 selects full 128-bit destination address inline.
	HcDstAddr128 uint16 = 0x0000
	// HcDstAddr64 selects 64-bit destination IID inline.
	HcDstAddr64 uint16 = 0x0001
	// HcDstAddr16 selects 16-bit destination address inline.
	HcDstAddr16 uint16 = 0x0002
	// HcDstAddrElided indicates the destination address is fully elided.
	HcDstAddrElided uint16 = 0x0003
)

// ---------------------------------------------------------------------------
// NHC (Next Header Compression) constants
// ---------------------------------------------------------------------------

const (
	// NhcExtDispatch is the Extension header NHC dispatch value (1110_EEE_N pattern).
	NhcExtDispatch uint8 = 0xE0
	// NhcExtDispatchMask is the mask for extension header NHC dispatch.
	NhcExtDispatchMask uint8 = 0xF0

	// NhcExtHopByHop is the NHC dispatch for Hop-by-Hop extension header (EID=0).
	NhcExtHopByHop uint8 = 0xE0
	// NhcExtRouting is the NHC dispatch for Routing extension header (EID=1).
	NhcExtRouting uint8 = 0xE2
	// NhcExtFragment is the NHC dispatch for Fragment extension header (EID=2).
	NhcExtFragment uint8 = 0xE4
	// NhcExtDstOpts is the NHC dispatch for Destination Options extension header (EID=3).
	NhcExtDstOpts uint8 = 0xE6
	// NhcExtMobility is the NHC dispatch for Mobility extension header (EID=4).
	NhcExtMobility uint8 = 0xE8
	// NhcExtIP6 is the NHC dispatch for IPv6 encapsulation extension header (EID=7).
	NhcExtIP6 uint8 = 0xEE

	// NhcExtNextHeaderFlag is the N bit indicating next header is also NHC-compressed.
	NhcExtNextHeaderFlag uint8 = 0x01

	// NhcUDPDispatch is the UDP NHC dispatch value (11110_C_PP pattern).
	NhcUDPDispatch uint8 = 0xF0
	// NhcUDPDispatchMask is the mask for UDP NHC dispatch.
	NhcUDPDispatchMask uint8 = 0xF8
	// NhcUDPChecksum is the C bit indicating the UDP checksum is elided.
	NhcUDPChecksum uint8 = 0x04
	// NhcUDPPortMask is the bitmask for the UDP port compression mode (PP bits).
	NhcUDPPortMask uint8 = 0x03
	// NhcUDPPortBothFull selects both source and destination ports as 16-bit inline (PP=00).
	NhcUDPPortBothFull uint8 = 0x00
	// NhcUDPPortDst8 selects source 16-bit inline, destination 8-bit compressed (PP=01).
	NhcUDPPortDst8 uint8 = 0x01
	// NhcUDPPortSrc8 selects source 8-bit compressed, destination 16-bit inline (PP=10).
	NhcUDPPortSrc8 uint8 = 0x02
	// NhcUDPPortBoth4 selects both ports as 4-bit nibble compressed (PP=11).
	NhcUDPPortBoth4 uint8 = 0x03
)

// UDP port compression bases.
const (
	udpPort8BitBase uint16 = 0xF000 // 8-bit compressed base
	udpPort4BitBase uint16 = 0xF0B0 // 4-bit compressed base
)

// ---------------------------------------------------------------------------
// Context for stateful compression
// ---------------------------------------------------------------------------

// Context holds a prefix used for stateful IPHC address compression.
type Context struct {
	Prefix    [16]byte // the context prefix bytes
	PrefixLen uint8    // prefix length in bits
}

// ---------------------------------------------------------------------------
// AddressContext holds MAC-layer addresses used for elided IPHC fields
// ---------------------------------------------------------------------------

// AddressContext provides the MAC-layer addressing information needed for
// IPHC compression and decompression of elided address fields.
type AddressContext struct {
	SrcExtAddr types.ExtAddress
	DstExtAddr types.ExtAddress
	SrcShort   types.ShortAddress
	DstShort   types.ShortAddress
}

// ---------------------------------------------------------------------------
// IPv6 header byte layout constants
// ---------------------------------------------------------------------------

const (
	ipv6HeaderSize = 40
	ipv6OffsetSrc  = 8
	ipv6OffsetDst  = 24
	udpHeaderSize  = 8
)

// Link-local prefix fe80::/10.
var linkLocalPrefix = [8]byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// IsLowpanHc returns true if data starts with the IPHC dispatch (top 3 bits
// of the first two bytes equal 011).
func IsLowpanHc(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	dispatch := encoding.BigEndianReadUint16(data[:2])
	return (dispatch & HcDispatchMask) == HcDispatch
}

// ---------------------------------------------------------------------------
// 6LoWPAN Fragment dispatch (RFC 4944 §5.3)
// ---------------------------------------------------------------------------

const (
	// FragDispatchMask masks the top 5 bits for fragment identification.
	FragDispatchMask byte = 0xF8

	// FragFirstDispatch is the dispatch value for first fragments (11000xxx).
	FragFirstDispatch byte = 0xC0

	// FragSubsequentDispatch is the dispatch value for subsequent fragments (11100xxx).
	FragSubsequentDispatch byte = 0xE0

	// FragFirstHeaderLen is the header length for a first fragment (4 bytes):
	// dispatch+size(2) + tag(2).
	FragFirstHeaderLen = 4

	// FragSubsequentHeaderLen is the header length for a subsequent fragment
	// (5 bytes): dispatch+size(2) + tag(2) + offset(1).
	FragSubsequentHeaderLen = 5
)

// IsFragment returns true if data starts with a 6LoWPAN fragment dispatch
// (either first-fragment 0xC0 or subsequent-fragment 0xE0).
func IsFragment(data []byte) bool {
	if len(data) < 1 {
		return false
	}
	d := data[0] & FragDispatchMask
	return d == FragFirstDispatch || d == FragSubsequentDispatch
}

// FragmentHeader holds the parsed fields of a 6LoWPAN fragment header.
type FragmentHeader struct {
	// DatagramSize is the total size of the unfragmented datagram.
	DatagramSize uint16
	// DatagramTag identifies which datagram this fragment belongs to.
	DatagramTag uint16
	// DatagramOffset is a BYTE offset in the original, uncompressed IPv6
	// datagram. The wire field encodes this in eight-octet units.
	DatagramOffset uint16
	// IsFirst is true when this is a first-fragment header (dispatch 0xC0).
	IsFirst bool
}

// ParseFragmentHeader parses a 6LoWPAN fragment header from data.
//
// Returns the parsed header, bytes consumed (header length), and any error.
// The caller can use data[consumed:] to access the fragment payload.
func ParseFragmentHeader(data []byte) (FragmentHeader, int, error) {
	if len(data) < FragFirstHeaderLen {
		return FragmentHeader{}, 0, errors.ErrParse
	}

	dispatch := data[0] & FragDispatchMask
	isFirst := dispatch == FragFirstDispatch
	isSubsequent := dispatch == FragSubsequentDispatch

	if !isFirst && !isSubsequent {
		return FragmentHeader{}, 0, errors.ErrParse
	}

	// datagram_size: 11 bits across bytes 0-1 (lower 3 bits of byte 0 + all 8 bits of byte 1).
	size := uint16(data[0]&0x07)<<8 | uint16(data[1])
	tag := uint16(data[2])<<8 | uint16(data[3])
	if size < ipv6HeaderSize {
		return FragmentHeader{}, 0, errors.ErrParse
	}

	if isFirst {
		return FragmentHeader{
			DatagramSize:   size,
			DatagramTag:    tag,
			DatagramOffset: 0,
			IsFirst:        true,
		}, FragFirstHeaderLen, nil
	}

	// Subsequent fragment: 5-byte header.
	if len(data) < FragSubsequentHeaderLen {
		return FragmentHeader{}, 0, errors.ErrParse
	}
	offset := uint16(data[4]) * 8 // offset is in units of 8 octets
	if offset == 0 || offset >= size {
		return FragmentHeader{}, 0, errors.ErrParse
	}

	return FragmentHeader{
		DatagramSize:   size,
		DatagramTag:    tag,
		DatagramOffset: offset,
		IsFirst:        false,
	}, FragSubsequentHeaderLen, nil
}

// DecompressHeader decompresses an IPHC-compressed header.
//
// It takes the compressed data, MAC address context, and an optional slice of
// network contexts for stateful compression.
//
// Returns the decompressed 40-byte IPv6 header, the number of compressed
// bytes consumed, whether the IPHC NH flag was set (meaning the next
// header is NHC-compressed and header[6] should be ignored), and any error.
func DecompressHeader(data []byte, macAddrs AddressContext, contexts []Context) (header [ipv6HeaderSize]byte, consumed int, nhCompressed bool, err error) {
	if len(data) < 2 {
		return header, 0, false, errors.ErrParse
	}

	iphc := encoding.BigEndianReadUint16(data[:2])
	if (iphc & HcDispatchMask) != HcDispatch {
		return header, 0, false, errors.ErrParse
	}

	pos := 2

	// --- Context Identifier Extension ---
	var sci, dci uint8
	if iphc&HcContextID != 0 {
		if pos >= len(data) {
			return header, 0, false, errors.ErrParse
		}
		sci = data[pos] >> 4
		dci = data[pos] & 0x0F
		pos++
	}

	// --- Traffic Class / Flow Label ---
	var ecn, dscp uint8
	var flow uint32

	switch iphc & HcTfMask {
	case HcTfFullInline: // TF=00: 4 bytes inline
		if pos+4 > len(data) {
			return header, 0, false, errors.ErrParse
		}
		// inline[0] = (ecn << 6) | dscp
		// inline[1] = 0000_FlowHi(4)
		// inline[2] = Flow(8)
		// inline[3] = FlowLo(8)
		ecn = data[pos] >> 6
		dscp = data[pos] & 0x3F
		flow = (uint32(data[pos+1]&0x0F) << 16) | (uint32(data[pos+2]) << 8) | uint32(data[pos+3])
		pos += 4

	case HcTfEcnFlowInline: // TF=01: 3 bytes inline (ECN + 2-byte flow, DSCP=0)
		if pos+3 > len(data) {
			return header, 0, false, errors.ErrParse
		}
		// inline[0] = (ecn << 6) | 00_FlowHi(4)
		// inline[1] = Flow(8)
		// inline[2] = FlowLo(8)
		ecn = data[pos] >> 6
		dscp = 0
		flow = (uint32(data[pos]&0x0F) << 16) | (uint32(data[pos+1]) << 8) | uint32(data[pos+2])
		pos += 3

	case HcTfEcnInline: // TF=10: 1 byte inline (ECN + DSCP, flow=0)
		if pos+1 > len(data) {
			return header, 0, false, errors.ErrParse
		}
		ecn = data[pos] >> 6
		dscp = data[pos] & 0x3F
		flow = 0
		pos++

	case HcTfElided: // TF=11: all elided
		ecn = 0
		dscp = 0
		flow = 0
	}

	// Build IPv6 header bytes 0-3:
	//   tc = (dscp << 2) | ecn
	//   byte[0] = (6 << 4) | (tc >> 4)
	//   byte[1] = (tc << 4) | (flow >> 16)
	//   byte[2] = (flow >> 8) & 0xFF
	//   byte[3] = flow & 0xFF
	tc := (dscp << 2) | ecn
	header[0] = 0x60 | (tc >> 4)
	header[1] = (tc << 4) | uint8((flow>>16)&0x0F)
	header[2] = uint8(flow >> 8)
	header[3] = uint8(flow)

	// --- Next Header ---
	nhCompressed = (iphc & HcNextHeader) != 0
	if !nhCompressed {
		if pos >= len(data) {
			return header, 0, false, errors.ErrParse
		}
		header[6] = data[pos]
		pos++
	}
	// If NH is compressed, we leave header[6] = 0 for now; the caller
	// will process it with DecompressUDPHeader or similar.

	// --- Hop Limit ---
	switch iphc & HcHopLimitMask {
	case HcHopLimitInline:
		if pos >= len(data) {
			return header, 0, false, errors.ErrParse
		}
		header[7] = data[pos]
		pos++
	case HcHopLimit1:
		header[7] = 1
	case HcHopLimit64:
		header[7] = 64
	case HcHopLimit255:
		header[7] = 255
	}

	// --- Source Address ---
	sac := (iphc & HcSrcAddrContext) != 0
	sam := iphc & HcSrcAddrMask

	if !sac {
		// Stateless source address.
		switch sam {
		case HcSrcAddr128: // 128-bit inline
			if pos+16 > len(data) {
				return header, 0, false, errors.ErrParse
			}
			copy(header[ipv6OffsetSrc:], data[pos:pos+16])
			pos += 16

		case HcSrcAddr64: // 64-bit IID inline, link-local prefix
			copy(header[ipv6OffsetSrc:], linkLocalPrefix[:])
			if pos+8 > len(data) {
				return header, 0, false, errors.ErrParse
			}
			copy(header[ipv6OffsetSrc+8:], data[pos:pos+8])
			pos += 8

		case HcSrcAddr16: // 16-bit inline
			copy(header[ipv6OffsetSrc:], linkLocalPrefix[:])
			if pos+2 > len(data) {
				return header, 0, false, errors.ErrParse
			}
			writeIIDFromShort(header[ipv6OffsetSrc+8:], encoding.BigEndianReadUint16(data[pos:pos+2]))
			pos += 2

		case HcSrcAddrElided: // fully elided from MAC ext addr
			copy(header[ipv6OffsetSrc:], linkLocalPrefix[:])
			writeIIDFromExtAddr(header[ipv6OffsetSrc+8:], macAddrs.SrcExtAddr)
		}
	} else {
		// Stateful source address (context from SCI).
		switch sam {
		case HcSrcAddr128: // SAC=1, SAM=00 → unspecified (::)
			// header[ipv6OffsetSrc:ipv6OffsetSrc+16] already zeroed

		case HcSrcAddr64: // SAC=1, SAM=01 → 64-bit IID inline, prefix from context
			ctx := lookupContext(contexts, sci)
			copyContextPrefix(header[ipv6OffsetSrc:], ctx)
			if pos+8 > len(data) {
				return header, 0, false, errors.ErrParse
			}
			copy(header[ipv6OffsetSrc+8:], data[pos:pos+8])
			pos += 8

		case HcSrcAddr16: // SAC=1, SAM=10 → 16-bit inline, prefix from context
			ctx := lookupContext(contexts, sci)
			copyContextPrefix(header[ipv6OffsetSrc:], ctx)
			if pos+2 > len(data) {
				return header, 0, false, errors.ErrParse
			}
			writeIIDFromShort(header[ipv6OffsetSrc+8:], encoding.BigEndianReadUint16(data[pos:pos+2]))
			pos += 2

		case HcSrcAddrElided: // SAC=1, SAM=11 → IID from MAC, prefix from context
			ctx := lookupContext(contexts, sci)
			copyContextPrefix(header[ipv6OffsetSrc:], ctx)
			writeIIDFromExtAddr(header[ipv6OffsetSrc+8:], macAddrs.SrcExtAddr)
		}
	}

	// --- Destination Address ---
	mcast := (iphc & HcMulticast) != 0
	dac := (iphc & HcDstAddrContext) != 0
	dam := iphc & HcDstAddrMask

	if !mcast {
		// Unicast destination.
		if !dac {
			// Stateless unicast.
			switch dam {
			case HcDstAddr128:
				if pos+16 > len(data) {
					return header, 0, false, errors.ErrParse
				}
				copy(header[ipv6OffsetDst:], data[pos:pos+16])
				pos += 16

			case HcDstAddr64:
				copy(header[ipv6OffsetDst:], linkLocalPrefix[:])
				if pos+8 > len(data) {
					return header, 0, false, errors.ErrParse
				}
				copy(header[ipv6OffsetDst+8:], data[pos:pos+8])
				pos += 8

			case HcDstAddr16:
				copy(header[ipv6OffsetDst:], linkLocalPrefix[:])
				if pos+2 > len(data) {
					return header, 0, false, errors.ErrParse
				}
				writeIIDFromShort(header[ipv6OffsetDst+8:], encoding.BigEndianReadUint16(data[pos:pos+2]))
				pos += 2

			case HcDstAddrElided:
				copy(header[ipv6OffsetDst:], linkLocalPrefix[:])
				writeIIDFromExtAddr(header[ipv6OffsetDst+8:], macAddrs.DstExtAddr)
			}
		} else {
			// Stateful unicast (context from DCI).
			switch dam {
			case HcDstAddr128:
				// DAC=1, DAM=00 is reserved per RFC 6282.
				return header, 0, false, errors.ErrParse

			case HcDstAddr64:
				ctx := lookupContext(contexts, dci)
				copyContextPrefix(header[ipv6OffsetDst:], ctx)
				if pos+8 > len(data) {
					return header, 0, false, errors.ErrParse
				}
				copy(header[ipv6OffsetDst+8:], data[pos:pos+8])
				pos += 8

			case HcDstAddr16:
				ctx := lookupContext(contexts, dci)
				copyContextPrefix(header[ipv6OffsetDst:], ctx)
				if pos+2 > len(data) {
					return header, 0, false, errors.ErrParse
				}
				writeIIDFromShort(header[ipv6OffsetDst+8:], encoding.BigEndianReadUint16(data[pos:pos+2]))
				pos += 2

			case HcDstAddrElided:
				ctx := lookupContext(contexts, dci)
				copyContextPrefix(header[ipv6OffsetDst:], ctx)
				writeIIDFromExtAddr(header[ipv6OffsetDst+8:], macAddrs.DstExtAddr)
			}
		}
	} else {
		// Multicast destination.
		if !dac {
			switch dam {
			case HcDstAddr128: // M=1, DAC=0, DAM=00: 128-bit inline
				if pos+16 > len(data) {
					return header, 0, false, errors.ErrParse
				}
				copy(header[ipv6OffsetDst:], data[pos:pos+16])
				pos += 16

			case HcDstAddr64: // M=1, DAC=0, DAM=01: 48-bit → ffXX::00XX:XXXX:XXXX
				if pos+6 > len(data) {
					return header, 0, false, errors.ErrParse
				}
				header[ipv6OffsetDst+0] = 0xFF
				header[ipv6OffsetDst+1] = data[pos]
				header[ipv6OffsetDst+11] = data[pos+1]
				header[ipv6OffsetDst+12] = data[pos+2]
				header[ipv6OffsetDst+13] = data[pos+3]
				header[ipv6OffsetDst+14] = data[pos+4]
				header[ipv6OffsetDst+15] = data[pos+5]
				pos += 6

			case HcDstAddr16: // M=1, DAC=0, DAM=10: 32-bit → ffXX::00XX:XXXX
				if pos+4 > len(data) {
					return header, 0, false, errors.ErrParse
				}
				header[ipv6OffsetDst+0] = 0xFF
				header[ipv6OffsetDst+1] = data[pos]
				header[ipv6OffsetDst+13] = data[pos+1]
				header[ipv6OffsetDst+14] = data[pos+2]
				header[ipv6OffsetDst+15] = data[pos+3]
				pos += 4

			case HcDstAddrElided: // M=1, DAC=0, DAM=11: 8-bit → ff02::00XX
				if pos+1 > len(data) {
					return header, 0, false, errors.ErrParse
				}
				header[ipv6OffsetDst+0] = 0xFF
				header[ipv6OffsetDst+1] = 0x02
				header[ipv6OffsetDst+15] = data[pos]
				pos++
			}
		} else {
			// M=1, DAC=1: unicast-prefix-based multicast.
			switch dam {
			case HcDstAddr128: // M=1, DAC=1, DAM=00: 48-bit unicast-prefix-based
				if pos+6 > len(data) {
					return header, 0, false, errors.ErrParse
				}
				// ffXX:XXLL:PPPP:PPPP:PPPP:PPPP:XXXX:XXXX
				// where P comes from context prefix, L = prefix length.
				ctx := lookupContext(contexts, dci)
				header[ipv6OffsetDst+0] = 0xFF
				header[ipv6OffsetDst+1] = data[pos]
				header[ipv6OffsetDst+2] = data[pos+1]
				if ctx != nil {
					header[ipv6OffsetDst+3] = ctx.PrefixLen
				}
				copy(header[ipv6OffsetDst+4:ipv6OffsetDst+12], ctx.Prefix[0:8])
				header[ipv6OffsetDst+12] = data[pos+2]
				header[ipv6OffsetDst+13] = data[pos+3]
				header[ipv6OffsetDst+14] = data[pos+4]
				header[ipv6OffsetDst+15] = data[pos+5]
				pos += 6

			default:
				// Other DAC=1 multicast modes are not defined in RFC 6282.
				return header, 0, false, errors.ErrParse
			}
		}
	}

	return header, pos, nhCompressed, nil
}

// DecompressUDPHeader decompresses an NHC-compressed UDP header.
//
// Returns the 8-byte UDP header, bytes consumed from data, and any error.
func DecompressUDPHeader(data []byte) (header [udpHeaderSize]byte, consumed int, err error) {
	if len(data) < 1 {
		return header, 0, errors.ErrParse
	}

	dispatch := data[0]
	if (dispatch & NhcUDPDispatchMask) != NhcUDPDispatch {
		return header, 0, errors.ErrParse
	}

	pos := 1
	checksumElided := (dispatch & NhcUDPChecksum) != 0
	portMode := dispatch & NhcUDPPortMask

	switch portMode {
	case NhcUDPPortBothFull: // PP=00: both 16-bit inline
		if pos+4 > len(data) {
			return header, 0, errors.ErrParse
		}
		encoding.BigEndianWriteUint16(encoding.BigEndianReadUint16(data[pos:]), header[0:])
		pos += 2
		encoding.BigEndianWriteUint16(encoding.BigEndianReadUint16(data[pos:]), header[2:])
		pos += 2

	case NhcUDPPortDst8: // PP=01: src 16-bit, dst 8-bit (0xF000+)
		if pos+3 > len(data) {
			return header, 0, errors.ErrParse
		}
		encoding.BigEndianWriteUint16(encoding.BigEndianReadUint16(data[pos:]), header[0:])
		pos += 2
		encoding.BigEndianWriteUint16(udpPort8BitBase+uint16(data[pos]), header[2:])
		pos++

	case NhcUDPPortSrc8: // PP=10: src 8-bit (0xF000+), dst 16-bit
		if pos+3 > len(data) {
			return header, 0, errors.ErrParse
		}
		encoding.BigEndianWriteUint16(udpPort8BitBase+uint16(data[pos]), header[0:])
		pos++
		encoding.BigEndianWriteUint16(encoding.BigEndianReadUint16(data[pos:]), header[2:])
		pos += 2

	case NhcUDPPortBoth4: // PP=11: both 4-bit nibble (0xF0B0+)
		if pos+1 > len(data) {
			return header, 0, errors.ErrParse
		}
		srcNibble := data[pos] >> 4
		dstNibble := data[pos] & 0x0F
		encoding.BigEndianWriteUint16(udpPort4BitBase+uint16(srcNibble), header[0:])
		encoding.BigEndianWriteUint16(udpPort4BitBase+uint16(dstNibble), header[2:])
		pos++
	}

	// Checksum: 2 bytes inline or elided (zeroed).
	if !checksumElided {
		if pos+2 > len(data) {
			return header, 0, errors.ErrParse
		}
		header[6] = data[pos]
		header[7] = data[pos+1]
		pos += 2
	}

	return header, pos, nil
}

// CompressHeader compresses a 40-byte IPv6 header using IPHC.
//
// Returns the compressed bytes and any error.
func CompressHeader(header [ipv6HeaderSize]byte, macAddrs AddressContext, contexts []Context) ([]byte, error) {
	// Verify version nibble.
	if (header[0] >> 4) != 6 {
		return nil, errors.ErrParse
	}

	iphc := HcDispatch
	// buf is sized for the worst case: 2 (dispatch) + 1 (CID) + 4 (TF) +
	// 1 (NH) + 1 (HL) + 16 (src) + 16 (dst) = 41.
	buf := make([]byte, 0, 48)
	buf = append(buf, 0, 0) // placeholder for dispatch
	pos := 2                // write cursor into buf

	// --- Context Identifier ---
	// Attempt stateful compression for src and dst.
	srcCtxIdx := findBestContext(header[ipv6OffsetSrc:ipv6OffsetSrc+16], contexts)
	dstCtxIdx := findBestContext(header[ipv6OffsetDst:ipv6OffsetDst+16], contexts)

	needCID := srcCtxIdx >= 0 || dstCtxIdx >= 0
	if needCID {
		iphc |= HcContextID
		var cidByte uint8
		if srcCtxIdx >= 0 {
			cidByte |= uint8(srcCtxIdx) << 4
		}
		if dstCtxIdx >= 0 {
			cidByte |= uint8(dstCtxIdx) & 0x0F
		}
		buf = append(buf, cidByte)
		pos++
	}

	// --- Traffic Class / Flow Label ---
	tc := (header[0]&0x0F)<<4 | header[1]>>4
	ecn := tc & 0x03
	dscp := tc >> 2
	flow := uint32(header[1]&0x0F)<<16 | uint32(header[2])<<8 | uint32(header[3])

	switch {
	case dscp == 0 && ecn == 0 && flow == 0:
		iphc |= HcTfElided
	case flow == 0:
		iphc |= HcTfEcnInline
		buf = append(buf, (ecn<<6)|dscp)
		pos++
	case dscp == 0:
		iphc |= HcTfEcnFlowInline
		buf = append(buf,
			(ecn<<6)|uint8((flow>>16)&0x0F),
			uint8(flow>>8),
			uint8(flow),
		)
		pos += 3
	default:
		iphc |= HcTfFullInline
		buf = append(buf,
			(ecn<<6)|dscp,
			uint8((flow>>16)&0x0F),
			uint8(flow>>8),
			uint8(flow),
		)
		pos += 4
	}

	// --- Next Header ---
	// We compress NH only for UDP (protocol 17) since that's the common
	// Thread case. For other protocols, send inline.
	nh := header[6]
	if nh == 17 {
		iphc |= HcNextHeader
	} else {
		buf = append(buf, nh)
		pos++
	}

	// --- Hop Limit ---
	hl := header[7]
	switch hl {
	case 1:
		iphc |= HcHopLimit1
	case 64:
		iphc |= HcHopLimit64
	case 255:
		iphc |= HcHopLimit255
	default:
		iphc |= HcHopLimitInline
		buf = append(buf, hl)
		pos++
	}

	// --- Source Address ---
	srcAddr := header[ipv6OffsetSrc : ipv6OffsetSrc+16]
	srcIID := header[ipv6OffsetSrc+8 : ipv6OffsetSrc+16]

	switch {
	case srcCtxIdx >= 0:
		iphc |= HcSrcAddrContext
		switch {
		case matchIIDExtAddr(srcIID, macAddrs.SrcExtAddr):
			iphc |= HcSrcAddrElided
		case matchIIDShort(srcIID):
			iphc |= HcSrcAddr16
			buf = append(buf, srcIID[6], srcIID[7])
			pos += 2
		default:
			iphc |= HcSrcAddr64
			buf = append(buf, srcIID...)
			pos += 8
		}
	case isUnspecified(srcAddr):
		// Unspecified address: SAC=1, SAM=00.
		iphc |= HcSrcAddrContext
		iphc |= HcSrcAddr128
	case isLinkLocal(srcAddr):
		switch {
		case matchIIDExtAddr(srcIID, macAddrs.SrcExtAddr):
			iphc |= HcSrcAddrElided
		case matchIIDShort(srcIID):
			iphc |= HcSrcAddr16
			buf = append(buf, srcIID[6], srcIID[7])
			pos += 2
		default:
			iphc |= HcSrcAddr64
			buf = append(buf, srcIID...)
			pos += 8
		}
	default:
		// Full 128-bit inline.
		iphc |= HcSrcAddr128
		buf = append(buf, srcAddr...)
		pos += 16
	}

	// --- Destination Address ---
	dstAddr := header[ipv6OffsetDst : ipv6OffsetDst+16]
	dstIID := header[ipv6OffsetDst+8 : ipv6OffsetDst+16]

	if dstAddr[0] == 0xFF {
		// Multicast.
		iphc |= HcMulticast
		switch {
		case dstCtxIdx >= 0:
			// Unicast-prefix-based multicast: M=1, DAC=1, DAM=00.
			iphc |= HcDstAddrContext
			iphc |= HcDstAddr128
			buf = append(buf,
				dstAddr[1], // scope
				dstAddr[2], // flags
				dstAddr[12], dstAddr[13], dstAddr[14], dstAddr[15],
			)
			pos += 6
		case dstAddr[1] == 0x02 && isZeros(dstAddr[2:15]):
			// ff02::00XX → 8-bit
			iphc |= HcDstAddrElided
			buf = append(buf, dstAddr[15])
			pos++
		case isZeros(dstAddr[2:13]):
			// ffXX::00XX:XXXX → 32-bit
			iphc |= HcDstAddr16
			buf = append(buf, dstAddr[1], dstAddr[13], dstAddr[14], dstAddr[15])
			pos += 4
		case isZeros(dstAddr[2:11]):
			// ffXX::00XX:XXXX:XXXX → 48-bit
			iphc |= HcDstAddr64
			buf = append(buf, dstAddr[1], dstAddr[11], dstAddr[12], dstAddr[13], dstAddr[14], dstAddr[15])
			pos += 6
		default:
			// Full 128-bit inline.
			iphc |= HcDstAddr128
			buf = append(buf, dstAddr...)
			pos += 16
		}
	} else {
		// Unicast destination.
		switch {
		case dstCtxIdx >= 0:
			iphc |= HcDstAddrContext
			switch {
			case matchIIDExtAddr(dstIID, macAddrs.DstExtAddr):
				iphc |= HcDstAddrElided
			case matchIIDShort(dstIID):
				iphc |= HcDstAddr16
				buf = append(buf, dstIID[6], dstIID[7])
				pos += 2
			default:
				iphc |= HcDstAddr64
				buf = append(buf, dstIID...)
				pos += 8
			}
		case isLinkLocal(dstAddr):
			switch {
			case matchIIDExtAddr(dstIID, macAddrs.DstExtAddr):
				iphc |= HcDstAddrElided
			case matchIIDShort(dstIID):
				iphc |= HcDstAddr16
				buf = append(buf, dstIID[6], dstIID[7])
				pos += 2
			default:
				iphc |= HcDstAddr64
				buf = append(buf, dstIID...)
				pos += 8
			}
		default:
			iphc |= HcDstAddr128
			buf = append(buf, dstAddr...)
			pos += 16
		}
	}

	// Write the IPHC dispatch.
	encoding.BigEndianWriteUint16(iphc, buf[0:2])

	return buf[:pos], nil
}

// CompressUDPHeader compresses an 8-byte UDP header using NHC.
//
// Returns the compressed bytes and any error.
func CompressUDPHeader(header [udpHeaderSize]byte) ([]byte, error) {
	srcPort := encoding.BigEndianReadUint16(header[0:2])
	dstPort := encoding.BigEndianReadUint16(header[2:4])
	checksum := encoding.BigEndianReadUint16(header[6:8])

	dispatch := NhcUDPDispatch
	var buf []byte

	switch {
	case srcPort >= udpPort4BitBase && srcPort < udpPort4BitBase+16 &&
		dstPort >= udpPort4BitBase && dstPort < udpPort4BitBase+16:
		// PP=11: both 4-bit nibble.
		dispatch |= NhcUDPPortBoth4
		nibbles := uint8(srcPort-udpPort4BitBase)<<4 | uint8(dstPort-udpPort4BitBase)
		buf = append(buf, dispatch, nibbles)
	case srcPort >= udpPort8BitBase && srcPort < udpPort8BitBase+256 &&
		dstPort >= udpPort8BitBase && dstPort < udpPort8BitBase+256:
		// Try 8-bit for both — but NHC only supports one at a time.
		// PP=01: src full, dst 8-bit or PP=10: src 8-bit, dst full.
		// Prefer whichever works.
		if dstPort >= udpPort8BitBase && dstPort < udpPort8BitBase+256 {
			dispatch |= NhcUDPPortDst8
			buf = append(buf, dispatch)
			buf = appendUint16BE(buf, srcPort)
			buf = append(buf, uint8(dstPort-udpPort8BitBase))
		} else {
			dispatch |= NhcUDPPortSrc8
			buf = append(buf, dispatch, uint8(srcPort-udpPort8BitBase))
			buf = appendUint16BE(buf, dstPort)
		}
	case dstPort >= udpPort8BitBase && dstPort < udpPort8BitBase+256:
		dispatch |= NhcUDPPortDst8
		buf = append(buf, dispatch)
		buf = appendUint16BE(buf, srcPort)
		buf = append(buf, uint8(dstPort-udpPort8BitBase))
	case srcPort >= udpPort8BitBase && srcPort < udpPort8BitBase+256:
		dispatch |= NhcUDPPortSrc8
		buf = append(buf, dispatch, uint8(srcPort-udpPort8BitBase))
		buf = appendUint16BE(buf, dstPort)
	default:
		// PP=00: both full.
		dispatch |= NhcUDPPortBothFull
		buf = append(buf, dispatch)
		buf = appendUint16BE(buf, srcPort)
		buf = appendUint16BE(buf, dstPort)
	}

	// Always include checksum (C=0). Thread requires the checksum.
	buf = appendUint16BE(buf, checksum)

	return buf, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// writeIIDFromExtAddr writes an IID derived from an IEEE 802.15.4 extended
// address into dst (8 bytes). The universal/local bit (bit 1 of byte 0) is
// toggled per RFC 4291.
func writeIIDFromExtAddr(dst []byte, addr types.ExtAddress) {
	copy(dst, addr[:])
	dst[0] ^= 0x02 // toggle U/L bit
}

// writeIIDFromShort writes an IID derived from a 16-bit short address.
// The IID is 0000:00FF:FE00:XXXX where XXXX is big-endian.
func writeIIDFromShort(dst []byte, short uint16) {
	dst[0] = 0x00
	dst[1] = 0x00
	dst[2] = 0x00
	dst[3] = 0xFF
	dst[4] = 0xFE
	dst[5] = 0x00
	dst[6] = uint8(short >> 8)
	dst[7] = uint8(short)
}

// lookupContext returns the context at the given index, or nil if out of range.
func lookupContext(contexts []Context, idx uint8) *Context {
	if int(idx) < len(contexts) {
		return &contexts[idx]
	}
	return nil
}

// copyContextPrefix copies the first 8 bytes of a context prefix into
// the address prefix portion. If ctx is nil, the prefix is zeroed.
func copyContextPrefix(dst []byte, ctx *Context) {
	if ctx != nil {
		// Copy up to 8 prefix bytes (for a /64 or shorter prefix).
		bytes := int(ctx.PrefixLen+7) / 8
		if bytes > 8 {
			bytes = 8
		}
		copy(dst[:bytes], ctx.Prefix[:bytes])
	}
}

// matchIIDExtAddr checks if an IID (8 bytes) matches the one derived from
// an extended address (with U/L bit toggled).
func matchIIDExtAddr(iid []byte, addr types.ExtAddress) bool {
	var expected [8]byte
	writeIIDFromExtAddr(expected[:], addr)
	for i := 0; i < 8; i++ {
		if iid[i] != expected[i] {
			return false
		}
	}
	return true
}

// matchIIDShort checks if an IID matches the 16-bit short address pattern:
// 0000:00FF:FE00:XXXX.
func matchIIDShort(iid []byte) bool {
	return iid[0] == 0x00 && iid[1] == 0x00 &&
		iid[2] == 0x00 && iid[3] == 0xFF &&
		iid[4] == 0xFE && iid[5] == 0x00
}

// isLinkLocal returns true if the 16-byte address starts with the link-local
// prefix fe80::/64 (bytes 0-7 match fe80::).
func isLinkLocal(addr []byte) bool {
	return addr[0] == 0xFE && addr[1] == 0x80 &&
		addr[2] == 0x00 && addr[3] == 0x00 &&
		addr[4] == 0x00 && addr[5] == 0x00 &&
		addr[6] == 0x00 && addr[7] == 0x00
}

// isUnspecified returns true if the 16-byte address is all zeros.
func isUnspecified(addr []byte) bool {
	for _, b := range addr[:16] {
		if b != 0 {
			return false
		}
	}
	return true
}

// isZeros returns true if all bytes in the slice are zero.
func isZeros(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// findBestContext returns the index of the first context whose prefix matches
// the given 16-byte address, or -1 if none match.
func findBestContext(addr []byte, contexts []Context) int {
	for i, ctx := range contexts {
		if ctx.PrefixLen == 0 {
			continue
		}
		bytes := int(ctx.PrefixLen+7) / 8
		if bytes > 8 {
			bytes = 8
		}
		match := true
		for j := 0; j < bytes; j++ {
			if j == bytes-1 && ctx.PrefixLen%8 != 0 {
				// Partial byte comparison.
				mask := byte(0xFF << (8 - ctx.PrefixLen%8))
				if (addr[j] & mask) != (ctx.Prefix[j] & mask) {
					match = false
					break
				}
			} else if addr[j] != ctx.Prefix[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// appendUint16BE appends a uint16 in big-endian order.
func appendUint16BE(buf []byte, v uint16) []byte {
	return append(buf, uint8(v>>8), uint8(v))
}
