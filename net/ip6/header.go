// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// IPv6 header types for Thread networks.
//
// This is a Go port of the header handling in OpenThread's
// src/core/net/ip6_headers.hpp and src/core/net/ip6_headers.cpp.

package ip6

import (
	"github.com/hilli/gothread/encoding"
)

// ---------------------------------------------------------------------------
// Protocol number constants
// ---------------------------------------------------------------------------

const (
	// ProtoHopOpts is the IPv6 Hop-by-Hop Options protocol number.
	ProtoHopOpts uint8 = 0
	// ProtoTCP is the TCP protocol number.
	ProtoTCP uint8 = 6
	// ProtoUDP is the UDP protocol number.
	ProtoUDP uint8 = 17
	// ProtoIPv6 is the IPv6 encapsulation protocol number.
	ProtoIPv6 uint8 = 41
	// ProtoRouting is the IPv6 Routing Header protocol number.
	ProtoRouting uint8 = 43
	// ProtoFragment is the IPv6 Fragment Header protocol number.
	ProtoFragment uint8 = 44
	// ProtoICMPv6 is the ICMPv6 protocol number.
	ProtoICMPv6 uint8 = 58
	// ProtoNone is the IPv6 No Next Header protocol number.
	ProtoNone uint8 = 59
	// ProtoDstOpts is the IPv6 Destination Options protocol number.
	ProtoDstOpts uint8 = 60
)

// ---------------------------------------------------------------------------
// DSCP and ECN types
// ---------------------------------------------------------------------------

// Dscp represents a 6-bit Differentiated Services Code Point value (0-63).
type Dscp uint8

const (
	// DscpCs0 is the Class Selector 0 DSCP value (best effort).
	DscpCs0 Dscp = 0
	// DscpCs1 is the Class Selector 1 DSCP value.
	DscpCs1 Dscp = 8
	// DscpCs2 is the Class Selector 2 DSCP value.
	DscpCs2 Dscp = 16
	// DscpCs3 is the Class Selector 3 DSCP value.
	DscpCs3 Dscp = 24
	// DscpCs4 is the Class Selector 4 DSCP value.
	DscpCs4 Dscp = 32
	// DscpCs5 is the Class Selector 5 DSCP value.
	DscpCs5 Dscp = 40
	// DscpCs6 is the Class Selector 6 DSCP value.
	DscpCs6 Dscp = 48
	// DscpCs7 is the Class Selector 7 DSCP value.
	DscpCs7 Dscp = 56

	// DscpTmfNetPriority is a Thread-specific DSCP value for network-priority traffic.
	DscpTmfNetPriority Dscp = 7
	// DscpTmfNormalPriority is a Thread-specific DSCP value for normal-priority traffic.
	DscpTmfNormalPriority Dscp = 15
	// DscpTmfLowPriority is a Thread-specific DSCP value for low-priority traffic.
	DscpTmfLowPriority Dscp = 23
)

// Ecn represents a 2-bit Explicit Congestion Notification value.
type Ecn uint8

const (
	// EcnNotCapable indicates the endpoint is not ECN-capable.
	EcnNotCapable Ecn = 0
	// EcnCapable0 indicates ECN-Capable Transport (ECT(0)).
	EcnCapable0 Ecn = 1
	// EcnCapable1 indicates ECN-Capable Transport (ECT(1)).
	EcnCapable1 Ecn = 2
	// EcnMarked indicates Congestion Experienced (CE).
	EcnMarked Ecn = 3
)

// ---------------------------------------------------------------------------
// Header (IPv6 fixed header, 40 bytes)
// ---------------------------------------------------------------------------

// HeaderSize is the size of an IPv6 fixed header in bytes.
const HeaderSize = 40

// Header represents a 40-byte IPv6 fixed header stored in network byte order.
//
// Wire layout (big-endian):
//
//	Offset  0: Version(4) | TrafficClass(8) | FlowLabel(20) — 4 bytes
//	Offset  4: PayloadLength — 2 bytes
//	Offset  6: NextHeader — 1 byte
//	Offset  7: HopLimit — 1 byte
//	Offset  8: Source Address — 16 bytes
//	Offset 24: Destination Address — 16 bytes
type Header struct {
	data [HeaderSize]byte
}

// Byte offsets within the header.
const (
	headerOffsetVerTcFlow = 0
	headerOffsetPayload   = 4
	headerOffsetNextHdr   = 6
	headerOffsetHopLimit  = 7
	headerOffsetSource    = 8
	headerOffsetDest      = 24
)

// HeaderFromBytes creates a Header from a 40-byte array. This is the inverse
// of the wire representation and can be used to wrap the output of
// lowpan.DecompressHeader directly.
func HeaderFromBytes(data [HeaderSize]byte) Header {
	return Header{data: data}
}

// Bytes returns a copy of the raw 40-byte header.
func (h *Header) Bytes() [HeaderSize]byte {
	return h.data
}

// GetVersion returns the 4-bit IP version field (normally 6).
func (h *Header) GetVersion() uint8 {
	return h.data[0] >> 4
}

// GetTrafficClass returns the 8-bit traffic class (DSCP + ECN).
//
// Bit layout of the first two bytes:
//
//	byte[0]: |Version(4)|TC_hi(4)|
//	byte[1]: |TC_lo(4)|FlowLabel_hi(4)|
//
// TrafficClass = (byte[0] & 0x0f) << 4 | byte[1] >> 4
func (h *Header) GetTrafficClass() uint8 {
	return (h.data[0]&0x0f)<<4 | h.data[1]>>4
}

// SetTrafficClass sets the 8-bit traffic class, preserving Version and
// FlowLabel bits.
func (h *Header) SetTrafficClass(tc uint8) {
	h.data[0] = (h.data[0] & 0xf0) | (tc >> 4)
	h.data[1] = (tc << 4) | (h.data[1] & 0x0f)
}

// GetDscp returns the 6-bit DSCP value from the traffic class.
func (h *Header) GetDscp() Dscp {
	return Dscp(h.GetTrafficClass() >> 2)
}

// SetDscp sets the 6-bit DSCP value, preserving the ECN bits.
func (h *Header) SetDscp(dscp Dscp) {
	tc := (uint8(dscp) << 2) | (h.GetTrafficClass() & 0x03)
	h.SetTrafficClass(tc)
}

// GetEcn returns the 2-bit ECN value from the traffic class.
func (h *Header) GetEcn() Ecn {
	return Ecn(h.GetTrafficClass() & 0x03)
}

// SetEcn sets the 2-bit ECN value, preserving the DSCP bits.
func (h *Header) SetEcn(ecn Ecn) {
	tc := (h.GetTrafficClass() & 0xfc) | uint8(ecn)
	h.SetTrafficClass(tc)
}

// GetFlowLabel returns the 20-bit flow label.
//
// FlowLabel = (byte[1] & 0x0f) << 16 | byte[2] << 8 | byte[3]
func (h *Header) GetFlowLabel() uint32 {
	return uint32(h.data[1]&0x0f)<<16 |
		uint32(h.data[2])<<8 |
		uint32(h.data[3])
}

// SetFlowLabel sets the 20-bit flow label, preserving the Version and
// TrafficClass bits in byte[0] and the upper nibble of byte[1].
func (h *Header) SetFlowLabel(flow uint32) {
	h.data[1] = (h.data[1] & 0xf0) | uint8((flow>>16)&0x0f)
	h.data[2] = uint8(flow >> 8)
	h.data[3] = uint8(flow)
}

// GetPayloadLength returns the 16-bit payload length.
func (h *Header) GetPayloadLength() uint16 {
	return encoding.BigEndianReadUint16(h.data[headerOffsetPayload:])
}

// SetPayloadLength sets the 16-bit payload length.
func (h *Header) SetPayloadLength(length uint16) {
	encoding.BigEndianWriteUint16(length, h.data[headerOffsetPayload:])
}

// GetNextHeader returns the next header protocol number.
func (h *Header) GetNextHeader() uint8 {
	return h.data[headerOffsetNextHdr]
}

// SetNextHeader sets the next header protocol number.
func (h *Header) SetNextHeader(nh uint8) {
	h.data[headerOffsetNextHdr] = nh
}

// GetHopLimit returns the hop limit.
func (h *Header) GetHopLimit() uint8 {
	return h.data[headerOffsetHopLimit]
}

// SetHopLimit sets the hop limit.
func (h *Header) SetHopLimit(hl uint8) {
	h.data[headerOffsetHopLimit] = hl
}

// GetSource returns the 128-bit source address.
func (h *Header) GetSource() Address {
	var addr Address
	copy(addr[:], h.data[headerOffsetSource:headerOffsetSource+16])
	return addr
}

// SetSource sets the 128-bit source address.
func (h *Header) SetSource(addr Address) {
	copy(h.data[headerOffsetSource:], addr[:])
}

// GetDestination returns the 128-bit destination address.
func (h *Header) GetDestination() Address {
	var addr Address
	copy(addr[:], h.data[headerOffsetDest:headerOffsetDest+16])
	return addr
}

// SetDestination sets the 128-bit destination address.
func (h *Header) SetDestination(addr Address) {
	copy(h.data[headerOffsetDest:], addr[:])
}

// NewHeader constructs an IPv6 header with the given parameters.
// The version is set to 6, traffic class and flow label to 0, and
// payload length to the given value.
func NewHeader(src, dst Address, nextHeader, hopLimit uint8, payloadLength uint16) Header {
	var h Header
	// Version = 6
	h.data[0] = 0x60
	h.SetNextHeader(nextHeader)
	h.SetHopLimit(hopLimit)
	h.SetPayloadLength(payloadLength)
	h.SetSource(src)
	h.SetDestination(dst)
	return h
}

// ---------------------------------------------------------------------------
// ExtensionHeader (generic IPv6 extension header)
// ---------------------------------------------------------------------------

// ExtensionHeader represents a generic IPv6 extension header.
//
// Wire layout (2 bytes minimum):
//
//	byte[0]: NextHeader
//	byte[1]: Length in 8-byte units, excluding the first 8 bytes
type ExtensionHeader struct {
	data [2]byte
}

// GetNextHeader returns the next header protocol number.
func (e *ExtensionHeader) GetNextHeader() uint8 {
	return e.data[0]
}

// SetNextHeader sets the next header protocol number.
func (e *ExtensionHeader) SetNextHeader(nh uint8) {
	e.data[0] = nh
}

// GetLength returns the total extension header length in bytes.
// The wire field stores (totalLength/8 - 1), so total = 8 * (data[1] + 1).
func (e *ExtensionHeader) GetLength() uint16 {
	return 8 * (uint16(e.data[1]) + 1)
}

// SetLength sets the length field in 8-byte units (excluding the first 8
// bytes). The value stored is the raw unit count, so total bytes =
// 8 * (lenInUnits + 1).
func (e *ExtensionHeader) SetLength(lenInUnits uint8) {
	e.data[1] = lenInUnits
}

// ---------------------------------------------------------------------------
// HopByHopHeader
// ---------------------------------------------------------------------------

// HopByHopHeader is an alias for ExtensionHeader representing the
// Hop-by-Hop Options header (Next Header = 0).
type HopByHopHeader = ExtensionHeader

// ---------------------------------------------------------------------------
// OptionHeader
// ---------------------------------------------------------------------------

// Option type constants.
const (
	OptionPad1 uint8 = 0x00
	OptionPadN uint8 = 0x01
)

// Option action mask and values (top 2 bits of the option type).
const (
	OptionActionMask                uint8 = 0xC0
	OptionActionSkip                uint8 = 0x00
	OptionActionDiscard             uint8 = 0x40
	OptionActionForceICMP           uint8 = 0x80
	OptionActionForceICMPIfNotMcast uint8 = 0xC0
)

// OptionHeader represents a generic TLV option within an IPv6 extension
// header.
type OptionHeader struct {
	Type   uint8
	Length uint8
}

// GetAction returns the action bits (top 2 bits) of the option type.
func (o *OptionHeader) GetAction() uint8 {
	return o.Type & OptionActionMask
}

// ---------------------------------------------------------------------------
// FragmentHeader (8 bytes)
// ---------------------------------------------------------------------------

// FragmentHeaderSize is the size of an IPv6 fragment header in bytes.
const FragmentHeaderSize = 8

// FragmentHeader represents an IPv6 Fragment extension header.
//
// Wire layout (8 bytes, big-endian):
//
//	byte[0]:   NextHeader
//	byte[1]:   Reserved
//	byte[2-3]: FragmentOffset(13) | Res(2) | M(1)
//	byte[4-7]: Identification
type FragmentHeader struct {
	data [FragmentHeaderSize]byte
}

// GetNextHeader returns the next header protocol number.
func (f *FragmentHeader) GetNextHeader() uint8 {
	return f.data[0]
}

// GetOffset returns the 13-bit fragment offset (in 8-octet units).
func (f *FragmentHeader) GetOffset() uint16 {
	return encoding.BigEndianReadUint16(f.data[2:4]) >> 3
}

// IsMoreFlagSet returns true if the More Fragments (M) flag is set.
func (f *FragmentHeader) IsMoreFlagSet() bool {
	return f.data[3]&0x01 != 0
}

// GetIdentification returns the 32-bit fragment identification value.
func (f *FragmentHeader) GetIdentification() uint32 {
	return encoding.BigEndianReadUint32(f.data[4:8])
}
