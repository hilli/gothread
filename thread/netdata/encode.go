// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package netdata

import "github.com/hilli/gothread/encoding"

// ---------------------------------------------------------------------------
// TLV Header encoding
// ---------------------------------------------------------------------------

// EncodeTLVHeader writes a 2-byte TLV header into buf and returns the number
// of bytes written (always TLVHeaderSize). The caller must ensure buf has at
// least TLVHeaderSize bytes available.
func EncodeTLVHeader(buf []byte, typ TLVType, stable bool, length uint8) {
	b0 := byte(typ) << 1
	if stable {
		b0 |= 0x01
	}
	buf[0] = b0
	buf[1] = length
}

// AppendTLVHeader appends a 2-byte TLV header and returns the extended slice.
func AppendTLVHeader(buf []byte, typ TLVType, stable bool, length uint8) []byte {
	var hdr [TLVHeaderSize]byte
	EncodeTLVHeader(hdr[:], typ, stable, length)
	return append(buf, hdr[:]...)
}

// ---------------------------------------------------------------------------
// HasRouteEntry encoding
// ---------------------------------------------------------------------------

// EncodeHasRouteEntry writes a HasRouteEntry into buf (must be >= HasRouteEntrySize).
func EncodeHasRouteEntry(buf []byte, e HasRouteEntry) {
	encoding.BigEndianWriteUint16(e.RLOC16, buf[0:2])
	var flags byte
	flags = RoutePreferenceToValue(e.Preference) << 6
	if e.NAT64 {
		flags |= 0x20
	}
	if e.AdvPio {
		flags |= 0x10
	}
	buf[2] = flags
}

// AppendHasRouteEntry appends a serialized HasRouteEntry and returns the
// extended slice.
func AppendHasRouteEntry(buf []byte, e HasRouteEntry) []byte {
	var b [HasRouteEntrySize]byte
	EncodeHasRouteEntry(b[:], e)
	return append(buf, b[:]...)
}

// ---------------------------------------------------------------------------
// BorderRouterEntry encoding
// ---------------------------------------------------------------------------

// EncodeBorderRouterEntry writes a BorderRouterEntry into buf (must be >=
// BorderRouterEntrySize).
func EncodeBorderRouterEntry(buf []byte, e BorderRouterEntry) {
	encoding.BigEndianWriteUint16(e.RLOC16, buf[0:2])
	var flags uint16
	flags = uint16(RoutePreferenceToValue(e.Preference)) << 14
	if e.Preferred {
		flags |= 1 << 13
	}
	if e.SLAAC {
		flags |= 1 << 12
	}
	if e.DHCP {
		flags |= 1 << 11
	}
	if e.Configure {
		flags |= 1 << 10
	}
	if e.DefaultRoute {
		flags |= 1 << 9
	}
	if e.OnMesh {
		flags |= 1 << 8
	}
	if e.NdDNS {
		flags |= 1 << 7
	}
	if e.Dp {
		flags |= 1 << 6
	}
	encoding.BigEndianWriteUint16(flags, buf[2:4])
}

// AppendBorderRouterEntry appends a serialized BorderRouterEntry and returns
// the extended slice.
func AppendBorderRouterEntry(buf []byte, e BorderRouterEntry) []byte {
	var b [BorderRouterEntrySize]byte
	EncodeBorderRouterEntry(b[:], e)
	return append(buf, b[:]...)
}

// ---------------------------------------------------------------------------
// ContextInfo encoding
// ---------------------------------------------------------------------------

// ContextValueSize is the wire size of a Context TLV value.
const ContextValueSize = 2

// EncodeContextValue writes a ContextInfo into buf (must be >= 2 bytes).
func EncodeContextValue(buf []byte, c ContextInfo) {
	var flags byte
	flags = c.ContextID & 0x0f
	if c.Compress {
		flags |= 0x10
	}
	buf[0] = flags
	buf[1] = c.ContextLength
}

// AppendContextValue appends a serialized ContextInfo value and returns the
// extended slice.
func AppendContextValue(buf []byte, c ContextInfo) []byte {
	var b [ContextValueSize]byte
	EncodeContextValue(b[:], c)
	return append(buf, b[:]...)
}

// ---------------------------------------------------------------------------
// ServerEntry encoding
// ---------------------------------------------------------------------------

// EncodeServerValue writes a ServerEntry into buf (must be >= 2+len(ServerData)).
func EncodeServerValue(buf []byte, s ServerEntry) {
	encoding.BigEndianWriteUint16(s.Server16, buf[0:2])
	copy(buf[2:], s.ServerData)
}

// AppendServerValue appends a serialized ServerEntry value and returns the
// extended slice.
func AppendServerValue(buf []byte, s ServerEntry) []byte {
	b := make([]byte, 2+len(s.ServerData))
	EncodeServerValue(b, s)
	return append(buf, b...)
}

// ---------------------------------------------------------------------------
// ServiceTLV value encoding
// ---------------------------------------------------------------------------

// ServiceValueSize returns the wire size of a Service TLV value (excluding
// TLV header), not counting sub-TLVs.
func ServiceValueSize(info ServiceTLVInfo) int {
	size := 1 // flagsServiceID byte
	if info.EnterpriseNumber != ThreadEnterpriseNumber {
		size += 4 // enterprise number
	}
	size += 1 + len(info.ServiceData) // serviceDataLen + serviceData
	size += len(info.SubTLVsData)
	return size
}

// AppendServiceValue appends a serialized Service TLV value (including any
// sub-TLV data carried in info.SubTLVsData) and returns the extended slice.
func AppendServiceValue(buf []byte, info ServiceTLVInfo) []byte {
	isThread := info.EnterpriseNumber == ThreadEnterpriseNumber
	var flagsServiceID byte
	flagsServiceID = info.ServiceID & 0x0f
	if isThread {
		flagsServiceID |= 0x80
	}
	buf = append(buf, flagsServiceID)

	if !isThread {
		var eb [4]byte
		encoding.BigEndianWriteUint32(info.EnterpriseNumber, eb[:])
		buf = append(buf, eb[:]...)
	}

	buf = append(buf, byte(len(info.ServiceData)))
	buf = append(buf, info.ServiceData...)
	buf = append(buf, info.SubTLVsData...)
	return buf
}

// ---------------------------------------------------------------------------
// PrefixTLV value encoding
// ---------------------------------------------------------------------------

// PrefixValueSize returns the wire size of a Prefix TLV value (excluding TLV
// header), not counting sub-TLVs.
func PrefixValueSize(info PrefixTLVInfo) int {
	return 2 + prefixByteSize(info.Prefix.GetLength()) + len(info.SubTLVsData)
}

// AppendPrefixValue appends a serialized Prefix TLV value (including any
// sub-TLV data carried in info.SubTLVsData) and returns the extended slice.
func AppendPrefixValue(buf []byte, info PrefixTLVInfo) []byte {
	pLen := info.Prefix.GetLength()
	pbs := prefixByteSize(pLen)
	buf = append(buf, info.DomainID, pLen)
	pBytes := info.Prefix.GetBytes()
	buf = append(buf, pBytes[:pbs]...)
	buf = append(buf, info.SubTLVsData...)
	return buf
}

// ---------------------------------------------------------------------------
// Full TLV encoding helpers
// ---------------------------------------------------------------------------

// AppendTLV appends a complete TLV (header + value) and returns the extended
// slice.
func AppendTLV(buf []byte, typ TLVType, stable bool, value []byte) []byte {
	buf = AppendTLVHeader(buf, typ, stable, uint8(len(value)))
	return append(buf, value...)
}

// AppendHasRouteTLV appends a complete HasRoute sub-TLV containing the given
// entries and returns the extended slice.
func AppendHasRouteTLV(buf []byte, stable bool, entries []HasRouteEntry) []byte {
	valueLen := len(entries) * HasRouteEntrySize
	buf = AppendTLVHeader(buf, TLVTypeHasRoute, stable, uint8(valueLen))
	for _, e := range entries {
		buf = AppendHasRouteEntry(buf, e)
	}
	return buf
}

// AppendBorderRouterTLV appends a complete BorderRouter sub-TLV containing
// the given entries and returns the extended slice.
func AppendBorderRouterTLV(buf []byte, stable bool, entries []BorderRouterEntry) []byte {
	valueLen := len(entries) * BorderRouterEntrySize
	buf = AppendTLVHeader(buf, TLVTypeBorderRouter, stable, uint8(valueLen))
	for _, e := range entries {
		buf = AppendBorderRouterEntry(buf, e)
	}
	return buf
}

// AppendContextTLV appends a complete Context sub-TLV and returns the extended
// slice.
func AppendContextTLV(buf []byte, stable bool, c ContextInfo) []byte {
	buf = AppendTLVHeader(buf, TLVTypeContext, stable, ContextValueSize)
	return AppendContextValue(buf, c)
}

// AppendServerTLV appends a complete Server sub-TLV and returns the extended
// slice.
func AppendServerTLV(buf []byte, stable bool, s ServerEntry) []byte {
	valueLen := uint8(2 + len(s.ServerData))
	buf = AppendTLVHeader(buf, TLVTypeServer, stable, valueLen)
	return AppendServerValue(buf, s)
}
