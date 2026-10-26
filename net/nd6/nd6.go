// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package nd6 implements IPv6 Neighbor Discovery (ND6) wire format types.
//
// This is a Go port of the ND6 types from OpenThread's
// src/core/net/nd6.hpp covering Router Advertisement, Neighbor
// Solicitation/Advertisement messages and their associated options.
//
// See RFC 4861, RFC 4191, RFC 8106, RFC 5175, and RFC 8781.
package nd6

import (
	"errors"

	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// ICMPv6 ND message type constants
// ---------------------------------------------------------------------------

const (
	// TypeRouterSolicit is the ICMPv6 type for Router Solicitation.
	TypeRouterSolicit uint8 = 133
	// TypeRouterAdvert is the ICMPv6 type for Router Advertisement.
	TypeRouterAdvert uint8 = 134
	// TypeNeighborSolicit is the ICMPv6 type for Neighbor Solicitation.
	TypeNeighborSolicit uint8 = 135
	// TypeNeighborAdvert is the ICMPv6 type for Neighbor Advertisement.
	TypeNeighborAdvert uint8 = 136
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

var (
	// ErrTooShort indicates the buffer is too short for the operation.
	ErrTooShort = errors.New("nd6: buffer too short")
	// ErrInvalidLength indicates an invalid option length field.
	ErrInvalidLength = errors.New("nd6: invalid length")
	// ErrInvalidPrefixLength indicates an unsupported prefix length.
	ErrInvalidPrefixLength = errors.New("nd6: invalid prefix length")
)

// ---------------------------------------------------------------------------
// Option — base ND option header (2 bytes)
// ---------------------------------------------------------------------------

// Option type constants.
const (
	OptionTypeSourceLinkLayerAddress uint8 = 1
	OptionTypeTargetLinkLayerAddress uint8 = 2
	OptionTypePrefixInfo             uint8 = 3
	OptionTypeRouteInfo              uint8 = 24
	OptionTypeRaDnsServer            uint8 = 25 //nolint:revive // Preserve the exported API spelling for existing callers.
	OptionTypeRaFlagsExtension       uint8 = 26
	OptionTypeNat64Prefix            uint8 = 38
)

const (
	// OptionHeaderSize is the size of the base option header in bytes.
	OptionHeaderSize = 2
	// OptionLengthUnit is the number of bytes per length unit.
	OptionLengthUnit = 8
)

// Option is the base ND option header (Type + Length).
type Option struct {
	Type   uint8 // Option type.
	Length uint8 // Length in units of 8 bytes.
}

// GetTotalSize returns the total option size in bytes (Length * 8).
func (o *Option) GetTotalSize() int {
	return int(o.Length) * OptionLengthUnit
}

// Marshal serializes the option header to a 2-byte array.
func (o *Option) Marshal() [2]byte {
	return [2]byte{o.Type, o.Length}
}

// Unmarshal deserializes the option header from a byte slice.
func (o *Option) Unmarshal(b []byte) error {
	if len(b) < OptionHeaderSize {
		return ErrTooShort
	}
	o.Type = b[0]
	o.Length = b[1]
	return nil
}

// ---------------------------------------------------------------------------
// RoutePreference
// ---------------------------------------------------------------------------

// RoutePreference represents the route preference value used in RIO and RA headers.
type RoutePreference uint8

const (
	// RoutePrefMedium is the medium (default) route preference.
	RoutePrefMedium RoutePreference = 0
	// RoutePrefHigh is the high route preference.
	RoutePrefHigh RoutePreference = 1
	// RoutePrefLow is the low route preference.
	RoutePrefLow RoutePreference = 3
)

// ---------------------------------------------------------------------------
// PrefixInfoOption — 32 bytes (RFC 4861 Section 4.6.2)
// ---------------------------------------------------------------------------

// PrefixInfoOptionSize is the total size of a Prefix Information Option.
const PrefixInfoOptionSize = 32

// PrefixInfoOption flag bit positions.
const (
	pioFlagOnLink     = 0x80 // L flag — bit 7
	pioFlagAutoConfig = 0x40 // A flag — bit 6
	pioFlagRouter     = 0x20 // R flag — bit 5
)

// PrefixInfoOption represents the Prefix Information Option (Type 3).
type PrefixInfoOption struct {
	header            Option
	PrefixLength      uint8
	Flags             uint8
	ValidLifetime     uint32
	PreferredLifetime uint32
	Reserved2         uint32
	Prefix            ip6.Address
}

// GetPrefixLength returns the prefix length in bits.
func (p *PrefixInfoOption) GetPrefixLength() uint8 { return p.PrefixLength }

// SetPrefixLength sets the prefix length in bits.
func (p *PrefixInfoOption) SetPrefixLength(v uint8) { p.PrefixLength = v }

// IsOnLinkFlagSet returns true if the On-Link (L) flag is set.
func (p *PrefixInfoOption) IsOnLinkFlagSet() bool { return p.Flags&pioFlagOnLink != 0 }

// SetOnLinkFlag sets the On-Link (L) flag.
func (p *PrefixInfoOption) SetOnLinkFlag() { p.Flags |= pioFlagOnLink }

// IsAutoAddrConfigFlagSet returns true if the Autonomous Address Configuration (A) flag is set.
func (p *PrefixInfoOption) IsAutoAddrConfigFlagSet() bool { return p.Flags&pioFlagAutoConfig != 0 }

// SetAutoAddrConfigFlag sets the Autonomous Address Configuration (A) flag.
func (p *PrefixInfoOption) SetAutoAddrConfigFlag() { p.Flags |= pioFlagAutoConfig }

// IsRouterFlagSet returns true if the Router (R) flag is set.
func (p *PrefixInfoOption) IsRouterFlagSet() bool { return p.Flags&pioFlagRouter != 0 }

// SetRouterFlag sets the Router (R) flag.
func (p *PrefixInfoOption) SetRouterFlag() { p.Flags |= pioFlagRouter }

// GetValidLifetime returns the valid lifetime in seconds.
func (p *PrefixInfoOption) GetValidLifetime() uint32 { return p.ValidLifetime }

// SetValidLifetime sets the valid lifetime in seconds.
func (p *PrefixInfoOption) SetValidLifetime(v uint32) { p.ValidLifetime = v }

// GetPreferredLifetime returns the preferred lifetime in seconds.
func (p *PrefixInfoOption) GetPreferredLifetime() uint32 { return p.PreferredLifetime }

// SetPreferredLifetime sets the preferred lifetime in seconds.
func (p *PrefixInfoOption) SetPreferredLifetime(v uint32) { p.PreferredLifetime = v }

// GetPrefix returns the prefix address.
func (p *PrefixInfoOption) GetPrefix() [16]byte { return p.Prefix }

// SetPrefix sets the prefix address.
func (p *PrefixInfoOption) SetPrefix(addr [16]byte) { p.Prefix = addr }

// Marshal serializes the PrefixInfoOption into a 32-byte array in network byte order.
func (p *PrefixInfoOption) Marshal() [PrefixInfoOptionSize]byte {
	var buf [PrefixInfoOptionSize]byte
	buf[0] = OptionTypePrefixInfo
	buf[1] = 4 // 32 / 8
	buf[2] = p.PrefixLength
	buf[3] = p.Flags
	encoding.BigEndianWriteUint32(p.ValidLifetime, buf[4:8])
	encoding.BigEndianWriteUint32(p.PreferredLifetime, buf[8:12])
	encoding.BigEndianWriteUint32(p.Reserved2, buf[12:16])
	copy(buf[16:32], p.Prefix[:])
	return buf
}

// Unmarshal deserializes a PrefixInfoOption from a byte slice.
func (p *PrefixInfoOption) Unmarshal(b []byte) error {
	if len(b) < PrefixInfoOptionSize {
		return ErrTooShort
	}
	p.header.Type = b[0]
	p.header.Length = b[1]
	p.PrefixLength = b[2]
	p.Flags = b[3]
	p.ValidLifetime = encoding.BigEndianReadUint32(b[4:8])
	p.PreferredLifetime = encoding.BigEndianReadUint32(b[8:12])
	p.Reserved2 = encoding.BigEndianReadUint32(b[12:16])
	copy(p.Prefix[:], b[16:32])
	return nil
}

// ---------------------------------------------------------------------------
// RouteInfoOption — variable length (RFC 4191 Section 2.3)
// ---------------------------------------------------------------------------

// RouteInfoOptionMinSize is the minimum size of a Route Information Option.
const RouteInfoOptionMinSize = 8

const (
	rioPreferenceOffset = 3
	rioPreferenceMask   = 0x18 // bits 4:3
)

// RouteInfoOption represents the Route Information Option (Type 24).
type RouteInfoOption struct {
	header        Option
	PrefixLength  uint8
	flags         uint8
	RouteLifetime uint32
	Prefix        ip6.Address
}

// GetPrefixLength returns the prefix length in bits.
func (r *RouteInfoOption) GetPrefixLength() uint8 { return r.PrefixLength }

// SetPrefixLength sets the prefix length in bits.
func (r *RouteInfoOption) SetPrefixLength(v uint8) { r.PrefixLength = v }

// GetRoutePreference returns the route preference.
func (r *RouteInfoOption) GetRoutePreference() RoutePreference {
	return RoutePreference((r.flags & rioPreferenceMask) >> rioPreferenceOffset)
}

// SetRoutePreference sets the route preference.
func (r *RouteInfoOption) SetRoutePreference(pref RoutePreference) {
	r.flags = (r.flags &^ rioPreferenceMask) | (uint8(pref) << rioPreferenceOffset)
}

// GetRouteLifetime returns the route lifetime in seconds.
func (r *RouteInfoOption) GetRouteLifetime() uint32 { return r.RouteLifetime }

// SetRouteLifetime sets the route lifetime in seconds.
func (r *RouteInfoOption) SetRouteLifetime(v uint32) { r.RouteLifetime = v }

// GetPrefix returns the prefix address.
func (r *RouteInfoOption) GetPrefix() [16]byte { return r.Prefix }

// SetPrefix sets the prefix address.
func (r *RouteInfoOption) SetPrefix(addr [16]byte) { r.Prefix = addr }

// optionLengthForPrefix returns the option Length field value (in units of 8 bytes)
// for a given prefix length in bits.
func optionLengthForPrefix(prefixLen uint8) uint8 {
	switch {
	case prefixLen == 0:
		return 1
	case prefixLen <= 64:
		return 2
	default:
		return 3
	}
}

// TotalSize returns the total option size in bytes based on the prefix length.
func (r *RouteInfoOption) TotalSize() int {
	return int(optionLengthForPrefix(r.PrefixLength)) * OptionLengthUnit
}

// prefixBytesNeeded returns the number of prefix bytes to include on the wire.
func prefixBytesNeeded(prefixLen uint8) int {
	switch {
	case prefixLen == 0:
		return 0
	case prefixLen <= 64:
		return 8
	default:
		return 16
	}
}

// Marshal serializes the RouteInfoOption into a byte slice.
func (r *RouteInfoOption) Marshal() []byte {
	optLen := optionLengthForPrefix(r.PrefixLength)
	totalSize := int(optLen) * OptionLengthUnit
	buf := make([]byte, totalSize)
	buf[0] = OptionTypeRouteInfo
	buf[1] = optLen
	buf[2] = r.PrefixLength
	buf[3] = r.flags
	encoding.BigEndianWriteUint32(r.RouteLifetime, buf[4:8])
	n := prefixBytesNeeded(r.PrefixLength)
	if n > 0 {
		copy(buf[8:8+n], r.Prefix[:n])
	}
	return buf
}

// Unmarshal deserializes a RouteInfoOption from a byte slice.
func (r *RouteInfoOption) Unmarshal(b []byte) error {
	if len(b) < RouteInfoOptionMinSize {
		return ErrTooShort
	}
	r.header.Type = b[0]
	r.header.Length = b[1]
	totalSize := int(b[1]) * OptionLengthUnit
	if len(b) < totalSize {
		return ErrTooShort
	}
	r.PrefixLength = b[2]
	r.flags = b[3]
	r.RouteLifetime = encoding.BigEndianReadUint32(b[4:8])
	r.Prefix = ip6.Address{}
	n := prefixBytesNeeded(r.PrefixLength)
	if n > 0 && totalSize >= 8+n {
		copy(r.Prefix[:n], b[8:8+n])
	}
	return nil
}

// ---------------------------------------------------------------------------
// RouterAdvertHeader — 16 bytes (RFC 4861 Section 4.2)
// ---------------------------------------------------------------------------

// RouterAdvertHeaderSize is the size of the RA-specific header after the ICMPv6 header.
// Note: the full RA ICMPv6 message includes an 8-byte ICMPv6 header before this,
// but we model only the RA-specific fields here.
const RouterAdvertHeaderSize = 16

const (
	raFlagManaged = 0x80 // M flag — bit 7
	raFlagOther   = 0x40 // O flag — bit 6
	raPrefOffset  = 3
	raPrefMask    = 0x18 // bits 4:3
)

// RouterAdvertHeader represents the RA-specific fields that follow the
// 8-byte ICMPv6 header (type=134, code=0, checksum, reserved).
//
// Wire format (16 bytes):
//
//	Byte  0:    CurHopLimit
//	Byte  1:    Flags (M|O|_|Prf|Prf|_|_|_)
//	Bytes 2-3:  RouterLifetime (big-endian, seconds)
//	Bytes 4-7:  ReachableTime (big-endian, milliseconds)
//	Bytes 8-11: RetransTimer (big-endian, milliseconds)
//	Bytes 12-15: (padding to 16 bytes — carried by options that follow)
//
// NOTE: The spec says RA header is only the first 12 bytes after the ICMPv6
// header, but we model 16 bytes to include the common case of reading full
// aligned blocks. The last 4 bytes are zero when no additional header fields
// exist.
type RouterAdvertHeader struct {
	CurHopLimit    uint8
	Flags          uint8
	RouterLifetime uint16 // seconds
	ReachableTime  uint32 // milliseconds
	RetransTimer   uint32 // milliseconds
}

// GetDefaultRouterPreference returns the default router preference from the flags.
func (h *RouterAdvertHeader) GetDefaultRouterPreference() RoutePreference {
	return RoutePreference((h.Flags & raPrefMask) >> raPrefOffset)
}

// SetDefaultRouterPreference sets the default router preference in the flags.
func (h *RouterAdvertHeader) SetDefaultRouterPreference(pref RoutePreference) {
	h.Flags = (h.Flags &^ raPrefMask) | (uint8(pref) << raPrefOffset)
}

// IsManagedAddrConfigFlagSet returns true if the Managed Address Configuration (M) flag is set.
func (h *RouterAdvertHeader) IsManagedAddrConfigFlagSet() bool { return h.Flags&raFlagManaged != 0 }

// SetManagedAddrConfigFlag sets the M flag.
func (h *RouterAdvertHeader) SetManagedAddrConfigFlag() { h.Flags |= raFlagManaged }

// IsOtherConfigFlagSet returns true if the Other Configuration (O) flag is set.
func (h *RouterAdvertHeader) IsOtherConfigFlagSet() bool { return h.Flags&raFlagOther != 0 }

// SetOtherConfigFlag sets the O flag.
func (h *RouterAdvertHeader) SetOtherConfigFlag() { h.Flags |= raFlagOther }

// GetRouterLifetime returns the router lifetime in seconds.
func (h *RouterAdvertHeader) GetRouterLifetime() uint16 { return h.RouterLifetime }

// SetRouterLifetime sets the router lifetime in seconds.
func (h *RouterAdvertHeader) SetRouterLifetime(v uint16) { h.RouterLifetime = v }

// GetReachableTime returns the reachable time in milliseconds.
func (h *RouterAdvertHeader) GetReachableTime() uint32 { return h.ReachableTime }

// SetReachableTime sets the reachable time in milliseconds.
func (h *RouterAdvertHeader) SetReachableTime(v uint32) { h.ReachableTime = v }

// GetRetransTimer returns the retransmission timer in milliseconds.
func (h *RouterAdvertHeader) GetRetransTimer() uint32 { return h.RetransTimer }

// SetRetransTimer sets the retransmission timer in milliseconds.
func (h *RouterAdvertHeader) SetRetransTimer(v uint32) { h.RetransTimer = v }

// Marshal serializes the RouterAdvertHeader into a 16-byte array in network byte order.
func (h *RouterAdvertHeader) Marshal() [RouterAdvertHeaderSize]byte {
	var buf [RouterAdvertHeaderSize]byte
	buf[0] = h.CurHopLimit
	buf[1] = h.Flags
	encoding.BigEndianWriteUint16(h.RouterLifetime, buf[2:4])
	encoding.BigEndianWriteUint32(h.ReachableTime, buf[4:8])
	encoding.BigEndianWriteUint32(h.RetransTimer, buf[8:12])
	// bytes 12-15 are zero (reserved / start of options area)
	return buf
}

// Unmarshal deserializes a RouterAdvertHeader from a byte slice.
func (h *RouterAdvertHeader) Unmarshal(b []byte) error {
	if len(b) < 12 {
		return ErrTooShort
	}
	h.CurHopLimit = b[0]
	h.Flags = b[1]
	h.RouterLifetime = encoding.BigEndianReadUint16(b[2:4])
	h.ReachableTime = encoding.BigEndianReadUint32(b[4:8])
	h.RetransTimer = encoding.BigEndianReadUint32(b[8:12])
	return nil
}

// ---------------------------------------------------------------------------
// RaMessage — higher-level RA message wrapper
// ---------------------------------------------------------------------------

// RaMessage wraps a Router Advertisement header and its raw option bytes.
type RaMessage struct {
	Header  RouterAdvertHeader
	Options []byte // raw option bytes following the RA header
}

// ParseOptions iterates through the raw option bytes and returns typed
// option descriptors.
func (m *RaMessage) ParseOptions() ([]Option, error) {
	var opts []Option
	b := m.Options
	for len(b) >= OptionHeaderSize {
		var o Option
		o.Type = b[0]
		o.Length = b[1]
		if o.Length == 0 {
			return nil, ErrInvalidLength
		}
		totalSize := o.GetTotalSize()
		if totalSize > len(b) {
			return nil, ErrTooShort
		}
		opts = append(opts, o)
		b = b[totalSize:]
	}
	return opts, nil
}

// FindPrefixInfoOptions returns all Prefix Information Options found in the
// raw option bytes.
func (m *RaMessage) FindPrefixInfoOptions() []PrefixInfoOption {
	var result []PrefixInfoOption
	b := m.Options
	for len(b) >= OptionHeaderSize {
		optType := b[0]
		optLen := b[1]
		if optLen == 0 {
			break
		}
		totalSize := int(optLen) * OptionLengthUnit
		if totalSize > len(b) {
			break
		}
		if optType == OptionTypePrefixInfo && totalSize >= PrefixInfoOptionSize {
			var pio PrefixInfoOption
			if err := pio.Unmarshal(b[:totalSize]); err == nil {
				result = append(result, pio)
			}
		}
		b = b[totalSize:]
	}
	return result
}

// FindRouteInfoOptions returns all Route Information Options found in the
// raw option bytes.
func (m *RaMessage) FindRouteInfoOptions() []RouteInfoOption {
	var result []RouteInfoOption
	b := m.Options
	for len(b) >= OptionHeaderSize {
		optType := b[0]
		optLen := b[1]
		if optLen == 0 {
			break
		}
		totalSize := int(optLen) * OptionLengthUnit
		if totalSize > len(b) {
			break
		}
		if optType == OptionTypeRouteInfo && totalSize >= RouteInfoOptionMinSize {
			var rio RouteInfoOption
			if err := rio.Unmarshal(b[:totalSize]); err == nil {
				result = append(result, rio)
			}
		}
		b = b[totalSize:]
	}
	return result
}

// Marshal serializes the RaMessage (header + options) into a byte slice.
func (m *RaMessage) Marshal() []byte {
	hdr := m.Header.Marshal()
	// Use only the first 12 bytes of the header (the meaningful fields)
	buf := make([]byte, 0, 12+len(m.Options))
	buf = append(buf, hdr[:12]...)
	buf = append(buf, m.Options...)
	return buf
}

// Unmarshal deserializes an RaMessage from a byte slice.
func (m *RaMessage) Unmarshal(b []byte) error {
	if len(b) < 12 {
		return ErrTooShort
	}
	if err := m.Header.Unmarshal(b[:12]); err != nil {
		return err
	}
	if len(b) > 12 {
		m.Options = make([]byte, len(b)-12)
		copy(m.Options, b[12:])
	} else {
		m.Options = nil
	}
	return nil
}

// ---------------------------------------------------------------------------
// NeighborSolicitHeader — 20 bytes (after ICMPv6 header)
// ---------------------------------------------------------------------------

// NeighborSolicitHeaderSize is the size of the NS-specific header.
const NeighborSolicitHeaderSize = 20

// NeighborSolicitHeader represents the Neighbor Solicitation fields after the
// ICMPv6 header. Wire format:
//
//	Bytes 0-3:   Reserved (uint32)
//	Bytes 4-19:  TargetAddress (16 bytes)
type NeighborSolicitHeader struct {
	Reserved      uint32
	TargetAddress ip6.Address
}

// GetTargetAddress returns the target address.
func (ns *NeighborSolicitHeader) GetTargetAddress() ip6.Address { return ns.TargetAddress }

// SetTargetAddress sets the target address.
func (ns *NeighborSolicitHeader) SetTargetAddress(addr ip6.Address) { ns.TargetAddress = addr }

// Marshal serializes the NeighborSolicitHeader into a 20-byte array.
func (ns *NeighborSolicitHeader) Marshal() [NeighborSolicitHeaderSize]byte {
	var buf [NeighborSolicitHeaderSize]byte
	encoding.BigEndianWriteUint32(ns.Reserved, buf[0:4])
	copy(buf[4:20], ns.TargetAddress[:])
	return buf
}

// Unmarshal deserializes a NeighborSolicitHeader from a byte slice.
func (ns *NeighborSolicitHeader) Unmarshal(b []byte) error {
	if len(b) < NeighborSolicitHeaderSize {
		return ErrTooShort
	}
	ns.Reserved = encoding.BigEndianReadUint32(b[0:4])
	copy(ns.TargetAddress[:], b[4:20])
	return nil
}

// ---------------------------------------------------------------------------
// NeighborAdvertHeader — 20 bytes (after ICMPv6 header)
// ---------------------------------------------------------------------------

// NeighborAdvertHeaderSize is the size of the NA-specific header.
const NeighborAdvertHeaderSize = 20

const (
	naFlagRouter    uint32 = 1 << 31 // R flag — bit 31
	naFlagSolicited uint32 = 1 << 30 // S flag — bit 30
	naFlagOverride  uint32 = 1 << 29 // O flag — bit 29
)

// NeighborAdvertHeader represents the Neighbor Advertisement fields after the
// ICMPv6 header. Wire format:
//
//	Bytes 0-3:   Flags (R|S|O|Reserved) — uint32 big-endian
//	Bytes 4-19:  TargetAddress (16 bytes)
type NeighborAdvertHeader struct {
	Flags         uint32
	TargetAddress ip6.Address
}

// IsRouterFlagSet returns true if the Router (R) flag is set.
func (na *NeighborAdvertHeader) IsRouterFlagSet() bool { return na.Flags&naFlagRouter != 0 }

// SetRouterFlag sets the Router (R) flag.
func (na *NeighborAdvertHeader) SetRouterFlag() { na.Flags |= naFlagRouter }

// IsSolicitedFlagSet returns true if the Solicited (S) flag is set.
func (na *NeighborAdvertHeader) IsSolicitedFlagSet() bool { return na.Flags&naFlagSolicited != 0 }

// SetSolicitedFlag sets the Solicited (S) flag.
func (na *NeighborAdvertHeader) SetSolicitedFlag() { na.Flags |= naFlagSolicited }

// IsOverrideFlagSet returns true if the Override (O) flag is set.
func (na *NeighborAdvertHeader) IsOverrideFlagSet() bool { return na.Flags&naFlagOverride != 0 }

// SetOverrideFlag sets the Override (O) flag.
func (na *NeighborAdvertHeader) SetOverrideFlag() { na.Flags |= naFlagOverride }

// GetTargetAddress returns the target address.
func (na *NeighborAdvertHeader) GetTargetAddress() ip6.Address { return na.TargetAddress }

// SetTargetAddress sets the target address.
func (na *NeighborAdvertHeader) SetTargetAddress(addr ip6.Address) { na.TargetAddress = addr }

// Marshal serializes the NeighborAdvertHeader into a 20-byte array.
func (na *NeighborAdvertHeader) Marshal() [NeighborAdvertHeaderSize]byte {
	var buf [NeighborAdvertHeaderSize]byte
	encoding.BigEndianWriteUint32(na.Flags, buf[0:4])
	copy(buf[4:20], na.TargetAddress[:])
	return buf
}

// Unmarshal deserializes a NeighborAdvertHeader from a byte slice.
func (na *NeighborAdvertHeader) Unmarshal(b []byte) error {
	if len(b) < NeighborAdvertHeaderSize {
		return ErrTooShort
	}
	na.Flags = encoding.BigEndianReadUint32(b[0:4])
	copy(na.TargetAddress[:], b[4:20])
	return nil
}

// ---------------------------------------------------------------------------
// Nat64PrefixOption — variable length (RFC 8781)
// ---------------------------------------------------------------------------

// PLC (Prefix Length Code) to prefix length mapping.
var plcToPrefixLength = [6]uint8{96, 64, 56, 48, 40, 32}

const (
	nat64LifetimeScalingUnit  = 8
	nat64ScaledLifetimeOffset = 3
	nat64PLCMask              = 0x07
)

// Nat64PrefixOption represents the NAT64 Prefix Option (Type 38, aka PREF64).
type Nat64PrefixOption struct {
	header Option
	// prefixAttr holds Scaled Lifetime (upper 13 bits) and PLC (lower 3 bits)
	// as a big-endian uint16.
	prefixAttr uint16
	Prefix     ip6.Address
}

// GetPrefixLengthCode returns the 3-bit prefix length code.
func (n *Nat64PrefixOption) GetPrefixLengthCode() uint8 {
	return uint8(n.prefixAttr & nat64PLCMask)
}

// GetPrefixLength returns the actual prefix length in bits derived from the PLC.
// Returns 0 if the PLC is invalid (>= 6).
func (n *Nat64PrefixOption) GetPrefixLength() uint8 {
	plc := n.GetPrefixLengthCode()
	if int(plc) >= len(plcToPrefixLength) {
		return 0
	}
	return plcToPrefixLength[plc]
}

// SetPrefixLength sets the prefix length by encoding it as a PLC.
// Returns ErrInvalidPrefixLength if the length is not a valid NAT64 prefix length.
func (n *Nat64PrefixOption) SetPrefixLength(length uint8) error {
	for plc, plen := range plcToPrefixLength {
		if plen == length {
			n.prefixAttr = (n.prefixAttr &^ nat64PLCMask) | uint16(plc)
			return nil
		}
	}
	return ErrInvalidPrefixLength
}

// GetLifetime returns the NAT64 prefix lifetime in seconds.
func (n *Nat64PrefixOption) GetLifetime() uint16 {
	return uint16(n.prefixAttr>>nat64ScaledLifetimeOffset) * nat64LifetimeScalingUnit
}

// SetLifetime sets the NAT64 prefix lifetime in seconds.
// The value is divided by 8 and stored in the upper 13 bits.
func (n *Nat64PrefixOption) SetLifetime(seconds uint16) {
	scaled := seconds / nat64LifetimeScalingUnit
	n.prefixAttr = (n.prefixAttr & nat64PLCMask) | (uint16(scaled) << nat64ScaledLifetimeOffset)
}

// GetPrefix returns the prefix address (zero-padded to 16 bytes).
func (n *Nat64PrefixOption) GetPrefix() [16]byte { return n.Prefix }

// SetPrefix sets the prefix address.
func (n *Nat64PrefixOption) SetPrefix(addr [16]byte) { n.Prefix = addr }

// Marshal serializes the Nat64PrefixOption. The option is always 16 bytes
// (header=2 + prefixAttr=2 + 12 prefix bytes), with Length field = 2.
func (n *Nat64PrefixOption) Marshal() []byte {
	buf := make([]byte, 16)
	buf[0] = OptionTypeNat64Prefix
	buf[1] = 2 // 16 / 8 = 2
	encoding.BigEndianWriteUint16(n.prefixAttr, buf[2:4])
	copy(buf[4:16], n.Prefix[:12])
	return buf
}

// Unmarshal deserializes a Nat64PrefixOption from a byte slice.
func (n *Nat64PrefixOption) Unmarshal(b []byte) error {
	if len(b) < 4 {
		return ErrTooShort
	}
	n.header.Type = b[0]
	n.header.Length = b[1]
	totalSize := int(b[1]) * OptionLengthUnit
	if len(b) < totalSize {
		return ErrTooShort
	}
	n.prefixAttr = encoding.BigEndianReadUint16(b[2:4])
	n.Prefix = ip6.Address{}
	// Copy up to 12 bytes of prefix.
	prefixBytes := totalSize - 4
	if prefixBytes > 12 {
		prefixBytes = 12
	}
	if prefixBytes > 0 {
		copy(n.Prefix[:prefixBytes], b[4:4+prefixBytes])
	}
	return nil
}

// ---------------------------------------------------------------------------
// RaDnsServerOption — variable length (RFC 8106 RDNSS)
// ---------------------------------------------------------------------------

// RaDnsServerOption represents the Recursive DNS Server Option (Type 25).
type RaDnsServerOption struct { //nolint:revive // Preserve the exported API spelling for existing callers.
	header    Option
	Reserved  uint16
	Lifetime  uint32
	Addresses []ip6.Address
}

// GetLifetime returns the RDNSS lifetime in seconds.
func (r *RaDnsServerOption) GetLifetime() uint32 { return r.Lifetime }

// SetLifetime sets the RDNSS lifetime in seconds.
func (r *RaDnsServerOption) SetLifetime(v uint32) { r.Lifetime = v }

// GetAddresses returns the list of DNS server IPv6 addresses.
func (r *RaDnsServerOption) GetAddresses() [][16]byte {
	result := make([][16]byte, len(r.Addresses))
	for i, a := range r.Addresses {
		result[i] = a
	}
	return result
}

// Marshal serializes the RaDnsServerOption into a byte slice.
func (r *RaDnsServerOption) Marshal() []byte {
	// header(2) + reserved(2) + lifetime(4) + addresses(n*16)
	payloadSize := 8 + len(r.Addresses)*16
	// Length in units of 8 bytes
	optLen := uint8(payloadSize / OptionLengthUnit)
	if payloadSize%OptionLengthUnit != 0 {
		optLen++
	}
	totalSize := int(optLen) * OptionLengthUnit
	buf := make([]byte, totalSize)
	buf[0] = OptionTypeRaDnsServer
	buf[1] = optLen
	encoding.BigEndianWriteUint16(r.Reserved, buf[2:4])
	encoding.BigEndianWriteUint32(r.Lifetime, buf[4:8])
	for i, addr := range r.Addresses {
		copy(buf[8+i*16:8+(i+1)*16], addr[:])
	}
	return buf
}

// Unmarshal deserializes a RaDnsServerOption from a byte slice.
func (r *RaDnsServerOption) Unmarshal(b []byte) error {
	if len(b) < 8 {
		return ErrTooShort
	}
	r.header.Type = b[0]
	r.header.Length = b[1]
	totalSize := int(b[1]) * OptionLengthUnit
	if len(b) < totalSize {
		return ErrTooShort
	}
	r.Reserved = encoding.BigEndianReadUint16(b[2:4])
	r.Lifetime = encoding.BigEndianReadUint32(b[4:8])

	// Each address is 16 bytes; addresses start at offset 8.
	addrBytes := totalSize - 8
	numAddrs := addrBytes / 16
	r.Addresses = make([]ip6.Address, numAddrs)
	for i := 0; i < numAddrs; i++ {
		copy(r.Addresses[i][:], b[8+i*16:8+(i+1)*16])
	}
	return nil
}

// ---------------------------------------------------------------------------
// RaFlagsExtOption — 8 bytes (RFC 5175)
// ---------------------------------------------------------------------------

// RaFlagsExtOptionSize is the total size of the RA Flags Extension Option.
const RaFlagsExtOptionSize = 8

// RaFlagsExtOption represents the RA Flags Extension Option (Type 26).
type RaFlagsExtOption struct {
	header Option
	Flags  [6]byte
}

// IsFlagSet returns true if the flag at the given bit position is set.
// Bit 0 is the MSB of Flags[0].
func (f *RaFlagsExtOption) IsFlagSet(bit uint) bool {
	if bit >= 48 {
		return false
	}
	byteIdx := bit / 8
	bitIdx := 7 - (bit % 8)
	return f.Flags[byteIdx]&(1<<bitIdx) != 0
}

// SetFlag sets the flag at the given bit position.
func (f *RaFlagsExtOption) SetFlag(bit uint) {
	if bit >= 48 {
		return
	}
	byteIdx := bit / 8
	bitIdx := 7 - (bit % 8)
	f.Flags[byteIdx] |= 1 << bitIdx
}

// ClearFlag clears the flag at the given bit position.
func (f *RaFlagsExtOption) ClearFlag(bit uint) {
	if bit >= 48 {
		return
	}
	byteIdx := bit / 8
	bitIdx := 7 - (bit % 8)
	f.Flags[byteIdx] &^= 1 << bitIdx
}

// Marshal serializes the RaFlagsExtOption into an 8-byte array.
func (f *RaFlagsExtOption) Marshal() [RaFlagsExtOptionSize]byte {
	var buf [RaFlagsExtOptionSize]byte
	buf[0] = OptionTypeRaFlagsExtension
	buf[1] = 1 // 8 / 8 = 1
	copy(buf[2:8], f.Flags[:])
	return buf
}

// Unmarshal deserializes a RaFlagsExtOption from a byte slice.
func (f *RaFlagsExtOption) Unmarshal(b []byte) error {
	if len(b) < RaFlagsExtOptionSize {
		return ErrTooShort
	}
	f.header.Type = b[0]
	f.header.Length = b[1]
	copy(f.Flags[:], b[2:8])
	return nil
}
