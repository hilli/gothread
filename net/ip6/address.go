// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package ip6 implements IPv6 address types and parsing for Thread networks.
//
// This is a Go port of the address handling in OpenThread's
// src/core/net/ip6_address.hpp and src/core/net/ip6_address.cpp.
package ip6

import (
	"fmt"
	"strings"

	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

// Address is a 128-bit IPv6 address stored in network byte order.
type Address [16]byte

// AddressFromString parses an IPv6 address string. It handles full addresses,
// :: compression, mixed-case hex, and embedded IPv4 suffixes.
func AddressFromString(s string) (Address, error) {
	var addr Address
	if len(s) == 0 {
		return addr, errors.ErrParse
	}

	// Check for exactly one :: (double-colon). More than one is invalid.
	dcIdx := strings.Index(s, "::")
	if dcIdx >= 0 && strings.Contains(s[dcIdx+2:], "::") {
		return addr, errors.ErrParse
	}

	// Split into head and tail around ::.
	var head, tail string
	hasDoubleColon := dcIdx >= 0
	if hasDoubleColon {
		head = s[:dcIdx]
		tail = s[dcIdx+2:]
	} else {
		head = s
		tail = ""
	}

	// Parse groups from head and tail.
	var headGroups []string
	var tailGroups []string
	if head != "" {
		headGroups = strings.Split(head, ":")
	}
	if tail != "" {
		tailGroups = strings.Split(tail, ":")
	}

	// Check for embedded IPv4 in the last group of tail (or head if no ::).
	var ipv4Bytes [4]byte
	hasIPv4 := false
	var lastGroups *[]string
	if len(tailGroups) > 0 {
		lastGroups = &tailGroups
	} else {
		lastGroups = &headGroups
	}
	if lastGroups != nil && len(*lastGroups) > 0 {
		lastGroup := (*lastGroups)[len(*lastGroups)-1]
		if strings.Contains(lastGroup, ".") {
			b, err := parseIPv4(lastGroup)
			if err != nil {
				return addr, errors.ErrParse
			}
			ipv4Bytes = b
			hasIPv4 = true
			// Remove the IPv4 group from the list.
			*lastGroups = (*lastGroups)[:len(*lastGroups)-1]
		}
	}

	// Count total groups (each IPv4 address consumes 2 groups worth).
	totalGroups := len(headGroups) + len(tailGroups)
	if hasIPv4 {
		totalGroups += 2
	}

	maxGroups := 8
	if hasDoubleColon {
		if totalGroups > maxGroups {
			return addr, errors.ErrParse
		}
	} else {
		if totalGroups != maxGroups {
			return addr, errors.ErrParse
		}
	}

	// Fill from head.
	idx := 0
	for _, g := range headGroups {
		v, err := parseHexGroup(g)
		if err != nil {
			return addr, errors.ErrParse
		}
		addr[idx] = byte(v >> 8)
		addr[idx+1] = byte(v)
		idx += 2
	}

	// Skip over the zero-filled gap for ::.
	if hasDoubleColon {
		zeroGroups := maxGroups - totalGroups
		idx += zeroGroups * 2
	}

	// Fill from tail.
	for _, g := range tailGroups {
		v, err := parseHexGroup(g)
		if err != nil {
			return addr, errors.ErrParse
		}
		addr[idx] = byte(v >> 8)
		addr[idx+1] = byte(v)
		idx += 2
	}

	// Fill IPv4 bytes at the end.
	if hasIPv4 {
		addr[idx] = ipv4Bytes[0]
		addr[idx+1] = ipv4Bytes[1]
		addr[idx+2] = ipv4Bytes[2]
		addr[idx+3] = ipv4Bytes[3]
	}

	return addr, nil
}

// parseHexGroup parses a 1-4 digit hex group, returning 0..65535.
func parseHexGroup(s string) (uint16, error) {
	if len(s) == 0 || len(s) > 4 {
		return 0, errors.ErrParse
	}
	var v uint16
	for _, c := range s {
		d, ok := hexVal(byte(c))
		if !ok {
			return 0, errors.ErrParse
		}
		v = v<<4 | uint16(d)
	}
	return v, nil
}

// hexVal returns the numeric value of a hex digit.
func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// parseIPv4 parses a dotted-decimal IPv4 address.
func parseIPv4(s string) ([4]byte, error) {
	var result [4]byte
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return result, errors.ErrParse
	}
	for i, p := range parts {
		if len(p) == 0 {
			return result, errors.ErrParse
		}
		var v int
		for _, c := range p {
			if c < '0' || c > '9' {
				return result, errors.ErrParse
			}
			v = v*10 + int(c-'0')
			if v > 255 {
				return result, errors.ErrParse
			}
		}
		result[i] = byte(v)
	}
	return result, nil
}

// ToString returns the address as a string in the form "x:x:x:x:x:x:x:x"
// with no :: compression and no leading zeros per group, matching OpenThread's
// Address::ToString behaviour.
func (a Address) ToString() string {
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
		uint16(a[0])<<8|uint16(a[1]),
		uint16(a[2])<<8|uint16(a[3]),
		uint16(a[4])<<8|uint16(a[5]),
		uint16(a[6])<<8|uint16(a[7]),
		uint16(a[8])<<8|uint16(a[9]),
		uint16(a[10])<<8|uint16(a[11]),
		uint16(a[12])<<8|uint16(a[13]),
		uint16(a[14])<<8|uint16(a[15]),
	)
}

// IsUnspecified returns true if the address is the all-zeros address (::).
func (a Address) IsUnspecified() bool {
	return a == Address{}
}

// IsLoopback returns true if the address is ::1.
func (a Address) IsLoopback() bool {
	var lb Address
	lb[15] = 1
	return a == lb
}

// IsMulticast returns true if the address is in the ff00::/8 range.
func (a Address) IsMulticast() bool {
	return a[0] == 0xff
}

// IsLinkLocal returns true if the address is in the fe80::/10 range
// (unicast link-local, not multicast).
func (a Address) IsLinkLocal() bool {
	return a[0] == 0xfe && (a[1]&0xc0) == 0x80
}

// IsLinkLocalMulticast returns true if the address is a link-local scope
// multicast address (ff02::/16).
func (a Address) IsLinkLocalMulticast() bool {
	return a.IsMulticast() && (a[1]&0x0f) == 2
}

// IsRealmLocalMulticast returns true if the address is a realm-local scope
// multicast address (ff03::/16).
func (a Address) IsRealmLocalMulticast() bool {
	return a.IsMulticast() && (a[1]&0x0f) == 3
}

// GetScope returns the IPv6 scope of the address.
// For multicast: scope field from byte[1] & 0x0f.
// For unicast: link-local → 2, loopback → 0, otherwise → 14 (global).
func (a Address) GetScope() uint8 {
	if a.IsMulticast() {
		return a[1] & 0x0f
	}
	if a.IsLinkLocal() {
		return 2
	}
	if a.IsLoopback() {
		return 0
	}
	return 14
}

// PrefixMatch returns the number of leading bits that match between a and b.
func (a Address) PrefixMatch(b Address) uint8 {
	var count uint8
	for i := 0; i < 16; i++ {
		xor := a[i] ^ b[i]
		if xor == 0 {
			count += 8
			continue
		}
		// Count leading zeros in the XOR byte.
		for bit := byte(0x80); bit != 0; bit >>= 1 {
			if xor&bit != 0 {
				return count
			}
			count++
		}
	}
	return count
}

// GetIid returns the Interface Identifier (last 8 bytes) of the address.
func (a Address) GetIid() InterfaceIdentifier {
	var iid InterfaceIdentifier
	copy(iid[:], a[8:16])
	return iid
}

// SetIid sets the Interface Identifier (last 8 bytes) of the address.
func (a *Address) SetIid(iid InterfaceIdentifier) {
	copy(a[8:16], iid[:])
}

// GetPrefix returns the Network Prefix (first 8 bytes) of the address.
func (a Address) GetPrefix() NetworkPrefix {
	var p NetworkPrefix
	copy(p[:], a[0:8])
	return p
}

// SetPrefix sets the Network Prefix (first 8 bytes) of the address.
func (a *Address) SetPrefix(p NetworkPrefix) {
	copy(a[0:8], p[:])
}

// IsRoutingLocator returns true if the address has an IID matching the
// Thread Routing Locator (RLOC) pattern: 0000:00ff:fe00:xxxx where
// byte[6] < 0xfc and byte[6] & 0x02 == 0.
func (a Address) IsRoutingLocator() bool {
	return a.GetIid().IsRoutingLocator()
}

// IsAnycastRoutingLocator returns true if the address has an IID matching the
// Thread Anycast Routing Locator (ALOC) pattern: 0000:00ff:fe00:fcxx.
func (a Address) IsAnycastRoutingLocator() bool {
	return a.GetIid().IsAnycastLocator()
}

// IsIidReserved returns true if the IID is reserved (subnet-router anycast,
// reserved subnet anycast, or ALOC).
func (a Address) IsIidReserved() bool {
	iid := a.GetIid()
	return iid.isSubnetRouterAnycast() || iid.isReservedSubnetAnycast() || iid.IsAnycastLocator()
}

// ---------------------------------------------------------------------------
// InterfaceIdentifier
// ---------------------------------------------------------------------------

// InterfaceIdentifier is the 64-bit Interface Identifier portion of an IPv6
// address.
type InterfaceIdentifier [8]byte

// isLocatorPattern returns true if the IID matches the Thread locator pattern
// 0000:00ff:fe00:xxxx (bytes 0-4 match the pattern).
func (iid InterfaceIdentifier) isLocatorPattern() bool {
	return iid[0] == 0x00 && iid[1] == 0x00 &&
		iid[2] == 0x00 && iid[3] == 0xff &&
		iid[4] == 0xfe && iid[5] == 0x00
}

// IsRoutingLocator returns true if the IID matches the RLOC pattern:
// 0000:00ff:fe00:xxxx where byte[6] < 0xfc and byte[6] & 0x02 == 0.
func (iid InterfaceIdentifier) IsRoutingLocator() bool {
	return iid.isLocatorPattern() && iid[6] < 0xfc && (iid[6]&0x02) == 0
}

// IsAnycastLocator returns true if the IID matches the ALOC pattern:
// 0000:00ff:fe00:fcxx (byte[6] == 0xfc).
func (iid InterfaceIdentifier) IsAnycastLocator() bool {
	return iid.isLocatorPattern() && iid[6] == 0xfc
}

// isSubnetRouterAnycast returns true if the IID is all zeros.
func (iid InterfaceIdentifier) isSubnetRouterAnycast() bool {
	return iid == InterfaceIdentifier{}
}

// isReservedSubnetAnycast returns true if the IID matches the reserved subnet
// anycast pattern: fdff:ffff:ffff:ff80-ffff (57 leading 1-bits after the
// first 0 bit, with a 7-bit anycast ID >= 0x80 in the last byte position).
// The exact pattern from OpenThread: first 7 bytes == {0xfd, 0xff, 0xff, 0xff,
// 0xff, 0xff, 0xff} and last byte >= 0x80.
func (iid InterfaceIdentifier) isReservedSubnetAnycast() bool {
	return iid[0] == 0xfd &&
		iid[1] == 0xff && iid[2] == 0xff && iid[3] == 0xff &&
		iid[4] == 0xff && iid[5] == 0xff && iid[6] == 0xff &&
		iid[7] >= 0x80
}

// GetLocator returns the 16-bit locator value from the last two bytes of the
// IID.
func (iid InterfaceIdentifier) GetLocator() uint16 {
	return uint16(iid[6])<<8 | uint16(iid[7])
}

// SetLocator sets the 16-bit locator value in the last two bytes of the IID.
func (iid *InterfaceIdentifier) SetLocator(loc uint16) {
	iid[6] = byte(loc >> 8)
	iid[7] = byte(loc)
}

// ToString returns the IID as a 16-character lowercase hex string.
func (iid InterfaceIdentifier) ToString() string {
	return fmt.Sprintf("%02x%02x%02x%02x%02x%02x%02x%02x",
		iid[0], iid[1], iid[2], iid[3], iid[4], iid[5], iid[6], iid[7])
}

// ---------------------------------------------------------------------------
// NetworkPrefix
// ---------------------------------------------------------------------------

// NetworkPrefix is the 64-bit network prefix portion of an IPv6 address.
type NetworkPrefix [8]byte

// IsUla returns true if the prefix is a Unique Local Address prefix (fd00::/8).
// In OpenThread, ULA is defined as the first byte being 0xfd.
func (p NetworkPrefix) IsUla() bool {
	return p[0] == 0xfd
}

// ToString returns the prefix as a 16-character lowercase hex string.
func (p NetworkPrefix) ToString() string {
	return fmt.Sprintf("%02x%02x%02x%02x%02x%02x%02x%02x",
		p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7])
}

// ---------------------------------------------------------------------------
// Prefix
// ---------------------------------------------------------------------------

// Prefix represents an IPv6 prefix: a network address and a prefix length.
type Prefix struct {
	addr   [16]byte
	length uint8
}

// NewPrefix creates a Prefix from the given address bytes and length.
func NewPrefix(addr [16]byte, length uint8) Prefix {
	return Prefix{addr: addr, length: length}
}

// PrefixFromString parses a prefix string of the form "address/length".
func PrefixFromString(s string) (Prefix, error) {
	slashIdx := strings.LastIndex(s, "/")
	if slashIdx < 0 {
		return Prefix{}, errors.ErrParse
	}

	addrStr := s[:slashIdx]
	lenStr := s[slashIdx+1:]

	if len(lenStr) == 0 {
		return Prefix{}, errors.ErrParse
	}

	// Parse the prefix length (decimal integer, 0-128).
	var plen int
	for _, c := range lenStr {
		if c < '0' || c > '9' {
			return Prefix{}, errors.ErrParse
		}
		plen = plen*10 + int(c-'0')
		if plen > 128 {
			return Prefix{}, errors.ErrParse
		}
	}

	addr, err := AddressFromString(addrStr)
	if err != nil {
		return Prefix{}, errors.ErrParse
	}

	return Prefix{addr: [16]byte(addr), length: uint8(plen)}, nil
}

// GetLength returns the prefix length in bits.
func (p Prefix) GetLength() uint8 {
	return p.length
}

// GetBytes returns the address bytes of the prefix.
func (p Prefix) GetBytes() [16]byte {
	return p.addr
}

// ToString returns the prefix as a string with :: compression before the
// /length suffix, matching OpenThread's Prefix::ToString behaviour.
// It outputs groups up to ceil(byteSize / 2) then appends :: if needed,
// then /length.
func (p Prefix) ToString() string {
	byteSize := (int(p.length) + 7) / 8
	groupCount := (byteSize + 1) / 2

	var sb strings.Builder

	if groupCount == 0 {
		sb.WriteString("::")
	} else {
		for i := 0; i < groupCount; i++ {
			if i > 0 {
				sb.WriteByte(':')
			}
			hi := int(i) * 2
			lo := hi + 1
			var v uint16
			if hi < 16 {
				v = uint16(p.addr[hi]) << 8
			}
			if lo < 16 {
				v |= uint16(p.addr[lo])
			}
			fmt.Fprintf(&sb, "%x", v)
		}
		if groupCount < 8 {
			sb.WriteString("::")
		}
	}

	fmt.Fprintf(&sb, "/%d", p.length)
	return sb.String()
}

// Tidy clears all bits in the address beyond the prefix length.
func (p *Prefix) Tidy() {
	fullBytes := int(p.length) / 8
	remainBits := p.length % 8

	if fullBytes < 16 {
		if remainBits > 0 {
			mask := byte(0xff << (8 - remainBits))
			p.addr[fullBytes] &= mask
			fullBytes++
		}
		for i := fullBytes; i < 16; i++ {
			p.addr[i] = 0
		}
	}
}

// IsLinkLocal returns true if the prefix is contained within fe80::/10.
func (p Prefix) IsLinkLocal() bool {
	if p.length < 10 {
		return false
	}
	return p.addr[0] == 0xfe && (p.addr[1]&0xc0) == 0x80
}

// IsMulticast returns true if the prefix is contained within ff00::/8.
func (p Prefix) IsMulticast() bool {
	if p.length < 8 {
		return false
	}
	return p.addr[0] == 0xff
}

// IsUniqueLocal returns true if the prefix is contained within fc00::/7.
func (p Prefix) IsUniqueLocal() bool {
	if p.length < 7 {
		return false
	}
	return (p.addr[0] & 0xfe) == 0xfc
}

// ContainsPrefix returns true if p contains sub, meaning p's length is <=
// sub's length and the first p.length bits match.
func (p Prefix) ContainsPrefix(sub Prefix) bool {
	if p.length > sub.length {
		return false
	}
	return matchBits(p.addr[:], sub.addr[:], p.length)
}

// IsEqual returns true if two prefixes have the same length and matching bits.
func (p Prefix) IsEqual(other Prefix) bool {
	if p.length != other.length {
		return false
	}
	return matchBits(p.addr[:], other.addr[:], p.length)
}

// LessThan returns true if p is ordered before other.
// Comparison is done on the first min(p.length, other.length) bits;
// if those bits are equal, the shorter prefix is considered less.
func (p Prefix) LessThan(other Prefix) bool {
	minLen := p.length
	if other.length < minLen {
		minLen = other.length
	}

	// Compare bit by bit through full bytes.
	fullBytes := int(minLen) / 8
	for i := 0; i < fullBytes; i++ {
		if p.addr[i] < other.addr[i] {
			return true
		}
		if p.addr[i] > other.addr[i] {
			return false
		}
	}

	// Compare remaining bits.
	remainBits := minLen % 8
	if remainBits > 0 {
		mask := byte(0xff << (8 - remainBits))
		pa := p.addr[fullBytes] & mask
		oa := other.addr[fullBytes] & mask
		if pa < oa {
			return true
		}
		if pa > oa {
			return false
		}
	}

	// Bits are equal up to minLen; shorter prefix is less.
	return p.length < other.length
}

// IsValidNat64 returns true if the prefix length is one of the valid
// NAT64 prefix lengths: 32, 40, 48, 56, 64, or 96.
func (p Prefix) IsValidNat64() bool {
	switch p.length {
	case 32, 40, 48, 56, 64, 96:
		return true
	default:
		return false
	}
}

// matchBits returns true if the first numBits bits of a and b are equal.
func matchBits(a, b []byte, numBits uint8) bool {
	fullBytes := int(numBits) / 8
	for i := 0; i < fullBytes; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	remainBits := numBits % 8
	if remainBits > 0 {
		mask := byte(0xff << (8 - remainBits))
		if (a[fullBytes] & mask) != (b[fullBytes] & mask) {
			return false
		}
	}
	return true
}
