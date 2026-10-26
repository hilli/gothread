// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package ip4 implements IPv4 address types, header parsing, and NAT64
// mapping for Thread networks.
//
// This is a Go port of the IPv4 handling in OpenThread's
// src/core/net/ip4_types.hpp and src/core/net/ip4_types.cpp.
package ip4

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Address size constants.
const (
	// AddressSize is the size of an IPv4 address in bytes.
	AddressSize = 4
)

// Protocol number constants (Internet Protocol Numbers).
const (
	// ProtocolICMP is the ICMP for IPv4 protocol number.
	ProtocolICMP uint8 = 1
	// ProtocolTCP is the TCP protocol number.
	ProtocolTCP uint8 = 6
	// ProtocolUDP is the UDP protocol number.
	ProtocolUDP uint8 = 17
)

// Header size constants.
const (
	// HeaderMinSize is the minimum IPv4 header size in bytes (no options).
	HeaderMinSize = 20
)

// ECN (Explicit Congestion Notification) marking constants.
// These mirror the ip6.Ecn values for IPv4.
const (
	EcnNotCapable ip6.Ecn = ip6.EcnNotCapable
	EcnCapable0   ip6.Ecn = ip6.EcnCapable0
	EcnCapable1   ip6.Ecn = ip6.EcnCapable1
	EcnMarked     ip6.Ecn = ip6.EcnMarked
)

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

// Address is a 32-bit IPv4 address stored in network byte order.
type Address [AddressSize]byte

// AddressFromString parses a dotted-decimal IPv4 address string (e.g. "192.168.1.1").
func AddressFromString(s string) (Address, error) {
	var addr Address
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return addr, errors.ErrParse
	}
	for i, p := range parts {
		if p == "" || len(p) > 3 {
			return addr, errors.ErrParse
		}
		// Reject leading zeros (except "0" itself).
		if len(p) > 1 && p[0] == '0' {
			return addr, errors.ErrParse
		}
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return addr, errors.ErrParse
		}
		addr[i] = byte(v)
	}
	return addr, nil
}

// String returns the address in dotted-decimal notation (e.g. "192.168.1.1").
func (a Address) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", a[0], a[1], a[2], a[3])
}

// IsUnspecified returns true if the address is 0.0.0.0.
func (a Address) IsUnspecified() bool {
	return a == Address{}
}

// IsLoopback returns true if the address is in the 127.0.0.0/8 range.
func (a Address) IsLoopback() bool {
	return a[0] == 127
}

// IsMulticast returns true if the address is in the 224.0.0.0/4 range.
func (a Address) IsMulticast() bool {
	return (a[0] & 0xf0) == 0xe0
}

// IsLinkLocal returns true if the address is in the 169.254.0.0/16 range.
func (a Address) IsLinkLocal() bool {
	return a[0] == 169 && a[1] == 254
}

// IsBroadcast returns true if the address is 255.255.255.255.
func (a Address) IsBroadcast() bool {
	return a == Address{255, 255, 255, 255}
}

// ---------------------------------------------------------------------------
// CIDR
// ---------------------------------------------------------------------------

// CIDR represents an IPv4 CIDR block (address + prefix length).
type CIDR struct {
	Address      Address
	PrefixLength uint8
}

// CIDRFromString parses a CIDR string of the form "address/length"
// (e.g. "192.168.1.0/24").
func CIDRFromString(s string) (CIDR, error) {
	slashIdx := strings.LastIndex(s, "/")
	if slashIdx < 0 {
		return CIDR{}, errors.ErrParse
	}

	addrStr := s[:slashIdx]
	lenStr := s[slashIdx+1:]

	if lenStr == "" {
		return CIDR{}, errors.ErrParse
	}

	addr, err := AddressFromString(addrStr)
	if err != nil {
		return CIDR{}, errors.ErrParse
	}

	plen, err := strconv.Atoi(lenStr)
	if err != nil || plen < 0 || plen > 32 {
		return CIDR{}, errors.ErrParse
	}

	return CIDR{Address: addr, PrefixLength: uint8(plen)}, nil
}

// String returns the CIDR in "address/length" notation (e.g. "192.168.1.0/24").
func (c CIDR) String() string {
	return fmt.Sprintf("%s/%d", c.Address.String(), c.PrefixLength)
}

// Contains returns true if the given address falls within this CIDR block.
func (c CIDR) Contains(addr Address) bool {
	mask := c.subnetMask()
	// Compare the masked network portions.
	for i := 0; i < AddressSize; i++ {
		if (c.Address[i] & mask[i]) != (addr[i] & mask[i]) {
			return false
		}
	}
	return true
}

// Equal returns true if two CIDRs have the same prefix length and the same
// network bits match.
func (c CIDR) Equal(other CIDR) bool {
	if c.PrefixLength != other.PrefixLength {
		return false
	}
	mask := c.subnetMask()
	for i := 0; i < AddressSize; i++ {
		if (c.Address[i] & mask[i]) != (other.Address[i] & mask[i]) {
			return false
		}
	}
	return true
}

// subnetMask returns the subnet mask as a 4-byte array.
func (c CIDR) subnetMask() [4]byte {
	var mask [4]byte
	if c.PrefixLength == 0 {
		return mask
	}
	// Build 32-bit mask.
	var m uint32
	if c.PrefixLength >= 32 {
		m = 0xffffffff
	} else {
		m = ^(uint32(1)<<(32-c.PrefixLength) - 1)
	}
	mask[0] = byte(m >> 24)
	mask[1] = byte(m >> 16)
	mask[2] = byte(m >> 8)
	mask[3] = byte(m)
	return mask
}

// hostMask returns the host mask as a big-endian uint32.
func (c CIDR) hostMask() uint32 {
	if c.PrefixLength >= 32 {
		return 0
	}
	return uint32(1)<<(32-c.PrefixLength) - 1
}

// SynthesizeFromCIDRAndHost creates an address by combining the network
// portion of the CIDR with the given host bits (in host byte order).
// Host bits beyond the host mask are ignored.
func SynthesizeFromCIDRAndHost(cidr CIDR, host uint32) Address {
	var addr Address
	sm := cidr.subnetMask()
	hm := cidr.hostMask()
	// host is in host byte order; convert to big-endian for OR.
	hostBE := [4]byte{
		byte(host >> 24),
		byte(host >> 16),
		byte(host >> 8),
		byte(host),
	}
	for i := 0; i < AddressSize; i++ {
		addr[i] = (cidr.Address[i] & sm[i]) | (hostBE[i] & byte(hm>>(24-i*8)))
	}
	return addr
}

// ---------------------------------------------------------------------------
// Header (IPv4 packet header, 20 bytes minimum)
// ---------------------------------------------------------------------------

// Header represents an IPv4 packet header in wire format.
//
// Wire layout (big-endian, 20 bytes without options):
//
//	Offset  0: Version(4) | IHL(4)
//	Offset  1: DSCP(6) | ECN(2)
//	Offset  2: Total Length (2 bytes)
//	Offset  4: Identification (2 bytes)
//	Offset  6: Flags(3) | Fragment Offset(13) (2 bytes)
//	Offset  8: TTL (1 byte)
//	Offset  9: Protocol (1 byte)
//	Offset 10: Header Checksum (2 bytes)
//	Offset 12: Source Address (4 bytes)
//	Offset 16: Destination Address (4 bytes)
type Header struct {
	data [HeaderMinSize]byte
}

// Header field offsets.
const (
	hdrOffVersIHL      = 0
	hdrOffDscpEcn      = 1
	hdrOffTotalLen     = 2
	hdrOffIdent        = 4
	hdrOffFlagsFragOff = 6
	hdrOffTTL          = 8
	hdrOffProtocol     = 9
	hdrOffChecksum     = 10
	hdrOffSrcAddr      = 12
	hdrOffDstAddr      = 16
)

// Header constants.
const (
	hdrVersion4    = 0x40
	hdrVersionMask = 0xf0
	hdrIHLMask     = 0x0f
	hdrVersIHLInit = 0x45 // Version 4, IHL = 5 (20 bytes)
	hdrDscpMask    = 0xfc
	hdrDscpShift   = 2
	hdrEcnMask     = 0x03
	hdrFlagDF      = 0x4000
	hdrFlagMF      = 0x2000
	hdrFragOffMask = 0x1fff
)

// Init initializes the header with Version=4 and IHL=5 (20 bytes).
// Other fields are zeroed.
func (h *Header) Init() {
	h.data = [HeaderMinSize]byte{}
	h.data[hdrOffVersIHL] = hdrVersIHLInit
}

// IsValid returns true if the version field is 4.
func (h *Header) IsValid() bool {
	return (h.data[hdrOffVersIHL] & hdrVersionMask) == hdrVersion4
}

// GetVersion returns the 4-bit IP version field.
func (h *Header) GetVersion() uint8 {
	return h.data[hdrOffVersIHL] >> 4
}

// GetIHL returns the 4-bit Internet Header Length (in 32-bit words).
func (h *Header) GetIHL() uint8 {
	return h.data[hdrOffVersIHL] & hdrIHLMask
}

// GetHeaderLength returns the header length in bytes (IHL * 4).
func (h *Header) GetHeaderLength() uint8 {
	return h.GetIHL() * 4
}

// GetDscpEcn returns the raw DSCP+ECN byte.
func (h *Header) GetDscpEcn() uint8 {
	return h.data[hdrOffDscpEcn]
}

// GetDscp returns the 6-bit DSCP value.
func (h *Header) GetDscp() uint8 {
	return (h.data[hdrOffDscpEcn] & hdrDscpMask) >> hdrDscpShift
}

// SetDscp sets the 6-bit DSCP value, preserving ECN bits.
func (h *Header) SetDscp(dscp uint8) {
	h.data[hdrOffDscpEcn] = (h.data[hdrOffDscpEcn] & ^uint8(hdrDscpMask)) | (dscp << hdrDscpShift)
}

// GetEcn returns the 2-bit ECN value.
func (h *Header) GetEcn() ip6.Ecn {
	return ip6.Ecn(h.data[hdrOffDscpEcn] & hdrEcnMask)
}

// SetEcn sets the 2-bit ECN value, preserving DSCP bits.
func (h *Header) SetEcn(ecn ip6.Ecn) {
	h.data[hdrOffDscpEcn] = (h.data[hdrOffDscpEcn] & ^uint8(hdrEcnMask)) | uint8(ecn)
}

// GetTotalLength returns the total packet length in bytes.
func (h *Header) GetTotalLength() uint16 {
	return encoding.BigEndianReadUint16(h.data[hdrOffTotalLen:])
}

// SetTotalLength sets the total packet length.
func (h *Header) SetTotalLength(length uint16) {
	encoding.BigEndianWriteUint16(length, h.data[hdrOffTotalLen:])
}

// GetIdentification returns the 16-bit identification field.
func (h *Header) GetIdentification() uint16 {
	return encoding.BigEndianReadUint16(h.data[hdrOffIdent:])
}

// SetIdentification sets the 16-bit identification field.
func (h *Header) SetIdentification(id uint16) {
	encoding.BigEndianWriteUint16(id, h.data[hdrOffIdent:])
}

// GetDF returns true if the Don't Fragment flag is set.
func (h *Header) GetDF() bool {
	return encoding.BigEndianReadUint16(h.data[hdrOffFlagsFragOff:])&hdrFlagDF != 0
}

// SetDF sets or clears the Don't Fragment flag.
func (h *Header) SetDF(df bool) {
	v := encoding.BigEndianReadUint16(h.data[hdrOffFlagsFragOff:])
	if df {
		v |= hdrFlagDF
	} else {
		v &^= hdrFlagDF
	}
	encoding.BigEndianWriteUint16(v, h.data[hdrOffFlagsFragOff:])
}

// GetMF returns true if the More Fragments flag is set.
func (h *Header) GetMF() bool {
	return encoding.BigEndianReadUint16(h.data[hdrOffFlagsFragOff:])&hdrFlagMF != 0
}

// SetMF sets or clears the More Fragments flag.
func (h *Header) SetMF(mf bool) {
	v := encoding.BigEndianReadUint16(h.data[hdrOffFlagsFragOff:])
	if mf {
		v |= hdrFlagMF
	} else {
		v &^= hdrFlagMF
	}
	encoding.BigEndianWriteUint16(v, h.data[hdrOffFlagsFragOff:])
}

// GetFragmentOffset returns the 13-bit fragment offset (in 8-octet units).
func (h *Header) GetFragmentOffset() uint16 {
	return encoding.BigEndianReadUint16(h.data[hdrOffFlagsFragOff:]) & hdrFragOffMask
}

// SetFragmentOffset sets the 13-bit fragment offset, preserving flags.
func (h *Header) SetFragmentOffset(offset uint16) {
	v := encoding.BigEndianReadUint16(h.data[hdrOffFlagsFragOff:])
	v = (v & ^uint16(hdrFragOffMask)) | (offset & hdrFragOffMask)
	encoding.BigEndianWriteUint16(v, h.data[hdrOffFlagsFragOff:])
}

// GetTTL returns the Time-to-Live value.
func (h *Header) GetTTL() uint8 {
	return h.data[hdrOffTTL]
}

// SetTTL sets the Time-to-Live value.
func (h *Header) SetTTL(ttl uint8) {
	h.data[hdrOffTTL] = ttl
}

// GetProtocol returns the protocol number.
func (h *Header) GetProtocol() uint8 {
	return h.data[hdrOffProtocol]
}

// SetProtocol sets the protocol number.
func (h *Header) SetProtocol(proto uint8) {
	h.data[hdrOffProtocol] = proto
}

// GetChecksum returns the header checksum in host byte order.
func (h *Header) GetChecksum() uint16 {
	return encoding.BigEndianReadUint16(h.data[hdrOffChecksum:])
}

// SetChecksum sets the header checksum (in host byte order).
func (h *Header) SetChecksum(cksum uint16) {
	encoding.BigEndianWriteUint16(cksum, h.data[hdrOffChecksum:])
}

// GetSource returns the source address.
func (h *Header) GetSource() Address {
	var addr Address
	copy(addr[:], h.data[hdrOffSrcAddr:hdrOffSrcAddr+AddressSize])
	return addr
}

// SetSource sets the source address.
func (h *Header) SetSource(addr Address) {
	copy(h.data[hdrOffSrcAddr:], addr[:])
}

// GetDestination returns the destination address.
func (h *Header) GetDestination() Address {
	var addr Address
	copy(addr[:], h.data[hdrOffDstAddr:hdrOffDstAddr+AddressSize])
	return addr
}

// SetDestination sets the destination address.
func (h *Header) SetDestination(addr Address) {
	copy(h.data[hdrOffDstAddr:], addr[:])
}

// Marshal serializes the header to a 20-byte wire-format buffer.
func (h *Header) Marshal() [HeaderMinSize]byte {
	return h.data
}

// MarshalTo writes the header into the provided buffer.
// Returns an error if the buffer is too small.
func (h *Header) MarshalTo(buf []byte) error {
	if len(buf) < HeaderMinSize {
		return errors.ErrInvalidArgs
	}
	copy(buf, h.data[:])
	return nil
}

// Unmarshal reads the header from a wire-format buffer.
// Returns an error if the buffer is too short or the header is invalid.
func (h *Header) Unmarshal(buf []byte) error {
	if len(buf) < HeaderMinSize {
		return errors.ErrParse
	}
	copy(h.data[:], buf[:HeaderMinSize])
	if !h.IsValid() {
		return errors.ErrParse
	}
	return nil
}

// ComputeChecksum computes and sets the IPv4 header checksum.
// The checksum field is set to zero before computation.
func (h *Header) ComputeChecksum() {
	h.SetChecksum(0)
	h.SetChecksum(InternetChecksum(h.data[:]))
}

// VerifyChecksum returns true if the header checksum is correct.
func (h *Header) VerifyChecksum() bool {
	return InternetChecksum(h.data[:]) == 0
}

// ---------------------------------------------------------------------------
// Internet Checksum (RFC 1071)
// ---------------------------------------------------------------------------

// InternetChecksum computes the Internet checksum (RFC 1071) over the given
// data. This is the one's complement of the one's complement sum of all
// 16-bit words. If the data has an odd number of bytes, the last byte is
// padded with a zero byte.
func InternetChecksum(data []byte) uint16 {
	var sum uint32
	length := len(data)
	i := 0

	// Sum 16-bit words.
	for i+1 < length {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
		i += 2
	}

	// Handle odd byte.
	if i < length {
		sum += uint32(data[i]) << 8
	}

	// Fold 32-bit sum to 16 bits.
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	return uint16(^sum)
}

// PseudoHeaderChecksum computes the pseudo-header contribution to a
// TCP/UDP/ICMP checksum over IPv4. The pseudo-header consists of:
//   - Source Address (4 bytes)
//   - Destination Address (4 bytes)
//   - Zero byte + Protocol (2 bytes)
//   - Upper-layer length (2 bytes)
//
// The returned value should be combined with the upper-layer data checksum
// using CombineChecksums.
func PseudoHeaderChecksum(src, dst Address, protocol uint8, upperLayerLen uint16) uint16 {
	var pseudo [12]byte
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[8] = 0
	pseudo[9] = protocol
	encoding.BigEndianWriteUint16(upperLayerLen, pseudo[10:12])
	return InternetChecksum(pseudo[:])
}

// CombineChecksums combines two partial Internet checksums.
// Each partial checksum should be the bitwise NOT of the running sum.
// This function produces the final combined checksum.
func CombineChecksums(a, b uint16) uint16 {
	sum := uint32(^a) + uint32(^b)
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return uint16(^sum)
}

// ---------------------------------------------------------------------------
// NAT64 mapping (RFC 6052)
// ---------------------------------------------------------------------------

// MappedToV6 maps an IPv4 address into an IPv6 address using the given NAT64
// prefix (RFC 6052). The prefix length must be one of 32, 40, 48, 56, 64, or
// 96.
//
// Returns the synthesized IPv6 address and an error if the prefix length is
// invalid.
func MappedToV6(addr Address, prefix ip6.Prefix) (ip6.Address, error) {
	plen := prefix.GetLength()
	if !prefix.IsValidNat64() {
		return ip6.Address{}, errors.ErrInvalidArgs
	}

	var v6 ip6.Address
	pfxBytes := prefix.GetBytes()

	// Copy prefix bytes.
	prefixByteLen := int(plen) / 8
	copy(v6[:prefixByteLen], pfxBytes[:prefixByteLen])

	// Place IPv4 bytes after the prefix, skipping byte index 8.
	const skipIndex = 8
	ip6Idx := prefixByteLen
	for _, b := range addr {
		if ip6Idx == skipIndex {
			ip6Idx++
		}
		v6[ip6Idx] = b
		ip6Idx++
	}

	return v6, nil
}

// ExtractFromV6 extracts an IPv4 address from a NAT64-mapped IPv6 address
// using the given prefix (RFC 6052). The prefix length must be one of 32, 40,
// 48, 56, 64, or 96.
//
// Returns the extracted IPv4 address and an error if the prefix length is
// invalid.
func ExtractFromV6(v6addr ip6.Address, prefix ip6.Prefix) (Address, error) {
	plen := prefix.GetLength()
	if !prefix.IsValidNat64() {
		return Address{}, errors.ErrInvalidArgs
	}

	var addr Address
	const skipIndex = 8
	ip6Idx := int(plen) / 8

	for i := range addr {
		if ip6Idx == skipIndex {
			ip6Idx++
		}
		addr[i] = v6addr[ip6Idx]
		ip6Idx++
	}

	return addr, nil
}
