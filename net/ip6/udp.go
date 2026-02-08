// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// UDP header type for Thread networks.
//
// This is a Go port of the UDP header handling in OpenThread's
// src/core/net/udp6.hpp.

package ip6

import (
	"github.com/hilli/gothread/encoding"
)

// ---------------------------------------------------------------------------
// UDPHeader (8 bytes)
// ---------------------------------------------------------------------------

// UDPHeaderSize is the size of a UDP header in bytes.
const UDPHeaderSize = 8

// UDPHeader represents an 8-byte UDP header stored in network byte order.
//
// Wire layout (big-endian):
//
//	Offset 0: Source Port — 2 bytes
//	Offset 2: Destination Port — 2 bytes
//	Offset 4: Length — 2 bytes
//	Offset 6: Checksum — 2 bytes
type UDPHeader struct {
	data [UDPHeaderSize]byte
}

// Byte offsets within the UDP header.
const (
	udpOffsetSrcPort  = 0
	udpOffsetDstPort  = 2
	udpOffsetLength   = 4
	udpOffsetChecksum = 6
)

// GetSourcePort returns the 16-bit source port.
func (u *UDPHeader) GetSourcePort() uint16 {
	return encoding.BigEndianReadUint16(u.data[udpOffsetSrcPort:])
}

// SetSourcePort sets the 16-bit source port.
func (u *UDPHeader) SetSourcePort(port uint16) {
	encoding.BigEndianWriteUint16(port, u.data[udpOffsetSrcPort:])
}

// GetDestinationPort returns the 16-bit destination port.
func (u *UDPHeader) GetDestinationPort() uint16 {
	return encoding.BigEndianReadUint16(u.data[udpOffsetDstPort:])
}

// SetDestinationPort sets the 16-bit destination port.
func (u *UDPHeader) SetDestinationPort(port uint16) {
	encoding.BigEndianWriteUint16(port, u.data[udpOffsetDstPort:])
}

// GetLength returns the 16-bit UDP length (header + payload).
func (u *UDPHeader) GetLength() uint16 {
	return encoding.BigEndianReadUint16(u.data[udpOffsetLength:])
}

// SetLength sets the 16-bit UDP length.
func (u *UDPHeader) SetLength(length uint16) {
	encoding.BigEndianWriteUint16(length, u.data[udpOffsetLength:])
}

// GetChecksum returns the 16-bit UDP checksum.
func (u *UDPHeader) GetChecksum() uint16 {
	return encoding.BigEndianReadUint16(u.data[udpOffsetChecksum:])
}

// SetChecksum sets the 16-bit UDP checksum.
func (u *UDPHeader) SetChecksum(checksum uint16) {
	encoding.BigEndianWriteUint16(checksum, u.data[udpOffsetChecksum:])
}
