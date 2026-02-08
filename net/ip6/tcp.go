// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// TCP header type for Thread networks.
//
// This is a Go port of the TCP header handling in OpenThread's
// src/core/net/tcp6.hpp.

package ip6

import (
	"github.com/hilli/gothread/encoding"
)

// ---------------------------------------------------------------------------
// TCPHeader (20 bytes minimum)
// ---------------------------------------------------------------------------

// TCPHeaderSize is the minimum size of a TCP header in bytes (without
// options).
const TCPHeaderSize = 20

// TCPHeader represents a 20-byte TCP header stored in network byte order.
//
// Wire layout (big-endian):
//
//	Offset  0: Source Port — 2 bytes
//	Offset  2: Destination Port — 2 bytes
//	Offset  4: Sequence Number — 4 bytes
//	Offset  8: Acknowledgment Number — 4 bytes
//	Offset 12: Data Offset(4) | Reserved(3) | Flags(9) — 2 bytes
//	Offset 14: Window — 2 bytes
//	Offset 16: Checksum — 2 bytes
//	Offset 18: Urgent Pointer — 2 bytes
type TCPHeader struct {
	data [TCPHeaderSize]byte
}

// Byte offsets within the TCP header.
const (
	tcpOffsetSrcPort  = 0
	tcpOffsetDstPort  = 2
	tcpOffsetSeqNum   = 4
	tcpOffsetAckNum   = 8
	tcpOffsetFlags    = 12
	tcpOffsetWindow   = 14
	tcpOffsetChecksum = 16
	tcpOffsetUrgent   = 18
)

// GetSourcePort returns the 16-bit source port.
func (t *TCPHeader) GetSourcePort() uint16 {
	return encoding.BigEndianReadUint16(t.data[tcpOffsetSrcPort:])
}

// SetSourcePort sets the 16-bit source port.
func (t *TCPHeader) SetSourcePort(port uint16) {
	encoding.BigEndianWriteUint16(port, t.data[tcpOffsetSrcPort:])
}

// GetDestinationPort returns the 16-bit destination port.
func (t *TCPHeader) GetDestinationPort() uint16 {
	return encoding.BigEndianReadUint16(t.data[tcpOffsetDstPort:])
}

// SetDestinationPort sets the 16-bit destination port.
func (t *TCPHeader) SetDestinationPort(port uint16) {
	encoding.BigEndianWriteUint16(port, t.data[tcpOffsetDstPort:])
}

// GetSequenceNumber returns the 32-bit sequence number.
func (t *TCPHeader) GetSequenceNumber() uint32 {
	return encoding.BigEndianReadUint32(t.data[tcpOffsetSeqNum:])
}

// SetSequenceNumber sets the 32-bit sequence number.
func (t *TCPHeader) SetSequenceNumber(seq uint32) {
	encoding.BigEndianWriteUint32(seq, t.data[tcpOffsetSeqNum:])
}

// GetAckNumber returns the 32-bit acknowledgment number.
func (t *TCPHeader) GetAckNumber() uint32 {
	return encoding.BigEndianReadUint32(t.data[tcpOffsetAckNum:])
}

// SetAckNumber sets the 32-bit acknowledgment number.
func (t *TCPHeader) SetAckNumber(ack uint32) {
	encoding.BigEndianWriteUint32(ack, t.data[tcpOffsetAckNum:])
}

// GetFlags returns the 16-bit field at offset 12, which contains the data
// offset (4 bits), reserved bits (3 bits), and TCP flags (9 bits).
func (t *TCPHeader) GetFlags() uint16 {
	return encoding.BigEndianReadUint16(t.data[tcpOffsetFlags:])
}

// SetFlags sets the 16-bit flags field at offset 12.
func (t *TCPHeader) SetFlags(flags uint16) {
	encoding.BigEndianWriteUint16(flags, t.data[tcpOffsetFlags:])
}

// GetWindow returns the 16-bit window size.
func (t *TCPHeader) GetWindow() uint16 {
	return encoding.BigEndianReadUint16(t.data[tcpOffsetWindow:])
}

// SetWindow sets the 16-bit window size.
func (t *TCPHeader) SetWindow(w uint16) {
	encoding.BigEndianWriteUint16(w, t.data[tcpOffsetWindow:])
}

// GetChecksum returns the 16-bit TCP checksum.
func (t *TCPHeader) GetChecksum() uint16 {
	return encoding.BigEndianReadUint16(t.data[tcpOffsetChecksum:])
}

// SetChecksum sets the 16-bit TCP checksum.
func (t *TCPHeader) SetChecksum(c uint16) {
	encoding.BigEndianWriteUint16(c, t.data[tcpOffsetChecksum:])
}

// GetUrgentPointer returns the 16-bit urgent pointer.
func (t *TCPHeader) GetUrgentPointer() uint16 {
	return encoding.BigEndianReadUint16(t.data[tcpOffsetUrgent:])
}

// SetUrgentPointer sets the 16-bit urgent pointer.
func (t *TCPHeader) SetUrgentPointer(u uint16) {
	encoding.BigEndianWriteUint16(u, t.data[tcpOffsetUrgent:])
}
