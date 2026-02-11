// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package trel implements the Thread Radio Encapsulation Link (TREL) protocol.
//
// TREL transports IEEE 802.15.4 frames over IPv6/UDP, enabling Thread
// communication across IP-based infrastructure links (e.g. Wi-Fi, Ethernet).
//
// This is a Go port of the TREL implementation in OpenThread's
// src/core/radio/trel_link.{hpp,cpp}, trel_packet.{hpp,cpp},
// trel_peer.{hpp,cpp}, and trel_interface.{hpp,cpp}.
package trel

import (
	"fmt"

	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
)

// --------------------------------------------------------------------------
// Header — TREL packet header
// --------------------------------------------------------------------------

// Type represents the TREL packet type.
type Type uint8

const (
	// TypeBroadcast is a TREL broadcast packet.
	TypeBroadcast Type = 0
	// TypeUnicast is a TREL unicast packet.
	TypeUnicast Type = 1
	// TypeAck is a TREL acknowledgment packet.
	TypeAck Type = 2
)

// String returns a human-readable name for the packet type.
func (t Type) String() string {
	switch t {
	case TypeBroadcast:
		return "broadcast"
	case TypeUnicast:
		return "unicast"
	case TypeAck:
		return "ack"
	default:
		return "unknown"
	}
}

// AckMode represents the TREL header ack mode field.
type AckMode uint8

const (
	// AckModeNoAck indicates no TREL ack is requested.
	AckModeNoAck AckMode = 0
	// AckModeRequested indicates a TREL ack is requested.
	AckModeRequested AckMode = 1
)

// Header field layout (big-endian, packed):
//
//	Byte 0:      Control (bits 0-1: Type, bit 2: AckMode, bits 5-7: Version)
//	Byte 1:      Channel
//	Bytes 2-3:   PAN ID (uint16 big-endian)
//	Bytes 4-7:   Packet Number (uint32 big-endian)
//	Bytes 8-15:  Source ExtAddress (8 bytes)
//	Bytes 16-23: Destination ExtAddress (8 bytes) — only for Unicast and Ack
//
// Total: 24 bytes for Unicast/Ack, 16 bytes for Broadcast.

const (
	// Control byte bitmasks.
	controlTypeMask    = 0x03 // bits 0-1
	controlAckModeFlag = 0x04 // bit 2
	controlVersionMask = 0xE0 // bits 5-7
	controlVersion     = 0x00 // current version (0 << 5)

	// Field offsets within the header.
	offsetControl      = 0
	offsetChannel      = 1
	offsetPanID        = 2
	offsetPacketNumber = 4
	offsetSource       = 8
	offsetDestination  = 16

	// HeaderSizeBroadcast is the header size for broadcast packets.
	HeaderSizeBroadcast = 16
	// HeaderSizeUnicast is the header size for unicast packets.
	HeaderSizeUnicast = 24
	// HeaderSizeAck is the header size for ack packets.
	HeaderSizeAck = 24
	// MaxHeaderSize is the maximum header size across all types.
	MaxHeaderSize = HeaderSizeUnicast
)

// HeaderSize returns the header size in bytes for the given packet type.
func HeaderSize(t Type) uint16 {
	switch t {
	case TypeBroadcast:
		return HeaderSizeBroadcast
	case TypeUnicast:
		return HeaderSizeUnicast
	case TypeAck:
		return HeaderSizeAck
	default:
		return MaxHeaderSize
	}
}

// Header provides methods to read and write TREL packet header fields
// directly on a backing byte slice. The caller must ensure the backing
// slice is large enough for the packet type being used.
type Header struct {
	buf []byte
}

// NewHeader wraps a byte slice as a Header for reading/writing fields.
// The slice must be at least HeaderSizeBroadcast bytes.
func NewHeader(buf []byte) Header {
	return Header{buf: buf}
}

// Init initializes the header for the given packet type by writing the
// control byte (version + type).
func (h Header) Init(t Type) {
	h.buf[offsetControl] = controlVersion | uint8(t)
}

// IsVersionValid returns true if the version bits in the control byte are
// valid (currently version 0).
func (h Header) IsVersionValid() bool {
	return (h.buf[offsetControl] & controlVersionMask) == controlVersion
}

// GetType returns the packet type from the control byte.
func (h Header) GetType() Type {
	return Type(h.buf[offsetControl] & controlTypeMask)
}

// GetLength returns the header length in bytes based on the packet type.
func (h Header) GetLength() uint16 {
	return HeaderSize(h.GetType())
}

// GetAckMode returns the ack mode from the control byte.
func (h Header) GetAckMode() AckMode {
	if h.buf[offsetControl]&controlAckModeFlag != 0 {
		return AckModeRequested
	}
	return AckModeNoAck
}

// SetAckMode sets the ack mode flag in the control byte.
func (h Header) SetAckMode(mode AckMode) {
	switch mode {
	case AckModeNoAck:
		h.buf[offsetControl] &^= controlAckModeFlag
	case AckModeRequested:
		h.buf[offsetControl] |= controlAckModeFlag
	}
}

// GetChannel returns the channel field.
func (h Header) GetChannel() uint8 {
	return h.buf[offsetChannel]
}

// SetChannel sets the channel field.
func (h Header) SetChannel(ch uint8) {
	h.buf[offsetChannel] = ch
}

// GetPanID returns the PAN ID field (big-endian).
func (h Header) GetPanID() types.PanID {
	return types.PanID(encoding.BigEndianReadUint16(h.buf[offsetPanID:]))
}

// SetPanID sets the PAN ID field (big-endian).
func (h Header) SetPanID(panID types.PanID) {
	encoding.BigEndianWriteUint16(uint16(panID), h.buf[offsetPanID:])
}

// GetPacketNumber returns the packet number field (big-endian).
func (h Header) GetPacketNumber() uint32 {
	return encoding.BigEndianReadUint32(h.buf[offsetPacketNumber:])
}

// SetPacketNumber sets the packet number field (big-endian).
func (h Header) SetPacketNumber(num uint32) {
	encoding.BigEndianWriteUint32(num, h.buf[offsetPacketNumber:])
}

// GetSource returns the source MAC extended address.
func (h Header) GetSource() types.ExtAddress {
	var addr types.ExtAddress
	copy(addr[:], h.buf[offsetSource:offsetSource+types.ExtAddressSize])
	return addr
}

// SetSource sets the source MAC extended address.
func (h Header) SetSource(addr types.ExtAddress) {
	copy(h.buf[offsetSource:offsetSource+types.ExtAddressSize], addr[:])
}

// GetDestination returns the destination MAC extended address.
// Must only be called for Unicast or Ack packet types.
func (h Header) GetDestination() types.ExtAddress {
	var addr types.ExtAddress
	copy(addr[:], h.buf[offsetDestination:offsetDestination+types.ExtAddressSize])
	return addr
}

// SetDestination sets the destination MAC extended address.
// Must only be called for Unicast or Ack packet types.
func (h Header) SetDestination(addr types.ExtAddress) {
	copy(h.buf[offsetDestination:offsetDestination+types.ExtAddressSize], addr[:])
}

// ToString returns a human-readable string representation of the header.
func (h Header) ToString() string {
	t := h.GetType()
	s := fmt.Sprintf("%s ch:%d panid:%04x num:%d src:%s",
		t.String(), h.GetChannel(), h.GetPanID(), h.GetPacketNumber(),
		h.GetSource().ToString())
	if t == TypeUnicast || t == TypeAck {
		s += fmt.Sprintf(" dst:%s", h.GetDestination().ToString())
	}
	if t == TypeUnicast || t == TypeBroadcast {
		if h.GetAckMode() == AckModeNoAck {
			s += " no-ack"
		} else {
			s += " ack-req"
		}
	}
	return s
}

// --------------------------------------------------------------------------
// Packet — TREL packet (header + payload)
// --------------------------------------------------------------------------

// Packet represents a TREL radio link packet containing a header and payload.
type Packet struct {
	buf []byte // complete packet buffer (header + payload)
}

// NewPacket creates a Packet wrapping the given buffer. The buffer should
// contain the complete packet (header followed by payload).
func NewPacket(buf []byte) Packet {
	return Packet{buf: buf}
}

// InitFromPayload initializes the Packet for the given type, using a buffer
// that has space reserved before the payload for the header. The payload
// parameter points to the start of the payload within a larger buffer, and
// payloadLen is the payload length. The caller must ensure the buffer has
// at least HeaderSize(t) bytes before the payload start.
//
// This matches OpenThread's Packet::Init(Type, uint8_t*, uint16_t) where
// the buffer is rewound by the header size.
func InitFromPayload(t Type, fullBuf []byte, headerOffset int, payloadLen uint16) Packet {
	hdrSize := int(HeaderSize(t))
	start := headerOffset - hdrSize
	if start < 0 {
		start = 0
	}
	totalLen := hdrSize + int(payloadLen)
	p := Packet{buf: fullBuf[start : start+totalLen]}
	p.GetHeader().Init(t)
	return p
}

// GetBuffer returns the raw buffer backing the packet.
func (p Packet) GetBuffer() []byte {
	return p.buf
}

// GetLength returns the total packet length (header + payload).
func (p Packet) GetLength() uint16 {
	return uint16(len(p.buf))
}

// IsHeaderValid checks whether the packet header is valid.
func (p Packet) IsHeaderValid() bool {
	if len(p.buf) == 0 {
		return false
	}
	h := p.GetHeader()
	if !h.IsVersionValid() {
		return false
	}
	return p.GetLength() >= h.GetLength()
}

// GetHeader returns a Header view over the packet buffer.
func (p Packet) GetHeader() Header {
	return NewHeader(p.buf)
}

// GetPayload returns the payload portion of the packet (after the header).
func (p Packet) GetPayload() []byte {
	hdrLen := p.GetHeader().GetLength()
	if uint16(len(p.buf)) <= hdrLen {
		return nil
	}
	return p.buf[hdrLen:]
}

// GetPayloadLength returns the payload length.
func (p Packet) GetPayloadLength() uint16 {
	hdrLen := p.GetHeader().GetLength()
	total := uint16(len(p.buf))
	if total <= hdrLen {
		return 0
	}
	return total - hdrLen
}

// MarshalHeader writes a complete header into buf and returns the number of
// bytes written and any error. This is a convenience for building packets
// from structured data.
func MarshalHeader(buf []byte, t Type, ackMode AckMode, channel uint8, panID types.PanID,
	packetNumber uint32, source types.ExtAddress, destination *types.ExtAddress) (int, error) {

	size := int(HeaderSize(t))
	if len(buf) < size {
		return 0, errors.ErrNoBufs
	}

	h := NewHeader(buf)
	h.Init(t)
	h.SetAckMode(ackMode)
	h.SetChannel(channel)
	h.SetPanID(panID)
	h.SetPacketNumber(packetNumber)
	h.SetSource(source)

	if (t == TypeUnicast || t == TypeAck) && destination != nil {
		h.SetDestination(*destination)
	}

	return size, nil
}
