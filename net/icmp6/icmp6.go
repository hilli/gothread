// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package icmp6 implements ICMPv6 message types and handler management
// for Thread networks.
//
// This is a Go port of the ICMPv6 handling in OpenThread's
// src/core/net/icmp6.hpp and src/core/net/icmp6.cpp.
package icmp6

import (
	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// ICMPv6 Header
// ---------------------------------------------------------------------------

// HeaderSize is the size of an ICMPv6 header in bytes.
const HeaderSize = 8

// Field offset constants within the ICMPv6 header.
const (
	// TypeFieldOffset is the byte offset of the Type field.
	TypeFieldOffset = 0
	// CodeFieldOffset is the byte offset of the Code field.
	CodeFieldOffset = 1
	// ChecksumFieldOffset is the byte offset of the Checksum field.
	ChecksumFieldOffset = 2
	// DataFieldOffset is the byte offset of the Data field (used as
	// ID+Sequence for echo messages).
	DataFieldOffset = 4
)

// Header represents an ICMPv6 message header (8 bytes).
//
// Wire layout:
//   - byte 0: Type
//   - byte 1: Code
//   - bytes 2-3: Checksum (big-endian)
//   - bytes 4-7: Data (4 bytes, used as ID+Sequence for echo)
type Header struct {
	data [HeaderSize]byte
}

// IsError returns true if the ICMPv6 type is an error type (type < 128).
func (h *Header) IsError() bool {
	return Type(h.data[TypeFieldOffset]) < TypeEchoRequest
}

// GetType returns the ICMPv6 message type.
func (h *Header) GetType() Type {
	return Type(h.data[TypeFieldOffset])
}

// SetType sets the ICMPv6 message type.
func (h *Header) SetType(t Type) {
	h.data[TypeFieldOffset] = byte(t)
}

// GetCode returns the ICMPv6 message code.
func (h *Header) GetCode() Code {
	return Code(h.data[CodeFieldOffset])
}

// SetCode sets the ICMPv6 message code.
func (h *Header) SetCode(c Code) {
	h.data[CodeFieldOffset] = byte(c)
}

// GetChecksum returns the ICMPv6 checksum in host byte order.
func (h *Header) GetChecksum() uint16 {
	return encoding.BigEndianReadUint16(h.data[ChecksumFieldOffset:])
}

// SetChecksum sets the ICMPv6 checksum from a host byte order value.
func (h *Header) SetChecksum(cs uint16) {
	encoding.BigEndianWriteUint16(cs, h.data[ChecksumFieldOffset:])
}

// GetID returns the echo identifier from the header data field.
func (h *Header) GetID() uint16 {
	return encoding.BigEndianReadUint16(h.data[DataFieldOffset:])
}

// SetID sets the echo identifier in the header data field.
func (h *Header) SetID(id uint16) {
	encoding.BigEndianWriteUint16(id, h.data[DataFieldOffset:])
}

// GetSequence returns the echo sequence number from the header data field.
func (h *Header) GetSequence() uint16 {
	return encoding.BigEndianReadUint16(h.data[DataFieldOffset+2:])
}

// SetSequence sets the echo sequence number in the header data field.
func (h *Header) SetSequence(seq uint16) {
	encoding.BigEndianWriteUint16(seq, h.data[DataFieldOffset+2:])
}

// Clear zeros all bytes in the header.
func (h *Header) Clear() {
	h.data = [HeaderSize]byte{}
}

// MarshalBinary returns a copy of the header's raw bytes.
func (h *Header) MarshalBinary() []byte {
	out := make([]byte, HeaderSize)
	copy(out, h.data[:])
	return out
}

// UnmarshalBinary populates the header from raw bytes. The input must be
// at least HeaderSize (8) bytes long.
func (h *Header) UnmarshalBinary(b []byte) error {
	if len(b) < HeaderSize {
		return errors.ErrParse
	}
	copy(h.data[:], b[:HeaderSize])
	return nil
}

// ---------------------------------------------------------------------------
// ICMPv6 Type
// ---------------------------------------------------------------------------

// Type represents an ICMPv6 message type.
type Type uint8

// ICMPv6 message type constants.
const (
	// TypeDstUnreach is Destination Unreachable (RFC 4443).
	TypeDstUnreach Type = 1
	// TypePacketTooBig is Packet Too Big (RFC 4443).
	TypePacketTooBig Type = 2
	// TypeTimeExceeded is Time Exceeded (RFC 4443).
	TypeTimeExceeded Type = 3
	// TypeParameterProblem is Parameter Problem (RFC 4443).
	TypeParameterProblem Type = 4
	// TypeEchoRequest is Echo Request (RFC 4443).
	TypeEchoRequest Type = 128
	// TypeEchoReply is Echo Reply (RFC 4443).
	TypeEchoReply Type = 129
	// TypeRouterSolicit is Router Solicitation (RFC 4861).
	TypeRouterSolicit Type = 133
	// TypeRouterAdvert is Router Advertisement (RFC 4861).
	TypeRouterAdvert Type = 134
	// TypeNeighborSolicit is Neighbor Solicitation (RFC 4861).
	TypeNeighborSolicit Type = 135
	// TypeNeighborAdvert is Neighbor Advertisement (RFC 4861).
	TypeNeighborAdvert Type = 136
)

// ---------------------------------------------------------------------------
// ICMPv6 Code
// ---------------------------------------------------------------------------

// Code represents an ICMPv6 message code.
type Code uint8

// ICMPv6 code constants.
const (
	// CodeDstUnreachNoRoute is No Route to Destination.
	CodeDstUnreachNoRoute Code = 0
	// CodeDstUnreachProhibited is Communication Administratively Prohibited.
	CodeDstUnreachProhibited Code = 1
	// CodeFragmReasTimeEx is Fragment Reassembly Time Exceeded.
	CodeFragmReasTimeEx Code = 1
)

// ---------------------------------------------------------------------------
// EchoMode
// ---------------------------------------------------------------------------

// EchoMode controls how the ICMPv6 handler responds to echo requests.
type EchoMode uint8

// Echo mode constants.
const (
	// EchoModeDisabled disables echo replies entirely.
	EchoModeDisabled EchoMode = 0
	// EchoModeUnicastOnly replies only to unicast echo requests.
	EchoModeUnicastOnly EchoMode = 1
	// EchoModeMulticastOnly replies only to multicast echo requests.
	EchoModeMulticastOnly EchoMode = 2
	// EchoModeAll replies to all echo requests.
	EchoModeAll EchoMode = 3
	// EchoModeRlocAlocOnly replies only to RLOC/ALOC echo requests.
	EchoModeRlocAlocOnly EchoMode = 4
)

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

// Handler is a callback for received ICMPv6 messages. Each handler holds
// a function that is invoked when a matching ICMPv6 message is received.
type Handler struct {
	callback func(messageInfo *ip6.MessageInfo, header *Header)
}

// NewHandler creates a Handler with the given callback function.
func NewHandler(callback func(messageInfo *ip6.MessageInfo, header *Header)) *Handler {
	return &Handler{callback: callback}
}

// ---------------------------------------------------------------------------
// Icmp — the ICMPv6 manager
// ---------------------------------------------------------------------------

// Icmp manages ICMPv6 handler registration, echo sequencing, and echo mode.
type Icmp struct {
	handlers     []*Handler
	echoSequence uint16
	echoMode     EchoMode
}

// New creates a new Icmp manager with default settings: echo sequence
// starts at 1 and echo mode is EchoModeAll.
func New() *Icmp {
	return &Icmp{
		echoSequence: 1,
		echoMode:     EchoModeAll,
	}
}

// RegisterHandler adds an ICMPv6 handler. It returns ErrAlready if the
// handler has already been registered.
func (m *Icmp) RegisterHandler(h *Handler) error {
	for _, existing := range m.handlers {
		if existing == h {
			return errors.ErrAlready
		}
	}
	m.handlers = append(m.handlers, h)
	return nil
}

// HandleMessage dispatches an incoming ICMPv6 message to all registered
// handlers. The payload must start with the 8-byte ICMPv6 header.
func (m *Icmp) HandleMessage(payload []byte, messageInfo *ip6.MessageInfo) {
	var hdr Header
	if err := hdr.UnmarshalBinary(payload); err != nil {
		return
	}
	for _, h := range m.handlers {
		if h != nil && h.callback != nil {
			h.callback(messageInfo, &hdr)
		}
	}
}

// GetEchoMode returns the current echo mode.
func (m *Icmp) GetEchoMode() EchoMode {
	return m.echoMode
}

// SetEchoMode sets the echo mode.
func (m *Icmp) SetEchoMode(mode EchoMode) {
	m.echoMode = mode
}

// GetEchoSequence returns the current echo sequence number.
func (m *Icmp) GetEchoSequence() uint16 {
	return m.echoSequence
}

// ShouldHandleEchoRequest determines whether an echo request to the given
// address should be handled, based on the current echo mode.
func (m *Icmp) ShouldHandleEchoRequest(addr ip6.Address) bool {
	switch m.echoMode {
	case EchoModeDisabled:
		return false
	case EchoModeUnicastOnly:
		return !addr.IsMulticast()
	case EchoModeMulticastOnly:
		return addr.IsMulticast()
	case EchoModeAll:
		return true
	case EchoModeRlocAlocOnly:
		iid := addr.GetIid()
		return iid.IsRoutingLocator() || iid.IsAnycastLocator()
	default:
		return false
	}
}
