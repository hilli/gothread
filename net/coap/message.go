// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package coap implements CoAP message parsing and building per RFC 7252.
//
// This is a Go port of the CoAP message handling in OpenThread's
// src/core/coap/coap_message.hpp, src/core/coap/coap_message.cpp,
// and include/openthread/coap.h.
package coap

import (
	"fmt"
	"strings"

	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Message Type
// ---------------------------------------------------------------------------

// Type represents the CoAP message type (2 bits in the header).
type Type uint8

const (
	// TypeConfirmable indicates a confirmable message (CON).
	TypeConfirmable Type = 0
	// TypeNonConfirmable indicates a non-confirmable message (NON).
	TypeNonConfirmable Type = 1
	// TypeAck indicates an acknowledgement message (ACK).
	TypeAck Type = 2
	// TypeReset indicates a reset message (RST).
	TypeReset Type = 3
)

// ---------------------------------------------------------------------------
// Code
// ---------------------------------------------------------------------------

// Code represents the CoAP code field (8 bits: class<<5 | detail).
type Code uint8

// Request codes (0.xx).
const (
	CodeEmpty  Code = 0x00 // 0.00
	CodeGet    Code = 0x01 // 0.01
	CodePost   Code = 0x02 // 0.02
	CodePut    Code = 0x03 // 0.03
	CodeDelete Code = 0x04 // 0.04
)

// Success codes (2.xx).
const (
	CodeCreated Code = 0x41 // 2.01
	CodeDeleted Code = 0x42 // 2.02
	CodeValid   Code = 0x43 // 2.03
	CodeChanged Code = 0x44 // 2.04
	CodeContent Code = 0x45 // 2.05
)

// Client error codes (4.xx).
const (
	CodeBadRequest         Code = 0x80 // 4.00
	CodeUnauthorized       Code = 0x81 // 4.01
	CodeBadOption          Code = 0x82 // 4.02
	CodeForbidden          Code = 0x83 // 4.03
	CodeNotFound           Code = 0x84 // 4.04
	CodeMethodNotAllowed   Code = 0x85 // 4.05
	CodeNotAcceptable      Code = 0x86 // 4.06
	CodeRequestIncomplete  Code = 0x88 // 4.08
	CodeConflict           Code = 0x89 // 4.09
	CodePreconditionFailed Code = 0x8c // 4.12
	CodeRequestTooLarge    Code = 0x8d // 4.13
	CodeUnsupportedFormat  Code = 0x8f // 4.15
)

// Server error codes (5.xx).
const (
	CodeInternalError      Code = 0xa0 // 5.00
	CodeNotImplemented     Code = 0xa1 // 5.01
	CodeBadGateway         Code = 0xa2 // 5.02
	CodeServiceUnavailable Code = 0xa3 // 5.03
	CodeGatewayTimeout     Code = 0xa4 // 5.04
	CodeProxyNotSupported  Code = 0xa5 // 5.05
)

// GetClass returns the code class (upper 3 bits).
func (c Code) GetClass() uint8 { return uint8(c) >> 5 }

// GetDetail returns the code detail (lower 5 bits).
func (c Code) GetDetail() uint8 { return uint8(c) & 0x1f }

// IsRequest reports whether c is a request code (0.01-0.04).
func (c Code) IsRequest() bool { return c >= CodeGet && c <= CodeDelete }

// IsResponse reports whether c is a response code (class >= 2).
func (c Code) IsResponse() bool { return c >= 0x40 }

// IsEmpty reports whether c is the empty code (0.00).
func (c Code) IsEmpty() bool { return c == CodeEmpty }

// IsSuccess reports whether c is a success code (2.xx).
func (c Code) IsSuccess() bool { return c.GetClass() == 2 }

// IsClientError reports whether c is a client error code (4.xx).
func (c Code) IsClientError() bool { return c.GetClass() == 4 }

// IsServerError reports whether c is a server error code (5.xx).
func (c Code) IsServerError() bool { return c.GetClass() == 5 }

// ToString returns the code in "class.detail" format (e.g. "2.05").
func (c Code) ToString() string {
	return fmt.Sprintf("%d.%02d", c.GetClass(), c.GetDetail())
}

// ---------------------------------------------------------------------------
// Option Numbers
// ---------------------------------------------------------------------------

// OptionNumber identifies a CoAP option per RFC 7252.
type OptionNumber uint16

const (
	// OptionIfMatch is the If-Match option (opaque, RFC 7252 Section 5.10.8.1).
	OptionIfMatch OptionNumber = 1
	// OptionURIHost is the Uri-Host option (string, RFC 7252 Section 5.10.1).
	OptionURIHost OptionNumber = 3
	// OptionETag is the ETag option (opaque, RFC 7252 Section 5.10.6).
	OptionETag OptionNumber = 4
	// OptionIfNoneMatch is the If-None-Match option (empty, RFC 7252 Section 5.10.8.2).
	OptionIfNoneMatch OptionNumber = 5
	// OptionObserve is the Observe option (uint, RFC 7641).
	OptionObserve OptionNumber = 6
	// OptionURIPort is the Uri-Port option (uint, RFC 7252 Section 5.10.1).
	OptionURIPort OptionNumber = 7
	// OptionLocationPath is the Location-Path option (string, RFC 7252 Section 5.10.7).
	OptionLocationPath OptionNumber = 8
	// OptionURIPath is the Uri-Path option (string, RFC 7252 Section 5.10.1).
	OptionURIPath OptionNumber = 11
	// OptionContentFormat is the Content-Format option (uint, RFC 7252 Section 5.10.3).
	OptionContentFormat OptionNumber = 12
	// OptionMaxAge is the Max-Age option (uint, RFC 7252 Section 5.10.5).
	OptionMaxAge OptionNumber = 14
	// OptionURIQuery is the Uri-Query option (string, RFC 7252 Section 5.10.1).
	OptionURIQuery OptionNumber = 15
	// OptionAccept is the Accept option (uint, RFC 7252 Section 5.10.4).
	OptionAccept OptionNumber = 17
	// OptionLocationQuery is the Location-Query option (string, RFC 7252 Section 5.10.7).
	OptionLocationQuery OptionNumber = 20
	// OptionBlock2 is the Block2 option (uint, RFC 7959).
	OptionBlock2 OptionNumber = 23
	// OptionBlock1 is the Block1 option (uint, RFC 7959).
	OptionBlock1 OptionNumber = 27
	// OptionSize2 is the Size2 option (uint, RFC 7959).
	OptionSize2 OptionNumber = 28
	// OptionProxyURI is the Proxy-Uri option (string, RFC 7252 Section 5.10.2).
	OptionProxyURI OptionNumber = 35
	// OptionProxyScheme is the Proxy-Scheme option (string, RFC 7252 Section 5.10.2).
	OptionProxyScheme OptionNumber = 39
	// OptionSize1 is the Size1 option (uint, RFC 7252 Section 5.10.9).
	OptionSize1 OptionNumber = 60
)

// ---------------------------------------------------------------------------
// Content Format
// ---------------------------------------------------------------------------

// ContentFormat identifies the content encoding of a CoAP payload.
type ContentFormat uint16

const (
	// ContentFormatTextPlain is the text/plain content format (UTF-8).
	ContentFormatTextPlain ContentFormat = 0
	// ContentFormatLinkFormat is the application/link-format content format.
	ContentFormatLinkFormat ContentFormat = 40
	// ContentFormatXML is the application/xml content format.
	ContentFormatXML ContentFormat = 41
	// ContentFormatOctetStream is the application/octet-stream content format.
	ContentFormatOctetStream ContentFormat = 42
	// ContentFormatJSON is the application/json content format.
	ContentFormatJSON ContentFormat = 50
	// ContentFormatCBOR is the application/cbor content format.
	ContentFormatCBOR ContentFormat = 60
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	// HeaderSize is the fixed CoAP header size in bytes.
	HeaderSize = 4

	// MaxTokenLength is the maximum token length (RFC 7252 sec 3).
	MaxTokenLength = 8

	// PayloadMarker is the byte that separates options from payload (0xFF).
	PayloadMarker byte = 0xFF

	// coapVersion is the CoAP version number (always 1).
	coapVersion = 1
)

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

// Message represents a CoAP message being built or parsed. The underlying
// data slice holds the complete wire representation: header + token +
// options + optional payload marker + payload.
type Message struct {
	data       []byte
	lastOption OptionNumber // tracks the last appended option for delta encoding
}

// ---------------------------------------------------------------------------
// Builder API
// ---------------------------------------------------------------------------

// NewMessage creates a new CoAP message with the given type, code, and
// message ID. The initial message contains only the 4-byte header with
// token length 0.
func NewMessage(typ Type, code Code, messageID uint16) *Message {
	m := &Message{
		data: make([]byte, HeaderSize),
	}
	// Byte 0: Version(2) | Type(2) | TKL(4)
	m.data[0] = (coapVersion << 6) | (uint8(typ) << 4)
	// Byte 1: Code
	m.data[1] = uint8(code)
	// Byte 2-3: MessageID (big-endian)
	encoding.BigEndianWriteUint16(messageID, m.data[2:4])
	return m
}

// SetToken sets the message token (0-8 bytes). It replaces any previously
// set token and updates the TKL field in the header. SetToken must be called
// before appending options or payload.
func (m *Message) SetToken(token []byte) error {
	if len(token) > MaxTokenLength {
		return errors.ErrInvalidArgs
	}
	if len(m.data) > HeaderSize {
		// Token must be set before options/payload.
		return errors.ErrInvalidState
	}
	// Reset to header only, then append token.
	m.data = m.data[:HeaderSize]
	m.data = append(m.data, token...)
	// Update TKL in header byte 0.
	m.data[0] = (m.data[0] & 0xF0) | uint8(len(token))
	return nil
}

// GetToken returns the token bytes, or nil if the token length is 0.
func (m *Message) GetToken() []byte {
	tkl := int(m.data[0] & 0x0F)
	if tkl == 0 {
		return nil
	}
	return m.data[HeaderSize : HeaderSize+tkl]
}

// ---------------------------------------------------------------------------
// Option encoding helpers
// ---------------------------------------------------------------------------

// encodeOptionHeader appends the option delta/length header (and any
// extended bytes) to buf and returns the result.
func encodeOptionHeader(buf []byte, delta, length uint16) []byte {
	deltaNibble, deltaExt := encodeNibble(delta)
	lengthNibble, lengthExt := encodeNibble(length)

	buf = append(buf, (deltaNibble<<4)|lengthNibble)
	buf = append(buf, deltaExt...)
	buf = append(buf, lengthExt...)
	return buf
}

// encodeNibble encodes a value into a 4-bit nibble plus optional extended
// bytes per RFC 7252 section 3.1.
func encodeNibble(v uint16) (nibble byte, ext []byte) {
	if v < 13 {
		return byte(v), nil
	}
	if v < 269 {
		return 13, []byte{byte(v - 13)}
	}
	ext = make([]byte, 2)
	encoding.BigEndianWriteUint16(v-269, ext)
	return 14, ext
}

// encodeUintOption encodes a uint32 value in big-endian with leading zero
// bytes stripped. Value 0 produces an empty slice.
func encodeUintOption(v uint32) []byte {
	if v == 0 {
		return nil
	}
	if v <= 0xFF {
		return []byte{byte(v)}
	}
	if v <= 0xFFFF {
		b := make([]byte, 2)
		encoding.BigEndianWriteUint16(uint16(v), b)
		return b
	}
	if v <= 0xFFFFFF {
		b := make([]byte, 3)
		encoding.BigEndianWriteUint24(v, b)
		return b
	}
	b := make([]byte, 4)
	encoding.BigEndianWriteUint32(v, b)
	return b
}

// AppendOption appends a raw option with the given number and value to the
// message. Options MUST be appended in non-decreasing order of option
// number; calling this with a number less than the previously appended
// option returns ErrInvalidArgs.
func (m *Message) AppendOption(number OptionNumber, value []byte) error {
	if number < m.lastOption {
		return errors.ErrInvalidArgs
	}
	delta := uint16(number - m.lastOption)
	length := uint16(len(value))

	m.data = encodeOptionHeader(m.data, delta, length)
	m.data = append(m.data, value...)
	m.lastOption = number
	return nil
}

// AppendUintOption appends an option with a uint32 value encoded in
// big-endian with leading zero bytes stripped.
func (m *Message) AppendUintOption(number OptionNumber, value uint32) error {
	return m.AppendOption(number, encodeUintOption(value))
}

// AppendStringOption appends an option with a string value.
func (m *Message) AppendStringOption(number OptionNumber, value string) error {
	return m.AppendOption(number, []byte(value))
}

// AppendURIPathOptions splits path on '/' and appends each non-empty
// segment as a Uri-Path option. A leading '/' is ignored.
func (m *Message) AppendURIPathOptions(path string) error {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return nil
	}
	for _, seg := range strings.Split(path, "/") {
		if err := m.AppendStringOption(OptionURIPath, seg); err != nil {
			return err
		}
	}
	return nil
}

// AppendURIQueryOptions splits query on '&' and appends each non-empty
// segment as a Uri-Query option.
func (m *Message) AppendURIQueryOptions(query string) error {
	if query == "" {
		return nil
	}
	for _, seg := range strings.Split(query, "&") {
		if err := m.AppendStringOption(OptionURIQuery, seg); err != nil {
			return err
		}
	}
	return nil
}

// AppendContentFormatOption appends a Content-Format option.
func (m *Message) AppendContentFormatOption(format ContentFormat) error {
	return m.AppendUintOption(OptionContentFormat, uint32(format))
}

// AppendMaxAgeOption appends a Max-Age option.
func (m *Message) AppendMaxAgeOption(maxAge uint32) error {
	return m.AppendUintOption(OptionMaxAge, maxAge)
}

// AppendObserveOption appends an Observe option.
func (m *Message) AppendObserveOption(value uint32) error {
	return m.AppendUintOption(OptionObserve, value)
}

// AppendBlockOption appends a Block1 or Block2 option. The number must be
// OptionBlock1 or OptionBlock2. blockNum is the block sequence number, more
// indicates whether more blocks follow, and szx is the size exponent (0-6,
// where block size = 2^(szx+4)).
func (m *Message) AppendBlockOption(number OptionNumber, blockNum uint32, more bool, szx uint8) error {
	if szx > 6 {
		return errors.ErrInvalidArgs
	}
	val := (blockNum << 4) | uint32(szx)
	if more {
		val |= 0x08
	}
	return m.AppendUintOption(number, val)
}

// AppendPayloadMarker appends the 0xFF payload marker byte.
func (m *Message) AppendPayloadMarker() error {
	m.data = append(m.data, PayloadMarker)
	return nil
}

// AppendPayload appends raw payload bytes. The caller should have already
// appended the payload marker.
func (m *Message) AppendPayload(payload []byte) error {
	m.data = append(m.data, payload...)
	return nil
}

// GetBytes returns the complete wire-format message.
func (m *Message) GetBytes() []byte {
	return m.data
}

// ---------------------------------------------------------------------------
// Parser API
// ---------------------------------------------------------------------------

// ParseMessage validates and wraps raw CoAP message data. It checks the
// header version, token length, option structure, and payload marker. The
// returned Message shares the underlying data slice.
func ParseMessage(data []byte) (*Message, error) {
	if len(data) < HeaderSize {
		return nil, errors.ErrParse
	}
	ver := data[0] >> 6
	if ver != coapVersion {
		return nil, errors.ErrParse
	}
	tkl := int(data[0] & 0x0F)
	if tkl > MaxTokenLength {
		return nil, errors.ErrParse
	}
	if len(data) < HeaderSize+tkl {
		return nil, errors.ErrParse
	}

	// Walk options to validate structure.
	offset := HeaderSize + tkl
	var lastOptNum OptionNumber
	for offset < len(data) {
		b := data[offset]
		if b == PayloadMarker {
			// Payload marker must be followed by at least one payload byte.
			if offset+1 >= len(data) {
				return nil, errors.ErrParse
			}
			break
		}

		// Decode delta nibble.
		deltaNibble := b >> 4
		lengthNibble := b & 0x0F
		offset++

		delta, n, err := decodeNibble(deltaNibble, data, offset)
		if err != nil {
			return nil, err
		}
		offset += n

		optLen, n, err := decodeNibble(lengthNibble, data, offset)
		if err != nil {
			return nil, err
		}
		offset += n

		lastOptNum += OptionNumber(delta)
		if offset+int(optLen) > len(data) {
			return nil, errors.ErrParse
		}
		offset += int(optLen)
	}
	_ = lastOptNum

	return &Message{data: data}, nil
}

// decodeNibble decodes a 4-bit nibble value and returns the decoded value,
// the number of extra bytes consumed, and any error. nibble value 15 is
// reserved and yields ErrParse.
func decodeNibble(nibble byte, data []byte, offset int) (uint16, int, error) {
	switch {
	case nibble < 13:
		return uint16(nibble), 0, nil
	case nibble == 13:
		if offset >= len(data) {
			return 0, 0, errors.ErrParse
		}
		return uint16(data[offset]) + 13, 1, nil
	case nibble == 14:
		if offset+2 > len(data) {
			return 0, 0, errors.ErrParse
		}
		return encoding.BigEndianReadUint16(data[offset:offset+2]) + 269, 2, nil
	default:
		// nibble == 15 is a message format error.
		return 0, 0, errors.ErrParse
	}
}

// GetType returns the message type.
func (m *Message) GetType() Type {
	return Type((m.data[0] >> 4) & 0x03)
}

// GetCode returns the message code.
func (m *Message) GetCode() Code {
	return Code(m.data[1])
}

// GetMessageID returns the message ID.
func (m *Message) GetMessageID() uint16 {
	return encoding.BigEndianReadUint16(m.data[2:4])
}

// GetTokenLength returns the token length from the header.
func (m *Message) GetTokenLength() uint8 {
	return m.data[0] & 0x0F
}

// ---------------------------------------------------------------------------
// Option Iterator
// ---------------------------------------------------------------------------

// OptionIterator iterates over the options in a parsed CoAP message.
type OptionIterator struct {
	data      []byte
	offset    int
	optionNum OptionNumber
}

// GetOptionIterator returns an iterator positioned at the first option.
func (m *Message) GetOptionIterator() OptionIterator {
	tkl := int(m.data[0] & 0x0F)
	return OptionIterator{
		data:   m.data,
		offset: HeaderSize + tkl,
	}
}

// Next advances the iterator and returns the next option. It returns
// (number, value, true) for each option, or (0, nil, false) when all
// options have been consumed or the payload marker is reached.
func (it *OptionIterator) Next() (OptionNumber, []byte, bool) {
	if it.offset >= len(it.data) {
		return 0, nil, false
	}
	b := it.data[it.offset]
	if b == PayloadMarker {
		return 0, nil, false
	}

	deltaNibble := b >> 4
	lengthNibble := b & 0x0F
	it.offset++

	delta, n, err := decodeNibble(deltaNibble, it.data, it.offset)
	if err != nil {
		return 0, nil, false
	}
	it.offset += n

	optLen, n, err := decodeNibble(lengthNibble, it.data, it.offset)
	if err != nil {
		return 0, nil, false
	}
	it.offset += n

	it.optionNum += OptionNumber(delta)
	value := it.data[it.offset : it.offset+int(optLen)]
	it.offset += int(optLen)

	return it.optionNum, value, true
}

// ---------------------------------------------------------------------------
// Payload
// ---------------------------------------------------------------------------

// GetPayload returns the payload bytes after the 0xFF payload marker,
// or nil if there is no payload.
func (m *Message) GetPayload() []byte {
	tkl := int(m.data[0] & 0x0F)
	offset := HeaderSize + tkl

	for offset < len(m.data) {
		b := m.data[offset]
		if b == PayloadMarker {
			return m.data[offset+1:]
		}

		// Skip this option.
		deltaNibble := b >> 4
		lengthNibble := b & 0x0F
		offset++

		_, n, err := decodeNibble(deltaNibble, m.data, offset)
		if err != nil {
			return nil
		}
		offset += n

		optLen, n, err := decodeNibble(lengthNibble, m.data, offset)
		if err != nil {
			return nil
		}
		offset += n
		offset += int(optLen)
	}
	return nil
}
