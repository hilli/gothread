// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package ie implements IEEE 802.15.4 Header Information Element parsing
// and building.
//
// This is a Go port of the IE handling in OpenThread's
// src/core/mac/mac_header_ie.hpp and src/core/mac/mac_header_ie.cpp.
//
// Header IEs are inserted between the MAC header and payload. Each IE
// has a 2-byte header encoded in little-endian:
//
//	Bits  0-6:  Length (7 bits, 0-127 bytes)
//	Bits  7-14: Element ID (8 bits)
//	Bit   15:   Type (0 = Header IE)
package ie

import (
	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/errors"
)

// Header IE Element IDs.
const (
	IEVendorSpecific     uint8 = 0x00 // Vendor-specific Header IE
	IECsl                uint8 = 0x1A // CSL IE (Coordinated Sampled Listening)
	IETimeSync           uint8 = 0x1B // Time Sync IE (Thread-specific, vendor IE)
	IEHeaderTermination1 uint8 = 0x7E // Header Termination 1 (payload follows)
	IEHeaderTermination2 uint8 = 0x7F // Header Termination 2 (no payload follows)
)

// Thread vendor OUI and sub-IE IDs.
const (
	ThreadVendorOUI     uint32 = 0xEAB89B // Thread Group vendor OUI
	ThreadIELinkMetrics uint8  = 0x00     // Enhanced ACK Link Metrics sub-IE
)

// Header IE header field layout (little-endian uint16).
const (
	headerIESize        = 2      // size of the IE header in bytes
	lengthMask   uint16 = 0x007F // bits 0-6
	idShift             = 7
	idMask       uint16 = 0x7F80 // bits 7-14
	maxLength           = 127    // max IE content length (7 bits)
)

// HeaderIE represents a parsed Header Information Element.
type HeaderIE struct {
	ElementID uint8
	Length    uint16
	Content   []byte
}

// ---------------- CSL IE ---------------------------------------------------

// CslIE contains Coordinated Sampled Listening parameters.
// The on-wire format is 4 bytes: Phase (uint16 LE) then Period (uint16 LE).
type CslIE struct {
	Period uint16 // CSL period in units of 10 symbols
	Phase  uint16 // CSL phase in units of 10 symbols
}

// CslIEContentSize is the content size of a CSL IE in bytes.
const CslIEContentSize = 4

// Marshal serialises the CSL IE content (Phase then Period) in little-endian.
func (c *CslIE) Marshal() []byte {
	buf := make([]byte, CslIEContentSize)
	encoding.LittleEndianWriteUint16(c.Phase, buf[0:2])
	encoding.LittleEndianWriteUint16(c.Period, buf[2:4])
	return buf
}

// ParseCslIE parses a CSL IE from raw content bytes.
func ParseCslIE(data []byte) (CslIE, error) {
	if len(data) < CslIEContentSize {
		return CslIE{}, errors.ErrParse
	}
	return CslIE{
		Phase:  encoding.LittleEndianReadUint16(data[0:2]),
		Period: encoding.LittleEndianReadUint16(data[2:4]),
	}, nil
}

// ---------------- Time Sync IE ---------------------------------------------

// TimeSyncIE contains network time synchronisation data.
// The on-wire format is 10 bytes: Sequence (1 byte) then Time (int64, 8 bytes LE).
type TimeSyncIE struct {
	Sequence uint8 // time sync sequence number
	Time     int64 // network time in microseconds
}

// TimeSyncIEContentSize is the content size of a Time Sync IE in bytes.
const TimeSyncIEContentSize = 9 // 1 (sequence) + 8 (time)

// Marshal serialises the Time Sync IE content in little-endian.
func (t *TimeSyncIE) Marshal() []byte {
	buf := make([]byte, TimeSyncIEContentSize)
	buf[0] = t.Sequence
	encoding.LittleEndianWriteUint64(uint64(t.Time), buf[1:9])
	return buf
}

// ParseTimeSyncIE parses a Time Sync IE from raw content bytes.
func ParseTimeSyncIE(data []byte) (TimeSyncIE, error) {
	if len(data) < TimeSyncIEContentSize {
		return TimeSyncIE{}, errors.ErrParse
	}
	return TimeSyncIE{
		Sequence: data[0],
		Time:     int64(encoding.LittleEndianReadUint64(data[1:9])),
	}, nil
}

// ---------------- IE Header encode/decode ----------------------------------

// encodeIEHeader builds the 2-byte Header IE header for the given element ID
// and content length, returned as a little-endian uint16.
func encodeIEHeader(elementID uint8, length uint16) uint16 {
	return (length & lengthMask) | (uint16(elementID) << idShift)
}

// decodeIEHeader extracts the element ID and content length from a 2-byte
// Header IE header (little-endian uint16).
func decodeIEHeader(h uint16) (elementID uint8, length uint16) {
	length = h & lengthMask
	elementID = uint8((h & idMask) >> idShift)
	return
}

// ---------------- Parser ---------------------------------------------------

// ParseHeaderIEs parses Header IEs from raw bytes. It returns the parsed
// IEs, the total number of bytes consumed, and any error. Parsing stops
// when a termination IE is encountered or the data is exhausted.
func ParseHeaderIEs(data []byte) ([]HeaderIE, int, error) {
	var ies []HeaderIE
	offset := 0

	for offset+headerIESize <= len(data) {
		h := encoding.LittleEndianReadUint16(data[offset : offset+headerIESize])
		elemID, length := decodeIEHeader(h)
		offset += headerIESize

		contentLen := int(length)
		if offset+contentLen > len(data) {
			return ies, offset - headerIESize, errors.ErrParse
		}

		var content []byte
		if contentLen > 0 {
			content = make([]byte, contentLen)
			copy(content, data[offset:offset+contentLen])
		}
		offset += contentLen

		ie := HeaderIE{
			ElementID: elemID,
			Length:    length,
			Content:   content,
		}
		ies = append(ies, ie)

		// Stop on termination IEs.
		if elemID == IEHeaderTermination1 || elemID == IEHeaderTermination2 {
			break
		}
	}

	return ies, offset, nil
}

// ---------------- Builder --------------------------------------------------

// AppendHeaderIE appends a Header IE with the given element ID and content
// to buf, returning the extended buffer.
func AppendHeaderIE(buf []byte, elementID uint8, content []byte) []byte {
	h := encodeIEHeader(elementID, uint16(len(content)))
	var hdr [headerIESize]byte
	encoding.LittleEndianWriteUint16(h, hdr[:])
	buf = append(buf, hdr[:]...)
	buf = append(buf, content...)
	return buf
}

// AppendTermination1 appends a Header Termination 1 IE (payload follows).
func AppendTermination1(buf []byte) []byte {
	return AppendHeaderIE(buf, IEHeaderTermination1, nil)
}

// AppendTermination2 appends a Header Termination 2 IE (no payload follows).
func AppendTermination2(buf []byte) []byte {
	return AppendHeaderIE(buf, IEHeaderTermination2, nil)
}

// AppendCslIE appends a CSL Header IE with the given period and phase.
func AppendCslIE(buf []byte, period, phase uint16) []byte {
	csl := CslIE{Period: period, Phase: phase}
	return AppendHeaderIE(buf, IECsl, csl.Marshal())
}

// ---------------- Lookup ---------------------------------------------------

// FindHeaderIE finds the first IE with the given Element ID in the list.
// Returns a pointer to the IE and true if found, nil and false otherwise.
func FindHeaderIE(ies []HeaderIE, elementID uint8) (*HeaderIE, bool) {
	for i := range ies {
		if ies[i].ElementID == elementID {
			return &ies[i], true
		}
	}
	return nil, false
}
