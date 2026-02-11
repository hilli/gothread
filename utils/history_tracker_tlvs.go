// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"encoding/binary"

	"github.com/hilli/gothread/errors"
)

// HistoryTrackerTLV type codes matching the C++ Tlv::Type enum.
const (
	HTTlvQueryID     uint8 = 0
	HTTlvAnswer      uint8 = 1
	HTTlvRequest     uint8 = 2
	HTTlvNetworkInfo uint8 = 3
)

// htTlvHeaderSize is the standard TLV header: 1 byte type + 1 byte length.
const htTlvHeaderSize = 2

// AnswerTlv represents a History Tracker Answer TLV.
//
// Wire format (big-endian, after TLV header):
//
//	Byte 0-1: FlagsIndex (uint16)
//	  Bit 15:   IsLast flag
//	  Bits 0-14: Index
//
// Reference: openthread/src/core/utils/history_tracker_tlvs.hpp AnswerTlv
type AnswerTlv struct {
	Index  uint16
	IsLast bool
}

const (
	answerIsLastFlag uint16 = 1 << 15
	answerIndexMask  uint16 = 0x7FFF
	answerValueSize         = 2
)

// MarshalAnswerTlv serializes an AnswerTlv to wire format.
func MarshalAnswerTlv(a *AnswerTlv) []byte {
	buf := make([]byte, htTlvHeaderSize+answerValueSize)
	buf[0] = HTTlvAnswer
	buf[1] = answerValueSize

	flagsIndex := a.Index & answerIndexMask
	if a.IsLast {
		flagsIndex |= answerIsLastFlag
	}
	binary.BigEndian.PutUint16(buf[2:4], flagsIndex)
	return buf
}

// ParseAnswerTlv parses an AnswerTlv from the value portion of a TLV
// (after the type and length bytes have been read).
func ParseAnswerTlv(value []byte) (*AnswerTlv, error) {
	if len(value) < answerValueSize {
		return nil, errors.ErrParse
	}
	flagsIndex := binary.BigEndian.Uint16(value[:2])
	return &AnswerTlv{
		Index:  flagsIndex & answerIndexMask,
		IsLast: flagsIndex&answerIsLastFlag != 0,
	}, nil
}

// RequestTlv represents a History Tracker Request TLV.
//
// Wire format (big-endian, after TLV header):
//
//	Byte 0:   TlvType (uint8) — the type of data being requested
//	Byte 1-2: NumEntries (uint16) — max entries to return (0 = all)
//	Byte 3-6: MaxEntryAge (uint32) — max age in ms (0 = no limit)
//
// Reference: openthread/src/core/utils/history_tracker_tlvs.hpp RequestTlv
type RequestTlv struct {
	TlvType     uint8
	NumEntries  uint16
	MaxEntryAge uint32
}

const requestValueSize = 1 + 2 + 4 // 7 bytes

// MarshalRequestTlv serializes a RequestTlv to wire format.
func MarshalRequestTlv(r *RequestTlv) []byte {
	buf := make([]byte, htTlvHeaderSize+requestValueSize)
	buf[0] = HTTlvRequest
	buf[1] = requestValueSize
	buf[2] = r.TlvType
	binary.BigEndian.PutUint16(buf[3:5], r.NumEntries)
	binary.BigEndian.PutUint32(buf[5:9], r.MaxEntryAge)
	return buf
}

// ParseRequestTlv parses a RequestTlv from the value portion of a TLV.
func ParseRequestTlv(value []byte) (*RequestTlv, error) {
	if len(value) < requestValueSize {
		return nil, errors.ErrParse
	}
	return &RequestTlv{
		TlvType:     value[0],
		NumEntries:  binary.BigEndian.Uint16(value[1:3]),
		MaxEntryAge: binary.BigEndian.Uint32(value[3:7]),
	}, nil
}

// IsValidRequestTlv checks whether the value portion has at least the
// minimum required length.
func IsValidRequestTlv(value []byte) bool {
	return len(value) >= requestValueSize
}

// NetworkInfoTlv represents a History Tracker Network Info TLV.
//
// Wire format (big-endian, after TLV header):
//
//	Byte 0-3: EntryAge (uint32) — age in milliseconds
//	Byte 4:   Role (uint8) — device role
//	Byte 5:   Mode (uint8) — device mode flags
//	Byte 6-7: Rloc16 (uint16) — RLOC16
//	Byte 8-11: PartitionId (uint32) — Thread partition ID
//
// Reference: openthread/src/core/utils/history_tracker_tlvs.hpp NetworkInfoTlv
type NetworkInfoTlv struct {
	EntryAge    uint32
	Role        uint8
	Mode        uint8
	Rloc16      uint16
	PartitionId uint32
}

const networkInfoValueSize = 4 + 1 + 1 + 2 + 4 // 12 bytes

// MarshalNetworkInfoTlv serializes a NetworkInfoTlv to wire format.
func MarshalNetworkInfoTlv(n *NetworkInfoTlv) []byte {
	buf := make([]byte, htTlvHeaderSize+networkInfoValueSize)
	buf[0] = HTTlvNetworkInfo
	buf[1] = networkInfoValueSize
	binary.BigEndian.PutUint32(buf[2:6], n.EntryAge)
	buf[6] = n.Role
	buf[7] = n.Mode
	binary.BigEndian.PutUint16(buf[8:10], n.Rloc16)
	binary.BigEndian.PutUint32(buf[10:14], n.PartitionId)
	return buf
}

// ParseNetworkInfoTlv parses a NetworkInfoTlv from the value portion of a TLV.
func ParseNetworkInfoTlv(value []byte) (*NetworkInfoTlv, error) {
	if len(value) < networkInfoValueSize {
		return nil, errors.ErrParse
	}
	return &NetworkInfoTlv{
		EntryAge:    binary.BigEndian.Uint32(value[:4]),
		Role:        value[4],
		Mode:        value[5],
		Rloc16:      binary.BigEndian.Uint16(value[6:8]),
		PartitionId: binary.BigEndian.Uint32(value[8:12]),
	}, nil
}

// IsValidNetworkInfoTlv checks whether the value portion has at least the
// minimum required length.
func IsValidNetworkInfoTlv(value []byte) bool {
	return len(value) >= networkInfoValueSize
}

// MarshalEmptyNetworkInfoTlv creates an empty NetworkInfo TLV (length=0),
// used as a terminator in server responses.
func MarshalEmptyNetworkInfoTlv() []byte {
	return []byte{HTTlvNetworkInfo, 0}
}

// QueryIDTlv helpers — QueryID is a simple uint16 value TLV.

const queryIDValueSize = 2

// MarshalQueryIDTlv serializes a QueryID TLV.
func MarshalQueryIDTlv(queryID uint16) []byte {
	buf := make([]byte, htTlvHeaderSize+queryIDValueSize)
	buf[0] = HTTlvQueryID
	buf[1] = queryIDValueSize
	binary.BigEndian.PutUint16(buf[2:4], queryID)
	return buf
}

// ParseQueryIDTlv parses a QueryID from the value portion of a TLV.
func ParseQueryIDTlv(value []byte) (uint16, error) {
	if len(value) < queryIDValueSize {
		return 0, errors.ErrParse
	}
	return binary.BigEndian.Uint16(value[:2]), nil
}

// ParseHTTlv reads a single History Tracker TLV from a byte slice.
// It returns the TLV type, the value bytes, the total number of bytes
// consumed, and any error.
func ParseHTTlv(data []byte) (tlvType uint8, value []byte, consumed int, err error) {
	if len(data) < htTlvHeaderSize {
		return 0, nil, 0, errors.ErrParse
	}
	tlvType = data[0]
	length := int(data[1])
	consumed = htTlvHeaderSize + length
	if len(data) < consumed {
		return 0, nil, 0, errors.ErrParse
	}
	value = data[htTlvHeaderSize:consumed]
	return tlvType, value, consumed, nil
}
