// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package tlvs defines Thread Network Layer TLV types and serialization.
//
// This is a Go port of the TLV definitions from OpenThread's
// src/core/thread/thread_tlvs.hpp.
package tlvs

import (
	"encoding/binary"

	"github.com/hilli/gothread/errors"
)

// Thread Network Layer TLV type constants.
const (
	TypeTarget                uint8 = 0
	TypeExtMACAddress         uint8 = 1
	TypeRLOC16                uint8 = 2
	TypeMeshLocalEID          uint8 = 3
	TypeStatus                uint8 = 4
	TypeLastTransactionTime   uint8 = 5
	TypeRouterMask            uint8 = 6
	TypeNDOption              uint8 = 7
	TypeNDData                uint8 = 8
	TypeThreadNetworkData     uint8 = 9
	TypeTimeout               uint8 = 10
	TypeIPv6Addresses         uint8 = 11
	TypeCommissionerUDPPort   uint8 = 12
	TypeTMFForwardingPort     uint8 = 13
	TypeJoinerUDPPort         uint8 = 14
	TypeCommissionerSessionID uint8 = 15
)

// Status TLV values.
const (
	StatusSuccess               uint8 = 0
	StatusNoAddressAvailable    uint8 = 1
	StatusTooFewRouters         uint8 = 2
	StatusHaveChildIDRequest    uint8 = 3
	StatusParentPartitionChange uint8 = 4
)

// TLV wire format: 1 byte type, 1 byte length, N bytes value.
const tlvHeaderSize = 2

// TargetTlv holds a 16-byte IPv6 target address.
type TargetTlv struct {
	Target [16]byte
}

// Type returns the TLV type constant for TargetTlv.
func (t *TargetTlv) Type() uint8 { return TypeTarget }

// Serialize returns the wire-format bytes.
func (t *TargetTlv) Serialize() []byte {
	buf := make([]byte, tlvHeaderSize+16)
	buf[0] = TypeTarget
	buf[1] = 16
	copy(buf[2:], t.Target[:])
	return buf
}

// ParseTargetTlv parses a TargetTlv from wire-format data.
func ParseTargetTlv(data []byte) (TargetTlv, error) {
	var t TargetTlv
	if len(data) < tlvHeaderSize {
		return t, errors.ErrParse
	}
	if data[0] != TypeTarget {
		return t, errors.ErrParse
	}
	length := int(data[1])
	if length != 16 || len(data) < tlvHeaderSize+length {
		return t, errors.ErrParse
	}
	copy(t.Target[:], data[2:18])
	return t, nil
}

// Rloc16Tlv holds a 16-bit RLOC16 value.
type Rloc16Tlv struct {
	RLOC16 uint16
}

// Type returns the TLV type constant for Rloc16Tlv.
func (t *Rloc16Tlv) Type() uint8 { return TypeRLOC16 }

// Serialize returns the wire-format bytes.
func (t *Rloc16Tlv) Serialize() []byte {
	buf := make([]byte, tlvHeaderSize+2)
	buf[0] = TypeRLOC16
	buf[1] = 2
	binary.BigEndian.PutUint16(buf[2:], t.RLOC16)
	return buf
}

// ParseRloc16Tlv parses an Rloc16Tlv from wire-format data.
func ParseRloc16Tlv(data []byte) (Rloc16Tlv, error) {
	var t Rloc16Tlv
	if len(data) < tlvHeaderSize {
		return t, errors.ErrParse
	}
	if data[0] != TypeRLOC16 {
		return t, errors.ErrParse
	}
	length := int(data[1])
	if length != 2 || len(data) < tlvHeaderSize+length {
		return t, errors.ErrParse
	}
	t.RLOC16 = binary.BigEndian.Uint16(data[2:4])
	return t, nil
}

// MeshLocalEidTlv holds an 8-byte mesh-local interface identifier.
type MeshLocalEidTlv struct {
	IID [8]byte
}

// Type returns the TLV type constant for MeshLocalEidTlv.
func (t *MeshLocalEidTlv) Type() uint8 { return TypeMeshLocalEID }

// Serialize returns the wire-format bytes.
func (t *MeshLocalEidTlv) Serialize() []byte {
	buf := make([]byte, tlvHeaderSize+8)
	buf[0] = TypeMeshLocalEID
	buf[1] = 8
	copy(buf[2:], t.IID[:])
	return buf
}

// ParseMeshLocalEidTlv parses a MeshLocalEidTlv from wire-format data.
func ParseMeshLocalEidTlv(data []byte) (MeshLocalEidTlv, error) {
	var t MeshLocalEidTlv
	if len(data) < tlvHeaderSize {
		return t, errors.ErrParse
	}
	if data[0] != TypeMeshLocalEID {
		return t, errors.ErrParse
	}
	length := int(data[1])
	if length != 8 || len(data) < tlvHeaderSize+length {
		return t, errors.ErrParse
	}
	copy(t.IID[:], data[2:10])
	return t, nil
}

// StatusTlv holds a status code.
type StatusTlv struct {
	Status uint8
}

// Type returns the TLV type constant for StatusTlv.
func (t *StatusTlv) Type() uint8 { return TypeStatus }

// Serialize returns the wire-format bytes.
func (t *StatusTlv) Serialize() []byte {
	return []byte{TypeStatus, 1, t.Status}
}

// ParseStatusTlv parses a StatusTlv from wire-format data.
func ParseStatusTlv(data []byte) (StatusTlv, error) {
	var t StatusTlv
	if len(data) < tlvHeaderSize {
		return t, errors.ErrParse
	}
	if data[0] != TypeStatus {
		return t, errors.ErrParse
	}
	length := int(data[1])
	if length != 1 || len(data) < tlvHeaderSize+length {
		return t, errors.ErrParse
	}
	t.Status = data[2]
	return t, nil
}

// TimeoutTlv holds a 32-bit timeout value in seconds.
type TimeoutTlv struct {
	Timeout uint32
}

// Type returns the TLV type constant for TimeoutTlv.
func (t *TimeoutTlv) Type() uint8 { return TypeTimeout }

// Serialize returns the wire-format bytes.
func (t *TimeoutTlv) Serialize() []byte {
	buf := make([]byte, tlvHeaderSize+4)
	buf[0] = TypeTimeout
	buf[1] = 4
	binary.BigEndian.PutUint32(buf[2:], t.Timeout)
	return buf
}

// ParseTimeoutTlv parses a TimeoutTlv from wire-format data.
func ParseTimeoutTlv(data []byte) (TimeoutTlv, error) {
	var t TimeoutTlv
	if len(data) < tlvHeaderSize {
		return t, errors.ErrParse
	}
	if data[0] != TypeTimeout {
		return t, errors.ErrParse
	}
	length := int(data[1])
	if length != 4 || len(data) < tlvHeaderSize+length {
		return t, errors.ErrParse
	}
	t.Timeout = binary.BigEndian.Uint32(data[2:6])
	return t, nil
}

// LastTransactionTimeTlv holds a 32-bit last-transaction time.
type LastTransactionTimeTlv struct {
	Time uint32
}

// Type returns the TLV type constant for LastTransactionTimeTlv.
func (t *LastTransactionTimeTlv) Type() uint8 { return TypeLastTransactionTime }

// Serialize returns the wire-format bytes.
func (t *LastTransactionTimeTlv) Serialize() []byte {
	buf := make([]byte, tlvHeaderSize+4)
	buf[0] = TypeLastTransactionTime
	buf[1] = 4
	binary.BigEndian.PutUint32(buf[2:], t.Time)
	return buf
}

// ParseLastTransactionTimeTlv parses a LastTransactionTimeTlv from wire-format data.
func ParseLastTransactionTimeTlv(data []byte) (LastTransactionTimeTlv, error) {
	var t LastTransactionTimeTlv
	if len(data) < tlvHeaderSize {
		return t, errors.ErrParse
	}
	if data[0] != TypeLastTransactionTime {
		return t, errors.ErrParse
	}
	length := int(data[1])
	if length != 4 || len(data) < tlvHeaderSize+length {
		return t, errors.ErrParse
	}
	t.Time = binary.BigEndian.Uint32(data[2:6])
	return t, nil
}

// RouterMaskTlv holds a router ID sequence number and a bitmask of
// allocated router IDs.
type RouterMaskTlv struct {
	IDSequence  uint8
	RouterIDSet [8]byte
}

// Type returns the TLV type constant for RouterMaskTlv.
func (t *RouterMaskTlv) Type() uint8 { return TypeRouterMask }

// Serialize returns the wire-format bytes.
func (t *RouterMaskTlv) Serialize() []byte {
	buf := make([]byte, tlvHeaderSize+9)
	buf[0] = TypeRouterMask
	buf[1] = 9
	buf[2] = t.IDSequence
	copy(buf[3:], t.RouterIDSet[:])
	return buf
}

// ParseRouterMaskTlv parses a RouterMaskTlv from wire-format data.
func ParseRouterMaskTlv(data []byte) (RouterMaskTlv, error) {
	var t RouterMaskTlv
	if len(data) < tlvHeaderSize {
		return t, errors.ErrParse
	}
	if data[0] != TypeRouterMask {
		return t, errors.ErrParse
	}
	length := int(data[1])
	if length != 9 || len(data) < tlvHeaderSize+length {
		return t, errors.ErrParse
	}
	t.IDSequence = data[2]
	copy(t.RouterIDSet[:], data[3:11])
	return t, nil
}
