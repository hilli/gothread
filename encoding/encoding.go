// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package encoding provides big-endian and little-endian byte-order
// read/write helpers for wire protocol encoding.
//
// This is a Go port of the utilities in OpenThread's
// src/core/common/encoding.hpp. The functions operate directly on []byte
// slices and use Go's encoding/binary package internally.
package encoding

import (
	"encoding/binary"
	"math/bits"
)

// --- Byte-swap functions ---

// Swap16 returns v with its bytes reversed.
func Swap16(v uint16) uint16 {
	return bits.ReverseBytes16(v)
}

// Swap32 returns v with its bytes reversed.
func Swap32(v uint32) uint32 {
	return bits.ReverseBytes32(v)
}

// Swap64 returns v with its bytes reversed.
func Swap64(v uint64) uint64 {
	return bits.ReverseBytes64(v)
}

// --- Bit-reversal ---

// Reverse32 returns v with all 32 bits reversed (bit 0 becomes bit 31, etc.).
// This mirrors ot::Reverse32 in encoding.hpp.
func Reverse32(v uint32) uint32 {
	return bits.Reverse32(v)
}

// --- Big-endian read functions ---

// BigEndianReadUint16 reads a uint16 from buf in big-endian byte order.
func BigEndianReadUint16(buf []byte) uint16 {
	return binary.BigEndian.Uint16(buf)
}

// BigEndianReadUint24 reads a 24-bit unsigned integer from buf in big-endian
// byte order, returned as a uint32.
func BigEndianReadUint24(buf []byte) uint32 {
	return uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2])
}

// BigEndianReadUint32 reads a uint32 from buf in big-endian byte order.
func BigEndianReadUint32(buf []byte) uint32 {
	return binary.BigEndian.Uint32(buf)
}

// BigEndianReadUint64 reads a uint64 from buf in big-endian byte order.
func BigEndianReadUint64(buf []byte) uint64 {
	return binary.BigEndian.Uint64(buf)
}

// --- Big-endian write functions ---

// BigEndianWriteUint16 writes v to buf in big-endian byte order.
func BigEndianWriteUint16(v uint16, buf []byte) {
	binary.BigEndian.PutUint16(buf, v)
}

// BigEndianWriteUint24 writes the low 24 bits of v to buf in big-endian byte order.
func BigEndianWriteUint24(v uint32, buf []byte) {
	buf[0] = byte(v >> 16)
	buf[1] = byte(v >> 8)
	buf[2] = byte(v)
}

// BigEndianWriteUint32 writes v to buf in big-endian byte order.
func BigEndianWriteUint32(v uint32, buf []byte) {
	binary.BigEndian.PutUint32(buf, v)
}

// BigEndianWriteUint64 writes v to buf in big-endian byte order.
func BigEndianWriteUint64(v uint64, buf []byte) {
	binary.BigEndian.PutUint64(buf, v)
}

// --- Little-endian read functions ---

// LittleEndianReadUint16 reads a uint16 from buf in little-endian byte order.
func LittleEndianReadUint16(buf []byte) uint16 {
	return binary.LittleEndian.Uint16(buf)
}

// LittleEndianReadUint24 reads a 24-bit unsigned integer from buf in
// little-endian byte order, returned as a uint32.
func LittleEndianReadUint24(buf []byte) uint32 {
	return uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16
}

// LittleEndianReadUint32 reads a uint32 from buf in little-endian byte order.
func LittleEndianReadUint32(buf []byte) uint32 {
	return binary.LittleEndian.Uint32(buf)
}

// LittleEndianReadUint64 reads a uint64 from buf in little-endian byte order.
func LittleEndianReadUint64(buf []byte) uint64 {
	return binary.LittleEndian.Uint64(buf)
}

// --- Little-endian write functions ---

// LittleEndianWriteUint16 writes v to buf in little-endian byte order.
func LittleEndianWriteUint16(v uint16, buf []byte) {
	binary.LittleEndian.PutUint16(buf, v)
}

// LittleEndianWriteUint24 writes the low 24 bits of v to buf in little-endian byte order.
func LittleEndianWriteUint24(v uint32, buf []byte) {
	buf[0] = byte(v)
	buf[1] = byte(v >> 8)
	buf[2] = byte(v >> 16)
}

// LittleEndianWriteUint32 writes v to buf in little-endian byte order.
func LittleEndianWriteUint32(v uint32, buf []byte) {
	binary.LittleEndian.PutUint32(buf, v)
}

// LittleEndianWriteUint64 writes v to buf in little-endian byte order.
func LittleEndianWriteUint64(v uint64, buf []byte) {
	binary.LittleEndian.PutUint64(buf, v)
}
