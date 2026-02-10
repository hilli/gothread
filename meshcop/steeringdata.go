// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"encoding/hex"

	"github.com/hilli/gothread/crc"
	goterrors "github.com/hilli/gothread/errors"
)

// SteeringData constants.
const (
	// SteeringDataMinLength is the minimum Steering Data length in bytes.
	SteeringDataMinLength = 1
	// SteeringDataMaxLength is the maximum Steering Data length in bytes.
	SteeringDataMaxLength = 16
)

// HashBitIndexes holds the two CRC16 hash bit indexes for a bloom filter entry.
// The first index is derived using CRC16-CCITT and the second using CRC16-ANSI.
type HashBitIndexes struct {
	Index [2]uint16
}

// SteeringData represents MeshCoP Steering Data — a bloom filter used to
// advertise which Joiners a Commissioner is willing to accept.
//
// The filter is 1–16 bytes (8–128 bits). Two hash functions (CRC16-CCITT and
// CRC16-ANSI) are used to map a Joiner ID to two bit positions.
//
// Bit addressing is big-endian: bit 0 maps to the last byte of the data
// buffer (data[length-1]).
type SteeringData struct {
	length uint8
	data   [SteeringDataMaxLength]byte
}

// Init initializes the SteeringData with the given length and clears all bits.
// Returns ErrInvalidArgs if length is not in [SteeringDataMinLength, SteeringDataMaxLength].
func (sd *SteeringData) Init(length uint8) error {
	if length < SteeringDataMinLength || length > SteeringDataMaxLength {
		return goterrors.ErrInvalidArgs
	}
	sd.length = length
	sd.data = [SteeringDataMaxLength]byte{}
	return nil
}

// InitWithData initializes the SteeringData with the given length and data.
// Returns ErrInvalidArgs if length is not valid.
func (sd *SteeringData) InitWithData(length uint8, data []byte) error {
	if err := sd.Init(length); err != nil {
		return err
	}
	copy(sd.data[:sd.length], data)
	return nil
}

// IsValid reports whether the SteeringData has a valid length.
func (sd *SteeringData) IsValid() bool {
	return sd.length >= SteeringDataMinLength && sd.length <= SteeringDataMaxLength
}

// Clear resets the bloom filter to one byte, all bits cleared (no Joiner accepted).
func (sd *SteeringData) Clear() {
	_ = sd.Init(1)
}

// SetToPermitAllJoiners sets the bloom filter to permit all Joiner IDs
// (one byte with all bits set).
func (sd *SteeringData) SetToPermitAllJoiners() {
	_ = sd.Init(1)
	sd.data[0] = 0xFF
}

// Length returns the SteeringData length in bytes.
func (sd *SteeringData) Length() uint8 {
	return sd.length
}

// Data returns a slice of the SteeringData bytes.
func (sd *SteeringData) Data() []byte {
	return sd.data[:sd.length]
}

// numBits returns the total number of bits in the bloom filter.
func (sd *SteeringData) numBits() uint16 {
	return uint16(sd.length) * 8
}

// byteIndex returns the byte index for a given bit number.
// Bit addressing is big-endian: bit 0 is in the last byte.
func (sd *SteeringData) byteIndex(bit uint16) uint8 {
	return sd.length - 1 - uint8(bit/8)
}

// bitFlag returns the bit mask within a byte for a given bit number.
func bitFlag(bit uint16) byte {
	return 1 << (bit % 8)
}

// getBit returns true if the given bit is set.
func (sd *SteeringData) getBit(bit uint16) bool {
	return sd.data[sd.byteIndex(bit)]&bitFlag(bit) != 0
}

// setBit sets the given bit.
func (sd *SteeringData) setBit(bit uint16) {
	sd.data[sd.byteIndex(bit)] |= bitFlag(bit)
}

// doesAllMatch reports whether every byte in the data equals aMatch.
func (sd *SteeringData) doesAllMatch(match byte) bool {
	if !sd.IsValid() {
		return false
	}
	for i := uint8(0); i < sd.length; i++ {
		if sd.data[i] != match {
			return false
		}
	}
	return true
}

// IsEmpty reports whether the bloom filter is empty (all bits cleared).
func (sd *SteeringData) IsEmpty() bool {
	return sd.doesAllMatch(0)
}

// PermitsAllJoiners reports whether the bloom filter permits all Joiner IDs
// (all bits set and length > 0).
func (sd *SteeringData) PermitsAllJoiners() bool {
	return sd.length > 0 && sd.doesAllMatch(0xFF)
}

// CalculateHashBitIndexes computes the bloom filter hash bit indexes from a
// Joiner ID (8-byte Extended Address). The first index uses CRC16-CCITT and
// the second uses CRC16-ANSI.
func CalculateHashBitIndexes(joinerID [8]byte) HashBitIndexes {
	var indexes HashBitIndexes
	indexes.Index[0] = crc.ChecksumCRC16CCITT(joinerID[:])
	indexes.Index[1] = crc.ChecksumCRC16ANSI(joinerID[:])
	return indexes
}

// CalculateHashBitIndexesFromDiscerner computes the bloom filter hash bit
// indexes from a Joiner Discerner. The discerner value bits are packed into
// an 8-byte Extended Address (zero-padded) starting from the least significant
// byte, matching OpenThread's JoinerDiscerner::CopyTo(ExtAddress).
func CalculateHashBitIndexesFromDiscerner(value uint64, bitLength uint8) HashBitIndexes {
	var addr [8]byte
	// Pack the discerner value into the address in big-endian order,
	// with the value's LSB in addr[7].
	for i := 0; i < 8; i++ {
		addr[7-i] = byte(value >> (uint(i) * 8))
	}
	// Clear any bits above bitLength.
	if bitLength < 64 {
		mask := (uint64(1) << bitLength) - 1
		val := uint64(0)
		for i := 0; i < 8; i++ {
			val = (val << 8) | uint64(addr[i])
		}
		val &= mask
		for i := 7; i >= 0; i-- {
			addr[i] = byte(val)
			val >>= 8
		}
	}
	return CalculateHashBitIndexes(addr)
}

// UpdateBloomFilter adds a Joiner ID to the bloom filter.
// Returns ErrInvalidArgs if the SteeringData is not valid.
func (sd *SteeringData) UpdateBloomFilter(joinerID [8]byte) error {
	indexes := CalculateHashBitIndexes(joinerID)
	return sd.updateBloomFilterWithIndexes(indexes)
}

// UpdateBloomFilterWithDiscerner adds a Joiner Discerner to the bloom filter.
// Returns ErrInvalidArgs if the SteeringData is not valid.
func (sd *SteeringData) UpdateBloomFilterWithDiscerner(value uint64, bitLength uint8) error {
	indexes := CalculateHashBitIndexesFromDiscerner(value, bitLength)
	return sd.updateBloomFilterWithIndexes(indexes)
}

// updateBloomFilterWithIndexes sets the two hash bit positions in the bloom filter.
func (sd *SteeringData) updateBloomFilterWithIndexes(indexes HashBitIndexes) error {
	if !sd.IsValid() {
		return goterrors.ErrInvalidArgs
	}
	numBits := sd.numBits()
	sd.setBit(indexes.Index[0] % numBits)
	sd.setBit(indexes.Index[1] % numBits)
	return nil
}

// MergeWith combines another SteeringData's bloom filter into this one using
// bitwise OR. The other filter's length must evenly divide this filter's length.
// Both filters must be valid.
// Returns ErrInvalidArgs if the lengths are invalid or incompatible.
func (sd *SteeringData) MergeWith(other *SteeringData) error {
	if !sd.IsValid() {
		return goterrors.ErrInvalidArgs
	}
	if !other.IsValid() {
		return goterrors.ErrInvalidArgs
	}
	if sd.length%other.length != 0 {
		return goterrors.ErrInvalidArgs
	}
	for i := uint8(0); i < sd.length; i++ {
		sd.data[i] |= other.data[i%other.length]
	}
	return nil
}

// Contains reports whether the bloom filter contains the given Joiner ID.
func (sd *SteeringData) Contains(joinerID [8]byte) bool {
	indexes := CalculateHashBitIndexes(joinerID)
	return sd.ContainsIndexes(indexes)
}

// ContainsDiscerner reports whether the bloom filter contains the given
// Joiner Discerner.
func (sd *SteeringData) ContainsDiscerner(value uint64, bitLength uint8) bool {
	indexes := CalculateHashBitIndexesFromDiscerner(value, bitLength)
	return sd.ContainsIndexes(indexes)
}

// ContainsIndexes reports whether the bloom filter contains the given
// hash bit indexes.
func (sd *SteeringData) ContainsIndexes(indexes HashBitIndexes) bool {
	if !sd.IsValid() {
		return false
	}
	numBits := sd.numBits()
	return sd.getBit(indexes.Index[0]%numBits) && sd.getBit(indexes.Index[1]%numBits)
}

// String returns a hex string representation of the SteeringData, e.g. "[00ff]".
func (sd *SteeringData) String() string {
	if sd.length == 0 {
		return "[]"
	}
	return "[" + hex.EncodeToString(sd.data[:sd.length]) + "]"
}
