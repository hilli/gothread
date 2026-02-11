// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"github.com/hilli/gothread/errors"
)

// MaxVerhoeffStringLength is the maximum length of a decimal string input
// for Verhoeff checksum calculation.
const MaxVerhoeffStringLength = 128

// verhoeff multiplication table (Dihedral group D5).
// Each row corresponds to a first operand [0-9], each column to a second.
// Values are compressed: two 4-bit values per byte.
var verhoeffMultiplication = [10][5]byte{
	{0x01, 0x23, 0x45, 0x67, 0x89},
	{0x12, 0x34, 0x06, 0x78, 0x95},
	{0x23, 0x40, 0x17, 0x89, 0x56},
	{0x34, 0x01, 0x28, 0x95, 0x67},
	{0x40, 0x12, 0x39, 0x56, 0x78},
	{0x59, 0x87, 0x60, 0x43, 0x21},
	{0x65, 0x98, 0x71, 0x04, 0x32},
	{0x76, 0x59, 0x82, 0x10, 0x43},
	{0x87, 0x65, 0x93, 0x21, 0x04},
	{0x98, 0x76, 0x54, 0x32, 0x10},
}

// verhoeff permutation table.
// 8 rows (for position mod 8), each with compressed 10 values.
var verhoeffPermutation = [8][5]byte{
	{0x01, 0x23, 0x45, 0x67, 0x89},
	{0x15, 0x76, 0x28, 0x30, 0x94},
	{0x58, 0x03, 0x79, 0x61, 0x42},
	{0x89, 0x16, 0x04, 0x35, 0x27},
	{0x94, 0x53, 0x12, 0x68, 0x70},
	{0x42, 0x86, 0x57, 0x39, 0x01},
	{0x27, 0x93, 0x80, 0x64, 0x15},
	{0x70, 0x46, 0x91, 0x32, 0x58},
}

// verhoeff inverse table.
var verhoeffInverse = [5]byte{0x04, 0x32, 0x15, 0x67, 0x89}

// verhoeffLookup extracts a value from a compressed array where two
// 4-bit entries are packed per byte.
func verhoeffLookup(index uint8, compressed []byte) uint8 {
	result := compressed[index/2]
	if index%2 == 0 {
		result >>= 4
	} else {
		result &= 0x0f
	}
	return result
}

// verhoeffMultiply performs multiplication in the Dihedral group D5.
func verhoeffMultiply(a, b uint8) uint8 {
	return verhoeffLookup(b, verhoeffMultiplication[a][:])
}

// verhoeffPermute applies the permutation at the given position to a value.
func verhoeffPermute(position, value uint8) uint8 {
	return verhoeffLookup(value, verhoeffPermutation[position][:])
}

// verhoeffInverseOf returns the inverse of a value in the Dihedral group D5.
func verhoeffInverseOf(value uint8) uint8 {
	return verhoeffLookup(value, verhoeffInverse[:])
}

// verhoeffComputeCode computes the Verhoeff code over a decimal string.
// If validate is true, the string is processed as-is (last digit is the checksum).
// If validate is false, an extra position is added for checksum calculation.
func verhoeffComputeCode(decimalString string, validate bool) (uint8, error) {
	length := len(decimalString)
	if length == 0 || length > MaxVerhoeffStringLength {
		return 0, errors.ErrInvalidArgs
	}

	var code uint8
	var index int
	processLength := length

	if !validate {
		processLength++
		index = 1
	}

	for ; index < processLength; index++ {
		ch := decimalString[processLength-index-1]
		if ch < '0' || ch > '9' {
			return 0, errors.ErrInvalidArgs
		}
		digit := uint8(ch - '0')
		code = verhoeffMultiply(code, verhoeffPermute(uint8(index%8), digit))
	}

	return code, nil
}

// VerhoeffCalculate computes the Verhoeff checksum digit for a given
// decimal string. The returned byte is the ASCII digit ('0'-'9') that
// should be appended to the string to make it valid.
//
// Reference: openthread/src/core/utils/verhoeff_checksum.cpp
func VerhoeffCalculate(decimalString string) (byte, error) {
	code, err := verhoeffComputeCode(decimalString, false)
	if err != nil {
		return 0, err
	}
	return '0' + verhoeffInverseOf(code), nil
}

// VerhoeffValidate validates the Verhoeff checksum of a given decimal
// string. The last character of the string is treated as the checksum digit.
// Returns nil if the checksum is valid.
//
// Reference: openthread/src/core/utils/verhoeff_checksum.cpp
func VerhoeffValidate(decimalString string) error {
	code, err := verhoeffComputeCode(decimalString, true)
	if err != nil {
		return err
	}
	if code != 0 {
		return errors.ErrFailed
	}
	return nil
}
