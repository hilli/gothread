package checksum

// This file implements the Verhoeff checksum algorithm for decimal digit strings.
//
// The Verhoeff checksum detects all single-digit errors and all adjacent
// transposition errors. It is used in OpenThread for validating numeric
// identifiers.
//
// Reference: openthread/src/core/utils/verhoeff_checksum.hpp
// Reference: openthread/src/core/utils/verhoeff_checksum.cpp

import "errors"

// verhoeffMultiplication is the Dihedral group D5 multiplication table.
// Each row/column index is in [0,9]. Two entries are packed per byte
// (high nibble first) to match the C++ compressed representation.
var verhoeffMultiplication = [10][5]uint8{
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

// verhoeffPermutation is the permutation table used in the Verhoeff algorithm.
// Position mod 8 selects the row; the value selects the column.
var verhoeffPermutation = [8][5]uint8{
	{0x01, 0x23, 0x45, 0x67, 0x89},
	{0x15, 0x76, 0x28, 0x30, 0x94},
	{0x58, 0x03, 0x79, 0x61, 0x42},
	{0x89, 0x16, 0x04, 0x35, 0x27},
	{0x94, 0x53, 0x12, 0x68, 0x70},
	{0x42, 0x86, 0x57, 0x39, 0x01},
	{0x27, 0x93, 0x80, 0x64, 0x15},
	{0x70, 0x46, 0x91, 0x32, 0x58},
}

// verhoeffInverse maps each value to its inverse in the D5 group.
var verhoeffInverse = [5]uint8{0x04, 0x32, 0x15, 0x67, 0x89}

// verhoeffLookup extracts a single nibble from a compressed array where two
// values [0-9] are packed per byte (high nibble at even indices, low nibble
// at odd indices).
func verhoeffLookup(index uint8, compressed []uint8) uint8 {
	b := compressed[index/2]
	if index%2 == 0 {
		return b >> 4
	}
	return b & 0x0f
}

func verhoeffMultiply(a, b uint8) uint8 {
	return verhoeffLookup(b, verhoeffMultiplication[a][:])
}

func verhoeffPermute(position, value uint8) uint8 {
	return verhoeffLookup(value, verhoeffPermutation[position][:])
}

func verhoeffInverseOf(v uint8) uint8 {
	return verhoeffLookup(v, verhoeffInverse[:])
}

// errInvalidFormat is returned when a string contains non-digit characters.
var errInvalidFormat = errors.New("checksum: string contains non-digit characters")

// verhoeffCompute is the shared computation for both Calculate and Validate.
// When validate is true, the entire string (including the check digit) is
// processed; the result code should be 0 for a valid string. When validate
// is false, the string is treated as the payload and the resulting code is
// used to derive the check digit.
func verhoeffCompute(s string, validate bool) (uint8, error) {
	length := len(s)

	index := uint16(0)
	if !validate {
		length++
		index++
	}

	var code uint8
	for ; int(index) < length; index++ {
		ch := s[length-int(index)-1]
		if ch < '0' || ch > '9' {
			return 0, errInvalidFormat
		}
		digit := uint8(ch - '0')
		code = verhoeffMultiply(code, verhoeffPermute(uint8(index%8), digit))
	}

	return code, nil
}

// VerhoeffCalculate computes the Verhoeff check digit for a decimal string.
// The input should contain only ASCII digits '0'-'9'. The returned byte is
// the check digit character ('0'-'9') that, when appended to the input,
// produces a string that passes [VerhoeffValidate].
//
// An empty string is valid input and produces check digit '0'.
func VerhoeffCalculate(s string) (byte, error) {
	// Validate characters first.
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errInvalidFormat
		}
	}

	code, err := verhoeffCompute(s, false)
	if err != nil {
		return 0, err
	}
	return '0' + verhoeffInverseOf(code), nil
}

// VerhoeffValidate checks whether a decimal string has a valid Verhoeff
// checksum. The last character of the string is treated as the check digit.
// Returns true if and only if the string is non-empty, contains only ASCII
// digits, and the check digit is correct.
func VerhoeffValidate(s string) bool {
	if s == "" {
		return false
	}
	code, err := verhoeffCompute(s, true)
	return err == nil && code == 0
}
