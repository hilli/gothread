// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"encoding/hex"
	"math"
	"net/netip"
	"strconv"
	"strings"

	"github.com/hilli/gothread/errors"
)

// ParseAsUint8 parses a string as a uint8 value.
// The string is parsed as decimal or hex (with 0x/0X prefix).
//
// Reference: openthread/src/core/utils/parse_cmdline.cpp
func ParseAsUint8(s string) (uint8, error) {
	v, err := ParseAsUint64(s)
	if err != nil {
		return 0, err
	}
	if v > math.MaxUint8 {
		return 0, errors.ErrInvalidArgs
	}
	return uint8(v), nil
}

// ParseAsUint16 parses a string as a uint16 value.
// The string is parsed as decimal or hex (with 0x/0X prefix).
//
// Reference: openthread/src/core/utils/parse_cmdline.cpp
func ParseAsUint16(s string) (uint16, error) {
	v, err := ParseAsUint64(s)
	if err != nil {
		return 0, err
	}
	if v > math.MaxUint16 {
		return 0, errors.ErrInvalidArgs
	}
	return uint16(v), nil
}

// ParseAsUint32 parses a string as a uint32 value.
// The string is parsed as decimal or hex (with 0x/0X prefix).
//
// Reference: openthread/src/core/utils/parse_cmdline.cpp
func ParseAsUint32(s string) (uint32, error) {
	v, err := ParseAsUint64(s)
	if err != nil {
		return 0, err
	}
	if v > math.MaxUint32 {
		return 0, errors.ErrInvalidArgs
	}
	return uint32(v), nil
}

// ParseAsUint64 parses a string as a uint64 value.
// The string is parsed as decimal or hex (with 0x/0X prefix).
//
// Reference: openthread/src/core/utils/parse_cmdline.cpp
func ParseAsUint64(s string) (uint64, error) {
	if s == "" {
		return 0, errors.ErrInvalidArgs
	}

	base := 10
	str := s
	if len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X') {
		str = str[2:]
		base = 16
	}

	if str == "" {
		return 0, errors.ErrInvalidArgs
	}

	v, err := strconv.ParseUint(str, base, 64)
	if err != nil {
		return 0, errors.ErrInvalidArgs
	}
	return v, nil
}

// ParseAsInt8 parses a string as an int8 value.
// The string is parsed as decimal or hex (with 0x/0X prefix) and may
// start with '+' or '-'.
//
// Reference: openthread/src/core/utils/parse_cmdline.cpp
func ParseAsInt8(s string) (int8, error) {
	v, err := ParseAsInt32(s)
	if err != nil {
		return 0, err
	}
	if v < math.MinInt8 || v > math.MaxInt8 {
		return 0, errors.ErrInvalidArgs
	}
	return int8(v), nil
}

// ParseAsInt16 parses a string as an int16 value.
// The string is parsed as decimal or hex (with 0x/0X prefix) and may
// start with '+' or '-'.
//
// Reference: openthread/src/core/utils/parse_cmdline.cpp
func ParseAsInt16(s string) (int16, error) {
	v, err := ParseAsInt32(s)
	if err != nil {
		return 0, err
	}
	if v < math.MinInt16 || v > math.MaxInt16 {
		return 0, errors.ErrInvalidArgs
	}
	return int16(v), nil
}

// ParseAsInt32 parses a string as an int32 value.
// The string is parsed as decimal or hex (with 0x/0X prefix) and may
// start with '+' or '-'.
//
// Reference: openthread/src/core/utils/parse_cmdline.cpp
func ParseAsInt32(s string) (int32, error) {
	if s == "" {
		return 0, errors.ErrInvalidArgs
	}

	negative := false
	str := s
	switch str[0] {
	case '-':
		negative = true
		str = str[1:]
	case '+':
		str = str[1:]
	}

	v, err := ParseAsUint64(str)
	if err != nil {
		return 0, err
	}

	if negative {
		// int32 min is -2147483648, so max absolute value is 2147483648
		if v > uint64(-math.MinInt32) {
			return 0, errors.ErrInvalidArgs
		}
		return -int32(v), nil
	}

	if v > math.MaxInt32 {
		return 0, errors.ErrInvalidArgs
	}
	return int32(v), nil
}

// ParseAsBool parses a string as a boolean value.
// Zero is treated as false; any non-zero value is treated as true.
//
// Reference: openthread/src/core/utils/parse_cmdline.cpp
func ParseAsBool(s string) (bool, error) {
	v, err := ParseAsUint32(s)
	if err != nil {
		return false, err
	}
	return v != 0, nil
}

// ParseAsIP6Address parses a string as an IPv6 address.
//
// Reference: openthread/src/core/utils/parse_cmdline.cpp
func ParseAsIP6Address(s string) ([16]byte, error) {
	if s == "" {
		return [16]byte{}, errors.ErrInvalidArgs
	}
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Is6() {
		return [16]byte{}, errors.ErrInvalidArgs
	}
	return addr.As16(), nil
}

// ParseAsIP6Prefix parses a string as an IPv6 prefix in the form
// "{address}/{length}".
//
// Reference: openthread/src/core/utils/parse_cmdline.cpp
func ParseAsIP6Prefix(s string) (address [16]byte, length uint8, err error) {
	if s == "" {
		return [16]byte{}, 0, errors.ErrInvalidArgs
	}
	prefix, err := netip.ParsePrefix(s)
	if err != nil || !prefix.Addr().Is6() {
		return [16]byte{}, 0, errors.ErrInvalidArgs
	}
	return prefix.Addr().As16(), uint8(prefix.Bits()), nil
}

// ParseAsHexString parses a hex string into a byte slice.
// Handles both even and odd length strings. For example, "AABBCC" produces
// {0xAA, 0xBB, 0xCC} and "123" produces {0x01, 0x23}.
//
// Reference: openthread/src/core/utils/parse_cmdline.cpp
func ParseAsHexString(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.ErrInvalidArgs
	}

	// Pad with leading zero if odd length
	str := s
	if len(str)%2 != 0 {
		str = "0" + str
	}

	buf, err := hex.DecodeString(str)
	if err != nil {
		return nil, errors.ErrInvalidArgs
	}

	return buf, nil
}

// ParseAsHexStringExact parses a hex string into a byte slice and verifies
// that the result is exactly the specified size.
//
// Reference: openthread/src/core/utils/parse_cmdline.cpp
func ParseAsHexStringExact(s string, size int) ([]byte, error) {
	buf, err := ParseAsHexString(s)
	if err != nil {
		return nil, err
	}
	if len(buf) != size {
		return buf, errors.ErrInvalidArgs
	}
	return buf, nil
}

// Arg represents a single argument from a parsed command line.
//
// Reference: openthread/src/core/utils/parse_cmdline.hpp
type Arg struct {
	value string
	empty bool
}

// NewArg creates an Arg from a string value.
func NewArg(s string) Arg {
	return Arg{value: s, empty: false}
}

// EmptyArg returns an empty Arg that represents the end of an argument list.
func EmptyArg() Arg {
	return Arg{empty: true}
}

// IsEmpty returns true if the argument is empty (end of argument list).
func (a Arg) IsEmpty() bool {
	return a.empty
}

// String returns the argument as a string, or "" if empty.
func (a Arg) String() string {
	if a.empty {
		return ""
	}
	return a.value
}

// Length returns the length of the argument string, or 0 if empty.
func (a Arg) Length() int {
	if a.empty {
		return 0
	}
	return len(a.value)
}

// Equals compares the argument to a string. Returns false if the
// argument is empty.
func (a Arg) Equals(s string) bool {
	if a.empty {
		return false
	}
	return a.value == s
}

// ParseAsUint8 parses this argument as a uint8 value.
func (a Arg) ParseAsUint8() (uint8, error) {
	if a.empty {
		return 0, errors.ErrInvalidArgs
	}
	return ParseAsUint8(a.value)
}

// ParseAsUint16 parses this argument as a uint16 value.
func (a Arg) ParseAsUint16() (uint16, error) {
	if a.empty {
		return 0, errors.ErrInvalidArgs
	}
	return ParseAsUint16(a.value)
}

// ParseAsUint32 parses this argument as a uint32 value.
func (a Arg) ParseAsUint32() (uint32, error) {
	if a.empty {
		return 0, errors.ErrInvalidArgs
	}
	return ParseAsUint32(a.value)
}

// ParseAsUint64 parses this argument as a uint64 value.
func (a Arg) ParseAsUint64() (uint64, error) {
	if a.empty {
		return 0, errors.ErrInvalidArgs
	}
	return ParseAsUint64(a.value)
}

// ParseAsInt8 parses this argument as an int8 value.
func (a Arg) ParseAsInt8() (int8, error) {
	if a.empty {
		return 0, errors.ErrInvalidArgs
	}
	return ParseAsInt8(a.value)
}

// ParseAsInt16 parses this argument as an int16 value.
func (a Arg) ParseAsInt16() (int16, error) {
	if a.empty {
		return 0, errors.ErrInvalidArgs
	}
	return ParseAsInt16(a.value)
}

// ParseAsInt32 parses this argument as an int32 value.
func (a Arg) ParseAsInt32() (int32, error) {
	if a.empty {
		return 0, errors.ErrInvalidArgs
	}
	return ParseAsInt32(a.value)
}

// ParseAsBool parses this argument as a boolean value.
func (a Arg) ParseAsBool() (bool, error) {
	if a.empty {
		return false, errors.ErrInvalidArgs
	}
	return ParseAsBool(a.value)
}

// ParseAsHexString parses this argument as a hex string into bytes.
func (a Arg) ParseAsHexString() ([]byte, error) {
	if a.empty {
		return nil, errors.ErrInvalidArgs
	}
	return ParseAsHexString(a.value)
}

// ParseCmd parses a command string into an argument list.
// Whitespace characters (space, tab, CR, LF) are used as separators.
// Backslash can be used to escape separators and the backslash itself.
// The maxArgs parameter limits the maximum number of arguments; if there
// are more, ErrInvalidArgs is returned.
//
// Reference: openthread/src/core/utils/parse_cmdline.cpp
func ParseCmd(commandString string, maxArgs int) ([]Arg, error) {
	if maxArgs <= 0 {
		return nil, errors.ErrInvalidArgs
	}

	// Process escape sequences and split on separators.
	// We iterate character by character to handle backslash escaping.
	var args []Arg
	var current strings.Builder
	inArg := false

	runes := []rune(commandString)
	for i := 0; i < len(runes); i++ {
		ch := runes[i]

		if ch == '\\' && i+1 < len(runes) {
			next := runes[i+1]
			if isSeparator(next) || next == '\\' {
				current.WriteRune(next)
				i++
				if !inArg {
					inArg = true
				}
				continue
			}
		}

		if isSeparator(ch) {
			if inArg {
				if len(args) >= maxArgs {
					return nil, errors.ErrInvalidArgs
				}
				args = append(args, NewArg(current.String()))
				current.Reset()
				inArg = false
			}
			continue
		}

		current.WriteRune(ch)
		if !inArg {
			inArg = true
		}
	}

	if inArg {
		if len(args) >= maxArgs {
			return nil, errors.ErrInvalidArgs
		}
		args = append(args, NewArg(current.String()))
	}

	return args, nil
}

// ArgsLength returns the number of non-empty arguments in the slice.
func ArgsLength(args []Arg) int {
	count := 0
	for _, a := range args {
		if a.IsEmpty() {
			break
		}
		count++
	}
	return count
}

// isSeparator returns whether a rune is a command line separator.
func isSeparator(ch rune) bool {
	return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n'
}
