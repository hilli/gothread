// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package dns provides DNS name encoding, decoding, and comparison helpers
// for wire-format DNS names used in Thread's mDNS and SRP protocols.
//
// This is a Go port of the Name class in OpenThread's
// src/core/net/dns_types.hpp and dns_types.cpp.
package dns

import (
	"strings"

	"github.com/hilli/gothread/errors"
)

// Wire-format constants for DNS names.
const (
	// MaxNameSize is the maximum DNS name wire size including the null terminator.
	// Corresponds to OT_DNS_MAX_NAME_SIZE (255).
	MaxNameSize = 255

	// MaxLabelSize is the maximum label buffer size including the null terminator.
	// The text part of a label is at most 63 characters.
	// Corresponds to OT_DNS_MAX_LABEL_SIZE (64).
	MaxLabelSize = 64

	// maxLabelLength is the max text length of a single label (63).
	maxLabelLength = MaxLabelSize - 1

	// maxNameLength is the max string length of a DNS name (254).
	maxNameLength = MaxNameSize - 1

	// labelTypeMask masks the two high bits of a label byte.
	labelTypeMask = 0xC0

	// textLabelType indicates a normal text label (top 2 bits = 00).
	textLabelType = 0x00

	// pointerLabelType indicates a compression pointer (top 2 bits = 11).
	pointerLabelType = 0xC0

	// pointerOffsetMask masks the 14-bit offset in a pointer label.
	pointerOffsetMask = 0x3FFF
)

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

// AppendName encodes a DNS name into wire format, appending to buf.
// Both "example.com" and "example.com." encode identically.
// Empty string, ".", and similar all encode as root {0x00}.
func AppendName(buf []byte, name string) ([]byte, error) {
	// Empty string and "." both encode as root {0x00}.
	if name == "" || name == "." {
		return AppendTerminator(buf), nil
	}

	if err := ValidateName(name); err != nil {
		return buf, err
	}

	buf, err := AppendMultipleLabels(buf, name)
	if err != nil {
		return buf, err
	}

	return AppendTerminator(buf), nil
}

// AppendLabel appends a single label (length byte + text) to buf.
// The label may contain any characters including dots (useful for
// service instance names like "My Printer").
func AppendLabel(buf []byte, label string) ([]byte, error) {
	n := len(label)
	if n == 0 || n > maxLabelLength {
		return buf, errors.ErrInvalidArgs
	}

	buf = append(buf, byte(n))
	buf = append(buf, label...)

	return buf, nil
}

// AppendTerminator appends a null terminator {0x00} to buf.
func AppendTerminator(buf []byte) []byte {
	return append(buf, 0x00)
}

// AppendPointerLabel appends a 2-byte compression pointer to buf.
// The offset must be less than 0x4000 (14-bit range).
func AppendPointerLabel(buf []byte, offset uint16) ([]byte, error) {
	if offset > pointerOffsetMask {
		return buf, errors.ErrInvalidArgs
	}

	val := offset | (uint16(pointerLabelType) << 8)
	buf = append(buf, byte(val>>8), byte(val))

	return buf, nil
}

// AppendMultipleLabels encodes a dot-separated label sequence without
// appending the null terminator. It mirrors OpenThread's
// Name::AppendMultipleLabels.
func AppendMultipleLabels(buf []byte, labels string) ([]byte, error) {
	if labels == "" || labels == "." {
		return buf, nil
	}

	idx := 0
	labelStart := 0

	for {
		var ch byte
		if idx < len(labels) {
			ch = labels[idx]
		}

		if ch == 0 || idx == len(labels) || ch == '.' {
			labelLen := idx - labelStart
			if labelLen == 0 {
				// Empty label: allowed only at end of string or if labels == "."
				if idx == len(labels) || (idx == 0 && len(labels) == 1 && labels[0] == '.') {
					return buf, nil
				}
				return buf, errors.ErrInvalidArgs
			}

			var err error
			buf, err = AppendLabel(buf, labels[labelStart:labelStart+labelLen])
			if err != nil {
				return buf, err
			}

			labelStart = idx + 1
		}

		if idx == len(labels) {
			break
		}
		idx++
	}

	return buf, nil
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

// ReadName reads a DNS name from wire data starting at offset, following
// compression pointers. Returns the decoded dotted name (always ending with
// a dot) and the new offset past the name field.
//
// The first label may contain dot characters (for service instance names).
// Subsequent labels with dots cause ErrParse.
func ReadName(data []byte, offset int) (string, int, error) {
	if offset < 0 || offset >= len(data) {
		return "", offset, errors.ErrParse
	}

	var b strings.Builder
	b.Grow(MaxNameSize)

	nameEndOffset := -1 // offset past the name field in the original data
	minOffset := offset // minimum allowed pointer target (for loop detection)
	firstLabel := true

	for {
		if offset < 0 || offset >= len(data) {
			return "", 0, errors.ErrParse
		}

		labelByte := data[offset]
		labelType := labelByte & labelTypeMask

		switch labelType {
		case textLabelType:
			labelLen := int(labelByte)

			if labelLen == 0 {
				// End of name — append trailing dot
				if nameEndOffset < 0 {
					nameEndOffset = offset + 1
				}
				b.WriteByte('.')
				return b.String(), nameEndOffset, nil
			}

			start := offset + 1
			end := start + labelLen
			if end > len(data) {
				return "", 0, errors.ErrParse
			}

			labelText := string(data[start:end])

			// After the first label, dots in labels are not allowed
			if !firstLabel && strings.ContainsRune(labelText, '.') {
				return "", 0, errors.ErrParse
			}

			if !firstLabel {
				b.WriteByte('.')
			}
			b.WriteString(labelText)

			offset = end
			firstLabel = false

		case pointerLabelType:
			if offset+1 >= len(data) {
				return "", 0, errors.ErrParse
			}

			if nameEndOffset < 0 {
				nameEndOffset = offset + 2
			}

			ptrVal := (int(data[offset])<<8 | int(data[offset+1])) & pointerOffsetMask
			if ptrVal >= minOffset {
				return "", 0, errors.ErrParse
			}

			offset = ptrVal
			minOffset = ptrVal

		default:
			// Reserved label types (01, 10)
			return "", 0, errors.ErrParse
		}
	}
}

// ReadLabel reads a single label or pointer from wire data at offset.
// Returns the label text, the new offset, whether it was a pointer, and any error.
// At a terminator (zero byte), returns ErrNotFound.
func ReadLabel(data []byte, offset int) (label string, newOffset int, isPointer bool, err error) {
	if offset < 0 || offset >= len(data) {
		return "", offset, false, errors.ErrParse
	}

	labelByte := data[offset]
	labelType := labelByte & labelTypeMask

	if labelType == textLabelType {
		labelLen := int(labelByte)
		if labelLen == 0 {
			// End of name
			return "", offset + 1, false, errors.ErrNotFound
		}

		start := offset + 1
		end := start + labelLen
		if end > len(data) {
			return "", offset, false, errors.ErrParse
		}

		return string(data[start:end]), end, false, nil
	}

	if labelType == pointerLabelType {
		if offset+1 >= len(data) {
			return "", offset, false, errors.ErrParse
		}

		ptrVal := (int(data[offset])<<8 | int(data[offset+1])) & pointerOffsetMask
		return "", ptrVal, true, nil
	}

	return "", offset, false, errors.ErrParse
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

// CompareName compares a wire-encoded name at offset against a string name,
// case-insensitively. Always advances offset past the wire name even on
// mismatch. Returns (match, newOffset, error).
func CompareName(data []byte, offset int, name string) (bool, int, error) {
	if offset < 0 || offset >= len(data) {
		return false, offset, errors.ErrParse
	}

	// Handle root comparison: if name is "." treat it as empty
	nameStr := name
	if nameStr == "." {
		nameStr = ""
	}

	// Strip trailing dot for comparison
	nameStr = strings.TrimSuffix(nameStr, ".")

	nameEndOffset := -1
	minOffset := offset
	matches := true
	namePos := 0

	for {
		if offset < 0 || offset >= len(data) {
			return false, 0, errors.ErrParse
		}

		labelByte := data[offset]
		labelType := labelByte & labelTypeMask

		switch labelType {
		case textLabelType:
			labelLen := int(labelByte)

			if labelLen == 0 {
				// End of wire name
				if nameEndOffset < 0 {
					nameEndOffset = offset + 1
				}
				if matches && namePos == len(nameStr) {
					return true, nameEndOffset, nil
				}
				return false, nameEndOffset, nil
			}

			start := offset + 1
			end := start + labelLen
			if end > len(data) {
				return false, 0, errors.ErrParse
			}

			if matches {
				// Compare label against nameStr starting at namePos
				if namePos > 0 {
					// Expect a dot separator in nameStr
					if namePos >= len(nameStr) || nameStr[namePos] != '.' {
						matches = false
					} else {
						namePos++
					}
				}

				if matches {
					// Check that there are enough characters in nameStr
					if namePos+labelLen > len(nameStr) {
						matches = false
					} else {
						for i := range labelLen {
							if !caseInsensitiveEqual(data[start+i], nameStr[namePos+i]) {
								matches = false
								break
							}
						}
						if matches {
							namePos += labelLen
						}
					}
				}
			}

			offset = end

		case pointerLabelType:
			if offset+1 >= len(data) {
				return false, 0, errors.ErrParse
			}

			if nameEndOffset < 0 {
				nameEndOffset = offset + 2
			}

			ptrVal := (int(data[offset])<<8 | int(data[offset+1])) & pointerOffsetMask
			if ptrVal >= minOffset {
				return false, 0, errors.ErrParse
			}

			offset = ptrVal
			minOffset = ptrVal

		default:
			return false, 0, errors.ErrParse
		}
	}
}

// CompareLabel returns true if a and b are equal under ASCII case-insensitive
// comparison.
func CompareLabel(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		if !caseInsensitiveEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

// IsSubDomainOf reports whether name is a proper subdomain of domain
// (case-insensitive). "a.b.c" is a subdomain of "b.c" but not of "a.b.c"
// itself. Both name and domain may optionally end with a dot.
func IsSubDomainOf(name, domain string) bool {
	nameLen := len(name)
	domainLen := len(domain)

	nameEndsWithDot := nameLen > 0 && name[nameLen-1] == '.'
	domainEndsWithDot := domainLen > 0 && domain[domainLen-1] == '.'

	if nameEndsWithDot {
		nameLen--
	}
	if domainEndsWithDot {
		domainLen--
	}

	if nameLen < domainLen {
		return false
	}

	// For proper subdomain, the name must be strictly longer
	if nameLen <= domainLen {
		return false
	}

	// The character before the domain portion must be a dot
	nameStart := nameLen - domainLen
	if name[nameStart-1] != '.' {
		return false
	}

	nameSuffix := name[nameStart : nameStart+domainLen]
	domainPart := domain[:domainLen]

	return strings.EqualFold(nameSuffix, domainPart)
}

// IsSameDomain reports whether a and b refer to the same domain name
// (case-insensitive). Both may optionally end with a dot.
func IsSameDomain(a, b string) bool {
	aLen := len(a)
	bLen := len(b)

	if aLen > 0 && a[aLen-1] == '.' {
		aLen--
	}
	if bLen > 0 && b[bLen-1] == '.' {
		bLen--
	}

	if aLen != bLen {
		return false
	}

	return strings.EqualFold(a[:aLen], b[:bLen])
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// ValidateName validates a DNS name string. Returns nil on success or
// an error for invalid names.
func ValidateName(name string) error {
	length := len(name)
	if length == 0 {
		return errors.ErrInvalidArgs
	}

	if name == "." {
		return nil
	}

	if length > maxNameLength {
		return errors.ErrInvalidArgs
	}

	// If name is exactly maxNameLength, it must end with a dot
	if length == maxNameLength && name[length-1] != '.' {
		return errors.ErrInvalidArgs
	}

	labelStart := 0
	for i := 0; i <= length; i++ {
		var ch byte
		if i < length {
			ch = name[i]
		}

		if ch == 0 || i == length || ch == '.' {
			labelLen := i - labelStart
			if labelLen > maxLabelLength {
				return errors.ErrInvalidArgs
			}

			if labelLen == 0 {
				// Empty label: allowed at end of string (trailing dot)
				// or if name == "." (handled above)
				if i == length {
					return nil
				}
				// Also allow "." as special case (index 0, next is end)
				if i == 0 && length == 1 {
					return nil
				}
				return errors.ErrInvalidArgs
			}

			labelStart = i + 1
		}
	}

	return nil
}

// ValidateLabel validates a single DNS label string.
func ValidateLabel(label string) error {
	n := len(label)
	if n == 0 || n > maxLabelLength {
		return errors.ErrInvalidArgs
	}
	return nil
}

// ---------------------------------------------------------------------------
// Label extraction
// ---------------------------------------------------------------------------

// ExtractLabels extracts the part of name before suffix.
// For example, ExtractLabels("a.b.example.com", "example.com") returns "a.b".
// Returns ErrParse if the suffix does not match or name equals the suffix.
func ExtractLabels(name, suffix string) (string, error) {
	nameLen := len(name)
	suffixLen := len(suffix)

	if nameLen >= MaxNameSize || suffixLen >= MaxNameSize {
		return "", errors.ErrParse
	}

	if nameLen <= suffixLen {
		return "", errors.ErrParse
	}

	// The suffix must match the end of name (case-insensitive)
	suffixStart := nameLen - suffixLen
	if !strings.EqualFold(name[suffixStart:], suffix) {
		return "", errors.ErrParse
	}

	// The character before the suffix must be a dot
	if suffixStart == 0 || name[suffixStart-1] != '.' {
		return "", errors.ErrParse
	}

	// Extract labels: everything before the dot
	labels := name[:suffixStart-1]
	return labels, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// caseInsensitiveEqual returns true if a and b are the same byte or differ
// only in ASCII letter case.
func caseInsensitiveEqual(a byte, b byte) bool {
	if a == b {
		return true
	}
	return toLower(a) == toLower(b)
}

// toLower converts an ASCII uppercase letter to lowercase; other bytes pass through.
func toLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
