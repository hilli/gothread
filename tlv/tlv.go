// Package tlv implements TLV (Type-Length-Value) encoding and decoding
// as used in the Thread protocol.
//
// Thread uses two TLV formats:
//
// Standard TLV:
//   - Type:   1 byte
//   - Length: 1 byte (0..254)
//   - Value:  Length bytes
//
// Extended TLV (when value length >= 255):
//   - Type:            1 byte
//   - Length:           1 byte (always 0xFF, the extended sentinel)
//   - Extended Length: 2 bytes (big-endian)
//   - Value:           Extended Length bytes
//
// This is a Go port of the TLV logic in OpenThread's
// openthread/src/core/common/tlvs.hpp and tlvs.cpp.
package tlv

import (
	"encoding/binary"
	"errors"
)

const (
	// MaxStandardLength is the maximum value length that fits in a standard
	// (non-extended) TLV. Corresponds to OT_NETWORK_BASE_TLV_MAX_LENGTH (254).
	MaxStandardLength = 254

	// ExtendedLengthSentinel is the length byte value that indicates an
	// extended TLV. Corresponds to kExtendedLength (255 / 0xFF).
	ExtendedLengthSentinel = 255

	// HeaderSize is the size in bytes of a standard TLV header (type + length).
	HeaderSize = 2

	// ExtendedHeaderSize is the size in bytes of an extended TLV header
	// (type + length sentinel + 2-byte extended length).
	ExtendedHeaderSize = 4
)

var (
	// ErrTruncated is returned when the input data is too short to contain
	// a complete TLV.
	ErrTruncated = errors.New("tlv: truncated data")
)

// TLV represents a single Type-Length-Value element.
type TLV struct {
	Type   uint8
	Length uint16
	Value  []byte
}

// Parse reads a single TLV from the start of data. It returns the parsed TLV,
// the number of bytes consumed, and any error. Both standard and extended
// formats are handled transparently.
func Parse(data []byte) (TLV, int, error) {
	if len(data) < HeaderSize {
		return TLV{}, 0, ErrTruncated
	}

	typ := data[0]
	lenByte := data[1]

	var valueLen uint16
	var hdrSize int

	if lenByte != ExtendedLengthSentinel {
		// Standard TLV.
		valueLen = uint16(lenByte)
		hdrSize = HeaderSize
	} else {
		// Extended TLV.
		if len(data) < ExtendedHeaderSize {
			return TLV{}, 0, ErrTruncated
		}
		valueLen = binary.BigEndian.Uint16(data[2:4])
		hdrSize = ExtendedHeaderSize
	}

	totalSize := hdrSize + int(valueLen)
	if len(data) < totalSize {
		return TLV{}, 0, ErrTruncated
	}

	var value []byte
	if valueLen > 0 {
		value = make([]byte, valueLen)
		copy(value, data[hdrSize:totalSize])
	}

	return TLV{
		Type:   typ,
		Length: valueLen,
		Value:  value,
	}, totalSize, nil
}

// ParseAll parses all consecutive TLVs from data. It returns an error if any
// TLV is malformed or if there are leftover bytes that do not form a valid TLV.
func ParseAll(data []byte) ([]TLV, error) {
	var tlvs []TLV
	offset := 0
	for offset < len(data) {
		t, n, err := Parse(data[offset:])
		if err != nil {
			return nil, err
		}
		tlvs = append(tlvs, t)
		offset += n
	}
	return tlvs, nil
}

// Marshal serializes the TLV to its wire format. The format (standard vs.
// extended) is selected automatically based on len(Value). The Length field
// is set to len(Value) during marshaling, so callers need not keep Length
// in sync with Value.
func (t TLV) Marshal() []byte {
	vLen := len(t.Value)

	if vLen > MaxStandardLength {
		// Extended format.
		buf := make([]byte, ExtendedHeaderSize+vLen)
		buf[0] = t.Type
		buf[1] = ExtendedLengthSentinel
		binary.BigEndian.PutUint16(buf[2:4], uint16(vLen))
		copy(buf[ExtendedHeaderSize:], t.Value)
		return buf
	}

	// Standard format.
	buf := make([]byte, HeaderSize+vLen)
	buf[0] = t.Type
	buf[1] = byte(vLen)
	copy(buf[HeaderSize:], t.Value)
	return buf
}

// FindByType returns a pointer to the first TLV in tlvs with the given type,
// or nil if no match is found.
func FindByType(tlvs []TLV, typ uint8) *TLV {
	for i := range tlvs {
		if tlvs[i].Type == typ {
			return &tlvs[i]
		}
	}
	return nil
}

// IsExtended reports whether the TLV at the start of data uses the extended
// format. It returns false if data is too short to determine the format.
func IsExtended(data []byte) bool {
	if len(data) < HeaderSize {
		return false
	}
	return data[1] == ExtendedLengthSentinel
}
