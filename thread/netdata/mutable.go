// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package netdata

import (
	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// MaxSize is the maximum size of Thread Network Data in bytes.
const MaxSize = 254

// MutableNetworkData is a mutable buffer for in-place manipulation of Thread
// Network Data TLVs. It mirrors OpenThread's MutableNetworkData class from
// src/core/thread/network_data.hpp.
//
// All operations work on a fixed-size backing array; the active data occupies
// buf[0:length].
type MutableNetworkData struct {
	buf    [MaxSize]byte
	length int
}

// NewMutableNetworkData creates a MutableNetworkData pre-loaded with the given
// data. If data is longer than MaxSize it is truncated.
func NewMutableNetworkData(data []byte) *MutableNetworkData {
	m := &MutableNetworkData{}
	n := len(data)
	if n > MaxSize {
		n = MaxSize
	}
	copy(m.buf[:], data[:n])
	m.length = n
	return m
}

// Data returns the active network data bytes. The returned slice aliases the
// internal buffer and must not be retained across mutations.
func (m *MutableNetworkData) Data() []byte {
	return m.buf[:m.length]
}

// Len returns the current length of the network data.
func (m *MutableNetworkData) Len() int {
	return m.length
}

// Clear resets the network data to empty.
func (m *MutableNetworkData) Clear() {
	m.length = 0
}

// CanInsert reports whether n bytes can be inserted without exceeding MaxSize.
func (m *MutableNetworkData) CanInsert(n int) bool {
	return m.length+n <= MaxSize
}

// ---------------------------------------------------------------------------
// Core mutations
// ---------------------------------------------------------------------------

// Insert inserts n zero bytes at the given offset, shifting subsequent data
// right. Returns errors.ErrNoBufs if there is insufficient space, or
// errors.ErrParse if the offset is out of range.
func (m *MutableNetworkData) Insert(offset, n int) error {
	if offset < 0 || offset > m.length {
		return errors.ErrParse
	}
	if !m.CanInsert(n) {
		return errors.ErrNoBufs
	}
	// Shift data at [offset, length) right by n.
	copy(m.buf[offset+n:], m.buf[offset:m.length])
	// Zero the inserted region.
	for i := offset; i < offset+n; i++ {
		m.buf[i] = 0
	}
	m.length += n
	return nil
}

// Remove removes n bytes starting at offset, shifting subsequent data left.
// Returns errors.ErrParse if the range is out of bounds.
func (m *MutableNetworkData) Remove(offset, n int) error {
	if offset < 0 || n < 0 || offset+n > m.length {
		return errors.ErrParse
	}
	copy(m.buf[offset:], m.buf[offset+n:m.length])
	m.length -= n
	return nil
}

// Append appends data to the end of the buffer. Returns errors.ErrNoBufs if
// there is insufficient space.
func (m *MutableNetworkData) Append(data []byte) error {
	if !m.CanInsert(len(data)) {
		return errors.ErrNoBufs
	}
	copy(m.buf[m.length:], data)
	m.length += len(data)
	return nil
}

// ---------------------------------------------------------------------------
// TLV accessors
// ---------------------------------------------------------------------------

// TLVLength returns the value-length field of the TLV at offset. Returns
// errors.ErrParse if the offset is out of range.
func (m *MutableNetworkData) TLVLength(offset int) (uint8, error) {
	if offset < 0 || offset+TLVHeaderSize > m.length {
		return 0, errors.ErrParse
	}
	return m.buf[offset+1], nil
}

// SetTLVLength sets the value-length field of the TLV at offset.
func (m *MutableNetworkData) SetTLVLength(offset int, length uint8) error {
	if offset < 0 || offset+TLVHeaderSize > m.length {
		return errors.ErrParse
	}
	m.buf[offset+1] = length
	return nil
}

// TLVType returns the TLV type and stable flag of the TLV at offset.
func (m *MutableNetworkData) TLVType(offset int) (TLVType, bool, error) {
	if offset < 0 || offset+TLVHeaderSize > m.length {
		return 0, false, errors.ErrParse
	}
	b0 := m.buf[offset]
	return TLVType(b0 >> 1), (b0 & 0x01) != 0, nil
}

// TLVSize returns the total size (header + value) of the TLV at offset.
func (m *MutableNetworkData) TLVSize(offset int) (int, error) {
	l, err := m.TLVLength(offset)
	if err != nil {
		return 0, err
	}
	return TLVHeaderSize + int(l), nil
}

// RemoveTLV removes the complete TLV (header + value) at the given offset.
func (m *MutableNetworkData) RemoveTLV(offset int) error {
	size, err := m.TLVSize(offset)
	if err != nil {
		return err
	}
	return m.Remove(offset, size)
}

// AppendTLVSpace appends space for a TLV of the given total size (header +
// value) at the end of the buffer and returns the offset where the new TLV
// starts. The caller is responsible for writing the TLV header and value into
// the buffer at the returned offset. Returns -1 and errors.ErrNoBufs if there
// is insufficient space.
func (m *MutableNetworkData) AppendTLVSpace(size int) (int, error) {
	if !m.CanInsert(size) {
		return -1, errors.ErrNoBufs
	}
	offset := m.length
	m.length += size
	return offset, nil
}

// InsertTLVSpace inserts space for a sub-TLV within a parent TLV. The space is
// inserted at insertOffset, and the parent TLV at parentOffset has its length
// increased by n bytes. Returns errors.ErrNoBufs or errors.ErrParse on failure.
func (m *MutableNetworkData) InsertTLVSpace(parentOffset, insertOffset, n int) error {
	if err := m.Insert(insertOffset, n); err != nil {
		return err
	}
	// Update parent TLV length.
	oldLen, err := m.TLVLength(parentOffset)
	if err != nil {
		return err
	}
	return m.SetTLVLength(parentOffset, oldLen+uint8(n))
}

// ---------------------------------------------------------------------------
// Find operations
// ---------------------------------------------------------------------------

// FindTLV finds the first top-level TLV with the given type and stable flag.
// Returns the byte offset of the TLV header, or -1 if not found.
func (m *MutableNetworkData) FindTLV(typ TLVType, stable bool) int {
	off := 0
	for off+TLVHeaderSize <= m.length {
		t, s, l, err := ParseTLVHeader(m.buf[off:m.length])
		if err != nil {
			return -1
		}
		if t == typ && s == stable {
			return off
		}
		off += TLVHeaderSize + int(l)
	}
	return -1
}

// FindPrefix finds a Prefix TLV whose prefix matches the given ip6.Prefix.
// Returns the byte offset of the Prefix TLV header, or -1 if not found.
// This matches OpenThread's NetworkData::FindPrefix().
func (m *MutableNetworkData) FindPrefix(prefix ip6.Prefix) int {
	off := 0
	for off+TLVHeaderSize <= m.length {
		typ, stable, length, err := ParseTLVHeader(m.buf[off:m.length])
		if err != nil {
			return -1
		}
		valueEnd := off + TLVHeaderSize + int(length)
		if valueEnd > m.length {
			return -1
		}
		if typ == TLVTypePrefix {
			info, pErr := ParsePrefixValue(m.buf[off+TLVHeaderSize:valueEnd], stable)
			if pErr == nil && info.Prefix.IsEqual(prefix) {
				return off
			}
		}
		off = valueEnd
	}
	return -1
}

// FindService finds a Service TLV matching the given enterprise number and
// service data. Returns the byte offset of the Service TLV header, or -1 if
// not found. This matches OpenThread's NetworkData::FindService().
func (m *MutableNetworkData) FindService(enterpriseNumber uint32, serviceData []byte) int {
	off := 0
	for off+TLVHeaderSize <= m.length {
		typ, stable, length, err := ParseTLVHeader(m.buf[off:m.length])
		if err != nil {
			return -1
		}
		valueEnd := off + TLVHeaderSize + int(length)
		if valueEnd > m.length {
			return -1
		}
		if typ == TLVTypeService {
			info, sErr := ParseServiceValue(m.buf[off+TLVHeaderSize:valueEnd], stable)
			if sErr == nil &&
				info.EnterpriseNumber == enterpriseNumber &&
				bytesEqual(info.ServiceData, serviceData) {
				return off
			}
		}
		off = valueEnd
	}
	return -1
}

// FindSubTLV finds a sub-TLV of the given type within the parent TLV at
// parentOffset. Returns the byte offset (relative to buffer start) of the
// sub-TLV header, or -1 if not found.
func (m *MutableNetworkData) FindSubTLV(parentOffset int, typ TLVType) int {
	pLen, err := m.TLVLength(parentOffset)
	if err != nil {
		return -1
	}

	// Determine the start of sub-TLVs within the parent value.
	subStart, err := m.subTLVsStart(parentOffset)
	if err != nil {
		return -1
	}

	parentEnd := parentOffset + TLVHeaderSize + int(pLen)
	off := subStart
	for off+TLVHeaderSize <= parentEnd {
		t, _, l, hErr := ParseTLVHeader(m.buf[off:parentEnd])
		if hErr != nil {
			return -1
		}
		if t == typ {
			return off
		}
		off += TLVHeaderSize + int(l)
	}
	return -1
}

// FindSubTLVStable finds a sub-TLV of the given type and stable flag within
// the parent TLV at parentOffset. Returns the byte offset (relative to buffer
// start) of the sub-TLV header, or -1 if not found.
func (m *MutableNetworkData) FindSubTLVStable(parentOffset int, typ TLVType, stable bool) int {
	pLen, err := m.TLVLength(parentOffset)
	if err != nil {
		return -1
	}

	subStart, err := m.subTLVsStart(parentOffset)
	if err != nil {
		return -1
	}

	parentEnd := parentOffset + TLVHeaderSize + int(pLen)
	off := subStart
	for off+TLVHeaderSize <= parentEnd {
		t, s, l, hErr := ParseTLVHeader(m.buf[off:parentEnd])
		if hErr != nil {
			return -1
		}
		if t == typ && s == stable {
			return off
		}
		off += TLVHeaderSize + int(l)
	}
	return -1
}

// subTLVsStart returns the byte offset where sub-TLVs begin for the parent
// TLV at parentOffset. For Prefix TLVs, this skips DomainID + PrefixLen +
// prefix bytes. For Service TLVs, this skips the service header. For other
// TLVs, sub-TLVs start immediately after the header.
func (m *MutableNetworkData) subTLVsStart(parentOffset int) (int, error) {
	if parentOffset < 0 || parentOffset+TLVHeaderSize > m.length {
		return 0, errors.ErrParse
	}
	typ := TLVType(m.buf[parentOffset] >> 1)
	valueStart := parentOffset + TLVHeaderSize

	switch typ {
	case TLVTypePrefix:
		// DomainID(1) + PrefixLength(1) + ceil(PrefixLength/8) bytes.
		if valueStart+2 > m.length {
			return 0, errors.ErrParse
		}
		prefixLen := m.buf[valueStart+1]
		pbs := prefixByteSize(prefixLen)
		return valueStart + 2 + pbs, nil

	case TLVTypeService:
		// flagsServiceID(1) [+ enterpriseNumber(4)] + serviceDataLen(1) + serviceData(N).
		if valueStart+1 > m.length {
			return 0, errors.ErrParse
		}
		flagsByte := m.buf[valueStart]
		isThread := (flagsByte & 0x80) != 0
		off := valueStart + 1
		if !isThread {
			off += 4 // enterprise number
		}
		if off+1 > m.length {
			return 0, errors.ErrParse
		}
		sdLen := int(m.buf[off])
		off += 1 + sdLen
		return off, nil

	default:
		return valueStart, nil
	}
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// Validate checks that all TLVs in the buffer are well-formed: each TLV
// header's declared length fits within the remaining data. Returns
// errors.ErrParse if the data is malformed.
func (m *MutableNetworkData) Validate() error {
	off := 0
	for off+TLVHeaderSize <= m.length {
		_, _, length, err := ParseTLVHeader(m.buf[off:m.length])
		if err != nil {
			return errors.ErrParse
		}
		next := off + TLVHeaderSize + int(length)
		if next > m.length {
			return errors.ErrParse
		}
		off = next
	}
	if off != m.length {
		return errors.ErrParse
	}
	return nil
}

// ---------------------------------------------------------------------------
// Copy
// ---------------------------------------------------------------------------

// CopyFrom replaces the buffer contents with data from src. Only the stable
// subset is copied if stableOnly is true; otherwise all data is copied.
func (m *MutableNetworkData) CopyFrom(src *MutableNetworkData, stableOnly bool) {
	if !stableOnly {
		m.length = src.length
		copy(m.buf[:], src.buf[:src.length])
		return
	}
	// Copy only stable TLVs.
	m.length = 0
	off := 0
	for off+TLVHeaderSize <= src.length {
		_, stable, length, err := ParseTLVHeader(src.buf[off:src.length])
		if err != nil {
			break
		}
		size := TLVHeaderSize + int(length)
		next := off + size
		if next > src.length {
			break
		}
		if stable {
			n := copy(m.buf[m.length:], src.buf[off:next])
			m.length += n
		}
		off = next
	}
}

// ---------------------------------------------------------------------------
// RLOC16 helpers
// ---------------------------------------------------------------------------

// ContainsEntriesFrom reports whether the parent TLV at parentOffset contains
// any HasRoute or BorderRouter entries with the given RLOC16, or any Server
// sub-TLVs with the given Server16 value.
func (m *MutableNetworkData) ContainsEntriesFrom(parentOffset int, rloc16 uint16) bool {
	pLen, err := m.TLVLength(parentOffset)
	if err != nil {
		return false
	}
	subStart, err := m.subTLVsStart(parentOffset)
	if err != nil {
		return false
	}
	parentEnd := parentOffset + TLVHeaderSize + int(pLen)
	off := subStart
	for off+TLVHeaderSize <= parentEnd {
		t, _, l, hErr := ParseTLVHeader(m.buf[off:parentEnd])
		if hErr != nil {
			return false
		}
		subValueStart := off + TLVHeaderSize
		subValueEnd := subValueStart + int(l)
		if subValueEnd > parentEnd {
			return false
		}

		switch t {
		case TLVTypeHasRoute:
			entryOff := subValueStart
			for entryOff+HasRouteEntrySize <= subValueEnd {
				r := encoding.BigEndianReadUint16(m.buf[entryOff : entryOff+2])
				if r == rloc16 {
					return true
				}
				entryOff += HasRouteEntrySize
			}
		case TLVTypeBorderRouter:
			entryOff := subValueStart
			for entryOff+BorderRouterEntrySize <= subValueEnd {
				r := encoding.BigEndianReadUint16(m.buf[entryOff : entryOff+2])
				if r == rloc16 {
					return true
				}
				entryOff += BorderRouterEntrySize
			}
		case TLVTypeServer:
			if subValueEnd-subValueStart >= 2 {
				r := encoding.BigEndianReadUint16(m.buf[subValueStart : subValueStart+2])
				if r == rloc16 {
					return true
				}
			}
		}

		off = subValueEnd
	}
	return false
}

// RemoveRLOC16Entries removes all HasRoute/BorderRouter entries and Server
// sub-TLVs that match the given RLOC16, cleaning up empty sub-TLVs and empty
// parent TLVs as it goes. matchMode controls how RLOC16s are compared:
//
//   - MatchModeRLOC16 compares exact RLOC16 values.
//   - MatchModeRouterID compares only the Router ID portion (upper 6 bits).
func (m *MutableNetworkData) RemoveRLOC16Entries(rloc16 uint16, matchMode MatchMode) {
	off := 0
	for off+TLVHeaderSize <= m.length {
		typ, _, length, err := ParseTLVHeader(m.buf[off:m.length])
		if err != nil {
			return
		}
		valueEnd := off + TLVHeaderSize + int(length)
		if valueEnd > m.length {
			return
		}

		switch typ {
		case TLVTypePrefix, TLVTypeService:
			m.removeRLOC16FromParent(off, rloc16, matchMode)
			// Re-read length as it may have changed.
			newLen, lErr := m.TLVLength(off)
			if lErr != nil {
				return
			}
			newValueEnd := off + TLVHeaderSize + int(newLen)
			// Check if the parent has any sub-TLVs left.
			subStart, sErr := m.subTLVsStart(off)
			if sErr != nil {
				off = newValueEnd
				continue
			}
			if subStart >= newValueEnd {
				// No sub-TLVs left — remove the entire parent TLV.
				_ = m.RemoveTLV(off)
				continue // don't advance off; next TLV is now at same position
			}
			off = newValueEnd
		default:
			off = valueEnd
		}
	}
}

// removeRLOC16FromParent removes matching entries from sub-TLVs within the
// parent TLV at parentOffset.
func (m *MutableNetworkData) removeRLOC16FromParent(parentOffset int, rloc16 uint16, matchMode MatchMode) {
	pLen, err := m.TLVLength(parentOffset)
	if err != nil {
		return
	}
	subStart, err := m.subTLVsStart(parentOffset)
	if err != nil {
		return
	}
	parentEnd := parentOffset + TLVHeaderSize + int(pLen)
	off := subStart

	for off+TLVHeaderSize <= parentEnd {
		t, _, l, hErr := ParseTLVHeader(m.buf[off:parentEnd])
		if hErr != nil {
			return
		}
		subValueStart := off + TLVHeaderSize
		subValueEnd := subValueStart + int(l)
		if subValueEnd > parentEnd {
			return
		}

		switch t {
		case TLVTypeHasRoute:
			m.removeMatchingEntries(parentOffset, off, HasRouteEntrySize, rloc16, matchMode)
		case TLVTypeBorderRouter:
			m.removeMatchingEntries(parentOffset, off, BorderRouterEntrySize, rloc16, matchMode)
		case TLVTypeServer:
			if subValueEnd-subValueStart >= 2 {
				r := encoding.BigEndianReadUint16(m.buf[subValueStart : subValueStart+2])
				if rloc16Matches(r, rloc16, matchMode) {
					size := TLVHeaderSize + int(l)
					_ = m.Remove(off, size)
					// Update parent length.
					newPLen, _ := m.TLVLength(parentOffset)
					_ = m.SetTLVLength(parentOffset, newPLen-uint8(size))
					// Re-read parentEnd.
					pLenNow, _ := m.TLVLength(parentOffset)
					parentEnd = parentOffset + TLVHeaderSize + int(pLenNow)
					continue // don't advance
				}
			}
		}

		// Re-read after possible mutations.
		newL, lErr := m.TLVLength(off)
		if lErr != nil {
			return
		}
		if newL == 0 {
			// Sub-TLV is now empty — remove it.
			size := TLVHeaderSize
			_ = m.Remove(off, size)
			curPLen, _ := m.TLVLength(parentOffset)
			_ = m.SetTLVLength(parentOffset, curPLen-uint8(size))
			pLenNow, _ := m.TLVLength(parentOffset)
			parentEnd = parentOffset + TLVHeaderSize + int(pLenNow)
			continue
		}
		off += TLVHeaderSize + int(newL)
		// Refresh parentEnd in case of mutations.
		pLenNow, _ := m.TLVLength(parentOffset)
		parentEnd = parentOffset + TLVHeaderSize + int(pLenNow)
	}
}

// removeMatchingEntries removes individual entries (HasRoute or BorderRouter)
// that match rloc16 from the sub-TLV at subTLVOffset, updating both the
// sub-TLV and parent TLV lengths.
func (m *MutableNetworkData) removeMatchingEntries(parentOffset, subTLVOffset, entrySize int, rloc16 uint16, matchMode MatchMode) {
	subLen, err := m.TLVLength(subTLVOffset)
	if err != nil {
		return
	}
	entryOff := subTLVOffset + TLVHeaderSize
	endOff := entryOff + int(subLen)

	for entryOff+entrySize <= endOff {
		r := encoding.BigEndianReadUint16(m.buf[entryOff : entryOff+2])
		if rloc16Matches(r, rloc16, matchMode) {
			_ = m.Remove(entryOff, entrySize)
			// Update sub-TLV length.
			newSubLen := subLen - uint8(entrySize)
			_ = m.SetTLVLength(subTLVOffset, newSubLen)
			subLen = newSubLen
			// Update parent length.
			pLen, _ := m.TLVLength(parentOffset)
			_ = m.SetTLVLength(parentOffset, pLen-uint8(entrySize))
			endOff -= entrySize
			continue // don't advance — next entry is now at same offset
		}
		entryOff += entrySize
	}
}

// MatchMode controls how RLOC16 values are compared.
type MatchMode uint8

const (
	// MatchModeRLOC16 compares exact RLOC16 values.
	MatchModeRLOC16 MatchMode = 0
	// MatchModeRouterID compares only the Router ID (upper 6 bits of RLOC16).
	MatchModeRouterID MatchMode = 1
)

// rloc16Matches reports whether candidate matches target according to mode.
func rloc16Matches(candidate, target uint16, mode MatchMode) bool {
	switch mode {
	case MatchModeRouterID:
		return (candidate >> 10) == (target >> 10)
	default:
		return candidate == target
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// bytesEqual reports whether a and b have equal contents.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
