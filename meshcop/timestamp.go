// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
)

// TimestampSize is the wire size of a Timestamp in bytes.
const TimestampSize = 8

// Wire format constants for Timestamp encoding.
const (
	ticksOffset       = 1
	ticksMask         = 0xFFFE
	authoritativeFlag = 1
	// MaxTicks is the maximum value for the 15-bit ticks field (32767).
	MaxTicks = 0x7FFF
)

// Sentinel values for the invalid timestamp (all wire bytes 0xFF).
const (
	invalidSeconds        = 0x0000FFFFFFFFFFFF
	invalidTicks   uint16 = MaxTicks
)

// Timestamp represents a MeshCoP timestamp with 48-bit seconds, 15-bit ticks,
// and 1-bit authoritative flag. It is encoded as 8 bytes on the wire.
type Timestamp struct {
	seconds       uint64 // Only lower 48 bits are used.
	ticks         uint16 // Only lower 15 bits are used (0-32767).
	authoritative bool
}

// Seconds returns the 48-bit seconds value.
func (t *Timestamp) Seconds() uint64 {
	return t.seconds
}

// SetSeconds sets the 48-bit seconds value. Only the lower 48 bits are retained.
func (t *Timestamp) SetSeconds(s uint64) {
	t.seconds = s & 0x0000FFFFFFFFFFFF
}

// Ticks returns the 15-bit ticks value.
func (t *Timestamp) Ticks() uint16 {
	return t.ticks
}

// SetTicks sets the 15-bit ticks value (max 32767).
func (t *Timestamp) SetTicks(ticks uint16) {
	t.ticks = ticks & MaxTicks
}

// Authoritative returns the authoritative flag.
func (t *Timestamp) Authoritative() bool {
	return t.authoritative
}

// SetAuthoritative sets the authoritative flag.
func (t *Timestamp) SetAuthoritative(auth bool) {
	t.authoritative = auth
}

// IsValid reports whether the timestamp is valid (not the all-0xFF sentinel).
// A timestamp is invalid when all wire bytes would be 0xFF, which corresponds
// to seconds=0x0000FFFFFFFFFFFF, ticks=0x7FFF, authoritative=true.
func (t *Timestamp) IsValid() bool {
	return t.seconds != invalidSeconds || t.ticks != invalidTicks || !t.authoritative
}

// SetToInvalid sets the timestamp to the invalid sentinel value.
// When marshaled, all 8 wire bytes will be 0xFF.
func (t *Timestamp) SetToInvalid() {
	t.seconds = invalidSeconds
	t.ticks = invalidTicks
	t.authoritative = true
}

// IsOrphanAnnounce reports whether this is an MLE Orphan Announce timestamp
// (seconds=0, ticks=0, authoritative=true).
func (t *Timestamp) IsOrphanAnnounce() bool {
	return t.seconds == 0 && t.ticks == 0 && t.authoritative
}

// SetToOrphanAnnounce sets the timestamp for MLE Orphan Announce
// (seconds=0, ticks=0, authoritative=true).
func (t *Timestamp) SetToOrphanAnnounce() {
	t.seconds = 0
	t.ticks = 0
	t.authoritative = true
}

// AdvanceRandomTicks increments ticks by a random value in [1, MaxTicks].
// If ticks overflow past MaxTicks, seconds is incremented and ticks wrap.
func (t *Timestamp) AdvanceRandomTicks() {
	advance := uint16(rand.IntN(MaxTicks) + 1) //nolint:gosec // non-crypto random, matching OpenThread
	newTicks := uint32(t.ticks) + uint32(advance)
	if newTicks > uint32(MaxTicks) {
		t.SetSeconds(t.seconds + 1)
	}
	t.ticks = uint16(newTicks) & MaxTicks
}

// Compare compares two timestamps. It returns -1 if a < b, 0 if a == b,
// or 1 if a > b.
//
// Ordering rules: valid timestamps are greater than invalid ones. For two
// valid timestamps, seconds are compared first, then ticks, then the
// authoritative flag (true > false). Two invalid timestamps are equal.
func Compare(a, b *Timestamp) int {
	aValid := a.IsValid()
	bValid := b.IsValid()

	if aValid != bValid {
		if aValid {
			return 1
		}
		return -1
	}

	// Both invalid.
	if !aValid {
		return 0
	}

	// Both valid: compare seconds.
	switch {
	case a.seconds > b.seconds:
		return 1
	case a.seconds < b.seconds:
		return -1
	}

	// Seconds equal: compare ticks.
	switch {
	case a.ticks > b.ticks:
		return 1
	case a.ticks < b.ticks:
		return -1
	}

	// Ticks equal: compare authoritative (true > false).
	switch {
	case a.authoritative && !b.authoritative:
		return 1
	case !a.authoritative && b.authoritative:
		return -1
	}

	return 0
}

// MarshalBinary encodes the timestamp to its 8-byte wire format.
//
// Wire layout (big-endian):
//
//	bytes [0:2] = uint16 high 16 bits of 48-bit seconds
//	bytes [2:6] = uint32 low 32 bits of 48-bit seconds
//	bytes [6:8] = uint16 (ticks << 1) | authoritativeFlag
func (t *Timestamp) MarshalBinary() ([]byte, error) {
	buf := make([]byte, TimestampSize)

	binary.BigEndian.PutUint16(buf[0:2], uint16(t.seconds>>32))
	binary.BigEndian.PutUint32(buf[2:6], uint32(t.seconds&0xFFFFFFFF))

	ticksAndAuth := (t.ticks & MaxTicks) << ticksOffset
	if t.authoritative {
		ticksAndAuth |= authoritativeFlag
	}
	binary.BigEndian.PutUint16(buf[6:8], ticksAndAuth)

	return buf, nil
}

// UnmarshalBinary decodes the timestamp from its 8-byte wire format.
func (t *Timestamp) UnmarshalBinary(data []byte) error {
	if len(data) < TimestampSize {
		return fmt.Errorf("meshcop: timestamp requires %d bytes, got %d", TimestampSize, len(data))
	}

	seconds16 := uint64(binary.BigEndian.Uint16(data[0:2]))
	seconds32 := uint64(binary.BigEndian.Uint32(data[2:6]))
	t.seconds = (seconds16 << 32) | seconds32

	ticksAndAuth := binary.BigEndian.Uint16(data[6:8])
	t.ticks = ticksAndAuth >> ticksOffset
	t.authoritative = (ticksAndAuth & authoritativeFlag) != 0

	return nil
}
