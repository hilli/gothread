// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// MPL (Multicast Protocol for Low-Power and Lossy Networks) implementation.
//
// This is a Go port of the MPL handling in OpenThread's
// src/core/net/ip6_mpl.hpp and src/core/net/ip6_mpl.cpp.

package ip6

import (
	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// MPLOption (wire format, 6 bytes max)
// ---------------------------------------------------------------------------

// MPL option constants.
const (
	// MPLOptionType is the IPv6 Hop-by-Hop option type for MPL.
	MPLOptionType uint8 = 0x6d

	// MPLOptionMinSize is the minimum MPL option size in bytes
	// (type + length + control + sequence).
	MPLOptionMinSize = 4
)

// MPLSeedIDLength represents the seed ID length encoding in the MPL option
// control byte (top 2 bits).
type MPLSeedIDLength uint8

const (
	// MPLSeedIDLength0 indicates a 0-byte seed ID.
	MPLSeedIDLength0 MPLSeedIDLength = 0 << 6
	// MPLSeedIDLength2 indicates a 2-byte seed ID.
	MPLSeedIDLength2 MPLSeedIDLength = 1 << 6
	// MPLSeedIDLength8 indicates an 8-byte seed ID.
	MPLSeedIDLength8 MPLSeedIDLength = 2 << 6
	// MPLSeedIDLength16 indicates a 16-byte seed ID.
	MPLSeedIDLength16 MPLSeedIDLength = 3 << 6
)

// MPLOption represents an MPL option carried in an IPv6 Hop-by-Hop extension
// header.
//
// Wire layout:
//
//	byte[0]:   Type (0x6d)
//	byte[1]:   Length (2 for SeedIDLength0, 4 for SeedIDLength2)
//	byte[2]:   Control (SeedIDLength in top 2 bits, M flag in bit 5)
//	byte[3]:   Sequence
//	byte[4-5]: SeedID (only present for SeedIDLength2)
type MPLOption struct {
	data [6]byte
}

// Init initializes the MPL option for the given seed ID length.
// Only MPLSeedIDLength0 and MPLSeedIDLength2 are supported; other values
// cause a panic.
func (o *MPLOption) Init(seedIDLength MPLSeedIDLength) {
	o.data = [6]byte{}
	o.data[0] = MPLOptionType

	switch seedIDLength {
	case MPLSeedIDLength0:
		o.data[1] = 2
	case MPLSeedIDLength2:
		o.data[1] = 4
	default:
		panic("ip6: unsupported MPL seed ID length")
	}

	o.data[2] = uint8(seedIDLength)
}

// GetSeedIDLength returns the seed ID length from the control byte.
func (o *MPLOption) GetSeedIDLength() MPLSeedIDLength {
	return MPLSeedIDLength(o.data[2] & 0xC0)
}

// IsMaxFlagSet returns true if the M (max) flag is set in the control byte.
func (o *MPLOption) IsMaxFlagSet() bool {
	return o.data[2]&0x20 != 0
}

// ClearMaxFlag clears the M (max) flag in the control byte.
func (o *MPLOption) ClearMaxFlag() {
	o.data[2] &^= 0x20
}

// SetMaxFlag sets the M (max) flag in the control byte.
func (o *MPLOption) SetMaxFlag() {
	o.data[2] |= 0x20
}

// GetSequence returns the MPL sequence number.
func (o *MPLOption) GetSequence() uint8 {
	return o.data[3]
}

// SetSequence sets the MPL sequence number.
func (o *MPLOption) SetSequence(seq uint8) {
	o.data[3] = seq
}

// GetSeedID returns the 16-bit seed ID (big-endian).
func (o *MPLOption) GetSeedID() uint16 {
	return encoding.BigEndianReadUint16(o.data[4:6])
}

// SetSeedID sets the 16-bit seed ID (big-endian).
func (o *MPLOption) SetSeedID(id uint16) {
	encoding.BigEndianWriteUint16(id, o.data[4:6])
}

// GetType returns the option type byte.
func (o *MPLOption) GetType() uint8 {
	return o.data[0]
}

// GetLength returns the option length byte (excludes type and length bytes).
func (o *MPLOption) GetLength() uint8 {
	return o.data[1]
}

// TotalSize returns the total option size in bytes (type + length + body).
func (o *MPLOption) TotalSize() int {
	return 2 + int(o.data[1])
}

// ---------------------------------------------------------------------------
// MPLSeedEntry
// ---------------------------------------------------------------------------

// MPLSeedEntry represents a single entry in the MPL seed set.
type MPLSeedEntry struct {
	SeedID   uint16
	Sequence uint8
	Lifetime uint8
}

// ---------------------------------------------------------------------------
// Mpl
// ---------------------------------------------------------------------------

// Mpl seed set constants.
const (
	// DefaultNumSeedEntries is the default number of seed set entries.
	DefaultNumSeedEntries = 32

	// DefaultSeedEntryLifetime is the default lifetime for a seed entry
	// in timer ticks (seconds).
	DefaultSeedEntryLifetime uint8 = 4
)

// Mpl manages the MPL seed set and sequence number state.
type Mpl struct {
	seedSet  []MPLSeedEntry
	sequence uint8
}

// NewMpl creates a new Mpl instance with an empty seed set.
func NewMpl() *Mpl {
	return &Mpl{
		seedSet:  make([]MPLSeedEntry, DefaultNumSeedEntries),
		sequence: 0,
	}
}

// GetSequence returns the current outgoing sequence number.
func (m *Mpl) GetSequence() uint8 {
	return m.sequence
}

// IncrementSequence advances the outgoing sequence number by one.
func (m *Mpl) IncrementSequence() {
	m.sequence++
}

// UpdateSeedSet processes an incoming MPL message identified by (seedID,
// sequence). It returns nil if the entry was successfully added, or
// errors.ErrDrop if the message is a duplicate or the seed set is full.
//
// Algorithm (ported from OpenThread ip6_mpl.cpp):
//  1. Scan entries grouped by seedID.
//  2. If (seedID, sequence) already exists, refresh its lifetime and return
//     ErrDrop.
//  3. Find the eviction candidate from the group with the most entries and
//     find the insertion point (maintaining sequence order within each group).
//  4. If evicting a valid entry, require the group to have at least 2 entries.
//  5. Shift entries and insert the new entry with DefaultSeedEntryLifetime.
//  6. Return nil on success, ErrDrop if no room.
func (m *Mpl) UpdateSeedSet(seedID uint16, sequence uint8) error {
	numEntries := len(m.seedSet)

	// bestGroup tracks the group with the most entries (eviction candidate).
	bestGroupCount := 0
	bestGroupLastIdx := 0 // index of last entry in the best group

	// insertIdx is where the new entry should be inserted.
	insertIdx := -1

	// Scan the seed set. Entries with Lifetime > 0 are valid.
	// Entries are logically grouped by SeedID.
	i := 0
	for i < numEntries && m.seedSet[i].Lifetime > 0 {
		groupSeedID := m.seedSet[i].SeedID
		groupCount := 0

		// Scan entries in this group (same seedID, contiguous).
		for i < numEntries && m.seedSet[i].Lifetime > 0 && m.seedSet[i].SeedID == groupSeedID {
			// Check for duplicate.
			if groupSeedID == seedID && m.seedSet[i].Sequence == sequence {
				m.seedSet[i].Lifetime = DefaultSeedEntryLifetime
				return errors.ErrDrop
			}

			groupCount++
			i++
		}

		// Track insertion point: within the matching seedID group,
		// insert at the end of the group.
		if groupSeedID == seedID {
			insertIdx = i
		}

		// Track the group with the most entries for eviction.
		if groupCount > bestGroupCount {
			bestGroupCount = groupCount
			bestGroupLastIdx = i - 1
		}
	}

	// If no matching seedID group was found, insert at the current position
	// (end of valid entries or in the first free slot).
	if insertIdx == -1 {
		insertIdx = i
	}

	// If there are free slots, just shift and insert.
	if i < numEntries {
		// Shift entries from insertIdx to i-1 down by one to make room.
		copy(m.seedSet[insertIdx+1:i+1], m.seedSet[insertIdx:i])
		m.seedSet[insertIdx] = MPLSeedEntry{
			SeedID:   seedID,
			Sequence: sequence,
			Lifetime: DefaultSeedEntryLifetime,
		}
		return nil
	}

	// No free slots — need to evict. Require the best group to have >= 2
	// entries so we don't remove the only entry for a seed.
	if bestGroupCount < 2 {
		return errors.ErrDrop
	}

	// Evict the last entry in the largest group.
	evictIdx := bestGroupLastIdx

	// Adjust insertIdx if needed after eviction.
	if insertIdx > evictIdx {
		insertIdx--
	}

	// Remove the evicted entry by shifting.
	copy(m.seedSet[evictIdx:numEntries-1], m.seedSet[evictIdx+1:numEntries])
	// Clear the last slot (now freed).
	m.seedSet[numEntries-1] = MPLSeedEntry{}

	// Shift entries to make room at insertIdx.
	copy(m.seedSet[insertIdx+1:numEntries], m.seedSet[insertIdx:numEntries-1])
	m.seedSet[insertIdx] = MPLSeedEntry{
		SeedID:   seedID,
		Sequence: sequence,
		Lifetime: DefaultSeedEntryLifetime,
	}

	return nil
}

// HandleTimeTick decrements the lifetime of all active seed entries and
// compacts the set by removing expired entries.
func (m *Mpl) HandleTimeTick() {
	writeIdx := 0

	for readIdx := 0; readIdx < len(m.seedSet); readIdx++ {
		entry := &m.seedSet[readIdx]
		if entry.Lifetime == 0 {
			break
		}

		entry.Lifetime--

		if entry.Lifetime > 0 {
			if writeIdx != readIdx {
				m.seedSet[writeIdx] = m.seedSet[readIdx]
			}
			writeIdx++
		}
	}

	// Zero out freed entries.
	for i := writeIdx; i < len(m.seedSet); i++ {
		if m.seedSet[i].Lifetime == 0 && m.seedSet[i].SeedID == 0 && m.seedSet[i].Sequence == 0 {
			break
		}
		m.seedSet[i] = MPLSeedEntry{}
	}
}
