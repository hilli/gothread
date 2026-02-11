// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package router

import (
	"github.com/hilli/gothread/crypto/sha256"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/nd6"
)

// ---------------------------------------------------------------------------
// OmrPrefix — an Off-Mesh Routable prefix with preference metadata
// ---------------------------------------------------------------------------

// OmrPrefix represents an OMR prefix with preference.
type OmrPrefix struct {
	Prefix     [16]byte
	PrefixLen  uint8
	Preference nd6.RoutePreference // High/Medium/Low
	IsLocal    bool                // generated locally vs learned from network data
}

// IsEmpty returns true if the prefix length is zero.
func (p OmrPrefix) IsEmpty() bool {
	return p.PrefixLen == 0
}

// IsEqual returns true if two OmrPrefix values have the same prefix and
// prefix length (ignoring preference and local flag).
func (p OmrPrefix) IsEqual(other OmrPrefix) bool {
	if p.PrefixLen != other.PrefixLen {
		return false
	}
	return matchBits(p.Prefix[:], other.Prefix[:], p.PrefixLen)
}

// preferenceRank maps a RoutePreference to a comparable integer.
// Higher rank means higher preference.
func preferenceRank(p nd6.RoutePreference) int {
	switch p {
	case nd6.RoutePrefHigh:
		return 2
	case nd6.RoutePrefMedium:
		return 1
	case nd6.RoutePrefLow:
		return 0
	default:
		return 1
	}
}

// IsFavoredOver returns true if p should be favored over other.
//
// Selection criteria (in order):
//  1. Longer prefix length is preferred.
//  2. Higher route preference is preferred.
//  3. Local prefix is preferred over remote.
//  4. Lexicographically smaller prefix bytes break ties.
func (p OmrPrefix) IsFavoredOver(other OmrPrefix) bool {
	if p.PrefixLen != other.PrefixLen {
		return p.PrefixLen > other.PrefixLen
	}
	r1 := preferenceRank(p.Preference)
	r2 := preferenceRank(other.Preference)
	if r1 != r2 {
		return r1 > r2
	}
	if p.IsLocal != other.IsLocal {
		return p.IsLocal
	}
	// Lexicographic comparison: smaller wins.
	bytes := int((p.PrefixLen + 7) / 8)
	for i := 0; i < bytes; i++ {
		if p.Prefix[i] != other.Prefix[i] {
			return p.Prefix[i] < other.Prefix[i]
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// OmrPrefixManager — selects and manages the OMR prefix
// ---------------------------------------------------------------------------

// OmrPrefixManager selects and manages the OMR prefix used by this border
// router. It generates a local ULA /64 prefix from the device's extended
// address and evaluates which prefix (local or from network data) should be
// the currently favored prefix.
type OmrPrefixManager struct {
	localPrefix      OmrPrefix // locally generated OMR prefix
	favoredPrefix    OmrPrefix // currently favored (best) OMR prefix
	hasLocalPrefix   bool
	hasFavoredPrefix bool
	isAddedInNetData bool // whether local prefix is published in network data
}

// NewOmrPrefixManager creates a new OmrPrefixManager.
func NewOmrPrefixManager() *OmrPrefixManager {
	return &OmrPrefixManager{}
}

// GenerateLocalPrefix generates a ULA /64 OMR prefix from the given extended
// address using SHA-256.
//
// The algorithm:
//  1. Compute hash = SHA-256(extAddr).
//  2. Set prefix byte 0 = 0xfd (ULA).
//  3. Copy hash bytes 0..4 into prefix bytes 1..5 (40 bits of hash).
//  4. Set prefix bytes 6..7 = 0 (subnet ID = 0).
//  5. Set prefix bytes 8..15 = 0 (IID portion, not part of /64 prefix).
//  6. Prefix length = 64.
func (m *OmrPrefixManager) GenerateLocalPrefix(extAddr [8]byte) error {
	var s sha256.Sha256
	s.Start()
	s.Update(extAddr[:])
	var h sha256.Hash
	s.Finish(&h)

	var prefix [16]byte
	prefix[0] = 0xfd
	copy(prefix[1:6], h[0:5])
	// prefix[6] and prefix[7] are already zero (subnet ID).
	// prefix[8:16] are already zero.

	m.localPrefix = OmrPrefix{
		Prefix:     prefix,
		PrefixLen:  64,
		Preference: nd6.RoutePrefMedium,
		IsLocal:    true,
	}
	m.hasLocalPrefix = true
	return nil
}

// Evaluate re-evaluates which OMR prefix should be favored, considering the
// local prefix and any prefixes discovered from network data. Returns true if
// the favored prefix changed.
func (m *OmrPrefixManager) Evaluate(networkPrefixes []OmrPrefix) bool {
	oldFavored := m.favoredPrefix
	oldHas := m.hasFavoredPrefix

	// Start with no favored prefix.
	m.hasFavoredPrefix = false
	m.favoredPrefix = OmrPrefix{}

	// Consider network prefixes.
	for _, np := range networkPrefixes {
		if np.IsEmpty() {
			continue
		}
		if !m.hasFavoredPrefix || np.IsFavoredOver(m.favoredPrefix) {
			m.favoredPrefix = np
			m.hasFavoredPrefix = true
		}
	}

	// Consider local prefix.
	if m.hasLocalPrefix {
		if !m.hasFavoredPrefix || m.localPrefix.IsFavoredOver(m.favoredPrefix) {
			m.favoredPrefix = m.localPrefix
			m.hasFavoredPrefix = true
		}
	}

	// Determine if the favored prefix changed.
	if oldHas != m.hasFavoredPrefix {
		return true
	}
	if !m.hasFavoredPrefix {
		return false
	}
	return !oldFavored.IsEqual(m.favoredPrefix) ||
		oldFavored.Preference != m.favoredPrefix.Preference
}

// GetFavoredPrefix returns the currently favored OMR prefix and true, or
// a zero OmrPrefix and false if none is selected.
func (m *OmrPrefixManager) GetFavoredPrefix() (OmrPrefix, bool) {
	return m.favoredPrefix, m.hasFavoredPrefix
}

// GetLocalPrefix returns the locally generated OMR prefix and true, or
// a zero OmrPrefix and false if none has been generated.
func (m *OmrPrefixManager) GetLocalPrefix() (OmrPrefix, bool) {
	return m.localPrefix, m.hasLocalPrefix
}

// ShouldPublish returns true if the local prefix is the favored prefix and
// should be published into the Thread network data.
func (m *OmrPrefixManager) ShouldPublish() bool {
	if !m.hasLocalPrefix || !m.hasFavoredPrefix {
		return false
	}
	return m.favoredPrefix.IsLocal && m.favoredPrefix.IsEqual(m.localPrefix)
}

// SetAddedInNetData records whether the local prefix is currently published
// in the Thread network data.
func (m *OmrPrefixManager) SetAddedInNetData(added bool) {
	m.isAddedInNetData = added
}

// IsAddedInNetData returns true if the local prefix is published in network data.
func (m *OmrPrefixManager) IsAddedInNetData() bool {
	return m.isAddedInNetData
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// matchBits returns true if the first numBits bits of a and b are equal.
func matchBits(a, b []byte, numBits uint8) bool {
	fullBytes := int(numBits) / 8
	for i := 0; i < fullBytes; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	remainBits := numBits % 8
	if remainBits > 0 {
		mask := byte(0xff << (8 - remainBits))
		if (a[fullBytes] & mask) != (b[fullBytes] & mask) {
			return false
		}
	}
	return true
}

// ValidateOmrPrefix checks that a prefix is a valid OMR prefix.
// A valid OMR prefix must be a /64 ULA (fd00::/8) or GUA (2000::/3) prefix
// that is not link-local or multicast.
func ValidateOmrPrefix(prefix [16]byte, prefixLen uint8) error {
	if prefixLen == 0 || prefixLen > 128 {
		return errors.ErrInvalidArgs
	}
	// Must not be link-local (fe80::/10).
	if prefix[0] == 0xfe && (prefix[1]&0xc0) == 0x80 {
		return errors.ErrInvalidArgs
	}
	// Must not be multicast (ff00::/8).
	if prefix[0] == 0xff {
		return errors.ErrInvalidArgs
	}
	// Must not be loopback (::1/128).
	if prefixLen == 128 {
		allZero := true
		for i := 0; i < 15; i++ {
			if prefix[i] != 0 {
				allZero = false
				break
			}
		}
		if allZero && prefix[15] == 1 {
			return errors.ErrInvalidArgs
		}
	}
	return nil
}
