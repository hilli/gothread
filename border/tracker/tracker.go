// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package tracker implements a Border Router State Tracker that monitors
// Thread Network Data for border router prefix information.
//
// This is a Go port of the border router tracking logic from OpenThread's
// src/core/border_router/routing_manager.cpp. It parses Thread Network Data
// TLVs to discover border routers and their advertised OMR and on-link
// prefixes.
package tracker

// ---------------------------------------------------------------------------
// Constants — Thread Network Data TLV types
// ---------------------------------------------------------------------------

const (
	// tlvTypePrefix is the Thread Network Data Prefix TLV type.
	tlvTypePrefix uint8 = 1
	// tlvTypeBorderRouter is the sub-TLV type for Border Router entries.
	tlvTypeBorderRouter uint8 = 0
	// tlvTypeHasRoute is the sub-TLV type for Has Route entries.
	tlvTypeHasRoute uint8 = 1
)

// Route preference values as encoded in Thread Network Data (2-bit field).
const (
	prefHigh   uint8 = 1
	prefMedium uint8 = 0
	prefLow    uint8 = 3
)

// ---------------------------------------------------------------------------
// BorderRouterEntry
// ---------------------------------------------------------------------------

// BorderRouterEntry represents a border router discovered from Thread
// Network Data.
type BorderRouterEntry struct {
	RouterID uint16
	Rloc16   uint16
}

// ---------------------------------------------------------------------------
// PrefixEntry
// ---------------------------------------------------------------------------

// PrefixEntry represents a prefix entry parsed from Thread Network Data.
type PrefixEntry struct {
	Prefix       [16]byte
	PrefixLength uint8
	Preference   uint8
	IsOnLink     bool
	Rloc16       uint16
}

// ---------------------------------------------------------------------------
// Tracker
// ---------------------------------------------------------------------------

// Tracker monitors Thread Network Data for border router prefix
// information. It maintains the set of discovered OMR and on-link prefixes
// along with their associated border routers.
type Tracker struct {
	prefixes      []PrefixEntry
	borderRouters []BorderRouterEntry
}

// NewTracker creates a new border router state tracker.
func NewTracker() *Tracker {
	return &Tracker{}
}

// HandleNetworkDataChanged parses Thread Network Data and updates the
// tracked prefix and border router information. The data is expected
// to be a sequence of Thread Network Data TLVs.
func (t *Tracker) HandleNetworkDataChanged(data []byte) {
	t.prefixes = nil
	t.borderRouters = nil

	t.parseNetworkData(data)
}

// GetBorderRouterCount returns the number of distinct border routers
// discovered from the network data.
func (t *Tracker) GetBorderRouterCount() int {
	return len(t.borderRouters)
}

// HasOmrPrefix returns true if the tracker contains an OMR prefix
// matching the given prefix and length. OMR prefixes are those with
// IsOnLink == false.
func (t *Tracker) HasOmrPrefix(prefix [16]byte, length uint8) bool {
	for i := range t.prefixes {
		if !t.prefixes[i].IsOnLink &&
			t.prefixes[i].PrefixLength == length &&
			matchPrefix(t.prefixes[i].Prefix, prefix, length) {
			return true
		}
	}
	return false
}

// HasOnLinkPrefix returns true if the tracker contains an on-link prefix
// matching the given prefix and length.
func (t *Tracker) HasOnLinkPrefix(prefix [16]byte, length uint8) bool {
	for i := range t.prefixes {
		if t.prefixes[i].IsOnLink &&
			t.prefixes[i].PrefixLength == length &&
			matchPrefix(t.prefixes[i].Prefix, prefix, length) {
			return true
		}
	}
	return false
}

// GetFavoredOmrPrefix returns the most preferred OMR prefix. Preference
// is first by route preference (High > Medium > Low), then by
// lexicographically smallest prefix bytes. Returns found=false if no
// OMR prefixes are present.
func (t *Tracker) GetFavoredOmrPrefix() (prefix [16]byte, length uint8, preference uint8, found bool) {
	first := true
	for i := range t.prefixes {
		if t.prefixes[i].IsOnLink {
			continue
		}
		if first || isBetterOmr(t.prefixes[i], PrefixEntry{
			Prefix:       prefix,
			PrefixLength: length,
			Preference:   preference,
		}) {
			prefix = t.prefixes[i].Prefix
			length = t.prefixes[i].PrefixLength
			preference = t.prefixes[i].Preference
			found = true
			first = false
		}
	}
	return
}

// GetPrefixes returns a copy of all tracked prefix entries.
func (t *Tracker) GetPrefixes() []PrefixEntry {
	if len(t.prefixes) == 0 {
		return nil
	}
	cp := make([]PrefixEntry, len(t.prefixes))
	copy(cp, t.prefixes)
	return cp
}

// GetBorderRouters returns a copy of all tracked border router entries.
func (t *Tracker) GetBorderRouters() []BorderRouterEntry {
	if len(t.borderRouters) == 0 {
		return nil
	}
	cp := make([]BorderRouterEntry, len(t.borderRouters))
	copy(cp, t.borderRouters)
	return cp
}

// Clear removes all tracked prefix and border router information.
func (t *Tracker) Clear() {
	t.prefixes = nil
	t.borderRouters = nil
}

// ---------------------------------------------------------------------------
// Network Data parsing
// ---------------------------------------------------------------------------

// parseNetworkData parses a sequence of Thread Network Data TLVs.
// Format per TLV: [type(1), length(1), value(length)]
func (t *Tracker) parseNetworkData(data []byte) {
	offset := 0
	for offset+2 <= len(data) {
		tlvType := data[offset]
		tlvLen := int(data[offset+1])
		offset += 2

		if offset+tlvLen > len(data) {
			break
		}

		tlvValue := data[offset : offset+tlvLen]
		offset += tlvLen

		if tlvType == tlvTypePrefix {
			t.parsePrefixTlv(tlvValue)
		}
	}
}

// parsePrefixTlv parses a Prefix TLV.
// Format: [domainID(1), prefixLenBits(1), prefix(ceil(prefixLenBits/8)),
//
//	sub-TLVs...]
func (t *Tracker) parsePrefixTlv(data []byte) {
	if len(data) < 2 {
		return
	}

	// domainID := data[0] // not used currently
	prefixLenBits := data[1]
	prefixBytes := int((prefixLenBits + 7) / 8)

	if len(data) < 2+prefixBytes {
		return
	}

	var prefix [16]byte
	copy(prefix[:], data[2:2+prefixBytes])

	subTlvData := data[2+prefixBytes:]
	t.parseSubTlvs(prefix, prefixLenBits, subTlvData)
}

// parseSubTlvs parses the sub-TLVs within a Prefix TLV.
func (t *Tracker) parseSubTlvs(prefix [16]byte, prefixLen uint8, data []byte) {
	offset := 0
	for offset+2 <= len(data) {
		subType := data[offset]
		subLen := int(data[offset+1])
		offset += 2

		if offset+subLen > len(data) {
			break
		}

		subValue := data[offset : offset+subLen]
		offset += subLen

		switch subType {
		case tlvTypeBorderRouter:
			t.parseBorderRouterSubTlv(prefix, prefixLen, subValue)
		case tlvTypeHasRoute:
			t.parseHasRouteSubTlv(prefix, prefixLen, subValue)
		}
	}
}

// parseBorderRouterSubTlv parses a Border Router sub-TLV.
// Each entry is 4 bytes: [RLOC16(2), flags(2)]
// Flags bits: P(bit15), S(bit14), D(bit13), C(bit12), R(bit11), O(bit10),
//
//	N(bit9), Dp(bit8), Pref(bits7-6), ...
func (t *Tracker) parseBorderRouterSubTlv(prefix [16]byte, prefixLen uint8, data []byte) {
	for i := 0; i+4 <= len(data); i += 4 {
		rloc16 := uint16(data[i])<<8 | uint16(data[i+1])
		flags := uint16(data[i+2])<<8 | uint16(data[i+3])

		// On-link flag is bit 10 (counting from MSB=bit 15).
		isOnLink := (flags & 0x0020) != 0 // bit 5 from LSB = O flag

		// Preference is bits 7-6 (2-bit field).
		pref := uint8((flags >> 6) & 0x03)

		t.prefixes = append(t.prefixes, PrefixEntry{
			Prefix:       prefix,
			PrefixLength: prefixLen,
			Preference:   pref,
			IsOnLink:     isOnLink,
			Rloc16:       rloc16,
		})

		t.addBorderRouter(rloc16)
	}
}

// parseHasRouteSubTlv parses a Has Route sub-TLV.
// Each entry is 3 bytes: [RLOC16(2), flags(1)]
// Flags: preference in bits 7-6.
func (t *Tracker) parseHasRouteSubTlv(prefix [16]byte, prefixLen uint8, data []byte) {
	for i := 0; i+3 <= len(data); i += 3 {
		rloc16 := uint16(data[i])<<8 | uint16(data[i+1])
		flags := data[i+2]
		pref := (flags >> 6) & 0x03

		t.prefixes = append(t.prefixes, PrefixEntry{
			Prefix:       prefix,
			PrefixLength: prefixLen,
			Preference:   pref,
			IsOnLink:     false,
			Rloc16:       rloc16,
		})

		t.addBorderRouter(rloc16)
	}
}

func (t *Tracker) addBorderRouter(rloc16 uint16) {
	routerID := rloc16 >> 10

	for i := range t.borderRouters {
		if t.borderRouters[i].RouterID == routerID {
			return
		}
	}

	t.borderRouters = append(t.borderRouters, BorderRouterEntry{
		RouterID: routerID,
		Rloc16:   rloc16,
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// matchPrefix compares two prefixes up to the given number of bits.
func matchPrefix(a, b [16]byte, bits uint8) bool {
	fullBytes := bits / 8
	for i := uint8(0); i < fullBytes && i < 16; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	remainBits := bits % 8
	if remainBits > 0 && fullBytes < 16 {
		mask := byte(0xFF << (8 - remainBits))
		if (a[fullBytes] & mask) != (b[fullBytes] & mask) {
			return false
		}
	}
	return true
}

// isBetterOmr returns true if candidate is a better OMR prefix than current.
func isBetterOmr(candidate, current PrefixEntry) bool {
	cr := prefRank(candidate.Preference)
	or := prefRank(current.Preference)

	if cr != or {
		return cr > or
	}

	// Tiebreak: lexicographically smaller prefix wins.
	for i := 0; i < 16; i++ {
		if candidate.Prefix[i] < current.Prefix[i] {
			return true
		}
		if candidate.Prefix[i] > current.Prefix[i] {
			return false
		}
	}
	return false
}

// prefRank maps the 2-bit route preference to a comparable rank.
func prefRank(pref uint8) int {
	switch pref {
	case prefHigh:
		return 2
	case prefMedium:
		return 1
	case prefLow:
		return 0
	default:
		return 1
	}
}
