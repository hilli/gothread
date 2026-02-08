// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

// ParentCandidate holds the data collected from a Parent Response that is
// used during parent selection to compare candidates.
//
// This mirrors the relevant fields stored in OpenThread's mParentCandidate.
type ParentCandidate struct {
	// Parent is the underlying Parent entry (Neighbor/Router embedded).
	Parent

	// Connectivity holds the Connectivity TLV from the Parent Response.
	Connectivity ConnectivityTLV

	// LinkMargin is the two-way link margin in dB.
	LinkMargin uint8

	// ThreadVersion is the Thread protocol version advertised by the parent.
	ThreadVersion uint16

	// RxChallenge is the challenge received from the parent, to be
	// echoed back in the Child ID Request.
	RxChallenge Challenge
}

// IsBetterParent reports whether candidate is strictly better than current
// as a parent.
//
// The comparison follows the priority ordering defined in the Thread
// Specification (Section 4.5.2.1):
//
//  1. Two-way link quality (quantised from link margin)
//  2. Is router (vs. REED)
//  3. Parent priority (from Connectivity TLV flags)
//  4. Number of link quality 3 neighbours
//  5. Thread version
//  6. SED buffer size
//  7. SED datagram count
//  8. Number of link quality 2 neighbours
//  9. Number of link quality 1 neighbours
//  10. Raw two-way link margin (tiebreaker)
//
// This is a Go port of OpenThread's Mle::IsBetterParent().
func IsBetterParent(
	candidateLinkMargin uint8,
	candidateRLOC16 uint16,
	candidateConnectivity ConnectivityTLV,
	candidateVersion uint16,
	currentLinkQuality uint8,
	currentRLOC16 uint16,
	currentConnectivity ConnectivityTLV,
	currentVersion uint16,
	currentLinkMargin uint8,
) bool {
	// 1. Two-way link quality (quantised).
	candidateLQ := LinkQualityForLinkMargin(candidateLinkMargin)
	if cmp := threeWayCompare(candidateLQ, currentLinkQuality); cmp != 0 {
		return cmp > 0
	}

	// 2. Router vs REED — routers are preferred.
	candidateIsRouter := boolToUint8(IsRouterRLOC16(candidateRLOC16))
	currentIsRouter := boolToUint8(IsRouterRLOC16(currentRLOC16))
	if cmp := threeWayCompare(candidateIsRouter, currentIsRouter); cmp != 0 {
		return cmp > 0
	}

	// 3. Parent priority.
	candidatePriority := parentPriority(candidateConnectivity.Flags)
	currentPriority := parentPriority(currentConnectivity.Flags)
	if cmp := threeWayCompareSigned(candidatePriority, currentPriority); cmp != 0 {
		return cmp > 0
	}

	// 4. Number of LQ3 neighbours.
	if cmp := threeWayCompare(candidateConnectivity.LinkQuality3, currentConnectivity.LinkQuality3); cmp != 0 {
		return cmp > 0
	}

	// 5. Thread version.
	if cmp := threeWayCompare16(candidateVersion, currentVersion); cmp != 0 {
		return cmp > 0
	}

	// 6. SED buffer size.
	if cmp := threeWayCompare16(candidateConnectivity.SEDBufferSize, currentConnectivity.SEDBufferSize); cmp != 0 {
		return cmp > 0
	}

	// 7. SED datagram count.
	if cmp := threeWayCompare(candidateConnectivity.SEDDatagramCount, currentConnectivity.SEDDatagramCount); cmp != 0 {
		return cmp > 0
	}

	// 8. Number of LQ2 neighbours.
	if cmp := threeWayCompare(candidateConnectivity.LinkQuality2, currentConnectivity.LinkQuality2); cmp != 0 {
		return cmp > 0
	}

	// 9. Number of LQ1 neighbours.
	if cmp := threeWayCompare(candidateConnectivity.LinkQuality1, currentConnectivity.LinkQuality1); cmp != 0 {
		return cmp > 0
	}

	// 10. Raw two-way link margin (final tiebreaker).
	return candidateLinkMargin > currentLinkMargin
}

// LinkQualityForLinkMargin converts a link margin in dB to a quantised
// link quality value (0–3).
//
// The thresholds match OpenThread's LinkQualityForLinkMargin:
//
//	LQ 3: margin >= 20 dB
//	LQ 2: margin >= 10 dB
//	LQ 1: margin >= 2 dB
//	LQ 0: margin < 2 dB
func LinkQualityForLinkMargin(margin uint8) uint8 {
	switch {
	case margin >= 20:
		return 3
	case margin >= 10:
		return 2
	case margin >= 2:
		return 1
	default:
		return 0
	}
}

// parentPriority extracts the parent priority from Connectivity TLV flags
// and returns it as a signed value in the range [-2, 1].
//
// The priority is encoded in the top 2 bits (bits 7:6) of the flags byte
// as a two's-complement 2-bit signed integer:
//
//	0b01 = +1 (highest)
//	0b00 =  0 (medium, default)
//	0b11 = -1
//	0b10 = -2 (lowest)
func parentPriority(flags uint8) int8 {
	raw := (flags & ConnectivityFlagParentPriority) >> 6
	// Interpret 2-bit two's complement.
	if raw&0x02 != 0 {
		return int8(raw) - 4 // 0b10 -> -2, 0b11 -> -1
	}
	return int8(raw) // 0b00 -> 0, 0b01 -> 1
}

// --- comparison helpers ---

// threeWayCompare returns +1 if a > b, -1 if a < b, 0 if equal.
func threeWayCompare(a, b uint8) int {
	switch {
	case a > b:
		return 1
	case a < b:
		return -1
	default:
		return 0
	}
}

// threeWayCompare16 returns +1 if a > b, -1 if a < b, 0 if equal.
func threeWayCompare16(a, b uint16) int {
	switch {
	case a > b:
		return 1
	case a < b:
		return -1
	default:
		return 0
	}
}

// threeWayCompareSigned returns +1 if a > b, -1 if a < b, 0 if equal.
func threeWayCompareSigned(a, b int8) int {
	switch {
	case a > b:
		return 1
	case a < b:
		return -1
	default:
		return 0
	}
}

// boolToUint8 converts a bool to 1 or 0.
func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
