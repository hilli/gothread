// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import "testing"

func TestLinkQualityForLinkMargin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		margin uint8
		want   uint8
	}{
		{0, 0},
		{1, 0},
		{2, 1},
		{9, 1},
		{10, 2},
		{19, 2},
		{20, 3},
		{50, 3},
		{255, 3},
	}

	for _, tt := range tests {
		got := LinkQualityForLinkMargin(tt.margin)
		if got != tt.want {
			t.Errorf("LinkQualityForLinkMargin(%d) = %d, want %d", tt.margin, got, tt.want)
		}
	}
}

func TestParentPriority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		flags uint8
		want  int8
	}{
		{0x00, 0},  // 0b00 -> 0
		{0x40, 1},  // 0b01 -> +1
		{0x80, -2}, // 0b10 -> -2
		{0xC0, -1}, // 0b11 -> -1
	}

	for _, tt := range tests {
		got := parentPriority(tt.flags)
		if got != tt.want {
			t.Errorf("parentPriority(0x%02X) = %d, want %d", tt.flags, got, tt.want)
		}
	}
}

func TestIsBetterParent_HigherLinkQualityWins(t *testing.T) {
	t.Parallel()

	conn := ConnectivityTLV{}

	// Candidate has LQ3 (margin 20), current has LQ2 (margin 10).
	got := IsBetterParent(20, 0x0400, conn, 4, 2, 0x0400, conn, 4, 10)
	if !got {
		t.Error("candidate with higher link quality should win")
	}

	// Reverse: current has higher link quality.
	got = IsBetterParent(10, 0x0400, conn, 4, 3, 0x0400, conn, 4, 20)
	if got {
		t.Error("candidate with lower link quality should lose")
	}
}

func TestIsBetterParent_RouterPreferredOverREED(t *testing.T) {
	t.Parallel()

	conn := ConnectivityTLV{}

	// Both have same link quality (margin 20 = LQ3).
	// Candidate is router (0x0400 = router ID 1, child ID 0), current is REED.
	routerRLOC := uint16(1 << RouterIDOffset) // Router RLOC16
	reedRLOC := uint16(1<<RouterIDOffset) | 1 // REED RLOC16 (child ID != 0)

	got := IsBetterParent(20, routerRLOC, conn, 4, 3, reedRLOC, conn, 4, 20)
	if !got {
		t.Error("router should be preferred over REED")
	}

	got = IsBetterParent(20, reedRLOC, conn, 4, 3, routerRLOC, conn, 4, 20)
	if got {
		t.Error("REED should lose to router")
	}
}

func TestIsBetterParent_HigherParentPriorityWins(t *testing.T) {
	t.Parallel()

	routerRLOC := uint16(1 << RouterIDOffset)

	connHigh := ConnectivityTLV{Flags: 0x40} // Priority +1
	connLow := ConnectivityTLV{Flags: 0x80}  // Priority -2

	got := IsBetterParent(20, routerRLOC, connHigh, 4, 3, routerRLOC, connLow, 4, 20)
	if !got {
		t.Error("higher parent priority should win")
	}

	got = IsBetterParent(20, routerRLOC, connLow, 4, 3, routerRLOC, connHigh, 4, 20)
	if got {
		t.Error("lower parent priority should lose")
	}
}

func TestIsBetterParent_MoreLQ3NeighboursWins(t *testing.T) {
	t.Parallel()

	routerRLOC := uint16(1 << RouterIDOffset)

	connMore := ConnectivityTLV{LinkQuality3: 5}
	connLess := ConnectivityTLV{LinkQuality3: 2}

	got := IsBetterParent(20, routerRLOC, connMore, 4, 3, routerRLOC, connLess, 4, 20)
	if !got {
		t.Error("more LQ3 neighbours should win")
	}
}

func TestIsBetterParent_HigherVersionWins(t *testing.T) {
	t.Parallel()

	routerRLOC := uint16(1 << RouterIDOffset)
	conn := ConnectivityTLV{}

	got := IsBetterParent(20, routerRLOC, conn, 5, 3, routerRLOC, conn, 4, 20)
	if !got {
		t.Error("higher version should win")
	}
}

func TestIsBetterParent_LargerSEDBufferWins(t *testing.T) {
	t.Parallel()

	routerRLOC := uint16(1 << RouterIDOffset)

	connBig := ConnectivityTLV{SEDBufferSize: 1000}
	connSmall := ConnectivityTLV{SEDBufferSize: 100}

	got := IsBetterParent(20, routerRLOC, connBig, 4, 3, routerRLOC, connSmall, 4, 20)
	if !got {
		t.Error("larger SED buffer should win")
	}
}

func TestIsBetterParent_RawLinkMarginTiebreaker(t *testing.T) {
	t.Parallel()

	routerRLOC := uint16(1 << RouterIDOffset)
	conn := ConnectivityTLV{}

	// Both have same LQ (margin 25 and 22 are both LQ3). Candidate has
	// higher raw margin.
	got := IsBetterParent(25, routerRLOC, conn, 4, 3, routerRLOC, conn, 4, 22)
	if !got {
		t.Error("higher raw link margin should win as tiebreaker")
	}

	// Equal raw margin: not strictly better.
	got = IsBetterParent(22, routerRLOC, conn, 4, 3, routerRLOC, conn, 4, 22)
	if got {
		t.Error("equal raw link margin should not be strictly better")
	}
}

func TestIsBetterParent_EqualCandidatesNotBetter(t *testing.T) {
	t.Parallel()

	routerRLOC := uint16(1 << RouterIDOffset)
	conn := ConnectivityTLV{
		LinkQuality3: 3,
		LinkQuality2: 2,
		LinkQuality1: 1,
	}

	// Completely equal candidates — should return false (not strictly better).
	got := IsBetterParent(20, routerRLOC, conn, 4, 3, routerRLOC, conn, 4, 20)
	if got {
		t.Error("equal candidates should not be strictly better")
	}
}

func TestThreeWayCompare(t *testing.T) {
	t.Parallel()

	tests := []struct {
		a, b uint8
		want int
	}{
		{5, 3, 1},
		{3, 5, -1},
		{5, 5, 0},
	}

	for _, tt := range tests {
		got := threeWayCompare(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("threeWayCompare(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestThreeWayCompare16(t *testing.T) {
	t.Parallel()

	tests := []struct {
		a, b uint16
		want int
	}{
		{500, 300, 1},
		{300, 500, -1},
		{500, 500, 0},
	}

	for _, tt := range tests {
		got := threeWayCompare16(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("threeWayCompare16(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestBoolToUint8(t *testing.T) {
	t.Parallel()

	if boolToUint8(true) != 1 {
		t.Error("boolToUint8(true) should be 1")
	}
	if boolToUint8(false) != 0 {
		t.Error("boolToUint8(false) should be 0")
	}
}
