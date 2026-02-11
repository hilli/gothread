// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"testing"
	"time"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Neighbor accessor tests
// ---------------------------------------------------------------------------

func TestNeighbor_GetSetRloc16(t *testing.T) {
	t.Parallel()

	var n Neighbor
	n.SetRloc16(0x0400)
	if got := n.GetRloc16(); got != 0x0400 {
		t.Errorf("GetRloc16() = 0x%04X, want 0x0400", got)
	}
}

func TestNeighbor_GetSetExtAddress(t *testing.T) {
	t.Parallel()

	var n Neighbor
	addr := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44}
	n.SetExtAddress(addr)
	if got := n.GetExtAddress(); got != addr {
		t.Errorf("GetExtAddress() = %v, want %v", got, addr)
	}
}

func TestNeighbor_GetSetState(t *testing.T) {
	t.Parallel()

	var n Neighbor
	n.SetState(StateValid)
	if got := n.GetState(); got != StateValid {
		t.Errorf("GetState() = %v, want %v", got, StateValid)
	}
}

func TestNeighbor_FrameCounters(t *testing.T) {
	t.Parallel()

	var n Neighbor
	n.Counters.LinkFrameCounter = 42
	n.Counters.MleFrameCounter = 99

	if got := n.GetLinkFrameCounters(); got != 42 {
		t.Errorf("GetLinkFrameCounters() = %d, want 42", got)
	}
	if got := n.GetMleFrameCounters(); got != 99 {
		t.Errorf("GetMleFrameCounters() = %d, want 99", got)
	}
}

func TestNeighbor_AgeAndLastHeard(t *testing.T) {
	t.Parallel()

	var n Neighbor

	// Zero time gives zero age.
	if got := n.GetAge(); got != 0 {
		t.Errorf("GetAge() on zero LastHeard = %v, want 0", got)
	}

	n.ResetAge()
	if n.GetLastHeard().IsZero() {
		t.Error("GetLastHeard should not be zero after ResetAge")
	}

	// Age should be very small (< 1 second).
	if got := n.GetAge(); got > time.Second {
		t.Errorf("GetAge() = %v, expected < 1s", got)
	}
}

func TestNeighbor_SetLinkQualityIn(t *testing.T) {
	t.Parallel()

	var n Neighbor
	// Default quality should be 0.
	if got := n.GetLinkQualityIn(); got != 0 {
		t.Errorf("initial GetLinkQualityIn() = %d, want 0", got)
	}
	// Set to quality 3.
	n.SetLinkQualityIn(3)
	if got := n.GetLinkQualityIn(); got != 3 {
		t.Errorf("GetLinkQualityIn() = %d, want 3", got)
	}
	// Set to quality 1.
	n.SetLinkQualityIn(1)
	if got := n.GetLinkQualityIn(); got != 1 {
		t.Errorf("GetLinkQualityIn() = %d, want 1", got)
	}
	// Out-of-range should clamp to 3.
	n.SetLinkQualityIn(255)
	if got := n.GetLinkQualityIn(); got != 3 {
		t.Errorf("GetLinkQualityIn() after 255 = %d, want 3 (clamped)", got)
	}
}

// ---------------------------------------------------------------------------
// Child accessor tests
// ---------------------------------------------------------------------------

func TestChild_GetSetNetworkDataVersion(t *testing.T) {
	t.Parallel()

	var c Child
	c.SetNetworkDataVersion(42)
	if got := c.GetNetworkDataVersion(); got != 42 {
		t.Errorf("GetNetworkDataVersion() = %d, want 42", got)
	}
}

func TestChild_RemoveIP6Address(t *testing.T) {
	t.Parallel()

	var c Child
	addr1 := ip6.Address{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	addr2 := ip6.Address{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	addr3 := ip6.Address{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}

	c.AddIP6Address(addr1)
	c.AddIP6Address(addr2)
	c.AddIP6Address(addr3)

	tests := []struct {
		name       string
		addr       ip6.Address
		wantResult bool
		wantCount  uint8
	}{
		{"remove middle", addr2, true, 2},
		{"remove non-existent", addr2, false, 2},
		{"remove first", addr1, true, 1},
		{"remove last", addr3, true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := c.RemoveIP6Address(tt.addr); got != tt.wantResult {
				t.Errorf("RemoveIP6Address() = %v, want %v", got, tt.wantResult)
			}
			if c.IP6AddressCount != tt.wantCount {
				t.Errorf("IP6AddressCount = %d, want %d", c.IP6AddressCount, tt.wantCount)
			}
		})
	}
}

func TestChild_GetSetTimeout(t *testing.T) {
	t.Parallel()

	var c Child
	c.SetTimeout(240)
	if got := c.GetTimeout(); got != 240 {
		t.Errorf("GetTimeout() = %d, want 240", got)
	}
}

func TestChild_CSLPeriodAndPhase(t *testing.T) {
	t.Parallel()

	var c Child
	c.SetCSLPeriod(100)
	c.SetCSLPhase(200)

	if got := c.GetCSLPeriod(); got != 100 {
		t.Errorf("GetCSLPeriod() = %d, want 100", got)
	}
	if got := c.GetCSLPhase(); got != 200 {
		t.Errorf("GetCSLPhase() = %d, want 200", got)
	}
}

// ---------------------------------------------------------------------------
// ChildTable accessor tests
// ---------------------------------------------------------------------------

func TestChildTable_GetMaxChildren(t *testing.T) {
	t.Parallel()

	ct := NewChildTable()
	if got := ct.GetMaxChildren(); got != MaxChildren {
		t.Errorf("GetMaxChildren() = %d, want %d", got, MaxChildren)
	}
}

func TestChildTable_GetChildAtIndex(t *testing.T) {
	t.Parallel()

	ct := NewChildTable()

	tests := []struct {
		name  string
		index int
		isNil bool
	}{
		{"valid 0", 0, false},
		{"valid last", MaxChildren - 1, false},
		{"negative", -1, true},
		{"too large", MaxChildren, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ct.GetChildAtIndex(tt.index)
			if (got == nil) != tt.isNil {
				t.Errorf("GetChildAtIndex(%d) nil = %v, want %v", tt.index, got == nil, tt.isNil)
			}
		})
	}
}

func TestChildTable_GetNumChildren(t *testing.T) {
	t.Parallel()

	ct := NewChildTable()

	c1 := ct.GetNewChild()
	c1.State = StateValid

	c2 := ct.GetNewChild()
	c2.State = StateParentRequest

	c3 := ct.GetNewChild()
	c3.State = StateValid

	tests := []struct {
		name   string
		filter NeighborState
		want   int
	}{
		{"all non-invalid", StateInvalid, 3},
		{"valid only", StateValid, 2},
		{"parent request", StateParentRequest, 1},
		{"link request", StateLinkRequest, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ct.GetNumChildren(tt.filter); got != tt.want {
				t.Errorf("GetNumChildren(%v) = %d, want %d", tt.filter, got, tt.want)
			}
		})
	}
}

func TestChildTable_HasChildrenWithState(t *testing.T) {
	t.Parallel()

	ct := NewChildTable()

	c := ct.GetNewChild()
	c.State = StateValid

	tests := []struct {
		name   string
		filter NeighborState
		want   bool
	}{
		{"has valid", StateValid, true},
		{"has non-invalid", StateInvalid, true},
		{"no parent request", StateParentRequest, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ct.HasChildrenWithState(tt.filter); got != tt.want {
				t.Errorf("HasChildrenWithState(%v) = %v, want %v", tt.filter, got, tt.want)
			}
		})
	}
}

func TestChildTable_FreeChild(t *testing.T) {
	t.Parallel()

	ct := NewChildTable()

	c := ct.GetNewChild()
	c.State = StateValid
	c.MacAddr = types.ExtAddress{0x01}

	ct.FreeChild(c)
	if c.State != StateInvalid {
		t.Errorf("State after FreeChild = %v, want StateInvalid", c.State)
	}
	if ct.HasChildren() {
		t.Error("table should have no active children after FreeChild")
	}
}

// ---------------------------------------------------------------------------
// NeighborTable accessor tests
// ---------------------------------------------------------------------------

func TestNeighborTable_GetNeighborCount(t *testing.T) {
	t.Parallel()

	nt := NewNeighborTable()

	// Add 2 children.
	c1 := nt.GetNewChild()
	c1.State = StateValid
	c2 := nt.GetNewChild()
	c2.State = StateValid

	// Add 1 router.
	r := nt.AllocateRouter(5)
	r.State = StateValid

	if got := nt.GetNeighborCount(); got != 3 {
		t.Errorf("GetNeighborCount() = %d, want 3", got)
	}
}
