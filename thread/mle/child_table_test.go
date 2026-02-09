// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"testing"

	"github.com/hilli/gothread/mac/types"
)

func TestNewChildTable(t *testing.T) {
	t.Parallel()

	ct := NewChildTable()
	if ct == nil {
		t.Fatal("NewChildTable returned nil")
	}
	if ct.HasChildren() {
		t.Error("new child table should have no children")
	}
	if ct.GetChildCount() != 0 {
		t.Errorf("GetChildCount = %d, want 0", ct.GetChildCount())
	}
}

func TestChildTable_FindChild(t *testing.T) {
	t.Parallel()

	ct := NewChildTable()
	addr1 := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	addr2 := types.ExtAddress{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}

	// Not found in empty table.
	if ct.FindChild(addr1) != nil {
		t.Error("expected nil for empty table")
	}

	// Add a child.
	c := ct.GetNewChild()
	if c == nil {
		t.Fatal("GetNewChild returned nil on empty table")
	}
	c.MacAddr = addr1
	c.State = StateValid

	// Find by address.
	found := ct.FindChild(addr1)
	if found == nil {
		t.Fatal("FindChild returned nil for known address")
	}
	if found.MacAddr != addr1 {
		t.Errorf("found MacAddr = %v, want %v", found.MacAddr, addr1)
	}

	// Not found for different address.
	if ct.FindChild(addr2) != nil {
		t.Error("expected nil for unknown address")
	}
}

func TestChildTable_FindChildByRLOC16(t *testing.T) {
	t.Parallel()

	ct := NewChildTable()
	c := ct.GetNewChild()
	c.State = StateValid
	c.RLOC16 = 0x0401

	found := ct.FindChildByRLOC16(0x0401)
	if found == nil {
		t.Fatal("FindChildByRLOC16 returned nil for known RLOC16")
	}
	if found.RLOC16 != 0x0401 {
		t.Errorf("found RLOC16 = 0x%04X, want 0x0401", found.RLOC16)
	}

	if ct.FindChildByRLOC16(0x0402) != nil {
		t.Error("expected nil for unknown RLOC16")
	}
}

func TestChildTable_GetNewChild_Full(t *testing.T) {
	t.Parallel()

	ct := NewChildTable()

	// Fill all slots.
	for i := 0; i < MaxChildren; i++ {
		c := ct.GetNewChild()
		if c == nil {
			t.Fatalf("GetNewChild returned nil at index %d", i)
		}
		c.State = StateValid
		c.MacAddr = types.ExtAddress{byte(i)}
	}

	// Table full.
	if ct.GetNewChild() != nil {
		t.Error("expected nil when table is full")
	}

	if ct.GetChildCount() != MaxChildren {
		t.Errorf("GetChildCount = %d, want %d", ct.GetChildCount(), MaxChildren)
	}
}

func TestChildTable_GetNewChild_ReusesInvalidSlot(t *testing.T) {
	t.Parallel()

	ct := NewChildTable()

	// Fill all slots.
	for i := 0; i < MaxChildren; i++ {
		c := ct.GetNewChild()
		c.State = StateValid
		c.MacAddr = types.ExtAddress{byte(i)}
	}

	// Invalidate one slot.
	child := ct.FindChild(types.ExtAddress{0x03})
	if child == nil {
		t.Fatal("child 0x03 not found")
	}
	child.State = StateInvalid

	// Should get a new child now.
	newChild := ct.GetNewChild()
	if newChild == nil {
		t.Fatal("expected to reuse invalidated slot")
	}
}

func TestChildTable_Counts(t *testing.T) {
	t.Parallel()

	ct := NewChildTable()

	// Add 3 children: 2 valid, 1 in parent request state.
	c1 := ct.GetNewChild()
	c1.State = StateValid
	c1.MacAddr = types.ExtAddress{0x01}

	c2 := ct.GetNewChild()
	c2.State = StateValid
	c2.MacAddr = types.ExtAddress{0x02}

	c3 := ct.GetNewChild()
	c3.State = StateParentRequest
	c3.MacAddr = types.ExtAddress{0x03}

	if ct.GetChildCount() != 3 {
		t.Errorf("GetChildCount = %d, want 3", ct.GetChildCount())
	}
	if ct.GetValidChildCount() != 2 {
		t.Errorf("GetValidChildCount = %d, want 2", ct.GetValidChildCount())
	}
}

func TestChildTable_ForEach(t *testing.T) {
	t.Parallel()

	ct := NewChildTable()

	c1 := ct.GetNewChild()
	c1.State = StateValid
	c1.MacAddr = types.ExtAddress{0x01}

	c2 := ct.GetNewChild()
	c2.State = StateParentRequest
	c2.MacAddr = types.ExtAddress{0x02}

	// ForEach iterates non-invalid entries.
	count := 0
	ct.ForEach(func(_ *Child) bool {
		count++
		return true
	})
	if count != 2 {
		t.Errorf("ForEach visited %d children, want 2", count)
	}

	// ForEach with early stop.
	count = 0
	ct.ForEach(func(_ *Child) bool {
		count++
		return false // stop after first
	})
	if count != 1 {
		t.Errorf("ForEach with early stop visited %d children, want 1", count)
	}
}

func TestChildTable_ForEachValid(t *testing.T) {
	t.Parallel()

	ct := NewChildTable()

	c1 := ct.GetNewChild()
	c1.State = StateValid
	c1.MacAddr = types.ExtAddress{0x01}

	c2 := ct.GetNewChild()
	c2.State = StateParentRequest
	c2.MacAddr = types.ExtAddress{0x02}

	c3 := ct.GetNewChild()
	c3.State = StateValid
	c3.MacAddr = types.ExtAddress{0x03}

	count := 0
	ct.ForEachValid(func(_ *Child) bool {
		count++
		return true
	})
	if count != 2 {
		t.Errorf("ForEachValid visited %d children, want 2", count)
	}
}

func TestChildTable_Clear(t *testing.T) {
	t.Parallel()

	ct := NewChildTable()

	for i := 0; i < 5; i++ {
		c := ct.GetNewChild()
		c.State = StateValid
		c.MacAddr = types.ExtAddress{byte(i)}
	}

	if ct.GetChildCount() != 5 {
		t.Fatalf("GetChildCount = %d, want 5", ct.GetChildCount())
	}

	ct.Clear()

	if ct.HasChildren() {
		t.Error("HasChildren should be false after Clear")
	}
	if ct.GetChildCount() != 0 {
		t.Errorf("GetChildCount = %d, want 0 after Clear", ct.GetChildCount())
	}
}

func TestChildTable_GetChildren(t *testing.T) {
	t.Parallel()

	ct := NewChildTable()

	c1 := ct.GetNewChild()
	c1.State = StateValid
	c1.MacAddr = types.ExtAddress{0x01}

	c2 := ct.GetNewChild()
	c2.State = StateParentRequest
	c2.MacAddr = types.ExtAddress{0x02}

	children := ct.GetChildren()
	if len(children) != 2 {
		t.Fatalf("GetChildren returned %d entries, want 2", len(children))
	}

	// Verify returned pointers reference internal entries.
	children[0].Timeout = 999
	found := ct.FindChild(children[0].MacAddr)
	if found.Timeout != 999 {
		t.Error("GetChildren returned copies instead of references")
	}
}

func TestChildTable_HasChildren(t *testing.T) {
	t.Parallel()

	ct := NewChildTable()

	if ct.HasChildren() {
		t.Error("empty table should not have children")
	}

	c := ct.GetNewChild()
	c.State = StateValid

	if !ct.HasChildren() {
		t.Error("table with one valid child should have children")
	}
}

func TestChildTable_FindChild_SkipsInvalid(t *testing.T) {
	t.Parallel()

	ct := NewChildTable()
	addr := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Add child then invalidate it.
	c := ct.GetNewChild()
	c.MacAddr = addr
	c.State = StateValid

	c.State = StateInvalid

	// Should not find invalidated child.
	if ct.FindChild(addr) != nil {
		t.Error("FindChild should skip invalid entries")
	}
}
