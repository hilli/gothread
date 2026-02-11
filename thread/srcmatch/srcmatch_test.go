// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package srcmatch

import (
	"testing"

	"github.com/hilli/gothread/errors"
)

func TestController_EnableDisable(t *testing.T) {
	t.Parallel()

	var c Controller

	if c.IsEnabled() {
		t.Error("new Controller should be disabled")
	}

	c.Enable()
	if !c.IsEnabled() {
		t.Error("Controller should be enabled after Enable()")
	}

	c.Disable()
	if c.IsEnabled() {
		t.Error("Controller should be disabled after Disable()")
	}
}

func TestController_FramePending(t *testing.T) {
	t.Parallel()

	var c Controller

	if c.GetFramePending() {
		t.Error("new Controller should have frame pending false")
	}

	c.SetFramePending(true)
	if !c.GetFramePending() {
		t.Error("GetFramePending should be true")
	}

	c.SetFramePending(false)
	if c.GetFramePending() {
		t.Error("GetFramePending should be false")
	}
}

func TestController_ShortEntries(t *testing.T) {
	t.Parallel()

	var c Controller

	if err := c.AddShortEntry(0x0401); err != nil {
		t.Fatalf("AddShortEntry(0x0401) error: %v", err)
	}
	if err := c.AddShortEntry(0x0402); err != nil {
		t.Fatalf("AddShortEntry(0x0402) error: %v", err)
	}

	if c.GetShortEntryCount() != 2 {
		t.Errorf("GetShortEntryCount() = %d, want 2", c.GetShortEntryCount())
	}
	if !c.HasShortEntry(0x0401) {
		t.Error("HasShortEntry(0x0401) should be true")
	}
	if !c.HasShortEntry(0x0402) {
		t.Error("HasShortEntry(0x0402) should be true")
	}

	// Duplicate.
	if err := c.AddShortEntry(0x0401); err != errors.ErrAlready {
		t.Errorf("duplicate AddShortEntry error = %v, want ErrAlready", err)
	}

	// Clear one.
	c.ClearShortEntry(0x0401)
	if c.HasShortEntry(0x0401) {
		t.Error("HasShortEntry(0x0401) should be false after clear")
	}
	if c.GetShortEntryCount() != 1 {
		t.Errorf("GetShortEntryCount() = %d, want 1", c.GetShortEntryCount())
	}

	// Clear non-existent (no-op).
	c.ClearShortEntry(0x9999)
	if c.GetShortEntryCount() != 1 {
		t.Errorf("GetShortEntryCount() = %d, want 1 after clearing non-existent", c.GetShortEntryCount())
	}
}

func TestController_ExtEntries(t *testing.T) {
	t.Parallel()

	var c Controller
	addr1 := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	addr2 := [8]byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}

	if err := c.AddExtEntry(addr1); err != nil {
		t.Fatalf("AddExtEntry(addr1) error: %v", err)
	}
	if err := c.AddExtEntry(addr2); err != nil {
		t.Fatalf("AddExtEntry(addr2) error: %v", err)
	}

	if c.GetExtEntryCount() != 2 {
		t.Errorf("GetExtEntryCount() = %d, want 2", c.GetExtEntryCount())
	}
	if !c.HasExtEntry(addr1) {
		t.Error("HasExtEntry(addr1) should be true")
	}

	// Duplicate.
	if err := c.AddExtEntry(addr1); err != errors.ErrAlready {
		t.Errorf("duplicate AddExtEntry error = %v, want ErrAlready", err)
	}

	// Clear.
	c.ClearExtEntry(addr1)
	if c.HasExtEntry(addr1) {
		t.Error("HasExtEntry(addr1) should be false after clear")
	}
	if c.GetExtEntryCount() != 1 {
		t.Errorf("GetExtEntryCount() = %d, want 1", c.GetExtEntryCount())
	}
}

func TestController_ClearTable(t *testing.T) {
	t.Parallel()

	var c Controller

	for i := 0; i < 5; i++ {
		_ = c.AddShortEntry(uint16(i + 1))
	}
	_ = c.AddExtEntry([8]byte{0x01})
	_ = c.AddExtEntry([8]byte{0x02})

	c.ClearTable()

	if c.GetShortEntryCount() != 0 {
		t.Errorf("GetShortEntryCount() = %d after ClearTable, want 0", c.GetShortEntryCount())
	}
	if c.GetExtEntryCount() != 0 {
		t.Errorf("GetExtEntryCount() = %d after ClearTable, want 0", c.GetExtEntryCount())
	}
}

func TestController_ShortEntries_Full(t *testing.T) {
	t.Parallel()

	var c Controller
	for i := 0; i < MaxShortEntries; i++ {
		if err := c.AddShortEntry(uint16(i + 1)); err != nil {
			t.Fatalf("AddShortEntry(%d) error: %v", i+1, err)
		}
	}

	if err := c.AddShortEntry(0xFFFF); err != errors.ErrNoBufs {
		t.Errorf("overflow AddShortEntry error = %v, want ErrNoBufs", err)
	}
}

func TestController_ExtEntries_Full(t *testing.T) {
	t.Parallel()

	var c Controller
	for i := 0; i < MaxExtEntries; i++ {
		addr := [8]byte{byte(i), byte(i >> 8)}
		if err := c.AddExtEntry(addr); err != nil {
			t.Fatalf("AddExtEntry(%d) error: %v", i, err)
		}
	}

	overflow := [8]byte{0xFF, 0xFF}
	if err := c.AddExtEntry(overflow); err != errors.ErrNoBufs {
		t.Errorf("overflow AddExtEntry error = %v, want ErrNoBufs", err)
	}
}
