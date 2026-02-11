// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package srcmatch provides a standalone source address match table
// controller for managing short and extended address entries.
//
// This is a simplified Go port of the source match controller defined
// in OpenThread's src/core/thread/src_match_controller.hpp, designed
// to work without a radio dependency.
package srcmatch

import "github.com/hilli/gothread/errors"

// MaxShortEntries is the maximum number of short address entries.
const MaxShortEntries = 64

// MaxExtEntries is the maximum number of extended address entries.
const MaxExtEntries = 64

// Controller manages short and extended source address match entries.
type Controller struct {
	shortAddrs   [MaxShortEntries]uint16
	shortCount   int
	extAddrs     [MaxExtEntries][8]byte
	extCount     int
	enabled      bool
	framePending bool
}

// Enable enables the source match controller.
func (c *Controller) Enable() {
	c.enabled = true
}

// Disable disables the source match controller.
func (c *Controller) Disable() {
	c.enabled = false
}

// IsEnabled reports whether the controller is enabled.
func (c *Controller) IsEnabled() bool {
	return c.enabled
}

// SetFramePending sets the frame-pending flag.
func (c *Controller) SetFramePending(enable bool) {
	c.framePending = enable
}

// GetFramePending returns the current frame-pending flag.
func (c *Controller) GetFramePending() bool {
	return c.framePending
}

// AddShortEntry adds a short address entry to the table.
// Returns ErrNoBufs if the table is full, ErrAlready if already present.
func (c *Controller) AddShortEntry(addr uint16) error {
	if c.HasShortEntry(addr) {
		return errors.ErrAlready
	}
	if c.shortCount >= MaxShortEntries {
		return errors.ErrNoBufs
	}
	c.shortAddrs[c.shortCount] = addr
	c.shortCount++
	return nil
}

// AddExtEntry adds an extended address entry to the table.
// Returns ErrNoBufs if the table is full, ErrAlready if already present.
func (c *Controller) AddExtEntry(addr [8]byte) error {
	if c.HasExtEntry(addr) {
		return errors.ErrAlready
	}
	if c.extCount >= MaxExtEntries {
		return errors.ErrNoBufs
	}
	c.extAddrs[c.extCount] = addr
	c.extCount++
	return nil
}

// ClearShortEntry removes a short address entry from the table.
func (c *Controller) ClearShortEntry(addr uint16) {
	for i := 0; i < c.shortCount; i++ {
		if c.shortAddrs[i] == addr {
			c.shortAddrs[i] = c.shortAddrs[c.shortCount-1]
			c.shortCount--
			return
		}
	}
}

// ClearExtEntry removes an extended address entry from the table.
func (c *Controller) ClearExtEntry(addr [8]byte) {
	for i := 0; i < c.extCount; i++ {
		if c.extAddrs[i] == addr {
			c.extAddrs[i] = c.extAddrs[c.extCount-1]
			c.extCount--
			return
		}
	}
}

// ClearTable removes all entries from the table.
func (c *Controller) ClearTable() {
	c.shortCount = 0
	c.extCount = 0
}

// GetShortEntryCount returns the number of short address entries.
func (c *Controller) GetShortEntryCount() int {
	return c.shortCount
}

// GetExtEntryCount returns the number of extended address entries.
func (c *Controller) GetExtEntryCount() int {
	return c.extCount
}

// HasShortEntry reports whether the given short address is in the table.
func (c *Controller) HasShortEntry(addr uint16) bool {
	for i := 0; i < c.shortCount; i++ {
		if c.shortAddrs[i] == addr {
			return true
		}
	}
	return false
}

// HasExtEntry reports whether the given extended address is in the table.
func (c *Controller) HasExtEntry(addr [8]byte) bool {
	for i := 0; i < c.extCount; i++ {
		if c.extAddrs[i] == addr {
			return true
		}
	}
	return false
}
