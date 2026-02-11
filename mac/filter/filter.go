// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package filter implements MAC address filtering for IEEE 802.15.4 frames.
//
// This is a Go port of the filter in OpenThread's
// src/core/mac/mac_filter.hpp and src/core/mac/mac_filter.cpp.
//
// The filter supports allowlist and denylist modes. In allowlist mode only
// addresses present in the list are accepted. In denylist mode addresses
// present in the list are rejected. A per-address fixed RSS value can be
// configured, as well as a default RSS for unmatched addresses.
package filter

import (
	"github.com/hilli/gothread/errors"
)

// Mode represents the MAC filter operating mode.
type Mode uint8

const (
	// ModeDisabled means the filter is disabled (accept all frames).
	ModeDisabled Mode = iota
	// ModeAllowlist only accepts frames from listed addresses.
	ModeAllowlist
	// ModeDenylist rejects frames from listed addresses.
	ModeDenylist
)

// FixedRssDisabled is the sentinel value indicating no fixed RSS is set.
const FixedRssDisabled int8 = -128

// DefaultMaxEntries is the default maximum number of filter entries.
const DefaultMaxEntries = 16

// Entry is a filter entry for an extended address.
type Entry struct {
	ExtAddress [8]byte // IEEE 802.15.4 Extended Address
	RssIn      int8    // Fixed RSSI value for this address (FixedRssDisabled = not set)
	RssInSet   bool    // Whether RssIn is set
}

// filterEntry is the internal representation of a filter entry.
type filterEntry struct {
	filtered   bool    // whether this entry is in the address filter list
	rssIn      int8    // per-address fixed RSS (FixedRssDisabled = not set)
	extAddress [8]byte // IEEE 802.15.4 Extended Address
}

// isInUse reports whether the entry is in use (filtered or has RSS set).
func (e *filterEntry) isInUse() bool {
	return e.filtered || e.rssIn != FixedRssDisabled
}

// Option configures a Filter.
type Option func(*Filter)

// WithMaxEntries sets the maximum number of filter entries.
func WithMaxEntries(n int) Option {
	return func(f *Filter) {
		if n > 0 {
			f.maxEntries = n
		}
	}
}

// Filter manages MAC address filtering.
type Filter struct {
	mode          Mode
	entries       []filterEntry
	maxEntries    int
	defaultRss    int8
	defaultRssSet bool
}

// NewFilter creates a new Filter with the given options.
func NewFilter(opts ...Option) *Filter {
	f := &Filter{
		mode:       ModeDisabled,
		maxEntries: DefaultMaxEntries,
		defaultRss: FixedRssDisabled,
	}
	for _, opt := range opts {
		opt(f)
	}
	f.entries = make([]filterEntry, f.maxEntries)
	for i := range f.entries {
		f.entries[i].rssIn = FixedRssDisabled
	}
	return f
}

// SetMode sets the filter operating mode.
func (f *Filter) SetMode(mode Mode) { f.mode = mode }

// GetMode returns the current filter operating mode.
func (f *Filter) GetMode() Mode { return f.mode }

// AddAddress adds an extended address to the filter list.
// If the address already exists, it is marked as filtered.
// Returns ErrNoBufs if no entry slot is available.
func (f *Filter) AddAddress(extAddr [8]byte) error {
	entry := f.findEntry(extAddr)
	if entry == nil {
		entry = f.findAvailableEntry()
		if entry == nil {
			return errors.ErrNoBufs
		}
		entry.extAddress = extAddr
	}
	entry.filtered = true
	return nil
}

// RemoveAddress removes an extended address from the filter list.
// No action is performed if the address is not in the list.
func (f *Filter) RemoveAddress(extAddr [8]byte) error {
	entry := f.findEntry(extAddr)
	if entry != nil {
		entry.filtered = false
	}
	return nil
}

// ClearAddresses removes all addresses from the filter list.
// Per-address RSS settings are preserved.
func (f *Filter) ClearAddresses() {
	for i := range f.entries {
		f.entries[i].filtered = false
	}
}

// GetEntries returns a copy of all active filter entries.
func (f *Filter) GetEntries() []Entry {
	var result []Entry
	for i := range f.entries {
		if f.entries[i].filtered {
			result = append(result, Entry{
				ExtAddress: f.entries[i].extAddress,
				RssIn:      f.entries[i].rssIn,
				RssInSet:   f.entries[i].rssIn != FixedRssDisabled,
			})
		}
	}
	return result
}

// SetAddressRssIn sets a fixed RSS value for the given extended address.
// Creates an entry if one does not exist. Returns ErrNoBufs if no slot
// is available.
func (f *Filter) SetAddressRssIn(extAddr [8]byte, rss int8) error {
	entry := f.findEntry(extAddr)
	if entry == nil {
		entry = f.findAvailableEntry()
		if entry == nil {
			return errors.ErrNoBufs
		}
		entry.extAddress = extAddr
	}
	entry.rssIn = rss
	return nil
}

// ClearAddressRssIn clears the fixed RSS value for the given extended address.
// No action is performed if the address is not in the list.
func (f *Filter) ClearAddressRssIn(extAddr [8]byte) error {
	entry := f.findEntry(extAddr)
	if entry != nil {
		entry.rssIn = FixedRssDisabled
	}
	return nil
}

// SetDefaultRssIn sets the default RSS value for addresses not in the list.
func (f *Filter) SetDefaultRssIn(rss int8) {
	f.defaultRss = rss
	f.defaultRssSet = true
}

// ClearDefaultRssIn clears the default RSS value.
func (f *Filter) ClearDefaultRssIn() {
	f.defaultRss = FixedRssDisabled
	f.defaultRssSet = false
}

// Apply checks whether a frame from extAddr should be accepted and returns
// the RSS value to use. The returned bool indicates acceptance.
//
// Logic:
//   - Disabled: accept all, use entry RSS if set, else default RSS if set,
//     else actual RSS.
//   - Allowlist: accept only if address is in list.
//   - Denylist: reject if address is in list.
//
// For accepted frames, the RSS precedence is: per-address RSS > default RSS > actualRss.
func (f *Filter) Apply(extAddr [8]byte, actualRss int8) (int8, bool) {
	entry := f.findEntry(extAddr)
	isInFilterList := entry != nil && entry.filtered

	// Start with the default RSS setting.
	rss := f.defaultRss

	switch f.mode {
	case ModeDisabled:
		// Accept all.
	case ModeAllowlist:
		if !isInFilterList {
			return actualRss, false
		}
	case ModeDenylist:
		if isInFilterList {
			return actualRss, false
		}
	}

	// Per-address RSS overrides the default.
	if entry != nil && entry.rssIn != FixedRssDisabled {
		rss = entry.rssIn
	}

	// If no fixed RSS was determined, use actual RSS.
	if rss == FixedRssDisabled {
		rss = actualRss
	}

	return rss, true
}

// FindEntry looks up a filter entry by extended address.
// Returns a copy of the entry and true if found, zero Entry and false otherwise.
func (f *Filter) FindEntry(extAddr [8]byte) (*Entry, bool) {
	entry := f.findEntry(extAddr)
	if entry == nil || !entry.isInUse() {
		return nil, false
	}
	return &Entry{
		ExtAddress: entry.extAddress,
		RssIn:      entry.rssIn,
		RssInSet:   entry.rssIn != FixedRssDisabled,
	}, true
}

// findEntry returns a pointer to the internal filter entry matching extAddr,
// or nil if not found.
func (f *Filter) findEntry(extAddr [8]byte) *filterEntry {
	for i := range f.entries {
		if f.entries[i].isInUse() && f.entries[i].extAddress == extAddr {
			return &f.entries[i]
		}
	}
	return nil
}

// findAvailableEntry returns a pointer to the first unused entry, or nil
// if all slots are occupied.
func (f *Filter) findAvailableEntry() *filterEntry {
	for i := range f.entries {
		if !f.entries[i].isInUse() {
			return &f.entries[i]
		}
	}
	return nil
}
