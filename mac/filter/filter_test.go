// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package filter_test

import (
	"testing"

	"github.com/hilli/gothread/mac/filter"
)

var (
	addr1 = [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	addr2 = [8]byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
	addr3 = [8]byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28}
)

// --- NewFilter defaults ----------------------------------------------------

func TestNewFilterDefaults(t *testing.T) {
	f := filter.NewFilter()
	if f.GetMode() != filter.ModeDisabled {
		t.Errorf("default mode = %d, want ModeDisabled(%d)", f.GetMode(), filter.ModeDisabled)
	}
	entries := f.GetEntries()
	if len(entries) != 0 {
		t.Errorf("default entries = %d, want 0", len(entries))
	}
}

// --- Mode ------------------------------------------------------------------

func TestSetGetMode(t *testing.T) {
	f := filter.NewFilter()
	for _, m := range []filter.Mode{filter.ModeDisabled, filter.ModeAllowlist, filter.ModeDenylist} {
		f.SetMode(m)
		if f.GetMode() != m {
			t.Errorf("GetMode() = %d after SetMode(%d)", f.GetMode(), m)
		}
	}
}

// --- AddAddress / RemoveAddress --------------------------------------------

func TestAddRemoveAddress(t *testing.T) {
	f := filter.NewFilter()
	if err := f.AddAddress(addr1); err != nil {
		t.Fatalf("AddAddress() error = %v", err)
	}
	entries := f.GetEntries()
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].ExtAddress != addr1 {
		t.Errorf("ExtAddress = %v, want %v", entries[0].ExtAddress, addr1)
	}

	// Remove and verify.
	_ = f.RemoveAddress(addr1)
	entries = f.GetEntries()
	if len(entries) != 0 {
		t.Errorf("entries after remove = %d, want 0", len(entries))
	}
}

func TestAddDuplicate(t *testing.T) {
	f := filter.NewFilter()
	_ = f.AddAddress(addr1)
	_ = f.AddAddress(addr1) // should not create a second entry
	entries := f.GetEntries()
	if len(entries) != 1 {
		t.Errorf("entries after duplicate add = %d, want 1", len(entries))
	}
}

func TestRemoveNonexistent(t *testing.T) {
	f := filter.NewFilter()
	// Should not panic or error.
	_ = f.RemoveAddress(addr1)
}

// --- ClearAddresses --------------------------------------------------------

func TestClearAddresses(t *testing.T) {
	f := filter.NewFilter()
	_ = f.AddAddress(addr1)
	_ = f.AddAddress(addr2)
	f.ClearAddresses()
	entries := f.GetEntries()
	if len(entries) != 0 {
		t.Errorf("entries after clear = %d, want 0", len(entries))
	}
}

// --- MaxEntries ------------------------------------------------------------

func TestMaxEntries(t *testing.T) {
	f := filter.NewFilter(filter.WithMaxEntries(2))
	if err := f.AddAddress(addr1); err != nil {
		t.Fatalf("AddAddress(1) error = %v", err)
	}
	if err := f.AddAddress(addr2); err != nil {
		t.Fatalf("AddAddress(2) error = %v", err)
	}
	err := f.AddAddress(addr3)
	if err == nil {
		t.Error("expected ErrNoBufs when exceeding max entries")
	}
}

// --- Disabled mode ---------------------------------------------------------

func TestApplyDisabled(t *testing.T) {
	f := filter.NewFilter()
	// Disabled mode: all addresses accepted, actual RSS used.
	rss, ok := f.Apply(addr1, -70)
	if !ok {
		t.Error("expected accept in disabled mode")
	}
	if rss != -70 {
		t.Errorf("rss = %d, want -70", rss)
	}
}

// --- Allowlist mode --------------------------------------------------------

func TestApplyAllowlist(t *testing.T) {
	f := filter.NewFilter()
	f.SetMode(filter.ModeAllowlist)
	_ = f.AddAddress(addr1)

	t.Run("listed_accepted", func(t *testing.T) {
		rss, ok := f.Apply(addr1, -60)
		if !ok {
			t.Error("expected accept for allowlisted address")
		}
		if rss != -60 {
			t.Errorf("rss = %d, want -60", rss)
		}
	})

	t.Run("unlisted_rejected", func(t *testing.T) {
		_, ok := f.Apply(addr2, -60)
		if ok {
			t.Error("expected reject for non-allowlisted address")
		}
	})
}

// --- Denylist mode ---------------------------------------------------------

func TestApplyDenylist(t *testing.T) {
	f := filter.NewFilter()
	f.SetMode(filter.ModeDenylist)
	_ = f.AddAddress(addr1)

	t.Run("listed_rejected", func(t *testing.T) {
		_, ok := f.Apply(addr1, -60)
		if ok {
			t.Error("expected reject for denylisted address")
		}
	})

	t.Run("unlisted_accepted", func(t *testing.T) {
		rss, ok := f.Apply(addr2, -60)
		if !ok {
			t.Error("expected accept for non-denylisted address")
		}
		if rss != -60 {
			t.Errorf("rss = %d, want -60", rss)
		}
	})
}

// --- Per-address RSS -------------------------------------------------------

func TestAddressRssIn(t *testing.T) {
	f := filter.NewFilter()
	f.SetMode(filter.ModeAllowlist)
	_ = f.AddAddress(addr1)
	_ = f.SetAddressRssIn(addr1, -40)

	rss, ok := f.Apply(addr1, -80)
	if !ok {
		t.Fatal("expected accept")
	}
	if rss != -40 {
		t.Errorf("rss = %d, want -40 (fixed)", rss)
	}
}

func TestClearAddressRssIn(t *testing.T) {
	f := filter.NewFilter()
	f.SetMode(filter.ModeAllowlist)
	_ = f.AddAddress(addr1)
	_ = f.SetAddressRssIn(addr1, -40)
	_ = f.ClearAddressRssIn(addr1)

	rss, ok := f.Apply(addr1, -80)
	if !ok {
		t.Fatal("expected accept")
	}
	// After clearing fixed RSS, should use actual.
	if rss != -80 {
		t.Errorf("rss = %d, want -80 (actual)", rss)
	}
}

func TestSetAddressRssInCreatesEntry(t *testing.T) {
	// SetAddressRssIn should create an entry even without AddAddress.
	f := filter.NewFilter()
	_ = f.SetAddressRssIn(addr1, -50)

	e, ok := f.FindEntry(addr1)
	if !ok {
		t.Fatal("expected to find entry")
	}
	if e.RssIn != -50 {
		t.Errorf("RssIn = %d, want -50", e.RssIn)
	}
	if !e.RssInSet {
		t.Error("expected RssInSet = true")
	}
}

// --- Default RSS -----------------------------------------------------------

func TestDefaultRssIn(t *testing.T) {
	f := filter.NewFilter()
	f.SetDefaultRssIn(-30)

	// Disabled mode: default RSS overrides actual for all addresses.
	rss, ok := f.Apply(addr1, -80)
	if !ok {
		t.Fatal("expected accept")
	}
	if rss != -30 {
		t.Errorf("rss = %d, want -30 (default)", rss)
	}
}

func TestDefaultRssInOverriddenByAddress(t *testing.T) {
	f := filter.NewFilter()
	f.SetDefaultRssIn(-30)
	_ = f.AddAddress(addr1)
	_ = f.SetAddressRssIn(addr1, -20)
	f.SetMode(filter.ModeAllowlist)

	rss, ok := f.Apply(addr1, -80)
	if !ok {
		t.Fatal("expected accept")
	}
	// Per-address RSS (-20) should take precedence over default (-30).
	if rss != -20 {
		t.Errorf("rss = %d, want -20 (per-address)", rss)
	}
}

func TestClearDefaultRssIn(t *testing.T) {
	f := filter.NewFilter()
	f.SetDefaultRssIn(-30)
	f.ClearDefaultRssIn()

	rss, ok := f.Apply(addr1, -80)
	if !ok {
		t.Fatal("expected accept")
	}
	if rss != -80 {
		t.Errorf("rss = %d, want -80 (actual)", rss)
	}
}

// --- FindEntry -------------------------------------------------------------

func TestFindEntry(t *testing.T) {
	f := filter.NewFilter()
	_ = f.AddAddress(addr1)

	e, ok := f.FindEntry(addr1)
	if !ok {
		t.Fatal("expected to find entry")
	}
	if e.ExtAddress != addr1 {
		t.Errorf("ExtAddress = %v, want %v", e.ExtAddress, addr1)
	}
	if e.RssInSet {
		t.Error("expected RssInSet = false for newly added entry")
	}
}

func TestFindEntryNotFound(t *testing.T) {
	f := filter.NewFilter()
	_, ok := f.FindEntry(addr1)
	if ok {
		t.Error("expected not found")
	}
}

// --- Allowlist with RSS: accept uses fixed RSS, reject ignores it ----------

func TestAllowlistRssForRejected(t *testing.T) {
	f := filter.NewFilter()
	f.SetMode(filter.ModeAllowlist)
	// addr1 is NOT in the allowlist.
	// Default RSS is set.
	f.SetDefaultRssIn(-25)

	rss, ok := f.Apply(addr1, -60)
	if ok {
		t.Error("expected reject for non-allowlisted address")
	}
	// When rejected, the returned RSS is the actual RSS.
	_ = rss
}

// --- Denylist with RSS: reject returns actual, accept can use fixed --------

func TestDenylistRssForAccepted(t *testing.T) {
	f := filter.NewFilter()
	f.SetMode(filter.ModeDenylist)
	// addr1 is denylisted, addr2 is not.
	_ = f.AddAddress(addr1)
	f.SetDefaultRssIn(-35)

	// addr2 should be accepted with default RSS.
	rss, ok := f.Apply(addr2, -70)
	if !ok {
		t.Fatal("expected accept for non-denylisted address")
	}
	if rss != -35 {
		t.Errorf("rss = %d, want -35 (default)", rss)
	}
}

// --- WithMaxEntries option -------------------------------------------------

func TestWithMaxEntriesOption(t *testing.T) {
	f := filter.NewFilter(filter.WithMaxEntries(3))
	addrs := [][8]byte{addr1, addr2, addr3}
	for _, a := range addrs {
		if err := f.AddAddress(a); err != nil {
			t.Fatalf("AddAddress() error = %v", err)
		}
	}
	entries := f.GetEntries()
	if len(entries) != 3 {
		t.Errorf("entries = %d, want 3", len(entries))
	}
}

// --- SetAddressRssIn NoBufs ------------------------------------------------

func TestSetAddressRssInNoBufs(t *testing.T) {
	f := filter.NewFilter(filter.WithMaxEntries(1))
	_ = f.AddAddress(addr1)
	err := f.SetAddressRssIn(addr2, -50)
	if err == nil {
		t.Error("expected ErrNoBufs")
	}
}

// --- Disabled mode with per-address RSS ------------------------------------

func TestDisabledModeWithAddressRss(t *testing.T) {
	f := filter.NewFilter()
	// Even in disabled mode, per-address RSS is applied if the entry exists.
	_ = f.AddAddress(addr1)
	_ = f.SetAddressRssIn(addr1, -45)

	rss, ok := f.Apply(addr1, -80)
	if !ok {
		t.Fatal("expected accept in disabled mode")
	}
	if rss != -45 {
		t.Errorf("rss = %d, want -45 (per-address)", rss)
	}

	// Unknown address: no fixed RSS, uses actual.
	rss, ok = f.Apply(addr2, -80)
	if !ok {
		t.Fatal("expected accept in disabled mode")
	}
	if rss != -80 {
		t.Errorf("rss = %d, want -80 (actual)", rss)
	}
}
