// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package ip6_test

import (
	"testing"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// MPLOption
// ---------------------------------------------------------------------------

func TestMPLOptionInit(t *testing.T) {
	t.Run("SeedIdLength0", func(t *testing.T) {
		var opt ip6.MPLOption
		opt.Init(ip6.MPLSeedIDLength0)

		if got := opt.GetType(); got != ip6.MPLOptionType {
			t.Errorf("GetType() = 0x%02x, want 0x%02x", got, ip6.MPLOptionType)
		}
		if got := opt.GetLength(); got != 2 {
			t.Errorf("GetLength() = %d, want 2", got)
		}
		if got := opt.GetSeedIDLength(); got != ip6.MPLSeedIDLength0 {
			t.Errorf("GetSeedIDLength() = %d, want %d", got, ip6.MPLSeedIDLength0)
		}
	})

	t.Run("SeedIdLength2", func(t *testing.T) {
		var opt ip6.MPLOption
		opt.Init(ip6.MPLSeedIDLength2)

		if got := opt.GetType(); got != ip6.MPLOptionType {
			t.Errorf("GetType() = 0x%02x, want 0x%02x", got, ip6.MPLOptionType)
		}
		if got := opt.GetLength(); got != 4 {
			t.Errorf("GetLength() = %d, want 4", got)
		}
		if got := opt.GetSeedIDLength(); got != ip6.MPLSeedIDLength2 {
			t.Errorf("GetSeedIDLength() = %d, want %d", got, ip6.MPLSeedIDLength2)
		}
	})

	t.Run("unsupported panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for unsupported seed ID length")
			}
		}()
		var opt ip6.MPLOption
		opt.Init(ip6.MPLSeedIDLength8)
	})
}

func TestMPLOptionSeedIdLength(t *testing.T) {
	tests := []struct {
		name   string
		length ip6.MPLSeedIDLength
		want   ip6.MPLSeedIDLength
	}{
		{"Length0", ip6.MPLSeedIDLength0, ip6.MPLSeedIDLength0},
		{"Length2", ip6.MPLSeedIDLength2, ip6.MPLSeedIDLength2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opt ip6.MPLOption
			opt.Init(tt.length)
			if got := opt.GetSeedIDLength(); got != tt.want {
				t.Errorf("GetSeedIDLength() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestMPLOptionMaxFlag(t *testing.T) {
	var opt ip6.MPLOption
	opt.Init(ip6.MPLSeedIDLength0)

	// Initially cleared.
	if opt.IsMaxFlagSet() {
		t.Error("expected M flag to be clear after Init")
	}

	// Set it.
	opt.SetMaxFlag()
	if !opt.IsMaxFlagSet() {
		t.Error("expected M flag to be set after SetMaxFlag")
	}

	// Clear it.
	opt.ClearMaxFlag()
	if opt.IsMaxFlagSet() {
		t.Error("expected M flag to be clear after ClearMaxFlag")
	}
}

func TestMPLOptionSequence(t *testing.T) {
	var opt ip6.MPLOption
	opt.Init(ip6.MPLSeedIDLength2)

	opt.SetSequence(0)
	if got := opt.GetSequence(); got != 0 {
		t.Errorf("GetSequence() = %d, want 0", got)
	}

	opt.SetSequence(42)
	if got := opt.GetSequence(); got != 42 {
		t.Errorf("GetSequence() = %d, want 42", got)
	}

	opt.SetSequence(255)
	if got := opt.GetSequence(); got != 255 {
		t.Errorf("GetSequence() = %d, want 255", got)
	}
}

func TestMPLOptionSeedId(t *testing.T) {
	var opt ip6.MPLOption
	opt.Init(ip6.MPLSeedIDLength2)

	opt.SetSeedID(0x0000)
	if got := opt.GetSeedID(); got != 0x0000 {
		t.Errorf("GetSeedID() = 0x%04x, want 0x0000", got)
	}

	opt.SetSeedID(0xABCD)
	if got := opt.GetSeedID(); got != 0xABCD {
		t.Errorf("GetSeedID() = 0x%04x, want 0xABCD", got)
	}

	opt.SetSeedID(0xFFFF)
	if got := opt.GetSeedID(); got != 0xFFFF {
		t.Errorf("GetSeedID() = 0x%04x, want 0xFFFF", got)
	}
}

func TestMPLOptionTotalSize(t *testing.T) {
	t.Run("SeedIdLength0", func(t *testing.T) {
		var opt ip6.MPLOption
		opt.Init(ip6.MPLSeedIDLength0)
		// TotalSize = 2 + Length = 2 + 2 = 4
		if got := opt.TotalSize(); got != 4 {
			t.Errorf("TotalSize() = %d, want 4", got)
		}
	})

	t.Run("SeedIdLength2", func(t *testing.T) {
		var opt ip6.MPLOption
		opt.Init(ip6.MPLSeedIDLength2)
		// TotalSize = 2 + Length = 2 + 4 = 6
		if got := opt.TotalSize(); got != 6 {
			t.Errorf("TotalSize() = %d, want 6", got)
		}
	})
}

// ---------------------------------------------------------------------------
// Mpl
// ---------------------------------------------------------------------------

func TestMplNewMpl(t *testing.T) {
	m := ip6.NewMpl()

	if got := m.GetSequence(); got != 0 {
		t.Errorf("initial GetSequence() = %d, want 0", got)
	}
}

func TestMplUpdateSeedSetNew(t *testing.T) {
	m := ip6.NewMpl()

	err := m.UpdateSeedSet(100, 1)
	if err != nil {
		t.Fatalf("UpdateSeedSet(100, 1) = %v, want nil", err)
	}
}

func TestMplUpdateSeedSetDuplicate(t *testing.T) {
	m := ip6.NewMpl()

	if err := m.UpdateSeedSet(100, 1); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	err := m.UpdateSeedSet(100, 1)
	if err != errors.ErrDrop {
		t.Errorf("duplicate insert = %v, want ErrDrop", err)
	}
}

func TestMplUpdateSeedSetMultipleSeeds(t *testing.T) {
	m := ip6.NewMpl()

	seeds := []struct {
		id  uint16
		seq uint8
	}{
		{100, 1},
		{200, 5},
		{300, 10},
	}

	for _, s := range seeds {
		if err := m.UpdateSeedSet(s.id, s.seq); err != nil {
			t.Fatalf("UpdateSeedSet(%d, %d) = %v, want nil", s.id, s.seq, err)
		}
	}

	// Verify all are now duplicates.
	for _, s := range seeds {
		if err := m.UpdateSeedSet(s.id, s.seq); err != errors.ErrDrop {
			t.Errorf("duplicate UpdateSeedSet(%d, %d) = %v, want ErrDrop", s.id, s.seq, err)
		}
	}
}

func TestMplUpdateSeedSetSequenceOrdering(t *testing.T) {
	m := ip6.NewMpl()

	// Insert multiple sequences for the same seed ID.
	if err := m.UpdateSeedSet(100, 5); err != nil {
		t.Fatalf("UpdateSeedSet(100, 5) = %v", err)
	}
	if err := m.UpdateSeedSet(100, 10); err != nil {
		t.Fatalf("UpdateSeedSet(100, 10) = %v", err)
	}
	if err := m.UpdateSeedSet(100, 3); err != nil {
		t.Fatalf("UpdateSeedSet(100, 3) = %v", err)
	}

	// All should be duplicates now.
	if err := m.UpdateSeedSet(100, 5); err != errors.ErrDrop {
		t.Errorf("duplicate (100, 5) = %v, want ErrDrop", err)
	}
	if err := m.UpdateSeedSet(100, 10); err != errors.ErrDrop {
		t.Errorf("duplicate (100, 10) = %v, want ErrDrop", err)
	}
	if err := m.UpdateSeedSet(100, 3); err != errors.ErrDrop {
		t.Errorf("duplicate (100, 3) = %v, want ErrDrop", err)
	}
}

func TestMplHandleTimeTick(t *testing.T) {
	m := ip6.NewMpl()

	if err := m.UpdateSeedSet(100, 1); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Verify entry exists.
	if err := m.UpdateSeedSet(100, 1); err != errors.ErrDrop {
		t.Fatalf("expected duplicate, got %v", err)
	}

	// Tick until the entry expires (DefaultSeedEntryLifetime = 4).
	for i := 0; i < int(ip6.DefaultSeedEntryLifetime); i++ {
		m.HandleTimeTick()
	}

	// After expiration, inserting the same (seedId, seq) should succeed
	// since the entry was cleaned up.
	if err := m.UpdateSeedSet(100, 1); err != nil {
		t.Errorf("after expiry, UpdateSeedSet(100, 1) = %v, want nil", err)
	}
}

func TestMplSequence(t *testing.T) {
	m := ip6.NewMpl()

	if got := m.GetSequence(); got != 0 {
		t.Errorf("initial sequence = %d, want 0", got)
	}

	m.IncrementSequence()
	if got := m.GetSequence(); got != 1 {
		t.Errorf("after increment = %d, want 1", got)
	}

	// Test wrap-around: set sequence to 255 via repeated increments is slow,
	// so increment 254 more times to reach 255.
	for i := 0; i < 254; i++ {
		m.IncrementSequence()
	}
	if got := m.GetSequence(); got != 255 {
		t.Errorf("at 255 = %d, want 255", got)
	}

	m.IncrementSequence()
	if got := m.GetSequence(); got != 0 {
		t.Errorf("after wrap = %d, want 0", got)
	}
}
