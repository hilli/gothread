// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package radioselector

import "testing"

// helper addresses
var (
	addr1 = [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	addr2 = [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	addr3 = [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
)

// ===========================================================================
// RadioType tests
// ===========================================================================

func TestRadioType_String(t *testing.T) {
	if RadioType154.String() != "IEEE 802.15.4" {
		t.Errorf("unexpected: %s", RadioType154.String())
	}
	if RadioTypeTrel.String() != "TREL" {
		t.Errorf("unexpected: %s", RadioTypeTrel.String())
	}
	if RadioType(99).String() != "Unknown" {
		t.Errorf("unexpected: %s", RadioType(99).String())
	}
}

// ===========================================================================
// NewSelector tests
// ===========================================================================

func TestNewSelector(t *testing.T) {
	s := NewSelector()

	prefs := s.GetPreferences()
	if len(prefs) != 0 {
		t.Errorf("expected empty preferences, got %d", len(prefs))
	}
}

// ===========================================================================
// FindPreference tests
// ===========================================================================

func TestSelector_FindPreference_NotFound(t *testing.T) {
	s := NewSelector()

	_, ok := s.FindPreference(addr1)
	if ok {
		t.Error("expected not found for unknown address")
	}
}

func TestSelector_FindPreference_ReturnsCopy(t *testing.T) {
	s := NewSelector()
	s.UpdatePreference(addr1, RadioType154, true)

	p, ok := s.FindPreference(addr1)
	if !ok {
		t.Fatal("expected to find preference")
	}

	// Mutating the copy should not affect the selector's internal state.
	p.FrameErrorRate154 = 9999

	p2, _ := s.FindPreference(addr1)
	if p2.FrameErrorRate154 != 0 {
		t.Error("FindPreference should return a copy")
	}
}

// ===========================================================================
// UpdatePreference tests
// ===========================================================================

func TestSelector_UpdatePreference_154Only(t *testing.T) {
	s := NewSelector()
	s.UpdatePreference(addr1, RadioType154, true)

	radio := s.SelectRadio(addr1)
	if radio != RadioType154 {
		t.Errorf("expected 802.15.4, got %s", radio)
	}
}

func TestSelector_UpdatePreference_TrelOnly(t *testing.T) {
	s := NewSelector()
	s.UpdatePreference(addr1, RadioTypeTrel, true)

	radio := s.SelectRadio(addr1)
	if radio != RadioTypeTrel {
		t.Errorf("expected TREL, got %s", radio)
	}
}

func TestSelector_UpdatePreference_BothAvailable_TrelLowError(t *testing.T) {
	s := NewSelector()
	s.UpdatePreference(addr1, RadioType154, true)
	s.UpdatePreference(addr1, RadioTypeTrel, true)

	// Default TREL frame error rate is 0, which is below threshold.
	radio := s.SelectRadio(addr1)
	if radio != RadioTypeTrel {
		t.Errorf("expected TREL (low error rate), got %s", radio)
	}
}

func TestSelector_UpdatePreference_BothAvailable_TrelHighError(t *testing.T) {
	s := NewSelector()
	s.UpdatePreference(addr1, RadioType154, true)
	s.UpdatePreference(addr1, RadioTypeTrel, true)
	s.SetFrameErrorRate(addr1, RadioTypeTrel, FrameErrorRateThreshold+100)

	radio := s.SelectRadio(addr1)
	if radio != RadioType154 {
		t.Errorf("expected 802.15.4 (TREL high error), got %s", radio)
	}
}

func TestSelector_UpdatePreference_NeitherAvailable(t *testing.T) {
	s := NewSelector()
	s.UpdatePreference(addr1, RadioType154, false)
	s.UpdatePreference(addr1, RadioTypeTrel, false)

	radio := s.SelectRadio(addr1)
	if radio != RadioType154 {
		t.Errorf("expected 802.15.4 default, got %s", radio)
	}
}

func TestSelector_UpdatePreference_DisableRadio(t *testing.T) {
	s := NewSelector()
	s.UpdatePreference(addr1, RadioType154, true)
	s.UpdatePreference(addr1, RadioTypeTrel, true)

	// Disable 802.15.4 — should switch to TREL.
	s.UpdatePreference(addr1, RadioType154, false)
	radio := s.SelectRadio(addr1)
	if radio != RadioTypeTrel {
		t.Errorf("expected TREL after disabling 802.15.4, got %s", radio)
	}
}

// ===========================================================================
// SetFrameErrorRate tests
// ===========================================================================

func TestSelector_SetFrameErrorRate(t *testing.T) {
	s := NewSelector()
	s.UpdatePreference(addr1, RadioType154, true)
	s.UpdatePreference(addr1, RadioTypeTrel, true)

	// TREL error rate at threshold — should switch to 802.15.4.
	s.SetFrameErrorRate(addr1, RadioTypeTrel, FrameErrorRateThreshold)
	radio := s.SelectRadio(addr1)
	if radio != RadioType154 {
		t.Errorf("expected 802.15.4 at threshold, got %s", radio)
	}

	// Drop TREL error rate below threshold — should switch to TREL.
	s.SetFrameErrorRate(addr1, RadioTypeTrel, FrameErrorRateThreshold-1)
	radio = s.SelectRadio(addr1)
	if radio != RadioTypeTrel {
		t.Errorf("expected TREL below threshold, got %s", radio)
	}
}

func TestSelector_SetFrameErrorRate_CreatesPreference(t *testing.T) {
	s := NewSelector()

	// Setting error rate for unknown address should create preference.
	s.SetFrameErrorRate(addr1, RadioType154, 100)

	p, ok := s.FindPreference(addr1)
	if !ok {
		t.Fatal("expected preference to be created")
	}
	if p.FrameErrorRate154 != 100 {
		t.Errorf("expected frame error rate 100, got %d", p.FrameErrorRate154)
	}
}

// ===========================================================================
// SetMessageErrorRate tests
// ===========================================================================

func TestSelector_SetMessageErrorRate(t *testing.T) {
	s := NewSelector()

	s.SetMessageErrorRate(addr1, RadioType154, 500)
	s.SetMessageErrorRate(addr1, RadioTypeTrel, 200)

	p, ok := s.FindPreference(addr1)
	if !ok {
		t.Fatal("expected preference to exist")
	}
	if p.MessageErrorRate154 != 500 {
		t.Errorf("expected 154 message error rate 500, got %d", p.MessageErrorRate154)
	}
	if p.MessageErrorRateTrel != 200 {
		t.Errorf("expected TREL message error rate 200, got %d", p.MessageErrorRateTrel)
	}
}

// ===========================================================================
// SelectRadio tests
// ===========================================================================

func TestSelector_SelectRadio_UnknownNeighbor(t *testing.T) {
	s := NewSelector()

	radio := s.SelectRadio(addr1)
	if radio != RadioType154 {
		t.Errorf("expected 802.15.4 default for unknown neighbor, got %s", radio)
	}
}

func TestSelector_SelectRadio_ThresholdBoundary(t *testing.T) {
	s := NewSelector()
	s.UpdatePreference(addr1, RadioType154, true)
	s.UpdatePreference(addr1, RadioTypeTrel, true)

	// Exactly at threshold — not below, so 802.15.4 preferred.
	s.SetFrameErrorRate(addr1, RadioTypeTrel, FrameErrorRateThreshold)
	if s.SelectRadio(addr1) != RadioType154 {
		t.Error("expected 802.15.4 at exact threshold")
	}

	// One below threshold — TREL preferred.
	s.SetFrameErrorRate(addr1, RadioTypeTrel, FrameErrorRateThreshold-1)
	if s.SelectRadio(addr1) != RadioTypeTrel {
		t.Error("expected TREL just below threshold")
	}
}

// ===========================================================================
// RemovePreference tests
// ===========================================================================

func TestSelector_RemovePreference(t *testing.T) {
	s := NewSelector()
	s.UpdatePreference(addr1, RadioType154, true)
	s.UpdatePreference(addr2, RadioTypeTrel, true)

	s.RemovePreference(addr1)

	_, ok := s.FindPreference(addr1)
	if ok {
		t.Error("expected preference removed")
	}

	// addr2 should still be present.
	_, ok = s.FindPreference(addr2)
	if !ok {
		t.Error("expected addr2 preference to remain")
	}
}

func TestSelector_RemovePreference_NonExistent(t *testing.T) {
	s := NewSelector()
	// Should not panic.
	s.RemovePreference(addr1)
}

// ===========================================================================
// GetPreferences tests
// ===========================================================================

func TestSelector_GetPreferences(t *testing.T) {
	s := NewSelector()
	s.UpdatePreference(addr1, RadioType154, true)
	s.UpdatePreference(addr2, RadioTypeTrel, true)
	s.UpdatePreference(addr3, RadioType154, true)

	prefs := s.GetPreferences()
	if len(prefs) != 3 {
		t.Fatalf("expected 3 preferences, got %d", len(prefs))
	}

	// Verify all addresses are present.
	found := make(map[[8]byte]bool)
	for _, p := range prefs {
		found[p.ExtAddress] = true
	}
	if !found[addr1] || !found[addr2] || !found[addr3] {
		t.Error("not all addresses found in preferences")
	}
}

func TestSelector_GetPreferences_Empty(t *testing.T) {
	s := NewSelector()
	prefs := s.GetPreferences()
	if len(prefs) != 0 {
		t.Errorf("expected 0 preferences, got %d", len(prefs))
	}
}

// ===========================================================================
// Selection logic edge cases
// ===========================================================================

func TestSelector_AdaptiveSwitching(t *testing.T) {
	s := NewSelector()
	s.UpdatePreference(addr1, RadioType154, true)
	s.UpdatePreference(addr1, RadioTypeTrel, true)

	// Initially TREL preferred (error rate = 0).
	if s.SelectRadio(addr1) != RadioTypeTrel {
		t.Error("expected TREL initially")
	}

	// TREL error rate degrades above threshold — switch to 802.15.4.
	s.SetFrameErrorRate(addr1, RadioTypeTrel, 1000)
	if s.SelectRadio(addr1) != RadioType154 {
		t.Error("expected 802.15.4 after TREL error rate increase")
	}

	// TREL error rate improves — switch back to TREL.
	s.SetFrameErrorRate(addr1, RadioTypeTrel, 100)
	if s.SelectRadio(addr1) != RadioTypeTrel {
		t.Error("expected TREL after error rate improvement")
	}
}

func TestSelector_MultipleNeighbors(t *testing.T) {
	s := NewSelector()

	// Neighbor 1: both radios, TREL low error.
	s.UpdatePreference(addr1, RadioType154, true)
	s.UpdatePreference(addr1, RadioTypeTrel, true)

	// Neighbor 2: only 802.15.4.
	s.UpdatePreference(addr2, RadioType154, true)

	// Neighbor 3: both radios, TREL high error.
	s.UpdatePreference(addr3, RadioType154, true)
	s.UpdatePreference(addr3, RadioTypeTrel, true)
	s.SetFrameErrorRate(addr3, RadioTypeTrel, 1000)

	if s.SelectRadio(addr1) != RadioTypeTrel {
		t.Error("expected TREL for addr1")
	}
	if s.SelectRadio(addr2) != RadioType154 {
		t.Error("expected 802.15.4 for addr2")
	}
	if s.SelectRadio(addr3) != RadioType154 {
		t.Error("expected 802.15.4 for addr3")
	}
}

// ===========================================================================
// selectBest direct tests
// ===========================================================================

func TestSelectBest(t *testing.T) {
	tests := []struct {
		name string
		pref RadioPreference
		want RadioType
	}{
		{
			name: "only 154",
			pref: RadioPreference{Radio154Available: true},
			want: RadioType154,
		},
		{
			name: "only TREL",
			pref: RadioPreference{RadioTrelAvailable: true},
			want: RadioTypeTrel,
		},
		{
			name: "both, TREL low error",
			pref: RadioPreference{
				Radio154Available:  true,
				RadioTrelAvailable: true,
				FrameErrorRateTrel: 0,
			},
			want: RadioTypeTrel,
		},
		{
			name: "both, TREL at threshold",
			pref: RadioPreference{
				Radio154Available:  true,
				RadioTrelAvailable: true,
				FrameErrorRateTrel: FrameErrorRateThreshold,
			},
			want: RadioType154,
		},
		{
			name: "both, TREL above threshold",
			pref: RadioPreference{
				Radio154Available:  true,
				RadioTrelAvailable: true,
				FrameErrorRateTrel: FrameErrorRateThreshold + 1,
			},
			want: RadioType154,
		},
		{
			name: "both, TREL just below threshold",
			pref: RadioPreference{
				Radio154Available:  true,
				RadioTrelAvailable: true,
				FrameErrorRateTrel: FrameErrorRateThreshold - 1,
			},
			want: RadioTypeTrel,
		},
		{
			name: "neither available",
			pref: RadioPreference{},
			want: RadioType154,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectBest(&tt.pref)
			if got != tt.want {
				t.Errorf("selectBest() = %s, want %s", got, tt.want)
			}
		})
	}
}
