// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package channelmask

import (
	"testing"
)

func TestNew(t *testing.T) {
	m := New(11, 15, 26)
	if !m.Contains(11) || !m.Contains(15) || !m.Contains(26) {
		t.Error("New should set specified channels")
	}
	if m.Contains(12) || m.Contains(25) {
		t.Error("New should not set unspecified channels")
	}
	if m.Count() != 3 {
		t.Errorf("Count() = %d, want 3", m.Count())
	}
}

func TestNewEmpty(t *testing.T) {
	m := New()
	if !m.IsEmpty() {
		t.Error("New() with no args should be empty")
	}
}

func TestNewOutOfRange(t *testing.T) {
	m := New(32, 255)
	if !m.IsEmpty() {
		t.Error("New with out-of-range channels should be empty")
	}
}

func TestConstants(t *testing.T) {
	if Channel11 != 11 {
		t.Errorf("Channel11 = %d, want 11", Channel11)
	}
	if Channel26 != 26 {
		t.Errorf("Channel26 = %d, want 26", Channel26)
	}

	if AllChannels802154.Count() != 16 {
		t.Errorf("AllChannels802154.Count() = %d, want 16", AllChannels802154.Count())
	}
	for ch := uint8(11); ch <= 26; ch++ {
		if !AllChannels802154.Contains(ch) {
			t.Errorf("AllChannels802154 should contain channel %d", ch)
		}
	}
	if AllChannels802154.Contains(10) || AllChannels802154.Contains(27) {
		t.Error("AllChannels802154 should not contain channels outside 11-26")
	}

	if !NoChannels.IsEmpty() {
		t.Error("NoChannels should be empty")
	}
}

func TestContains(t *testing.T) {
	m := New(11, 15, 26)

	tests := []struct {
		ch   uint8
		want bool
	}{
		{10, false},
		{11, true},
		{12, false},
		{15, true},
		{26, true},
		{27, false},
		{0, false},
		{31, false},
	}
	for _, tt := range tests {
		if got := m.Contains(tt.ch); got != tt.want {
			t.Errorf("Contains(%d) = %v, want %v", tt.ch, got, tt.want)
		}
	}
}

func TestContainsOutOfRange(t *testing.T) {
	m := Mask(0xffffffff)
	if m.Contains(32) {
		t.Error("Contains(32) should be false")
	}
	if m.Contains(255) {
		t.Error("Contains(255) should be false")
	}
}

func TestAdd(t *testing.T) {
	m := New(11)
	m2 := m.Add(15)

	// Original unchanged.
	if m.Contains(15) {
		t.Error("original mask should not be modified by Add")
	}
	// New mask has both.
	if !m2.Contains(11) || !m2.Contains(15) {
		t.Error("Add should return mask with new channel")
	}
}

func TestAddOutOfRange(t *testing.T) {
	m := New(11)
	m2 := m.Add(32)
	if m2 != m {
		t.Error("Add(32) should return same mask")
	}
}

func TestRemove(t *testing.T) {
	m := New(11, 15, 26)
	m2 := m.Remove(15)

	// Original unchanged.
	if !m.Contains(15) {
		t.Error("original mask should not be modified by Remove")
	}
	// New mask without 15.
	if m2.Contains(15) {
		t.Error("Remove should return mask without channel")
	}
	if !m2.Contains(11) || !m2.Contains(26) {
		t.Error("Remove should not affect other channels")
	}
}

func TestRemoveOutOfRange(t *testing.T) {
	m := New(11)
	m2 := m.Remove(32)
	if m2 != m {
		t.Error("Remove(32) should return same mask")
	}
}

func TestUnion(t *testing.T) {
	m1 := New(11, 15)
	m2 := New(15, 26)
	result := m1.Union(m2)

	if result.Count() != 3 {
		t.Errorf("Union count = %d, want 3", result.Count())
	}
	if !result.Contains(11) || !result.Contains(15) || !result.Contains(26) {
		t.Error("Union should contain channels from both masks")
	}
}

func TestIntersect(t *testing.T) {
	m1 := New(11, 14, 15, 16, 17, 20, 21, 22, 24, 25)
	m2 := New(14, 21, 26)
	result := m1.Intersect(m2)

	want := []uint8{14, 21}
	got := result.Iterate()
	if len(got) != len(want) {
		t.Fatalf("Intersect: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Intersect: channels[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

func TestIsEmpty(t *testing.T) {
	if !NoChannels.IsEmpty() {
		t.Error("NoChannels should be empty")
	}
	if New(11).IsEmpty() {
		t.Error("mask with channel should not be empty")
	}
}

func TestCount(t *testing.T) {
	tests := []struct {
		name     string
		channels []uint8
		want     int
	}{
		{"empty", nil, 0},
		{"single", []uint8{15}, 1},
		{"several", []uint8{11, 14, 15, 16, 17, 20, 21, 22, 24, 25}, 10},
		{"all", []uint8{11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26}, 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(tt.channels...)
			if m.Count() != tt.want {
				t.Errorf("Count() = %d, want %d", m.Count(), tt.want)
			}
		})
	}
}

func TestGetFirstChannel(t *testing.T) {
	tests := []struct {
		name     string
		channels []uint8
		wantCh   uint8
		wantOk   bool
	}{
		{"empty", nil, 0, false},
		{"single 20", []uint8{20}, 20, true},
		{"multiple", []uint8{15, 20, 25}, 15, true},
		{"channel 0", []uint8{0, 11, 26}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(tt.channels...)
			ch, ok := m.GetFirstChannel()
			if ok != tt.wantOk || ch != tt.wantCh {
				t.Errorf("GetFirstChannel() = (%d, %v), want (%d, %v)", ch, ok, tt.wantCh, tt.wantOk)
			}
		})
	}
}

func TestGetNextChannel(t *testing.T) {
	m := New(11, 15, 20, 26)

	ch, ok := m.GetNextChannel(11)
	if !ok || ch != 15 {
		t.Errorf("GetNextChannel(11) = (%d, %v), want (15, true)", ch, ok)
	}

	ch, ok = m.GetNextChannel(15)
	if !ok || ch != 20 {
		t.Errorf("GetNextChannel(15) = (%d, %v), want (20, true)", ch, ok)
	}

	ch, ok = m.GetNextChannel(20)
	if !ok || ch != 26 {
		t.Errorf("GetNextChannel(20) = (%d, %v), want (26, true)", ch, ok)
	}

	_, ok = m.GetNextChannel(26)
	if ok {
		t.Error("GetNextChannel(26) should return false")
	}

	_, ok = m.GetNextChannel(31)
	if ok {
		t.Error("GetNextChannel(31) should return false")
	}
}

func TestGetNextChannelIterateAll(t *testing.T) {
	m := AllChannels802154
	var channels []uint8

	ch, ok := m.GetFirstChannel()
	for ok {
		channels = append(channels, ch)
		ch, ok = m.GetNextChannel(ch)
	}

	if len(channels) != 16 {
		t.Fatalf("iterated %d channels, want 16", len(channels))
	}
	for i, want := range channels {
		if want != uint8(11+i) {
			t.Errorf("channels[%d] = %d, want %d", i, want, 11+i)
		}
	}
}

func TestIterate(t *testing.T) {
	tests := []struct {
		name     string
		channels []uint8
		want     []uint8
	}{
		{"empty", nil, nil},
		{"single", []uint8{20}, []uint8{20}},
		{"multiple", []uint8{26, 11, 15}, []uint8{11, 15, 26}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(tt.channels...)
			got := m.Iterate()
			if len(got) != len(tt.want) {
				t.Fatalf("Iterate() len = %d, want %d", len(got), len(tt.want))
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("Iterate()[%d] = %d, want %d", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestChooseRandomChannelEmpty(t *testing.T) {
	_, ok := NoChannels.ChooseRandomChannel()
	if ok {
		t.Error("ChooseRandomChannel on empty mask should return false")
	}
}

func TestChooseRandomChannelSingle(t *testing.T) {
	m := New(20)
	for range 100 {
		ch, ok := m.ChooseRandomChannel()
		if !ok {
			t.Fatal("ChooseRandomChannel should return true for non-empty mask")
		}
		if ch != 20 {
			t.Errorf("ChooseRandomChannel = %d, want 20 (single channel)", ch)
		}
	}
}

func TestChooseRandomChannelMultiple(t *testing.T) {
	m := New(11, 15, 20, 26)
	seen := make(map[uint8]bool)

	for range 200 {
		ch, ok := m.ChooseRandomChannel()
		if !ok {
			t.Fatal("ChooseRandomChannel should return true")
		}
		if !m.Contains(ch) {
			t.Errorf("ChooseRandomChannel returned %d which is not in mask", ch)
		}
		seen[ch] = true
	}

	// With 200 tries and 4 channels, we should see all of them.
	if len(seen) != 4 {
		t.Errorf("expected to see all 4 channels, saw %d: %v", len(seen), seen)
	}
}

func TestString(t *testing.T) {
	tests := []struct {
		name     string
		channels []uint8
		want     string
	}{
		{"empty", nil, "{ }"},
		{"all channels", []uint8{11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26}, "{ 11-26 }"},
		{"channels1", []uint8{11, 14, 15, 16, 17, 20, 21, 22, 24, 25}, "{ 11, 14-17, 20-22, 24, 25 }"},
		{"channels2", []uint8{14, 21, 26}, "{ 14, 21, 26 }"},
		{"channels3", []uint8{14, 21}, "{ 14, 21 }"},
		{"single channel", []uint8{20}, "{ 20 }"},
		{"two consecutive", []uint8{14, 15}, "{ 14, 15 }"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(tt.channels...)
			got := m.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
