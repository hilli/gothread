// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package types_test

import (
	"testing"

	"github.com/hilli/gothread/mac/types"
)

// Test vectors extracted from OpenThread tests/unit/test_mac_frame.cpp.

func TestChannelMaskEmpty(t *testing.T) {
	var m types.ChannelMask
	if !m.IsEmpty() {
		t.Error("zero ChannelMask should be empty")
	}
	if m.Count() != 0 {
		t.Errorf("Count() = %d, want 0", m.Count())
	}
	channels := m.Iterate()
	if len(channels) != 0 {
		t.Errorf("Iterate() = %v, want nil/empty", channels)
	}
	if _, ok := m.GetLowest(); ok {
		t.Error("GetLowest() should return false for empty mask")
	}
	if s := m.ToString(); s != "{ }" {
		t.Errorf("ToString() = %q, want %q", s, "{ }")
	}
}

func TestChannelMaskAllChannels(t *testing.T) {
	// Build mask with channels 11-26 (Thread 2.4 GHz).
	var m types.ChannelMask
	for ch := uint8(11); ch <= 26; ch++ {
		m.Add(ch)
	}

	if m.IsEmpty() {
		t.Error("should not be empty")
	}
	if m.Count() != 16 {
		t.Errorf("Count() = %d, want 16", m.Count())
	}

	channels := m.Iterate()
	if len(channels) != 16 {
		t.Fatalf("Iterate() len = %d, want 16", len(channels))
	}
	for i, want := range []uint8{11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26} {
		if channels[i] != want {
			t.Errorf("channels[%d] = %d, want %d", i, channels[i], want)
		}
	}

	if s := m.ToString(); s != "{ 11-26 }" {
		t.Errorf("ToString() = %q, want %q", s, "{ 11-26 }")
	}

	lowest, ok := m.GetLowest()
	if !ok || lowest != 11 {
		t.Errorf("GetLowest() = (%d, %v), want (11, true)", lowest, ok)
	}
}

func TestChannelMaskContains(t *testing.T) {
	var m types.ChannelMask
	m.Add(11)
	m.Add(15)
	m.Add(26)

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
		if m.Contains(tt.ch) != tt.want {
			t.Errorf("Contains(%d) = %v, want %v", tt.ch, m.Contains(tt.ch), tt.want)
		}
	}
}

func TestChannelMaskContainsOutOfRange(t *testing.T) {
	m := types.ChannelMask(0xffffffff)
	if m.Contains(32) {
		t.Error("Contains(32) should be false for uint32 mask")
	}
	if m.Contains(255) {
		t.Error("Contains(255) should be false for uint32 mask")
	}
}

func TestChannelMaskRemove(t *testing.T) {
	// OpenThread test: start with all channels, remove one by one.
	allChannels := []uint8{11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26}

	var m types.ChannelMask
	for _, ch := range allChannels {
		m.Add(ch)
	}

	for i := 0; i < len(allChannels)-1; i++ {
		m.Remove(allChannels[i])
		remaining := allChannels[i+1:]

		got := m.Iterate()
		if len(got) != len(remaining) {
			t.Fatalf("after removing ch %d: Iterate() len = %d, want %d",
				allChannels[i], len(got), len(remaining))
		}
		for j, ch := range remaining {
			if got[j] != ch {
				t.Errorf("after removing ch %d: channels[%d] = %d, want %d",
					allChannels[i], j, got[j], ch)
			}
		}
	}

	// Remove last one.
	m.Remove(26)
	if !m.IsEmpty() {
		t.Error("should be empty after removing all channels")
	}
}

func TestChannelMaskAddRemoveOutOfRange(t *testing.T) {
	var m types.ChannelMask
	// Adding channel >= 32 should be a no-op.
	m.Add(32)
	if !m.IsEmpty() {
		t.Error("Add(32) should be a no-op")
	}
	m.Add(255)
	if !m.IsEmpty() {
		t.Error("Add(255) should be a no-op")
	}

	m.Add(11)
	m.Remove(32)  // no-op
	m.Remove(255) // no-op
	if !m.Contains(11) {
		t.Error("Remove(32/255) should not affect channel 11")
	}
}

func TestChannelMaskIntersect(t *testing.T) {
	// From OpenThread test:
	// channels1 = {11, 14, 15, 16, 17, 20, 21, 22, 24, 25}
	// channels2 = {14, 21, 26}
	// intersection = {14, 21}
	channels1 := []uint8{11, 14, 15, 16, 17, 20, 21, 22, 24, 25}
	channels2 := []uint8{14, 21, 26}

	var m1, m2 types.ChannelMask
	for _, ch := range channels1 {
		m1.Add(ch)
	}
	for _, ch := range channels2 {
		m2.Add(ch)
	}

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

func TestChannelMaskToString(t *testing.T) {
	// Test vectors from OpenThread test_mac_frame.cpp.
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m types.ChannelMask
			for _, ch := range tt.channels {
				m.Add(ch)
			}
			got := m.ToString()
			if got != tt.want {
				t.Errorf("ToString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestChannelMaskCount(t *testing.T) {
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
			var m types.ChannelMask
			for _, ch := range tt.channels {
				m.Add(ch)
			}
			if m.Count() != tt.want {
				t.Errorf("Count() = %d, want %d", m.Count(), tt.want)
			}
		})
	}
}

func TestChannelMaskGetLowest(t *testing.T) {
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
			var m types.ChannelMask
			for _, ch := range tt.channels {
				m.Add(ch)
			}
			ch, ok := m.GetLowest()
			if ok != tt.wantOk || ch != tt.wantCh {
				t.Errorf("GetLowest() = (%d, %v), want (%d, %v)", ch, ok, tt.wantCh, tt.wantOk)
			}
		})
	}
}

func TestChannelMaskToStringTwoConsecutive(t *testing.T) {
	// Two consecutive channels should be listed individually, not as a range.
	// OpenThread: rangeEnd == rangeStart + 1 uses ", " separator.
	var m types.ChannelMask
	m.Add(14)
	m.Add(15)
	got := m.ToString()
	want := "{ 14, 15 }"
	if got != want {
		t.Errorf("ToString() = %q, want %q", got, want)
	}
}

func TestChannelMaskEquality(t *testing.T) {
	var m1, m2 types.ChannelMask
	if m1 != m2 {
		t.Error("two empty masks should be equal")
	}

	for ch := uint8(11); ch <= 26; ch++ {
		m1.Add(ch)
		m2.Add(ch)
	}
	if m1 != m2 {
		t.Error("masks with same channels should be equal")
	}

	m2.Remove(11)
	if m1 == m2 {
		t.Error("masks with different channels should not be equal")
	}
}
