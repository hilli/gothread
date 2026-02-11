// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import "testing"

func TestChildMask_SetAndHas(t *testing.T) {
	t.Parallel()

	var m ChildMask

	tests := []struct {
		name  string
		index int
		want  bool
	}{
		{"set index 0", 0, true},
		{"set index 5", 5, true},
		{"set last valid index", MaxChildren - 1, true},
		{"unset index 3", 3, false},
	}

	m.Set(0)
	m.Set(5)
	m.Set(MaxChildren - 1)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := m.Has(tt.index); got != tt.want {
				t.Errorf("Has(%d) = %v, want %v", tt.index, got, tt.want)
			}
		})
	}
}

func TestChildMask_Clear(t *testing.T) {
	t.Parallel()

	var m ChildMask
	m.Set(3)
	m.Set(7)

	m.Clear(3)
	if m.Has(3) {
		t.Error("Has(3) should be false after Clear(3)")
	}
	if !m.Has(7) {
		t.Error("Has(7) should still be true")
	}
}

func TestChildMask_OutOfBounds(t *testing.T) {
	t.Parallel()

	var m ChildMask

	tests := []struct {
		name  string
		index int
	}{
		{"negative", -1},
		{"at MaxChildren", MaxChildren},
		{"large positive", 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m.Set(tt.index)   // should be a no-op
			m.Clear(tt.index) // should be a no-op
			if m.Has(tt.index) {
				t.Errorf("Has(%d) should be false for out-of-bounds", tt.index)
			}
		})
	}
}

func TestChildMask_IsEmpty(t *testing.T) {
	t.Parallel()

	var m ChildMask
	if !m.IsEmpty() {
		t.Error("new ChildMask should be empty")
	}

	m.Set(4)
	if m.IsEmpty() {
		t.Error("ChildMask with bit set should not be empty")
	}

	m.Clear(4)
	if !m.IsEmpty() {
		t.Error("ChildMask should be empty after clearing only set bit")
	}
}

func TestChildMask_Count(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		indices []int
		want    int
	}{
		{"none", nil, 0},
		{"one", []int{3}, 1},
		{"three", []int{0, 5, 9}, 3},
		{"all", func() []int {
			all := make([]int, MaxChildren)
			for i := range all {
				all[i] = i
			}
			return all
		}(), MaxChildren},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var m ChildMask
			for _, idx := range tt.indices {
				m.Set(idx)
			}
			if got := m.Count(); got != tt.want {
				t.Errorf("Count() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestChildMask_ClearAll(t *testing.T) {
	t.Parallel()

	var m ChildMask
	for i := 0; i < MaxChildren; i++ {
		m.Set(i)
	}

	m.ClearAll()
	if !m.IsEmpty() {
		t.Error("ClearAll should make mask empty")
	}
	if m.Count() != 0 {
		t.Errorf("Count() = %d after ClearAll, want 0", m.Count())
	}
}

func TestChildMask_GetFirstSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		indices   []int
		wantIndex int
		wantOK    bool
	}{
		{"empty", nil, 0, false},
		{"single at 0", []int{0}, 0, true},
		{"single at 7", []int{7}, 7, true},
		{"multiple", []int{3, 5, 9}, 3, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var m ChildMask
			for _, idx := range tt.indices {
				m.Set(idx)
			}
			gotIdx, gotOK := m.GetFirstSet()
			if gotIdx != tt.wantIndex || gotOK != tt.wantOK {
				t.Errorf("GetFirstSet() = (%d, %v), want (%d, %v)", gotIdx, gotOK, tt.wantIndex, tt.wantOK)
			}
		})
	}
}
