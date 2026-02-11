// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package maxpower

import "testing"

func TestNew(t *testing.T) {
	tbl := New()
	for ch := uint8(MinChannel); ch <= uint8(MaxChannel); ch++ {
		p, ok := tbl.GetMaxPower(ch)
		if !ok {
			t.Errorf("GetMaxPower(%d) returned false", ch)
		}
		if p != DefaultPower {
			t.Errorf("GetMaxPower(%d) = %d, want %d", ch, p, DefaultPower)
		}
	}
}

func TestSetAndGet(t *testing.T) {
	tbl := New()
	tbl.SetMaxPower(15, 10)
	p, ok := tbl.GetMaxPower(15)
	if !ok {
		t.Fatal("GetMaxPower(15) returned false")
	}
	if p != 10 {
		t.Errorf("GetMaxPower(15) = %d, want 10", p)
	}
	// Other channels should still be default.
	p2, ok := tbl.GetMaxPower(11)
	if !ok || p2 != DefaultPower {
		t.Errorf("GetMaxPower(11) = %d, %v; want %d, true", p2, ok, DefaultPower)
	}
}

func TestOutOfRange(t *testing.T) {
	tbl := New()
	tests := []uint8{0, 10, 27, 255}
	for _, ch := range tests {
		_, ok := tbl.GetMaxPower(ch)
		if ok {
			t.Errorf("GetMaxPower(%d) should return false", ch)
		}
	}
	// SetMaxPower on out-of-range should be no-op (no panic).
	tbl.SetMaxPower(0, 5)
	tbl.SetMaxPower(27, 5)
}

func TestClear(t *testing.T) {
	tbl := New()
	tbl.SetMaxPower(20, -5)
	tbl.Clear()
	p, ok := tbl.GetMaxPower(20)
	if !ok {
		t.Fatal("GetMaxPower(20) returned false after Clear")
	}
	if p != DefaultPower {
		t.Errorf("after Clear, GetMaxPower(20) = %d, want %d", p, DefaultPower)
	}
}

func TestNegativePower(t *testing.T) {
	tbl := New()
	tbl.SetMaxPower(11, -20)
	p, ok := tbl.GetMaxPower(11)
	if !ok {
		t.Fatal("GetMaxPower(11) returned false")
	}
	if p != -20 {
		t.Errorf("GetMaxPower(11) = %d, want -20", p)
	}
}

func TestBoundaryChannels(t *testing.T) {
	tbl := New()
	for _, tc := range []struct {
		ch   uint8
		want bool
	}{
		{10, false},
		{11, true},
		{26, true},
		{27, false},
	} {
		_, ok := tbl.GetMaxPower(tc.ch)
		if ok != tc.want {
			t.Errorf("GetMaxPower(%d) ok = %v, want %v", tc.ch, ok, tc.want)
		}
	}
}
