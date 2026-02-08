// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"bytes"
	"testing"
)

func TestTimestampGettersSetters(t *testing.T) {
	var ts Timestamp

	ts.SetSeconds(0x123456789ABC)
	if got := ts.Seconds(); got != 0x123456789ABC {
		t.Errorf("Seconds() = %#x, want 0x123456789ABC", got)
	}

	// Only lower 48 bits should be retained.
	ts.SetSeconds(0xFFFFFFFFFFFFFF)
	if got := ts.Seconds(); got != 0x0000FFFFFFFFFFFF {
		t.Errorf("Seconds() after overflow = %#x, want 0x0000FFFFFFFFFFFF", got)
	}

	ts.SetTicks(12345)
	if got := ts.Ticks(); got != 12345 {
		t.Errorf("Ticks() = %d, want 12345", got)
	}

	// Only lower 15 bits should be retained.
	ts.SetTicks(0xFFFF)
	if got := ts.Ticks(); got != MaxTicks {
		t.Errorf("Ticks() after overflow = %d, want %d", got, MaxTicks)
	}

	ts.SetAuthoritative(true)
	if !ts.Authoritative() {
		t.Error("Authoritative() = false, want true")
	}
	ts.SetAuthoritative(false)
	if ts.Authoritative() {
		t.Error("Authoritative() = true, want false")
	}
}

func TestTimestampMarshalUnmarshalRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		seconds uint64
		ticks   uint16
		auth    bool
	}{
		{"zero", 0, 0, false},
		{"typical", 1000, 500, true},
		{"max-seconds", 0x0000FFFFFFFFFFFF, 0, false},
		{"max-ticks", 0, MaxTicks, false},
		{"all-set", 0x0000FFFFFFFFFFFF, MaxTicks, true},
		{"orphan-announce", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ts Timestamp
			ts.SetSeconds(tt.seconds)
			ts.SetTicks(tt.ticks)
			ts.SetAuthoritative(tt.auth)

			data, err := ts.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			if len(data) != TimestampSize {
				t.Fatalf("MarshalBinary: len = %d, want %d", len(data), TimestampSize)
			}

			var ts2 Timestamp
			if err := ts2.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary: %v", err)
			}
			if ts2.Seconds() != tt.seconds {
				t.Errorf("Seconds = %#x, want %#x", ts2.Seconds(), tt.seconds)
			}
			if ts2.Ticks() != tt.ticks {
				t.Errorf("Ticks = %d, want %d", ts2.Ticks(), tt.ticks)
			}
			if ts2.Authoritative() != tt.auth {
				t.Errorf("Authoritative = %v, want %v", ts2.Authoritative(), tt.auth)
			}
		})
	}
}

func TestTimestampInvalidSentinel(t *testing.T) {
	var ts Timestamp
	ts.SetToInvalid()

	if ts.IsValid() {
		t.Error("IsValid() = true after SetToInvalid, want false")
	}

	data, err := ts.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	// All 8 wire bytes should be 0xFF.
	want := bytes.Repeat([]byte{0xFF}, TimestampSize)
	if !bytes.Equal(data, want) {
		t.Errorf("MarshalBinary = %x, want all FF", data)
	}

	// Unmarshal and verify still invalid.
	var ts2 Timestamp
	if err := ts2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if ts2.IsValid() {
		t.Error("IsValid() = true after unmarshal of invalid sentinel")
	}
}

func TestTimestampValidAfterConstruction(t *testing.T) {
	var ts Timestamp
	// Zero-value timestamp should be valid (it's not the all-0xFF sentinel).
	if !ts.IsValid() {
		t.Error("zero-value Timestamp should be valid")
	}
}

func TestTimestampOrphanAnnounce(t *testing.T) {
	var ts Timestamp
	ts.SetToOrphanAnnounce()

	if !ts.IsOrphanAnnounce() {
		t.Error("IsOrphanAnnounce() = false after SetToOrphanAnnounce")
	}
	if ts.Seconds() != 0 {
		t.Errorf("Seconds() = %d, want 0", ts.Seconds())
	}
	if ts.Ticks() != 0 {
		t.Errorf("Ticks() = %d, want 0", ts.Ticks())
	}
	if !ts.Authoritative() {
		t.Error("Authoritative() = false, want true")
	}
	// Orphan announce should be valid (not the invalid sentinel).
	if !ts.IsValid() {
		t.Error("Orphan announce should be valid")
	}
}

func TestTimestampAdvanceRandomTicks(t *testing.T) {
	var ts Timestamp
	ts.SetSeconds(100)
	ts.SetTicks(0)

	// Run several times to exercise the random path.
	for i := 0; i < 100; i++ {
		before := ts.Ticks()
		beforeSec := ts.Seconds()
		ts.AdvanceRandomTicks()

		// Ticks should have changed (extremely unlikely to stay same with random advance).
		// After advance, either ticks increased or seconds wrapped.
		if ts.Seconds() == beforeSec && ts.Ticks() <= before {
			// This could theoretically happen if ticks wrapped exactly to 0
			// and seconds incremented, so check that case.
			if ts.Seconds() != beforeSec+1 {
				t.Errorf("iteration %d: ticks did not advance: before=%d after=%d sec_before=%d sec_after=%d",
					i, before, ts.Ticks(), beforeSec, ts.Seconds())
			}
		}
	}
}

func TestTimestampAdvanceRandomTicksWraps(t *testing.T) {
	// Set ticks near max to force a wrap.
	var ts Timestamp
	ts.SetSeconds(10)
	ts.SetTicks(MaxTicks) // max ticks

	// After advancing, seconds must have incremented.
	ts.AdvanceRandomTicks()
	if ts.Seconds() != 11 {
		t.Errorf("Seconds() = %d after wrap, want 11", ts.Seconds())
	}
	// Ticks should be within valid range.
	if ts.Ticks() > MaxTicks {
		t.Errorf("Ticks() = %d, exceeds MaxTicks", ts.Ticks())
	}
}

func TestTimestampCompare(t *testing.T) {
	tests := []struct {
		name string
		a, b Timestamp
		want int
	}{
		{
			name: "equal-zero",
			want: 0,
		},
		{
			name: "seconds-greater",
			a:    makeTimestamp(100, 0, false),
			b:    makeTimestamp(50, 0, false),
			want: 1,
		},
		{
			name: "seconds-less",
			a:    makeTimestamp(50, 0, false),
			b:    makeTimestamp(100, 0, false),
			want: -1,
		},
		{
			name: "ticks-greater",
			a:    makeTimestamp(100, 500, false),
			b:    makeTimestamp(100, 100, false),
			want: 1,
		},
		{
			name: "ticks-less",
			a:    makeTimestamp(100, 100, false),
			b:    makeTimestamp(100, 500, false),
			want: -1,
		},
		{
			name: "auth-true-greater",
			a:    makeTimestamp(100, 500, true),
			b:    makeTimestamp(100, 500, false),
			want: 1,
		},
		{
			name: "auth-false-less",
			a:    makeTimestamp(100, 500, false),
			b:    makeTimestamp(100, 500, true),
			want: -1,
		},
		{
			name: "valid-greater-than-invalid",
			a:    makeTimestamp(0, 0, false),
			b:    makeInvalidTimestamp(),
			want: 1,
		},
		{
			name: "invalid-less-than-valid",
			a:    makeInvalidTimestamp(),
			b:    makeTimestamp(0, 0, false),
			want: -1,
		},
		{
			name: "both-invalid-equal",
			a:    makeInvalidTimestamp(),
			b:    makeInvalidTimestamp(),
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Compare(&tt.a, &tt.b); got != tt.want {
				t.Errorf("Compare = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestTimestampUnmarshalTooShort(t *testing.T) {
	var ts Timestamp
	if err := ts.UnmarshalBinary([]byte{0x01, 0x02}); err == nil {
		t.Error("UnmarshalBinary with 2 bytes: expected error, got nil")
	}
}

// makeTimestamp creates a Timestamp with the given values.
func makeTimestamp(seconds uint64, ticks uint16, auth bool) Timestamp {
	var ts Timestamp
	ts.SetSeconds(seconds)
	ts.SetTicks(ticks)
	ts.SetAuthoritative(auth)
	return ts
}

// makeInvalidTimestamp creates an invalid sentinel timestamp.
func makeInvalidTimestamp() Timestamp {
	var ts Timestamp
	ts.SetToInvalid()
	return ts
}
