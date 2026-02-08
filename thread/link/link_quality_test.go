// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package link

import (
	"math/rand/v2"
	"testing"
)

// ---------------------------------------------------------------------------
// SuccessRateTracker
// ---------------------------------------------------------------------------

func TestSuccessRateTracker(t *testing.T) {
	t.Run("AfterClear", func(t *testing.T) {
		var s SuccessRateTracker
		s.Clear()
		if s.GetFailureRate() != 0 {
			t.Fatalf("expected failure rate 0, got %d", s.GetFailureRate())
		}
		if s.GetSuccessRate() != MaxRateValue {
			t.Fatalf("expected success rate %d, got %d", MaxRateValue, s.GetSuccessRate())
		}
	})

	t.Run("AllSuccess", func(t *testing.T) {
		var s SuccessRateTracker
		s.Clear()
		for i := 0; i < 1000; i++ {
			s.AddSample(true, defaultWeight)
		}
		if s.GetFailureRate() != 0 {
			t.Fatalf("expected failure rate 0 after all success, got %d", s.GetFailureRate())
		}
		if s.GetSuccessRate() != MaxRateValue {
			t.Fatalf("expected success rate %d after all success, got %d", MaxRateValue, s.GetSuccessRate())
		}
	})

	t.Run("AllFailure", func(t *testing.T) {
		var s SuccessRateTracker
		s.Clear()
		for i := 0; i < 1000; i++ {
			s.AddSample(false, defaultWeight)
		}
		// The IIR filter converges to a stable fixed point slightly below
		// MaxRateValue due to integer truncation in the averaging formula.
		// With weight=64, the steady state is 65504.
		tolerance := uint16(MaxRateValue / 100) // 1% tolerance
		if MaxRateValue-s.GetFailureRate() > tolerance {
			t.Fatalf("expected failure rate near %d after all failure, got %d", MaxRateValue, s.GetFailureRate())
		}
		if s.GetSuccessRate() > tolerance {
			t.Fatalf("expected success rate near 0 after all failure, got %d", s.GetSuccessRate())
		}
	})

	t.Run("ParametricWeightsAndPeriods", func(t *testing.T) {
		weights := []uint16{64, 128, 256, 300, 512, 810, 900}
		periods := []uint16{1, 2, 4, 8, 16, 32, 64}

		for _, w := range weights {
			for _, p := range periods {
				var s SuccessRateTracker
				s.Clear()

				// Run the filter for enough iterations to converge.
				// With period p, the expected failure rate is MaxRateValue/p.
				iterations := uint32(w) * 20
				for i := uint32(0); i < iterations; i++ {
					success := (i % uint32(p)) != 0
					s.AddSample(success, w)
				}

				expected := float64(MaxRateValue) / float64(p)
				actual := float64(s.GetFailureRate())

				// Allow 1% error.
				tolerance := 0.01 * float64(MaxRateValue)
				diff := actual - expected
				if diff < 0 {
					diff = -diff
				}
				if diff > tolerance {
					t.Errorf("weight=%d period=%d: expected failure rate ~%.0f, got %.0f (diff=%.0f, tolerance=%.0f)",
						w, p, expected, actual, diff, tolerance)
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// RSSAverager
// ---------------------------------------------------------------------------

func TestRSSAverager(t *testing.T) {
	t.Run("AfterClear", func(t *testing.T) {
		var r RSSAverager
		r.Clear()
		if r.GetAverage() != InvalidRSSI {
			t.Fatalf("expected InvalidRSSI, got %d", r.GetAverage())
		}
		if r.HasAverage() {
			t.Fatal("expected HasAverage to be false")
		}
		if r.GetRaw() != 0 {
			t.Fatalf("expected raw 0, got %d", r.GetRaw())
		}
	})

	t.Run("SingleValue", func(t *testing.T) {
		var r RSSAverager
		r.Clear()
		if err := r.Add(-70); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if r.GetAverage() != -70 {
			t.Fatalf("expected -70, got %d", r.GetAverage())
		}
	})

	t.Run("ClearAfterAdd", func(t *testing.T) {
		var r RSSAverager
		if err := r.Add(-70); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		r.Clear()
		if r.GetAverage() != InvalidRSSI {
			t.Fatalf("expected InvalidRSSI after clear, got %d", r.GetAverage())
		}
	})

	t.Run("SameValueRepeated", func(t *testing.T) {
		testValues := []int8{-128, -70, -40, -41, -10, 0}
		for _, v := range testValues {
			var r RSSAverager
			r.Clear()
			for i := 0; i < 300; i++ {
				if err := r.Add(v); err != nil {
					t.Fatalf("unexpected error adding %d: %v", v, err)
				}
				if r.GetAverage() != v {
					t.Fatalf("value=%d iteration=%d: expected %d, got %d", v, i, v, r.GetAverage())
				}
			}
		}
	})

	t.Run("TwoValues", func(t *testing.T) {
		// With two values, the average should be the arithmetic mean.
		// The averager computes: avg_raw = ((-rss1)*8 + (-rss2)*8) / 2
		// Then GetAverage returns -(avg_raw >> 3) with rounding.
		testCases := []struct {
			rss1, rss2 int8
			expected   int8
		}{
			{-70, -80, -75},
			{-70, -71, -71}, // (-70+-71)/2 = -70.5, rounds to -71
			{-50, -60, -55},
			{-40, -40, -40},
		}
		for _, tc := range testCases {
			var r RSSAverager
			r.Clear()
			_ = r.Add(tc.rss1)
			_ = r.Add(tc.rss2)
			got := r.GetAverage()
			if got != tc.expected {
				t.Errorf("rss1=%d rss2=%d: expected %d, got %d", tc.rss1, tc.rss2, tc.expected, got)
			}
		}
	})

	t.Run("First8ArithmeticMean", func(t *testing.T) {
		// For the first 8 values the averager computes an arithmetic mean.
		rng := rand.New(rand.NewPCG(12345, 67890))
		for iter := 0; iter < 1000; iter++ {
			var r RSSAverager
			r.Clear()

			n := rng.IntN(8) + 1 // 1..8 samples
			var sum int32
			for i := 0; i < n; i++ {
				v := int8(-int(rng.IntN(128))) // -127..0
				sum += int32(v)
				_ = r.Add(v)
			}

			// Compute expected: the averager stores negated, scaled values
			// and then negates back. The arithmetic should match integer division
			// of the sum of negated-scaled values.
			got := r.GetAverage()
			avg := r.GetRaw()

			// Verify raw average is consistent with the reported average.
			expectedFromRaw := -int8(avg >> precisionBitShift)
			if avg&precisionBitMask >= precision/2 {
				expectedFromRaw--
			}
			if got != expectedFromRaw {
				t.Fatalf("iter=%d: GetAverage()=%d inconsistent with raw=%d (expected %d)", iter, got, avg, expectedFromRaw)
			}

			// The reported average should be close to the true arithmetic mean.
			trueMean := float64(sum) / float64(n)
			diff := float64(got) - trueMean
			if diff < 0 {
				diff = -diff
			}
			if diff > 1.0 {
				t.Errorf("iter=%d: n=%d sum=%d trueMean=%.2f got=%d diff=%.2f",
					iter, n, sum, trueMean, got, diff)
			}
		}
	})

	t.Run("AlternatingValues", func(t *testing.T) {
		rss1 := int8(-50)
		rss2 := int8(-90)
		var r RSSAverager
		r.Clear()

		for i := 0; i < 500; i++ {
			if i%2 == 0 {
				_ = r.Add(rss1)
			} else {
				_ = r.Add(rss2)
			}
			avg := r.GetAverage()
			if avg < rss2 || avg > rss1 {
				t.Fatalf("iteration %d: average %d out of range [%d, %d]", i, avg, rss2, rss1)
			}
		}

		// After many alternating samples the average should be close to the midpoint.
		avg := r.GetAverage()
		arithmeticMean := (int16(rss1) + int16(rss2)) / 2
		diff := int16(avg) - arithmeticMean
		if diff < 0 {
			diff = -diff
		}
		if diff > 16 {
			t.Errorf("alternating average %d too far from arithmetic mean %d (diff=%d)", avg, arithmeticMean, diff)
		}
	})

	t.Run("InvalidRSSIRejected", func(t *testing.T) {
		var r RSSAverager
		r.Clear()
		err := r.Add(InvalidRSSI)
		if err == nil {
			t.Fatal("expected error for InvalidRSSI, got nil")
		}
	})
}

// ---------------------------------------------------------------------------
// LQIAverager
// ---------------------------------------------------------------------------

func TestLQIAverager(t *testing.T) {
	t.Run("AfterClear", func(t *testing.T) {
		var l LQIAverager
		l.Clear()
		if l.GetAverage() != 0 {
			t.Fatalf("expected 0, got %d", l.GetAverage())
		}
		if l.GetCount() != 0 {
			t.Fatalf("expected count 0, got %d", l.GetCount())
		}
	})

	t.Run("SingleValue", func(t *testing.T) {
		var l LQIAverager
		l.Clear()
		l.Add(200)
		if l.GetAverage() != 200 {
			t.Fatalf("expected 200, got %d", l.GetAverage())
		}
		if l.GetCount() != 1 {
			t.Fatalf("expected count 1, got %d", l.GetCount())
		}
	})

	t.Run("SameValueRepeated", func(t *testing.T) {
		var l LQIAverager
		l.Clear()
		for i := 0; i < 100; i++ {
			l.Add(150)
		}
		if l.GetAverage() != 150 {
			t.Fatalf("expected 150, got %d", l.GetAverage())
		}
	})
}

// ---------------------------------------------------------------------------
// ComputeLinkMargin
// ---------------------------------------------------------------------------

func TestComputeLinkMargin(t *testing.T) {
	tests := []struct {
		noiseFloor int8
		rss        int8
		expected   uint8
	}{
		{-100, -80, 20},
		{-100, -100, 0},
		{-100, -110, 0},
		{-90, -70, 20},
		{-90, InvalidRSSI, 0},
		{-100, -50, 50},
		{-100, 0, 100},
		{-50, -50, 0},
	}

	for _, tc := range tests {
		got := ComputeLinkMargin(tc.noiseFloor, tc.rss)
		if got != tc.expected {
			t.Errorf("ComputeLinkMargin(%d, %d) = %d, want %d", tc.noiseFloor, tc.rss, got, tc.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// QualityForLinkMargin
// ---------------------------------------------------------------------------

func TestQualityForLinkMargin(t *testing.T) {
	tests := []struct {
		margin   uint8
		expected uint8
	}{
		{0, Quality0},
		{2, Quality0},
		{3, Quality1},
		{10, Quality1},
		{11, Quality2},
		{20, Quality2},
		{21, Quality3},
		{255, Quality3},
	}

	for _, tc := range tests {
		got := QualityForLinkMargin(tc.margin)
		if got != tc.expected {
			t.Errorf("QualityForLinkMargin(%d) = %d, want %d", tc.margin, got, tc.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// CostForQuality
// ---------------------------------------------------------------------------

func TestCostForQuality(t *testing.T) {
	tests := []struct {
		quality  uint8
		expected uint8
	}{
		{Quality0, 16},
		{Quality1, 4},
		{Quality2, 2},
		{Quality3, 1},
	}

	for _, tc := range tests {
		got := CostForQuality(tc.quality)
		if got != tc.expected {
			t.Errorf("CostForQuality(%d) = %d, want %d", tc.quality, got, tc.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// QualityInfo with RSS sequences
// ---------------------------------------------------------------------------

func TestQualityInfoWithRSSSequences(t *testing.T) {
	const noiseFloor int8 = -100

	tests := []struct {
		name            string
		sequence        []int8
		expectedQuality uint8
	}{
		{
			name:            "HighQuality",
			sequence:        []int8{-81, -80, -79, -78, -76, -80, -77, -75, -77, -76, -77, -74},
			expectedQuality: Quality3,
		},
		{
			name:            "MediumQuality",
			sequence:        []int8{-90, -80, -85},
			expectedQuality: Quality2,
		},
		{
			name:            "LowQuality",
			sequence:        []int8{-95, -96, -98, -99, -100, -100, -98, -99, -100, -100, -100, -100, -100},
			expectedQuality: Quality0,
		},
		{
			name:            "Quality1Transition",
			sequence:        []int8{-75, -100, -100, -100, -100, -100, -95, -92, -93, -94, -93, -93},
			expectedQuality: Quality1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			qi := NewQualityInfo(noiseFloor)

			var minRSS, maxRSS int8
			minRSS = 0
			maxRSS = -128

			for _, rss := range tc.sequence {
				qi.AddRSS(rss)
				if rss < minRSS {
					minRSS = rss
				}
				if rss > maxRSS {
					maxRSS = rss
				}
			}

			// Verify LastRSS
			lastRSS := tc.sequence[len(tc.sequence)-1]
			if qi.LastRSS != lastRSS {
				t.Errorf("LastRSS = %d, want %d", qi.LastRSS, lastRSS)
			}

			// Verify average is within bounds
			avgRSS := qi.GetAverageRSS()
			if avgRSS < minRSS || avgRSS > maxRSS {
				t.Errorf("GetAverageRSS() = %d, out of range [%d, %d]", avgRSS, minRSS, maxRSS)
			}

			// Verify quality
			if qi.GetQualityIn() != tc.expectedQuality {
				t.Errorf("GetQualityIn() = %d, want %d", qi.GetQualityIn(), tc.expectedQuality)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetTypicalRSSForQuality
// ---------------------------------------------------------------------------

func TestGetTypicalRSSForQuality(t *testing.T) {
	const noiseFloor int8 = -100

	tests := []struct {
		quality  uint8
		expected int8
	}{
		{Quality0, -100},
		{Quality1, -95},
		{Quality2, -85},
		{Quality3, -50},
	}

	for _, tc := range tests {
		got := GetTypicalRSSForQuality(noiseFloor, tc.quality)
		if got != tc.expected {
			t.Errorf("GetTypicalRSSForQuality(%d, %d) = %d, want %d", noiseFloor, tc.quality, got, tc.expected)
		}
	}
}
