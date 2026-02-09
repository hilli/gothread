// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"testing"
	"time"
)

// deterministicRandFn returns a function that always picks the midpoint
// of the range [0, n), which gives t = I/2 + I/4 = 3I/4.
func deterministicRandFn(fraction float64) func(time.Duration) time.Duration {
	return func(n time.Duration) time.Duration {
		return time.Duration(float64(n) * fraction)
	}
}

func TestTrickleTimer_StartStop(t *testing.T) {
	timer := NewTrickleTimer(TrickleTimerConfig{
		IMin:   1 * time.Second,
		IMax:   4 * time.Second,
		RandFn: deterministicRandFn(0.5),
	})

	if timer.IsRunning() {
		t.Error("timer should not be running after creation")
	}

	timer.Start()
	if !timer.IsRunning() {
		t.Error("timer should be running after Start")
	}
	if timer.GetInterval() != 1*time.Second {
		t.Errorf("initial interval = %v, want %v", timer.GetInterval(), 1*time.Second)
	}

	timer.Stop()
	if timer.IsRunning() {
		t.Error("timer should not be running after Stop")
	}
}

func TestTrickleTimer_HandleTimeTick_Transmit(t *testing.T) {
	// With iMin=1s and rand fraction=0.5, txTime = 500ms + 250ms = 750ms.
	timer := NewTrickleTimer(TrickleTimerConfig{
		IMin:   1 * time.Second,
		IMax:   4 * time.Second,
		RandFn: deterministicRandFn(0.5),
	})
	timer.Start()

	// Tick at 500ms — before txTime, no transmit.
	if timer.HandleTimeTick(500 * time.Millisecond) {
		t.Error("should not transmit before txTime")
	}

	// Tick at another 300ms (total 800ms) — crosses 750ms txTime.
	if !timer.HandleTimeTick(300 * time.Millisecond) {
		t.Error("should transmit when crossing txTime")
	}

	// Tick at another 300ms (total 1100ms) — past interval, no transmit here
	// (but interval ends and new period starts).
	_ = timer.HandleTimeTick(300 * time.Millisecond)
}

func TestTrickleTimer_IntervalDoubling(t *testing.T) {
	timer := NewTrickleTimer(TrickleTimerConfig{
		IMin:   1 * time.Second,
		IMax:   8 * time.Second,
		RandFn: deterministicRandFn(0.5),
	})
	timer.Start()

	if timer.GetInterval() != 1*time.Second {
		t.Fatalf("initial interval = %v, want 1s", timer.GetInterval())
	}

	// Advance past the first interval (1s).
	timer.HandleTimeTick(1100 * time.Millisecond)
	if timer.GetInterval() != 2*time.Second {
		t.Errorf("after first interval: interval = %v, want 2s", timer.GetInterval())
	}

	// Advance past the second interval (2s).
	timer.HandleTimeTick(2100 * time.Millisecond)
	if timer.GetInterval() != 4*time.Second {
		t.Errorf("after second interval: interval = %v, want 4s", timer.GetInterval())
	}

	// Advance past the third interval (4s).
	timer.HandleTimeTick(4100 * time.Millisecond)
	if timer.GetInterval() != 8*time.Second {
		t.Errorf("after third interval: interval = %v, want 8s", timer.GetInterval())
	}

	// Advance past the fourth interval (8s) — should stay at iMax.
	timer.HandleTimeTick(8100 * time.Millisecond)
	if timer.GetInterval() != 8*time.Second {
		t.Errorf("after fourth interval: interval = %v, want 8s (capped)", timer.GetInterval())
	}
}

func TestTrickleTimer_Reset(t *testing.T) {
	timer := NewTrickleTimer(TrickleTimerConfig{
		IMin:   1 * time.Second,
		IMax:   8 * time.Second,
		RandFn: deterministicRandFn(0.5),
	})
	timer.Start()

	// Let it double a couple times.
	timer.HandleTimeTick(1100 * time.Millisecond) // I -> 2s
	timer.HandleTimeTick(2100 * time.Millisecond) // I -> 4s
	if timer.GetInterval() != 4*time.Second {
		t.Fatalf("pre-reset interval = %v, want 4s", timer.GetInterval())
	}

	// Reset brings it back to iMin.
	timer.Reset()
	if timer.GetInterval() != 1*time.Second {
		t.Errorf("post-reset interval = %v, want 1s", timer.GetInterval())
	}
}

func TestTrickleTimer_ResetWhenStopped(t *testing.T) {
	timer := NewTrickleTimer(TrickleTimerConfig{
		IMin:   1 * time.Second,
		IMax:   4 * time.Second,
		RandFn: deterministicRandFn(0.5),
	})

	// Reset on a stopped timer is a no-op, should not panic.
	timer.Reset()
	if timer.IsRunning() {
		t.Error("Reset on stopped timer should not start it")
	}
}

func TestTrickleTimer_ConsistencyCounter(t *testing.T) {
	// k=1 means: suppress if c >= 1.
	timer := NewTrickleTimer(TrickleTimerConfig{
		IMin:   1 * time.Second,
		IMax:   4 * time.Second,
		K:      1,
		RandFn: deterministicRandFn(0.5),
	})
	timer.Start()

	// Before indicating consistency, transmit should work.
	// txTime = 750ms
	timer.HandleTimeTick(500 * time.Millisecond) // phase=500ms, no tx
	timer.IndicateConsistent()                   // c=1 now, c >= k=1

	// Cross txTime — should be suppressed because c >= k.
	if timer.HandleTimeTick(300 * time.Millisecond) {
		t.Error("should suppress transmission when c >= k")
	}
}

func TestTrickleTimer_ConsistencyCounter_NoSuppression(t *testing.T) {
	// k=0 means no suppression (infinite k).
	timer := NewTrickleTimer(TrickleTimerConfig{
		IMin:   1 * time.Second,
		IMax:   4 * time.Second,
		K:      0,
		RandFn: deterministicRandFn(0.5),
	})
	timer.Start()

	// Even with many IndicateConsistent, k=0 means always transmit.
	for i := 0; i < 100; i++ {
		timer.IndicateConsistent()
	}

	timer.HandleTimeTick(500 * time.Millisecond)
	if !timer.HandleTimeTick(300 * time.Millisecond) {
		t.Error("k=0 should never suppress transmission")
	}
}

func TestTrickleTimer_PlainTimerMode(t *testing.T) {
	timer := NewTrickleTimer(TrickleTimerConfig{
		IMin:   1 * time.Second,
		IMax:   4 * time.Second,
		Mode:   TrickleModePlainTimer,
		RandFn: deterministicRandFn(0.5),
	})
	timer.Start()

	// In plain timer mode, interval should NOT double.
	timer.HandleTimeTick(1100 * time.Millisecond)
	if timer.GetInterval() != 1*time.Second {
		t.Errorf("plain mode: after first interval, interval = %v, want 1s", timer.GetInterval())
	}

	timer.HandleTimeTick(1100 * time.Millisecond)
	if timer.GetInterval() != 1*time.Second {
		t.Errorf("plain mode: after second interval, interval = %v, want 1s", timer.GetInterval())
	}
}

func TestTrickleTimer_PlainTimerMode_AlwaysTransmits(t *testing.T) {
	// In plain timer mode, consistency counter is ignored.
	timer := NewTrickleTimer(TrickleTimerConfig{
		IMin:   1 * time.Second,
		IMax:   4 * time.Second,
		K:      1,
		Mode:   TrickleModePlainTimer,
		RandFn: deterministicRandFn(0.5),
	})
	timer.Start()

	timer.IndicateConsistent() // c=1 >= k=1, but plain mode ignores it

	timer.HandleTimeTick(500 * time.Millisecond)
	if !timer.HandleTimeTick(300 * time.Millisecond) {
		t.Error("plain timer mode should always transmit regardless of consistency counter")
	}
}

func TestTrickleTimer_SetIntervalMax(t *testing.T) {
	timer := NewTrickleTimer(TrickleTimerConfig{
		IMin:   1 * time.Second,
		IMax:   8 * time.Second,
		RandFn: deterministicRandFn(0.5),
	})
	timer.Start()

	// Double to 2s, then 4s.
	timer.HandleTimeTick(1100 * time.Millisecond)
	timer.HandleTimeTick(2100 * time.Millisecond)
	if timer.GetInterval() != 4*time.Second {
		t.Fatalf("interval = %v, want 4s", timer.GetInterval())
	}

	// Reduce iMax to 3s — interval should be clamped.
	timer.SetIntervalMax(3 * time.Second)
	if timer.GetInterval() != 3*time.Second {
		t.Errorf("after SetIntervalMax(3s): interval = %v, want 3s", timer.GetInterval())
	}
}

func TestTrickleTimer_HandleTimeTick_WhenStopped(t *testing.T) {
	timer := NewTrickleTimer(TrickleTimerConfig{
		IMin:   1 * time.Second,
		IMax:   4 * time.Second,
		RandFn: deterministicRandFn(0.5),
	})

	if timer.HandleTimeTick(1 * time.Second) {
		t.Error("stopped timer should never return true from HandleTimeTick")
	}
}

func TestTrickleTimer_MultipleTransmissions(t *testing.T) {
	// Verify we get a transmission in each period.
	timer := NewTrickleTimer(TrickleTimerConfig{
		IMin:   1 * time.Second,
		IMax:   2 * time.Second,
		RandFn: deterministicRandFn(0.5),
	})
	timer.Start()

	txCount := 0

	// Run for 10 seconds in 100ms ticks.
	for elapsed := time.Duration(0); elapsed < 10*time.Second; elapsed += 100 * time.Millisecond {
		if timer.HandleTimeTick(100 * time.Millisecond) {
			txCount++
		}
	}

	// With iMax=2s, after doubling from 1s->2s we stay at 2s.
	// ~1 transmit per period. With 10s total and periods of ~2s,
	// expect roughly 5 transmissions.
	if txCount < 3 || txCount > 8 {
		t.Errorf("txCount = %d, expected roughly 4-6 over 10s with 2s periods", txCount)
	}
}

func TestTrickleTimer_ConsistencyCounterResetsOnNewPeriod(t *testing.T) {
	timer := NewTrickleTimer(TrickleTimerConfig{
		IMin:   1 * time.Second,
		IMax:   1 * time.Second, // fixed interval for predictability
		K:      1,
		RandFn: deterministicRandFn(0.5),
	})
	timer.Start()

	// Period 1: suppress.
	timer.IndicateConsistent() // c=1 >= k=1
	timer.HandleTimeTick(500 * time.Millisecond)
	if timer.HandleTimeTick(300 * time.Millisecond) {
		t.Error("period 1: should suppress when c >= k")
	}

	// Complete period 1 — counter resets.
	timer.HandleTimeTick(300 * time.Millisecond)

	// Period 2: no IndicateConsistent, so c=0 < k=1.
	timer.HandleTimeTick(500 * time.Millisecond)
	if !timer.HandleTimeTick(300 * time.Millisecond) {
		t.Error("period 2: should transmit when c < k after period reset")
	}
}
