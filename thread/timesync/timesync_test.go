// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package timesync

import "testing"

// ===========================================================================
// serialGreater tests
// ===========================================================================

func TestSerialGreater(t *testing.T) {
	tests := []struct {
		a, b uint8
		want bool
	}{
		{1, 0, true},
		{0, 1, false},
		{0, 0, false},
		{255, 254, true},
		{254, 255, false},
		// Wraparound: 0 is "after" 255 in serial-number arithmetic.
		{0, 255, true},
		{1, 255, true},
		{128, 0, false}, // 128-0 = 128 which is -128 as int8, not > 0
		{127, 0, true},  // 127-0 = 127 which is > 0
		{200, 100, true},
		{100, 200, false},
	}
	for _, tt := range tests {
		got := serialGreater(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("serialGreater(%d, %d) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

// ===========================================================================
// NewService tests
// ===========================================================================

func TestNewService_Defaults(t *testing.T) {
	s := NewService()

	if s.GetStatus() != StatusUnsynchronized {
		t.Error("expected StatusUnsynchronized initially")
	}
	if s.GetPeriod() != defaultPeriod {
		t.Errorf("expected default period %d, got %d", defaultPeriod, s.GetPeriod())
	}
	if s.GetThreshold() != defaultThreshold {
		t.Errorf("expected default threshold %d, got %d", defaultThreshold, s.GetThreshold())
	}
	if s.GetSequence() != 0 {
		t.Errorf("expected sequence 0, got %d", s.GetSequence())
	}
	if s.IsTimeSyncRequired() {
		t.Error("expected time sync not required initially")
	}
}

func TestNewService_WithOptions(t *testing.T) {
	s := NewService(
		WithPeriod(60),
		WithThreshold(240),
	)

	if s.GetPeriod() != 60 {
		t.Errorf("expected period 60, got %d", s.GetPeriod())
	}
	if s.GetThreshold() != 240 {
		t.Errorf("expected threshold 240, got %d", s.GetThreshold())
	}
}

func TestNewService_WithZeroOptionsIgnored(t *testing.T) {
	s := NewService(
		WithPeriod(0),
		WithThreshold(0),
	)

	if s.GetPeriod() != defaultPeriod {
		t.Errorf("expected default period, got %d", s.GetPeriod())
	}
	if s.GetThreshold() != defaultThreshold {
		t.Errorf("expected default threshold, got %d", s.GetThreshold())
	}
}

// ===========================================================================
// Enable / Disable tests
// ===========================================================================

func TestService_EnableDisable(t *testing.T) {
	s := NewService()

	// The service doesn't expose enabled directly, but behavior changes.
	// HandleTimeSyncIE should be a no-op when disabled.
	s.HandleTimeSyncIE(1, 1000000, 100)
	if s.GetStatus() != StatusUnsynchronized {
		t.Error("expected unsynchronized when disabled")
	}

	s.Enable()
	s.HandleTimeSyncIE(1, 1000000, 100)
	if s.GetStatus() != StatusSynchronized {
		t.Error("expected synchronized after enable + IE")
	}

	s.Disable()
	if s.GetStatus() != StatusUnsynchronized {
		t.Error("expected unsynchronized after disable")
	}
	if s.IsTimeSyncRequired() {
		t.Error("expected time sync not required after disable")
	}
}

// ===========================================================================
// HandleTimeSyncIE tests
// ===========================================================================

func TestService_HandleTimeSyncIE_Basic(t *testing.T) {
	s := NewService()
	s.Enable()

	s.HandleTimeSyncIE(1, 5000000, 1000)

	nt, status := s.GetNetworkTime()
	if status != StatusSynchronized {
		t.Error("expected synchronized")
	}
	if nt != 5000000 {
		t.Errorf("expected network time 5000000, got %d", nt)
	}
	if s.GetSequence() != 1 {
		t.Errorf("expected sequence 1, got %d", s.GetSequence())
	}
}

func TestService_HandleTimeSyncIE_NewerSequence(t *testing.T) {
	s := NewService()
	s.Enable()

	// First sync at sequence 5.
	s.HandleTimeSyncIE(5, 1000000, 100)
	if s.GetSequence() != 5 {
		t.Errorf("expected sequence 5, got %d", s.GetSequence())
	}

	// Newer sequence 10 updates.
	s.HandleTimeSyncIE(10, 2000000, 200)
	nt, _ := s.GetNetworkTime()
	if nt != 2000000 {
		t.Errorf("expected network time 2000000, got %d", nt)
	}
	if s.GetSequence() != 10 {
		t.Errorf("expected sequence 10, got %d", s.GetSequence())
	}
}

func TestService_HandleTimeSyncIE_OlderSequenceIgnored(t *testing.T) {
	s := NewService()
	s.Enable()

	s.HandleTimeSyncIE(10, 1000000, 100)

	// Older sequence 5 should be ignored.
	s.HandleTimeSyncIE(5, 9999999, 200)
	nt, _ := s.GetNetworkTime()
	if nt != 1000000 {
		t.Errorf("expected network time unchanged at 1000000, got %d", nt)
	}
	if s.GetSequence() != 10 {
		t.Errorf("expected sequence 10, got %d", s.GetSequence())
	}
}

func TestService_HandleTimeSyncIE_EqualSequenceIgnored(t *testing.T) {
	s := NewService()
	s.Enable()

	s.HandleTimeSyncIE(5, 1000000, 100)
	s.HandleTimeSyncIE(5, 9999999, 200) // same sequence — ignored

	nt, _ := s.GetNetworkTime()
	if nt != 1000000 {
		t.Errorf("expected network time 1000000, got %d", nt)
	}
}

func TestService_HandleTimeSyncIE_SequenceWraparound(t *testing.T) {
	s := NewService()
	s.Enable()

	// Manually set sequence to 254 via the lock so we can test wraparound.
	s.mu.Lock()
	s.sequence = 254
	s.status = StatusSynchronized
	s.networkTime = 1000000
	s.mu.Unlock()

	// Sequence 255 is one ahead of 254 — should be accepted.
	s.HandleTimeSyncIE(255, 1500000, 150)
	if s.GetSequence() != 255 {
		t.Errorf("expected sequence 255, got %d", s.GetSequence())
	}

	// Sequence 0 wraps around and is "newer" than 255 in serial arithmetic.
	// int8(0 - 255) = int8(1) = 1 > 0, so 0 > 255.
	s.HandleTimeSyncIE(0, 2000000, 200)
	if s.GetSequence() != 0 {
		t.Errorf("expected sequence 0 after wraparound, got %d", s.GetSequence())
	}
	nt, _ := s.GetNetworkTime()
	if nt != 2000000 {
		t.Errorf("expected network time 2000000 after wraparound, got %d", nt)
	}

	// Sequence 1 is after 0 — should also work.
	s.HandleTimeSyncIE(1, 3000000, 300)
	if s.GetSequence() != 1 {
		t.Errorf("expected sequence 1, got %d", s.GetSequence())
	}
}

func TestService_HandleTimeSyncIE_ClearsRequired(t *testing.T) {
	s := NewService()
	s.Enable()
	s.SetTimeSyncRequired(true)

	s.HandleTimeSyncIE(1, 1000000, 100)

	if s.IsTimeSyncRequired() {
		t.Error("expected time sync required cleared after receiving IE")
	}
}

func TestService_HandleTimeSyncIE_DisabledNoOp(t *testing.T) {
	s := NewService()
	// Not enabled — should be no-op.
	s.HandleTimeSyncIE(1, 1000000, 100)

	if s.GetStatus() != StatusUnsynchronized {
		t.Error("expected unsynchronized when disabled")
	}
	if s.GetSequence() != 0 {
		t.Errorf("expected sequence 0, got %d", s.GetSequence())
	}
}

// ===========================================================================
// HandleTimer tests
// ===========================================================================

func TestService_HandleTimer_SyncLoss(t *testing.T) {
	s := NewService(WithThreshold(10)) // 10 seconds
	s.Enable()

	// Synchronize at local time 1000 ms.
	s.HandleTimeSyncIE(1, 5000000, 1000)
	if s.GetStatus() != StatusSynchronized {
		t.Fatal("expected synchronized")
	}

	// At 5000 ms (4s elapsed) — still synchronized.
	s.HandleTimer(5000)
	if s.GetStatus() != StatusSynchronized {
		t.Error("expected still synchronized at 5s")
	}

	// At 11001 ms (10.001s elapsed) — threshold is 10s = 10000ms, exceeded.
	s.HandleTimer(11001)
	if s.GetStatus() != StatusUnsynchronized {
		t.Error("expected unsynchronized after threshold exceeded")
	}
}

func TestService_HandleTimer_SyncRequired(t *testing.T) {
	s := NewService(WithPeriod(5), WithThreshold(120)) // 5s period
	s.Enable()

	s.HandleTimeSyncIE(1, 5000000, 1000)

	// At 4000 ms (3s elapsed) — not yet time.
	s.HandleTimer(4000)
	if s.IsTimeSyncRequired() {
		t.Error("expected not required at 3s")
	}

	// At 6001 ms (5.001s elapsed) — period exceeded.
	s.HandleTimer(6001)
	if !s.IsTimeSyncRequired() {
		t.Error("expected time sync required after period")
	}
}

func TestService_HandleTimer_UnsynchronizedNoOp(t *testing.T) {
	s := NewService()
	s.Enable()

	// Not yet synchronized — HandleTimer should be a no-op.
	s.HandleTimer(999999)
	if s.GetStatus() != StatusUnsynchronized {
		t.Error("expected still unsynchronized")
	}
	if s.IsTimeSyncRequired() {
		t.Error("expected not required when unsynchronized")
	}
}

func TestService_HandleTimer_DisabledNoOp(t *testing.T) {
	s := NewService()
	// Disabled — HandleTimer should be a no-op.
	s.HandleTimer(999999)
	if s.GetStatus() != StatusUnsynchronized {
		t.Error("expected unsynchronized when disabled")
	}
}

// ===========================================================================
// GetTimeSyncIEData tests
// ===========================================================================

func TestService_GetTimeSyncIEData(t *testing.T) {
	s := NewService()
	s.Enable()

	s.HandleTimeSyncIE(42, 12345678, 1000)

	seq, nt := s.GetTimeSyncIEData()
	if seq != 42 {
		t.Errorf("expected sequence 42, got %d", seq)
	}
	if nt != 12345678 {
		t.Errorf("expected network time 12345678, got %d", nt)
	}
}

// ===========================================================================
// IncrementSequence tests
// ===========================================================================

func TestService_IncrementSequence(t *testing.T) {
	s := NewService()

	if s.GetSequence() != 0 {
		t.Fatalf("expected initial sequence 0, got %d", s.GetSequence())
	}

	s.IncrementSequence()
	if s.GetSequence() != 1 {
		t.Errorf("expected sequence 1, got %d", s.GetSequence())
	}

	// Test wraparound.
	s.mu.Lock()
	s.sequence = 255
	s.mu.Unlock()

	s.IncrementSequence()
	if s.GetSequence() != 0 {
		t.Errorf("expected sequence 0 after wraparound, got %d", s.GetSequence())
	}
}

// ===========================================================================
// SetTimeSyncRequired tests
// ===========================================================================

func TestService_SetTimeSyncRequired(t *testing.T) {
	s := NewService()

	s.SetTimeSyncRequired(true)
	if !s.IsTimeSyncRequired() {
		t.Error("expected required")
	}

	s.SetTimeSyncRequired(false)
	if s.IsTimeSyncRequired() {
		t.Error("expected not required")
	}
}

// ===========================================================================
// Callback tests
// ===========================================================================

func TestService_Callback(t *testing.T) {
	var calledWith int64
	called := false

	s := NewService(WithCallback(func(networkTime int64) {
		called = true
		calledWith = networkTime
	}))
	s.Enable()

	s.HandleTimeSyncIE(1, 7777777, 100)

	if !called {
		t.Fatal("expected callback to be called")
	}
	if calledWith != 7777777 {
		t.Errorf("expected callback with 7777777, got %d", calledWith)
	}
}

func TestService_Callback_NotCalledOnOlderSequence(t *testing.T) {
	called := false
	s := NewService(WithCallback(func(_ int64) {
		called = true
	}))
	s.Enable()

	s.HandleTimeSyncIE(10, 1000000, 100)
	called = false // reset

	s.HandleTimeSyncIE(5, 2000000, 200) // older — ignored
	if called {
		t.Error("callback should not be called for older sequence")
	}
}

// ===========================================================================
// Status String tests
// ===========================================================================

func TestStatus_String(t *testing.T) {
	if StatusUnsynchronized.String() != "Unsynchronized" {
		t.Errorf("unexpected: %s", StatusUnsynchronized.String())
	}
	if StatusSynchronized.String() != "Synchronized" {
		t.Errorf("unexpected: %s", StatusSynchronized.String())
	}
	if Status(99).String() != "Unknown" {
		t.Errorf("unexpected: %s", Status(99).String())
	}
}

// ===========================================================================
// elapsedMs tests
// ===========================================================================

func TestElapsedMs(t *testing.T) {
	// Normal case.
	if elapsedMs(100, 500) != 400 {
		t.Error("expected 400")
	}
	// Wraparound: start near max, now near zero.
	// 0xFFFFFFFF - 0xFFFFFFF0 + 0x10 = 0x1F + 1 = 32
	if elapsedMs(0xFFFFFFF0, 0x10) != 32 {
		t.Errorf("expected 32 for wraparound, got %d", elapsedMs(0xFFFFFFF0, 0x10))
	}
}

// ===========================================================================
// Full lifecycle test
// ===========================================================================

func TestService_FullLifecycle(t *testing.T) {
	s := NewService(WithPeriod(10), WithThreshold(30))

	// 1. Initially disabled and unsynchronized.
	if s.GetStatus() != StatusUnsynchronized {
		t.Fatal("expected unsynchronized")
	}

	// 2. Enable.
	s.Enable()

	// 3. Receive first Time Sync IE.
	s.HandleTimeSyncIE(1, 1000000, 100)
	if s.GetStatus() != StatusSynchronized {
		t.Fatal("expected synchronized")
	}

	// 4. Time passes within period — still synced, not required.
	s.HandleTimer(5000) // 4.9s elapsed
	if s.GetStatus() != StatusSynchronized {
		t.Error("expected still synchronized")
	}
	if s.IsTimeSyncRequired() {
		t.Error("expected not required within period")
	}

	// 5. Period elapses — sync required.
	s.HandleTimer(10200) // 10.1s elapsed
	if !s.IsTimeSyncRequired() {
		t.Error("expected sync required after period")
	}

	// 6. Receive newer IE — clears required, resets timer.
	s.HandleTimeSyncIE(2, 2000000, 10200)
	if s.IsTimeSyncRequired() {
		t.Error("expected required cleared after new IE")
	}

	// 7. No sync for too long — loses sync.
	s.HandleTimer(10200 + 30001) // 30.001s since last sync
	if s.GetStatus() != StatusUnsynchronized {
		t.Error("expected unsynchronized after threshold")
	}

	// 8. Disable.
	s.Disable()
	if s.GetStatus() != StatusUnsynchronized {
		t.Error("expected unsynchronized after disable")
	}
}
