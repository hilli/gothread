// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package wakeup

import "testing"

// --------------------------------------------------------------------------
// Config tests
// --------------------------------------------------------------------------

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{"valid", Config{IntervalUs: 1000, DurationMs: 5000}, false},
		{"zero interval", Config{IntervalUs: 0, DurationMs: 5000}, true},
		{"zero duration valid", Config{IntervalUs: 1000, DurationMs: 0}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// --------------------------------------------------------------------------
// Scheduler constructor tests
// --------------------------------------------------------------------------

func TestNewScheduler(t *testing.T) {
	s := NewScheduler(5, 4)
	if s.connectionRetryInterval != 5 {
		t.Errorf("retryInterval = %d, want 5", s.connectionRetryInterval)
	}
	if s.connectionRetryCount != 4 {
		t.Errorf("retryCount = %d, want 4", s.connectionRetryCount)
	}
	if s.IsRunning() {
		t.Error("expected not running")
	}
}

func TestNewDefaultScheduler(t *testing.T) {
	s := NewDefaultScheduler()
	if s.connectionRetryInterval != DefaultConnectionRetryInterval {
		t.Errorf("retryInterval = %d, want %d", s.connectionRetryInterval, DefaultConnectionRetryInterval)
	}
	if s.connectionRetryCount != DefaultConnectionRetryCount {
		t.Errorf("retryCount = %d, want %d", s.connectionRetryCount, DefaultConnectionRetryCount)
	}
}

// --------------------------------------------------------------------------
// Start/Stop tests
// --------------------------------------------------------------------------

func TestStartStop(t *testing.T) {
	s := NewDefaultScheduler()

	if err := s.Start(1000, 5000, 0); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if !s.IsRunning() {
		t.Error("expected running after Start")
	}

	// Double start should fail.
	if err := s.Start(1000, 5000, 0); err != ErrInvalidState {
		t.Errorf("expected ErrInvalidState on double start, got %v", err)
	}

	s.Stop()
	if s.IsRunning() {
		t.Error("expected not running after Stop")
	}

	// Can start again after stop.
	if err := s.Start(2000, 3000, 100); err != nil {
		t.Fatalf("Restart failed: %v", err)
	}
	if !s.IsRunning() {
		t.Error("expected running after restart")
	}
}

func TestStartInvalidInterval(t *testing.T) {
	s := NewDefaultScheduler()
	if err := s.Start(0, 5000, 0); err != ErrInvalidConfig {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

// --------------------------------------------------------------------------
// GetConnectionWindowUs tests
// --------------------------------------------------------------------------

func TestGetConnectionWindowUs(t *testing.T) {
	tests := []struct {
		name          string
		intervalUs    uint16
		retryInterval uint8
		retryCount    uint8
		wantWindowUs  uint32
	}{
		{
			"defaults",
			1000,
			DefaultConnectionRetryInterval,
			DefaultConnectionRetryCount,
			1000 * uint32(DefaultConnectionRetryInterval) * uint32(DefaultConnectionRetryCount),
		},
		{
			"custom",
			2000,
			5,
			2,
			2000 * 5 * 2,
		},
		{
			"zero interval",
			0,
			4,
			3,
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScheduler(tt.retryInterval, tt.retryCount)
			s.intervalUs = tt.intervalUs
			got := s.GetConnectionWindowUs()
			if got != tt.wantWindowUs {
				t.Errorf("GetConnectionWindowUs() = %d, want %d", got, tt.wantWindowUs)
			}
		})
	}
}

// --------------------------------------------------------------------------
// GetTxEndTimeUs tests
// --------------------------------------------------------------------------

func TestGetTxEndTimeUs(t *testing.T) {
	s := NewDefaultScheduler()
	nowUs := uint64(1_000_000)
	intervalUs := uint16(1000)
	durationMs := uint16(5000)

	_ = s.Start(intervalUs, durationMs, nowUs)

	// txEndTime = nowUs + durationMs*1000 + intervalUs
	//           = 1_000_000 + 5_000_000 + 1000 = 6_001_000
	want := nowUs + uint64(durationMs)*1000 + uint64(intervalUs)
	if s.GetTxEndTimeUs() != want {
		t.Errorf("GetTxEndTimeUs() = %d, want %d", s.GetTxEndTimeUs(), want)
	}
}

// --------------------------------------------------------------------------
// ScheduleNext tests
// --------------------------------------------------------------------------

func TestScheduleNextNotRunning(t *testing.T) {
	s := NewDefaultScheduler()
	delay, ok := s.ScheduleNext(0)
	if ok {
		t.Error("expected ok=false when not running")
	}
	if delay != 0 {
		t.Errorf("delay = %d, want 0", delay)
	}
}

func TestScheduleNextSequence(t *testing.T) {
	s := NewDefaultScheduler()
	intervalUs := uint16(1000)
	durationMs := uint16(5) // 5ms = 5000µs
	nowUs := uint64(0)

	_ = s.Start(intervalUs, durationMs, nowUs)
	// txEndTime = 0 + 5000 + 1000 = 6000

	// Schedule frames one by one.
	var totalDelay uint64
	count := 0
	for {
		delay, ok := s.ScheduleNext(nowUs + totalDelay)
		if !ok {
			break
		}
		totalDelay += delay + uint64(intervalUs)
		count++
	}

	if count == 0 {
		t.Error("expected at least one frame scheduled")
	}
	if s.IsRunning() {
		t.Error("expected not running after sequence completes")
	}
}

func TestScheduleNextStopsAtEnd(t *testing.T) {
	s := NewDefaultScheduler()
	_ = s.Start(1000, 2, 0) // 2ms duration, 1000µs interval
	// txEndTime = 0 + 2000 + 1000 = 3000

	// First call: txTime advances to 0 + 1000 = 1000. 1000 < 3000, ok.
	delay1, ok1 := s.ScheduleNext(0)
	if !ok1 {
		t.Fatal("expected first schedule to succeed")
	}
	if delay1 != 1000 {
		t.Errorf("delay1 = %d, want 1000", delay1)
	}

	// Second call: txTime advances to 1000 + 1000 = 2000. 2000 < 3000, ok.
	delay2, ok2 := s.ScheduleNext(1000)
	if !ok2 {
		t.Fatal("expected second schedule to succeed")
	}
	if delay2 != 1000 {
		t.Errorf("delay2 = %d, want 1000", delay2)
	}

	// Third call: txTime would advance to 2000 + 1000 = 3000. 3000 >= 3000, stop.
	_, ok3 := s.ScheduleNext(2000)
	if ok3 {
		t.Error("expected third schedule to stop the sequence")
	}
	if s.IsRunning() {
		t.Error("expected not running after end")
	}
}

func TestScheduleNextCatchesUp(t *testing.T) {
	s := NewDefaultScheduler()
	_ = s.Start(1000, 10, 0) // 10ms duration, 1000µs interval
	// txEndTime = 0 + 10000 + 1000 = 11000

	// If nowUs has jumped far ahead, nextTx should catch up.
	delay, ok := s.ScheduleNext(5000)
	if !ok {
		t.Fatal("expected schedule to succeed")
	}
	// nextTx = 0 + 1000 = 1000, but 1000 < 5000, so nextTx = 5000.
	// delay = 5000 - 5000 = 0.
	if delay != 0 {
		t.Errorf("delay = %d, want 0 (catch up)", delay)
	}
}

// --------------------------------------------------------------------------
// GetIntervalUs test
// --------------------------------------------------------------------------

func TestGetIntervalUs(t *testing.T) {
	s := NewDefaultScheduler()
	_ = s.Start(2500, 100, 0)
	if s.GetIntervalUs() != 2500 {
		t.Errorf("GetIntervalUs() = %d, want 2500", s.GetIntervalUs())
	}
}
