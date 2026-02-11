// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package csl

import (
	"testing"
	"time"

	"github.com/hilli/gothread/mac/types"
)

// --------------------------------------------------------------------------
// NeighborInfo tests
// --------------------------------------------------------------------------

func TestNeighborInfoIsCslSynchronized(t *testing.T) {
	tests := []struct {
		name   string
		synced bool
		period uint16
		want   bool
	}{
		{"synced with period", true, 100, true},
		{"synced no period", true, 0, false},
		{"not synced with period", false, 100, false},
		{"not synced no period", false, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &NeighborInfo{
				CslSynchronized: tt.synced,
				CslPeriod:       tt.period,
			}
			if got := n.IsCslSynchronized(); got != tt.want {
				t.Errorf("IsCslSynchronized() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNeighborInfoTxAttempts(t *testing.T) {
	n := &NeighborInfo{}

	if n.CslTxAttempts != 0 {
		t.Errorf("initial attempts = %d, want 0", n.CslTxAttempts)
	}

	n.IncrementCslTxAttempts()
	n.IncrementCslTxAttempts()
	n.IncrementCslTxAttempts()
	if n.CslTxAttempts != 3 {
		t.Errorf("after 3 increments = %d, want 3", n.CslTxAttempts)
	}

	n.ResetCslTxAttempts()
	if n.CslTxAttempts != 0 {
		t.Errorf("after reset = %d, want 0", n.CslTxAttempts)
	}
}

func TestNeighborInfoMaxAttempts(t *testing.T) {
	n := &NeighborInfo{CslSynchronized: true, CslPeriod: 100}

	for range MaxCslTriggeredTxAttempts {
		n.IncrementCslTxAttempts()
	}

	if n.CslTxAttempts < MaxCslTriggeredTxAttempts {
		t.Errorf("attempts = %d, want >= %d", n.CslTxAttempts, MaxCslTriggeredTxAttempts)
	}

	// Simulate the behavior: after max attempts, mark out of sync.
	if n.CslTxAttempts >= MaxCslTriggeredTxAttempts {
		n.CslSynchronized = false
		n.ResetCslTxAttempts()
	}

	if n.IsCslSynchronized() {
		t.Error("expected not synchronized after max attempts")
	}
	if n.CslTxAttempts != 0 {
		t.Errorf("expected 0 attempts after reset, got %d", n.CslTxAttempts)
	}
}

// --------------------------------------------------------------------------
// Scheduler tests
// --------------------------------------------------------------------------

func makeAddr(b byte) types.ExtAddress {
	return types.ExtAddress{b, 0, 0, 0, 0, 0, 0, 0}
}

func TestSchedulerAddRemove(t *testing.T) {
	s := NewScheduler()

	info := &NeighborInfo{ExtAddr: makeAddr(1)}
	if err := s.Add(info); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if s.Count() != 1 {
		t.Errorf("count = %d, want 1", s.Count())
	}

	// Duplicate add.
	if err := s.Add(info); err != ErrAlreadyExists {
		t.Errorf("expected ErrAlreadyExists, got %v", err)
	}

	// Get.
	got := s.Get(makeAddr(1))
	if got != info {
		t.Error("Get returned wrong info")
	}

	// Get non-existent.
	if s.Get(makeAddr(2)) != nil {
		t.Error("expected nil for non-existent")
	}

	// Remove.
	if err := s.Remove(makeAddr(1)); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}
	if s.Count() != 0 {
		t.Errorf("count = %d after remove, want 0", s.Count())
	}

	// Remove non-existent.
	if err := s.Remove(makeAddr(1)); err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSchedulerUpdate(t *testing.T) {
	s := NewScheduler()

	info := &NeighborInfo{ExtAddr: makeAddr(1), CslPeriod: 100}
	_ = s.Add(info)

	updated := &NeighborInfo{ExtAddr: makeAddr(1), CslPeriod: 200}
	if err := s.Update(updated); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	got := s.Get(makeAddr(1))
	if got.CslPeriod != 200 {
		t.Errorf("period = %d, want 200", got.CslPeriod)
	}

	// Update non-existent.
	notExist := &NeighborInfo{ExtAddr: makeAddr(99)}
	if err := s.Update(notExist); err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSchedulerClear(t *testing.T) {
	s := NewScheduler()
	for i := byte(0); i < 5; i++ {
		_ = s.Add(&NeighborInfo{ExtAddr: makeAddr(i)})
	}
	if s.Count() != 5 {
		t.Fatalf("count = %d, want 5", s.Count())
	}

	s.Clear()
	if s.Count() != 0 {
		t.Errorf("count = %d after clear, want 0", s.Count())
	}
}

// --------------------------------------------------------------------------
// Delay calculation tests
// --------------------------------------------------------------------------

func TestGetNextTransmissionDelayBasic(t *testing.T) {
	// Child with CSL period = 100 (100 * 160µs = 16000µs per period).
	// Phase = 50 (50 * 160µs = 8000µs offset from LastRx).
	// LastRxTimestamp = 1_000_000 µs.
	// radioNow = 1_100_000 µs.
	// aheadUs = 0.
	info := &NeighborInfo{
		CslSynchronized: true,
		CslPeriod:       100,
		CslPhase:        50,
		LastRxTimestamp: 1_000_000,
		ExtAddr:         makeAddr(1),
	}

	radioNow := uint64(1_100_000)
	aheadUs := uint32(0)

	delayUs, delayFromLastRx, err := GetNextTransmissionDelay(info, radioNow, aheadUs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// periodInUs = 100 * 160 = 16000.
	// firstTxWindow = 1_000_000 + 50*160 = 1_008_000.
	// 1_008_000 % 16_000 = 0 (since 63*16000 = 1_008_000).
	// nextTxWindow = 1_100_000 - (1_100_000 % 16000) + 0
	//             = 1_100_000 - 12000 + 0 = 1_088_000.
	// Since 1_088_000 < 1_100_000 + 0, advance: 1_088_000 + 16000 = 1_104_000.
	// delayUs = 1_104_000 - 1_100_000 - 0 = 4000.
	// delayFromLastRx = 1_104_000 - 1_000_000 = 104_000.

	if delayUs != 4000 {
		t.Errorf("delayUs = %d, want 4000", delayUs)
	}
	if delayFromLastRx != 104000 {
		t.Errorf("delayFromLastRx = %d, want 104000", delayFromLastRx)
	}
}

func TestGetNextTransmissionDelayWithAhead(t *testing.T) {
	info := &NeighborInfo{
		CslSynchronized: true,
		CslPeriod:       100,
		CslPhase:        0,
		LastRxTimestamp: 0,
		ExtAddr:         makeAddr(1),
	}

	radioNow := uint64(0)
	aheadUs := uint32(1000) // 1ms ahead

	delayUs, _, err := GetNextTransmissionDelay(info, radioNow, aheadUs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// periodInUs = 16000.
	// firstTxWindow = 0.
	// nextTxWindow = 0 - 0 + 0 = 0.
	// 0 < 0 + 1000, advance: 16000.
	// delayUs = 16000 - 0 - 1000 = 15000.
	if delayUs != 15000 {
		t.Errorf("delayUs = %d, want 15000", delayUs)
	}
}

func TestGetNextTransmissionDelayNotSynchronized(t *testing.T) {
	tests := []struct {
		name string
		info *NeighborInfo
	}{
		{"not synced", &NeighborInfo{CslSynchronized: false, CslPeriod: 100}},
		{"zero period", &NeighborInfo{CslSynchronized: true, CslPeriod: 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := GetNextTransmissionDelay(tt.info, 0, 0)
			if err != ErrNotSynchronized {
				t.Errorf("expected ErrNotSynchronized, got %v", err)
			}
		})
	}
}

func TestGetNextTransmissionDelayExactWindow(t *testing.T) {
	// Radio is exactly at a CSL window boundary.
	info := &NeighborInfo{
		CslSynchronized: true,
		CslPeriod:       100,
		CslPhase:        0,
		LastRxTimestamp: 0,
		ExtAddr:         makeAddr(1),
	}

	// radioNow is exactly at a window (multiple of 16000).
	radioNow := uint64(16000)
	aheadUs := uint32(0)

	delayUs, _, err := GetNextTransmissionDelay(info, radioNow, aheadUs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// nextTxWindow = 16000 - 0 + 0 = 16000.
	// 16000 >= 16000 + 0, so no advance.
	// delayUs = 16000 - 16000 - 0 = 0.
	if delayUs != 0 {
		t.Errorf("delayUs = %d, want 0 (exact window)", delayUs)
	}
}

// --------------------------------------------------------------------------
// NeighborInfo field tests
// --------------------------------------------------------------------------

func TestNeighborInfoFields(t *testing.T) {
	now := time.Now()
	n := &NeighborInfo{
		CslTxAttempts:   2,
		CslSynchronized: true,
		CslChannel:      15,
		CslTimeout:      300,
		CslPeriod:       200,
		CslPhase:        50,
		CslLastHeard:    now,
		LastRxTimestamp: 12345678,
		ExtAddr:         types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11},
	}

	if n.CslChannel != 15 {
		t.Errorf("CslChannel = %d, want 15", n.CslChannel)
	}
	if n.CslTimeout != 300 {
		t.Errorf("CslTimeout = %d, want 300", n.CslTimeout)
	}
	if !n.CslLastHeard.Equal(now) {
		t.Error("CslLastHeard mismatch")
	}
	if n.LastRxTimestamp != 12345678 {
		t.Errorf("LastRxTimestamp = %d, want 12345678", n.LastRxTimestamp)
	}
}
