// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package datapoll

import (
	"testing"
	"time"
)

// ============================================================================
// Handler tests
// ============================================================================

type mockHandlerCallbacks struct {
	handleDataPollCount    int
	handleDataPollAddr     uint16
	handleDataPollReturn   bool
	handleFrameChangeCount int
	handleFrameChangeAddr  uint16
	handleFrameChangetype  FrameChange
}

func (m *mockHandlerCallbacks) HandleDataPoll(childShortAddr uint16) bool {
	m.handleDataPollCount++
	m.handleDataPollAddr = childShortAddr
	return m.handleDataPollReturn
}

func (m *mockHandlerCallbacks) HandleFrameChange(childShortAddr uint16, change FrameChange) {
	m.handleFrameChangeCount++
	m.handleFrameChangeAddr = childShortAddr
	m.handleFrameChangetype = change
}

func TestNewHandler(t *testing.T) {
	cb := &mockHandlerCallbacks{}
	h := NewHandler(cb)
	if h == nil {
		t.Fatal("NewHandler returned nil")
	}
}

func TestHandleDataPoll(t *testing.T) {
	cb := &mockHandlerCallbacks{handleDataPollReturn: true}
	h := NewHandler(cb)

	h.HandleDataPoll(0x1234)

	if cb.handleDataPollCount != 1 {
		t.Errorf("HandleDataPoll callback count = %d, want 1", cb.handleDataPollCount)
	}
	if cb.handleDataPollAddr != 0x1234 {
		t.Errorf("HandleDataPoll addr = 0x%04x, want 0x1234", cb.handleDataPollAddr)
	}
	if !h.GetFramePending(0x1234) {
		t.Error("child should have frame pending after poll with pending=true")
	}
}

func TestHandleDataPollNoPending(t *testing.T) {
	cb := &mockHandlerCallbacks{handleDataPollReturn: false}
	h := NewHandler(cb)

	h.HandleDataPoll(0x1234)

	if h.GetFramePending(0x1234) {
		t.Error("child should not have frame pending after poll with pending=false")
	}
}

func TestHandleDataPollNilCallbacks(t *testing.T) {
	h := NewHandler(nil)
	// Should not panic.
	h.HandleDataPoll(0x1234)
}

func TestSetFramePending(t *testing.T) {
	cb := &mockHandlerCallbacks{}
	h := NewHandler(cb)

	h.SetFramePending(0x1234, true)
	if !h.GetFramePending(0x1234) {
		t.Error("GetFramePending should return true after SetFramePending(true)")
	}

	h.SetFramePending(0x1234, false)
	if h.GetFramePending(0x1234) {
		t.Error("GetFramePending should return false after SetFramePending(false)")
	}
}

func TestGetFramePendingUnknownChild(t *testing.T) {
	cb := &mockHandlerCallbacks{}
	h := NewHandler(cb)

	if h.GetFramePending(0x9999) {
		t.Error("GetFramePending should return false for unknown child")
	}
}

func TestPurgeFrame(t *testing.T) {
	cb := &mockHandlerCallbacks{}
	h := NewHandler(cb)

	h.SetFramePending(0x1234, true)
	h.PurgeFrame(0x1234)

	if h.GetFramePending(0x1234) {
		t.Error("GetFramePending should return false after PurgeFrame")
	}
}

func TestClear(t *testing.T) {
	cb := &mockHandlerCallbacks{}
	h := NewHandler(cb)

	h.SetFramePending(0x1234, true)
	h.SetFramePending(0x5678, true)
	h.Clear()

	if h.GetFramePending(0x1234) || h.GetFramePending(0x5678) {
		t.Error("all children should be cleared")
	}
}

func TestFrameChangeConstants(t *testing.T) {
	if PurgeFrame != 0 {
		t.Errorf("PurgeFrame = %d, want 0", PurgeFrame)
	}
	if ReplaceFrame != 1 {
		t.Errorf("ReplaceFrame = %d, want 1", ReplaceFrame)
	}
}

// ============================================================================
// Sender tests
// ============================================================================

type mockSenderCallbacks struct {
	sendDataPollCount int
	sendDataPollErr   error
}

func (m *mockSenderCallbacks) SendDataPoll() error {
	m.sendDataPollCount++
	return m.sendDataPollErr
}

type mockSenderTimer struct {
	scheduledDelay time.Duration
	scheduledFn    func()
	scheduleCount  int
	cancelCount    int
}

func (mt *mockSenderTimer) schedule(delay time.Duration, fn func()) func() {
	mt.scheduledDelay = delay
	mt.scheduledFn = fn
	mt.scheduleCount++
	return func() {
		mt.cancelCount++
	}
}

func (mt *mockSenderTimer) fire() {
	if mt.scheduledFn != nil {
		fn := mt.scheduledFn
		mt.scheduledFn = nil
		fn()
	}
}

func TestNewSender(t *testing.T) {
	cb := &mockSenderCallbacks{}
	timer := &mockSenderTimer{}
	s := NewSender(cb, timer.schedule)

	if s.IsEnabled() {
		t.Error("new sender should not be enabled")
	}
	if s.GetPollPeriod() != 0 {
		t.Errorf("initial poll period = %d, want 0", s.GetPollPeriod())
	}
}

func TestStartStop(t *testing.T) {
	cb := &mockSenderCallbacks{}
	timer := &mockSenderTimer{}
	s := NewSender(cb, timer.schedule)

	s.Start()
	if !s.IsEnabled() {
		t.Error("sender should be enabled after Start")
	}
	if timer.scheduleCount < 1 {
		t.Error("timer should be scheduled after Start")
	}

	s.Stop()
	if s.IsEnabled() {
		t.Error("sender should not be enabled after Stop")
	}
}

func TestAttachMode(t *testing.T) {
	cb := &mockSenderCallbacks{}
	timer := &mockSenderTimer{}
	s := NewSender(cb, timer.schedule)

	s.SetAttachMode(true)
	s.Start()

	if s.GetPollPeriod() != AttachDataPollPeriod {
		t.Errorf("poll period in attach mode = %d, want %d", s.GetPollPeriod(), AttachDataPollPeriod)
	}

	s.SetAttachMode(false)
	if s.GetPollPeriod() == AttachDataPollPeriod {
		t.Error("poll period should change after exiting attach mode")
	}
}

func TestRetxMode(t *testing.T) {
	cb := &mockSenderCallbacks{}
	timer := &mockSenderTimer{}
	s := NewSender(cb, timer.schedule)

	s.Start()
	s.SetRetxMode(true)

	if s.GetPollPeriod() != RetxPollPeriod {
		t.Errorf("poll period in retx mode = %d, want %d", s.GetPollPeriod(), RetxPollPeriod)
	}

	s.SetRetxMode(false)
	if s.GetPollPeriod() == RetxPollPeriod {
		t.Error("poll period should change after exiting retx mode")
	}
}

func TestFastPolls(t *testing.T) {
	cb := &mockSenderCallbacks{}
	timer := &mockSenderTimer{}
	s := NewSender(cb, timer.schedule)

	s.Start()
	s.SendFastPolls(3)

	if s.GetPollPeriod() != FastPollPeriod {
		t.Errorf("poll period during fast polls = %d, want %d", s.GetPollPeriod(), FastPollPeriod)
	}
}

func TestFastPollsDefaultCount(t *testing.T) {
	cb := &mockSenderCallbacks{}
	timer := &mockSenderTimer{}
	s := NewSender(cb, timer.schedule)

	s.Start()
	s.SendFastPolls(0) // should use DefaultFastPollCount

	if s.fastPollsRemaining != DefaultFastPollCount {
		t.Errorf("fastPollsRemaining = %d, want %d", s.fastPollsRemaining, DefaultFastPollCount)
	}
}

func TestGetPollPeriodPriority(t *testing.T) {
	cb := &mockSenderCallbacks{}
	timer := &mockSenderTimer{}
	s := NewSender(cb, timer.schedule)

	// Default period.
	s.Start()
	if s.GetPollPeriod() != DefaultPollPeriod {
		t.Errorf("default period = %d, want %d", s.GetPollPeriod(), DefaultPollPeriod)
	}

	// External period overrides default.
	s.SetExternalPollPeriod(500)
	if s.GetPollPeriod() != 500 {
		t.Errorf("external period = %d, want 500", s.GetPollPeriod())
	}

	// Fast polls override external.
	s.SendFastPolls(1)
	if s.GetPollPeriod() != FastPollPeriod {
		t.Errorf("fast poll period = %d, want %d", s.GetPollPeriod(), FastPollPeriod)
	}

	// Retx overrides fast.
	s.SetRetxMode(true)
	if s.GetPollPeriod() != RetxPollPeriod {
		t.Errorf("retx period = %d, want %d", s.GetPollPeriod(), RetxPollPeriod)
	}

	// Attach overrides all.
	s.SetAttachMode(true)
	if s.GetPollPeriod() != AttachDataPollPeriod {
		t.Errorf("attach period = %d, want %d", s.GetPollPeriod(), AttachDataPollPeriod)
	}
}

func TestSetExternalPollPeriod(t *testing.T) {
	cb := &mockSenderCallbacks{}
	timer := &mockSenderTimer{}
	s := NewSender(cb, timer.schedule)

	s.SetExternalPollPeriod(2000)
	if s.GetExternalPollPeriod() != 2000 {
		t.Errorf("external period = %d, want 2000", s.GetExternalPollPeriod())
	}
}

func TestHandlePollTimer(t *testing.T) {
	cb := &mockSenderCallbacks{}
	timer := &mockSenderTimer{}
	s := NewSender(cb, timer.schedule)

	s.Start()
	beforeCount := cb.sendDataPollCount
	beforeSchedule := timer.scheduleCount

	// Fire the timer.
	timer.fire()

	if cb.sendDataPollCount != beforeCount+1 {
		t.Errorf("SendDataPoll count = %d, want %d", cb.sendDataPollCount, beforeCount+1)
	}
	if timer.scheduleCount <= beforeSchedule {
		t.Error("timer should be rescheduled after poll")
	}
}

func TestFastPollsDecrement(t *testing.T) {
	cb := &mockSenderCallbacks{}
	timer := &mockSenderTimer{}
	s := NewSender(cb, timer.schedule)

	s.Start()
	s.SendFastPolls(3)

	// Fire 3 times — fast polls should decrement.
	for i := range 3 {
		remaining := s.fastPollsRemaining
		if remaining != uint16(3-i) {
			t.Errorf("before fire %d: fastPollsRemaining = %d, want %d", i, remaining, 3-i)
		}
		timer.fire()
	}

	if s.fastPollsRemaining != 0 {
		t.Errorf("after 3 fires: fastPollsRemaining = %d, want 0", s.fastPollsRemaining)
	}

	// Period should revert to default.
	if s.GetPollPeriod() != DefaultPollPeriod {
		t.Errorf("after fast polls exhausted: period = %d, want %d", s.GetPollPeriod(), DefaultPollPeriod)
	}
}

func TestPollPeriodConstants(t *testing.T) {
	if AttachDataPollPeriod != 100 {
		t.Errorf("AttachDataPollPeriod = %d, want 100", AttachDataPollPeriod)
	}
	if RetxPollPeriod != 188 {
		t.Errorf("RetxPollPeriod = %d, want 188", RetxPollPeriod)
	}
	if FastPollPeriod != 188 {
		t.Errorf("FastPollPeriod = %d, want 188", FastPollPeriod)
	}
	if DefaultPollPeriod != 1000 {
		t.Errorf("DefaultPollPeriod = %d, want 1000", DefaultPollPeriod)
	}
	if DefaultFastPollCount != 8 {
		t.Errorf("DefaultFastPollCount = %d, want 8", DefaultFastPollCount)
	}
}
