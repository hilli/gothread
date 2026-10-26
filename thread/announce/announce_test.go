// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package announce

import (
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Test helpers / mocks
// ---------------------------------------------------------------------------

// mockSender records SendAnnounce calls.
type mockSender struct {
	mu    sync.Mutex
	calls []sendCall
	err   error
}

type sendCall struct {
	Channel        uint16
	OrphanAnnounce bool
}

func (m *mockSender) SendAnnounce(channel uint16, orphanAnnounce bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, sendCall{Channel: channel, OrphanAnnounce: orphanAnnounce})
	return m.err
}

func (m *mockSender) getCalls() []sendCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]sendCall, len(m.calls))
	copy(out, m.calls)
	return out
}

// mockTimer is a deterministic timer for testing.
type mockTimer struct {
	mu      sync.Mutex
	running bool
	delay   uint32
	starts  int
}

func (t *mockTimer) Start(delay uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.running = true
	t.delay = delay
	t.starts++
}

func (t *mockTimer) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.running = false
}

func (t *mockTimer) IsRunning() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.running
}

func (t *mockTimer) getStarts() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.starts
}

func (t *mockTimer) getDelay() uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.delay
}

// zeroRand always returns 0, for deterministic testing.
func zeroRand(_ uint32) uint32 { return 0 }

// maxRand returns n-1, for deterministic testing.
func maxRand(n uint32) uint32 {
	if n == 0 {
		return 0
	}
	return n - 1
}

// channelMask builds a 32-bit mask from a list of channel numbers.
func channelMask(channels ...uint8) uint32 {
	var mask uint32
	for _, ch := range channels {
		mask |= 1 << ch
	}
	return mask
}

// ---------------------------------------------------------------------------
// Channel mask helper tests
// ---------------------------------------------------------------------------

func TestChannelMaskIsEmpty(t *testing.T) {
	if !channelMaskIsEmpty(0) {
		t.Error("expected empty mask for 0")
	}
	if channelMaskIsEmpty(1 << 11) {
		t.Error("expected non-empty mask for channel 11")
	}
}

func TestChannelMaskContains(t *testing.T) {
	mask := channelMask(11, 15, 26)

	if !channelMaskContains(mask, 11) {
		t.Error("expected mask to contain channel 11")
	}
	if !channelMaskContains(mask, 15) {
		t.Error("expected mask to contain channel 15")
	}
	if !channelMaskContains(mask, 26) {
		t.Error("expected mask to contain channel 26")
	}
	if channelMaskContains(mask, 12) {
		t.Error("expected mask to NOT contain channel 12")
	}
	if channelMaskContains(mask, 0) {
		t.Error("expected mask to NOT contain channel 0")
	}
}

func TestFirstChannelInMask(t *testing.T) {
	tests := []struct {
		name string
		mask uint32
		want uint8
	}{
		{"single channel 11", channelMask(11), 11},
		{"single channel 26", channelMask(26), 26},
		{"channels 15,20,25", channelMask(15, 20, 25), 15},
		{"all channels 11-26", channelMask(11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26), 11},
		{"channel 0", channelMask(0), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := firstChannelInMask(tt.mask)
			if got != tt.want {
				t.Errorf("firstChannelInMask(%#x) = %d, want %d", tt.mask, got, tt.want)
			}
		})
	}
}

func TestNextChannelInMask(t *testing.T) {
	mask := channelMask(11, 15, 20, 26)

	tests := []struct {
		from uint8
		want uint8
	}{
		{11, 15},
		{15, 20},
		{20, 26},
		{26, 11}, // wraps around
	}

	for _, tt := range tests {
		got := nextChannelInMask(mask, tt.from)
		if got != tt.want {
			t.Errorf("nextChannelInMask(mask, %d) = %d, want %d", tt.from, got, tt.want)
		}
	}
}

func TestChannelCount(t *testing.T) {
	if channelCount(0) != 0 {
		t.Error("expected 0 for empty mask")
	}
	if channelCount(channelMask(11)) != 1 {
		t.Error("expected 1 for single channel")
	}
	if channelCount(channelMask(11, 15, 20, 26)) != 4 {
		t.Error("expected 4 for four channels")
	}
}

func TestAddJitter(t *testing.T) {
	// No jitter
	if addJitter(1000, 0, zeroRand) != 1000 {
		t.Error("expected period unchanged with zero jitter")
	}

	// Jitter with zeroRand: period + 0 - jitter = period - jitter
	got := addJitter(1000, 100, zeroRand)
	if got != 900 {
		t.Errorf("expected 900, got %d", got)
	}

	// Jitter with maxRand: period + 2*jitter - jitter = period + jitter
	got = addJitter(1000, 100, maxRand)
	if got != 1100 {
		t.Errorf("expected 1100, got %d", got)
	}

	// Clamped to 1 when period is small and jitter large
	got = addJitter(1, 100, zeroRand) // 1 + 0 - 100 = -99 → clamped to 1
	if got != 1 {
		t.Errorf("expected 1 (clamped), got %d", got)
	}
}

func TestAddCount(t *testing.T) {
	if addCount(3, 5) != 8 {
		t.Error("expected 8")
	}
	if addCount(200, 200) != 255 {
		t.Error("expected saturation at 255")
	}
	if addCount(0, 5) != 5 {
		t.Error("expected 5")
	}
}

// ---------------------------------------------------------------------------
// AnnounceSender tests
// ---------------------------------------------------------------------------

func TestNewAnnounceSender_Defaults(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer)

	if a.GetPeriod() != DefaultPeriod {
		t.Errorf("default period = %d, want %d", a.GetPeriod(), DefaultPeriod)
	}
	if a.GetJitter() != DefaultJitter {
		t.Errorf("default jitter = %d, want %d", a.GetJitter(), DefaultJitter)
	}
	if a.GetCount() != DefaultCount {
		t.Errorf("default count = %d, want %d", a.GetCount(), DefaultCount)
	}
	if a.IsRunning() {
		t.Error("should not be running initially")
	}
}

func TestNewAnnounceSender_WithOptions(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer,
		WithPeriod(2000),
		WithJitter(250),
		WithCount(5),
	)

	if a.GetPeriod() != 2000 {
		t.Errorf("period = %d, want 2000", a.GetPeriod())
	}
	if a.GetJitter() != 250 {
		t.Errorf("jitter = %d, want 250", a.GetJitter())
	}
	if a.GetCount() != 5 {
		t.Errorf("count = %d, want 5", a.GetCount())
	}
}

func TestSendAnnounce_EmptyMask(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand))

	// Don't set a channel mask — should be a no-op.
	a.SendAnnounce(3)

	if timer.IsRunning() {
		t.Error("timer should not be running with empty mask")
	}
}

func TestSendAnnounce_ZeroPeriod(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithPeriod(0), WithRandFunc(zeroRand))

	a.SetChannelMask(channelMask(11, 15, 20))
	a.SendAnnounce(3)

	if timer.IsRunning() {
		t.Error("timer should not be running with zero period")
	}
}

func TestSendAnnounce_StartsTimer(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand), WithJitter(100))

	a.SetChannelMask(channelMask(11, 15, 20))
	a.SendAnnounce(2)

	if !timer.IsRunning() {
		t.Error("timer should be running after SendAnnounce")
	}
	// With zeroRand and jitter=100, initial delay = zeroRand(101) = 0.
	if timer.getDelay() != 0 {
		t.Errorf("initial delay = %d, want 0", timer.getDelay())
	}
}

func TestSendAnnounce_AddsCountWhenRunning(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand))

	a.SetChannelMask(channelMask(11))
	a.SendAnnounce(2)

	if a.GetCount() != 2 {
		t.Errorf("count = %d, want 2", a.GetCount())
	}

	// Second call while running should add counts.
	a.SendAnnounce(3)
	if a.GetCount() != 5 {
		t.Errorf("count = %d, want 5 after adding", a.GetCount())
	}
}

func TestHandleTimer_SingleChannel(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand), WithJitter(0))

	a.SetChannelMask(channelMask(15))
	a.SendAnnounce(2)

	// First timer fire: sends on channel 15, wraps to 15 (starting), count 2→1.
	a.HandleTimer()
	calls := s.getCalls()
	if len(calls) != 1 || calls[0].Channel != 15 {
		t.Fatalf("first fire: calls=%v, want [{15 false}]", calls)
	}

	// Second timer fire: sends on channel 15 again, count 1→0 → stops.
	a.HandleTimer()
	calls = s.getCalls()
	if len(calls) != 2 || calls[1].Channel != 15 {
		t.Fatalf("second fire: calls=%v", calls)
	}

	// Timer should not have been restarted after count reached 0.
	// The timer.starts count should be: 1 (initial) + 1 (after first HandleTimer) = 2.
	if timer.getStarts() != 2 {
		t.Errorf("timer starts = %d, want 2", timer.getStarts())
	}
}

func TestHandleTimer_MultipleChannels(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand), WithJitter(0))

	mask := channelMask(11, 15, 20)
	a.SetChannelMask(mask)
	a.SendAnnounce(1)

	// Should iterate through channels 11, 15, 20 in one cycle.
	expectedChannels := []uint16{11, 15, 20}

	for i, expected := range expectedChannels {
		a.HandleTimer()
		calls := s.getCalls()
		if len(calls) != i+1 {
			t.Fatalf("fire %d: expected %d calls, got %d", i, i+1, len(calls))
		}
		if calls[i].Channel != expected {
			t.Errorf("fire %d: channel = %d, want %d", i, calls[i].Channel, expected)
		}
	}

	// After the third fire, channel wraps to 11 (starting), count 1→0 → done.
	// Timer should not be restarted.
	// Starts: 1 (initial SendAnnounce) + 2 (first two HandleTimer restarts) = 3.
	if timer.getStarts() != 3 {
		t.Errorf("timer starts = %d, want 3", timer.getStarts())
	}
}

func TestHandleTimer_MultipleCycles(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand), WithJitter(0))

	mask := channelMask(11, 20)
	a.SetChannelMask(mask)
	a.SendAnnounce(2)

	// Cycle 1: channels 11, 20
	// Cycle 2: channels 11, 20
	expected := []uint16{11, 20, 11, 20}

	for range expected {
		a.HandleTimer()
	}

	calls := s.getCalls()
	if len(calls) != 4 {
		t.Fatalf("expected 4 calls, got %d", len(calls))
	}
	for i, exp := range expected {
		if calls[i].Channel != exp {
			t.Errorf("call %d: channel = %d, want %d", i, calls[i].Channel, exp)
		}
	}
}

func TestStop(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand))

	a.SetChannelMask(channelMask(11, 15))
	a.SendAnnounce(5)

	if !a.IsRunning() {
		t.Fatal("expected running after SendAnnounce")
	}

	a.Stop()

	if a.IsRunning() {
		t.Error("expected not running after Stop")
	}
	if a.GetCount() != 0 {
		t.Errorf("count = %d, want 0 after Stop", a.GetCount())
	}
}

func TestSetChannelMask_EmptyStops(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand))

	a.SetChannelMask(channelMask(11, 15))
	a.SendAnnounce(3)

	if !a.IsRunning() {
		t.Fatal("expected running")
	}

	// Set empty mask — should stop.
	a.SetChannelMask(0)

	if a.IsRunning() {
		t.Error("expected not running after setting empty mask")
	}
}

func TestSetStartingChannel(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand), WithJitter(0))

	mask := channelMask(11, 15, 20)
	a.SetChannelMask(mask)
	a.SetStartingChannel(15)

	if a.GetStartingChannel() != 15 {
		t.Errorf("starting channel = %d, want 15", a.GetStartingChannel())
	}

	a.SendAnnounce(1)

	// Should start from channel 15.
	a.HandleTimer()
	calls := s.getCalls()
	if len(calls) != 1 || calls[0].Channel != 15 {
		t.Fatalf("first fire: calls=%v, want [{15 false}]", calls)
	}

	// Next: 20
	a.HandleTimer()
	calls = s.getCalls()
	if calls[1].Channel != 20 {
		t.Errorf("second fire: channel = %d, want 20", calls[1].Channel)
	}

	// Next: 11 (wraps around)
	a.HandleTimer()
	calls = s.getCalls()
	if calls[2].Channel != 11 {
		t.Errorf("third fire: channel = %d, want 11", calls[2].Channel)
	}
}

func TestSetStartingChannel_NotInMask(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand))

	mask := channelMask(11, 15, 20)
	a.SetChannelMask(mask)
	// Set to a channel not in the mask — should fall back to first in mask.
	a.SetStartingChannel(13)

	if a.GetStartingChannel() != 11 {
		t.Errorf("starting channel = %d, want 11 (fallback to first)", a.GetStartingChannel())
	}
}

func TestSetJitter(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer)

	a.SetJitter(200)
	if a.GetJitter() != 200 {
		t.Errorf("jitter = %d, want 200", a.GetJitter())
	}
}

func TestSetPeriod(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer)

	a.SetPeriod(5000)
	if a.GetPeriod() != 5000 {
		t.Errorf("period = %d, want 5000", a.GetPeriod())
	}
}

func TestHandleTimer_InfiniteCount(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand), WithJitter(0), WithCount(0))

	a.SetChannelMask(channelMask(11))
	a.SendAnnounce(0) // 0 = infinite

	// Fire many times — should keep going.
	for i := 0; i < 100; i++ {
		a.HandleTimer()
	}

	calls := s.getCalls()
	if len(calls) != 100 {
		t.Errorf("expected 100 calls for infinite mode, got %d", len(calls))
	}

	// Timer should still be running (restarted after each fire).
	if !a.IsRunning() {
		t.Error("expected running in infinite mode")
	}
}

func TestHandleTimer_JitterApplied(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(maxRand), WithJitter(100), WithPeriod(1000))

	a.SetChannelMask(channelMask(11, 15))
	a.SendAnnounce(2)

	// First HandleTimer — the timer delay for next fire should be:
	// addJitter(1000, 100, maxRand) = 1000 + (2*100) - 100 = 1100
	a.HandleTimer()
	if timer.getDelay() != 1100 {
		t.Errorf("delay after first fire = %d, want 1100", timer.getDelay())
	}
}

// ---------------------------------------------------------------------------
// AnnounceBeginServer tests
// ---------------------------------------------------------------------------

func TestAnnounceBeginServer_HandleRequest(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand))
	srv := NewAnnounceBeginServer(a)

	mask := channelMask(11, 15, 20)
	err := srv.HandleRequest(mask, 500, 3)
	if err != nil {
		t.Fatalf("HandleRequest returned error: %v", err)
	}

	if a.GetPeriod() != 500 {
		t.Errorf("period = %d, want 500", a.GetPeriod())
	}
	if a.GetJitter() != BeginDefaultJitter {
		t.Errorf("jitter = %d, want %d", a.GetJitter(), BeginDefaultJitter)
	}
	if a.GetChannelMask() != mask {
		t.Errorf("mask = %#x, want %#x", a.GetChannelMask(), mask)
	}
	if !a.IsRunning() {
		t.Error("expected running after HandleRequest")
	}

	// Fire through all channels for 3 cycles.
	for i := 0; i < 9; i++ {
		a.HandleTimer()
	}

	calls := s.getCalls()
	if len(calls) != 9 {
		t.Errorf("expected 9 calls (3 channels * 3 cycles), got %d", len(calls))
	}
}

func TestAnnounceBeginServer_HandleRequest_EmptyMask(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand))
	srv := NewAnnounceBeginServer(a)

	err := srv.HandleRequest(0, 500, 3)
	if err == nil {
		t.Error("expected error for empty channel mask")
	}
}

func TestAnnounceBeginServer_HandleRequest_ZeroPeriod(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand))
	srv := NewAnnounceBeginServer(a)

	err := srv.HandleRequest(channelMask(11), 0, 3)
	if err == nil {
		t.Error("expected error for zero period")
	}
}

func TestAnnounceBeginServer_HandleRequest_ZeroCount(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand))
	srv := NewAnnounceBeginServer(a)

	err := srv.HandleRequest(channelMask(11), 500, 0)
	if err == nil {
		t.Error("expected error for zero count")
	}
}

func TestAnnounceBeginServer_HandleRequest_StopsPrevious(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand))
	srv := NewAnnounceBeginServer(a)

	// Start one request.
	_ = srv.HandleRequest(channelMask(11), 500, 10)
	a.HandleTimer() // Fire once.

	// Start another request — should replace the previous.
	_ = srv.HandleRequest(channelMask(20), 200, 1)

	// The mask should now be channel 20 only.
	if a.GetChannelMask() != channelMask(20) {
		t.Errorf("mask = %#x, want %#x", a.GetChannelMask(), channelMask(20))
	}

	// Fire once — should be channel 20.
	a.HandleTimer()
	calls := s.getCalls()
	lastCall := calls[len(calls)-1]
	if lastCall.Channel != 20 {
		t.Errorf("last channel = %d, want 20", lastCall.Channel)
	}
}

func TestAnnounceBeginServer_SendAnnounce(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand))
	srv := NewAnnounceBeginServer(a)

	mask := channelMask(11, 26)
	srv.SendAnnounce(mask, 2, 300)

	if a.GetPeriod() != 300 {
		t.Errorf("period = %d, want 300", a.GetPeriod())
	}
	if !a.IsRunning() {
		t.Error("expected running after SendAnnounce")
	}

	// Fire through 2 channels * 2 cycles = 4.
	for i := 0; i < 4; i++ {
		a.HandleTimer()
	}

	calls := s.getCalls()
	if len(calls) != 4 {
		t.Errorf("expected 4 calls, got %d", len(calls))
	}
}

func TestAnnounceBeginServer_SendAnnounce_Defaults(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand))
	srv := NewAnnounceBeginServer(a)

	// Pass 0 for count and period — should use defaults.
	srv.SendAnnounce(channelMask(11), 0, 0)

	if a.GetPeriod() != BeginDefaultPeriod {
		t.Errorf("period = %d, want %d", a.GetPeriod(), BeginDefaultPeriod)
	}
	if a.GetCount() != BeginDefaultCount {
		t.Errorf("count = %d, want %d", a.GetCount(), BeginDefaultCount)
	}
}

// ---------------------------------------------------------------------------
// Integration-style tests
// ---------------------------------------------------------------------------

func TestFullCycle_AllChannels11to26(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand), WithJitter(0))

	// Set all 16 Thread channels.
	var mask uint32
	for ch := uint8(11); ch <= 26; ch++ {
		mask |= 1 << ch
	}
	a.SetChannelMask(mask)
	a.SendAnnounce(1)

	// Fire 16 times for one complete cycle.
	for i := 0; i < 16; i++ {
		a.HandleTimer()
	}

	calls := s.getCalls()
	if len(calls) != 16 {
		t.Fatalf("expected 16 calls, got %d", len(calls))
	}
	for i, call := range calls {
		expectedCh := uint16(11 + i)
		if call.Channel != expectedCh {
			t.Errorf("call %d: channel = %d, want %d", i, call.Channel, expectedCh)
		}
	}
}

func TestSetChannelMask_UpdatesStartingChannel(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand))

	a.SetChannelMask(channelMask(11, 15, 20))
	a.SetStartingChannel(15)
	if a.GetStartingChannel() != 15 {
		t.Fatalf("starting = %d, want 15", a.GetStartingChannel())
	}

	// Change mask to not include 15 — starting should update.
	a.SetChannelMask(channelMask(11, 20))
	if a.GetStartingChannel() != 11 {
		t.Errorf("starting = %d, want 11 after mask change", a.GetStartingChannel())
	}
}

func TestAnnounceSender_ConcurrentAccess(t *testing.T) {
	s := &mockSender{}
	timer := &mockTimer{}
	a := NewAnnounceSender(s, timer, WithRandFunc(zeroRand))

	a.SetChannelMask(channelMask(11, 15, 20))

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.SendAnnounce(1)
			a.IsRunning()
			a.GetChannelMask()
			a.GetPeriod()
			a.GetJitter()
			a.HandleTimer()
		}()
	}
	wg.Wait()

	// Just verify no panic/deadlock occurred.
}
