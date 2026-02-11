// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mpl

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Mock sender
// ---------------------------------------------------------------------------

type mockSender struct {
	sent [][]byte
	err  error // if non-nil, SendMulticast returns this error
}

func (m *mockSender) SendMulticast(payload []byte) error {
	if m.err != nil {
		return m.err
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	m.sent = append(m.sent, cp)
	return nil
}

func (m *mockSender) reset() {
	m.sent = nil
}

// ---------------------------------------------------------------------------
// SequenceGreater
// ---------------------------------------------------------------------------

func TestSequenceGreater(t *testing.T) {
	tests := []struct {
		a, b uint8
		want bool
	}{
		{1, 0, true},
		{0, 1, false},
		{0, 0, false},
		{255, 0, false}, // 255 - 0 = 255 => int8(-1) => not > 0
		{0, 255, true},  // 0 - 255 = 1 => int8(1) => > 0
		{128, 0, false}, // 128 - 0 = 128 => int8(-128) => not > 0
		{127, 0, true},  // 127 - 0 = 127 => int8(127) => > 0
		{200, 100, true},
		{100, 200, false},
		// Wraparound cases
		{5, 250, true},   // 5 - 250 = 11 => int8(11) > 0
		{250, 5, false},  // 250 - 5 = 245 => int8(-11) not > 0
		{130, 125, true}, // 5 difference
	}
	for _, tt := range tests {
		got := SequenceGreater(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("SequenceGreater(%d, %d) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// TrickleTimer
// ---------------------------------------------------------------------------

func TestTrickleTimerNew(t *testing.T) {
	tt := NewTrickleTimer(10, 600, 1)
	if tt.GetInterval() != 10 {
		t.Errorf("initial interval = %d, want 10", tt.GetInterval())
	}
}

func TestTrickleTimerReset(t *testing.T) {
	tt := NewTrickleTimer(10, 600, 1)
	// Double the interval a few times.
	tt.IntervalExpired()
	tt.IntervalExpired()
	if tt.GetInterval() <= 10 {
		t.Fatal("interval should have grown after IntervalExpired")
	}
	tt.Reset()
	if tt.GetInterval() != 10 {
		t.Errorf("after Reset, interval = %d, want 10", tt.GetInterval())
	}
}

func TestTrickleTimerIntervalDoubling(t *testing.T) {
	tt := NewTrickleTimer(10, 100, 1)
	// 10 -> 20 -> 40 -> 80 -> 100 (capped)
	tt.IntervalExpired()
	if tt.GetInterval() != 20 {
		t.Errorf("interval = %d, want 20", tt.GetInterval())
	}
	tt.IntervalExpired()
	if tt.GetInterval() != 40 {
		t.Errorf("interval = %d, want 40", tt.GetInterval())
	}
	tt.IntervalExpired()
	if tt.GetInterval() != 80 {
		t.Errorf("interval = %d, want 80", tt.GetInterval())
	}
	tt.IntervalExpired()
	if tt.GetInterval() != 100 {
		t.Errorf("interval = %d, want 100 (capped at imax)", tt.GetInterval())
	}
	// Should stay at imax.
	tt.IntervalExpired()
	if tt.GetInterval() != 100 {
		t.Errorf("interval = %d, want 100 (capped)", tt.GetInterval())
	}
}

func TestTrickleTimerShouldTransmit(t *testing.T) {
	tt := NewTrickleTimer(10, 600, 2)

	// Counter starts at 0, k=2 => should transmit.
	if !tt.ShouldTransmit() {
		t.Error("ShouldTransmit() should be true when counter=0, k=2")
	}

	tt.IndicateConsistent()
	// Counter = 1, k=2 => still should transmit.
	if !tt.ShouldTransmit() {
		t.Error("ShouldTransmit() should be true when counter=1, k=2")
	}

	tt.IndicateConsistent()
	// Counter = 2, k=2 => suppressed.
	if tt.ShouldTransmit() {
		t.Error("ShouldTransmit() should be false when counter=2, k=2")
	}
}

func TestTrickleTimerIndicateInconsistent(t *testing.T) {
	tt := NewTrickleTimer(10, 600, 1)
	tt.IntervalExpired()
	tt.IntervalExpired()
	big := tt.GetInterval()

	tt.IndicateInconsistent()
	if tt.GetInterval() != 10 {
		t.Errorf("after IndicateInconsistent, interval = %d, want 10 (was %d)", tt.GetInterval(), big)
	}
}

// ---------------------------------------------------------------------------
// Forwarder — new message reception
// ---------------------------------------------------------------------------

func TestProcessMessageNew(t *testing.T) {
	s := &mockSender{}
	f := NewForwarder(s, 0x0001)

	isNew := f.ProcessMessage(0x1000, 1, []byte("hello"))
	if !isNew {
		t.Error("ProcessMessage should return true for a new message")
	}
	if f.GetSeedEntryCount() != 1 {
		t.Errorf("seed count = %d, want 1", f.GetSeedEntryCount())
	}
	if f.GetBufferedMessageCount() != 1 {
		t.Errorf("buffered count = %d, want 1", f.GetBufferedMessageCount())
	}
}

func TestProcessMessageMultipleSeeds(t *testing.T) {
	s := &mockSender{}
	f := NewForwarder(s, 0x0001)

	f.ProcessMessage(0x1000, 1, []byte("a"))
	f.ProcessMessage(0x2000, 1, []byte("b"))
	f.ProcessMessage(0x3000, 1, []byte("c"))

	if f.GetSeedEntryCount() != 3 {
		t.Errorf("seed count = %d, want 3", f.GetSeedEntryCount())
	}
	if f.GetBufferedMessageCount() != 3 {
		t.Errorf("buffered count = %d, want 3", f.GetBufferedMessageCount())
	}
}

// ---------------------------------------------------------------------------
// Forwarder — duplicate suppression
// ---------------------------------------------------------------------------

func TestProcessMessageDuplicate(t *testing.T) {
	s := &mockSender{}
	f := NewForwarder(s, 0x0001)

	isNew := f.ProcessMessage(0x1000, 5, []byte("data"))
	if !isNew {
		t.Error("first message should be new")
	}

	isNew = f.ProcessMessage(0x1000, 5, []byte("data"))
	if isNew {
		t.Error("duplicate message should not be new")
	}
}

func TestProcessMessageOlderSequence(t *testing.T) {
	s := &mockSender{}
	f := NewForwarder(s, 0x0001)

	f.ProcessMessage(0x1000, 10, []byte("newer"))
	isNew := f.ProcessMessage(0x1000, 5, []byte("older"))
	if isNew {
		t.Error("older sequence should not be treated as new")
	}
}

func TestProcessMessageNewerSequence(t *testing.T) {
	s := &mockSender{}
	f := NewForwarder(s, 0x0001)

	f.ProcessMessage(0x1000, 5, []byte("first"))
	isNew := f.ProcessMessage(0x1000, 6, []byte("second"))
	if !isNew {
		t.Error("newer sequence should be treated as new")
	}
	// Should still have 1 seed.
	if f.GetSeedEntryCount() != 1 {
		t.Errorf("seed count = %d, want 1", f.GetSeedEntryCount())
	}
}

// ---------------------------------------------------------------------------
// Forwarder — Trickle consistency on duplicate
// ---------------------------------------------------------------------------

func TestDuplicateIndicatesConsistent(t *testing.T) {
	s := &mockSender{}
	f := NewForwarder(s, 0x0001, WithKConstant(2))

	f.ProcessMessage(0x1000, 1, []byte("data"))

	// The buffered message's Trickle counter should be 0 initially.
	if f.messages[0].Trickle.counter != 0 {
		t.Fatalf("initial counter = %d, want 0", f.messages[0].Trickle.counter)
	}

	// Receiving the same message again should indicate consistent.
	f.ProcessMessage(0x1000, 1, []byte("data"))
	if f.messages[0].Trickle.counter != 1 {
		t.Errorf("counter after duplicate = %d, want 1", f.messages[0].Trickle.counter)
	}
}

// ---------------------------------------------------------------------------
// Forwarder — sequence wraparound
// ---------------------------------------------------------------------------

func TestProcessMessageSequenceWraparound(t *testing.T) {
	s := &mockSender{}
	f := NewForwarder(s, 0x0001)

	// Start near the wraparound boundary.
	f.ProcessMessage(0x1000, 254, []byte("a"))
	isNew := f.ProcessMessage(0x1000, 255, []byte("b"))
	if !isNew {
		t.Error("255 should be newer than 254")
	}

	// Wrap around: 0 is newer than 255 in serial number arithmetic.
	isNew = f.ProcessMessage(0x1000, 0, []byte("c"))
	if !isNew {
		t.Error("0 should be newer than 255 (wraparound)")
	}

	// 1 is newer than 0.
	isNew = f.ProcessMessage(0x1000, 1, []byte("d"))
	if !isNew {
		t.Error("1 should be newer than 0")
	}
}

// ---------------------------------------------------------------------------
// Forwarder — seed expiry via HandleTimer
// ---------------------------------------------------------------------------

func TestSeedExpiry(t *testing.T) {
	s := &mockSender{}
	f := NewForwarder(s, 0x0001, WithSeedLifetime(3))

	f.ProcessMessage(0x1000, 1, []byte("data"))
	if f.GetSeedEntryCount() != 1 {
		t.Fatalf("seed count = %d, want 1", f.GetSeedEntryCount())
	}

	// Tick 3 times — lifetime starts at 3, decremented each tick.
	// Tick 1: lifetime 3 -> 2 (kept)
	// Tick 2: lifetime 2 -> 1 (kept)
	// Tick 3: lifetime 1 -> 0 (removed)
	f.HandleTimer()
	f.HandleTimer()
	f.HandleTimer()

	if f.GetSeedEntryCount() != 0 {
		t.Errorf("seed count after expiry = %d, want 0", f.GetSeedEntryCount())
	}
}

// ---------------------------------------------------------------------------
// Forwarder — buffer full scenario
// ---------------------------------------------------------------------------

func TestBufferFullEviction(t *testing.T) {
	s := &mockSender{}
	f := NewForwarder(s, 0x0001, WithMaxMessages(2), WithMaxTxCount(10))

	f.ProcessMessage(0x1000, 1, []byte("msg1"))
	f.ProcessMessage(0x2000, 1, []byte("msg2"))

	if f.GetBufferedMessageCount() != 2 {
		t.Fatalf("buffered count = %d, want 2", f.GetBufferedMessageCount())
	}

	// Third message should evict the oldest.
	f.ProcessMessage(0x3000, 1, []byte("msg3"))
	if f.GetBufferedMessageCount() != 2 {
		t.Errorf("buffered count = %d, want 2 (oldest evicted)", f.GetBufferedMessageCount())
	}

	// Verify the oldest was evicted: msg1 from seed 0x1000 should be gone.
	for _, m := range f.messages {
		if m.SeedID == 0x1000 && m.Sequence == 1 && string(m.Payload) == "msg1" {
			t.Error("msg1 should have been evicted")
		}
	}
}

func TestSeedCapacityFull(t *testing.T) {
	s := &mockSender{}
	f := NewForwarder(s, 0x0001, WithMaxSeeds(2))

	f.ProcessMessage(0x1000, 1, []byte("a"))
	f.ProcessMessage(0x2000, 1, []byte("b"))
	isNew := f.ProcessMessage(0x3000, 1, []byte("c"))
	if isNew {
		t.Error("should reject message when seed table is full")
	}
	if f.GetSeedEntryCount() != 2 {
		t.Errorf("seed count = %d, want 2", f.GetSeedEntryCount())
	}
}

// ---------------------------------------------------------------------------
// Forwarder — SendMessage
// ---------------------------------------------------------------------------

func TestSendMessage(t *testing.T) {
	s := &mockSender{}
	f := NewForwarder(s, 0x0001)

	err := f.SendMessage([]byte("multicast payload"))
	if err != nil {
		t.Fatalf("SendMessage returned error: %v", err)
	}

	if len(s.sent) != 1 {
		t.Fatalf("sender.sent count = %d, want 1", len(s.sent))
	}
	if string(s.sent[0]) != "multicast payload" {
		t.Errorf("sent payload = %q, want %q", s.sent[0], "multicast payload")
	}

	// Should have created a seed entry and buffered message.
	if f.GetSeedEntryCount() != 1 {
		t.Errorf("seed count = %d, want 1", f.GetSeedEntryCount())
	}
	if f.GetBufferedMessageCount() != 1 {
		t.Errorf("buffered count = %d, want 1", f.GetBufferedMessageCount())
	}

	// TxCount should be 1 (first transmission already done).
	if f.messages[0].TxCount != 1 {
		t.Errorf("TxCount = %d, want 1", f.messages[0].TxCount)
	}
}

func TestSendMessageSequenceIncrement(t *testing.T) {
	s := &mockSender{}
	f := NewForwarder(s, 0x0001)

	_ = f.SendMessage([]byte("a"))
	_ = f.SendMessage([]byte("b"))
	_ = f.SendMessage([]byte("c"))

	if f.GetBufferedMessageCount() != 3 {
		t.Fatalf("buffered count = %d, want 3", f.GetBufferedMessageCount())
	}

	// Sequences should be 0, 1, 2.
	for i, want := range []uint8{0, 1, 2} {
		if f.messages[i].Sequence != want {
			t.Errorf("message[%d].Sequence = %d, want %d", i, f.messages[i].Sequence, want)
		}
	}
}

func TestSendMessageBufferFull(t *testing.T) {
	s := &mockSender{}
	f := NewForwarder(s, 0x0001, WithMaxMessages(1))

	err := f.SendMessage([]byte("first"))
	if err != nil {
		t.Fatalf("first SendMessage failed: %v", err)
	}

	err = f.SendMessage([]byte("second"))
	if err == nil {
		t.Error("expected error when message buffer is full")
	}
}

// ---------------------------------------------------------------------------
// Forwarder — HandleTimer retransmission
// ---------------------------------------------------------------------------

func TestHandleTimerRetransmit(t *testing.T) {
	s := &mockSender{}
	f := NewForwarder(s, 0x0001, WithMaxTxCount(3), WithKConstant(1))

	f.ProcessMessage(0x1000, 1, []byte("data"))
	if f.GetBufferedMessageCount() != 1 {
		t.Fatalf("buffered count = %d, want 1", f.GetBufferedMessageCount())
	}

	// Each HandleTimer call where ShouldTransmit() is true will send and
	// increment TxCount, then advance the interval. After 3 ticks, TxCount
	// should reach MaxTxCount and the message should be removed.
	for i := 0; i < 3; i++ {
		f.HandleTimer()
	}

	if f.GetBufferedMessageCount() != 0 {
		t.Errorf("buffered count = %d, want 0 (message should be removed after max tx)", f.GetBufferedMessageCount())
	}

	// Sender should have received 3 transmissions from HandleTimer.
	if len(s.sent) != 3 {
		t.Errorf("total sends = %d, want 3", len(s.sent))
	}
}

func TestHandleTimerSuppressed(t *testing.T) {
	s := &mockSender{}
	f := NewForwarder(s, 0x0001, WithMaxTxCount(5), WithKConstant(1))

	f.ProcessMessage(0x1000, 1, []byte("data"))

	// Mark consistent enough to suppress (k=1, so counter >= 1 suppresses).
	f.messages[0].Trickle.IndicateConsistent()

	f.HandleTimer()

	// ShouldTransmit() is false, so no send should have happened.
	if len(s.sent) != 0 {
		t.Errorf("sends = %d, want 0 (transmission should be suppressed)", len(s.sent))
	}
}

// ---------------------------------------------------------------------------
// Forwarder — functional options
// ---------------------------------------------------------------------------

func TestDefaultOptions(t *testing.T) {
	s := &mockSender{}
	f := NewForwarder(s, 0x0001)

	if f.maxMessages != DefaultMaxMessages {
		t.Errorf("maxMessages = %d, want %d", f.maxMessages, DefaultMaxMessages)
	}
	if f.maxSeeds != DefaultMaxSeeds {
		t.Errorf("maxSeeds = %d, want %d", f.maxSeeds, DefaultMaxSeeds)
	}
	if f.seedLifetime != DefaultSeedLifetime {
		t.Errorf("seedLifetime = %d, want %d", f.seedLifetime, DefaultSeedLifetime)
	}
	if f.timePeriod != DefaultTimePeriod {
		t.Errorf("timePeriod = %d, want %d", f.timePeriod, DefaultTimePeriod)
	}
	if f.expirationTime != DefaultExpirationTime {
		t.Errorf("expirationTime = %d, want %d", f.expirationTime, DefaultExpirationTime)
	}
	if f.kConstant != DefaultKConstant {
		t.Errorf("kConstant = %d, want %d", f.kConstant, DefaultKConstant)
	}
	if f.maxTxCount != DefaultMaxTxCount {
		t.Errorf("maxTxCount = %d, want %d", f.maxTxCount, DefaultMaxTxCount)
	}
}

func TestCustomOptions(t *testing.T) {
	s := &mockSender{}
	f := NewForwarder(s, 0x0001,
		WithMaxMessages(16),
		WithMaxSeeds(64),
		WithSeedLifetime(600000),
		WithTimePeriod(20),
		WithExpirationTime(1200),
		WithKConstant(3),
		WithMaxTxCount(5),
	)

	if f.maxMessages != 16 {
		t.Errorf("maxMessages = %d, want 16", f.maxMessages)
	}
	if f.maxSeeds != 64 {
		t.Errorf("maxSeeds = %d, want 64", f.maxSeeds)
	}
	if f.seedLifetime != 600000 {
		t.Errorf("seedLifetime = %d, want 600000", f.seedLifetime)
	}
	if f.timePeriod != 20 {
		t.Errorf("timePeriod = %d, want 20", f.timePeriod)
	}
	if f.expirationTime != 1200 {
		t.Errorf("expirationTime = %d, want 1200", f.expirationTime)
	}
	if f.kConstant != 3 {
		t.Errorf("kConstant = %d, want 3", f.kConstant)
	}
	if f.maxTxCount != 5 {
		t.Errorf("maxTxCount = %d, want 5", f.maxTxCount)
	}
}

// ---------------------------------------------------------------------------
// Forwarder — payload isolation
// ---------------------------------------------------------------------------

func TestPayloadIsolation(t *testing.T) {
	s := &mockSender{}
	f := NewForwarder(s, 0x0001)

	payload := []byte("original")
	f.ProcessMessage(0x1000, 1, payload)

	// Mutate the original slice.
	payload[0] = 'X'

	// Buffered message should retain the original payload.
	if string(f.messages[0].Payload) != "original" {
		t.Errorf("payload = %q, want %q", f.messages[0].Payload, "original")
	}
}

// ---------------------------------------------------------------------------
// Forwarder — combined scenario
// ---------------------------------------------------------------------------

func TestCombinedScenario(t *testing.T) {
	s := &mockSender{}
	f := NewForwarder(s, 0x0001,
		WithMaxMessages(4),
		WithMaxSeeds(4),
		WithMaxTxCount(2),
		WithKConstant(1),
		WithSeedLifetime(5),
	)

	// Receive messages from 3 different seeds.
	if !f.ProcessMessage(0xA, 1, []byte("a1")) {
		t.Error("a1 should be new")
	}
	if !f.ProcessMessage(0xB, 1, []byte("b1")) {
		t.Error("b1 should be new")
	}
	if !f.ProcessMessage(0xC, 1, []byte("c1")) {
		t.Error("c1 should be new")
	}

	if f.GetSeedEntryCount() != 3 {
		t.Fatalf("seed count = %d, want 3", f.GetSeedEntryCount())
	}
	if f.GetBufferedMessageCount() != 3 {
		t.Fatalf("buffered count = %d, want 3", f.GetBufferedMessageCount())
	}

	// Duplicate from seed A should be suppressed.
	if f.ProcessMessage(0xA, 1, []byte("a1")) {
		t.Error("duplicate a1 should be suppressed")
	}

	// Newer message from seed A.
	if !f.ProcessMessage(0xA, 2, []byte("a2")) {
		t.Error("a2 should be new")
	}

	// After 2 HandleTimer calls, most messages (b1, c1, a2) reach
	// MaxTxCount=2 and are removed. Message a1 had its Trickle counter
	// incremented by the duplicate, suppressing one transmission, so it
	// needs one extra tick.
	f.HandleTimer()
	f.HandleTimer()

	if f.GetBufferedMessageCount() != 1 {
		t.Errorf("buffered count = %d, want 1 after 2 timer ticks (a1 still pending)", f.GetBufferedMessageCount())
	}

	// Third tick removes the remaining message (a1).
	f.HandleTimer()

	if f.GetBufferedMessageCount() != 0 {
		t.Errorf("buffered count = %d, want 0 after 3 timer ticks", f.GetBufferedMessageCount())
	}

	// Seeds should still be alive (lifetime was 5, ticked 3 times: 5->4->3->2).
	if f.GetSeedEntryCount() != 3 {
		t.Errorf("seed count = %d, want 3", f.GetSeedEntryCount())
	}

	// Tick 2 more times to expire all seeds (2->1->0).
	f.HandleTimer()
	f.HandleTimer()

	if f.GetSeedEntryCount() != 0 {
		t.Errorf("seed count after full expiry = %d, want 0", f.GetSeedEntryCount())
	}
}

// ---------------------------------------------------------------------------
// Forwarder — SendMessage with nil sender
// ---------------------------------------------------------------------------

func TestSendMessageNilSender(t *testing.T) {
	f := NewForwarder(nil, 0x0001)
	err := f.SendMessage([]byte("test"))
	if err == nil {
		t.Error("expected error when sender is nil")
	}
}
