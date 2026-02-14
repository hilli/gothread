// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package supervision

import (
	"testing"
	"time"

	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// DataPollSender – additional tests
// ---------------------------------------------------------------------------

func TestDataPollSender_SendDataPoll_NilTransmitter(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender() // no transmitter set
	d.Start()
	defer d.Stop()

	// Should succeed without panicking even with nil transmitter.
	if err := d.SendDataPoll(); err != nil {
		t.Errorf("SendDataPoll with nil transmitter = %v, want nil", err)
	}
}

func TestDataPollSender_SendDataPoll_OtherError(t *testing.T) {
	t.Parallel()

	tx := &mockPollTransmitter{err: errors.ErrFailed}
	d := NewDataPollSender(WithPollTransmitter(tx))
	d.Start()

	err := d.SendDataPoll()
	if err != errors.ErrFailed {
		t.Errorf("SendDataPoll = %v, want ErrFailed", err)
	}
	// Should still be enabled (only ErrInvalidState stops it).
	if !d.IsEnabled() {
		t.Error("sender should still be enabled after non-InvalidState error")
	}
	d.Stop()
}

func TestDataPollSender_HandlePollSent_NotEnabled(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender()
	// Should not panic when not started.
	d.HandlePollSent(nil)
	d.HandlePollSent(errors.ErrNoAck)
}

func TestDataPollSender_HandlePollTimeout_NotEnabled(t *testing.T) {
	t.Parallel()

	tx := &mockPollTransmitter{}
	d := NewDataPollSender(WithPollTransmitter(tx))

	// Not started — should not panic or transmit.
	d.HandlePollTimeout()
	if tx.getCallCount() != 0 {
		t.Errorf("transmitter calls = %d, want 0 when not enabled", tx.getCallCount())
	}
}

func TestDataPollSender_HandlePollTimeout_QuickPollsExhausted(t *testing.T) {
	t.Parallel()

	tx := &mockPollTransmitter{}
	d := NewDataPollSender(WithPollTransmitter(tx))
	d.Start()
	defer d.Stop()

	// Exhaust quick polls after timeout.
	for i := uint8(0); i < QuickPollsAfterTimeout; i++ {
		d.HandlePollTimeout()
	}
	callsAtExhaust := tx.getCallCount()

	// Next timeout should reset counter, not trigger additional tx.
	d.HandlePollTimeout()
	// After counter reset, it starts transmitting again from the first slot.
	if tx.getCallCount() != callsAtExhaust+1 {
		t.Errorf("transmitter calls = %d, want %d", tx.getCallCount(), callsAtExhaust+1)
	}
}

func TestDataPollSender_HandlePollSent_AbortEntersRetxMode(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender(WithDefaultPollPeriod(100000))
	d.Start()
	defer d.Stop()

	d.HandlePollSent(errors.ErrAbort)
	if got := d.GetPollPeriod(); got != RetxPollPeriod {
		t.Errorf("period = %d, want %d after abort", got, RetxPollPeriod)
	}
}

func TestDataPollSender_SetExternalPollPeriod_WhileEnabled(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender(WithDefaultPollPeriod(100000))
	d.Start()
	defer d.Stop()

	// Setting external period while enabled should trigger reschedule.
	if err := d.SetExternalPollPeriod(500); err != nil {
		t.Fatalf("SetExternalPollPeriod = %v", err)
	}
	if got := d.GetPollPeriod(); got != 500 {
		t.Errorf("period = %d, want 500", got)
	}

	// Setting same value should be no-op (no error).
	if err := d.SetExternalPollPeriod(500); err != nil {
		t.Errorf("SetExternalPollPeriod(same) = %v", err)
	}
}

func TestDataPollSender_StopFastPolls_AtMaxUsers(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender(WithDefaultPollPeriod(100000))
	d.Start()
	defer d.Stop()

	// Fill up to MaxFastPollsUsers.
	for i := uint8(0); i < MaxFastPollsUsers; i++ {
		d.SendFastPolls(5)
	}

	// StopFastPolls at max users should be a no-op (let HandlePollSent clear).
	d.StopFastPolls()
	// Fast polls should still be active.
	if got := d.GetPollPeriod(); got != FastPollPeriod {
		t.Errorf("period = %d, want %d (should remain in fast poll)", got, FastPollPeriod)
	}
}

func TestDataPollSender_StopFastPolls_NoUsers(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender()
	// Should not panic with 0 users.
	d.StopFastPolls()
}

func TestDataPollSender_FastPolls_MultipleSendFastPolls(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender(WithDefaultPollPeriod(100000))
	d.Start()
	defer d.Stop()

	// First call with 3 fast polls.
	d.SendFastPolls(3)
	// Second call with 5 fast polls should increase remaining.
	d.SendFastPolls(5)

	d.mu.Lock()
	remaining := d.remainingFastPolls
	users := d.fastPollsUsers
	d.mu.Unlock()

	if remaining != 5 {
		t.Errorf("remaining = %d, want 5", remaining)
	}
	if users != 2 {
		t.Errorf("users = %d, want 2", users)
	}
}

func TestDataPollSender_GetKeepAlivePollPeriod_ExternalLarger(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender(WithDefaultPollPeriod(10000))

	_ = d.SetExternalPollPeriod(20000)
	if got := d.GetKeepAlivePollPeriod(); got != 10000 {
		t.Errorf("keepalive = %d, want 10000 (default wins)", got)
	}
}

func TestDataPollSender_PollPeriodPriority_AllModes(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender(WithDefaultPollPeriod(100000))
	d.Start()
	defer d.Stop()

	// Enable all modes — smallest period should win.
	d.SetAttachMode(true)
	d.SendFastPolls(5)
	_ = d.SetExternalPollPeriod(MinPollPeriod)

	if got := d.GetPollPeriod(); got != MinPollPeriod {
		t.Errorf("period = %d, want %d (external smallest)", got, MinPollPeriod)
	}
}

func TestDataPollSender_HandlePollSent_SuccessAllFastPollsClearUsers(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender(WithDefaultPollPeriod(100000))
	d.Start()
	defer d.Stop()

	d.SendFastPolls(1) // 1 remaining fast poll
	d.HandlePollSent(nil) // decrements to 0, should clear users

	d.mu.Lock()
	remaining := d.remainingFastPolls
	users := d.fastPollsUsers
	d.mu.Unlock()

	if remaining != 0 {
		t.Errorf("remaining = %d, want 0", remaining)
	}
	if users != 0 {
		t.Errorf("users = %d, want 0 (cleared on reaching 0 remaining)", users)
	}
}

// ---------------------------------------------------------------------------
// DataPollHandler – additional tests
// ---------------------------------------------------------------------------

func TestDataPollHandler_WithOptions(t *testing.T) {
	t.Parallel()

	cp := &mockChildProvider{}
	is := &mockIndirectSender{}

	h := NewDataPollHandler(
		WithIndirectSender(is),
		WithHandlerChildProvider(cp),
	)
	if h == nil {
		t.Fatal("NewDataPollHandler with options returned nil")
	}
}

func TestDataPollHandler_GetTxInfo_CreatesNew(t *testing.T) {
	t.Parallel()

	h := NewDataPollHandler()
	child := newSleepyChild(0x0401)

	info := h.GetTxInfo(child)
	if info == nil {
		t.Fatal("GetTxInfo returned nil")
	}
	// Default values.
	if info.DataPollPending || info.FramePurgePending || info.FrameReplacePending {
		t.Error("new IndirectTxInfo should have all pending flags false")
	}
	if info.IndirectTxAttempts != 0 {
		t.Errorf("tx attempts = %d, want 0", info.IndirectTxAttempts)
	}
}

func TestDataPollHandler_GetTxInfo_ReturnsSame(t *testing.T) {
	t.Parallel()

	h := NewDataPollHandler()
	child := newSleepyChild(0x0401)

	info1 := h.GetTxInfo(child)
	info2 := h.GetTxInfo(child)
	if info1 != info2 {
		t.Error("GetTxInfo should return same pointer for same child")
	}
}

func TestDataPollHandler_HandleDataPoll_UpdatesLastHeard(t *testing.T) {
	t.Parallel()

	h := NewDataPollHandler()
	child := newSleepyChild(0x0401)
	child.LastHeard = time.Time{}

	h.HandleDataPoll(child)
	if child.LastHeard.IsZero() {
		t.Error("LastHeard should be updated")
	}
}

func TestDataPollHandler_RequestFrameChange_FrameAdded_ActiveTx(t *testing.T) {
	t.Parallel()

	h := NewDataPollHandler()
	child := newSleepyChild(0x0401)
	h.HandleDataPoll(child)

	h.RequestFrameChange(FrameAdded, child)

	info := h.GetTxInfo(child)
	if !info.FrameReplacePending {
		t.Error("FrameReplacePending should be true for FrameAdded on active tx")
	}
}

func TestDataPollHandler_RequestFrameChange_NoSender(t *testing.T) {
	t.Parallel()

	// No indirect sender — should not panic.
	h := NewDataPollHandler()
	child := newSleepyChild(0x0401)

	h.RequestFrameChange(FrameAdded, child)

	info := h.GetTxInfo(child)
	if info.IndirectTxAttempts != 0 {
		t.Errorf("tx attempts = %d, want 0", info.IndirectTxAttempts)
	}
}

func TestDataPollHandler_HandleFrameSent_FailureBelowMax(t *testing.T) {
	t.Parallel()

	is := &mockIndirectSender{}
	h := NewDataPollHandler(WithIndirectSender(is))
	child := newSleepyChild(0x0401)

	h.HandleDataPoll(child)
	h.HandleFrameSent(child, errors.ErrNoAck)

	info := h.GetTxInfo(child)
	if info.IndirectTxAttempts != 1 {
		t.Errorf("tx attempts = %d, want 1", info.IndirectTxAttempts)
	}
	// Below max, HandleSentFrameToChild should NOT be called.
	if is.getSentFrameCount() != 0 {
		t.Errorf("sent frame count = %d, want 0 (below max)", is.getSentFrameCount())
	}
}

func TestDataPollHandler_HandleFrameSent_NoIndirectSender(t *testing.T) {
	t.Parallel()

	h := NewDataPollHandler() // no indirect sender
	child := newSleepyChild(0x0401)

	h.HandleDataPoll(child)
	// Should not panic with nil indirect sender.
	h.HandleFrameSent(child, nil)

	if h.GetIndirectTxChild() != nil {
		t.Error("indirect tx child should be cleared")
	}
}

func TestDataPollHandler_ProcessPendingPolls_NoProvider(t *testing.T) {
	t.Parallel()

	h := NewDataPollHandler() // no child provider
	child1 := newSleepyChild(0x0401)
	child2 := newSleepyChild(0x0402)

	h.HandleDataPoll(child1)
	h.HandleDataPoll(child2)

	h.HandleFrameSent(child1, nil)

	// Without provider, pending polls can't be resolved.
	if h.GetIndirectTxChild() != nil {
		t.Error("should not find next child without provider")
	}
}

func TestDataPollHandler_Clear_ResetsAllState(t *testing.T) {
	t.Parallel()

	h := NewDataPollHandler()
	child1 := newSleepyChild(0x0401)
	child2 := newSleepyChild(0x0402)

	h.HandleDataPoll(child1)
	h.HandleDataPoll(child2)

	h.Clear()

	if h.GetIndirectTxChild() != nil {
		t.Error("indirect tx child should be nil after Clear")
	}
	// TxInfo should be fresh after Clear.
	info := h.GetTxInfo(child1)
	if info.DataPollPending || info.FramePurgePending {
		t.Error("txInfo should be fresh after Clear")
	}
}

func TestDataPollHandler_ProcessPendingPolls_EarliestLastHeard(t *testing.T) {
	t.Parallel()

	cp := &mockChildProvider{}
	h := NewDataPollHandler(WithHandlerChildProvider(cp))

	// child2 has earlier LastHeard — should be served first.
	child1 := newSleepyChild(0x0401)
	child1.LastHeard = time.Now()
	child2 := newSleepyChild(0x0402)
	child2.LastHeard = time.Now().Add(-10 * time.Second)
	child3 := newSleepyChild(0x0403)
	child3.LastHeard = time.Now().Add(-5 * time.Second)

	cp.addChild(child1)
	cp.addChild(child2)
	cp.addChild(child3)

	h.HandleDataPoll(child1)
	h.HandleDataPoll(child2)
	h.HandleDataPoll(child3)

	// Complete child1.
	h.HandleFrameSent(child1, nil)

	// child2 has earliest LastHeard.
	if h.GetIndirectTxChild() != child2 {
		got := h.GetIndirectTxChild()
		rloc := uint16(0)
		if got != nil {
			rloc = got.RLOC16
		}
		t.Errorf("indirect tx child RLOC = 0x%04X, want 0x0402 (earliest)", rloc)
	}
}

// ---------------------------------------------------------------------------
// IndirectTxInfo – additional tests
// ---------------------------------------------------------------------------

func TestIndirectTxInfo_Fields(t *testing.T) {
	t.Parallel()

	info := &IndirectTxInfo{
		DataPollPending:      true,
		FramePurgePending:    true,
		FrameReplacePending:  true,
		IndirectFrameCounter: 42,
		IndirectKeyID:        7,
		IndirectDSN:          99,
		IndirectTxAttempts:   3,
	}

	if !info.DataPollPending {
		t.Error("DataPollPending should be true")
	}
	if !info.FramePurgePending {
		t.Error("FramePurgePending should be true")
	}
	if !info.FrameReplacePending {
		t.Error("FrameReplacePending should be true")
	}
	if info.IndirectFrameCounter != 42 {
		t.Errorf("IndirectFrameCounter = %d, want 42", info.IndirectFrameCounter)
	}
	if info.IndirectKeyID != 7 {
		t.Errorf("IndirectKeyID = %d, want 7", info.IndirectKeyID)
	}
	if info.IndirectDSN != 99 {
		t.Errorf("IndirectDSN = %d, want 99", info.IndirectDSN)
	}

	info.ResetTxAttempts()
	if info.IndirectTxAttempts != 0 {
		t.Errorf("IndirectTxAttempts = %d, want 0 after reset", info.IndirectTxAttempts)
	}
}

// ---------------------------------------------------------------------------
// DataPoll constants – additional checks
// ---------------------------------------------------------------------------

func TestDataPollConstants(t *testing.T) {
	t.Parallel()

	if DefaultPollPeriod != 240_000 {
		t.Errorf("DefaultPollPeriod = %d, want 240000", DefaultPollPeriod)
	}
	if RetxPollPeriod != 1000 {
		t.Errorf("RetxPollPeriod = %d, want 1000", RetxPollPeriod)
	}
	if AttachPollPeriod != 100 {
		t.Errorf("AttachPollPeriod = %d, want 100", AttachPollPeriod)
	}
	if MaxFastPollsUsers != 63 {
		t.Errorf("MaxFastPollsUsers = %d, want 63", MaxFastPollsUsers)
	}
	if QuickPollsAfterTimeout != 5 {
		t.Errorf("QuickPollsAfterTimeout = %d, want 5", QuickPollsAfterTimeout)
	}
	if MaxPollRetxAttempts != 4 {
		t.Errorf("MaxPollRetxAttempts = %d, want 4", MaxPollRetxAttempts)
	}
	if MaxPollTriggeredTxAttempts != 5 {
		t.Errorf("MaxPollTriggeredTxAttempts = %d, want 5", MaxPollTriggeredTxAttempts)
	}
}
