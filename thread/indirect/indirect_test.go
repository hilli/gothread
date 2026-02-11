// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package indirect

import (
	"fmt"
	"testing"

	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Mock radio for SourceMatchController tests
// ---------------------------------------------------------------------------

type mockRadio struct {
	shortEntries  map[uint16]bool
	extEntries    map[[8]byte]bool
	enabled       bool
	addShortErr   error // inject error on AddShortSourceMatch
	addExtErr     error // inject error on AddExtSourceMatch
	clearShortErr error
	clearExtErr   error
	calls         []string // record of method calls
}

func newMockRadio() *mockRadio {
	return &mockRadio{
		shortEntries: make(map[uint16]bool),
		extEntries:   make(map[[8]byte]bool),
	}
}

func (r *mockRadio) AddShortSourceMatch(addr uint16) error {
	r.calls = append(r.calls, fmt.Sprintf("AddShort(%d)", addr))
	if r.addShortErr != nil {
		return r.addShortErr
	}
	r.shortEntries[addr] = true
	return nil
}

func (r *mockRadio) AddExtSourceMatch(addr [8]byte) error {
	r.calls = append(r.calls, fmt.Sprintf("AddExt(%v)", addr))
	if r.addExtErr != nil {
		return r.addExtErr
	}
	r.extEntries[addr] = true
	return nil
}

func (r *mockRadio) ClearShortSourceMatch(addr uint16) error {
	r.calls = append(r.calls, fmt.Sprintf("ClearShort(%d)", addr))
	if r.clearShortErr != nil {
		return r.clearShortErr
	}
	delete(r.shortEntries, addr)
	return nil
}

func (r *mockRadio) ClearExtSourceMatch(addr [8]byte) error {
	r.calls = append(r.calls, fmt.Sprintf("ClearExt(%v)", addr))
	if r.clearExtErr != nil {
		return r.clearExtErr
	}
	delete(r.extEntries, addr)
	return nil
}

func (r *mockRadio) ClearSourceMatchTable() {
	r.calls = append(r.calls, "ClearTable")
	r.shortEntries = make(map[uint16]bool)
	r.extEntries = make(map[[8]byte]bool)
}

func (r *mockRadio) EnableSourceMatch(enable bool) {
	r.calls = append(r.calls, fmt.Sprintf("Enable(%v)", enable))
	r.enabled = enable
}

// ---------------------------------------------------------------------------
// Mock child for Sender tests
// ---------------------------------------------------------------------------

type mockChild struct {
	shortAddr       uint16
	extAddr         [8]byte
	rxOnWhenIdle    bool
	indirectPending bool
}

func (c *mockChild) GetShortAddress() uint16        { return c.shortAddr }
func (c *mockChild) GetExtAddress() [8]byte         { return c.extAddr }
func (c *mockChild) IsRxOnWhenIdle() bool           { return c.rxOnWhenIdle }
func (c *mockChild) IsIndirectMessagePending() bool { return c.indirectPending }

// ---------------------------------------------------------------------------
// Mock frame sender
// ---------------------------------------------------------------------------

type mockFrameSender struct {
	sent    []sentFrame
	sendErr error
}

type sentFrame struct {
	childAddr uint16
	payload   []byte
}

func (f *mockFrameSender) SendIndirectFrame(child ChildInfo, payload []byte) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	buf := make([]byte, len(payload))
	copy(buf, payload)
	f.sent = append(f.sent, sentFrame{
		childAddr: child.GetShortAddress(),
		payload:   buf,
	})
	return nil
}

// ===========================================================================
// SourceMatchController tests
// ===========================================================================

func TestSourceMatchController_NewInitialState(t *testing.T) {
	radio := newMockRadio()
	c := NewSourceMatchController(radio)

	if c.IsEnabled() {
		t.Error("expected source match to be disabled initially")
	}
	if c.HasPending(0x1234) {
		t.Error("expected no pending for arbitrary address")
	}
}

func TestSourceMatchController_SetFramePendingShort(t *testing.T) {
	radio := newMockRadio()
	c := NewSourceMatchController(radio)

	if err := c.SetFramePending(0x0001, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.HasPending(0x0001) {
		t.Error("expected pending for 0x0001")
	}
	if !c.IsEnabled() {
		t.Error("expected source match to be enabled after adding entry")
	}
	if !radio.shortEntries[0x0001] {
		t.Error("expected radio to have short entry 0x0001")
	}
}

func TestSourceMatchController_SetFramePendingClear(t *testing.T) {
	radio := newMockRadio()
	c := NewSourceMatchController(radio)

	_ = c.SetFramePending(0x0001, true)
	if err := c.SetFramePending(0x0001, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.HasPending(0x0001) {
		t.Error("expected no pending after clearing")
	}
	if radio.shortEntries[0x0001] {
		t.Error("expected radio to not have short entry 0x0001")
	}
}

func TestSourceMatchController_SetFramePendingAlready(t *testing.T) {
	radio := newMockRadio()
	c := NewSourceMatchController(radio)

	_ = c.SetFramePending(0x0001, true)
	err := c.SetFramePending(0x0001, true)
	if err != errors.ErrAlready {
		t.Fatalf("expected ErrAlready, got %v", err)
	}
}

func TestSourceMatchController_SetFramePendingExt(t *testing.T) {
	radio := newMockRadio()
	c := NewSourceMatchController(radio)

	addr := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	if err := c.SetFramePendingExt(addr, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.HasPendingExt(addr) {
		t.Error("expected pending for ext address")
	}
	if !c.IsEnabled() {
		t.Error("expected source match to be enabled")
	}
}

func TestSourceMatchController_SetFramePendingExtClear(t *testing.T) {
	radio := newMockRadio()
	c := NewSourceMatchController(radio)

	addr := [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}

	_ = c.SetFramePendingExt(addr, true)
	if err := c.SetFramePendingExt(addr, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.HasPendingExt(addr) {
		t.Error("expected no pending after clearing ext")
	}
}

func TestSourceMatchController_SetFramePendingExtAlready(t *testing.T) {
	radio := newMockRadio()
	c := NewSourceMatchController(radio)

	addr := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	_ = c.SetFramePendingExt(addr, true)
	err := c.SetFramePendingExt(addr, true)
	if err != errors.ErrAlready {
		t.Fatalf("expected ErrAlready, got %v", err)
	}
}

func TestSourceMatchController_ClearTable(t *testing.T) {
	radio := newMockRadio()
	c := NewSourceMatchController(radio)

	_ = c.SetFramePending(0x0001, true)
	_ = c.SetFramePending(0x0002, true)
	addr := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	_ = c.SetFramePendingExt(addr, true)

	c.ClearTable()

	if c.HasPending(0x0001) || c.HasPending(0x0002) || c.HasPendingExt(addr) {
		t.Error("expected no pending entries after ClearTable")
	}
	if c.IsEnabled() {
		t.Error("expected source match disabled after ClearTable")
	}
}

func TestSourceMatchController_EnableDisable(t *testing.T) {
	radio := newMockRadio()
	c := NewSourceMatchController(radio)

	c.Enable(true)
	if !c.IsEnabled() {
		t.Error("expected enabled")
	}
	c.Enable(false)
	if c.IsEnabled() {
		t.Error("expected disabled")
	}
}

func TestSourceMatchController_RadioAddError_DisablesMatching(t *testing.T) {
	radio := newMockRadio()
	radio.addShortErr = fmt.Errorf("table full")
	c := NewSourceMatchController(radio)

	// When the radio can't add the entry, the controller should disable
	// source matching (so the radio sets Frame Pending on all ACKs as a safe
	// fallback) and still track the entry internally.
	err := c.SetFramePending(0x0001, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.HasPending(0x0001) {
		t.Error("expected entry to be tracked internally")
	}
	if c.IsEnabled() {
		t.Error("expected source match disabled when radio add fails")
	}
}

func TestSourceMatchController_RadioAddExtError_DisablesMatching(t *testing.T) {
	radio := newMockRadio()
	radio.addExtErr = fmt.Errorf("table full")
	c := NewSourceMatchController(radio)

	addr := [8]byte{0xAA, 0xBB}
	err := c.SetFramePendingExt(addr, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.HasPendingExt(addr) {
		t.Error("expected entry to be tracked internally")
	}
	if c.IsEnabled() {
		t.Error("expected source match disabled when radio add fails")
	}
}

func TestSourceMatchController_MultipleEntries(t *testing.T) {
	radio := newMockRadio()
	c := NewSourceMatchController(radio)

	_ = c.SetFramePending(0x0001, true)
	_ = c.SetFramePending(0x0002, true)
	_ = c.SetFramePending(0x0003, true)

	if !c.IsEnabled() {
		t.Error("expected enabled with entries")
	}

	// Remove one — still has entries, should stay enabled.
	_ = c.SetFramePending(0x0001, false)
	if !c.IsEnabled() {
		t.Error("expected still enabled with remaining entries")
	}

	// Remove remaining.
	_ = c.SetFramePending(0x0002, false)
	_ = c.SetFramePending(0x0003, false)
	if c.IsEnabled() {
		t.Error("expected disabled with no entries")
	}
}

func TestSourceMatchController_ClearNonExistent(t *testing.T) {
	radio := newMockRadio()
	c := NewSourceMatchController(radio)

	// Clearing a non-existent entry should not error.
	err := c.SetFramePending(0x9999, false)
	if err != nil {
		t.Fatalf("unexpected error clearing non-existent: %v", err)
	}
}

func TestSourceMatchController_ClearExtNonExistent(t *testing.T) {
	radio := newMockRadio()
	c := NewSourceMatchController(radio)

	addr := [8]byte{0xFF, 0xFF}
	err := c.SetFramePendingExt(addr, false)
	if err != nil {
		t.Fatalf("unexpected error clearing non-existent ext: %v", err)
	}
}

// ===========================================================================
// Sender tests
// ===========================================================================

func TestSender_NewDefaults(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{}
	s := NewSender(fs, srcMatch)

	if s.maxMessages != defaultMaxMessages {
		t.Errorf("expected maxMessages=%d, got %d", defaultMaxMessages, s.maxMessages)
	}
	if s.defaultMaxRetries != defaultMaxRetries {
		t.Errorf("expected defaultMaxRetries=%d, got %d", defaultMaxRetries, s.defaultMaxRetries)
	}
	if s.maxTxAttempts != defaultMaxTxAttempts {
		t.Errorf("expected maxTxAttempts=%d, got %d", defaultMaxTxAttempts, s.maxTxAttempts)
	}
	if s.GetTotalMessageCount() != 0 {
		t.Error("expected empty queue")
	}
}

func TestSender_Options(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{}
	s := NewSender(fs, srcMatch,
		WithMaxMessages(128),
		WithDefaultMaxRetries(5),
		WithMaxTxAttempts(10),
	)

	if s.maxMessages != 128 {
		t.Errorf("expected maxMessages=128, got %d", s.maxMessages)
	}
	if s.defaultMaxRetries != 5 {
		t.Errorf("expected defaultMaxRetries=5, got %d", s.defaultMaxRetries)
	}
	if s.maxTxAttempts != 10 {
		t.Errorf("expected maxTxAttempts=10, got %d", s.maxTxAttempts)
	}
}

func TestSender_AddMessage(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{}
	s := NewSender(fs, srcMatch)

	err := s.AddMessage(0x0001, []byte{0xAA, 0xBB})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.GetTotalMessageCount() != 1 {
		t.Errorf("expected 1 message, got %d", s.GetTotalMessageCount())
	}
	if s.GetMessageCount(0x0001) != 1 {
		t.Errorf("expected 1 message for 0x0001, got %d", s.GetMessageCount(0x0001))
	}

	// Source match should have pending for this child.
	if !srcMatch.HasPending(0x0001) {
		t.Error("expected source match pending for 0x0001")
	}
}

func TestSender_AddMessage_NoBufs(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{}
	s := NewSender(fs, srcMatch, WithMaxMessages(2))

	_ = s.AddMessage(0x0001, []byte{1})
	_ = s.AddMessage(0x0001, []byte{2})
	err := s.AddMessage(0x0001, []byte{3})
	if err != errors.ErrNoBufs {
		t.Fatalf("expected ErrNoBufs, got %v", err)
	}
}

func TestSender_AddMessage_PayloadCopied(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{}
	s := NewSender(fs, srcMatch)

	payload := []byte{0x01, 0x02, 0x03}
	_ = s.AddMessage(0x0001, payload)

	// Mutate the original — should not affect the queued message.
	payload[0] = 0xFF

	s.mu.Lock()
	if s.messages[0].Payload[0] != 0x01 {
		t.Error("payload was not copied on AddMessage")
	}
	s.mu.Unlock()
}

func TestSender_RemoveMessages(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{}
	s := NewSender(fs, srcMatch)

	_ = s.AddMessage(0x0001, []byte{1})
	_ = s.AddMessage(0x0001, []byte{2})
	_ = s.AddMessage(0x0002, []byte{3})

	removed := s.RemoveMessages(0x0001)
	if removed != 2 {
		t.Errorf("expected 2 removed, got %d", removed)
	}
	if s.GetTotalMessageCount() != 1 {
		t.Errorf("expected 1 remaining, got %d", s.GetTotalMessageCount())
	}
	if s.GetMessageCount(0x0001) != 0 {
		t.Error("expected no messages for 0x0001")
	}
	if srcMatch.HasPending(0x0001) {
		t.Error("expected source match cleared for 0x0001")
	}
	// 0x0002 should still be pending.
	if !srcMatch.HasPending(0x0002) {
		t.Error("expected source match still pending for 0x0002")
	}
}

func TestSender_RemoveMessages_None(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{}
	s := NewSender(fs, srcMatch)

	removed := s.RemoveMessages(0x9999)
	if removed != 0 {
		t.Errorf("expected 0 removed, got %d", removed)
	}
}

func TestSender_HandleDataPoll_Success(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{}
	s := NewSender(fs, srcMatch)

	child := &mockChild{shortAddr: 0x0001}

	_ = s.AddMessage(0x0001, []byte{0xDE, 0xAD})

	err := s.HandleDataPoll(child)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fs.sent) != 1 {
		t.Fatalf("expected 1 sent frame, got %d", len(fs.sent))
	}
	if fs.sent[0].childAddr != 0x0001 {
		t.Errorf("expected child addr 0x0001, got 0x%04x", fs.sent[0].childAddr)
	}
	if len(fs.sent[0].payload) != 2 || fs.sent[0].payload[0] != 0xDE {
		t.Error("unexpected payload in sent frame")
	}

	// Message should be removed from queue.
	if s.GetTotalMessageCount() != 0 {
		t.Errorf("expected 0 messages, got %d", s.GetTotalMessageCount())
	}
	// Source match should be cleared.
	if srcMatch.HasPending(0x0001) {
		t.Error("expected source match cleared after last message sent")
	}
}

func TestSender_HandleDataPoll_MultipleMessages(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{}
	s := NewSender(fs, srcMatch)

	child := &mockChild{shortAddr: 0x0001}

	_ = s.AddMessage(0x0001, []byte{1})
	_ = s.AddMessage(0x0001, []byte{2})

	// First poll sends first message.
	err := s.HandleDataPoll(child)
	if err != nil {
		t.Fatalf("first poll error: %v", err)
	}
	if s.GetMessageCount(0x0001) != 1 {
		t.Errorf("expected 1 message remaining, got %d", s.GetMessageCount(0x0001))
	}
	// Source match should still be pending (more messages).
	if !srcMatch.HasPending(0x0001) {
		t.Error("expected source match still pending")
	}

	// Second poll sends second message.
	err = s.HandleDataPoll(child)
	if err != nil {
		t.Fatalf("second poll error: %v", err)
	}
	if s.GetMessageCount(0x0001) != 0 {
		t.Errorf("expected 0 messages, got %d", s.GetMessageCount(0x0001))
	}
	if srcMatch.HasPending(0x0001) {
		t.Error("expected source match cleared")
	}

	if len(fs.sent) != 2 {
		t.Errorf("expected 2 sent frames, got %d", len(fs.sent))
	}
}

func TestSender_HandleDataPoll_NoMessages(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{}
	s := NewSender(fs, srcMatch)

	child := &mockChild{shortAddr: 0x0001}
	err := s.HandleDataPoll(child)
	if err != errors.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSender_HandleDataPoll_SendFailure_Retry(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{sendErr: fmt.Errorf("tx failed")}
	s := NewSender(fs, srcMatch, WithDefaultMaxRetries(2))

	child := &mockChild{shortAddr: 0x0001}
	_ = s.AddMessage(0x0001, []byte{0x42})

	// First failure — message should stay in queue with incremented retry.
	err := s.HandleDataPoll(child)
	if err != errors.ErrFailed {
		t.Fatalf("expected ErrFailed, got %v", err)
	}
	if s.GetMessageCount(0x0001) != 1 {
		t.Error("expected message to remain in queue after first failure")
	}

	// Second failure.
	err = s.HandleDataPoll(child)
	if err != errors.ErrFailed {
		t.Fatalf("expected ErrFailed, got %v", err)
	}
	if s.GetMessageCount(0x0001) != 1 {
		t.Error("expected message to remain after second failure")
	}

	// Third failure — exceeds max retries (2), message should be dropped.
	err = s.HandleDataPoll(child)
	if err != errors.ErrFailed {
		t.Fatalf("expected ErrFailed, got %v", err)
	}
	if s.GetMessageCount(0x0001) != 0 {
		t.Error("expected message to be dropped after exceeding max retries")
	}
	if srcMatch.HasPending(0x0001) {
		t.Error("expected source match cleared after dropping last message")
	}
}

func TestSender_HandleSentSuccess(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{}
	s := NewSender(fs, srcMatch)

	// Simulate some previous failures.
	s.mu.Lock()
	s.txAttempts[0x0001] = 3
	s.mu.Unlock()

	s.HandleSentSuccess(0x0001)

	s.mu.Lock()
	if _, ok := s.txAttempts[0x0001]; ok {
		t.Error("expected txAttempts cleared on success")
	}
	s.mu.Unlock()
}

func TestSender_HandleSentFailure(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{}
	s := NewSender(fs, srcMatch, WithMaxTxAttempts(3))

	// 1st failure — should not remove child.
	if s.HandleSentFailure(0x0001) {
		t.Error("expected false on 1st failure")
	}
	// 2nd failure.
	if s.HandleSentFailure(0x0001) {
		t.Error("expected false on 2nd failure")
	}
	// 3rd failure — should signal child removal.
	if !s.HandleSentFailure(0x0001) {
		t.Error("expected true on 3rd failure (maxTxAttempts=3)")
	}
}

func TestSender_HandleChildRemoved(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{}
	s := NewSender(fs, srcMatch)

	_ = s.AddMessage(0x0001, []byte{1})
	_ = s.AddMessage(0x0001, []byte{2})
	s.mu.Lock()
	s.txAttempts[0x0001] = 2
	s.mu.Unlock()

	s.HandleChildRemoved(0x0001)

	if s.GetMessageCount(0x0001) != 0 {
		t.Error("expected all messages removed")
	}
	if srcMatch.HasPending(0x0001) {
		t.Error("expected source match cleared")
	}
	s.mu.Lock()
	if _, ok := s.txAttempts[0x0001]; ok {
		t.Error("expected txAttempts cleared")
	}
	s.mu.Unlock()
}

func TestSender_GetTotalMessageCount(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{}
	s := NewSender(fs, srcMatch)

	_ = s.AddMessage(0x0001, []byte{1})
	_ = s.AddMessage(0x0002, []byte{2})
	_ = s.AddMessage(0x0001, []byte{3})

	if s.GetTotalMessageCount() != 3 {
		t.Errorf("expected 3, got %d", s.GetTotalMessageCount())
	}
}

func TestSender_HandleDataPoll_MultipleChildren(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{}
	s := NewSender(fs, srcMatch)

	child1 := &mockChild{shortAddr: 0x0001}
	child2 := &mockChild{shortAddr: 0x0002}

	_ = s.AddMessage(0x0001, []byte{0x11})
	_ = s.AddMessage(0x0002, []byte{0x22})
	_ = s.AddMessage(0x0001, []byte{0x33})

	// Child 2 polls — should get its message.
	if err := s.HandleDataPoll(child2); err != nil {
		t.Fatalf("child2 poll error: %v", err)
	}
	if s.GetMessageCount(0x0002) != 0 {
		t.Error("expected 0 messages for child2")
	}
	if s.GetMessageCount(0x0001) != 2 {
		t.Error("expected 2 messages for child1 still")
	}

	// Child 1 polls — should get first queued message.
	if err := s.HandleDataPoll(child1); err != nil {
		t.Fatalf("child1 poll error: %v", err)
	}
	if s.GetMessageCount(0x0001) != 1 {
		t.Errorf("expected 1 message for child1, got %d", s.GetMessageCount(0x0001))
	}

	// Verify payloads.
	if len(fs.sent) != 2 {
		t.Fatalf("expected 2 sent, got %d", len(fs.sent))
	}
	if fs.sent[0].payload[0] != 0x22 {
		t.Errorf("expected child2 payload 0x22, got 0x%02x", fs.sent[0].payload[0])
	}
	if fs.sent[1].payload[0] != 0x11 {
		t.Errorf("expected child1 first payload 0x11, got 0x%02x", fs.sent[1].payload[0])
	}
}

// ===========================================================================
// CslTxScheduler tests
// ===========================================================================

func TestCslTxScheduler_SetGetRemoveConfig(t *testing.T) {
	csl := NewCslTxScheduler()

	if csl.HasConfig(0x0001) {
		t.Error("expected no config initially")
	}

	config := CslConfig{Period: 100, Timeout: 30, Channel: 11}
	csl.SetConfig(0x0001, config)

	if !csl.HasConfig(0x0001) {
		t.Error("expected config after SetConfig")
	}

	got, ok := csl.GetConfig(0x0001)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if got.Period != 100 || got.Timeout != 30 || got.Channel != 11 {
		t.Errorf("unexpected config: %+v", got)
	}

	csl.RemoveConfig(0x0001)
	if csl.HasConfig(0x0001) {
		t.Error("expected no config after RemoveConfig")
	}

	_, ok = csl.GetConfig(0x0001)
	if ok {
		t.Error("expected ok=false after RemoveConfig")
	}
}

func TestCslTxScheduler_GetConfig_ReturnsCopy(t *testing.T) {
	csl := NewCslTxScheduler()

	csl.SetConfig(0x0001, CslConfig{Period: 100, Timeout: 30, Channel: 11})

	got, _ := csl.GetConfig(0x0001)
	got.Period = 999

	got2, _ := csl.GetConfig(0x0001)
	if got2.Period != 100 {
		t.Error("GetConfig should return a copy, not a reference")
	}
}

func TestCslTxScheduler_MultipleChildren(t *testing.T) {
	csl := NewCslTxScheduler()

	csl.SetConfig(0x0001, CslConfig{Period: 100})
	csl.SetConfig(0x0002, CslConfig{Period: 200})

	c1, _ := csl.GetConfig(0x0001)
	c2, _ := csl.GetConfig(0x0002)

	if c1.Period != 100 {
		t.Errorf("expected period 100, got %d", c1.Period)
	}
	if c2.Period != 200 {
		t.Errorf("expected period 200, got %d", c2.Period)
	}

	csl.RemoveConfig(0x0001)
	if csl.HasConfig(0x0001) {
		t.Error("expected no config for 0x0001")
	}
	if !csl.HasConfig(0x0002) {
		t.Error("expected config for 0x0002 still present")
	}
}

// ===========================================================================
// Integration: Sender + SourceMatchController end-to-end
// ===========================================================================

func TestIntegration_SenderSourceMatch(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{}
	s := NewSender(fs, srcMatch)

	child := &mockChild{shortAddr: 0x0042}

	// Initially no pending.
	if srcMatch.HasPending(0x0042) {
		t.Error("expected no pending initially")
	}

	// Add message — should set pending.
	_ = s.AddMessage(0x0042, []byte{0xCA, 0xFE})
	if !srcMatch.HasPending(0x0042) {
		t.Error("expected pending after AddMessage")
	}

	// Child polls and message is sent.
	if err := s.HandleDataPoll(child); err != nil {
		t.Fatalf("poll error: %v", err)
	}

	// No more messages — pending should be cleared.
	if srcMatch.HasPending(0x0042) {
		t.Error("expected pending cleared after all messages sent")
	}
	if s.GetTotalMessageCount() != 0 {
		t.Error("expected empty queue")
	}
}

func TestIntegration_ChildRemovedClearsEverything(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{}
	s := NewSender(fs, srcMatch)

	_ = s.AddMessage(0x0042, []byte{1})
	_ = s.AddMessage(0x0042, []byte{2})
	_ = s.AddMessage(0x0042, []byte{3})

	// Simulate some failures.
	s.HandleSentFailure(0x0042)
	s.HandleSentFailure(0x0042)

	s.HandleChildRemoved(0x0042)

	if s.GetTotalMessageCount() != 0 {
		t.Error("expected empty queue after child removed")
	}
	if srcMatch.HasPending(0x0042) {
		t.Error("expected source match cleared after child removed")
	}
}

func TestSender_Options_ZeroValues(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{}

	// Zero values for WithMaxMessages and WithMaxTxAttempts should be ignored.
	s := NewSender(fs, srcMatch,
		WithMaxMessages(0),
		WithMaxTxAttempts(0),
		WithDefaultMaxRetries(0),
	)

	if s.maxMessages != defaultMaxMessages {
		t.Errorf("expected default maxMessages, got %d", s.maxMessages)
	}
	if s.maxTxAttempts != defaultMaxTxAttempts {
		t.Errorf("expected default maxTxAttempts, got %d", s.maxTxAttempts)
	}
	// DefaultMaxRetries of 0 is valid (no retries).
	if s.defaultMaxRetries != 0 {
		t.Errorf("expected defaultMaxRetries=0, got %d", s.defaultMaxRetries)
	}
}

func TestSender_HandleSentFailure_ResetOnSuccess(t *testing.T) {
	radio := newMockRadio()
	srcMatch := NewSourceMatchController(radio)
	fs := &mockFrameSender{}
	s := NewSender(fs, srcMatch, WithMaxTxAttempts(3))

	// Two failures.
	s.HandleSentFailure(0x0001)
	s.HandleSentFailure(0x0001)

	// Success resets the counter.
	s.HandleSentSuccess(0x0001)

	// Two more failures — should not trigger removal yet.
	if s.HandleSentFailure(0x0001) {
		t.Error("expected false after reset")
	}
	if s.HandleSentFailure(0x0001) {
		t.Error("expected false on 2nd failure after reset")
	}

	// Third after reset — now should trigger.
	if !s.HandleSentFailure(0x0001) {
		t.Error("expected true on 3rd failure")
	}
}
