// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package supervision

import (
	"sync"
	"testing"
	"time"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/thread/mle"
)

// ---------------------------------------------------------------------------
// Test helpers / mocks
// ---------------------------------------------------------------------------

// mockChildProvider implements ChildProvider for tests.
type mockChildProvider struct {
	mu       sync.Mutex
	children []*mle.Child
}

func (m *mockChildProvider) GetChildren() []*mle.Child {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*mle.Child, len(m.children))
	copy(out, m.children)
	return out
}

func (m *mockChildProvider) addChild(c *mle.Child) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.children = append(m.children, c)
}

// mockMessageSender implements MessageSender for tests.
type mockMessageSender struct {
	mu   sync.Mutex
	sent []*mle.Child
	err  error
}

func (m *mockMessageSender) SendSupervisionMessage(child *mle.Child) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, child)
	return m.err
}

func (m *mockMessageSender) getSentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

func (m *mockMessageSender) getLastSent() *mle.Child {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) == 0 {
		return nil
	}
	return m.sent[len(m.sent)-1]
}

// mockTimer implements Timer for deterministic testing.
type mockTimer struct {
	mu      sync.Mutex
	ch      chan time.Time
	pending bool
	dur     time.Duration
}

func newMockTimer() *mockTimer {
	return &mockTimer{
		ch: make(chan time.Time, 1),
	}
}

func (t *mockTimer) Reset(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dur = d
	t.pending = true
}

func (t *mockTimer) Stop() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	was := t.pending
	t.pending = false
	return was
}

func (t *mockTimer) C() <-chan time.Time {
	return t.ch
}

func (t *mockTimer) fire() {
	t.mu.Lock()
	t.pending = false
	t.mu.Unlock()
	t.ch <- time.Now()
}

func (t *mockTimer) isPending() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pending
}

func (t *mockTimer) getDuration() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dur
}

// mockParentLossHandler implements ParentLossHandler.
type mockParentLossHandler struct {
	mu    sync.Mutex
	count int
}

func (h *mockParentLossHandler) HandleParentLoss() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.count++
}

func (h *mockParentLossHandler) getCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.count
}

// mockPollTransmitter implements PollTransmitter.
type mockPollTransmitter struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (m *mockPollTransmitter) TransmitDataPoll() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return m.err
}

func (m *mockPollTransmitter) getCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// mockIndirectSender implements IndirectSender.
type mockIndirectSender struct {
	mu                   sync.Mutex
	frameChangeDone      []*mle.Child
	sentFrameToChild     []*mle.Child
	sentFrameErrors      []error
	indirectMessageCount uint16
}

func (m *mockIndirectSender) HandleFrameChangeDone(child *mle.Child) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.frameChangeDone = append(m.frameChangeDone, child)
}

func (m *mockIndirectSender) HandleSentFrameToChild(child *mle.Child, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentFrameToChild = append(m.sentFrameToChild, child)
	m.sentFrameErrors = append(m.sentFrameErrors, err)
}

func (m *mockIndirectSender) GetIndirectMessageCount(_ *mle.Child) uint16 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.indirectMessageCount
}

func (m *mockIndirectSender) getFrameChangeDoneCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.frameChangeDone)
}

func (m *mockIndirectSender) getSentFrameCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sentFrameToChild)
}

// newSleepyChild creates a child in StateValid with RxOnWhenIdle=false.
func newSleepyChild(rloc uint16) *mle.Child {
	c := &mle.Child{}
	c.State = mle.StateValid
	c.RLOC16 = rloc
	c.Mode = mle.NewDeviceMode(0) // RxOnWhenIdle = false
	c.MacAddr = types.ExtAddress{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, byte(rloc >> 8), byte(rloc)}
	return c
}

// newRxOnChild creates a child in StateValid with RxOnWhenIdle=true.
func newRxOnChild(rloc uint16) *mle.Child {
	c := &mle.Child{}
	c.State = mle.StateValid
	c.RLOC16 = rloc
	c.Mode = mle.NewDeviceMode(mle.ModeRxOnWhenIdle)
	c.MacAddr = types.ExtAddress{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, byte(rloc >> 8), byte(rloc)}
	return c
}

// ---------------------------------------------------------------------------
// Supervisor tests
// ---------------------------------------------------------------------------

func TestNewSupervisor(t *testing.T) {
	t.Parallel()

	s := NewSupervisor()
	if s == nil {
		t.Fatal("NewSupervisor returned nil")
	}
	if s.GetSupervisionInterval() != DefaultSupervisionInterval {
		t.Errorf("interval = %d, want %d", s.GetSupervisionInterval(), DefaultSupervisionInterval)
	}
	if s.IsRunning() {
		t.Error("supervisor should not be running before Start")
	}
}

func TestSupervisor_WithOptions(t *testing.T) {
	t.Parallel()

	cp := &mockChildProvider{}
	ms := &mockMessageSender{}

	s := NewSupervisor(
		WithSupervisionInterval(100),
		WithChildProvider(cp),
		WithMessageSender(ms),
	)

	if s.GetSupervisionInterval() != 100 {
		t.Errorf("interval = %d, want 100", s.GetSupervisionInterval())
	}
}

func TestSupervisor_StartStop(t *testing.T) {
	t.Parallel()

	s := NewSupervisor()

	s.Start()
	if !s.IsRunning() {
		t.Error("supervisor should be running after Start")
	}

	// Double start is a no-op.
	s.Start()
	if !s.IsRunning() {
		t.Error("supervisor should still be running after double Start")
	}

	s.Stop()
	if s.IsRunning() {
		t.Error("supervisor should not be running after Stop")
	}

	// Double stop is safe.
	s.Stop()
}

func TestSupervisor_SetGetInterval(t *testing.T) {
	t.Parallel()

	s := NewSupervisor()
	s.SetSupervisionInterval(42)
	if got := s.GetSupervisionInterval(); got != 42 {
		t.Errorf("interval = %d, want 42", got)
	}
}

func TestSupervisor_UpdateOnSend(t *testing.T) {
	t.Parallel()

	s := NewSupervisor()
	child := newSleepyChild(0x0401)
	child.SecondsSinceSupervision = 100

	s.UpdateOnSend(child)
	if child.SecondsSinceSupervision != 0 {
		t.Errorf("SecondsSinceSupervision = %d, want 0", child.SecondsSinceSupervision)
	}

	// Nil child should not panic.
	s.UpdateOnSend(nil)
}

func TestSupervisor_HandleTimer_SendsToSleepyChild(t *testing.T) {
	t.Parallel()

	cp := &mockChildProvider{}
	ms := &mockMessageSender{}

	child := newSleepyChild(0x0401)
	child.SupervisionInterval = 5
	cp.addChild(child)

	s := NewSupervisor(
		WithChildProvider(cp),
		WithMessageSender(ms),
		WithSupervisionInterval(10),
	)

	// Tick 4 times — not enough.
	for i := 0; i < 4; i++ {
		s.HandleTimer()
	}
	if ms.getSentCount() != 0 {
		t.Errorf("sent = %d, want 0 before interval", ms.getSentCount())
	}

	// 5th tick should trigger send.
	s.HandleTimer()
	if ms.getSentCount() != 1 {
		t.Errorf("sent = %d, want 1 after interval", ms.getSentCount())
	}
	if ms.getLastSent() != child {
		t.Error("sent to wrong child")
	}
	// Timer should be reset.
	if child.SecondsSinceSupervision != 0 {
		t.Errorf("SecondsSinceSupervision = %d, want 0 after send", child.SecondsSinceSupervision)
	}
}

func TestSupervisor_HandleTimer_SkipsRxOnChild(t *testing.T) {
	t.Parallel()

	cp := &mockChildProvider{}
	ms := &mockMessageSender{}

	rxOnChild := newRxOnChild(0x0401)
	rxOnChild.SupervisionInterval = 1
	cp.addChild(rxOnChild)

	s := NewSupervisor(
		WithChildProvider(cp),
		WithMessageSender(ms),
	)

	// Even after many ticks, no message should be sent to an RxOn child.
	for i := 0; i < 10; i++ {
		s.HandleTimer()
	}
	if ms.getSentCount() != 0 {
		t.Errorf("sent = %d, want 0 for RxOn child", ms.getSentCount())
	}
}

func TestSupervisor_HandleTimer_SkipsInvalidState(t *testing.T) {
	t.Parallel()

	cp := &mockChildProvider{}
	ms := &mockMessageSender{}

	child := newSleepyChild(0x0401)
	child.State = mle.StateRestored
	child.SupervisionInterval = 1
	cp.addChild(child)

	s := NewSupervisor(
		WithChildProvider(cp),
		WithMessageSender(ms),
	)

	for i := 0; i < 5; i++ {
		s.HandleTimer()
	}
	if ms.getSentCount() != 0 {
		t.Errorf("sent = %d, want 0 for non-valid child", ms.getSentCount())
	}
}

func TestSupervisor_HandleTimer_UsesDefaultInterval(t *testing.T) {
	t.Parallel()

	cp := &mockChildProvider{}
	ms := &mockMessageSender{}

	child := newSleepyChild(0x0401)
	child.SupervisionInterval = 0 // use supervisor default
	cp.addChild(child)

	s := NewSupervisor(
		WithChildProvider(cp),
		WithMessageSender(ms),
		WithSupervisionInterval(3),
	)

	for i := 0; i < 3; i++ {
		s.HandleTimer()
	}
	if ms.getSentCount() != 1 {
		t.Errorf("sent = %d, want 1 using default interval", ms.getSentCount())
	}
}

func TestSupervisor_HandleTimer_ZeroIntervalSkips(t *testing.T) {
	t.Parallel()

	cp := &mockChildProvider{}
	ms := &mockMessageSender{}

	child := newSleepyChild(0x0401)
	child.SupervisionInterval = 0
	cp.addChild(child)

	s := NewSupervisor(
		WithChildProvider(cp),
		WithMessageSender(ms),
		WithSupervisionInterval(0), // both zero = disabled
	)

	for i := 0; i < 10; i++ {
		s.HandleTimer()
	}
	if ms.getSentCount() != 0 {
		t.Errorf("sent = %d, want 0 when interval is 0", ms.getSentCount())
	}
}

func TestSupervisor_HandleTimer_MultipleChildren(t *testing.T) {
	t.Parallel()

	cp := &mockChildProvider{}
	ms := &mockMessageSender{}

	child1 := newSleepyChild(0x0401)
	child1.SupervisionInterval = 2

	child2 := newSleepyChild(0x0402)
	child2.SupervisionInterval = 3

	rxOn := newRxOnChild(0x0403)
	rxOn.SupervisionInterval = 1

	cp.addChild(child1)
	cp.addChild(child2)
	cp.addChild(rxOn)

	s := NewSupervisor(
		WithChildProvider(cp),
		WithMessageSender(ms),
	)

	// Tick 6 times.
	for i := 0; i < 6; i++ {
		s.HandleTimer()
	}

	// child1: interval=2, should fire at tick 2, 4, 6 = 3 sends
	// child2: interval=3, should fire at tick 3, 6 = 2 sends
	// rxOn: skipped
	if ms.getSentCount() != 5 {
		t.Errorf("sent = %d, want 5", ms.getSentCount())
	}
}

func TestSupervisor_HandleTimer_NilProvider(t *testing.T) {
	t.Parallel()

	s := NewSupervisor()
	// Should not panic.
	s.HandleTimer()
}

// ---------------------------------------------------------------------------
// SupervisionListener tests
// ---------------------------------------------------------------------------

func TestNewSupervisionListener(t *testing.T) {
	t.Parallel()

	l := NewSupervisionListener()
	if l == nil {
		t.Fatal("NewSupervisionListener returned nil")
	}
	if l.GetTimeout() != DefaultSupervisionTimeout {
		t.Errorf("timeout = %d, want %d", l.GetTimeout(), DefaultSupervisionTimeout)
	}
	if l.GetInterval() != DefaultSupervisionInterval {
		t.Errorf("interval = %d, want %d", l.GetInterval(), DefaultSupervisionInterval)
	}
	if l.GetCounter() != 0 {
		t.Errorf("counter = %d, want 0", l.GetCounter())
	}
}

func TestSupervisionListener_WithOptions(t *testing.T) {
	t.Parallel()

	timer := newMockTimer()
	handler := &mockParentLossHandler{}

	l := NewSupervisionListener(
		WithTimeout(42),
		WithListenerInterval(99),
		WithTimer(timer),
		WithParentLossHandler(handler),
	)

	if l.GetTimeout() != 42 {
		t.Errorf("timeout = %d, want 42", l.GetTimeout())
	}
	if l.GetInterval() != 99 {
		t.Errorf("interval = %d, want 99", l.GetInterval())
	}
}

func TestSupervisionListener_StartStop(t *testing.T) {
	t.Parallel()

	timer := newMockTimer()
	l := NewSupervisionListener(WithTimer(timer), WithTimeout(10))

	l.Start()
	if !l.IsRunning() {
		t.Error("listener should be running after Start")
	}
	if !timer.isPending() {
		t.Error("timer should be pending after Start")
	}

	// Double start is safe.
	l.Start()

	l.Stop()
	if l.IsRunning() {
		t.Error("listener should not be running after Stop")
	}

	// Double stop is safe.
	l.Stop()
}

func TestSupervisionListener_SetTimeout(t *testing.T) {
	t.Parallel()

	timer := newMockTimer()
	l := NewSupervisionListener(WithTimer(timer))

	l.Start()
	l.SetTimeout(30)
	if l.GetTimeout() != 30 {
		t.Errorf("timeout = %d, want 30", l.GetTimeout())
	}
	if timer.getDuration() != 30*time.Second {
		t.Errorf("timer duration = %v, want 30s", timer.getDuration())
	}

	// Setting same value is a no-op.
	l.SetTimeout(30)

	// Setting to zero stops the timer.
	l.SetTimeout(0)
	if timer.isPending() {
		t.Error("timer should be stopped when timeout is 0")
	}

	l.Stop()
}

func TestSupervisionListener_SetInterval(t *testing.T) {
	t.Parallel()

	l := NewSupervisionListener()
	l.SetInterval(50)
	if l.GetInterval() != 50 {
		t.Errorf("interval = %d, want 50", l.GetInterval())
	}

	// Same value is no-op.
	l.SetInterval(50)
}

func TestSupervisionListener_UpdateOnReceive(t *testing.T) {
	t.Parallel()

	timer := newMockTimer()
	l := NewSupervisionListener(WithTimer(timer), WithTimeout(60))

	// Not running — should be no-op.
	l.UpdateOnReceive()
	if timer.isPending() {
		t.Error("timer should not be pending when not running")
	}

	l.Start()
	if !timer.isPending() {
		t.Error("timer should be pending after Start")
	}

	// Receive should restart the timer.
	l.UpdateOnReceive()
	if !timer.isPending() {
		t.Error("timer should still be pending after UpdateOnReceive")
	}
	if timer.getDuration() != 60*time.Second {
		t.Errorf("timer duration = %v, want 60s", timer.getDuration())
	}

	l.Stop()
}

func TestSupervisionListener_HandleTimer(t *testing.T) {
	t.Parallel()

	timer := newMockTimer()
	handler := &mockParentLossHandler{}

	l := NewSupervisionListener(
		WithTimer(timer),
		WithTimeout(10),
		WithParentLossHandler(handler),
	)

	l.Start()

	// Simulate timeout.
	l.HandleTimer()
	if l.GetCounter() != 1 {
		t.Errorf("counter = %d, want 1", l.GetCounter())
	}
	if handler.getCount() != 1 {
		t.Errorf("handler called %d times, want 1", handler.getCount())
	}

	// Timer should be restarted.
	if !timer.isPending() {
		t.Error("timer should be restarted after HandleTimer")
	}

	// Another timeout.
	l.HandleTimer()
	if l.GetCounter() != 2 {
		t.Errorf("counter = %d, want 2", l.GetCounter())
	}
	if handler.getCount() != 2 {
		t.Errorf("handler called %d times, want 2", handler.getCount())
	}

	l.Stop()
}

func TestSupervisionListener_ResetCounter(t *testing.T) {
	t.Parallel()

	l := NewSupervisionListener()
	l.Start()

	l.HandleTimer()
	l.HandleTimer()
	if l.GetCounter() != 2 {
		t.Errorf("counter = %d, want 2", l.GetCounter())
	}

	l.ResetCounter()
	if l.GetCounter() != 0 {
		t.Errorf("counter = %d, want 0 after reset", l.GetCounter())
	}

	l.Stop()
}

func TestSupervisionListener_TimerFire(t *testing.T) {
	t.Parallel()

	timer := newMockTimer()
	handler := &mockParentLossHandler{}

	l := NewSupervisionListener(
		WithTimer(timer),
		WithTimeout(10),
		WithParentLossHandler(handler),
	)

	l.Start()

	// Give goroutine time to start.
	time.Sleep(10 * time.Millisecond)

	// Fire the timer.
	timer.fire()

	// Give goroutine time to process.
	time.Sleep(50 * time.Millisecond)

	if handler.getCount() != 1 {
		t.Errorf("handler called %d times, want 1 after timer fire", handler.getCount())
	}
	if l.GetCounter() != 1 {
		t.Errorf("counter = %d, want 1 after timer fire", l.GetCounter())
	}

	l.Stop()
}

func TestSupervisionListener_DisabledTimeout(t *testing.T) {
	t.Parallel()

	timer := newMockTimer()
	l := NewSupervisionListener(WithTimer(timer), WithTimeout(0))

	l.Start()

	// Timer should not be pending when timeout is 0.
	if timer.isPending() {
		t.Error("timer should not be pending when timeout is 0")
	}

	l.Stop()
}

// ---------------------------------------------------------------------------
// DataPollSender tests
// ---------------------------------------------------------------------------

func TestNewDataPollSender(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender()
	if d == nil {
		t.Fatal("NewDataPollSender returned nil")
	}
	if d.IsEnabled() {
		t.Error("should not be enabled before Start")
	}
}

func TestDataPollSender_WithOptions(t *testing.T) {
	t.Parallel()

	tx := &mockPollTransmitter{}
	d := NewDataPollSender(
		WithDefaultPollPeriod(5000),
		WithPollTransmitter(tx),
	)

	// Start to compute period.
	d.Start()
	if d.GetPollPeriod() != 5000 {
		t.Errorf("poll period = %d, want 5000", d.GetPollPeriod())
	}
	d.Stop()
}

func TestDataPollSender_StartStop(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender()

	d.Start()
	if !d.IsEnabled() {
		t.Error("should be enabled after Start")
	}

	// Double start is safe.
	d.Start()

	d.Stop()
	if d.IsEnabled() {
		t.Error("should not be enabled after Stop")
	}

	// Double stop is safe.
	d.Stop()
}

func TestDataPollSender_SendDataPoll(t *testing.T) {
	t.Parallel()

	tx := &mockPollTransmitter{}
	d := NewDataPollSender(WithPollTransmitter(tx))

	// Not enabled — should fail.
	if err := d.SendDataPoll(); err != errors.ErrInvalidState {
		t.Errorf("SendDataPoll when disabled = %v, want ErrInvalidState", err)
	}

	d.Start()
	if err := d.SendDataPoll(); err != nil {
		t.Errorf("SendDataPoll = %v, want nil", err)
	}
	if tx.getCallCount() != 1 {
		t.Errorf("transmitter calls = %d, want 1", tx.getCallCount())
	}

	d.Stop()
}

func TestDataPollSender_SetExternalPollPeriod(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender(WithDefaultPollPeriod(100000))

	// Too small.
	if err := d.SetExternalPollPeriod(5); err != errors.ErrInvalidArgs {
		t.Errorf("SetExternalPollPeriod(5) = %v, want ErrInvalidArgs", err)
	}

	// Valid.
	if err := d.SetExternalPollPeriod(500); err != nil {
		t.Errorf("SetExternalPollPeriod(500) = %v, want nil", err)
	}
	if d.GetExternalPollPeriod() != 500 {
		t.Errorf("external period = %d, want 500", d.GetExternalPollPeriod())
	}

	// Clamp to max.
	if err := d.SetExternalPollPeriod(MaxExternalPeriod + 100); err != nil {
		t.Errorf("SetExternalPollPeriod(max+100) = %v, want nil", err)
	}
	if d.GetExternalPollPeriod() != MaxExternalPeriod {
		t.Errorf("external period = %d, want %d", d.GetExternalPollPeriod(), MaxExternalPeriod)
	}

	// Clear.
	if err := d.SetExternalPollPeriod(0); err != nil {
		t.Errorf("SetExternalPollPeriod(0) = %v, want nil", err)
	}
	if d.GetExternalPollPeriod() != 0 {
		t.Errorf("external period = %d, want 0", d.GetExternalPollPeriod())
	}
}

func TestDataPollSender_CalculatePollPeriod(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender(WithDefaultPollPeriod(100000))
	d.Start()

	// Default period.
	if d.GetPollPeriod() != 100000 {
		t.Errorf("period = %d, want 100000", d.GetPollPeriod())
	}

	// External period wins if smaller.
	_ = d.SetExternalPollPeriod(5000)
	if d.GetPollPeriod() != 5000 {
		t.Errorf("period = %d, want 5000 with external", d.GetPollPeriod())
	}

	// Attach mode overrides if smaller.
	d.SetAttachMode(true)
	if got := d.GetPollPeriod(); got != AttachPollPeriod {
		t.Errorf("period = %d, want %d in attach mode", got, AttachPollPeriod)
	}

	d.SetAttachMode(false)
	_ = d.SetExternalPollPeriod(0)

	d.Stop()
}

func TestDataPollSender_FastPolls(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender(WithDefaultPollPeriod(100000))
	d.Start()

	d.SendFastPolls(5)
	if got := d.GetPollPeriod(); got != FastPollPeriod {
		t.Errorf("period = %d, want %d during fast poll", got, FastPollPeriod)
	}

	// StopFastPolls clears.
	d.StopFastPolls()
	if got := d.GetPollPeriod(); got != 100000 {
		t.Errorf("period = %d, want 100000 after StopFastPolls", got)
	}

	d.Stop()
}

func TestDataPollSender_FastPollsDefault(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender(WithDefaultPollPeriod(100000))
	d.Start()

	d.SendFastPolls(0) // Should use DefaultFastPolls
	if got := d.GetPollPeriod(); got != FastPollPeriod {
		t.Errorf("period = %d, want %d", got, FastPollPeriod)
	}

	d.Stop()
}

func TestDataPollSender_FastPollsClamped(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender(WithDefaultPollPeriod(100000))
	d.Start()

	d.SendFastPolls(200) // Exceeds MaxFastPolls, should be clamped
	if got := d.GetPollPeriod(); got != FastPollPeriod {
		t.Errorf("period = %d, want %d", got, FastPollPeriod)
	}

	d.Stop()
}

func TestDataPollSender_HandlePollSent_Success(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender(WithDefaultPollPeriod(100000))
	d.Start()

	d.SendFastPolls(3)

	// Simulate successful sends decrementing fast polls.
	d.HandlePollSent(nil)
	d.HandlePollSent(nil)

	// After 2 successful sends, 1 remaining.
	if got := d.GetPollPeriod(); got != FastPollPeriod {
		t.Errorf("period = %d, want %d with 1 fast poll remaining", got, FastPollPeriod)
	}

	// 3rd success clears fast polls.
	d.HandlePollSent(nil)
	if got := d.GetPollPeriod(); got != 100000 {
		t.Errorf("period = %d, want 100000 after all fast polls", got)
	}

	d.Stop()
}

func TestDataPollSender_HandlePollSent_Failure(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender(WithDefaultPollPeriod(100000))
	d.Start()

	// Channel access failure puts into retx mode.
	d.HandlePollSent(errors.ErrChannelAccessFailure)
	if got := d.GetPollPeriod(); got != RetxPollPeriod {
		t.Errorf("period = %d, want %d in retx mode", got, RetxPollPeriod)
	}

	// Success clears retx mode.
	d.HandlePollSent(nil)
	if got := d.GetPollPeriod(); got != 100000 {
		t.Errorf("period = %d, want 100000 after success", got)
	}

	d.Stop()
}

func TestDataPollSender_HandlePollSent_NoAck(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender(WithDefaultPollPeriod(100000))
	d.Start()

	// Multiple NoAck failures.
	for i := uint8(0); i < MaxPollRetxAttempts-1; i++ {
		d.HandlePollSent(errors.ErrNoAck)
	}
	// Should be in retx mode.
	if got := d.GetPollPeriod(); got != RetxPollPeriod {
		t.Errorf("period = %d, want %d in retx mode", got, RetxPollPeriod)
	}

	// One more failure exceeds max retx.
	d.HandlePollSent(errors.ErrNoAck)
	if got := d.GetPollPeriod(); got != 100000 {
		t.Errorf("period = %d, want 100000 after max retx", got)
	}

	d.Stop()
}

func TestDataPollSender_HandlePollTimeout(t *testing.T) {
	t.Parallel()

	tx := &mockPollTransmitter{}
	d := NewDataPollSender(WithPollTransmitter(tx), WithDefaultPollPeriod(100000))
	d.Start()

	// First timeout should trigger a quick poll.
	d.HandlePollTimeout()
	if tx.getCallCount() != 1 {
		t.Errorf("transmitter calls = %d, want 1 after timeout", tx.getCallCount())
	}

	d.Stop()
}

func TestDataPollSender_GetKeepAlivePollPeriod(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender(WithDefaultPollPeriod(100000))

	if got := d.GetKeepAlivePollPeriod(); got != 100000 {
		t.Errorf("keep-alive period = %d, want 100000", got)
	}

	_ = d.SetExternalPollPeriod(5000)
	if got := d.GetKeepAlivePollPeriod(); got != 5000 {
		t.Errorf("keep-alive period = %d, want 5000", got)
	}
}

func TestDataPollSender_SetAttachMode(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender(WithDefaultPollPeriod(100000))
	d.Start()

	d.SetAttachMode(true)
	if got := d.GetPollPeriod(); got != AttachPollPeriod {
		t.Errorf("period = %d, want %d in attach mode", got, AttachPollPeriod)
	}

	d.SetAttachMode(false)
	if got := d.GetPollPeriod(); got != 100000 {
		t.Errorf("period = %d, want 100000 after clearing attach mode", got)
	}

	// Double set is a no-op.
	d.SetAttachMode(false)

	d.Stop()
}

func TestDataPollSender_RecalculatePollPeriod(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender(WithDefaultPollPeriod(100000))

	// Not enabled — should be no-op.
	d.RecalculatePollPeriod()

	d.Start()
	d.RecalculatePollPeriod()
	if got := d.GetPollPeriod(); got != 100000 {
		t.Errorf("period = %d, want 100000", got)
	}

	d.Stop()
}

func TestDataPollSender_SendDataPoll_InvalidState(t *testing.T) {
	t.Parallel()

	tx := &mockPollTransmitter{err: errors.ErrInvalidState}
	d := NewDataPollSender(WithPollTransmitter(tx))
	d.Start()

	err := d.SendDataPoll()
	if err != errors.ErrInvalidState {
		t.Errorf("err = %v, want ErrInvalidState", err)
	}
	// Should have stopped.
	if d.IsEnabled() {
		t.Error("should be disabled after ErrInvalidState from transmitter")
	}
}

func TestDataPollSender_MinPollPeriodGuard(t *testing.T) {
	t.Parallel()

	d := NewDataPollSender(WithDefaultPollPeriod(0))
	d.Start()

	// Period of 0 should be clamped to MinPollPeriod.
	if got := d.GetPollPeriod(); got != MinPollPeriod {
		t.Errorf("period = %d, want %d (min)", got, MinPollPeriod)
	}

	d.Stop()
}

// ---------------------------------------------------------------------------
// DataPollHandler tests
// ---------------------------------------------------------------------------

func TestNewDataPollHandler(t *testing.T) {
	t.Parallel()

	h := NewDataPollHandler()
	if h == nil {
		t.Fatal("NewDataPollHandler returned nil")
	}
	if h.GetIndirectTxChild() != nil {
		t.Error("indirect tx child should be nil initially")
	}
}

func TestDataPollHandler_Clear(t *testing.T) {
	t.Parallel()

	h := NewDataPollHandler()
	child := newSleepyChild(0x0401)

	h.HandleDataPoll(child)
	if h.GetIndirectTxChild() == nil {
		t.Error("should have indirect tx child after HandleDataPoll")
	}

	h.Clear()
	if h.GetIndirectTxChild() != nil {
		t.Error("should have no indirect tx child after Clear")
	}
}

func TestDataPollHandler_HandleDataPoll(t *testing.T) {
	t.Parallel()

	h := NewDataPollHandler()
	child := newSleepyChild(0x0401)
	child.LinkFailures = 5

	h.HandleDataPoll(child)

	// Should reset link failures.
	if child.LinkFailures != 0 {
		t.Errorf("link failures = %d, want 0", child.LinkFailures)
	}

	// Should become the indirect tx child.
	if h.GetIndirectTxChild() != child {
		t.Error("should be the indirect tx child")
	}

	// Second child should have pending poll.
	child2 := newSleepyChild(0x0402)
	h.HandleDataPoll(child2)

	info := h.GetTxInfo(child2)
	if !info.DataPollPending {
		t.Error("second child should have DataPollPending")
	}
}

func TestDataPollHandler_HandleDataPoll_Nil(t *testing.T) {
	t.Parallel()

	h := NewDataPollHandler()
	// Should not panic.
	h.HandleDataPoll(nil)
}

func TestDataPollHandler_RequestFrameChange_NoActiveTx(t *testing.T) {
	t.Parallel()

	is := &mockIndirectSender{}
	h := NewDataPollHandler(WithIndirectSender(is))
	child := newSleepyChild(0x0401)

	h.RequestFrameChange(FramePurged, child)

	if is.getFrameChangeDoneCount() != 1 {
		t.Errorf("frame change done = %d, want 1", is.getFrameChangeDoneCount())
	}

	info := h.GetTxInfo(child)
	if info.IndirectTxAttempts != 0 {
		t.Errorf("tx attempts = %d, want 0", info.IndirectTxAttempts)
	}
}

func TestDataPollHandler_RequestFrameChange_ActiveTx_Purge(t *testing.T) {
	t.Parallel()

	is := &mockIndirectSender{}
	h := NewDataPollHandler(WithIndirectSender(is))
	child := newSleepyChild(0x0401)

	// Make child the active indirect tx child.
	h.HandleDataPoll(child)

	// Request purge while transmitting.
	h.RequestFrameChange(FramePurged, child)

	info := h.GetTxInfo(child)
	if !info.FramePurgePending {
		t.Error("FramePurgePending should be true")
	}
}

func TestDataPollHandler_RequestFrameChange_ActiveTx_Replace(t *testing.T) {
	t.Parallel()

	is := &mockIndirectSender{}
	h := NewDataPollHandler(WithIndirectSender(is))
	child := newSleepyChild(0x0401)

	h.HandleDataPoll(child)
	h.RequestFrameChange(FrameRemoved, child)

	info := h.GetTxInfo(child)
	if !info.FrameReplacePending {
		t.Error("FrameReplacePending should be true")
	}
}

func TestDataPollHandler_HandleFrameSent_Success(t *testing.T) {
	t.Parallel()

	is := &mockIndirectSender{}
	h := NewDataPollHandler(WithIndirectSender(is))
	child := newSleepyChild(0x0401)

	h.HandleDataPoll(child)
	h.HandleFrameSent(child, nil)

	if h.GetIndirectTxChild() != nil {
		t.Error("indirect tx child should be cleared after success")
	}
	if is.getSentFrameCount() != 1 {
		t.Errorf("sent frame count = %d, want 1", is.getSentFrameCount())
	}
}

func TestDataPollHandler_HandleFrameSent_WithPurgePending(t *testing.T) {
	t.Parallel()

	is := &mockIndirectSender{}
	h := NewDataPollHandler(WithIndirectSender(is))
	child := newSleepyChild(0x0401)

	h.HandleDataPoll(child)

	// Set purge pending.
	info := h.GetTxInfo(child)
	info.FramePurgePending = true

	h.HandleFrameSent(child, nil)

	// Purge should trigger HandleFrameChangeDone, not HandleSentFrameToChild.
	if is.getFrameChangeDoneCount() != 1 {
		t.Errorf("frame change done = %d, want 1", is.getFrameChangeDoneCount())
	}
	if is.getSentFrameCount() != 0 {
		t.Errorf("sent frame count = %d, want 0", is.getSentFrameCount())
	}
}

func TestDataPollHandler_HandleFrameSent_Failure(t *testing.T) {
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
}

func TestDataPollHandler_HandleFrameSent_MaxAttempts(t *testing.T) {
	t.Parallel()

	is := &mockIndirectSender{}
	h := NewDataPollHandler(WithIndirectSender(is))
	child := newSleepyChild(0x0401)

	// Set attempts to max-1.
	info := h.GetTxInfo(child)
	info.IndirectTxAttempts = MaxPollTriggeredTxAttempts - 1

	h.HandleDataPoll(child)
	h.HandleFrameSent(child, errors.ErrNoAck)

	// Should have been reset and HandleSentFrameToChild called.
	info = h.GetTxInfo(child)
	if info.IndirectTxAttempts != 0 {
		t.Errorf("tx attempts = %d, want 0 after max", info.IndirectTxAttempts)
	}
	if is.getSentFrameCount() != 1 {
		t.Errorf("sent frame count = %d, want 1", is.getSentFrameCount())
	}
}

func TestDataPollHandler_HandleFrameSent_ReplacePending(t *testing.T) {
	t.Parallel()

	is := &mockIndirectSender{}
	h := NewDataPollHandler(WithIndirectSender(is))
	child := newSleepyChild(0x0401)

	h.HandleDataPoll(child)

	info := h.GetTxInfo(child)
	info.FrameReplacePending = true

	h.HandleFrameSent(child, errors.ErrNoAck)

	// Replace pending + failure should trigger HandleFrameChangeDone.
	if is.getFrameChangeDoneCount() != 1 {
		t.Errorf("frame change done = %d, want 1", is.getFrameChangeDoneCount())
	}
}

func TestDataPollHandler_HandleFrameSent_Nil(t *testing.T) {
	t.Parallel()

	h := NewDataPollHandler()
	// Should not panic.
	h.HandleFrameSent(nil, nil)
}

func TestDataPollHandler_ProcessPendingPolls(t *testing.T) {
	t.Parallel()

	cp := &mockChildProvider{}
	is := &mockIndirectSender{}
	h := NewDataPollHandler(
		WithIndirectSender(is),
		WithHandlerChildProvider(cp),
	)

	child1 := newSleepyChild(0x0401)
	child1.LastHeard = time.Now().Add(-10 * time.Second)
	child2 := newSleepyChild(0x0402)
	child2.LastHeard = time.Now().Add(-5 * time.Second)

	cp.addChild(child1)
	cp.addChild(child2)

	// First poll goes to child1 (active tx).
	h.HandleDataPoll(child1)
	// Second poll is pending.
	h.HandleDataPoll(child2)

	// Complete first child's transmission.
	h.HandleFrameSent(child1, nil)

	// child2 should now be the indirect tx child (earlier LastHeard).
	if h.GetIndirectTxChild() != child2 {
		got := h.GetIndirectTxChild()
		if got == nil {
			t.Error("indirect tx child should be child2, got nil")
		} else {
			t.Errorf("indirect tx child RLOC = 0x%04X, want 0x0402", got.RLOC16)
		}
	}
}

func TestDataPollHandler_RequestFrameChange_Nil(t *testing.T) {
	t.Parallel()

	h := NewDataPollHandler()
	// Should not panic.
	h.RequestFrameChange(FramePurged, nil)
}

// ---------------------------------------------------------------------------
// IndirectTxInfo tests
// ---------------------------------------------------------------------------

func TestIndirectTxInfo_ResetTxAttempts(t *testing.T) {
	t.Parallel()

	info := &IndirectTxInfo{IndirectTxAttempts: 5}
	info.ResetTxAttempts()
	if info.IndirectTxAttempts != 0 {
		t.Errorf("attempts = %d, want 0", info.IndirectTxAttempts)
	}
}

// ---------------------------------------------------------------------------
// FrameChange tests
// ---------------------------------------------------------------------------

func TestFrameChange_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		fc   FrameChange
		want string
	}{
		{FrameAdded, "FrameAdded"},
		{FrameRemoved, "FrameRemoved"},
		{FramePurged, "FramePurged"},
		{FrameChange(99), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.fc.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.fc, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Constants sanity checks
// ---------------------------------------------------------------------------

func TestConstants(t *testing.T) {
	t.Parallel()

	if DefaultSupervisionInterval != 190 {
		t.Errorf("DefaultSupervisionInterval = %d, want 190", DefaultSupervisionInterval)
	}
	if DefaultSupervisionTimeout != 190 {
		t.Errorf("DefaultSupervisionTimeout = %d, want 190", DefaultSupervisionTimeout)
	}
	if DefaultFastPolls != 8 {
		t.Errorf("DefaultFastPolls = %d, want 8", DefaultFastPolls)
	}
	if MaxFastPolls != 15 {
		t.Errorf("MaxFastPolls = %d, want 15", MaxFastPolls)
	}
	if FastPollPeriod != 188 {
		t.Errorf("FastPollPeriod = %d, want 188", FastPollPeriod)
	}
	if MinPollPeriod != 10 {
		t.Errorf("MinPollPeriod = %d, want 10", MinPollPeriod)
	}
	if MaxExternalPeriod != (1<<26)-1 {
		t.Errorf("MaxExternalPeriod = %d, want %d", MaxExternalPeriod, (1<<26)-1)
	}
}
