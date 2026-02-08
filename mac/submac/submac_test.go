// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package submac

import (
	"testing"
	"time"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/radio"
)

// --------------------------------------------------------------------------
// Mock radio
// --------------------------------------------------------------------------

type mockRadio struct {
	caps              radio.Caps
	state             radio.State
	enabled           bool
	channel           uint8
	panID             uint16
	shortAddr         types.ShortAddress
	extAddr           types.ExtAddress
	promiscuous       bool
	rssi              int8
	txPower           int8
	transmitBuf       radio.Frame
	srcMatchEnabled   bool
	macKeyIDMode      uint8
	macKeyID          uint8
	macFrameCounter   uint32
	receiveCount      int
	sleepCount        int
	transmitCount     int
	enableCount       int
	disableCount      int
	energyScanCount   int
	energyScanChannel uint8
	energyScanDur     uint16

	// Control transmit behavior.
	transmitErr error
}

func newMockRadio(caps radio.Caps) *mockRadio {
	return &mockRadio{
		caps:  caps,
		state: radio.StateDisabled,
		rssi:  -50,
	}
}

func (r *mockRadio) Enable() error {
	r.enabled = true
	r.state = radio.StateSleep
	r.enableCount++
	return nil
}

func (r *mockRadio) Disable() error {
	r.enabled = false
	r.state = radio.StateDisabled
	r.disableCount++
	return nil
}

func (r *mockRadio) IsEnabled() bool       { return r.enabled }
func (r *mockRadio) GetState() radio.State { return r.state }

func (r *mockRadio) Sleep() error {
	r.state = radio.StateSleep
	r.sleepCount++
	return nil
}

func (r *mockRadio) Receive(channel uint8) error {
	r.state = radio.StateReceive
	r.channel = channel
	r.receiveCount++
	return nil
}

func (r *mockRadio) Transmit(_ *radio.Frame) error {
	if r.transmitErr != nil {
		return r.transmitErr
	}
	r.state = radio.StateTransmit
	r.transmitCount++
	return nil
}

func (r *mockRadio) GetTransmitBuffer() *radio.Frame {
	return &r.transmitBuf
}

func (r *mockRadio) GetCaps() radio.Caps                      { return r.caps }
func (r *mockRadio) GetIEEEEui64() [8]byte                    { return [8]byte{} }
func (r *mockRadio) SetPanID(panID uint16)                    { r.panID = panID }
func (r *mockRadio) SetExtendedAddress(addr types.ExtAddress) { r.extAddr = addr }
func (r *mockRadio) SetShortAddress(addr types.ShortAddress)  { r.shortAddr = addr }
func (r *mockRadio) GetTransmitPower() (int8, error)          { return r.txPower, nil }
func (r *mockRadio) SetTransmitPower(power int8) error {
	r.txPower = power
	return nil
}
func (r *mockRadio) GetPromiscuous() bool            { return r.promiscuous }
func (r *mockRadio) SetPromiscuous(enable bool)      { r.promiscuous = enable }
func (r *mockRadio) GetRSSI() int8                   { return r.rssi }
func (r *mockRadio) GetSupportedChannelMask() uint32 { return 0x07FFF800 }
func (r *mockRadio) GetPreferredChannelMask() uint32 { return 0x07FFF800 }
func (r *mockRadio) GetReceiveSensitivity() int8     { return -100 }

func (r *mockRadio) EnableSrcMatch(_ bool)                              { r.srcMatchEnabled = true }
func (r *mockRadio) AddSrcMatchShortEntry(_ types.ShortAddress) error   { return nil }
func (r *mockRadio) AddSrcMatchExtEntry(_ types.ExtAddress) error       { return nil }
func (r *mockRadio) ClearSrcMatchShortEntry(_ types.ShortAddress) error { return nil }
func (r *mockRadio) ClearSrcMatchExtEntry(_ types.ExtAddress) error     { return nil }
func (r *mockRadio) ClearSrcMatchShortEntries()                         {}
func (r *mockRadio) ClearSrcMatchExtEntries()                           {}

func (r *mockRadio) SetMacKey(keyIDMode, keyID uint8, _, _, _ types.KeyMaterial) {
	r.macKeyIDMode = keyIDMode
	r.macKeyID = keyID
}
func (r *mockRadio) SetMacFrameCounter(counter uint32) { r.macFrameCounter = counter }
func (r *mockRadio) SetMacFrameCounterIfLarger(counter uint32) {
	if counter > r.macFrameCounter {
		r.macFrameCounter = counter
	}
}

func (r *mockRadio) EnergyScan(channel uint8, duration uint16) error {
	r.energyScanCount++
	r.energyScanChannel = channel
	r.energyScanDur = duration
	return nil
}

// --------------------------------------------------------------------------
// Mock callbacks
// --------------------------------------------------------------------------

type mockCallbacks struct {
	receiveDoneCount    int
	transmitDoneCount   int
	transmitDoneFrame   *radio.Frame
	transmitDoneAck     *radio.Frame
	transmitDoneErr     error
	recordStatusCount   int
	recordStatusWillRtx []bool
	recordStatusErrs    []error
	recordCcaCount      int
	recordCcaSuccess    []bool
	energyScanDoneCount int
	energyScanMaxRSSI   int8
	frameCounterUsed    uint32
}

func (c *mockCallbacks) ReceiveDone(_ *radio.Frame, _ error) {
	c.receiveDoneCount++
}

func (c *mockCallbacks) TransmitDone(frame *radio.Frame, ackFrame *radio.Frame, err error) {
	c.transmitDoneCount++
	c.transmitDoneFrame = frame
	c.transmitDoneAck = ackFrame
	c.transmitDoneErr = err
}

func (c *mockCallbacks) RecordFrameTransmitStatus(_ *radio.Frame, err error, _ uint8, willRetx bool) {
	c.recordStatusCount++
	c.recordStatusWillRtx = append(c.recordStatusWillRtx, willRetx)
	c.recordStatusErrs = append(c.recordStatusErrs, err)
}

func (c *mockCallbacks) RecordCcaStatus(ccaSuccess bool, _ uint8) {
	c.recordCcaCount++
	c.recordCcaSuccess = append(c.recordCcaSuccess, ccaSuccess)
}

func (c *mockCallbacks) EnergyScanDone(maxRSSI int8) {
	c.energyScanDoneCount++
	c.energyScanMaxRSSI = maxRSSI
}

func (c *mockCallbacks) FrameCounterUsed(counter uint32) {
	c.frameCounterUsed = counter
}

// --------------------------------------------------------------------------
// Test timer helper — immediate synchronous execution
// --------------------------------------------------------------------------

type mockTimer struct {
	pendingFn func()
	scheduled int
	stopped   int
}

func newMockTimer() *mockTimer {
	return &mockTimer{}
}

func (t *mockTimer) schedule(_ time.Duration, fn func()) {
	t.pendingFn = fn
	t.scheduled++
}

func (t *mockTimer) stop() {
	t.pendingFn = nil
	t.stopped++
}

func (t *mockTimer) fire() {
	if t.pendingFn != nil {
		fn := t.pendingFn
		t.pendingFn = nil
		fn()
	}
}

// --------------------------------------------------------------------------
// newTestSubMac creates a SubMac with mock dependencies
// --------------------------------------------------------------------------

func newTestSubMac(caps radio.Caps) (*SubMac, *mockRadio, *mockCallbacks, *mockTimer) {
	r := newMockRadio(caps)
	cb := &mockCallbacks{}
	timer := newMockTimer()
	sm := New(Config{
		Radio:         r,
		Callbacks:     cb,
		ScheduleTimer: timer.schedule,
		StopTimer:     timer.stop,
	})
	return sm, r, cb, timer
}

// ==========================================================================
// Tests
// ==========================================================================

func TestNewSubMac(t *testing.T) {
	sm, r, _, _ := newTestSubMac(radio.CapNone)

	if sm.GetState() != StateDisabled {
		t.Errorf("initial state = %v, want Disabled", sm.GetState())
	}
	if sm.GetTransmitFrame() != &r.transmitBuf {
		t.Error("transmit frame should point to radio's buffer")
	}
}

func TestNewSubMacNilRadio(t *testing.T) {
	sm := New(Config{})
	if sm.GetState() != StateDisabled {
		t.Errorf("state = %v, want Disabled", sm.GetState())
	}
	if sm.GetTransmitFrame() != nil {
		t.Error("transmit frame should be nil with nil radio")
	}
}

// --------------------------------------------------------------------------
// Lifecycle
// --------------------------------------------------------------------------

func TestEnable(t *testing.T) {
	sm, r, _, _ := newTestSubMac(radio.CapNone)

	if err := sm.Enable(); err != nil {
		t.Fatalf("Enable() error: %v", err)
	}
	if sm.GetState() != StateSleep {
		t.Errorf("state after Enable = %v, want Sleep", sm.GetState())
	}
	if r.enableCount != 1 {
		t.Errorf("radio.Enable called %d times, want 1", r.enableCount)
	}
	if r.sleepCount != 1 {
		t.Errorf("radio.Sleep called %d times, want 1", r.sleepCount)
	}
}

func TestEnableNilRadio(t *testing.T) {
	sm := New(Config{})
	if err := sm.Enable(); err != ErrInvalidState {
		t.Errorf("Enable() with nil radio = %v, want ErrInvalidState", err)
	}
}

func TestDisable(t *testing.T) {
	sm, r, _, _ := newTestSubMac(radio.CapNone)
	_ = sm.Enable()

	if err := sm.Disable(); err != nil {
		t.Fatalf("Disable() error: %v", err)
	}
	if sm.GetState() != StateDisabled {
		t.Errorf("state after Disable = %v, want Disabled", sm.GetState())
	}
	if r.disableCount != 1 {
		t.Errorf("radio.Disable called %d times, want 1", r.disableCount)
	}
}

func TestDisableStopsTimer(t *testing.T) {
	sm, _, _, timer := newTestSubMac(radio.CapNone)
	_ = sm.Enable()

	_ = sm.Disable()
	if timer.stopped < 1 {
		t.Error("Disable should stop pending timer")
	}
}

// --------------------------------------------------------------------------
// State transitions
// --------------------------------------------------------------------------

func TestSleep(t *testing.T) {
	sm, _, _, _ := newTestSubMac(radio.CapNone)
	_ = sm.Enable()
	_ = sm.Receive(15)

	if err := sm.Sleep(); err != nil {
		t.Fatalf("Sleep() error: %v", err)
	}
	if sm.GetState() != StateSleep {
		t.Errorf("state = %v, want Sleep", sm.GetState())
	}
}

func TestSleepDisabledReturnsError(t *testing.T) {
	sm, _, _, _ := newTestSubMac(radio.CapNone)
	if err := sm.Sleep(); err != ErrInvalidState {
		t.Errorf("Sleep() when disabled = %v, want ErrInvalidState", err)
	}
}

func TestReceive(t *testing.T) {
	sm, r, _, _ := newTestSubMac(radio.CapNone)
	_ = sm.Enable()

	if err := sm.Receive(15); err != nil {
		t.Fatalf("Receive() error: %v", err)
	}
	if sm.GetState() != StateReceive {
		t.Errorf("state = %v, want Receive", sm.GetState())
	}
	if r.channel != 15 {
		t.Errorf("channel = %d, want 15", r.channel)
	}
}

func TestReceiveDisabledReturnsError(t *testing.T) {
	sm, _, _, _ := newTestSubMac(radio.CapNone)
	if err := sm.Receive(15); err != ErrInvalidState {
		t.Errorf("Receive() when disabled = %v, want ErrInvalidState", err)
	}
}

func TestIsTransmittingOrScanning(t *testing.T) {
	sm, _, _, _ := newTestSubMac(radio.CapNone)
	_ = sm.Enable()

	if sm.IsTransmittingOrScanning() {
		t.Error("should not be transmitting/scanning in Sleep")
	}

	_ = sm.Receive(15)
	if sm.IsTransmittingOrScanning() {
		t.Error("should not be transmitting/scanning in Receive")
	}
}

// --------------------------------------------------------------------------
// State.String()
// --------------------------------------------------------------------------

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateDisabled, "Disabled"},
		{StateSleep, "Sleep"},
		{StateReceive, "Receive"},
		{StateCsmaBackoff, "CsmaBackoff"},
		{StateTransmit, "Transmit"},
		{StateEnergyScan, "EnergyScan"},
		{State(99), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

// --------------------------------------------------------------------------
// Send — invalid states
// --------------------------------------------------------------------------

func TestSendFromDisabledReturnsError(t *testing.T) {
	sm, _, _, _ := newTestSubMac(radio.CapNone)
	err := sm.Send(TxRequest{Channel: 15})
	if err != ErrInvalidState {
		t.Errorf("Send() from Disabled = %v, want ErrInvalidState", err)
	}
}

func TestSendFromReceive(t *testing.T) {
	sm, _, _, _ := newTestSubMac(radio.CapNone)
	_ = sm.Enable()
	_ = sm.Receive(15)

	err := sm.Send(TxRequest{Channel: 15, CsmaCaEnabled: false})
	if err != nil {
		t.Fatalf("Send() from Receive = %v, want nil", err)
	}
	// With no CSMA (CsmaCaEnabled=false), should immediately begin transmit.
	if sm.GetState() != StateTransmit {
		t.Errorf("state = %v, want Transmit", sm.GetState())
	}
}

func TestSendFromSleep(t *testing.T) {
	sm, _, _, _ := newTestSubMac(radio.CapNone)
	_ = sm.Enable()

	err := sm.Send(TxRequest{Channel: 15, CsmaCaEnabled: false})
	if err != nil {
		t.Fatalf("Send() from Sleep = %v, want nil", err)
	}
}

// --------------------------------------------------------------------------
// CSMA-CA backoff (software)
// --------------------------------------------------------------------------

func TestCsmaBackoffSoftware(t *testing.T) {
	// Radio with no CSMA cap => SubMac handles CSMA in software.
	sm, _, _, timer := newTestSubMac(radio.CapNone)
	_ = sm.Enable()
	_ = sm.Receive(15)

	err := sm.Send(TxRequest{
		Channel:         15,
		CsmaCaEnabled:   true,
		MaxCsmaBackoffs: DefaultMaxCsmaBackoffsDirect,
		MaxFrameRetries: DefaultMaxFrameRetriesDirect,
	})
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	// Should be in CsmaBackoff state waiting for timer.
	if sm.GetState() != StateCsmaBackoff {
		t.Errorf("state = %v, want CsmaBackoff", sm.GetState())
	}
	if timer.scheduled < 1 {
		t.Error("timer should have been scheduled for CSMA backoff")
	}

	// Fire the timer — should transition to transmit.
	timer.fire()
	if sm.GetState() != StateTransmit {
		t.Errorf("state after timer = %v, want Transmit", sm.GetState())
	}
}

func TestCsmaBackoffRadioReceivesDuringBackoffWhenRxOnWhenIdle(t *testing.T) {
	sm, r, _, _ := newTestSubMac(radio.CapNone)
	_ = sm.Enable()
	_ = sm.Receive(15)
	sm.SetRxOnWhenIdle(true)

	rcBefore := r.receiveCount
	_ = sm.Send(TxRequest{
		Channel:         20,
		CsmaCaEnabled:   true,
		MaxCsmaBackoffs: 4,
	})

	// Radio should have been told to receive during backoff.
	if r.receiveCount <= rcBefore {
		t.Error("radio.Receive should be called during CSMA backoff when rxOnWhenIdle=true")
	}
	if r.channel != 20 {
		t.Errorf("channel during backoff = %d, want 20", r.channel)
	}
}

func TestCsmaBackoffRadioSleepsDuringBackoffWhenNotRxOnWhenIdle(t *testing.T) {
	sm, r, _, _ := newTestSubMac(radio.CapNone)
	_ = sm.Enable()
	_ = sm.Receive(15)
	sm.SetRxOnWhenIdle(false)

	sleepBefore := r.sleepCount
	_ = sm.Send(TxRequest{
		Channel:         15,
		CsmaCaEnabled:   true,
		MaxCsmaBackoffs: 4,
	})

	if r.sleepCount <= sleepBefore {
		t.Error("radio.Sleep should be called during CSMA backoff when rxOnWhenIdle=false")
	}
}

func TestCsmaBackoffSkippedWithHardwareCap(t *testing.T) {
	// Radio supports CSMA natively.
	sm, _, _, timer := newTestSubMac(radio.CapCsmaBackoff)
	_ = sm.Enable()
	_ = sm.Receive(15)

	_ = sm.Send(TxRequest{
		Channel:       15,
		CsmaCaEnabled: true,
	})

	// Should skip CSMA backoff and go straight to transmit.
	if sm.GetState() != StateTransmit {
		t.Errorf("state = %v, want Transmit (hardware CSMA)", sm.GetState())
	}
	// Timer should not be scheduled for CSMA.
	if timer.scheduled != 0 {
		t.Errorf("timer scheduled %d times, want 0 (hardware CSMA)", timer.scheduled)
	}
}

func TestCsmaBackoffSkippedWithTransmitRetriesCap(t *testing.T) {
	// CapTransmitRetries also implies hardware handles CSMA.
	sm, _, _, timer := newTestSubMac(radio.CapTransmitRetries)
	_ = sm.Enable()
	_ = sm.Receive(15)

	_ = sm.Send(TxRequest{
		Channel:       15,
		CsmaCaEnabled: true,
	})

	if sm.GetState() != StateTransmit {
		t.Errorf("state = %v, want Transmit", sm.GetState())
	}
	if timer.scheduled != 0 {
		t.Errorf("timer scheduled = %d, want 0", timer.scheduled)
	}
}

func TestCsmaBackoffNotUsedWhenCsmaCaDisabled(t *testing.T) {
	sm, _, _, timer := newTestSubMac(radio.CapNone)
	_ = sm.Enable()
	_ = sm.Receive(15)

	_ = sm.Send(TxRequest{
		Channel:       15,
		CsmaCaEnabled: false,
	})

	// No CSMA requested => immediate transmit.
	if sm.GetState() != StateTransmit {
		t.Errorf("state = %v, want Transmit", sm.GetState())
	}
	if timer.scheduled != 0 {
		t.Errorf("timer scheduled = %d, want 0", timer.scheduled)
	}
}

// --------------------------------------------------------------------------
// Channel access failure + CSMA retry
// --------------------------------------------------------------------------

func TestCsmaRetryOnChannelAccessFailure(t *testing.T) {
	sm, _, cb, timer := newTestSubMac(radio.CapNone)
	_ = sm.Enable()
	_ = sm.Receive(15)

	_ = sm.Send(TxRequest{
		Channel:         15,
		CsmaCaEnabled:   true,
		MaxCsmaBackoffs: 2,
		MaxFrameRetries: 0,
	})

	// Fire initial backoff timer => beginTransmit.
	timer.fire()
	if sm.GetState() != StateTransmit {
		t.Fatalf("state = %v, want Transmit", sm.GetState())
	}

	// Simulate CCA failure from radio.
	sm.HandleTransmitDone(sm.txFrame, nil, ErrChannelAccessFailure)

	// Should be in CsmaBackoff for retry #1.
	if sm.GetState() != StateCsmaBackoff {
		t.Errorf("state = %v, want CsmaBackoff (retry)", sm.GetState())
	}
	if cb.recordCcaSuccess[0] != false {
		t.Error("CCA should be recorded as failed")
	}
	if cb.recordStatusWillRtx[0] != true {
		t.Error("should signal willRetx=true")
	}

	// Fire backoff again => transmit attempt #2.
	timer.fire()
	if sm.GetState() != StateTransmit {
		t.Fatalf("state = %v, want Transmit (attempt 2)", sm.GetState())
	}

	// Another CCA failure => retry #2.
	sm.HandleTransmitDone(sm.txFrame, nil, ErrChannelAccessFailure)
	if sm.GetState() != StateCsmaBackoff {
		t.Errorf("state = %v, want CsmaBackoff (retry 2)", sm.GetState())
	}

	timer.fire()
	// Third CCA failure — max backoffs exhausted (0,1,2 = 3 attempts, MaxCsmaBackoffs=2).
	sm.HandleTransmitDone(sm.txFrame, nil, ErrChannelAccessFailure)

	// Now at MaxFrameRetries=0, so should complete with failure.
	if sm.GetState() != StateReceive {
		t.Errorf("state = %v, want Receive (backoffs exhausted)", sm.GetState())
	}
	if cb.transmitDoneCount != 1 {
		t.Errorf("TransmitDone called %d times, want 1", cb.transmitDoneCount)
	}
	if cb.transmitDoneErr != ErrChannelAccessFailure {
		t.Errorf("TransmitDone err = %v, want ErrChannelAccessFailure", cb.transmitDoneErr)
	}
}

// --------------------------------------------------------------------------
// Frame retries
// --------------------------------------------------------------------------

func TestFrameRetryOnNoAck(t *testing.T) {
	sm, _, cb, timer := newTestSubMac(radio.CapNone)
	_ = sm.Enable()
	_ = sm.Receive(15)

	_ = sm.Send(TxRequest{
		Channel:         15,
		CsmaCaEnabled:   false,
		MaxCsmaBackoffs: 0,
		MaxFrameRetries: 2,
	})

	// First transmit.
	if sm.GetState() != StateTransmit {
		t.Fatalf("state = %v, want Transmit", sm.GetState())
	}

	// Simulate no-ack.
	sm.HandleTransmitDone(sm.txFrame, nil, ErrNoAck)

	// Should retry — resets CSMA and goes back to CsmaBackoff/Transmit.
	// CsmaCaEnabled=false so it will immediately transmit.
	if sm.GetState() != StateTransmit {
		t.Errorf("state = %v, want Transmit (retry 1)", sm.GetState())
	}
	if sm.GetTransmitRetries() != 1 {
		t.Errorf("transmitRetries = %d, want 1", sm.GetTransmitRetries())
	}

	// Another no-ack.
	sm.HandleTransmitDone(sm.txFrame, nil, ErrNoAck)
	if sm.GetState() != StateTransmit {
		t.Errorf("state = %v, want Transmit (retry 2)", sm.GetState())
	}
	if sm.GetTransmitRetries() != 2 {
		t.Errorf("transmitRetries = %d, want 2", sm.GetTransmitRetries())
	}

	// Third no-ack — retries exhausted.
	sm.HandleTransmitDone(sm.txFrame, nil, ErrNoAck)
	if sm.GetState() != StateReceive {
		t.Errorf("state = %v, want Receive (retries exhausted)", sm.GetState())
	}
	if cb.transmitDoneErr != ErrNoAck {
		t.Errorf("final err = %v, want ErrNoAck", cb.transmitDoneErr)
	}

	// Verify record calls: 3 retries + 1 final = 4 status records,
	// but actually: attempt0 fail => willRetx=true, attempt1 fail => willRetx=true,
	// attempt2 fail => willRetx=false (+ final recordStatus call).
	// The recordStatus is called once per handleTransmitResult invocation.
	// Retry 1: willRetx=true, Retry 2: willRetx=true, Final: willRetx=false.
	if len(cb.recordStatusWillRtx) != 3 {
		t.Fatalf("recordStatus calls = %d, want 3", len(cb.recordStatusWillRtx))
	}
	if !cb.recordStatusWillRtx[0] || !cb.recordStatusWillRtx[1] {
		t.Error("first two retries should have willRetx=true")
	}
	if cb.recordStatusWillRtx[2] {
		t.Error("final attempt should have willRetx=false")
	}
	_ = timer
}

func TestFrameRetrySkippedWithHardwareCap(t *testing.T) {
	sm, _, cb, _ := newTestSubMac(radio.CapTransmitRetries)
	_ = sm.Enable()
	_ = sm.Receive(15)

	_ = sm.Send(TxRequest{
		Channel:         15,
		CsmaCaEnabled:   false,
		MaxFrameRetries: 15,
	})

	// Simulate error — radio handles retries, so SubMac should not retry.
	sm.HandleTransmitDone(sm.txFrame, nil, ErrNoAck)

	if sm.GetState() != StateReceive {
		t.Errorf("state = %v, want Receive (hardware retries)", sm.GetState())
	}
	if cb.transmitDoneCount != 1 {
		t.Errorf("TransmitDone count = %d, want 1", cb.transmitDoneCount)
	}
}

// --------------------------------------------------------------------------
// Successful transmit
// --------------------------------------------------------------------------

func TestSuccessfulTransmit(t *testing.T) {
	sm, _, cb, _ := newTestSubMac(radio.CapNone)
	_ = sm.Enable()
	_ = sm.Receive(15)

	_ = sm.Send(TxRequest{
		Channel:       15,
		CsmaCaEnabled: false,
	})

	ack := &radio.Frame{PSDU: []byte{0x02, 0x00, 0x42}}
	sm.HandleTransmitDone(sm.txFrame, ack, nil)

	if sm.GetState() != StateReceive {
		t.Errorf("state = %v, want Receive", sm.GetState())
	}
	if cb.transmitDoneCount != 1 {
		t.Errorf("TransmitDone count = %d, want 1", cb.transmitDoneCount)
	}
	if cb.transmitDoneErr != nil {
		t.Errorf("TransmitDone err = %v, want nil", cb.transmitDoneErr)
	}
	if cb.transmitDoneAck != ack {
		t.Error("TransmitDone should receive the ACK frame")
	}
}

// --------------------------------------------------------------------------
// ACK timeout (software)
// --------------------------------------------------------------------------

func TestAckTimeoutSoftware(t *testing.T) {
	sm, _, cb, timer := newTestSubMac(radio.CapNone)
	_ = sm.Enable()
	_ = sm.Receive(15)

	_ = sm.Send(TxRequest{
		Channel:         15,
		CsmaCaEnabled:   false,
		AckRequest:      true,
		MaxFrameRetries: 0,
	})

	// Simulate radio starting TX.
	sm.HandleTransmitStarted(sm.txFrame)

	// Timer should be scheduled for ACK timeout.
	if timer.scheduled < 1 {
		t.Fatal("timer should be scheduled for ACK timeout")
	}

	// Fire the ACK timeout.
	timer.fire()

	// Should report no-ack.
	if cb.transmitDoneCount != 1 {
		t.Fatalf("TransmitDone count = %d, want 1", cb.transmitDoneCount)
	}
	if cb.transmitDoneErr != ErrNoAck {
		t.Errorf("TransmitDone err = %v, want ErrNoAck", cb.transmitDoneErr)
	}
	if sm.GetState() != StateReceive {
		t.Errorf("state = %v, want Receive", sm.GetState())
	}
}

func TestAckTimeoutNotSetWithHardwareCap(t *testing.T) {
	sm, _, _, timer := newTestSubMac(radio.CapAckTimeout)
	_ = sm.Enable()
	_ = sm.Receive(15)

	_ = sm.Send(TxRequest{
		Channel:    15,
		AckRequest: true,
	})

	sm.HandleTransmitStarted(sm.txFrame)

	// Timer should NOT be scheduled — radio handles ACK timeout.
	if timer.scheduled != 0 {
		t.Errorf("timer scheduled %d times, want 0 (hardware ACK timeout)", timer.scheduled)
	}
}

func TestAckTimeoutNotSetWithoutAckRequest(t *testing.T) {
	sm, _, _, timer := newTestSubMac(radio.CapNone)
	_ = sm.Enable()
	_ = sm.Receive(15)

	_ = sm.Send(TxRequest{
		Channel:    15,
		AckRequest: false,
	})

	sm.HandleTransmitStarted(sm.txFrame)

	// No ACK requested => no timeout.
	if timer.scheduled != 0 {
		t.Errorf("timer scheduled %d times, want 0 (no ACK requested)", timer.scheduled)
	}
}

func TestAckTimeoutIgnoredIfNotInTransmitState(t *testing.T) {
	sm, _, cb, _ := newTestSubMac(radio.CapNone)
	_ = sm.Enable()
	_ = sm.Receive(15)

	_ = sm.Send(TxRequest{
		Channel:    15,
		AckRequest: true,
	})

	sm.HandleTransmitStarted(sm.txFrame)

	// Complete transmit successfully before timeout fires.
	sm.HandleTransmitDone(sm.txFrame, &radio.Frame{}, nil)

	if sm.GetState() != StateReceive {
		t.Fatalf("state = %v, want Receive", sm.GetState())
	}

	// Now fire the stale ACK timeout — should be a no-op since stopTimer
	// was called by HandleTransmitDone. But even if somehow the fn was
	// still pending, handleAckTimeout checks state != StateTransmit.
	origCount := cb.transmitDoneCount
	sm.handleAckTimeout()
	if cb.transmitDoneCount != origCount {
		t.Error("stale ACK timeout should be ignored when not in Transmit state")
	}
}

// --------------------------------------------------------------------------
// Energy scan — hardware delegation
// --------------------------------------------------------------------------

func TestEnergyScanHardware(t *testing.T) {
	sm, r, _, _ := newTestSubMac(radio.CapEnergyScan)
	_ = sm.Enable()
	_ = sm.Receive(15)

	if err := sm.EnergyScan(20, 300); err != nil {
		t.Fatalf("EnergyScan() error: %v", err)
	}

	if sm.GetState() != StateEnergyScan {
		t.Errorf("state = %v, want EnergyScan", sm.GetState())
	}
	if r.energyScanCount != 1 {
		t.Errorf("radio.EnergyScan called %d times, want 1", r.energyScanCount)
	}
	if r.energyScanChannel != 20 {
		t.Errorf("scan channel = %d, want 20", r.energyScanChannel)
	}
	if r.energyScanDur != 300 {
		t.Errorf("scan duration = %d, want 300", r.energyScanDur)
	}
}

func TestEnergyScanHardwareDoneCallback(t *testing.T) {
	sm, _, cb, _ := newTestSubMac(radio.CapEnergyScan)
	_ = sm.Enable()
	_ = sm.Receive(15)
	_ = sm.EnergyScan(20, 300)

	// Simulate hardware scan done.
	sm.HandleEnergyScanDone(-45)

	if sm.GetState() != StateReceive {
		t.Errorf("state = %v, want Receive after scan done", sm.GetState())
	}
	if cb.energyScanDoneCount != 1 {
		t.Errorf("EnergyScanDone count = %d, want 1", cb.energyScanDoneCount)
	}
	if cb.energyScanMaxRSSI != -45 {
		t.Errorf("maxRSSI = %d, want -45", cb.energyScanMaxRSSI)
	}
}

// --------------------------------------------------------------------------
// Energy scan — software sampling
// --------------------------------------------------------------------------

func TestEnergyScanSoftware(t *testing.T) {
	sm, r, cb, timer := newTestSubMac(radio.CapNone)
	_ = sm.Enable()
	_ = sm.Receive(15)

	if err := sm.EnergyScan(20, 10); err != nil {
		t.Fatalf("EnergyScan() error: %v", err)
	}

	if sm.GetState() != StateEnergyScan {
		t.Errorf("state = %v, want EnergyScan", sm.GetState())
	}
	// Radio should be set to receive on scan channel.
	if r.channel != 20 {
		t.Errorf("channel = %d, want 20", r.channel)
	}
	// Timer should be scheduled for RSSI sampling.
	if timer.scheduled < 1 {
		t.Fatal("timer should be scheduled for RSSI sampling")
	}

	// Simulate RSSI samples — vary the readings.
	r.rssi = -70
	timer.fire() // sample 1: -70

	if sm.energyScanMaxRSSI != -70 {
		t.Errorf("maxRSSI after sample 1 = %d, want -70", sm.energyScanMaxRSSI)
	}

	r.rssi = -45
	timer.fire() // sample 2: -45

	if sm.energyScanMaxRSSI != -45 {
		t.Errorf("maxRSSI after sample 2 = %d, want -45", sm.energyScanMaxRSSI)
	}

	r.rssi = -60
	timer.fire() // sample 3: -60 (less than -45, max stays at -45)

	if sm.energyScanMaxRSSI != -45 {
		t.Errorf("maxRSSI after sample 3 = %d, want -45", sm.energyScanMaxRSSI)
	}

	// Fast-forward past the end time to complete the scan.
	sm.energyScanEndTime = time.Now().Add(-1 * time.Millisecond)
	r.rssi = -40
	timer.fire() // final sample

	if sm.GetState() != StateReceive {
		t.Errorf("state = %v, want Receive after software scan done", sm.GetState())
	}
	if cb.energyScanDoneCount != 1 {
		t.Fatalf("EnergyScanDone count = %d, want 1", cb.energyScanDoneCount)
	}
	if cb.energyScanMaxRSSI != -40 {
		t.Errorf("final maxRSSI = %d, want -40", cb.energyScanMaxRSSI)
	}
}

func TestEnergyScanFromDisabledReturnsError(t *testing.T) {
	sm, _, _, _ := newTestSubMac(radio.CapNone)
	if err := sm.EnergyScan(15, 100); err != ErrInvalidState {
		t.Errorf("EnergyScan() when disabled = %v, want ErrInvalidState", err)
	}
}

func TestEnergyScanFromCsmaBackoffReturnsError(t *testing.T) {
	sm, _, _, _ := newTestSubMac(radio.CapNone)
	_ = sm.Enable()
	_ = sm.Receive(15)

	// Start a CSMA transmit.
	_ = sm.Send(TxRequest{Channel: 15, CsmaCaEnabled: true, MaxCsmaBackoffs: 4})

	// Now try energy scan — should fail.
	if err := sm.EnergyScan(20, 100); err != ErrInvalidState {
		t.Errorf("EnergyScan() during CSMA = %v, want ErrInvalidState", err)
	}
}

// --------------------------------------------------------------------------
// Configuration
// --------------------------------------------------------------------------

func TestSetPanID(t *testing.T) {
	sm, r, _, _ := newTestSubMac(radio.CapNone)
	sm.SetPanID(0x1234)
	if r.panID != 0x1234 {
		t.Errorf("panID = 0x%04x, want 0x1234", r.panID)
	}
}

func TestSetShortAddress(t *testing.T) {
	sm, r, _, _ := newTestSubMac(radio.CapNone)
	addr := types.ShortAddress(0x5678)
	sm.SetShortAddress(addr)

	if sm.GetShortAddress() != addr {
		t.Errorf("GetShortAddress() = %v, want %v", sm.GetShortAddress(), addr)
	}
	if r.shortAddr != addr {
		t.Errorf("radio shortAddr = %v, want %v", r.shortAddr, addr)
	}
}

func TestSetExtAddress(t *testing.T) {
	sm, r, _, _ := newTestSubMac(radio.CapNone)
	addr := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	sm.SetExtAddress(addr)

	if sm.GetExtAddress() != addr {
		t.Errorf("GetExtAddress() = %v, want %v", sm.GetExtAddress(), addr)
	}
	if r.extAddr != addr {
		t.Errorf("radio extAddr = %v, want %v", r.extAddr, addr)
	}
}

func TestSetRxOnWhenIdle(t *testing.T) {
	sm, _, _, _ := newTestSubMac(radio.CapNone)
	sm.SetRxOnWhenIdle(true)
	if !sm.rxOnWhenIdle {
		t.Error("rxOnWhenIdle should be true")
	}
	sm.SetRxOnWhenIdle(false)
	if sm.rxOnWhenIdle {
		t.Error("rxOnWhenIdle should be false")
	}
}

func TestGetRSSI(t *testing.T) {
	sm, r, _, _ := newTestSubMac(radio.CapNone)
	r.rssi = -65
	if got := sm.GetRSSI(); got != -65 {
		t.Errorf("GetRSSI() = %d, want -65", got)
	}
}

func TestGetRSSINilRadio(t *testing.T) {
	sm := New(Config{})
	if got := sm.GetRSSI(); got != radio.RSSIInvalid {
		t.Errorf("GetRSSI() nil radio = %d, want %d", got, radio.RSSIInvalid)
	}
}

func TestGetNoiseFloor(t *testing.T) {
	sm, _, _, _ := newTestSubMac(radio.CapNone)
	if got := sm.GetNoiseFloor(); got != -100 {
		t.Errorf("GetNoiseFloor() = %d, want -100", got)
	}
}

func TestGetNoiseFloorNilRadio(t *testing.T) {
	sm := New(Config{})
	if got := sm.GetNoiseFloor(); got != radio.RSSIInvalid {
		t.Errorf("GetNoiseFloor() nil radio = %d, want %d", got, radio.RSSIInvalid)
	}
}

// --------------------------------------------------------------------------
// MAC security — keys and frame counter
// --------------------------------------------------------------------------

func TestSetMacKeyNoTransmitSec(t *testing.T) {
	sm, r, _, _ := newTestSubMac(radio.CapNone)
	var prev, curr, next types.KeyMaterial
	var prevKey, currKey, nextKey types.Key
	prevKey[0] = 0xAA
	currKey[0] = 0xBB
	nextKey[0] = 0xCC
	prev.SetKey(prevKey)
	curr.SetKey(currKey)
	next.SetKey(nextKey)

	sm.SetMacKey(1, 5, prev, curr, next)

	if sm.keyID != 5 {
		t.Errorf("keyID = %d, want 5", sm.keyID)
	}
	if sm.currKey.GetKey()[0] != 0xBB {
		t.Errorf("currKey[0] = 0x%02x, want 0xBB", sm.currKey.GetKey()[0])
	}
	// Without CapTransmitSec, radio should NOT be called.
	if r.macKeyID != 0 {
		t.Error("radio.SetMacKey should not be called without CapTransmitSec")
	}
}

func TestSetMacKeyWithTransmitSec(t *testing.T) {
	sm, r, _, _ := newTestSubMac(radio.CapTransmitSec)
	var prev, curr, next types.KeyMaterial
	sm.SetMacKey(1, 7, prev, curr, next)

	if r.macKeyID != 7 {
		t.Errorf("radio macKeyID = %d, want 7", r.macKeyID)
	}
}

func TestSetFrameCounter(t *testing.T) {
	sm, _, _, _ := newTestSubMac(radio.CapNone)
	sm.SetFrameCounter(42, false)
	if sm.GetFrameCounter() != 42 {
		t.Errorf("frameCounter = %d, want 42", sm.GetFrameCounter())
	}
}

func TestSetFrameCounterIfLarger(t *testing.T) {
	sm, _, _, _ := newTestSubMac(radio.CapNone)
	sm.SetFrameCounter(100, false)
	sm.SetFrameCounter(50, true)
	if sm.GetFrameCounter() != 100 {
		t.Errorf("frameCounter = %d, want 100 (not decreased)", sm.GetFrameCounter())
	}
	sm.SetFrameCounter(200, true)
	if sm.GetFrameCounter() != 200 {
		t.Errorf("frameCounter = %d, want 200", sm.GetFrameCounter())
	}
}

func TestSetFrameCounterWithTransmitSec(t *testing.T) {
	sm, r, _, _ := newTestSubMac(radio.CapTransmitSec)
	sm.SetFrameCounter(99, false)
	if r.macFrameCounter != 99 {
		t.Errorf("radio frameCounter = %d, want 99", r.macFrameCounter)
	}

	sm.SetFrameCounter(50, true)
	// setIfLarger with 50 < 99 => radio should still be at 99.
	if r.macFrameCounter != 99 {
		t.Errorf("radio frameCounter = %d, want 99 (setIfLarger)", r.macFrameCounter)
	}
}

// --------------------------------------------------------------------------
// HandleReceiveDone
// --------------------------------------------------------------------------

func TestHandleReceiveDone(t *testing.T) {
	sm, _, cb, _ := newTestSubMac(radio.CapNone)
	frame := &radio.Frame{PSDU: []byte{0x01, 0x02}}
	sm.HandleReceiveDone(frame, nil)

	if cb.receiveDoneCount != 1 {
		t.Errorf("ReceiveDone count = %d, want 1", cb.receiveDoneCount)
	}
}

func TestHandleReceiveDoneNilCallbacks(_ *testing.T) {
	sm := New(Config{})
	// Should not panic.
	sm.HandleReceiveDone(nil, nil)
}

// --------------------------------------------------------------------------
// HandleTransmitStarted in wrong state
// --------------------------------------------------------------------------

func TestHandleTransmitStartedIgnoredWhenNotTransmitting(t *testing.T) {
	sm, _, _, timer := newTestSubMac(radio.CapNone)
	_ = sm.Enable()
	_ = sm.Receive(15)

	// Call directly without transmitting — should be ignored.
	sm.HandleTransmitStarted(nil)

	if timer.scheduled != 0 {
		t.Error("timer should not be scheduled when not transmitting")
	}
}

// --------------------------------------------------------------------------
// Immediate transmit failure (radio.Transmit returns error)
// --------------------------------------------------------------------------

func TestImmediateTransmitFailure(t *testing.T) {
	sm, r, cb, _ := newTestSubMac(radio.CapNone)
	_ = sm.Enable()
	_ = sm.Receive(15)

	r.transmitErr = ErrChannelAccessFailure

	_ = sm.Send(TxRequest{
		Channel:         15,
		CsmaCaEnabled:   false,
		MaxCsmaBackoffs: 0,
		MaxFrameRetries: 0,
	})

	// Radio.Transmit fails immediately => channel access failure reported.
	if cb.transmitDoneCount != 1 {
		t.Fatalf("TransmitDone count = %d, want 1", cb.transmitDoneCount)
	}
	if cb.transmitDoneErr != ErrChannelAccessFailure {
		t.Errorf("err = %v, want ErrChannelAccessFailure", cb.transmitDoneErr)
	}
	if sm.GetState() != StateReceive {
		t.Errorf("state = %v, want Receive", sm.GetState())
	}
}

// --------------------------------------------------------------------------
// Error sentinels
// --------------------------------------------------------------------------

func TestErrorMessages(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{ErrInvalidState, "submac: invalid state"},
		{ErrChannelAccessFailure, "submac: channel access failure"},
		{ErrNoAck, "submac: no ack"},
		{ErrAbort, "submac: abort"},
	}
	for _, tt := range tests {
		if got := tt.err.Error(); got != tt.want {
			t.Errorf("error = %q, want %q", got, tt.want)
		}
	}
}

// --------------------------------------------------------------------------
// Capability checks
// --------------------------------------------------------------------------

func TestShouldHandleCsmaBackoff(t *testing.T) {
	tests := []struct {
		name string
		caps radio.Caps
		want bool
	}{
		{"no caps", radio.CapNone, true},
		{"CSMA cap", radio.CapCsmaBackoff, false},
		{"TransmitRetries cap", radio.CapTransmitRetries, false},
		{"both caps", radio.CapCsmaBackoff | radio.CapTransmitRetries, false},
		{"unrelated cap", radio.CapEnergyScan, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm, _, _, _ := newTestSubMac(tt.caps)
			if got := sm.shouldHandleCsmaBackoff(); got != tt.want {
				t.Errorf("shouldHandleCsmaBackoff() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldHandleRetries(t *testing.T) {
	tests := []struct {
		name string
		caps radio.Caps
		want bool
	}{
		{"no caps", radio.CapNone, true},
		{"TransmitRetries cap", radio.CapTransmitRetries, false},
		{"unrelated cap", radio.CapEnergyScan, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm, _, _, _ := newTestSubMac(tt.caps)
			if got := sm.shouldHandleRetries(); got != tt.want {
				t.Errorf("shouldHandleRetries() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldHandleAckTimeout(t *testing.T) {
	tests := []struct {
		name string
		caps radio.Caps
		want bool
	}{
		{"no caps", radio.CapNone, true},
		{"AckTimeout cap", radio.CapAckTimeout, false},
		{"unrelated cap", radio.CapEnergyScan, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm, _, _, _ := newTestSubMac(tt.caps)
			if got := sm.shouldHandleAckTimeout(); got != tt.want {
				t.Errorf("shouldHandleAckTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --------------------------------------------------------------------------
// Frame retry resets CSMA backoffs
// --------------------------------------------------------------------------

func TestFrameRetryResetsCsmaBackoffs(t *testing.T) {
	sm, _, _, timer := newTestSubMac(radio.CapNone)
	_ = sm.Enable()
	_ = sm.Receive(15)

	_ = sm.Send(TxRequest{
		Channel:         15,
		CsmaCaEnabled:   true,
		MaxCsmaBackoffs: 4,
		MaxFrameRetries: 1,
	})

	// Backoff then transmit.
	timer.fire()

	// Simulate a CCA failure to bump csmaBackoffs.
	sm.HandleTransmitDone(sm.txFrame, nil, ErrChannelAccessFailure)
	// csmaBackoffs should be 1.
	timer.fire()

	// Another CCA failure.
	sm.HandleTransmitDone(sm.txFrame, nil, ErrChannelAccessFailure)
	// csmaBackoffs should be 2.
	timer.fire()

	// Now a no-ack error to trigger frame retry.
	sm.HandleTransmitDone(sm.txFrame, nil, ErrNoAck)

	// Frame retry should reset csmaBackoffs to 0.
	if sm.csmaBackoffs != 0 {
		t.Errorf("csmaBackoffs = %d, want 0 (reset on frame retry)", sm.csmaBackoffs)
	}
	if sm.transmitRetries != 1 {
		t.Errorf("transmitRetries = %d, want 1", sm.transmitRetries)
	}
}

// --------------------------------------------------------------------------
// SleepToTx capability
// --------------------------------------------------------------------------

func TestBeginTransmitSleepToTx(t *testing.T) {
	sm, r, _, _ := newTestSubMac(radio.CapSleepToTx)
	_ = sm.Enable()
	_ = sm.Receive(15)

	rcBefore := r.receiveCount
	_ = sm.Send(TxRequest{
		Channel:       15,
		CsmaCaEnabled: false,
	})

	// With SleepToTx, radio.Receive should NOT be called before transmit.
	if r.receiveCount != rcBefore {
		t.Error("radio.Receive should not be called with CapSleepToTx before transmit")
	}
}

func TestBeginTransmitWithoutSleepToTx(t *testing.T) {
	sm, r, _, _ := newTestSubMac(radio.CapNone)
	_ = sm.Enable()
	_ = sm.Receive(15)

	rcBefore := r.receiveCount
	_ = sm.Send(TxRequest{
		Channel:       15,
		CsmaCaEnabled: false,
	})

	// Without SleepToTx, radio.Receive should be called before transmit.
	if r.receiveCount <= rcBefore {
		t.Error("radio.Receive should be called without CapSleepToTx before transmit")
	}
}

// --------------------------------------------------------------------------
// Nil callbacks safety
// --------------------------------------------------------------------------

func TestTransmitDoneWithNilCallbacks(t *testing.T) {
	r := newMockRadio(radio.CapNone)
	timer := newMockTimer()
	sm := New(Config{
		Radio:         r,
		Callbacks:     nil,
		ScheduleTimer: timer.schedule,
		StopTimer:     timer.stop,
	})
	_ = sm.Enable()
	_ = sm.Receive(15)

	_ = sm.Send(TxRequest{
		Channel:       15,
		CsmaCaEnabled: false,
	})

	// Should not panic with nil callbacks.
	sm.HandleTransmitDone(sm.txFrame, nil, nil)

	if sm.GetState() != StateReceive {
		t.Errorf("state = %v, want Receive", sm.GetState())
	}
}

func TestEnergyScanDoneWithNilCallbacks(_ *testing.T) {
	r := newMockRadio(radio.CapEnergyScan)
	sm := New(Config{Radio: r})
	_ = sm.Enable()
	_ = sm.Receive(15)
	_ = sm.EnergyScan(20, 100)

	// Should not panic with nil callbacks.
	sm.HandleEnergyScanDone(-50)
}

// --------------------------------------------------------------------------
// Config setters with nil radio
// --------------------------------------------------------------------------

func TestSetPanIDNilRadio(_ *testing.T) {
	sm := New(Config{})
	// Should not panic.
	sm.SetPanID(0x1234)
}

func TestSetShortAddressNilRadio(t *testing.T) {
	sm := New(Config{})
	addr := types.ShortAddress(0x5678)
	sm.SetShortAddress(addr)
	if sm.GetShortAddress() != addr {
		t.Errorf("GetShortAddress() = %v, want %v", sm.GetShortAddress(), addr)
	}
}

func TestSetExtAddressNilRadio(t *testing.T) {
	sm := New(Config{})
	addr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	sm.SetExtAddress(addr)
	if sm.GetExtAddress() != addr {
		t.Errorf("GetExtAddress() = %v, want %v", sm.GetExtAddress(), addr)
	}
}

// --------------------------------------------------------------------------
// Timer with nil functions
// --------------------------------------------------------------------------

func TestScheduleTimerNilFn(_ *testing.T) {
	sm := New(Config{})
	// Should not panic.
	sm.scheduleTimer(time.Second, func() {})
}

func TestStopTimerNilFn(_ *testing.T) {
	sm := New(Config{})
	// Should not panic.
	sm.stopTimer()
}

// --------------------------------------------------------------------------
// Constants verification
// --------------------------------------------------------------------------

func TestConstants(t *testing.T) {
	if CsmaMinBE != 3 {
		t.Errorf("CsmaMinBE = %d, want 3", CsmaMinBE)
	}
	if CsmaMaxBE != 5 {
		t.Errorf("CsmaMaxBE = %d, want 5", CsmaMaxBE)
	}
	if UnitBackoffPeriod != 20 {
		t.Errorf("UnitBackoffPeriod = %d, want 20", UnitBackoffPeriod)
	}
	if SymbolTimeUs != 16 {
		t.Errorf("SymbolTimeUs = %d, want 16", SymbolTimeUs)
	}
	if AckTimeoutUs != 16_000 {
		t.Errorf("AckTimeoutUs = %d, want 16000", AckTimeoutUs)
	}
	if EnergyScanSampleIntervalUs != 1_000 {
		t.Errorf("EnergyScanSampleIntervalUs = %d, want 1000", EnergyScanSampleIntervalUs)
	}
	if DefaultMaxCsmaBackoffsDirect != 4 {
		t.Errorf("DefaultMaxCsmaBackoffsDirect = %d, want 4", DefaultMaxCsmaBackoffsDirect)
	}
	if DefaultMaxCsmaBackoffsIndirect != 4 {
		t.Errorf("DefaultMaxCsmaBackoffsIndirect = %d, want 4", DefaultMaxCsmaBackoffsIndirect)
	}
	if DefaultMaxFrameRetriesDirect != 15 {
		t.Errorf("DefaultMaxFrameRetriesDirect = %d, want 15", DefaultMaxFrameRetriesDirect)
	}
	if DefaultMaxFrameRetriesIndirect != 0 {
		t.Errorf("DefaultMaxFrameRetriesIndirect = %d, want 0", DefaultMaxFrameRetriesIndirect)
	}
}
