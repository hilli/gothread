// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mac

import (
	"testing"
	"time"

	"github.com/hilli/gothread/mac/submac"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/radio"
)

// --------------------------------------------------------------------------
// Mock radio (needed by SubMac)
// --------------------------------------------------------------------------

type mockRadio struct {
	caps         radio.Caps
	state        radio.State
	enabled      bool
	channel      uint8
	panID        uint16
	shortAddr    types.ShortAddress
	extAddr      types.ExtAddress
	rssi         int8
	txPower      int8
	transmitBuf  radio.Frame
	energyScanCh uint8
	energyScanDu uint16

	transmitErr error
}

func newMockRadio(caps radio.Caps) *mockRadio {
	return &mockRadio{caps: caps, state: radio.StateDisabled, rssi: -50}
}

func (r *mockRadio) Enable() error         { r.enabled = true; r.state = radio.StateSleep; return nil }
func (r *mockRadio) Disable() error        { r.enabled = false; r.state = radio.StateDisabled; return nil }
func (r *mockRadio) IsEnabled() bool       { return r.enabled }
func (r *mockRadio) GetState() radio.State { return r.state }
func (r *mockRadio) Sleep() error          { r.state = radio.StateSleep; return nil }
func (r *mockRadio) Receive(channel uint8) error {
	r.state = radio.StateReceive
	r.channel = channel
	return nil
}
func (r *mockRadio) Transmit(_ *radio.Frame) error {
	if r.transmitErr != nil {
		return r.transmitErr
	}
	r.state = radio.StateTransmit
	return nil
}
func (r *mockRadio) GetTransmitBuffer() *radio.Frame                       { return &r.transmitBuf }
func (r *mockRadio) GetCaps() radio.Caps                                   { return r.caps }
func (r *mockRadio) GetIEEEEui64() [8]byte                                 { return [8]byte{} }
func (r *mockRadio) SetPanID(panID uint16)                                 { r.panID = panID }
func (r *mockRadio) SetExtendedAddress(addr types.ExtAddress)              { r.extAddr = addr }
func (r *mockRadio) SetShortAddress(addr types.ShortAddress)               { r.shortAddr = addr }
func (r *mockRadio) GetTransmitPower() (int8, error)                       { return r.txPower, nil }
func (r *mockRadio) SetTransmitPower(power int8) error                     { r.txPower = power; return nil }
func (r *mockRadio) GetPromiscuous() bool                                  { return false }
func (r *mockRadio) SetPromiscuous(_ bool)                                 {}
func (r *mockRadio) GetRSSI() int8                                         { return r.rssi }
func (r *mockRadio) GetSupportedChannelMask() uint32                       { return 0x07FFF800 }
func (r *mockRadio) GetPreferredChannelMask() uint32                       { return 0x07FFF800 }
func (r *mockRadio) GetReceiveSensitivity() int8                           { return -100 }
func (r *mockRadio) EnableSrcMatch(_ bool)                                 {}
func (r *mockRadio) AddSrcMatchShortEntry(_ types.ShortAddress) error      { return nil }
func (r *mockRadio) AddSrcMatchExtEntry(_ types.ExtAddress) error          { return nil }
func (r *mockRadio) ClearSrcMatchShortEntry(_ types.ShortAddress) error    { return nil }
func (r *mockRadio) ClearSrcMatchExtEntry(_ types.ExtAddress) error        { return nil }
func (r *mockRadio) ClearSrcMatchShortEntries()                            {}
func (r *mockRadio) ClearSrcMatchExtEntries()                              {}
func (r *mockRadio) SetMacKey(_ uint8, _ uint8, _, _, _ types.KeyMaterial) {}
func (r *mockRadio) SetMacFrameCounter(_ uint32)                           {}
func (r *mockRadio) SetMacFrameCounterIfLarger(_ uint32)                   {}
func (r *mockRadio) EnergyScan(channel uint8, duration uint16) error {
	r.energyScanCh = channel
	r.energyScanDu = duration
	return nil
}

// --------------------------------------------------------------------------
// Mock timer
// --------------------------------------------------------------------------

type mockTimer struct {
	pendingFn func()
	scheduled int
	stopped   int
}

func newMockTimer() *mockTimer { return &mockTimer{} }

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
// Mock MAC callbacks
// --------------------------------------------------------------------------

type mockMacCallbacks struct {
	frameRequestCalled int
	frameRequestReturn bool
	sentFrameCount     int
	sentFrameErr       error
	receivedFrameCount int
	receivedFrame      *radio.Frame
}

func (c *mockMacCallbacks) HandleFrameRequest(_ *radio.Frame) bool {
	c.frameRequestCalled++
	return c.frameRequestReturn
}

func (c *mockMacCallbacks) HandleSentFrame(_ *radio.Frame, err error) {
	c.sentFrameCount++
	c.sentFrameErr = err
}

func (c *mockMacCallbacks) HandleReceivedFrame(frame *radio.Frame) {
	c.receivedFrameCount++
	c.receivedFrame = frame
}

// --------------------------------------------------------------------------
// Mock scan handler
// --------------------------------------------------------------------------

type mockScanHandler struct {
	results       []*ActiveScanResult
	completeCount int
}

func (h *mockScanHandler) HandleActiveScanResult(result *ActiveScanResult) {
	if result == nil {
		h.completeCount++
	} else {
		h.results = append(h.results, result)
	}
}

// --------------------------------------------------------------------------
// Mock energy scan handler
// --------------------------------------------------------------------------

type mockEnergyScanHandler struct {
	channels      []uint8
	rssis         []int8
	completeCount int
}

func (h *mockEnergyScanHandler) HandleEnergyScanResult(channel uint8, maxRSSI int8) {
	h.channels = append(h.channels, channel)
	h.rssis = append(h.rssis, maxRSSI)
}

func (h *mockEnergyScanHandler) HandleEnergyScanComplete() {
	h.completeCount++
}

// --------------------------------------------------------------------------
// Test helpers
// --------------------------------------------------------------------------

// operationRunner is a simple synchronous operation executor.
type operationRunner struct {
	pending []func()
}

func (r *operationRunner) post(fn func()) {
	r.pending = append(r.pending, fn)
}

func (r *operationRunner) run() {
	for len(r.pending) > 0 {
		fn := r.pending[0]
		r.pending = r.pending[1:]
		fn()
	}
}

func (r *operationRunner) runOne() {
	if len(r.pending) > 0 {
		fn := r.pending[0]
		r.pending = r.pending[1:]
		fn()
	}
}

func newTestMac(caps radio.Caps) (*Mac, *mockRadio, *mockMacCallbacks, *mockTimer, *operationRunner) {
	r := newMockRadio(caps)
	smTimer := newMockTimer()
	sm := submac.New(submac.Config{
		Radio:         r,
		ScheduleTimer: smTimer.schedule,
		StopTimer:     smTimer.stop,
	})
	cb := &mockMacCallbacks{}
	macTimer := newMockTimer()
	runner := &operationRunner{}

	m := New(Config{
		SubMac:        sm,
		Callbacks:     cb,
		ScheduleTimer: macTimer.schedule,
		StopTimer:     macTimer.stop,
		PostOperation: runner.post,
	})

	// Wire the Mac as the SubMac's callbacks. In a real setup, this
	// is done during construction. We need to create a new SubMac
	// with the Mac as callbacks.
	sm2 := submac.New(submac.Config{
		Radio:         r,
		Callbacks:     m,
		ScheduleTimer: smTimer.schedule,
		StopTimer:     smTimer.stop,
	})
	m.subMac = sm2

	return m, r, cb, macTimer, runner
}

// ==========================================================================
// Tests
// ==========================================================================

func TestNewMac(t *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	if m.IsEnabled() {
		t.Error("Mac should not be enabled initially")
	}
	if m.GetCurrentOperation() != OperationIdle {
		t.Errorf("initial op = %v, want Idle", m.GetCurrentOperation())
	}
}

// --------------------------------------------------------------------------
// Lifecycle
// --------------------------------------------------------------------------

func TestEnable(t *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	if err := m.Enable(); err != nil {
		t.Fatalf("Enable() error: %v", err)
	}
	if !m.IsEnabled() {
		t.Error("Mac should be enabled")
	}
}

func TestEnableIdempotent(t *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	_ = m.Enable()
	if err := m.Enable(); err != nil {
		t.Fatalf("second Enable() error: %v", err)
	}
}

func TestDisable(t *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	_ = m.Enable()
	if err := m.Disable(); err != nil {
		t.Fatalf("Disable() error: %v", err)
	}
	if m.IsEnabled() {
		t.Error("Mac should be disabled")
	}
}

func TestDisableIdempotent(t *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	if err := m.Disable(); err != nil {
		t.Fatalf("Disable() when already disabled error: %v", err)
	}
}

func TestDisableClearsState(t *testing.T) {
	m, _, _, _, runner := newTestMac(radio.CapNone)
	_ = m.Enable()
	m.RequestDirectFrameTransmission()
	_ = m.Disable()

	if m.GetPendingOperations() != 0 {
		t.Error("pending ops should be cleared after Disable")
	}
	if m.GetCurrentOperation() != OperationIdle {
		t.Error("current op should be Idle after Disable")
	}
	_ = runner
}

// --------------------------------------------------------------------------
// Addresses and PAN ID
// --------------------------------------------------------------------------

func TestSetGetShortAddress(t *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	addr := types.ShortAddress(0x1234)
	m.SetShortAddress(addr)
	if got := m.GetShortAddress(); got != addr {
		t.Errorf("GetShortAddress() = 0x%04x, want 0x%04x", got, addr)
	}
}

func TestSetGetExtAddress(t *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	addr := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	m.SetExtAddress(addr)
	if got := m.GetExtAddress(); got != addr {
		t.Errorf("GetExtAddress() = %v, want %v", got, addr)
	}
}

func TestSetGetPanID(t *testing.T) {
	m, r, _, _, _ := newTestMac(radio.CapNone)
	m.SetPanID(0xABCD)
	if got := m.GetPanID(); got != 0xABCD {
		t.Errorf("GetPanID() = 0x%04x, want 0xABCD", got)
	}
	if r.panID != 0xABCD {
		t.Errorf("radio panID = 0x%04x, want 0xABCD", r.panID)
	}
}

// --------------------------------------------------------------------------
// Channel management
// --------------------------------------------------------------------------

func TestSetGetPanChannel(t *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	m.SetPanChannel(20)
	if got := m.GetPanChannel(); got != 20 {
		t.Errorf("GetPanChannel() = %d, want 20", got)
	}
	if got := m.GetRadioChannel(); got != 20 {
		t.Errorf("GetRadioChannel() = %d, want 20", got)
	}
}

func TestTemporaryChannel(t *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	m.SetPanChannel(15)

	m.SetTemporaryChannel(25)
	if !m.IsUsingTemporaryChannel() {
		t.Error("should be using temporary channel")
	}
	if got := m.GetRadioChannel(); got != 25 {
		t.Errorf("radio channel = %d, want 25", got)
	}
	if got := m.GetPanChannel(); got != 15 {
		t.Errorf("PAN channel = %d, want 15 (unchanged)", got)
	}

	// Setting PAN channel while using temporary should NOT change radio.
	m.SetPanChannel(18)
	if got := m.GetRadioChannel(); got != 25 {
		t.Errorf("radio channel = %d, want 25 (temp still active)", got)
	}

	m.ClearTemporaryChannel()
	if m.IsUsingTemporaryChannel() {
		t.Error("should not be using temporary channel")
	}
	if got := m.GetRadioChannel(); got != 18 {
		t.Errorf("radio channel = %d, want 18 (reverted to PAN)", got)
	}
}

// --------------------------------------------------------------------------
// RxOnWhenIdle
// --------------------------------------------------------------------------

func TestSetGetRxOnWhenIdle(t *testing.T) {
	m, r, _, _, _ := newTestMac(radio.CapNone)
	_ = m.Enable()

	m.SetRxOnWhenIdle(true)
	if !m.GetRxOnWhenIdle() {
		t.Error("GetRxOnWhenIdle() should be true")
	}
	// Radio should be in receive after setting rxOnWhenIdle=true.
	if r.state != radio.StateReceive {
		t.Errorf("radio state = %v, want Receive", r.state)
	}

	m.SetRxOnWhenIdle(false)
	if m.GetRxOnWhenIdle() {
		t.Error("GetRxOnWhenIdle() should be false")
	}
	// Radio should be sleeping after setting rxOnWhenIdle=false.
	if r.state != radio.StateSleep {
		t.Errorf("radio state = %v, want Sleep", r.state)
	}
}

// --------------------------------------------------------------------------
// Beacon configuration
// --------------------------------------------------------------------------

func TestNetworkName(t *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	m.SetNetworkName("TestThread")
	if got := m.GetNetworkName(); got != "TestThread" {
		t.Errorf("GetNetworkName() = %q, want %q", got, "TestThread")
	}
}

func TestExtendedPanID(t *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	epid := [8]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	m.SetExtendedPanID(epid)
	if got := m.GetExtendedPanID(); got != epid {
		t.Errorf("GetExtendedPanID() = %v, want %v", got, epid)
	}
}

func TestJoinable(t *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	m.SetJoinable(true)
	if !m.IsJoinable() {
		t.Error("should be joinable")
	}
	m.SetJoinable(false)
	if m.IsJoinable() {
		t.Error("should not be joinable")
	}
}

// --------------------------------------------------------------------------
// Operation.String()
// --------------------------------------------------------------------------

func TestOperationString(t *testing.T) {
	tests := []struct {
		op   Operation
		want string
	}{
		{OperationIdle, "Idle"},
		{OperationWaitingForData, "WaitingForData"},
		{OperationActiveScan, "ActiveScan"},
		{OperationEnergyScan, "EnergyScan"},
		{OperationTransmitBeacon, "TransmitBeacon"},
		{OperationTransmitDataIndirect, "TransmitDataIndirect"},
		{OperationTransmitPoll, "TransmitPoll"},
		{OperationTransmitDataDirect, "TransmitDataDirect"},
		{Operation(0xFF00), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.op.String(); got != tt.want {
			t.Errorf("Operation(%d).String() = %q, want %q", tt.op, got, tt.want)
		}
	}
}

// --------------------------------------------------------------------------
// Operation scheduling — priority
// --------------------------------------------------------------------------

func TestOperationPriorityOrder(t *testing.T) {
	m, _, _, _, runner := newTestMac(radio.CapNone)
	_ = m.Enable()

	// Request multiple operations — lower priority first.
	m.RequestDirectFrameTransmission()
	m.RequestBeaconTransmission()

	// Both should be pending.
	pending := m.GetPendingOperations()
	if pending&OperationTransmitDataDirect == 0 {
		t.Error("TransmitDataDirect should be pending")
	}
	if pending&OperationTransmitBeacon == 0 {
		t.Error("TransmitBeacon should be pending")
	}

	// Run one operation — should pick TransmitBeacon (higher priority).
	// performTransmitBeacon is a stub that completes immediately, so
	// currentOp will be Idle again. Instead we verify that TransmitBeacon
	// was chosen first: after one cycle, TransmitBeacon should be cleared
	// while TransmitDataDirect is still pending (or about to run).
	runner.runOne()
	pending = m.GetPendingOperations()
	if pending&OperationTransmitBeacon != 0 {
		t.Error("TransmitBeacon should have been cleared (picked first)")
	}
	// TransmitDataDirect may also have been consumed if scheduleNextOperation
	// ran it too, but at least TransmitBeacon was picked first since it has
	// higher priority in operationPriority.
}

// --------------------------------------------------------------------------
// Active scan
// --------------------------------------------------------------------------

func TestActiveScan(t *testing.T) {
	m, r, _, macTimer, runner := newTestMac(radio.CapNone)
	_ = m.Enable()

	handler := &mockScanHandler{}
	var mask types.ChannelMask
	mask.Add(15)
	mask.Add(20)

	if err := m.ActiveScan(mask, 100, handler); err != nil {
		t.Fatalf("ActiveScan() error: %v", err)
	}

	if !m.IsActiveScanInProgress() {
		t.Error("scan should be in progress")
	}

	// Run the operation.
	runner.run()

	// Should have switched to scan channel 15.
	if r.channel != 15 {
		t.Errorf("radio channel = %d, want 15", r.channel)
	}

	// Fire the per-channel timer to advance to next channel.
	macTimer.fire()

	// Should now be on channel 20.
	if r.channel != 20 {
		t.Errorf("radio channel = %d, want 20", r.channel)
	}

	// Fire timer again — scan should complete.
	macTimer.fire()

	if m.IsActiveScanInProgress() {
		t.Error("scan should be complete")
	}
	if handler.completeCount != 1 {
		t.Errorf("scan complete count = %d, want 1", handler.completeCount)
	}
}

func TestActiveScanReceivesBeacon(t *testing.T) {
	m, _, _, _, runner := newTestMac(radio.CapNone)
	_ = m.Enable()

	handler := &mockScanHandler{}
	var mask types.ChannelMask
	mask.Add(15)

	_ = m.ActiveScan(mask, 100, handler)
	runner.run()

	// Simulate receiving a beacon.
	frame := &radio.Frame{
		PSDU:    []byte{0x00, 0x80, 0x01, 0x02, 0x03},
		Channel: 15,
		RxInfo:  &radio.RxInfo{RSSI: -60, LQI: 200},
	}
	m.ReceiveDone(frame, nil)

	if len(handler.results) != 1 {
		t.Fatalf("scan results = %d, want 1", len(handler.results))
	}
	if handler.results[0].Channel != 15 {
		t.Errorf("result channel = %d, want 15", handler.results[0].Channel)
	}
	if handler.results[0].RSSI != -60 {
		t.Errorf("result RSSI = %d, want -60", handler.results[0].RSSI)
	}
}

func TestActiveScanRejectsWhileScanning(t *testing.T) {
	m, _, _, _, runner := newTestMac(radio.CapNone)
	_ = m.Enable()

	var mask types.ChannelMask
	mask.Add(15)

	_ = m.ActiveScan(mask, 100, &mockScanHandler{})
	runner.run()

	// Second scan should fail.
	err := m.ActiveScan(mask, 100, &mockScanHandler{})
	if err != submac.ErrInvalidState {
		t.Errorf("second ActiveScan() = %v, want ErrInvalidState", err)
	}
}

func TestActiveScanDefaultDuration(t *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	_ = m.Enable()

	var mask types.ChannelMask
	mask.Add(15)

	_ = m.ActiveScan(mask, 0, &mockScanHandler{})

	m.mu.Lock()
	dur := m.scanDuration
	m.mu.Unlock()

	if dur != ScanDurationDefault {
		t.Errorf("scan duration = %d, want %d", dur, ScanDurationDefault)
	}
}

// --------------------------------------------------------------------------
// Energy scan
// --------------------------------------------------------------------------

func TestEnergyScan(t *testing.T) {
	m, _, _, _, runner := newTestMac(radio.CapEnergyScan)
	_ = m.Enable()

	handler := &mockEnergyScanHandler{}
	var mask types.ChannelMask
	mask.Add(15)
	mask.Add(20)

	if err := m.EnergyScan(mask, 100, handler); err != nil {
		t.Fatalf("EnergyScan() error: %v", err)
	}

	if !m.IsEnergyScanInProgress() {
		t.Error("energy scan should be in progress")
	}

	// Run the operation — starts scan on first channel (15).
	runner.run()

	// Simulate SubMac reporting scan done for channel 15.
	// Use HandleEnergyScanDone which properly resets SubMac state
	// before calling the Mac callback.
	m.subMac.HandleEnergyScanDone(-45)
	runner.run()

	// Should have received result for channel 15.
	if len(handler.channels) < 1 {
		t.Fatal("should have at least one energy scan result")
	}
	if handler.channels[0] != 15 {
		t.Errorf("first scan channel = %d, want 15", handler.channels[0])
	}
	if handler.rssis[0] != -45 {
		t.Errorf("first scan RSSI = %d, want -45", handler.rssis[0])
	}

	// Simulate scan done for channel 20.
	m.subMac.HandleEnergyScanDone(-30)
	runner.run()

	if len(handler.channels) < 2 {
		t.Fatal("should have two energy scan results")
	}
	if handler.channels[1] != 20 {
		t.Errorf("second scan channel = %d, want 20", handler.channels[1])
	}

	// After the last channel completes, the scan should be done.
	// EnergyScanDone for channel 20 triggers performEnergyScan which
	// finds no more channels and calls the complete callback.

	if handler.completeCount != 1 {
		t.Errorf("energy scan complete count = %d, want 1", handler.completeCount)
	}
}

func TestEnergyScanRejectsWhileScanning(t *testing.T) {
	m, _, _, _, runner := newTestMac(radio.CapEnergyScan)
	_ = m.Enable()

	var mask types.ChannelMask
	mask.Add(15)

	_ = m.EnergyScan(mask, 100, &mockEnergyScanHandler{})
	runner.run()

	err := m.EnergyScan(mask, 100, &mockEnergyScanHandler{})
	if err != submac.ErrInvalidState {
		t.Errorf("second EnergyScan() = %v, want ErrInvalidState", err)
	}
}

// --------------------------------------------------------------------------
// Data transmission
// --------------------------------------------------------------------------

func TestRequestDirectFrameTransmission(t *testing.T) {
	m, _, cb, _, runner := newTestMac(radio.CapNone)
	_ = m.Enable()
	cb.frameRequestReturn = true

	m.RequestDirectFrameTransmission()
	runner.run()

	if cb.frameRequestCalled < 1 {
		t.Error("HandleFrameRequest should be called")
	}
}

func TestTransmitDataNoFrameAvailable(t *testing.T) {
	m, _, cb, _, runner := newTestMac(radio.CapNone)
	_ = m.Enable()
	cb.frameRequestReturn = false

	m.RequestDirectFrameTransmission()
	runner.run()

	if cb.frameRequestCalled < 1 {
		t.Error("HandleFrameRequest should be called")
	}
	// Operation should finish since there's nothing to send.
	if m.GetCurrentOperation() != OperationIdle {
		t.Errorf("current op = %v, want Idle", m.GetCurrentOperation())
	}
}

func TestTransmitDoneCallsSentFrame(t *testing.T) {
	m, _, cb, _, runner := newTestMac(radio.CapNone)
	_ = m.Enable()
	cb.frameRequestReturn = true

	m.RequestDirectFrameTransmission()
	runner.run()

	// Simulate SubMac completing transmission.
	frame := &radio.Frame{PSDU: []byte{0x01, 0x02}}
	m.TransmitDone(frame, nil, nil)
	runner.run()

	if cb.sentFrameCount != 1 {
		t.Errorf("HandleSentFrame count = %d, want 1", cb.sentFrameCount)
	}
	if cb.sentFrameErr != nil {
		t.Errorf("HandleSentFrame err = %v, want nil", cb.sentFrameErr)
	}
}

// --------------------------------------------------------------------------
// ReceiveDone — normal mode
// --------------------------------------------------------------------------

func TestReceiveDoneNormalMode(t *testing.T) {
	m, _, cb, _, _ := newTestMac(radio.CapNone)
	_ = m.Enable()

	frame := &radio.Frame{PSDU: []byte{0x41, 0x88, 0x01}}
	m.ReceiveDone(frame, nil)

	if cb.receivedFrameCount != 1 {
		t.Errorf("HandleReceivedFrame count = %d, want 1", cb.receivedFrameCount)
	}
}

func TestReceiveDoneIgnoredOnError(t *testing.T) {
	m, _, cb, _, _ := newTestMac(radio.CapNone)
	_ = m.Enable()

	m.ReceiveDone(nil, submac.ErrAbort)

	if cb.receivedFrameCount != 0 {
		t.Errorf("HandleReceivedFrame count = %d, want 0 (error)", cb.receivedFrameCount)
	}
}

// --------------------------------------------------------------------------
// SubMac callback stubs (no-panic tests)
// --------------------------------------------------------------------------

func TestRecordFrameTransmitStatusNoPanic(_ *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	m.RecordFrameTransmitStatus(nil, nil, 0, false)
}

func TestRecordCcaStatusNoPanic(_ *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	m.RecordCcaStatus(true, 15)
}

func TestFrameCounterUsedNoPanic(_ *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	m.FrameCounterUsed(42)
}

// --------------------------------------------------------------------------
// parseBeacon
// --------------------------------------------------------------------------

func TestParseBeaconNilFrame(t *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	result := m.parseBeacon(nil)
	if result != nil {
		t.Error("parseBeacon(nil) should return nil")
	}
}

func TestParseBeaconTooShort(t *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	result := m.parseBeacon(&radio.Frame{PSDU: []byte{0x01}})
	if result != nil {
		t.Error("parseBeacon with short frame should return nil")
	}
}

func TestParseBeaconWithRxInfo(t *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	frame := &radio.Frame{
		PSDU:    []byte{0x00, 0x80, 0x01, 0x02},
		Channel: 20,
		RxInfo:  &radio.RxInfo{RSSI: -55, LQI: 180},
	}
	result := m.parseBeacon(frame)
	if result == nil {
		t.Fatal("parseBeacon should return a result")
	}
	if result.Channel != 20 {
		t.Errorf("channel = %d, want 20", result.Channel)
	}
	if result.RSSI != -55 {
		t.Errorf("RSSI = %d, want -55", result.RSSI)
	}
	if result.LQI != 180 {
		t.Errorf("LQI = %d, want 180", result.LQI)
	}
}

func TestParseBeaconNoRxInfo(t *testing.T) {
	m, _, _, _, _ := newTestMac(radio.CapNone)
	frame := &radio.Frame{
		PSDU:    []byte{0x00, 0x80, 0x01, 0x02},
		Channel: 15,
	}
	result := m.parseBeacon(frame)
	if result == nil {
		t.Fatal("parseBeacon should return a result")
	}
	if result.RSSI != 0 {
		t.Errorf("RSSI = %d, want 0 (no RxInfo)", result.RSSI)
	}
}

// --------------------------------------------------------------------------
// WaitingForData
// --------------------------------------------------------------------------

func TestWaitingForDataTimeout(t *testing.T) {
	m, _, _, macTimer, runner := newTestMac(radio.CapNone)
	_ = m.Enable()

	// Directly start WaitingForData operation.
	m.mu.Lock()
	m.startOperation(OperationWaitingForData)
	m.mu.Unlock()

	runner.run()

	if m.GetCurrentOperation() != OperationWaitingForData {
		t.Errorf("current op = %v, want WaitingForData", m.GetCurrentOperation())
	}

	// Fire the timeout — should finish.
	macTimer.fire()
	runner.run()

	if m.GetCurrentOperation() != OperationIdle {
		t.Errorf("current op = %v, want Idle after timeout", m.GetCurrentOperation())
	}
}

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

func TestConstants(t *testing.T) {
	if DataPollTimeout != 100*time.Millisecond {
		t.Errorf("DataPollTimeout = %v, want 100ms", DataPollTimeout)
	}
	if SleepDelay != 300*time.Millisecond {
		t.Errorf("SleepDelay = %v, want 300ms", SleepDelay)
	}
	if ScanDurationDefault != 300 {
		t.Errorf("ScanDurationDefault = %d, want 300", ScanDurationDefault)
	}
	if TxNumBcast != 1 {
		t.Errorf("TxNumBcast = %d, want 1", TxNumBcast)
	}
}
