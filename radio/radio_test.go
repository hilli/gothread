// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package radio

import (
	"testing"

	"github.com/hilli/gothread/mac/types"
)

// --------------------------------------------------------------------------
// Mock radio — compile-time interface verification
// --------------------------------------------------------------------------

type mockRadio struct {
	state       State
	enabled     bool
	panID       uint16
	extAddr     types.ExtAddress
	shortAddr   types.ShortAddress
	txPower     int8
	promiscuous bool
	srcMatch    bool
	txBuf       Frame
	caps        Caps
	counter     uint32
}

func (r *mockRadio) Enable() error             { r.enabled = true; r.state = StateSleep; return nil }
func (r *mockRadio) Disable() error            { r.enabled = false; r.state = StateDisabled; return nil }
func (r *mockRadio) IsEnabled() bool           { return r.enabled }
func (r *mockRadio) GetState() State           { return r.state }
func (r *mockRadio) Sleep() error              { r.state = StateSleep; return nil }
func (r *mockRadio) Receive(_ uint8) error     { r.state = StateReceive; return nil }
func (r *mockRadio) Transmit(_ *Frame) error   { r.state = StateTransmit; return nil }
func (r *mockRadio) GetTransmitBuffer() *Frame { return &r.txBuf }
func (r *mockRadio) GetCaps() Caps             { return r.caps }
func (r *mockRadio) GetIEEEEui64() [8]byte {
	return [8]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
}
func (r *mockRadio) SetPanID(panID uint16)                                 { r.panID = panID }
func (r *mockRadio) SetExtendedAddress(addr types.ExtAddress)              { r.extAddr = addr }
func (r *mockRadio) SetShortAddress(addr types.ShortAddress)               { r.shortAddr = addr }
func (r *mockRadio) GetTransmitPower() (int8, error)                       { return r.txPower, nil }
func (r *mockRadio) SetTransmitPower(power int8) error                     { r.txPower = power; return nil }
func (r *mockRadio) GetPromiscuous() bool                                  { return r.promiscuous }
func (r *mockRadio) SetPromiscuous(enable bool)                            { r.promiscuous = enable }
func (r *mockRadio) GetRSSI() int8                                         { return RSSIInvalid }
func (r *mockRadio) GetSupportedChannelMask() uint32                       { return 0x07FFF800 }
func (r *mockRadio) GetPreferredChannelMask() uint32                       { return 0x07FFF800 }
func (r *mockRadio) GetReceiveSensitivity() int8                           { return -100 }
func (r *mockRadio) EnableSrcMatch(enable bool)                            { r.srcMatch = enable }
func (r *mockRadio) AddSrcMatchShortEntry(_ types.ShortAddress) error      { return nil }
func (r *mockRadio) AddSrcMatchExtEntry(_ types.ExtAddress) error          { return nil }
func (r *mockRadio) ClearSrcMatchShortEntry(_ types.ShortAddress) error    { return nil }
func (r *mockRadio) ClearSrcMatchExtEntry(_ types.ExtAddress) error        { return nil }
func (r *mockRadio) ClearSrcMatchShortEntries()                            {}
func (r *mockRadio) ClearSrcMatchExtEntries()                              {}
func (r *mockRadio) SetMacKey(_ uint8, _ uint8, _, _, _ types.KeyMaterial) {}
func (r *mockRadio) SetMacFrameCounter(counter uint32)                     { r.counter = counter }
func (r *mockRadio) SetMacFrameCounterIfLarger(counter uint32) {
	if counter > r.counter {
		r.counter = counter
	}
}
func (r *mockRadio) EnergyScan(_ uint8, _ uint16) error { return nil }

type mockCallbacks struct {
	rxFrame *Frame
	txFrame *Frame
	maxRSSI int8
}

func (c *mockCallbacks) HandleReceiveDone(frame *Frame, _ error)        { c.rxFrame = frame }
func (c *mockCallbacks) HandleTransmitStarted(frame *Frame)             { c.txFrame = frame }
func (c *mockCallbacks) HandleTransmitDone(_ *Frame, _ *Frame, _ error) {}
func (c *mockCallbacks) HandleEnergyScanDone(maxRSSI int8)              { c.maxRSSI = maxRSSI }

// Compile-time interface checks.
var (
	_ Radio     = (*mockRadio)(nil)
	_ Callbacks = (*mockCallbacks)(nil)
)

// --------------------------------------------------------------------------
// State tests
// --------------------------------------------------------------------------

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateDisabled, "Disabled"},
		{StateSleep, "Sleep"},
		{StateReceive, "Receive"},
		{StateTransmit, "Transmit"},
		{State(99), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

// --------------------------------------------------------------------------
// Caps tests
// --------------------------------------------------------------------------

func TestCapsHas(t *testing.T) {
	caps := CapAckTimeout | CapEnergyScan | CapTransmitRetries

	if !caps.Has(CapAckTimeout) {
		t.Error("expected Has(CapAckTimeout) to be true")
	}
	if !caps.Has(CapEnergyScan) {
		t.Error("expected Has(CapEnergyScan) to be true")
	}
	if caps.Has(CapSleepToTx) {
		t.Error("expected Has(CapSleepToTx) to be false")
	}
}

func TestCapsValues(t *testing.T) {
	tests := []struct {
		cap  Caps
		want uint16
	}{
		{CapNone, 0},
		{CapAckTimeout, 1},
		{CapEnergyScan, 2},
		{CapTransmitRetries, 4},
		{CapCsmaBackoff, 8},
		{CapSleepToTx, 16},
		{CapTransmitSec, 32},
		{CapTransmitTiming, 64},
		{CapReceiveTiming, 128},
		{CapRxOnWhenIdle, 256},
		{CapTransmitFramePower, 512},
		{CapAltShortAddr, 1024},
	}
	for _, tt := range tests {
		if uint16(tt.cap) != tt.want {
			t.Errorf("Cap %d != expected %d", uint16(tt.cap), tt.want)
		}
	}
}

// --------------------------------------------------------------------------
// Constants tests
// --------------------------------------------------------------------------

func TestConstants(t *testing.T) {
	if FrameMaxSize != 127 {
		t.Errorf("FrameMaxSize = %d, want 127", FrameMaxSize)
	}
	if FrameMinSize != 3 {
		t.Errorf("FrameMinSize = %d, want 3", FrameMinSize)
	}
	if FrameFCSSize != 2 {
		t.Errorf("FrameFCSSize = %d, want 2", FrameFCSSize)
	}
	if RSSIInvalid != 127 {
		t.Errorf("RSSIInvalid = %d, want 127", RSSIInvalid)
	}
	if PowerInvalid != 127 {
		t.Errorf("PowerInvalid = %d, want 127", PowerInvalid)
	}
	if Channel24GHzMin != 11 {
		t.Errorf("Channel24GHzMin = %d, want 11", Channel24GHzMin)
	}
	if Channel24GHzMax != 26 {
		t.Errorf("Channel24GHzMax = %d, want 26", Channel24GHzMax)
	}
	if Channel915MHzMin != 1 {
		t.Errorf("Channel915MHzMin = %d, want 1", Channel915MHzMin)
	}
	if Channel915MHzMax != 10 {
		t.Errorf("Channel915MHzMax = %d, want 10", Channel915MHzMax)
	}
}

// --------------------------------------------------------------------------
// Frame tests
// --------------------------------------------------------------------------

func TestFrameCreation(t *testing.T) {
	f := &Frame{
		PSDU:    make([]byte, FrameMaxSize),
		Channel: 15,
		TxInfo: &TxInfo{
			MaxCsmaBackoffs: 4,
			MaxFrameRetries: 3,
			TxPower:         PowerInvalid,
			CsmaCaEnabled:   true,
		},
	}

	if len(f.PSDU) != FrameMaxSize {
		t.Errorf("PSDU len = %d, want %d", len(f.PSDU), FrameMaxSize)
	}
	if f.Channel != 15 {
		t.Errorf("Channel = %d, want 15", f.Channel)
	}
	if f.TxInfo == nil {
		t.Fatal("TxInfo should not be nil")
	}
	if f.TxInfo.MaxCsmaBackoffs != 4 {
		t.Errorf("MaxCsmaBackoffs = %d, want 4", f.TxInfo.MaxCsmaBackoffs)
	}
	if f.RxInfo != nil {
		t.Error("RxInfo should be nil for TX frame")
	}
}

func TestRxFrame(t *testing.T) {
	f := &Frame{
		PSDU:    []byte{0x01, 0x02, 0x03},
		Channel: 20,
		RxInfo: &RxInfo{
			Timestamp:             12345678,
			RSSI:                  -75,
			LQI:                   200,
			AckedWithFramePending: true,
		},
	}

	if f.RxInfo.RSSI != -75 {
		t.Errorf("RSSI = %d, want -75", f.RxInfo.RSSI)
	}
	if f.RxInfo.LQI != 200 {
		t.Errorf("LQI = %d, want 200", f.RxInfo.LQI)
	}
	if !f.RxInfo.AckedWithFramePending {
		t.Error("AckedWithFramePending should be true")
	}
}

// --------------------------------------------------------------------------
// Radio lifecycle tests (via mock)
// --------------------------------------------------------------------------

func TestRadioLifecycle(t *testing.T) {
	r := &mockRadio{}

	// Initially disabled
	if r.IsEnabled() {
		t.Error("radio should start disabled")
	}
	if r.GetState() != StateDisabled {
		t.Error("initial state should be Disabled")
	}

	// Enable → Sleep
	if err := r.Enable(); err != nil {
		t.Fatalf("Enable() error: %v", err)
	}
	if !r.IsEnabled() {
		t.Error("radio should be enabled after Enable()")
	}
	if r.GetState() != StateSleep {
		t.Errorf("state after Enable() = %v, want Sleep", r.GetState())
	}

	// Sleep → Receive
	if err := r.Receive(15); err != nil {
		t.Fatalf("Receive() error: %v", err)
	}
	if r.GetState() != StateReceive {
		t.Errorf("state after Receive() = %v, want Receive", r.GetState())
	}

	// Receive → Transmit
	frame := &Frame{PSDU: []byte{0x01, 0x02}, Channel: 15}
	if err := r.Transmit(frame); err != nil {
		t.Fatalf("Transmit() error: %v", err)
	}
	if r.GetState() != StateTransmit {
		t.Errorf("state after Transmit() = %v, want Transmit", r.GetState())
	}

	// Back to sleep
	if err := r.Sleep(); err != nil {
		t.Fatalf("Sleep() error: %v", err)
	}
	if r.GetState() != StateSleep {
		t.Errorf("state after Sleep() = %v, want Sleep", r.GetState())
	}

	// Disable
	if err := r.Disable(); err != nil {
		t.Fatalf("Disable() error: %v", err)
	}
	if r.IsEnabled() {
		t.Error("radio should be disabled after Disable()")
	}
}

func TestRadioConfiguration(t *testing.T) {
	r := &mockRadio{}

	r.SetPanID(0x1234)
	if r.panID != 0x1234 {
		t.Errorf("PanID = %#04x, want 0x1234", r.panID)
	}

	if err := r.SetTransmitPower(5); err != nil {
		t.Fatalf("SetTransmitPower() error: %v", err)
	}
	power, err := r.GetTransmitPower()
	if err != nil {
		t.Fatalf("GetTransmitPower() error: %v", err)
	}
	if power != 5 {
		t.Errorf("TxPower = %d, want 5", power)
	}

	r.SetPromiscuous(true)
	if !r.GetPromiscuous() {
		t.Error("promiscuous should be true")
	}
}

func TestRadioMacFrameCounter(t *testing.T) {
	r := &mockRadio{}

	r.SetMacFrameCounter(100)
	if r.counter != 100 {
		t.Errorf("counter = %d, want 100", r.counter)
	}

	// SetMacFrameCounterIfLarger — larger value should update
	r.SetMacFrameCounterIfLarger(200)
	if r.counter != 200 {
		t.Errorf("counter = %d, want 200", r.counter)
	}

	// SetMacFrameCounterIfLarger — smaller value should not update
	r.SetMacFrameCounterIfLarger(50)
	if r.counter != 200 {
		t.Errorf("counter = %d, want 200 (should not decrease)", r.counter)
	}
}

func TestRadioSupportedChannelMask(t *testing.T) {
	r := &mockRadio{}
	mask := r.GetSupportedChannelMask()
	// 0x07FFF800 = channels 11-26 (bits 11..26 set)
	for ch := uint8(11); ch <= 26; ch++ {
		if mask&(1<<ch) == 0 {
			t.Errorf("channel %d should be supported", ch)
		}
	}
	for ch := uint8(0); ch <= 10; ch++ {
		if mask&(1<<ch) != 0 {
			t.Errorf("channel %d should not be supported", ch)
		}
	}
}

func TestCallbacksReceiveDone(t *testing.T) {
	cb := &mockCallbacks{}
	frame := &Frame{PSDU: []byte{0xAA, 0xBB}, Channel: 11}
	cb.HandleReceiveDone(frame, nil)
	if cb.rxFrame != frame {
		t.Error("HandleReceiveDone should store the frame")
	}
}

func TestCallbacksEnergyScanDone(t *testing.T) {
	cb := &mockCallbacks{}
	cb.HandleEnergyScanDone(-50)
	if cb.maxRSSI != -50 {
		t.Errorf("maxRSSI = %d, want -50", cb.maxRSSI)
	}
}
