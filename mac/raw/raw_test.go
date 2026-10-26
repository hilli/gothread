// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package raw

import (
	"errors"
	"testing"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/radio"
)

// --------------------------------------------------------------------------
// Mock radio
// --------------------------------------------------------------------------

type mockRadio struct {
	caps          radio.Caps
	state         radio.State
	enabled       bool
	channel       uint8
	panID         uint16
	shortAddr     types.ShortAddress
	extAddr       types.ExtAddress
	promiscuous   bool
	rssi          int8
	txPower       int8
	transmitBuf   radio.Frame
	macKeyIDMode  uint8
	macKeyID      uint8
	macFrameCount uint32

	enableCount     int
	disableCount    int
	receiveCount    int
	transmitCount   int
	energyScanCount int

	transmitErr   error
	energyScanErr error
}

func newMockRadio() *mockRadio {
	return &mockRadio{
		caps:  radio.CapNone,
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

func (r *mockRadio) GetTransmitBuffer() *radio.Frame          { return &r.transmitBuf }
func (r *mockRadio) GetCaps() radio.Caps                      { return r.caps }
func (r *mockRadio) GetIEEEEui64() [8]byte                    { return [8]byte{} }
func (r *mockRadio) SetPanID(panID uint16)                    { r.panID = panID }
func (r *mockRadio) SetExtendedAddress(addr types.ExtAddress) { r.extAddr = addr }
func (r *mockRadio) SetShortAddress(addr types.ShortAddress)  { r.shortAddr = addr }
func (r *mockRadio) GetTransmitPower() (int8, error)          { return r.txPower, nil }
func (r *mockRadio) SetTransmitPower(power int8) error        { r.txPower = power; return nil }
func (r *mockRadio) GetPromiscuous() bool                     { return r.promiscuous }
func (r *mockRadio) SetPromiscuous(enable bool)               { r.promiscuous = enable }
func (r *mockRadio) GetRSSI() int8                            { return r.rssi }
func (r *mockRadio) GetSupportedChannelMask() uint32          { return 0x07FFF800 }
func (r *mockRadio) GetPreferredChannelMask() uint32          { return 0x07FFF800 }
func (r *mockRadio) GetReceiveSensitivity() int8              { return -100 }

func (r *mockRadio) EnableSrcMatch(_ bool)                              {}
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

func (r *mockRadio) SetMacFrameCounter(counter uint32) { r.macFrameCount = counter }
func (r *mockRadio) SetMacFrameCounterIfLarger(counter uint32) {
	if counter > r.macFrameCount {
		r.macFrameCount = counter
	}
}

func (r *mockRadio) EnergyScan(_ uint8, _ uint16) error {
	if r.energyScanErr != nil {
		return r.energyScanErr
	}
	r.energyScanCount++
	return nil
}

// --------------------------------------------------------------------------
// Mock callbacks
// --------------------------------------------------------------------------

type mockCallbacks struct {
	receiveDoneCount    int
	receiveDoneFrame    *radio.Frame
	receiveDoneErr      error
	transmitDoneCount   int
	transmitDoneFrame   *radio.Frame
	transmitDoneAck     *radio.Frame
	transmitDoneErr     error
	energyScanDoneCount int
	energyScanMaxRSSI   int8
}

func (c *mockCallbacks) ReceiveDone(frame *radio.Frame, err error) {
	c.receiveDoneCount++
	c.receiveDoneFrame = frame
	c.receiveDoneErr = err
}

func (c *mockCallbacks) TransmitDone(frame, ackFrame *radio.Frame, err error) {
	c.transmitDoneCount++
	c.transmitDoneFrame = frame
	c.transmitDoneAck = ackFrame
	c.transmitDoneErr = err
}

func (c *mockCallbacks) EnergyScanDone(maxRSSI int8) {
	c.energyScanDoneCount++
	c.energyScanMaxRSSI = maxRSSI
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

func TestNewDefaults(t *testing.T) {
	r := newMockRadio()
	lr := New(r)

	if lr.IsEnabled() {
		t.Error("expected disabled after New")
	}
	if lr.GetChannel() != 11 {
		t.Errorf("expected channel 11, got %d", lr.GetChannel())
	}
	if lr.GetPanID() != 0xFFFF {
		t.Errorf("expected PAN ID 0xFFFF, got 0x%04x", lr.GetPanID())
	}
}

func TestEnableDisable(t *testing.T) {
	r := newMockRadio()
	lr := New(r)
	cb := &mockCallbacks{}

	// Enable with nil callbacks should fail.
	if err := lr.Enable(nil); err != ErrInvalidState {
		t.Errorf("expected ErrInvalidState for nil callbacks, got %v", err)
	}

	// Enable should succeed.
	if err := lr.Enable(cb); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}
	if !lr.IsEnabled() {
		t.Error("expected enabled after Enable")
	}
	if r.enableCount != 1 {
		t.Errorf("expected radio Enable called once, got %d", r.enableCount)
	}

	// Double enable should fail.
	if err := lr.Enable(cb); err != ErrInvalidState {
		t.Errorf("expected ErrInvalidState on double enable, got %v", err)
	}

	// Disable should succeed.
	if err := lr.Disable(); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}
	if lr.IsEnabled() {
		t.Error("expected disabled after Disable")
	}
}

func TestDisableWhileBusy(t *testing.T) {
	r := newMockRadio()
	lr := New(r)
	cb := &mockCallbacks{}
	_ = lr.Enable(cb)

	// Start a transmit to make it busy.
	_ = lr.Transmit()

	if err := lr.Disable(); err != ErrBusy {
		t.Errorf("expected ErrBusy while transmitting, got %v", err)
	}

	// Complete the transmit.
	lr.InvokeTransmitDone(nil, nil, nil)

	// Now disable should work.
	if err := lr.Disable(); err != nil {
		t.Fatalf("Disable failed after transmit done: %v", err)
	}
}

func TestSetChannelNotEnabled(t *testing.T) {
	r := newMockRadio()
	lr := New(r)

	if err := lr.SetChannel(15); err != ErrNotEnabled {
		t.Errorf("expected ErrNotEnabled, got %v", err)
	}
}

func TestSetChannel(t *testing.T) {
	r := newMockRadio()
	lr := New(r)
	cb := &mockCallbacks{}
	_ = lr.Enable(cb)

	if err := lr.SetChannel(15); err != nil {
		t.Fatalf("SetChannel failed: %v", err)
	}
	if lr.GetChannel() != 15 {
		t.Errorf("expected channel 15, got %d", lr.GetChannel())
	}
}

func TestSetPanID(t *testing.T) {
	r := newMockRadio()
	lr := New(r)
	cb := &mockCallbacks{}
	_ = lr.Enable(cb)

	if err := lr.SetPanID(0x1234); err != nil {
		t.Fatalf("SetPanID failed: %v", err)
	}
	if lr.GetPanID() != 0x1234 {
		t.Errorf("expected PAN ID 0x1234, got 0x%04x", lr.GetPanID())
	}
	if r.panID != 0x1234 {
		t.Error("radio PAN ID not updated")
	}
}

func TestSetShortAddress(t *testing.T) {
	r := newMockRadio()
	lr := New(r)
	cb := &mockCallbacks{}
	_ = lr.Enable(cb)

	addr := types.ShortAddress(0x0001)
	if err := lr.SetShortAddress(addr); err != nil {
		t.Fatalf("SetShortAddress failed: %v", err)
	}
	if lr.GetShortAddress() != addr {
		t.Error("short address mismatch")
	}
	if r.shortAddr != addr {
		t.Error("radio short address not updated")
	}
}

func TestSetExtAddress(t *testing.T) {
	r := newMockRadio()
	lr := New(r)
	cb := &mockCallbacks{}
	_ = lr.Enable(cb)

	addr := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if err := lr.SetExtAddress(addr); err != nil {
		t.Fatalf("SetExtAddress failed: %v", err)
	}
	if lr.GetExtAddress() != addr {
		t.Error("ext address mismatch")
	}
	if r.extAddr != addr {
		t.Error("radio ext address not updated")
	}
}

func TestPromiscuous(t *testing.T) {
	r := newMockRadio()
	lr := New(r)

	lr.SetPromiscuous(true)
	if !lr.GetPromiscuous() {
		t.Error("expected promiscuous true")
	}
	lr.SetPromiscuous(false)
	if lr.GetPromiscuous() {
		t.Error("expected promiscuous false")
	}
}

func TestReceive(t *testing.T) {
	r := newMockRadio()
	lr := New(r)

	// Not enabled.
	if err := lr.Receive(); err != ErrNotEnabled {
		t.Errorf("expected ErrNotEnabled, got %v", err)
	}

	cb := &mockCallbacks{}
	_ = lr.Enable(cb)
	_ = lr.SetChannel(15)

	if err := lr.Receive(); err != nil {
		t.Fatalf("Receive failed: %v", err)
	}
	if r.channel != 15 {
		t.Errorf("expected radio channel 15, got %d", r.channel)
	}
}

func TestTransmitAndDone(t *testing.T) {
	r := newMockRadio()
	lr := New(r)
	cb := &mockCallbacks{}
	_ = lr.Enable(cb)

	if err := lr.Transmit(); err != nil {
		t.Fatalf("Transmit failed: %v", err)
	}
	if !lr.IsTransmitting() {
		t.Error("expected transmitting")
	}

	// Cannot transmit again while transmitting.
	if err := lr.Transmit(); err != ErrBusy {
		t.Errorf("expected ErrBusy, got %v", err)
	}

	// Complete.
	frame := &radio.Frame{PSDU: []byte{1, 2, 3}}
	lr.InvokeTransmitDone(frame, nil, nil)

	if lr.IsTransmitting() {
		t.Error("expected not transmitting after done")
	}
	if cb.transmitDoneCount != 1 {
		t.Errorf("expected 1 transmit done callback, got %d", cb.transmitDoneCount)
	}
	if cb.transmitDoneFrame != frame {
		t.Error("transmit done frame mismatch")
	}
}

func TestTransmitError(t *testing.T) {
	r := newMockRadio()
	r.transmitErr = errors.New("radio tx error")
	lr := New(r)
	cb := &mockCallbacks{}
	_ = lr.Enable(cb)

	if err := lr.Transmit(); err == nil {
		t.Error("expected error from Transmit")
	}
	if lr.IsTransmitting() {
		t.Error("should not be transmitting on error")
	}
}

func TestReceiveDoneCallback(t *testing.T) {
	r := newMockRadio()
	lr := New(r)
	cb := &mockCallbacks{}
	_ = lr.Enable(cb)

	frame := &radio.Frame{PSDU: []byte{0xAA}}
	lr.InvokeReceiveDone(frame, nil)

	if cb.receiveDoneCount != 1 {
		t.Errorf("expected 1 receive done callback, got %d", cb.receiveDoneCount)
	}
	if cb.receiveDoneFrame != frame {
		t.Error("receive done frame mismatch")
	}

	// With error, callback should NOT be called.
	lr.InvokeReceiveDone(nil, errors.New("rx error"))
	if cb.receiveDoneCount != 1 {
		t.Error("callback should not fire on error")
	}
}

func TestEnergyScan(t *testing.T) {
	r := newMockRadio()
	lr := New(r)
	cb := &mockCallbacks{}

	// Not enabled.
	if err := lr.EnergyScan(11, 100); err != ErrNotEnabled {
		t.Errorf("expected ErrNotEnabled, got %v", err)
	}

	_ = lr.Enable(cb)

	if err := lr.EnergyScan(15, 200); err != nil {
		t.Fatalf("EnergyScan failed: %v", err)
	}
	if !lr.IsEnergyScanning() {
		t.Error("expected energy scanning")
	}

	// Cannot start another scan.
	if err := lr.EnergyScan(15, 200); err != ErrBusy {
		t.Errorf("expected ErrBusy, got %v", err)
	}

	// Complete.
	lr.InvokeEnergyScanDone(-40)
	if lr.IsEnergyScanning() {
		t.Error("expected not scanning after done")
	}
	if cb.energyScanDoneCount != 1 {
		t.Errorf("expected 1 energy scan done, got %d", cb.energyScanDoneCount)
	}
	if cb.energyScanMaxRSSI != -40 {
		t.Errorf("expected maxRSSI -40, got %d", cb.energyScanMaxRSSI)
	}
}

func TestSetMacKey(t *testing.T) {
	r := newMockRadio()
	lr := New(r)

	// Not enabled.
	if err := lr.SetMacKey(1, 2, types.KeyMaterial{}, types.KeyMaterial{}, types.KeyMaterial{}); err != ErrNotEnabled {
		t.Errorf("expected ErrNotEnabled, got %v", err)
	}

	cb := &mockCallbacks{}
	_ = lr.Enable(cb)

	if err := lr.SetMacKey(1, 5, types.KeyMaterial{}, types.KeyMaterial{}, types.KeyMaterial{}); err != nil {
		t.Fatalf("SetMacKey failed: %v", err)
	}
	if r.macKeyIDMode != 1 || r.macKeyID != 5 {
		t.Error("radio mac key not updated")
	}
}

func TestSetMacFrameCounter(t *testing.T) {
	r := newMockRadio()
	lr := New(r)
	cb := &mockCallbacks{}
	_ = lr.Enable(cb)

	// Direct set.
	if err := lr.SetMacFrameCounter(100, false); err != nil {
		t.Fatalf("SetMacFrameCounter failed: %v", err)
	}
	if r.macFrameCount != 100 {
		t.Errorf("expected 100, got %d", r.macFrameCount)
	}

	// Set if larger — lower value should not change.
	if err := lr.SetMacFrameCounter(50, true); err != nil {
		t.Fatalf("SetMacFrameCounter failed: %v", err)
	}
	if r.macFrameCount != 100 {
		t.Errorf("expected 100 (unchanged), got %d", r.macFrameCount)
	}

	// Set if larger — higher value should change.
	if err := lr.SetMacFrameCounter(200, true); err != nil {
		t.Fatalf("SetMacFrameCounter failed: %v", err)
	}
	if r.macFrameCount != 200 {
		t.Errorf("expected 200, got %d", r.macFrameCount)
	}
}

func TestGetRSSI(t *testing.T) {
	r := newMockRadio()
	r.rssi = -75
	lr := New(r)

	if lr.GetRSSI() != -75 {
		t.Errorf("expected RSSI -75, got %d", lr.GetRSSI())
	}
}

func TestOperationsNotEnabled(t *testing.T) {
	r := newMockRadio()
	lr := New(r)

	tests := []struct {
		name string
		fn   func() error
	}{
		{"SetPanID", func() error { return lr.SetPanID(0x1234) }},
		{"SetShortAddress", func() error { return lr.SetShortAddress(0x0001) }},
		{"SetExtAddress", func() error { return lr.SetExtAddress(types.ExtAddress{}) }},
		{"Receive", func() error { return lr.Receive() }},
		{"Transmit", func() error { return lr.Transmit() }},
		{"EnergyScan", func() error { return lr.EnergyScan(11, 100) }},
		{"SetMacFrameCounter", func() error { return lr.SetMacFrameCounter(1, false) }},
	}

	for _, tt := range tests {
		if err := tt.fn(); err != ErrNotEnabled {
			t.Errorf("%s: expected ErrNotEnabled, got %v", tt.name, err)
		}
	}
}
