// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package links

import (
	"testing"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/radio"
)

// --------------------------------------------------------------------------
// Mock radio
// --------------------------------------------------------------------------

type mockRadio struct {
	enabled     bool
	state       radio.State
	channel     uint8
	panID       uint16
	shortAddr   types.ShortAddress
	extAddr     types.ExtAddress
	rssi        int8
	sensitivity int8
	txBuf       radio.Frame
	txCount     int
	txErr       error
}

func newMockRadio() *mockRadio {
	return &mockRadio{
		rssi:        -50,
		sensitivity: -100,
	}
}

func (r *mockRadio) Enable() error {
	r.enabled = true
	r.state = radio.StateSleep
	return nil
}
func (r *mockRadio) Disable() error {
	r.enabled = false
	r.state = radio.StateDisabled
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
	return nil
}
func (r *mockRadio) Transmit(frame *radio.Frame) error {
	if r.txErr != nil {
		return r.txErr
	}
	r.state = radio.StateTransmit
	r.txCount++
	return nil
}
func (r *mockRadio) GetTransmitBuffer() *radio.Frame          { return &r.txBuf }
func (r *mockRadio) GetCaps() radio.Caps                      { return radio.CapNone }
func (r *mockRadio) GetIEEEEui64() [8]byte                    { return [8]byte{} }
func (r *mockRadio) SetPanID(panID uint16)                    { r.panID = panID }
func (r *mockRadio) SetExtendedAddress(addr types.ExtAddress) { r.extAddr = addr }
func (r *mockRadio) SetShortAddress(addr types.ShortAddress)  { r.shortAddr = addr }
func (r *mockRadio) GetTransmitPower() (int8, error)          { return 0, nil }
func (r *mockRadio) SetTransmitPower(_ int8) error            { return nil }
func (r *mockRadio) GetPromiscuous() bool                     { return false }
func (r *mockRadio) SetPromiscuous(_ bool)                    {}
func (r *mockRadio) GetRSSI() int8                            { return r.rssi }
func (r *mockRadio) GetSupportedChannelMask() uint32          { return 0x07FFF800 }
func (r *mockRadio) GetPreferredChannelMask() uint32          { return 0x07FFF800 }
func (r *mockRadio) GetReceiveSensitivity() int8              { return r.sensitivity }

func (r *mockRadio) EnableSrcMatch(_ bool)                              {}
func (r *mockRadio) AddSrcMatchShortEntry(_ types.ShortAddress) error   { return nil }
func (r *mockRadio) AddSrcMatchExtEntry(_ types.ExtAddress) error       { return nil }
func (r *mockRadio) ClearSrcMatchShortEntry(_ types.ShortAddress) error { return nil }
func (r *mockRadio) ClearSrcMatchExtEntry(_ types.ExtAddress) error     { return nil }
func (r *mockRadio) ClearSrcMatchShortEntries()                         {}
func (r *mockRadio) ClearSrcMatchExtEntries()                           {}

func (r *mockRadio) SetMacKey(_, _ uint8, _, _, _ types.KeyMaterial) {}
func (r *mockRadio) SetMacFrameCounter(_ uint32)                     {}
func (r *mockRadio) SetMacFrameCounterIfLarger(_ uint32)             {}
func (r *mockRadio) EnergyScan(_ uint8, _ uint16) error              { return nil }

// --------------------------------------------------------------------------
// RadioType tests
// --------------------------------------------------------------------------

func TestRadioTypeString(t *testing.T) {
	tests := []struct {
		rt   RadioType
		want string
	}{
		{RadioTypeIeee802154, "15.4"},
		{RadioTypeTrel, "TREL"},
		{RadioType(99), "Unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.rt.String(); got != tt.want {
			t.Errorf("RadioType(%d).String() = %q, want %q", tt.rt, got, tt.want)
		}
	}
}

// --------------------------------------------------------------------------
// RadioTypes tests
// --------------------------------------------------------------------------

func TestRadioTypesEmpty(t *testing.T) {
	var rt RadioTypes
	if !rt.IsEmpty() {
		t.Error("expected empty")
	}
	if rt.ContainsSingleRadio() {
		t.Error("expected not single radio when empty")
	}
	if rt.Contains(RadioTypeIeee802154) {
		t.Error("empty set should not contain 15.4")
	}
}

func TestRadioTypesAddContains(t *testing.T) {
	var rt RadioTypes
	rt = rt.Add(RadioTypeIeee802154)
	if !rt.Contains(RadioTypeIeee802154) {
		t.Error("expected to contain 15.4")
	}
	if rt.Contains(RadioTypeTrel) {
		t.Error("expected not to contain TREL")
	}
	if !rt.ContainsSingleRadio() {
		t.Error("expected single radio")
	}
}

func TestRadioTypesAddAll(t *testing.T) {
	var rt RadioTypes
	rt = rt.AddAll()
	if !rt.Contains(RadioTypeIeee802154) {
		t.Error("expected to contain 15.4")
	}
	if !rt.Contains(RadioTypeTrel) {
		t.Error("expected to contain TREL")
	}
	if rt.ContainsSingleRadio() {
		t.Error("expected not single radio when both set")
	}
}

func TestRadioTypesRemove(t *testing.T) {
	var rt RadioTypes
	rt = rt.AddAll()
	rt = rt.Remove(RadioTypeTrel)
	if !rt.Contains(RadioTypeIeee802154) {
		t.Error("expected 15.4 after removing TREL")
	}
	if rt.Contains(RadioTypeTrel) {
		t.Error("expected no TREL after remove")
	}
}

func TestRadioTypesClear(t *testing.T) {
	var rt RadioTypes
	rt = rt.AddAll()
	rt = rt.Clear()
	if !rt.IsEmpty() {
		t.Error("expected empty after clear")
	}
}

func TestRadioTypesSubtract(t *testing.T) {
	all := RadioTypes(0).AddAll()
	trelOnly := RadioTypes(0).Add(RadioTypeTrel)
	result := all.Subtract(trelOnly)
	if !result.Contains(RadioTypeIeee802154) {
		t.Error("expected 15.4 in result")
	}
	if result.Contains(RadioTypeTrel) {
		t.Error("expected no TREL in result")
	}
}

func TestRadioTypesGetAsBitMask(t *testing.T) {
	rt := RadioTypes(0).Add(RadioTypeIeee802154).Add(RadioTypeTrel)
	if rt.GetAsBitMask() != 0x03 {
		t.Errorf("expected bitmask 0x03, got 0x%02x", rt.GetAsBitMask())
	}
}

func TestRadioTypesString(t *testing.T) {
	tests := []struct {
		rt   RadioTypes
		want string
	}{
		{RadioTypes(0), "{}"},
		{RadioTypes(0).Add(RadioTypeIeee802154), "{15.4}"},
		{RadioTypes(0).Add(RadioTypeTrel), "{TREL}"},
		{RadioTypes(0).AddAll(), "{15.4, TREL}"},
	}
	for _, tt := range tests {
		if got := tt.rt.String(); got != tt.want {
			t.Errorf("RadioTypes(%d).String() = %q, want %q", tt.rt, got, tt.want)
		}
	}
}

// --------------------------------------------------------------------------
// TxFrames tests
// --------------------------------------------------------------------------

func TestTxFramesGetTxFrame(t *testing.T) {
	tf := NewTxFrames()
	f := tf.GetTxFrame(RadioTypeIeee802154)
	if f == nil {
		t.Fatal("expected non-nil frame")
	}
	if !tf.GetSelectedRadioTypes().Contains(RadioTypeIeee802154) {
		t.Error("expected 15.4 in selected types")
	}
	if tf.GetSelectedRadioTypes().Contains(RadioTypeTrel) {
		t.Error("expected no TREL in selected types")
	}
}

func TestTxFramesGetBroadcastTxFrame(t *testing.T) {
	tf := NewTxFrames()
	f := tf.GetBroadcastTxFrame()
	if f == nil {
		t.Fatal("expected non-nil frame")
	}
	sel := tf.GetSelectedRadioTypes()
	if !sel.Contains(RadioTypeIeee802154) || !sel.Contains(RadioTypeTrel) {
		t.Error("expected all radio types selected for broadcast")
	}
}

func TestTxFramesClear(t *testing.T) {
	tf := NewTxFrames()
	f := tf.GetTxFrame(RadioTypeIeee802154)
	f.PSDU = append(f.PSDU, 1, 2, 3)
	tf.SetRequiredRadioTypes(RadioTypes(0).Add(RadioTypeIeee802154))

	tf.Clear()

	if len(tf.GetTxFrame(RadioTypeIeee802154).PSDU) != 0 {
		// GetTxFrame adds to selected, but we just want to check PSDU was cleared
		t.Error("expected PSDU cleared")
	}
	if !tf.GetRequiredRadioTypes().IsEmpty() {
		t.Error("expected required types cleared")
	}
}

func TestTxFramesSetChannel(t *testing.T) {
	tf := NewTxFrames()
	tf.SetChannel(15)
	for i, rt := range AllRadioTypes {
		f := tf.frames[rt]
		if f.Channel != 15 {
			t.Errorf("frame[%d] channel = %d, want 15", i, f.Channel)
		}
	}
}

func TestTxFramesRequiredTypes(t *testing.T) {
	tf := NewTxFrames()
	rt := RadioTypes(0).Add(RadioTypeIeee802154)
	tf.SetRequiredRadioTypes(rt)
	if tf.GetRequiredRadioTypes() != rt {
		t.Error("required types mismatch")
	}
}

// --------------------------------------------------------------------------
// Links tests
// --------------------------------------------------------------------------

func TestLinksNew(t *testing.T) {
	ieee := newMockRadio()
	l := New(ieee, nil)

	if l.GetShortAddress() != types.ShortAddressInvalid {
		t.Error("expected invalid short address")
	}
	if l.IsEnabled() {
		t.Error("expected not enabled")
	}
	if !l.HasRadio(RadioTypeIeee802154) {
		t.Error("expected IEEE radio")
	}
	if l.HasRadio(RadioTypeTrel) {
		t.Error("expected no TREL radio")
	}
}

func TestLinksEnableDisable(t *testing.T) {
	ieee := newMockRadio()
	trel := newMockRadio()
	l := New(ieee, trel)

	if err := l.Enable(); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}
	if !l.IsEnabled() {
		t.Error("expected enabled")
	}
	if !ieee.enabled || !trel.enabled {
		t.Error("expected both radios enabled")
	}

	if err := l.Disable(); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}
	if l.IsEnabled() {
		t.Error("expected not enabled")
	}
	if ieee.enabled || trel.enabled {
		t.Error("expected both radios disabled")
	}
}

func TestLinksSetPanID(t *testing.T) {
	ieee := newMockRadio()
	trel := newMockRadio()
	l := New(ieee, trel)

	l.SetPanID(0x1234)
	if ieee.panID != 0x1234 {
		t.Errorf("ieee PAN ID = 0x%04x, want 0x1234", ieee.panID)
	}
	if trel.panID != 0x1234 {
		t.Errorf("trel PAN ID = 0x%04x, want 0x1234", trel.panID)
	}
}

func TestLinksSetShortAddress(t *testing.T) {
	ieee := newMockRadio()
	l := New(ieee, nil)

	l.SetShortAddress(0x0001)
	if l.GetShortAddress() != 0x0001 {
		t.Errorf("short address = %v, want 0x0001", l.GetShortAddress())
	}
	if ieee.shortAddr != 0x0001 {
		t.Error("radio short address not set")
	}
}

func TestLinksSetExtAddress(t *testing.T) {
	ieee := newMockRadio()
	trel := newMockRadio()
	l := New(ieee, trel)

	addr := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	l.SetExtAddress(addr)
	if l.GetExtAddress() != addr {
		t.Error("ext address mismatch")
	}
	if ieee.extAddr != addr {
		t.Error("ieee ext address not set")
	}
	if trel.extAddr != addr {
		t.Error("trel ext address not set")
	}
}

func TestLinksSleepReceive(t *testing.T) {
	ieee := newMockRadio()
	l := New(ieee, nil)
	_ = l.Enable()

	if err := l.Sleep(); err != nil {
		t.Fatalf("Sleep failed: %v", err)
	}
	if ieee.state != radio.StateSleep {
		t.Error("expected sleep state")
	}

	if err := l.Receive(15); err != nil {
		t.Fatalf("Receive failed: %v", err)
	}
	if ieee.channel != 15 {
		t.Errorf("channel = %d, want 15", ieee.channel)
	}
	if ieee.state != radio.StateReceive {
		t.Error("expected receive state")
	}
}

func TestLinksSend(t *testing.T) {
	ieee := newMockRadio()
	l := New(ieee, nil)
	_ = l.Enable()

	tf := l.GetTxFrames()
	f := tf.GetTxFrame(RadioTypeIeee802154)
	f.PSDU = append(f.PSDU, 0xAA, 0xBB)

	if err := l.Send(RadioTypeIeee802154); err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	if ieee.txCount != 1 {
		t.Errorf("expected 1 transmit, got %d", ieee.txCount)
	}
}

func TestLinksSendNoRadio(t *testing.T) {
	l := New(nil, nil)
	if err := l.Send(RadioTypeIeee802154); err != ErrNotImplemented {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
}

func TestLinksEnergyScan(t *testing.T) {
	ieee := newMockRadio()
	l := New(ieee, nil)

	if err := l.EnergyScan(15, 100); err != nil {
		t.Fatalf("EnergyScan failed: %v", err)
	}

	// No IEEE radio.
	l2 := New(nil, nil)
	if err := l2.EnergyScan(15, 100); err != ErrNotImplemented {
		t.Errorf("expected ErrNotImplemented, got %v", err)
	}
}

func TestLinksGetRssi(t *testing.T) {
	ieee := newMockRadio()
	ieee.rssi = -75
	l := New(ieee, nil)

	if l.GetRssi() != -75 {
		t.Errorf("RSSI = %d, want -75", l.GetRssi())
	}

	l2 := New(nil, nil)
	if l2.GetRssi() != radio.RSSIInvalid {
		t.Errorf("expected RSSIInvalid, got %d", l2.GetRssi())
	}
}

func TestLinksGetNoiseFloor(t *testing.T) {
	ieee := newMockRadio()
	ieee.sensitivity = -95
	l := New(ieee, nil)

	if l.GetNoiseFloor() != -95 {
		t.Errorf("noise floor = %d, want -95", l.GetNoiseFloor())
	}

	l2 := New(nil, nil)
	if l2.GetNoiseFloor() != -100 {
		t.Errorf("expected -100 default, got %d", l2.GetNoiseFloor())
	}
}

func TestLinksGetTransmitRetries(t *testing.T) {
	l := New(nil, nil)
	if l.GetTransmitRetries() != 0 {
		t.Errorf("expected 0 retries initially, got %d", l.GetTransmitRetries())
	}
}

func TestLinksSetLastTxRetries(t *testing.T) {
	l := New(nil, nil)
	l.SetLastTxRetries(5)
	if got := l.GetTransmitRetries(); got != 5 {
		t.Errorf("GetTransmitRetries() = %d, want 5", got)
	}
	l.SetLastTxRetries(0)
	if got := l.GetTransmitRetries(); got != 0 {
		t.Errorf("GetTransmitRetries() = %d, want 0 after reset", got)
	}
}
