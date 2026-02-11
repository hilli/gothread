// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package diags

import (
	"math"
	"strings"
	"testing"

	"github.com/hilli/gothread/errors"
)

// --------------------------------------------------------------------------
// Mock RadioControl
// --------------------------------------------------------------------------

type mockRadio struct {
	channel    uint16
	txPower    int8
	rssi       int8
	enabled    bool
	receiving  bool
	txPayloads [][]byte

	// Error injection.
	enableErr   error
	disableErr  error
	channelErr  error
	txPowerErr  error
	transmitErr error
	receiveErr  error
	stopRecvErr error
	rssiErr     error
	sleepErr    error
}

func newMockRadio() *mockRadio {
	return &mockRadio{
		channel: 11,
		rssi:    -60,
	}
}

func (r *mockRadio) SetChannel(ch uint16) error {
	if r.channelErr != nil {
		return r.channelErr
	}
	r.channel = ch
	return nil
}

func (r *mockRadio) GetChannel() uint16 { return r.channel }

func (r *mockRadio) SetTxPower(power int8) error {
	if r.txPowerErr != nil {
		return r.txPowerErr
	}
	r.txPower = power
	return nil
}

func (r *mockRadio) GetTxPower() (int8, error) {
	if r.txPowerErr != nil {
		return 0, r.txPowerErr
	}
	return r.txPower, nil
}

func (r *mockRadio) Transmit(payload []byte) error {
	if r.transmitErr != nil {
		return r.transmitErr
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	r.txPayloads = append(r.txPayloads, cp)
	return nil
}

func (r *mockRadio) StartReceive() error {
	if r.receiveErr != nil {
		return r.receiveErr
	}
	r.receiving = true
	return nil
}

func (r *mockRadio) StopReceive() error {
	if r.stopRecvErr != nil {
		return r.stopRecvErr
	}
	r.receiving = false
	return nil
}

func (r *mockRadio) GetRssi() (int8, error) {
	if r.rssiErr != nil {
		return 0, r.rssiErr
	}
	return r.rssi, nil
}

func (r *mockRadio) Sleep() error {
	if r.sleepErr != nil {
		return r.sleepErr
	}
	return nil
}

func (r *mockRadio) Enable() error {
	if r.enableErr != nil {
		return r.enableErr
	}
	r.enabled = true
	return nil
}

func (r *mockRadio) Disable() error {
	if r.disableErr != nil {
		return r.disableErr
	}
	r.enabled = false
	return nil
}

// Compile-time interface check.
var _ RadioControl = (*mockRadio)(nil)

// --------------------------------------------------------------------------
// NewDiags
// --------------------------------------------------------------------------

func TestNewDiags(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)

	if d.IsEnabled() {
		t.Fatal("new Diags should be disabled")
	}
	if d.GetState() != DiagStateDisabled {
		t.Fatalf("expected DiagStateDisabled, got %v", d.GetState())
	}
	if d.GetChannel() != defaultChannel {
		t.Fatalf("expected default channel %d, got %d", defaultChannel, d.GetChannel())
	}
}

// --------------------------------------------------------------------------
// Start / Stop
// --------------------------------------------------------------------------

func TestStartStop(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)

	if err := d.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if !d.IsEnabled() {
		t.Fatal("expected enabled after Start()")
	}
	if d.GetState() != DiagStateIdle {
		t.Fatalf("expected DiagStateIdle, got %v", d.GetState())
	}
	if !r.enabled {
		t.Fatal("radio should be enabled")
	}

	// Double-start should fail.
	if err := d.Start(); err != errors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState on double start, got %v", err)
	}

	if err := d.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if d.IsEnabled() {
		t.Fatal("expected disabled after Stop()")
	}
	if d.GetState() != DiagStateDisabled {
		t.Fatalf("expected DiagStateDisabled, got %v", d.GetState())
	}

	// Double-stop should fail.
	if err := d.Stop(); err != errors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState on double stop, got %v", err)
	}
}

func TestStartRadioEnableError(t *testing.T) {
	r := newMockRadio()
	r.enableErr = errors.ErrFailed
	d := NewDiags(r)

	if err := d.Start(); err != errors.ErrFailed {
		t.Fatalf("expected ErrFailed, got %v", err)
	}
	if d.IsEnabled() {
		t.Fatal("should not be enabled after failed start")
	}
}

// --------------------------------------------------------------------------
// Channel
// --------------------------------------------------------------------------

func TestSetChannel(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)

	// Should fail when disabled.
	if err := d.SetChannel(15); err != errors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}

	_ = d.Start()

	// Valid channels.
	for ch := uint16(11); ch <= 26; ch++ {
		if err := d.SetChannel(ch); err != nil {
			t.Fatalf("SetChannel(%d) error: %v", ch, err)
		}
		if d.GetChannel() != ch {
			t.Fatalf("expected channel %d, got %d", ch, d.GetChannel())
		}
		if r.channel != ch {
			t.Fatalf("radio channel not updated to %d", ch)
		}
	}

	// Invalid channels.
	for _, ch := range []uint16{0, 10, 27, 100} {
		if err := d.SetChannel(ch); err != errors.ErrInvalidArgs {
			t.Fatalf("SetChannel(%d) expected ErrInvalidArgs, got %v", ch, err)
		}
	}
}

// --------------------------------------------------------------------------
// Power
// --------------------------------------------------------------------------

func TestSetTxPower(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)

	// Should fail when disabled.
	if err := d.SetTxPower(5); err != errors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
	if _, err := d.GetTxPower(); err != errors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}

	_ = d.Start()

	if err := d.SetTxPower(-10); err != nil {
		t.Fatalf("SetTxPower() error: %v", err)
	}
	p, err := d.GetTxPower()
	if err != nil {
		t.Fatalf("GetTxPower() error: %v", err)
	}
	if p != -10 {
		t.Fatalf("expected -10, got %d", p)
	}
	if r.txPower != -10 {
		t.Fatalf("radio txPower not updated")
	}
}

// --------------------------------------------------------------------------
// Transmit test
// --------------------------------------------------------------------------

func TestStartTransmit(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_ = d.Start()

	config := TxConfig{Length: 20, Count: 5, Interval: 100}
	if err := d.StartTransmit(config); err != nil {
		t.Fatalf("StartTransmit() error: %v", err)
	}
	if d.GetState() != DiagStateTransmitting {
		t.Fatalf("expected DiagStateTransmitting, got %v", d.GetState())
	}
	if len(r.txPayloads) != 1 {
		t.Fatalf("expected 1 TX, got %d", len(r.txPayloads))
	}
	// Verify payload pattern.
	payload := r.txPayloads[0]
	if len(payload) != 20 {
		t.Fatalf("payload length = %d, want 20", len(payload))
	}
	for i, b := range payload {
		if b != byte(i&0xff) {
			t.Fatalf("payload[%d] = %d, want %d", i, b, i&0xff)
		}
	}
}

func TestStartTransmitInvalidState(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)

	// Disabled state.
	config := TxConfig{Length: 20, Count: 5, Interval: 100}
	if err := d.StartTransmit(config); err != errors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}

	_ = d.Start()
	_ = d.StartTransmit(config)

	// Already transmitting.
	if err := d.StartTransmit(config); err != errors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState for double start, got %v", err)
	}
}

func TestStartTransmitInvalidArgs(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_ = d.Start()

	// Zero length.
	if err := d.StartTransmit(TxConfig{Length: 0, Count: 1, Interval: 100}); err != errors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs for zero length, got %v", err)
	}

	// Zero interval.
	if err := d.StartTransmit(TxConfig{Length: 10, Count: 1, Interval: 0}); err != errors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs for zero interval, got %v", err)
	}
}

func TestHandleTransmitDone(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_ = d.Start()

	config := TxConfig{Length: 10, Count: 3, Interval: 100}
	_ = d.StartTransmit(config)

	// Simulate 3 completions: success, fail, success.
	d.HandleTransmitDone(nil)
	d.HandleTransmitDone(errors.ErrFailed)
	d.HandleTransmitDone(nil)

	stats := d.GetTxStats()
	// PacketCount includes the initial send (no HandleTransmitDone for it yet)
	// plus the 3 HandleTransmitDone calls. But the initial Transmit in
	// StartTransmit doesn't call HandleTransmitDone. So we get 3 from
	// HandleTransmitDone.
	if stats.PacketCount != 3 {
		t.Fatalf("PacketCount = %d, want 3", stats.PacketCount)
	}
	if stats.SuccessCount != 2 {
		t.Fatalf("SuccessCount = %d, want 2", stats.SuccessCount)
	}
	if stats.FailCount != 1 {
		t.Fatalf("FailCount = %d, want 1", stats.FailCount)
	}

	// After 3 of 3, should be back to idle.
	if d.GetState() != DiagStateIdle {
		t.Fatalf("expected DiagStateIdle after count reached, got %v", d.GetState())
	}
}

func TestHandleTransmitDoneContinuous(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_ = d.Start()

	// Continuous mode (count=0).
	config := TxConfig{Length: 10, Count: 0, Interval: 50}
	_ = d.StartTransmit(config)

	// Even after many completions, should still be transmitting.
	for i := 0; i < 100; i++ {
		d.HandleTransmitDone(nil)
	}
	if d.GetState() != DiagStateTransmitting {
		t.Fatal("continuous mode should not auto-stop")
	}

	d.StopTransmit()
	if d.GetState() != DiagStateIdle {
		t.Fatalf("expected idle after StopTransmit, got %v", d.GetState())
	}
}

func TestHandleTimer(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_ = d.Start()

	config := TxConfig{Length: 5, Count: 0, Interval: 100}
	_ = d.StartTransmit(config)

	initialTx := len(r.txPayloads)
	d.HandleTimer()
	if len(r.txPayloads) != initialTx+1 {
		t.Fatalf("HandleTimer should have sent another packet")
	}
}

func TestHandleTimerStopsWhenCountReached(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_ = d.Start()

	config := TxConfig{Length: 5, Count: 2, Interval: 100}
	_ = d.StartTransmit(config)

	// First HandleTransmitDone.
	d.HandleTransmitDone(nil)
	// Second HandleTransmitDone — this should make txCount reach Count.
	d.HandleTransmitDone(nil)

	// Now HandleTimer should not send.
	prevTx := len(r.txPayloads)
	d.HandleTimer()
	if len(r.txPayloads) != prevTx {
		t.Fatal("HandleTimer should not send after count reached")
	}
}

func TestStopTransmitNoop(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_ = d.Start()

	// StopTransmit when not transmitting should be a no-op.
	d.StopTransmit()
	if d.GetState() != DiagStateIdle {
		t.Fatalf("state should remain idle, got %v", d.GetState())
	}
}

// --------------------------------------------------------------------------
// Receive test
// --------------------------------------------------------------------------

func TestStartReceive(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_ = d.Start()

	if err := d.StartReceive(); err != nil {
		t.Fatalf("StartReceive() error: %v", err)
	}
	if d.GetState() != DiagStateReceiving {
		t.Fatalf("expected DiagStateReceiving, got %v", d.GetState())
	}
	if !r.receiving {
		t.Fatal("radio should be receiving")
	}
}

func TestStartReceiveInvalidState(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)

	// Disabled.
	if err := d.StartReceive(); err != errors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}

	_ = d.Start()
	_ = d.StartReceive()

	// Already receiving.
	if err := d.StartReceive(); err != errors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState for double receive, got %v", err)
	}
}

func TestStartReceiveRadioError(t *testing.T) {
	r := newMockRadio()
	r.receiveErr = errors.ErrFailed
	d := NewDiags(r)
	_ = d.Start()

	if err := d.StartReceive(); err != errors.ErrFailed {
		t.Fatalf("expected ErrFailed, got %v", err)
	}
	// Should remain idle on error.
	if d.GetState() != DiagStateIdle {
		t.Fatalf("expected idle after failed receive start, got %v", d.GetState())
	}
}

func TestHandleReceived(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_ = d.Start()
	_ = d.StartReceive()

	d.HandleReceived(-70, 200)
	d.HandleReceived(-50, 220)
	d.HandleReceived(-80, 180)

	stats := d.GetRxStats()
	if stats.PacketCount != 3 {
		t.Fatalf("PacketCount = %d, want 3", stats.PacketCount)
	}
	if stats.RssiMin != -80 {
		t.Fatalf("RssiMin = %d, want -80", stats.RssiMin)
	}
	if stats.RssiMax != -50 {
		t.Fatalf("RssiMax = %d, want -50", stats.RssiMax)
	}
	expectedRssiAvg := int8((-70 + -50 + -80) / 3)
	if stats.AverageRssi() != expectedRssiAvg {
		t.Fatalf("AverageRssi = %d, want %d", stats.AverageRssi(), expectedRssiAvg)
	}
	if stats.LqiMin != 180 {
		t.Fatalf("LqiMin = %d, want 180", stats.LqiMin)
	}
	if stats.LqiMax != 220 {
		t.Fatalf("LqiMax = %d, want 220", stats.LqiMax)
	}
	expectedLqiAvg := uint8((200 + 220 + 180) / 3)
	if stats.AverageLqi() != expectedLqiAvg {
		t.Fatalf("AverageLqi = %d, want %d", stats.AverageLqi(), expectedLqiAvg)
	}
}

func TestHandleReceivedIgnoredWhenNotReceiving(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_ = d.Start()

	// Not in receive mode — should be ignored.
	d.HandleReceived(-60, 200)
	stats := d.GetRxStats()
	if stats.PacketCount != 0 {
		t.Fatalf("should not record packets when not receiving")
	}
}

func TestStopReceive(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_ = d.Start()
	_ = d.StartReceive()

	d.StopReceive()
	if d.GetState() != DiagStateIdle {
		t.Fatalf("expected idle after StopReceive, got %v", d.GetState())
	}
	if r.receiving {
		t.Fatal("radio should not be receiving after stop")
	}
}

func TestStopReceiveNoop(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_ = d.Start()

	// StopReceive when not receiving should be a no-op.
	d.StopReceive()
	if d.GetState() != DiagStateIdle {
		t.Fatalf("state should remain idle, got %v", d.GetState())
	}
}

// --------------------------------------------------------------------------
// RSSI
// --------------------------------------------------------------------------

func TestGetRssi(t *testing.T) {
	r := newMockRadio()
	r.rssi = -75
	d := NewDiags(r)

	// Should fail when disabled.
	if _, err := d.GetRssi(); err != errors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}

	_ = d.Start()
	rssi, err := d.GetRssi()
	if err != nil {
		t.Fatalf("GetRssi() error: %v", err)
	}
	if rssi != -75 {
		t.Fatalf("expected -75, got %d", rssi)
	}
}

// --------------------------------------------------------------------------
// RxStats / TxStats
// --------------------------------------------------------------------------

func TestRxStatsReset(t *testing.T) {
	s := &RxStats{
		PacketCount: 10,
		RssiSum:     -500,
		RssiMin:     -80,
		RssiMax:     -40,
		LqiSum:      2000,
		LqiMin:      150,
		LqiMax:      250,
	}
	s.Reset()

	if s.PacketCount != 0 {
		t.Fatal("PacketCount should be 0 after reset")
	}
	if s.RssiSum != 0 {
		t.Fatal("RssiSum should be 0 after reset")
	}
	if s.RssiMin != math.MaxInt8 {
		t.Fatalf("RssiMin should be MaxInt8, got %d", s.RssiMin)
	}
	if s.RssiMax != math.MinInt8 {
		t.Fatalf("RssiMax should be MinInt8, got %d", s.RssiMax)
	}
	if s.LqiMin != math.MaxUint8 {
		t.Fatalf("LqiMin should be MaxUint8, got %d", s.LqiMin)
	}
	if s.LqiMax != 0 {
		t.Fatalf("LqiMax should be 0, got %d", s.LqiMax)
	}
}

func TestRxStatsAverageNoPackets(t *testing.T) {
	s := &RxStats{}
	s.Reset()
	if s.AverageRssi() != 0 {
		t.Fatalf("AverageRssi with no packets should be 0, got %d", s.AverageRssi())
	}
	if s.AverageLqi() != 0 {
		t.Fatalf("AverageLqi with no packets should be 0, got %d", s.AverageLqi())
	}
}

func TestTxStatsReset(t *testing.T) {
	s := &TxStats{PacketCount: 10, SuccessCount: 8, FailCount: 2}
	s.Reset()
	if s.PacketCount != 0 || s.SuccessCount != 0 || s.FailCount != 0 {
		t.Fatal("TxStats should be zero after reset")
	}
}

// --------------------------------------------------------------------------
// DiagState.String()
// --------------------------------------------------------------------------

func TestDiagStateString(t *testing.T) {
	tests := []struct {
		state DiagState
		want  string
	}{
		{DiagStateDisabled, "disabled"},
		{DiagStateIdle, "idle"},
		{DiagStateTransmitting, "transmitting"},
		{DiagStateReceiving, "receiving"},
		{DiagState(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("DiagState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

// --------------------------------------------------------------------------
// Stop while transmitting / receiving
// --------------------------------------------------------------------------

func TestStopWhileTransmitting(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_ = d.Start()
	_ = d.StartTransmit(TxConfig{Length: 10, Count: 0, Interval: 100})

	if err := d.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if d.IsEnabled() {
		t.Fatal("should be disabled after stop")
	}
}

func TestStopWhileReceiving(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_ = d.Start()
	_ = d.StartReceive()

	if err := d.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if d.IsEnabled() {
		t.Fatal("should be disabled after stop")
	}
	if r.receiving {
		t.Fatal("radio should not be receiving after stop")
	}
}

// --------------------------------------------------------------------------
// makePayload
// --------------------------------------------------------------------------

func TestMakePayload(t *testing.T) {
	p := makePayload(256)
	if len(p) != 256 {
		t.Fatalf("expected length 256, got %d", len(p))
	}
	for i := 0; i < 256; i++ {
		if p[i] != byte(i&0xff) {
			t.Fatalf("payload[%d] = %d, want %d", i, p[i], i&0xff)
		}
	}

	// Zero-length payload.
	p = makePayload(0)
	if len(p) != 0 {
		t.Fatalf("expected empty payload, got length %d", len(p))
	}
}

// --------------------------------------------------------------------------
// isChannelValid
// --------------------------------------------------------------------------

func TestIsChannelValid(t *testing.T) {
	for ch := uint16(0); ch <= 30; ch++ {
		got := isChannelValid(ch)
		want := ch >= 11 && ch <= 26
		if got != want {
			t.Errorf("isChannelValid(%d) = %v, want %v", ch, got, want)
		}
	}
}

// --------------------------------------------------------------------------
// ProcessCommand — comprehensive CLI tests
// --------------------------------------------------------------------------

func TestProcessCommandEmpty(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)

	out, err := d.ProcessCommand("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "disabled") {
		t.Fatalf("expected 'disabled' in output, got %q", out)
	}
}

func TestProcessCommandStart(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)

	out, err := d.ProcessCommand("start")
	if err != nil {
		t.Fatalf("start error: %v", err)
	}
	if !strings.Contains(out, "enabled") {
		t.Fatalf("expected 'enabled' in output, got %q", out)
	}
	if !d.IsEnabled() {
		t.Fatal("should be enabled after 'start'")
	}
}

func TestProcessCommandStop(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_, _ = d.ProcessCommand("start")

	out, err := d.ProcessCommand("stop")
	if err != nil {
		t.Fatalf("stop error: %v", err)
	}
	if !strings.Contains(out, "disabled") {
		t.Fatalf("expected 'disabled' in output, got %q", out)
	}
}

func TestProcessCommandChannelGet(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_, _ = d.ProcessCommand("start")

	out, err := d.ProcessCommand("channel")
	if err != nil {
		t.Fatalf("channel error: %v", err)
	}
	if out != "20" {
		t.Fatalf("expected '20', got %q", out)
	}
}

func TestProcessCommandChannelSet(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_, _ = d.ProcessCommand("start")

	out, err := d.ProcessCommand("channel 15")
	if err != nil {
		t.Fatalf("channel set error: %v", err)
	}
	if !strings.Contains(out, "15") {
		t.Fatalf("expected '15' in output, got %q", out)
	}
	if d.GetChannel() != 15 {
		t.Fatalf("channel not set to 15")
	}
}

func TestProcessCommandChannelInvalid(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_, _ = d.ProcessCommand("start")

	_, err := d.ProcessCommand("channel 5")
	if err != errors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs, got %v", err)
	}

	_, err = d.ProcessCommand("channel abc")
	if err != errors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs for non-numeric, got %v", err)
	}
}

func TestProcessCommandPowerGet(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_, _ = d.ProcessCommand("start")

	out, err := d.ProcessCommand("power")
	if err != nil {
		t.Fatalf("power error: %v", err)
	}
	if out != "0 dBm" {
		t.Fatalf("expected '0 dBm', got %q", out)
	}
}

func TestProcessCommandPowerSet(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_, _ = d.ProcessCommand("start")

	out, err := d.ProcessCommand("power -5")
	if err != nil {
		t.Fatalf("power set error: %v", err)
	}
	if !strings.Contains(out, "-5") {
		t.Fatalf("expected '-5' in output, got %q", out)
	}
	p, _ := d.GetTxPower()
	if p != -5 {
		t.Fatalf("power not set to -5")
	}
}

func TestProcessCommandPowerInvalid(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_, _ = d.ProcessCommand("start")

	_, err := d.ProcessCommand("power xyz")
	if err != errors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs, got %v", err)
	}
}

func TestProcessCommandSend(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_, _ = d.ProcessCommand("start")

	out, err := d.ProcessCommand("send 10 20")
	if err != nil {
		t.Fatalf("send error: %v", err)
	}
	if !strings.Contains(out, "10") || !strings.Contains(out, "20") {
		t.Fatalf("expected count and length in output, got %q", out)
	}
	if d.GetState() != DiagStateTransmitting {
		t.Fatal("should be transmitting after send")
	}
}

func TestProcessCommandSendMissingArgs(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_, _ = d.ProcessCommand("start")

	_, err := d.ProcessCommand("send 10")
	if err != errors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs for send with 1 arg, got %v", err)
	}

	_, err = d.ProcessCommand("send")
	if err != errors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs for send with no args, got %v", err)
	}
}

func TestProcessCommandRepeat(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_, _ = d.ProcessCommand("start")

	out, err := d.ProcessCommand("repeat 50 15")
	if err != nil {
		t.Fatalf("repeat error: %v", err)
	}
	if !strings.Contains(out, "50") || !strings.Contains(out, "15") {
		t.Fatalf("expected interval and length in output, got %q", out)
	}
	if d.GetState() != DiagStateTransmitting {
		t.Fatal("should be transmitting after repeat")
	}
}

func TestProcessCommandRepeatMissingArgs(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_, _ = d.ProcessCommand("start")

	_, err := d.ProcessCommand("repeat 50")
	if err != errors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs for repeat with 1 arg, got %v", err)
	}
}

func TestProcessCommandReceive(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_, _ = d.ProcessCommand("start")

	out, err := d.ProcessCommand("receive")
	if err != nil {
		t.Fatalf("receive error: %v", err)
	}
	if !strings.Contains(out, "receive") {
		t.Fatalf("expected 'receive' in output, got %q", out)
	}
	if d.GetState() != DiagStateReceiving {
		t.Fatal("should be receiving")
	}
}

func TestProcessCommandStats(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_, _ = d.ProcessCommand("start")

	out, err := d.ProcessCommand("stats")
	if err != nil {
		t.Fatalf("stats error: %v", err)
	}
	if !strings.Contains(out, "received packets:") {
		t.Fatalf("expected stats output, got %q", out)
	}
	if !strings.Contains(out, "sent packets:") {
		t.Fatalf("expected sent stats in output, got %q", out)
	}
}

func TestProcessCommandStatsClear(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_, _ = d.ProcessCommand("start")

	// Generate some stats.
	_ = d.StartReceive()
	d.HandleReceived(-60, 200)
	d.StopReceive()

	out, err := d.ProcessCommand("stats clear")
	if err != nil {
		t.Fatalf("stats clear error: %v", err)
	}
	if !strings.Contains(out, "cleared") {
		t.Fatalf("expected 'cleared' in output, got %q", out)
	}

	rx := d.GetRxStats()
	if rx.PacketCount != 0 {
		t.Fatal("stats should be cleared")
	}
}

func TestProcessCommandRssi(t *testing.T) {
	r := newMockRadio()
	r.rssi = -65
	d := NewDiags(r)
	_, _ = d.ProcessCommand("start")

	out, err := d.ProcessCommand("rssi")
	if err != nil {
		t.Fatalf("rssi error: %v", err)
	}
	if out != "-65 dBm" {
		t.Fatalf("expected '-65 dBm', got %q", out)
	}
}

func TestProcessCommandUnknown(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_, _ = d.ProcessCommand("start")

	_, err := d.ProcessCommand("foobar")
	if err != errors.ErrInvalidCommand {
		t.Fatalf("expected ErrInvalidCommand, got %v", err)
	}
}

func TestProcessCommandRequiresEnabled(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)

	// All these should fail when disabled.
	cmds := []string{"channel", "channel 15", "power", "power 5",
		"send 10 20", "repeat 50 15", "receive", "stats", "rssi"}
	for _, cmd := range cmds {
		_, err := d.ProcessCommand(cmd)
		if err != errors.ErrInvalidState {
			t.Fatalf("%q: expected ErrInvalidState, got %v", cmd, err)
		}
	}
}

func TestProcessCommandWhitespace(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)

	// Leading/trailing whitespace should be handled.
	out, err := d.ProcessCommand("  start  ")
	if err != nil {
		t.Fatalf("start with whitespace error: %v", err)
	}
	if !strings.Contains(out, "enabled") {
		t.Fatalf("expected 'enabled' in output, got %q", out)
	}
}

// --------------------------------------------------------------------------
// Transmit with radio error
// --------------------------------------------------------------------------

func TestStartTransmitRadioError(t *testing.T) {
	r := newMockRadio()
	r.transmitErr = errors.ErrFailed
	d := NewDiags(r)
	_ = d.Start()

	// StartTransmit should still return nil (test started, error tracked in stats).
	err := d.StartTransmit(TxConfig{Length: 10, Count: 5, Interval: 100})
	if err != nil {
		t.Fatalf("StartTransmit should succeed even with radio error, got %v", err)
	}

	stats := d.GetTxStats()
	if stats.FailCount != 1 {
		t.Fatalf("FailCount = %d, want 1", stats.FailCount)
	}
}

// --------------------------------------------------------------------------
// HandleTransmitDone when not transmitting
// --------------------------------------------------------------------------

func TestHandleTransmitDoneIgnoredWhenNotTransmitting(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_ = d.Start()

	// Not transmitting — should be a no-op.
	d.HandleTransmitDone(nil)
	stats := d.GetTxStats()
	if stats.PacketCount != 0 {
		t.Fatal("should not record packets when not transmitting")
	}
}

// --------------------------------------------------------------------------
// HandleTimer when not active
// --------------------------------------------------------------------------

func TestHandleTimerNoopWhenIdle(t *testing.T) {
	r := newMockRadio()
	d := NewDiags(r)
	_ = d.Start()

	prevTx := len(r.txPayloads)
	d.HandleTimer()
	if len(r.txPayloads) != prevTx {
		t.Fatal("HandleTimer should be a no-op when idle")
	}
}
