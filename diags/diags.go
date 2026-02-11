// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package diags implements factory diagnostics for direct radio hardware
// testing. When enabled, the diagnostics module takes exclusive control
// of the radio for TX/RX testing.
//
// This is a Go port of OpenThread's factory diagnostics module declared in
// openthread/src/core/diags/factory_diags.hpp and factory_diags.cpp.
package diags

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/hilli/gothread/errors"
)

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

const (
	// channelMin is the lowest valid IEEE 802.15.4 channel (2.4 GHz band).
	channelMin uint16 = 11
	// channelMax is the highest valid IEEE 802.15.4 channel (2.4 GHz band).
	channelMax uint16 = 26
	// defaultChannel is the initial channel at startup.
	defaultChannel uint16 = 20
	// defaultTxInterval is the default interval between TX packets in ms.
	defaultTxInterval uint32 = 100
)

// --------------------------------------------------------------------------
// RadioControl — interface for direct radio access during diagnostics
// --------------------------------------------------------------------------

// RadioControl provides direct radio control for diagnostics. A concrete
// platform must implement this interface to support factory diagnostics.
type RadioControl interface {
	SetChannel(channel uint16) error
	GetChannel() uint16
	SetTxPower(power int8) error
	GetTxPower() (int8, error)
	Transmit(payload []byte) error
	StartReceive() error
	StopReceive() error
	GetRssi() (int8, error)
	Sleep() error
	Enable() error
	Disable() error
}

// --------------------------------------------------------------------------
// DiagState — diagnostic mode state machine
// --------------------------------------------------------------------------

// DiagState represents the current diagnostic mode state.
type DiagState uint8

const (
	// DiagStateDisabled means diagnostics mode is off.
	DiagStateDisabled DiagState = iota
	// DiagStateIdle means diagnostics mode is on but no test is running.
	DiagStateIdle
	// DiagStateTransmitting means a transmit test is in progress.
	DiagStateTransmitting
	// DiagStateReceiving means a receive test is in progress.
	DiagStateReceiving
)

// String returns a human-readable name for the state.
func (s DiagState) String() string {
	switch s {
	case DiagStateDisabled:
		return "disabled"
	case DiagStateIdle:
		return "idle"
	case DiagStateTransmitting:
		return "transmitting"
	case DiagStateReceiving:
		return "receiving"
	default:
		return "unknown"
	}
}

// --------------------------------------------------------------------------
// TxConfig — transmit test configuration
// --------------------------------------------------------------------------

// TxConfig holds transmission test configuration.
type TxConfig struct {
	// Length is the packet length in bytes.
	Length uint16
	// Count is the number of packets to send (0 = continuous).
	Count uint32
	// Interval is the interval between packets in milliseconds.
	Interval uint32
}

// --------------------------------------------------------------------------
// RxStats — receive test statistics
// --------------------------------------------------------------------------

// RxStats holds receive test statistics.
type RxStats struct {
	PacketCount uint32
	RssiSum     int64
	RssiMin     int8
	RssiMax     int8
	LqiSum      uint32
	LqiMin      uint8
	LqiMax      uint8
}

// AverageRssi returns the average RSSI across all received packets.
// Returns 0 if no packets have been received.
func (s *RxStats) AverageRssi() int8 {
	if s.PacketCount == 0 {
		return 0
	}
	return int8(s.RssiSum / int64(s.PacketCount))
}

// AverageLqi returns the average LQI across all received packets.
// Returns 0 if no packets have been received.
func (s *RxStats) AverageLqi() uint8 {
	if s.PacketCount == 0 {
		return 0
	}
	return uint8(s.LqiSum / uint32(s.PacketCount))
}

// Reset clears all receive statistics.
func (s *RxStats) Reset() {
	*s = RxStats{
		RssiMin: math.MaxInt8,
		RssiMax: math.MinInt8,
		LqiMin:  math.MaxUint8,
	}
}

// --------------------------------------------------------------------------
// TxStats — transmit test statistics
// --------------------------------------------------------------------------

// TxStats holds transmit test statistics.
type TxStats struct {
	PacketCount  uint32
	SuccessCount uint32
	FailCount    uint32
}

// Reset clears all transmit statistics.
func (s *TxStats) Reset() {
	*s = TxStats{}
}

// --------------------------------------------------------------------------
// Diags — factory diagnostics module
// --------------------------------------------------------------------------

// Diags provides factory diagnostic functionality for testing radio hardware.
type Diags struct {
	radio    RadioControl
	state    DiagState
	channel  uint16
	txPower  int8
	txConfig TxConfig
	rxStats  RxStats
	txStats  TxStats
	txActive bool
	txCount  uint32 // packets sent so far in current test
}

// NewDiags creates a new diagnostics module using the given radio control.
func NewDiags(radio RadioControl) *Diags {
	d := &Diags{
		radio:   radio,
		state:   DiagStateDisabled,
		channel: defaultChannel,
	}
	d.rxStats.Reset()
	return d
}

// --------------------------------------------------------------------------
// Mode control
// --------------------------------------------------------------------------

// Start enters factory diagnostic mode, configuring the radio for direct
// testing. Returns ErrInvalidState if already enabled.
func (d *Diags) Start() error {
	if d.state != DiagStateDisabled {
		return errors.ErrInvalidState
	}
	if err := d.radio.Enable(); err != nil {
		return err
	}
	if err := d.radio.SetChannel(d.channel); err != nil {
		return err
	}
	if err := d.radio.SetTxPower(d.txPower); err != nil {
		return err
	}
	d.state = DiagStateIdle
	d.rxStats.Reset()
	d.txStats.Reset()
	return nil
}

// Stop exits factory diagnostic mode. Returns ErrInvalidState if not enabled.
func (d *Diags) Stop() error {
	if d.state == DiagStateDisabled {
		return errors.ErrInvalidState
	}
	if d.state == DiagStateTransmitting {
		d.StopTransmit()
	}
	if d.state == DiagStateReceiving {
		d.StopReceive()
	}
	if err := d.radio.Disable(); err != nil {
		return err
	}
	d.state = DiagStateDisabled
	return nil
}

// IsEnabled returns whether diagnostic mode is active.
func (d *Diags) IsEnabled() bool {
	return d.state != DiagStateDisabled
}

// GetState returns the current diagnostic state.
func (d *Diags) GetState() DiagState {
	return d.state
}

// --------------------------------------------------------------------------
// Channel commands
// --------------------------------------------------------------------------

// isChannelValid reports whether a channel number is in the valid
// IEEE 802.15.4 2.4 GHz range (11-26).
func isChannelValid(channel uint16) bool {
	return channel >= channelMin && channel <= channelMax
}

// SetChannel sets the radio channel. Returns ErrInvalidArgs for an invalid
// channel, or ErrInvalidState if diagnostics mode is not active.
func (d *Diags) SetChannel(channel uint16) error {
	if d.state == DiagStateDisabled {
		return errors.ErrInvalidState
	}
	if !isChannelValid(channel) {
		return errors.ErrInvalidArgs
	}
	d.channel = channel
	return d.radio.SetChannel(channel)
}

// GetChannel returns the current channel.
func (d *Diags) GetChannel() uint16 {
	return d.channel
}

// --------------------------------------------------------------------------
// Power commands
// --------------------------------------------------------------------------

// SetTxPower sets the transmit power. Returns ErrInvalidState if diagnostics
// mode is not active.
func (d *Diags) SetTxPower(power int8) error {
	if d.state == DiagStateDisabled {
		return errors.ErrInvalidState
	}
	d.txPower = power
	return d.radio.SetTxPower(power)
}

// GetTxPower returns the current transmit power. Returns ErrInvalidState if
// diagnostics mode is not active.
func (d *Diags) GetTxPower() (int8, error) {
	if d.state == DiagStateDisabled {
		return 0, errors.ErrInvalidState
	}
	return d.txPower, nil
}

// --------------------------------------------------------------------------
// Transmit test
// --------------------------------------------------------------------------

// StartTransmit begins a transmit test with the given configuration.
// Returns ErrInvalidState if not idle, ErrInvalidArgs if config is invalid.
func (d *Diags) StartTransmit(config TxConfig) error {
	if d.state != DiagStateIdle {
		return errors.ErrInvalidState
	}
	if config.Length == 0 {
		return errors.ErrInvalidArgs
	}
	if config.Interval == 0 {
		return errors.ErrInvalidArgs
	}
	d.txConfig = config
	d.txCount = 0
	d.txActive = true
	d.state = DiagStateTransmitting

	// Send first packet.
	payload := makePayload(config.Length)
	if err := d.radio.Transmit(payload); err != nil {
		d.txStats.PacketCount++
		d.txStats.FailCount++
		// Even on error, we started the test. Return nil to indicate
		// the test has begun; the error is tracked in stats.
	}
	return nil
}

// StopTransmit stops an active transmit test.
func (d *Diags) StopTransmit() {
	if d.state != DiagStateTransmitting {
		return
	}
	d.txActive = false
	d.state = DiagStateIdle
}

// HandleTransmitDone is called by the radio driver when a transmission
// completes. It updates statistics and schedules the next transmission.
func (d *Diags) HandleTransmitDone(err error) {
	if d.state != DiagStateTransmitting {
		return
	}
	d.txStats.PacketCount++
	if err != nil {
		d.txStats.FailCount++
	} else {
		d.txStats.SuccessCount++
	}
	d.txCount++

	// Check if we are done (non-continuous mode).
	if d.txConfig.Count > 0 && d.txCount >= d.txConfig.Count {
		d.StopTransmit()
	}
}

// HandleTimer is called on the transmit interval timer. It sends the next
// packet if the transmit test is still active.
func (d *Diags) HandleTimer() {
	if d.state != DiagStateTransmitting || !d.txActive {
		return
	}
	// Check if we are done (non-continuous mode).
	if d.txConfig.Count > 0 && d.txCount >= d.txConfig.Count {
		d.StopTransmit()
		return
	}

	payload := makePayload(d.txConfig.Length)
	if err := d.radio.Transmit(payload); err != nil {
		d.txStats.PacketCount++
		d.txStats.FailCount++
	}
}

// GetTxStats returns the current transmit test statistics.
func (d *Diags) GetTxStats() TxStats {
	return d.txStats
}

// makePayload creates a test payload of the given length with sequential
// byte values (matching OpenThread's pattern).
func makePayload(length uint16) []byte {
	buf := make([]byte, length)
	for i := range buf {
		buf[i] = byte(i & 0xff)
	}
	return buf
}

// --------------------------------------------------------------------------
// Receive test
// --------------------------------------------------------------------------

// StartReceive begins a receive test. Returns ErrInvalidState if not idle.
func (d *Diags) StartReceive() error {
	if d.state != DiagStateIdle {
		return errors.ErrInvalidState
	}
	if err := d.radio.StartReceive(); err != nil {
		return err
	}
	d.state = DiagStateReceiving
	return nil
}

// StopReceive stops an active receive test.
func (d *Diags) StopReceive() {
	if d.state != DiagStateReceiving {
		return
	}
	_ = d.radio.StopReceive()
	d.state = DiagStateIdle
}

// HandleReceived is called by the radio driver when a frame is received
// during a receive test. It updates receive statistics.
func (d *Diags) HandleReceived(rssi int8, lqi uint8) {
	if d.state != DiagStateReceiving {
		return
	}
	d.rxStats.PacketCount++
	d.rxStats.RssiSum += int64(rssi)
	if rssi < d.rxStats.RssiMin {
		d.rxStats.RssiMin = rssi
	}
	if rssi > d.rxStats.RssiMax {
		d.rxStats.RssiMax = rssi
	}
	d.rxStats.LqiSum += uint32(lqi)
	if lqi < d.rxStats.LqiMin {
		d.rxStats.LqiMin = lqi
	}
	if lqi > d.rxStats.LqiMax {
		d.rxStats.LqiMax = lqi
	}
}

// GetRxStats returns the current receive test statistics.
func (d *Diags) GetRxStats() RxStats {
	return d.rxStats
}

// --------------------------------------------------------------------------
// RSSI query
// --------------------------------------------------------------------------

// GetRssi reads the current RSSI from the radio. Returns ErrInvalidState
// if diagnostics mode is not active.
func (d *Diags) GetRssi() (int8, error) {
	if d.state == DiagStateDisabled {
		return 0, errors.ErrInvalidState
	}
	return d.radio.GetRssi()
}

// --------------------------------------------------------------------------
// ProcessCommand — CLI command dispatcher
// --------------------------------------------------------------------------

// ProcessCommand handles a diagnostic CLI command string and returns output.
//
// Supported commands:
//
//	"start"                   -> Start()
//	"stop"                    -> Stop()
//	"channel"                 -> GetChannel()
//	"channel <n>"             -> SetChannel(n)
//	"power"                   -> GetTxPower()
//	"power <n>"               -> SetTxPower(n)
//	"send <count> <length>"   -> StartTransmit({Length: length, Count: count, Interval: 100})
//	"repeat <interval> <len>" -> StartTransmit({Length: len, Count: 0, Interval: interval})
//	"receive"                 -> StartReceive()
//	"stats"                   -> GetRxStats() + GetTxStats()
//	"stats clear"             -> Reset stats
//	"rssi"                    -> GetRssi()
func (d *Diags) ProcessCommand(command string) (string, error) {
	args := strings.Fields(strings.TrimSpace(command))
	if len(args) == 0 {
		return fmt.Sprintf("diagnostics mode is %s", d.GetState()), nil
	}

	cmd := args[0]
	rest := args[1:]

	// "start" does not require diagnostics to be enabled.
	if cmd == "start" {
		return d.cmdStart(rest)
	}

	// All other commands (except checking state) require diag mode.
	if !d.IsEnabled() && cmd != "stop" {
		return "", errors.ErrInvalidState
	}

	switch cmd {
	case "stop":
		return d.cmdStop(rest)
	case "channel":
		return d.cmdChannel(rest)
	case "power":
		return d.cmdPower(rest)
	case "send":
		return d.cmdSend(rest)
	case "repeat":
		return d.cmdRepeat(rest)
	case "receive":
		return d.cmdReceive(rest)
	case "stats":
		return d.cmdStats(rest)
	case "rssi":
		return d.cmdRssi(rest)
	default:
		return "", errors.ErrInvalidCommand
	}
}

func (d *Diags) cmdStart(_ []string) (string, error) {
	if err := d.Start(); err != nil {
		return "", err
	}
	return "diagnostics mode is enabled", nil
}

func (d *Diags) cmdStop(_ []string) (string, error) {
	if err := d.Stop(); err != nil {
		return "", err
	}
	return "diagnostics mode is disabled", nil
}

func (d *Diags) cmdChannel(args []string) (string, error) {
	if len(args) == 0 {
		return fmt.Sprintf("%d", d.GetChannel()), nil
	}
	ch, err := strconv.ParseUint(args[0], 10, 16)
	if err != nil {
		return "", errors.ErrInvalidArgs
	}
	if err := d.SetChannel(uint16(ch)); err != nil {
		return "", err
	}
	return "set channel to " + args[0], nil
}

func (d *Diags) cmdPower(args []string) (string, error) {
	if len(args) == 0 {
		p, err := d.GetTxPower()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d dBm", p), nil
	}
	p, err := strconv.ParseInt(args[0], 10, 8)
	if err != nil {
		return "", errors.ErrInvalidArgs
	}
	if err := d.SetTxPower(int8(p)); err != nil {
		return "", err
	}
	return "set tx power to " + args[0] + " dBm", nil
}

func (d *Diags) cmdSend(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.ErrInvalidArgs
	}
	count, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return "", errors.ErrInvalidArgs
	}
	length, err := strconv.ParseUint(args[1], 10, 16)
	if err != nil {
		return "", errors.ErrInvalidArgs
	}
	config := TxConfig{
		Length:   uint16(length),
		Count:    uint32(count),
		Interval: defaultTxInterval,
	}
	if err := d.StartTransmit(config); err != nil {
		return "", err
	}
	return fmt.Sprintf("sending %d packets of length %d", count, length), nil
}

func (d *Diags) cmdRepeat(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.ErrInvalidArgs
	}
	interval, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return "", errors.ErrInvalidArgs
	}
	length, err := strconv.ParseUint(args[1], 10, 16)
	if err != nil {
		return "", errors.ErrInvalidArgs
	}
	config := TxConfig{
		Length:   uint16(length),
		Count:    0, // continuous
		Interval: uint32(interval),
	}
	if err := d.StartTransmit(config); err != nil {
		return "", err
	}
	return fmt.Sprintf("sending packets of length %d every %d ms", length, interval), nil
}

func (d *Diags) cmdReceive(_ []string) (string, error) {
	if err := d.StartReceive(); err != nil {
		return "", err
	}
	return "receive mode enabled", nil
}

func (d *Diags) cmdStats(args []string) (string, error) {
	if len(args) > 0 && args[0] == "clear" {
		d.rxStats.Reset()
		d.txStats.Reset()
		return "stats cleared", nil
	}
	rx := d.GetRxStats()
	tx := d.GetTxStats()
	return fmt.Sprintf(
		"received packets: %d\n"+
			"rx average rssi: %d\n"+
			"sent packets: %d\n"+
			"sent success: %d\n"+
			"sent fail: %d",
		rx.PacketCount,
		rx.AverageRssi(),
		tx.PacketCount,
		tx.SuccessCount,
		tx.FailCount,
	), nil
}

func (d *Diags) cmdRssi(_ []string) (string, error) {
	rssi, err := d.GetRssi()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d dBm", rssi), nil
}
