// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package submac implements the IEEE 802.15.4 Sub-MAC layer for gothread.
// It provides software CSMA-CA backoff, frame retransmissions, ACK timeout,
// and energy scanning when the radio platform does not natively support
// these features.
//
// This is a Go port of the SubMac subsystem from OpenThread's
// src/core/mac/sub_mac.hpp and src/core/mac/sub_mac.cpp.
package submac

import (
	"math/rand/v2"
	"time"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/radio"
)

// --------------------------------------------------------------------------
// Constants — IEEE 802.15.4 MAC parameters
// --------------------------------------------------------------------------

const (
	// CsmaMinBE is macMinBE per IEEE 802.15.4-2006.
	CsmaMinBE = 3
	// CsmaMaxBE is macMaxBE per IEEE 802.15.4-2006.
	CsmaMaxBE = 5
	// UnitBackoffPeriod is the number of symbols per unit backoff period.
	UnitBackoffPeriod = 20
	// SymbolTimeUs is the duration of one symbol in microseconds (2.4 GHz).
	SymbolTimeUs = 16
	// AckTimeoutUs is the timeout for receiving an ACK in microseconds.
	AckTimeoutUs = 16_000
	// EnergyScanSampleIntervalUs is the RSSI sample interval during
	// software energy scanning in microseconds.
	EnergyScanSampleIntervalUs = 1_000

	// DefaultMaxCsmaBackoffsDirect is the default max CSMA-CA backoffs
	// for direct transmissions.
	DefaultMaxCsmaBackoffsDirect uint8 = 4
	// DefaultMaxCsmaBackoffsIndirect is the default max CSMA-CA backoffs
	// for indirect transmissions.
	DefaultMaxCsmaBackoffsIndirect uint8 = 4

	// DefaultMaxFrameRetriesDirect is the default max frame retries for
	// direct transmissions.
	DefaultMaxFrameRetriesDirect uint8 = 15
	// DefaultMaxFrameRetriesIndirect is the default max frame retries for
	// indirect transmissions.
	DefaultMaxFrameRetriesIndirect uint8 = 0
)

// --------------------------------------------------------------------------
// State — SubMac state machine
// --------------------------------------------------------------------------

// State represents the SubMac state machine state.
type State uint8

const (
	// StateDisabled indicates the radio is disabled.
	StateDisabled State = iota
	// StateSleep indicates the radio is sleeping.
	StateSleep
	// StateReceive indicates the radio is receiving.
	StateReceive
	// StateCsmaBackoff indicates a CSMA-CA backoff is in progress.
	StateCsmaBackoff
	// StateTransmit indicates the radio is transmitting.
	StateTransmit
	// StateEnergyScan indicates an energy scan is in progress.
	StateEnergyScan
)

// String returns the human-readable name of a SubMac State.
func (s State) String() string {
	switch s {
	case StateDisabled:
		return "Disabled"
	case StateSleep:
		return "Sleep"
	case StateReceive:
		return "Receive"
	case StateCsmaBackoff:
		return "CsmaBackoff"
	case StateTransmit:
		return "Transmit"
	case StateEnergyScan:
		return "EnergyScan"
	default:
		return "Unknown"
	}
}

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

// Error codes returned by SubMac operations.
var (
	// ErrInvalidState is returned when an operation is not valid in the
	// current state.
	ErrInvalidState = &subMacError{msg: "submac: invalid state"}
	// ErrChannelAccessFailure is returned when CCA fails (channel busy).
	ErrChannelAccessFailure = &subMacError{msg: "submac: channel access failure"}
	// ErrNoAck is returned when an ACK is not received within the timeout.
	ErrNoAck = &subMacError{msg: "submac: no ack"}
	// ErrAbort is returned when a transmission is aborted.
	ErrAbort = &subMacError{msg: "submac: abort"}
)

type subMacError struct {
	msg string
}

func (e *subMacError) Error() string {
	return e.msg
}

// --------------------------------------------------------------------------
// Callbacks — SubMac to upper MAC layer
// --------------------------------------------------------------------------

// Callbacks defines the interface from SubMac back to the upper MAC layer.
type Callbacks interface {
	// ReceiveDone is called when a frame has been received.
	ReceiveDone(frame *radio.Frame, err error)
	// TransmitDone is called when transmission of a frame completes
	// (after all CSMA retries and frame retries are exhausted or success).
	TransmitDone(frame, ackFrame *radio.Frame, err error)
	// RecordFrameTransmitStatus is called after each transmission attempt
	// (before retry decisions) for statistics.
	RecordFrameTransmitStatus(frame *radio.Frame, err error, retryCount uint8, willRetx bool)
	// RecordCcaStatus is called after each CCA attempt for statistics.
	RecordCcaStatus(ccaSuccess bool, channel uint8)
	// EnergyScanDone is called when an energy scan completes.
	EnergyScanDone(maxRSSI int8)
	// FrameCounterUsed is called when a frame counter is consumed.
	FrameCounterUsed(counter uint32)
}

// --------------------------------------------------------------------------
// TxRequest — per-frame transmission parameters
// --------------------------------------------------------------------------

// TxRequest holds the per-frame transmission parameters that the upper
// MAC sets before calling Send.
type TxRequest struct {
	// MaxCsmaBackoffs is the maximum number of CSMA-CA backoff attempts.
	MaxCsmaBackoffs uint8
	// MaxFrameRetries is the maximum number of frame retransmission attempts.
	MaxFrameRetries uint8
	// CsmaCaEnabled indicates whether CSMA-CA should be used.
	CsmaCaEnabled bool
	// AckRequest indicates whether an ACK is expected.
	AckRequest bool
	// Channel is the channel to transmit on.
	Channel uint8
}

// --------------------------------------------------------------------------
// SubMac — the Sub-MAC layer
// --------------------------------------------------------------------------

// SubMac implements the IEEE 802.15.4 Sub-MAC layer. It manages CSMA-CA
// backoff, frame retransmissions, ACK timeout, and energy scanning,
// providing software fallbacks when the radio does not support these
// features natively.
type SubMac struct {
	radio     radio.Radio
	callbacks Callbacks

	state State

	// Addresses
	shortAddress types.ShortAddress
	extAddress   types.ExtAddress

	// Radio capabilities (cached)
	radioCaps radio.Caps

	// CSMA-CA state
	csmaBackoffs uint8

	// Frame retry state
	transmitRetries uint8

	// Energy scan state
	energyScanMaxRSSI int8
	energyScanEndTime time.Time
	energyScanChannel uint8

	// Transmit state
	txRequest TxRequest
	txFrame   *radio.Frame

	// Configuration
	rxOnWhenIdle bool

	// MAC keys
	prevKey types.KeyMaterial
	currKey types.KeyMaterial
	nextKey types.KeyMaterial
	keyID   uint8

	// Frame counter
	frameCounter uint32

	// Timer management — the SubMac uses a single timer for:
	// CSMA backoff delay, ACK timeout, and energy scan sampling.
	timerFn   func(delay time.Duration, fn func())
	timerStop func()
}

// Config holds the dependencies for creating a SubMac.
type Config struct {
	// Radio is the platform radio interface.
	Radio radio.Radio
	// Callbacks receives SubMac events.
	Callbacks Callbacks
	// ScheduleTimer schedules a function to run after a delay.
	// The returned function cancels the timer.
	ScheduleTimer func(delay time.Duration, fn func())
	// StopTimer cancels any pending timer.
	StopTimer func()
}

// New creates a new SubMac with the given configuration.
func New(config Config) *SubMac {
	sm := &SubMac{
		radio:     config.Radio,
		callbacks: config.Callbacks,
		state:     StateDisabled,
		timerFn:   config.ScheduleTimer,
		timerStop: config.StopTimer,
	}
	if sm.radio != nil {
		sm.radioCaps = sm.radio.GetCaps()
		sm.txFrame = sm.radio.GetTransmitBuffer()
	}
	return sm
}

// --------------------------------------------------------------------------
// Lifecycle
// --------------------------------------------------------------------------

// Enable enables the radio and transitions to Sleep state.
func (sm *SubMac) Enable() error {
	if sm.radio == nil {
		return ErrInvalidState
	}
	if err := sm.radio.Enable(); err != nil {
		return err
	}
	if err := sm.radio.Sleep(); err != nil {
		return err
	}
	sm.state = StateSleep
	return nil
}

// Disable disables the radio and transitions to Disabled state.
func (sm *SubMac) Disable() error {
	sm.stopTimer()
	if sm.radio != nil {
		_ = sm.radio.Sleep()
		_ = sm.radio.Disable()
	}
	sm.state = StateDisabled
	return nil
}

// GetState returns the current SubMac state.
func (sm *SubMac) GetState() State {
	return sm.state
}

// --------------------------------------------------------------------------
// State transitions
// --------------------------------------------------------------------------

// Sleep transitions the radio to sleep mode.
func (sm *SubMac) Sleep() error {
	if sm.state == StateDisabled {
		return ErrInvalidState
	}
	if err := sm.radio.Sleep(); err != nil {
		return err
	}
	sm.state = StateSleep
	return nil
}

// Receive transitions the radio to receive mode on the given channel.
func (sm *SubMac) Receive(channel uint8) error {
	if sm.state == StateDisabled {
		return ErrInvalidState
	}
	if err := sm.radio.Receive(channel); err != nil {
		return err
	}
	sm.state = StateReceive
	return nil
}

// IsTransmittingOrScanning reports whether the SubMac is currently
// transmitting or performing an energy scan.
func (sm *SubMac) IsTransmittingOrScanning() bool {
	switch sm.state {
	case StateCsmaBackoff, StateTransmit, StateEnergyScan:
		return true
	default:
		return false
	}
}

// --------------------------------------------------------------------------
// Transmit
// --------------------------------------------------------------------------

// GetTransmitFrame returns the radio's pre-allocated transmit frame buffer.
func (sm *SubMac) GetTransmitFrame() *radio.Frame {
	return sm.txFrame
}

// Send starts the transmission process for the current transmit frame
// with the given parameters. It propagates the request channel and CSMA flag
// to the radio frame without replacing any other transmit metadata.
func (sm *SubMac) Send(req TxRequest) error {
	switch sm.state {
	case StateReceive, StateSleep:
		// OK
	default:
		return ErrInvalidState
	}
	if sm.txFrame == nil {
		return ErrInvalidState
	}

	sm.txRequest = req
	sm.txFrame.Channel = req.Channel
	if sm.txFrame.TxInfo == nil {
		sm.txFrame.TxInfo = &radio.TxInfo{}
	}
	sm.txFrame.TxInfo.CsmaCaEnabled = req.CsmaCaEnabled
	sm.csmaBackoffs = 0
	sm.transmitRetries = 0
	sm.startCsmaBackoff()
	return nil
}

// GetTransmitRetries returns the number of retries used for the last
// transmission.
func (sm *SubMac) GetTransmitRetries() uint8 {
	return sm.transmitRetries
}

// --------------------------------------------------------------------------
// Energy scan
// --------------------------------------------------------------------------

// EnergyScan starts an energy scan on the given channel for the specified
// duration in milliseconds. If the radio rejects the start, the prior state,
// timer, and scan bookkeeping are unchanged.
func (sm *SubMac) EnergyScan(channel uint8, durationMs uint16) error {
	switch sm.state {
	case StateReceive, StateSleep:
		// OK
	default:
		return ErrInvalidState
	}

	// If the radio supports hardware energy scan, delegate.
	hardwareScan := sm.radioCaps.Has(radio.CapEnergyScan)
	if hardwareScan {
		if err := sm.radio.EnergyScan(channel, durationMs); err != nil {
			return err
		}
	} else if err := sm.radio.Receive(channel); err != nil {
		return err
	}

	sm.state = StateEnergyScan
	sm.energyScanChannel = channel
	if hardwareScan {
		return nil
	}

	// Software energy scan.
	sm.energyScanMaxRSSI = radio.RSSIInvalid
	sm.energyScanEndTime = time.Now().Add(time.Duration(durationMs) * time.Millisecond)
	sm.scheduleTimer(0, sm.sampleRSSI)
	return nil
}

// --------------------------------------------------------------------------
// Configuration
// --------------------------------------------------------------------------

// SetPanID sets the radio PAN ID for frame filtering.
func (sm *SubMac) SetPanID(panID uint16) {
	if sm.radio != nil {
		sm.radio.SetPanID(panID)
	}
}

// GetShortAddress returns the short address.
func (sm *SubMac) GetShortAddress() types.ShortAddress {
	return sm.shortAddress
}

// SetShortAddress sets the short address on the radio.
func (sm *SubMac) SetShortAddress(addr types.ShortAddress) {
	sm.shortAddress = addr
	if sm.radio != nil {
		sm.radio.SetShortAddress(addr)
	}
}

// GetExtAddress returns the extended address.
func (sm *SubMac) GetExtAddress() types.ExtAddress {
	return sm.extAddress
}

// SetExtAddress sets the extended address on the radio.
func (sm *SubMac) SetExtAddress(addr types.ExtAddress) {
	sm.extAddress = addr
	if sm.radio != nil {
		sm.radio.SetExtendedAddress(addr)
	}
}

// SetRxOnWhenIdle sets whether the radio should receive when idle.
func (sm *SubMac) SetRxOnWhenIdle(rxOnWhenIdle bool) {
	sm.rxOnWhenIdle = rxOnWhenIdle
}

// GetRSSI returns the current RSSI reading from the radio.
func (sm *SubMac) GetRSSI() int8 {
	if sm.radio == nil {
		return radio.RSSIInvalid
	}
	return sm.radio.GetRSSI()
}

// GetNoiseFloor returns the radio receive sensitivity (noise floor).
func (sm *SubMac) GetNoiseFloor() int8 {
	if sm.radio == nil {
		return radio.RSSIInvalid
	}
	return sm.radio.GetReceiveSensitivity()
}

// --------------------------------------------------------------------------
// MAC security
// --------------------------------------------------------------------------

// SetMacKey sets the MAC encryption keys.
func (sm *SubMac) SetMacKey(keyIDMode, keyID uint8, prevKey, currKey, nextKey types.KeyMaterial) {
	sm.keyID = keyID
	sm.prevKey = prevKey
	sm.currKey = currKey
	sm.nextKey = nextKey

	if sm.radioCaps.Has(radio.CapTransmitSec) && sm.radio != nil {
		sm.radio.SetMacKey(keyIDMode, keyID, prevKey, currKey, nextKey)
	}
}

// GetFrameCounter returns the current MAC frame counter.
func (sm *SubMac) GetFrameCounter() uint32 {
	return sm.frameCounter
}

// SetFrameCounter sets the MAC frame counter.
func (sm *SubMac) SetFrameCounter(counter uint32, setIfLarger bool) {
	if setIfLarger && counter <= sm.frameCounter {
		return
	}
	sm.frameCounter = counter

	if sm.radioCaps.Has(radio.CapTransmitSec) && sm.radio != nil {
		if setIfLarger {
			sm.radio.SetMacFrameCounterIfLarger(counter)
		} else {
			sm.radio.SetMacFrameCounter(counter)
		}
	}
}

// --------------------------------------------------------------------------
// Radio callbacks — called by the platform radio driver
// --------------------------------------------------------------------------

// HandleReceiveDone is called by the radio when a frame is received.
func (sm *SubMac) HandleReceiveDone(frame *radio.Frame, err error) {
	if sm.callbacks != nil {
		sm.callbacks.ReceiveDone(frame, err)
	}
}

// HandleTransmitStarted is called by the radio when transmission begins.
func (sm *SubMac) HandleTransmitStarted(_ *radio.Frame) {
	if sm.state != StateTransmit {
		return
	}
	// Start ACK timeout if needed.
	if sm.txRequest.AckRequest && sm.shouldHandleAckTimeout() {
		sm.scheduleTimer(time.Duration(AckTimeoutUs)*time.Microsecond, sm.handleAckTimeout)
	}
}

// HandleTransmitDone is called by the radio when transmission completes.
func (sm *SubMac) HandleTransmitDone(frame, ackFrame *radio.Frame, err error) {
	if sm.state != StateTransmit {
		return // A late completion must not retry/revive a disabled transmitter.
	}
	sm.stopTimer()
	sm.handleTransmitResult(frame, ackFrame, err)
}

// HandleEnergyScanDone is called by the radio when a hardware energy
// scan completes.
func (sm *SubMac) HandleEnergyScanDone(maxRSSI int8) {
	sm.state = StateReceive
	if sm.callbacks != nil {
		sm.callbacks.EnergyScanDone(maxRSSI)
	}
}

// --------------------------------------------------------------------------
// Internal — CSMA-CA
// --------------------------------------------------------------------------

func (sm *SubMac) startCsmaBackoff() {
	sm.state = StateCsmaBackoff

	if !sm.txRequest.CsmaCaEnabled || !sm.shouldHandleCsmaBackoff() {
		// No software CSMA — transmit immediately.
		sm.beginTransmit()
		return
	}

	// Calculate backoff delay.
	be := CsmaMinBE + int(sm.csmaBackoffs)
	if be > CsmaMaxBE {
		be = CsmaMaxBE
	}
	maxBackoff := uint32(1) << be
	randomBackoff := rand.Uint32N(maxBackoff)
	delayUs := time.Duration(randomBackoff) * UnitBackoffPeriod * SymbolTimeUs * time.Microsecond

	// During backoff: receive if rxOnWhenIdle, otherwise sleep.
	if sm.rxOnWhenIdle {
		_ = sm.radio.Receive(sm.txRequest.Channel)
	} else {
		_ = sm.radio.Sleep()
	}

	sm.scheduleTimer(delayUs, sm.beginTransmit)
}

func (sm *SubMac) beginTransmit() {
	sm.state = StateTransmit

	// Ensure radio is in receive before transmit (if radio doesn't
	// support sleep-to-tx).
	if !sm.radioCaps.Has(radio.CapSleepToTx) {
		_ = sm.radio.Receive(sm.txRequest.Channel)
	}

	if err := sm.radio.Transmit(sm.txFrame); err != nil {
		// Transmit failed immediately — report as channel access failure.
		sm.handleTransmitResult(sm.txFrame, nil, ErrChannelAccessFailure)
	}
}

func (sm *SubMac) handleTransmitResult(frame, ackFrame *radio.Frame, err error) {
	willRetx := false

	// Record CCA status.
	if sm.callbacks != nil {
		sm.callbacks.RecordCcaStatus(err != ErrChannelAccessFailure, sm.txRequest.Channel)
	}

	// Channel access failure: retry CSMA if possible.
	if err == ErrChannelAccessFailure && sm.shouldHandleCsmaBackoff() {
		if sm.csmaBackoffs < sm.txRequest.MaxCsmaBackoffs {
			sm.csmaBackoffs++
			willRetx = true
			sm.recordStatus(frame, err, willRetx)
			sm.startCsmaBackoff()
			return
		}
	}

	// Frame retry on any error.
	if err != nil && sm.shouldHandleRetries() {
		if sm.transmitRetries < sm.txRequest.MaxFrameRetries {
			sm.transmitRetries++
			willRetx = true
			sm.recordStatus(frame, err, willRetx)
			// Reset CSMA backoffs for the retry.
			sm.csmaBackoffs = 0
			sm.startCsmaBackoff()
			return
		}
	}

	// Final result — no more retries.
	sm.recordStatus(frame, err, false)
	sm.state = StateReceive
	_ = sm.radio.Receive(sm.txRequest.Channel)

	if sm.callbacks != nil {
		sm.callbacks.TransmitDone(frame, ackFrame, err)
	}
}

func (sm *SubMac) recordStatus(frame *radio.Frame, err error, willRetx bool) {
	if sm.callbacks != nil {
		sm.callbacks.RecordFrameTransmitStatus(frame, err, sm.transmitRetries, willRetx)
	}
}

// --------------------------------------------------------------------------
// Internal — ACK timeout
// --------------------------------------------------------------------------

func (sm *SubMac) handleAckTimeout() {
	if sm.state != StateTransmit {
		return
	}
	// Switch radio back to receive and report no-ack.
	_ = sm.radio.Receive(sm.txRequest.Channel)
	sm.handleTransmitResult(sm.txFrame, nil, ErrNoAck)
}

// --------------------------------------------------------------------------
// Internal — energy scan (software)
// --------------------------------------------------------------------------

func (sm *SubMac) sampleRSSI() {
	if sm.state != StateEnergyScan {
		return
	}

	rssi := sm.radio.GetRSSI()
	if sm.energyScanMaxRSSI == radio.RSSIInvalid || rssi > sm.energyScanMaxRSSI {
		sm.energyScanMaxRSSI = rssi
	}

	if time.Now().Before(sm.energyScanEndTime) {
		sm.scheduleTimer(
			time.Duration(EnergyScanSampleIntervalUs)*time.Microsecond,
			sm.sampleRSSI,
		)
	} else {
		sm.state = StateReceive
		if sm.callbacks != nil {
			sm.callbacks.EnergyScanDone(sm.energyScanMaxRSSI)
		}
	}
}

// --------------------------------------------------------------------------
// Internal — capability checks
// --------------------------------------------------------------------------

func (sm *SubMac) shouldHandleCsmaBackoff() bool {
	// Handle CSMA in software if the radio doesn't support it natively.
	return !sm.radioCaps.Has(radio.CapCsmaBackoff) && !sm.radioCaps.Has(radio.CapTransmitRetries)
}

func (sm *SubMac) shouldHandleRetries() bool {
	return !sm.radioCaps.Has(radio.CapTransmitRetries)
}

func (sm *SubMac) shouldHandleAckTimeout() bool {
	return !sm.radioCaps.Has(radio.CapAckTimeout)
}

// --------------------------------------------------------------------------
// Internal — timer helpers
// --------------------------------------------------------------------------

func (sm *SubMac) scheduleTimer(delay time.Duration, fn func()) {
	if sm.timerFn != nil {
		sm.timerFn(delay, fn)
	}
}

func (sm *SubMac) stopTimer() {
	if sm.timerStop != nil {
		sm.timerStop()
	}
}
