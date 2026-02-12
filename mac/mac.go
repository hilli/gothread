// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package mac implements the IEEE 802.15.4 MAC layer for gothread.
// It coordinates channel scanning, beacon generation, data transmission
// scheduling, and data poll management on top of the SubMac layer.
//
// This is a Go port of the Mac subsystem from OpenThread's
// src/core/mac/mac.hpp and src/core/mac/mac.cpp.
package mac

import (
	"strings"
	"sync"
	"time"

	"github.com/hilli/gothread/mac/frame"
	"github.com/hilli/gothread/mac/submac"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/radio"
)

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

const (
	// DataPollTimeout is the timeout (in ms) while waiting for data after
	// a data poll ACK with frame-pending set.
	DataPollTimeout = 100 * time.Millisecond
	// SleepDelay is the delay before entering sleep after the last
	// transmission or active scan completes.
	SleepDelay = 300 * time.Millisecond
	// ScanDurationDefault is the default per-channel scan duration in ms.
	ScanDurationDefault uint16 = 300
	// TxNumBcast is the number of times a broadcast frame is transmitted.
	TxNumBcast uint8 = 1
	// BeaconOverhead is the MAC header + payload overhead for beacon frames.
	BeaconOverhead = 22
)

// --------------------------------------------------------------------------
// Operation — MAC operations, ordered by priority (highest first)
// --------------------------------------------------------------------------

// Operation represents a MAC-layer operation.
type Operation uint16

const (
	// OperationIdle indicates no operation is active.
	OperationIdle Operation = 0
	// OperationWaitingForData keeps the radio in RX after a data-poll
	// ACK with frame-pending set.
	OperationWaitingForData Operation = 1 << 0
	// OperationActiveScan sends beacon requests and listens for beacons.
	OperationActiveScan Operation = 1 << 1
	// OperationEnergyScan measures energy on each channel.
	OperationEnergyScan Operation = 1 << 2
	// OperationTransmitBeacon transmits a beacon response.
	OperationTransmitBeacon Operation = 1 << 3
	// OperationTransmitDataIndirect transmits an indirect data frame.
	OperationTransmitDataIndirect Operation = 1 << 4
	// OperationTransmitPoll transmits a data poll.
	OperationTransmitPoll Operation = 1 << 5
	// OperationTransmitDataDirect transmits a direct data frame.
	OperationTransmitDataDirect Operation = 1 << 6
)

// operationPriority lists operations from highest to lowest priority.
var operationPriority = []Operation{
	OperationWaitingForData,
	OperationActiveScan,
	OperationEnergyScan,
	OperationTransmitBeacon,
	OperationTransmitDataIndirect,
	OperationTransmitPoll,
	OperationTransmitDataDirect,
}

// String returns the human-readable name of an Operation.
func (o Operation) String() string {
	switch o {
	case OperationIdle:
		return "Idle"
	case OperationWaitingForData:
		return "WaitingForData"
	case OperationActiveScan:
		return "ActiveScan"
	case OperationEnergyScan:
		return "EnergyScan"
	case OperationTransmitBeacon:
		return "TransmitBeacon"
	case OperationTransmitDataIndirect:
		return "TransmitDataIndirect"
	case OperationTransmitPoll:
		return "TransmitPoll"
	case OperationTransmitDataDirect:
		return "TransmitDataDirect"
	default:
		return "Unknown"
	}
}

// --------------------------------------------------------------------------
// ActiveScanResult — reported to the caller for each beacon received
// --------------------------------------------------------------------------

// ActiveScanResult contains the information extracted from a received
// beacon during an active scan.
type ActiveScanResult struct {
	// ExtAddress is the extended address of the beacon sender.
	ExtAddress types.ExtAddress
	// NetworkName is the Thread network name from the beacon payload.
	NetworkName string
	// ExtendedPanID is the Thread extended PAN ID from the beacon payload.
	ExtendedPanID [8]byte
	// PanID is the PAN ID of the beacon sender.
	PanID uint16
	// Channel is the channel on which the beacon was received.
	Channel uint8
	// RSSI is the received signal strength of the beacon.
	RSSI int8
	// LQI is the link quality indicator of the beacon.
	LQI uint8
	// IsJoinable indicates the network accepts new devices.
	IsJoinable bool
	// IsNative indicates this is a native Thread beacon.
	IsNative bool
}

// --------------------------------------------------------------------------
// Callbacks — MAC to upper layer (MeshForwarder, DataPollSender)
// --------------------------------------------------------------------------

// Callbacks defines the interface from the MAC layer to upper layers.
// In OpenThread this maps to MeshForwarder and DataPollSender.
type Callbacks interface {
	// HandleFrameRequest is called when the MAC needs a data frame
	// to transmit. The upper layer fills the provided frame buffer.
	// Returns true if a frame was prepared, false if nothing to send.
	HandleFrameRequest(frame *radio.Frame) bool
	// HandleSentFrame is called after a data frame has been sent.
	HandleSentFrame(frame *radio.Frame, err error)
	// HandleReceivedFrame is called when a data frame is received.
	HandleReceivedFrame(frame *radio.Frame)
}

// ScanHandler receives active scan results.
type ScanHandler interface {
	// HandleActiveScanResult is called for each beacon during active scan.
	// A nil result signals scan complete.
	HandleActiveScanResult(result *ActiveScanResult)
}

// EnergyScanHandler receives energy scan results.
type EnergyScanHandler interface {
	// HandleEnergyScanResult is called for each channel scanned.
	// maxRSSI is RSSIInvalid when the scan is complete.
	HandleEnergyScanResult(channel uint8, maxRSSI int8)
	// HandleEnergyScanComplete is called when the full energy scan finishes.
	HandleEnergyScanComplete()
}

// --------------------------------------------------------------------------
// Mac — the MAC layer
// --------------------------------------------------------------------------

// Mac implements the IEEE 802.15.4 MAC layer. It manages operation
// scheduling, active/energy scanning, beacon handling, and transmission
// coordination on top of the SubMac.
type Mac struct {
	mu sync.Mutex

	subMac    *submac.SubMac
	callbacks Callbacks

	// Operation scheduling
	currentOp    Operation
	pendingOps   Operation // bitmask
	operationsFn func()    // posts an operation check (like a tasklet)

	// Timer management
	timerFn   func(delay time.Duration, fn func())
	timerStop func()

	// Addresses
	shortAddress types.ShortAddress
	extAddress   types.ExtAddress
	panID        types.PanID

	// Channel
	panChannel    uint8
	radioChannel  uint8
	usingTempChan bool
	rxOnWhenIdle  bool

	// Active scan state
	scanChannelMask types.ChannelMask
	scanChannel     uint8
	scanDuration    uint16
	scanHandler     ScanHandler
	scanning        bool

	// Energy scan state
	energyScanHandler EnergyScanHandler
	energyScanning    bool

	// WaitingForData timeout
	waitingForDataTimeout time.Duration

	// Beacon payload
	networkName   string
	extendedPanID [8]byte
	joinable      bool

	// Transmit state
	transmitPending bool

	// Enabled state
	enabled bool
}

// Config holds the dependencies for creating a Mac.
type Config struct {
	// SubMac is the Sub-MAC layer instance.
	SubMac *submac.SubMac
	// Callbacks receives MAC events.
	Callbacks Callbacks
	// ScheduleTimer schedules a function to run after a delay.
	ScheduleTimer func(delay time.Duration, fn func())
	// StopTimer cancels any pending MAC timer.
	StopTimer func()
	// PostOperation posts a function to execute the next pending operation.
	// This acts like OpenThread's tasklet mechanism.
	PostOperation func(fn func())
}

// New creates a new Mac with the given configuration.
func New(config Config) *Mac {
	m := &Mac{
		subMac:                config.SubMac,
		callbacks:             config.Callbacks,
		timerFn:               config.ScheduleTimer,
		timerStop:             config.StopTimer,
		panChannel:            radio.Channel24GHzMin,
		radioChannel:          radio.Channel24GHzMin,
		waitingForDataTimeout: DataPollTimeout,
	}
	if config.PostOperation != nil {
		m.operationsFn = func() { config.PostOperation(m.performNextOperation) }
	}
	return m
}

// --------------------------------------------------------------------------
// Lifecycle
// --------------------------------------------------------------------------

// Enable enables the MAC layer and its underlying SubMac.
func (m *Mac) Enable() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.enabled {
		return nil
	}
	if err := m.subMac.Enable(); err != nil {
		return err
	}
	m.enabled = true
	m.updateIdleMode()
	return nil
}

// Disable disables the MAC layer.
func (m *Mac) Disable() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.enabled {
		return nil
	}
	m.stopTimer()
	m.pendingOps = 0
	m.currentOp = OperationIdle
	m.scanning = false
	m.energyScanning = false
	if err := m.subMac.Disable(); err != nil {
		return err
	}
	m.enabled = false
	return nil
}

// IsEnabled reports whether the MAC is enabled.
func (m *Mac) IsEnabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enabled
}

// --------------------------------------------------------------------------
// Addresses and PAN ID
// --------------------------------------------------------------------------

// GetShortAddress returns the short address.
func (m *Mac) GetShortAddress() types.ShortAddress {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.shortAddress
}

// SetShortAddress sets the short address.
func (m *Mac) SetShortAddress(addr types.ShortAddress) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shortAddress = addr
	m.subMac.SetShortAddress(addr)
}

// GetExtAddress returns the extended address.
func (m *Mac) GetExtAddress() types.ExtAddress {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.extAddress
}

// SetExtAddress sets the extended address.
func (m *Mac) SetExtAddress(addr types.ExtAddress) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.extAddress = addr
	m.subMac.SetExtAddress(addr)
}

// GetPanID returns the PAN ID.
func (m *Mac) GetPanID() types.PanID {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.panID
}

// SetPanID sets the PAN ID.
func (m *Mac) SetPanID(panID types.PanID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.panID = panID
	m.subMac.SetPanID(uint16(panID))
}

// --------------------------------------------------------------------------
// Channel management
// --------------------------------------------------------------------------

// GetPanChannel returns the Thread PAN channel.
func (m *Mac) GetPanChannel() uint8 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.panChannel
}

// SetPanChannel sets the Thread PAN channel and updates the radio channel
// if not using a temporary channel override.
func (m *Mac) SetPanChannel(channel uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.panChannel = channel
	if !m.usingTempChan {
		m.radioChannel = channel
		m.updateIdleMode()
	}
}

// GetRadioChannel returns the current radio channel.
func (m *Mac) GetRadioChannel() uint8 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.radioChannel
}

// SetTemporaryChannel overrides the radio channel temporarily, e.g.
// for joining on a different channel.
func (m *Mac) SetTemporaryChannel(channel uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.radioChannel = channel
	m.usingTempChan = true
	m.updateIdleMode()
}

// ClearTemporaryChannel reverts to the PAN channel.
func (m *Mac) ClearTemporaryChannel() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.usingTempChan = false
	m.radioChannel = m.panChannel
	m.updateIdleMode()
}

// IsUsingTemporaryChannel reports whether a temporary channel override is
// active.
func (m *Mac) IsUsingTemporaryChannel() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.usingTempChan
}

// --------------------------------------------------------------------------
// RxOnWhenIdle
// --------------------------------------------------------------------------

// GetRxOnWhenIdle reports whether the radio should be in receive mode
// when idle.
func (m *Mac) GetRxOnWhenIdle() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rxOnWhenIdle
}

// SetRxOnWhenIdle sets whether the radio should receive when idle.
func (m *Mac) SetRxOnWhenIdle(rxOnWhenIdle bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rxOnWhenIdle = rxOnWhenIdle
	m.subMac.SetRxOnWhenIdle(rxOnWhenIdle)
	m.updateIdleMode()
}

// --------------------------------------------------------------------------
// Beacon configuration
// --------------------------------------------------------------------------

// SetNetworkName sets the Thread network name for beacon payloads.
func (m *Mac) SetNetworkName(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.networkName = name
}

// GetNetworkName returns the Thread network name.
func (m *Mac) GetNetworkName() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.networkName
}

// SetExtendedPanID sets the extended PAN ID for beacon payloads.
func (m *Mac) SetExtendedPanID(extPanID [8]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.extendedPanID = extPanID
}

// GetExtendedPanID returns the extended PAN ID.
func (m *Mac) GetExtendedPanID() [8]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.extendedPanID
}

// SetJoinable sets whether the network is accepting new devices.
func (m *Mac) SetJoinable(joinable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.joinable = joinable
}

// IsJoinable reports whether the network is accepting new devices.
func (m *Mac) IsJoinable() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.joinable
}

// --------------------------------------------------------------------------
// Active scan
// --------------------------------------------------------------------------

// ActiveScan starts an active scan on the given channels for the given
// per-channel duration. The handler is called for each beacon found and
// once with nil when the scan is complete.
func (m *Mac) ActiveScan(channelMask types.ChannelMask, duration uint16, handler ScanHandler) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.scanning || m.energyScanning {
		return submac.ErrInvalidState
	}

	if duration == 0 {
		duration = ScanDurationDefault
	}

	m.scanChannelMask = channelMask
	m.scanDuration = duration
	m.scanHandler = handler
	m.scanning = true
	m.scanChannel = 0 // will be advanced in performActiveScan

	m.startOperation(OperationActiveScan)
	return nil
}

// IsActiveScanInProgress reports whether an active scan is running.
func (m *Mac) IsActiveScanInProgress() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.scanning
}

// --------------------------------------------------------------------------
// Energy scan
// --------------------------------------------------------------------------

// EnergyScan starts an energy scan on the given channels.
func (m *Mac) EnergyScan(channelMask types.ChannelMask, duration uint16, handler EnergyScanHandler) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.scanning || m.energyScanning {
		return submac.ErrInvalidState
	}

	if duration == 0 {
		duration = ScanDurationDefault
	}

	m.scanChannelMask = channelMask
	m.scanDuration = duration
	m.energyScanHandler = handler
	m.energyScanning = true
	m.scanChannel = 0

	m.startOperation(OperationEnergyScan)
	return nil
}

// IsEnergyScanInProgress reports whether an energy scan is running.
func (m *Mac) IsEnergyScanInProgress() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.energyScanning
}

// --------------------------------------------------------------------------
// Data transmission
// --------------------------------------------------------------------------

// RequestDirectFrameTransmission signals that the upper layer has a
// direct data frame to send.
func (m *Mac) RequestDirectFrameTransmission() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startOperation(OperationTransmitDataDirect)
}

// RequestDataPollTransmission signals that the upper layer wants to
// send a data poll.
func (m *Mac) RequestDataPollTransmission() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startOperation(OperationTransmitPoll)
}

// RequestBeaconTransmission signals that a beacon should be sent.
func (m *Mac) RequestBeaconTransmission() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startOperation(OperationTransmitBeacon)
}

// --------------------------------------------------------------------------
// Operation scheduling
// --------------------------------------------------------------------------

func (m *Mac) startOperation(op Operation) {
	m.pendingOps |= op
	if m.currentOp == OperationIdle && m.operationsFn != nil {
		m.operationsFn()
	}
}

func (m *Mac) finishOperation() {
	m.currentOp = OperationIdle
}

func (m *Mac) performNextOperation() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.currentOp != OperationIdle {
		return
	}
	if !m.enabled {
		return
	}

	// Select the highest-priority pending operation.
	for _, op := range operationPriority {
		if m.pendingOps&op != 0 {
			m.pendingOps &^= op
			m.currentOp = op
			m.executeOperation(op)
			return
		}
	}

	// No pending operations — go idle.
	m.updateIdleMode()
}

func (m *Mac) executeOperation(op Operation) {
	switch op {
	case OperationActiveScan:
		m.performActiveScan()
	case OperationEnergyScan:
		m.performEnergyScan()
	case OperationTransmitBeacon:
		m.performTransmitBeacon()
	case OperationTransmitDataDirect:
		m.performTransmitData()
	case OperationTransmitPoll:
		m.performTransmitPoll()
	case OperationTransmitDataIndirect:
		m.performTransmitIndirect()
	case OperationWaitingForData:
		m.performWaitingForData()
	default:
		m.finishOperation()
		m.scheduleNextOperation()
	}
}

func (m *Mac) scheduleNextOperation() {
	if m.operationsFn != nil && m.pendingOps != 0 {
		m.operationsFn()
	}
}

// --------------------------------------------------------------------------
// Active scan execution
// --------------------------------------------------------------------------

func (m *Mac) performActiveScan() {
	// Advance to the next channel in the mask.
	found := false
	for ch := m.scanChannel + 1; ch <= radio.Channel24GHzMax; ch++ {
		if m.scanChannelMask.Contains(ch) {
			m.scanChannel = ch
			found = true
			break
		}
	}

	if !found {
		// Scan complete.
		m.scanning = false
		handler := m.scanHandler
		m.scanHandler = nil
		m.finishOperation()
		if handler != nil {
			handler.HandleActiveScanResult(nil)
		}
		m.scheduleNextOperation()
		return
	}

	// Switch radio to scan channel and listen for beacons.
	_ = m.subMac.Receive(m.scanChannel)

	// Schedule timeout for this channel's scan duration.
	m.scheduleTimer(time.Duration(m.scanDuration)*time.Millisecond, func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.currentOp == OperationActiveScan && m.scanning {
			// Move to the next channel.
			m.performActiveScan()
		}
	})
}

// --------------------------------------------------------------------------
// Energy scan execution
// --------------------------------------------------------------------------

func (m *Mac) performEnergyScan() {
	// Advance to the next channel in the mask.
	found := false
	for ch := m.scanChannel + 1; ch <= radio.Channel24GHzMax; ch++ {
		if m.scanChannelMask.Contains(ch) {
			m.scanChannel = ch
			found = true
			break
		}
	}

	if !found {
		// Scan complete.
		m.energyScanning = false
		handler := m.energyScanHandler
		m.energyScanHandler = nil
		m.finishOperation()
		if handler != nil {
			handler.HandleEnergyScanComplete()
		}
		m.scheduleNextOperation()
		return
	}

	// Start energy scan on this channel via SubMac.
	if err := m.subMac.EnergyScan(m.scanChannel, m.scanDuration); err != nil {
		// Skip this channel and try the next.
		m.performEnergyScan()
	}
}

// --------------------------------------------------------------------------
// Transmit operations
// --------------------------------------------------------------------------

func (m *Mac) performTransmitBeacon() {
	// Build a minimal beacon response into the SubMac's transmit buffer.
	// In a full implementation this would construct a proper IEEE 802.15.4
	// beacon frame. For now, we signal completion.
	m.finishOperation()
	m.scheduleNextOperation()
}

func (m *Mac) performTransmitData() {
	if m.callbacks == nil {
		m.finishOperation()
		m.scheduleNextOperation()
		return
	}

	frame := m.subMac.GetTransmitFrame()
	if frame == nil {
		m.finishOperation()
		m.scheduleNextOperation()
		return
	}

	if !m.callbacks.HandleFrameRequest(frame) {
		// Nothing to send.
		m.finishOperation()
		m.scheduleNextOperation()
		return
	}

	m.transmitPending = true
	err := m.subMac.Send(submac.TxRequest{
		Channel:         m.radioChannel,
		CsmaCaEnabled:   true,
		AckRequest:      true,
		MaxCsmaBackoffs: uint8(submac.DefaultMaxCsmaBackoffsDirect),
		MaxFrameRetries: uint8(submac.DefaultMaxFrameRetriesDirect),
	})
	if err != nil {
		m.transmitPending = false
		m.callbacks.HandleSentFrame(frame, err)
		m.finishOperation()
		m.scheduleNextOperation()
	}
}

func (m *Mac) performTransmitPoll() {
	// Data poll is a MAC command frame. In a full implementation
	// the upper layer (DataPollSender) would prepare the frame.
	// For now we signal completion.
	m.finishOperation()
	m.scheduleNextOperation()
}

func (m *Mac) performTransmitIndirect() {
	// Indirect transmission (FTD only). Placeholder for now.
	m.finishOperation()
	m.scheduleNextOperation()
}

// --------------------------------------------------------------------------
// WaitingForData
// --------------------------------------------------------------------------

func (m *Mac) performWaitingForData() {
	// Stay in receive mode and set a timeout.
	_ = m.subMac.Receive(m.radioChannel)
	m.scheduleTimer(m.waitingForDataTimeout, func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.currentOp == OperationWaitingForData {
			m.finishOperation()
			m.scheduleNextOperation()
		}
	})
}

// --------------------------------------------------------------------------
// SubMac callbacks (implements submac.Callbacks)
// --------------------------------------------------------------------------

// ReceiveDone is called by the SubMac when a frame has been received.
func (m *Mac) ReceiveDone(frame *radio.Frame, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err != nil {
		return
	}

	// During active scan, received beacons are reported to the scan handler.
	if m.scanning && m.currentOp == OperationActiveScan {
		if m.scanHandler != nil {
			result := m.parseBeacon(frame)
			if result != nil {
				m.scanHandler.HandleActiveScanResult(result)
			}
		}
		return
	}

	// Normal receive — deliver to upper layer.
	if m.callbacks != nil {
		m.callbacks.HandleReceivedFrame(frame)
	}
}

// TransmitDone is called by the SubMac when a frame transmission completes.
func (m *Mac) TransmitDone(frame *radio.Frame, _ *radio.Frame, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.transmitPending {
		return
	}
	m.transmitPending = false

	if m.callbacks != nil {
		m.callbacks.HandleSentFrame(frame, err)
	}

	m.finishOperation()
	m.scheduleNextOperation()
}

// RecordFrameTransmitStatus is called after each TX attempt for stats.
func (m *Mac) RecordFrameTransmitStatus(_ *radio.Frame, _ error, _ uint8, _ bool) {
	// Statistics tracking placeholder.
}

// RecordCcaStatus is called after each CCA attempt for statistics.
func (m *Mac) RecordCcaStatus(_ bool, _ uint8) {
	// Statistics tracking placeholder.
}

// EnergyScanDone is called by the SubMac when an energy scan on a single
// channel completes.
func (m *Mac) EnergyScanDone(maxRSSI int8) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.energyScanning {
		return
	}

	// Report result for this channel.
	if m.energyScanHandler != nil {
		m.energyScanHandler.HandleEnergyScanResult(m.scanChannel, maxRSSI)
	}

	// Continue to the next channel.
	m.performEnergyScan()
}

// FrameCounterUsed is called when a frame counter is consumed.
func (m *Mac) FrameCounterUsed(_ uint32) {
	// Frame counter management placeholder.
}

// --------------------------------------------------------------------------
// GetCurrentOperation returns the current active operation (for testing).
// --------------------------------------------------------------------------

// GetCurrentOperation returns the current active MAC operation.
func (m *Mac) GetCurrentOperation() Operation {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.currentOp
}

// GetPendingOperations returns the pending operations bitmask (for testing).
func (m *Mac) GetPendingOperations() Operation {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pendingOps
}

// --------------------------------------------------------------------------
// Internal
// --------------------------------------------------------------------------

func (m *Mac) updateIdleMode() {
	if m.subMac == nil {
		return
	}
	if m.rxOnWhenIdle {
		_ = m.subMac.Receive(m.radioChannel)
	} else {
		_ = m.subMac.Sleep()
	}
}

func (m *Mac) scheduleTimer(delay time.Duration, fn func()) {
	if m.timerFn != nil {
		m.timerFn(delay, fn)
	}
}

func (m *Mac) stopTimer() {
	if m.timerStop != nil {
		m.timerStop()
	}
}

// parseBeacon extracts beacon information from a received frame.
// It parses the IEEE 802.15.4 beacon frame header and the Thread
// beacon payload to populate the ActiveScanResult fields.
//
// Thread beacon payload layout (after the 4-byte 802.15.4 beacon
// superframe/GTS/pending-address fields):
//
//	Offset  Size  Field
//	0       1     Protocol ID (must be 3 for Thread)
//	1       1     Flags: bit3=Native, bit0=Joinable
//	2       16    Network Name (null-padded UTF-8)
//	18      8     Extended PAN ID
//
// Total Thread beacon payload: 26 bytes minimum.
func (m *Mac) parseBeacon(f *radio.Frame) *ActiveScanResult {
	if f == nil || len(f.PSDU) < 4 {
		return nil
	}

	mf := frame.NewFrame(f.PSDU)
	if mf.GetType() != frame.TypeBeacon {
		return nil
	}

	result := &ActiveScanResult{
		Channel: f.Channel,
	}
	if f.RxInfo != nil {
		result.RSSI = f.RxInfo.RSSI
		result.LQI = f.RxInfo.LQI
	}

	// Extract PAN ID from the MAC header (try destination first, then source).
	if panID, err := mf.GetDstPanID(); err == nil {
		result.PanID = uint16(panID)
	} else if panID, err := mf.GetSrcPanID(); err == nil {
		result.PanID = uint16(panID)
	}

	// Extract source extended address from the MAC header.
	if srcAddr, err := mf.GetSrcAddr(); err == nil && srcAddr.IsExtended() {
		result.ExtAddress = srcAddr.GetExtended()
	}

	// Parse the MAC payload: superframe spec (2) + GTS spec (1) +
	// pending address spec (1) = 4 bytes before the Thread beacon payload.
	payload, err := mf.GetPayload()
	if err != nil || len(payload) < 4 {
		return result
	}

	threadPayload := payload[4:]
	const threadBeaconMinLen = 26 // 1 + 1 + 16 + 8
	if len(threadPayload) < threadBeaconMinLen {
		return result
	}

	// Protocol ID must be 3 for Thread.
	if threadPayload[0] != 3 {
		return result
	}

	flags := threadPayload[1]
	result.IsNative = (flags & 0x08) != 0
	result.IsJoinable = (flags & 0x01) != 0

	// Network name: 16 bytes, null-padded.
	result.NetworkName = strings.TrimRight(string(threadPayload[2:18]), "\x00")

	// Extended PAN ID: 8 bytes.
	copy(result.ExtendedPanID[:], threadPayload[18:26])

	return result
}
