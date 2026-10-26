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

	macframe "github.com/hilli/gothread/mac/frame"
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
	beaconSequence  uint8
	pollSequence    uint8
	parentShortAddr types.ShortAddress

	// Transmission counters
	txTotal    uint32
	txSuccess  uint32
	txRetry    uint32
	txNoAck    uint32
	ccaSuccess uint32
	ccaFailure uint32

	// Callbacks
	onFrameCounterUsed func(uint32)

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

// SetParentShortAddress sets the parent's short address, used for data
// poll (MAC Data Request) frames.
func (m *Mac) SetParentShortAddress(addr types.ShortAddress) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.parentShortAddr = addr
}

// GetParentShortAddress returns the parent's short address.
func (m *Mac) GetParentShortAddress() types.ShortAddress {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.parentShortAddr
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

// RequestIndirectFrameTransmission signals that the upper layer has an
// indirect data frame to send (FTD only — for sleepy children).
func (m *Mac) RequestIndirectFrameTransmission() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startOperation(OperationTransmitDataIndirect)
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
	frame := m.subMac.GetTransmitFrame()
	if frame == nil {
		m.finishOperation()
		m.scheduleNextOperation()
		return
	}

	// Build an IEEE 802.15.4 beacon frame into the transmit buffer.
	//
	// Layout:
	//   FCF (2 LE) | Seq (1) | SrcPanID (2 LE) | SrcExtAddr (8) |
	//   SuperframeSpec (2) | GTSSpec (1) | PendingAddrSpec (1) |
	//   ProtocolID (1) | Flags (1) | NetworkName (16) | ExtPanID (8) |
	//   FCS (2)
	//
	// Total: 2+1+2+8+2+1+1+1+1+16+8+2 = 45 bytes.

	var d [45]byte
	p := 0

	// Frame Control Field: Beacon(0) | SrcAddrExt(0xC000) | Version2003(0)
	// = 0xC000, little-endian.
	d[p] = 0x00
	d[p+1] = 0xC0
	p += 2

	// Sequence number.
	d[p] = m.beaconSequence
	m.beaconSequence++
	p++

	// Source PAN ID (little-endian).
	panIDVal := uint16(m.panID)
	d[p] = byte(panIDVal)
	d[p+1] = byte(panIDVal >> 8)
	p += 2

	// Source Extended Address (little-endian on wire — reversed).
	for i := 7; i >= 0; i-- {
		d[p] = m.extAddress[i]
		p++
	}

	// Superframe Specification (2 bytes) — non-PAN-coordinator values.
	d[p] = 0xFF
	d[p+1] = 0xCF
	p += 2

	// GTS Specification (1 byte) — no GTS.
	d[p] = 0x00
	p++

	// Pending Address Specification (1 byte) — none.
	d[p] = 0x00
	p++

	// Thread Beacon Payload.
	// Protocol ID = 3 (Thread).
	d[p] = 0x03
	p++

	// Flags: bit 3 = native (always true for Thread), bit 0 = joinable.
	flags := byte(0x08) // native
	if m.joinable {
		flags |= 0x01
	}
	d[p] = flags
	p++

	// Network Name (16 bytes, null-padded).
	var nameBytes [16]byte
	copy(nameBytes[:], m.networkName)
	copy(d[p:p+16], nameBytes[:])
	p += 16

	// Extended PAN ID (8 bytes).
	copy(d[p:p+8], m.extendedPanID[:])
	p += 8

	// FCS (2 bytes — placeholder, hardware/radio appends real CRC).
	d[p] = 0x00
	d[p+1] = 0x00
	p += 2

	frame.PSDU = make([]byte, p)
	copy(frame.PSDU, d[:p])
	frame.Channel = m.radioChannel

	// Beacons are broadcast — no ACK request, no retries.
	m.transmitPending = true
	err := m.subMac.Send(submac.TxRequest{
		Channel:         m.radioChannel,
		CsmaCaEnabled:   true,
		AckRequest:      false,
		MaxCsmaBackoffs: uint8(submac.DefaultMaxCsmaBackoffsDirect),
		MaxFrameRetries: 0,
	})
	if err != nil {
		m.transmitPending = false
		m.finishOperation()
		m.scheduleNextOperation()
	}
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
	// A data poll is an IEEE 802.15.4 MAC Command frame with
	// Command ID = 0x04 (Data Request), addressed to the parent.
	if m.parentShortAddr == 0 {
		// No parent set — cannot poll.
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

	// Build the MAC Command frame (Data Request).
	//
	// FCF (2 bytes LE):
	//   bits 0-2:   Frame Type    = 011 (MAC Command)
	//   bit 5:      ACK Request   = 1
	//   bit 6:      PAN ID Compr  = 1
	//   bits 10-11: Dst Addr Mode = 10 (Short)
	//   bits 14-15: Src Addr Mode = 10 (Short)
	//   Low byte  = 0x63, High byte = 0x88
	//
	// Layout: FCF(2) + Seq(1) + DstPanID(2) + DstShort(2) + SrcShort(2)
	//         + CmdID(1) + FCS(2) = 12 bytes total.
	const pollFrameLen = 12
	var d [pollFrameLen]byte

	// FCF.
	d[0] = 0x63
	d[1] = 0x88

	// Sequence number.
	d[2] = m.pollSequence
	m.pollSequence++

	// Destination PAN ID (little-endian).
	panID := uint16(m.panID)
	d[3] = byte(panID)
	d[4] = byte(panID >> 8)

	// Destination Short Address — parent (little-endian).
	parentAddr := uint16(m.parentShortAddr)
	d[5] = byte(parentAddr)
	d[6] = byte(parentAddr >> 8)

	// Source Short Address — us (little-endian).
	srcAddr := uint16(m.shortAddress)
	d[7] = byte(srcAddr)
	d[8] = byte(srcAddr >> 8)

	// MAC Command ID: Data Request = 0x04.
	d[9] = 0x04

	// FCS placeholder (2 bytes — hardware/radio appends real CRC).
	d[10] = 0x00
	d[11] = 0x00

	frame.PSDU = make([]byte, pollFrameLen)
	copy(frame.PSDU, d[:])
	frame.Channel = m.radioChannel

	// Data polls require ACK, use CSMA-CA, with direct retry parameters.
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
		if m.callbacks != nil {
			m.callbacks.HandleSentFrame(frame, err)
		}
		m.finishOperation()
		m.scheduleNextOperation()
	}
}

func (m *Mac) performTransmitIndirect() {
	// Indirect transmission (FTD only) — same flow as direct TX but
	// uses indirect CSMA backoff and retry parameters.
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
		MaxCsmaBackoffs: uint8(submac.DefaultMaxCsmaBackoffsIndirect),
		MaxFrameRetries: uint8(submac.DefaultMaxFrameRetriesIndirect),
	})
	if err != nil {
		m.transmitPending = false
		m.callbacks.HandleSentFrame(frame, err)
		m.finishOperation()
		m.scheduleNextOperation()
	}
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
func (m *Mac) TransmitDone(frame, _ *radio.Frame, err error) {
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
func (m *Mac) RecordFrameTransmitStatus(_ *radio.Frame, txErr error, retryCount uint8, willRetry bool) {
	m.txTotal++
	if txErr == nil {
		m.txSuccess++
	} else if !willRetry {
		m.txNoAck++
	}
	m.txRetry += uint32(retryCount)
}

// RecordCcaStatus is called after each CCA attempt for statistics.
func (m *Mac) RecordCcaStatus(success bool, _ uint8) {
	if success {
		m.ccaSuccess++
	} else {
		m.ccaFailure++
	}
}

// GetCounters returns the current transmission/CCA counters.
//
//nolint:gocritic // Preserve the public counter snapshot API.
func (m *Mac) GetCounters() (txTotal, txSuccess, txRetry, txNoAck, ccaSuccess, ccaFailure uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.txTotal, m.txSuccess, m.txRetry, m.txNoAck, m.ccaSuccess, m.ccaFailure
}

// ResetCounters resets all transmission/CCA counters to zero.
func (m *Mac) ResetCounters() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.txTotal = 0
	m.txSuccess = 0
	m.txRetry = 0
	m.txNoAck = 0
	m.ccaSuccess = 0
	m.ccaFailure = 0
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
func (m *Mac) FrameCounterUsed(counter uint32) {
	if m.onFrameCounterUsed != nil {
		m.onFrameCounterUsed(counter)
	}
}

// SetOnFrameCounterUsed sets a callback that is invoked whenever a
// frame counter value is consumed during transmission.
func (m *Mac) SetOnFrameCounterUsed(fn func(uint32)) {
	m.onFrameCounterUsed = fn
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

	mf := macframe.NewFrame(f.PSDU)
	if mf.GetType() != macframe.TypeBeacon {
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
