// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package radio defines the radio hardware abstraction interface used by
// gothread. A concrete platform must implement the Radio interface to provide
// IEEE 802.15.4 radio access.
//
// This is a Go port of the radio interface declared in OpenThread's
// include/openthread/platform/radio.h and src/core/radio/radio.hpp.
package radio

import "github.com/hilli/gothread/mac/types"

// --------------------------------------------------------------------------
// State — radio state machine
// --------------------------------------------------------------------------

// State represents the current radio state.
type State uint8

const (
	// StateDisabled indicates the radio is off.
	StateDisabled State = 0
	// StateSleep indicates the radio is in low-power sleep.
	StateSleep State = 1
	// StateReceive indicates the radio is actively receiving.
	StateReceive State = 2
	// StateTransmit indicates the radio is actively transmitting.
	StateTransmit State = 3
)

// String returns the human-readable name of a radio State.
func (s State) String() string {
	switch s {
	case StateDisabled:
		return "Disabled"
	case StateSleep:
		return "Sleep"
	case StateReceive:
		return "Receive"
	case StateTransmit:
		return "Transmit"
	default:
		return "Unknown"
	}
}

// --------------------------------------------------------------------------
// Caps — radio capabilities bitmask
// --------------------------------------------------------------------------

// Caps is a bitmask of radio capabilities.
type Caps uint16

const (
	// CapNone indicates no special capabilities.
	CapNone Caps = 0
	// CapAckTimeout indicates the radio handles ACK timeout internally.
	CapAckTimeout Caps = 1 << 0
	// CapEnergyScan indicates the radio supports hardware energy scanning.
	CapEnergyScan Caps = 1 << 1
	// CapTransmitRetries indicates the radio handles TX retries with CSMA-CA.
	CapTransmitRetries Caps = 1 << 2
	// CapCsmaBackoff indicates the radio handles CSMA backoff internally.
	CapCsmaBackoff Caps = 1 << 3
	// CapSleepToTx indicates the radio can transmit directly from sleep.
	CapSleepToTx Caps = 1 << 4
	// CapTransmitSec indicates the radio handles TX security (encryption).
	CapTransmitSec Caps = 1 << 5
	// CapTransmitTiming indicates the radio supports scheduled transmission.
	CapTransmitTiming Caps = 1 << 6
	// CapReceiveTiming indicates the radio supports scheduled reception.
	CapReceiveTiming Caps = 1 << 7
	// CapRxOnWhenIdle indicates the radio auto-manages sleep/receive.
	CapRxOnWhenIdle Caps = 1 << 8
	// CapTransmitFramePower indicates the radio supports per-frame TX power.
	CapTransmitFramePower Caps = 1 << 9
	// CapAltShortAddr indicates the radio supports alternate short addresses.
	CapAltShortAddr Caps = 1 << 10
)

// Has reports whether the Caps bitmask contains the given capability.
func (c Caps) Has(capability Caps) bool {
	return c&capability == capability
}

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

const (
	// FrameMaxSize is the maximum IEEE 802.15.4 PSDU length in bytes.
	FrameMaxSize = 127
	// FrameMinSize is the minimum IEEE 802.15.4 frame size (FCF + seq).
	FrameMinSize = 3
	// FrameFCSSize is the Frame Check Sequence length in bytes.
	FrameFCSSize = 2

	// RSSIInvalid is the sentinel value for an invalid/unknown RSSI reading.
	RSSIInvalid int8 = 127
	// PowerInvalid is the sentinel value indicating "use default TX power".
	PowerInvalid int8 = 127

	// Channel24GHzMin is the lowest IEEE 802.15.4 channel in the 2.4 GHz band.
	Channel24GHzMin uint8 = 11
	// Channel24GHzMax is the highest IEEE 802.15.4 channel in the 2.4 GHz band.
	Channel24GHzMax uint8 = 26
	// Channel915MHzMin is the lowest IEEE 802.15.4 channel in the 915 MHz band.
	Channel915MHzMin uint8 = 1
	// Channel915MHzMax is the highest IEEE 802.15.4 channel in the 915 MHz band.
	Channel915MHzMax uint8 = 10
)

// --------------------------------------------------------------------------
// Frame — radio frame (PSDU + metadata)
// --------------------------------------------------------------------------

// TxInfo contains metadata for a frame to be transmitted.
type TxInfo struct {
	// MaxCsmaBackoffs is the maximum number of CSMA-CA backoffs.
	MaxCsmaBackoffs uint8
	// MaxFrameRetries is the maximum number of frame transmission retries.
	MaxFrameRetries uint8
	// RxChannelAfterTx is the channel to receive on after transmission.
	RxChannelAfterTx uint8
	// TxPower is the transmit power in dBm (PowerInvalid = use default).
	TxPower int8
	// Timestamp is the radio clock time in microseconds.
	Timestamp uint64
	// CsmaCaEnabled indicates whether CSMA-CA is enabled.
	CsmaCaEnabled bool
	// IsHeaderUpdated indicates whether the header has been updated by radio.
	IsHeaderUpdated bool
	// IsARetx indicates whether this is a retransmission.
	IsARetx bool
	// IsSecurityProcessed indicates whether security has been applied.
	IsSecurityProcessed bool
	// CslPresent indicates whether CSL IEs are present.
	CslPresent bool
}

// RxInfo contains metadata for a received frame.
type RxInfo struct {
	// Timestamp is the radio clock time in microseconds when frame was received.
	Timestamp uint64
	// AckFrameCounter is the frame counter from the received ACK.
	AckFrameCounter uint32
	// AckKeyID is the key ID from the received ACK.
	AckKeyID uint8
	// RSSI is the received signal strength in dBm.
	RSSI int8
	// LQI is the link quality indicator.
	LQI uint8
	// AckedWithFramePending indicates the ACK had the frame-pending bit set.
	AckedWithFramePending bool
	// AckedWithSecEnhAck indicates the ACK used security (enhanced ACK).
	AckedWithSecEnhAck bool
}

// Frame represents an IEEE 802.15.4 radio frame with PHY-layer metadata.
type Frame struct {
	// PSDU is the PHY Service Data Unit (frame payload, max 127 bytes).
	PSDU []byte
	// Channel is the IEEE 802.15.4 channel number.
	Channel uint8
	// RadioType identifies the radio type (for multi-radio platforms).
	RadioType uint8
	// TxInfo contains transmit metadata (non-nil for frames being sent).
	TxInfo *TxInfo
	// RxInfo contains receive metadata (non-nil for received frames).
	RxInfo *RxInfo
}

// --------------------------------------------------------------------------
// Radio — the core radio interface
// --------------------------------------------------------------------------

// Radio defines the platform radio hardware abstraction. A concrete
// platform implementation must satisfy this interface to provide IEEE
// 802.15.4 radio access to the Thread stack.
type Radio interface {
	// --- Lifecycle ---

	// Enable turns on the radio.
	Enable() error
	// Disable turns off the radio.
	Disable() error
	// IsEnabled reports whether the radio is enabled.
	IsEnabled() bool
	// GetState returns the current radio state.
	GetState() State

	// --- State transitions ---

	// Sleep puts the radio into low-power sleep mode.
	Sleep() error
	// Receive puts the radio into receive mode on the given channel.
	Receive(channel uint8) error
	// Transmit begins transmitting the given frame.
	Transmit(frame *Frame) error
	// GetTransmitBuffer returns the pre-allocated transmit frame buffer.
	GetTransmitBuffer() *Frame

	// --- Configuration ---

	// GetCaps returns the radio capability bitmask.
	GetCaps() Caps
	// GetIEEEEui64 returns the factory-assigned IEEE EUI-64 identifier in
	// canonical byte order (most significant byte first), like types.ExtAddress.
	GetIEEEEui64() [8]byte
	// SetPanID sets the IEEE 802.15.4 PAN ID for frame filtering.
	SetPanID(panID uint16)
	// SetExtendedAddress sets the IEEE 802.15.4 extended address in canonical
	// byte order. The driver handles any hardware-specific byte reversal.
	SetExtendedAddress(addr types.ExtAddress)
	// SetShortAddress sets the IEEE 802.15.4 short address.
	SetShortAddress(addr types.ShortAddress)
	// GetTransmitPower returns the current transmit power in dBm.
	GetTransmitPower() (int8, error)
	// SetTransmitPower sets the transmit power in dBm.
	SetTransmitPower(power int8) error
	// GetPromiscuous reports whether promiscuous mode is enabled.
	GetPromiscuous() bool
	// SetPromiscuous enables or disables promiscuous mode.
	SetPromiscuous(enable bool)
	// GetRSSI returns the current RSSI reading in dBm.
	GetRSSI() int8
	// GetSupportedChannelMask returns a bitmask of supported channels.
	GetSupportedChannelMask() uint32
	// GetPreferredChannelMask returns a bitmask of preferred channels.
	GetPreferredChannelMask() uint32
	// GetReceiveSensitivity returns the radio receive sensitivity in dBm.
	GetReceiveSensitivity() int8

	// --- Source address match (frame-pending bit in ACKs) ---

	// EnableSrcMatch enables or disables source address matching.
	EnableSrcMatch(enable bool)
	// AddSrcMatchShortEntry adds a short address to the source match table.
	AddSrcMatchShortEntry(addr types.ShortAddress) error
	// AddSrcMatchExtEntry adds an extended address to the source match table.
	AddSrcMatchExtEntry(addr types.ExtAddress) error
	// ClearSrcMatchShortEntry removes a short address from the source match table.
	ClearSrcMatchShortEntry(addr types.ShortAddress) error
	// ClearSrcMatchExtEntry removes an extended address from the source match table.
	ClearSrcMatchExtEntry(addr types.ExtAddress) error
	// ClearSrcMatchShortEntries removes all short addresses from the source match table.
	ClearSrcMatchShortEntries()
	// ClearSrcMatchExtEntries removes all extended addresses from the source match table.
	ClearSrcMatchExtEntries()

	// --- Security ---

	// SetMacKey sets the MAC encryption keys for the given key ID mode.
	SetMacKey(keyIDMode uint8, keyID uint8, prevKey, currKey, nextKey types.KeyMaterial)
	// SetMacFrameCounter sets the MAC frame counter.
	SetMacFrameCounter(counter uint32)
	// SetMacFrameCounterIfLarger sets the MAC frame counter only if the
	// new value is larger than the current value.
	SetMacFrameCounterIfLarger(counter uint32)

	// --- Energy scan ---

	// EnergyScan starts an energy scan on the given channel for the
	// specified duration in milliseconds.
	EnergyScan(channel uint8, duration uint16) error
}

// --------------------------------------------------------------------------
// Callbacks — radio-to-stack callbacks
// --------------------------------------------------------------------------

// Callbacks defines the callbacks from the radio driver back into the
// Thread stack. The stack implements this interface; the radio driver calls
// these methods to deliver events.
type Callbacks interface {
	// HandleReceiveDone is called when a frame has been received.
	HandleReceiveDone(frame *Frame, err error)
	// HandleTransmitStarted is called when transmission of a frame begins.
	HandleTransmitStarted(frame *Frame)
	// HandleTransmitDone is called when transmission completes.
	HandleTransmitDone(frame *Frame, ackFrame *Frame, err error)
	// HandleEnergyScanDone is called when an energy scan completes.
	HandleEnergyScanDone(maxRSSI int8)
}
