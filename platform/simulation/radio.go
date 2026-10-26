// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package simulation

import (
	"sync"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/radio"
)

// Compile-time interface check.
var _ radio.Radio = (*SimRadio)(nil)

// SimRadio implements radio.Radio as a simulation stub with state tracking.
type SimRadio struct {
	mu          sync.Mutex
	enabled     bool
	channel     uint8
	panID       uint16
	shortAddr   types.ShortAddress
	extAddr     types.ExtAddress
	txPower     int8
	txBuf       radio.Frame
	state       radio.State
	promiscuous bool
	srcMatch    bool
	eui64       [8]byte

	macFrameCounter uint32

	medium *Medium
	rxChan chan *radio.Frame
	rxCb   func(*radio.Frame)
}

// NewSimRadio creates a new SimRadio in the disabled state.
func NewSimRadio() *SimRadio {
	return &SimRadio{
		eui64:   [8]byte{0x18, 0xb4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x01},
		txPower: 0,
		channel: radio.Channel24GHzMin,
		rxChan:  make(chan *radio.Frame, 64),
	}
}

// Enable turns on the radio.
func (r *SimRadio) Enable() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = true
	r.state = radio.StateSleep
	return nil
}

// Disable turns off the radio.
func (r *SimRadio) Disable() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = false
	r.state = radio.StateDisabled
	return nil
}

// IsEnabled reports whether the radio is enabled.
func (r *SimRadio) IsEnabled() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.enabled
}

// GetState returns the current radio state.
func (r *SimRadio) GetState() radio.State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

// Sleep puts the radio into low-power sleep mode.
func (r *SimRadio) Sleep() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state = radio.StateSleep
	return nil
}

// Receive puts the radio into receive mode on the given channel.
func (r *SimRadio) Receive(channel uint8) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.channel = channel
	r.state = radio.StateReceive
	return nil
}

// Transmit begins transmitting the given frame.
func (r *SimRadio) Transmit(frame *radio.Frame) error {
	r.mu.Lock()
	r.state = radio.StateTransmit
	m := r.medium
	r.mu.Unlock()
	if m != nil {
		m.Broadcast(r, frame)
	}
	return nil
}

// GetTransmitBuffer returns the pre-allocated transmit frame buffer.
func (r *SimRadio) GetTransmitBuffer() *radio.Frame {
	return &r.txBuf
}

// GetCaps returns the radio capability bitmask.
func (r *SimRadio) GetCaps() radio.Caps {
	return radio.CapNone
}

// GetIEEEEui64 returns the factory-assigned IEEE EUI-64 identifier.
func (r *SimRadio) GetIEEEEui64() [8]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.eui64
}

// SetPanID sets the IEEE 802.15.4 PAN ID for frame filtering.
func (r *SimRadio) SetPanID(panID uint16) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.panID = panID
}

// SetExtendedAddress sets the IEEE 802.15.4 extended address.
func (r *SimRadio) SetExtendedAddress(addr types.ExtAddress) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.extAddr = addr
}

// SetShortAddress sets the IEEE 802.15.4 short address.
func (r *SimRadio) SetShortAddress(addr types.ShortAddress) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.shortAddr = addr
}

// GetTransmitPower returns the current transmit power in dBm.
func (r *SimRadio) GetTransmitPower() (int8, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.txPower, nil
}

// SetTransmitPower sets the transmit power in dBm.
func (r *SimRadio) SetTransmitPower(power int8) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.txPower = power
	return nil
}

// GetPromiscuous reports whether promiscuous mode is enabled.
func (r *SimRadio) GetPromiscuous() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.promiscuous
}

// SetPromiscuous enables or disables promiscuous mode.
func (r *SimRadio) SetPromiscuous(enable bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.promiscuous = enable
}

// GetRSSI returns the current RSSI reading in dBm.
func (r *SimRadio) GetRSSI() int8 {
	return -50
}

// GetSupportedChannelMask returns a bitmask of supported channels.
func (r *SimRadio) GetSupportedChannelMask() uint32 {
	return 0x07FFF800 // channels 11–26
}

// GetPreferredChannelMask returns a bitmask of preferred channels.
func (r *SimRadio) GetPreferredChannelMask() uint32 {
	return 0x07FFF800
}

// GetReceiveSensitivity returns the radio receive sensitivity in dBm.
func (r *SimRadio) GetReceiveSensitivity() int8 {
	return -100
}

// EnableSrcMatch enables or disables source address matching.
func (r *SimRadio) EnableSrcMatch(enable bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.srcMatch = enable
}

// AddSrcMatchShortEntry adds a short address to the source match table.
func (r *SimRadio) AddSrcMatchShortEntry(addr types.ShortAddress) error { return nil }

// AddSrcMatchExtEntry adds an extended address to the source match table.
func (r *SimRadio) AddSrcMatchExtEntry(addr types.ExtAddress) error { return nil }

// ClearSrcMatchShortEntry removes a short address from the source match table.
func (r *SimRadio) ClearSrcMatchShortEntry(addr types.ShortAddress) error {
	return nil
}

// ClearSrcMatchExtEntry removes an extended address from the source match table.
func (r *SimRadio) ClearSrcMatchExtEntry(addr types.ExtAddress) error { return nil }

// ClearSrcMatchShortEntries removes all short addresses from the source match table.
func (r *SimRadio) ClearSrcMatchShortEntries() {}

// ClearSrcMatchExtEntries removes all extended addresses from the source match table.
func (r *SimRadio) ClearSrcMatchExtEntries() {}

// SetMacKey sets the MAC encryption keys for the given key ID mode.
func (r *SimRadio) SetMacKey(keyIDMode, keyID uint8, prevKey, currKey, nextKey types.KeyMaterial) {
}

// SetMacFrameCounter sets the MAC frame counter.
func (r *SimRadio) SetMacFrameCounter(counter uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.macFrameCounter = counter
}

// SetMacFrameCounterIfLarger sets the MAC frame counter only if the
// new value is larger than the current value.
func (r *SimRadio) SetMacFrameCounterIfLarger(counter uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if counter > r.macFrameCounter {
		r.macFrameCounter = counter
	}
}

// EnergyScan starts an energy scan on the given channel for the
// specified duration in milliseconds.
func (r *SimRadio) EnergyScan(channel uint8, duration uint16) error {
	return nil
}

// SetMedium connects or disconnects this radio from a shared medium.
func (r *SimRadio) SetMedium(m *Medium) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.medium = m
}

// DeliverFrame pushes a received frame into the radio's receive buffer.
// Called by the Medium; non-blocking (drops if buffer full).
func (r *SimRadio) DeliverFrame(frame *radio.Frame) {
	select {
	case r.rxChan <- frame:
	default:
	}
	r.mu.Lock()
	cb := r.rxCb
	r.mu.Unlock()
	if cb != nil {
		cb(frame)
	}
}

// ReceiveFrame returns the next received frame, or nil if none is available.
func (r *SimRadio) ReceiveFrame() *radio.Frame {
	select {
	case f := <-r.rxChan:
		return f
	default:
		return nil
	}
}

// SetReceiveCallback registers a function called when a frame is delivered.
func (r *SimRadio) SetReceiveCallback(cb func(*radio.Frame)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rxCb = cb
}
