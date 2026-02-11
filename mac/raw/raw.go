// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package raw provides raw link-layer radio access for sniffer and
// packet-injection use cases. It wraps a radio.Radio and exposes
// receive, transmit, energy-scan, and address/PAN configuration.
//
// This is a Go port of the raw link-layer class in OpenThread's
// src/core/mac/link_raw.hpp and src/core/mac/link_raw.cpp.
package raw

import (
	"errors"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/radio"
)

// Error sentinels.
var (
	// ErrInvalidState indicates the LinkRaw is not in the right state for
	// the requested operation (e.g. not enabled).
	ErrInvalidState = errors.New("raw: invalid state")
	// ErrNotEnabled indicates the LinkRaw has not been enabled.
	ErrNotEnabled = errors.New("raw: not enabled")
	// ErrBusy indicates the radio is busy with another operation.
	ErrBusy = errors.New("raw: busy")
)

// Callbacks defines the interface for receiving asynchronous radio events
// when using raw link-layer access.
type Callbacks interface {
	// ReceiveDone is called when a frame has been received.
	// frame may be nil if the receive operation failed.
	ReceiveDone(frame *radio.Frame, err error)
	// TransmitDone is called when a frame transmission completes.
	// ackFrame may be nil if no ACK was received.
	TransmitDone(frame *radio.Frame, ackFrame *radio.Frame, err error)
	// EnergyScanDone is called when an energy scan completes.
	EnergyScanDone(maxRSSI int8)
}

// LinkRaw provides raw (non-Thread) access to the radio. It is used for
// sniffer applications and raw packet injection. Only one of the Thread
// MAC or LinkRaw should be active at a time.
type LinkRaw struct {
	radio   radio.Radio
	channel uint8
	panID   uint16

	enabled        bool
	transmitting   bool
	energyScanning bool
	callbacks      Callbacks

	shortAddr types.ShortAddress
	extAddr   types.ExtAddress
}

// New creates a new LinkRaw wrapping the given radio.
// The default channel is set to 11 and the PAN ID to broadcast (0xFFFF).
func New(r radio.Radio) *LinkRaw {
	return &LinkRaw{
		radio:     r,
		channel:   11,
		panID:     0xFFFF,
		shortAddr: types.ShortAddressInvalid,
	}
}

// IsEnabled reports whether raw link-layer access is enabled.
func (l *LinkRaw) IsEnabled() bool {
	return l.enabled
}

// Enable turns on the raw link-layer. The radio is enabled and put into
// receive mode on the current channel. A Callbacks implementation must be
// provided to receive asynchronous events.
func (l *LinkRaw) Enable(cb Callbacks) error {
	if l.enabled {
		return ErrInvalidState
	}
	if cb == nil {
		return ErrInvalidState
	}
	if err := l.radio.Enable(); err != nil {
		return err
	}
	l.callbacks = cb
	l.enabled = true
	return nil
}

// Disable turns off the raw link-layer and disables the radio.
func (l *LinkRaw) Disable() error {
	if !l.enabled {
		return nil
	}
	if l.transmitting || l.energyScanning {
		return ErrBusy
	}
	l.enabled = false
	l.callbacks = nil
	return l.radio.Disable()
}

// GetCaps returns the radio capability bitmask.
func (l *LinkRaw) GetCaps() radio.Caps {
	return l.radio.GetCaps()
}

// GetChannel returns the current receive channel.
func (l *LinkRaw) GetChannel() uint8 {
	return l.channel
}

// SetChannel sets the receive channel. LinkRaw must be enabled.
func (l *LinkRaw) SetChannel(channel uint8) error {
	if !l.enabled {
		return ErrNotEnabled
	}
	l.channel = channel
	return nil
}

// GetPanID returns the current PAN ID.
func (l *LinkRaw) GetPanID() uint16 {
	return l.panID
}

// SetPanID configures the PAN ID on the radio. LinkRaw must be enabled.
func (l *LinkRaw) SetPanID(panID uint16) error {
	if !l.enabled {
		return ErrNotEnabled
	}
	l.radio.SetPanID(panID)
	l.panID = panID
	return nil
}

// GetShortAddress returns the current short address.
func (l *LinkRaw) GetShortAddress() types.ShortAddress {
	return l.shortAddr
}

// SetShortAddress sets the IEEE 802.15.4 short address on the radio.
// LinkRaw must be enabled.
func (l *LinkRaw) SetShortAddress(addr types.ShortAddress) error {
	if !l.enabled {
		return ErrNotEnabled
	}
	l.radio.SetShortAddress(addr)
	l.shortAddr = addr
	return nil
}

// GetExtAddress returns the current extended address.
func (l *LinkRaw) GetExtAddress() types.ExtAddress {
	return l.extAddr
}

// SetExtAddress sets the IEEE 802.15.4 extended address on the radio.
// LinkRaw must be enabled.
func (l *LinkRaw) SetExtAddress(addr types.ExtAddress) error {
	if !l.enabled {
		return ErrNotEnabled
	}
	l.radio.SetExtendedAddress(addr)
	l.extAddr = addr
	return nil
}

// GetPromiscuous reports whether promiscuous mode is enabled.
func (l *LinkRaw) GetPromiscuous() bool {
	return l.radio.GetPromiscuous()
}

// SetPromiscuous enables or disables promiscuous mode on the radio.
func (l *LinkRaw) SetPromiscuous(enable bool) {
	l.radio.SetPromiscuous(enable)
}

// GetRSSI returns the current RSSI reading from the radio.
func (l *LinkRaw) GetRSSI() int8 {
	return l.radio.GetRSSI()
}

// Receive puts the radio into receive mode on the current channel.
// LinkRaw must be enabled.
func (l *LinkRaw) Receive() error {
	if !l.enabled {
		return ErrNotEnabled
	}
	return l.radio.Receive(l.channel)
}

// GetTransmitBuffer returns the pre-allocated transmit frame buffer from
// the radio. The caller should populate this frame before calling Transmit.
func (l *LinkRaw) GetTransmitBuffer() *radio.Frame {
	return l.radio.GetTransmitBuffer()
}

// Transmit begins transmitting the frame currently in the transmit buffer.
// LinkRaw must be enabled and the radio must be in receive state.
func (l *LinkRaw) Transmit() error {
	if !l.enabled {
		return ErrNotEnabled
	}
	if l.transmitting {
		return ErrBusy
	}
	frame := l.radio.GetTransmitBuffer()
	if err := l.radio.Transmit(frame); err != nil {
		return err
	}
	l.transmitting = true
	return nil
}

// InvokeTransmitDone should be called by the radio driver when a
// transmission completes. It clears the transmitting flag and invokes the
// registered callback.
func (l *LinkRaw) InvokeTransmitDone(frame *radio.Frame, ackFrame *radio.Frame, err error) {
	l.transmitting = false
	if l.callbacks != nil {
		l.callbacks.TransmitDone(frame, ackFrame, err)
	}
}

// InvokeReceiveDone should be called by the radio driver when a frame is
// received. It invokes the registered callback if enabled and no error.
func (l *LinkRaw) InvokeReceiveDone(frame *radio.Frame, err error) {
	if l.callbacks != nil && err == nil {
		l.callbacks.ReceiveDone(frame, err)
	}
}

// EnergyScan starts an energy scan on the given channel for the specified
// duration in milliseconds. LinkRaw must be enabled.
func (l *LinkRaw) EnergyScan(channel uint8, durationMs uint16) error {
	if !l.enabled {
		return ErrNotEnabled
	}
	if l.energyScanning {
		return ErrBusy
	}
	if err := l.radio.EnergyScan(channel, durationMs); err != nil {
		return err
	}
	l.energyScanning = true
	return nil
}

// InvokeEnergyScanDone should be called by the radio driver when an
// energy scan completes. It clears the scanning flag and invokes the
// registered callback.
func (l *LinkRaw) InvokeEnergyScanDone(maxRSSI int8) {
	l.energyScanning = false
	if l.enabled && l.callbacks != nil {
		l.callbacks.EnergyScanDone(maxRSSI)
	}
}

// SetMacKey sets the MAC encryption keys for the given key ID mode.
// LinkRaw must be enabled.
func (l *LinkRaw) SetMacKey(keyIDMode, keyID uint8, prevKey, currKey, nextKey types.KeyMaterial) error {
	if !l.enabled {
		return ErrNotEnabled
	}
	l.radio.SetMacKey(keyIDMode, keyID, prevKey, currKey, nextKey)
	return nil
}

// SetMacFrameCounter sets the MAC frame counter value.
// If setIfLarger is true, the counter is only updated if the new value
// is larger than the current one.
// LinkRaw must be enabled.
func (l *LinkRaw) SetMacFrameCounter(counter uint32, setIfLarger bool) error {
	if !l.enabled {
		return ErrNotEnabled
	}
	if setIfLarger {
		l.radio.SetMacFrameCounterIfLarger(counter)
	} else {
		l.radio.SetMacFrameCounter(counter)
	}
	return nil
}

// IsTransmitting reports whether a transmission is currently in progress.
func (l *LinkRaw) IsTransmitting() bool {
	return l.transmitting
}

// IsEnergyScanning reports whether an energy scan is currently in progress.
func (l *LinkRaw) IsEnergyScanning() bool {
	return l.energyScanning
}
