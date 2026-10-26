// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package ble provides a simplified BLE secure transport abstraction.
//
// This is a Go port of the BLE secure transport from OpenThread's
// src/core/radio/ble_secure.hpp / ble_secure.cpp, adapted to a simpler
// state-machine API without the full TLS/TCAT coupling.
package ble

import (
	"sync"

	"github.com/hilli/gothread/errors"
)

// State represents the BLE secure transport state.
type State uint8

const (
	// StateDisabled indicates the BLE transport is off.
	StateDisabled State = iota
	// StateIdle indicates the BLE transport is enabled but not connected.
	StateIdle
	// StateConnecting indicates a connection is being established.
	StateConnecting
	// StateConnected indicates an active BLE connection.
	StateConnected
)

// String returns the human-readable name of a BLE State.
func (s State) String() string {
	switch s {
	case StateDisabled:
		return "Disabled"
	case StateIdle:
		return "Idle"
	case StateConnecting:
		return "Connecting"
	case StateConnected:
		return "Connected"
	default:
		return "Unknown"
	}
}

// ReceiveCallback is called when data is received over the BLE connection.
type ReceiveCallback func(data []byte)

// ConnectionCallback is called when the connection state changes.
type ConnectionCallback func(connected bool)

// Platform defines the platform-level BLE operations that a concrete
// implementation must provide.
type Platform interface {
	// BleEnable enables the BLE hardware.
	BleEnable() error
	// BleDisable disables the BLE hardware.
	BleDisable() error
	// GapConnect initiates a connection to the given peer address.
	GapConnect(peerAddr []byte) error
	// GapDisconnect terminates the current connection.
	GapDisconnect() error
	// BleSend sends data over the active BLE connection.
	BleSend(data []byte) error
}

// BleSecure provides a BLE secure transport with connection state management.
//
//nolint:revive // Retain the exported type name for source compatibility.
type BleSecure struct {
	mu        sync.Mutex
	platform  Platform
	state     State
	receiveCb ReceiveCallback
	connectCb ConnectionCallback
}

// NewBleSecure creates a new BleSecure instance backed by the given platform.
func NewBleSecure(platform Platform) *BleSecure {
	return &BleSecure{
		platform: platform,
		state:    StateDisabled,
	}
}

// Enable enables the BLE transport.
func (b *BleSecure) Enable() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != StateDisabled {
		return errors.ErrAlready
	}
	if err := b.platform.BleEnable(); err != nil {
		return err
	}
	b.state = StateIdle
	return nil
}

// Disable disables the BLE transport, disconnecting if necessary.
func (b *BleSecure) Disable() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == StateDisabled {
		return errors.ErrAlready
	}
	if b.state == StateConnected || b.state == StateConnecting {
		_ = b.platform.GapDisconnect()
	}
	if err := b.platform.BleDisable(); err != nil {
		return err
	}
	b.state = StateDisabled
	b.receiveCb = nil
	b.connectCb = nil
	return nil
}

// IsEnabled reports whether the BLE transport is enabled.
func (b *BleSecure) IsEnabled() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state != StateDisabled
}

// Connect initiates a BLE connection to the given peer address.
func (b *BleSecure) Connect(peerAddr []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != StateIdle {
		return errors.ErrInvalidState
	}
	if err := b.platform.GapConnect(peerAddr); err != nil {
		return err
	}
	b.state = StateConnecting
	return nil
}

// Disconnect terminates the current BLE connection.
func (b *BleSecure) Disconnect() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != StateConnected && b.state != StateConnecting {
		return errors.ErrInvalidState
	}
	if err := b.platform.GapDisconnect(); err != nil {
		return err
	}
	b.state = StateIdle
	if b.connectCb != nil {
		b.connectCb(false)
	}
	return nil
}

// IsConnected reports whether a BLE connection is active.
func (b *BleSecure) IsConnected() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state == StateConnected
}

// Send transmits data over the active BLE connection.
func (b *BleSecure) Send(data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != StateConnected {
		return errors.ErrInvalidState
	}
	return b.platform.BleSend(data)
}

// SetReceiveCallback sets the callback invoked when data is received.
func (b *BleSecure) SetReceiveCallback(cb ReceiveCallback) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.receiveCb = cb
}

// SetConnectionCallback sets the callback invoked on connection state changes.
func (b *BleSecure) SetConnectionCallback(cb ConnectionCallback) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.connectCb = cb
}

// GetState returns the current BLE transport state.
func (b *BleSecure) GetState() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// HandleConnected should be called by the platform when a connection is
// established. It transitions the state and invokes the connection callback.
func (b *BleSecure) HandleConnected() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != StateConnecting {
		return
	}
	b.state = StateConnected
	if b.connectCb != nil {
		b.connectCb(true)
	}
}

// HandleDisconnected should be called by the platform when a connection is
// lost. It transitions the state and invokes the connection callback.
func (b *BleSecure) HandleDisconnected() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != StateConnected && b.state != StateConnecting {
		return
	}
	b.state = StateIdle
	if b.connectCb != nil {
		b.connectCb(false)
	}
}

// HandleReceive should be called by the platform when data is received.
// It invokes the receive callback if one is set.
func (b *BleSecure) HandleReceive(data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.receiveCb != nil {
		b.receiveCb(data)
	}
}
