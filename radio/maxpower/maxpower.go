// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package maxpower provides a per-channel maximum transmit power table for
// IEEE 802.15.4 radios in the 2.4 GHz band (channels 11–26).
//
// This is a Go port of OpenThread's src/core/radio/max_power_table.hpp.
package maxpower

import "github.com/hilli/gothread/radio"

// Constants for the max power table.
const (
	// MinChannel is the lowest channel in the 2.4 GHz band.
	MinChannel = radio.Channel24GHzMin
	// MaxChannel is the highest channel in the 2.4 GHz band.
	MaxChannel = radio.Channel24GHzMax
	// NumChannels is the number of channels in the 2.4 GHz band.
	NumChannels = int(MaxChannel-MinChannel) + 1
	// DefaultPower is the default maximum transmit power in dBm.
	DefaultPower int8 = 30
)

// Table holds the per-channel maximum transmit power values.
type Table struct {
	powers [NumChannels]int8
}

// New creates a new Table with all channels set to DefaultPower.
func New() *Table {
	t := &Table{}
	t.Clear()
	return t
}

// Clear resets all channel powers to DefaultPower.
func (t *Table) Clear() {
	for i := range t.powers {
		t.powers[i] = DefaultPower
	}
}

// GetMaxPower returns the maximum transmit power for the given channel.
// The second return value is false if the channel is out of range.
func (t *Table) GetMaxPower(channel uint8) (int8, bool) {
	if channel < uint8(MinChannel) || channel > uint8(MaxChannel) {
		return 0, false
	}
	return t.powers[channel-uint8(MinChannel)], true
}

// SetMaxPower sets the maximum transmit power for the given channel.
// If the channel is out of range the call is a no-op.
func (t *Table) SetMaxPower(channel uint8, power int8) {
	if channel < uint8(MinChannel) || channel > uint8(MaxChannel) {
		return
	}
	t.powers[channel-uint8(MinChannel)] = power
}
