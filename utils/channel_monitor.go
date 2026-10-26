// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package utils implements utility modules for OpenThread including channel
// monitoring, channel management, and jam detection.
//
// This is a Go port of the utilities in OpenThread's src/core/utils/.
package utils

import (
	"github.com/hilli/gothread/errors"
)

// IEEE 802.15.4 channel range for 2.4 GHz band.
const (
	ChannelMin  = 11
	ChannelMax  = 26
	NumChannels = ChannelMax - ChannelMin + 1
)

// Default values for ChannelMonitor configuration.
const (
	DefaultSampleInterval uint32 = 41000 // ms between samples
	DefaultRssiThreshold  int8   = -75   // dBm
	DefaultSampleWindow   uint32 = 960   // number of recent samples to consider
	MaxOccupancy          uint16 = 0xffff
)

// EnergyScanner performs energy scans on a channel.
type EnergyScanner interface {
	// EnergyScan performs an energy scan on the given channel for the
	// specified duration and returns the maximum RSSI observed.
	EnergyScan(channel uint16, duration uint16) (int8, error)
}

// ChannelOccupancy stores occupancy data for a channel.
type ChannelOccupancy struct {
	Channel     uint16
	Occupancy   uint16 // occupancy rate (0-65535, where 65535 = 100%)
	SampleCount uint32
}

// ChannelMonitor periodically samples channel quality via energy scans.
//
// It maintains an exponentially weighted moving average of the occupancy
// rate (percentage of RSSI samples above a threshold) for each channel
// in the 2.4 GHz band (channels 11-26).
//
// Reference: openthread/src/core/utils/channel_monitor.hpp
type ChannelMonitor struct {
	scanner        EnergyScanner
	enabled        bool
	sampleInterval uint32 // ms between samples
	rssiThreshold  int8   // RSSI threshold for "occupied"
	sampleWindow   uint32 // number of recent samples to consider
	sampleCount    uint32 // total samples taken
	channelData    [NumChannels]uint16
	scanIndex      uint16 // next channel index to scan
}

// MonitorOption configures a ChannelMonitor.
type MonitorOption func(*ChannelMonitor)

// WithSampleInterval sets the interval between samples in milliseconds.
func WithSampleInterval(ms uint32) MonitorOption {
	return func(m *ChannelMonitor) {
		if ms > 0 {
			m.sampleInterval = ms
		}
	}
}

// WithRssiThreshold sets the RSSI threshold (in dBm) above which a
// channel is considered "occupied".
func WithRssiThreshold(dBm int8) MonitorOption {
	return func(m *ChannelMonitor) {
		m.rssiThreshold = dBm
	}
}

// WithSampleWindow sets the number of recent samples used for the
// occupancy average.
func WithSampleWindow(n uint32) MonitorOption {
	return func(m *ChannelMonitor) {
		if n > 0 {
			m.sampleWindow = n
		}
	}
}

// NewChannelMonitor creates a new ChannelMonitor with the given scanner
// and optional configuration.
func NewChannelMonitor(scanner EnergyScanner, opts ...MonitorOption) *ChannelMonitor {
	m := &ChannelMonitor{
		scanner:        scanner,
		sampleInterval: DefaultSampleInterval,
		rssiThreshold:  DefaultRssiThreshold,
		sampleWindow:   DefaultSampleWindow,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Start begins the channel monitoring operation. Any previously collected
// data is cleared.
func (m *ChannelMonitor) Start() error {
	if m.enabled {
		return errors.ErrAlready
	}
	m.clear()
	m.enabled = true
	return nil
}

// Stop stops the channel monitoring operation. Previously collected data
// remains accessible.
func (m *ChannelMonitor) Stop() {
	m.enabled = false
}

// IsEnabled reports whether the channel monitor is running.
func (m *ChannelMonitor) IsEnabled() bool {
	return m.enabled
}

// clear resets all collected data.
func (m *ChannelMonitor) clear() {
	m.sampleCount = 0
	m.scanIndex = 0
	m.channelData = [NumChannels]uint16{}
}

// HandleTimer performs the next sampling cycle. It scans each channel
// in sequence and updates the occupancy data.
//
// The caller is responsible for invoking HandleTimer at the configured
// sample interval.
func (m *ChannelMonitor) HandleTimer() {
	if !m.enabled || m.scanner == nil {
		return
	}

	for i := 0; i < NumChannels; i++ {
		channel := uint16(ChannelMin + i)
		rssi, err := m.scanner.EnergyScan(channel, 0)
		if err != nil {
			continue
		}

		var newValue uint32
		if rssi >= m.rssiThreshold {
			newValue = uint32(MaxOccupancy)
		}

		// Exponentially weighted moving average, matching the C++
		// implementation: for the first sampleWindow samples use the
		// actual ratio; after that use weight = sampleWindow-1.
		var weight uint32
		if m.sampleCount >= m.sampleWindow {
			weight = m.sampleWindow - 1
		} else {
			weight = m.sampleCount
		}

		cur := uint32(m.channelData[i])
		newAvg := (cur*weight + newValue) / (weight + 1)
		m.channelData[i] = uint16(newAvg)
	}

	m.sampleCount++
}

// GetChannelOccupancy returns the occupancy rate for the given channel.
// The value ranges from 0 (completely clear) to 65535 (100% occupied).
func (m *ChannelMonitor) GetChannelOccupancy(channel uint16) (uint16, error) {
	if channel < ChannelMin || channel > ChannelMax {
		return 0, errors.ErrInvalidArgs
	}
	return m.channelData[channel-ChannelMin], nil
}

// GetBestChannels returns the best count channels sorted by lowest
// occupancy. If count exceeds the number of available channels, all
// channels are returned.
func (m *ChannelMonitor) GetBestChannels(count int) []uint16 {
	if count <= 0 {
		return nil
	}
	if count > NumChannels {
		count = NumChannels
	}

	// Build a list of (channel, occupancy) pairs and sort by occupancy.
	type chanOcc struct {
		channel   uint16
		occupancy uint16
	}
	channels := make([]chanOcc, NumChannels)
	for i := 0; i < NumChannels; i++ {
		channels[i] = chanOcc{
			channel:   uint16(ChannelMin + i),
			occupancy: m.channelData[i],
		}
	}

	// Simple selection sort for 16 elements.
	for i := 0; i < count; i++ {
		minIdx := i
		for j := i + 1; j < NumChannels; j++ {
			if channels[j].occupancy < channels[minIdx].occupancy {
				minIdx = j
			}
		}
		channels[i], channels[minIdx] = channels[minIdx], channels[i]
	}

	result := make([]uint16, count)
	for i := 0; i < count; i++ {
		result[i] = channels[i].channel
	}
	return result
}

// GetSampleCount returns the total number of sample rounds taken.
func (m *ChannelMonitor) GetSampleCount() uint32 {
	return m.sampleCount
}

// FindBestChannel returns the channel with the lowest occupancy from the
// given channel mask (bitmask where bit N represents channel N). It also
// returns the occupancy of the best channel.
func (m *ChannelMonitor) FindBestChannel(mask uint32) (channel, occupancy uint16) {
	var bestChannel uint16
	var bestOccupancy = MaxOccupancy
	found := false

	for ch := uint16(ChannelMin); ch <= ChannelMax; ch++ {
		if mask&(1<<ch) == 0 {
			continue
		}
		occ := m.channelData[ch-ChannelMin]
		if !found || occ < bestOccupancy {
			bestOccupancy = occ
			bestChannel = ch
			found = true
		}
	}

	if !found {
		return 0, MaxOccupancy
	}
	return bestChannel, bestOccupancy
}
