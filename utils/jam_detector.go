// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"math/bits"

	"github.com/hilli/gothread/errors"
)

// Default values for JamDetector configuration.
const (
	DefaultJamRssiThreshold  int8   = -45 // dBm
	DefaultJamWindow         uint32 = 63  // seconds
	DefaultJamBusyPeriod     uint32 = 40  // seconds
	DefaultJamSampleInterval uint32 = 256 // ms

	// MaxJamWindow is the maximum detection window (limited by 64-bit bitmap).
	MaxJamWindow uint32 = 63
)

// RssiReader reads the current RSSI on the channel.
type RssiReader interface {
	// GetRssi returns the current RSSI reading in dBm.
	GetRssi() (int8, error)
}

// JamCallback is called when the jam state changes.
type JamCallback func(jamDetected bool)

// JamDetector detects signal jamming by monitoring RSSI levels over a
// sliding window of 1-second intervals.
//
// It maintains a 64-bit history bitmap where each bit represents one
// second. If the RSSI exceeds the threshold during a second interval,
// that bit is set. Jamming is detected when the number of "busy"
// seconds in the window exceeds the busy period threshold.
//
// Reference: openthread/src/core/utils/jam_detector.hpp
type JamDetector struct {
	reader               RssiReader
	callback             JamCallback
	enabled              bool
	rssiThreshold        int8   // RSSI above this = "busy"
	window               uint32 // detection window in seconds
	busyPeriod           uint32 // busy seconds needed to trigger
	history              uint64 // bitfield of busy/clear seconds
	historyLen           uint32 // valid bits in history
	jamDetected          bool
	sampleInterval       uint32 // ms between samples
	alwaysAboveThreshold bool   // state for current 1-second interval
	currentSecondSamples uint32 // samples taken in current second
}

// JamOption configures a JamDetector.
type JamOption func(*JamDetector)

// WithJamRssiThreshold sets the RSSI threshold (in dBm) above which
// the channel is considered "busy".
func WithJamRssiThreshold(dBm int8) JamOption {
	return func(d *JamDetector) {
		d.rssiThreshold = dBm
	}
}

// WithWindow sets the detection window in seconds (1-63).
func WithWindow(seconds uint32) JamOption {
	return func(d *JamDetector) {
		if seconds > 0 && seconds <= MaxJamWindow {
			d.window = seconds
		}
	}
}

// WithBusyPeriod sets the number of busy seconds within the window
// needed to trigger jam detection.
func WithBusyPeriod(seconds uint32) JamOption {
	return func(d *JamDetector) {
		if seconds > 0 {
			d.busyPeriod = seconds
		}
	}
}

// WithJamSampleInterval sets the interval in milliseconds between RSSI samples.
func WithJamSampleInterval(ms uint32) JamOption {
	return func(d *JamDetector) {
		if ms > 0 {
			d.sampleInterval = ms
		}
	}
}

// NewJamDetector creates a new JamDetector with the given RSSI reader
// and optional configuration.
func NewJamDetector(reader RssiReader, opts ...JamOption) *JamDetector {
	d := &JamDetector{
		reader:         reader,
		rssiThreshold:  DefaultJamRssiThreshold,
		window:         DefaultJamWindow,
		busyPeriod:     DefaultJamBusyPeriod,
		sampleInterval: DefaultJamSampleInterval,
	}
	for _, opt := range opts {
		opt(d)
	}
	// Ensure busyPeriod <= window.
	if d.busyPeriod > d.window {
		d.busyPeriod = d.window
	}
	return d
}

// Start begins jam detection. Returns ErrAlready if already enabled.
func (d *JamDetector) Start() error {
	if d.enabled {
		return errors.ErrAlready
	}
	d.enabled = true
	d.history = 0
	d.historyLen = 0
	d.jamDetected = false
	d.alwaysAboveThreshold = true
	d.currentSecondSamples = 0
	return nil
}

// Stop stops jam detection.
func (d *JamDetector) Stop() {
	d.enabled = false
	d.jamDetected = false
}

// IsEnabled reports whether the jam detector is active.
func (d *JamDetector) IsEnabled() bool {
	return d.enabled
}

// HandleTimer samples the RSSI and updates the jam detection history.
//
// The caller is responsible for invoking HandleTimer at the configured
// sample interval. Multiple calls within a 1-second window are aggregated:
// if any sample within the second is below the threshold, the second is
// considered "clear".
//
// After accumulating enough samples for one second (based on
// sampleInterval), the history bitmap is updated and jam state is
// re-evaluated.
func (d *JamDetector) HandleTimer() {
	if !d.enabled || d.reader == nil {
		return
	}

	rssi, err := d.reader.GetRssi()
	if err != nil {
		return
	}

	didExceed := rssi >= d.rssiThreshold
	if !didExceed {
		d.alwaysAboveThreshold = false
	}

	d.currentSecondSamples++

	// Calculate how many samples make up one second.
	samplesPerSecond := uint32(1000) / d.sampleInterval
	if samplesPerSecond == 0 {
		samplesPerSecond = 1
	}

	if d.currentSecondSamples >= samplesPerSecond {
		d.updateHistory()
		d.currentSecondSamples = 0
		d.alwaysAboveThreshold = true
	}
}

// updateHistory shifts the history bitmap and appends the current second.
func (d *JamDetector) updateHistory() {
	d.history <<= 1

	if d.alwaysAboveThreshold {
		d.history |= 1
	}

	if d.historyLen < MaxJamWindow {
		d.historyLen++
	}

	d.updateJamState()
}

// updateJamState counts busy bits in the window and updates jam detection.
func (d *JamDetector) updateJamState() {
	// Mask to only consider bits within the window.
	mask := uint64(0)
	if d.window < 64 {
		mask = (uint64(1) << d.window) - 1
	} else {
		mask = ^uint64(0)
	}

	masked := d.history & mask
	busyCount := uint32(bits.OnesCount64(masked))

	newJamState := busyCount >= d.busyPeriod
	if newJamState != d.jamDetected {
		d.jamDetected = newJamState
		if d.callback != nil {
			d.callback(newJamState)
		}
	}
}

// IsJamDetected reports whether jamming is currently detected.
func (d *JamDetector) IsJamDetected() bool {
	return d.jamDetected
}

// SetCallback sets the function called when the jam state changes.
func (d *JamDetector) SetCallback(cb JamCallback) {
	d.callback = cb
}

// GetHistoryBitmap returns the 64-bit history bitmap. Bit 0 (LSB)
// represents the most recent 1-second interval.
func (d *JamDetector) GetHistoryBitmap() uint64 {
	return d.history
}

// GetWindow returns the detection window in seconds.
func (d *JamDetector) GetWindow() uint32 {
	return d.window
}

// GetBusyPeriod returns the busy period threshold in seconds.
func (d *JamDetector) GetBusyPeriod() uint32 {
	return d.busyPeriod
}

// GetRssiThreshold returns the RSSI threshold in dBm.
func (d *JamDetector) GetRssiThreshold() int8 {
	return d.rssiThreshold
}
