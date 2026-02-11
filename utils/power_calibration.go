// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"math"
	"sync"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/radio"
)

// Power calibration constants.
const (
	// MaxRawPowerSettingSize is the maximum size of a raw power setting byte array.
	MaxRawPowerSettingSize = 16

	// MaxCalibratedPowerEntries is the maximum number of calibrated power
	// entries per channel.
	MaxCalibratedPowerEntries = 16

	// invalidPower is the sentinel value indicating an unset target power.
	invalidPower int16 = math.MaxInt16
)

// numChannels is the number of IEEE 802.15.4 channels in the 2.4 GHz band.
var numChannels = int(radio.Channel24GHzMax - radio.Channel24GHzMin + 1)

// CalibratedPowerEntry holds a single calibrated power entry mapping an
// actual power level to a raw power setting.
//
// Reference: openthread/src/core/utils/power_calibration.hpp CalibratedPowerEntry
type CalibratedPowerEntry struct {
	ActualPower int16
	Settings    []byte
}

// PowerSettings holds the result of a GetPowerSettings query.
type PowerSettings struct {
	TargetPower int16
	ActualPower int16
	RawPower    []byte
}

// PowerCalibration implements radio power calibration tables.
//
// It stores per-channel calibrated power tables and target powers,
// and provides an API to look up the best raw power setting for a
// given channel based on the target power.
//
// Reference: openthread/src/core/utils/power_calibration.hpp/.cpp
type PowerCalibration struct {
	mu                    sync.Mutex
	lastChannel           uint8
	calibratedPowerIndex  int // -1 means "needs update"
	targetPowerTable      []int16
	calibratedPowerTables [][]CalibratedPowerEntry
}

// NewPowerCalibration creates a new PowerCalibration instance.
func NewPowerCalibration() *PowerCalibration {
	targets := make([]int16, numChannels)
	for i := range targets {
		targets[i] = invalidPower
	}

	tables := make([][]CalibratedPowerEntry, numChannels)
	for i := range tables {
		tables[i] = make([]CalibratedPowerEntry, 0)
	}

	return &PowerCalibration{
		lastChannel:           0,
		calibratedPowerIndex:  -1,
		targetPowerTable:      targets,
		calibratedPowerTables: tables,
	}
}

// isChannelValid checks whether a channel is within the supported range.
func isChannelValid(channel uint8) bool {
	return channel >= radio.Channel24GHzMin && channel <= radio.Channel24GHzMax
}

// channelIndex returns the zero-based index for a channel.
func channelIndex(channel uint8) int {
	return int(channel - radio.Channel24GHzMin)
}

// isPowerUpdated returns true when the calibrated power index needs recalculation.
func (pc *PowerCalibration) isPowerUpdated() bool {
	return pc.calibratedPowerIndex == -1
}

// AddCalibratedPower adds a calibrated power entry for the specified channel.
//
// Each entry maps an actual power level (in 0.01 dBm) to a raw power setting
// byte array. Duplicate actual power values for the same channel are rejected.
//
// Returns:
//   - ErrInvalidArgs if channel is out of range, raw power setting is too long,
//     or a duplicate actual power already exists.
//   - ErrNoBufs if the channel's calibration table is full.
func (pc *PowerCalibration) AddCalibratedPower(channel uint8, actualPower int16, rawPowerSetting []byte) error {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if !isChannelValid(channel) || len(rawPowerSetting) > MaxRawPowerSettingSize || len(rawPowerSetting) == 0 {
		return errors.ErrInvalidArgs
	}

	idx := channelIndex(channel)
	table := pc.calibratedPowerTables[idx]

	// Check for duplicate actual power.
	for _, entry := range table {
		if entry.ActualPower == actualPower {
			return errors.ErrInvalidArgs
		}
	}

	// Check capacity.
	if len(table) >= MaxCalibratedPowerEntries {
		return errors.ErrNoBufs
	}

	// Copy the raw power setting.
	settings := make([]byte, len(rawPowerSetting))
	copy(settings, rawPowerSetting)

	pc.calibratedPowerTables[idx] = append(table, CalibratedPowerEntry{
		ActualPower: actualPower,
		Settings:    settings,
	})

	if channel == pc.lastChannel {
		pc.calibratedPowerIndex = -1
	}

	return nil
}

// ClearCalibratedPowers removes all calibrated power entries for all channels.
func (pc *PowerCalibration) ClearCalibratedPowers() {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	for i := range pc.calibratedPowerTables {
		pc.calibratedPowerTables[i] = pc.calibratedPowerTables[i][:0]
	}
	pc.calibratedPowerIndex = -1
}

// SetChannelTargetPower sets the target power for the given channel.
// The target power is in 0.01 dBm. Setting it to math.MaxInt16 disables
// the channel.
//
// Returns ErrInvalidArgs if the channel is out of range.
func (pc *PowerCalibration) SetChannelTargetPower(channel uint8, targetPower int16) error {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if !isChannelValid(channel) {
		return errors.ErrInvalidArgs
	}

	pc.targetPowerTable[channelIndex(channel)] = targetPower

	if channel == pc.lastChannel {
		pc.calibratedPowerIndex = -1
	}

	return nil
}

// GetPowerSettings returns the power settings for the given channel.
//
// It selects the calibrated power entry whose actual power is closest to
// (but not exceeding) the target power. If no entry is at or below the
// target, the entry with the lowest actual power is used.
//
// Returns:
//   - ErrInvalidArgs if the channel is out of range.
//   - ErrNotFound if no target power is set or no calibration data exists.
func (pc *PowerCalibration) GetPowerSettings(channel uint8) (*PowerSettings, error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if !isChannelValid(channel) {
		return nil, errors.ErrInvalidArgs
	}

	// Check if we need to recalculate.
	if pc.lastChannel == channel && !pc.isPowerUpdated() {
		// Use cached result.
		return pc.buildResult(channel)
	}

	idx := channelIndex(channel)
	targetPower := pc.targetPowerTable[idx]
	if targetPower == invalidPower {
		return nil, errors.ErrNotFound
	}

	table := pc.calibratedPowerTables[idx]
	if len(table) == 0 {
		return nil, errors.ErrNotFound
	}

	// Find best matching entry.
	powerIndex := -1
	foundPower := invalidPower
	minPower := int16(math.MaxInt16)
	minPowerIndex := -1

	for i, entry := range table {
		ap := entry.ActualPower
		if ap <= targetPower && (foundPower == invalidPower || foundPower <= ap) {
			foundPower = ap
			powerIndex = i
		} else if ap < minPower {
			minPower = ap
			minPowerIndex = i
		}
	}

	if powerIndex != -1 {
		pc.calibratedPowerIndex = powerIndex
	} else {
		pc.calibratedPowerIndex = minPowerIndex
	}
	pc.lastChannel = channel

	return pc.buildResult(channel)
}

// buildResult constructs a PowerSettings from the current cached state.
// Caller must hold pc.mu.
func (pc *PowerCalibration) buildResult(channel uint8) (*PowerSettings, error) {
	idx := channelIndex(channel)
	if pc.calibratedPowerIndex < 0 || pc.calibratedPowerIndex >= len(pc.calibratedPowerTables[idx]) {
		return nil, errors.ErrNotFound
	}

	entry := &pc.calibratedPowerTables[idx][pc.calibratedPowerIndex]
	rawCopy := make([]byte, len(entry.Settings))
	copy(rawCopy, entry.Settings)

	return &PowerSettings{
		TargetPower: pc.targetPowerTable[idx],
		ActualPower: entry.ActualPower,
		RawPower:    rawCopy,
	}, nil
}

// GetChannelTargetPower returns the target power for the given channel.
// Returns ErrInvalidArgs if the channel is invalid, or ErrNotFound if
// no target power has been set.
func (pc *PowerCalibration) GetChannelTargetPower(channel uint8) (int16, error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if !isChannelValid(channel) {
		return 0, errors.ErrInvalidArgs
	}

	tp := pc.targetPowerTable[channelIndex(channel)]
	if tp == invalidPower {
		return 0, errors.ErrNotFound
	}
	return tp, nil
}

// GetCalibratedPowerCount returns the number of calibrated power entries
// for the given channel.
func (pc *PowerCalibration) GetCalibratedPowerCount(channel uint8) (int, error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if !isChannelValid(channel) {
		return 0, errors.ErrInvalidArgs
	}

	return len(pc.calibratedPowerTables[channelIndex(channel)]), nil
}
