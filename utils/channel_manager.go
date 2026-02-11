// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"github.com/hilli/gothread/errors"
)

// Default values for ChannelManager configuration.
const (
	DefaultDelay              uint32 = 120   // seconds before channel change
	DefaultAutoSelectInterval uint32 = 10800 // seconds (3 hours)
	MinimumDelay              uint32 = 120   // minimum allowed delay

	// DefaultSupportedChannelMask includes all 2.4 GHz channels (11-26).
	DefaultSupportedChannelMask uint32 = 0x07FFF800

	// ThresholdToSkipFavored is the minimum occupancy difference to
	// prefer an unfavored channel over a favored one.
	ThresholdToSkipFavored uint16 = 0x0700

	// ThresholdToChangeChannel is the minimum occupancy improvement
	// required to trigger a channel change.
	ThresholdToChangeChannel uint16 = 0x0300
)

// ChannelManager states.
const (
	stateIdle             = 0
	stateChangeRequested  = 1
	stateChangeInProgress = 2
)

// NetworkDataUpdater publishes channel changes to the network.
type NetworkDataUpdater interface {
	// RequestChannelChange requests the network switch to the given channel.
	RequestChannelChange(channel uint16) error
}

// ChannelManager handles automated channel selection and change based on
// quality metrics collected by a ChannelMonitor.
//
// Reference: openthread/src/core/utils/channel_manager.hpp
type ChannelManager struct {
	monitor              *ChannelMonitor
	updater              NetworkDataUpdater
	enabled              bool
	autoSelectEnabled    bool
	favoredChannelMask   uint32
	supportedChannelMask uint32
	delay                uint32 // seconds before channel change
	currentChannel       uint16
	selectedChannel      uint16
	state                uint8
	autoSelectInterval   uint32 // seconds between auto-select evaluations
}

// ManagerOption configures a ChannelManager.
type ManagerOption func(*ChannelManager)

// WithDelay sets the delay (in seconds) before a channel change is applied.
func WithDelay(seconds uint32) ManagerOption {
	return func(m *ChannelManager) {
		if seconds >= MinimumDelay {
			m.delay = seconds
		}
	}
}

// WithAutoSelectInterval sets the interval (in seconds) between
// automatic channel selection evaluations.
func WithAutoSelectInterval(seconds uint32) ManagerOption {
	return func(m *ChannelManager) {
		if seconds > 0 {
			m.autoSelectInterval = seconds
		}
	}
}

// WithFavoredChannels sets the preferred channel mask.
func WithFavoredChannels(mask uint32) ManagerOption {
	return func(m *ChannelManager) {
		m.favoredChannelMask = mask
	}
}

// WithSupportedChannels sets the supported channel mask.
func WithSupportedChannels(mask uint32) ManagerOption {
	return func(m *ChannelManager) {
		m.supportedChannelMask = mask
	}
}

// NewChannelManager creates a new ChannelManager with the given monitor,
// updater, and optional configuration.
func NewChannelManager(monitor *ChannelMonitor, updater NetworkDataUpdater, opts ...ManagerOption) *ChannelManager {
	m := &ChannelManager{
		monitor:              monitor,
		updater:              updater,
		delay:                DefaultDelay,
		autoSelectInterval:   DefaultAutoSelectInterval,
		supportedChannelMask: DefaultSupportedChannelMask,
		favoredChannelMask:   DefaultSupportedChannelMask,
		state:                stateIdle,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// RequestChannelChange requests a channel change to the specified channel.
// The change is applied after the configured delay.
func (m *ChannelManager) RequestChannelChange(channel uint16) error {
	if channel < ChannelMin || channel > ChannelMax {
		return errors.ErrInvalidArgs
	}
	if channel == m.currentChannel {
		return errors.ErrAlready
	}
	if m.state == stateChangeInProgress && m.selectedChannel == channel {
		return errors.ErrAlready
	}

	m.selectedChannel = channel
	m.state = stateChangeRequested
	return nil
}

// RequestChannelSelect selects the best channel based on monitoring data.
//
// If skipQualityCheck is false, selection only proceeds if the current
// channel quality is poor enough to justify a change.
//
// If skipQualityCheck is true, the best available channel is always selected.
func (m *ChannelManager) RequestChannelSelect(skipQualityCheck bool) error {
	if m.monitor == nil {
		return errors.ErrInvalidState
	}

	if !skipQualityCheck && m.monitor.GetSampleCount() == 0 {
		return errors.ErrInvalidState
	}

	newChannel, newOccupancy := m.findBestChannel()
	if newChannel == 0 {
		return errors.ErrFailed
	}

	if newChannel == m.currentChannel {
		return nil // already on best channel
	}

	if !skipQualityCheck {
		curOccupancy, _ := m.monitor.GetChannelOccupancy(m.currentChannel)
		// Only switch if the improvement exceeds the threshold.
		if newOccupancy >= curOccupancy {
			return nil
		}
		if curOccupancy-newOccupancy < ThresholdToChangeChannel {
			return nil
		}
	}

	return m.RequestChannelChange(newChannel)
}

// findBestChannel selects the best channel from favored channels,
// falling back to all supported channels if favored ones are worse.
func (m *ChannelManager) findBestChannel() (uint16, uint16) {
	if m.monitor == nil {
		return 0, MaxOccupancy
	}

	favoredAndSupported := m.favoredChannelMask & m.supportedChannelMask

	favoredBest, favoredOcc := m.monitor.FindBestChannel(favoredAndSupported)
	supportedBest, supportedOcc := m.monitor.FindBestChannel(m.supportedChannelMask)

	// Prefer favored channels unless they are significantly worse
	// than the best supported channel.
	if favoredBest == 0 ||
		(favoredOcc >= ThresholdToSkipFavored &&
			supportedOcc+ThresholdToSkipFavored <= favoredOcc) {
		return supportedBest, supportedOcc
	}

	return favoredBest, favoredOcc
}

// HandleTimer processes a timer tick. In the idle state with auto-select
// enabled, it triggers automatic channel selection. In the change-requested
// state, it applies the pending channel change via the updater.
func (m *ChannelManager) HandleTimer() {
	switch m.state {
	case stateIdle:
		if m.autoSelectEnabled {
			_ = m.RequestChannelSelect(false)
		}
	case stateChangeRequested:
		if m.updater != nil {
			err := m.updater.RequestChannelChange(m.selectedChannel)
			if err == nil {
				m.currentChannel = m.selectedChannel
				m.state = stateIdle
			} else {
				// Retry on next timer tick.
			}
		} else {
			m.currentChannel = m.selectedChannel
			m.state = stateIdle
		}
	case stateChangeInProgress:
		// Wait for completion.
	}
}

// SetAutoSelectEnabled enables or disables automatic channel selection.
func (m *ChannelManager) SetAutoSelectEnabled(enabled bool) {
	m.autoSelectEnabled = enabled
}

// IsAutoSelectEnabled reports whether automatic channel selection is enabled.
func (m *ChannelManager) IsAutoSelectEnabled() bool {
	return m.autoSelectEnabled
}

// SetFavoredChannels sets the favored channel mask.
func (m *ChannelManager) SetFavoredChannels(mask uint32) {
	m.favoredChannelMask = mask
}

// GetFavoredChannels returns the favored channel mask.
func (m *ChannelManager) GetFavoredChannels() uint32 {
	return m.favoredChannelMask
}

// SetSupportedChannels sets the supported channel mask.
func (m *ChannelManager) SetSupportedChannels(mask uint32) {
	m.supportedChannelMask = mask
}

// GetSupportedChannels returns the supported channel mask.
func (m *ChannelManager) GetSupportedChannels() uint32 {
	return m.supportedChannelMask
}

// SetDelay sets the delay (in seconds) before a channel change is applied.
func (m *ChannelManager) SetDelay(seconds uint32) {
	if seconds >= MinimumDelay {
		m.delay = seconds
	}
}

// GetDelay returns the delay (in seconds) before a channel change.
func (m *ChannelManager) GetDelay() uint32 {
	return m.delay
}

// GetCurrentChannel returns the current operating channel.
func (m *ChannelManager) GetCurrentChannel() uint16 {
	return m.currentChannel
}

// SetCurrentChannel sets the current operating channel. This is used
// to inform the manager of the actual channel in use.
func (m *ChannelManager) SetCurrentChannel(channel uint16) {
	m.currentChannel = channel
}

// GetAutoSelectInterval returns the auto-select interval in seconds.
func (m *ChannelManager) GetAutoSelectInterval() uint32 {
	return m.autoSelectInterval
}
