// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package discover implements the MLE Discover Scanner for Thread networks.
//
// The Discover Scanner performs an active scan for Thread networks by sending
// MLE Discovery Requests on each channel in a channel mask and collecting
// Discovery Responses. This is a Go port of OpenThread's DiscoverScanner
// from src/core/thread/discover_scanner.hpp and discover_scanner.cpp.
package discover

import (
	"sync"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/meshcop"
)

// IEEE 802.15.4 channel constants for the 2.4 GHz band.
const (
	// ChannelMin is the lowest 802.15.4 channel (2.4 GHz band).
	ChannelMin uint16 = 11
	// ChannelMax is the highest 802.15.4 channel (2.4 GHz band).
	ChannelMax uint16 = 26

	// DefaultScanDuration is the default per-channel scan duration in milliseconds.
	DefaultScanDuration uint32 = 300

	// PanIDBroadcast is the broadcast PAN ID used when no specific PAN ID filter is wanted.
	PanIDBroadcast uint16 = 0xFFFF

	// MaxNetworkNameLen is the maximum length of a Thread network name.
	MaxNetworkNameLen = 16
)

// state represents the scanner's internal state machine.
type state uint8

const (
	stateIdle     state = iota // not scanning
	stateScanning              // actively scanning channels
	stateScanDone              // all channels scanned, finishing up
)

// ScanResult represents a discovered Thread network.
type ScanResult struct {
	// ExtPanID is the Extended PAN ID of the discovered network.
	ExtPanID [8]byte

	// NetworkName is the Thread network name (max 16 chars).
	NetworkName string

	// SteeringData is the raw steering data bytes for Joiner filtering.
	SteeringData []byte

	// PanID is the IEEE 802.15.4 PAN ID of the network.
	PanID uint16

	// JoinerUDPPort is the UDP port for Joiner communication.
	JoinerUDPPort uint16

	// Channel is the IEEE 802.15.4 channel where the network was found.
	Channel uint16

	// RSSI is the received signal strength indicator in dBm.
	RSSI int8

	// LQI is the link quality indicator (0-255).
	LQI uint8

	// Version is the Thread protocol version of the responder.
	Version uint8

	// IsNative indicates whether native commissioning is enabled.
	IsNative bool

	// IsJoinable indicates whether the network allows joining
	// (steering data is present and not empty).
	IsJoinable bool

	// ExtAddress is the responder's IEEE 802.15.4 Extended MAC address.
	ExtAddress [8]byte
}

// ScanHandler is called for each discovered network. A nil result
// indicates the scan is complete.
type ScanHandler func(result *ScanResult)

// DiscoverySender abstracts the low-level mechanism for sending an
// MLE Discovery Request on a specific channel.
type DiscoverySender interface {
	// SendDiscoveryRequest sends an MLE Discovery Request on the given
	// channel with the specified PAN ID. The enableFiltering flag indicates
	// whether the request should include Joiner filtering information.
	SendDiscoveryRequest(channel uint16, panID uint16, enableFiltering bool) error
}

// Timer abstracts a one-shot timer for per-channel scan durations.
type Timer interface {
	// Start begins the timer with the given delay in milliseconds.
	Start(delayMs uint32)
	// Stop cancels the timer if it is running.
	Stop()
	// IsRunning reports whether the timer is currently active.
	IsRunning() bool
}

// Option configures a Scanner via the functional options pattern.
type Option func(*Scanner)

// WithScanDuration sets the per-channel scan duration in milliseconds.
// The default is DefaultScanDuration (300 ms).
func WithScanDuration(ms uint32) Option {
	return func(s *Scanner) {
		if ms > 0 {
			s.scanDuration = ms
		}
	}
}

// WithFilterExtPanID restricts scan results to networks matching the
// given Extended PAN ID.
func WithFilterExtPanID(extPanID [8]byte) Option {
	return func(s *Scanner) {
		s.filterByExtPanID = true
		s.extPanIDFilter = extPanID
	}
}

// WithFilterIndexes enables steering data filtering using the given
// HashBitIndexes. When enabled, Discovery Responses whose steering data
// does not contain the filter indexes are discarded.
func WithFilterIndexes(indexes meshcop.HashBitIndexes) Option {
	return func(s *Scanner) {
		s.enableFiltering = true
		s.filterIndexes = indexes
	}
}

// Scanner performs MLE Discovery scans across IEEE 802.15.4 channels
// to find Thread networks.
type Scanner struct {
	mu sync.Mutex

	// Configuration.
	channelMask  uint32 // bitmask of channels to scan
	panID        uint16 // PAN ID filter (PanIDBroadcast = any)
	scanDuration uint32 // per-channel scan duration in ms
	joinerFlag   bool   // include Joiner flag in Discovery Request

	// Filtering.
	filterByExtPanID bool
	extPanIDFilter   [8]byte
	enableFiltering  bool
	filterIndexes    meshcop.HashBitIndexes

	// Runtime state.
	state          state
	currentChannel uint16
	results        []ScanResult
	handler        ScanHandler

	// Interfaces.
	sender DiscoverySender
	timer  Timer
}

// NewScanner creates a new Scanner with the given sender and options.
func NewScanner(sender DiscoverySender, timer Timer, opts ...Option) *Scanner {
	s := &Scanner{
		sender:       sender,
		timer:        timer,
		scanDuration: DefaultScanDuration,
		panID:        PanIDBroadcast,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Discover starts a Thread Discovery Scan.
//
// channelMask is a bitmask of 802.15.4 channels to scan (bit N set means
// scan channel N). If channelMask is 0, all channels 11-26 are scanned.
//
// panID filters responses to a specific PAN ID. Use PanIDBroadcast (0xFFFF)
// to accept any PAN ID.
//
// joinerFlag sets the Joiner Flag in the Discovery Request TLV.
//
// handler is called for each discovered network. When the scan completes,
// handler is called with a nil result.
//
// Returns ErrBusy if a scan is already in progress, or ErrInvalidArgs if
// handler is nil.
func (s *Scanner) Discover(channelMask uint32, panID uint16, joinerFlag bool, handler ScanHandler) error {
	if handler == nil {
		return goterrors.ErrInvalidArgs
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != stateIdle {
		return goterrors.ErrBusy
	}

	s.channelMask = channelMask
	if s.channelMask == 0 {
		// Default: scan all channels 11-26.
		for ch := ChannelMin; ch <= ChannelMax; ch++ {
			s.channelMask |= 1 << ch
		}
	}

	s.panID = panID
	s.joinerFlag = joinerFlag
	s.handler = handler
	s.results = nil

	// Find the first channel to scan.
	ch, ok := s.nextChannel(ChannelMin - 1)
	if !ok {
		// No channels in the mask — immediately complete.
		s.state = stateScanDone
		s.finishScan()
		return nil
	}

	s.currentChannel = ch
	s.state = stateScanning

	return s.scanCurrentChannel()
}

// IsScanning reports whether a scan is currently in progress.
func (s *Scanner) IsScanning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state != stateIdle
}

// Stop aborts the current scan. If a handler was registered, it is called
// with a nil result to signal completion.
func (s *Scanner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == stateIdle {
		return
	}

	s.timer.Stop()
	s.finishScan()
}

// HandleDiscoveryResponse processes a received Discovery Response.
// This should be called by the MLE layer when a Discovery Response is
// received during an active scan.
func (s *Scanner) HandleDiscoveryResponse(result *ScanResult) {
	if result == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != stateScanning {
		return
	}

	// Apply Extended PAN ID filter.
	if s.filterByExtPanID && result.ExtPanID != s.extPanIDFilter {
		return
	}

	// Apply steering data filter.
	if s.enableFiltering {
		if len(result.SteeringData) == 0 {
			// No steering data and filtering is enabled — drop.
			return
		}
		var sd meshcop.SteeringData
		sdLen := uint8(len(result.SteeringData))
		if sdLen > meshcop.SteeringDataMaxLength {
			sdLen = meshcop.SteeringDataMaxLength
		}
		if err := sd.InitWithData(sdLen, result.SteeringData); err != nil {
			return
		}
		if !sd.ContainsIndexes(s.filterIndexes) {
			return
		}
	}

	// Determine joinability from steering data presence.
	if len(result.SteeringData) > 0 {
		var sd meshcop.SteeringData
		sdLen := uint8(len(result.SteeringData))
		if sdLen > meshcop.SteeringDataMaxLength {
			sdLen = meshcop.SteeringDataMaxLength
		}
		if err := sd.InitWithData(sdLen, result.SteeringData); err == nil {
			result.IsJoinable = !sd.IsEmpty()
		}
	}

	s.results = append(s.results, *result)

	// Invoke the handler for this result.
	if s.handler != nil {
		s.handler(result)
	}
}

// HandleTimer is called when the per-channel scan timer fires. It advances
// to the next channel or completes the scan.
func (s *Scanner) HandleTimer() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != stateScanning {
		return
	}

	// Try to advance to the next channel.
	ch, ok := s.nextChannel(s.currentChannel)
	if !ok {
		// No more channels — scan is complete.
		s.state = stateScanDone
		s.finishScan()
		return
	}

	s.currentChannel = ch
	if err := s.scanCurrentChannel(); err != nil {
		// If we fail to send on this channel, finish the scan.
		s.state = stateScanDone
		s.finishScan()
	}
}

// HandleScanComplete is called when all channels have been scanned.
// It resets the scanner state and invokes the handler with nil to signal
// completion. This is an alias for the internal finishScan behavior and
// can be called externally if needed.
func (s *Scanner) HandleScanComplete() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == stateIdle {
		return
	}
	s.timer.Stop()
	s.finishScan()
}

// Results returns a copy of all scan results collected so far.
func (s *Scanner) Results() []ScanResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.results) == 0 {
		return nil
	}
	out := make([]ScanResult, len(s.results))
	copy(out, s.results)
	return out
}

// CurrentChannel returns the channel currently being scanned.
// Returns 0 if no scan is in progress.
func (s *Scanner) CurrentChannel() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != stateScanning {
		return 0
	}
	return s.currentChannel
}

// --- internal helpers ---

// nextChannel returns the next channel to scan after afterChannel.
// It iterates through set bits in channelMask starting from afterChannel+1.
// Returns the channel number and true, or 0 and false if no more channels.
func (s *Scanner) nextChannel(afterChannel uint16) (uint16, bool) {
	for ch := afterChannel + 1; ch <= ChannelMax; ch++ {
		if s.channelMask&(1<<ch) != 0 {
			return ch, true
		}
	}
	return 0, false
}

// scanCurrentChannel sends a Discovery Request on the current channel
// and starts the scan timer.
func (s *Scanner) scanCurrentChannel() error {
	err := s.sender.SendDiscoveryRequest(s.currentChannel, s.panID, s.enableFiltering)
	if err != nil {
		return err
	}
	s.timer.Start(s.scanDuration)
	return nil
}

// finishScan resets the scanner to idle and invokes the handler with nil.
// Must be called with s.mu held.
func (s *Scanner) finishScan() {
	s.state = stateIdle
	handler := s.handler
	s.handler = nil

	if handler != nil {
		handler(nil)
	}
}
