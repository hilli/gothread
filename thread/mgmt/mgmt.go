// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package mgmt implements the Energy Scan Server, PAN ID Query Server, and
// Anycast Locator components of the Thread management protocol.
//
// The Energy Scan Server handles energy scan requests from the Commissioner,
// performing an energy scan on specified channels and reporting results back.
//
// The PAN ID Query Server handles PAN ID query requests from the Commissioner,
// scanning specified channels for the presence of a given PAN ID and reporting
// conflicts.
//
// The Anycast Locator resolves Thread anycast addresses to their RLOC16 and
// mesh-local EID.
//
// This is a Go port of the logic in OpenThread's
// src/core/thread/energy_scan_server.{hpp,cpp},
// src/core/thread/panid_query_server.{hpp,cpp}, and
// src/core/thread/anycast_locator.{hpp,cpp}.
package mgmt

import (
	"sync"

	"github.com/hilli/gothread/errors"
)

// IEEE 802.15.4 channel range for Thread.
const (
	ChannelMin = 11 // Lowest 802.15.4 channel.
	ChannelMax = 26 // Highest 802.15.4 channel.
)

// ---------------------------------------------------------------------------
// Energy Scan Server
// ---------------------------------------------------------------------------

// Constants matching OpenThread's energy_scan_server.hpp.
const (
	energyScanDelay   uint32 = 1000 // SCAN_DELAY (ms)
	energyReportDelay uint32 = 500  // Delay before sending a report (ms)
	energyMinCount    uint8  = 1
	energyMaxCount    uint8  = 3

	defaultScanDuration uint16 = 200 // Default scan duration per channel (ms).
	defaultCount        uint8  = 1   // Default number of scans per channel.
)

// EnergyScanner is the platform interface for performing energy scans.
type EnergyScanner interface {
	// EnergyScan performs an energy scan on the given channel for the
	// specified duration (ms) and returns the maximum RSSI observed.
	EnergyScan(channel uint16, duration uint16) (int8, error)
}

// EnergyScanResult holds the result of a single energy scan on one channel.
type EnergyScanResult struct {
	Channel uint16
	MaxRssi int8
}

// EnergyScanOption configures an EnergyScanServer.
type EnergyScanOption func(*EnergyScanServer)

// WithDefaultScanDuration sets the default scan duration in milliseconds.
func WithDefaultScanDuration(ms uint16) EnergyScanOption {
	return func(s *EnergyScanServer) {
		s.scanDuration = ms
	}
}

// WithDefaultCount sets the default number of scans per channel.
func WithDefaultCount(n uint8) EnergyScanOption {
	return func(s *EnergyScanServer) {
		if n < energyMinCount {
			n = energyMinCount
		}
		if n > energyMaxCount {
			n = energyMaxCount
		}
		s.count = n
	}
}

// EnergyScanServer handles energy scan TMF requests from the Commissioner.
// It scans a set of channels for energy levels and reports back the maximum
// RSSI observed per channel per scan pass.
type EnergyScanServer struct {
	mu sync.Mutex

	scanner      EnergyScanner
	channelMask  uint32
	count        uint8  // number of scan passes over all channels
	period       uint16 // interval between scan passes (ms)
	scanDuration uint16 // duration per individual channel scan (ms)

	results     []EnergyScanResult
	scanning    bool
	currentChan uint16
	scanCount   uint8 // scans completed so far for the current pass

	// channelMaskCurrent tracks which channels remain in the current pass.
	channelMaskCurrent uint32

	reportCb func(channelMask uint32, results []EnergyScanResult)
}

// NewEnergyScanServer creates a new EnergyScanServer with the given platform
// scanner and optional configuration.
func NewEnergyScanServer(scanner EnergyScanner, opts ...EnergyScanOption) *EnergyScanServer {
	s := &EnergyScanServer{
		scanner:      scanner,
		scanDuration: defaultScanDuration,
		count:        defaultCount,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// HandleRequest starts an energy scan across the channels specified by
// channelMask. The scan will be repeated count times, with period (ms)
// between passes, and each channel scanned for scanDuration (ms).
func (s *EnergyScanServer) HandleRequest(channelMask uint32, count uint8, period, scanDuration uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if channelMask == 0 {
		return errors.ErrInvalidArgs
	}
	if s.scanning {
		return errors.ErrBusy
	}

	// Clamp count to [min, max].
	if count < energyMinCount {
		count = energyMinCount
	}
	if count > energyMaxCount {
		count = energyMaxCount
	}

	s.channelMask = channelMask
	s.channelMaskCurrent = channelMask
	s.count = count
	s.period = period
	s.scanDuration = scanDuration
	s.results = nil
	s.scanning = true
	s.scanCount = 0
	s.currentChan = lowestChannel(s.channelMaskCurrent)

	return nil
}

// HandleTimer advances the energy scan state machine. Call this periodically
// (or in response to a timer event) to drive the scanning process.
//
// The state machine mirrors OpenThread's approach: for each pass it scans the
// lowest remaining channel, records the result, clears that channel from the
// current mask, and advances. After all channels in a pass are done, the pass
// count decrements and (if passes remain) the channel mask resets for the next
// pass. When all passes are complete, the report callback is invoked.
func (s *EnergyScanServer) HandleTimer() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.scanning {
		return
	}

	if s.count == 0 {
		// All passes complete — send report.
		s.scanning = false
		s.sendReport()
		return
	}

	// Determine the lowest set channel in the current mask.
	ch := lowestChannel(s.channelMaskCurrent)
	if ch == 0 {
		// No channels left in this pass; should not happen if count > 0.
		s.scanning = false
		s.sendReport()
		return
	}
	s.currentChan = ch

	// Perform the scan on this channel.
	rssi, err := s.scanner.EnergyScan(ch, s.scanDuration)
	if err != nil {
		// On error, skip this channel.
		rssi = -128 // Use minimum RSSI as a sentinel.
	}

	s.results = append(s.results, EnergyScanResult{
		Channel: ch,
		MaxRssi: rssi,
	})
	s.scanCount++

	// Clear the lowest channel from the current mask.
	s.channelMaskCurrent &= s.channelMaskCurrent - 1

	if s.channelMaskCurrent == 0 {
		// This pass is complete — reset for next pass.
		s.channelMaskCurrent = s.channelMask
		s.count--
	}

	if s.count == 0 {
		s.scanning = false
		s.sendReport()
	}
}

// sendReport invokes the report callback if set.
// Must be called with s.mu held.
func (s *EnergyScanServer) sendReport() {
	if s.reportCb != nil {
		cb := s.reportCb
		mask := s.channelMask
		results := make([]EnergyScanResult, len(s.results))
		copy(results, s.results)
		// Release the lock before invoking the callback to prevent deadlock.
		s.mu.Unlock()
		cb(mask, results)
		s.mu.Lock()
	}
}

// IsScanning reports whether a scan is currently in progress.
func (s *EnergyScanServer) IsScanning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scanning
}

// Stop cancels any in-progress scan.
func (s *EnergyScanServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanning = false
	s.channelMaskCurrent = 0
	s.count = 0
}

// SetReportCallback sets the callback invoked when a scan completes.
// The callback receives the original channel mask and the collected results.
func (s *EnergyScanServer) SetReportCallback(cb func(uint32, []EnergyScanResult)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reportCb = cb
}

// Results returns a copy of the current scan results.
func (s *EnergyScanServer) Results() []EnergyScanResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]EnergyScanResult, len(s.results))
	copy(out, s.results)
	return out
}

// ---------------------------------------------------------------------------
// PAN ID Query Server
// ---------------------------------------------------------------------------

// PanIdScanner performs active scans to detect PAN IDs on channels.
type PanIdScanner interface { //nolint:revive // Preserve the exported API spelling for existing callers.
	// ScanForPanId scans the given channel for the specified PAN ID.
	// Returns true if the PAN ID was detected, false otherwise.
	ScanForPanId(channel uint16, panID uint16) (bool, error)
}

// PanIdQueryServer handles PAN ID query TMF requests from the Commissioner.
// It scans a set of channels for the presence of a given PAN ID and reports
// which channels have a conflict.
type PanIdQueryServer struct { //nolint:revive // Preserve the exported API spelling for existing callers.
	mu sync.Mutex

	scanner     PanIdScanner
	panID       uint16
	channelMask uint32
	scanning    bool
	currentChan uint16
	conflicts   uint32 // bitmask of channels where PAN ID was found

	reportCb func(panID uint16, channelMask uint32)
}

// NewPanIdQueryServer creates a new PanIdQueryServer with the given platform
// scanner.
func NewPanIdQueryServer(scanner PanIdScanner) *PanIdQueryServer { //nolint:revive // Preserve the exported API spelling for existing callers.
	return &PanIdQueryServer{
		scanner: scanner,
		panID:   0xffff, // broadcast PAN ID, matching OpenThread's kPanIdBroadcast
	}
}

// HandleRequest starts a PAN ID query scan across the channels specified by
// channelMask, looking for the given panID.
func (s *PanIdQueryServer) HandleRequest(panID uint16, channelMask uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if channelMask == 0 {
		return errors.ErrInvalidArgs
	}
	if s.scanning {
		return errors.ErrBusy
	}

	s.panID = panID
	s.channelMask = channelMask
	s.conflicts = 0
	s.scanning = true
	s.currentChan = lowestChannel(channelMask)

	return nil
}

// HandleTimer advances the PAN ID query state machine. Call this periodically
// to drive the scanning process.
//
// Like OpenThread's PanIdQueryServer::HandleTimer, this scans channels one at
// a time, records conflicts, and reports when all channels are done.
func (s *PanIdQueryServer) HandleTimer() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.scanning {
		return
	}

	if s.channelMask == 0 {
		// All channels scanned.
		s.scanning = false
		s.sendConflict()
		return
	}

	ch := lowestChannel(s.channelMask)
	if ch == 0 {
		s.scanning = false
		s.sendConflict()
		return
	}
	s.currentChan = ch

	found, err := s.scanner.ScanForPanId(ch, s.panID)
	if err == nil && found {
		s.conflicts |= 1 << ch
	}

	// Clear the channel we just scanned.
	s.channelMask &= s.channelMask - 1

	if s.channelMask == 0 {
		s.scanning = false
		s.sendConflict()
	}
}

// sendConflict invokes the report callback if set and conflicts were found.
// Must be called with s.mu held.
func (s *PanIdQueryServer) sendConflict() {
	if s.reportCb != nil && s.conflicts != 0 {
		cb := s.reportCb
		panID := s.panID
		conflicts := s.conflicts
		s.mu.Unlock()
		cb(panID, conflicts)
		s.mu.Lock()
	}
}

// IsScanning reports whether a query is currently in progress.
func (s *PanIdQueryServer) IsScanning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scanning
}

// Stop cancels any in-progress query.
func (s *PanIdQueryServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanning = false
	s.channelMask = 0
}

// SetReportCallback sets the callback invoked when a query completes with
// conflicts. The callback receives the queried PAN ID and a bitmask of
// channels where the PAN ID was found.
func (s *PanIdQueryServer) SetReportCallback(cb func(uint16, uint32)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reportCb = cb
}

// Conflicts returns the current conflict bitmask.
func (s *PanIdQueryServer) Conflicts() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conflicts
}

// ---------------------------------------------------------------------------
// Anycast Locator
// ---------------------------------------------------------------------------

// AnycastLocator resolves Thread anycast addresses to their RLOC16 and
// mesh-local EID. It mirrors OpenThread's AnycastLocator, using a callback
// pattern for asynchronous resolution.
type AnycastLocator struct {
	mu       sync.Mutex
	pending  bool
	callback func(err error, rloc16 uint16, meshLocalEid [16]byte)
}

// NewAnycastLocator creates a new AnycastLocator.
func NewAnycastLocator() *AnycastLocator {
	return &AnycastLocator{}
}

// Locate initiates resolution of an anycast address. The callback is invoked
// when the response is received or an error occurs. If a previous Locate
// request is still pending, it is replaced (the previous callback will not be
// invoked).
//
// Returns ErrInvalidArgs if cb is nil.
func (l *AnycastLocator) Locate(anycastAddr [16]byte, cb func(error, uint16, [16]byte)) error {
	if cb == nil {
		return errors.ErrInvalidArgs
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.pending = true
	l.callback = cb

	return nil
}

// HandleResponse delivers a successful resolution result. It invokes and
// clears the pending callback with a nil error.
func (l *AnycastLocator) HandleResponse(rloc16 uint16, meshLocalEid [16]byte) {
	l.mu.Lock()
	cb := l.callback
	if !l.pending {
		l.mu.Unlock()
		return
	}
	l.pending = false
	l.callback = nil
	l.mu.Unlock()

	if cb != nil {
		cb(nil, rloc16, meshLocalEid)
	}
}

// HandleError delivers an error result. It invokes and clears the pending
// callback with the given error and zero values.
func (l *AnycastLocator) HandleError(err error) {
	l.mu.Lock()
	cb := l.callback
	if !l.pending {
		l.mu.Unlock()
		return
	}
	l.pending = false
	l.callback = nil
	l.mu.Unlock()

	if cb != nil {
		cb(err, 0, [16]byte{})
	}
}

// IsInProgress reports whether a Locate request is pending.
func (l *AnycastLocator) IsInProgress() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pending
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// lowestChannel extracts the lowest set bit position from a channel bitmask,
// returning the channel number (e.g. 11-26). Returns 0 if the mask is zero.
func lowestChannel(mask uint32) uint16 {
	if mask == 0 {
		return 0
	}
	// Isolate lowest set bit and find its position.
	isolated := mask & (^mask + 1) // equivalent to mask & -mask
	var pos uint16
	for isolated >>= 1; isolated != 0; isolated >>= 1 {
		pos++
	}
	return pos
}
