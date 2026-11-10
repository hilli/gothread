// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package discover implements bounded MLE discovery, not network attachment.
package discover

import (
	"errors"
	"sync"
	"unicode/utf8"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/meshcop"
)

const (
	// ChannelMin and ChannelMax bound the supported 2.4GHz channel numbers.
	ChannelMin uint16 = 11
	// ChannelMax is the highest supported 2.4GHz channel.
	ChannelMax uint16 = 26
	// DefaultScanDuration is milliseconds per channel.
	DefaultScanDuration uint32 = 300
	// PanIDBroadcast disables the PAN filter.
	PanIDBroadcast uint16 = 0xffff
	// MaxNetworkNameLen is the protocol byte bound.
	MaxNetworkNameLen = 16
	// MaxScanResults bounds retained unique channel/PAN/responder tuples.
	MaxScanResults = 16
)

type state uint8

const (
	stateIdle state = iota
	stateScanning
	stateScanDone
)

// ScanResult describes an observed, unauthenticated network advertisement.
type ScanResult struct {
	ExtPanID      [8]byte
	NetworkName   string
	SteeringData  []byte
	PanID         uint16
	JoinerUDPPort uint16
	Channel       uint16
	RSSI          int8
	LQI           uint8
	Version       uint8
	IsNative      bool
	IsJoinable    bool
	ExtAddress    [8]byte
}

// ScanHandler receives owned results; nil means terminal, not necessarily
// success. Legacy callers read Err for the terminal cause.
type ScanHandler func(*ScanResult)

// ScanOutcome owns bounded results, including explicitly partial error outcomes.
type ScanOutcome struct {
	ID      uint64
	Results []ScanResult
	Err     error
}

// DiscoverySender sends a real request and reports admission failure.
type DiscoverySender interface {
	SendDiscoveryRequest(channel uint16, panID uint16, joinerFlag bool) error
}

// Timer is a bounded one-shot per-channel timer.
type Timer interface {
	Start(delayMs uint32)
	Stop()
	IsRunning() bool
}

// IdentityTimer preserves event identity when canceled callbacks arrive late.
type IdentityTimer interface {
	StartFor(delayMs uint32, id uint64)
	StopFor(id uint64)
}

// DiscoveryCleanup releases the sender's actual radio ownership. A failure
// retains scanner ownership until RetryCleanup succeeds.
type DiscoveryCleanup interface{ FinishDiscovery(id uint64) error }

// Option configures a scanner before use.
type Option func(*Scanner)

// WithScanDuration sets milliseconds per channel.
func WithScanDuration(ms uint32) Option {
	return func(s *Scanner) {
		if ms > 0 {
			s.scanDuration = ms
		}
	}
}

// WithFilterExtPanID selects an advertised extended PAN ID.
func WithFilterExtPanID(id [8]byte) Option {
	return func(s *Scanner) { s.filterByExtPanID, s.extPanIDFilter = true, id }
}

// WithFilterIndexes selects steering-data Bloom filter indexes.
func WithFilterIndexes(indexes meshcop.HashBitIndexes) Option {
	return func(s *Scanner) { s.enableFiltering, s.filterIndexes = true, indexes }
}

// Scanner retains at most MaxScanResults owned advertisements.
type Scanner struct {
	mu               sync.Mutex
	channelMask      uint32
	panID            uint16
	scanDuration     uint32
	joinerFlag       bool
	filterByExtPanID bool
	extPanIDFilter   [8]byte
	enableFiltering  bool
	filterIndexes    meshcop.HashBitIndexes
	state            state
	currentChannel   uint16
	results          []ScanResult
	handler          ScanHandler
	complete         func(ScanOutcome)
	sender           DiscoverySender
	timer            Timer
	id               uint64
	strict           bool
	lastErr          error
	cleaning         bool
}

// NewScanner binds a sender/timer; missing backends are refused at admission.
func NewScanner(sender DiscoverySender, timer Timer, opts ...Option) *Scanner {
	s := &Scanner{sender: sender, timer: timer, scanDuration: DefaultScanDuration, panID: PanIDBroadcast}
	for _, option := range opts {
		option(s)
	}
	return s
}

// Discover preserves the legacy callback signature. Initial send failure now
// releases ownership and reports both the returned cause and terminal callback.
func (s *Scanner) Discover(mask uint32, pan uint16, joiner bool, handler ScanHandler) error {
	if handler == nil {
		return goterrors.ErrInvalidArgs
	}
	_, err := s.start(mask, pan, joiner, handler, nil, false)
	return err
}

// DiscoverBounded additionally checks real tuple metadata and supplies a typed
// terminal cause exactly once. Invalid admission returns no session/callback.
func (s *Scanner) DiscoverBounded(mask uint32, pan uint16, joiner bool, handler ScanHandler, complete func(ScanOutcome)) (uint64, error) {
	if complete == nil {
		return 0, goterrors.ErrInvalidArgs
	}
	return s.start(mask, pan, joiner, handler, complete, true)
}

func (s *Scanner) start(mask uint32, pan uint16, joiner bool, handler ScanHandler, complete func(ScanOutcome), strict bool) (uint64, error) {
	s.mu.Lock()
	if s.state != stateIdle {
		s.mu.Unlock()
		return 0, goterrors.ErrBusy
	}
	if s.sender == nil || s.timer == nil {
		s.mu.Unlock()
		return 0, goterrors.ErrNotCapable
	}
	if strict && (s.scanDuration == 0 || s.scanDuration > 1000) {
		s.mu.Unlock()
		return 0, goterrors.ErrInvalidArgs
	}
	if s.id == ^uint64(0) {
		s.mu.Unlock()
		return 0, goterrors.ErrNoBufs
	}
	const channels = uint32(0x07fff800)
	if mask == 0 {
		mask = channels
	}
	if strict && (mask&^channels != 0 || mask&channels == 0) {
		s.mu.Unlock()
		return 0, goterrors.ErrInvalidArgs
	}
	if !strict {
		mask &= channels
	}
	s.id++
	id := s.id
	s.channelMask, s.panID, s.joinerFlag = mask, pan, joiner
	s.handler, s.complete, s.strict = handler, complete, strict
	s.results, s.lastErr = nil, nil
	if mask == 0 {
		s.currentChannel = 0
		s.mu.Unlock()
		handler(nil)
		return id, nil
	}
	s.currentChannel, _ = s.nextChannel(ChannelMin - 1)
	s.state = stateScanning
	s.mu.Unlock()
	err := s.send(id)
	return id, err
}

// IsScanning includes failed restoration whose ownership is still retained.
func (s *Scanner) IsScanning() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.state != stateIdle }

// Identity is the current monotonic component lifetime, not network authority.
func (s *Scanner) Identity() uint64 { s.mu.Lock(); defer s.mu.Unlock(); return s.id }

// Err reports the last terminal cause, including initial/later sender failure.
func (s *Scanner) Err() error { s.mu.Lock(); defer s.mu.Unlock(); return s.lastErr }

// CurrentChannel is zero when no channel is actively being scanned.
func (s *Scanner) CurrentChannel() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != stateScanning {
		return 0
	}
	return s.currentChannel
}

// Results deep-copies all retained advertisement payloads.
func (s *Scanner) Results() []ScanResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneResults(s.results)
}

func cloneResult(result ScanResult) ScanResult {
	result.SteeringData = append([]byte(nil), result.SteeringData...)
	return result
}
func cloneResults(results []ScanResult) []ScanResult {
	if len(results) == 0 {
		return nil
	}
	out := make([]ScanResult, len(results))
	for i := range results {
		out[i] = cloneResult(results[i])
	}
	return out
}

// Stop aborts the current legacy scan; nil callback means terminal, not success.
func (s *Scanner) Stop() { s.Cancel(s.Identity(), goterrors.ErrAbort) }

// Cancel only affects its named lifetime.
func (s *Scanner) Cancel(id uint64, cause error) {
	if cause == nil {
		cause = goterrors.ErrAbort
	}
	s.finish(id, cause)
}

// Fail terminates the named lifetime with an actual backend/receive cause.
func (s *Scanner) Fail(id uint64, cause error) {
	if cause != nil {
		s.finish(id, cause)
	}
}

// HandleScanComplete preserves the legacy hook; typed scans cannot use it to
// manufacture successful completion before actual channel timers.
func (s *Scanner) HandleScanComplete() {
	s.mu.Lock()
	id, strict := s.id, s.strict
	s.mu.Unlock()
	if strict {
		s.finish(id, goterrors.ErrAbort)
	} else {
		s.finish(id, nil)
	}
}

// HandleTimer is the legacy timer hook.
func (s *Scanner) HandleTimer() { s.HandleTimerFor(s.Identity()) }

// HandleTimerFor ignores timers from superseded scans.
func (s *Scanner) HandleTimerFor(id uint64) {
	s.mu.Lock()
	if id != s.id || s.state != stateScanning {
		s.mu.Unlock()
		return
	}
	channel, more := s.nextChannel(s.currentChannel)
	if more {
		s.currentChannel = channel
	}
	s.mu.Unlock()
	if !more {
		s.finish(id, nil)
		return
	}
	_ = s.send(id) // send reports its exact cause through finish.
}

func (s *Scanner) send(id uint64) error {
	s.mu.Lock()
	if s.id != id || s.state != stateScanning {
		s.mu.Unlock()
		return goterrors.ErrAbort
	}
	channel, pan, joiner, duration := s.currentChannel, s.panID, s.joinerFlag, s.scanDuration
	s.mu.Unlock()
	if err := s.sender.SendDiscoveryRequest(channel, pan, joiner); err != nil {
		s.finish(id, err)
		return err
	}
	s.mu.Lock()
	current := s.id == id && s.state == stateScanning && s.currentChannel == channel
	s.mu.Unlock()
	if current {
		if timer, ok := s.timer.(IdentityTimer); ok {
			timer.StartFor(duration, id)
		} else {
			s.timer.Start(duration)
		}
	}
	return nil
}

// HandleDiscoveryResponse is the legacy delivery hook.
func (s *Scanner) HandleDiscoveryResponse(result *ScanResult) {
	s.mu.Lock()
	id, strict := s.id, s.strict
	s.mu.Unlock()
	if strict {
		return
	} // Typed native delivery must carry admitted link identity.
	s.HandleDiscoveryResponseFor(id, result)
}

// HandleDiscoveryResponseFor binds delivery to the admitted scan identity.
func (s *Scanner) HandleDiscoveryResponseFor(id uint64, result *ScanResult) {
	if result == nil {
		return
	}
	s.mu.Lock()
	if id != s.id || s.state != stateScanning {
		s.mu.Unlock()
		return
	}
	if len(result.NetworkName) > MaxNetworkNameLen || !utf8.ValidString(result.NetworkName) ||
		len(result.SteeringData) > meshcop.SteeringDataMaxLength ||
		s.strict && (result.Channel != s.currentChannel || result.PanID == PanIDBroadcast ||
			result.ExtAddress == ([8]byte{}) || result.ExtAddress[0]&1 != 0 || result.Version == 0 || result.Version > 15) {
		s.mu.Unlock()
		s.finish(id, goterrors.ErrParse)
		return
	}
	if s.filterByExtPanID && result.ExtPanID != s.extPanIDFilter {
		s.mu.Unlock()
		return
	}
	if s.strict && s.panID != PanIDBroadcast && result.PanID != s.panID {
		s.mu.Unlock()
		return
	}
	owned := cloneResult(*result)
	if len(owned.SteeringData) > 0 {
		var data meshcop.SteeringData
		if err := data.InitWithData(uint8(len(owned.SteeringData)), owned.SteeringData); err != nil {
			s.mu.Unlock()
			s.finish(id, err)
			return
		}
		owned.IsJoinable = !data.IsEmpty()
		if s.enableFiltering && !data.ContainsIndexes(s.filterIndexes) {
			s.mu.Unlock()
			return
		}
	} else if s.enableFiltering {
		s.mu.Unlock()
		return
	}
	index := -1
	for i := range s.results {
		other := &s.results[i]
		if other.ExtAddress == owned.ExtAddress && other.Channel == owned.Channel && other.PanID == owned.PanID &&
			other.ExtPanID == owned.ExtPanID {
			index = i
			break
		}
	}
	if index < 0 {
		if len(s.results) == MaxScanResults {
			s.mu.Unlock()
			s.finish(id, goterrors.ErrNoBufs)
			return
		}
		s.results = append(s.results, owned)
	} else {
		s.results[index] = owned
	}
	handler := s.handler
	delivery := cloneResult(owned)
	s.mu.Unlock()
	if handler != nil {
		handler(&delivery)
	}
}

func (s *Scanner) finish(id uint64, cause error) {
	s.mu.Lock()
	if s.id != id || s.state != stateScanning {
		s.mu.Unlock()
		return
	}
	s.state = stateScanDone
	s.cleaning = true
	s.mu.Unlock()
	if timer, ok := s.timer.(IdentityTimer); ok {
		timer.StopFor(id)
	} else {
		s.timer.Stop()
	}
	var cleanup error
	if sender, ok := s.sender.(DiscoveryCleanup); ok {
		cleanup = sender.FinishDiscovery(id)
	}
	s.mu.Lock()
	s.lastErr = errors.Join(cause, cleanup)
	s.cleaning = false
	outcome := ScanOutcome{ID: id, Results: cloneResults(s.results), Err: s.lastErr}
	handler, complete := s.handler, s.complete
	s.handler, s.complete = nil, nil
	if cleanup == nil {
		s.state = stateIdle
	}
	s.mu.Unlock()
	if complete != nil {
		complete(outcome)
	}
	if handler != nil {
		handler(nil)
	}
}

// RetryCleanup never repeats terminal callbacks or discards the original cause.
func (s *Scanner) RetryCleanup(id uint64) error {
	s.mu.Lock()
	if s.id != id || s.state != stateScanDone {
		s.mu.Unlock()
		return goterrors.ErrInvalidState
	}
	if s.cleaning {
		s.mu.Unlock()
		return goterrors.ErrBusy
	}
	s.cleaning = true
	s.mu.Unlock()
	sender, ok := s.sender.(DiscoveryCleanup)
	if !ok {
		s.mu.Lock()
		s.cleaning = false
		s.mu.Unlock()
		return goterrors.ErrNotCapable
	}
	err := sender.FinishDiscovery(id)
	s.mu.Lock()
	s.cleaning = false
	if s.id == id && s.state == stateScanDone && err == nil {
		s.state = stateIdle
	}
	s.mu.Unlock()
	return err
}

func (s *Scanner) nextChannel(after uint16) (uint16, bool) {
	for channel := after + 1; channel <= ChannelMax; channel++ {
		if s.channelMask&(1<<channel) != 0 {
			return channel, true
		}
	}
	return 0, false
}
