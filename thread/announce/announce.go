// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package announce implements the Announce Sender and Announce Begin Server
// components of the Thread protocol.
//
// The Announce Sender periodically transmits MLE Announce messages across a
// set of channels to resolve channel/PAN ID conflicts. The Announce Begin
// Server handles TMF Announce Begin requests from the Commissioner to trigger
// announcement floods.
//
// This is a Go port of the logic in OpenThread's
// src/core/thread/announce_sender.{hpp,cpp} and
// src/core/thread/announce_begin_server.{hpp,cpp}.
package announce

import (
	"math/rand/v2"
	"sync"

	"github.com/hilli/gothread/errors"
)

// IEEE 802.15.4 channel range for Thread.
const (
	ChannelMin = 11 // Lowest 802.15.4 channel
	ChannelMax = 26 // Highest 802.15.4 channel
)

// Default values matching OpenThread's announce_begin_server.hpp.
const (
	DefaultPeriod uint32 = 1000 // Default period between announcements (ms)
	DefaultJitter uint16 = 500  // Default jitter (ms)
	DefaultCount  uint8  = 0    // 0 means infinite
)

// channelIteratorFirst is a sentinel indicating "start from the first channel
// in the mask". This mirrors OpenThread's kChannelIteratorFirst.
const channelIteratorFirst uint8 = 0

// MessageSender is the interface for transmitting MLE Announce messages.
type MessageSender interface {
	// SendAnnounce transmits an MLE Announce message on the given channel.
	// If orphanAnnounce is true, the message is sent as an orphan announce.
	SendAnnounce(channel uint16, orphanAnnounce bool) error
}

// Timer is the interface for scheduling delayed callbacks.
type Timer interface {
	// Start schedules a timer to fire after delay milliseconds.
	Start(delay uint32)
	// Stop cancels a pending timer.
	Stop()
	// IsRunning reports whether the timer is currently pending.
	IsRunning() bool
}

// RandFunc returns a random uint32 in [0, n). Used for jitter computation.
// If nil, math/rand/v2 is used.
type RandFunc func(n uint32) uint32

// ---------------------------------------------------------------------------
// AnnounceSender
// ---------------------------------------------------------------------------

// AnnounceSender manages periodic MLE Announcement transmission across a set
// of channels. It mirrors the AnnounceSenderBase from OpenThread.
type AnnounceSender struct {
	mu sync.Mutex

	channelMask     uint32 // bitmask of channels to announce on
	period          uint32 // interval between announcements (ms)
	jitter          uint16 // random jitter (ms)
	count           uint8  // remaining announcement rounds (0 = infinite)
	channel         uint8  // current channel being announced
	startingChannel uint8  // first channel in each cycle

	sender MessageSender
	timer  Timer
	rand   RandFunc
}

// Option configures an AnnounceSender.
type Option func(*AnnounceSender)

// WithPeriod sets the interval between successive announcements (ms).
func WithPeriod(ms uint32) Option {
	return func(a *AnnounceSender) { a.period = ms }
}

// WithJitter sets the random jitter applied to each period (ms).
func WithJitter(ms uint16) Option {
	return func(a *AnnounceSender) { a.jitter = ms }
}

// WithCount sets the number of announcement cycles. 0 means infinite.
func WithCount(n uint8) Option {
	return func(a *AnnounceSender) { a.count = n }
}

// WithRandFunc sets a custom random function for deterministic testing.
func WithRandFunc(fn RandFunc) Option {
	return func(a *AnnounceSender) { a.rand = fn }
}

// NewAnnounceSender creates a new AnnounceSender with the given message sender
// and timer, configured with functional options.
func NewAnnounceSender(sender MessageSender, timer Timer, opts ...Option) *AnnounceSender {
	a := &AnnounceSender{
		period:          DefaultPeriod,
		jitter:          DefaultJitter,
		count:           DefaultCount,
		startingChannel: channelIteratorFirst,
		sender:          sender,
		timer:           timer,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// SendAnnounce starts or extends an announcement sequence on the configured
// channel mask. aCount specifies the number of full cycles to transmit. If a
// transmission is already in progress, aCount cycles are added.
func (a *AnnounceSender) SendAnnounce(aCount uint8) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.timer.IsRunning() {
		// Already running — add cycles.
		a.count = addCount(a.count, aCount)
		return
	}

	if a.period == 0 || channelMaskIsEmpty(a.channelMask) {
		return
	}

	a.selectStartingChannel()
	a.count = aCount
	a.channel = a.startingChannel

	// First transmission happens after a random delay in [0, jitter].
	delay := a.randN(uint32(a.jitter) + 1)
	a.timer.Start(delay)
}

// Stop cancels any ongoing announcement sequence.
func (a *AnnounceSender) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stop()
}

func (a *AnnounceSender) stop() {
	a.timer.Stop()
	a.count = 0
}

// HandleTimer must be called when the timer fires. It sends the next
// announcement and advances to the next channel.
func (a *AnnounceSender) HandleTimer() {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Send announce on current channel.
	_ = a.sender.SendAnnounce(uint16(a.channel), false)

	// Advance to the next channel in the mask. Wrap around if needed.
	a.channel = nextChannelInMask(a.channelMask, a.channel)

	// If we've wrapped back to the starting channel, one cycle is complete.
	if a.channel == a.startingChannel && a.count != 0 {
		a.count--
		if a.count == 0 {
			// All cycles done.
			return
		}
	}

	// Schedule next transmission.
	delay := addJitter(a.period, a.jitter, a.randN)
	a.timer.Start(delay)
}

// SetChannelMask updates the channel mask. If the mask becomes empty, the
// sender is stopped. The starting channel is revalidated.
func (a *AnnounceSender) SetChannelMask(mask uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.channelMask = mask

	if channelMaskIsEmpty(a.channelMask) {
		a.stop()
		return
	}

	a.selectStartingChannel()
}

// GetChannelMask returns the current channel mask.
func (a *AnnounceSender) GetChannelMask() uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.channelMask
}

// IsRunning reports whether an announcement sequence is in progress.
func (a *AnnounceSender) IsRunning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.timer.IsRunning()
}

// SetJitter updates the jitter value (ms).
func (a *AnnounceSender) SetJitter(jitter uint16) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.jitter = jitter
}

// GetJitter returns the current jitter value (ms).
func (a *AnnounceSender) GetJitter() uint16 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.jitter
}

// SetPeriod updates the period between announcements (ms).
func (a *AnnounceSender) SetPeriod(period uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.period = period
}

// GetPeriod returns the current period (ms).
func (a *AnnounceSender) GetPeriod() uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.period
}

// SetStartingChannel sets the first channel in each announcement cycle.
// If the channel is not in the mask, the first channel in the mask is used.
func (a *AnnounceSender) SetStartingChannel(ch uint8) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.startingChannel = ch
	a.selectStartingChannel()
}

// GetStartingChannel returns the current starting channel.
func (a *AnnounceSender) GetStartingChannel() uint8 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.startingChannel
}

// GetCount returns the remaining cycle count.
func (a *AnnounceSender) GetCount() uint8 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.count
}

// selectStartingChannel validates that the starting channel is in the mask;
// if not, it resets to the first channel in the mask. Must be called with
// mu held.
func (a *AnnounceSender) selectStartingChannel() {
	if channelMaskIsEmpty(a.channelMask) {
		return
	}

	if a.startingChannel == channelIteratorFirst || !channelMaskContains(a.channelMask, a.startingChannel) {
		a.startingChannel = firstChannelInMask(a.channelMask)
	}
}

// randN returns a random uint32 in [0, n). Uses the configured RandFunc or
// falls back to math/rand/v2.
func (a *AnnounceSender) randN(n uint32) uint32 {
	if n == 0 {
		return 0
	}
	if a.rand != nil {
		return a.rand(n)
	}
	return rand.Uint32N(n)
}

// ---------------------------------------------------------------------------
// AnnounceBeginServer
// ---------------------------------------------------------------------------

// AnnounceBeginServer handles TMF Announce Begin requests from the
// Commissioner to trigger announcement floods. It mirrors OpenThread's
// AnnounceBeginServer.
type AnnounceBeginServer struct {
	sender *AnnounceSender
}

// Default values for AnnounceBeginServer, matching OpenThread's defaults.
const (
	BeginDefaultCount  uint8  = 3
	BeginDefaultPeriod uint32 = 1000
	BeginDefaultJitter uint16 = 0
)

// NewAnnounceBeginServer creates a new AnnounceBeginServer that uses the
// given AnnounceSender for transmission.
func NewAnnounceBeginServer(sender *AnnounceSender) *AnnounceBeginServer {
	return &AnnounceBeginServer{sender: sender}
}

// HandleRequest processes an Announce Begin TMF request. It configures the
// sender with the provided parameters and starts the announcement.
func (s *AnnounceBeginServer) HandleRequest(channelMask uint32, period uint32, count uint8) error {
	if channelMaskIsEmpty(channelMask) {
		return errors.ErrInvalidArgs
	}
	if period == 0 {
		return errors.ErrInvalidArgs
	}
	if count == 0 {
		return errors.ErrInvalidArgs
	}

	s.sender.mu.Lock()
	// Stop any ongoing sequence.
	s.sender.stop()

	s.sender.channelMask = channelMask
	s.sender.period = period
	s.sender.jitter = BeginDefaultJitter
	s.sender.selectStartingChannel()
	s.sender.mu.Unlock()

	s.sender.SendAnnounce(count)
	return nil
}

// SendAnnounce is a convenience method matching the C++ API signature.
// channelMask is the raw 32-bit mask, count defaults to BeginDefaultCount,
// period defaults to BeginDefaultPeriod.
func (s *AnnounceBeginServer) SendAnnounce(channelMask uint32, count uint8, period uint32) {
	if count == 0 {
		count = BeginDefaultCount
	}
	if period == 0 {
		period = BeginDefaultPeriod
	}

	s.sender.mu.Lock()
	s.sender.stop()

	s.sender.channelMask = channelMask
	s.sender.period = period
	s.sender.jitter = BeginDefaultJitter
	s.sender.selectStartingChannel()
	s.sender.mu.Unlock()

	s.sender.SendAnnounce(count)
}

// ---------------------------------------------------------------------------
// Channel mask helpers
// ---------------------------------------------------------------------------

// channelMaskIsEmpty reports whether the mask has no channels set.
func channelMaskIsEmpty(mask uint32) bool {
	return mask == 0
}

// channelMaskContains reports whether the given channel is set in the mask.
func channelMaskContains(mask uint32, ch uint8) bool {
	if ch > 31 {
		return false
	}
	return mask&(1<<ch) != 0
}

// firstChannelInMask returns the lowest-numbered channel set in the mask.
// Returns 0 if the mask is empty (caller should check).
func firstChannelInMask(mask uint32) uint8 {
	for ch := uint8(ChannelMin); ch <= ChannelMax; ch++ {
		if mask&(1<<ch) != 0 {
			return ch
		}
	}
	// Fallback: scan all 32 bits.
	for ch := uint8(0); ch < 32; ch++ {
		if mask&(1<<ch) != 0 {
			return ch
		}
	}
	return 0
}

// nextChannelInMask returns the next channel after ch that is set in the mask.
// Wraps around to the beginning of the mask if needed.
func nextChannelInMask(mask uint32, ch uint8) uint8 {
	// Scan from ch+1 to 31.
	for next := ch + 1; next < 32; next++ {
		if mask&(1<<next) != 0 {
			return next
		}
	}
	// Wrap around: scan from 0 to ch (inclusive for full wrap).
	for next := uint8(0); next <= ch; next++ {
		if mask&(1<<next) != 0 {
			return next
		}
	}
	// Should not happen if mask is non-empty.
	return ch
}

// channelCount returns the number of channels set in the mask.
func channelCount(mask uint32) int {
	n := 0
	for mask != 0 {
		n += int(mask & 1)
		mask >>= 1
	}
	return n
}

// addJitter computes period + random(-jitter, +jitter). The result is
// clamped to a minimum of 1.
func addJitter(period uint32, jitter uint16, randFn func(uint32) uint32) uint32 {
	if jitter == 0 {
		return period
	}
	// Random value in [0, 2*jitter], then subtract jitter to get [-jitter, jitter].
	r := randFn(uint32(jitter)*2 + 1)
	val := int64(period) + int64(r) - int64(jitter)
	if val < 1 {
		val = 1
	}
	return uint32(val)
}

// addCount safely adds two uint8 counts, saturating at 255. A value of 0
// on either side is treated as "infinite" and remains 0.
func addCount(existing, additional uint8) uint8 {
	// In OpenThread, count == 0 is not used as "infinite" in base — it just
	// adds. But we follow the pattern where 0 means "infinite" for the
	// AnnounceSender's configured count.
	sum := uint16(existing) + uint16(additional)
	if sum > 255 {
		return 255
	}
	return uint8(sum)
}
