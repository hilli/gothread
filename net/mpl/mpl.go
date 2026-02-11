// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package mpl implements MPL (Multicast Protocol for Low-Power and Lossy
// Networks) as defined in RFC 7731.
//
// MPL uses a Trickle-based algorithm (RFC 6206) to forward multicast messages
// efficiently in mesh networks. Each multicast message is identified by a
// (seed, sequence) pair and is retransmitted a configured number of times with
// Trickle-managed intervals.
//
// This is a Go port of the MPL forwarder in OpenThread's
// src/core/net/ip6_mpl.hpp and src/core/net/ip6_mpl.cpp.
package mpl

import (
	"math/rand/v2"

	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Sequence number comparison
// ---------------------------------------------------------------------------

// SequenceGreater returns true if a > b accounting for uint8 wraparound.
// This uses signed comparison of the difference, matching the serial number
// arithmetic defined in RFC 1982 (for 8-bit sequence space).
func SequenceGreater(a, b uint8) bool {
	return int8(a-b) > 0
}

// ---------------------------------------------------------------------------
// Trickle Timer (RFC 6206)
// ---------------------------------------------------------------------------

// TrickleTimer implements the Trickle algorithm defined in RFC 6206.
//
// The timer maintains a current interval that doubles on each expiration
// (up to imax). A counter tracks consistent transmissions; a transmission
// is suppressed when the counter reaches the redundancy constant k.
type TrickleTimer struct {
	imin     uint32 // minimum interval (ms)
	imax     uint32 // maximum interval (ms)
	k        uint8  // redundancy constant
	interval uint32 // current interval (ms)
	time     uint32 // time within current interval to transmit (ms)
	counter  uint8  // consistency counter c
}

// NewTrickleTimer creates a TrickleTimer with the given parameters and
// initialises the interval to imin.
func NewTrickleTimer(imin, imax uint32, k uint8) *TrickleTimer {
	t := &TrickleTimer{
		imin: imin,
		imax: imax,
		k:    k,
	}
	t.Reset()
	return t
}

// Reset sets the interval back to imin, resets the counter, and picks a
// new random transmit time in [interval/2, interval).
func (t *TrickleTimer) Reset() {
	t.interval = t.imin
	t.counter = 0
	t.pickTransmitTime()
}

// IndicateConsistent increments the consistency counter.
func (t *TrickleTimer) IndicateConsistent() {
	if t.counter < 255 {
		t.counter++
	}
}

// IndicateInconsistent resets the timer to imin (same as Reset).
func (t *TrickleTimer) IndicateInconsistent() {
	t.Reset()
}

// ShouldTransmit returns true if the counter c is less than k, meaning
// the message should be transmitted at the scheduled time.
func (t *TrickleTimer) ShouldTransmit() bool {
	return t.counter < t.k
}

// IntervalExpired doubles the current interval (capped at imax), resets
// the counter, and picks a new transmit time. It returns t for chaining.
func (t *TrickleTimer) IntervalExpired() *TrickleTimer {
	t.interval *= 2
	if t.interval > t.imax {
		t.interval = t.imax
	}
	t.counter = 0
	t.pickTransmitTime()
	return t
}

// GetInterval returns the current interval in milliseconds.
func (t *TrickleTimer) GetInterval() uint32 {
	return t.interval
}

// pickTransmitTime selects a random time t in [interval/2, interval).
func (t *TrickleTimer) pickTransmitTime() {
	half := t.interval / 2
	if half == 0 {
		t.time = 0
		return
	}
	t.time = half + uint32(rand.IntN(int(half)))
}

// ---------------------------------------------------------------------------
// Seed Entry
// ---------------------------------------------------------------------------

// SeedEntry tracks the most recent sequence number from a specific seed
// (source) and the remaining lifetime of the entry.
type SeedEntry struct {
	SeedID   uint16 // seed identifier
	Sequence uint8  // most recent sequence number
	Lifetime uint32 // remaining lifetime (ms)
}

// ---------------------------------------------------------------------------
// Buffered Message
// ---------------------------------------------------------------------------

// BufferedMessage is a multicast message being forwarded via MPL.
type BufferedMessage struct {
	SeedID     uint16       // originating seed
	Sequence   uint8        // MPL sequence number
	Payload    []byte       // the multicast message payload
	Trickle    TrickleTimer // per-message Trickle timer
	TxCount    uint8        // number of times transmitted
	MaxTxCount uint8        // max transmissions allowed
}

// ---------------------------------------------------------------------------
// MessageSender interface
// ---------------------------------------------------------------------------

// MessageSender is the interface used by the Forwarder to transmit multicast
// messages over the network.
type MessageSender interface {
	SendMulticast(payload []byte) error
}

// ---------------------------------------------------------------------------
// Option — functional options for Forwarder
// ---------------------------------------------------------------------------

// Option configures the Forwarder.
type Option func(*Forwarder)

// WithMaxMessages sets the maximum number of buffered messages.
func WithMaxMessages(n int) Option {
	return func(f *Forwarder) { f.maxMessages = n }
}

// WithMaxSeeds sets the maximum number of seed entries.
func WithMaxSeeds(n int) Option {
	return func(f *Forwarder) { f.maxSeeds = n }
}

// WithSeedLifetime sets the seed entry lifetime in milliseconds.
func WithSeedLifetime(ms uint32) Option {
	return func(f *Forwarder) { f.seedLifetime = ms }
}

// WithTimePeriod sets the Trickle imin parameter in milliseconds.
func WithTimePeriod(ms uint32) Option {
	return func(f *Forwarder) { f.timePeriod = ms }
}

// WithExpirationTime sets the Trickle imax parameter in milliseconds.
func WithExpirationTime(ms uint32) Option {
	return func(f *Forwarder) { f.expirationTime = ms }
}

// WithKConstant sets the Trickle redundancy constant k.
func WithKConstant(k uint8) Option {
	return func(f *Forwarder) { f.kConstant = k }
}

// WithMaxTxCount sets the maximum number of retransmissions.
func WithMaxTxCount(n uint8) Option {
	return func(f *Forwarder) { f.maxTxCount = n }
}

// ---------------------------------------------------------------------------
// Forwarder
// ---------------------------------------------------------------------------

// Default configuration values.
const (
	DefaultMaxMessages    = 8
	DefaultMaxSeeds       = 32
	DefaultSeedLifetime   = 300000 // 5 minutes in ms
	DefaultTimePeriod     = 10     // Trickle imin (ms)
	DefaultExpirationTime = 600    // Trickle imax (ms)
	DefaultKConstant      = 1
	DefaultMaxTxCount     = 3
)

// Forwarder manages MPL message forwarding using Trickle timers.
type Forwarder struct {
	seeds    []SeedEntry
	messages []BufferedMessage

	maxMessages int
	maxSeeds    int
	sender      MessageSender

	// MPL parameters
	seedLifetime   uint32 // seed entry lifetime (ms)
	timePeriod     uint32 // Trickle imin (ms)
	expirationTime uint32 // Trickle imax (ms)
	kConstant      uint8  // Trickle k
	maxTxCount     uint8  // max retransmissions

	localSeedID   uint16 // this node's seed ID
	localSequence uint8  // next sequence number for local messages
}

// NewForwarder creates an MPL Forwarder with the given sender and local seed
// ID. Functional options may override the defaults.
func NewForwarder(sender MessageSender, localSeedID uint16, opts ...Option) *Forwarder {
	f := &Forwarder{
		maxMessages:    DefaultMaxMessages,
		maxSeeds:       DefaultMaxSeeds,
		sender:         sender,
		seedLifetime:   DefaultSeedLifetime,
		timePeriod:     DefaultTimePeriod,
		expirationTime: DefaultExpirationTime,
		kConstant:      DefaultKConstant,
		maxTxCount:     DefaultMaxTxCount,
		localSeedID:    localSeedID,
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// ProcessMessage handles an incoming MPL multicast message identified by
// (seedID, sequence). It returns true if the message is new and should be
// delivered to upper layers.
//
// Behaviour:
//  1. If the seed is unknown and there is capacity, a new seed entry is
//     created and the message is buffered for retransmission.
//  2. If the seed is known and the sequence is newer (SequenceGreater),
//     the seed entry is updated and the message is buffered.
//  3. If the sequence is not new (duplicate or older), the Trickle timer
//     of the matching buffered message (if any) is marked consistent, and
//     the message is suppressed.
func (f *Forwarder) ProcessMessage(seedID uint16, sequence uint8, payload []byte) bool {
	// Look up existing seed entry.
	seedIdx := f.findSeed(seedID)

	if seedIdx >= 0 {
		// Seed exists — check whether the sequence is new.
		seed := &f.seeds[seedIdx]

		if sequence == seed.Sequence || !SequenceGreater(sequence, seed.Sequence) {
			// Duplicate or older — indicate consistent on matching buffered message.
			for i := range f.messages {
				if f.messages[i].SeedID == seedID && f.messages[i].Sequence == sequence {
					f.messages[i].Trickle.IndicateConsistent()
				}
			}
			return false
		}

		// New sequence from known seed.
		seed.Sequence = sequence
		seed.Lifetime = f.seedLifetime
		f.bufferMessage(seedID, sequence, payload)
		return true
	}

	// Unknown seed — try to add a new entry.
	if len(f.seeds) >= f.maxSeeds {
		// No room for new seed; drop message.
		return false
	}

	f.seeds = append(f.seeds, SeedEntry{
		SeedID:   seedID,
		Sequence: sequence,
		Lifetime: f.seedLifetime,
	})
	f.bufferMessage(seedID, sequence, payload)
	return true
}

// SendMessage originates a new multicast message from this node. It assigns
// the next local sequence number, buffers the message for Trickle-based
// retransmission, and sends the first copy immediately.
func (f *Forwarder) SendMessage(payload []byte) error {
	if f.sender == nil {
		return errors.ErrFailed
	}

	seq := f.localSequence
	f.localSequence++

	// Ensure our own seed entry exists.
	seedIdx := f.findSeed(f.localSeedID)
	if seedIdx >= 0 {
		f.seeds[seedIdx].Sequence = seq
		f.seeds[seedIdx].Lifetime = f.seedLifetime
	} else {
		if len(f.seeds) >= f.maxSeeds {
			return errors.ErrNoBufs
		}
		f.seeds = append(f.seeds, SeedEntry{
			SeedID:   f.localSeedID,
			Sequence: seq,
			Lifetime: f.seedLifetime,
		})
	}

	// Buffer the message.
	if len(f.messages) >= f.maxMessages {
		return errors.ErrNoBufs
	}

	buf := make([]byte, len(payload))
	copy(buf, payload)

	msg := BufferedMessage{
		SeedID:     f.localSeedID,
		Sequence:   seq,
		Payload:    buf,
		Trickle:    *NewTrickleTimer(f.timePeriod, f.expirationTime, f.kConstant),
		TxCount:    1, // first transmission counted immediately
		MaxTxCount: f.maxTxCount,
	}
	f.messages = append(f.messages, msg)

	// Transmit immediately.
	return f.sender.SendMulticast(buf)
}

// HandleTimer should be called periodically to process Trickle timers. It
// performs the following for each buffered message:
//   - If ShouldTransmit() is true, retransmit the message and increment
//     TxCount.
//   - Call IntervalExpired() to advance the Trickle timer.
//   - If TxCount >= MaxTxCount, remove the buffered message.
//
// It also decrements seed entry lifetimes. If a seed's lifetime reaches
// zero the entry is removed.
func (f *Forwarder) HandleTimer() {
	// Process buffered messages.
	n := 0
	for i := range f.messages {
		msg := &f.messages[i]

		if msg.Trickle.ShouldTransmit() && f.sender != nil {
			_ = f.sender.SendMulticast(msg.Payload)
			msg.TxCount++
		}

		msg.Trickle.IntervalExpired()

		if msg.TxCount >= msg.MaxTxCount {
			// Remove this message (don't keep it).
			continue
		}
		f.messages[n] = f.messages[i]
		n++
	}
	f.messages = f.messages[:n]

	// Expire seed entries.
	n = 0
	for i := range f.seeds {
		if f.seeds[i].Lifetime > 0 {
			f.seeds[i].Lifetime--
		}
		if f.seeds[i].Lifetime > 0 {
			f.seeds[n] = f.seeds[i]
			n++
		}
	}
	f.seeds = f.seeds[:n]
}

// GetSeedEntryCount returns the number of active seed entries.
func (f *Forwarder) GetSeedEntryCount() int {
	return len(f.seeds)
}

// GetBufferedMessageCount returns the number of buffered messages awaiting
// retransmission.
func (f *Forwarder) GetBufferedMessageCount() int {
	return len(f.messages)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// findSeed returns the index of the seed entry with the given seedID, or -1 if
// not found.
func (f *Forwarder) findSeed(seedID uint16) int {
	for i := range f.seeds {
		if f.seeds[i].SeedID == seedID {
			return i
		}
	}
	return -1
}

// bufferMessage adds a message to the retransmission buffer. If the buffer is
// full the oldest entry is evicted.
func (f *Forwarder) bufferMessage(seedID uint16, sequence uint8, payload []byte) {
	buf := make([]byte, len(payload))
	copy(buf, payload)

	msg := BufferedMessage{
		SeedID:     seedID,
		Sequence:   sequence,
		Payload:    buf,
		Trickle:    *NewTrickleTimer(f.timePeriod, f.expirationTime, f.kConstant),
		TxCount:    0,
		MaxTxCount: f.maxTxCount,
	}

	if len(f.messages) >= f.maxMessages {
		// Evict oldest buffered message.
		f.messages = f.messages[1:]
	}
	f.messages = append(f.messages, msg)
}
