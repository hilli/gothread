// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"sync"

	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// PingConfig
// ---------------------------------------------------------------------------

// Default ping configuration values.
const (
	DefaultPingSize     uint16 = 8
	DefaultPingCount    uint16 = 1
	DefaultPingInterval uint32 = 1000 // ms
	DefaultPingTimeout  uint32 = 3000 // ms
)

// PingConfig holds ping configuration parameters.
type PingConfig struct {
	Destination       [16]byte
	Source            [16]byte // zero = auto-select
	Size              uint16   // payload size in bytes, default 8
	Count             uint16   // number of pings, 0 = infinite
	Interval          uint32   // interval between pings in ms, default 1000
	Timeout           uint32   // per-ping timeout in ms, default 3000
	HopLimit          uint8    // IPv6 hop limit, 0 = default
	AllowZeroHopLimit bool
}

// ---------------------------------------------------------------------------
// PingStatistics
// ---------------------------------------------------------------------------

// PingStatistics tracks ping results.
type PingStatistics struct {
	Sent     uint16
	Received uint16
	Lost     uint16
	MinRtt   uint32 // microseconds
	MaxRtt   uint32 // microseconds
	AvgRtt   uint32 // microseconds
	TotalRtt uint64 // microseconds (for computing average)
}

// ---------------------------------------------------------------------------
// PingReply
// ---------------------------------------------------------------------------

// PingReply represents a received echo reply.
type PingReply struct {
	Source        [16]byte
	Size          uint16
	Sequence      uint16
	HopLimit      uint8
	RoundTripTime uint32 // microseconds
}

// ---------------------------------------------------------------------------
// PingCallback
// ---------------------------------------------------------------------------

// PingCallback is called for ping events.
type PingCallback interface {
	HandleReply(reply PingReply)
	HandleDone(stats PingStatistics)
}

// ---------------------------------------------------------------------------
// IcmpSender
// ---------------------------------------------------------------------------

// IcmpSender sends ICMPv6 echo requests.
type IcmpSender interface {
	SendEchoRequest(dest, source [16]byte, payload []byte, hopLimit uint8, sequence uint16) error
}

// ---------------------------------------------------------------------------
// PingSender
// ---------------------------------------------------------------------------

// PingSender manages ping operations.
type PingSender struct {
	mu         sync.Mutex
	config     PingConfig
	stats      PingStatistics
	callback   PingCallback
	sender     IcmpSender
	active     bool
	sequence   uint16
	identifier uint16
}

// NewPingSender creates a new PingSender that uses the given IcmpSender.
func NewPingSender(sender IcmpSender) *PingSender {
	return &PingSender{
		sender: sender,
	}
}

// Start begins a ping session with the given configuration and callback.
// Returns ErrInvalidState if a session is already active, ErrInvalidArgs
// if the sender is nil, or ErrInvalidArgs if the destination is unspecified.
func (p *PingSender) Start(config PingConfig, cb PingCallback) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.active {
		return errors.ErrInvalidState
	}
	if p.sender == nil {
		return errors.ErrInvalidArgs
	}
	if cb == nil {
		return errors.ErrInvalidArgs
	}

	// Validate destination is not all zeros.
	var zero [16]byte
	if config.Destination == zero {
		return errors.ErrInvalidArgs
	}

	// Apply defaults.
	if config.Size == 0 {
		config.Size = DefaultPingSize
	}
	if config.Count == 0 {
		config.Count = DefaultPingCount
	}
	if config.Interval == 0 {
		config.Interval = DefaultPingInterval
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultPingTimeout
	}

	p.config = config
	p.callback = cb
	p.stats = PingStatistics{}
	p.sequence = 0
	p.identifier++
	p.active = true

	return nil
}

// Stop cancels the current ping session. If a callback is registered and
// at least one ping was sent, the callback receives HandleDone.
func (p *PingSender) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.active {
		return
	}

	p.active = false
	p.finishLocked()
}

// finishLocked computes final statistics and notifies the callback.
// Must be called with p.mu held.
func (p *PingSender) finishLocked() {
	p.stats.Lost = p.stats.Sent - p.stats.Received
	if p.stats.Received > 0 {
		p.stats.AvgRtt = uint32(p.stats.TotalRtt / uint64(p.stats.Received))
	}

	if p.callback != nil {
		cb := p.callback
		stats := p.stats
		// Release lock before calling back to avoid deadlocks.
		p.mu.Unlock()
		cb.HandleDone(stats)
		p.mu.Lock()
	}
}

// IsActive reports whether a ping session is in progress.
func (p *PingSender) IsActive() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.active
}

// HandleTimer sends the next ping or finishes the session when the
// count is reached. This should be called by the timer subsystem at
// the configured interval.
func (p *PingSender) HandleTimer() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.active {
		return
	}

	// Check if we have sent all requested pings.
	if p.stats.Sent >= p.config.Count {
		p.active = false
		p.finishLocked()
		return
	}

	// Build the payload.
	payload := make([]byte, p.config.Size)
	// Fill with a simple pattern for identification.
	for i := range payload {
		payload[i] = byte(i & 0xff)
	}

	seq := p.sequence
	p.sequence++

	hopLimit := p.config.HopLimit
	if hopLimit == 0 && !p.config.AllowZeroHopLimit {
		hopLimit = 64 // default hop limit
	}

	err := p.sender.SendEchoRequest(
		p.config.Destination,
		p.config.Source,
		payload,
		hopLimit,
		seq,
	)
	if err == nil {
		p.stats.Sent++
	}
}

// HandleEchoReply processes a received echo reply. The caller provides the
// source address, sequence number, hop limit, and round-trip time in
// microseconds.
func (p *PingSender) HandleEchoReply(source [16]byte, sequence uint16, hopLimit uint8, rtt uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.active {
		return
	}

	p.stats.Received++
	p.stats.TotalRtt += uint64(rtt)

	if p.stats.Received == 1 || rtt < p.stats.MinRtt {
		p.stats.MinRtt = rtt
	}
	if rtt > p.stats.MaxRtt {
		p.stats.MaxRtt = rtt
	}

	reply := PingReply{
		Source:        source,
		Size:          p.config.Size,
		Sequence:      sequence,
		HopLimit:      hopLimit,
		RoundTripTime: rtt,
	}

	if p.callback != nil {
		cb := p.callback
		p.mu.Unlock()
		cb.HandleReply(reply)
		p.mu.Lock()
	}
}

// GetStatistics returns a snapshot of the current ping statistics.
func (p *PingSender) GetStatistics() PingStatistics {
	p.mu.Lock()
	defer p.mu.Unlock()

	stats := p.stats
	stats.Lost = stats.Sent - stats.Received
	if stats.Received > 0 {
		stats.AvgRtt = uint32(stats.TotalRtt / uint64(stats.Received))
	}
	return stats
}
