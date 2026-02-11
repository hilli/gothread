// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package indirect implements the indirect transmission sender and source
// address match controller for Thread sleepy end devices.
//
// The Source Match Controller manages the radio's source address match table,
// which determines whether to set the Frame Pending bit in acknowledgments
// to data poll requests from sleepy children.
//
// The Indirect Sender manages buffering and transmission of frames destined
// for sleepy end devices. When a parent has frames for a sleepy child, it
// queues them and transmits when the child polls.
//
// This is a Go port of OpenThread's src/core/thread/indirect_sender.{hpp,cpp}
// and src/core/thread/src_match_controller.{hpp,cpp}.
package indirect

import (
	"sync"

	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// RadioSourceMatch — platform interface for the source address match table
// ---------------------------------------------------------------------------

// RadioSourceMatch is the platform interface for managing the radio's source
// address match table. The table controls the Frame Pending bit in ACKs sent
// in response to data poll requests from sleepy children.
type RadioSourceMatch interface {
	// AddShortSourceMatch adds a short address to the source match table.
	AddShortSourceMatch(shortAddr uint16) error
	// AddExtSourceMatch adds an extended address to the source match table.
	AddExtSourceMatch(extAddr [8]byte) error
	// ClearShortSourceMatch removes a short address from the source match table.
	ClearShortSourceMatch(shortAddr uint16) error
	// ClearExtSourceMatch removes an extended address from the source match table.
	ClearExtSourceMatch(extAddr [8]byte) error
	// ClearSourceMatchTable removes all entries from the source match table.
	ClearSourceMatchTable()
	// EnableSourceMatch enables or disables source address matching. When
	// disabled the radio sets the Frame Pending bit on all acknowledgments.
	EnableSourceMatch(enable bool)
}

// ---------------------------------------------------------------------------
// SourceMatchController
// ---------------------------------------------------------------------------

// SourceMatchController manages the source address match table on the radio.
//
// The source address match feature controls how the radio decides the "frame
// pending" bit for acknowledgments sent in response to data poll requests from
// sleepy children. When enabled, the radio consults the table; when disabled,
// the radio sets Frame Pending on every acknowledgment.
//
// This mirrors OpenThread's SourceMatchController.
type SourceMatchController struct {
	mu         sync.Mutex
	radio      RadioSourceMatch
	enabled    bool
	entries    map[uint16]bool  // short address -> has pending frames
	extEntries map[[8]byte]bool // ext address -> has pending frames
}

// NewSourceMatchController creates a new SourceMatchController backed by the
// given radio interface. The table is initially cleared and matching disabled.
func NewSourceMatchController(radio RadioSourceMatch) *SourceMatchController {
	c := &SourceMatchController{
		radio:      radio,
		enabled:    false,
		entries:    make(map[uint16]bool),
		extEntries: make(map[[8]byte]bool),
	}
	c.radio.ClearSourceMatchTable()
	c.radio.EnableSourceMatch(false)
	return c
}

// SetFramePending adds or removes a short address from the source match table
// depending on whether the child has frames pending. When pending is true the
// address is added so the radio will set Frame Pending in the ACK; when false
// the address is removed.
func (c *SourceMatchController) SetFramePending(shortAddr uint16, pending bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	prev, existed := c.entries[shortAddr]
	if existed && prev == pending {
		return errors.ErrAlready
	}

	if pending {
		if err := c.radio.AddShortSourceMatch(shortAddr); err != nil {
			// If we cannot add the entry, disable source matching so the
			// radio sets Frame Pending on all ACKs (safe fallback).
			c.setEnabled(false)
			c.entries[shortAddr] = true
			return nil
		}
		c.entries[shortAddr] = true
		c.enableIfAllResolved()
	} else {
		if existed {
			if err := c.radio.ClearShortSourceMatch(shortAddr); err != nil {
				// Best-effort removal; drop the tracking entry regardless.
				delete(c.entries, shortAddr)
				return err
			}
		}
		delete(c.entries, shortAddr)
		c.enableIfAllResolved()
	}
	return nil
}

// SetFramePendingExt adds or removes an extended address from the source match
// table. Semantics are the same as SetFramePending.
func (c *SourceMatchController) SetFramePendingExt(extAddr [8]byte, pending bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	prev, existed := c.extEntries[extAddr]
	if existed && prev == pending {
		return errors.ErrAlready
	}

	if pending {
		if err := c.radio.AddExtSourceMatch(extAddr); err != nil {
			c.setEnabled(false)
			c.extEntries[extAddr] = true
			return nil
		}
		c.extEntries[extAddr] = true
		c.enableIfAllResolved()
	} else {
		if existed {
			if err := c.radio.ClearExtSourceMatch(extAddr); err != nil {
				delete(c.extEntries, extAddr)
				return err
			}
		}
		delete(c.extEntries, extAddr)
		c.enableIfAllResolved()
	}
	return nil
}

// ClearTable removes all entries from the source match table and disables
// source matching.
func (c *SourceMatchController) ClearTable() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.radio.ClearSourceMatchTable()
	c.entries = make(map[uint16]bool)
	c.extEntries = make(map[[8]byte]bool)
	c.setEnabled(false)
}

// Enable enables or disables the source match controller. When disabled, the
// radio sets Frame Pending on all acknowledgments.
func (c *SourceMatchController) Enable(enable bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setEnabled(enable)
}

// IsEnabled reports whether source address matching is currently enabled.
func (c *SourceMatchController) IsEnabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enabled
}

// HasPending reports whether the given short address has frames pending.
func (c *SourceMatchController) HasPending(shortAddr uint16) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.entries[shortAddr]
}

// HasPendingExt reports whether the given extended address has frames pending.
func (c *SourceMatchController) HasPendingExt(extAddr [8]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.extEntries[extAddr]
}

// setEnabled is the unlocked helper that updates the enabled flag and radio.
func (c *SourceMatchController) setEnabled(enable bool) {
	c.enabled = enable
	c.radio.EnableSourceMatch(enable)
}

// enableIfAllResolved enables source matching if there are entries in the
// table (all resolved), or disables it when the table is empty.
func (c *SourceMatchController) enableIfAllResolved() {
	if len(c.entries) > 0 || len(c.extEntries) > 0 {
		c.setEnabled(true)
	} else {
		c.setEnabled(false)
	}
}

// ---------------------------------------------------------------------------
// ChildInfo — interface the sender uses to query child state
// ---------------------------------------------------------------------------

// ChildInfo provides child information to the indirect sender.
type ChildInfo interface {
	// GetShortAddress returns the child's 16-bit short address.
	GetShortAddress() uint16
	// GetExtAddress returns the child's 64-bit extended address.
	GetExtAddress() [8]byte
	// IsRxOnWhenIdle reports whether the child keeps its receiver on when idle.
	// Non-sleepy children (RxOnWhenIdle=true) do not need indirect transmission.
	IsRxOnWhenIdle() bool
	// IsIndirectMessagePending reports whether the child has an indirect
	// message currently being transmitted.
	IsIndirectMessagePending() bool
}

// ---------------------------------------------------------------------------
// FrameSender — interface for actually sending frames
// ---------------------------------------------------------------------------

// FrameSender sends frames to children.
type FrameSender interface {
	// SendIndirectFrame transmits a frame to the given child.
	SendIndirectFrame(child ChildInfo, payload []byte) error
}

// ---------------------------------------------------------------------------
// IndirectMessage — a queued message for indirect transmission
// ---------------------------------------------------------------------------

// IndirectMessage represents a message queued for indirect transmission to
// a sleepy end device.
type IndirectMessage struct {
	// ChildAddr is the destination child's short address.
	ChildAddr uint16
	// Payload is the message payload.
	Payload []byte
	// RetryCount is the number of transmission retries attempted so far.
	RetryCount uint8
	// MaxRetries is the maximum number of retries before the message is dropped.
	MaxRetries uint8
}

// ---------------------------------------------------------------------------
// Functional options
// ---------------------------------------------------------------------------

// Option configures a Sender.
type Option func(*Sender)

// WithMaxMessages sets the maximum number of queued indirect messages.
// Default is 64.
func WithMaxMessages(n int) Option {
	return func(s *Sender) {
		if n > 0 {
			s.maxMessages = n
		}
	}
}

// WithDefaultMaxRetries sets the default maximum retries per message.
// Default is 3.
func WithDefaultMaxRetries(n uint8) Option {
	return func(s *Sender) {
		s.defaultMaxRetries = n
	}
}

// WithMaxTxAttempts sets the maximum consecutive transmission failures before
// a child is considered unreachable. Default is 5.
func WithMaxTxAttempts(n uint8) Option {
	return func(s *Sender) {
		if n > 0 {
			s.maxTxAttempts = n
		}
	}
}

// ---------------------------------------------------------------------------
// Sender — manages indirect frame transmission to sleepy children
// ---------------------------------------------------------------------------

const (
	defaultMaxMessages   = 64
	defaultMaxRetries    = 3
	defaultMaxTxAttempts = 5
)

// Sender manages indirect frame transmission to sleepy children.
//
// When a parent has frames for a sleepy child it buffers them. The frames are
// transmitted one at a time when the child sends a data poll request.
//
// This corresponds to OpenThread's IndirectSender.
type Sender struct {
	mu                sync.Mutex
	frameSender       FrameSender
	srcMatch          *SourceMatchController
	messages          []IndirectMessage
	maxMessages       int
	defaultMaxRetries uint8
	txAttempts        map[uint16]uint8 // child short addr -> consecutive failures
	maxTxAttempts     uint8
}

// NewSender creates a new indirect Sender.
func NewSender(frameSender FrameSender, srcMatch *SourceMatchController, opts ...Option) *Sender {
	s := &Sender{
		frameSender:       frameSender,
		srcMatch:          srcMatch,
		messages:          make([]IndirectMessage, 0),
		maxMessages:       defaultMaxMessages,
		defaultMaxRetries: defaultMaxRetries,
		txAttempts:        make(map[uint16]uint8),
		maxTxAttempts:     defaultMaxTxAttempts,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// AddMessage queues a message for indirect transmission to the child identified
// by childAddr. Returns ErrNoBufs if the queue is full.
func (s *Sender) AddMessage(childAddr uint16, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.messages) >= s.maxMessages {
		return errors.ErrNoBufs
	}

	buf := make([]byte, len(payload))
	copy(buf, payload)

	s.messages = append(s.messages, IndirectMessage{
		ChildAddr:  childAddr,
		Payload:    buf,
		RetryCount: 0,
		MaxRetries: s.defaultMaxRetries,
	})

	// Update the source match table so the child receives Frame Pending in
	// the acknowledgment to its next data poll.
	_ = s.srcMatch.SetFramePending(childAddr, true)

	return nil
}

// RemoveMessages removes all queued messages for the given child and returns
// the number of messages removed.
func (s *Sender) RemoveMessages(childAddr uint16) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.removeMessagesLocked(childAddr)
}

// removeMessagesLocked removes all messages for childAddr. Caller must hold mu.
func (s *Sender) removeMessagesLocked(childAddr uint16) int {
	removed := 0
	filtered := s.messages[:0]
	for _, m := range s.messages {
		if m.ChildAddr == childAddr {
			removed++
		} else {
			filtered = append(filtered, m)
		}
	}
	s.messages = filtered

	if removed > 0 {
		_ = s.srcMatch.SetFramePending(childAddr, false)
	}
	return removed
}

// HandleDataPoll is called when a child sends a data poll. It transmits the
// next queued message for the child. Returns ErrNotFound if there are no
// queued messages.
func (s *Sender) HandleDataPoll(child ChildInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	childAddr := child.GetShortAddress()

	// Find the first queued message for this child.
	idx := -1
	for i := range s.messages {
		if s.messages[i].ChildAddr == childAddr {
			idx = i
			break
		}
	}
	if idx == -1 {
		return errors.ErrNotFound
	}

	msg := s.messages[idx]

	// Attempt transmission (unlock during the actual send to avoid holding
	// the lock across a potentially slow operation — but for simplicity and
	// correctness in the common embedded use-case we keep it locked here).
	err := s.frameSender.SendIndirectFrame(child, msg.Payload)
	if err != nil {
		// Increment retry count.
		s.messages[idx].RetryCount++
		if s.messages[idx].RetryCount > s.messages[idx].MaxRetries {
			// Drop the message after exceeding max retries.
			s.messages = append(s.messages[:idx], s.messages[idx+1:]...)
			if s.getMessageCountLocked(childAddr) == 0 {
				_ = s.srcMatch.SetFramePending(childAddr, false)
			}
		}
		return errors.ErrFailed
	}

	// Transmission was accepted — remove the message from the queue.
	s.messages = append(s.messages[:idx], s.messages[idx+1:]...)

	// Clear the source match entry if no more messages are queued.
	if s.getMessageCountLocked(childAddr) == 0 {
		_ = s.srcMatch.SetFramePending(childAddr, false)
	}

	return nil
}

// HandleSentSuccess is called when an indirect frame was successfully
// acknowledged by the child. It resets the consecutive failure counter.
func (s *Sender) HandleSentSuccess(childAddr uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.txAttempts, childAddr)
}

// HandleSentFailure is called when an indirect frame transmission failed
// (e.g. no ACK). It increments the consecutive failure counter and returns
// true if the child should be removed (too many failures).
func (s *Sender) HandleSentFailure(childAddr uint16) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.txAttempts[childAddr]++
	if s.txAttempts[childAddr] >= s.maxTxAttempts {
		return true
	}
	return false
}

// GetMessageCount returns the number of messages queued for the given child.
func (s *Sender) GetMessageCount(childAddr uint16) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getMessageCountLocked(childAddr)
}

func (s *Sender) getMessageCountLocked(childAddr uint16) int {
	count := 0
	for _, m := range s.messages {
		if m.ChildAddr == childAddr {
			count++
		}
	}
	return count
}

// GetTotalMessageCount returns the total number of queued indirect messages
// across all children.
func (s *Sender) GetTotalMessageCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

// HandleChildRemoved cleans up all state associated with a child that is
// being removed.
func (s *Sender) HandleChildRemoved(childAddr uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.removeMessagesLocked(childAddr)
	delete(s.txAttempts, childAddr)
}

// ---------------------------------------------------------------------------
// CslConfig — CSL transmission parameters
// ---------------------------------------------------------------------------

// CslConfig holds Coordinated Sampled Listening transmission parameters for
// a child.
type CslConfig struct {
	// Period is the CSL period in units of 10 symbols.
	Period uint16
	// Timeout is the CSL timeout in seconds.
	Timeout uint32
	// Channel is the CSL channel.
	Channel uint8
}

// ---------------------------------------------------------------------------
// CslTxScheduler — schedules transmissions aligned to CSL windows
// ---------------------------------------------------------------------------

// CslTxScheduler schedules indirect transmissions aligned to a child's CSL
// sampling windows. This is a simplified representation; a full implementation
// would integrate with the MAC scheduler and timing subsystem.
type CslTxScheduler struct {
	mu      sync.Mutex
	configs map[uint16]*CslConfig // child short addr -> CSL config
}

// NewCslTxScheduler creates a new CSL transmission scheduler.
func NewCslTxScheduler() *CslTxScheduler {
	return &CslTxScheduler{
		configs: make(map[uint16]*CslConfig),
	}
}

// SetConfig sets the CSL configuration for a child.
func (c *CslTxScheduler) SetConfig(childAddr uint16, config CslConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cfg := config // copy
	c.configs[childAddr] = &cfg
}

// RemoveConfig removes the CSL configuration for a child.
func (c *CslTxScheduler) RemoveConfig(childAddr uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.configs, childAddr)
}

// GetConfig returns the CSL configuration for a child and whether one exists.
func (c *CslTxScheduler) GetConfig(childAddr uint16) (*CslConfig, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cfg, ok := c.configs[childAddr]
	if !ok {
		return nil, false
	}
	// Return a copy to prevent races.
	cp := *cfg
	return &cp, true
}

// HasConfig reports whether a CSL configuration exists for the given child.
func (c *CslTxScheduler) HasConfig(childAddr uint16) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.configs[childAddr]
	return ok
}
