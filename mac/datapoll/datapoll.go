// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package datapoll implements the data poll handler (FTD/parent side)
// and data poll sender (SED/child side) for Thread sleepy devices.
//
// This is a Go port of the data poll handling in OpenThread's
// src/core/mac/data_poll_handler.hpp/.cpp and
// src/core/mac/data_poll_sender.hpp/.cpp.
package datapoll

import "time"

// ============================================================================
// Part 1: PollHandler (FTD/parent side)
// ============================================================================

// FrameChange indicates what to do with a queued indirect frame.
type FrameChange uint8

const (
	// PurgeFrame indicates the indirect frame should be purged (removed).
	PurgeFrame FrameChange = iota
	// ReplaceFrame indicates the indirect frame should be replaced.
	ReplaceFrame
)

// HandlerCallbacks defines the interface that a parent MAC uses to manage
// indirect frames in response to data poll events.
type HandlerCallbacks interface {
	// HandleDataPoll is called when a data poll is received from a child.
	// Returns true if there is a pending frame for the child.
	HandleDataPoll(childShortAddr uint16) bool
	// HandleFrameChange is called to purge or replace an indirect frame.
	HandleFrameChange(childShortAddr uint16, change FrameChange)
}

// childPollState tracks indirect transmission state for a single child.
type childPollState struct {
	// FramePending indicates whether there is a pending indirect frame.
	FramePending bool
	// RetxCount tracks the number of retransmission attempts.
	RetxCount uint8
}

// Handler tracks indirect transmission state for sleepy children
// (FTD/parent side).
type Handler struct {
	callbacks HandlerCallbacks
	children  map[uint16]*childPollState
}

// NewHandler creates a new data poll handler.
func NewHandler(cb HandlerCallbacks) *Handler {
	return &Handler{
		callbacks: cb,
		children:  make(map[uint16]*childPollState),
	}
}

// HandleDataPoll is called when a data poll arrives from a child.
// It delegates to the callbacks and tracks retransmission state.
func (h *Handler) HandleDataPoll(childAddr uint16) {
	if h.callbacks == nil {
		return
	}

	pending := h.callbacks.HandleDataPoll(childAddr)

	state, exists := h.children[childAddr]
	if !exists {
		state = &childPollState{}
		h.children[childAddr] = state
	}

	state.FramePending = pending
	if pending {
		state.RetxCount++
	}
}

// SetFramePending marks whether a child has a pending indirect frame.
func (h *Handler) SetFramePending(childAddr uint16, pending bool) {
	state, exists := h.children[childAddr]
	if !exists {
		state = &childPollState{}
		h.children[childAddr] = state
	}
	state.FramePending = pending
	if !pending {
		state.RetxCount = 0
	}
}

// GetFramePending reports whether a child has a pending indirect frame.
func (h *Handler) GetFramePending(childAddr uint16) bool {
	state, exists := h.children[childAddr]
	if !exists {
		return false
	}
	return state.FramePending
}

// PurgeFrame removes the tracking state for a child.
func (h *Handler) PurgeFrame(childAddr uint16) {
	delete(h.children, childAddr)
}

// Clear removes all tracked children.
func (h *Handler) Clear() {
	h.children = make(map[uint16]*childPollState)
}

// ============================================================================
// Part 2: PollSender (SED/child side)
// ============================================================================

// Data poll period constants in milliseconds.
const (
	// AttachDataPollPeriod is the data poll period during attach.
	AttachDataPollPeriod uint32 = 100
	// RetxPollPeriod is the poll period when retransmitting.
	RetxPollPeriod uint32 = 188
	// FastPollPeriod is the period for fast polls.
	FastPollPeriod uint32 = 188
	// DefaultPollPeriod is the default data poll period.
	DefaultPollPeriod uint32 = 1000
	// DefaultFastPollCount is the default number of fast polls to send.
	DefaultFastPollCount uint16 = 8
)

// SenderCallbacks defines the interface the SED MAC uses for sending polls.
type SenderCallbacks interface {
	// SendDataPoll sends a data poll frame to the parent.
	SendDataPoll() error
}

// TimerFunc schedules a callback after a delay. Returns a cancel function.
type TimerFunc func(delay time.Duration, fn func()) func()

// Sender manages data poll scheduling for a Sleepy End Device (SED).
type Sender struct {
	callbacks     SenderCallbacks
	scheduleTimer TimerFunc
	cancelTimer   func()

	pollPeriod         uint32 // effective poll period in ms
	externalPeriod     uint32 // externally configured poll period
	attachMode         bool
	retxMode           bool
	fastPollsRemaining uint16
	enabled            bool
}

// NewSender creates a new data poll sender.
func NewSender(cb SenderCallbacks, timer TimerFunc) *Sender {
	return &Sender{
		callbacks:     cb,
		scheduleTimer: timer,
	}
}

// Start enables data polling and schedules the first poll.
func (s *Sender) Start() {
	s.enabled = true
	s.recalculatePollPeriod()
	s.schedulePoll()
}

// Stop disables data polling and cancels any pending timer.
func (s *Sender) Stop() {
	s.enabled = false
	s.cancelPendingTimer()
}

// SetExternalPollPeriod sets the externally configured poll period in
// milliseconds.
func (s *Sender) SetExternalPollPeriod(periodMs uint32) {
	s.externalPeriod = periodMs
	s.recalculatePollPeriod()
	if s.enabled {
		s.schedulePoll()
	}
}

// GetExternalPollPeriod returns the externally configured poll period.
func (s *Sender) GetExternalPollPeriod() uint32 {
	return s.externalPeriod
}

// SetAttachMode enters or exits attach mode. Attach mode uses a short
// poll period (AttachDataPollPeriod).
func (s *Sender) SetAttachMode(attach bool) {
	s.attachMode = attach
	s.recalculatePollPeriod()
	if s.enabled {
		s.schedulePoll()
	}
}

// SetRetxMode enters or exits retransmission mode. Retx mode uses
// RetxPollPeriod.
func (s *Sender) SetRetxMode(retx bool) {
	s.retxMode = retx
	s.recalculatePollPeriod()
	if s.enabled {
		s.schedulePoll()
	}
}

// SendFastPolls initiates fast polling. If count is 0, the default
// count (DefaultFastPollCount) is used.
func (s *Sender) SendFastPolls(count uint16) {
	if count == 0 {
		count = DefaultFastPollCount
	}
	s.fastPollsRemaining = count
	s.recalculatePollPeriod()
	if s.enabled {
		s.schedulePoll()
	}
}

// GetPollPeriod returns the effective poll period in milliseconds.
func (s *Sender) GetPollPeriod() uint32 {
	return s.pollPeriod
}

// IsEnabled reports whether polling is enabled.
func (s *Sender) IsEnabled() bool {
	return s.enabled
}

// recalculatePollPeriod recalculates the effective poll period based on
// the current mode. Priority: attach > retx > fast > external > default.
func (s *Sender) recalculatePollPeriod() {
	switch {
	case s.attachMode:
		s.pollPeriod = AttachDataPollPeriod
	case s.retxMode:
		s.pollPeriod = RetxPollPeriod
	case s.fastPollsRemaining > 0:
		s.pollPeriod = FastPollPeriod
	case s.externalPeriod > 0:
		s.pollPeriod = s.externalPeriod
	default:
		s.pollPeriod = DefaultPollPeriod
	}
}

// handlePollTimer is called when the poll timer fires.
func (s *Sender) handlePollTimer() {
	if !s.enabled {
		return
	}

	if s.callbacks != nil {
		_ = s.callbacks.SendDataPoll()
	}

	if s.fastPollsRemaining > 0 {
		s.fastPollsRemaining--
		s.recalculatePollPeriod()
	}

	s.schedulePoll()
}

// schedulePoll schedules the next poll timer.
func (s *Sender) schedulePoll() {
	s.cancelPendingTimer()
	if s.scheduleTimer != nil && s.enabled {
		delay := time.Duration(s.pollPeriod) * time.Millisecond
		s.cancelTimer = s.scheduleTimer(delay, s.handlePollTimer)
	}
}

// cancelPendingTimer cancels any pending poll timer.
func (s *Sender) cancelPendingTimer() {
	if s.cancelTimer != nil {
		s.cancelTimer()
		s.cancelTimer = nil
	}
}
