// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file implements the Data Poll Sender and Data Poll Handler for
// Thread sleepy end devices and their parents.
//
// DataPollSender (runs on a sleepy end device) manages 802.15.4 data poll
// requests to the parent, including poll interval management with default,
// fast-poll, and external poll periods.
//
// DataPollHandler (runs on a parent/router FTD) manages the indirect
// transmission queue for sleepy children, tracks pending frames, and
// handles incoming data poll requests.
//
// This is a Go port of OpenThread's src/core/mac/data_poll_sender.hpp,
// src/core/mac/data_poll_sender.cpp, src/core/mac/data_poll_handler.hpp,
// and src/core/mac/data_poll_handler.cpp.
package supervision

import (
	"sync"
	"time"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/thread/mle"
)

// Data poll constants.
const (
	// DefaultFastPolls is the default number of fast poll transmissions.
	DefaultFastPolls uint8 = 8

	// MaxFastPolls is the maximum number of fast poll transmissions allowed.
	MaxFastPolls uint8 = 15

	// MaxFastPollsUsers is the maximum number of callers that can request fast polls.
	MaxFastPollsUsers uint8 = 63

	// DefaultPollPeriod is the default data poll period in milliseconds.
	// This is derived from the child timeout (typically 240s) minus headroom.
	DefaultPollPeriod uint32 = 240_000

	// FastPollPeriod is the poll period used during fast polling (milliseconds).
	FastPollPeriod uint32 = 188

	// RetxPollPeriod is the poll period used for retransmission (milliseconds).
	RetxPollPeriod uint32 = 1000

	// AttachPollPeriod is the poll period used during attach (milliseconds).
	AttachPollPeriod uint32 = 100

	// MinPollPeriod is the minimum allowed poll period (milliseconds).
	MinPollPeriod uint32 = 10

	// MaxExternalPeriod is the maximum allowed external poll period ~18.6 hours.
	MaxExternalPeriod uint32 = (1 << 26) - 1

	// QuickPollsAfterTimeout is the number of quick polls after a timeout.
	QuickPollsAfterTimeout uint8 = 5

	// MaxPollRetxAttempts is the maximum poll retransmission attempts.
	MaxPollRetxAttempts uint8 = 4

	// MaxPollTriggeredTxAttempts is the maximum indirect tx attempts
	// triggered by data polls (for DataPollHandler).
	MaxPollTriggeredTxAttempts uint8 = 5
)

// FrameChange defines the type of frame change request for the DataPollHandler.
type FrameChange uint8

const (
	// FrameAdded indicates a new frame was added to the indirect queue.
	FrameAdded FrameChange = iota
	// FrameRemoved indicates a frame was removed from the indirect queue.
	FrameRemoved
	// FramePurged indicates a frame was purged and any ongoing tx aborted.
	FramePurged
)

// String returns a human-readable name for the FrameChange.
func (fc FrameChange) String() string {
	switch fc {
	case FrameAdded:
		return "FrameAdded"
	case FrameRemoved:
		return "FrameRemoved"
	case FramePurged:
		return "FramePurged"
	default:
		return "Unknown"
	}
}

// PollTransmitter abstracts the ability to transmit a data poll frame.
type PollTransmitter interface {
	// TransmitDataPoll sends a data poll (MAC Data Request) to the parent.
	// Returns nil on success.
	TransmitDataPoll() error
}

// IndirectSender abstracts the indirect frame transmission interface
// used by the DataPollHandler on the parent side.
type IndirectSender interface {
	// HandleFrameChangeDone is called when a frame change for a child is
	// complete and the indirect frame can be updated.
	HandleFrameChangeDone(child *mle.Child)
	// HandleSentFrameToChild is called after an indirect frame is sent.
	HandleSentFrameToChild(child *mle.Child, err error)
	// GetIndirectMessageCount returns the number of indirect messages
	// queued for the given child.
	GetIndirectMessageCount(child *mle.Child) uint16
}

// ---------------------------------------------------------------------------
// DataPollSender (runs on sleepy end device / SED)
// ---------------------------------------------------------------------------

// DataPollSenderOption configures a DataPollSender.
type DataPollSenderOption func(*DataPollSender)

// WithDefaultPollPeriod sets the default poll period in milliseconds.
func WithDefaultPollPeriod(ms uint32) DataPollSenderOption {
	return func(d *DataPollSender) {
		d.defaultPollPeriod = ms
	}
}

// WithPollTransmitter sets the PollTransmitter.
func WithPollTransmitter(pt PollTransmitter) DataPollSenderOption {
	return func(d *DataPollSender) {
		d.transmitter = pt
	}
}

// DataPollSender manages 802.15.4 data poll requests sent by a sleepy
// end device to its parent.
type DataPollSender struct {
	mu sync.Mutex

	defaultPollPeriod  uint32 // default poll period in ms
	externalPollPeriod uint32 // user-specified poll period in ms (0 = not set)
	pollPeriod         uint32 // current effective poll period in ms

	enabled            bool
	attachMode         bool
	retxMode           bool
	pollTimeoutCounter uint8
	pollTxFailCounter  uint8
	remainingFastPolls uint8
	fastPollsUsers     uint8

	transmitter PollTransmitter

	// timer state
	timer     *time.Timer
	timerStop chan struct{}
}

// NewDataPollSender creates a DataPollSender with the given options.
func NewDataPollSender(opts ...DataPollSenderOption) *DataPollSender {
	d := &DataPollSender{
		defaultPollPeriod: DefaultPollPeriod,
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

// Start begins periodic data polling. It is a no-op if already started.
func (d *DataPollSender) Start() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.enabled {
		return
	}
	d.enabled = true
	d.timerStop = make(chan struct{})
	d.scheduleNextPoll(true)
}

// Stop halts data polling and resets all state.
func (d *DataPollSender) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.stopInternal()
}

// stopInternal halts polling. Must be called with d.mu held.
func (d *DataPollSender) stopInternal() {
	if !d.enabled {
		return
	}
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	close(d.timerStop)
	d.enabled = false
	d.attachMode = false
	d.retxMode = false
	d.pollTimeoutCounter = 0
	d.pollTxFailCounter = 0
	d.remainingFastPolls = 0
	d.fastPollsUsers = 0
}

// IsEnabled reports whether polling is active.
func (d *DataPollSender) IsEnabled() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.enabled
}

// SendDataPoll enqueues a data poll transmission.
func (d *DataPollSender) SendDataPoll() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.enabled {
		return errors.ErrInvalidState
	}

	if d.timer != nil {
		d.timer.Stop()
	}

	tx := d.transmitter
	d.mu.Unlock()

	var err error
	if tx != nil {
		err = tx.TransmitDataPoll()
	}

	d.mu.Lock()

	switch err {
	case nil:
		d.scheduleNextPoll(false)
	case errors.ErrInvalidState:
		d.stopInternal()
	default:
		d.scheduleNextPoll(true)
	}

	return err
}

// HandlePollSent processes the result of a data poll transmission.
func (d *DataPollSender) HandlePollSent(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.enabled {
		return
	}

	shouldRecalc := false

	switch err {
	case nil:
		if d.remainingFastPolls > 0 {
			d.remainingFastPolls--
			if d.remainingFastPolls == 0 {
				shouldRecalc = true
				d.fastPollsUsers = 0
			}
		}
		if d.retxMode {
			d.retxMode = false
			d.pollTxFailCounter = 0
			shouldRecalc = true
		}

	case errors.ErrChannelAccessFailure, errors.ErrAbort:
		d.retxMode = true
		shouldRecalc = true

	default:
		// NoAck or other failure
		d.pollTxFailCounter++
		if d.pollTxFailCounter < MaxPollRetxAttempts {
			if !d.retxMode {
				d.retxMode = true
				shouldRecalc = true
			}
		} else {
			d.retxMode = false
			d.pollTxFailCounter = 0
			shouldRecalc = true
		}
	}

	if shouldRecalc {
		d.scheduleNextPoll(true)
	}
}

// HandlePollTimeout processes a data poll timeout (ack indicated frame
// pending but no frame received).
func (d *DataPollSender) HandlePollTimeout() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.enabled {
		return
	}

	d.pollTimeoutCounter++

	if d.pollTimeoutCounter < QuickPollsAfterTimeout {
		// Trigger another poll quickly. We unlock/relock around SendDataPoll
		// to avoid recursive lock.
		tx := d.transmitter
		d.mu.Unlock()
		if tx != nil {
			_ = tx.TransmitDataPoll()
		}
		d.mu.Lock()
	} else {
		d.pollTimeoutCounter = 0
	}
}

// GetPollPeriod returns the current effective poll period in milliseconds.
func (d *DataPollSender) GetPollPeriod() uint32 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calculatePollPeriod()
}

// GetExternalPollPeriod returns the user-specified poll period in milliseconds.
func (d *DataPollSender) GetExternalPollPeriod() uint32 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.externalPollPeriod
}

// SetExternalPollPeriod sets a user-specified poll period in milliseconds.
// A value of zero clears the external period. Returns ErrInvalidArgs if
// the period is non-zero but less than MinPollPeriod.
func (d *DataPollSender) SetExternalPollPeriod(period uint32) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if period != 0 {
		if period < MinPollPeriod {
			return errors.ErrInvalidArgs
		}
		if period > MaxExternalPeriod {
			period = MaxExternalPeriod
		}
	}

	if d.externalPollPeriod != period {
		d.externalPollPeriod = period
		if d.enabled {
			d.scheduleNextPoll(true)
		}
	}

	return nil
}

// GetKeepAlivePollPeriod returns the maximum data polling period used for
// keep-alive, which is the minimum of the default and external periods.
func (d *DataPollSender) GetKeepAlivePollPeriod() uint32 {
	d.mu.Lock()
	defer d.mu.Unlock()

	period := d.defaultPollPeriod
	if d.externalPollPeriod != 0 && d.externalPollPeriod < period {
		period = d.externalPollPeriod
	}
	return period
}

// SetAttachMode enables or disables attach mode, which uses a faster poll period.
func (d *DataPollSender) SetAttachMode(mode bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.attachMode != mode {
		d.attachMode = mode
		if d.enabled {
			d.scheduleNextPoll(true)
		}
	}
}

// SendFastPolls requests that the next numFastPolls polls be sent at the
// fast poll rate. If numFastPolls is 0, DefaultFastPolls is used.
func (d *DataPollSender) SendFastPolls(numFastPolls uint8) {
	d.mu.Lock()
	defer d.mu.Unlock()

	shouldRecalc := d.remainingFastPolls == 0

	if d.fastPollsUsers < MaxFastPollsUsers {
		d.fastPollsUsers++
	}

	if numFastPolls == 0 {
		numFastPolls = DefaultFastPolls
	}
	if numFastPolls > MaxFastPolls {
		numFastPolls = MaxFastPolls
	}
	if numFastPolls > d.remainingFastPolls {
		d.remainingFastPolls = numFastPolls
	}

	if d.enabled && shouldRecalc {
		d.scheduleNextPoll(true)
	}
}

// StopFastPolls decrements the fast poll user count and, if it reaches zero,
// clears remaining fast polls.
func (d *DataPollSender) StopFastPolls() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.fastPollsUsers == 0 {
		return
	}
	// If we hit the max, let HandlePollSent clear it.
	if d.fastPollsUsers >= MaxFastPollsUsers {
		return
	}

	d.fastPollsUsers--

	if d.fastPollsUsers == 0 {
		d.remainingFastPolls = 0
		if d.enabled {
			d.scheduleNextPoll(true)
		}
	}
}

// RecalculatePollPeriod forces a recalculation of the poll period.
func (d *DataPollSender) RecalculatePollPeriod() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.enabled {
		d.scheduleNextPoll(true)
	}
}

// calculatePollPeriod computes the effective poll period. Must be called
// with d.mu held.
func (d *DataPollSender) calculatePollPeriod() uint32 {
	period := d.defaultPollPeriod

	if d.attachMode && AttachPollPeriod < period {
		period = AttachPollPeriod
	}
	if d.retxMode && RetxPollPeriod < period {
		period = RetxPollPeriod
	}
	if d.remainingFastPolls > 0 && FastPollPeriod < period {
		period = FastPollPeriod
	}
	if d.externalPollPeriod != 0 && d.externalPollPeriod < period {
		period = d.externalPollPeriod
	}
	if period == 0 {
		period = MinPollPeriod
	}
	return period
}

// scheduleNextPoll sets or resets the internal timer. Must be called with
// d.mu held. If recalculate is true, the poll period is recalculated.
func (d *DataPollSender) scheduleNextPoll(recalculate bool) {
	if recalculate {
		d.pollPeriod = d.calculatePollPeriod()
	}

	dur := time.Duration(d.pollPeriod) * time.Millisecond

	if d.timer != nil {
		d.timer.Reset(dur)
	} else {
		stop := d.timerStop
		d.timer = time.AfterFunc(dur, func() {
			select {
			case <-stop:
				return
			default:
			}
			d.mu.Lock()
			tx := d.transmitter
			enabled := d.enabled
			d.mu.Unlock()

			if enabled && tx != nil {
				_ = tx.TransmitDataPoll()
			}
		})
	}
}

// ---------------------------------------------------------------------------
// IndirectTxInfo tracks per-child indirect transmission state.
// ---------------------------------------------------------------------------

// IndirectTxInfo holds the per-child state for indirect frame transmission,
// matching OpenThread's DataPollHandler::NeighborInfo.
type IndirectTxInfo struct {
	DataPollPending      bool
	FramePurgePending    bool
	FrameReplacePending  bool
	IndirectFrameCounter uint32
	IndirectKeyID        uint8
	IndirectDSN          uint8
	IndirectTxAttempts   uint8
}

// ResetTxAttempts resets the indirect transmission attempt counter.
func (info *IndirectTxInfo) ResetTxAttempts() {
	info.IndirectTxAttempts = 0
}

// ---------------------------------------------------------------------------
// DataPollHandler (runs on parent / router / FTD)
// ---------------------------------------------------------------------------

// DataPollHandlerOption configures a DataPollHandler.
type DataPollHandlerOption func(*DataPollHandler)

// WithIndirectSender sets the IndirectSender for the handler.
func WithIndirectSender(is IndirectSender) DataPollHandlerOption {
	return func(h *DataPollHandler) {
		h.indirectSender = is
	}
}

// WithHandlerChildProvider sets the ChildProvider for the handler.
func WithHandlerChildProvider(cp ChildProvider) DataPollHandlerOption {
	return func(h *DataPollHandler) {
		h.children = cp
	}
}

// DataPollHandler manages indirect frame transmissions to sleepy children.
// It runs on a parent/router (FTD).
type DataPollHandler struct {
	mu sync.Mutex

	children       ChildProvider
	indirectSender IndirectSender

	// indirectTxChild is the child currently being served (nil if none).
	indirectTxChild *mle.Child

	// txInfo maps child RLOC16 to per-child indirect tx state.
	txInfo map[uint16]*IndirectTxInfo
}

// NewDataPollHandler creates a DataPollHandler with the given options.
func NewDataPollHandler(opts ...DataPollHandlerOption) *DataPollHandler {
	h := &DataPollHandler{
		txInfo: make(map[uint16]*IndirectTxInfo),
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

// Clear resets all per-child state.
func (h *DataPollHandler) Clear() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.indirectTxChild = nil
	h.txInfo = make(map[uint16]*IndirectTxInfo)
}

// GetTxInfo returns (or creates) the IndirectTxInfo for a child.
func (h *DataPollHandler) GetTxInfo(child *mle.Child) *IndirectTxInfo {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.getOrCreateTxInfo(child)
}

// getOrCreateTxInfo returns existing or creates new IndirectTxInfo. Must be
// called with h.mu held.
func (h *DataPollHandler) getOrCreateTxInfo(child *mle.Child) *IndirectTxInfo {
	info, ok := h.txInfo[child.RLOC16]
	if !ok {
		info = &IndirectTxInfo{}
		h.txInfo[child.RLOC16] = info
	}
	return info
}

// HandleDataPoll processes an incoming data poll from a child.
func (h *DataPollHandler) HandleDataPoll(child *mle.Child) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if child == nil {
		return
	}

	child.LastHeard = time.Now()
	child.LinkFailures = 0

	info := h.getOrCreateTxInfo(child)

	if h.indirectTxChild == nil {
		h.indirectTxChild = child
		// In production this would trigger MAC indirect frame transmission.
	} else {
		info.DataPollPending = true
	}
}

// RequestFrameChange requests a frame change for a child's indirect
// transmission.
func (h *DataPollHandler) RequestFrameChange(change FrameChange, child *mle.Child) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if child == nil {
		return
	}

	info := h.getOrCreateTxInfo(child)

	if h.indirectTxChild == child {
		// Currently transmitting to this child.
		switch change {
		case FramePurged:
			info.FramePurgePending = true
		case FrameRemoved:
			info.FrameReplacePending = true
		case FrameAdded:
			info.FrameReplacePending = true
		}
	} else {
		// No active transmission to this child — handle immediately.
		info.ResetTxAttempts()
		if h.indirectSender != nil {
			h.indirectSender.HandleFrameChangeDone(child)
		}
	}
}

// HandleFrameSent processes the result of an indirect frame transmission.
func (h *DataPollHandler) HandleFrameSent(child *mle.Child, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if child == nil {
		return
	}

	info := h.getOrCreateTxInfo(child)

	// If the current indirect tx child matches, clear it.
	if h.indirectTxChild == child {
		h.indirectTxChild = nil
	}

	// Handle purge pending.
	if info.FramePurgePending {
		info.FramePurgePending = false
		info.FrameReplacePending = false
		info.ResetTxAttempts()
		if h.indirectSender != nil {
			h.indirectSender.HandleFrameChangeDone(child)
		}
		h.processPendingPolls()
		return
	}

	switch err {
	case nil:
		info.ResetTxAttempts()
		info.FrameReplacePending = false

	default:
		// NoAck or channel access failure
		info.IndirectTxAttempts++

		if info.FrameReplacePending {
			info.FrameReplacePending = false
			info.ResetTxAttempts()
			if h.indirectSender != nil {
				h.indirectSender.HandleFrameChangeDone(child)
			}
			h.processPendingPolls()
			return
		}

		if info.IndirectTxAttempts >= MaxPollTriggeredTxAttempts {
			info.ResetTxAttempts()
		} else {
			// Keep state for retransmission on next poll.
			h.processPendingPolls()
			return
		}
	}

	if h.indirectSender != nil {
		h.indirectSender.HandleSentFrameToChild(child, err)
	}

	h.processPendingPolls()
}

// GetIndirectTxChild returns the child currently being served with an
// indirect transmission, or nil.
func (h *DataPollHandler) GetIndirectTxChild() *mle.Child {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.indirectTxChild
}

// processPendingPolls finds the next child with a pending data poll and
// starts serving it. Must be called with h.mu held.
func (h *DataPollHandler) processPendingPolls() {
	if h.indirectTxChild != nil {
		return
	}

	var earliest *mle.Child
	var earliestTime time.Time

	for rloc, info := range h.txInfo {
		if !info.DataPollPending {
			continue
		}
		// Find the child from the provider.
		if h.children != nil {
			for _, c := range h.children.GetChildren() {
				if c != nil && c.RLOC16 == rloc {
					if earliest == nil || c.LastHeard.Before(earliestTime) {
						earliest = c
						earliestTime = c.LastHeard
					}
					break
				}
			}
		}
	}

	if earliest != nil {
		info := h.txInfo[earliest.RLOC16]
		info.DataPollPending = false
		h.indirectTxChild = earliest
	}
}
