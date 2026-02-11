// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package supervision implements the Thread Child Supervision and Data Poll
// functionality.
//
// Child supervision provides a mechanism for a parent to ensure that a
// message is sent to each sleepy child within a fixed interval (the
// supervision interval). If there is no transmission to the child within
// the interval, the supervisor enqueues and sends a supervision message
// (an empty-payload data frame) to the child.
//
// On the child side, the supervision listener monitors incoming messages
// from the parent. If the child does not hear from its parent for a
// configured timeout, it assumes it may be disconnected and initiates
// re-attachment.
//
// This is a Go port of OpenThread's src/core/thread/child_supervision.hpp
// and src/core/thread/child_supervision.cpp.
package supervision

import (
	"sync"
	"time"

	"github.com/hilli/gothread/thread/mle"
)

// DefaultSupervisionInterval is the default interval (in seconds) at which
// the supervisor sends supervision messages to sleepy children.
const DefaultSupervisionInterval uint16 = 190

// DefaultSupervisionTimeout is the default timeout (in seconds) for the
// supervision listener on the child side.
const DefaultSupervisionTimeout uint16 = 190

// ChildProvider abstracts access to the child table so the supervisor can
// iterate over children without depending on a concrete child table.
type ChildProvider interface {
	// GetChildren returns a snapshot of children in StateValid.
	GetChildren() []*mle.Child
}

// MessageSender abstracts the ability to send a supervision message to a child.
type MessageSender interface {
	// SendSupervisionMessage sends an empty supervision frame to the child.
	// Returns nil on success.
	SendSupervisionMessage(child *mle.Child) error
}

// Timer abstracts a resettable one-shot timer for testing.
type Timer interface {
	// Reset schedules the timer to fire after d. If the timer was already
	// pending it is rescheduled.
	Reset(d time.Duration)
	// Stop cancels the pending timer. Returns true if it was pending.
	Stop() bool
	// C returns the channel on which the timer fires.
	C() <-chan time.Time
}

// ParentLossHandler is called when the supervision listener determines that
// the child has lost contact with its parent.
type ParentLossHandler interface {
	// HandleParentLoss is invoked when no frame has been received from the
	// parent within the supervision timeout.
	HandleParentLoss()
}

// ---------------------------------------------------------------------------
// Supervisor (runs on parent / router / FTD)
// ---------------------------------------------------------------------------

// SupervisorOption configures a Supervisor.
type SupervisorOption func(*Supervisor)

// WithSupervisionInterval sets the default supervision interval (seconds).
func WithSupervisionInterval(seconds uint16) SupervisorOption {
	return func(s *Supervisor) {
		s.interval = seconds
	}
}

// WithChildProvider sets the ChildProvider used by the supervisor.
func WithChildProvider(cp ChildProvider) SupervisorOption {
	return func(s *Supervisor) {
		s.children = cp
	}
}

// WithMessageSender sets the MessageSender used by the supervisor.
func WithMessageSender(ms MessageSender) SupervisorOption {
	return func(s *Supervisor) {
		s.sender = ms
	}
}

// Supervisor tracks each child's last interaction time and periodically
// sends empty supervision messages to sleepy children that have not been
// heard from within the supervision interval.
type Supervisor struct {
	mu       sync.Mutex
	interval uint16 // supervision interval in seconds
	running  bool
	children ChildProvider
	sender   MessageSender

	// done is closed to signal the ticker goroutine to stop.
	done chan struct{}
}

// NewSupervisor creates a Supervisor with the given options.
func NewSupervisor(opts ...SupervisorOption) *Supervisor {
	s := &Supervisor{
		interval: DefaultSupervisionInterval,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// GetSupervisionInterval returns the current supervision interval in seconds.
func (s *Supervisor) GetSupervisionInterval() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.interval
}

// SetSupervisionInterval sets the supervision interval in seconds.
func (s *Supervisor) SetSupervisionInterval(seconds uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.interval = seconds
}

// Start begins periodic supervision. It is safe to call multiple times;
// subsequent calls are no-ops if the supervisor is already running.
func (s *Supervisor) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return
	}
	s.running = true
	s.done = make(chan struct{})

	go s.loop()
}

// Stop halts the supervision loop. It is safe to call when not running.
func (s *Supervisor) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}
	s.running = false
	close(s.done)
}

// IsRunning reports whether the supervisor is active.
func (s *Supervisor) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// UpdateOnSend resets the supervision timer for a child, recording that
// a message was successfully sent.
func (s *Supervisor) UpdateOnSend(child *mle.Child) {
	if child == nil {
		return
	}
	child.SecondsSinceSupervision = 0
}

// HandleTimer performs a single supervision tick (1 second). For each
// sleepy child in StateValid whose supervision interval has elapsed, a
// supervision message is sent. This method is exposed for deterministic
// testing; in production it is driven by the internal ticker.
func (s *Supervisor) HandleTimer() {
	s.mu.Lock()
	children := s.children
	s.mu.Unlock()

	if children == nil {
		return
	}

	for _, child := range children.GetChildren() {
		if child == nil {
			continue
		}

		// Only supervise sleepy children in valid state.
		if child.State != mle.StateValid {
			continue
		}
		if child.IsRxOnWhenIdle() {
			continue
		}

		interval := child.SupervisionInterval
		if interval == 0 {
			// Use the supervisor's default interval if the child has
			// none configured.
			s.mu.Lock()
			interval = s.interval
			s.mu.Unlock()
		}
		if interval == 0 {
			continue
		}

		child.SecondsSinceSupervision++

		if child.SecondsSinceSupervision >= interval {
			s.mu.Lock()
			sender := s.sender
			s.mu.Unlock()

			if sender != nil {
				_ = sender.SendSupervisionMessage(child)
			}
			// Reset after send attempt regardless of success (matches OT).
			child.SecondsSinceSupervision = 0
		}
	}
}

// loop is the internal goroutine that drives HandleTimer every second.
func (s *Supervisor) loop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.HandleTimer()
		}
	}
}

// ---------------------------------------------------------------------------
// SupervisionListener (runs on child / SED)
// ---------------------------------------------------------------------------

// ListenerOption configures a SupervisionListener.
type ListenerOption func(*SupervisionListener)

// WithTimeout sets the supervision check timeout in seconds.
func WithTimeout(seconds uint16) ListenerOption {
	return func(l *SupervisionListener) {
		l.timeout = seconds
	}
}

// WithListenerInterval sets the supervision interval advertised by the child.
func WithListenerInterval(seconds uint16) ListenerOption {
	return func(l *SupervisionListener) {
		l.interval = seconds
	}
}

// WithTimer sets the Timer implementation for the listener.
func WithTimer(t Timer) ListenerOption {
	return func(l *SupervisionListener) {
		l.timer = t
	}
}

// WithParentLossHandler sets the handler invoked on parent loss.
func WithParentLossHandler(h ParentLossHandler) ListenerOption {
	return func(l *SupervisionListener) {
		l.handler = h
	}
}

// SupervisionListener monitors incoming messages from the parent. If no
// message is received within the configured timeout, it invokes the
// ParentLossHandler.
type SupervisionListener struct {
	mu       sync.Mutex
	timeout  uint16 // supervision check timeout in seconds (0 = disabled)
	interval uint16 // supervision interval in seconds
	counter  uint16 // number of supervision check failures
	running  bool
	timer    Timer
	handler  ParentLossHandler

	// done is closed to signal the internal goroutine to stop.
	done chan struct{}
}

// NewSupervisionListener creates a listener with the given options.
func NewSupervisionListener(opts ...ListenerOption) *SupervisionListener {
	l := &SupervisionListener{
		timeout:  DefaultSupervisionTimeout,
		interval: DefaultSupervisionInterval,
	}
	for _, o := range opts {
		o(l)
	}
	return l
}

// GetTimeout returns the supervision check timeout in seconds.
func (l *SupervisionListener) GetTimeout() uint16 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.timeout
}

// SetTimeout sets the supervision check timeout in seconds. Setting it to
// zero disables the supervision check.
func (l *SupervisionListener) SetTimeout(seconds uint16) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.timeout == seconds {
		return
	}
	l.timeout = seconds
	l.restartTimer()
}

// GetInterval returns the supervision interval in seconds.
func (l *SupervisionListener) GetInterval() uint16 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.interval
}

// SetInterval sets the supervision interval in seconds.
func (l *SupervisionListener) SetInterval(seconds uint16) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.interval == seconds {
		return
	}
	l.interval = seconds
}

// GetCounter returns the number of supervision check timeout failures.
func (l *SupervisionListener) GetCounter() uint16 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.counter
}

// ResetCounter resets the supervision check failure counter.
func (l *SupervisionListener) ResetCounter() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.counter = 0
}

// Start begins the supervision listener. If a timer is configured and
// timeout is non-zero, the timer is started.
func (l *SupervisionListener) Start() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return
	}
	l.running = true
	l.done = make(chan struct{})
	l.restartTimer()

	if l.timer != nil {
		go l.listenLoop()
	}
}

// Stop stops the supervision listener.
func (l *SupervisionListener) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.running {
		return
	}
	l.running = false
	if l.timer != nil {
		l.timer.Stop()
	}
	close(l.done)
}

// IsRunning reports whether the listener is active.
func (l *SupervisionListener) IsRunning() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.running
}

// UpdateOnReceive should be called when a secure frame is received from the
// parent. It restarts the supervision timer.
func (l *SupervisionListener) UpdateOnReceive() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.running {
		return
	}
	l.restartTimer()
}

// HandleTimer processes a supervision timeout event. It increments the
// failure counter and invokes the ParentLossHandler. This is exposed for
// deterministic testing; in production it is driven by the timer.
func (l *SupervisionListener) HandleTimer() {
	l.mu.Lock()
	l.counter++
	handler := l.handler
	l.restartTimer()
	l.mu.Unlock()

	if handler != nil {
		handler.HandleParentLoss()
	}
}

// restartTimer resets or stops the internal timer based on current config.
// Must be called with l.mu held.
func (l *SupervisionListener) restartTimer() {
	if l.timer == nil {
		return
	}
	if l.timeout != 0 && l.running {
		l.timer.Reset(time.Duration(l.timeout) * time.Second)
	} else {
		l.timer.Stop()
	}
}

// listenLoop runs in a goroutine and waits for timer fires.
func (l *SupervisionListener) listenLoop() {
	for {
		l.mu.Lock()
		if !l.running || l.timer == nil {
			l.mu.Unlock()
			return
		}
		ch := l.timer.C()
		done := l.done
		l.mu.Unlock()

		select {
		case <-done:
			return
		case _, ok := <-ch:
			if !ok {
				return
			}
			l.HandleTimer()
		}
	}
}
