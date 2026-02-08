// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package instance provides the central Instance struct and event loop for
// gothread. Instance owns all Thread stack modules and drives them via a
// single-goroutine cooperative event loop.
//
// This is a Go port of the Instance, Tasklet, Timer, and Notifier
// subsystems from OpenThread's src/core/instance/ and
// src/core/common/ directories.
package instance

import (
	"sync"
	"time"

	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/radio"
)

// --------------------------------------------------------------------------
// Notifier — event flag dispatch
// --------------------------------------------------------------------------

// Event is a bitmask of state-change events that modules can signal.
type Event uint32

const (
	// EventIPv6AddressAdded signals that an IPv6 address was added.
	EventIPv6AddressAdded Event = 1 << 0
	// EventIPv6AddressRemoved signals that an IPv6 address was removed.
	EventIPv6AddressRemoved Event = 1 << 1
	// EventThreadRoleChanged signals that the Thread device role changed.
	EventThreadRoleChanged Event = 1 << 2
	// EventThreadLinkLocalAddrChanged signals a link-local address change.
	EventThreadLinkLocalAddrChanged Event = 1 << 3
	// EventThreadMeshLocalAddrChanged signals a mesh-local address change.
	EventThreadMeshLocalAddrChanged Event = 1 << 4
	// EventThreadRlocAdded signals that an RLOC address was added.
	EventThreadRlocAdded Event = 1 << 5
	// EventThreadRlocRemoved signals that an RLOC address was removed.
	EventThreadRlocRemoved Event = 1 << 6
	// EventThreadNetDataChanged signals a network data change.
	EventThreadNetDataChanged Event = 1 << 7
	// EventThreadChildAdded signals that a child was added.
	EventThreadChildAdded Event = 1 << 8
	// EventThreadChildRemoved signals that a child was removed.
	EventThreadChildRemoved Event = 1 << 9
	// EventChannelChanged signals that the radio channel changed.
	EventChannelChanged Event = 1 << 10
	// EventSecurityPolicyChanged signals a security policy change.
	EventSecurityPolicyChanged Event = 1 << 11
	// EventActiveDatasetChanged signals an active dataset change.
	EventActiveDatasetChanged Event = 1 << 12
	// EventPendingDatasetChanged signals a pending dataset change.
	EventPendingDatasetChanged Event = 1 << 13
)

// NotifierCallback is a function invoked when notifier events are dispatched.
type NotifierCallback func(events Event)

// notifier tracks pending events and dispatches them to registered callbacks.
type notifier struct {
	pending   Event
	callbacks []NotifierCallback
}

// signal sets the given events as pending.
func (n *notifier) signal(events Event) {
	n.pending |= events
}

// process dispatches all pending events to registered callbacks, then
// clears the pending flags. Returns true if any events were dispatched.
func (n *notifier) process() bool {
	if n.pending == 0 {
		return false
	}
	events := n.pending
	n.pending = 0
	for _, cb := range n.callbacks {
		cb(events)
	}
	return true
}

// register adds a callback for notifier events.
func (n *notifier) register(cb NotifierCallback) {
	n.callbacks = append(n.callbacks, cb)
}

// --------------------------------------------------------------------------
// Timer — sorted timer list
// --------------------------------------------------------------------------

// timer represents a scheduled callback that fires after a delay.
type timer struct {
	fireAt time.Time
	fn     func()
}

// timerScheduler maintains a sorted list of pending timers.
type timerScheduler struct {
	timers []timer
}

// schedule adds a timer that fires after delay, calling fn.
func (ts *timerScheduler) schedule(delay time.Duration, fn func()) {
	fireAt := time.Now().Add(delay)
	// Insert in sorted order (earliest first).
	idx := 0
	for idx < len(ts.timers) && ts.timers[idx].fireAt.Before(fireAt) {
		idx++
	}
	ts.timers = append(ts.timers, timer{})
	copy(ts.timers[idx+1:], ts.timers[idx:])
	ts.timers[idx] = timer{fireAt: fireAt, fn: fn}
}

// processExpired fires all timers whose deadline has passed. Returns the
// number of timers fired.
func (ts *timerScheduler) processExpired() int {
	now := time.Now()
	fired := 0
	for len(ts.timers) > 0 && !ts.timers[0].fireAt.After(now) {
		fn := ts.timers[0].fn
		ts.timers = ts.timers[1:]
		fn()
		fired++
	}
	return fired
}

// nextDeadline returns the time until the next timer fires, or 0 if there
// are no pending timers. The bool return is false if no timers are pending.
func (ts *timerScheduler) nextDeadline() (time.Duration, bool) {
	if len(ts.timers) == 0 {
		return 0, false
	}
	d := time.Until(ts.timers[0].fireAt)
	if d < 0 {
		d = 0
	}
	return d, true
}

// count returns the number of pending timers.
func (ts *timerScheduler) count() int {
	return len(ts.timers)
}

// --------------------------------------------------------------------------
// Config — dependency injection
// --------------------------------------------------------------------------

// Config holds the platform dependencies injected into an Instance.
type Config struct {
	// Alarm provides millisecond-precision timing.
	Alarm platform.Alarm
	// Entropy provides cryptographic random bytes.
	Entropy platform.Entropy
	// Settings provides persistent non-volatile storage.
	Settings platform.Settings
	// Logger provides platform logging.
	Logger platform.Logger
	// Radio provides IEEE 802.15.4 radio access.
	Radio radio.Radio
}

// --------------------------------------------------------------------------
// Instance — the central Thread stack object
// --------------------------------------------------------------------------

// Instance is the central object that owns all Thread stack modules and
// drives them via a single-goroutine cooperative event loop.
//
// The event loop processes tasks (posted functions), timers, and notifier
// events. All stack operations run on the event loop goroutine, avoiding
// the need for locks within individual modules.
type Instance struct {
	// Platform interfaces
	alarm    platform.Alarm
	entropy  platform.Entropy
	settings platform.Settings
	logger   platform.Logger
	radio    radio.Radio

	// Event loop
	taskCh chan func()
	stopCh chan struct{}
	doneCh chan struct{}

	// Timer scheduler (accessed only from event loop goroutine)
	timers *timerScheduler

	// Notifier (accessed only from event loop goroutine)
	notifier *notifier

	// running tracks whether the event loop is active.
	running   bool
	runningMu sync.Mutex
}

// New creates a new Instance with the given platform configuration.
// Call Start() to begin the event loop.
func New(config Config) *Instance {
	return &Instance{
		alarm:    config.Alarm,
		entropy:  config.Entropy,
		settings: config.Settings,
		logger:   config.Logger,
		radio:    config.Radio,
		taskCh:   make(chan func(), 256),
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
		timers:   &timerScheduler{},
		notifier: &notifier{},
	}
}

// Start launches the event loop goroutine. It is an error to call Start
// on an already-running Instance.
func (inst *Instance) Start() error {
	inst.runningMu.Lock()
	if inst.running {
		inst.runningMu.Unlock()
		return errAlreadyRunning
	}
	inst.running = true
	inst.runningMu.Unlock()

	go inst.eventLoop()
	return nil
}

// Stop signals the event loop to shut down and waits for it to finish.
func (inst *Instance) Stop() {
	inst.runningMu.Lock()
	if !inst.running {
		inst.runningMu.Unlock()
		return
	}
	inst.runningMu.Unlock()

	close(inst.stopCh)
	<-inst.doneCh

	inst.runningMu.Lock()
	inst.running = false
	// Reset channels for potential restart.
	inst.stopCh = make(chan struct{})
	inst.doneCh = make(chan struct{})
	inst.runningMu.Unlock()
}

// IsRunning reports whether the event loop is active.
func (inst *Instance) IsRunning() bool {
	inst.runningMu.Lock()
	defer inst.runningMu.Unlock()
	return inst.running
}

// PostTask schedules a function to run on the event loop goroutine.
// It is safe to call from any goroutine. If the task channel is full,
// PostTask blocks until space is available.
func (inst *Instance) PostTask(fn func()) {
	inst.taskCh <- fn
}

// ScheduleTimer schedules a function to run after the given delay on
// the event loop goroutine.
func (inst *Instance) ScheduleTimer(delay time.Duration, fn func()) {
	inst.PostTask(func() {
		inst.timers.schedule(delay, fn)
	})
}

// SignalEvents signals notifier events from within the event loop.
// Must be called from the event loop goroutine (e.g. from a posted task).
func (inst *Instance) SignalEvents(events Event) {
	inst.notifier.signal(events)
}

// RegisterNotifier registers a callback for notifier events. Must be
// called before Start() or from within a posted task.
func (inst *Instance) RegisterNotifier(cb NotifierCallback) {
	inst.notifier.register(cb)
}

// Alarm returns the platform Alarm interface.
func (inst *Instance) Alarm() platform.Alarm { return inst.alarm }

// Entropy returns the platform Entropy interface.
func (inst *Instance) Entropy() platform.Entropy { return inst.entropy }

// Settings returns the platform Settings interface.
func (inst *Instance) Settings() platform.Settings { return inst.settings }

// Logger returns the platform Logger interface.
func (inst *Instance) Logger() platform.Logger { return inst.logger }

// Radio returns the platform Radio interface.
func (inst *Instance) Radio() radio.Radio { return inst.radio }

// --------------------------------------------------------------------------
// Event loop
// --------------------------------------------------------------------------

// eventLoop is the main processing loop. It runs in a single goroutine
// and processes tasks, timers, and notifier events cooperatively.
func (inst *Instance) eventLoop() {
	defer close(inst.doneCh)

	for {
		// Determine how long to wait for the next timer.
		var timerCh <-chan time.Time
		if d, ok := inst.timers.nextDeadline(); ok {
			timerCh = time.After(d)
		}

		select {
		case <-inst.stopCh:
			// Drain remaining tasks before exit.
			inst.drainTasks()
			return

		case fn := <-inst.taskCh:
			fn()
			// After running a task, process any timers and notifier events.
			inst.timers.processExpired()
			inst.notifier.process()

		case <-timerCh:
			inst.timers.processExpired()
			inst.notifier.process()
		}
	}
}

// drainTasks processes any remaining tasks in the channel.
func (inst *Instance) drainTasks() {
	for {
		select {
		case fn := <-inst.taskCh:
			fn()
		default:
			return
		}
	}
}

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

// errAlreadyRunning is returned when Start is called on a running Instance.
var errAlreadyRunning = &instanceError{msg: "instance: already running"}

type instanceError struct {
	msg string
}

func (e *instanceError) Error() string {
	return e.msg
}
