// Copyright (c) 2026, Jan Hillegeer. All rights reserved.
// Copyright (c) 2016-2017, The OpenThread Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from this
//    software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

// Package notifier implements the OpenThread state-change notification system.
//
// This is a Go port of openthread/src/core/common/notifier.hpp and
// notifier.cpp. It allows subsystems to register callbacks that are invoked
// when specific events occur, using a bitmask-based event model.
package notifier

import "sync"

// Events is a bitmask of event flags that have been signaled.
type Events uint32

// Event flag constants matching OpenThread's Event enum.
// Each event is a single bit in the Events bitmask.
const (
	EventIPv6AddressAdded          Events = 1 << 0
	EventIPv6AddressRemoved        Events = 1 << 1
	EventRole                      Events = 1 << 2
	EventLinkLocalAddr             Events = 1 << 3
	EventMeshLocalAddr             Events = 1 << 4
	EventRlocAdded                 Events = 1 << 5
	EventRlocRemoved               Events = 1 << 6
	EventPartitionId               Events = 1 << 7
	EventThreadKeySeqCounter       Events = 1 << 8
	EventThreadNetdata             Events = 1 << 9
	EventChildAdded                Events = 1 << 10
	EventChildRemoved              Events = 1 << 11
	EventIPv6MulticastSubscribed   Events = 1 << 12
	EventIPv6MulticastUnsubscribed Events = 1 << 13
	EventChannel                   Events = 1 << 14
	EventPanId                     Events = 1 << 15
	EventNetworkName               Events = 1 << 16
	EventExtPanId                  Events = 1 << 17
	EventNetworkKey                Events = 1 << 18
	EventPSKc                      Events = 1 << 19
	EventSecurityPolicy            Events = 1 << 20
	EventChannelManagerNewChannel  Events = 1 << 21
	EventSupportedChannelMask      Events = 1 << 22
	EventCommissionerState         Events = 1 << 23
	EventNetifState                Events = 1 << 24
	EventBackboneRouterState       Events = 1 << 25
	EventBackboneRouterLocal       Events = 1 << 26
	EventJoinerState               Events = 1 << 27
	EventActiveDataset             Events = 1 << 28
	EventPendingDataset            Events = 1 << 29
	EventNat64TranslatorState      Events = 1 << 30
	EventParentLinkQuality         Events = 1 << 31

	// Aliases used by the task description.
	EventLinkState  = EventNetifState
	EventJoinerPort = EventJoinerState
)

// Contains reports whether e includes all bits in event.
func (e Events) Contains(event Events) bool { return e&event == event }

// ContainsAny reports whether e includes any bits in events.
func (e Events) ContainsAny(events Events) bool { return e&events != 0 }

// IsEmpty reports whether e has no events set.
func (e Events) IsEmpty() bool { return e == 0 }

// Callback is the signature for notifier event handlers.
type Callback func(events Events)

// Notifier collects pending events and dispatches them to registered
// callbacks when Process is called.
type Notifier struct {
	mu             sync.Mutex
	callbacks      []Callback
	eventsToSignal Events
	signaledEvents Events
}

// New creates a Notifier with no registered callbacks.
func New() *Notifier {
	return &Notifier{}
}

// RegisterCallback adds a callback to be invoked on Process.
func (n *Notifier) RegisterCallback(cb Callback) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.callbacks = append(n.callbacks, cb)
}

// Signal schedules event(s) for the next Process call and records them in
// the signaled-ever set.
func (n *Notifier) Signal(events Events) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.eventsToSignal |= events
	n.signaledEvents |= events
}

// SignalIfFirst schedules event(s) only if they have never been signaled
// before (i.e., not present in the signaled-ever set).
func (n *Notifier) SignalIfFirst(events Events) {
	n.mu.Lock()
	defer n.mu.Unlock()
	first := events &^ n.signaledEvents
	if first != 0 {
		n.eventsToSignal |= first
		n.signaledEvents |= first
	}
}

// HasSignaled reports whether event has ever been signaled (including events
// that have already been processed).
func (n *Notifier) HasSignaled(event Events) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.signaledEvents&event == event
}

// IsPending reports whether there are unprocessed events.
func (n *Notifier) IsPending() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.eventsToSignal != 0
}

// Process drains all pending events and invokes every registered callback
// with the accumulated event set. Callbacks are invoked with the lock
// released so they may call Signal without deadlock.
func (n *Notifier) Process() {
	n.mu.Lock()
	if n.eventsToSignal == 0 {
		n.mu.Unlock()
		return
	}
	events := n.eventsToSignal
	n.eventsToSignal = 0
	// Snapshot callbacks to avoid holding the lock during invocation.
	cbs := make([]Callback, len(n.callbacks))
	copy(cbs, n.callbacks)
	n.mu.Unlock()

	for _, cb := range cbs {
		cb(events)
	}
}
