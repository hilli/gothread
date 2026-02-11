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

package notifier

import (
	"testing"
)

func TestSignalAndProcess(t *testing.T) {
	n := New()
	var received Events

	n.RegisterCallback(func(events Events) {
		received = events
	})

	n.Signal(EventRole)
	n.Signal(EventNetworkKey)
	n.Process()

	want := EventRole | EventNetworkKey
	if received != want {
		t.Errorf("received = 0x%08x, want 0x%08x", received, want)
	}
}

func TestProcessClearsPending(t *testing.T) {
	n := New()
	n.Signal(EventRole)
	n.Process()

	if n.IsPending() {
		t.Error("expected no pending events after Process")
	}

	// Second Process should be a no-op.
	var called bool
	n.RegisterCallback(func(Events) { called = true })
	n.Process()
	if called {
		t.Error("callback should not be called when no pending events")
	}
}

func TestMultipleCallbacks(t *testing.T) {
	n := New()
	var count int

	n.RegisterCallback(func(Events) { count++ })
	n.RegisterCallback(func(Events) { count++ })
	n.RegisterCallback(func(Events) { count++ })

	n.Signal(EventPSKc)
	n.Process()

	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
}

func TestSignalIfFirst(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(n *Notifier)
		signal     Events
		wantSignal bool
	}{
		{
			name:       "first time",
			setup:      func(n *Notifier) {},
			signal:     EventChannel,
			wantSignal: true,
		},
		{
			name: "already signaled",
			setup: func(n *Notifier) {
				n.Signal(EventChannel)
				n.Process()
			},
			signal:     EventChannel,
			wantSignal: false,
		},
		{
			name: "different event",
			setup: func(n *Notifier) {
				n.Signal(EventChannel)
				n.Process()
			},
			signal:     EventPanId,
			wantSignal: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := New()
			tt.setup(n)
			n.SignalIfFirst(tt.signal)
			if got := n.IsPending(); got != tt.wantSignal {
				t.Errorf("IsPending() = %v, want %v", got, tt.wantSignal)
			}
		})
	}
}

func TestHasSignaled(t *testing.T) {
	n := New()

	if n.HasSignaled(EventRole) {
		t.Error("HasSignaled should be false before any signal")
	}

	n.Signal(EventRole)
	if !n.HasSignaled(EventRole) {
		t.Error("HasSignaled should be true after Signal")
	}

	n.Process()
	if !n.HasSignaled(EventRole) {
		t.Error("HasSignaled should remain true after Process")
	}
}

func TestEventsContains(t *testing.T) {
	tests := []struct {
		name string
		e    Events
		q    Events
		want bool
	}{
		{"single match", EventRole | EventPSKc, EventRole, true},
		{"both match", EventRole | EventPSKc, EventRole | EventPSKc, true},
		{"partial match", EventRole, EventRole | EventPSKc, false},
		{"no match", EventRole, EventChannel, false},
		{"empty", 0, EventRole, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.Contains(tt.q); got != tt.want {
				t.Errorf("Contains = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEventsContainsAny(t *testing.T) {
	tests := []struct {
		name string
		e    Events
		q    Events
		want bool
	}{
		{"overlap", EventRole | EventPSKc, EventPSKc | EventChannel, true},
		{"no overlap", EventRole, EventChannel, false},
		{"empty", 0, EventRole, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.ContainsAny(tt.q); got != tt.want {
				t.Errorf("ContainsAny = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEventsIsEmpty(t *testing.T) {
	if !(Events(0)).IsEmpty() {
		t.Error("zero Events should be empty")
	}
	if EventRole.IsEmpty() {
		t.Error("non-zero Events should not be empty")
	}
}

func TestProcessNoCallbacks(t *testing.T) {
	n := New()
	n.Signal(EventRole)
	n.Process() // should not panic
	if n.IsPending() {
		t.Error("expected no pending after Process")
	}
}

func TestCallbackSignalsDuringProcess(t *testing.T) {
	n := New()
	var secondCall Events

	n.RegisterCallback(func(events Events) {
		if events.Contains(EventRole) {
			n.Signal(EventChannel) // signal new event during callback
		}
		if events.Contains(EventChannel) {
			secondCall = events
		}
	})

	n.Signal(EventRole)
	n.Process()

	// The new event should be pending now.
	if !n.IsPending() {
		t.Error("expected pending event after callback signaled new event")
	}

	// Process the second batch.
	n.Process()
	if secondCall != EventChannel {
		t.Errorf("secondCall = 0x%08x, want 0x%08x", secondCall, EventChannel)
	}
}

func TestEventAliases(t *testing.T) {
	// Verify that aliases refer to the same underlying values.
	if EventLinkState != EventNetifState {
		t.Error("EventLinkState should equal EventNetifState")
	}
	if EventJoinerPort != EventJoinerState {
		t.Error("EventJoinerPort should equal EventJoinerState")
	}
}
