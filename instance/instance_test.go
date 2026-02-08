// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --------------------------------------------------------------------------
// Instance lifecycle tests
// --------------------------------------------------------------------------

func TestNewInstance(t *testing.T) {
	inst := New(Config{})
	if inst == nil {
		t.Fatal("New() returned nil")
	}
	if inst.IsRunning() {
		t.Error("new instance should not be running")
	}
}

func TestStartStop(t *testing.T) {
	inst := New(Config{})

	if err := inst.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if !inst.IsRunning() {
		t.Error("instance should be running after Start()")
	}

	inst.Stop()
	if inst.IsRunning() {
		t.Error("instance should not be running after Stop()")
	}
}

func TestDoubleStart(t *testing.T) {
	inst := New(Config{})

	if err := inst.Start(); err != nil {
		t.Fatalf("first Start() error: %v", err)
	}
	defer inst.Stop()

	if err := inst.Start(); err == nil {
		t.Error("second Start() should return error")
	}
}

func TestStopIdempotent(t *testing.T) {
	inst := New(Config{})
	// Stop on a not-started instance should be a no-op.
	inst.Stop()
	if inst.IsRunning() {
		t.Error("Stop() on non-running instance should be safe")
	}
}

func TestRestart(t *testing.T) {
	inst := New(Config{})

	if err := inst.Start(); err != nil {
		t.Fatalf("first Start() error: %v", err)
	}
	inst.Stop()

	// Should be able to restart.
	if err := inst.Start(); err != nil {
		t.Fatalf("restart Start() error: %v", err)
	}
	inst.Stop()
}

// --------------------------------------------------------------------------
// PostTask tests
// --------------------------------------------------------------------------

func TestPostTask(t *testing.T) {
	inst := New(Config{})
	if err := inst.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer inst.Stop()

	done := make(chan struct{})
	inst.PostTask(func() {
		close(done)
	})

	select {
	case <-done:
		// success
	case <-time.After(time.Second):
		t.Fatal("PostTask function was not executed within 1s")
	}
}

func TestPostTaskOrdering(t *testing.T) {
	inst := New(Config{})
	if err := inst.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer inst.Stop()

	var mu sync.Mutex
	var order []int
	done := make(chan struct{})

	for i := range 5 {
		v := i
		inst.PostTask(func() {
			mu.Lock()
			order = append(order, v)
			if len(order) == 5 {
				close(done)
			}
			mu.Unlock()
		})
	}

	select {
	case <-done:
		mu.Lock()
		defer mu.Unlock()
		for i, v := range order {
			if v != i {
				t.Errorf("order[%d] = %d, want %d", i, v, i)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tasks were not completed within 2s")
	}
}

func TestPostTaskFromTask(t *testing.T) {
	inst := New(Config{})
	if err := inst.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer inst.Stop()

	done := make(chan int, 1)
	inst.PostTask(func() {
		// Post another task from within a task.
		inst.PostTask(func() {
			done <- 42
		})
	})

	select {
	case v := <-done:
		if v != 42 {
			t.Errorf("got %d, want 42", v)
		}
	case <-time.After(time.Second):
		t.Fatal("nested PostTask was not executed within 1s")
	}
}

// --------------------------------------------------------------------------
// Timer tests
// --------------------------------------------------------------------------

func TestScheduleTimer(t *testing.T) {
	inst := New(Config{})
	if err := inst.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer inst.Stop()

	done := make(chan struct{})
	inst.ScheduleTimer(50*time.Millisecond, func() {
		close(done)
	})

	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("timer did not fire within 2s")
	}
}

func TestTimerOrdering(t *testing.T) {
	inst := New(Config{})
	if err := inst.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer inst.Stop()

	var mu sync.Mutex
	var order []int
	done := make(chan struct{})

	// Schedule timers in reverse order — should fire in chronological order.
	inst.PostTask(func() {
		inst.timers.schedule(150*time.Millisecond, func() {
			mu.Lock()
			order = append(order, 3)
			if len(order) == 3 {
				close(done)
			}
			mu.Unlock()
		})
		inst.timers.schedule(50*time.Millisecond, func() {
			mu.Lock()
			order = append(order, 1)
			mu.Unlock()
		})
		inst.timers.schedule(100*time.Millisecond, func() {
			mu.Lock()
			order = append(order, 2)
			mu.Unlock()
		})
	})

	select {
	case <-done:
		mu.Lock()
		defer mu.Unlock()
		if len(order) != 3 {
			t.Fatalf("expected 3 timers, got %d", len(order))
		}
		for i, v := range order {
			if v != i+1 {
				t.Errorf("order[%d] = %d, want %d", i, v, i+1)
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timers did not complete within 3s")
	}
}

// --------------------------------------------------------------------------
// Notifier tests
// --------------------------------------------------------------------------

func TestNotifierSignalAndProcess(t *testing.T) {
	n := &notifier{}

	var received Event
	n.register(func(events Event) {
		received = events
	})

	n.signal(EventThreadRoleChanged | EventChannelChanged)
	if !n.process() {
		t.Error("process() should return true when events are pending")
	}

	if received != EventThreadRoleChanged|EventChannelChanged {
		t.Errorf("received events = %#08x, want %#08x",
			received, EventThreadRoleChanged|EventChannelChanged)
	}

	// Second process should return false (no pending events).
	if n.process() {
		t.Error("process() should return false when no events are pending")
	}
}

func TestNotifierMultipleCallbacks(t *testing.T) {
	n := &notifier{}

	var count int32
	for range 3 {
		n.register(func(_ Event) {
			count++
		})
	}

	n.signal(EventIPv6AddressAdded)
	n.process()

	if count != 3 {
		t.Errorf("expected 3 callbacks, got %d", count)
	}
}

func TestNotifierViaInstance(t *testing.T) {
	inst := New(Config{})

	var received atomic.Uint32
	inst.RegisterNotifier(func(events Event) {
		received.Store(uint32(events))
	})

	if err := inst.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer inst.Stop()

	done := make(chan struct{})
	inst.PostTask(func() {
		inst.SignalEvents(EventActiveDatasetChanged)
		// Notifier is processed after task completes in event loop,
		// but we need to trigger another task to ensure processing.
		inst.PostTask(func() {
			close(done)
		})
	})

	select {
	case <-done:
		// Give a moment for the notifier to be processed.
		time.Sleep(50 * time.Millisecond)
		got := Event(received.Load())
		if got != EventActiveDatasetChanged {
			t.Errorf("notifier received %#08x, want %#08x", got, EventActiveDatasetChanged)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("notifier test timed out")
	}
}

// --------------------------------------------------------------------------
// Timer scheduler unit tests
// --------------------------------------------------------------------------

func TestTimerSchedulerCount(t *testing.T) {
	ts := &timerScheduler{}
	if ts.count() != 0 {
		t.Errorf("empty scheduler count = %d, want 0", ts.count())
	}

	ts.schedule(time.Hour, func() {})
	ts.schedule(time.Hour, func() {})
	if ts.count() != 2 {
		t.Errorf("scheduler count = %d, want 2", ts.count())
	}
}

func TestTimerSchedulerNextDeadline(t *testing.T) {
	ts := &timerScheduler{}

	_, ok := ts.nextDeadline()
	if ok {
		t.Error("nextDeadline() should return false for empty scheduler")
	}

	ts.schedule(100*time.Millisecond, func() {})
	d, ok := ts.nextDeadline()
	if !ok {
		t.Error("nextDeadline() should return true with pending timer")
	}
	if d > 100*time.Millisecond {
		t.Errorf("nextDeadline() = %v, want <= 100ms", d)
	}
}

func TestTimerSchedulerProcessExpired(t *testing.T) {
	ts := &timerScheduler{}

	var fired int
	ts.schedule(0, func() { fired++ })         // fires immediately
	ts.schedule(0, func() { fired++ })         // fires immediately
	ts.schedule(time.Hour, func() { fired++ }) // should NOT fire

	count := ts.processExpired()
	if count != 2 {
		t.Errorf("processExpired() = %d, want 2", count)
	}
	if fired != 2 {
		t.Errorf("fired = %d, want 2", fired)
	}
	if ts.count() != 1 {
		t.Errorf("remaining timers = %d, want 1", ts.count())
	}
}

// --------------------------------------------------------------------------
// Event constant tests
// --------------------------------------------------------------------------

func TestEventConstants(t *testing.T) {
	// Verify events are distinct powers of 2.
	events := []Event{
		EventIPv6AddressAdded,
		EventIPv6AddressRemoved,
		EventThreadRoleChanged,
		EventThreadLinkLocalAddrChanged,
		EventThreadMeshLocalAddrChanged,
		EventThreadRlocAdded,
		EventThreadRlocRemoved,
		EventThreadNetDataChanged,
		EventThreadChildAdded,
		EventThreadChildRemoved,
		EventChannelChanged,
		EventSecurityPolicyChanged,
		EventActiveDatasetChanged,
		EventPendingDatasetChanged,
	}

	seen := make(map[Event]bool)
	for _, e := range events {
		if seen[e] {
			t.Errorf("duplicate event value: %#08x", e)
		}
		seen[e] = true

		// Each should be a power of 2.
		if e == 0 || e&(e-1) != 0 {
			t.Errorf("event %#08x is not a power of 2", e)
		}
	}
}

// --------------------------------------------------------------------------
// Platform accessor tests
// --------------------------------------------------------------------------

func TestInstanceAccessors(t *testing.T) {
	inst := New(Config{})

	// All should be nil since no platform was provided.
	if inst.Alarm() != nil {
		t.Error("Alarm() should be nil")
	}
	if inst.Entropy() != nil {
		t.Error("Entropy() should be nil")
	}
	if inst.Settings() != nil {
		t.Error("Settings() should be nil")
	}
	if inst.Logger() != nil {
		t.Error("Logger() should be nil")
	}
	if inst.Radio() != nil {
		t.Error("Radio() should be nil")
	}
}

// --------------------------------------------------------------------------
// Drain tasks on stop
// --------------------------------------------------------------------------

func TestDrainOnStop(t *testing.T) {
	inst := New(Config{})
	if err := inst.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	var executed atomic.Int32

	// Post several tasks and immediately stop.
	for range 10 {
		inst.PostTask(func() {
			executed.Add(1)
		})
	}

	// Give time for some tasks to be processed.
	time.Sleep(50 * time.Millisecond)
	inst.Stop()

	// At least some tasks should have been executed.
	if executed.Load() == 0 {
		t.Error("expected at least some tasks to be executed before/during stop")
	}
}
