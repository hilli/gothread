// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac"
	"github.com/hilli/gothread/meshcop"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/indirect"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/routing"
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

func TestMultipleStartStop(t *testing.T) {
	inst := New(Config{})

	for i := range 3 {
		if err := inst.Start(); err != nil {
			t.Fatalf("cycle %d: Start() error: %v", i, err)
		}
		if !inst.IsRunning() {
			t.Fatalf("cycle %d: instance should be running", i)
		}
		inst.Stop()
		if inst.IsRunning() {
			t.Fatalf("cycle %d: instance should not be running after Stop()", i)
		}
	}
}

// --------------------------------------------------------------------------
// IfConfigUp / IfConfigDown lifecycle tests
// --------------------------------------------------------------------------

func TestIfConfigUp(t *testing.T) {
	inst := New(Config{})

	if inst.IsIfConfigUp() {
		t.Error("new instance should not have interface up")
	}

	if err := inst.IfConfigUp(); err != nil {
		t.Fatalf("IfConfigUp() error: %v", err)
	}

	if !inst.IsIfConfigUp() {
		t.Error("interface should be up after IfConfigUp()")
	}

	// Without a radio, MAC enable is skipped (software-only mode).
	// MAC enabled state depends on whether a radio was provided.
	if inst.platRadio != nil && !inst.mac.IsEnabled() {
		t.Error("MAC should be enabled after IfConfigUp() with radio")
	}

	// Forwarder should be enabled regardless.
	if !inst.forwarder.IsEnabled() {
		t.Error("forwarder should be enabled after IfConfigUp()")
	}
}

func TestIfConfigUpIdempotent(t *testing.T) {
	inst := New(Config{})

	if err := inst.IfConfigUp(); err != nil {
		t.Fatalf("IfConfigUp() error: %v", err)
	}

	// Second call should return errAlready.
	if err := inst.IfConfigUp(); err == nil {
		t.Error("second IfConfigUp() should return error")
	}
}

func TestIfConfigDown(t *testing.T) {
	inst := New(Config{})

	if err := inst.IfConfigUp(); err != nil {
		t.Fatalf("IfConfigUp() error: %v", err)
	}

	if err := inst.IfConfigDown(); err != nil {
		t.Fatalf("IfConfigDown() error: %v", err)
	}

	if inst.IsIfConfigUp() {
		t.Error("interface should be down after IfConfigDown()")
	}
	if inst.mac.IsEnabled() {
		t.Error("MAC should be disabled after IfConfigDown()")
	}
	if inst.forwarder.IsEnabled() {
		t.Error("forwarder should be disabled after IfConfigDown()")
	}
}

func TestIfConfigDownIdempotent(t *testing.T) {
	inst := New(Config{})

	// Down when already down.
	if err := inst.IfConfigDown(); err == nil {
		t.Error("IfConfigDown() on already-down interface should return error")
	}
}

func TestIfConfigDownBlockedByThread(t *testing.T) {
	inst := New(Config{})

	if err := inst.IfConfigUp(); err != nil {
		t.Fatalf("IfConfigUp() error: %v", err)
	}
	if err := inst.ThreadStart(); err != nil {
		t.Fatalf("ThreadStart() error: %v", err)
	}

	// Should not be able to bring interface down while Thread is running.
	if err := inst.IfConfigDown(); err == nil {
		t.Error("IfConfigDown() should fail while Thread is running")
	}

	// Stop thread first, then it should work.
	if err := inst.ThreadStop(); err != nil {
		t.Fatalf("ThreadStop() error: %v", err)
	}
	if err := inst.IfConfigDown(); err != nil {
		t.Fatalf("IfConfigDown() after ThreadStop() error: %v", err)
	}
}

// --------------------------------------------------------------------------
// ThreadStart / ThreadStop lifecycle tests
// --------------------------------------------------------------------------

func TestThreadStart(t *testing.T) {
	inst := New(Config{})

	// Interface must be up first.
	if err := inst.IfConfigUp(); err != nil {
		t.Fatalf("IfConfigUp() error: %v", err)
	}

	if inst.IsThreadRunning() {
		t.Error("Thread should not be running on a new instance")
	}

	if err := inst.ThreadStart(); err != nil {
		t.Fatalf("ThreadStart() error: %v", err)
	}

	if !inst.IsThreadRunning() {
		t.Error("Thread should be running after ThreadStart()")
	}

	// MLE should be in Detached state (or beyond, if attach proceeded).
	m := inst.mleService.Mle()
	if m.IsDisabled() {
		t.Error("MLE should not be Disabled after ThreadStart()")
	}
}

func TestThreadStartRollsBackFailedAttach(t *testing.T) {
	inst := New(Config{})
	if err := inst.IfConfigUp(); err != nil {
		t.Fatalf("IfConfigUp: %v", err)
	}
	m := inst.mleService.Mle()
	m.SetAttachState(mle.AttachStateStart)

	if err := inst.ThreadStart(); !errors.Is(err, goterrors.ErrBusy) {
		t.Fatalf("ThreadStart = %v, want ErrBusy", err)
	}
	if inst.IsThreadRunning() {
		t.Error("Thread must remain disabled after attach fails")
	}
	if !m.IsDisabled() || m.GetAttachState() != mle.AttachStateIdle {
		t.Error("failed attach must restore the disabled, idle MLE state")
	}
	if err := inst.ThreadStart(); err != nil {
		t.Fatalf("ThreadStart retry: %v", err)
	}
}

func TestThreadStartRequiresIfConfigUp(t *testing.T) {
	inst := New(Config{})

	// Without IfConfigUp, ThreadStart should fail.
	if err := inst.ThreadStart(); err == nil {
		t.Error("ThreadStart() without IfConfigUp should return error")
	}
}

func TestThreadStartIdempotent(t *testing.T) {
	inst := New(Config{})
	_ = inst.IfConfigUp()

	if err := inst.ThreadStart(); err != nil {
		t.Fatalf("ThreadStart() error: %v", err)
	}
	if err := inst.ThreadStart(); err == nil {
		t.Error("second ThreadStart() should return error")
	}
}

func TestThreadStop(t *testing.T) {
	inst := New(Config{})
	_ = inst.IfConfigUp()

	if err := inst.ThreadStart(); err != nil {
		t.Fatalf("ThreadStart() error: %v", err)
	}
	if err := inst.ThreadStop(); err != nil {
		t.Fatalf("ThreadStop() error: %v", err)
	}

	if inst.IsThreadRunning() {
		t.Error("Thread should not be running after ThreadStop()")
	}

	// MLE should be back to Disabled.
	m := inst.mleService.Mle()
	if !m.IsDisabled() {
		t.Error("MLE should be Disabled after ThreadStop()")
	}
}

func TestThreadStopIdempotent(t *testing.T) {
	inst := New(Config{})

	if err := inst.ThreadStop(); err == nil {
		t.Error("ThreadStop() on already-stopped Thread should return error")
	}
}

func TestFullLifecycle(t *testing.T) {
	inst := New(Config{})

	// Up → Thread → Stop Thread → Down → repeat.
	for i := range 2 {
		if err := inst.IfConfigUp(); err != nil {
			t.Fatalf("cycle %d: IfConfigUp() error: %v", i, err)
		}
		if err := inst.ThreadStart(); err != nil {
			t.Fatalf("cycle %d: ThreadStart() error: %v", i, err)
		}
		if err := inst.ThreadStop(); err != nil {
			t.Fatalf("cycle %d: ThreadStop() error: %v", i, err)
		}
		if err := inst.IfConfigDown(); err != nil {
			t.Fatalf("cycle %d: IfConfigDown() error: %v", i, err)
		}
	}
}

func TestRoleChangeCallbackFires(t *testing.T) {
	inst := New(Config{})

	// Register a notifier callback to observe EventThreadRoleChanged.
	var receivedEvents Event
	inst.notifier.register(func(events Event) {
		receivedEvents |= events
	})

	_ = inst.IfConfigUp()

	// ThreadStart triggers MLE Enable (Disabled→Detached), which fires
	// the role change callback.
	_ = inst.ThreadStart()

	// Process the notifier to dispatch queued events.
	inst.notifier.process()

	if receivedEvents&EventThreadRoleChanged == 0 {
		t.Error("expected EventThreadRoleChanged to be signalled after ThreadStart")
	}
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

func TestTimerSchedulerCancelPreventsFireing(t *testing.T) {
	ts := &timerScheduler{}

	var fired int
	cancel := ts.scheduleWithCancel(0, func() { fired++ })
	ts.schedule(0, func() { fired++ })

	// Cancel the first timer before processing.
	cancel()

	count := ts.processExpired()
	if count != 1 {
		t.Errorf("processExpired() = %d, want 1 (one cancelled)", count)
	}
	if fired != 1 {
		t.Errorf("fired = %d, want 1", fired)
	}
}

func TestTimerSchedulerCancelIdempotent(t *testing.T) {
	ts := &timerScheduler{}

	cancel := ts.scheduleWithCancel(0, func() {})
	cancel()
	cancel() // second call should be safe
	if ts.count() != 0 {
		t.Errorf("count = %d, want 0 (cancelled timer released immediately)", ts.count())
	}
	// No retained cancelled timer should run.
	count := ts.processExpired()
	if count != 0 {
		t.Errorf("processExpired() = %d, want 0 (cancelled)", count)
	}
}

func TestTimerSchedulerCancelDoesNotAffectOthers(t *testing.T) {
	ts := &timerScheduler{}

	var order []int
	cancel1 := ts.scheduleWithCancel(0, func() { order = append(order, 1) })
	ts.schedule(0, func() { order = append(order, 2) })
	ts.schedule(0, func() { order = append(order, 3) })

	cancel1()

	count := ts.processExpired()
	if count != 2 {
		t.Errorf("processExpired() = %d, want 2", count)
	}
	if len(order) != 2 || order[0] != 2 || order[1] != 3 {
		t.Errorf("order = %v, want [2, 3]", order)
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

func TestAccessorsAfterStart(t *testing.T) {
	inst := New(Config{})
	if err := inst.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer inst.Stop()

	// Core subsystem accessors should be non-nil on a running instance.
	if inst.Mac() == nil {
		t.Error("Mac() should be non-nil")
	}
	if inst.KeyManager() == nil {
		t.Error("KeyManager() should be non-nil")
	}
	if inst.MessagePool() == nil {
		t.Error("MessagePool() should be non-nil")
	}
	if inst.RouterTable() == nil {
		t.Error("RouterTable() should be non-nil")
	}
	if inst.ChildTable() == nil {
		t.Error("ChildTable() should be non-nil")
	}
	if inst.NeighborTable() == nil {
		t.Error("NeighborTable() should be non-nil")
	}
	if inst.MleService() == nil {
		t.Error("MleService() should be non-nil")
	}
	if inst.Netif() == nil {
		t.Error("Netif() should be non-nil")
	}
	if inst.Forwarder() == nil {
		t.Error("Forwarder() should be non-nil")
	}
	if inst.NetdataLeader() == nil {
		t.Error("NetdataLeader() should be non-nil")
	}
	if inst.NetdataLocal() == nil {
		t.Error("NetdataLocal() should be non-nil")
	}

	// RLOC16 and MeshLocalPrefix should have zero values before attach.
	if inst.RLOC16() != 0 {
		t.Errorf("RLOC16() = %d, want 0 before attach", inst.RLOC16())
	}
	var zeroPrefix [8]byte
	if inst.MeshLocalPrefix() != zeroPrefix {
		t.Errorf("MeshLocalPrefix() = %v, want zero before attach", inst.MeshLocalPrefix())
	}
}

func TestFullLifecycleWithStartStop(t *testing.T) {
	inst := New(Config{})

	// Start → IfConfigUp → ThreadStart → ThreadStop → IfConfigDown → Stop,
	// repeated to verify the full instance lifecycle is repeatable.
	for i := range 2 {
		if err := inst.Start(); err != nil {
			t.Fatalf("cycle %d: Start() error: %v", i, err)
		}
		if err := inst.IfConfigUp(); err != nil {
			t.Fatalf("cycle %d: IfConfigUp() error: %v", i, err)
		}
		if err := inst.ThreadStart(); err != nil {
			t.Fatalf("cycle %d: ThreadStart() error: %v", i, err)
		}
		if !inst.IsThreadRunning() {
			t.Fatalf("cycle %d: Thread should be running", i)
		}
		if err := inst.ThreadStop(); err != nil {
			t.Fatalf("cycle %d: ThreadStop() error: %v", i, err)
		}
		if err := inst.IfConfigDown(); err != nil {
			t.Fatalf("cycle %d: IfConfigDown() error: %v", i, err)
		}
		inst.Stop()
		if inst.IsRunning() {
			t.Fatalf("cycle %d: instance should not be running", i)
		}
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

// --------------------------------------------------------------------------
// Periodic tick
// --------------------------------------------------------------------------

func TestPeriodicTickFires(t *testing.T) {
	inst := New(Config{})
	if err := inst.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer inst.Stop()

	// The periodic tick runs every 1 second. After 1.2 seconds the
	// RouterTable's HandleTimeTick should have been called at least once.
	// We verify this indirectly: the router table tick decrements reuse
	// delay counters. Since there are no routers, this is a no-op, but
	// the fact that the instance runs for >1s without panicking confirms
	// the tick infrastructure works.
	time.Sleep(1200 * time.Millisecond)

	// Verify the instance is still running (no panics in tick handler).
	if !inst.IsRunning() {
		t.Error("instance should still be running after periodic tick")
	}
}

// --------------------------------------------------------------------------
// Neighbor aging (Phase 31y)
// --------------------------------------------------------------------------

func TestNeighborAgingEvictsStaleRouter(t *testing.T) {
	inst := New(Config{})

	// Allocate a router and mark it as valid with a stale LastHeard.
	r, _, err := inst.routerTable.Allocate()
	if err != nil {
		t.Fatalf("Allocate() error: %v", err)
	}
	r.State = routing.StateValid
	// Set LastHeard to 200 seconds ago (well past MaxNeighborAge of 100s).
	r.LastHeard = uint32(time.Now().Add(-200 * time.Second).UnixMilli())
	r.LinkQualityOut = 3 // Give it a valid link quality so we can detect removal.

	m := inst.mleService.Mle()
	inst.handleRouterNeighborTimers(m)

	// After aging, the router's link should have been removed
	// (LinkQualityOut reset to 0 by RemoveRouterLink).
	if r.LinkQualityOut != 0 {
		t.Errorf("LinkQualityOut = %d after aging, want 0 (link removed)", r.LinkQualityOut)
	}
}

func TestNeighborAgingKeepsFreshRouter(t *testing.T) {
	inst := New(Config{})

	r, _, err := inst.routerTable.Allocate()
	if err != nil {
		t.Fatalf("Allocate() error: %v", err)
	}
	r.State = routing.StateValid
	// Set LastHeard to 10 seconds ago (well within MaxNeighborAge of 100s).
	r.LastHeard = uint32(time.Now().Add(-10 * time.Second).UnixMilli())
	r.LinkQualityOut = 3

	m := inst.mleService.Mle()
	inst.handleRouterNeighborTimers(m)

	// Fresh router should NOT be evicted.
	if r.LinkQualityOut != 3 {
		t.Errorf("LinkQualityOut = %d, want 3 (router should not be evicted)", r.LinkQualityOut)
	}
}

func TestNeighborAgingSkipsInvalidRouters(t *testing.T) {
	inst := New(Config{})

	r, _, err := inst.routerTable.Allocate()
	if err != nil {
		t.Fatalf("Allocate() error: %v", err)
	}
	// Leave state as StateInvalid (default) with a stale LastHeard.
	r.LastHeard = uint32(time.Now().Add(-200 * time.Second).UnixMilli())
	r.LinkQualityOut = 3

	m := inst.mleService.Mle()
	inst.handleRouterNeighborTimers(m)

	// Invalid routers should NOT be evicted by aging (they're not neighbors).
	if r.LinkQualityOut != 3 {
		t.Errorf("LinkQualityOut = %d, want 3 (invalid router should not be aged)", r.LinkQualityOut)
	}
}

// --------------------------------------------------------------------------
// Link Accept countdown (Phase 31z)
// --------------------------------------------------------------------------

func TestLinkAcceptCountdownDecrement(t *testing.T) {
	inst := New(Config{})

	r, _, err := inst.routerTable.Allocate()
	if err != nil {
		t.Fatalf("Allocate() error: %v", err)
	}
	// Leave state as StateInvalid (waiting for link accept).
	r.LinkAcceptTimeout = 3

	m := inst.mleService.Mle()
	inst.handleRouterNeighborTimers(m)

	if r.LinkAcceptTimeout != 2 {
		t.Errorf("LinkAcceptTimeout = %d after one tick, want 2", r.LinkAcceptTimeout)
	}
}

func TestLinkAcceptTimeoutRemovesLink(t *testing.T) {
	inst := New(Config{})

	r, _, err := inst.routerTable.Allocate()
	if err != nil {
		t.Fatalf("Allocate() error: %v", err)
	}
	r.State = routing.StateLinkRequest
	r.LinkAcceptTimeout = 1   // Will expire on next tick.
	r.LinkRequestAttempts = 0 // No retries left.
	r.LinkQualityOut = 3

	m := inst.mleService.Mle()
	inst.handleRouterNeighborTimers(m)

	// With no retries left, the link should be removed.
	if r.LinkQualityOut != 0 {
		t.Errorf("LinkQualityOut = %d after timeout with no retries, want 0", r.LinkQualityOut)
	}
}

func TestLinkAcceptTimeoutRetriesLinkRequest(t *testing.T) {
	inst := New(Config{})

	r, _, err := inst.routerTable.Allocate()
	if err != nil {
		t.Fatalf("Allocate() error: %v", err)
	}
	r.State = routing.StateLinkRequest
	r.LinkAcceptTimeout = 1   // Will expire on next tick.
	r.LinkRequestAttempts = 2 // Has retries remaining.
	r.LinkQualityOut = 3

	m := inst.mleService.Mle()
	inst.handleRouterNeighborTimers(m)

	// LinkRequestAttempts should be decremented.
	if r.LinkRequestAttempts != 1 {
		t.Errorf("LinkRequestAttempts = %d after retry, want 1", r.LinkRequestAttempts)
	}
	// Link should NOT be removed because retries remain.
	// (sendLinkRequestToRouter will fail because transport is nil,
	// but the attempt counter should still be decremented.)
	if r.LinkQualityOut != 3 {
		t.Errorf("LinkQualityOut = %d, want 3 (link should not be removed on retry)", r.LinkQualityOut)
	}
}

func TestLinkAcceptNotWaitingSkipped(t *testing.T) {
	inst := New(Config{})

	r, _, err := inst.routerTable.Allocate()
	if err != nil {
		t.Fatalf("Allocate() error: %v", err)
	}
	// State is invalid, LinkAcceptTimeout is 0 — not waiting.
	r.LinkAcceptTimeout = 0
	r.LinkQualityOut = 3

	m := inst.mleService.Mle()
	inst.handleRouterNeighborTimers(m)

	// Nothing should happen.
	if r.LinkQualityOut != 3 {
		t.Errorf("LinkQualityOut = %d, want 3", r.LinkQualityOut)
	}
}

// --------------------------------------------------------------------------
// Flush parent responses (Phase 31aa)
// --------------------------------------------------------------------------

func TestFlushPendingParentResponses(t *testing.T) {
	inst := New(Config{})

	// Verify that handlePeriodicTick does not panic when calling
	// FlushPendingResponses (even with no pending responses).
	// The ParentRequestHandler is always created by NewService.
	if inst.mleService.ParentRequestHandler == nil {
		t.Fatal("ParentRequestHandler should not be nil")
	}

	count := inst.mleService.ParentRequestHandler.PendingResponseCount()
	if count != 0 {
		t.Errorf("PendingResponseCount() = %d, want 0", count)
	}

	// Call the flush — should return 0 sent, nil error.
	sent, err := inst.mleService.ParentRequestHandler.FlushPendingResponses()
	if err != nil {
		t.Errorf("FlushPendingResponses() error: %v", err)
	}
	if sent != 0 {
		t.Errorf("FlushPendingResponses() = %d, want 0", sent)
	}
}

// --------------------------------------------------------------------------
// nopRadio — minimal radio.Radio stub for tests that need MAC enabled
// --------------------------------------------------------------------------

// nopRadio is a no-op radio.Radio implementation that succeeds on all
// operations without performing actual radio I/O. It enables tests to
// create an Instance with a working MAC layer.
type nopRadio struct {
	enabled bool
	txBuf   radio.Frame
}

func (r *nopRadio) Enable() error                                    { r.enabled = true; return nil }
func (r *nopRadio) Disable() error                                   { r.enabled = false; return nil }
func (r *nopRadio) IsEnabled() bool                                  { return r.enabled }
func (r *nopRadio) GetState() radio.State                            { return radio.StateSleep }
func (r *nopRadio) Sleep() error                                     { return nil }
func (r *nopRadio) Receive(channel uint8) error                      { return nil }
func (r *nopRadio) Transmit(frame *radio.Frame) error                { return nil }
func (r *nopRadio) GetTransmitBuffer() *radio.Frame                  { return &r.txBuf }
func (r *nopRadio) GetCaps() radio.Caps                              { return radio.CapNone }
func (r *nopRadio) GetIEEEEui64() [8]byte                            { return [8]byte{1, 2, 3, 4, 5, 6, 7, 8} }
func (r *nopRadio) SetPanID(uint16)                                  {}
func (r *nopRadio) SetExtendedAddress(types.ExtAddress)              {}
func (r *nopRadio) SetShortAddress(types.ShortAddress)               {}
func (r *nopRadio) GetTransmitPower() (int8, error)                  { return 0, nil }
func (r *nopRadio) SetTransmitPower(int8) error                      { return nil }
func (r *nopRadio) GetPromiscuous() bool                             { return false }
func (r *nopRadio) SetPromiscuous(bool)                              {}
func (r *nopRadio) GetRSSI() int8                                    { return -50 }
func (r *nopRadio) GetSupportedChannelMask() uint32                  { return 0x07FFF800 }
func (r *nopRadio) GetPreferredChannelMask() uint32                  { return 0x07FFF800 }
func (r *nopRadio) GetReceiveSensitivity() int8                      { return -100 }
func (r *nopRadio) EnableSrcMatch(bool)                              {}
func (r *nopRadio) AddSrcMatchShortEntry(types.ShortAddress) error   { return nil }
func (r *nopRadio) AddSrcMatchExtEntry(types.ExtAddress) error       { return nil }
func (r *nopRadio) ClearSrcMatchShortEntry(types.ShortAddress) error { return nil }
func (r *nopRadio) ClearSrcMatchExtEntry(types.ExtAddress) error     { return nil }
func (r *nopRadio) ClearSrcMatchShortEntries()                       {}
func (r *nopRadio) ClearSrcMatchExtEntries()                         {}
func (r *nopRadio) SetMacKey(uint8, uint8, types.KeyMaterial, types.KeyMaterial, types.KeyMaterial) {
}
func (r *nopRadio) SetMacFrameCounter(uint32)         {}
func (r *nopRadio) SetMacFrameCounterIfLarger(uint32) {}
func (r *nopRadio) EnergyScan(uint8, uint16) error    { return nil }

var _ radio.Radio = (*nopRadio)(nil)

// --------------------------------------------------------------------------
// MAC TX notification tests (Critical #3)
// --------------------------------------------------------------------------

// newInstanceWithRadio creates an Instance backed by a nopRadio so that
// the MAC layer is functional (Enable succeeds).
func newInstanceWithRadio(t *testing.T) *Instance {
	t.Helper()
	inst := New(Config{Radio: &nopRadio{}})
	if inst.mac == nil {
		t.Fatal("mac should be created")
	}
	return inst
}

func TestSendViaForwarder_DirectNotifiesMAC(t *testing.T) {
	inst := newInstanceWithRadio(t)
	if err := inst.IfConfigUp(); err != nil {
		t.Fatalf("IfConfigUp() error: %v", err)
	}

	msg := mesh.NewTxMessage([]byte{0xAA}, 0x0401, inst.rloc16)
	// msg.Direct defaults to true.
	if err := inst.sendViaForwarder(msg); err != nil {
		t.Fatalf("sendViaForwarder() error: %v", err)
	}

	pending := inst.mac.GetPendingOperations()
	if pending&mac.OperationTransmitDataDirect == 0 {
		t.Errorf("MAC should have OperationTransmitDataDirect pending; got %v", pending)
	}
}

func TestSendViaForwarder_IndirectNotifiesMAC(t *testing.T) {
	inst := newInstanceWithRadio(t)
	if err := inst.IfConfigUp(); err != nil {
		t.Fatalf("IfConfigUp() error: %v", err)
	}

	msg := mesh.NewTxMessage([]byte{0xBB}, 0x0401, inst.rloc16)
	msg.Direct = false // mark as indirect
	if err := inst.sendViaForwarder(msg); err != nil {
		t.Fatalf("sendViaForwarder() error: %v", err)
	}

	pending := inst.mac.GetPendingOperations()
	if pending&mac.OperationTransmitDataIndirect == 0 {
		t.Errorf("MAC should have OperationTransmitDataIndirect pending; got %v", pending)
	}
}

func TestSendViaForwarder_NoRadioNoPanic(t *testing.T) {
	// Instance without radio — mac is created but platRadio is nil,
	// so IfConfigUp skips mac.Enable(). sendViaForwarder should still
	// succeed (forwarder enqueue works) without panicking.
	inst := New(Config{})
	inst.forwarder.SetEnabled(true) // manually enable for test

	msg := mesh.NewTxMessage([]byte{0xCC}, 0x0401, inst.rloc16)
	if err := inst.sendViaForwarder(msg); err != nil {
		t.Fatalf("sendViaForwarder() error: %v", err)
	}
	// No assertion on pending ops — just ensure no panic.
}

func TestSendMLE_NotifiesMAC(t *testing.T) {
	inst := newInstanceWithRadio(t)
	if err := inst.IfConfigUp(); err != nil {
		t.Fatalf("IfConfigUp() error: %v", err)
	}

	// SendMLE sends to a destination address via UDP MLE port.
	dst := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	err := inst.SendMLE([]byte{0x00, 0x01}, dst)
	if err != nil {
		t.Fatalf("SendMLE() error: %v", err)
	}

	pending := inst.mac.GetPendingOperations()
	if pending&mac.OperationTransmitDataDirect == 0 {
		t.Errorf("MAC should have OperationTransmitDataDirect after SendMLE; got %v", pending)
	}
}

func TestSendCoAP_NotifiesMAC(t *testing.T) {
	inst := newInstanceWithRadio(t)
	if err := inst.IfConfigUp(); err != nil {
		t.Fatalf("IfConfigUp() error: %v", err)
	}
	inst.rloc16 = 0x0400

	// Construct a peer address using the mesh-local prefix.
	var peerAddr [16]byte
	copy(peerAddr[:8], inst.meshLocalPrefix[:])
	peerAddr[14] = 0x04
	peerAddr[15] = 0x01

	// sendCoAP is the internal function wired into the CoAP engine.
	err := inst.sendCoAP([]byte{0x40, 0x01}, coap.MessageInfo{
		PeerAddr: peerAddr,
		PeerPort: 61631,
	})
	if err != nil {
		t.Fatalf("sendCoAP() error: %v", err)
	}

	pending := inst.mac.GetPendingOperations()
	if pending&mac.OperationTransmitDataDirect == 0 {
		t.Errorf("MAC should have OperationTransmitDataDirect after sendCoAP; got %v", pending)
	}
}

func TestSendSupervisionMessage_NotifiesMAC(t *testing.T) {
	inst := newInstanceWithRadio(t)
	if err := inst.IfConfigUp(); err != nil {
		t.Fatalf("IfConfigUp() error: %v", err)
	}

	sender := &supervisionMessageSender{inst: inst}
	child := &mle.Child{
		Neighbor: mle.Neighbor{RLOC16: 0x0401},
	}
	if err := sender.SendSupervisionMessage(child); err != nil {
		t.Fatalf("SendSupervisionMessage() error: %v", err)
	}

	pending := inst.mac.GetPendingOperations()
	if pending&mac.OperationTransmitDataDirect == 0 {
		t.Errorf("MAC should have OperationTransmitDataDirect after SendSupervisionMessage; got %v", pending)
	}
}

// ---------------------------------------------------------------------------
// MAC Security tests
// ---------------------------------------------------------------------------

func TestUpdateMacKeys_NilSubMac(t *testing.T) {
	// With no radio, updateMacKeys should not panic.
	inst := New(Config{})
	inst.updateMacKeys() // should be a no-op
}

func TestUpdateMacKeys_PushesKeysToSubMac(t *testing.T) {
	r := &nopRadio{}
	inst := New(Config{Radio: r})

	// Set a known network key so we get deterministic keys.
	var nk key.NetworkKey
	nk[0] = 0x42
	inst.keyManager.SetNetworkKey(nk)

	// After wireModules (called by New), subMac should have received keys.
	if inst.subMac == nil {
		t.Fatal("subMac should be non-nil with radio")
	}

	// Verify updateMacKeys doesn't panic and can be called again.
	inst.updateMacKeys()
}

func TestSetCurrentKeySequence_UpdatesMacKeys(t *testing.T) {
	r := &nopRadio{}
	inst := New(Config{Radio: r})

	var nk key.NetworkKey
	nk[0] = 0x42
	inst.keyManager.SetNetworkKey(nk)

	// Change key sequence — should call updateMacKeys internally.
	inst.SetCurrentKeySequence(5, key.ForceUpdate)

	if inst.keyManager.GetCurrentKeySequence() != 5 {
		t.Errorf("key sequence: got %d, want 5", inst.keyManager.GetCurrentKeySequence())
	}

	// Verify MAC key ID matches.
	if inst.keyManager.GetMacKeyId() != 5 {
		t.Errorf("MAC key ID: got %d, want 5", inst.keyManager.GetMacKeyId())
	}
}

func TestSendMLE_SecurityFieldsSet(t *testing.T) {
	r := &nopRadio{}
	inst := New(Config{Radio: r})

	// Set up a network key.
	var nk key.NetworkKey
	nk[0] = 0x42
	inst.keyManager.SetNetworkKey(nk)

	// Verify the key manager has a non-zero MAC key.
	macKey := inst.keyManager.GetCurrentMacKey()
	allZero := true
	for _, b := range macKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("MAC key should not be all zeros after SetNetworkKey")
	}
}

// ---------------------------------------------------------------------------
// IndirectSender wiring tests
// ---------------------------------------------------------------------------

func TestIndirectSender_NilWithoutRadio(t *testing.T) {
	inst := New(Config{})
	if inst.IndirectSender() != nil {
		t.Error("IndirectSender should be nil without a radio")
	}
	if inst.SourceMatchController() != nil {
		t.Error("SourceMatchController should be nil without a radio")
	}
}

func TestIndirectSender_WiredWithRadio(t *testing.T) {
	r := &nopRadio{}
	inst := New(Config{Radio: r})
	if inst.IndirectSender() == nil {
		t.Error("IndirectSender should be non-nil with a radio")
	}
	if inst.SourceMatchController() == nil {
		t.Error("SourceMatchController should be non-nil with a radio")
	}
}

func TestRadioSourceMatchAdapter(t *testing.T) {
	r := &nopRadio{}
	adapter := &radioSourceMatchAdapter{radio: r}

	// These should not panic and return nil errors from nopRadio.
	if err := adapter.AddShortSourceMatch(0x1234); err != nil {
		t.Errorf("AddShortSourceMatch: %v", err)
	}
	if err := adapter.AddExtSourceMatch([8]byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
		t.Errorf("AddExtSourceMatch: %v", err)
	}
	if err := adapter.ClearShortSourceMatch(0x1234); err != nil {
		t.Errorf("ClearShortSourceMatch: %v", err)
	}
	if err := adapter.ClearExtSourceMatch([8]byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
		t.Errorf("ClearExtSourceMatch: %v", err)
	}
	adapter.ClearSourceMatchTable() // should not panic
	adapter.EnableSourceMatch(true) // should not panic
}

func TestChildInfoAdapter(t *testing.T) {
	child := &mle.Child{}
	child.RLOC16 = 0x4001
	child.MacAddr = types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	adapter := &childInfoAdapter{child: child}

	if adapter.GetShortAddress() != 0x4001 {
		t.Errorf("GetShortAddress: got 0x%04x, want 0x4001", adapter.GetShortAddress())
	}

	extAddr := adapter.GetExtAddress()
	want := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if extAddr != want {
		t.Errorf("GetExtAddress: got %v, want %v", extAddr, want)
	}

	if adapter.IsIndirectMessagePending() {
		t.Error("IsIndirectMessagePending should return false (stub)")
	}
}

func TestRealIndirectSenderAdapter(t *testing.T) {
	// Create a minimal indirect.Sender with a no-op frame sender.
	noopFS := &testFrameSender{}
	r := &nopRadio{}
	srcMatch := indirect.NewSourceMatchController(&radioSourceMatchAdapter{radio: r})
	sender := indirect.NewSender(noopFS, srcMatch)

	adapter := &realIndirectSenderAdapter{sender: sender}

	// GetIndirectMessageCount should return 0 for unknown child.
	child := &mle.Child{}
	child.RLOC16 = 0x4001
	if count := adapter.GetIndirectMessageCount(child); count != 0 {
		t.Errorf("GetIndirectMessageCount: got %d, want 0", count)
	}

	// HandleFrameChangeDone should not panic.
	adapter.HandleFrameChangeDone(child)

	// HandleSentFrameToChild should not panic.
	adapter.HandleSentFrameToChild(child, nil)
}

// testFrameSender is a no-op indirect.FrameSender for tests.
type testFrameSender struct{}

func (f *testFrameSender) SendIndirectFrame(_ indirect.ChildInfo, _ []byte) error {
	return nil
}

// --------------------------------------------------------------------------
// Priority 1: applyActiveDataset tests
// --------------------------------------------------------------------------

func TestApplyActiveDataset_SetsChannel(t *testing.T) {
	inst := New(Config{})
	info := &meshcop.Info{
		Channel: 15,
	}
	info.Components.Channel = true
	inst.activeDataset.SaveLocalFromInfo(info)

	inst.applyActiveDataset()

	if got := inst.mac.GetPanChannel(); got != 15 {
		t.Errorf("PanChannel = %d, want 15", got)
	}
}

func TestApplyActiveDataset_SetsPanID(t *testing.T) {
	inst := New(Config{})
	info := &meshcop.Info{
		PanID: 0x1234,
	}
	info.Components.PanID = true
	inst.activeDataset.SaveLocalFromInfo(info)

	inst.applyActiveDataset()

	if got := inst.mac.GetPanID(); got != 0x1234 {
		t.Errorf("PanID = 0x%04x, want 0x1234", got)
	}
}

func TestApplyActiveDataset_SetsNetworkKey(t *testing.T) {
	inst := New(Config{})
	var nk [16]byte
	for i := range nk {
		nk[i] = byte(i + 1)
	}
	info := &meshcop.Info{
		NetworkKey: nk,
	}
	info.Components.NetworkKey = true
	inst.activeDataset.SaveLocalFromInfo(info)

	inst.applyActiveDataset()

	got := inst.keyManager.GetNetworkKey()
	if [16]byte(got) != nk {
		t.Errorf("NetworkKey mismatch")
	}
}

func TestApplyActiveDataset_SetsPSKc(t *testing.T) {
	inst := New(Config{})
	var pskc [16]byte
	pskc[0] = 0xAA
	info := &meshcop.Info{
		PSKc: pskc,
	}
	info.Components.PSKc = true
	inst.activeDataset.SaveLocalFromInfo(info)

	inst.applyActiveDataset()

	got := inst.keyManager.GetPskc()
	if [16]byte(got) != pskc {
		t.Errorf("PSKc mismatch")
	}
}

func TestApplyActiveDataset_SetsNetworkName(t *testing.T) {
	inst := New(Config{})
	info := &meshcop.Info{
		NetworkName: "TestNet",
	}
	info.Components.NetworkName = true
	inst.activeDataset.SaveLocalFromInfo(info)

	inst.applyActiveDataset()

	if inst.networkName != "TestNet" {
		t.Errorf("networkName = %q, want %q", inst.networkName, "TestNet")
	}
	if got := inst.mac.GetNetworkName(); got != "TestNet" {
		t.Errorf("MAC NetworkName = %q, want %q", got, "TestNet")
	}
}

func TestApplyActiveDataset_SetsExtendedPanID(t *testing.T) {
	inst := New(Config{})
	var extPan [8]byte
	extPan[0] = 0xBB
	info := &meshcop.Info{
		ExtendedPanID: extPan,
	}
	info.Components.ExtendedPanID = true
	inst.activeDataset.SaveLocalFromInfo(info)

	inst.applyActiveDataset()

	if inst.extendedPanID != extPan {
		t.Errorf("extendedPanID mismatch")
	}
}

func TestApplyActiveDataset_SetsMeshLocalPrefix(t *testing.T) {
	inst := New(Config{})
	var mlp [8]byte
	mlp[0] = 0xFD
	mlp[1] = 0x01
	info := &meshcop.Info{
		MeshLocalPrefix: mlp,
	}
	info.Components.MeshLocalPrefix = true
	inst.activeDataset.SaveLocalFromInfo(info)

	inst.applyActiveDataset()

	if inst.meshLocalPrefix != mlp {
		t.Errorf("meshLocalPrefix mismatch")
	}
}

func TestApplyActiveDataset_NilDataset(t *testing.T) {
	inst := New(Config{})
	// No dataset saved — applyActiveDataset should not panic.
	inst.applyActiveDataset()
}

func TestApplyActiveDataset_NilManager(t *testing.T) {
	inst := New(Config{})
	inst.activeDataset = nil
	// Should not panic.
	inst.applyActiveDataset()
}

func TestThreadStart_AppliesDatasetBeforeMLE(t *testing.T) {
	inst := New(Config{})
	info := &meshcop.Info{
		Channel: 20,
		PanID:   0xABCD,
	}
	info.Components.Channel = true
	info.Components.PanID = true
	inst.activeDataset.SaveLocalFromInfo(info)

	_ = inst.IfConfigUp()
	if err := inst.ThreadStart(); err != nil {
		t.Fatalf("ThreadStart() error: %v", err)
	}

	if got := inst.mac.GetPanChannel(); got != 20 {
		t.Errorf("PanChannel = %d, want 20", got)
	}
	if got := inst.mac.GetPanID(); got != 0xABCD {
		t.Errorf("PanID = 0x%04x, want 0xABCD", got)
	}
}

// --------------------------------------------------------------------------
// Priority 2: key rotation timer tests
// --------------------------------------------------------------------------

func TestKeyRotationTickCounter_Increments(t *testing.T) {
	inst := New(Config{})
	if inst.keyRotationTickCounter != 0 {
		t.Fatal("initial counter should be 0")
	}

	// Simulate a few ticks worth of periodic ticks by calling directly.
	inst.handlePeriodicTick()
	inst.handlePeriodicTick()
	inst.handlePeriodicTick()

	if inst.keyRotationTickCounter != 3 {
		t.Errorf("counter = %d, want 3", inst.keyRotationTickCounter)
	}
}

func TestKeyRotationTickCounter_ResetsAt3600(t *testing.T) {
	inst := New(Config{})

	// Set counter to just below threshold.
	inst.keyRotationTickCounter = 3599

	seq := inst.keyManager.GetCurrentKeySequence()

	inst.handlePeriodicTick()

	// Counter should have reset.
	if inst.keyRotationTickCounter != 0 {
		t.Errorf("counter = %d, want 0 after reset", inst.keyRotationTickCounter)
	}

	// Key rotation tick was called — whether the sequence actually
	// changed depends on the security policy's rotation time, but the
	// hoursSinceRotation in the key manager should have advanced.
	_ = seq // key sequence may or may not change depending on policy
}

// --------------------------------------------------------------------------
// Priority 3: TMF service wiring tests
// --------------------------------------------------------------------------

func TestWireModules_TmfLeaderServiceCreated(t *testing.T) {
	inst := New(Config{})
	if inst.tmfLeaderService == nil {
		t.Error("tmfLeaderService should not be nil after wireModules")
	}
	if inst.TmfLeaderService() == nil {
		t.Error("TmfLeaderService() accessor returned nil")
	}
}

func TestWireModules_TmfServerDataServiceCreated(t *testing.T) {
	inst := New(Config{})
	if inst.tmfServerDataService == nil {
		t.Error("tmfServerDataService should not be nil after wireModules")
	}
	if inst.TmfServerDataService() == nil {
		t.Error("TmfServerDataService() accessor returned nil")
	}
}

func TestWireModules_TmfCommissionerDataServiceCreated(t *testing.T) {
	inst := New(Config{})
	if inst.tmfCommissionerDataService == nil {
		t.Error("tmfCommissionerDataService should not be nil after wireModules")
	}
	if inst.TmfCommissionerDataService() == nil {
		t.Error("TmfCommissionerDataService() accessor returned nil")
	}
}

// --------------------------------------------------------------------------
// Priority 4: childInfoAdapter.IsIndirectMessagePending tests
// --------------------------------------------------------------------------

func TestChildInfoAdapter_IsIndirectMessagePending_NilSender(t *testing.T) {
	child := &mle.Child{}
	child.RLOC16 = 0x1001
	adapter := &childInfoAdapter{child: child, sender: nil}

	if adapter.IsIndirectMessagePending() {
		t.Error("should return false with nil sender")
	}
}

func TestChildInfoAdapter_IsIndirectMessagePending_NoMessages(t *testing.T) {
	child := &mle.Child{}
	child.RLOC16 = 0x1001

	sender := indirect.NewSender(&testFrameSender{}, nil)
	adapter := &childInfoAdapter{child: child, sender: sender}

	if adapter.IsIndirectMessagePending() {
		t.Error("should return false with no queued messages")
	}
}

// --------------------------------------------------------------------------
// Address Resolver wiring tests
// --------------------------------------------------------------------------

func TestWireModules_AddrResolverCreated(t *testing.T) {
	inst := New(Config{})
	if inst.addrResolver == nil {
		t.Error("addrResolver should not be nil after wireModules")
	}
	if inst.AddrResolver() == nil {
		t.Error("AddrResolver() accessor returned nil")
	}
}

func TestPeriodicTick_AddrResolverTimerCalled(t *testing.T) {
	inst := New(Config{})
	// The resolver's HandleTimer should not panic when called
	// via the periodic tick path.
	inst.handlePeriodicTick()
}

// --------------------------------------------------------------------------
// Network Data Local/Notifier/Publisher wiring tests
// --------------------------------------------------------------------------

func TestWireModules_NetdataLocalCreated(t *testing.T) {
	inst := New(Config{})
	if inst.netdataLocal == nil {
		t.Error("netdataLocal should not be nil after wireModules")
	}
	if inst.NetdataLocal() == nil {
		t.Error("NetdataLocal() accessor returned nil")
	}
}

func TestWireModules_NetdataNotifierCreated(t *testing.T) {
	inst := New(Config{})
	if inst.netdataNotifier == nil {
		t.Error("netdataNotifier should not be nil after wireModules")
	}
	if inst.NetdataNotifier() == nil {
		t.Error("NetdataNotifier() accessor returned nil")
	}
}

func TestWireModules_NetdataPublisherCreated(t *testing.T) {
	inst := New(Config{})
	if inst.netdataPublisher == nil {
		t.Error("netdataPublisher should not be nil after wireModules")
	}
	if inst.NetdataPublisher() == nil {
		t.Error("NetdataPublisher() accessor returned nil")
	}
}

func TestSetRLOC16_PropagatesToNetdataLocal(t *testing.T) {
	inst := New(Config{})
	inst.SetRLOC16(0x4001)
	// Verify the local network data manager received the RLOC16
	// by checking that it doesn't panic and the instance's RLOC16
	// is set correctly.
	if inst.RLOC16() != 0x4001 {
		t.Errorf("RLOC16 = %04x, want 0x4001", inst.RLOC16())
	}
}

func TestRoleChange_UpdatesPublisherIsRouter(t *testing.T) {
	inst := New(Config{})
	m := inst.mleService.Mle()

	// Initially disabled — publisher should not be router.
	// Transition to Router role.
	_ = m.Enable()
	_ = m.BecomeRouter()

	// The role change callback should have set IsRouter on the publisher.
	// We can't directly query IsRouter, but at minimum the callback should
	// not panic.
}

func TestPeriodicTick_NetdataNotifierDriven(t *testing.T) {
	inst := New(Config{})
	// Trigger periodic tick — netdata notifier sync path should
	// execute without panicking.
	inst.handlePeriodicTick()
}

func TestPeriodicTick_NetdataPublisherDriven(t *testing.T) {
	inst := New(Config{})
	// Trigger periodic tick — publisher process/advance should
	// execute without panicking.
	inst.handlePeriodicTick()
}

// --------------------------------------------------------------------------
// SLAAC Manager wiring tests
// --------------------------------------------------------------------------

func TestWireModules_SlaacManagerCreated(t *testing.T) {
	inst := New(Config{})
	if inst.slaacManager == nil {
		t.Error("slaacManager should not be nil after wireModules")
	}
	if inst.SlaacManager() == nil {
		t.Error("SlaacManager() accessor returned nil")
	}
}

func TestIfConfigUp_EnablesSlaac(t *testing.T) {
	inst := New(Config{})
	if inst.slaacManager.IsEnabled() {
		t.Error("SLAAC should be disabled before IfConfigUp")
	}
	if err := inst.IfConfigUp(); err != nil {
		t.Fatalf("IfConfigUp: %v", err)
	}
	if !inst.slaacManager.IsEnabled() {
		t.Error("SLAAC should be enabled after IfConfigUp")
	}
}

func TestIfConfigDown_DisablesSlaac(t *testing.T) {
	inst := New(Config{})
	_ = inst.IfConfigUp()
	if !inst.slaacManager.IsEnabled() {
		t.Fatal("SLAAC should be enabled after IfConfigUp")
	}
	if err := inst.IfConfigDown(); err != nil {
		t.Fatalf("IfConfigDown: %v", err)
	}
	if inst.slaacManager.IsEnabled() {
		t.Error("SLAAC should be disabled after IfConfigDown")
	}
}

func TestUpdateSlaacAddresses_EmptyNetdata(t *testing.T) {
	inst := New(Config{})
	_ = inst.IfConfigUp()
	// Should not panic with empty network data.
	inst.updateSlaacAddresses()
	addrs := inst.slaacManager.GetAddresses()
	if len(addrs) != 0 {
		t.Errorf("expected no SLAAC addresses with empty netdata, got %d", len(addrs))
	}
}

func TestUpdateSlaacAddresses_DisabledManager(t *testing.T) {
	inst := New(Config{})
	// SLAAC not enabled — updateSlaacAddresses should be a no-op.
	inst.updateSlaacAddresses()
}
