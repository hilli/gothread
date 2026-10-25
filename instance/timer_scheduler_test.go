// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTimerSchedulerCallbackReschedulesAndCancels(t *testing.T) {
	ts := &timerScheduler{}
	var order []int
	var cancelSelf, cancelNext func()
	cancelSelf = ts.scheduleWithCancel(-3*time.Hour, func() {
		order = append(order, 1)
		cancelSelf()
		cancelNext()
		ts.schedule(-4*time.Hour, func() { order = append(order, 2) })
		// This new zero-delay timer's deadline is after this pass's cutoff.
		ts.schedule(0, func() { order = append(order, 4) })
		if count := ts.count(); count != 5 {
			t.Errorf("callback count() = %d, want 5", count)
		}
		if d, ok := ts.nextDeadline(); !ok || d != 0 {
			t.Errorf("callback nextDeadline() = (%v, %v), want (0, true)", d, ok)
		}
	})
	cancelNext = ts.scheduleWithCancel(-2*time.Hour, func() {
		t.Error("callback cancelled by an earlier callback fired")
	})
	ts.schedule(-time.Hour, func() { order = append(order, 3) })
	ts.schedule(time.Hour, func() { t.Error("future timer fired") })

	done := make(chan int, 1)
	go func() { done <- ts.processExpired() }()
	select {
	case fired := <-done:
		if fired != 3 {
			t.Errorf("processExpired() = %d, want 3", fired)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("callback deadlocked while rescheduling or cancelling")
	}
	if !slices.Equal(order, []int{1, 2, 3}) {
		t.Fatalf("callback order = %v, want [1 2 3]", order)
	}
	if fired := ts.processExpired(); fired != 1 {
		t.Errorf("second processExpired() = %d, want 1", fired)
	}
	if !slices.Equal(order, []int{1, 2, 3, 4}) {
		t.Errorf("callback order = %v, want [1 2 3 4]", order)
	}
	if count := ts.count(); count != 1 {
		t.Errorf("remaining timers = %d, want 1", count)
	}
	if d, ok := ts.nextDeadline(); !ok || d <= 0 {
		t.Errorf("nextDeadline() = (%v, %v), want future deadline", d, ok)
	}
}

func TestTimerSchedulerCancelDuringDispatch(t *testing.T) {
	ts := &timerScheduler{}
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	cancelRunning := ts.scheduleWithCancel(-2*time.Hour, func() {
		close(entered)
		<-release
	})
	cancelPending := ts.scheduleWithCancel(-time.Hour, func() {
		t.Error("pending timer fired after cancellation")
	})
	done := make(chan int, 1)
	go func() { done <- ts.processExpired() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first callback did not start")
	}

	cancelled := make(chan struct{})
	go func() {
		// Cancelling a dispatched callback must not wait for it to return.
		cancelRunning()
		cancelRunning()
		cancelPending()
		cancelPending()
		ts.schedule(-time.Hour, func() {})
		if count := ts.count(); count != 2 {
			t.Errorf("count during callback = %d, want 2", count)
		}
		if d, ok := ts.nextDeadline(); !ok || d != 0 {
			t.Errorf("nextDeadline during callback = (%v, %v), want (0, true)", d, ok)
		}
		close(cancelled)
	}()
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("scheduler operations blocked on a running callback")
	}
	release <- struct{}{}
	select {
	case fired := <-done:
		if fired != 2 {
			t.Errorf("processExpired() = %d, want 2", fired)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dispatch did not complete")
	}
	if count := ts.count(); count != 0 {
		t.Errorf("remaining timers = %d, want 0", count)
	}
}

func TestTimerSchedulerConcurrentAccess(t *testing.T) {
	const workers, iterations = 8, 128
	ts := &timerScheduler{}
	var calls [workers * iterations]atomic.Int32
	start := make(chan struct{})
	stop := make(chan struct{})
	processed := make(chan int, 1)
	go func() {
		<-start
		fired := 0
		for {
			fired += ts.processExpired()
			select {
			case <-stop:
				processed <- fired + ts.processExpired()
				return
			default:
			}
		}
	}()
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		<-start
		for {
			ts.count()
			ts.nextDeadline()
			select {
			case <-stop:
				return
			default:
			}
		}
	}()

	var writers sync.WaitGroup
	for worker := range workers {
		writers.Add(1)
		go func() {
			defer writers.Done()
			<-start
			for i := range iterations {
				index := worker*iterations + i
				cancel := ts.scheduleWithCancel(0, func() { calls[index].Add(1) })
				if i%2 == 0 {
					// Cancellation may win or lose against dispatch.
					cancel()
					cancel()
				}
			}
		}()
	}
	close(start)
	writers.Wait()
	close(stop)
	fired := <-processed
	<-readDone

	var total int
	for i := range calls {
		count := calls[i].Load()
		if count < 0 || count > 1 {
			t.Errorf("timer %d fired %d times, want at most once", i, count)
		}
		if i%2 != 0 && count != 1 {
			t.Errorf("uncancelled timer %d fired %d times, want once", i, count)
		}
		total += int(count)
	}
	if fired != total {
		t.Errorf("processed %d timers, but %d callbacks ran", fired, total)
	}
	if count := ts.count(); count != 0 {
		t.Errorf("remaining timers = %d, want 0", count)
	}
	if d, ok := ts.nextDeadline(); ok || d != 0 {
		t.Errorf("empty nextDeadline() = (%v, %v), want (0, false)", d, ok)
	}
}

func TestTimerSchedulerConcurrentCancel(t *testing.T) {
	ts := &timerScheduler{}
	cancel := ts.scheduleWithCancel(0, func() { t.Error("cancelled timer fired") })
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 128 {
				cancel()
			}
		}()
	}
	wg.Wait()
	if count := ts.count(); count != 1 {
		t.Errorf("count() = %d, want 1 (cancelled timer still queued)", count)
	}
	if d, ok := ts.nextDeadline(); !ok || d != 0 {
		t.Errorf("cancelled nextDeadline() = (%v, %v), want (0, true)", d, ok)
	}
	if fired := ts.processExpired(); fired != 0 {
		t.Errorf("processExpired() = %d, want 0", fired)
	}
	if count := ts.count(); count != 0 {
		t.Errorf("remaining timers = %d, want 0", count)
	}
}

func TestTimerSchedulerStopWaitsForCallback(t *testing.T) {
	inst := New(Config{})
	if err := inst.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var futureCalls atomic.Int32
	inst.ScheduleTimer(0, func() {
		close(entered)
		<-release
		cancel := inst.timers.scheduleWithCancel(time.Hour, func() { futureCalls.Add(1) })
		cancel()
	})
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		inst.Stop()
		t.Fatal("timer callback did not start")
	}
	stopped := make(chan struct{})
	go func() {
		inst.Stop()
		close(stopped)
	}()
	select {
	case <-inst.stopCh:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("Stop did not signal shutdown")
	}
	select {
	case <-stopped:
		close(release)
		t.Fatal("Stop returned before the running callback completed")
	default:
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop deadlocked with a callback rescheduling and cancelling")
	}
	if inst.IsRunning() {
		t.Error("instance is still running after Stop")
	}
	if count := futureCalls.Load(); count != 0 {
		t.Errorf("future callback fired %d times, want 0", count)
	}
	if err := inst.Start(); err != nil {
		t.Fatalf("restart error: %v", err)
	}
	inst.Stop()
}
