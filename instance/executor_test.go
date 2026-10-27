// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
)

func waitExecutorSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal("executor barrier timed out")
	}
}

func waitExecutorResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("executor result timed out")
		return nil
	}
}

func waitQueuedTasks(t *testing.T, inst *Instance, count int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(inst.taskCh) != count {
		if time.Now().After(deadline) {
			t.Fatalf("queued tasks = %d, want %d", len(inst.taskCh), count)
		}
		runtime.Gosched()
	}
}

func newExecutorInstance(t *testing.T) *Instance {
	t.Helper()
	inst := New(Config{})
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inst.Stop)
	return inst
}

func blockExecutor(t *testing.T, inst *Instance) func() {
	t.Helper()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	inst.PostTask(func() {
		close(entered)
		<-release
	})
	waitExecutorSignal(t, entered)
	return unblock
}

func TestDoValidationAndOperationResult(t *testing.T) {
	inst := New(Config{})
	opErr := errors.New("operation result")
	op := func() error { return opErr }
	if got := inst.Do(nil, op); got != goterrors.ErrInvalidArgs { //nolint:staticcheck // Exercise the public invalid-context contract.
		t.Fatalf("nil context = %v", got)
	}
	if got := inst.Do(context.Background(), nil); got != goterrors.ErrInvalidArgs {
		t.Fatalf("nil operation = %v", got)
	}
	if got := inst.Do(context.Background(), op); got != goterrors.ErrInvalidState {
		t.Fatalf("not-started admission = %v", got)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	if got := inst.Do(context.Background(), op); got != opErr {
		t.Errorf("operation result identity = %v, want %v", got, opErr)
	}
	inst.Stop()
	if got := inst.Do(context.Background(), op); got != goterrors.ErrInvalidState {
		t.Fatalf("stopped admission = %v", got)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	defer inst.Stop()
	if got := inst.Do(context.Background(), op); got != opErr {
		t.Errorf("restarted operation result = %v", got)
	}
}

func TestDoPreCancelledNeverAdmits(t *testing.T) {
	inst := newExecutorInstance(t)
	unblock := blockExecutor(t, inst)
	var calls atomic.Int32
	for _, expired := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		want := context.Canceled
		if expired {
			cancel()
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
			want = context.DeadlineExceeded
		} else {
			cancel()
		}
		if err := inst.Do(ctx, func() error { calls.Add(1); return nil }); err != want {
			t.Errorf("pre-cancelled admission = %v, want %v", err, want)
		}
		cancel()
	}
	if len(inst.taskCh) != 0 {
		t.Error("pre-cancelled operation entered task queue")
	}
	unblock()
	if err := inst.Do(context.Background(), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("pre-cancelled operation executed")
	}
}

func TestDoQueuedCancellationNeverExecutesLater(t *testing.T) {
	inst := newExecutorInstance(t)
	unblock := blockExecutor(t, inst)
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	result := make(chan error, 1)
	go func() {
		result <- inst.Do(ctx, func() error { calls.Add(1); return nil })
	}()
	waitQueuedTasks(t, inst, 1)
	cancel()
	if got := waitExecutorResult(t, result); got != context.Canceled {
		t.Fatalf("queued cancellation = %v", got)
	}
	unblock()
	if err := inst.Do(context.Background(), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("cancelled queued operation executed later")
	}
}

func TestDoStartedCancellationWaitsForExactResult(t *testing.T) {
	for _, opErr := range []error{nil, errors.New("exact started result")} {
		inst := newExecutorInstance(t)
		ctx, cancel := context.WithCancel(context.Background())
		entered, release := make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		t.Cleanup(unblock)
		var calls atomic.Int32
		result := make(chan error, 1)
		go func() {
			result <- inst.Do(ctx, func() error {
				calls.Add(1)
				close(entered)
				<-release
				return opErr
			})
		}()
		waitExecutorSignal(t, entered)
		cancel()
		select {
		case err := <-result:
			t.Fatalf("started cancellation returned before operation: %v", err)
		default:
		}
		unblock()
		if got := waitExecutorResult(t, result); got != opErr {
			t.Fatalf("started result = %v, want identical %v", got, opErr)
		}
		if calls.Load() != 1 {
			t.Fatal("started operation did not execute exactly once")
		}
	}
}

func TestDoQueuePressureIsBounded(t *testing.T) {
	inst := newExecutorInstance(t)
	unblock := blockExecutor(t, inst)
	for range cap(inst.taskCh) {
		inst.PostTask(func() {})
	}
	if got := inst.Do(context.Background(), func() error { t.Error("rejected operation ran"); return nil }); got != goterrors.ErrNoBufs {
		t.Fatalf("full queue admission = %v, want ErrNoBufs", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := inst.Do(ctx, func() error { return nil }); got != context.Canceled {
		t.Fatalf("cancelled full queue admission = %v", got)
	}
	unblock()
	waitQueuedTasks(t, inst, 0)
	if err := inst.Do(context.Background(), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestDoStopReleasesQueuedAndProtectsRunGeneration(t *testing.T) {
	inst := newExecutorInstance(t)
	unblock := blockExecutor(t, inst)
	var calls atomic.Int32
	op := func() error { calls.Add(1); return nil }
	staleResult := make(chan error, 1)
	go func() { staleResult <- inst.Do(context.Background(), op) }()
	waitQueuedTasks(t, inst, 1)
	// Retain a dispatched wrapper to explicitly exercise a stale generation
	// after restart, not merely the normal shutdown drain.
	stale := <-inst.taskCh
	queuedResult := make(chan error, 1)
	go func() { queuedResult <- inst.Do(context.Background(), op) }()
	waitQueuedTasks(t, inst, 1)
	stop := inst.stopCh
	var stopping sync.WaitGroup
	for range 16 {
		stopping.Go(inst.Stop)
	}
	waitExecutorSignal(t, stop)
	if got := waitExecutorResult(t, staleResult); got != goterrors.ErrInvalidState {
		t.Errorf("stale queued result = %v", got)
	}
	if got := waitExecutorResult(t, queuedResult); got != goterrors.ErrInvalidState {
		t.Errorf("queued shutdown result = %v", got)
	}
	if got := inst.Do(context.Background(), op); got != goterrors.ErrInvalidState {
		t.Errorf("admission during shutdown = %v", got)
	}
	if err := inst.Start(); err == nil {
		t.Fatal("Start succeeded while old loop was stopping")
	}
	unblock()
	stopping.Wait()
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	inst.PostTask(stale)
	if err := inst.Do(context.Background(), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("old generation operation executed during stop or restart")
	}
	if err := inst.Do(context.Background(), op); err != nil || calls.Load() != 1 {
		t.Fatalf("new generation operation: %v, calls=%d", err, calls.Load())
	}
}

func TestDoStartedOperationSurvivesConcurrentStop(t *testing.T) {
	inst := newExecutorInstance(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	opErr := errors.New("committed operation result")
	result := make(chan error, 1)
	go func() {
		result <- inst.Do(context.Background(), func() error {
			close(entered)
			<-release
			return opErr
		})
	}()
	waitExecutorSignal(t, entered)
	stopped := make(chan struct{})
	go func() { inst.Stop(); close(stopped) }()
	waitExecutorSignal(t, inst.stopCh)
	select {
	case err := <-result:
		t.Fatalf("started operation lost its result on stop: %v", err)
	case <-stopped:
		t.Fatal("Stop did not wait for started operation")
	default:
	}
	unblock()
	if got := waitExecutorResult(t, result); got != opErr {
		t.Fatalf("result after stop = %v", got)
	}
	waitExecutorSignal(t, stopped)
}

func TestDoFullQueueDoesNotDeadlockInternalMACTasklet(t *testing.T) {
	inst := newExecutorInstance(t)
	entered, release, taskletRan := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	result := make(chan error, 1)
	go func() {
		result <- inst.Do(context.Background(), func() error {
			close(entered)
			<-release
			inst.postTask(func() { close(taskletRan) })
			inst.postTask(func() { t.Error("MAC tasklet was not coalesced") })
			return nil
		})
	}()
	waitExecutorSignal(t, entered)
	for range cap(inst.taskCh) {
		inst.PostTask(func() {})
	}
	unblock()
	if err := waitExecutorResult(t, result); err != nil {
		t.Fatal(err)
	}
	waitExecutorSignal(t, taskletRan)
}

func TestDoConcurrentAdmissionStopAndRestart(t *testing.T) {
	inst := New(Config{})
	defer inst.Stop()
	for range 10 {
		if err := inst.Start(); err != nil {
			t.Fatal(err)
		}
		unblock := blockExecutor(t, inst)
		const callers = 32
		var counts [callers]atomic.Int32
		opErr := errors.New("operation completed")
		results := make(chan error, callers)
		var workers sync.WaitGroup
		for i := range callers {
			workers.Go(func() {
				err := inst.Do(context.Background(), func() error {
					counts[i].Add(1)
					return opErr
				})
				if (err == opErr && counts[i].Load() != 1) ||
					(err == goterrors.ErrInvalidState && counts[i].Load() != 0) ||
					(err != opErr && err != goterrors.ErrInvalidState) {
					results <- err
				}
			})
		}
		stopped := make(chan struct{})
		go func() { inst.Stop(); close(stopped) }()
		waitExecutorSignal(t, inst.stopCh)
		unblock()
		workers.Wait()
		waitExecutorSignal(t, stopped)
		close(results)
		for err := range results {
			t.Errorf("stop/admission outcome disagrees with execution: %v", err)
		}
		for i := range callers {
			if counts[i].Load() > 1 {
				t.Fatal("operation executed more than once")
			}
		}
	}
}
