// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"context"
	"sync"

	goterrors "github.com/hilli/gothread/errors"
)

// Do runs op once on the current event-loop generation and returns its exact
// result. Call it only outside the loop; loop callbacks call stack APIs directly.
//
// Admission is bounded by the existing task queue: a full queue returns
// errors.ErrNoBufs without waiting. Nil ctx/op returns errors.ErrInvalidArgs.
// A non-running/stopping instance or a stopped generation returns
// errors.ErrInvalidState when the operation has not started.
//
// Cancellation that wins before op starts guarantees op will never execute.
// Once op starts, Do waits for its actual result even if ctx expires or Stop
// begins. Cancellation is not rollback and must not be used to retry an
// operation that has started. Stop waits for started operations to finish.
func (inst *Instance) Do(ctx context.Context, op func() error) error {
	if ctx == nil || op == nil {
		return goterrors.ErrInvalidArgs
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	request := &loopRequest{ctx: ctx, op: op, result: make(chan error, 1)}
	inst.runningMu.Lock()
	if !inst.running || inst.stopping {
		inst.runningMu.Unlock()
		return goterrors.ErrInvalidState
	}
	if err := ctx.Err(); err != nil {
		inst.runningMu.Unlock()
		return err
	}
	stop, generation := inst.stopCh, inst.doneCh
	select {
	case inst.taskCh <- func() { inst.executeRequest(request, generation) }:
		inst.runningMu.Unlock()
	default:
		inst.runningMu.Unlock()
		return goterrors.ErrNoBufs
	}

	select {
	case err := <-request.result:
		return err
	case <-ctx.Done():
		request.cancel(ctx.Err())
	case <-stop:
		request.cancel(goterrors.ErrInvalidState)
	}
	return <-request.result
}

type loopRequest struct {
	mu      sync.Mutex
	ctx     context.Context
	op      func() error
	started bool
	done    bool
	result  chan error
}

func (r *loopRequest) cancel(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started && !r.done {
		r.finish(err)
	}
}

// finish requires r.mu. The buffered result never blocks the event loop, even
// when cancellation or shutdown has already released the caller.
func (r *loopRequest) finish(err error) {
	r.done = true
	r.op = nil
	r.result <- err
}

func (inst *Instance) executeRequest(r *loopRequest, generation chan struct{}) {
	// Serialize the start claim with Stop's admission barrier.
	inst.runningMu.Lock()
	r.mu.Lock()
	if r.done {
		r.mu.Unlock()
		inst.runningMu.Unlock()
		return
	}
	switch {
	case !inst.running || inst.stopping || inst.doneCh != generation:
		r.finish(goterrors.ErrInvalidState)
	case r.ctx.Err() != nil:
		r.finish(r.ctx.Err())
	default:
		r.started = true
	}
	op := r.op
	r.mu.Unlock()
	inst.runningMu.Unlock()
	if op == nil {
		return
	}

	err := op()
	r.mu.Lock()
	r.finish(err)
	r.mu.Unlock()
}
