// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import goterrors "github.com/hilli/gothread/errors"

// loopTask pairs the ORIGINAL invocation with its explicit SDK-owned obligation.
// Ordinary tasks have no owner. No queued wrapper retires its own invocation.
type loopTask struct {
	fn    func()
	owner *Instance
}

// dispatchLoopTask is the genuine task/timer dispatcher, not a posted function.
// The queued task.fn returns BEFORE security maintenance and owned retirement.
func dispatchLoopTask(task loopTask) {
	returned := false
	defer func() {
		if task.owner != nil && !returned {
			task.owner.radioOwner.mu.Lock()
			task.owner.radioOwner.interrupted = true
			if task.owner.radioOwner.failure == nil {
				task.owner.radioOwner.failure = goterrors.ErrAbort
			}
			task.owner.radioOwner.mu.Unlock()
		}
	}()
	task.fn()
	if task.owner != nil {
		task.owner.processSecurityFence()
		returned = true
		task.owner.retireRadioWork()
	}
}

func (inst *Instance) retireRadioWork() {
	inst.radioOwner.mu.Lock()
	inst.radioOwner.pending--
	inst.radioOwner.mu.Unlock()
}
