// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package srp

import (
	"time"

	"github.com/hilli/gothread/errors"
)

// A rejected, timed-out, or locally failed attempt does not acknowledge
// registration/removal. Restore the exact pending operation for a later retry.
var newStateOnUpdateFailure = [8]ItemState{
	ItemStateToAdd, ItemStateToAdd,
	ItemStateToRefresh, ItemStateToRefresh,
	ItemStateToRemove, ItemStateToRemove,
	ItemStateRegistered, ItemStateRemoved,
}

// armTimer gives every scheduled callback immutable ownership. Timer.Stop
// cannot retract a callback already queued by a platform timer.
// All helpers in this file require c.mu unless stated otherwise.
func (c *Client) armTimer(delay time.Duration, handler func()) {
	c.stopTimer()
	epoch := c.timerEpoch
	c.timer = c.afterFunc(delay, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.timerEpoch != epoch {
			return
		}
		c.timer = nil
		c.timerEpoch++ // The same queued callback cannot fire twice.
		handler()
	})
}

func (c *Client) cancelAttempt() {
	c.stopTimer()
	c.attemptEpoch++
}

// restartPending invalidates old timer/send ownership when the application
// changes the operation. In particular a cleared service cannot be acknowledged
// by an earlier update's response.
func (c *Client) restartPending() {
	c.cancelAttempt()
	c.changeHostAndServiceStates(&newStateOnUpdateFailure, false)
	c.txFailureRetryCount = 0
	c.retryWaitInterval = 0
	if c.state != StateStopped && c.state != StatePaused {
		c.setState(StateUpdated)
		c.updateState()
	}
}

func (c *Client) responseWait() time.Duration {
	jitterRange := c.retryWaitInterval / RetryJitterDivisor
	if jitterRange > RetryIntervalJitter {
		jitterRange = RetryIntervalJitter
	}
	return time.Duration(c.retryWaitInterval+c.randUint32(jitterRange)) * time.Millisecond
}

func (c *Client) scheduleResponseDeadline() {
	if c.retryWaitInterval == 0 {
		c.growRetryWaitInterval()
	}
	c.armTimer(c.responseWait(), c.handleTimer)
}

// failAttempt notifies exactly once for each rejected/timed-out attempt.
// Immediate send/build errors retain the existing terminal-only ErrFailed
// notification. The eight-failure limit belongs only to consecutive local
// build/send failures. Response failure retry wiring is new (the old client
// never armed a deadline), using its existing capped wait/backoff scaffolding
// and the pinned OpenThread retry approach, without a new response-count stop.
func (c *Client) failAttempt(err error, responseFailure bool) {
	c.cancelAttempt()
	c.changeHostAndServiceStates(&newStateOnUpdateFailure, false)
	if responseFailure {
		c.txFailureRetryCount = 0 // The server response/accepted send was not a local send failure.
		c.growRetryWaitInterval()
		c.setState(StateToRetry)
		c.armTimer(c.responseWait(), c.handleTimer)
		c.invokeCallback(err)
		return // No state/timer mutation after external callback re-entry.
	}
	c.txFailureRetryCount++
	if c.txFailureRetryCount >= MaxTxFailureRetries {
		// Updated means quiescent, not Registered: item flags retain pending
		// work after the existing consecutive-local-send-failure bound.
		c.txFailureRetryCount = 0
		c.setState(StateUpdated)
		c.invokeCallback(err)
		return
	}
	c.setState(StateToUpdate)
	delay := TxFailureRetryInterval + c.randUint32(TxFailureRetryJitter)
	c.armTimer(time.Duration(delay)*time.Millisecond, c.handleTimer)
}

func (c *Client) responseTimedOut() {
	c.failAttempt(errors.ErrResponseTimeout, true)
}
