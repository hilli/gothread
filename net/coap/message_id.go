// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package coap

import goterrors "github.com/hilli/gothread/errors"

// Called with the engine lock. Wrapping is allowed, but an active request's
// MID is never reused. Native owner capacity bounds this search to nine IDs.
func (e *Engine) allocateMessageIDLocked() (uint16, error) {
	if len(e.pending) >= 1<<16 {
		return 0, goterrors.ErrNoBufs
	}
	for attempt := 0; attempt <= len(e.pending); attempt++ {
		candidate := e.nextMessageID()
		used := false
		for _, pending := range e.pending {
			if pending.messageID == candidate {
				used = true
				break
			}
		}
		if !used {
			return candidate, nil
		}
	}
	return 0, goterrors.ErrNoBufs
}
