// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/thread/mle"
)

// Called only after Dispatcher authentication, replay and handler success,
// before any follow-on request captures the parent's response sequence.
func (inst *Instance) observeAuthenticatedParent(payload []byte, source types.ExtAddress) error {
	attachment := inst.ownedAttachment
	if attachment == nil || source != attachment.parentExt || !inst.mleService.Mle().IsChild() {
		return nil
	}
	message, err := mle.ParseMessage(payload)
	if err != nil {
		return err
	}
	if message.SecuritySuite != mle.SecuritySuiteEncMic32 {
		return goterrors.ErrSecurity
	}
	if err := inst.SecurityError(); err != nil {
		return err
	}
	if err := inst.PersistenceError(); err != nil {
		return err
	}
	parent := inst.mleService.Mle().GetParent()
	sequence := message.SecHeader.KeySource
	if sequence != parent.KeySequence {
		return goterrors.ErrInvalidState
	}
	for _, expected := range inst.expectedMLE {
		if expected != nil && expected.sequence != sequence {
			inst.retireExpectedMLE(expected)
		}
	}
	return nil
}
