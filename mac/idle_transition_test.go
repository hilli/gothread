// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mac

import (
	"testing"

	"github.com/hilli/gothread/mac/submac"
	"github.com/hilli/gothread/radio"
)

func TestIdleModeChangeDoesNotOverwriteActiveTransmitOwner(t *testing.T) {
	m, _, callbacks, _, runner := newTestMac(radio.CapCsmaBackoff | radio.CapAckTimeout | radio.CapTransmitRetries)
	if err := m.Enable(); err != nil {
		t.Fatal(err)
	}
	callbacks.frameRequestReturn = true
	m.RequestDirectFrameTransmission()
	runner.runOne()
	if m.subMac.GetState() != submac.StateTransmit {
		t.Fatal("fixture did not start a transmit")
	}
	for _, receive := range []bool{false, true} {
		m.SetRxOnWhenIdle(receive)
		if m.subMac.GetState() != submac.StateTransmit {
			t.Error("idle-mode update replaced active TX state and would discard its completion")
		}
	}
}
