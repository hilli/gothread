// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package submac

import (
	"testing"

	"github.com/hilli/gothread/radio"
)

func TestDisabledTransmitCompletionCannotRetryOldFragment(t *testing.T) {
	sm, r, callbacks, _ := newTestSubMac(radio.CapNone)
	if err := sm.Enable(); err != nil {
		t.Fatal(err)
	}
	if err := sm.Send(TxRequest{Channel: 20, MaxFrameRetries: 1}); err != nil {
		t.Fatal(err)
	}
	if err := sm.Disable(); err != nil {
		t.Fatal(err)
	}
	sm.HandleTransmitDone(sm.GetTransmitFrame(), nil, ErrNoAck)
	if sm.GetState() != StateDisabled || r.transmitCount != 1 || callbacks.transmitDoneCount != 0 {
		t.Fatal("late completion revived/retried a disabled frame")
	}
	if err := sm.Enable(); err != nil {
		t.Fatal(err)
	}
	if err := sm.Send(TxRequest{Channel: 20}); err != nil || r.transmitCount != 2 {
		t.Fatalf("new transmit after disable/enable: %v count=%d", err, r.transmitCount)
	}
}
