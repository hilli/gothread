// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package submac

import (
	"fmt"
	"testing"

	"github.com/hilli/gothread/radio"
)

func TestOldTransmitCompletionAfterReenableCannotCompleteB(t *testing.T) {
	for _, oldErr := range []error{nil, ErrNoAck} {
		t.Run(fmt.Sprint(oldErr), func(t *testing.T) {
			sm, r, callbacks, timer := newTestSubMac(radio.CapNone)
			if err := sm.Enable(); err != nil {
				t.Fatal(err)
			}
			sm.GetTransmitFrame().PSDU = []byte{0xaa}
			request := TxRequest{Channel: 20, AckRequest: true}
			if err := sm.Send(request); err != nil {
				t.Fatal(err)
			}
			submittedA := r.transmitFrame // Capture at actual Radio.Transmit.
			if err := sm.Disable(); err != nil {
				t.Fatal(err)
			}
			if err := sm.Enable(); err != nil {
				t.Fatal(err)
			}
			sm.GetTransmitFrame().PSDU = []byte{0xbb}
			if err := sm.Send(request); err != nil {
				t.Fatal(err)
			}
			submittedB := r.transmitFrame
			sm.HandleTransmitStarted(submittedB)
			scheduled, stopped := timer.scheduled, timer.stopped
			sm.HandleTransmitStarted(submittedA)
			sm.HandleTransmitDone(submittedA, nil, oldErr)
			if sm.GetState() != StateTransmit || callbacks.transmitDoneCount != 0 ||
				timer.stopped != stopped || timer.scheduled != scheduled {
				t.Errorf("old A callback modified B: state=%v done=%d timers=%d/%d want=%d/%d",
					sm.GetState(), callbacks.transmitDoneCount, timer.scheduled, timer.stopped, scheduled, stopped)
			}
			sm.HandleTransmitDone(submittedB, nil, nil)
			if callbacks.transmitDoneCount != 1 || callbacks.transmitDoneErr != nil {
				t.Fatal("B did not receive exactly its own successful completion")
			}
		})
	}
}

func TestOldScheduledBackoffCannotStartReenabledB(t *testing.T) {
	sm, r, _, timer := newTestSubMac(radio.CapNone)
	if err := sm.Enable(); err != nil {
		t.Fatal(err)
	}
	if err := sm.Send(TxRequest{Channel: 20, CsmaCaEnabled: true}); err != nil {
		t.Fatal(err)
	}
	oldBackoff := timer.pendingFn
	if err := sm.Disable(); err != nil {
		t.Fatal(err)
	}
	if err := sm.Enable(); err != nil {
		t.Fatal(err)
	}
	if err := sm.Send(TxRequest{Channel: 20, CsmaCaEnabled: true}); err != nil {
		t.Fatal(err)
	}
	oldBackoff()
	if r.transmitCount != 0 || sm.GetState() != StateCsmaBackoff {
		t.Error("old scheduled A callback started B before B's timer")
	}
	timer.fire()
	if r.transmitCount != 1 {
		t.Fatalf("B's own backoff submitted %d transmissions, want 1", r.transmitCount)
	}
}
