// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package submac

import (
	"bytes"
	"testing"

	"github.com/hilli/gothread/radio"
)

func TestCopiedSubmissionIdentityAndStagingIsolation(t *testing.T) {
	sm, r, callbacks, _ := newTestSubMac(radio.CapNone)
	if err := sm.Enable(); err != nil {
		t.Fatal(err)
	}
	staging := sm.GetTransmitFrame()
	staging.PSDU = []byte{1, 2, 3}
	staging.TxInfo = &radio.TxInfo{TxPower: -9, IsSecurityProcessed: true}
	if err := sm.Send(TxRequest{Channel: 20}); err != nil {
		t.Fatal(err)
	}
	submitted := r.transmitFrame
	if submitted == staging || submitted.TxInfo == staging.TxInfo ||
		submitted.TxInfo.SubmissionID == 0 || staging.TxInfo.SubmissionID != 0 {
		t.Fatal("submitted origin was not isolated from staging")
	}
	staging.PSDU[0] = 9
	staging.TxInfo.TxPower = 7
	if !bytes.Equal(submitted.PSDU, []byte{1, 2, 3}) ||
		submitted.TxInfo.TxPower != -9 || !submitted.TxInfo.IsSecurityProcessed {
		t.Fatal("staging reuse changed submitted bytes/metadata")
	}
	sm.HandleTransmitDone(staging, nil, nil)
	if callbacks.transmitDoneCount != 0 || sm.GetState() != StateTransmit {
		t.Fatal("identity-free staging completion was accepted")
	}
	copied := *submitted
	info := *submitted.TxInfo
	copied.TxInfo = &info
	sm.HandleTransmitDone(&copied, nil, nil)
	if callbacks.transmitDoneCount != 1 || callbacks.transmitDoneErr != nil {
		t.Fatal("legitimate driver-owned frame/metadata copy was rejected")
	}
}

func TestOldAttemptTimeoutCannotAffectRetry(t *testing.T) {
	sm, r, callbacks, timer := newTestSubMac(radio.CapCsmaBackoff)
	if err := sm.Enable(); err != nil {
		t.Fatal(err)
	}
	if err := sm.Send(TxRequest{Channel: 20, AckRequest: true, MaxFrameRetries: 1}); err != nil {
		t.Fatal(err)
	}
	first := r.transmitFrame
	sm.HandleTransmitStarted(first)
	oldTimeout := timer.pendingFn
	sm.HandleTransmitDone(first, nil, ErrNoAck)
	retry := r.transmitFrame
	if retry.TxInfo.SubmissionID == first.TxInfo.SubmissionID {
		t.Fatal("radio attempts reused an origin ID")
	}
	oldTimeout()
	if callbacks.transmitDoneCount != 0 || sm.GetState() != StateTransmit {
		t.Fatal("old attempt timer completed the new retry")
	}
	sm.HandleTransmitDone(retry, nil, nil)
	if callbacks.transmitDoneCount != 1 || callbacks.transmitDoneErr != nil {
		t.Fatal("retry did not complete with its exact own result")
	}
}
