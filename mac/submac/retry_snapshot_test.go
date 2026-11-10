// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package submac

import (
	"bytes"
	"testing"

	"github.com/hilli/gothread/radio"
)

func TestRetryPreservesBorrowedRadioUpdatesAndNewSubmissionIdentity(t *testing.T) {
	sm, r, callbacks, _ := newTestSubMac(radio.CapCsmaBackoff)
	if err := sm.Enable(); err != nil {
		t.Fatal(err)
	}
	sm.GetTransmitFrame().PSDU = []byte{1, 2, 3}
	if err := sm.Send(TxRequest{Channel: 20, MaxFrameRetries: 1}); err != nil {
		t.Fatal(err)
	}
	first := *r.transmitFrame
	info := *first.TxInfo
	first.TxInfo = &info
	first.PSDU = []byte{9, 8, 7}
	first.TxInfo.IsHeaderUpdated, first.TxInfo.IsSecurityProcessed = true, true
	sm.HandleTransmitDone(&first, nil, ErrNoAck)
	retry := r.transmitFrame
	if !bytes.Equal(retry.PSDU, []byte{9, 8, 7}) || !retry.TxInfo.IsHeaderUpdated ||
		!retry.TxInfo.IsSecurityProcessed || retry.TxInfo.SubmissionID == first.TxInfo.SubmissionID {
		t.Fatal("retry lost exact radio-updated wire bytes/metadata or reused an attempt identity")
	}
	sm.HandleTransmitDone(retry, nil, nil)
	if callbacks.transmitDoneCount != 1 {
		t.Fatal("retry did not complete")
	}
	clear(retry.PSDU)
	retry.TxInfo.IsSecurityProcessed = false
	if !bytes.Equal(callbacks.transmitDoneFrame.PSDU, []byte{9, 8, 7}) ||
		!callbacks.transmitDoneFrame.TxInfo.IsSecurityProcessed {
		t.Fatal("borrowed driver callback storage leaked into retained completion")
	}
}
