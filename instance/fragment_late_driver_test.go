// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"bytes"
	"context"
	"testing"

	"github.com/hilli/gothread/mac/submac"
	"github.com/hilli/gothread/platform/simulation"
)

func TestCopiedDriverACompletionAfterBStartsCannotRetireB(t *testing.T) {
	src := newFragmentEndpoint(t, fragmentSource, udpPeerExt, 0x0400, 0x0800, simulation.NewSimSettings())
	dst := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
	info := fragmentInfo(fragmentSource, udpPeerExt, false)
	if err := src.inst.Do(context.Background(), func() error { return src.inst.SendUDP(make([]byte, 1232), info) }); err != nil {
		t.Fatal(err)
	}
	oldA := captureUDP(t, src.driver.boundedUDPRadio) // Driver-owned deep metadata copy.
	payload := bytes.Repeat([]byte{0xb3}, 1232)
	if err := src.inst.Do(context.Background(), func() error {
		if err := src.inst.ThreadStop(); err != nil {
			return err
		}
		if err := src.inst.IfConfigDown(); err != nil {
			return err
		}
		if err := src.inst.IfConfigUp(); err != nil {
			return err
		}
		if err := src.inst.ThreadStart(); err != nil {
			return err
		}
		if err := src.inst.mleService.Mle().SetStateRouter(0x0400); err != nil {
			return err
		}
		return src.inst.SendUDP(payload, info)
	}); err != nil {
		t.Fatal(err)
	}
	currentB := captureUDP(t, src.driver.boundedUDPRadio)
	if oldA.frame.TxInfo.SubmissionID == 0 || oldA.frame.TxInfo.SubmissionID == currentB.frame.TxInfo.SubmissionID {
		t.Fatal("driver snapshots did not retain distinct submission origins")
	}
	if err := src.inst.Do(context.Background(), func() error {
		usage, pending := src.inst.forwarder.GetBufferUsage(), src.inst.pendingTxMsg
		src.inst.subMac.HandleTransmitStarted(&oldA.frame)
		src.inst.subMac.HandleTransmitDone(&oldA.frame, nil, submac.ErrNoAck)
		if src.inst.forwarder.GetBufferUsage() != usage || src.inst.pendingTxMsg != pending {
			t.Error("copied stale A completion changed B's datagram ownership")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for frames := 0; ; frames++ {
		if frames >= 20 {
			t.Fatal("B did not finish its normal bounded fragment sequence")
		}
		deliverNativeFrame(t, dst, currentB)
		completeNativeFrame(t, src, currentB, nil)
		var done bool
		if err := src.inst.Do(context.Background(), func() error {
			done = src.inst.forwarder.GetBufferUsage().TxDatagrams == 0
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if done {
			break
		}
		currentB = captureUDP(t, src.driver.boundedUDPRadio)
	}
	assertFragmentDelivery(t, src, dst, payload, info, 1)
}
