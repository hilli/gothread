// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"context"
	"errors"
	"testing"

	"github.com/hilli/gothread/mac/submac"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/mle"
)

func TestMTDParentHandoffLostDuringCSMADoesNotSubmitStaleFrame(t *testing.T) {
	node, info := newMTDHandoffEndpointCaps(t, true, simulation.NewSimSettings(), radio.CapNone)
	if err := node.inst.Do(context.Background(), func() error {
		counter := node.inst.keyManager.GetMacFrameCounter()
		if err := node.inst.SendUDP(make([]byte, 1232), info); err != nil {
			return err
		}
		// Run only the existing zero-delay MAC tasklet before returning this
		// operation. processExpired snapshots time; the backoff it creates is
		// newer and cannot run until after we invalidate the parent below.
		node.inst.timers.processExpired()
		if node.inst.pendingTxMsg == nil || node.inst.subMac.GetState() != submac.StateCsmaBackoff ||
			node.inst.keyManager.GetMacFrameCounter() != counter+1 {
			return errors.New("fixture did not build/encrypt a frame before CSMA")
		}
		node.inst.mleService.Mle().GetParent().State = mle.StateInvalid
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	waitUDPCondition(t, node.inst, func() bool {
		return node.inst.forwarder.GetBufferUsage().TxDatagrams == 0
	})
	select {
	case <-node.driver.captures:
		t.Fatal("built CSMA frame reached Radio.Transmit after losing the parent")
	default:
	}
	if err := node.inst.Do(context.Background(), func() error {
		if node.inst.forwarder.GetCounters().TxDropped != 1 || node.callbacks != 0 {
			t.Error("delayed parent loss was not observed as one datagram drop")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMTDParentHandoffLostBeforeRetryDoesNotResubmit(t *testing.T) {
	node, info := newMTDHandoffEndpointCaps(t, true, simulation.NewSimSettings(), radio.CapCsmaBackoff|radio.CapAckTimeout)
	if err := node.inst.Do(context.Background(), func() error { return node.inst.SendUDP(make([]byte, 1232), info) }); err != nil {
		t.Fatal(err)
	}
	first := captureUDP(t, node.driver.boundedUDPRadio)
	ctx, _ := nativeAdaptation(t, first, node.macKey)
	if err := node.inst.Do(context.Background(), func() error {
		node.inst.mleService.Mle().GetParent().State = mle.StateInvalid
		node.inst.subMac.HandleTransmitDone(&first.frame, nil, submac.ErrNoAck)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	waitUDPCondition(t, node.inst, func() bool {
		return node.inst.forwarder.GetBufferUsage().TxDatagrams == 0
	})
	select {
	case <-node.driver.captures:
		t.Fatal("software retry submitted the frame to a lost parent")
	default:
	}
	if err := node.inst.Do(context.Background(), func() error {
		if node.inst.forwarder.GetCounters().TxDropped != 1 ||
			node.inst.keyManager.GetMacFrameCounter() != ctx.Security.FrameCounter+1 {
			t.Error("refused stale-parent retry took a new counter or hid the drop")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
