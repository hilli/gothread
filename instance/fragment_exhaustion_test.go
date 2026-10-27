// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"context"
	"math"
	"testing"

	"github.com/hilli/gothread/platform/simulation"
)

func TestStandardFragmentedCounterExhaustionDoesNotWrap(t *testing.T) {
	src := newFragmentEndpoint(t, fragmentSource, udpPeerExt, 0x0400, 0x0800, simulation.NewSimSettings())
	info := fragmentInfo(fragmentSource, udpPeerExt, false)
	if err := src.inst.Do(context.Background(), func() error {
		src.inst.keyManager.SetMacFrameCounter(math.MaxUint32 - 10)
		return src.inst.SendUDP(make([]byte, 1232), info)
	}); err != nil {
		t.Fatal(err)
	}
	for i := uint32(0); i < 10; i++ {
		frame := captureUDP(t, src.driver.boundedUDPRadio)
		ctx, _ := nativeAdaptation(t, frame, src.macKey)
		if ctx.Security.FrameCounter != math.MaxUint32-10+i {
			t.Fatalf("fragment counter at exhaustion=%d", ctx.Security.FrameCounter)
		}
		completeNativeFrame(t, src, nil)
	}
	waitUDPCondition(t, src.inst, func() bool {
		return src.inst.forwarder.GetBufferUsage().TxBytes == 0
	})
	if err := src.inst.Do(context.Background(), func() error {
		if src.inst.keyManager.GetMacFrameCounter() != math.MaxUint32 ||
			src.inst.forwarder.GetCounters().TxDropped != 1 {
			t.Error("exhausted fragmented packet wrapped or retained owned resources")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-src.driver.captures:
		t.Fatal("exhausted sentinel was transmitted or a counter wrapped")
	default:
	}
}
