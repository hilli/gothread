// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"bytes"
	"context"
	"testing"

	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/thread/key"
)

func TestStandardFragmentedKeyRotationBetweenFragments(t *testing.T) {
	src := newFragmentEndpoint(t, fragmentSource, udpPeerExt, 0x0400, 0x0800, simulation.NewSimSettings())
	dst := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
	info := fragmentInfo(fragmentSource, udpPeerExt, false)
	payload := bytes.Repeat([]byte{0x71}, 98)
	if err := src.inst.Do(context.Background(), func() error { return src.inst.SendUDP(payload, info) }); err != nil {
		t.Fatal(err)
	}
	first := captureUDP(t, src.driver.boundedUDPRadio)
	firstCtx, _ := nativeAdaptation(t, first, src.macKey)
	deliverNativeFrame(t, dst, first)
	for _, node := range []*fragmentEndpoint{src, dst} {
		if err := node.inst.Do(context.Background(), func() error {
			node.inst.SetCurrentKeySequence(1, key.ForceUpdate)
			node.macKey = node.inst.keyManager.GetCurrentMacKey()
			return node.inst.PersistenceError()
		}); err != nil {
			t.Fatal(err)
		}
	}
	completeNativeFrame(t, src, nil)
	last := captureUDP(t, src.driver.boundedUDPRadio)
	lastCtx, _ := nativeAdaptation(t, last, src.macKey)
	if lastCtx.Security.FrameCounter != firstCtx.Security.FrameCounter+1 {
		t.Fatal("persistent key rotation reset a fragment counter")
	}
	deliverNativeFrame(t, dst, last)
	completeNativeFrame(t, src, nil)
	assertFragmentDelivery(t, src, dst, payload, info, 1)
}
