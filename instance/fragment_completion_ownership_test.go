// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hilli/gothread/platform/simulation"
)

func TestDeferredACompletionCannotAdvanceReenabledFragmentedB(t *testing.T) {
	src := newFragmentEndpoint(t, fragmentSource, udpPeerExt, 0x0400, 0x0800, simulation.NewSimSettings())
	info := fragmentInfo(fragmentSource, udpPeerExt, false)
	if err := src.inst.Do(context.Background(), func() error { return src.inst.SendUDP(make([]byte, 1232), info) }); err != nil {
		t.Fatal(err)
	}
	_ = captureUDP(t, src.driver.boundedUDPRadio)
	var delayed func()
	if err := src.inst.Do(context.Background(), func() error {
		submittedA := src.driver.lastSubmit
		src.inst.subMac.HandleTransmitDone(submittedA, nil, nil)
		// Hold the actual deferred bridge callback until AFTER B has started.
		src.inst.timers.mu.Lock()
		for _, timer := range src.inst.timers.timers {
			if !timer.cancelled && !timer.fireAt.After(time.Now()) {
				delayed, timer.cancelled = timer.fn, true
				break
			}
		}
		src.inst.timers.mu.Unlock()
		if delayed == nil {
			return errors.New("A's real deferred completion was not scheduled")
		}
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
		return src.inst.SendUDP(make([]byte, 1232), info)
	}); err != nil {
		t.Fatal(err)
	}
	_ = captureUDP(t, src.driver.boundedUDPRadio)
	if err := src.inst.Do(context.Background(), func() error {
		usage, pending := src.inst.forwarder.GetBufferUsage(), src.inst.pendingTxMsg
		delayed()
		if src.inst.forwarder.GetBufferUsage() != usage || src.inst.pendingTxMsg != pending {
			t.Error("deferred A completion advanced/retired B without B completing")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
