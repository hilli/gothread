// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"context"
	"errors"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/submac"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/mle"
)

func TestMTDParentHandoffAdmissionSnapshotRetiresOnChange(t *testing.T) {
	for _, afterFirstFrame := range []bool{false, true} {
		for _, test := range []struct {
			name   string
			change func(*Instance)
		}{
			{"parent-lost", func(i *Instance) { i.mleService.Mle().GetParent().State = mle.StateInvalid }},
			{"parent-replaced-eui", func(i *Instance) { i.mleService.Mle().GetParent().MacAddr = types.ExtAddress{0x18, 7: 0x55} }},
			{"parent-replaced-rloc", func(i *Instance) { i.mleService.Mle().GetParent().RLOC16 = 0x0c00 }},
			{"parent-sleeps", func(i *Instance) { i.mleService.Mle().GetParent().Mode.Set(mle.ModeFullThreadDevice) }},
			{"role-router", func(i *Instance) { _ = i.mleService.Mle().SetStateRouter(0x0400) }},
			{"role-detached", func(i *Instance) { _ = i.mleService.Mle().BecomeDetached() }},
			{"mode-ftd", func(i *Instance) { i.mleService.Mle().SetDeviceMode(mle.NewDeviceMode(0x0f)) }},
			{"mode-sleepy", func(i *Instance) { i.mleService.Mle().SetDeviceMode(mle.NewDeviceMode(0)) }},
			{"mac-rx-off", func(i *Instance) { i.mac.SetRxOnWhenIdle(false) }},
			{"source-invalidated", func(i *Instance) { i.netif.GetUnicastAddresses()[0].Valid = false }},
			{"source-prefix-lost", func(i *Instance) { i.netif.GetUnicastAddresses()[0].PrefixLength = 0 }},
			{"source-scope-changed", func(i *Instance) {
				addresses := i.netif.GetUnicastAddresses()
				addresses[0].ScopeOverrideValid, addresses[0].ScopeOverride = true, ip6.ScopeRealmLocal
			}},
			{"local-eui-changed", func(i *Instance) { i.mac.SetExtAddress(types.ExtAddress{0xa4, 7: 0x66}) }},
			{"local-rloc-changed", func(i *Instance) { i.SetRLOC16(0x0802) }},
			{"mac-rloc-changed", func(i *Instance) { i.mac.SetShortAddress(0x0802) }},
			{"pan-changed", func(i *Instance) { i.mac.SetPanID(0xbeef) }},
			{"mesh-prefix-changed", func(i *Instance) { i.SetMeshLocalPrefix([8]byte{0xfd, 0x22, 7: 1}) }},
			{"network-key-changed", func(i *Instance) { i.keyManager.SetNetworkKey(key.NetworkKey{9, 8, 7}) }},
		} {
			name := "queued/"
			if afterFirstFrame {
				name = "between-fragments/"
			}
			t.Run(name+test.name, func(t *testing.T) {
				node, info := newMTDHandoffEndpoint(t, true)
				var counter uint32
				if err := node.inst.Do(context.Background(), func() error {
					counter = node.inst.keyManager.GetMacFrameCounter()
					if err := node.inst.SendUDP(make([]byte, 1232), info); err != nil {
						return err
					}
					if !afterFirstFrame {
						test.change(node.inst)
					}
					return nil // Admission succeeded even though later validation may fail.
				}); err != nil {
					t.Fatal(err)
				}
				if afterFirstFrame {
					first := captureUDP(t, node.driver.boundedUDPRadio)
					ctx, _ := nativeAdaptation(t, first, node.macKey)
					if ctx.Security.FrameCounter != counter {
						t.Error("initial parent fragment skipped normal counter allocation")
					}
					counter++
					if err := node.inst.Do(context.Background(), func() error {
						test.change(node.inst)
						return nil
					}); err != nil {
						t.Fatal(err)
					}
					completeNativeFrame(t, node, first, nil)
				}
				waitUDPCondition(t, node.inst, func() bool {
					return node.inst.forwarder.GetBufferUsage().TxDatagrams == 0
				})
				if err := node.inst.Do(context.Background(), func() error {
					counters := node.inst.forwarder.GetCounters()
					if counters.TxDropped != 1 || counters.TxDirect != 0 ||
						node.inst.keyManager.GetMacFrameCounter() != counter {
						t.Errorf("changed route did not retire before counter/frame: %+v counter=%d want=%d",
							counters, node.inst.keyManager.GetMacFrameCounter(), counter)
					}
					if node.callbacks != 0 || node.inst.PersistenceError() != nil {
						t.Error("route invalidation caused local delivery or a fictional persistence latch")
					}
					if test.name == "mac-rx-off" && node.inst.subMac.GetState() != submac.StateSleep {
						t.Error("deferred idle-mode change was not applied after TX finished")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				select {
				case <-node.driver.captures:
					t.Fatal("unsent data reached a stale/replaced parent route")
				default:
				}
			})
		}
	}
}

func TestMTDParentHandoffLossThenExplicitReadmission(t *testing.T) {
	node, info := newMTDHandoffEndpoint(t, true)
	if err := node.inst.Do(context.Background(), func() error {
		if err := node.inst.SendUDP(make([]byte, 1232), info); err != nil {
			return err
		}
		node.inst.mleService.Mle().GetParent().State = mle.StateInvalid
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	waitUDPCondition(t, node.inst, func() bool { return node.inst.forwarder.GetBufferUsage().TxDatagrams == 0 })
	if err := node.inst.Do(context.Background(), func() error {
		if got := node.inst.SendUDP([]byte{1}, info); got != goterrors.ErrNoRoute {
			t.Errorf("lost-parent admission=%v", got)
		}
		node.inst.mleService.Mle().GetParent().State = mle.StateValid
		return node.inst.SendUDP([]byte{3, 5, 7}, info)
	}); err != nil {
		t.Fatal(err)
	}
	captureParentHandoff(t, node, info, []byte{3, 5, 7})
}

func TestMTDParentHandoffKeyRotationAndAsyncPersistenceIdentity(t *testing.T) {
	settings := &udpFaultSettings{SimSettings: simulation.NewSimSettings()}
	node, info := newMTDHandoffEndpointSettings(t, true, settings)
	payload := make([]byte, 1232)
	if err := node.inst.Do(context.Background(), func() error { return node.inst.SendUDP(payload, info) }); err != nil {
		t.Fatal(err)
	}
	first := captureUDP(t, node.driver.boundedUDPRadio)
	ctx, _ := nativeAdaptation(t, first, node.macKey)
	if err := node.inst.Do(context.Background(), func() error {
		node.inst.SetCurrentKeySequence(1, key.ForceUpdate)
		node.macKey = node.inst.keyManager.GetCurrentMacKey()
		return node.inst.PersistenceError()
	}); err != nil {
		t.Fatal(err)
	}
	completeNativeFrame(t, node, first, nil)
	next := captureUDP(t, node.driver.boundedUDPRadio)
	nextCtx, _ := nativeAdaptation(t, next, node.macKey)
	if nextCtx.Security.FrameCounter != ctx.Security.FrameCounter+1 || nextCtx.Security.KeyId == ctx.Security.KeyId {
		t.Error("key-sequence rotation broke parent fragment/counter identity")
	}
	writeErr := errors.New("parent-handoff reservation failure")
	if err := node.inst.Do(context.Background(), func() error {
		node.inst.keyManager.SetMacFrameCounter(node.inst.keyManager.GetStoredMacFrameCounter())
		settings.fail = writeErr
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	completeNativeFrame(t, node, next, nil)
	waitUDPCondition(t, node.inst, func() bool { return node.inst.forwarder.GetBufferUsage().TxDatagrams == 0 })
	if err := node.inst.Do(context.Background(), func() error {
		if !errors.Is(node.inst.PersistenceError(), writeErr) ||
			node.inst.forwarder.GetCounters().TxDropped != 1 {
			t.Error("parent-handoff asynchronous persistence failure was hidden")
		}
		if err := node.inst.SendUDP(nil, info); !errors.Is(err, writeErr) {
			t.Errorf("parent admission lost persistence error identity: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
