// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"context"
	"fmt"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
)

func TestMTDParentHandoffRefusalMatrix(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Instance, *ip6.MessageInfo)
		want   error
	}{
		{"detached", func(i *Instance, _ *ip6.MessageInfo) { _ = i.mleService.Mle().BecomeDetached() }, goterrors.ErrDetached},
		{"mle-disabled", func(i *Instance, _ *ip6.MessageInfo) { _ = i.mleService.Mle().Disable() }, goterrors.ErrDetached},
		{"thread-disabled", func(i *Instance, _ *ip6.MessageInfo) { i.threadEnabled = false }, goterrors.ErrInvalidState},
		{"interface-down", func(i *Instance, _ *ip6.MessageInfo) { i.ifConfigUp = false }, goterrors.ErrInvalidState},
		{"mac-disabled", func(i *Instance, _ *ip6.MessageInfo) { _ = i.mac.Disable() }, goterrors.ErrInvalidState},
		{"router", func(i *Instance, _ *ip6.MessageInfo) { _ = i.mleService.Mle().SetStateRouter(0x0400) }, goterrors.ErrNoRoute},
		{"leader", func(i *Instance, _ *ip6.MessageInfo) { _ = i.mleService.Mle().SetStateLeader(0x0400) }, goterrors.ErrNoRoute},
		{"ftd-child", func(i *Instance, _ *ip6.MessageInfo) { i.mleService.Mle().SetDeviceMode(mle.NewDeviceMode(0x0f)) }, goterrors.ErrNoRoute},
		{"sleepy-mtd", func(i *Instance, _ *ip6.MessageInfo) { i.mleService.Mle().SetDeviceMode(mle.NewDeviceMode(0)) }, goterrors.ErrNoRoute},
		{"mac-rx-off", func(i *Instance, _ *ip6.MessageInfo) { i.mac.SetRxOnWhenIdle(false) }, goterrors.ErrNoRoute},
		{"no-parent", func(i *Instance, _ *ip6.MessageInfo) { *i.mleService.Mle().GetParent() = mle.Parent{} }, goterrors.ErrNoRoute},
		{"invalid-parent", func(i *Instance, _ *ip6.MessageInfo) { i.mleService.Mle().GetParent().State = mle.StateInvalid }, goterrors.ErrNoRoute},
		{"restored-parent", func(i *Instance, _ *ip6.MessageInfo) { i.mleService.Mle().GetParent().State = mle.StateRestored }, goterrors.ErrNoRoute},
		{"sleepy-parent", func(i *Instance, _ *ip6.MessageInfo) {
			i.mleService.Mle().GetParent().Mode.Set(mle.ModeFullThreadDevice)
		}, goterrors.ErrNoRoute},
		{"non-router-parent", func(i *Instance, _ *ip6.MessageInfo) { i.mleService.Mle().GetParent().Mode.Set(mle.ModeRxOnWhenIdle) }, goterrors.ErrNoRoute},
		{"parent-eui-zero", func(i *Instance, _ *ip6.MessageInfo) { i.mleService.Mle().GetParent().MacAddr = types.ExtAddress{} }, goterrors.ErrNoRoute},
		{"parent-eui-group", func(i *Instance, _ *ip6.MessageInfo) { i.mleService.Mle().GetParent().MacAddr[0] |= 1 }, goterrors.ErrNoRoute},
		{"parent-eui-self", func(i *Instance, _ *ip6.MessageInfo) { i.mleService.Mle().GetParent().MacAddr = i.GetExtAddress() }, goterrors.ErrNoRoute},
		{"parent-is-child-rloc", func(i *Instance, _ *ip6.MessageInfo) { i.mleService.Mle().GetParent().RLOC16 = 0x0802 }, goterrors.ErrNoRoute},
		{"parent-other-router", func(i *Instance, _ *ip6.MessageInfo) { i.mleService.Mle().GetParent().RLOC16 = 0x0c00 }, goterrors.ErrNoRoute},
		{"parent-invalid-rloc", func(i *Instance, _ *ip6.MessageInfo) { i.mleService.Mle().GetParent().RLOC16 = mle.InvalidRLOC16 }, goterrors.ErrNoRoute},
		{"own-invalid-rloc", func(i *Instance, _ *ip6.MessageInfo) { _ = i.mleService.Mle().SetStateChild(mle.InvalidRLOC16) }, goterrors.ErrNoRoute},
		{"own-router-rloc", func(i *Instance, _ *ip6.MessageInfo) { _ = i.mleService.Mle().SetStateChild(0x0800) }, goterrors.ErrNoRoute},
		{"own-reserved-rloc-bit", func(i *Instance, _ *ip6.MessageInfo) { _ = i.mleService.Mle().SetStateChild(0x0a01) }, goterrors.ErrNoRoute},
		{"instance-rloc-mismatch", func(i *Instance, _ *ip6.MessageInfo) { i.SetRLOC16(0x0802) }, goterrors.ErrNoRoute},
		{"mac-rloc-mismatch", func(i *Instance, _ *ip6.MessageInfo) { i.mac.SetShortAddress(0x0802) }, goterrors.ErrNoRoute},
		{"local-eui-zero", func(i *Instance, _ *ip6.MessageInfo) { i.mac.SetExtAddress(types.ExtAddress{}) }, goterrors.ErrSecurity},
		{"local-eui-group", func(i *Instance, _ *ip6.MessageInfo) { i.mac.SetExtAddress(types.ExtAddress{1, 7: 1}) }, goterrors.ErrSecurity},
		{"broadcast-pan", func(i *Instance, _ *ip6.MessageInfo) { i.mac.SetPanID(types.BroadcastPanID) }, goterrors.ErrNoRoute},
		{"no-mesh-prefix", func(i *Instance, _ *ip6.MessageInfo) { i.SetMeshLocalPrefix([8]byte{}) }, goterrors.ErrNoRoute},
		{"unspecified-peer", func(_ *Instance, info *ip6.MessageInfo) { info.PeerAddr = ip6.Address{} }, goterrors.ErrInvalidArgs},
		{"loopback-peer", func(_ *Instance, info *ip6.MessageInfo) { info.PeerAddr = ip6.Address{15: 1} }, goterrors.ErrInvalidArgs},
		{"self-peer", func(_ *Instance, info *ip6.MessageInfo) { info.PeerAddr = info.SockAddr }, goterrors.ErrNoRoute},
		{"multicast-peer", func(_ *Instance, info *ip6.MessageInfo) { info.PeerAddr = ip6.Address{0xff, 2, 15: 1} }, goterrors.ErrNotCapable},
		{"mapped-peer", func(_ *Instance, info *ip6.MessageInfo) {
			info.PeerAddr = ip6.Address{10: 0xff, 11: 0xff, 12: 127, 15: 1}
		}, goterrors.ErrNoRoute},
		{"reserved-peer-iid", func(_ *Instance, info *ip6.MessageInfo) { clear(info.PeerAddr[8:]) }, goterrors.ErrNoRoute},
		{"anycast-peer", func(i *Instance, info *ip6.MessageInfo) {
			info.PeerAddr = i.GetMeshLocalAddress()
			info.PeerAddr[14] = 0xfc
		}, goterrors.ErrNoRoute},
		{"unknown-link-local", func(i *Instance, info *ip6.MessageInfo) {
			info.SockAddr = i.GetLinkLocalAddress()
			info.PeerAddr = linkLocalAddress(types.ExtAddress{0x18, 7: 0x99})
		}, goterrors.ErrNoRoute},
		{"mixed-scope", func(i *Instance, info *ip6.MessageInfo) { info.PeerAddr = i.GetLinkLocalAddress() }, goterrors.ErrNoRoute},
		{"unspecified-source", func(_ *Instance, info *ip6.MessageInfo) { info.SockAddr = ip6.Address{} }, goterrors.ErrInvalidArgs},
		{"unassigned-source", func(_ *Instance, info *ip6.MessageInfo) { info.SockAddr[15]++ }, goterrors.ErrInvalidSourceAddress},
		{"loopback-source", func(_ *Instance, info *ip6.MessageInfo) { info.SockAddr = ip6.Address{15: 1} }, goterrors.ErrInvalidArgs},
		{"multicast-source", func(_ *Instance, info *ip6.MessageInfo) { info.SockAddr = ip6.Address{0xff, 2, 15: 1} }, goterrors.ErrInvalidArgs},
		{"mapped-source", func(_ *Instance, info *ip6.MessageInfo) {
			info.SockAddr = ip6.Address{10: 0xff, 11: 0xff, 12: 127, 15: 1}
		}, goterrors.ErrInvalidSourceAddress},
		{"source-port-zero", func(_ *Instance, info *ip6.MessageInfo) { info.SockPort = 0 }, goterrors.ErrInvalidArgs},
		{"peer-port-zero", func(_ *Instance, info *ip6.MessageInfo) { info.PeerPort = 0 }, goterrors.ErrInvalidArgs},
		{"ecn", func(_ *Instance, info *ip6.MessageInfo) { info.Ecn = ip6.EcnMarked }, goterrors.ErrNotCapable},
		{"host-interface", func(_ *Instance, info *ip6.MessageInfo) { info.IsHostInterface = true }, goterrors.ErrNotCapable},
		{"multicast-loop", func(_ *Instance, info *ip6.MessageInfo) { info.MulticastLoop = true }, goterrors.ErrNotCapable},
		{"literal-hop-zero", func(_ *Instance, info *ip6.MessageInfo) { info.AllowZeroHopLimit = true }, goterrors.ErrNotCapable},
		{"rx-link-info", func(_ *Instance, info *ip6.MessageInfo) { info.LinkInfo = &ip6.LinkInfo{} }, goterrors.ErrNotCapable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			node, info := newMTDHandoffEndpoint(t, true)
			if err := node.inst.Do(context.Background(), func() error {
				test.change(node.inst, &info)
				before := node.inst.forwarder.GetBufferUsage()
				counter := node.inst.keyManager.GetMacFrameCounter()
				if got := node.inst.SendUDP(nil, info); got != test.want {
					t.Errorf("refusal=%v, want identical %v", got, test.want)
				}
				if node.inst.forwarder.GetBufferUsage() != before || node.inst.keyManager.GetMacFrameCounter() != counter {
					t.Error("refused route mutated owned resources or security counter")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-node.driver.captures:
				t.Fatal("refused MTD handoff reached Radio.Transmit")
			default:
			}
		})
	}
}

func TestMTDParentHandoffSourceQualification(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Instance, *ip6.MessageInfo)
	}{
		{"mesh-local-source-offmesh", func(i *Instance, info *ip6.MessageInfo) { info.SockAddr = i.GetMeshLocalAddress() }},
		{"assigned-mesh-prefix-source", func(i *Instance, info *ip6.MessageInfo) {
			source := i.GetMeshLocalAddress()
			source[8], source[15] = 0x12, 0x34
			i.netif.AddUnicastAddress(&ip6.UnicastAddress{Address: source, Valid: true, PrefixLength: 64})
			info.SockAddr = source
		}},
		{"invalid-assigned-source", func(i *Instance, _ *ip6.MessageInfo) { i.netif.GetUnicastAddresses()[0].Valid = false }},
		{"no-prefix-metadata", func(i *Instance, _ *ip6.MessageInfo) { i.netif.GetUnicastAddresses()[0].PrefixLength = 0 }},
		{"invalid-prefix-metadata", func(i *Instance, _ *ip6.MessageInfo) { i.netif.GetUnicastAddresses()[0].PrefixLength = 129 }},
		{"marked-mesh-local", func(i *Instance, _ *ip6.MessageInfo) { i.netif.GetUnicastAddresses()[0].MeshLocal = true }},
		{"marked-rloc", func(i *Instance, _ *ip6.MessageInfo) { i.netif.GetUnicastAddresses()[0].RLOC = true }},
		{"realm-local-scope", func(i *Instance, _ *ip6.MessageInfo) {
			local := i.netif.GetUnicastAddresses()
			local[0].ScopeOverrideValid, local[0].ScopeOverride = true, ip6.ScopeRealmLocal
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			node, info := newMTDHandoffEndpoint(t, true)
			if err := node.inst.Do(context.Background(), func() error {
				test.change(node.inst, &info)
				if got := node.inst.SendUDP(nil, info); got != goterrors.ErrInvalidSourceAddress {
					t.Errorf("offmesh source refusal=%v, want ErrInvalidSourceAddress", got)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMTDParentGatePreservesExistingDirectDelivery(t *testing.T) {
	for _, role := range []string{"ftd-child", "sleepy-child", "router", "leader"} {
		for _, linkLocal := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/link-local=%v", role, linkLocal), func(t *testing.T) {
				node, info := newMTDHandoffEndpoint(t, false)
				if err := node.inst.Do(context.Background(), func() error {
					m := node.inst.mleService.Mle()
					switch role {
					case "ftd-child":
						m.SetDeviceMode(mle.NewDeviceMode(0x0f))
					case "sleepy-child":
						m.SetDeviceMode(mle.NewDeviceMode(0))
					case "router":
						_ = m.SetStateRouter(0x0400)
						node.inst.SetRLOC16(0x0400)
						node.inst.mac.SetShortAddress(0x0400)
					case "leader":
						_ = m.SetStateLeader(0x0400)
						node.inst.SetRLOC16(0x0400)
						node.inst.mac.SetShortAddress(0x0400)
					}
					if linkLocal {
						info.SockAddr = node.inst.GetLinkLocalAddress()
						info.PeerAddr = linkLocalAddress(udpPeerExt)
					} else {
						info.PeerAddr = node.inst.GetMeshLocalAddress()
						info.PeerAddr[14], info.PeerAddr[15] = 8, 0
					}
					return node.inst.SendUDP([]byte{7}, info)
				}); err != nil {
					t.Fatal(err)
				}
				captureParentHandoff(t, node, info, []byte{7})
			})
		}
	}
}

func TestMTDParentHandoffSharedQueueAndMTUBounds(t *testing.T) {
	node, info := newMTDHandoffEndpoint(t, true)
	if err := node.inst.Do(context.Background(), func() error {
		if got := node.inst.SendUDP(make([]byte, 1233), info); got != goterrors.ErrNoBufs {
			t.Errorf("1233-byte payload refusal=%v", got)
		}
		for range 4 {
			if err := node.inst.SendUDP(make([]byte, 1232), info); err != nil {
				return err
			}
		}
		before := node.inst.forwarder.GetBufferUsage()
		if before.TxBytes != mesh.MaxPendingDatagramBytes || before.TxDatagrams != 4 {
			t.Errorf("handoff resource use=%+v", before)
		}
		counter := node.inst.keyManager.GetMacFrameCounter()
		if got := node.inst.SendUDP(nil, info); got != mesh.ErrQueueFull {
			t.Errorf("shared byte budget refusal=%v", got)
		}
		if node.inst.forwarder.GetBufferUsage() != before || node.inst.keyManager.GetMacFrameCounter() != counter {
			t.Error("queue refusal changed bytes or security counter")
		}
		return node.inst.ThreadStop()
	}); err != nil {
		t.Fatal(err)
	}
}
