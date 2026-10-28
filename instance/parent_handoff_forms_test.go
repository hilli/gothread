// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"context"
	"fmt"
	"testing"

	"github.com/hilli/gothread/net/ip6"
)

func TestMTDParentHandoffExplicitULASourceAndHopForms(t *testing.T) {
	for _, hop := range []uint8{0, 1, 64, 255} {
		t.Run(fmt.Sprint(hop), func(t *testing.T) {
			node, info := newMTDHandoffEndpoint(t, true)
			info.HopLimit = hop
			if err := node.inst.Do(context.Background(), func() error {
				old := node.inst.netif.GetUnicastAddresses()[0]
				node.inst.netif.RemoveUnicastAddress(&old)
				info.SockAddr = ip6.Address{0xfd, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 8: 0x12, 15: 0x34}
				node.inst.netif.AddUnicastAddress(&ip6.UnicastAddress{
					Address: info.SockAddr, Valid: true, PrefixLength: 64, Origin: ip6.OriginManual,
				})
				// Explicit assignment is sufficient for LOCAL handoff, not proof
				// of a border-router advertisement or global ULA reachability.
				return node.inst.SendUDP(nil, info)
			}); err != nil {
				t.Fatal(err)
			}
			captureParentHandoff(t, node, info, nil)
		})
	}
}

func TestMTDParentHandoffCanonicalRouterRLOCZero(t *testing.T) {
	node, info := newMTDHandoffEndpoint(t, false)
	if err := node.inst.Do(context.Background(), func() error {
		m := node.inst.mleService.Mle()
		if err := m.SetStateChild(1); err != nil {
			return err
		}
		node.inst.SetRLOC16(1)
		node.inst.mac.SetShortAddress(1)
		m.GetParent().RLOC16 = 0 // Valid router ID zero, not an absent-parent sentinel.
		return node.inst.SendUDP([]byte{1, 2, 3}, info)
	}); err != nil {
		t.Fatal(err)
	}
	captureParentHandoff(t, node, info, []byte{1, 2, 3})
}
