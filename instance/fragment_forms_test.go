// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"context"
	"fmt"
	"testing"

	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/udp"
	"github.com/hilli/gothread/platform/simulation"
)

func TestStandardFragmentedCompressedPortAndHopForms(t *testing.T) {
	for _, test := range []struct {
		rloc             bool
		hop              uint8
		srcPort, dstPort uint16
	}{
		{false, 42, 0xf0b1, 5540},
		{true, 1, 5540, 0xf012},
		{false, 255, 0xf0b1, 0xf0b2},
		{true, 255, 5540, 5540},
		{true, 42, 0xf0b1, 0xf0b2},
	} {
		t.Run(fmt.Sprintf("rloc=%v/hop=%d/ports=%d-%d", test.rloc, test.hop, test.srcPort, test.dstPort), func(t *testing.T) {
			src := newFragmentEndpoint(t, fragmentSource, udpPeerExt, 0x0400, 0x0800, simulation.NewSimSettings())
			dst := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
			info := fragmentInfo(fragmentSource, udpPeerExt, test.rloc)
			info.HopLimit, info.SockPort, info.PeerPort = test.hop, test.srcPort, test.dstPort
			if test.dstPort != 5540 {
				if err := dst.inst.Do(context.Background(), func() error {
					socket := &udp.Socket{}
					if err := dst.inst.udpManager.Open(socket, udp.NetifThreadInternal, func(payload []byte, metadata *ip6.MessageInfo) {
						dst.callbacks++
						copied := *metadata
						if metadata.LinkInfo != nil {
							link := *metadata.LinkInfo
							copied.LinkInfo = &link
						}
						select {
						case dst.incoming <- fragmentDelivery{payload: append([]byte(nil), payload...), info: copied}:
						default:
							t.Error("bounded alternate-port queue overflow")
						}
					}); err != nil {
						return err
					}
					return dst.inst.udpManager.Bind(socket, ip6.SockAddr{Port: test.dstPort})
				}); err != nil {
					t.Fatal(err)
				}
			}
			payload := make([]byte, 1232)
			for i := range payload {
				payload[i] = byte(i*13 + 1)
			}
			sendNativeDatagram(t, src, dst, payload, info, true)
			assertFragmentDelivery(t, src, dst, payload, info, 1)
		})
	}
}

func TestStandardFragmentedStatelessShortSourceIID(t *testing.T) {
	src := newFragmentEndpoint(t, fragmentSource, udpPeerExt, 0x0400, 0x0800, simulation.NewSimSettings())
	dst := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
	info := fragmentInfo(fragmentSource, udpPeerExt, false)
	info.SockAddr = ip6.Address{0xfe, 0x80, 11: 0xff, 12: 0xfe, 14: 0x12, 15: 0x34}
	if err := src.inst.Do(context.Background(), func() error {
		src.inst.netif.AddUnicastAddress(&ip6.UnicastAddress{Address: info.SockAddr, Valid: true})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 1232)
	for i := range payload {
		payload[i] = byte(i*7 + 1)
	}
	sendNativeDatagram(t, src, dst, payload, info, true)
	assertFragmentDelivery(t, src, dst, payload, info, 1)
}
