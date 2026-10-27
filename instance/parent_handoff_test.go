// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/lowpan"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
)

func newMTDHandoffEndpoint(t *testing.T, offMesh bool) (*fragmentEndpoint, ip6.MessageInfo) {
	return newMTDHandoffEndpointSettings(t, offMesh, simulation.NewSimSettings())
}

func newMTDHandoffEndpointSettings(t *testing.T, offMesh bool, settings platform.Settings) (*fragmentEndpoint, ip6.MessageInfo) {
	return newMTDHandoffEndpointCaps(t, offMesh, settings, radio.CapCsmaBackoff|radio.CapTransmitRetries|radio.CapAckTimeout)
}

func newMTDHandoffEndpointCaps(t *testing.T, offMesh bool, settings platform.Settings, caps radio.Caps) (*fragmentEndpoint, ip6.MessageInfo) {
	t.Helper()
	node := newFragmentEndpointCaps(t, fragmentSource, udpPeerExt, 0x0400, 0x0800, settings, caps)
	info := ip6.MessageInfo{SockPort: 5540, PeerPort: 61616, HopLimit: 42}
	if err := node.inst.Do(context.Background(), func() error {
		m := node.inst.mleService.Mle()
		m.SetDeviceMode(mle.NewDeviceMode(mle.ModeRxOnWhenIdle))
		parent := m.GetParent()
		parent.MacAddr, parent.RLOC16, parent.State = udpPeerExt, 0x0800, mle.StateValid
		parent.Mode.Set(mle.ModeRxOnWhenIdle | mle.ModeFullThreadDevice)
		if err := m.SetStateChild(0x0801); err != nil {
			return err
		}
		node.inst.SetRLOC16(0x0801)
		node.inst.mac.SetShortAddress(0x0801)
		node.inst.mac.SetRxOnWhenIdle(true)
		info.SockAddr = ip6.Address{0xfd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 8: 0x12, 15: 0x34}
		info.PeerAddr = info.SockAddr
		info.PeerAddr[8], info.PeerAddr[15] = 0x56, 0x78 // A final EID, not the parent.
		if offMesh {
			info.SockAddr = ip6.Address{0x20, 1, 0x0d, 0xb8, 0, 1, 8: 0x12, 15: 0x34}
			info.PeerAddr = ip6.Address{0x20, 1, 0x0d, 0xb8, 0, 2, 8: 0x56, 15: 0x78}
		}
		node.inst.netif.AddUnicastAddress(&ip6.UnicastAddress{
			Address: info.SockAddr, PrefixLength: 64, Valid: true, Preferred: true, Origin: ip6.OriginManual,
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return node, info
}

func captureParentHandoff(t *testing.T, node *fragmentEndpoint, info ip6.MessageInfo, payload []byte) []byte {
	t.Helper()
	var packet []byte
	size, covered, frames := 0, 0, 0
	var lastCounter uint32
	ids := make(map[uint64]bool)
	for {
		capture := captureUDP(t, node.driver.boundedUDPRadio)
		ctx, wire := nativeAdaptation(t, capture, node.macKey)
		if ctx.SrcExtAddr != fragmentSource || ctx.DstExtAddr != udpPeerExt || ctx.PanId != 0xface {
			t.Fatalf("parent next hop changed: %+v", ctx)
		}
		if frames != 0 && ctx.Security.FrameCounter != lastCounter+1 {
			t.Fatalf("handoff fragment counter %d -> %d", lastCounter, ctx.Security.FrameCounter)
		}
		lastCounter = ctx.Security.FrameCounter
		if capture.frame.TxInfo == nil || capture.frame.TxInfo.SubmissionID == 0 || ids[capture.frame.TxInfo.SubmissionID] {
			t.Fatal("handoff radio submission origin missing/reused")
		}
		ids[capture.frame.TxInfo.SubmissionID] = true
		switch wire[0] & 0xf8 {
		case 0xc0:
			if frames != 0 || len(wire) < 4 {
				t.Fatal("misordered/truncated FRAG1")
			}
			size = int(wire[0]&7)<<8 | int(wire[1])
			if size != 40+8+len(payload) {
				t.Fatalf("original IPv6 datagram_size=%d", size)
			}
			packet = make([]byte, size)
			first, err := lowpan.DecompressDatagram(wire[4:], lowpan.AddressContext{
				SrcExtAddr: fragmentSource, DstExtAddr: udpPeerExt,
			}, uint16(size))
			if err != nil {
				t.Fatal(err)
			}
			covered = copy(packet, first)
		case 0xe0:
			if len(wire) < 5 || packet == nil {
				t.Fatal("FRAGN preceded first transmit")
			}
			if int(wire[0]&7)<<8|int(wire[1]) != size || int(wire[4])*8 != covered {
				t.Fatalf("FRAGN original coordinate=%d, want=%d", int(wire[4])*8, covered)
			}
			covered += copy(packet[covered:], wire[5:])
		default:
			if frames != 0 {
				t.Fatal("unfragmented data in a fragment sequence")
			}
			var err error
			packet, err = lowpan.DecompressDatagram(wire, lowpan.AddressContext{
				SrcExtAddr: fragmentSource, DstExtAddr: udpPeerExt,
			}, 0)
			if err != nil {
				t.Fatal(err)
			}
			size, covered = len(packet), len(packet)
		}
		if covered < size && covered%8 != 0 {
			t.Fatal("handoff fragment endpoint not aligned in original byte space")
		}
		completeNativeFrame(t, node, capture, nil)
		frames++
		var usage mesh.BufferUsage
		if err := node.inst.Do(context.Background(), func() error { usage = node.inst.forwarder.GetBufferUsage(); return nil }); err != nil {
			t.Fatal(err)
		}
		if usage.TxDatagrams == 0 {
			break
		}
		if frames >= 20 {
			t.Fatal("handoff did not retire bounded fragment plan")
		}
	}
	if covered != size {
		t.Fatalf("partial local handoff covered=%d of %d", covered, size)
	}
	if len(payload) == 1232 && frames != 15 {
		t.Fatalf("maximum handoff used %d frames, want 15", frames)
	}
	verifyParentIPv6UDP(t, packet, info, payload)
	if err := node.inst.Do(context.Background(), func() error {
		if node.callbacks != 0 || node.inst.forwarder.GetBufferUsage().TxBytes != 0 {
			t.Error("handoff reinjected local UDP or retained owned bytes")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return packet
}

func verifyParentIPv6UDP(t *testing.T, packet []byte, info ip6.MessageInfo, payload []byte) {
	t.Helper()
	hop := info.HopLimit
	if hop == 0 {
		hop = 64
	}
	if len(packet) != 48+len(payload) || packet[0]>>4 != 6 || packet[6] != 17 || packet[7] != hop ||
		!bytes.Equal(packet[8:24], info.SockAddr[:]) || !bytes.Equal(packet[24:40], info.PeerAddr[:]) ||
		binary.BigEndian.Uint16(packet[40:42]) != info.SockPort || binary.BigEndian.Uint16(packet[42:44]) != info.PeerPort ||
		int(binary.BigEndian.Uint16(packet[4:6])) != 8+len(payload) || int(binary.BigEndian.Uint16(packet[44:46])) != 8+len(payload) ||
		!bytes.Equal(packet[48:], payload) {
		t.Fatalf("logical source/final peer/UDP tuple changed by parent handoff: header=%x payload=%d", packet[:48], len(packet)-48)
	}
	// Independent original-tuple pseudo-header checksum, not a local parent
	// receive/forward fixture or the library's checksum calculation.
	pseudo := append([]byte(nil), packet[8:40]...)
	pseudo = append(pseudo, 0, 0, packet[4], packet[5], 0, 0, 0, 17)
	pseudo = append(pseudo, packet[40:]...)
	if len(pseudo)%2 != 0 {
		pseudo = append(pseudo, 0)
	}
	var sum uint32
	for i := 0; i < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	if sum != 0xffff || binary.BigEndian.Uint16(packet[46:48]) == 0 {
		t.Fatalf("handoff original-tuple UDP checksum invalid: %x", sum)
	}
}

func TestMTDParentHandoffPreservesFinalTuple(t *testing.T) {
	for _, offMesh := range []bool{false, true} {
		t.Run(fmt.Sprint(offMesh), func(t *testing.T) {
			node, info := newMTDHandoffEndpoint(t, offMesh)
			payload := make([]byte, 1232)
			for i := range payload {
				payload[i] = byte(i*13 + 3)
			}
			want := append([]byte(nil), payload...)
			if err := node.inst.Do(context.Background(), func() error {
				if err := node.inst.SendUDP(payload, info); err != nil {
					return err
				}
				clear(payload)
				return nil
			}); err != nil {
				t.Fatalf("eligible always-on MTD parent admission: %v", err)
			}
			captureParentHandoff(t, node, info, want)
		})
	}
}
