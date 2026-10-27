// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"testing"

	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/mesh"
)

func TestStandardFragmentedShortMACSourceZeroIdentity(t *testing.T) {
	dst := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0000, simulation.NewSimSettings())
	first := []byte{0xc0, 0x86, 0x12, 0x34, 0x7e, 0x33, 0xf0, 0x15, 0xa4, 0x15, 0xa4, 0x61, 0x41}
	for i := byte(0); i < 80; i++ {
		first = append(first, i)
	}
	last := []byte{0xe0, 0x86, 0x12, 0x34, 0x10, 80, 81, 82, 83, 84, 85}
	for i, data := range [][]byte{last, first} {
		ctx := &mesh.FrameContext{
			SrcShortAddr: 0, DstShortAddr: 0x0800,
			SrcExtAddr: fragmentSource, DstExtAddr: udpPeerExt,
			UseSrcShort: true, UseDstShort: true, PanId: 0xface, SecurityEnabled: true,
			Security: mesh.SecurityMaterial{Key: dst.macKey, KeyIdMode: 1, FrameCounter: uint32(80 + i)},
		}
		psdu, err := mesh.NewFramer().BuildDataFrame(ctx, data)
		if err != nil {
			t.Fatal(err)
		}
		deliverNativeFrame(t, dst, udpRadioCapture{frame: radio.Frame{PSDU: psdu, Channel: 20}})
	}
	select {
	case packet := <-dst.incoming:
		if len(packet.payload) != 86 || packet.info.LinkInfo == nil || packet.info.LinkInfo.SrcExtAddr != fragmentSource {
			t.Fatal("short MAC source zero was not resolved to complete peer identity")
		}
	default:
		t.Fatal("valid zero short address prevented standard reassembly")
	}
}
