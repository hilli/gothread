// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import (
	"bytes"
	"encoding/binary"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
)

func fragmentTxMessage(payload int, rloc bool) *TxMessage {
	src := [16]byte{0xfe, 0x80, 8: 0xa6, 9: 0x17, 10: 0x2b, 11: 0xc3, 12: 0x5d, 13: 0xe6, 14: 0x79, 15: 0x80}
	dst := [16]byte{0xfe, 0x80, 8: 0x1a, 9: 0x23, 10: 0x45, 11: 0x67, 12: 0x89, 13: 0xab, 14: 0xcd, 15: 0xef}
	if rloc {
		src = [16]byte{0xfd, 1, 11: 0xff, 12: 0xfe, 14: 4}
		dst = [16]byte{0xfd, 1, 11: 0xff, 12: 0xfe, 14: 8}
	}
	meta := BuildUDPMetadata(src, dst, 5540, 5540, 64)
	meta.SrcExtAddr = [8]byte{0xa4, 0x17, 0x2b, 0xc3, 0x5d, 0xe6, 0x79, 0x80}
	meta.DstExtAddr = [8]byte{0x18, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	meta.SecurityEnabled = true
	meta.Security = SecurityMaterial{Key: [16]byte{1, 2, 3}, KeyIdMode: 1}
	data := make([]byte, payload)
	for i := range data {
		data[i] = byte(i)
	}
	return NewTxMessageWithMetadata(data, 0x0800, 0x0400, meta)
}

func TestFragmentTXOriginalOffsetsAndAtomicOwnership(t *testing.T) {
	f := NewForwarder()
	f.SetEnabled(true)
	msg := fragmentTxMessage(1232, false)
	borrowed := msg.Data
	if err := f.SendMessage(msg); err != nil {
		t.Fatal(err)
	}
	clear(borrowed)
	before := f.GetBufferUsage()
	if before.TxBytes != IPv6MTU || before.TxDatagrams != 1 || before.TxFragments != 15 {
		t.Fatalf("whole-datagram admission=%+v", before)
	}
	offset, frames := 0, 0
	for f.HasPendingDirect() {
		current := f.HandleFrameRequest()
		if current != msg {
			t.Fatal("datagram ownership changed between fragments")
		}
		current.Metadata.Security.FrameCounter = uint32(frames)
		frame, err := BuildTxFrame(current, uint8(frames))
		if err != nil {
			t.Fatal(err)
		}
		ctx, start, err := NewFramer().ParseFrameHeader(frame)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := DecryptFramePayload(frame, start, ctx, [16]byte{1, 2, 3}, ctx.SrcExtAddr)
		if err != nil {
			t.Fatal(err)
		}
		if len(frame) > MaxPsduSize-FCSSize || wire[0]&7 != 5 || wire[1] != 0 {
			t.Fatalf("invalid MTU fragment frame=%d adaptation=%x", len(frame), wire[:4])
		}
		if frames == 0 {
			if wire[0] != 0xc5 || len(wire) != 93 || !bytes.Equal(wire[4:11], []byte{0x7e, 0x33, 0xf0, 0x15, 0xa4, 0x15, 0xa4}) {
				t.Fatalf("FRAG1 shape=%x, length=%d", wire[:13], len(wire))
			}
			// Compressed headers are nine bytes; ORIGINAL headers are 48.
			offset = 48 + len(wire) - 4 - 9
		} else {
			if wire[0] != 0xe5 || int(wire[4])*8 != offset {
				t.Fatalf("FRAGN offset=%d, original expectation=%d", int(wire[4])*8, offset)
			}
			offset += len(wire) - 5
		}
		if offset < IPv6MTU && offset%8 != 0 {
			t.Fatal("nonfinal original endpoint is not eight-byte aligned")
		}
		f.FramePrepared(current)
		f.HandleSentFrame(current, true)
		frames++
	}
	if offset != IPv6MTU || frames != 15 {
		t.Fatalf("fragment coverage offset=%d frames=%d", offset, frames)
	}
	if usage := f.GetBufferUsage(); usage.TxBytes != 0 || usage.TxFragments != 0 || usage.TxDatagrams != 0 {
		t.Fatalf("completed TX retained owned resources: %+v", usage)
	}
	if counters := f.GetCounters(); counters.TxFragment != 15 || counters.TxDirect != 1 {
		t.Fatalf("datagram/fragment counters=%+v", counters)
	}
}

func TestFragmentTXByteCountAndFragmentBudgets(t *testing.T) {
	t.Run("bytes", func(t *testing.T) {
		f := NewForwarder()
		f.SetEnabled(true)
		for i := 0; i < MaxPendingDatagramBytes/IPv6MTU; i++ {
			if err := f.SendMessage(fragmentTxMessage(1232, false)); err != nil {
				t.Fatal(err)
			}
		}
		before, tag := f.GetBufferUsage(), f.nextFragTag
		rejected := fragmentTxMessage(1232, false)
		input := rejected.Data
		if err := f.SendMessage(rejected); err != ErrQueueFull {
			t.Fatalf("TX byte budget failure=%v", err)
		}
		if f.GetBufferUsage() != before || f.nextFragTag != tag || &rejected.Data[0] != &input[0] {
			t.Fatal("failed admission changed ownership, tag, or resource state")
		}
		rejected = fragmentTxMessage(1233, false)
		if err := f.SendMessage(rejected); err != goterrors.ErrNoBufs {
			t.Fatalf("oversize IPv6 MTU admission=%v", err)
		}
		if f.GetBufferUsage() != before || f.nextFragTag != tag {
			t.Fatal("MTU refusal mutated owned resources")
		}
	})
	t.Run("fragments-before-bytes-or-count", func(t *testing.T) {
		f := NewForwarder()
		f.SetEnabled(true)
		for range 10 {
			if err := f.SendMessage(fragmentTxMessage(54, true)); err != nil { // 102 bytes, two fragments.
				t.Fatal(err)
			}
		}
		for range 80 {
			if err := f.SendMessage(fragmentTxMessage(0, true)); err != nil {
				t.Fatal(err)
			}
		}
		before := f.GetBufferUsage()
		if before.TxFragments != 100 || before.TxBytes >= MaxPendingDatagramBytes || before.TxDatagrams >= MaxFramesInDirectTxQueue {
			t.Fatalf("fragment-pressure fixture=%+v", before)
		}
		if err := f.SendMessage(fragmentTxMessage(0, true)); err != ErrQueueFull || f.GetBufferUsage() != before {
			t.Fatalf("logical pending fragment bound not enforced: %v", err)
		}
	})
	t.Run("shared-indirect-count", func(t *testing.T) {
		f := NewForwarder()
		f.SetEnabled(true)
		for i := 0; i < MaxFramesInDirectTxQueue; i++ {
			msg := NewTxMessage([]byte{1}, 0x0800, 0x0400)
			msg.Direct = i%2 == 0
			if err := f.SendMessage(msg); err != nil {
				t.Fatal(err)
			}
		}
		extra := NewTxMessage([]byte{2}, 0x0800, 0x0400)
		extra.Direct = false
		if err := f.SendMessage(extra); err != ErrQueueFull {
			t.Fatalf("indirect queue bypassed shared count: %v", err)
		}
	})
}

func TestFragmentTXPartialFailureAndTeardownRelease(t *testing.T) {
	f := NewForwarder()
	f.SetEnabled(true)
	first, next := fragmentTxMessage(1232, false), fragmentTxMessage(1232, false)
	for _, msg := range []*TxMessage{first, next} {
		if err := f.SendMessage(msg); err != nil {
			t.Fatal(err)
		}
	}
	for _, success := range []bool{true, false} {
		msg := f.HandleFrameRequest()
		if msg != first {
			t.Fatal("fragmented datagram did not remain current")
		}
		if _, err := BuildTxFrame(msg, 0); err != nil {
			t.Fatal(err)
		}
		f.HandleSentFrame(msg, success)
	}
	if usage := f.GetBufferUsage(); usage.TxBytes != IPv6MTU || usage.TxDatagrams != 1 || usage.TxFragments != 15 {
		t.Fatalf("partial failure retained bytes/fragments: %+v", usage)
	}
	small := fragmentTxMessage(0, false)
	if err := f.SendMessage(small); err != nil {
		t.Fatal(err)
	}
	f.AbortFragments()
	if usage := f.GetBufferUsage(); usage.TxBytes != 48 || usage.TxDatagrams != 1 || usage.TxFragments != 1 {
		t.Fatalf("teardown did not discard only fragmented datagrams: %+v", usage)
	}
	f.HandleSentFrame(next, true) // Stale completion cannot revive an aborted datagram.
	if f.GetCounters().TxDirect != 0 {
		t.Fatal("stale completion reported an aborted datagram as delivered")
	}
	if f.HandleFrameRequest() != small {
		t.Fatal("teardown changed pre-existing unfragmented lifecycle behavior")
	}
	f.SetEnabled(false)
	if usage := f.GetBufferUsage(); usage != (BufferUsage{}) {
		t.Fatalf("interface disable retained resources: %+v", usage)
	}
}

func TestFragmentUtilityUsesOriginalIPv6Size(t *testing.T) {
	f := NewForwarder()
	msg := fragmentTxMessage(86, false)
	state, err := prepareTransmit(msg)
	if err != nil {
		t.Fatal(err)
	}
	parts, _, err := f.FragmentMessage(state.packet, 80)
	if err != nil {
		t.Fatal(err)
	}
	if int(binary.BigEndian.Uint16(parts[0][:2])&0x7ff) != len(state.packet) || parts[0][4] != 0x41 {
		t.Fatalf("standalone utility did not encode original IPv6 bytes: %x", parts[0][:5])
	}
}
