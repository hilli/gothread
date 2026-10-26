// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import (
	"testing"
	"time"
)

func TestBuildParseMeshHeader_ShortHops(t *testing.T) {
	// Hops <= 15: 5-byte header (no deep hops byte).
	for _, hops := range []uint8{0, 1, 7, 15} {
		source := uint16(0x0400)
		dest := uint16(0x0800)

		hdr := BuildMeshHeader(source, dest, hops)

		if len(hdr) != meshHeaderMinLen {
			t.Fatalf("hops=%d: header len=%d, want %d", hops, len(hdr), meshHeaderMinLen)
		}

		parsedSrc, parsedDst, parsedHops, headerLen, err := ParseMeshHeader(hdr)
		if err != nil {
			t.Fatalf("hops=%d: ParseMeshHeader error: %v", hops, err)
		}
		if headerLen != meshHeaderMinLen {
			t.Errorf("hops=%d: headerLen=%d, want %d", hops, headerLen, meshHeaderMinLen)
		}
		if parsedSrc != source {
			t.Errorf("hops=%d: source=0x%04X, want 0x%04X", hops, parsedSrc, source)
		}
		if parsedDst != dest {
			t.Errorf("hops=%d: dest=0x%04X, want 0x%04X", hops, parsedDst, dest)
		}
		if parsedHops != hops {
			t.Errorf("hops=%d: hopsLeft=%d, want %d", hops, parsedHops, hops)
		}
	}
}

func TestBuildParseMeshHeader_DeepHops(t *testing.T) {
	// Hops > 15: 6-byte header with deep hops byte.
	for _, hops := range []uint8{16, 17, 19, 20} {
		source := uint16(0x1234)
		dest := uint16(0x5678)

		hdr := BuildMeshHeader(source, dest, hops)

		if len(hdr) != meshHeaderDeepHopsLen {
			t.Fatalf("hops=%d: header len=%d, want %d", hops, len(hdr), meshHeaderDeepHopsLen)
		}

		parsedSrc, parsedDst, parsedHops, headerLen, err := ParseMeshHeader(hdr)
		if err != nil {
			t.Fatalf("hops=%d: ParseMeshHeader error: %v", hops, err)
		}
		if headerLen != meshHeaderDeepHopsLen {
			t.Errorf("hops=%d: headerLen=%d, want %d", hops, headerLen, meshHeaderDeepHopsLen)
		}
		if parsedSrc != source {
			t.Errorf("hops=%d: source=0x%04X, want 0x%04X", hops, parsedSrc, source)
		}
		if parsedDst != dest {
			t.Errorf("hops=%d: dest=0x%04X, want 0x%04X", hops, parsedDst, dest)
		}
		if parsedHops != hops {
			t.Errorf("hops=%d: hopsLeft=%d, want %d", hops, parsedHops, hops)
		}
	}
}

func TestBuildMeshHeader_ClampsMaxHops(t *testing.T) {
	// Hops above MaxHopsLeft should be clamped.
	hdr := BuildMeshHeader(0x0400, 0x0800, 255)
	_, _, hops, _, err := ParseMeshHeader(hdr)
	if err != nil {
		t.Fatalf("ParseMeshHeader error: %v", err)
	}
	if hops != MaxHopsLeft {
		t.Errorf("hopsLeft=%d, want %d (clamped)", hops, MaxHopsLeft)
	}
}

func TestParseMeshHeader_InvalidData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too_short", []byte{MeshDispatch | MeshSourceShortFlag | 5, 0x04}},
		{"wrong_dispatch", []byte{0x40, 0x04, 0x00, 0x08, 0x00}},
		{"deep_hops_too_short", []byte{MeshDispatch | MeshSourceShortFlag | MeshDeepHopsFlag | MeshHopsLeftMask, 16, 0x04, 0x00, 0x08}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, err := ParseMeshHeader(tt.data)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestFragmentMessage_AndReassemble(t *testing.T) {
	fwd := NewForwarder()
	fwd.SetEnabled(true)

	// Create a 200-byte payload.
	payload := make([]byte, 200)
	for i := range payload {
		payload[i] = byte(i)
	}

	fragments, tag, err := fwd.FragmentMessage(payload, 80)
	if err != nil {
		t.Fatalf("FragmentMessage error: %v", err)
	}
	if tag == 0 {
		t.Error("tag should be non-zero")
	}
	if len(fragments) < 2 {
		t.Fatalf("expected at least 2 fragments, got %d", len(fragments))
	}

	// Verify first fragment has FragFirstDispatch.
	if fragments[0][0]&FragDispatchMask != FragFirstDispatch {
		t.Errorf("first fragment dispatch=0x%02X, want 0x%02X", fragments[0][0]&FragDispatchMask, FragFirstDispatch)
	}

	// Verify subsequent fragments have FragSubsequentDispatch.
	for i := 1; i < len(fragments); i++ {
		if fragments[i][0]&FragDispatchMask != FragSubsequentDispatch {
			t.Errorf("fragment[%d] dispatch=0x%02X, want 0x%02X", i, fragments[i][0]&FragDispatchMask, FragSubsequentDispatch)
		}
	}

	// Verify counters.
	counters := fwd.GetCounters()
	if counters.TxFragment != uint32(len(fragments)) {
		t.Errorf("TxFragment=%d, want %d", counters.TxFragment, len(fragments))
	}
}

func TestReassembleFragments(t *testing.T) {
	fwd := NewForwarder()
	fwd.SetEnabled(true)

	// Create a test datagram.
	payload := make([]byte, 160)
	for i := range payload {
		payload[i] = byte(i)
	}

	srcAddr := [8]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
	tag := uint16(42)
	size := uint16(len(payload))

	// Send fragments with 80-byte chunks.
	frag1Data := payload[0:80]
	frag2Data := payload[80:160]

	result, err := fwd.HandleFragment(srcAddr, tag, size, 0, frag1Data)
	if err != nil {
		t.Fatalf("HandleFragment(frag1) error: %v", err)
	}
	if result != nil {
		t.Error("expected nil result after first fragment")
	}

	if fwd.GetReassemblyList() != 1 {
		t.Errorf("reassembly list len=%d, want 1", fwd.GetReassemblyList())
	}

	result, err = fwd.HandleFragment(srcAddr, tag, size, 80, frag2Data)
	if err != nil {
		t.Fatalf("HandleFragment(frag2) error: %v", err)
	}
	if result == nil {
		t.Fatal("expected complete datagram after second fragment")
	}

	if len(result) != len(payload) {
		t.Fatalf("reassembled len=%d, want %d", len(result), len(payload))
	}
	for i, b := range result {
		if b != payload[i] {
			t.Errorf("result[%d]=0x%02X, want 0x%02X", i, b, payload[i])
			break
		}
	}

	// After reassembly, the entry should be removed.
	if fwd.GetReassemblyList() != 0 {
		t.Errorf("reassembly list len=%d after completion, want 0", fwd.GetReassemblyList())
	}

	// Verify RxFragment counter.
	counters := fwd.GetCounters()
	if counters.RxFragment != 2 {
		t.Errorf("RxFragment=%d, want 2", counters.RxFragment)
	}
}

func TestReassemblyTimeoutCleanup(t *testing.T) {
	fwd := NewForwarder()
	fwd.SetEnabled(true)

	srcAddr := [8]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}

	// Add a fragment that won't complete.
	_, err := fwd.HandleFragment(srcAddr, 100, 200, 0, make([]byte, 80))
	if err != nil {
		t.Fatalf("HandleFragment error: %v", err)
	}

	if fwd.GetReassemblyList() != 1 {
		t.Fatalf("reassembly list len=%d, want 1", fwd.GetReassemblyList())
	}

	// Manually expire the entry by backdating its timer.
	fwd.mu.Lock()
	for _, info := range fwd.reassemblyMap {
		info.Timer = time.Now().Add(-(FragReassemblyTimeoutSec + 1) * time.Second)
	}
	fwd.mu.Unlock()

	removed := fwd.CleanupExpiredReassemblies()
	if removed != 1 {
		t.Errorf("CleanupExpiredReassemblies removed=%d, want 1", removed)
	}

	if fwd.GetReassemblyList() != 0 {
		t.Errorf("reassembly list len=%d after cleanup, want 0", fwd.GetReassemblyList())
	}

	counters := fwd.GetCounters()
	if counters.ReassemblyTimeout != 1 {
		t.Errorf("ReassemblyTimeout=%d, want 1", counters.ReassemblyTimeout)
	}
}

func TestQueueManagement(t *testing.T) {
	fwd := NewForwarder()
	fwd.SetEnabled(true)

	// Enqueue messages with different priorities.
	for i := 0; i < 5; i++ {
		msg := NewTxMessage([]byte{byte(i)}, 0x0800, 0x0400)
		msg.Priority = uint8(i % 4) // cycle through priorities 0-3
		err := fwd.SendMessage(msg)
		if err != nil {
			t.Fatalf("SendMessage(%d) error: %v", i, err)
		}
	}

	direct, indirect := fwd.GetQueueLength()
	if direct != 5 {
		t.Errorf("direct queue len=%d, want 5", direct)
	}
	if indirect != 0 {
		t.Errorf("indirect queue len=%d, want 0", indirect)
	}

	// Dequeue one message.
	msg := fwd.HandleFrameRequest()
	if msg == nil {
		t.Fatal("HandleFrameRequest returned nil")
	}
	if msg.Data[0] != 0 {
		t.Errorf("dequeued msg data=%d, want 0 (FIFO order)", msg.Data[0])
	}

	direct, _ = fwd.GetQueueLength()
	if direct != 4 {
		t.Errorf("direct queue len=%d after dequeue, want 4", direct)
	}

	// Evict the lowest priority message (priority < PriorityNet=3).
	evicted := fwd.EvictMessage(uint8(PriorityNet))
	if !evicted {
		t.Error("EvictMessage should have evicted a message")
	}

	direct, _ = fwd.GetQueueLength()
	if direct != 3 {
		t.Errorf("direct queue len=%d after eviction, want 3", direct)
	}
}

func TestQueueFull(t *testing.T) {
	fwd := NewForwarder()
	fwd.SetEnabled(true)

	// Fill the queue to capacity.
	for i := 0; i < MaxFramesInDirectTxQueue; i++ {
		msg := NewTxMessage([]byte{byte(i)}, 0x0800, 0x0400)
		err := fwd.SendMessage(msg)
		if err != nil {
			t.Fatalf("SendMessage(%d) error: %v", i, err)
		}
	}

	// Next message should fail.
	msg := NewTxMessage([]byte{0xFF}, 0x0800, 0x0400)
	err := fwd.SendMessage(msg)
	if err != ErrQueueFull {
		t.Errorf("expected ErrQueueFull, got %v", err)
	}

	counters := fwd.GetCounters()
	if counters.TxDropped != 1 {
		t.Errorf("TxDropped=%d, want 1", counters.TxDropped)
	}
}

func TestPrepareDirectFrame(t *testing.T) {
	fwd := NewForwarder()

	msg := NewTxMessage([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 0x0800, 0x0400)
	frame, meta := fwd.PrepareDirectFrame(msg)

	if len(frame) != 4 {
		t.Fatalf("frame len=%d, want 4", len(frame))
	}
	if frame[0] != 0xDE || frame[3] != 0xEF {
		t.Errorf("frame data mismatch: %v", frame)
	}
	if meta.DstAddr != 0x0800 {
		t.Errorf("meta.DstAddr=0x%04X, want 0x0800", meta.DstAddr)
	}
	if meta.SrcAddr != 0x0400 {
		t.Errorf("meta.SrcAddr=0x%04X, want 0x0400", meta.SrcAddr)
	}
	if !meta.AckRequest {
		t.Error("meta.AckRequest should be true")
	}

	// Verify original data is not aliased.
	frame[0] = 0xFF
	if msg.Data[0] == 0xFF {
		t.Error("PrepareDirectFrame should copy data, not alias it")
	}
}

func TestPrepareMeshFrame(t *testing.T) {
	fwd := NewForwarder()

	msg := NewTxMessage([]byte{0x01, 0x02, 0x03}, 0x0800, 0x0400)
	msg.MaxHops = 10

	frame, meta, err := fwd.PrepareMeshFrame(msg)
	if err != nil {
		t.Fatalf("PrepareMeshFrame error: %v", err)
	}

	// Mesh header for hops=10 is 5 bytes, plus 3 bytes payload = 8 bytes.
	if len(frame) != meshHeaderMinLen+3 {
		t.Fatalf("frame len=%d, want %d", len(frame), meshHeaderMinLen+3)
	}

	// Parse the mesh header from the frame.
	src, dst, hops, hdrLen, err := ParseMeshHeader(frame)
	if err != nil {
		t.Fatalf("ParseMeshHeader error: %v", err)
	}
	if src != 0x0400 {
		t.Errorf("source=0x%04X, want 0x0400", src)
	}
	if dst != 0x0800 {
		t.Errorf("dest=0x%04X, want 0x0800", dst)
	}
	if hops != 10 {
		t.Errorf("hopsLeft=%d, want 10", hops)
	}

	// Verify payload follows the header.
	payload := frame[hdrLen:]
	if len(payload) != 3 || payload[0] != 0x01 || payload[2] != 0x03 {
		t.Errorf("payload mismatch: %v", payload)
	}

	if meta.DstAddr != 0x0800 {
		t.Errorf("meta.DstAddr=0x%04X, want 0x0800", meta.DstAddr)
	}

	counters := fwd.GetCounters()
	if counters.TxMesh != 1 {
		t.Errorf("TxMesh=%d, want 1", counters.TxMesh)
	}
}

func TestHandleReceivedFrame_Dispatching(t *testing.T) {
	fwd := NewForwarder()
	fwd.SetEnabled(true)

	info := &ReceivedFrameInfo{Rssi: -50, Lqi: 200, Channel: 11}

	t.Run("mesh_frame", func(t *testing.T) {
		// Build a mesh-header frame.
		hdr := BuildMeshHeader(0x0400, 0x0800, 5)
		payload := []byte{0xAA, 0xBB}
		frame := append(append([]byte(nil), hdr...), payload...)

		result, isMesh, err := fwd.HandleReceivedFrame(frame, info)
		if err != nil {
			t.Fatalf("HandleReceivedFrame error: %v", err)
		}
		if !isMesh {
			t.Error("expected isMesh=true for mesh frame")
		}
		if len(result) != len(payload) {
			t.Errorf("result len=%d, want %d", len(result), len(payload))
		}
	})

	t.Run("direct_frame", func(t *testing.T) {
		// Non-mesh frame (dispatch does not match 0b10xxxxxx).
		frame := []byte{0x41, 0x88, 0x01, 0x02, 0x03}

		result, isMesh, err := fwd.HandleReceivedFrame(frame, info)
		if err != nil {
			t.Fatalf("HandleReceivedFrame error: %v", err)
		}
		if isMesh {
			t.Error("expected isMesh=false for direct frame")
		}
		if len(result) != len(frame) {
			t.Errorf("result len=%d, want %d", len(result), len(frame))
		}
	})

	t.Run("empty_frame", func(t *testing.T) {
		_, _, err := fwd.HandleReceivedFrame([]byte{}, info)
		if err == nil {
			t.Error("expected error for empty frame")
		}
	})

	t.Run("disabled", func(t *testing.T) {
		fwd2 := NewForwarder() // not enabled
		_, _, err := fwd2.HandleReceivedFrame([]byte{0x41}, info)
		if err != ErrForwarderDisabled {
			t.Errorf("expected ErrForwarderDisabled, got %v", err)
		}
	})
}

func TestForwarderCounters(t *testing.T) {
	fwd := NewForwarder()
	fwd.SetEnabled(true)

	// Send some messages and verify counters.
	msg1 := NewTxMessage([]byte{0x01}, 0x0800, 0x0400)
	msg2 := NewTxMessage([]byte{0x02}, 0xFFFF, 0x0400) // broadcast

	_ = fwd.SendMessage(msg1)
	_ = fwd.SendMessage(msg2)

	fwd.HandleSentFrame(msg1, true)
	fwd.HandleSentFrame(msg2, true)

	counters := fwd.GetCounters()
	if counters.TxDirect != 2 {
		t.Errorf("TxDirect=%d, want 2", counters.TxDirect)
	}
	if counters.TxUnicast != 1 {
		t.Errorf("TxUnicast=%d, want 1", counters.TxUnicast)
	}
	if counters.TxBroadcast != 1 {
		t.Errorf("TxBroadcast=%d, want 1", counters.TxBroadcast)
	}

	// Failed send.
	msg3 := NewTxMessage([]byte{0x03}, 0x0800, 0x0400)
	fwd.HandleSentFrame(msg3, false)

	counters = fwd.GetCounters()
	if counters.TxDropped != 1 {
		t.Errorf("TxDropped=%d, want 1", counters.TxDropped)
	}

	// Reset.
	fwd.ResetCounters()
	counters = fwd.GetCounters()
	if counters.TxDirect != 0 || counters.TxUnicast != 0 || counters.TxBroadcast != 0 || counters.TxDropped != 0 {
		t.Errorf("counters not zero after reset: %+v", counters)
	}
}

func TestEnableDisableForwarder(t *testing.T) {
	fwd := NewForwarder()

	if fwd.IsEnabled() {
		t.Error("forwarder should be disabled initially")
	}

	// Cannot send when disabled.
	msg := NewTxMessage([]byte{0x01}, 0x0800, 0x0400)
	err := fwd.SendMessage(msg)
	if err != ErrForwarderDisabled {
		t.Errorf("expected ErrForwarderDisabled, got %v", err)
	}

	// Enable.
	fwd.SetEnabled(true)
	if !fwd.IsEnabled() {
		t.Error("forwarder should be enabled after SetEnabled(true)")
	}

	err = fwd.SendMessage(msg)
	if err != nil {
		t.Fatalf("SendMessage after enable error: %v", err)
	}

	direct, _ := fwd.GetQueueLength()
	if direct != 1 {
		t.Errorf("direct queue len=%d, want 1", direct)
	}

	// Disable should clear queues.
	fwd.SetEnabled(false)
	if fwd.IsEnabled() {
		t.Error("forwarder should be disabled after SetEnabled(false)")
	}

	direct, _ = fwd.GetQueueLength()
	if direct != 0 {
		t.Errorf("direct queue len=%d after disable, want 0", direct)
	}
}

func TestRxOnWhenIdle(t *testing.T) {
	fwd := NewForwarder()

	if fwd.GetRxOnWhenIdle() {
		t.Error("RxOnWhenIdle should be false initially")
	}

	fwd.SetRxOnWhenIdle(true)
	if !fwd.GetRxOnWhenIdle() {
		t.Error("RxOnWhenIdle should be true after SetRxOnWhenIdle(true)")
	}

	fwd.SetRxOnWhenIdle(false)
	if fwd.GetRxOnWhenIdle() {
		t.Error("RxOnWhenIdle should be false after SetRxOnWhenIdle(false)")
	}
}

func TestFragmentMessageTooLarge(t *testing.T) {
	fwd := NewForwarder()

	// Datagram exceeding FragMaxSize.
	data := make([]byte, FragMaxSize+1)
	_, _, err := fwd.FragmentMessage(data, 80)
	if err != ErrFragmentTooLarge {
		t.Errorf("expected ErrFragmentTooLarge, got %v", err)
	}
}

func TestFragmentTagWraparound(t *testing.T) {
	fwd := NewForwarder()

	// Set tag close to wraparound.
	fwd.mu.Lock()
	fwd.nextFragTag = 0xFFFF
	fwd.mu.Unlock()

	_, tag1, err := fwd.FragmentMessage([]byte{0x01, 0x02}, 10)
	if err != nil {
		t.Fatalf("FragmentMessage error: %v", err)
	}
	if tag1 != 0xFFFF {
		t.Errorf("tag1=%d, want 0xFFFF", tag1)
	}

	// Next tag should wrap around, skipping 0.
	_, tag2, err := fwd.FragmentMessage([]byte{0x01, 0x02}, 10)
	if err != nil {
		t.Fatalf("FragmentMessage error: %v", err)
	}
	if tag2 != 1 {
		t.Errorf("tag2=%d, want 1 (wrapped around, skipping 0)", tag2)
	}
}

func TestNewTxMessageDefaults(t *testing.T) {
	msg := NewTxMessage([]byte{0xAA}, 0x1234, 0x5678)

	if msg.MeshDest != 0x1234 {
		t.Errorf("MeshDest=0x%04X, want 0x1234", msg.MeshDest)
	}
	if msg.MeshSource != 0x5678 {
		t.Errorf("MeshSource=0x%04X, want 0x5678", msg.MeshSource)
	}
	if msg.Priority != uint8(PriorityNormal) {
		t.Errorf("Priority=%d, want %d", msg.Priority, PriorityNormal)
	}
	if !msg.Direct {
		t.Error("Direct should default to true")
	}
	if !msg.AckRequired {
		t.Error("AckRequired should default to true")
	}
	if msg.MaxHops != MaxHopsLeft {
		t.Errorf("MaxHops=%d, want %d", msg.MaxHops, MaxHopsLeft)
	}
}

func TestIndirectQueue(t *testing.T) {
	fwd := NewForwarder()
	fwd.SetEnabled(true)

	msg := NewTxMessage([]byte{0x01}, 0x0800, 0x0400)
	msg.Direct = false

	err := fwd.SendMessage(msg)
	if err != nil {
		t.Fatalf("SendMessage error: %v", err)
	}

	direct, indirect := fwd.GetQueueLength()
	if direct != 0 {
		t.Errorf("direct=%d, want 0", direct)
	}
	if indirect != 1 {
		t.Errorf("indirect=%d, want 1", indirect)
	}

	queue := fwd.GetIndirectQueue()
	if len(queue) != 1 {
		t.Fatalf("indirect queue len=%d, want 1", len(queue))
	}
	if queue[0].Data[0] != 0x01 {
		t.Errorf("indirect msg data=0x%02X, want 0x01", queue[0].Data[0])
	}
}
