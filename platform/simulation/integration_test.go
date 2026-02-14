// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package simulation

import (
	"sync"
	"testing"
	"time"

	"github.com/hilli/gothread/instance"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/radio"
)

// TestMediumFrameDelivery verifies basic frame relay between two radios
// connected to the same Medium and tuned to the same channel.
func TestMediumFrameDelivery(t *testing.T) {
	m := NewMedium()
	a := NewSimRadio()
	b := NewSimRadio()
	m.Register(a)
	m.Register(b)

	_ = a.Enable()
	_ = b.Enable()
	_ = b.Receive(15)

	var mu sync.Mutex
	var received *radio.Frame
	b.SetReceiveCallback(func(f *radio.Frame) {
		mu.Lock()
		received = f
		mu.Unlock()
	})

	frame := &radio.Frame{
		PSDU:    []byte{0xDE, 0xAD, 0xBE, 0xEF},
		Channel: 15,
	}
	_ = a.Transmit(frame)

	mu.Lock()
	defer mu.Unlock()
	if received == nil {
		t.Fatal("radio B callback was not invoked")
	}
	if len(received.PSDU) != 4 {
		t.Fatalf("expected 4-byte PSDU, got %d", len(received.PSDU))
	}
	if received.PSDU[0] != 0xDE || received.PSDU[3] != 0xEF {
		t.Fatalf("PSDU content mismatch: %x", received.PSDU)
	}

	// Also verify via the channel-based ReceiveFrame path.
	polled := b.ReceiveFrame()
	if polled == nil {
		t.Fatal("ReceiveFrame should also return the delivered frame")
	}
}

// TestTwoNodeSendReceive creates two full Instance objects, each backed by a
// SimRadio on the same Medium. It verifies that a frame transmitted by one
// instance's radio is received by the other instance's radio.
func TestTwoNodeSendReceive(t *testing.T) {
	m := NewMedium()

	// Build two simulation platforms sharing the same medium.
	p1 := NewPlatform()
	p2 := NewPlatform()
	m.Register(p1.Radio)
	m.Register(p2.Radio)

	// Create instances using platform components.
	inst1 := instance.New(instance.Config{
		Alarm:    p1.Alarm,
		Entropy:  p1.Entropy,
		Settings: p1.Settings,
		Logger:   p1.Logger,
		Radio:    p1.Radio,
	})
	inst2 := instance.New(instance.Config{
		Alarm:    p2.Alarm,
		Entropy:  p2.Entropy,
		Settings: p2.Settings,
		Logger:   p2.Logger,
		Radio:    p2.Radio,
	})
	_ = inst1 // instances are created successfully

	// Enable radios, put receiver into receive mode on channel 15.
	_ = p1.Radio.Enable()
	_ = p2.Radio.Enable()
	_ = p2.Radio.Receive(15)

	// Track received frames via callback on node 2's radio.
	var mu sync.Mutex
	var got *radio.Frame
	done := make(chan struct{}, 1)
	p2.Radio.SetReceiveCallback(func(f *radio.Frame) {
		mu.Lock()
		got = f
		mu.Unlock()
		select {
		case done <- struct{}{}:
		default:
		}
	})

	// Transmit from node 1's radio through the medium.
	payload := []byte{0x41, 0x88, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x08}
	frame := &radio.Frame{
		PSDU:    payload,
		Channel: 15,
	}
	_ = p1.Radio.Transmit(frame)

	// Wait briefly for delivery.
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
	}

	mu.Lock()
	defer mu.Unlock()
	if got == nil {
		t.Fatal("instance 2's radio did not receive the frame from instance 1")
	}
	if len(got.PSDU) != len(payload) {
		t.Fatalf("PSDU length mismatch: got %d, want %d", len(got.PSDU), len(payload))
	}
	for i, b := range payload {
		if got.PSDU[i] != b {
			t.Fatalf("PSDU byte %d: got 0x%02x, want 0x%02x", i, got.PSDU[i], b)
		}
	}

	// Verify that inst2 is valid (non-nil) to confirm full-stack wiring.
	if inst2 == nil {
		t.Fatal("instance 2 should not be nil")
	}
}

// TestMediumChannelIsolation_Integration verifies that radios on different
// channels do not receive each other's frames, while radios on the same
// channel do.
func TestMediumChannelIsolation_Integration(t *testing.T) {
	m := NewMedium()
	a := NewSimRadio() // transmitter on ch15
	b := NewSimRadio() // receiver on ch15
	c := NewSimRadio() // receiver on ch20

	m.Register(a)
	m.Register(b)
	m.Register(c)

	_ = a.Enable()
	_ = b.Enable()
	_ = c.Enable()
	_ = b.Receive(15)
	_ = c.Receive(20)

	// Track callbacks on both receivers.
	var muB sync.Mutex
	var gotB *radio.Frame
	b.SetReceiveCallback(func(f *radio.Frame) {
		muB.Lock()
		gotB = f
		muB.Unlock()
	})

	var muC sync.Mutex
	var gotC *radio.Frame
	c.SetReceiveCallback(func(f *radio.Frame) {
		muC.Lock()
		gotC = f
		muC.Unlock()
	})

	frame := &radio.Frame{
		PSDU:    []byte{0xCA, 0xFE},
		Channel: 15,
	}
	_ = a.Transmit(frame)

	// B (ch15) should receive the frame.
	muB.Lock()
	if gotB == nil {
		t.Fatal("radio B (ch15) should have received the frame")
	}
	if gotB.PSDU[0] != 0xCA || gotB.PSDU[1] != 0xFE {
		t.Fatalf("radio B PSDU mismatch: %x", gotB.PSDU)
	}
	muB.Unlock()

	// C (ch20) should NOT receive the frame.
	muC.Lock()
	if gotC != nil {
		t.Fatal("radio C (ch20) should NOT have received the frame on ch15")
	}
	muC.Unlock()

	// Also verify via polling.
	if rx := b.ReceiveFrame(); rx == nil {
		t.Fatal("radio B ReceiveFrame should return the frame")
	}
	if rx := c.ReceiveFrame(); rx != nil {
		t.Fatal("radio C ReceiveFrame should return nil")
	}

	// Now transmit on ch20 and verify C receives but B does not.
	frame2 := &radio.Frame{
		PSDU:    []byte{0xBA, 0xBE},
		Channel: 20,
	}
	// Reset callbacks.
	muB.Lock()
	gotB = nil
	muB.Unlock()
	muC.Lock()
	gotC = nil
	muC.Unlock()

	_ = a.Transmit(frame2)

	muC.Lock()
	if gotC == nil {
		t.Fatal("radio C (ch20) should have received the ch20 frame")
	}
	muC.Unlock()

	muB.Lock()
	if gotB != nil {
		t.Fatal("radio B (ch15) should NOT have received the ch20 frame")
	}
	muB.Unlock()
}

// TestMediumFrameDeliveryWithInstances verifies that frames injected via
// Instance.Radio() are delivered through the medium correctly — bridging
// the instance radio accessor with the simulation medium.
func TestMediumFrameDeliveryWithInstances(t *testing.T) {
	m := NewMedium()
	p1 := NewPlatform()
	p2 := NewPlatform()
	m.Register(p1.Radio)
	m.Register(p2.Radio)

	inst1 := instance.New(instance.Config{
		Alarm:    p1.Alarm,
		Entropy:  p1.Entropy,
		Settings: p1.Settings,
		Logger:   NewSimLogger(platform.LogLevelWarn),
		Radio:    p1.Radio,
	})
	inst2 := instance.New(instance.Config{
		Alarm:    p2.Alarm,
		Entropy:  p2.Entropy,
		Settings: p2.Settings,
		Logger:   NewSimLogger(platform.LogLevelWarn),
		Radio:    p2.Radio,
	})

	// Verify that the instance Radio() accessor returns the same radio.
	r1, ok := inst1.Radio().(*SimRadio)
	if !ok {
		t.Fatal("inst1.Radio() should return *SimRadio")
	}
	r2, ok := inst2.Radio().(*SimRadio)
	if !ok {
		t.Fatal("inst2.Radio() should return *SimRadio")
	}

	_ = r1.Enable()
	_ = r2.Enable()
	_ = r2.Receive(15)

	rxFrame := r2.ReceiveFrame()
	if rxFrame != nil {
		t.Fatal("no frame should be pending before transmit")
	}

	_ = r1.Transmit(&radio.Frame{
		PSDU:    []byte{0x11, 0x22, 0x33},
		Channel: 15,
	})

	rxFrame = r2.ReceiveFrame()
	if rxFrame == nil {
		t.Fatal("inst2 radio should have received the frame via medium")
	}
	if len(rxFrame.PSDU) != 3 || rxFrame.PSDU[0] != 0x11 {
		t.Fatalf("unexpected PSDU: %x", rxFrame.PSDU)
	}
}
