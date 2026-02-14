// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package simulation

import (
	"testing"

	"github.com/hilli/gothread/radio"
)

func TestMediumRegisterUnregister(t *testing.T) {
	m := NewMedium()
	r1 := NewSimRadio()
	r2 := NewSimRadio()

	m.Register(r1)
	m.Register(r2)

	if len(m.radios) != 2 {
		t.Fatalf("expected 2 radios, got %d", len(m.radios))
	}

	m.Unregister(r1)
	if len(m.radios) != 1 {
		t.Fatalf("expected 1 radio after unregister, got %d", len(m.radios))
	}
	if m.radios[0] != r2 {
		t.Fatal("wrong radio remaining after unregister")
	}

	// Unregister non-existent radio is safe.
	m.Unregister(r1)
	if len(m.radios) != 1 {
		t.Fatalf("expected 1 radio after double unregister, got %d", len(m.radios))
	}
}

func TestMediumBroadcast(t *testing.T) {
	m := NewMedium()
	a := NewSimRadio()
	b := NewSimRadio()
	m.Register(a)
	m.Register(b)

	_ = a.Enable()
	_ = b.Enable()
	_ = b.Receive(15)

	frame := &radio.Frame{
		PSDU:    []byte{0x01, 0x02, 0x03},
		Channel: 15,
	}
	_ = a.Transmit(frame)

	rx := b.ReceiveFrame()
	if rx == nil {
		t.Fatal("radio B should have received a frame")
	}
	if len(rx.PSDU) != 3 || rx.PSDU[0] != 0x01 {
		t.Fatalf("received frame PSDU mismatch: %v", rx.PSDU)
	}
	// Ensure it's a copy, not the same slice.
	if &rx.PSDU[0] == &frame.PSDU[0] {
		t.Fatal("received frame should be a deep copy")
	}
}

func TestMediumChannelIsolation(t *testing.T) {
	m := NewMedium()
	a := NewSimRadio()
	b := NewSimRadio()
	m.Register(a)
	m.Register(b)

	_ = a.Enable()
	_ = b.Enable()
	_ = b.Receive(20) // B listens on channel 20

	frame := &radio.Frame{
		PSDU:    []byte{0xAA},
		Channel: 15, // A transmits on channel 15
	}
	_ = a.Transmit(frame)

	rx := b.ReceiveFrame()
	if rx != nil {
		t.Fatal("radio B should NOT receive a frame on a different channel")
	}
}

func TestMediumMultipleReceivers(t *testing.T) {
	m := NewMedium()
	sender := NewSimRadio()
	receivers := make([]*SimRadio, 4)
	for i := range receivers {
		receivers[i] = NewSimRadio()
		m.Register(receivers[i])
		_ = receivers[i].Enable()
		_ = receivers[i].Receive(11)
	}
	m.Register(sender)
	_ = sender.Enable()

	frame := &radio.Frame{
		PSDU:    []byte{0xBB, 0xCC},
		Channel: 11,
	}
	n := m.Broadcast(sender, frame)
	if n != 4 {
		t.Fatalf("expected 4 receivers, got %d", n)
	}

	for i, r := range receivers {
		rx := r.ReceiveFrame()
		if rx == nil {
			t.Fatalf("receiver %d did not get the frame", i)
		}
	}
}

func TestMediumSenderExcluded(t *testing.T) {
	m := NewMedium()
	a := NewSimRadio()
	m.Register(a)
	_ = a.Enable()
	_ = a.Receive(11)

	frame := &radio.Frame{
		PSDU:    []byte{0xDD},
		Channel: 11,
	}
	n := m.Broadcast(a, frame)
	if n != 0 {
		t.Fatalf("sender should be excluded, got %d receivers", n)
	}

	rx := a.ReceiveFrame()
	if rx != nil {
		t.Fatal("sender should NOT receive its own frame")
	}
}

func TestMediumReceiveCallback(t *testing.T) {
	m := NewMedium()
	a := NewSimRadio()
	b := NewSimRadio()
	m.Register(a)
	m.Register(b)

	_ = a.Enable()
	_ = b.Enable()
	_ = b.Receive(11)

	called := false
	b.SetReceiveCallback(func(f *radio.Frame) {
		called = true
	})

	frame := &radio.Frame{
		PSDU:    []byte{0xEE},
		Channel: 11,
	}
	_ = a.Transmit(frame)

	if !called {
		t.Fatal("receive callback should have been invoked")
	}
}
