// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//go:build !tinygo

package simulation

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hilli/gothread/crc"
	"github.com/hilli/gothread/radio"
)

func TestUDPSimRadio_CreateAndStart(t *testing.T) {
	r, err := NewUDPSimRadioWithPort(1, 19000)
	if err != nil {
		t.Fatalf("NewUDPSimRadio: %v", err)
	}
	if err := r.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer r.Stop()

	if err := r.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if !r.IsEnabled() {
		t.Error("expected radio to be enabled")
	}
	if r.GetState() != radio.StateSleep {
		t.Errorf("state = %v, want Sleep", r.GetState())
	}
}

func TestUDPSimRadio_LoopbackTransmit(t *testing.T) {
	// Use a unique port base to avoid conflicts with other tests.
	portBase := uint16(19100)

	// RadioA only transmits — we create a minimal sender with a direct UDP socket.
	// RadioB receives. This avoids the macOS SO_REUSEPORT in-process load-balancing issue
	// where two RX sockets on the same multicast port steal packets from each other.
	radioB, err := NewUDPSimRadioWithPort(2, portBase)
	if err != nil {
		t.Fatalf("NewUDPSimRadio B: %v", err)
	}

	if err := radioB.Start(); err != nil {
		t.Fatalf("Start B: %v", err)
	}
	defer radioB.Stop()

	_ = radioB.Enable()

	channel := uint8(15)
	_ = radioB.Receive(channel)

	var received *radio.Frame
	var mu sync.Mutex
	done := make(chan struct{})

	radioB.SetReceiveCallback(func(f *radio.Frame) {
		mu.Lock()
		defer mu.Unlock()
		received = f
		select {
		case done <- struct{}{}:
		default:
		}
	})

	// Give sockets time to be ready.
	time.Sleep(50 * time.Millisecond)

	// Send via a raw UDP socket bound to portBase+1 (simulating node 1),
	// with IP_MULTICAST_IF set to loopback.
	txAddr, _ := net.ResolveUDPAddr("udp4", fmt.Sprintf("127.0.0.1:%d", portBase+1))
	txConn, err := net.ListenUDP("udp4", txAddr)
	if err != nil {
		t.Fatalf("TX bind: %v", err)
	}
	defer txConn.Close()
	txRaw, _ := txConn.SyscallConn()
	txRaw.Control(func(fd uintptr) {
		lo := [4]byte{127, 0, 0, 1}
		syscall.SetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, lo)
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 1)
	})

	payload := []byte{0x41, 0x88, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x07}
	checksum := crc.ChecksumCRC16CCITT(payload)
	msg := make([]byte, 1+len(payload)+2)
	msg[0] = channel
	copy(msg[1:], payload)
	binary.LittleEndian.PutUint16(msg[1+len(payload):], checksum)

	dst, _ := net.ResolveUDPAddr("udp4", fmt.Sprintf("224.0.0.116:%d", portBase))
	txConn.WriteToUDP(msg, dst)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for frame reception")
	}

	mu.Lock()
	defer mu.Unlock()
	if received == nil {
		t.Fatal("received frame is nil")
	}
	if received.Channel != channel {
		t.Errorf("channel = %d, want %d", received.Channel, channel)
	}

	// The received PSDU includes the original payload + 2-byte CRC.
	expectedLen := len(payload) + 2
	if len(received.PSDU) != expectedLen {
		t.Fatalf("PSDU len = %d, want %d", len(received.PSDU), expectedLen)
	}
	for i, b := range payload {
		if received.PSDU[i] != b {
			t.Errorf("PSDU[%d] = 0x%02x, want 0x%02x", i, received.PSDU[i], b)
		}
	}
	gotCRC := binary.LittleEndian.Uint16(received.PSDU[len(payload):])
	wantCRC := crc.ChecksumCRC16CCITT(payload)
	if gotCRC != wantCRC {
		t.Errorf("CRC = 0x%04x, want 0x%04x", gotCRC, wantCRC)
	}
}

func TestUDPSimRadio_ChannelFilter(t *testing.T) {
	portBase := uint16(19200)

	radioB, err := NewUDPSimRadioWithPort(2, portBase)
	if err != nil {
		t.Fatalf("NewUDPSimRadio B: %v", err)
	}

	if err := radioB.Start(); err != nil {
		t.Fatalf("Start B: %v", err)
	}
	defer radioB.Stop()

	_ = radioB.Enable()

	// B on channel 20 — should NOT receive a frame sent on channel 15.
	_ = radioB.Receive(20)

	gotFrame := make(chan struct{}, 1)
	radioB.SetReceiveCallback(func(f *radio.Frame) {
		select {
		case gotFrame <- struct{}{}:
		default:
		}
	})

	time.Sleep(50 * time.Millisecond)

	// Send on channel 15 via raw UDP.
	txAddr, _ := net.ResolveUDPAddr("udp4", fmt.Sprintf("127.0.0.1:%d", portBase+1))
	txConn, err := net.ListenUDP("udp4", txAddr)
	if err != nil {
		t.Fatalf("TX bind: %v", err)
	}
	defer txConn.Close()
	txRaw, _ := txConn.SyscallConn()
	txRaw.Control(func(fd uintptr) {
		lo := [4]byte{127, 0, 0, 1}
		syscall.SetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, lo)
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 1)
	})

	msg := []byte{15, 0x01, 0x02, 0x03} // channel 15
	dst, _ := net.ResolveUDPAddr("udp4", fmt.Sprintf("224.0.0.116:%d", portBase))
	txConn.WriteToUDP(msg, dst)

	select {
	case <-gotFrame:
		t.Error("B should not have received a frame on a different channel")
	case <-time.After(200 * time.Millisecond):
		// Expected: no frame received.
	}
}

func TestUDPSimRadio_CRC16(t *testing.T) {
	// Known test vector: "123456789" → CRC-16/CCITT (init=0) = 0x31C3
	data := []byte("123456789")
	got := crc.ChecksumCRC16CCITT(data)
	want := uint16(0x31C3)
	if got != want {
		t.Errorf("CRC16CCITT(%q) = 0x%04X, want 0x%04X", data, got, want)
	}
}
