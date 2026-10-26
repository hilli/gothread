// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//go:build !tinygo

package simulation

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hilli/gothread/common/log"
	"github.com/hilli/gothread/crc"
	"github.com/hilli/gothread/radio"
	"golang.org/x/sys/unix"
)

func TestUDPSimRadioStopReportsSocketCloseErrors(t *testing.T) {
	var diagnostics bytes.Buffer
	original := log.GetLogger()
	log.SetLogger(log.NewDefaultLogger(&diagnostics, log.LevelWarn))
	t.Cleanup(func() { log.SetLogger(original) })

	r := &UDPSimRadio{}
	for _, conn := range []**net.UDPConn{&r.rxConn, &r.txConn} {
		var err error
		*conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("ListenUDP: %v", err)
		}
		if err := (*conn).Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}

	r.Stop()
	if r.rxConn != nil || r.txConn != nil {
		t.Error("Stop must clear both socket references even when closing fails")
	}
	if strings.Count(diagnostics.String(), net.ErrClosed.Error()) != 2 {
		t.Fatalf("expected both socket close errors to be logged: %q", diagnostics.String())
	}
}

func TestUDPSimRadio_SharedSocketOptions(t *testing.T) {
	const portBase = 19300
	for nodeID := uint16(1); nodeID <= 2; nodeID++ {
		r, err := NewUDPSimRadioWithPort(nodeID, portBase)
		if err != nil {
			t.Fatalf("NewUDPSimRadio: %v", err)
		}
		if err := r.Start(); err != nil {
			t.Fatalf("Start node %d on shared multicast port: %v", nodeID, err)
		}
		t.Cleanup(r.Stop)

		for _, option := range []struct {
			name  string
			value int
		}{
			{"SO_REUSEADDR", syscall.SO_REUSEADDR},
			{"SO_REUSEPORT", unix.SO_REUSEPORT},
		} {
			value, err := syscall.GetsockoptInt(r.rxFd, syscall.SOL_SOCKET, option.value)
			if err != nil {
				t.Fatalf("get %s: %v", option.name, err)
			}
			if value == 0 {
				t.Errorf("node %d %s is disabled", nodeID, option.name)
			}
		}
		addr, err := syscall.Getsockname(r.rxFd)
		if err != nil {
			t.Fatalf("get RX address: %v", err)
		}
		rxAddr, ok := addr.(*syscall.SockaddrInet4)
		if !ok || rxAddr.Port != portBase || rxAddr.Addr != [4]byte{224, 0, 0, 116} {
			t.Errorf("RX address = %v, want %s:%d", addr, SimMulticastAddr, portBase)
		}
		flags, err := unix.FcntlInt(uintptr(r.rxFd), unix.F_GETFL, 0)
		if err != nil {
			t.Fatalf("get RX flags: %v", err)
		}
		if flags&unix.O_NONBLOCK == 0 {
			t.Error("RX socket must be nonblocking before Start returns")
		}
		txAddr, ok := r.txConn.LocalAddr().(*net.UDPAddr)
		if !ok || !txAddr.IP.Equal(net.IPv4(127, 0, 0, 1)) || txAddr.Port != portBase+int(nodeID) {
			t.Errorf("TX address = %v, want 127.0.0.1:%d", r.txConn.LocalAddr(), portBase+int(nodeID))
		}
		raw, err := r.txConn.SyscallConn()
		if err != nil {
			t.Fatalf("TX syscall conn: %v", err)
		}
		var iface [4]byte
		var loop int
		var optionErr error
		if err := raw.Control(func(fd uintptr) {
			iface, optionErr = syscall.GetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF)
			if optionErr == nil {
				loop, optionErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP)
			}
		}); err != nil {
			t.Fatalf("inspect TX socket: %v", err)
		}
		if optionErr != nil {
			t.Fatalf("get TX multicast options: %v", optionErr)
		}
		if iface != [4]byte{127, 0, 0, 1} || loop != 1 {
			t.Errorf("TX multicast interface/loop = %v/%d, want 127.0.0.1/1", iface, loop)
		}
	}
}

func TestUDPSimRadio_StartBindFailureCleansUp(t *testing.T) {
	const portBase = 19310
	// Use a raw socket to avoid net.ListenUDP's default reuse options.
	blocker, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		t.Fatalf("create blocking socket: %v", err)
	}
	t.Cleanup(func() {
		if blocker >= 0 {
			if err := syscall.Close(blocker); err != nil {
				t.Errorf("close blocking socket: %v", err)
			}
		}
	})
	if err := syscall.Bind(blocker, &syscall.SockaddrInet4{Addr: [4]byte{224, 0, 0, 116}, Port: portBase}); err != nil {
		t.Fatalf("occupy multicast port: %v", err)
	}
	r, err := NewUDPSimRadioWithPort(1, portBase)
	if err != nil {
		t.Fatalf("NewUDPSimRadio: %v", err)
	}
	t.Cleanup(r.Stop)
	err = r.Start()
	if !errors.Is(err, syscall.EADDRINUSE) || !strings.Contains(err.Error(), "bind rx") {
		t.Fatalf("Start error = %v, want bind rx: address already in use", err)
	}
	if r.txConn != nil || r.rxFd != 0 || r.rxMreq != nil || r.stopCh != nil {
		t.Fatal("failed Start published partially initialized sockets")
	}
	// A failed RX bind must release the TX port as well.
	tx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: portBase + 1})
	if err != nil {
		t.Fatalf("TX port leaked after failed Start: %v", err)
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("close TX probe: %v", err)
	}
	if err := syscall.Close(blocker); err != nil {
		t.Fatalf("release multicast port: %v", err)
	}
	blocker = -1
	if err := r.Start(); err != nil {
		t.Fatalf("retry Start after releasing multicast port: %v", err)
	}
}

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
