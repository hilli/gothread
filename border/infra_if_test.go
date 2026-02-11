// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package border

import (
	"testing"

	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

type mockPlatform struct {
	sendCalled     bool
	sendDest       ip6.Address
	sendBuf        []byte
	sendErr        error
	hasAddrResult  bool
	discoverCalled bool
	discoverErr    error
	linkLayerAddr  []byte
}

func (m *mockPlatform) SendIcmp6Nd(_ uint32, dest ip6.Address, buf []byte) error {
	m.sendCalled = true
	m.sendDest = dest
	m.sendBuf = buf
	return m.sendErr
}

func (m *mockPlatform) HasAddress(_ uint32, _ ip6.Address) bool {
	return m.hasAddrResult
}

func (m *mockPlatform) DiscoverNat64Prefix(_ uint32) error {
	m.discoverCalled = true
	return m.discoverErr
}

func (m *mockPlatform) GetLinkLayerAddress(_ uint32) []byte {
	return m.linkLayerAddr
}

type mockCallbacks struct {
	stateChangedCount int
	receivedCalls     []receivedCall
}

type receivedCall struct {
	ifIndex  uint32
	src      ip6.Address
	icmpType uint8
	buf      []byte
}

func (m *mockCallbacks) HandleInfraIfStateChanged() {
	m.stateChangedCount++
}

func (m *mockCallbacks) HandleReceiveIcmp6Nd(ifIndex uint32, src ip6.Address, icmpType uint8, buf []byte) {
	m.receivedCalls = append(m.receivedCalls, receivedCall{ifIndex, src, icmpType, buf})
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestInfraIfNewUninitialized(t *testing.T) {
	p := &mockPlatform{}
	c := &mockCallbacks{}
	inf := NewInfraIf(p, c)

	if inf.IsInitialized() {
		t.Error("expected not initialized")
	}
	if inf.IsRunning() {
		t.Error("expected not running")
	}
	if inf.GetIfIndex() != 0 {
		t.Error("expected ifIndex 0")
	}
}

func TestInfraIfInit(t *testing.T) {
	p := &mockPlatform{}
	c := &mockCallbacks{}
	inf := NewInfraIf(p, c)

	if err := inf.Init(42); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !inf.IsInitialized() {
		t.Error("expected initialized")
	}
	if inf.GetIfIndex() != 42 {
		t.Errorf("ifIndex = %d, want 42", inf.GetIfIndex())
	}

	// Re-init with same index is fine.
	if err := inf.Init(42); err != nil {
		t.Errorf("re-Init same index: %v", err)
	}

	// Re-init with different index fails.
	if err := inf.Init(99); err == nil {
		t.Error("expected error re-init with different index")
	}
}

func TestInfraIfDeinit(t *testing.T) {
	p := &mockPlatform{}
	c := &mockCallbacks{}
	inf := NewInfraIf(p, c)
	_ = inf.Init(5)
	inf.SetRunning(true)
	inf.Deinit()

	if inf.IsInitialized() {
		t.Error("expected not initialized after deinit")
	}
	if inf.IsRunning() {
		t.Error("expected not running after deinit")
	}
}

func TestInfraIfSetRunning(t *testing.T) {
	p := &mockPlatform{}
	c := &mockCallbacks{}
	inf := NewInfraIf(p, c)
	_ = inf.Init(1)

	// Not running -> running: should change and notify.
	if !inf.SetRunning(true) {
		t.Error("expected state change")
	}
	if c.stateChangedCount != 1 {
		t.Errorf("stateChangedCount = %d, want 1", c.stateChangedCount)
	}

	// Running -> running: no change.
	if inf.SetRunning(true) {
		t.Error("expected no state change")
	}
	if c.stateChangedCount != 1 {
		t.Errorf("stateChangedCount = %d, want 1", c.stateChangedCount)
	}

	// Running -> not running: should change and notify.
	if !inf.SetRunning(false) {
		t.Error("expected state change")
	}
	if c.stateChangedCount != 2 {
		t.Errorf("stateChangedCount = %d, want 2", c.stateChangedCount)
	}
}

func TestInfraIfSetRunningNotInitialized(t *testing.T) {
	p := &mockPlatform{}
	c := &mockCallbacks{}
	inf := NewInfraIf(p, c)

	if inf.SetRunning(true) {
		t.Error("expected no state change when not initialized")
	}
}

func TestInfraIfSendIcmp6Nd(t *testing.T) {
	p := &mockPlatform{}
	c := &mockCallbacks{}
	inf := NewInfraIf(p, c)

	// Not initialized -> error.
	dest := ip6.Address{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	if err := inf.SendIcmp6Nd(dest, []byte{1, 2, 3}); err == nil {
		t.Error("expected error when not initialized")
	}

	_ = inf.Init(10)
	// Initialized but not running -> error.
	if err := inf.SendIcmp6Nd(dest, []byte{1, 2, 3}); err == nil {
		t.Error("expected error when not running")
	}

	inf.SetRunning(true)
	// Should succeed.
	if err := inf.SendIcmp6Nd(dest, []byte{1, 2, 3}); err != nil {
		t.Fatalf("SendIcmp6Nd: %v", err)
	}
	if !p.sendCalled {
		t.Error("expected platform.SendIcmp6Nd called")
	}
	if p.sendDest != dest {
		t.Error("destination mismatch")
	}
}

func TestInfraIfHasAddress(t *testing.T) {
	p := &mockPlatform{hasAddrResult: true}
	c := &mockCallbacks{}
	inf := NewInfraIf(p, c)

	// Not initialized -> false.
	addr := ip6.Address{0x20, 0x01}
	if inf.HasAddress(addr) {
		t.Error("expected false when not initialized")
	}

	_ = inf.Init(1)
	if !inf.HasAddress(addr) {
		t.Error("expected true")
	}
}

func TestInfraIfDiscoverNat64Prefix(t *testing.T) {
	p := &mockPlatform{}
	c := &mockCallbacks{}
	inf := NewInfraIf(p, c)

	// Not initialized.
	if err := inf.DiscoverNat64Prefix(); err == nil {
		t.Error("expected error when not initialized")
	}

	_ = inf.Init(1)
	// Not running.
	if err := inf.DiscoverNat64Prefix(); err == nil {
		t.Error("expected error when not running")
	}

	inf.SetRunning(true)
	if err := inf.DiscoverNat64Prefix(); err != nil {
		t.Fatalf("DiscoverNat64Prefix: %v", err)
	}
	if !p.discoverCalled {
		t.Error("expected platform discover called")
	}
}

func TestInfraIfGetLinkLayerAddress(t *testing.T) {
	mac := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	p := &mockPlatform{linkLayerAddr: mac}
	c := &mockCallbacks{}
	inf := NewInfraIf(p, c)

	if inf.GetLinkLayerAddress() != nil {
		t.Error("expected nil when not initialized")
	}

	_ = inf.Init(1)
	got := inf.GetLinkLayerAddress()
	if len(got) != 6 {
		t.Fatalf("got %d bytes, want 6", len(got))
	}
	for i, b := range mac {
		if got[i] != b {
			t.Errorf("byte %d: got %02x, want %02x", i, got[i], b)
		}
	}
}

func TestInfraIfHandleReceiveIcmp6Nd(t *testing.T) {
	p := &mockPlatform{}
	c := &mockCallbacks{}
	inf := NewInfraIf(p, c)

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	// Not initialized.
	if err := inf.HandleReceiveIcmp6Nd(src, 134, []byte{0xAA}); err == nil {
		t.Error("expected error when not initialized")
	}

	_ = inf.Init(7)
	if err := inf.HandleReceiveIcmp6Nd(src, 134, []byte{0xBB}); err != nil {
		t.Fatalf("HandleReceiveIcmp6Nd: %v", err)
	}
	if len(c.receivedCalls) != 1 {
		t.Fatalf("expected 1 received call, got %d", len(c.receivedCalls))
	}
	call := c.receivedCalls[0]
	if call.ifIndex != 7 {
		t.Errorf("ifIndex = %d, want 7", call.ifIndex)
	}
	if call.src != src {
		t.Error("src mismatch")
	}
	if call.icmpType != 134 {
		t.Errorf("icmpType = %d, want 134", call.icmpType)
	}
}

func TestGetLinkLocalAllRoutersAddress(t *testing.T) {
	addr := GetLinkLocalAllRoutersAddress()
	expected := ip6.Address{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	if addr != expected {
		t.Errorf("got %v, want %v", addr, expected)
	}
}

func TestInfraIfSendIcmp6NdPlatformError(t *testing.T) {
	p := &mockPlatform{sendErr: errNotRunning} // reuse sentinel as a stand-in
	c := &mockCallbacks{}
	inf := NewInfraIf(p, c)
	_ = inf.Init(1)
	inf.SetRunning(true)

	dest := ip6.Address{0xff, 0x02}
	err := inf.SendIcmp6Nd(dest, []byte{1})
	if err == nil {
		t.Error("expected platform error to propagate")
	}
}
