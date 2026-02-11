// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package ble

import (
	"testing"

	"github.com/hilli/gothread/errors"
)

// mockPlatform is a test double for the Platform interface.
type mockPlatform struct {
	enableErr     error
	disableErr    error
	connectErr    error
	disconnectErr error
	sendErr       error
	sent          [][]byte
}

func (m *mockPlatform) BleEnable() error          { return m.enableErr }
func (m *mockPlatform) BleDisable() error         { return m.disableErr }
func (m *mockPlatform) GapConnect(_ []byte) error { return m.connectErr }
func (m *mockPlatform) GapDisconnect() error      { return m.disconnectErr }
func (m *mockPlatform) BleSend(data []byte) error {
	m.sent = append(m.sent, data)
	return m.sendErr
}

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateDisabled, "Disabled"},
		{StateIdle, "Idle"},
		{StateConnecting, "Connecting"},
		{StateConnected, "Connected"},
		{State(99), "Unknown"},
	}
	for _, tc := range tests {
		if got := tc.state.String(); got != tc.want {
			t.Errorf("State(%d).String() = %q, want %q", tc.state, got, tc.want)
		}
	}
}

func TestEnableDisable(t *testing.T) {
	p := &mockPlatform{}
	b := NewBleSecure(p)

	if b.IsEnabled() {
		t.Error("should start disabled")
	}
	if err := b.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	if !b.IsEnabled() {
		t.Error("should be enabled after Enable()")
	}
	if b.GetState() != StateIdle {
		t.Errorf("state = %v, want Idle", b.GetState())
	}
	// Double enable should fail.
	if err := b.Enable(); err != errors.ErrAlready {
		t.Errorf("double Enable() = %v, want ErrAlready", err)
	}

	if err := b.Disable(); err != nil {
		t.Fatalf("Disable() = %v", err)
	}
	if b.IsEnabled() {
		t.Error("should be disabled after Disable()")
	}
	// Double disable.
	if err := b.Disable(); err != errors.ErrAlready {
		t.Errorf("double Disable() = %v, want ErrAlready", err)
	}
}

func TestConnectDisconnect(t *testing.T) {
	p := &mockPlatform{}
	b := NewBleSecure(p)
	b.Enable()

	addr := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	if err := b.Connect(addr); err != nil {
		t.Fatalf("Connect() = %v", err)
	}
	if b.GetState() != StateConnecting {
		t.Errorf("state = %v, want Connecting", b.GetState())
	}

	// Simulate platform reporting connection established.
	b.HandleConnected()
	if b.GetState() != StateConnected {
		t.Errorf("state = %v, want Connected", b.GetState())
	}
	if !b.IsConnected() {
		t.Error("IsConnected() should be true")
	}

	if err := b.Disconnect(); err != nil {
		t.Fatalf("Disconnect() = %v", err)
	}
	if b.GetState() != StateIdle {
		t.Errorf("state = %v, want Idle", b.GetState())
	}
}

func TestConnectWhenNotIdle(t *testing.T) {
	p := &mockPlatform{}
	b := NewBleSecure(p)
	// Not enabled.
	if err := b.Connect(nil); err != errors.ErrInvalidState {
		t.Errorf("Connect() when disabled = %v, want ErrInvalidState", err)
	}
}

func TestSend(t *testing.T) {
	p := &mockPlatform{}
	b := NewBleSecure(p)
	b.Enable()
	b.Connect([]byte{1, 2, 3})
	b.HandleConnected()

	data := []byte("hello BLE")
	if err := b.Send(data); err != nil {
		t.Fatalf("Send() = %v", err)
	}
	if len(p.sent) != 1 {
		t.Fatalf("platform received %d sends, want 1", len(p.sent))
	}
	if string(p.sent[0]) != "hello BLE" {
		t.Errorf("sent data = %q, want %q", p.sent[0], "hello BLE")
	}
}

func TestSendWhenNotConnected(t *testing.T) {
	p := &mockPlatform{}
	b := NewBleSecure(p)
	b.Enable()
	if err := b.Send([]byte("x")); err != errors.ErrInvalidState {
		t.Errorf("Send() when idle = %v, want ErrInvalidState", err)
	}
}

func TestReceiveCallback(t *testing.T) {
	p := &mockPlatform{}
	b := NewBleSecure(p)
	b.Enable()

	var received []byte
	b.SetReceiveCallback(func(data []byte) {
		received = data
	})
	b.HandleReceive([]byte("incoming"))
	if string(received) != "incoming" {
		t.Errorf("received = %q, want %q", received, "incoming")
	}
}

func TestConnectionCallback(t *testing.T) {
	p := &mockPlatform{}
	b := NewBleSecure(p)
	b.Enable()

	var connected *bool
	b.SetConnectionCallback(func(c bool) {
		connected = &c
	})
	b.Connect([]byte{1})
	b.HandleConnected()
	if connected == nil || !*connected {
		t.Error("connection callback should report connected=true")
	}

	connected = nil
	b.Disconnect()
	if connected == nil || *connected {
		t.Error("connection callback should report connected=false on disconnect")
	}
}

func TestHandleDisconnected(t *testing.T) {
	p := &mockPlatform{}
	b := NewBleSecure(p)
	b.Enable()
	b.Connect([]byte{1})
	b.HandleConnected()

	var cbCalled bool
	b.SetConnectionCallback(func(c bool) {
		cbCalled = true
		if c {
			t.Error("HandleDisconnected should report connected=false")
		}
	})
	b.HandleDisconnected()
	if !cbCalled {
		t.Error("connection callback was not called")
	}
	if b.GetState() != StateIdle {
		t.Errorf("state = %v, want Idle", b.GetState())
	}
}

func TestDisableWhileConnected(t *testing.T) {
	p := &mockPlatform{}
	b := NewBleSecure(p)
	b.Enable()
	b.Connect([]byte{1})
	b.HandleConnected()

	if err := b.Disable(); err != nil {
		t.Fatalf("Disable() while connected = %v", err)
	}
	if b.GetState() != StateDisabled {
		t.Errorf("state = %v, want Disabled", b.GetState())
	}
}
