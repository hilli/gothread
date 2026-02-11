// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package socket

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Address tests
// ---------------------------------------------------------------------------

func TestAddressIsUnspecified(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr Address
		want bool
	}{
		{"zero address and port", Address{}, true},
		{"zero address nonzero port", Address{Port: 80}, false},
		{"nonzero address zero port", Address{Addr: [16]byte{15: 1}}, false},
		{"both nonzero", Address{Addr: [16]byte{15: 1}, Port: 80}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.addr.IsUnspecified(); got != tt.want {
				t.Errorf("IsUnspecified() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddressIsAddrUnspecified(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr Address
		want bool
	}{
		{"zero address", Address{}, true},
		{"zero address nonzero port", Address{Port: 80}, true},
		{"nonzero address", Address{Addr: [16]byte{15: 1}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.addr.IsAddrUnspecified(); got != tt.want {
				t.Errorf("IsAddrUnspecified() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddressEqual(t *testing.T) {
	t.Parallel()

	a := Address{Addr: [16]byte{0: 0xfe, 1: 0x80, 15: 1}, Port: 1234}
	b := Address{Addr: [16]byte{0: 0xfe, 1: 0x80, 15: 1}, Port: 1234}
	c := Address{Addr: [16]byte{0: 0xfe, 1: 0x80, 15: 2}, Port: 1234}
	d := Address{Addr: [16]byte{0: 0xfe, 1: 0x80, 15: 1}, Port: 5678}

	if !a.Equal(b) {
		t.Error("Equal: identical addresses should be equal")
	}
	if a.Equal(c) {
		t.Error("Equal: different addr should not be equal")
	}
	if a.Equal(d) {
		t.Error("Equal: different port should not be equal")
	}
}

func TestAddressString(t *testing.T) {
	t.Parallel()

	a := Address{Port: 5683}
	s := a.String()
	if !strings.Contains(s, ":5683") {
		t.Errorf("String() = %q, want port suffix :5683", s)
	}
	if !strings.HasPrefix(s, "[") || !strings.Contains(s, "]") {
		t.Errorf("String() = %q, want bracket-enclosed address", s)
	}

	// Non-zero address.
	a2 := Address{Addr: [16]byte{0: 0x20, 1: 0x01, 2: 0x0d, 3: 0xb8, 15: 1}, Port: 80}
	s2 := a2.String()
	if !strings.HasPrefix(s2, "[2001:db8:") {
		t.Errorf("String() = %q, want to start with [2001:db8:", s2)
	}
}

// ---------------------------------------------------------------------------
// Handle tests
// ---------------------------------------------------------------------------

func TestHandleNewState(t *testing.T) {
	t.Parallel()

	h := NewHandle()
	if h.IsBound() {
		t.Error("new handle should not be bound")
	}
	if h.IsConnected() {
		t.Error("new handle should not be connected")
	}
	if !h.GetSockName().IsUnspecified() {
		t.Error("new handle sock name should be unspecified")
	}
	if !h.GetPeerName().IsUnspecified() {
		t.Error("new handle peer name should be unspecified")
	}
}

func TestHandleBindConnect(t *testing.T) {
	t.Parallel()

	h := NewHandle()
	local := Address{Port: 5683}
	peer := Address{Addr: [16]byte{15: 1}, Port: 853}

	if err := h.Bind(local); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if !h.IsBound() {
		t.Error("should be bound after Bind")
	}
	if h.GetSockName() != local {
		t.Errorf("GetSockName() = %v, want %v", h.GetSockName(), local)
	}

	// Double bind should fail.
	if err := h.Bind(local); err == nil {
		t.Error("expected error on double bind")
	}

	if err := h.Connect(peer); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if !h.IsConnected() {
		t.Error("should be connected after Connect")
	}
	if h.GetPeerName() != peer {
		t.Errorf("GetPeerName() = %v, want %v", h.GetPeerName(), peer)
	}

	// Double connect should fail.
	if err := h.Connect(peer); err == nil {
		t.Error("expected error on double connect")
	}
}

func TestHandleConnectRequiresBind(t *testing.T) {
	t.Parallel()

	h := NewHandle()
	peer := Address{Addr: [16]byte{15: 1}, Port: 853}
	if err := h.Connect(peer); err == nil {
		t.Error("expected error when connecting without bind")
	}
}

func TestHandleClose(t *testing.T) {
	t.Parallel()

	h := NewHandle()
	local := Address{Port: 5683}
	peer := Address{Addr: [16]byte{15: 1}, Port: 853}

	_ = h.Bind(local)
	_ = h.Connect(peer)

	h.Close()

	if h.IsBound() {
		t.Error("should not be bound after Close")
	}
	if h.IsConnected() {
		t.Error("should not be connected after Close")
	}
	if !h.GetSockName().IsUnspecified() {
		t.Error("sock name should be unspecified after Close")
	}
	if !h.GetPeerName().IsUnspecified() {
		t.Error("peer name should be unspecified after Close")
	}

	// Should be able to bind again after close.
	if err := h.Bind(local); err != nil {
		t.Fatalf("Bind after Close: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Muxer tests
// ---------------------------------------------------------------------------

func TestMuxerRegisterFind(t *testing.T) {
	t.Parallel()

	m := NewMuxer()
	h1 := NewHandle()
	h2 := NewHandle()

	if err := m.Register(h1, 5683); err != nil {
		t.Fatalf("Register h1: %v", err)
	}
	if err := m.Register(h2, 5684); err != nil {
		t.Fatalf("Register h2: %v", err)
	}
	if m.GetRegisteredCount() != 2 {
		t.Errorf("count = %d, want 2", m.GetRegisteredCount())
	}

	if got := m.FindHandler(5683); got != h1 {
		t.Error("FindHandler(5683) should return h1")
	}
	if got := m.FindHandler(5684); got != h2 {
		t.Error("FindHandler(5684) should return h2")
	}
	if got := m.FindHandler(9999); got != nil {
		t.Error("FindHandler(9999) should return nil")
	}
}

func TestMuxerDuplicatePort(t *testing.T) {
	t.Parallel()

	m := NewMuxer()
	h1 := NewHandle()
	h2 := NewHandle()

	if err := m.Register(h1, 5683); err != nil {
		t.Fatalf("Register h1: %v", err)
	}
	if err := m.Register(h2, 5683); err == nil {
		t.Error("expected error on duplicate port registration")
	}
}

func TestMuxerNilHandle(t *testing.T) {
	t.Parallel()

	m := NewMuxer()
	if err := m.Register(nil, 5683); err == nil {
		t.Error("expected error on nil handle")
	}
}

func TestMuxerUnregister(t *testing.T) {
	t.Parallel()

	m := NewMuxer()
	h1 := NewHandle()
	h2 := NewHandle()

	_ = m.Register(h1, 5683)
	_ = m.Register(h2, 5684)

	m.Unregister(h1)
	if m.GetRegisteredCount() != 1 {
		t.Errorf("count after unregister = %d, want 1", m.GetRegisteredCount())
	}
	if got := m.FindHandler(5683); got != nil {
		t.Error("FindHandler(5683) should return nil after unregister")
	}
	if got := m.FindHandler(5684); got != h2 {
		t.Error("FindHandler(5684) should still return h2")
	}

	// Unregister non-existent handle is a no-op.
	m.Unregister(h1)
	if m.GetRegisteredCount() != 1 {
		t.Errorf("count after second unregister = %d, want 1", m.GetRegisteredCount())
	}
}

func TestMuxerReRegisterAfterUnregister(t *testing.T) {
	t.Parallel()

	m := NewMuxer()
	h1 := NewHandle()
	h2 := NewHandle()

	_ = m.Register(h1, 5683)
	m.Unregister(h1)

	// Port should now be available.
	if err := m.Register(h2, 5683); err != nil {
		t.Fatalf("Re-register on freed port: %v", err)
	}
	if got := m.FindHandler(5683); got != h2 {
		t.Error("FindHandler(5683) should return h2 after re-register")
	}
}

func TestMuxerEmpty(t *testing.T) {
	t.Parallel()

	m := NewMuxer()
	if m.GetRegisteredCount() != 0 {
		t.Errorf("empty muxer count = %d, want 0", m.GetRegisteredCount())
	}
	if got := m.FindHandler(80); got != nil {
		t.Error("FindHandler on empty muxer should return nil")
	}
}
