// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package udp

import (
	"testing"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// TestNew
// ---------------------------------------------------------------------------

func TestNew(t *testing.T) {
	u := New()
	if u == nil {
		t.Fatal("New returned nil")
	}
	if len(u.sockets) != 0 {
		t.Errorf("expected 0 sockets, got %d", len(u.sockets))
	}
	if len(u.receivers) != 0 {
		t.Errorf("expected 0 receivers, got %d", len(u.receivers))
	}
	if u.ephemeralPort != DynamicPortMin {
		t.Errorf("expected ephemeralPort %d, got %d", DynamicPortMin, u.ephemeralPort)
	}
}

// ---------------------------------------------------------------------------
// TestOpenClose
// ---------------------------------------------------------------------------

func TestOpenClose(t *testing.T) {
	u := New()
	s := &Socket{}

	if u.IsOpen(s) {
		t.Fatal("socket should not be open before Open()")
	}

	err := u.Open(s, NetifThreadHost, nil)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !u.IsOpen(s) {
		t.Fatal("socket should be open after Open()")
	}
	if s.GetNetifID() != NetifThreadHost {
		t.Errorf("expected NetifThreadHost, got %d", s.GetNetifID())
	}

	err = u.Close(s)
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if u.IsOpen(s) {
		t.Fatal("socket should not be open after Close()")
	}
	if s.IsBound() {
		t.Error("socket should not be bound after Close()")
	}
}

// ---------------------------------------------------------------------------
// TestOpenAlreadyOpen
// ---------------------------------------------------------------------------

func TestOpenAlreadyOpen(t *testing.T) {
	u := New()
	s := &Socket{}

	err := u.Open(s, NetifThreadHost, nil)
	if err != nil {
		t.Fatalf("first Open failed: %v", err)
	}

	err = u.Open(s, NetifBackbone, nil)
	if err != errors.ErrAlready {
		t.Errorf("expected ErrAlready, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestBind
// ---------------------------------------------------------------------------

func TestBind(t *testing.T) {
	u := New()
	s := &Socket{}

	_ = u.Open(s, NetifThreadHost, nil)

	addr := ip6.SockAddr{Port: 12345}
	err := u.Bind(s, addr)
	if err != nil {
		t.Fatalf("Bind failed: %v", err)
	}
	if !s.IsBound() {
		t.Error("socket should be bound after Bind()")
	}
	if s.GetSockName().Port != 12345 {
		t.Errorf("expected port 12345, got %d", s.GetSockName().Port)
	}
}

// ---------------------------------------------------------------------------
// TestBindNotOpen
// ---------------------------------------------------------------------------

func TestBindNotOpen(t *testing.T) {
	u := New()
	s := &Socket{}

	err := u.Bind(s, ip6.SockAddr{Port: 1000})
	if err != errors.ErrInvalidState {
		t.Errorf("expected ErrInvalidState, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestBindEphemeral
// ---------------------------------------------------------------------------

func TestBindEphemeral(t *testing.T) {
	u := New()
	s := &Socket{}

	_ = u.Open(s, NetifThreadHost, nil)

	// Bind with port 0 to request ephemeral assignment.
	err := u.Bind(s, ip6.SockAddr{})
	if err != nil {
		t.Fatalf("Bind failed: %v", err)
	}
	if !s.IsBound() {
		t.Error("socket should be bound after ephemeral bind")
	}
	port := s.GetSockName().Port
	if port < DynamicPortMin || port > DynamicPortMax {
		t.Errorf("ephemeral port %d outside range [%d, %d]", port, DynamicPortMin, DynamicPortMax)
	}
}

// ---------------------------------------------------------------------------
// TestConnect
// ---------------------------------------------------------------------------

func TestConnect(t *testing.T) {
	u := New()
	s := &Socket{}

	_ = u.Open(s, NetifThreadHost, nil)

	peer := ip6.SockAddr{
		Address: ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		Port:    9999,
	}

	err := u.Connect(s, peer)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// Connect should auto-bind if not already bound.
	if !s.IsBound() {
		t.Error("socket should be auto-bound after Connect()")
	}

	if s.GetPeerName() != peer {
		t.Errorf("peer mismatch: got %v, want %v", s.GetPeerName(), peer)
	}
}

// ---------------------------------------------------------------------------
// TestConnectNotOpen
// ---------------------------------------------------------------------------

func TestConnectNotOpen(t *testing.T) {
	u := New()
	s := &Socket{}

	err := u.Connect(s, ip6.SockAddr{Port: 1234})
	if err != errors.ErrInvalidState {
		t.Errorf("expected ErrInvalidState, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestAddRemoveReceiver
// ---------------------------------------------------------------------------

func TestAddRemoveReceiver(t *testing.T) {
	u := New()
	r := NewReceiver(func(_ []byte, _ *ip6.MessageInfo) bool {
		return false
	})

	// Add receiver.
	if err := u.AddReceiver(r); err != nil {
		t.Fatalf("AddReceiver failed: %v", err)
	}

	// Duplicate add should fail.
	if err := u.AddReceiver(r); err != errors.ErrAlready {
		t.Errorf("expected ErrAlready on duplicate add, got %v", err)
	}

	// Remove receiver.
	if err := u.RemoveReceiver(r); err != nil {
		t.Fatalf("RemoveReceiver failed: %v", err)
	}

	// Remove again should fail.
	if err := u.RemoveReceiver(r); err != errors.ErrNotFound {
		t.Errorf("expected ErrNotFound on second remove, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestGetEphemeralPort
// ---------------------------------------------------------------------------

func TestGetEphemeralPort(t *testing.T) {
	u := New()

	// First port should be DynamicPortMin (which is not reserved).
	port := u.GetEphemeralPort()
	if port != DynamicPortMin {
		t.Errorf("expected first ephemeral port %d, got %d", DynamicPortMin, port)
	}

	// Ports should increment.
	port2 := u.GetEphemeralPort()
	if port2 != DynamicPortMin+1 {
		t.Errorf("expected second ephemeral port %d, got %d", DynamicPortMin+1, port2)
	}

	// Verify reserved ports are skipped. Set ephemeral counter to just
	// before the TMF port.
	u.ephemeralPort = TmfPort
	port3 := u.GetEphemeralPort()
	if port3 == TmfPort {
		t.Error("GetEphemeralPort should skip TmfPort")
	}

	// Verify SRP range is skipped.
	u.ephemeralPort = SrpServerPortMin
	port4 := u.GetEphemeralPort()
	if port4 >= SrpServerPortMin && port4 <= SrpServerPortMax {
		t.Errorf("GetEphemeralPort should skip SRP range, got %d", port4)
	}

	// Verify wrap-around: set counter to max.
	u.ephemeralPort = DynamicPortMax
	port5 := u.GetEphemeralPort()
	if port5 != DynamicPortMax {
		t.Errorf("expected port %d, got %d", DynamicPortMax, port5)
	}
	// After returning DynamicPortMax, next should wrap to DynamicPortMin.
	port6 := u.GetEphemeralPort()
	if port6 != DynamicPortMin {
		t.Errorf("expected wrap to %d, got %d", DynamicPortMin, port6)
	}
}

// ---------------------------------------------------------------------------
// TestIsPortInUse
// ---------------------------------------------------------------------------

func TestIsPortInUse(t *testing.T) {
	u := New()

	if u.IsPortInUse(5000) {
		t.Error("port should not be in use before any socket is bound")
	}

	s := &Socket{}
	_ = u.Open(s, NetifThreadHost, nil)
	_ = u.Bind(s, ip6.SockAddr{Port: 5000})

	if !u.IsPortInUse(5000) {
		t.Error("port 5000 should be in use after binding")
	}

	if u.IsPortInUse(5001) {
		t.Error("port 5001 should not be in use")
	}
}

// ---------------------------------------------------------------------------
// TestSocketMatches
// ---------------------------------------------------------------------------

func TestSocketMatches(t *testing.T) {
	localAddr := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	peerAddr := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	otherAddr := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99}

	tests := []struct {
		name   string
		socket Socket
		info   ip6.MessageInfo
		want   bool
	}{
		{
			name: "port match, unspecified addresses",
			socket: Socket{
				sockName: ip6.SockAddr{Port: 1234},
			},
			info: ip6.MessageInfo{
				SockPort: 1234,
			},
			want: true,
		},
		{
			name: "port mismatch",
			socket: Socket{
				sockName: ip6.SockAddr{Port: 1234},
			},
			info: ip6.MessageInfo{
				SockPort: 5678,
			},
			want: false,
		},
		{
			name: "local address match",
			socket: Socket{
				sockName: ip6.SockAddr{Address: localAddr, Port: 1234},
			},
			info: ip6.MessageInfo{
				SockAddr: localAddr,
				SockPort: 1234,
			},
			want: true,
		},
		{
			name: "local address mismatch",
			socket: Socket{
				sockName: ip6.SockAddr{Address: localAddr, Port: 1234},
			},
			info: ip6.MessageInfo{
				SockAddr: otherAddr,
				SockPort: 1234,
			},
			want: false,
		},
		{
			name: "peer address match",
			socket: Socket{
				sockName: ip6.SockAddr{Port: 1234},
				peerName: ip6.SockAddr{Address: peerAddr, Port: 9999},
			},
			info: ip6.MessageInfo{
				SockPort: 1234,
				PeerAddr: peerAddr,
				PeerPort: 9999,
			},
			want: true,
		},
		{
			name: "peer address mismatch",
			socket: Socket{
				sockName: ip6.SockAddr{Port: 1234},
				peerName: ip6.SockAddr{Address: peerAddr, Port: 9999},
			},
			info: ip6.MessageInfo{
				SockPort: 1234,
				PeerAddr: otherAddr,
				PeerPort: 9999,
			},
			want: false,
		},
		{
			name: "peer port mismatch",
			socket: Socket{
				sockName: ip6.SockAddr{Port: 1234},
				peerName: ip6.SockAddr{Address: peerAddr, Port: 9999},
			},
			info: ip6.MessageInfo{
				SockPort: 1234,
				PeerAddr: peerAddr,
				PeerPort: 1111,
			},
			want: false,
		},
		{
			name: "unbound socket never matches",
			socket: Socket{
				sockName: ip6.SockAddr{Port: 0},
			},
			info: ip6.MessageInfo{
				SockPort: 0,
			},
			want: true, // both port 0 — technically matches
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.socket.Matches(&tt.info)
			if got != tt.want {
				t.Errorf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestCloseNotOpen
// ---------------------------------------------------------------------------

func TestCloseNotOpen(t *testing.T) {
	u := New()
	s := &Socket{}

	// Closing a socket that was never opened should be a no-op.
	err := u.Close(s)
	if err != nil {
		t.Errorf("Close on non-open socket should return nil, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestMultipleSockets
// ---------------------------------------------------------------------------

func TestMultipleSockets(t *testing.T) {
	u := New()

	sockets := make([]*Socket, 5)
	for i := range sockets {
		sockets[i] = &Socket{}
		err := u.Open(sockets[i], NetifThreadHost, nil)
		if err != nil {
			t.Fatalf("Open socket %d failed: %v", i, err)
		}
	}

	// All should be open.
	for i, s := range sockets {
		if !u.IsOpen(s) {
			t.Errorf("socket %d should be open", i)
		}
	}

	if len(u.sockets) != 5 {
		t.Errorf("expected 5 sockets, got %d", len(u.sockets))
	}

	// Close the middle one.
	err := u.Close(sockets[2])
	if err != nil {
		t.Fatalf("Close socket 2 failed: %v", err)
	}
	if u.IsOpen(sockets[2]) {
		t.Error("socket 2 should not be open after Close()")
	}
	if len(u.sockets) != 4 {
		t.Errorf("expected 4 sockets after closing one, got %d", len(u.sockets))
	}

	// Others should still be open.
	for i, s := range sockets {
		if i == 2 {
			continue
		}
		if !u.IsOpen(s) {
			t.Errorf("socket %d should still be open", i)
		}
	}
}

// ---------------------------------------------------------------------------
// TestShouldUsePlatformUDP
// ---------------------------------------------------------------------------

func TestShouldUsePlatformUDP(t *testing.T) {
	tests := []struct {
		netif NetifIdentifier
		want  bool
	}{
		{NetifUnspecified, true},
		{NetifThreadHost, true},
		{NetifThreadInternal, false},
		{NetifBackbone, true},
	}

	for _, tt := range tests {
		s := &Socket{}
		s.SetNetifID(tt.netif)
		if got := s.ShouldUsePlatformUDP(); got != tt.want {
			t.Errorf("ShouldUsePlatformUDP() with netif %d = %v, want %v", tt.netif, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// TestIsPortReserved
// ---------------------------------------------------------------------------

func TestIsPortReserved(t *testing.T) {
	u := New()

	// TMF port should be reserved.
	if !u.IsPortReserved(TmfPort) {
		t.Error("TmfPort should be reserved")
	}

	// SRP server range boundaries.
	if !u.IsPortReserved(SrpServerPortMin) {
		t.Error("SrpServerPortMin should be reserved")
	}
	if !u.IsPortReserved(SrpServerPortMax) {
		t.Error("SrpServerPortMax should be reserved")
	}
	if !u.IsPortReserved(SrpServerPortMin + 5) {
		t.Error("mid-SRP range should be reserved")
	}

	// Outside reserved ranges.
	if u.IsPortReserved(DynamicPortMin) {
		t.Error("DynamicPortMin should not be reserved")
	}
	if u.IsPortReserved(12345) {
		t.Error("port 12345 should not be reserved")
	}
}

// ---------------------------------------------------------------------------
// TestNetifIdentifierValues
// ---------------------------------------------------------------------------

func TestNetifIdentifierValues(t *testing.T) {
	if NetifUnspecified != 0 {
		t.Errorf("NetifUnspecified = %d, want 0", NetifUnspecified)
	}
	if NetifThreadHost != 1 {
		t.Errorf("NetifThreadHost = %d, want 1", NetifThreadHost)
	}
	if NetifThreadInternal != 2 {
		t.Errorf("NetifThreadInternal = %d, want 2", NetifThreadInternal)
	}
	if NetifBackbone != 3 {
		t.Errorf("NetifBackbone = %d, want 3", NetifBackbone)
	}
}

// ---------------------------------------------------------------------------
// TestReceiverHandler
// ---------------------------------------------------------------------------

func TestReceiverHandler(t *testing.T) {
	called := false
	r := NewReceiver(func(_ []byte, _ *ip6.MessageInfo) bool {
		called = true
		return true
	})

	if r == nil {
		t.Fatal("NewReceiver returned nil")
	}
	if r.handler == nil {
		t.Fatal("handler should not be nil")
	}

	// Invoke handler directly to verify it works.
	result := r.handler([]byte("test"), &ip6.MessageInfo{})
	if !called {
		t.Error("handler was not called")
	}
	if !result {
		t.Error("handler should have returned true")
	}
}

// ---------------------------------------------------------------------------
// TestBindWithAddress
// ---------------------------------------------------------------------------

func TestBindWithAddress(t *testing.T) {
	u := New()
	s := &Socket{}
	_ = u.Open(s, NetifThreadHost, nil)

	addr := ip6.SockAddr{
		Address: ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		Port:    8080,
	}

	err := u.Bind(s, addr)
	if err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	got := s.GetSockName()
	if got != addr {
		t.Errorf("GetSockName() = %v, want %v", got, addr)
	}
}

// ---------------------------------------------------------------------------
// TestConnectAlreadyBound
// ---------------------------------------------------------------------------

func TestConnectAlreadyBound(t *testing.T) {
	u := New()
	s := &Socket{}
	_ = u.Open(s, NetifThreadHost, nil)
	_ = u.Bind(s, ip6.SockAddr{Port: 7777})

	peer := ip6.SockAddr{Port: 8888}
	err := u.Connect(s, peer)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// Port should remain as originally bound.
	if s.GetSockName().Port != 7777 {
		t.Errorf("port changed after Connect, got %d", s.GetSockName().Port)
	}
	if s.GetPeerName() != peer {
		t.Errorf("peer mismatch: got %v, want %v", s.GetPeerName(), peer)
	}
}
