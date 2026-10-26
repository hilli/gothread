// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package dhcp6pd

import (
	"testing"
	"time"

	"github.com/hilli/gothread/net/dhcp6"
)

// ---------------------------------------------------------------------------
// Mock platform
// ---------------------------------------------------------------------------

type mockPlatform struct {
	sent      []mockSentMsg
	listening bool
}

type mockSentMsg struct {
	payload []byte
	dst     [16]byte
}

func (m *mockPlatform) SendDhcp6(payload []byte, dst [16]byte) error {
	cp := make([]byte, len(payload))
	copy(cp, payload)
	m.sent = append(m.sent, mockSentMsg{payload: cp, dst: dst})
	return nil
}

func (m *mockPlatform) SetDhcp6ListeningEnabled(enabled bool) {
	m.listening = enabled
}

// ---------------------------------------------------------------------------
// Mock clock
// ---------------------------------------------------------------------------

type mockClock struct {
	now    int64
	timers []*mockTimer
	rng    int64
}

func (c *mockClock) NowMs() int64 { return c.now }

func (c *mockClock) NewTimer(fn func()) dhcp6.PdTimer {
	t := &mockTimer{fn: fn, clock: c}
	c.timers = append(c.timers, t)
	return t
}

func (c *mockClock) RandomInt63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	c.rng++
	return c.rng % n
}

type mockTimer struct {
	fn      func()
	clock   *mockClock
	pending bool
	expiry  int64
}

func (t *mockTimer) Reset(d time.Duration) {
	t.pending = true
	t.expiry = t.clock.now + d.Milliseconds()
}

func (t *mockTimer) Stop() bool {
	was := t.pending
	t.pending = false
	return was
}

// ---------------------------------------------------------------------------
// Tests: State
// ---------------------------------------------------------------------------

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateDisabled, "Disabled"},
		{StateStopped, "Stopped"},
		{StateRunning, "Running"},
		{State(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests: PrefixEntry
// ---------------------------------------------------------------------------

func TestPrefixEntryIsValid(t *testing.T) {
	var e PrefixEntry
	if e.IsValid() {
		t.Error("zero PrefixEntry should not be valid")
	}
	e.PrefixLength = 64
	if !e.IsValid() {
		t.Error("PrefixEntry with PrefixLength=64 should be valid")
	}
}

// ---------------------------------------------------------------------------
// Tests: Client lifecycle
// ---------------------------------------------------------------------------

func TestClientInitialState(t *testing.T) {
	plat := &mockPlatform{}
	cl := NewClient(plat, [8]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if cl.GetState() != StateDisabled {
		t.Fatalf("initial state = %v, want StateDisabled", cl.GetState())
	}
	if cl.IsEnabled() {
		t.Fatal("should not be enabled initially")
	}
}

func TestClientEnableDisable(t *testing.T) {
	plat := &mockPlatform{}
	cl := NewClient(plat, [8]byte{1, 2, 3, 4, 5, 6, 7, 8})

	// Enable.
	if !cl.Enable() {
		t.Fatal("Enable should return true")
	}
	if cl.GetState() != StateStopped {
		t.Fatalf("state after Enable = %v, want StateStopped", cl.GetState())
	}
	if !cl.IsEnabled() {
		t.Fatal("should be enabled after Enable")
	}

	// Enable again — no-op.
	if cl.Enable() {
		t.Fatal("Enable on non-disabled should return false")
	}

	// Disable.
	if !cl.Disable() {
		t.Fatal("Disable should return true")
	}
	if cl.GetState() != StateDisabled {
		t.Fatalf("state after Disable = %v, want StateDisabled", cl.GetState())
	}
	if cl.IsEnabled() {
		t.Fatal("should not be enabled after Disable")
	}

	// Disable again — no-op.
	if cl.Disable() {
		t.Fatal("Disable on disabled should return false")
	}
}

func TestClientStartStop(t *testing.T) {
	plat := &mockPlatform{}
	clock := &mockClock{now: 1000}
	cl := NewClient(plat, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, WithClock(clock))

	// Cannot start when disabled.
	if cl.Start() {
		t.Fatal("Start should return false when disabled")
	}

	cl.Enable()

	// Start.
	if !cl.Start() {
		t.Fatal("Start should return true")
	}
	if cl.GetState() != StateRunning {
		t.Fatalf("state after Start = %v, want StateRunning", cl.GetState())
	}

	// Start again — no-op.
	if cl.Start() {
		t.Fatal("Start on running should return false")
	}

	// Stop.
	if !cl.Stop() {
		t.Fatal("Stop should return true")
	}
	if cl.GetState() != StateStopped {
		t.Fatalf("state after Stop = %v, want StateStopped", cl.GetState())
	}

	// Stop again — no-op.
	if cl.Stop() {
		t.Fatal("Stop on stopped should return false")
	}
}

func TestClientStateCallback(t *testing.T) {
	plat := &mockPlatform{}
	clock := &mockClock{now: 1000}
	cl := NewClient(plat, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, WithClock(clock))

	var states []State
	cl.SetStateCallback(func(s State) {
		states = append(states, s)
	})

	cl.Enable()
	cl.Start()
	cl.Stop()
	cl.Disable()

	want := []State{StateStopped, StateRunning, StateStopped, StateDisabled}
	if len(states) != len(want) {
		t.Fatalf("got %d state changes, want %d", len(states), len(want))
	}
	for i, s := range states {
		if s != want[i] {
			t.Errorf("states[%d] = %v, want %v", i, s, want[i])
		}
	}
}

func TestClientDisableWhileRunning(t *testing.T) {
	plat := &mockPlatform{}
	clock := &mockClock{now: 1000}
	cl := NewClient(plat, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, WithClock(clock))

	cl.Enable()
	cl.Start()
	if cl.GetState() != StateRunning {
		t.Fatal("expected running")
	}

	cl.Disable()
	if cl.GetState() != StateDisabled {
		t.Fatalf("state = %v, want StateDisabled", cl.GetState())
	}
}

func TestClientGetPrefixNilWhenNone(t *testing.T) {
	plat := &mockPlatform{}
	cl := NewClient(plat, [8]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if cl.GetPrefix() != nil {
		t.Fatal("GetPrefix should be nil initially")
	}
}

func TestClientHandleReceiveWhenNotRunning(t *testing.T) {
	plat := &mockPlatform{}
	cl := NewClient(plat, [8]byte{1, 2, 3, 4, 5, 6, 7, 8})
	// Should not panic when not running.
	cl.HandleReceive([]byte{1, 2, 3}, [16]byte{})
}

// ---------------------------------------------------------------------------
// Tests: GenerateDUID
// ---------------------------------------------------------------------------

func TestGenerateDUID(t *testing.T) {
	extAddr := [8]byte{0x18, 0xb4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x01}
	duid := GenerateDUID(extAddr)
	if duid == nil {
		t.Fatal("GenerateDUID returned nil")
	}
	if len(duid) < 4 {
		t.Fatalf("DUID too short: %d bytes", len(duid))
	}
}

func TestGenerateDUIDDeterministic(t *testing.T) {
	extAddr := [8]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	duid1 := GenerateDUID(extAddr)
	duid2 := GenerateDUID(extAddr)
	if len(duid1) != len(duid2) {
		t.Fatal("DUID lengths differ")
	}
	for i := range duid1 {
		if duid1[i] != duid2[i] {
			t.Fatalf("DUID byte %d differs: %02x != %02x", i, duid1[i], duid2[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Tests: Sentinel errors
// ---------------------------------------------------------------------------

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{ErrNotEnabled, "dhcp6pd: not enabled"},
		{ErrNotRunning, "dhcp6pd: not running"},
		{ErrAlreadyRunning, "dhcp6pd: already running"},
	}

	for _, tt := range tests {
		if got := tt.err.Error(); got != tt.want {
			t.Errorf("error = %q, want %q", got, tt.want)
		}
	}
}
