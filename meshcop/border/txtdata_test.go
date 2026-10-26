// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package border

import (
	"bytes"
	"testing"
	"time"
)

func TestTxtDataSetGet(t *testing.T) {
	td := NewTxtData()

	td.Set("foo", []byte("bar"))
	got := td.Get("foo")
	if string(got) != "bar" {
		t.Errorf("Get(foo) = %q, want %q", got, "bar")
	}

	// Missing key.
	if v := td.Get("missing"); v != nil {
		t.Errorf("Get(missing) = %v, want nil", v)
	}
}

func TestTxtDataHas(t *testing.T) {
	td := NewTxtData()

	if td.Has("x") {
		t.Error("Has(x) should be false initially")
	}

	td.Set("x", []byte("1"))
	if !td.Has("x") {
		t.Error("Has(x) should be true after Set")
	}
}

func TestTxtDataReplace(t *testing.T) {
	td := NewTxtData()

	td.Set("key", []byte("v1"))
	td.Set("key", []byte("v2"))

	if string(td.Get("key")) != "v2" {
		t.Errorf("Get(key) = %q, want %q", td.Get("key"), "v2")
	}

	entries := td.Entries()
	count := 0
	for _, e := range entries {
		if e.Key == "key" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 entry for key, got %d", count)
	}
}

func TestTxtDataRemove(t *testing.T) {
	td := NewTxtData()
	td.Set("a", []byte("1"))
	td.Set("b", []byte("2"))

	td.Remove("a")
	if td.Has("a") {
		t.Error("key 'a' should be removed")
	}
	if !td.Has("b") {
		t.Error("key 'b' should still exist")
	}

	// Remove non-existent — no panic.
	td.Remove("nonexistent")
}

func TestTxtDataEncodeDecodeRoundTrip(t *testing.T) {
	td := NewTxtData()
	td.Set("nn", []byte("MyNetwork"))
	td.Set("vn", []byte("Vendor"))
	td.Set("tv", []byte("1.3"))

	encoded := td.Encode()

	td2 := NewTxtData()
	if err := td2.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	for _, key := range []string{"nn", "vn", "tv"} {
		orig := td.Get(key)
		decoded := td2.Get(key)
		if !bytes.Equal(orig, decoded) {
			t.Errorf("key %q: orig=%q, decoded=%q", key, orig, decoded)
		}
	}
}

func TestTxtDataDecodeEmpty(t *testing.T) {
	td := NewTxtData()
	if err := td.Decode(nil); err != nil {
		t.Fatalf("Decode(nil): %v", err)
	}
	if len(td.Entries()) != 0 {
		t.Error("expected 0 entries for empty data")
	}
}

func TestTxtDataDecodeTruncated(t *testing.T) {
	// Length byte says 10 but only 2 bytes follow.
	td := NewTxtData()
	err := td.Decode([]byte{10, 'a', 'b'})
	if err == nil {
		t.Error("expected error for truncated data")
	}
}

func TestTxtDataDecodeBooleanKey(t *testing.T) {
	// Encode a boolean key (no '=' in the entry).
	data := []byte{3, 'f', 'o', 'o'}
	td := NewTxtData()
	if err := td.Decode(data); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !td.Has("foo") {
		t.Error("should have key 'foo'")
	}
	if td.Get("foo") != nil {
		t.Error("boolean key should have nil value")
	}
}

func TestTxtDataEncodeEmptyValue(t *testing.T) {
	td := NewTxtData()
	td.Set("k", []byte{})

	encoded := td.Encode()

	td2 := NewTxtData()
	if err := td2.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	v := td2.Get("k")
	if v == nil {
		t.Error("key 'k' should be present")
	}
	if len(v) != 0 {
		t.Errorf("value length = %d, want 0", len(v))
	}
}

// ---------------------------------------------------------------------------
// Typed getter/setter tests
// ---------------------------------------------------------------------------

func TestTxtDataNetworkName(t *testing.T) {
	td := NewTxtData()
	td.SetNetworkName("TestNet")
	if got := td.GetNetworkName(); got != "TestNet" {
		t.Errorf("GetNetworkName = %q, want %q", got, "TestNet")
	}

	// Not set.
	td2 := NewTxtData()
	if got := td2.GetNetworkName(); got != "" {
		t.Errorf("GetNetworkName = %q, want empty", got)
	}
}

func TestTxtDataExtPanID(t *testing.T) {
	td := NewTxtData()
	id := [8]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x12, 0x34}
	td.SetExtPanID(id)

	got := td.GetExtPanID()
	if got != id {
		t.Errorf("GetExtPanID = %x, want %x", got, id)
	}
}

func TestTxtDataThreadVersion(t *testing.T) {
	td := NewTxtData()
	td.SetThreadVersion("1.3.0")
	if got := td.GetThreadVersion(); got != "1.3.0" {
		t.Errorf("GetThreadVersion = %q, want %q", got, "1.3.0")
	}
}

func TestTxtDataVendorName(t *testing.T) {
	td := NewTxtData()
	td.SetVendorName("ACME Corp")
	if got := td.GetVendorName(); got != "ACME Corp" {
		t.Errorf("GetVendorName = %q, want %q", got, "ACME Corp")
	}
}

func TestTxtDataModelName(t *testing.T) {
	td := NewTxtData()
	td.SetModelName("Router-X")
	if got := td.GetModelName(); got != "Router-X" {
		t.Errorf("GetModelName = %q, want %q", got, "Router-X")
	}
}

func TestTxtDataActiveTimestamp(t *testing.T) {
	td := NewTxtData()
	td.SetActiveTimestamp(0x123456789ABCDEF0)

	got := td.GetActiveTimestamp()
	if got != 0x123456789ABCDEF0 {
		t.Errorf("GetActiveTimestamp = %x, want %x", got, uint64(0x123456789ABCDEF0))
	}

	// Not set.
	td2 := NewTxtData()
	if got := td2.GetActiveTimestamp(); got != 0 {
		t.Errorf("GetActiveTimestamp = %d, want 0", got)
	}
}

func TestTxtDataPartitionID(t *testing.T) {
	td := NewTxtData()
	td.SetPartitionID(0xDEADBEEF)

	got := td.GetPartitionID()
	if got != 0xDEADBEEF {
		t.Errorf("GetPartitionID = %x, want %x", got, uint32(0xDEADBEEF))
	}
}

func TestTxtDataSequenceNumber(t *testing.T) {
	td := NewTxtData()
	td.SetSequenceNumber(42)

	got := td.GetSequenceNumber()
	if got != 42 {
		t.Errorf("GetSequenceNumber = %d, want %d", got, 42)
	}
}

func TestTxtDataStateBitmap(t *testing.T) {
	td := NewTxtData()
	td.SetStateBitmap(0x00010203)

	got := td.GetStateBitmap()
	if got != 0x00010203 {
		t.Errorf("GetStateBitmap = %x, want %x", got, uint32(0x00010203))
	}
}

func TestTxtDataDiscriminator(t *testing.T) {
	td := NewTxtData()
	disc := []byte{0xAB, 0xCD}
	td.SetDiscriminator(disc)

	got := td.GetDiscriminator()
	if len(got) != 2 || got[0] != 0xAB || got[1] != 0xCD {
		t.Errorf("GetDiscriminator = %x, want %x", got, disc)
	}
}

func TestTxtDataBorderAgentID(t *testing.T) {
	td := NewTxtData()
	id := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	td.SetBorderAgentID(id)

	got := td.GetBorderAgentID()
	if len(got) != 16 {
		t.Fatalf("GetBorderAgentID length = %d, want 16", len(got))
	}
	for i, b := range got {
		if b != id[i] {
			t.Errorf("byte %d: got %02x, want %02x", i, b, id[i])
		}
	}
}

func TestTxtDataFullRoundTrip(t *testing.T) {
	td := NewTxtData()
	td.SetNetworkName("OpenThread")
	td.SetExtPanID([8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	td.SetThreadVersion("1.3")
	td.SetVendorName("TestVendor")
	td.SetModelName("TestModel")
	td.SetActiveTimestamp(12345)
	td.SetPartitionID(99)
	td.SetSequenceNumber(7)
	td.SetStateBitmap(0xFF)

	encoded := td.Encode()

	td2 := NewTxtData()
	if err := td2.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if td2.GetNetworkName() != "OpenThread" {
		t.Errorf("NetworkName = %q", td2.GetNetworkName())
	}
	if td2.GetThreadVersion() != "1.3" {
		t.Errorf("ThreadVersion = %q", td2.GetThreadVersion())
	}
	if td2.GetVendorName() != "TestVendor" {
		t.Errorf("VendorName = %q", td2.GetVendorName())
	}
	if td2.GetModelName() != "TestModel" {
		t.Errorf("ModelName = %q", td2.GetModelName())
	}
	if td2.GetActiveTimestamp() != 12345 {
		t.Errorf("ActiveTimestamp = %d", td2.GetActiveTimestamp())
	}
	if td2.GetPartitionID() != 99 {
		t.Errorf("PartitionID = %d", td2.GetPartitionID())
	}
	if td2.GetSequenceNumber() != 7 {
		t.Errorf("SequenceNumber = %d", td2.GetSequenceNumber())
	}
	if td2.GetStateBitmap() != 0xFF {
		t.Errorf("StateBitmap = %x", td2.GetStateBitmap())
	}
}

func TestTrackerStateString(t *testing.T) {
	tests := []struct {
		s    TrackerState
		want string
	}{
		{StateDisconnected, "Disconnected"},
		{StateConnecting, "Connecting"},
		{StateConnected, "Connected"},
		{TrackerState(99), "TrackerState(99)"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("TrackerState(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestTrackerStateMachine(t *testing.T) {
	tr := NewTracker()

	if tr.GetState() != StateDisconnected {
		t.Errorf("initial state = %s, want Disconnected", tr.GetState())
	}

	peer := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	var lastState TrackerState
	tr.SetStateCallback(func(state TrackerState) {
		lastState = state
	})

	tr.HandleConnecting(peer)
	if tr.GetState() != StateConnecting {
		t.Errorf("state = %s, want Connecting", tr.GetState())
	}
	if lastState != StateConnecting {
		t.Errorf("callback state = %s, want Connecting", lastState)
	}
	if tr.GetPeerAddress() != peer {
		t.Errorf("peer address mismatch")
	}

	tr.HandleConnected(peer)
	if tr.GetState() != StateConnected {
		t.Errorf("state = %s, want Connected", tr.GetState())
	}

	tr.HandleDisconnected()
	if tr.GetState() != StateDisconnected {
		t.Errorf("state = %s, want Disconnected", tr.GetState())
	}
	if tr.GetPeerAddress() != ([16]byte{}) {
		t.Error("peer address should be zero after disconnect")
	}
}

func TestEphemeralKeyManager(t *testing.T) {
	m := NewEphemeralKeyManager()

	if m.IsActive() {
		t.Error("should not be active initially")
	}
	if m.GetPort() != 0 {
		t.Errorf("GetPort = %d, want 0", m.GetPort())
	}
	if m.GetKey() != "" {
		t.Errorf("GetKey = %q, want empty", m.GetKey())
	}
}

func TestEphemeralKeyStartStop(t *testing.T) {
	m := NewEphemeralKeyManager()

	err := m.Start("mysecretkey", 12345, DefaultTimeout)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !m.IsActive() {
		t.Error("should be active after Start")
	}
	if m.GetPort() != 12345 {
		t.Errorf("GetPort = %d, want 12345", m.GetPort())
	}
	if m.GetKey() != "mysecretkey" {
		t.Errorf("GetKey = %q, want %q", m.GetKey(), "mysecretkey")
	}

	// Double start fails.
	if err := m.Start("other", 99, 0); err == nil {
		t.Error("double Start should return error")
	}

	m.Stop()
	if m.IsActive() {
		t.Error("should not be active after Stop")
	}
	if m.GetKey() != "" {
		t.Errorf("GetKey = %q, want empty after Stop", m.GetKey())
	}
}

func TestEphemeralKeyValidation(t *testing.T) {
	m := NewEphemeralKeyManager()

	// Too short.
	if err := m.Start("12345", 1000, 0); err == nil {
		t.Error("should reject key shorter than MinKeyLength")
	}

	// Too long.
	longKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 34 chars > 32
	if err := m.Start(longKey, 1000, 0); err == nil {
		t.Error("should reject key longer than MaxKeyLength")
	}

	// Exact min length.
	if err := m.Start("123456", 1000, 0); err != nil {
		t.Fatalf("Start with min length: %v", err)
	}
	m.Stop()
}

func TestEphemeralKeyDefaultTimeout(t *testing.T) {
	m := NewEphemeralKeyManager()

	// Timeout 0 should use DefaultTimeout.
	err := m.Start("validkey", 8000, 0)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !m.IsActive() {
		t.Error("should be active")
	}
	m.Stop()
}

func TestEphemeralKeyStoppedCallback(t *testing.T) {
	m := NewEphemeralKeyManager()

	called := false
	m.SetStoppedCallback(func() {
		called = true
	})

	_ = m.Start("123456", 9000, DefaultTimeout)
	m.Stop()

	if !called {
		t.Error("stopped callback should have been called")
	}
}

func TestEphemeralKeyHandleTimeout(t *testing.T) {
	m := NewEphemeralKeyManager()

	called := false
	m.SetStoppedCallback(func() {
		called = true
	})

	// Override afterFunc to capture the timer callback.
	var timerCB func()
	m.afterFunc = func(d time.Duration, f func()) Timer {
		timerCB = f
		return &noopTimer{}
	}

	_ = m.Start("123456", 9000, DefaultTimeout)

	// Simulate timeout.
	if timerCB != nil {
		timerCB()
	}

	if m.IsActive() {
		t.Error("should not be active after timeout")
	}
	if !called {
		t.Error("stopped callback should have been called on timeout")
	}
}

// noopTimer implements Timer for testing.
type noopTimer struct{}

func (t *noopTimer) Stop() bool { return false }
