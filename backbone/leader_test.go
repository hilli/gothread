// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package backbone

import (
	"testing"

	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

type leaderCBRecorder struct {
	primaryStates  []LeaderState
	primaryConfigs []Config
	domainEvents   []DomainPrefixEvent
	domainPrefixes []ip6.Prefix
}

func (r *leaderCBRecorder) OnPrimaryUpdated(state LeaderState, config Config) {
	r.primaryStates = append(r.primaryStates, state)
	r.primaryConfigs = append(r.primaryConfigs, config)
}

func (r *leaderCBRecorder) OnDomainPrefixUpdated(event DomainPrefixEvent, prefix ip6.Prefix) {
	r.domainEvents = append(r.domainEvents, event)
	r.domainPrefixes = append(r.domainPrefixes, prefix)
}

func testPrefix(b byte, length uint8) ip6.Prefix {
	var addr [16]byte
	addr[0] = b
	return ip6.NewPrefix(addr, length)
}

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------

func TestLeader_InitialStateNoPrimary(t *testing.T) {
	l := NewLeader(nil)
	if l.HasPrimary() {
		t.Fatal("expected no primary after NewLeader")
	}
	if l.GetServer16() != InvalidServer16 {
		t.Fatalf("Server16 = 0x%04x, want 0x%04x", l.GetServer16(), InvalidServer16)
	}
}

func TestLeader_InitialStateNoDomainPrefix(t *testing.T) {
	l := NewLeader(nil)
	if l.HasDomainPrefix() {
		t.Fatal("expected no domain prefix after NewLeader")
	}
}

func TestLeader_InitialServiceID(t *testing.T) {
	l := NewLeader(nil)
	if l.GetServiceID() != 0 {
		t.Fatalf("ServiceID = %d, want 0", l.GetServiceID())
	}
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

func TestLeader_ResetClearsPrimary(t *testing.T) {
	l := NewLeader(nil)
	cfg := Config{Server16: 0x0400, SequenceNumber: 10, MlrTimeout: 3600}
	l.UpdatePrimary(&cfg)
	l.Reset()
	if l.HasPrimary() {
		t.Fatal("expected no primary after Reset")
	}
}

func TestLeader_ResetClearsDomainPrefix(t *testing.T) {
	l := NewLeader(nil)
	p := testPrefix(0xfd, 64)
	l.UpdateDomainPrefix(&p)
	l.Reset()
	if l.HasDomainPrefix() {
		t.Fatal("expected no domain prefix after Reset")
	}
}

// ---------------------------------------------------------------------------
// GetServiceID / SetServiceID
// ---------------------------------------------------------------------------

func TestLeader_SetGetServiceID(t *testing.T) {
	l := NewLeader(nil)
	l.SetServiceID(42)
	if l.GetServiceID() != 42 {
		t.Fatalf("ServiceID = %d, want 42", l.GetServiceID())
	}
}

// ---------------------------------------------------------------------------
// UpdatePrimary — Added
// ---------------------------------------------------------------------------

func TestLeader_UpdatePrimary_Added(t *testing.T) {
	rec := &leaderCBRecorder{}
	l := NewLeader(rec)

	cfg := Config{Server16: 0x0400, SequenceNumber: 1, ReregistrationDelay: 5, MlrTimeout: 3600}
	l.UpdatePrimary(&cfg)

	if len(rec.primaryStates) != 1 || rec.primaryStates[0] != LeaderStateAdded {
		t.Fatalf("state = %v, want [LeaderStateAdded]", rec.primaryStates)
	}
	if !l.HasPrimary() {
		t.Fatal("expected HasPrimary after add")
	}
}

// ---------------------------------------------------------------------------
// UpdatePrimary — Removed
// ---------------------------------------------------------------------------

func TestLeader_UpdatePrimary_Removed(t *testing.T) {
	rec := &leaderCBRecorder{}
	l := NewLeader(rec)

	cfg := Config{Server16: 0x0400, SequenceNumber: 1, MlrTimeout: 3600}
	l.UpdatePrimary(&cfg)

	l.UpdatePrimary(nil)

	if len(rec.primaryStates) != 2 || rec.primaryStates[1] != LeaderStateRemoved {
		t.Fatalf("states = %v, want [Added, Removed]", rec.primaryStates)
	}
	if l.HasPrimary() {
		t.Fatal("expected no primary after removal")
	}
}

// ---------------------------------------------------------------------------
// UpdatePrimary — None (no primary both times)
// ---------------------------------------------------------------------------

func TestLeader_UpdatePrimary_NoneBothTimes(t *testing.T) {
	rec := &leaderCBRecorder{}
	l := NewLeader(rec)

	l.UpdatePrimary(nil)

	if len(rec.primaryStates) != 1 || rec.primaryStates[0] != LeaderStateNone {
		t.Fatalf("state = %v, want [LeaderStateNone]", rec.primaryStates)
	}
}

// ---------------------------------------------------------------------------
// UpdatePrimary — Unchanged
// ---------------------------------------------------------------------------

func TestLeader_UpdatePrimary_Unchanged(t *testing.T) {
	rec := &leaderCBRecorder{}
	l := NewLeader(rec)

	cfg := Config{Server16: 0x0400, SequenceNumber: 1, ReregistrationDelay: 5, MlrTimeout: 3600}
	l.UpdatePrimary(&cfg)
	l.UpdatePrimary(&cfg)

	if len(rec.primaryStates) != 2 || rec.primaryStates[1] != LeaderStateUnchanged {
		t.Fatalf("states = %v, want [Added, Unchanged]", rec.primaryStates)
	}
}

// ---------------------------------------------------------------------------
// UpdatePrimary — ToTriggerRereg (RLOC16 changed)
// ---------------------------------------------------------------------------

func TestLeader_UpdatePrimary_Rloc16Change(t *testing.T) {
	rec := &leaderCBRecorder{}
	l := NewLeader(rec)

	cfg1 := Config{Server16: 0x0400, SequenceNumber: 1, MlrTimeout: 3600}
	l.UpdatePrimary(&cfg1)

	cfg2 := Config{Server16: 0x0800, SequenceNumber: 1, MlrTimeout: 3600}
	l.UpdatePrimary(&cfg2)

	if rec.primaryStates[1] != LeaderStateToTriggerRereg {
		t.Fatalf("state = %d, want LeaderStateToTriggerRereg", rec.primaryStates[1])
	}
}

// ---------------------------------------------------------------------------
// UpdatePrimary — ToTriggerRereg (sequence number changed)
// ---------------------------------------------------------------------------

func TestLeader_UpdatePrimary_SeqNumChange(t *testing.T) {
	rec := &leaderCBRecorder{}
	l := NewLeader(rec)

	cfg1 := Config{Server16: 0x0400, SequenceNumber: 1, MlrTimeout: 3600}
	l.UpdatePrimary(&cfg1)

	cfg2 := Config{Server16: 0x0400, SequenceNumber: 2, MlrTimeout: 3600}
	l.UpdatePrimary(&cfg2)

	if rec.primaryStates[1] != LeaderStateToTriggerRereg {
		t.Fatalf("state = %d, want LeaderStateToTriggerRereg", rec.primaryStates[1])
	}
}

// ---------------------------------------------------------------------------
// UpdatePrimary — Refreshed (timeout changed)
// ---------------------------------------------------------------------------

func TestLeader_UpdatePrimary_Refreshed_TimeoutChange(t *testing.T) {
	rec := &leaderCBRecorder{}
	l := NewLeader(rec)

	cfg1 := Config{Server16: 0x0400, SequenceNumber: 1, ReregistrationDelay: 5, MlrTimeout: 3600}
	l.UpdatePrimary(&cfg1)

	cfg2 := Config{Server16: 0x0400, SequenceNumber: 1, ReregistrationDelay: 5, MlrTimeout: 7200}
	l.UpdatePrimary(&cfg2)

	if rec.primaryStates[1] != LeaderStateRefreshed {
		t.Fatalf("state = %d, want LeaderStateRefreshed", rec.primaryStates[1])
	}
}

// ---------------------------------------------------------------------------
// UpdatePrimary — Refreshed (delay changed)
// ---------------------------------------------------------------------------

func TestLeader_UpdatePrimary_Refreshed_DelayChange(t *testing.T) {
	rec := &leaderCBRecorder{}
	l := NewLeader(rec)

	cfg1 := Config{Server16: 0x0400, SequenceNumber: 1, ReregistrationDelay: 5, MlrTimeout: 3600}
	l.UpdatePrimary(&cfg1)

	cfg2 := Config{Server16: 0x0400, SequenceNumber: 1, ReregistrationDelay: 10, MlrTimeout: 3600}
	l.UpdatePrimary(&cfg2)

	if rec.primaryStates[1] != LeaderStateRefreshed {
		t.Fatalf("state = %d, want LeaderStateRefreshed", rec.primaryStates[1])
	}
}

// ---------------------------------------------------------------------------
// UpdatePrimary — MlrTimeout clamping
// ---------------------------------------------------------------------------

func TestLeader_UpdatePrimary_ClampMlrTimeoutMin(t *testing.T) {
	l := NewLeader(nil)
	cfg := Config{Server16: 0x0400, MlrTimeout: 100} // below min
	l.UpdatePrimary(&cfg)
	if l.GetConfig().MlrTimeout != MinMlrTimeout {
		t.Fatalf("MlrTimeout = %d, want %d", l.GetConfig().MlrTimeout, MinMlrTimeout)
	}
}

func TestLeader_UpdatePrimary_ClampMlrTimeoutMax(t *testing.T) {
	l := NewLeader(nil)
	cfg := Config{Server16: 0x0400, MlrTimeout: MaxMlrTimeout + 1000}
	l.UpdatePrimary(&cfg)
	if l.GetConfig().MlrTimeout != MaxMlrTimeout {
		t.Fatalf("MlrTimeout = %d, want %d", l.GetConfig().MlrTimeout, MaxMlrTimeout)
	}
}

func TestLeader_UpdatePrimary_NoClamWhenRemoved(t *testing.T) {
	l := NewLeader(nil)
	// When no primary, MlrTimeout is not clamped.
	l.UpdatePrimary(nil)
	if l.GetConfig().MlrTimeout != 0 {
		t.Fatalf("MlrTimeout = %d, want 0 when no primary", l.GetConfig().MlrTimeout)
	}
}

// ---------------------------------------------------------------------------
// UpdatePrimary — nil callbacks
// ---------------------------------------------------------------------------

func TestLeader_UpdatePrimary_NilCallbacks(t *testing.T) {
	l := NewLeader(nil) // no callbacks
	cfg := Config{Server16: 0x0400, MlrTimeout: 3600}
	l.UpdatePrimary(&cfg) // should not panic
	l.UpdatePrimary(nil)  // should not panic
}

// ---------------------------------------------------------------------------
// UpdateDomainPrefix — Added
// ---------------------------------------------------------------------------

func TestLeader_UpdateDomainPrefix_Added(t *testing.T) {
	rec := &leaderCBRecorder{}
	l := NewLeader(rec)

	p := testPrefix(0xfd, 64)
	l.UpdateDomainPrefix(&p)

	if len(rec.domainEvents) != 1 || rec.domainEvents[0] != DomainPrefixAdded {
		t.Fatalf("events = %v, want [DomainPrefixAdded]", rec.domainEvents)
	}
	if !l.HasDomainPrefix() {
		t.Fatal("expected HasDomainPrefix after add")
	}
}

// ---------------------------------------------------------------------------
// UpdateDomainPrefix — Removed
// ---------------------------------------------------------------------------

func TestLeader_UpdateDomainPrefix_Removed(t *testing.T) {
	rec := &leaderCBRecorder{}
	l := NewLeader(rec)

	p := testPrefix(0xfd, 64)
	l.UpdateDomainPrefix(&p)
	l.UpdateDomainPrefix(nil)

	if len(rec.domainEvents) != 2 || rec.domainEvents[1] != DomainPrefixRemoved {
		t.Fatalf("events = %v, want [Added, Removed]", rec.domainEvents)
	}
	if l.HasDomainPrefix() {
		t.Fatal("expected no domain prefix after removal")
	}
}

// ---------------------------------------------------------------------------
// UpdateDomainPrefix — Unchanged
// ---------------------------------------------------------------------------

func TestLeader_UpdateDomainPrefix_Unchanged(t *testing.T) {
	rec := &leaderCBRecorder{}
	l := NewLeader(rec)

	p := testPrefix(0xfd, 64)
	l.UpdateDomainPrefix(&p)
	l.UpdateDomainPrefix(&p)

	if rec.domainEvents[1] != DomainPrefixUnchanged {
		t.Fatalf("event = %d, want DomainPrefixUnchanged", rec.domainEvents[1])
	}
}

// ---------------------------------------------------------------------------
// UpdateDomainPrefix — Refreshed
// ---------------------------------------------------------------------------

func TestLeader_UpdateDomainPrefix_Refreshed(t *testing.T) {
	rec := &leaderCBRecorder{}
	l := NewLeader(rec)

	p1 := testPrefix(0xfd, 64)
	l.UpdateDomainPrefix(&p1)

	p2 := testPrefix(0xfe, 64)
	l.UpdateDomainPrefix(&p2)

	if rec.domainEvents[1] != DomainPrefixRefreshed {
		t.Fatalf("event = %d, want DomainPrefixRefreshed", rec.domainEvents[1])
	}
}

// ---------------------------------------------------------------------------
// UpdateDomainPrefix — nil when none set (no-op)
// ---------------------------------------------------------------------------

func TestLeader_UpdateDomainPrefix_NilWhenNoneSet(t *testing.T) {
	rec := &leaderCBRecorder{}
	l := NewLeader(rec)

	l.UpdateDomainPrefix(nil) // should be no-op

	if len(rec.domainEvents) != 0 {
		t.Fatalf("events = %v, want none", rec.domainEvents)
	}
}

// ---------------------------------------------------------------------------
// IsDomainUnicast
// ---------------------------------------------------------------------------

func TestLeader_IsDomainUnicast_Matches(t *testing.T) {
	l := NewLeader(nil)
	p := testPrefix(0xfd, 8)
	l.UpdateDomainPrefix(&p)

	var addr [16]byte
	addr[0] = 0xfd
	addr[1] = 0x01

	if !l.IsDomainUnicast(addr) {
		t.Fatal("expected IsDomainUnicast true for matching prefix")
	}
}

func TestLeader_IsDomainUnicast_Multicast(t *testing.T) {
	l := NewLeader(nil)
	p := testPrefix(0xff, 8)
	l.UpdateDomainPrefix(&p)

	var addr [16]byte
	addr[0] = 0xff
	addr[1] = 0x05

	if l.IsDomainUnicast(addr) {
		t.Fatal("expected IsDomainUnicast false for multicast")
	}
}

func TestLeader_IsDomainUnicast_NoDomainPrefix(t *testing.T) {
	l := NewLeader(nil)

	var addr [16]byte
	addr[0] = 0xfd

	if l.IsDomainUnicast(addr) {
		t.Fatal("expected IsDomainUnicast false when no domain prefix")
	}
}

func TestLeader_IsDomainUnicast_PrefixMismatch(t *testing.T) {
	l := NewLeader(nil)
	p := testPrefix(0xfd, 8)
	l.UpdateDomainPrefix(&p)

	var addr [16]byte
	addr[0] = 0xfe // does not match 0xfd/8

	if l.IsDomainUnicast(addr) {
		t.Fatal("expected IsDomainUnicast false for non-matching prefix")
	}
}

// ---------------------------------------------------------------------------
// GetConfig
// ---------------------------------------------------------------------------

func TestLeader_GetConfig(t *testing.T) {
	l := NewLeader(nil)
	cfg := Config{Server16: 0x0400, SequenceNumber: 5, ReregistrationDelay: 10, MlrTimeout: 3600}
	l.UpdatePrimary(&cfg)

	got := l.GetConfig()
	if got.Server16 != 0x0400 {
		t.Fatalf("Server16 = 0x%04x, want 0x0400", got.Server16)
	}
	if got.SequenceNumber != 5 {
		t.Fatalf("SequenceNumber = %d, want 5", got.SequenceNumber)
	}
}
