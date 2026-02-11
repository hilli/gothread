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

type localCBRecorder struct {
	stateChanges   [][2]LocalState // [old, new]
	serviceAdded   []Config
	serviceRemoved int
	domainAdded    []ip6.Prefix
	domainRemoved  []ip6.Prefix
}

func (r *localCBRecorder) OnLocalStateChanged(old, new_ LocalState) {
	r.stateChanges = append(r.stateChanges, [2]LocalState{old, new_})
}

func (r *localCBRecorder) OnServiceAdded(config Config) {
	r.serviceAdded = append(r.serviceAdded, config)
}

func (r *localCBRecorder) OnServiceRemoved() {
	r.serviceRemoved++
}

func (r *localCBRecorder) OnDomainPrefixAdded(prefix ip6.Prefix) {
	r.domainAdded = append(r.domainAdded, prefix)
}

func (r *localCBRecorder) OnDomainPrefixRemoved(prefix ip6.Prefix) {
	r.domainRemoved = append(r.domainRemoved, prefix)
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

func TestLocal_Defaults(t *testing.T) {
	l := NewLocal(nil)
	if l.GetState() != LocalStateDisabled {
		t.Fatalf("state = %d, want Disabled", l.GetState())
	}
	if l.IsEnabled() {
		t.Fatal("expected not enabled")
	}
	if l.IsPrimary() {
		t.Fatal("expected not primary")
	}
	if l.GetSequenceNumber() != 0 {
		t.Fatalf("seq = %d, want 0", l.GetSequenceNumber())
	}
	if l.GetReregistrationDelay() != DefaultRegistrationDelay {
		t.Fatalf("delay = %d, want %d", l.GetReregistrationDelay(), DefaultRegistrationDelay)
	}
	if l.GetMlrTimeout() != DefaultMlrTimeout {
		t.Fatalf("timeout = %d, want %d", l.GetMlrTimeout(), DefaultMlrTimeout)
	}
	if l.GetRegistrationJitter() != DefaultRegistrationJitter {
		t.Fatalf("jitter = %d, want %d", l.GetRegistrationJitter(), DefaultRegistrationJitter)
	}
}

// ---------------------------------------------------------------------------
// SetEnabled
// ---------------------------------------------------------------------------

func TestLocal_SetEnabled_True(t *testing.T) {
	rec := &localCBRecorder{}
	l := NewLocal(rec)

	l.SetEnabled(true)
	if l.GetState() != LocalStateSecondary {
		t.Fatalf("state = %d, want Secondary", l.GetState())
	}
	if !l.IsEnabled() {
		t.Fatal("expected enabled")
	}
	if len(rec.stateChanges) != 1 {
		t.Fatalf("state changes = %d, want 1", len(rec.stateChanges))
	}
	if rec.stateChanges[0] != [2]LocalState{LocalStateDisabled, LocalStateSecondary} {
		t.Fatalf("state change = %v, want [Disabled, Secondary]", rec.stateChanges[0])
	}
}

func TestLocal_SetEnabled_False(t *testing.T) {
	rec := &localCBRecorder{}
	l := NewLocal(rec)
	l.SetEnabled(true)
	rec.stateChanges = nil

	l.SetEnabled(false)
	if l.GetState() != LocalStateDisabled {
		t.Fatalf("state = %d, want Disabled", l.GetState())
	}
	if len(rec.stateChanges) != 1 || rec.stateChanges[0][1] != LocalStateDisabled {
		t.Fatalf("state changes = %v, want transition to Disabled", rec.stateChanges)
	}
}

func TestLocal_SetEnabled_IdempotentTrue(t *testing.T) {
	rec := &localCBRecorder{}
	l := NewLocal(rec)
	l.SetEnabled(true)
	rec.stateChanges = nil

	l.SetEnabled(true) // no-op
	if len(rec.stateChanges) != 0 {
		t.Fatalf("expected no state change for idempotent enable")
	}
}

func TestLocal_SetEnabled_IdempotentFalse(t *testing.T) {
	rec := &localCBRecorder{}
	l := NewLocal(rec)

	l.SetEnabled(false) // already disabled, no-op
	if len(rec.stateChanges) != 0 {
		t.Fatalf("expected no state change for idempotent disable")
	}
}

// ---------------------------------------------------------------------------
// GetConfig / SetConfig
// ---------------------------------------------------------------------------

func TestLocal_GetSetConfig(t *testing.T) {
	l := NewLocal(nil)
	cfg := Config{SequenceNumber: 42, ReregistrationDelay: 10, MlrTimeout: 7200}
	l.SetConfig(cfg)

	got := l.GetConfig()
	if got.SequenceNumber != 42 {
		t.Fatalf("seq = %d, want 42", got.SequenceNumber)
	}
	if got.ReregistrationDelay != 10 {
		t.Fatalf("delay = %d, want 10", got.ReregistrationDelay)
	}
	if got.MlrTimeout != 7200 {
		t.Fatalf("timeout = %d, want 7200", got.MlrTimeout)
	}
}

// ---------------------------------------------------------------------------
// Getters / Setters
// ---------------------------------------------------------------------------

func TestLocal_SetGetSequenceNumber(t *testing.T) {
	l := NewLocal(nil)
	l.SetSequenceNumber(100)
	if l.GetSequenceNumber() != 100 {
		t.Fatalf("seq = %d, want 100", l.GetSequenceNumber())
	}
}

func TestLocal_SetGetReregistrationDelay(t *testing.T) {
	l := NewLocal(nil)
	l.SetReregistrationDelay(20)
	if l.GetReregistrationDelay() != 20 {
		t.Fatalf("delay = %d, want 20", l.GetReregistrationDelay())
	}
}

func TestLocal_SetGetMlrTimeout(t *testing.T) {
	l := NewLocal(nil)
	l.SetMlrTimeout(9999)
	if l.GetMlrTimeout() != 9999 {
		t.Fatalf("timeout = %d, want 9999", l.GetMlrTimeout())
	}
}

func TestLocal_SetGetRegistrationJitter(t *testing.T) {
	l := NewLocal(nil)
	l.SetRegistrationJitter(10)
	if l.GetRegistrationJitter() != 10 {
		t.Fatalf("jitter = %d, want 10", l.GetRegistrationJitter())
	}
}

// ---------------------------------------------------------------------------
// IncrementSequenceNumber
// ---------------------------------------------------------------------------

func TestLocal_IncrementSequenceNumber_Normal(t *testing.T) {
	l := NewLocal(nil)
	l.SetSequenceNumber(50)
	l.IncrementSequenceNumber()
	if l.GetSequenceNumber() != 51 {
		t.Fatalf("seq = %d, want 51", l.GetSequenceNumber())
	}
}

func TestLocal_IncrementSequenceNumber_126Wraps(t *testing.T) {
	l := NewLocal(nil)
	l.SetSequenceNumber(126)
	l.IncrementSequenceNumber()
	if l.GetSequenceNumber() != 0 {
		t.Fatalf("seq = %d, want 0 (wrap from 126)", l.GetSequenceNumber())
	}
}

func TestLocal_IncrementSequenceNumber_127Wraps(t *testing.T) {
	l := NewLocal(nil)
	l.SetSequenceNumber(127)
	l.IncrementSequenceNumber()
	if l.GetSequenceNumber() != 0 {
		t.Fatalf("seq = %d, want 0 (wrap from 127)", l.GetSequenceNumber())
	}
}

func TestLocal_IncrementSequenceNumber_254Wraps(t *testing.T) {
	l := NewLocal(nil)
	l.SetSequenceNumber(254)
	l.IncrementSequenceNumber()
	if l.GetSequenceNumber() != 128 {
		t.Fatalf("seq = %d, want 128 (wrap from 254)", l.GetSequenceNumber())
	}
}

func TestLocal_IncrementSequenceNumber_255Wraps(t *testing.T) {
	l := NewLocal(nil)
	l.SetSequenceNumber(255)
	l.IncrementSequenceNumber()
	if l.GetSequenceNumber() != 128 {
		t.Fatalf("seq = %d, want 128 (wrap from 255)", l.GetSequenceNumber())
	}
}

func TestLocal_IncrementSequenceNumber_125Normal(t *testing.T) {
	l := NewLocal(nil)
	l.SetSequenceNumber(125)
	l.IncrementSequenceNumber()
	if l.GetSequenceNumber() != 126 {
		t.Fatalf("seq = %d, want 126", l.GetSequenceNumber())
	}
}

func TestLocal_IncrementSequenceNumber_253Normal(t *testing.T) {
	l := NewLocal(nil)
	l.SetSequenceNumber(253)
	l.IncrementSequenceNumber()
	if l.GetSequenceNumber() != 254 {
		t.Fatalf("seq = %d, want 254", l.GetSequenceNumber())
	}
}

func TestLocal_IncrementSequenceNumber_128Normal(t *testing.T) {
	l := NewLocal(nil)
	l.SetSequenceNumber(128)
	l.IncrementSequenceNumber()
	if l.GetSequenceNumber() != 129 {
		t.Fatalf("seq = %d, want 129", l.GetSequenceNumber())
	}
}

// ---------------------------------------------------------------------------
// AddService / RemoveService
// ---------------------------------------------------------------------------

func TestLocal_AddService(t *testing.T) {
	rec := &localCBRecorder{}
	l := NewLocal(rec)
	l.SetEnabled(true)

	cfg := l.AddService()
	if !l.IsServiceAdded() {
		t.Fatal("expected service added")
	}
	if len(rec.serviceAdded) != 1 {
		t.Fatalf("serviceAdded callbacks = %d, want 1", len(rec.serviceAdded))
	}
	if cfg.SequenceNumber != 0 {
		t.Fatalf("seq = %d, want 0", cfg.SequenceNumber)
	}
}

func TestLocal_RemoveService(t *testing.T) {
	rec := &localCBRecorder{}
	l := NewLocal(rec)
	l.SetEnabled(true)
	l.AddService()

	l.RemoveService()
	if l.IsServiceAdded() {
		t.Fatal("expected service not added")
	}
	if rec.serviceRemoved != 1 {
		t.Fatalf("serviceRemoved = %d, want 1", rec.serviceRemoved)
	}
}

// ---------------------------------------------------------------------------
// HandleBackboneRouterPrimaryUpdate
// ---------------------------------------------------------------------------

func TestLocal_HandleBBRPrimaryUpdate_MatchingRloc(t *testing.T) {
	rec := &localCBRecorder{}
	l := NewLocal(rec)
	l.SetEnabled(true)
	l.AddService()

	cfg := Config{Server16: 0x0400, SequenceNumber: 0, MlrTimeout: 3600}
	l.HandleBackboneRouterPrimaryUpdate(LeaderStateAdded, cfg, 0x0400)

	if l.GetState() != LocalStatePrimary {
		t.Fatalf("state = %d, want Primary", l.GetState())
	}
}

func TestLocal_HandleBBRPrimaryUpdate_DifferentRloc(t *testing.T) {
	rec := &localCBRecorder{}
	l := NewLocal(rec)
	l.SetEnabled(true)
	l.AddService()

	// Simulate this device becoming primary first.
	cfg1 := Config{Server16: 0x0400, SequenceNumber: 0, MlrTimeout: 3600}
	l.HandleBackboneRouterPrimaryUpdate(LeaderStateAdded, cfg1, 0x0400)

	// Now a different device is primary.
	cfg2 := Config{Server16: 0x0800, SequenceNumber: 1, MlrTimeout: 3600}
	l.HandleBackboneRouterPrimaryUpdate(LeaderStateAdded, cfg2, 0x0400)

	if l.GetState() != LocalStateSecondary {
		t.Fatalf("state = %d, want Secondary (stepped down)", l.GetState())
	}
}

func TestLocal_HandleBBRPrimaryUpdate_NoPrimary(t *testing.T) {
	l := NewLocal(nil)
	l.SetEnabled(true)

	cfg := Config{Server16: InvalidServer16}
	l.HandleBackboneRouterPrimaryUpdate(LeaderStateRemoved, cfg, 0x0400)

	// Should stay secondary, no panic.
	if l.GetState() != LocalStateSecondary {
		t.Fatalf("state = %d, want Secondary", l.GetState())
	}
}

func TestLocal_HandleBBRPrimaryUpdate_Disabled(t *testing.T) {
	l := NewLocal(nil)
	// Not enabled — should be a no-op.
	cfg := Config{Server16: 0x0400}
	l.HandleBackboneRouterPrimaryUpdate(LeaderStateAdded, cfg, 0x0400)

	if l.GetState() != LocalStateDisabled {
		t.Fatalf("state = %d, want Disabled", l.GetState())
	}
}

func TestLocal_HandleBBRPrimaryUpdate_RestoreFromConfig(t *testing.T) {
	rec := &localCBRecorder{}
	l := NewLocal(rec)
	l.SetEnabled(true)
	// Service NOT added — should restore from config.

	cfg := Config{Server16: 0x0400, SequenceNumber: 10, ReregistrationDelay: 20, MlrTimeout: 7200}
	l.HandleBackboneRouterPrimaryUpdate(LeaderStateAdded, cfg, 0x0400)

	// Should have adopted config, incremented seq, and added service.
	if l.GetSequenceNumber() != 11 {
		t.Fatalf("seq = %d, want 11 (adopted 10, incremented)", l.GetSequenceNumber())
	}
	if l.GetReregistrationDelay() != 20 {
		t.Fatalf("delay = %d, want 20", l.GetReregistrationDelay())
	}
	if !l.IsServiceAdded() {
		t.Fatal("expected service added after restore")
	}
}

// ---------------------------------------------------------------------------
// SetDomainPrefix / RemoveDomainPrefix
// ---------------------------------------------------------------------------

func TestLocal_SetDomainPrefix(t *testing.T) {
	rec := &localCBRecorder{}
	l := NewLocal(rec)

	p := testPrefix(0xfd, 64)
	l.SetDomainPrefix(p)

	prefix, ok := l.GetDomainPrefix()
	if !ok {
		t.Fatal("expected domain prefix set")
	}
	if !prefix.IsEqual(p) {
		t.Fatal("domain prefix mismatch")
	}
	if len(rec.domainAdded) != 1 {
		t.Fatalf("domainAdded = %d, want 1", len(rec.domainAdded))
	}
}

func TestLocal_RemoveDomainPrefix(t *testing.T) {
	rec := &localCBRecorder{}
	l := NewLocal(rec)

	p := testPrefix(0xfd, 64)
	l.SetDomainPrefix(p)
	l.RemoveDomainPrefix()

	_, ok := l.GetDomainPrefix()
	if ok {
		t.Fatal("expected no domain prefix after removal")
	}
	if len(rec.domainRemoved) != 1 {
		t.Fatalf("domainRemoved = %d, want 1", len(rec.domainRemoved))
	}
}

func TestLocal_RemoveDomainPrefix_WhenNone(t *testing.T) {
	rec := &localCBRecorder{}
	l := NewLocal(rec)

	l.RemoveDomainPrefix() // should be no-op
	if len(rec.domainRemoved) != 0 {
		t.Fatalf("domainRemoved = %d, want 0", len(rec.domainRemoved))
	}
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

func TestLocal_Reset_FromPrimary(t *testing.T) {
	rec := &localCBRecorder{}
	l := NewLocal(rec)
	l.SetEnabled(true)
	l.AddService()

	cfg := Config{Server16: 0x0400, SequenceNumber: 0, MlrTimeout: 3600}
	l.HandleBackboneRouterPrimaryUpdate(LeaderStateAdded, cfg, 0x0400)

	l.Reset()

	if l.GetState() != LocalStateSecondary {
		t.Fatalf("state = %d, want Secondary after Reset from Primary", l.GetState())
	}
	if l.IsServiceAdded() {
		t.Fatal("expected service removed after Reset")
	}
	// Sequence number should have been incremented (from 0 to 1).
	if l.GetSequenceNumber() != 1 {
		t.Fatalf("seq = %d, want 1 after Reset increment", l.GetSequenceNumber())
	}
}

func TestLocal_Reset_Disabled(t *testing.T) {
	l := NewLocal(nil)
	l.Reset() // no-op on disabled
	if l.GetState() != LocalStateDisabled {
		t.Fatalf("state = %d, want Disabled", l.GetState())
	}
}

func TestLocal_Reset_Secondary(t *testing.T) {
	l := NewLocal(nil)
	l.SetEnabled(true)
	l.Reset() // not primary, so no seq increment
	if l.GetState() != LocalStateSecondary {
		t.Fatalf("state = %d, want Secondary", l.GetState())
	}
	if l.GetSequenceNumber() != 0 {
		t.Fatalf("seq = %d, want 0 (no increment from Secondary)", l.GetSequenceNumber())
	}
}

// ---------------------------------------------------------------------------
// SetEnabled false removes service
// ---------------------------------------------------------------------------

func TestLocal_SetEnabled_False_RemovesService(t *testing.T) {
	rec := &localCBRecorder{}
	l := NewLocal(rec)
	l.SetEnabled(true)
	l.AddService()

	l.SetEnabled(false)
	if l.IsServiceAdded() {
		t.Fatal("expected service removed when disabled")
	}
	if rec.serviceRemoved != 1 {
		t.Fatalf("serviceRemoved = %d, want 1", rec.serviceRemoved)
	}
}
