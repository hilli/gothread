// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"testing"
	"time"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
)

// --- NeighborState tests ---

func TestNeighborStateString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state NeighborState
		want  string
	}{
		{StateInvalid, "Invalid"},
		{StateRestored, "Restored"},
		{StateParentRequest, "ParentRequest"},
		{StateParentResponse, "ParentResponse"},
		{StateChildIDRequest, "ChildIDRequest"},
		{StateLinkRequest, "LinkRequest"},
		{StateChildUpdateRequest, "ChildUpdateRequest"},
		{StateValid, "Valid"},
		{NeighborState(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("NeighborState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

// --- Challenge tests ---

func TestChallengeGenerate(t *testing.T) {
	t.Parallel()

	var c Challenge
	c.GenerateChallenge()

	// The probability of all 8 bytes being zero is negligible.
	allZero := true
	for _, b := range c {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("GenerateChallenge produced all zeros (extremely unlikely)")
	}
}

// --- Neighbor tests ---

func TestNeighborStatePredicates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state            NeighborState
		valid            bool
		restoring        bool
		validOrRestoring bool
		validOrAttaching bool
		anyExceptInvalid bool
	}{
		{StateInvalid, false, false, false, false, false},
		{StateRestored, false, true, true, false, true},
		{StateParentRequest, false, false, false, true, true},
		{StateParentResponse, false, false, false, true, true},
		{StateChildIDRequest, false, false, false, true, true},
		{StateLinkRequest, false, false, false, true, true},
		{StateChildUpdateRequest, false, true, true, true, true},
		{StateValid, true, false, true, true, true},
	}

	for _, tt := range tests {
		n := &Neighbor{State: tt.state}
		if got := n.IsStateValid(); got != tt.valid {
			t.Errorf("State %v: IsStateValid() = %v, want %v", tt.state, got, tt.valid)
		}
		if got := n.IsStateRestoring(); got != tt.restoring {
			t.Errorf("State %v: IsStateRestoring() = %v, want %v", tt.state, got, tt.restoring)
		}
		if got := n.IsStateValidOrRestoring(); got != tt.validOrRestoring {
			t.Errorf("State %v: IsStateValidOrRestoring() = %v, want %v", tt.state, got, tt.validOrRestoring)
		}
		if got := n.IsStateValidOrAttaching(); got != tt.validOrAttaching {
			t.Errorf("State %v: IsStateValidOrAttaching() = %v, want %v", tt.state, got, tt.validOrAttaching)
		}
		if got := n.IsStateAnyExceptInvalid(); got != tt.anyExceptInvalid {
			t.Errorf("State %v: IsStateAnyExceptInvalid() = %v, want %v", tt.state, got, tt.anyExceptInvalid)
		}
	}
}

func TestNeighborDeviceModeHelpers(t *testing.T) {
	t.Parallel()

	n := &Neighbor{
		Mode: NewDeviceMode(ModeRxOnWhenIdle | ModeFullThreadDevice | ModeFullNetworkData),
	}

	if !n.IsRxOnWhenIdle() {
		t.Error("expected RxOnWhenIdle")
	}
	if !n.IsFullThreadDevice() {
		t.Error("expected FullThreadDevice")
	}
	if n.GetDeviceMode().Get() != (ModeRxOnWhenIdle | ModeReserved | ModeFullThreadDevice | ModeFullNetworkData) {
		t.Errorf("unexpected mode byte: 0x%02x", n.GetDeviceMode().Get())
	}
}

func TestNeighborInvalidate(t *testing.T) {
	t.Parallel()

	n := &Neighbor{State: StateValid}
	n.Invalidate()
	if n.State != StateInvalid {
		t.Errorf("Invalidate: state = %v, want Invalid", n.State)
	}
}

func TestNeighborGenerateChallenge(t *testing.T) {
	t.Parallel()

	n := &Neighbor{}
	n.GenerateChallenge()

	allZero := true
	for _, b := range n.PendingChallenge {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Neighbor.GenerateChallenge produced all zeros")
	}
}

// --- Router tests ---

func TestRouterNewRouter(t *testing.T) {
	t.Parallel()

	r := NewRouter()
	if r.NextHop != InvalidRouterID {
		t.Errorf("NewRouter().NextHop = %d, want %d", r.NextHop, InvalidRouterID)
	}
	if r.HasRoute() {
		t.Error("NewRouter().HasRoute() should be false")
	}
}

func TestRouterNextHopAndCost(t *testing.T) {
	t.Parallel()

	r := NewRouter()
	r.SetNextHopAndCost(5, 3)

	if !r.HasRoute() {
		t.Error("HasRoute() should be true after SetNextHopAndCost")
	}
	if r.NextHop != 5 || r.Cost != 3 {
		t.Errorf("NextHop=%d Cost=%d, want 5, 3", r.NextHop, r.Cost)
	}

	r.SetNextHopToInvalid()
	if r.HasRoute() {
		t.Error("HasRoute() should be false after SetNextHopToInvalid")
	}
	if r.Cost != 0 {
		t.Errorf("Cost should be 0 after SetNextHopToInvalid, got %d", r.Cost)
	}
}

func TestRouterTwoWayLinkQuality(t *testing.T) {
	t.Parallel()

	r := NewRouter()
	r.LinkQualityOut = 3

	// LinkInfo not initialized, so qualityIn = 0 (Quality0)
	if got := r.GetTwoWayLinkQuality(); got != 0 {
		t.Errorf("GetTwoWayLinkQuality() = %d, want 0 (min of in=0, out=3)", got)
	}

	r.LinkQualityOut = 0
	if got := r.GetTwoWayLinkQuality(); got != 0 {
		t.Errorf("GetTwoWayLinkQuality() = %d, want 0", got)
	}
}

func TestRouterLinkAcceptTimeout(t *testing.T) {
	t.Parallel()

	r := NewRouter()
	if r.IsWaitingForLinkAccept() {
		t.Error("should not be waiting initially")
	}

	r.RestartLinkAcceptTimeout()
	if !r.IsWaitingForLinkAccept() {
		t.Error("should be waiting after restart")
	}

	for i := 0; i < int(LinkAcceptTimeout)-1; i++ {
		expired := r.DecrementLinkAcceptTimeout()
		if expired {
			t.Errorf("expired too early at step %d", i)
		}
	}

	expired := r.DecrementLinkAcceptTimeout()
	if !expired {
		t.Error("should have expired on last decrement")
	}

	r.RestartLinkAcceptTimeout()
	r.ClearLinkAcceptTimeout()
	if r.IsWaitingForLinkAccept() {
		t.Error("should not be waiting after clear")
	}
}

func TestRouterLinkRequestAttempts(t *testing.T) {
	t.Parallel()

	r := NewRouter()
	if r.HasRemainingLinkRequestAttempts() {
		t.Error("should have no attempts initially")
	}

	r.SetLinkRequestAttemptsToMax()
	if !r.HasRemainingLinkRequestAttempts() {
		t.Error("should have attempts after set to max")
	}

	for i := uint8(0); i < LinkRequestAttempts; i++ {
		r.DecrementLinkRequestAttempts()
	}
	if r.HasRemainingLinkRequestAttempts() {
		t.Error("should have no attempts after exhausting all")
	}

	// Decrementing past zero should be safe.
	r.DecrementLinkRequestAttempts()
	if r.RemainingLinkRequestAttempts != 0 {
		t.Error("should not go negative")
	}
}

// --- Parent tests ---

func TestParentLeaderCost(t *testing.T) {
	t.Parallel()

	p := &Parent{}
	p.LeaderCost = 5
	if p.LeaderCost != 5 {
		t.Errorf("LeaderCost = %d, want 5", p.LeaderCost)
	}
}

// --- Child tests ---

func TestChildIP6Addresses(t *testing.T) {
	t.Parallel()

	c := &Child{}

	addr1 := ip6.Address{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	addr2 := ip6.Address{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	if c.HasIP6Address(addr1) {
		t.Error("should not have addr1 initially")
	}

	if !c.AddIP6Address(addr1) {
		t.Error("should be able to add addr1")
	}
	if !c.HasIP6Address(addr1) {
		t.Error("should have addr1 after adding")
	}
	if c.HasIP6Address(addr2) {
		t.Error("should not have addr2")
	}

	if !c.AddIP6Address(addr2) {
		t.Error("should be able to add addr2")
	}
	if c.IP6AddressCount != 2 {
		t.Errorf("IP6AddressCount = %d, want 2", c.IP6AddressCount)
	}

	// Fill to capacity.
	for i := uint8(2); i < MaxChildIPAddresses; i++ {
		var a ip6.Address
		a[15] = byte(i + 10)
		if !c.AddIP6Address(a) {
			t.Errorf("should be able to add address %d", i)
		}
	}

	// One more should fail.
	overflow := ip6.Address{0xff}
	if c.AddIP6Address(overflow) {
		t.Error("should not be able to add beyond capacity")
	}

	c.ClearIP6Addresses()
	if c.IP6AddressCount != 0 {
		t.Errorf("IP6AddressCount after clear = %d, want 0", c.IP6AddressCount)
	}
	if c.HasIP6Address(addr1) {
		t.Error("should not have addr1 after clear")
	}
}

func TestChildMeshLocalIP6Address(t *testing.T) {
	t.Parallel()

	c := &Child{}
	c.MeshLocalIID = ip6.InterfaceIdentifier{0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x04, 0x00}

	prefix := ip6.NetworkPrefix{0xfd, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde}
	addr := c.GetMeshLocalIP6Address(prefix)

	// First 8 bytes should be the prefix.
	for i := 0; i < 8; i++ {
		if addr[i] != prefix[i] {
			t.Errorf("addr[%d] = 0x%02x, want 0x%02x", i, addr[i], prefix[i])
		}
	}
	// Last 8 bytes should be the IID.
	iid := c.MeshLocalIID
	for i := 0; i < 8; i++ {
		if addr[8+i] != iid[i] {
			t.Errorf("addr[%d] = 0x%02x, want 0x%02x", 8+i, addr[8+i], iid[i])
		}
	}
}

// --- Mle state machine tests ---

func TestMleNewMle(t *testing.T) {
	t.Parallel()

	m := NewMle()

	if m.Role() != RoleDisabled {
		t.Errorf("initial role = %v, want Disabled", m.Role())
	}
	if m.RLOC16() != InvalidRLOC16 {
		t.Errorf("initial RLOC16 = 0x%04x, want 0x%04x", m.RLOC16(), InvalidRLOC16)
	}
	if !m.IsDisabled() {
		t.Error("should be disabled initially")
	}
	if m.IsAttached() {
		t.Error("should not be attached initially")
	}
	if !m.IsRouterEligible() {
		t.Error("should be router eligible by default")
	}
	if m.GetDeviceMode().Get()&ModeFullThreadDevice == 0 {
		t.Error("default mode should include FullThreadDevice")
	}
}

func TestMleEnableDisable(t *testing.T) {
	t.Parallel()

	m := NewMle()

	if err := m.Enable(); err != nil {
		t.Fatalf("Enable() error: %v", err)
	}
	if !m.IsDetached() {
		t.Error("should be detached after Enable")
	}

	// Enable again should return ErrAlready.
	if err := m.Enable(); err == nil {
		t.Error("Enable() on non-disabled should return error")
	}

	if err := m.Disable(); err != nil {
		t.Fatalf("Disable() error: %v", err)
	}
	if !m.IsDisabled() {
		t.Error("should be disabled after Disable")
	}

	// Disable again should return ErrAlready.
	if err := m.Disable(); err == nil {
		t.Error("Disable() on already disabled should return error")
	}
}

func TestMleBecomeDetached(t *testing.T) {
	t.Parallel()

	m := NewMle()

	// Should fail when disabled.
	if err := m.BecomeDetached(); err == nil {
		t.Error("BecomeDetached() should fail when disabled")
	}

	_ = m.Enable()
	if err := m.BecomeDetached(); err != nil {
		t.Fatalf("BecomeDetached() error: %v", err)
	}
	if !m.IsDetached() {
		t.Error("should be detached")
	}
	if m.RLOC16() != InvalidRLOC16 {
		t.Error("RLOC16 should be invalid after BecomeDetached")
	}
}

func TestMleStateChild(t *testing.T) {
	t.Parallel()

	m := NewMle()
	_ = m.Enable()

	rloc := uint16(0x0401)
	if err := m.SetStateChild(rloc); err != nil {
		t.Fatalf("SetStateChild() error: %v", err)
	}
	if !m.IsChild() {
		t.Error("should be Child")
	}
	if !m.IsAttached() {
		t.Error("should be attached as Child")
	}
	if m.RLOC16() != rloc {
		t.Errorf("RLOC16 = 0x%04x, want 0x%04x", m.RLOC16(), rloc)
	}
}

func TestMleStateRouter(t *testing.T) {
	t.Parallel()

	m := NewMle()
	_ = m.Enable()
	_ = m.SetStateChild(0x0401)

	routerRLOC := RLOC16FromRouterID(1) // 0x0400
	if err := m.SetStateRouter(routerRLOC); err != nil {
		t.Fatalf("SetStateRouter() error: %v", err)
	}
	if !m.IsRouter() {
		t.Error("should be Router")
	}
	if !m.IsRouterOrLeader() {
		t.Error("should be RouterOrLeader")
	}
	if m.RLOC16() != routerRLOC {
		t.Errorf("RLOC16 = 0x%04x, want 0x%04x", m.RLOC16(), routerRLOC)
	}
}

func TestMleStateLeader(t *testing.T) {
	t.Parallel()

	m := NewMle()
	_ = m.Enable()

	leaderRLOC := RLOC16FromRouterID(10) // 0x2800
	if err := m.SetStateLeader(leaderRLOC); err != nil {
		t.Fatalf("SetStateLeader() error: %v", err)
	}
	if !m.IsLeader() {
		t.Error("should be Leader")
	}
	if !m.IsRouterOrLeader() {
		t.Error("should be RouterOrLeader")
	}
}

func TestMleRoleChangeCallback(t *testing.T) {
	t.Parallel()

	m := NewMle()

	var transitions []struct{ old, new DeviceRole }
	m.SetRoleChangeCallback(func(oldRole, newRole DeviceRole) {
		transitions = append(transitions, struct{ old, new DeviceRole }{oldRole, newRole})
	})

	_ = m.Enable() // Disabled -> Detached
	_ = m.SetStateChild(0x0401)
	_ = m.SetStateRouter(0x0400)
	_ = m.BecomeDetached()

	expected := []struct{ old, new DeviceRole }{
		{RoleDisabled, RoleDetached},
		{RoleDetached, RoleChild},
		{RoleChild, RoleRouter},
		{RoleRouter, RoleDetached},
	}

	if len(transitions) != len(expected) {
		t.Fatalf("got %d transitions, want %d", len(transitions), len(expected))
	}
	for i, tr := range transitions {
		if tr.old != expected[i].old || tr.new != expected[i].new {
			t.Errorf("transition[%d] = %v->%v, want %v->%v",
				i, tr.old, tr.new, expected[i].old, expected[i].new)
		}
	}
}

func TestMleCounters(t *testing.T) {
	t.Parallel()

	m := NewMle()

	_ = m.Enable()               // Detached
	_ = m.SetStateChild(0x0401)  // Child
	_ = m.SetStateRouter(0x0400) // Router
	_ = m.SetStateLeader(0x0400) // Leader
	_ = m.BecomeDetached()       // Detached
	_ = m.Disable()              // Disabled

	c := m.GetCounters()
	if c.DetachedCount != 2 {
		t.Errorf("DetachedCount = %d, want 2", c.DetachedCount)
	}
	if c.ChildCount != 1 {
		t.Errorf("ChildCount = %d, want 1", c.ChildCount)
	}
	if c.RouterCount != 1 {
		t.Errorf("RouterCount = %d, want 1", c.RouterCount)
	}
	if c.LeaderCount != 1 {
		t.Errorf("LeaderCount = %d, want 1", c.LeaderCount)
	}
	if c.DisabledCount != 1 {
		t.Errorf("DisabledCount = %d, want 1", c.DisabledCount)
	}
}

func TestMleParentInvalidatedOnRoleChange(t *testing.T) {
	t.Parallel()

	m := NewMle()
	_ = m.Enable()
	_ = m.SetStateChild(0x0401)

	// Set parent to valid.
	m.parent.State = StateValid
	m.parent.MacAddr = types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Transition to Router — parent should be invalidated.
	_ = m.SetStateRouter(0x0400)

	if m.parent.State != StateInvalid {
		t.Error("parent should be invalidated when leaving Child role")
	}
}

func TestMleParentChangeCounter(t *testing.T) {
	t.Parallel()

	m := NewMle()
	_ = m.Enable()

	// First attach — router ID 1, child 1.
	_ = m.SetStateChild(0x0401)
	c := m.GetCounters()
	// First attach from InvalidRLOC16 — parent changed.
	if c.ParentChanges != 1 {
		t.Errorf("ParentChanges after first attach = %d, want 1", c.ParentChanges)
	}

	// Re-attach to same router — no parent change.
	_ = m.BecomeDetached()
	m.mu.Lock()
	m.rloc16 = 0x0401 // Simulate remembering the previous RLOC
	m.mu.Unlock()
	_ = m.SetStateChild(0x0402) // Same router ID 1, different child ID
	c = m.GetCounters()
	if c.ParentChanges != 1 {
		t.Errorf("ParentChanges after same-router re-attach = %d, want 1", c.ParentChanges)
	}

	// Re-attach to different router — parent changed.
	_ = m.SetStateChild(0x0801) // Router ID 2
	c = m.GetCounters()
	if c.ParentChanges != 2 {
		t.Errorf("ParentChanges after new-router attach = %d, want 2", c.ParentChanges)
	}
}

func TestMleLastAttachTime(t *testing.T) {
	t.Parallel()

	m := NewMle()
	_ = m.Enable()

	before := time.Now()
	_ = m.SetStateChild(0x0401)
	after := time.Now()

	lat := m.LastAttachTime()
	if lat.Before(before) || lat.After(after) {
		t.Error("LastAttachTime should be between before and after timestamps")
	}
}

func TestMleStartAttach(t *testing.T) {
	t.Parallel()

	m := NewMle()

	// Fail when disabled.
	if err := m.StartAttach(AttachAnyPartition); err == nil {
		t.Error("StartAttach should fail when disabled")
	}

	_ = m.Enable()

	if err := m.StartAttach(AttachAnyPartition); err != nil {
		t.Fatalf("StartAttach() error: %v", err)
	}
	if m.GetAttachState() != AttachStateStart {
		t.Errorf("AttachState = %v, want Start", m.GetAttachState())
	}

	// Starting again while busy should fail.
	if err := m.StartAttach(AttachAnyPartition); err == nil {
		t.Error("StartAttach should fail when already attaching")
	}

	c := m.GetCounters()
	if c.AttachAttempts != 1 {
		t.Errorf("AttachAttempts = %d, want 1", c.AttachAttempts)
	}
}

func TestMleBecomeRouterPreconditions(t *testing.T) {
	t.Parallel()

	m := NewMle()

	// Disabled.
	if err := m.BecomeRouter(); err == nil {
		t.Error("BecomeRouter should fail when disabled")
	}

	_ = m.Enable()

	// Detached.
	if err := m.BecomeRouter(); err == nil {
		t.Error("BecomeRouter should fail when detached")
	}

	// Child, not eligible.
	_ = m.SetStateChild(0x0401)
	m.SetRouterEligible(false)
	if err := m.BecomeRouter(); err == nil {
		t.Error("BecomeRouter should fail when not eligible")
	}

	// Child, eligible — should succeed.
	m.SetRouterEligible(true)
	if err := m.BecomeRouter(); err != nil {
		t.Errorf("BecomeRouter() error: %v", err)
	}

	// Already router — no-op.
	_ = m.SetStateRouter(0x0400)
	if err := m.BecomeRouter(); err != nil {
		t.Errorf("BecomeRouter() on router should be no-op, got: %v", err)
	}
}

func TestMleBecomeLeaderPreconditions(t *testing.T) {
	t.Parallel()

	m := NewMle()

	// Disabled.
	if err := m.BecomeLeader(); err == nil {
		t.Error("BecomeLeader should fail when disabled")
	}

	_ = m.Enable()

	// Not eligible.
	m.SetRouterEligible(false)
	if err := m.BecomeLeader(); err == nil {
		t.Error("BecomeLeader should fail when not eligible")
	}

	m.SetRouterEligible(true)

	// Already leader.
	_ = m.SetStateLeader(0x0400)
	if err := m.BecomeLeader(); err == nil {
		t.Error("BecomeLeader should return ErrAlready when already leader")
	}
}

func TestMleSetAttachState(t *testing.T) {
	t.Parallel()

	m := NewMle()
	_ = m.Enable()

	m.SetAttachState(AttachStateParentRequest)
	if m.GetAttachState() != AttachStateParentRequest {
		t.Errorf("AttachState = %v, want ParentRequest", m.GetAttachState())
	}
}

func TestMleDisableFromAttached(t *testing.T) {
	t.Parallel()

	m := NewMle()
	_ = m.Enable()
	_ = m.SetStateChild(0x0401)

	if err := m.Disable(); err != nil {
		t.Fatalf("Disable() error: %v", err)
	}
	if !m.IsDisabled() {
		t.Error("should be disabled")
	}
	if m.RLOC16() != InvalidRLOC16 {
		t.Error("RLOC16 should be invalid after disable")
	}
	if m.GetAttachState() != AttachStateIdle {
		t.Error("attach state should be idle after disable")
	}
}

func TestMlePreviousRole(t *testing.T) {
	t.Parallel()

	m := NewMle()
	_ = m.Enable()
	_ = m.SetStateChild(0x0401)
	_ = m.SetStateRouter(0x0400)

	if m.PreviousRole() != RoleChild {
		t.Errorf("PreviousRole = %v, want Child", m.PreviousRole())
	}
}

func TestMleLeaderData(t *testing.T) {
	t.Parallel()

	m := NewMle()

	ld := LeaderData{
		PartitionID:       0x12345678,
		Weighting:         64,
		DataVersion:       10,
		StableDataVersion: 5,
		LeaderRouterID:    3,
	}
	m.SetLeaderData(ld)

	got := m.GetLeaderData()
	if got != ld {
		t.Errorf("GetLeaderData() = %+v, want %+v", got, ld)
	}
}

func TestMleChildTimeout(t *testing.T) {
	t.Parallel()

	m := NewMle()
	if m.GetChildTimeout() != 240 {
		t.Errorf("default child timeout = %d, want 240", m.GetChildTimeout())
	}

	m.SetChildTimeout(120)
	if m.GetChildTimeout() != 120 {
		t.Errorf("child timeout = %d, want 120", m.GetChildTimeout())
	}
}

// --- AttachMode and AttachState String tests ---

func TestAttachModeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode AttachMode
		want string
	}{
		{AttachAnyPartition, "AnyPartition"},
		{AttachSamePartition, "SamePartition"},
		{AttachBetterPartition, "BetterPartition"},
		{AttachSamePartitionRetry, "SamePartitionRetry"},
		{AttachBetterParent, "BetterParent"},
		{AttachSelectedParent, "SelectedParent"},
		{AttachMode(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.mode.String(); got != tt.want {
			t.Errorf("AttachMode(%d).String() = %q, want %q", tt.mode, got, tt.want)
		}
	}
}

func TestAttachStateString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state AttachState
		want  string
	}{
		{AttachStateIdle, "Idle"},
		{AttachStateStart, "Start"},
		{AttachStateParentRequest, "ParentRequest"},
		{AttachStateAnnounce, "Announce"},
		{AttachStateChildIDRequest, "ChildIDRequest"},
		{AttachState(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("AttachState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

// --- RoleStartTime test ---

func TestMleRoleStartTime(t *testing.T) {
	t.Parallel()

	m := NewMle()
	before := time.Now()
	_ = m.Enable()
	after := time.Now()

	rst := m.RoleStartTime()
	if rst.Before(before) || rst.After(after) {
		t.Error("RoleStartTime should be between before and after timestamps")
	}
}

// Ensure SetStateChild from disabled returns error.
func TestMleSetStateChildDisabled(t *testing.T) {
	t.Parallel()

	m := NewMle()
	if err := m.SetStateChild(0x0401); err == nil {
		t.Error("SetStateChild should fail when disabled")
	}
}

// Ensure SetStateRouter from disabled returns error.
func TestMleSetStateRouterDisabled(t *testing.T) {
	t.Parallel()

	m := NewMle()
	if err := m.SetStateRouter(0x0400); err == nil {
		t.Error("SetStateRouter should fail when disabled")
	}
}

// Ensure SetStateLeader from disabled returns error.
func TestMleSetStateLeaderDisabled(t *testing.T) {
	t.Parallel()

	m := NewMle()
	if err := m.SetStateLeader(0x0400); err == nil {
		t.Error("SetStateLeader should fail when disabled")
	}
}
