// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"testing"
	"time"
)

// --- RouterRoleTransition tests ---

func TestRouterRoleTransitionDefaults(t *testing.T) {
	t.Parallel()

	tr := NewRouterRoleTransition()

	if tr.IsPending() {
		t.Error("new transition should not be pending")
	}
	if tr.GetTimeout() != 0 {
		t.Errorf("timeout = %d, want 0", tr.GetTimeout())
	}
	if tr.GetJitter() != RouterSelectionJitter {
		t.Errorf("jitter = %d, want %d", tr.GetJitter(), RouterSelectionJitter)
	}
}

func TestRouterRoleTransitionStartTimeout(t *testing.T) {
	t.Parallel()

	tr := NewRouterRoleTransition()

	// Use a deterministic rand function that returns 50.
	tr.StartTimeout(func(_ int) int { return 50 })

	if !tr.IsPending() {
		t.Error("should be pending after StartTimeout")
	}
	if tr.GetTimeout() != 50 {
		t.Errorf("timeout = %d, want 50", tr.GetTimeout())
	}
}

func TestRouterRoleTransitionStartTimeoutZeroResult(t *testing.T) {
	t.Parallel()

	tr := NewRouterRoleTransition()

	// randFn returns 0 -- StartTimeout should clamp to 1.
	tr.StartTimeout(func(_ int) int { return 0 })

	if tr.GetTimeout() != 1 {
		t.Errorf("timeout = %d, want 1 (clamped from 0)", tr.GetTimeout())
	}
}

func TestRouterRoleTransitionStartTimeoutLowJitter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		jitter uint8
	}{
		{"zero jitter", 0},
		{"jitter=1", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tr := NewRouterRoleTransition()
			tr.SetJitter(tt.jitter)
			tr.StartTimeout(func(_ int) int { return 99 })

			if tr.GetTimeout() != 1 {
				t.Errorf("timeout = %d, want 1 for jitter=%d", tr.GetTimeout(), tt.jitter)
			}
		})
	}
}

func TestRouterRoleTransitionHandleTimeTick(t *testing.T) {
	t.Parallel()

	tr := NewRouterRoleTransition()
	tr.StartTimeout(func(_ int) int { return 3 })

	// Tick 1: 3 -> 2, not expired.
	if expired := tr.HandleTimeTick(); expired {
		t.Error("should not expire on first tick")
	}
	if tr.GetTimeout() != 2 {
		t.Errorf("timeout after 1 tick = %d, want 2", tr.GetTimeout())
	}

	// Tick 2: 2 -> 1, not expired.
	if expired := tr.HandleTimeTick(); expired {
		t.Error("should not expire on second tick")
	}

	// Tick 3: 1 -> 0, expired.
	if expired := tr.HandleTimeTick(); !expired {
		t.Error("should expire on third tick")
	}
	if tr.IsPending() {
		t.Error("should not be pending after expiry")
	}

	// Tick on zero: no-op, not expired.
	if expired := tr.HandleTimeTick(); expired {
		t.Error("ticking at zero should not report expired")
	}
}

func TestRouterRoleTransitionStopTimeout(t *testing.T) {
	t.Parallel()

	tr := NewRouterRoleTransition()
	tr.StartTimeout(func(_ int) int { return 50 })

	tr.StopTimeout()
	if tr.IsPending() {
		t.Error("should not be pending after StopTimeout")
	}
	if tr.GetTimeout() != 0 {
		t.Errorf("timeout = %d, want 0 after StopTimeout", tr.GetTimeout())
	}
}

func TestRouterRoleTransitionIncreaseTimeout(t *testing.T) {
	t.Parallel()

	tr := NewRouterRoleTransition()
	tr.StartTimeout(func(_ int) int { return 10 })

	tr.IncreaseTimeout(5)
	if tr.GetTimeout() != 15 {
		t.Errorf("timeout = %d, want 15 after +5", tr.GetTimeout())
	}

	// Increase beyond jitter should cap at jitter.
	tr.IncreaseTimeout(200)
	if tr.GetTimeout() != RouterSelectionJitter {
		t.Errorf("timeout = %d, want %d (capped at jitter)", tr.GetTimeout(), RouterSelectionJitter)
	}
}

func TestRouterRoleTransitionSetJitter(t *testing.T) {
	t.Parallel()

	tr := NewRouterRoleTransition()
	tr.SetJitter(60)
	if tr.GetJitter() != 60 {
		t.Errorf("jitter = %d, want 60", tr.GetJitter())
	}
}

// --- FtdState default values ---

func TestNewFtdState(t *testing.T) {
	t.Parallel()

	s := newFtdState()

	if s.routerID != InvalidRouterID {
		t.Errorf("routerID = %d, want %d", s.routerID, InvalidRouterID)
	}
	if s.addressSolicitPending {
		t.Error("addressSolicitPending should be false")
	}
	if s.addressSolicitRejected {
		t.Error("addressSolicitRejected should be false")
	}
	if s.networkIDTimeout != NetworkIDTimeout {
		t.Errorf("networkIDTimeout = %d, want %d", s.networkIDTimeout, NetworkIDTimeout)
	}
	if s.routerUpgradeThreshold != DefaultRouterUpgradeThreshold {
		t.Errorf("routerUpgradeThreshold = %d, want %d", s.routerUpgradeThreshold, DefaultRouterUpgradeThreshold)
	}
	if s.routerDowngradeThreshold != DefaultRouterDowngradeThreshold {
		t.Errorf("routerDowngradeThreshold = %d, want %d", s.routerDowngradeThreshold, DefaultRouterDowngradeThreshold)
	}
	if s.leaderWeight != 64 {
		t.Errorf("leaderWeight = %d, want 64", s.leaderWeight)
	}
	if s.childRouterLinks != ChildRouterLinks {
		t.Errorf("childRouterLinks = %d, want %d", s.childRouterLinks, ChildRouterLinks)
	}
	if s.previousPartitionID != 0 {
		t.Errorf("previousPartitionID = %d, want 0", s.previousPartitionID)
	}
	if s.previousPartitionRouterIDSequence != 0 {
		t.Errorf("previousPartitionRouterIDSequence = %d, want 0", s.previousPartitionRouterIDSequence)
	}
	if s.previousPartitionRouterIDSet != (RouterIDSet{}) {
		t.Error("previousPartitionRouterIDSet should be zero value")
	}
	if s.routerRoleTransition.GetJitter() != RouterSelectionJitter {
		t.Errorf("routerRoleTransition jitter = %d, want %d",
			s.routerRoleTransition.GetJitter(), RouterSelectionJitter)
	}
}

// --- FTD accessors on Mle ---

func TestMleFtdRouterID(t *testing.T) {
	t.Parallel()

	m := NewMle()

	if m.GetRouterID() != InvalidRouterID {
		t.Errorf("initial router ID = %d, want %d", m.GetRouterID(), InvalidRouterID)
	}

	m.SetRouterID(5)
	if m.GetRouterID() != 5 {
		t.Errorf("router ID = %d, want 5", m.GetRouterID())
	}
}

func TestMleFtdAddressSolicitPending(t *testing.T) {
	t.Parallel()

	m := NewMle()

	if m.IsAddressSolicitPending() {
		t.Error("should not be pending initially")
	}

	m.SetAddressSolicitPending(true)
	if !m.IsAddressSolicitPending() {
		t.Error("should be pending after set")
	}

	m.SetAddressSolicitPending(false)
	if m.IsAddressSolicitPending() {
		t.Error("should not be pending after clear")
	}
}

func TestMleFtdAddressSolicitRejected(t *testing.T) {
	t.Parallel()

	m := NewMle()

	if m.IsAddressSolicitRejected() {
		t.Error("should not be rejected initially")
	}

	m.SetAddressSolicitRejected(true)
	if !m.IsAddressSolicitRejected() {
		t.Error("should be rejected after set")
	}
}

func TestMleFtdNetworkIDTimeout(t *testing.T) {
	t.Parallel()

	m := NewMle()

	if m.GetNetworkIDTimeout() != NetworkIDTimeout {
		t.Errorf("default = %d, want %d", m.GetNetworkIDTimeout(), NetworkIDTimeout)
	}

	m.SetNetworkIDTimeout(60)
	if m.GetNetworkIDTimeout() != 60 {
		t.Errorf("timeout = %d, want 60", m.GetNetworkIDTimeout())
	}
}

func TestMleFtdRouterUpgradeThreshold(t *testing.T) {
	t.Parallel()

	m := NewMle()

	if m.GetRouterUpgradeThreshold() != DefaultRouterUpgradeThreshold {
		t.Errorf("default = %d, want %d", m.GetRouterUpgradeThreshold(), DefaultRouterUpgradeThreshold)
	}

	m.SetRouterUpgradeThreshold(10)
	if m.GetRouterUpgradeThreshold() != 10 {
		t.Errorf("threshold = %d, want 10", m.GetRouterUpgradeThreshold())
	}
}

func TestMleFtdRouterDowngradeThreshold(t *testing.T) {
	t.Parallel()

	m := NewMle()

	if m.GetRouterDowngradeThreshold() != DefaultRouterDowngradeThreshold {
		t.Errorf("default = %d, want %d", m.GetRouterDowngradeThreshold(), DefaultRouterDowngradeThreshold)
	}

	m.SetRouterDowngradeThreshold(30)
	if m.GetRouterDowngradeThreshold() != 30 {
		t.Errorf("threshold = %d, want 30", m.GetRouterDowngradeThreshold())
	}
}

func TestMleFtdLeaderWeight(t *testing.T) {
	t.Parallel()

	m := NewMle()

	if m.GetLeaderWeight() != 64 {
		t.Errorf("default = %d, want 64", m.GetLeaderWeight())
	}

	m.SetLeaderWeight(128)
	if m.GetLeaderWeight() != 128 {
		t.Errorf("weight = %d, want 128", m.GetLeaderWeight())
	}
}

func TestMleFtdChildRouterLinks(t *testing.T) {
	t.Parallel()

	m := NewMle()

	if m.GetChildRouterLinks() != ChildRouterLinks {
		t.Errorf("default = %d, want %d", m.GetChildRouterLinks(), ChildRouterLinks)
	}

	m.SetChildRouterLinks(5)
	if m.GetChildRouterLinks() != 5 {
		t.Errorf("links = %d, want 5", m.GetChildRouterLinks())
	}
}

func TestMleFtdPreviousPartitionID(t *testing.T) {
	t.Parallel()

	m := NewMle()

	if m.GetPreviousPartitionID() != 0 {
		t.Errorf("default = %d, want 0", m.GetPreviousPartitionID())
	}

	m.SetPreviousPartitionID(0xDEADBEEF)
	if m.GetPreviousPartitionID() != 0xDEADBEEF {
		t.Errorf("id = 0x%08x, want 0xDEADBEEF", m.GetPreviousPartitionID())
	}
}

func TestMleFtdPreviousPartitionRouterIDSequence(t *testing.T) {
	t.Parallel()

	m := NewMle()

	if m.GetPreviousPartitionRouterIDSequence() != 0 {
		t.Errorf("default = %d, want 0", m.GetPreviousPartitionRouterIDSequence())
	}

	m.SetPreviousPartitionRouterIDSequence(42)
	if m.GetPreviousPartitionRouterIDSequence() != 42 {
		t.Errorf("seq = %d, want 42", m.GetPreviousPartitionRouterIDSequence())
	}
}

func TestMleFtdPreviousPartitionRouterIDSet(t *testing.T) {
	t.Parallel()

	m := NewMle()

	zero := RouterIDSet{}
	if m.GetPreviousPartitionRouterIDSet() != zero {
		t.Error("default should be zero RouterIDSet")
	}

	var set RouterIDSet
	set.Add(5)
	set.Add(10)
	m.SetPreviousPartitionRouterIDSet(set)

	got := m.GetPreviousPartitionRouterIDSet()
	if got != set {
		t.Errorf("set = %v, want %v", got, set)
	}
}

func TestMleFtdGetRouterRoleTransition(t *testing.T) {
	t.Parallel()

	m := NewMle()

	tr := m.GetRouterRoleTransition()
	if tr == nil {
		t.Fatal("GetRouterRoleTransition returned nil")
	}
	if tr.GetJitter() != RouterSelectionJitter {
		t.Errorf("jitter = %d, want %d", tr.GetJitter(), RouterSelectionJitter)
	}

	// Mutating via the pointer should be reflected.
	tr.StartTimeout(func(_ int) int { return 25 })
	if m.GetRouterRoleTransition().GetTimeout() != 25 {
		t.Errorf("timeout = %d, want 25", m.GetRouterRoleTransition().GetTimeout())
	}
}

// --- SavePreviousPartitionInfo ---

func TestMleSavePreviousPartitionInfo(t *testing.T) {
	t.Parallel()

	m := NewMle()

	// Set current leader data with a known partition ID.
	m.SetLeaderData(LeaderData{
		PartitionID:    0x12345678,
		Weighting:      64,
		LeaderRouterID: 3,
	})

	var idSet RouterIDSet
	idSet.Add(1)
	idSet.Add(3)
	idSet.Add(10)

	m.SavePreviousPartitionInfo(7, idSet)

	if m.GetPreviousPartitionID() != 0x12345678 {
		t.Errorf("previousPartitionID = 0x%08x, want 0x12345678", m.GetPreviousPartitionID())
	}
	if m.GetPreviousPartitionRouterIDSequence() != 7 {
		t.Errorf("previousPartitionRouterIDSequence = %d, want 7",
			m.GetPreviousPartitionRouterIDSequence())
	}
	if m.GetPreviousPartitionRouterIDSet() != idSet {
		t.Errorf("previousPartitionRouterIDSet = %v, want %v",
			m.GetPreviousPartitionRouterIDSet(), idSet)
	}
}

// --- IsFullThreadDevice ---

func TestMleIsFullThreadDevice(t *testing.T) {
	t.Parallel()

	m := NewMle()

	// Default mode includes FTD.
	if !m.IsFullThreadDevice() {
		t.Error("default device should be FTD")
	}

	// Clear FTD flag.
	m.SetDeviceMode(NewDeviceMode(ModeRxOnWhenIdle | ModeFullNetworkData))
	if m.IsFullThreadDevice() {
		t.Error("should not be FTD after clearing flag")
	}
}

// --- DetermineAdvertiseIntervalMax ---

func TestDetermineAdvertiseIntervalMax(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		lq2Neighbors int
		want         time.Duration
	}{
		{
			name:         "zero neighbors clamps to lower bound",
			lq2Neighbors: 0,
			// (0+1)*4000ms = 4000ms < 12000ms => 12000ms
			want: AdvIntervalMaxLowerBound,
		},
		{
			name:         "one neighbor clamps to lower bound",
			lq2Neighbors: 1,
			// (1+1)*4000ms = 8000ms < 12000ms => 12000ms
			want: AdvIntervalMaxLowerBound,
		},
		{
			name:         "two neighbors clamps to lower bound",
			lq2Neighbors: 2,
			// (2+1)*4000ms = 12000ms == 12000ms => 12000ms
			want: AdvIntervalMaxLowerBound,
		},
		{
			name:         "three neighbors in range",
			lq2Neighbors: 3,
			// (3+1)*4000ms = 16000ms
			want: 16000 * time.Millisecond,
		},
		{
			name:         "five neighbors in range",
			lq2Neighbors: 5,
			// (5+1)*4000ms = 24000ms
			want: 24000 * time.Millisecond,
		},
		{
			name:         "seven neighbors clamps to upper bound",
			lq2Neighbors: 7,
			// (7+1)*4000ms = 32000ms == 32000ms => 32000ms
			want: AdvIntervalMaxUpperBound,
		},
		{
			name:         "ten neighbors clamps to upper bound",
			lq2Neighbors: 10,
			// (10+1)*4000ms = 44000ms > 32000ms => 32000ms
			want: AdvIntervalMaxUpperBound,
		},
		{
			name:         "large neighbor count clamps to upper bound",
			lq2Neighbors: 100,
			want:         AdvIntervalMaxUpperBound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := DetermineAdvertiseIntervalMax(tt.lq2Neighbors)
			if got != tt.want {
				t.Errorf("DetermineAdvertiseIntervalMax(%d) = %v, want %v",
					tt.lq2Neighbors, got, tt.want)
			}
		})
	}
}

// --- RouterUpgradeReason ---

func TestRouterUpgradeReasonValues(t *testing.T) {
	t.Parallel()

	// Verify the enum values match OpenThread.
	tests := []struct {
		reason RouterUpgradeReason
		want   uint8
	}{
		{UpgradeReasonTooFewRouters, 2},
		{UpgradeReasonHaveChildIDRequest, 3},
		{UpgradeReasonParentPartitionChange, 4},
		{UpgradeReasonBorderRouterRequest, 5},
	}

	for _, tt := range tests {
		if uint8(tt.reason) != tt.want {
			t.Errorf("RouterUpgradeReason %d != expected %d", uint8(tt.reason), tt.want)
		}
	}
}

// --- FTD constant sanity checks ---

func TestFtdConstantValues(t *testing.T) {
	t.Parallel()

	// Verify timing constants are sane.
	if AdvIntervalMin != 1*time.Second {
		t.Errorf("AdvIntervalMin = %v, want 1s", AdvIntervalMin)
	}
	if AdvIntervalNeighborMultiplier != 4*time.Second {
		t.Errorf("AdvIntervalNeighborMultiplier = %v, want 4s", AdvIntervalNeighborMultiplier)
	}
	if AdvIntervalMaxLowerBound != 12*time.Second {
		t.Errorf("AdvIntervalMaxLowerBound = %v, want 12s", AdvIntervalMaxLowerBound)
	}
	if AdvIntervalMaxUpperBound != 32*time.Second {
		t.Errorf("AdvIntervalMaxUpperBound = %v, want 32s", AdvIntervalMaxUpperBound)
	}
	if ReedAdvIntervalMin != 570*time.Second {
		t.Errorf("ReedAdvIntervalMin = %v, want 570s", ReedAdvIntervalMin)
	}
	if ReedAdvIntervalMax != 630*time.Second {
		t.Errorf("ReedAdvIntervalMax = %v, want 630s", ReedAdvIntervalMax)
	}
	if MaxLinkRequestDelayOnRouter != 1*time.Second {
		t.Errorf("MaxLinkRequestDelayOnRouter = %v, want 1s", MaxLinkRequestDelayOnRouter)
	}
	if LinkRequestTimeout != 2*time.Second {
		t.Errorf("LinkRequestTimeout = %v, want 2s", LinkRequestTimeout)
	}
	if MaxNeighborAge != 100*time.Second {
		t.Errorf("MaxNeighborAge = %v, want 100s", MaxNeighborAge)
	}

	// Verify threshold constants.
	if RouterSelectionJitter != 120 {
		t.Errorf("RouterSelectionJitter = %d, want 120", RouterSelectionJitter)
	}
	if DefaultRouterUpgradeThreshold != 16 {
		t.Errorf("DefaultRouterUpgradeThreshold = %d, want 16", DefaultRouterUpgradeThreshold)
	}
	if DefaultRouterDowngradeThreshold != 23 {
		t.Errorf("DefaultRouterDowngradeThreshold = %d, want 23", DefaultRouterDowngradeThreshold)
	}
}
