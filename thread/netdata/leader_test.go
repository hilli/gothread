// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package netdata

import (
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// mockRouterChecker implements RouterChecker for tests.
type mockRouterChecker struct {
	allocated map[uint8]bool
}

func newMockRouterChecker(ids ...uint8) *mockRouterChecker {
	m := &mockRouterChecker{allocated: make(map[uint8]bool)}
	for _, id := range ids {
		m.allocated[id] = true
	}
	return m
}

func (m *mockRouterChecker) IsRouterIDAllocated(id uint8) bool {
	return m.allocated[id]
}

// buildRegistration builds a valid registration blob with a single Prefix TLV
// containing one HasRoute entry for the given RLOC16.
func buildRegistration(prefix ip6.Prefix, rloc16 uint16, pref RoutePreference, stable bool) []byte {
	entry := HasRouteEntry{RLOC16: rloc16, Preference: pref}
	hrTLV := AppendHasRouteTLV(nil, stable, []HasRouteEntry{entry})

	info := PrefixTLVInfo{
		DomainID:    0,
		Prefix:      prefix,
		SubTLVsData: hrTLV,
		Stable:      stable,
	}
	value := AppendPrefixValue(nil, info)
	return AppendTLV(nil, TLVTypePrefix, stable, value)
}

// buildBorderRouterRegistration builds a registration blob with a Prefix TLV
// containing one BorderRouter entry.
func buildBorderRouterRegistration(prefix ip6.Prefix, rloc16 uint16, pref RoutePreference, onMesh, stable bool) []byte {
	entry := BorderRouterEntry{
		RLOC16:     rloc16,
		Preference: pref,
		OnMesh:     onMesh,
	}
	brTLV := AppendBorderRouterTLV(nil, stable, []BorderRouterEntry{entry})

	info := PrefixTLVInfo{
		DomainID:    0,
		Prefix:      prefix,
		SubTLVsData: brTLV,
		Stable:      stable,
	}
	value := AppendPrefixValue(nil, info)
	return AppendTLV(nil, TLVTypePrefix, stable, value)
}

// buildServerRegistration builds a registration blob with a Service TLV
// containing one Server sub-TLV.
func buildServerRegistration(enterpriseNumber uint32, serviceData []byte, rloc16 uint16, serverData []byte, stable bool) []byte {
	se := ServerEntry{Server16: rloc16, ServerData: serverData}
	serverTLV := AppendServerTLV(nil, stable, se)

	info := ServiceTLVInfo{
		ServiceID:        0,
		EnterpriseNumber: enterpriseNumber,
		ServiceData:      serviceData,
		SubTLVsData:      serverTLV,
		Stable:           stable,
	}
	value := AppendServiceValue(nil, info)
	return AppendTLV(nil, TLVTypeService, stable, value)
}

func testPrefix64(a, b byte) ip6.Prefix {
	var addr [16]byte
	addr[0] = 0x20
	addr[1] = 0x01
	addr[2] = 0x0D
	addr[3] = 0xB8
	addr[4] = a
	addr[5] = b
	return ip6.NewPrefix(addr, 64)
}

// ---------------------------------------------------------------------------
// ChangedFlags
// ---------------------------------------------------------------------------

func TestChangedFlagsInitialState(t *testing.T) {
	t.Parallel()
	var f ChangedFlags
	if f.DidChange() {
		t.Fatal("new ChangedFlags should not have changed")
	}
	if f.DidStableChange() {
		t.Fatal("new ChangedFlags should not have stable changed")
	}
}

func TestChangedFlagsUpdate(t *testing.T) {
	t.Parallel()

	var f1 ChangedFlags
	f1.Update(false) // temporary
	if !f1.DidChange() {
		t.Fatal("should have changed")
	}
	if f1.DidStableChange() {
		t.Fatal("should not have stable changed")
	}

	var f2 ChangedFlags
	f2.Update(true) // stable
	if !f2.DidChange() {
		t.Fatal("should have changed")
	}
	if !f2.DidStableChange() {
		t.Fatal("should have stable changed")
	}
}

// ---------------------------------------------------------------------------
// Leader construction and reset
// ---------------------------------------------------------------------------

func TestLeaderNewAndReset(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	if l.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", l.Len())
	}

	// Versions are randomized, just check they exist.
	v := l.Version()
	sv := l.StableVersion()

	l.Reset()
	// After reset, data should be empty and versions re-randomized.
	if l.Len() != 0 {
		t.Fatalf("Len() after Reset = %d, want 0", l.Len())
	}
	// Versions are random; they MAY be the same but very unlikely.
	_ = v
	_ = sv
}

// ---------------------------------------------------------------------------
// Version management
// ---------------------------------------------------------------------------

func TestLeaderIncrementVersions(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker()
	l := NewLeader(rc)

	v0 := l.Version()
	sv0 := l.StableVersion()

	l.IncrementVersions(false)
	if l.Version() != v0+1 {
		t.Fatalf("Version = %d, want %d", l.Version(), v0+1)
	}
	if l.StableVersion() != sv0 {
		t.Fatalf("StableVersion = %d, want %d (unchanged)", l.StableVersion(), sv0)
	}

	l.IncrementVersions(true)
	if l.Version() != v0+2 {
		t.Fatalf("Version = %d, want %d", l.Version(), v0+2)
	}
	if l.StableVersion() != sv0+1 {
		t.Fatalf("StableVersion = %d, want %d", l.StableVersion(), sv0+1)
	}
}

func TestLeaderOnChangedCallback(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker()
	l := NewLeader(rc)

	called := 0
	l.SetOnChanged(func() { called++ })

	l.IncrementVersions(false)
	if called != 1 {
		t.Fatalf("onChanged called %d times, want 1", called)
	}
}

// ---------------------------------------------------------------------------
// StableData
// ---------------------------------------------------------------------------

func TestLeaderStableData(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1, 2)
	l := NewLeader(rc)

	prefix1 := testPrefix64(0x00, 0x01)
	prefix2 := testPrefix64(0x00, 0x02)
	rloc1 := uint16(0x0400) // router ID 1
	rloc2 := uint16(0x0800) // router ID 2

	// Register a stable HasRoute from one router and an unstable one from another.
	regStable := buildRegistration(prefix1, rloc1, RoutePreferenceHigh, true)
	regUnstable := buildRegistration(prefix2, rloc2, RoutePreferenceLow, false)

	if err := l.RegisterNetworkData(rloc1, regStable); err != nil {
		t.Fatalf("register stable: %v", err)
	}
	if err := l.RegisterNetworkData(rloc2, regUnstable); err != nil {
		t.Fatalf("register unstable: %v", err)
	}

	// Full data should contain both.
	fullData := l.Data()
	if len(fullData) == 0 {
		t.Fatal("full data should not be empty")
	}

	// StableData should contain only the stable prefix.
	stableData := l.StableData()
	if len(stableData) == 0 {
		t.Fatal("stable data should not be empty")
	}
	if len(stableData) >= len(fullData) {
		t.Fatalf("stable data (%d bytes) should be smaller than full data (%d bytes)",
			len(stableData), len(fullData))
	}

	// Parse stable data — should only contain the stable prefix route.
	it := NewIterator(stableData)
	route, err := it.NextExternalRoute()
	if err != nil {
		t.Fatalf("NextExternalRoute on stable data: %v", err)
	}
	if !route.Prefix.IsEqual(prefix1) {
		t.Fatalf("stable route prefix mismatch: got %v, want %v", route.Prefix, prefix1)
	}

	// Should be no more routes in stable data.
	_, err = it.NextExternalRoute()
	if err == nil {
		t.Fatal("expected no more routes in stable data")
	}
}

func TestLeaderStableDataEmpty(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	stableData := l.StableData()
	if len(stableData) != 0 {
		t.Fatalf("StableData() = %d bytes, want 0 for empty leader", len(stableData))
	}
}

// ---------------------------------------------------------------------------
// RegisterNetworkData — HasRoute
// ---------------------------------------------------------------------------

func TestLeaderRegisterHasRoute(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1) // router ID 1
	l := NewLeader(rc)

	prefix := testPrefix64(0x00, 0x01)
	rloc16 := uint16(0x0400) // router ID 1

	reg := buildRegistration(prefix, rloc16, RoutePreferenceHigh, true)

	v0 := l.Version()
	sv0 := l.StableVersion()

	err := l.RegisterNetworkData(rloc16, reg)
	if err != nil {
		t.Fatalf("RegisterNetworkData error: %v", err)
	}

	if l.Len() == 0 {
		t.Fatal("leader data should not be empty after registration")
	}
	if l.Version() != v0+1 {
		t.Fatalf("Version = %d, want %d", l.Version(), v0+1)
	}
	if l.StableVersion() != sv0+1 {
		t.Fatalf("StableVersion = %d, want %d", l.StableVersion(), sv0+1)
	}

	// Verify the data can be parsed and contains our entry.
	it := NewIterator(l.Data())
	route, err := it.NextExternalRoute()
	if err != nil {
		t.Fatalf("NextExternalRoute error: %v", err)
	}
	if route.RLOC16 != rloc16 {
		t.Fatalf("route RLOC16 = 0x%04X, want 0x%04X", route.RLOC16, rloc16)
	}
	if route.Preference != RoutePreferenceHigh {
		t.Fatalf("route Preference = %d, want %d", route.Preference, RoutePreferenceHigh)
	}
	if !route.Prefix.IsEqual(prefix) {
		t.Fatal("route prefix mismatch")
	}
}

func TestLeaderRegisterTwoDevicesHasRoute(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1, 2)
	l := NewLeader(rc)

	prefix := testPrefix64(0x00, 0x01)
	rloc1 := uint16(0x0400) // router ID 1
	rloc2 := uint16(0x0800) // router ID 2

	reg1 := buildRegistration(prefix, rloc1, RoutePreferenceHigh, true)
	reg2 := buildRegistration(prefix, rloc2, RoutePreferenceLow, true)

	if err := l.RegisterNetworkData(rloc1, reg1); err != nil {
		t.Fatalf("Register device 1: %v", err)
	}
	if err := l.RegisterNetworkData(rloc2, reg2); err != nil {
		t.Fatalf("Register device 2: %v", err)
	}

	// Should have two routes for the same prefix.
	it := NewIterator(l.Data())
	count := 0
	for {
		_, err := it.NextExternalRoute()
		if err != nil {
			break
		}
		count++
	}
	if count != 2 {
		t.Fatalf("expected 2 external routes, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// RegisterNetworkData — idempotent re-registration
// ---------------------------------------------------------------------------

func TestLeaderReRegistrationIdempotent(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	prefix := testPrefix64(0x00, 0x01)
	rloc16 := uint16(0x0400)

	reg := buildRegistration(prefix, rloc16, RoutePreferenceHigh, true)

	if err := l.RegisterNetworkData(rloc16, reg); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	lenAfterFirst := l.Len()

	// Re-register the same data.
	if err := l.RegisterNetworkData(rloc16, reg); err != nil {
		t.Fatalf("second registration: %v", err)
	}

	if l.Len() != lenAfterFirst {
		t.Fatalf("Len after re-registration = %d, want %d (idempotent)", l.Len(), lenAfterFirst)
	}
}

// ---------------------------------------------------------------------------
// RegisterNetworkData — update (replace entry)
// ---------------------------------------------------------------------------

func TestLeaderReRegistrationUpdate(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	prefix := testPrefix64(0x00, 0x01)
	rloc16 := uint16(0x0400)

	reg1 := buildRegistration(prefix, rloc16, RoutePreferenceHigh, true)
	if err := l.RegisterNetworkData(rloc16, reg1); err != nil {
		t.Fatalf("first registration: %v", err)
	}

	// Update: change preference to Low.
	reg2 := buildRegistration(prefix, rloc16, RoutePreferenceLow, true)
	if err := l.RegisterNetworkData(rloc16, reg2); err != nil {
		t.Fatalf("update registration: %v", err)
	}

	// Should only have one route, with the new preference.
	it := NewIterator(l.Data())
	route, err := it.NextExternalRoute()
	if err != nil {
		t.Fatalf("NextExternalRoute: %v", err)
	}
	if route.Preference != RoutePreferenceLow {
		t.Fatalf("route Preference = %d, want %d", route.Preference, RoutePreferenceLow)
	}

	// No second route.
	_, err = it.NextExternalRoute()
	if err == nil {
		t.Fatal("expected no more routes after update")
	}
}

// ---------------------------------------------------------------------------
// RegisterNetworkData — validation
// ---------------------------------------------------------------------------

func TestLeaderRegisterRejectsUnallocatedRouter(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker() // no routers allocated
	l := NewLeader(rc)

	prefix := testPrefix64(0x00, 0x01)
	rloc16 := uint16(0x0400)

	reg := buildRegistration(prefix, rloc16, RoutePreferenceHigh, true)
	err := l.RegisterNetworkData(rloc16, reg)
	if err == nil {
		t.Fatal("expected error for unallocated router")
	}
}

func TestLeaderRegisterRejectsWrongRLOC16(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1, 2)
	l := NewLeader(rc)

	prefix := testPrefix64(0x00, 0x01)
	// Build registration with RLOC16 for router 2, but register under router 1.
	wrongRLOC := uint16(0x0800)
	claimedRLOC := uint16(0x0400)

	reg := buildRegistration(prefix, wrongRLOC, RoutePreferenceHigh, true)
	err := l.RegisterNetworkData(claimedRLOC, reg)
	if err == nil {
		t.Fatal("expected error for wrong RLOC16 in entries")
	}
}

// ---------------------------------------------------------------------------
// RemoveBorderRouter
// ---------------------------------------------------------------------------

func TestLeaderRemoveBorderRouter(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1, 2)
	l := NewLeader(rc)

	prefix := testPrefix64(0x00, 0x01)
	rloc1 := uint16(0x0400)
	rloc2 := uint16(0x0800)

	reg1 := buildRegistration(prefix, rloc1, RoutePreferenceHigh, true)
	reg2 := buildRegistration(prefix, rloc2, RoutePreferenceLow, true)

	_, _ = l.RegisterNetworkData(rloc1, reg1), l.RegisterNetworkData(rloc2, reg2)

	v0 := l.Version()
	l.RemoveBorderRouter(rloc1, MatchModeRLOC16)

	if l.Version() <= v0 {
		t.Fatal("version should have incremented")
	}

	// Should only have rloc2's route now.
	it := NewIterator(l.Data())
	route, err := it.NextExternalRoute()
	if err != nil {
		t.Fatalf("NextExternalRoute: %v", err)
	}
	if route.RLOC16 != rloc2 {
		t.Fatalf("remaining route RLOC = 0x%04X, want 0x%04X", route.RLOC16, rloc2)
	}
	_, err = it.NextExternalRoute()
	if err == nil {
		t.Fatal("expected only one route remaining")
	}
}

func TestLeaderRemoveBorderRouterCleansUpEmptyPrefix(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	prefix := testPrefix64(0x00, 0x01)
	rloc16 := uint16(0x0400)

	reg := buildRegistration(prefix, rloc16, RoutePreferenceHigh, true)
	if err := l.RegisterNetworkData(rloc16, reg); err != nil {
		t.Fatalf("register: %v", err)
	}

	l.RemoveBorderRouter(rloc16, MatchModeRLOC16)

	if l.Len() != 0 {
		t.Fatalf("Len = %d, want 0 (prefix TLV should be cleaned up)", l.Len())
	}
}

// ---------------------------------------------------------------------------
// BorderRouter with Context ID allocation
// ---------------------------------------------------------------------------

func TestLeaderRegisterBorderRouterAllocatesContextID(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	prefix := testPrefix64(0x00, 0x01)
	rloc16 := uint16(0x0400)

	reg := buildBorderRouterRegistration(prefix, rloc16, RoutePreferenceHigh, true, true)
	err := l.RegisterNetworkData(rloc16, reg)
	if err != nil {
		t.Fatalf("RegisterNetworkData: %v", err)
	}

	// Should have an on-mesh prefix.
	it := NewIterator(l.Data())
	omp, err := it.NextOnMeshPrefix()
	if err != nil {
		t.Fatalf("NextOnMeshPrefix: %v", err)
	}
	if omp.RLOC16 != rloc16 {
		t.Fatalf("RLOC16 = 0x%04X, want 0x%04X", omp.RLOC16, rloc16)
	}

	// Context ID 1 should be allocated (first available).
	if l.ContextIDManager().State(1) != ContextIDInUse {
		t.Fatal("context ID 1 should be InUse")
	}
}

func TestLeaderRemoveBorderRouterSchedulesContextRemoval(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	prefix := testPrefix64(0x00, 0x01)
	rloc16 := uint16(0x0400)

	reg := buildBorderRouterRegistration(prefix, rloc16, RoutePreferenceHigh, true, true)
	if err := l.RegisterNetworkData(rloc16, reg); err != nil {
		t.Fatalf("register: %v", err)
	}

	l.RemoveBorderRouter(rloc16, MatchModeRLOC16)

	// Context ID 1 should be scheduled for removal (not immediately freed).
	state := l.ContextIDManager().State(1)
	if state != ContextIDScheduledToRemove {
		t.Fatalf("context ID 1 state = %d, want ContextIDScheduledToRemove", state)
	}
}

// ---------------------------------------------------------------------------
// Service registration
// ---------------------------------------------------------------------------

func TestLeaderRegisterService(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	rloc16 := uint16(0x0400)
	reg := buildServerRegistration(ThreadEnterpriseNumber, []byte{0x01}, rloc16, []byte{0xAA, 0xBB}, true)

	err := l.RegisterNetworkData(rloc16, reg)
	if err != nil {
		t.Fatalf("RegisterNetworkData: %v", err)
	}

	if l.Len() == 0 {
		t.Fatal("leader data should not be empty after service registration")
	}

	// Verify by parsing TLVs.
	tlvs := ParseTLVs(l.Data())
	foundService := false
	for _, tlv := range tlvs {
		if tlv.Type == TLVTypeService {
			foundService = true
		}
	}
	if !foundService {
		t.Fatal("expected a Service TLV in leader data")
	}
}

func TestLeaderRemoveServiceCleansUp(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	rloc16 := uint16(0x0400)
	reg := buildServerRegistration(ThreadEnterpriseNumber, []byte{0x01}, rloc16, []byte{0xAA}, true)

	if err := l.RegisterNetworkData(rloc16, reg); err != nil {
		t.Fatalf("register: %v", err)
	}

	l.RemoveBorderRouter(rloc16, MatchModeRLOC16)

	if l.Len() != 0 {
		t.Fatalf("Len = %d, want 0 after removing all entries", l.Len())
	}
}

// ---------------------------------------------------------------------------
// FindContextForPrefix / FindContextForID
// ---------------------------------------------------------------------------

func TestLeaderFindContextForPrefix(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	prefix := testPrefix64(0x00, 0x01)
	rloc16 := uint16(0x0400)

	reg := buildBorderRouterRegistration(prefix, rloc16, RoutePreferenceHigh, true, true)
	if err := l.RegisterNetworkData(rloc16, reg); err != nil {
		t.Fatalf("register: %v", err)
	}

	ctx, err := l.FindContextForPrefix(prefix)
	if err != nil {
		t.Fatalf("FindContextForPrefix: %v", err)
	}
	if ctx.ContextID == 0 {
		t.Fatal("ContextID should be non-zero")
	}
	if !ctx.Compress {
		t.Fatal("Compress should be true")
	}
}

func TestLeaderFindContextForID(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	prefix := testPrefix64(0x00, 0x01)
	rloc16 := uint16(0x0400)

	reg := buildBorderRouterRegistration(prefix, rloc16, RoutePreferenceHigh, true, true)
	if err := l.RegisterNetworkData(rloc16, reg); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Context ID 1 should have been allocated.
	ctx, foundPrefix, err := l.FindContextForID(1)
	if err != nil {
		t.Fatalf("FindContextForID: %v", err)
	}
	if ctx.ContextID != 1 {
		t.Fatalf("ContextID = %d, want 1", ctx.ContextID)
	}
	if !foundPrefix.IsEqual(prefix) {
		t.Fatal("prefix mismatch")
	}
}

func TestLeaderFindContextForIDNotFound(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker()
	l := NewLeader(rc)

	_, _, err := l.FindContextForID(1)
	if err != goterrors.ErrNotFound {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

func TestLeaderFindContextForPrefixNotFound(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker()
	l := NewLeader(rc)

	prefix := testPrefix64(0x00, 0x01)
	_, err := l.FindContextForPrefix(prefix)
	if err != goterrors.ErrNotFound {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// RemoveContext
// ---------------------------------------------------------------------------

func TestLeaderRemoveContext(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	prefix := testPrefix64(0x00, 0x01)
	rloc16 := uint16(0x0400)

	reg := buildBorderRouterRegistration(prefix, rloc16, RoutePreferenceHigh, true, true)
	if err := l.RegisterNetworkData(rloc16, reg); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Remove the border router entries (this schedules context removal).
	l.RemoveBorderRouter(rloc16, MatchModeRLOC16)

	v0 := l.Version()
	sv0 := l.StableVersion()

	// Simulate timer expiry by calling RemoveContext directly.
	l.RemoveContext(1)

	if l.Version() != v0+1 {
		t.Fatalf("Version = %d, want %d", l.Version(), v0+1)
	}
	if l.StableVersion() != sv0+1 {
		t.Fatalf("StableVersion = %d, want %d", l.StableVersion(), sv0+1)
	}

	// The prefix TLV should be fully cleaned up.
	if l.Len() != 0 {
		t.Fatalf("Len = %d, want 0 after RemoveContext", l.Len())
	}
}

// ---------------------------------------------------------------------------
// Multiple prefixes and context ID tracking
// ---------------------------------------------------------------------------

func TestLeaderMultiplePrefixesUseDistinctContextIDs(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	prefix1 := testPrefix64(0x00, 0x01)
	prefix2 := testPrefix64(0x00, 0x02)
	rloc16 := uint16(0x0400)

	reg1 := buildBorderRouterRegistration(prefix1, rloc16, RoutePreferenceHigh, true, true)
	reg2 := buildBorderRouterRegistration(prefix2, rloc16, RoutePreferenceMedium, true, true)

	// Register both in a single blob by concatenating.
	combined := make([]byte, 0, len(reg1)+len(reg2))
	combined = append(combined, reg1...)
	combined = append(combined, reg2...)
	if err := l.RegisterNetworkData(rloc16, combined); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Both context IDs 1 and 2 should be in use.
	if l.ContextIDManager().State(1) != ContextIDInUse {
		t.Fatal("context ID 1 should be InUse")
	}
	if l.ContextIDManager().State(2) != ContextIDInUse {
		t.Fatal("context ID 2 should be InUse")
	}

	// FindContextForID for both should work.
	ctx1, p1, err := l.FindContextForID(1)
	if err != nil {
		t.Fatalf("FindContextForID(1): %v", err)
	}
	ctx2, p2, err := l.FindContextForID(2)
	if err != nil {
		t.Fatalf("FindContextForID(2): %v", err)
	}

	// Verify they map to different prefixes.
	if p1.IsEqual(p2) {
		t.Fatal("prefixes should be different")
	}
	if ctx1.ContextID == ctx2.ContextID {
		t.Fatal("context IDs should be different")
	}
}

// ---------------------------------------------------------------------------
// MatchModeRouterID
// ---------------------------------------------------------------------------

func TestLeaderRemoveBorderRouterByRouterID(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	prefix := testPrefix64(0x00, 0x01)
	// Router ID 1 = RLOC16 0x0400, a child would be 0x0401.
	routerRLOC := uint16(0x0400)
	childRLOC := uint16(0x0401)

	reg1 := buildRegistration(prefix, routerRLOC, RoutePreferenceHigh, true)
	if err := l.RegisterNetworkData(routerRLOC, reg1); err != nil {
		t.Fatalf("register router: %v", err)
	}

	reg2 := buildRegistration(prefix, childRLOC, RoutePreferenceLow, true)
	if err := l.RegisterNetworkData(childRLOC, reg2); err != nil {
		t.Fatalf("register child: %v", err)
	}

	// Remove by router ID — should remove both.
	l.RemoveBorderRouter(routerRLOC, MatchModeRouterID)

	if l.Len() != 0 {
		t.Fatalf("Len = %d, want 0 after router ID removal", l.Len())
	}
}

// ---------------------------------------------------------------------------
// ValidateRegistration
// ---------------------------------------------------------------------------

func TestValidateRegistrationGoodData(t *testing.T) {
	t.Parallel()
	prefix := testPrefix64(0x00, 0x01)
	rloc16 := uint16(0x0400)

	reg := buildRegistration(prefix, rloc16, RoutePreferenceHigh, true)
	if err := ValidateRegistration(reg, rloc16); err != nil {
		t.Fatalf("ValidateRegistration: %v", err)
	}
}

func TestValidateRegistrationBadRLOC(t *testing.T) {
	t.Parallel()
	prefix := testPrefix64(0x00, 0x01)
	rloc16 := uint16(0x0400)
	wrongRLOC := uint16(0x0800)

	reg := buildRegistration(prefix, rloc16, RoutePreferenceHigh, true)
	err := ValidateRegistration(reg, wrongRLOC)
	if err == nil {
		t.Fatal("expected error for wrong RLOC")
	}
}

func TestValidateRegistrationEmpty(t *testing.T) {
	t.Parallel()
	// Empty data should be valid.
	if err := ValidateRegistration(nil, 0x0400); err != nil {
		t.Fatalf("ValidateRegistration(nil): %v", err)
	}
}

// ---------------------------------------------------------------------------
// CommissioningData methods
// ---------------------------------------------------------------------------

func TestLeaderSetCommissioningData(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	verBefore := l.Version()
	stableBefore := l.StableVersion()

	meshCop := []byte{0x01, 0x02, 0x03, 0x04}
	if err := l.SetCommissioningData(meshCop); err != nil {
		t.Fatalf("SetCommissioningData: %v", err)
	}

	got := l.GetCommissioningData()
	if len(got) != len(meshCop) {
		t.Fatalf("GetCommissioningData len = %d, want %d", len(got), len(meshCop))
	}
	for i, b := range got {
		if b != meshCop[i] {
			t.Errorf("GetCommissioningData[%d] = 0x%02X, want 0x%02X", i, b, meshCop[i])
		}
	}

	// Full version should have been bumped, stable should NOT.
	if l.Version() != verBefore+1 {
		t.Errorf("Version = %d, want %d", l.Version(), verBefore+1)
	}
	if l.StableVersion() != stableBefore {
		t.Errorf("StableVersion = %d, want %d (unchanged)", l.StableVersion(), stableBefore)
	}
}

func TestLeaderSetCommissioningDataReplace(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	first := []byte{0xAA, 0xBB}
	if err := l.SetCommissioningData(first); err != nil {
		t.Fatalf("SetCommissioningData(first): %v", err)
	}

	second := []byte{0xCC, 0xDD, 0xEE}
	if err := l.SetCommissioningData(second); err != nil {
		t.Fatalf("SetCommissioningData(second): %v", err)
	}

	got := l.GetCommissioningData()
	if len(got) != len(second) {
		t.Fatalf("GetCommissioningData len = %d, want %d", len(got), len(second))
	}
	for i, b := range got {
		if b != second[i] {
			t.Errorf("GetCommissioningData[%d] = 0x%02X, want 0x%02X", i, b, second[i])
		}
	}
}

func TestLeaderSetCommissioningDataEmpty(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	// Set data, then remove by setting empty.
	if err := l.SetCommissioningData([]byte{0x01}); err != nil {
		t.Fatalf("SetCommissioningData: %v", err)
	}
	if l.GetCommissioningData() == nil {
		t.Fatal("expected non-nil commissioning data")
	}

	if err := l.SetCommissioningData(nil); err != nil {
		t.Fatalf("SetCommissioningData(nil): %v", err)
	}
	if l.GetCommissioningData() != nil {
		t.Error("expected nil after setting empty data")
	}
}

func TestLeaderGetCommissioningDataNone(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	if got := l.GetCommissioningData(); got != nil {
		t.Errorf("GetCommissioningData = %v, want nil on fresh leader", got)
	}
}

func TestLeaderRemoveCommissioningData(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	if err := l.SetCommissioningData([]byte{0xDE, 0xAD}); err != nil {
		t.Fatalf("SetCommissioningData: %v", err)
	}

	verBefore := l.Version()
	stableBefore := l.StableVersion()

	l.RemoveCommissioningData()

	if l.GetCommissioningData() != nil {
		t.Error("expected nil after RemoveCommissioningData")
	}

	// Full version bumped, stable unchanged.
	if l.Version() != verBefore+1 {
		t.Errorf("Version = %d, want %d", l.Version(), verBefore+1)
	}
	if l.StableVersion() != stableBefore {
		t.Errorf("StableVersion = %d, want %d (unchanged)", l.StableVersion(), stableBefore)
	}
}

func TestLeaderRemoveCommissioningDataNoop(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	// Should not panic when no commissioning data exists.
	l.RemoveCommissioningData()

	if l.GetCommissioningData() != nil {
		t.Error("expected nil")
	}
}

func TestLeaderCommissioningDataIsUnstable(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	meshCop := []byte{0x10, 0x20}
	if err := l.SetCommissioningData(meshCop); err != nil {
		t.Fatalf("SetCommissioningData: %v", err)
	}

	// Walk the raw data and find the CommissioningData TLV header.
	data := l.Data()
	found := false
	off := 0
	for off < len(data) {
		if off+TLVHeaderSize > len(data) {
			break
		}
		typ, stable, length, err := ParseTLVHeader(data[off:])
		if err != nil {
			t.Fatalf("ParseTLVHeader at offset %d: %v", off, err)
		}
		if typ == TLVTypeCommissioningData {
			found = true
			if stable {
				t.Error("CommissioningData TLV has stable_bit=1, want 0 (unstable)")
			}
			if int(length) != len(meshCop) {
				t.Errorf("TLV length = %d, want %d", length, len(meshCop))
			}
			break
		}
		off += TLVHeaderSize + int(length)
	}
	if !found {
		t.Fatal("CommissioningData TLV not found in raw data")
	}
}

func TestLeaderCommissioningDataCoexistsWithOtherTLVs(t *testing.T) {
	t.Parallel()
	rc := newMockRouterChecker(1)
	l := NewLeader(rc)

	// Register a HasRoute entry first.
	prefix := testPrefix64(0x00, 0x01)
	reg := buildRegistration(prefix, 0x0400, RoutePreferenceHigh, true)
	if err := l.RegisterNetworkData(0x0400, reg); err != nil {
		t.Fatalf("RegisterNetworkData: %v", err)
	}
	lenBefore := l.Len()

	// Add commissioning data.
	meshCop := []byte{0xCA, 0xFE}
	if err := l.SetCommissioningData(meshCop); err != nil {
		t.Fatalf("SetCommissioningData: %v", err)
	}

	// The network data should be larger now.
	if l.Len() <= lenBefore {
		t.Errorf("Len = %d, expected > %d after adding commissioning data", l.Len(), lenBefore)
	}

	// Both should be retrievable.
	if l.GetCommissioningData() == nil {
		t.Error("commissioning data nil after coexist test")
	}

	// Remove commissioning data; prefix data should remain.
	l.RemoveCommissioningData()
	if l.Len() == 0 {
		t.Error("Len = 0, expected prefix data to remain")
	}
	if l.GetCommissioningData() != nil {
		t.Error("commissioning data should be nil after removal")
	}
}
