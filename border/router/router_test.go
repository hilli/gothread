// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package router

import (
	"testing"

	"github.com/hilli/gothread/border"
	"github.com/hilli/gothread/crypto/sha256"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/nd6"
)

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

// testExtAddr is a deterministic extended address for reproducible tests.
var testExtAddr = [8]byte{0x18, 0xb4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x01}

// computeExpectedHash returns the SHA-256 of extAddr for verifying prefix
// generation.
func computeExpectedHash(extAddr [8]byte) sha256.Hash {
	var s sha256.Sha256
	s.Start()
	s.Update(extAddr[:])
	var h sha256.Hash
	s.Finish(&h)
	return h
}

// ---------------------------------------------------------------------------
// OmrPrefix tests
// ---------------------------------------------------------------------------

func TestOmrPrefixIsEmpty(t *testing.T) {
	var p OmrPrefix
	if !p.IsEmpty() {
		t.Fatal("zero OmrPrefix should be empty")
	}
	p.PrefixLen = 64
	if p.IsEmpty() {
		t.Fatal("OmrPrefix with PrefixLen=64 should not be empty")
	}
}

func TestOmrPrefixIsEqual(t *testing.T) {
	a := OmrPrefix{Prefix: [16]byte{0xfd, 0x01}, PrefixLen: 64, Preference: nd6.RoutePrefMedium}
	b := OmrPrefix{Prefix: [16]byte{0xfd, 0x01}, PrefixLen: 64, Preference: nd6.RoutePrefHigh}
	if !a.IsEqual(b) {
		t.Fatal("prefixes with same addr/len should be equal regardless of preference")
	}

	c := OmrPrefix{Prefix: [16]byte{0xfd, 0x02}, PrefixLen: 64}
	if a.IsEqual(c) {
		t.Fatal("prefixes with different addr should not be equal")
	}

	d := OmrPrefix{Prefix: [16]byte{0xfd, 0x01}, PrefixLen: 48}
	if a.IsEqual(d) {
		t.Fatal("prefixes with different length should not be equal")
	}
}

func TestOmrPrefixIsFavoredOver(t *testing.T) {
	// Longer prefix wins.
	long := OmrPrefix{Prefix: [16]byte{0xfd}, PrefixLen: 64, Preference: nd6.RoutePrefLow}
	short := OmrPrefix{Prefix: [16]byte{0xfd}, PrefixLen: 48, Preference: nd6.RoutePrefHigh}
	if !long.IsFavoredOver(short) {
		t.Fatal("longer prefix should be favored")
	}

	// Higher preference wins when length is equal.
	high := OmrPrefix{Prefix: [16]byte{0xfd}, PrefixLen: 64, Preference: nd6.RoutePrefHigh}
	med := OmrPrefix{Prefix: [16]byte{0xfd}, PrefixLen: 64, Preference: nd6.RoutePrefMedium}
	if !high.IsFavoredOver(med) {
		t.Fatal("higher preference should be favored")
	}
	if med.IsFavoredOver(high) {
		t.Fatal("medium should not be favored over high")
	}

	// Local wins over remote when same prefix/pref.
	local := OmrPrefix{Prefix: [16]byte{0xfd, 0xaa}, PrefixLen: 64, Preference: nd6.RoutePrefMedium, IsLocal: true}
	remote := OmrPrefix{Prefix: [16]byte{0xfd, 0xaa}, PrefixLen: 64, Preference: nd6.RoutePrefMedium, IsLocal: false}
	if !local.IsFavoredOver(remote) {
		t.Fatal("local should be favored over remote")
	}

	// Lexicographic tiebreak: smaller prefix bytes win.
	a := OmrPrefix{Prefix: [16]byte{0xfd, 0x00, 0x01}, PrefixLen: 64, Preference: nd6.RoutePrefMedium, IsLocal: true}
	b := OmrPrefix{Prefix: [16]byte{0xfd, 0x00, 0x02}, PrefixLen: 64, Preference: nd6.RoutePrefMedium, IsLocal: true}
	if !a.IsFavoredOver(b) {
		t.Fatal("lexicographically smaller prefix should win")
	}
	if b.IsFavoredOver(a) {
		t.Fatal("lexicographically larger prefix should not win")
	}
}

// ---------------------------------------------------------------------------
// OmrPrefixManager tests
// ---------------------------------------------------------------------------

func TestOmrPrefixManagerGenerateLocalPrefix(t *testing.T) {
	m := NewOmrPrefixManager()

	if _, ok := m.GetLocalPrefix(); ok {
		t.Fatal("should have no local prefix before generation")
	}

	if err := m.GenerateLocalPrefix(testExtAddr); err != nil {
		t.Fatalf("GenerateLocalPrefix failed: %v", err)
	}

	lp, ok := m.GetLocalPrefix()
	if !ok {
		t.Fatal("should have local prefix after generation")
	}

	if lp.PrefixLen != 64 {
		t.Fatalf("expected prefix length 64, got %d", lp.PrefixLen)
	}
	if lp.Prefix[0] != 0xfd {
		t.Fatalf("expected ULA prefix (0xfd), got 0x%02x", lp.Prefix[0])
	}
	if !lp.IsLocal {
		t.Fatal("local prefix should have IsLocal=true")
	}
	if lp.Preference != nd6.RoutePrefMedium {
		t.Fatal("local prefix should have medium preference")
	}

	// Verify hash-derived bytes.
	h := computeExpectedHash(testExtAddr)
	for i := 0; i < 5; i++ {
		if lp.Prefix[1+i] != h[i] {
			t.Fatalf("prefix byte %d mismatch: got 0x%02x, want 0x%02x", 1+i, lp.Prefix[1+i], h[i])
		}
	}

	// Subnet ID bytes should be zero.
	if lp.Prefix[6] != 0 || lp.Prefix[7] != 0 {
		t.Fatal("subnet ID bytes should be zero")
	}
}

func TestOmrPrefixManagerGenerateDeterministic(t *testing.T) {
	m1 := NewOmrPrefixManager()
	m2 := NewOmrPrefixManager()

	_ = m1.GenerateLocalPrefix(testExtAddr)
	_ = m2.GenerateLocalPrefix(testExtAddr)

	p1, _ := m1.GetLocalPrefix()
	p2, _ := m2.GetLocalPrefix()

	if !p1.IsEqual(p2) {
		t.Fatal("same extended address should produce the same OMR prefix")
	}
}

func TestOmrPrefixManagerDifferentAddresses(t *testing.T) {
	m1 := NewOmrPrefixManager()
	m2 := NewOmrPrefixManager()

	addr1 := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	addr2 := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	_ = m1.GenerateLocalPrefix(addr1)
	_ = m2.GenerateLocalPrefix(addr2)

	p1, _ := m1.GetLocalPrefix()
	p2, _ := m2.GetLocalPrefix()

	if p1.IsEqual(p2) {
		t.Fatal("different extended addresses should produce different OMR prefixes")
	}
}

func TestOmrPrefixManagerEvaluateLocalOnly(t *testing.T) {
	m := NewOmrPrefixManager()
	_ = m.GenerateLocalPrefix(testExtAddr)

	changed := m.Evaluate(nil)
	if !changed {
		t.Fatal("first Evaluate should report changed")
	}

	fp, ok := m.GetFavoredPrefix()
	if !ok {
		t.Fatal("should have favored prefix after evaluate")
	}
	if !fp.IsLocal {
		t.Fatal("favored prefix should be local when no network prefixes")
	}

	// Second evaluate with same state should not change.
	changed = m.Evaluate(nil)
	if changed {
		t.Fatal("second Evaluate with same state should not report changed")
	}
}

func TestOmrPrefixManagerEvaluateWithNetworkPrefixes(t *testing.T) {
	m := NewOmrPrefixManager()
	_ = m.GenerateLocalPrefix(testExtAddr)

	// Network prefix with higher preference should become favored.
	networkPrefix := OmrPrefix{
		Prefix:     [16]byte{0xfd, 0xde, 0xad, 0xbe, 0xef, 0x00},
		PrefixLen:  64,
		Preference: nd6.RoutePrefHigh,
		IsLocal:    false,
	}

	changed := m.Evaluate([]OmrPrefix{networkPrefix})
	if !changed {
		t.Fatal("Evaluate with new network prefix should report changed")
	}

	fp, ok := m.GetFavoredPrefix()
	if !ok {
		t.Fatal("should have favored prefix")
	}
	if fp.IsLocal {
		t.Fatal("favored should be network prefix (higher preference)")
	}
	if fp.Preference != nd6.RoutePrefHigh {
		t.Fatal("favored should have high preference")
	}
}

func TestOmrPrefixManagerEvaluateLocalFavoredOverLowNetwork(t *testing.T) {
	m := NewOmrPrefixManager()
	_ = m.GenerateLocalPrefix(testExtAddr)

	// Network prefix with low preference should lose to local medium.
	networkPrefix := OmrPrefix{
		Prefix:     [16]byte{0xfd, 0xde, 0xad, 0xbe, 0xef, 0x00},
		PrefixLen:  64,
		Preference: nd6.RoutePrefLow,
		IsLocal:    false,
	}

	m.Evaluate([]OmrPrefix{networkPrefix})

	fp, _ := m.GetFavoredPrefix()
	if !fp.IsLocal {
		t.Fatal("local (medium) should be favored over network (low)")
	}
}

func TestOmrPrefixManagerShouldPublish(t *testing.T) {
	m := NewOmrPrefixManager()
	_ = m.GenerateLocalPrefix(testExtAddr)
	m.Evaluate(nil)

	if !m.ShouldPublish() {
		t.Fatal("should publish when local is favored")
	}

	// Add a better network prefix.
	networkPrefix := OmrPrefix{
		Prefix:     [16]byte{0xfd, 0xde, 0xad, 0xbe, 0xef, 0x00},
		PrefixLen:  64,
		Preference: nd6.RoutePrefHigh,
		IsLocal:    false,
	}
	m.Evaluate([]OmrPrefix{networkPrefix})

	if m.ShouldPublish() {
		t.Fatal("should not publish when network prefix is favored")
	}
}

func TestOmrPrefixManagerNetDataFlag(t *testing.T) {
	m := NewOmrPrefixManager()

	if m.IsAddedInNetData() {
		t.Fatal("should not be in net data initially")
	}
	m.SetAddedInNetData(true)
	if !m.IsAddedInNetData() {
		t.Fatal("should be in net data after setting")
	}
	m.SetAddedInNetData(false)
	if m.IsAddedInNetData() {
		t.Fatal("should not be in net data after clearing")
	}
}

// ---------------------------------------------------------------------------
// OnLinkPrefixManager tests
// ---------------------------------------------------------------------------

func TestOnLinkPrefixManagerGenerateLocalPrefix(t *testing.T) {
	m := NewOnLinkPrefixManager()

	if _, _, ok := m.GetLocalPrefix(); ok {
		t.Fatal("should have no local prefix before generation")
	}

	if err := m.GenerateLocalPrefix(testExtAddr); err != nil {
		t.Fatalf("GenerateLocalPrefix failed: %v", err)
	}

	prefix, prefixLen, ok := m.GetLocalPrefix()
	if !ok {
		t.Fatal("should have local prefix after generation")
	}
	if prefixLen != 48 {
		t.Fatalf("expected prefix length 48, got %d", prefixLen)
	}
	if prefix[0] != 0xfd {
		t.Fatalf("expected ULA prefix (0xfd), got 0x%02x", prefix[0])
	}

	// Verify hash bytes 5..9 are used.
	h := computeExpectedHash(testExtAddr)
	for i := 0; i < 5; i++ {
		if prefix[1+i] != h[5+i] {
			t.Fatalf("prefix byte %d mismatch: got 0x%02x, want 0x%02x", 1+i, prefix[1+i], h[5+i])
		}
	}

	// Remaining bytes should be zero.
	for i := 6; i < 16; i++ {
		if prefix[i] != 0 {
			t.Fatalf("prefix byte %d should be zero, got 0x%02x", i, prefix[i])
		}
	}
}

func TestOnLinkPrefixManagerDifferentFromOmr(t *testing.T) {
	omr := NewOmrPrefixManager()
	onLink := NewOnLinkPrefixManager()

	_ = omr.GenerateLocalPrefix(testExtAddr)
	_ = onLink.GenerateLocalPrefix(testExtAddr)

	omrP, _ := omr.GetLocalPrefix()
	onLinkP, _, _ := onLink.GetLocalPrefix()

	// The prefixes should differ because they use different hash byte ranges.
	same := true
	for i := 1; i < 6; i++ {
		if omrP.Prefix[i] != onLinkP[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("OMR and on-link prefix should use different hash bytes")
	}
}

func TestOnLinkPrefixManagerEvaluate(t *testing.T) {
	m := NewOnLinkPrefixManager()
	_ = m.GenerateLocalPrefix(testExtAddr)

	// No discovered on-link prefix: should advertise.
	changed := m.Evaluate(false)
	if !changed {
		t.Fatal("first Evaluate should change (false -> true)")
	}
	if !m.ShouldAdvertise() {
		t.Fatal("should advertise when no discovered on-link prefix")
	}

	// Idempotent.
	changed = m.Evaluate(false)
	if changed {
		t.Fatal("second Evaluate with same state should not change")
	}

	// Discovered on-link prefix: should stop advertising.
	changed = m.Evaluate(true)
	if !changed {
		t.Fatal("Evaluate should report change when discovered prefix appears")
	}
	if m.ShouldAdvertise() {
		t.Fatal("should not advertise when discovered on-link prefix exists")
	}

	// Discovered prefix goes away: resume advertising.
	changed = m.Evaluate(false)
	if !changed {
		t.Fatal("should report change when discovered prefix disappears")
	}
	if !m.ShouldAdvertise() {
		t.Fatal("should resume advertising")
	}
}

func TestOnLinkPrefixManagerShouldAdvertiseWithoutGenerate(t *testing.T) {
	m := NewOnLinkPrefixManager()

	// Without generating a prefix, should never advertise.
	m.Evaluate(false)
	if m.ShouldAdvertise() {
		t.Fatal("should not advertise without generated prefix")
	}
}

// ---------------------------------------------------------------------------
// RoutePublisher tests
// ---------------------------------------------------------------------------

func TestRoutePublisherAddAndGet(t *testing.T) {
	p := NewRoutePublisher()

	prefix := [16]byte{0x20, 0x01, 0x0d, 0xb8}
	err := p.AddRoute(prefix, 48, nd6.RoutePrefMedium)
	if err != nil {
		t.Fatalf("AddRoute failed: %v", err)
	}

	routes := p.GetRoutes()
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].PrefixLen != 48 {
		t.Fatalf("expected prefix len 48, got %d", routes[0].PrefixLen)
	}
	if routes[0].Preference != nd6.RoutePrefMedium {
		t.Fatal("expected medium preference")
	}
	if !routes[0].Stable {
		t.Fatal("route should be stable by default")
	}
}

func TestRoutePublisherAddUpdatesExisting(t *testing.T) {
	p := NewRoutePublisher()
	prefix := [16]byte{0x20, 0x01, 0x0d, 0xb8}

	_ = p.AddRoute(prefix, 48, nd6.RoutePrefMedium)
	_ = p.AddRoute(prefix, 48, nd6.RoutePrefHigh)

	routes := p.GetRoutes()
	if len(routes) != 1 {
		t.Fatalf("expected 1 route after update, got %d", len(routes))
	}
	if routes[0].Preference != nd6.RoutePrefHigh {
		t.Fatal("preference should be updated to high")
	}
}

func TestRoutePublisherHasRoute(t *testing.T) {
	p := NewRoutePublisher()
	prefix := [16]byte{0x20, 0x01, 0x0d, 0xb8}
	_ = p.AddRoute(prefix, 48, nd6.RoutePrefMedium)

	if !p.HasRoute(prefix, 48) {
		t.Fatal("should have the route")
	}

	other := [16]byte{0x20, 0x01, 0x0d, 0xb9}
	if p.HasRoute(other, 48) {
		t.Fatal("should not have different route")
	}

	if p.HasRoute(prefix, 64) {
		t.Fatal("should not match different prefix length")
	}
}

func TestRoutePublisherRemoveRoute(t *testing.T) {
	p := NewRoutePublisher()
	prefix := [16]byte{0x20, 0x01, 0x0d, 0xb8}
	_ = p.AddRoute(prefix, 48, nd6.RoutePrefMedium)

	if !p.RemoveRoute(prefix, 48) {
		t.Fatal("RemoveRoute should return true")
	}
	if p.HasRoute(prefix, 48) {
		t.Fatal("route should be gone after removal")
	}
	if p.Count() != 0 {
		t.Fatal("count should be 0")
	}

	// Remove non-existent.
	if p.RemoveRoute(prefix, 48) {
		t.Fatal("RemoveRoute on empty should return false")
	}
}

func TestRoutePublisherClearRoutes(t *testing.T) {
	p := NewRoutePublisher()
	_ = p.AddRoute([16]byte{0x20, 0x01}, 32, nd6.RoutePrefMedium)
	_ = p.AddRoute([16]byte{0x20, 0x02}, 32, nd6.RoutePrefHigh)

	if p.Count() != 2 {
		t.Fatal("expected 2 routes")
	}

	p.ClearRoutes()

	if p.Count() != 0 {
		t.Fatal("expected 0 routes after clear")
	}
}

func TestRoutePublisherMaxEntries(t *testing.T) {
	p := NewRoutePublisher(WithMaxEntries(2))

	_ = p.AddRoute([16]byte{0x20, 0x01}, 32, nd6.RoutePrefMedium)
	_ = p.AddRoute([16]byte{0x20, 0x02}, 32, nd6.RoutePrefMedium)
	err := p.AddRoute([16]byte{0x20, 0x03}, 32, nd6.RoutePrefMedium)

	if err != errors.ErrNoBufs {
		t.Fatalf("expected ErrNoBufs, got %v", err)
	}
	if p.Count() != 2 {
		t.Fatal("count should still be 2")
	}
}

func TestRoutePublisherGetRoutesReturnsCopy(t *testing.T) {
	p := NewRoutePublisher()
	_ = p.AddRoute([16]byte{0x20, 0x01}, 32, nd6.RoutePrefMedium)

	routes := p.GetRoutes()
	routes[0].Preference = nd6.RoutePrefHigh // mutate the copy

	original := p.GetRoutes()
	if original[0].Preference != nd6.RoutePrefMedium {
		t.Fatal("GetRoutes should return a copy; mutation should not affect publisher")
	}
}

func TestRoutePublisherMultipleRoutes(t *testing.T) {
	p := NewRoutePublisher()
	prefixes := [][16]byte{
		{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01},
		{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02},
		{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x03},
	}

	for _, pfx := range prefixes {
		_ = p.AddRoute(pfx, 48, nd6.RoutePrefMedium)
	}

	if p.Count() != 3 {
		t.Fatalf("expected 3 routes, got %d", p.Count())
	}

	// Remove middle one.
	p.RemoveRoute(prefixes[1], 48)
	if p.Count() != 2 {
		t.Fatalf("expected 2 routes after remove, got %d", p.Count())
	}
	if p.HasRoute(prefixes[1], 48) {
		t.Fatal("middle route should be gone")
	}
	if !p.HasRoute(prefixes[0], 48) || !p.HasRoute(prefixes[2], 48) {
		t.Fatal("remaining routes should still exist")
	}
}

// ---------------------------------------------------------------------------
// ValidateOmrPrefix tests
// ---------------------------------------------------------------------------

func TestValidateOmrPrefix(t *testing.T) {
	// Valid ULA prefix.
	if err := ValidateOmrPrefix([16]byte{0xfd, 0x01}, 64); err != nil {
		t.Fatalf("ULA /64 should be valid: %v", err)
	}

	// Valid GUA prefix.
	if err := ValidateOmrPrefix([16]byte{0x20, 0x01}, 48); err != nil {
		t.Fatalf("GUA /48 should be valid: %v", err)
	}

	// Invalid: zero length.
	if err := ValidateOmrPrefix([16]byte{0xfd}, 0); err == nil {
		t.Fatal("zero prefix length should be invalid")
	}

	// Invalid: > 128.
	if err := ValidateOmrPrefix([16]byte{0xfd}, 129); err == nil {
		t.Fatal("prefix length > 128 should be invalid")
	}

	// Invalid: link-local.
	if err := ValidateOmrPrefix([16]byte{0xfe, 0x80}, 64); err == nil {
		t.Fatal("link-local prefix should be invalid")
	}

	// Invalid: multicast.
	if err := ValidateOmrPrefix([16]byte{0xff, 0x02}, 16); err == nil {
		t.Fatal("multicast prefix should be invalid")
	}
}

// ---------------------------------------------------------------------------
// RoutingManager tests
// ---------------------------------------------------------------------------

func TestRoutingManagerNewState(t *testing.T) {
	m := NewRoutingManager()
	if m.GetState() != StateUninitialized {
		t.Fatal("new manager should be Uninitialized")
	}
	if m.IsRunning() {
		t.Fatal("new manager should not be running")
	}
}

func TestRoutingManagerInitAndEnable(t *testing.T) {
	m := NewRoutingManager()

	// Cannot enable before Init.
	if err := m.SetEnabled(true); err != errors.ErrInvalidState {
		t.Fatalf("SetEnabled before Init should fail with ErrInvalidState, got %v", err)
	}

	if err := m.Init(testExtAddr); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if m.GetState() != StateDisabled {
		t.Fatal("after Init, state should be Disabled")
	}

	// Enable without infra up: should stay disabled.
	if err := m.SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled(true) failed: %v", err)
	}
	if m.GetState() != StateDisabled {
		t.Fatal("should stay disabled when infra is not running")
	}

	// Bring infra up: should transition to Running.
	m.HandleInfraIfStateChanged(true)
	if m.GetState() != StateRunning {
		t.Fatal("should be Running after infra comes up")
	}
	if !m.IsRunning() {
		t.Fatal("IsRunning should be true")
	}
}

func TestRoutingManagerInfraUpBeforeEnable(t *testing.T) {
	m := NewRoutingManager()
	_ = m.Init(testExtAddr)

	// Infra comes up but manager is not enabled.
	m.HandleInfraIfStateChanged(true)
	if m.GetState() != StateDisabled {
		t.Fatal("should stay disabled when not enabled")
	}

	// Now enable.
	_ = m.SetEnabled(true)
	if m.GetState() != StateRunning {
		t.Fatal("should be Running when enabled with infra up")
	}
}

func TestRoutingManagerDisable(t *testing.T) {
	m := NewRoutingManager()
	_ = m.Init(testExtAddr)
	m.HandleInfraIfStateChanged(true)
	_ = m.SetEnabled(true)

	if m.GetState() != StateRunning {
		t.Fatal("should be Running")
	}

	_ = m.SetEnabled(false)
	if m.GetState() != StateDisabled {
		t.Fatal("should be Disabled after SetEnabled(false)")
	}
}

func TestRoutingManagerInfraDown(t *testing.T) {
	m := NewRoutingManager()
	_ = m.Init(testExtAddr)
	_ = m.SetEnabled(true)
	m.HandleInfraIfStateChanged(true)

	if m.GetState() != StateRunning {
		t.Fatal("should be Running")
	}

	m.HandleInfraIfStateChanged(false)
	if m.GetState() != StateDisabled {
		t.Fatal("should be Disabled when infra goes down")
	}

	// Bring infra back up.
	m.HandleInfraIfStateChanged(true)
	if m.GetState() != StateRunning {
		t.Fatal("should be Running again when infra comes back up")
	}
}

func TestRoutingManagerDoubleInit(t *testing.T) {
	m := NewRoutingManager()
	_ = m.Init(testExtAddr)
	_ = m.SetEnabled(true)
	m.HandleInfraIfStateChanged(true)

	// Init while running should fail.
	if err := m.Init(testExtAddr); err != errors.ErrInvalidState {
		t.Fatalf("Init while running should fail with ErrInvalidState, got %v", err)
	}
}

func TestRoutingManagerGetOmrPrefix(t *testing.T) {
	m := NewRoutingManager()
	_ = m.Init(testExtAddr)

	// Before running, no favored prefix.
	_, ok := m.GetOmrPrefix()
	if ok {
		t.Fatal("should have no OMR prefix before running")
	}

	_ = m.SetEnabled(true)
	m.HandleInfraIfStateChanged(true)

	omr, ok := m.GetOmrPrefix()
	if !ok {
		t.Fatal("should have OMR prefix when running")
	}
	if omr.Prefix[0] != 0xfd {
		t.Fatal("OMR prefix should be ULA")
	}
	if omr.PrefixLen != 64 {
		t.Fatalf("OMR prefix length should be 64, got %d", omr.PrefixLen)
	}
}

func TestRoutingManagerGetOnLinkPrefix(t *testing.T) {
	m := NewRoutingManager()
	_ = m.Init(testExtAddr)
	_ = m.SetEnabled(true)
	m.HandleInfraIfStateChanged(true)

	prefix, prefixLen, ok := m.GetOnLinkPrefix()
	if !ok {
		t.Fatal("should have on-link prefix when running")
	}
	if prefix[0] != 0xfd {
		t.Fatal("on-link prefix should be ULA")
	}
	if prefixLen != 48 {
		t.Fatalf("on-link prefix length should be 48, got %d", prefixLen)
	}
}

func TestRoutingManagerHandleTimer(t *testing.T) {
	m := NewRoutingManager()
	_ = m.Init(testExtAddr)

	// HandleTimer before running should be a no-op.
	m.HandleTimer() // should not panic

	_ = m.SetEnabled(true)
	m.HandleInfraIfStateChanged(true)

	// HandleTimer while running should not panic.
	m.HandleTimer()

	// State should still be running.
	if m.GetState() != StateRunning {
		t.Fatal("should still be running after HandleTimer")
	}
}

func TestRoutingManagerGetRoutePublisher(t *testing.T) {
	m := NewRoutingManager()

	rp := m.GetRoutePublisher()
	if rp == nil {
		t.Fatal("route publisher should not be nil")
	}

	// Add a route through the publisher.
	err := rp.AddRoute([16]byte{0x20, 0x01, 0x0d, 0xb8}, 32, nd6.RoutePrefMedium)
	if err != nil {
		t.Fatalf("AddRoute failed: %v", err)
	}

	if rp.Count() != 1 {
		t.Fatal("route publisher should have 1 route")
	}
}

func TestRoutingManagerWithOptions(t *testing.T) {
	m := NewRoutingManager(
		WithRaSendInterval(300),
		WithRoutePublisherOptions(WithMaxEntries(4)),
	)

	if m.GetRaSendInterval() != 300 {
		t.Fatalf("expected RA interval 300, got %d", m.GetRaSendInterval())
	}

	rp := m.GetRoutePublisher()
	for i := 0; i < 4; i++ {
		prefix := [16]byte{0x20, 0x01, byte(i)}
		_ = rp.AddRoute(prefix, 32, nd6.RoutePrefMedium)
	}

	err := rp.AddRoute([16]byte{0x20, 0x01, 0xff}, 32, nd6.RoutePrefMedium)
	if err != errors.ErrNoBufs {
		t.Fatal("5th route should fail with ErrNoBufs")
	}
}

func TestRoutingManagerRaSendIntervalBounds(t *testing.T) {
	// Too low: should use default.
	m := NewRoutingManager(WithRaSendInterval(100))
	if m.GetRaSendInterval() != DefaultRaSendInterval {
		t.Fatalf("interval 100 should be rejected, got %d", m.GetRaSendInterval())
	}

	// Too high: should use default.
	m = NewRoutingManager(WithRaSendInterval(5000))
	if m.GetRaSendInterval() != DefaultRaSendInterval {
		t.Fatalf("interval 5000 should be rejected, got %d", m.GetRaSendInterval())
	}

	// Exact boundary values should be accepted.
	m = NewRoutingManager(WithRaSendInterval(MinRaSendInterval))
	if m.GetRaSendInterval() != MinRaSendInterval {
		t.Fatalf("min interval should be accepted, got %d", m.GetRaSendInterval())
	}
	m = NewRoutingManager(WithRaSendInterval(MaxRaSendInterval))
	if m.GetRaSendInterval() != MaxRaSendInterval {
		t.Fatalf("max interval should be accepted, got %d", m.GetRaSendInterval())
	}
}

func TestRoutingManagerEvaluatePolicyWhenNotRunning(t *testing.T) {
	m := NewRoutingManager()
	_ = m.Init(testExtAddr)

	// Should be a no-op, no panic.
	m.EvaluateRoutingPolicy()

	if m.GetState() != StateDisabled {
		t.Fatal("state should still be Disabled")
	}
}

func TestRoutingManagerStopClearsRoutes(t *testing.T) {
	m := NewRoutingManager()
	_ = m.Init(testExtAddr)
	_ = m.SetEnabled(true)
	m.HandleInfraIfStateChanged(true)

	rp := m.GetRoutePublisher()
	_ = rp.AddRoute([16]byte{0x20, 0x01}, 32, nd6.RoutePrefMedium)

	if rp.Count() != 1 {
		t.Fatal("should have 1 route before disable")
	}

	_ = m.SetEnabled(false)

	if rp.Count() != 0 {
		t.Fatal("routes should be cleared on disable")
	}
}

// ---------------------------------------------------------------------------
// State.String() test
// ---------------------------------------------------------------------------

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateDisabled, "Disabled"},
		{StateUninitialized, "Uninitialized"},
		{StateRunning, "Running"},
		{State(99), "Unknown"},
	}
	for _, tc := range tests {
		if got := tc.state.String(); got != tc.want {
			t.Errorf("State(%d).String() = %q, want %q", tc.state, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// matchBits tests (internal but important for correctness)
// ---------------------------------------------------------------------------

func TestMatchBits(t *testing.T) {
	a := []byte{0xff, 0xf0, 0x00}
	b := []byte{0xff, 0xf0, 0x00}

	if !matchBits(a, b, 20) {
		t.Fatal("identical slices should match")
	}

	c := []byte{0xff, 0xe0, 0x00}
	if matchBits(a, c, 20) {
		t.Fatal("different slices should not match for 20 bits")
	}

	// Match first 12 bits: 0xff 0xf0 and 0xff 0xf8 should match for 12 bits.
	d := []byte{0xff, 0xf8, 0x00}
	if !matchBits(a, d, 12) {
		t.Fatal("should match for first 12 bits")
	}

	// Zero bits always matches.
	if !matchBits(a, c, 0) {
		t.Fatal("zero bits should always match")
	}
}

// ---------------------------------------------------------------------------
// Mock InfraIfPlatform for testing
// ---------------------------------------------------------------------------

type mockPlatform struct {
	sentMessages [][]byte
	sentDests    []ip6.Address
}

func (m *mockPlatform) SendIcmp6Nd(_ uint32, dest ip6.Address, buf []byte) error {
	msg := make([]byte, len(buf))
	copy(msg, buf)
	m.sentMessages = append(m.sentMessages, msg)
	m.sentDests = append(m.sentDests, dest)
	return nil
}

func (m *mockPlatform) HasAddress(_ uint32, _ ip6.Address) bool { return false }
func (m *mockPlatform) DiscoverNat64Prefix(_ uint32) error      { return nil }
func (m *mockPlatform) GetLinkLayerAddress(_ uint32) []byte     { return nil }

// mockCallbacks is a no-op InfraIfCallbacks implementation.
type mockCallbacks struct{}

func (mockCallbacks) HandleInfraIfStateChanged()                                      {}
func (mockCallbacks) HandleReceiveIcmp6Nd(_ uint32, _ ip6.Address, _ uint8, _ []byte) {}

// ---------------------------------------------------------------------------
// RA builder tests
// ---------------------------------------------------------------------------

func TestBuildPrefixInfoOption(t *testing.T) {
	prefix := [16]byte{0xfd, 0x01, 0x02, 0x03, 0x04, 0x05}
	buf := buildPrefixInfoOption(prefix, 48)

	if len(buf) != nd6.PrefixInfoOptionSize {
		t.Fatalf("expected PIO size %d, got %d", nd6.PrefixInfoOptionSize, len(buf))
	}

	// Parse it back.
	var pio nd6.PrefixInfoOption
	if err := pio.Unmarshal(buf); err != nil {
		t.Fatalf("Unmarshal PIO failed: %v", err)
	}

	if pio.GetPrefixLength() != 48 {
		t.Fatalf("expected prefix length 48, got %d", pio.GetPrefixLength())
	}
	if !pio.IsOnLinkFlagSet() {
		t.Fatal("On-Link flag should be set")
	}
	if !pio.IsAutoAddrConfigFlagSet() {
		t.Fatal("Auto Address Config flag should be set")
	}
	if pio.GetValidLifetime() != defaultPrefixLifetime {
		t.Fatalf("expected valid lifetime %d, got %d", defaultPrefixLifetime, pio.GetValidLifetime())
	}
	if pio.GetPreferredLifetime() != defaultPrefixLifetime {
		t.Fatalf("expected preferred lifetime %d, got %d", defaultPrefixLifetime, pio.GetPreferredLifetime())
	}
	if pio.GetPrefix() != prefix {
		t.Fatal("prefix mismatch")
	}
}

func TestBuildRouteInfoOption(t *testing.T) {
	omr := OmrPrefix{
		Prefix:     [16]byte{0xfd, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00},
		PrefixLen:  64,
		Preference: nd6.RoutePrefHigh,
	}

	buf := buildRouteInfoOption(omr)

	if len(buf) < nd6.RouteInfoOptionMinSize {
		t.Fatalf("RIO too short: %d bytes", len(buf))
	}

	// Parse it back.
	var rio nd6.RouteInfoOption
	if err := rio.Unmarshal(buf); err != nil {
		t.Fatalf("Unmarshal RIO failed: %v", err)
	}

	if rio.GetPrefixLength() != 64 {
		t.Fatalf("expected prefix length 64, got %d", rio.GetPrefixLength())
	}
	if rio.GetRoutePreference() != nd6.RoutePrefHigh {
		t.Fatalf("expected high preference, got %d", rio.GetRoutePreference())
	}
	if rio.GetRouteLifetime() != defaultPrefixLifetime {
		t.Fatalf("expected route lifetime %d, got %d", defaultPrefixLifetime, rio.GetRouteLifetime())
	}

	gotPrefix := rio.GetPrefix()
	for i := 0; i < 8; i++ {
		if gotPrefix[i] != omr.Prefix[i] {
			t.Fatalf("prefix byte %d mismatch: got 0x%02x, want 0x%02x", i, gotPrefix[i], omr.Prefix[i])
		}
	}
}

func TestBuildRaFlagsExtOption(t *testing.T) {
	buf := buildRaFlagsExtOption()

	if len(buf) != nd6.RaFlagsExtOptionSize {
		t.Fatalf("expected RA Flags Ext size %d, got %d", nd6.RaFlagsExtOptionSize, len(buf))
	}

	// Parse it back.
	var ext nd6.RaFlagsExtOption
	if err := ext.Unmarshal(buf); err != nil {
		t.Fatalf("Unmarshal RaFlagsExt failed: %v", err)
	}

	if !ext.IsFlagSet(border.StubRouterFlag) {
		t.Fatal("stub router flag should be set")
	}

	// Other flags should not be set.
	for bit := uint(0); bit < 48; bit++ {
		if bit == border.StubRouterFlag {
			continue
		}
		if ext.IsFlagSet(bit) {
			t.Fatalf("unexpected flag set at bit %d", bit)
		}
	}
}

// ---------------------------------------------------------------------------
// buildRaPayload tests
// ---------------------------------------------------------------------------

func TestBuildRaPayload(t *testing.T) {
	m := NewRoutingManager()
	_ = m.Init(testExtAddr)
	_ = m.SetEnabled(true)
	m.HandleInfraIfStateChanged(true)

	payload := m.buildRaPayload()
	if payload == nil {
		t.Fatal("buildRaPayload should return non-nil when running with prefixes")
	}

	// Parse the RA.
	var ra nd6.RaMessage
	if err := ra.Unmarshal(payload); err != nil {
		t.Fatalf("Unmarshal RA failed: %v", err)
	}

	// Router lifetime should be 0 (not a default router).
	if ra.Header.GetRouterLifetime() != 0 {
		t.Fatalf("expected router lifetime 0, got %d", ra.Header.GetRouterLifetime())
	}

	// Should contain a PIO (on-link prefix).
	pios := ra.FindPrefixInfoOptions()
	if len(pios) != 1 {
		t.Fatalf("expected 1 PIO, got %d", len(pios))
	}
	if !pios[0].IsOnLinkFlagSet() {
		t.Fatal("PIO should have On-Link flag")
	}
	if !pios[0].IsAutoAddrConfigFlagSet() {
		t.Fatal("PIO should have Auto Address Config flag")
	}

	// Should contain a RIO (OMR prefix).
	rios := ra.FindRouteInfoOptions()
	if len(rios) != 1 {
		t.Fatalf("expected 1 RIO, got %d", len(rios))
	}
	if rios[0].GetPrefixLength() != 64 {
		t.Fatalf("RIO prefix length should be 64, got %d", rios[0].GetPrefixLength())
	}
}

func TestBuildRaPayloadNotRunning(t *testing.T) {
	m := NewRoutingManager()
	_ = m.Init(testExtAddr)

	// Not running — buildRaPayload called directly still works but
	// no prefixes evaluated, so RA Flags Ext alone is emitted.
	// Actually, since omr and on-link are not evaluated, only the
	// RA Flags Extension option should be present.
	payload := m.buildRaPayload()
	if payload == nil {
		t.Fatal("buildRaPayload should return non-nil (at least RA Flags Ext)")
	}

	var ra nd6.RaMessage
	if err := ra.Unmarshal(payload); err != nil {
		t.Fatalf("Unmarshal RA failed: %v", err)
	}

	// No PIO or RIO since prefixes haven't been evaluated.
	pios := ra.FindPrefixInfoOptions()
	rios := ra.FindRouteInfoOptions()
	if len(pios) != 0 {
		t.Fatalf("expected 0 PIOs, got %d", len(pios))
	}
	if len(rios) != 0 {
		t.Fatalf("expected 0 RIOs, got %d", len(rios))
	}
}

// ---------------------------------------------------------------------------
// SendRouterAdvertisement tests
// ---------------------------------------------------------------------------

func TestSendRouterAdvertisementNoInfraIf(t *testing.T) {
	m := NewRoutingManager()
	_ = m.Init(testExtAddr)
	_ = m.SetEnabled(true)
	m.HandleInfraIfStateChanged(true)

	// No InfraIf configured — should return nil payload, no error.
	payload, err := m.SendRouterAdvertisement()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if payload != nil {
		t.Fatal("should return nil when no InfraIf configured")
	}
}

func TestSendRouterAdvertisementNotRunning(t *testing.T) {
	plat := &mockPlatform{}
	infraIf := border.NewInfraIf(plat, mockCallbacks{})
	_ = infraIf.Init(1)
	infraIf.SetRunning(true)

	m := NewRoutingManager(WithInfraIf(infraIf))
	_ = m.Init(testExtAddr)
	// Not enabled / not running.

	payload, err := m.SendRouterAdvertisement()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if payload != nil {
		t.Fatal("should return nil when not running")
	}
}

func TestSendRouterAdvertisementSuccess(t *testing.T) {
	plat := &mockPlatform{}
	cb := mockCallbacks{}
	infraIf := border.NewInfraIf(plat, cb)
	_ = infraIf.Init(1)
	infraIf.SetRunning(true)

	tracker := border.NewRxRaTracker()

	m := NewRoutingManager(
		WithInfraIf(infraIf),
		WithRxRaTracker(tracker),
	)
	_ = m.Init(testExtAddr)
	_ = m.SetEnabled(true)
	m.HandleInfraIfStateChanged(true)

	payload, err := m.SendRouterAdvertisement()
	if err != nil {
		t.Fatalf("SendRouterAdvertisement failed: %v", err)
	}
	if payload == nil {
		t.Fatal("expected non-nil payload")
	}

	// Verify the platform received the message.
	if len(plat.sentMessages) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(plat.sentMessages))
	}

	// Destination should be ff02::1.
	expectedDest := ip6.Address{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	if plat.sentDests[0] != expectedDest {
		t.Fatalf("expected dest ff02::1, got %v", plat.sentDests[0])
	}

	// The sent message should match the returned payload.
	if len(plat.sentMessages[0]) != len(payload) {
		t.Fatalf("sent message length %d != payload length %d", len(plat.sentMessages[0]), len(payload))
	}
	for i := range payload {
		if plat.sentMessages[0][i] != payload[i] {
			t.Fatalf("sent message byte %d differs", i)
		}
	}

	// The RA hash should be registered in the tracker.
	if !tracker.IsSelfGeneratedRa(payload) {
		t.Fatal("self-RA hash should be registered in tracker")
	}
}

func TestSendRouterAdvertisementRaParseable(t *testing.T) {
	plat := &mockPlatform{}
	infraIf := border.NewInfraIf(plat, mockCallbacks{})
	_ = infraIf.Init(1)
	infraIf.SetRunning(true)

	m := NewRoutingManager(WithInfraIf(infraIf))
	_ = m.Init(testExtAddr)
	_ = m.SetEnabled(true)
	m.HandleInfraIfStateChanged(true)

	payload, err := m.SendRouterAdvertisement()
	if err != nil {
		t.Fatalf("SendRouterAdvertisement failed: %v", err)
	}

	// Parse the RA payload to verify structure.
	var ra nd6.RaMessage
	if err := ra.Unmarshal(payload); err != nil {
		t.Fatalf("Unmarshal RA failed: %v", err)
	}

	// Should have PIO, RIO, and options should parse without error.
	_, parseErr := ra.ParseOptions()
	if parseErr != nil {
		t.Fatalf("ParseOptions failed: %v", parseErr)
	}
}

// ---------------------------------------------------------------------------
// evaluateOmrPrefix with RxRaTracker tests
// ---------------------------------------------------------------------------

func TestEvaluateOmrPrefixWithTracker(t *testing.T) {
	tracker := border.NewRxRaTracker()

	// Build an RA with a high-preference route prefix and feed it to the tracker.
	routePrefix := [16]byte{0xfd, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00}
	var rio nd6.RouteInfoOption
	rio.SetPrefixLength(64)
	rio.SetRoutePreference(nd6.RoutePrefHigh)
	rio.SetRouteLifetime(1800)
	rio.SetPrefix(routePrefix)

	var ra nd6.RaMessage
	ra.Header.SetRouterLifetime(600)
	ra.Options = rio.Marshal()
	raBytes := ra.Marshal()

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	if err := tracker.ProcessReceivedRa(src, raBytes); err != nil {
		t.Fatalf("ProcessReceivedRa failed: %v", err)
	}

	m := NewRoutingManager(WithRxRaTracker(tracker))
	_ = m.Init(testExtAddr)
	_ = m.SetEnabled(true)
	m.HandleInfraIfStateChanged(true)

	// The favored OMR prefix should be the high-preference network prefix.
	omr, ok := m.GetOmrPrefix()
	if !ok {
		t.Fatal("should have favored OMR prefix")
	}
	if omr.IsLocal {
		t.Fatal("favored OMR should be the network prefix (high preference)")
	}
	if omr.Preference != nd6.RoutePrefHigh {
		t.Fatalf("expected high preference, got %d", omr.Preference)
	}
	for i := 0; i < 8; i++ {
		if omr.Prefix[i] != routePrefix[i] {
			t.Fatalf("OMR prefix byte %d mismatch", i)
		}
	}
}

func TestEvaluateOmrPrefixFiltersInvalid(t *testing.T) {
	tracker := border.NewRxRaTracker()

	// Build an RA with a link-local route prefix (should be filtered out).
	linkLocalPrefix := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0}
	var rio nd6.RouteInfoOption
	rio.SetPrefixLength(64)
	rio.SetRoutePreference(nd6.RoutePrefHigh)
	rio.SetRouteLifetime(1800)
	rio.SetPrefix(linkLocalPrefix)

	var ra nd6.RaMessage
	ra.Header.SetRouterLifetime(600)
	ra.Options = rio.Marshal()
	raBytes := ra.Marshal()

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	_ = tracker.ProcessReceivedRa(src, raBytes)

	m := NewRoutingManager(WithRxRaTracker(tracker))
	_ = m.Init(testExtAddr)
	_ = m.SetEnabled(true)
	m.HandleInfraIfStateChanged(true)

	// The favored OMR should be the local prefix (link-local filtered out).
	omr, ok := m.GetOmrPrefix()
	if !ok {
		t.Fatal("should have favored OMR prefix")
	}
	if !omr.IsLocal {
		t.Fatal("favored OMR should be local (link-local network prefix filtered)")
	}
}

// ---------------------------------------------------------------------------
// evaluateOnLinkPrefix with RxRaTracker tests
// ---------------------------------------------------------------------------

func TestEvaluateOnLinkPrefixWithTracker(t *testing.T) {
	tracker := border.NewRxRaTracker()

	// Build an RA with an on-link PIO.
	onLinkPrefix := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01}
	var pio nd6.PrefixInfoOption
	pio.SetPrefixLength(64)
	pio.SetOnLinkFlag()
	pio.SetValidLifetime(1800)
	pio.SetPreferredLifetime(1800)
	pio.SetPrefix(onLinkPrefix)
	pioBuf := pio.Marshal()

	var ra nd6.RaMessage
	ra.Header.SetRouterLifetime(600)
	ra.Options = pioBuf[:]

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03}
	_ = tracker.ProcessReceivedRa(src, ra.Marshal())

	m := NewRoutingManager(WithRxRaTracker(tracker))
	_ = m.Init(testExtAddr)
	_ = m.SetEnabled(true)
	m.HandleInfraIfStateChanged(true)

	// With a discovered on-link prefix, we should NOT advertise our own.
	_, _, ok := m.GetOnLinkPrefix()
	if ok {
		t.Fatal("should not advertise on-link prefix when another is discovered")
	}
}

func TestEvaluateOnLinkPrefixWithoutTracker(t *testing.T) {
	m := NewRoutingManager()
	_ = m.Init(testExtAddr)
	_ = m.SetEnabled(true)
	m.HandleInfraIfStateChanged(true)

	// Without tracker, we should advertise our own on-link prefix.
	prefix, prefixLen, ok := m.GetOnLinkPrefix()
	if !ok {
		t.Fatal("should advertise on-link prefix when no tracker")
	}
	if prefix[0] != 0xfd {
		t.Fatal("on-link prefix should be ULA")
	}
	if prefixLen != 48 {
		t.Fatalf("expected on-link prefix length 48, got %d", prefixLen)
	}
}
