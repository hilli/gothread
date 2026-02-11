// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package border

import (
	"testing"

	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/nd6"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildRa constructs a raw RA byte payload from an RaMessage.
func buildRa(t *testing.T, ra *nd6.RaMessage) []byte {
	t.Helper()
	return ra.Marshal()
}

// routerAddr returns a link-local address like fe80::n.
func routerAddr(n byte) ip6.Address {
	return ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, n}
}

// testPrefix returns 2001:db8:n::/48.
func testPrefix(n byte) ip6.Address {
	return ip6.Address{0x20, 0x01, 0x0d, 0xb8, 0x00, n}
}

// marshalPIO marshals a PrefixInfoOption (returns [32]byte) to a []byte slice.
func marshalPIO(pio *nd6.PrefixInfoOption) []byte {
	b := pio.Marshal()
	return b[:]
}

// marshalFE marshals a RaFlagsExtOption (returns [8]byte) to a []byte slice.
func marshalFE(fe *nd6.RaFlagsExtOption) []byte {
	b := fe.Marshal()
	return b[:]
}

// ---------------------------------------------------------------------------
// NewRxRaTracker
// ---------------------------------------------------------------------------

func TestNewRxRaTrackerDefaults(t *testing.T) {
	tr := NewRxRaTracker()
	if tr.GetRouterCount() != 0 {
		t.Errorf("initial router count = %d, want 0", tr.GetRouterCount())
	}
	if tr.maxRouters != DefaultMaxRouters {
		t.Errorf("maxRouters = %d, want %d", tr.maxRouters, DefaultMaxRouters)
	}
}

func TestNewRxRaTrackerWithOptions(t *testing.T) {
	tr := NewRxRaTracker(WithMaxRouters(4), WithMaxOnLinkPrefixes(2), WithMaxRoutePrefixes(2))
	if tr.maxRouters != 4 {
		t.Errorf("maxRouters = %d, want 4", tr.maxRouters)
	}
	if tr.maxOnLinkPrefixes != 2 {
		t.Errorf("maxOnLinkPrefixes = %d, want 2", tr.maxOnLinkPrefixes)
	}
}

// ---------------------------------------------------------------------------
// ProcessReceivedRa — basic RA with no options
// ---------------------------------------------------------------------------

func TestProcessReceivedRaBasic(t *testing.T) {
	tr := NewRxRaTracker()
	ra := &nd6.RaMessage{}
	ra.Header.SetRouterLifetime(1800)
	ra.Header.SetDefaultRouterPreference(nd6.RoutePrefHigh)

	src := routerAddr(1)
	raw := buildRa(t, ra)
	if err := tr.ProcessReceivedRa(src, raw); err != nil {
		t.Fatalf("ProcessReceivedRa: %v", err)
	}
	if tr.GetRouterCount() != 1 {
		t.Fatalf("router count = %d, want 1", tr.GetRouterCount())
	}
	r := tr.FindRouter(src)
	if r == nil {
		t.Fatal("router not found")
	}
	if r.RouterLifetime != 1800 {
		t.Errorf("RouterLifetime = %d, want 1800", r.RouterLifetime)
	}
	if r.DefaultRouterPreference != nd6.RoutePrefHigh {
		t.Errorf("DefaultRouterPreference = %d, want High", r.DefaultRouterPreference)
	}
}

// ---------------------------------------------------------------------------
// ProcessReceivedRa — with PIO (on-link)
// ---------------------------------------------------------------------------

func TestProcessReceivedRaWithPIO(t *testing.T) {
	tr := NewRxRaTracker()
	pio := &nd6.PrefixInfoOption{}
	pio.SetPrefixLength(64)
	pio.Prefix = testPrefix(1)
	pio.Flags = 0x80 // On-Link flag
	pio.ValidLifetime = 3600
	pio.PreferredLifetime = 1800

	ra := &nd6.RaMessage{}
	ra.Header.SetRouterLifetime(600)
	pioBytes := pio.Marshal()
	ra.Options = pioBytes[:]

	src := routerAddr(2)
	if err := tr.ProcessReceivedRa(src, buildRa(t, ra)); err != nil {
		t.Fatalf("ProcessReceivedRa: %v", err)
	}
	r := tr.FindRouter(src)
	if r == nil {
		t.Fatal("router not found")
	}
	if len(r.OnLinkPrefixes) != 1 {
		t.Fatalf("on-link prefixes = %d, want 1", len(r.OnLinkPrefixes))
	}
	if r.OnLinkPrefixes[0].ValidLifetime != 3600 {
		t.Errorf("on-link valid lifetime = %d, want 3600", r.OnLinkPrefixes[0].ValidLifetime)
	}
}

// ---------------------------------------------------------------------------
// ProcessReceivedRa — PIO without on-link flag is ignored
// ---------------------------------------------------------------------------

func TestProcessReceivedRaPIONoOnLinkFlag(t *testing.T) {
	tr := NewRxRaTracker()
	pio := &nd6.PrefixInfoOption{}
	pio.SetPrefixLength(64)
	pio.Prefix = testPrefix(3)
	pio.Flags = 0x40 // AutoConfig only, no On-Link
	pio.ValidLifetime = 3600

	ra := &nd6.RaMessage{}
	ra.Header.SetRouterLifetime(300)
	ra.Options = marshalPIO(pio)

	src := routerAddr(3)
	if err := tr.ProcessReceivedRa(src, buildRa(t, ra)); err != nil {
		t.Fatalf("ProcessReceivedRa: %v", err)
	}
	r := tr.FindRouter(src)
	if r == nil {
		t.Fatal("router not found")
	}
	if len(r.OnLinkPrefixes) != 0 {
		t.Errorf("expected no on-link prefixes, got %d", len(r.OnLinkPrefixes))
	}
}

// ---------------------------------------------------------------------------
// ProcessReceivedRa — with RIO
// ---------------------------------------------------------------------------

func TestProcessReceivedRaWithRIO(t *testing.T) {
	tr := NewRxRaTracker()
	rio := &nd6.RouteInfoOption{}
	rio.SetPrefixLength(48)
	rio.SetPrefix(testPrefix(5))
	rio.SetRouteLifetime(7200)
	rio.SetRoutePreference(nd6.RoutePrefLow)

	ra := &nd6.RaMessage{}
	ra.Header.SetRouterLifetime(600)
	ra.Options = rio.Marshal()

	src := routerAddr(4)
	if err := tr.ProcessReceivedRa(src, buildRa(t, ra)); err != nil {
		t.Fatalf("ProcessReceivedRa: %v", err)
	}
	r := tr.FindRouter(src)
	if r == nil {
		t.Fatal("router not found")
	}
	if len(r.RoutePrefixes) != 1 {
		t.Fatalf("route prefixes = %d, want 1", len(r.RoutePrefixes))
	}
	rp := r.RoutePrefixes[0]
	if rp.RouteLifetime != 7200 {
		t.Errorf("RouteLifetime = %d, want 7200", rp.RouteLifetime)
	}
	if rp.RoutePreference != nd6.RoutePrefLow {
		t.Errorf("RoutePreference = %d, want Low", rp.RoutePreference)
	}
}

// ---------------------------------------------------------------------------
// ProcessReceivedRa — with NAT64 prefix (PREF64)
// ---------------------------------------------------------------------------

func TestProcessReceivedRaWithNat64(t *testing.T) {
	tr := NewRxRaTracker()
	nat := &nd6.Nat64PrefixOption{}
	if err := nat.SetPrefixLength(96); err != nil {
		t.Fatalf("SetPrefixLength: %v", err)
	}
	nat.SetLifetime(600)
	nat.SetPrefix(ip6.Address{0x00, 0x64, 0xff, 0x9b})

	ra := &nd6.RaMessage{}
	ra.Header.SetRouterLifetime(300)
	ra.Options = nat.Marshal()

	src := routerAddr(5)
	if err := tr.ProcessReceivedRa(src, buildRa(t, ra)); err != nil {
		t.Fatalf("ProcessReceivedRa: %v", err)
	}
	r := tr.FindRouter(src)
	if r == nil {
		t.Fatal("router not found")
	}
	if r.Nat64Prefix == nil {
		t.Fatal("expected NAT64 prefix")
	}
	if r.Nat64Prefix.GetLength() != 96 {
		t.Errorf("NAT64 prefix length = %d, want 96", r.Nat64Prefix.GetLength())
	}
	if r.Nat64Lifetime == 0 {
		t.Error("expected non-zero NAT64 lifetime")
	}
}

// ---------------------------------------------------------------------------
// ProcessReceivedRa — with RA Flags Extension (stub router)
// ---------------------------------------------------------------------------

func TestProcessReceivedRaStubRouter(t *testing.T) {
	tr := NewRxRaTracker()
	fe := &nd6.RaFlagsExtOption{}
	fe.SetFlag(StubRouterFlag)

	ra := &nd6.RaMessage{}
	ra.Header.SetRouterLifetime(100)
	ra.Options = marshalFE(fe)

	src := routerAddr(6)
	if err := tr.ProcessReceivedRa(src, buildRa(t, ra)); err != nil {
		t.Fatalf("ProcessReceivedRa: %v", err)
	}
	r := tr.FindRouter(src)
	if r == nil {
		t.Fatal("router not found")
	}
	if !r.IsStubRouter {
		t.Error("expected stub router flag set")
	}
}

// ---------------------------------------------------------------------------
// ProcessReceivedRa — update existing router
// ---------------------------------------------------------------------------

func TestProcessReceivedRaUpdateExisting(t *testing.T) {
	tr := NewRxRaTracker()
	src := routerAddr(7)

	// First RA.
	ra1 := &nd6.RaMessage{}
	ra1.Header.SetRouterLifetime(100)
	if err := tr.ProcessReceivedRa(src, buildRa(t, ra1)); err != nil {
		t.Fatal(err)
	}
	if tr.GetRouterCount() != 1 {
		t.Fatalf("count = %d, want 1", tr.GetRouterCount())
	}

	// Second RA from same router updates, doesn't add.
	ra2 := &nd6.RaMessage{}
	ra2.Header.SetRouterLifetime(200)
	if err := tr.ProcessReceivedRa(src, buildRa(t, ra2)); err != nil {
		t.Fatal(err)
	}
	if tr.GetRouterCount() != 1 {
		t.Fatalf("count = %d after update, want 1", tr.GetRouterCount())
	}
	r := tr.FindRouter(src)
	if r.RouterLifetime != 200 {
		t.Errorf("lifetime = %d, want 200", r.RouterLifetime)
	}
}

// ---------------------------------------------------------------------------
// ProcessReceivedRa — PIO update updates lifetime
// ---------------------------------------------------------------------------

func TestProcessReceivedRaPIOUpdate(t *testing.T) {
	tr := NewRxRaTracker()
	src := routerAddr(8)
	prefix := testPrefix(10)

	// First RA with on-link prefix.
	pio := &nd6.PrefixInfoOption{}
	pio.SetPrefixLength(64)
	pio.Prefix = prefix
	pio.Flags = 0x80
	pio.ValidLifetime = 3600

	ra := &nd6.RaMessage{}
	ra.Header.SetRouterLifetime(600)
	ra.Options = marshalPIO(pio)

	if err := tr.ProcessReceivedRa(src, buildRa(t, ra)); err != nil {
		t.Fatal(err)
	}

	// Second RA updates the same on-link prefix lifetime.
	pio.ValidLifetime = 7200
	ra.Options = marshalPIO(pio)
	if err := tr.ProcessReceivedRa(src, buildRa(t, ra)); err != nil {
		t.Fatal(err)
	}

	r := tr.FindRouter(src)
	if len(r.OnLinkPrefixes) != 1 {
		t.Fatalf("on-link count = %d, want 1", len(r.OnLinkPrefixes))
	}
	if r.OnLinkPrefixes[0].ValidLifetime != 7200 {
		t.Errorf("valid lifetime = %d, want 7200", r.OnLinkPrefixes[0].ValidLifetime)
	}
}

// ---------------------------------------------------------------------------
// ProcessReceivedRa — invalid payload
// ---------------------------------------------------------------------------

func TestProcessReceivedRaInvalidPayload(t *testing.T) {
	tr := NewRxRaTracker()
	err := tr.ProcessReceivedRa(routerAddr(9), []byte{0, 1, 2}) // too short
	if err == nil {
		t.Error("expected error for too-short payload")
	}
}

// ---------------------------------------------------------------------------
// MaxRouters / eviction
// ---------------------------------------------------------------------------

func TestMaxRoutersEviction(t *testing.T) {
	tr := NewRxRaTracker(WithMaxRouters(2))

	ra := &nd6.RaMessage{}
	ra.Header.SetRouterLifetime(100)

	_ = tr.ProcessReceivedRa(routerAddr(1), buildRa(t, ra))
	_ = tr.ProcessReceivedRa(routerAddr(2), buildRa(t, ra))

	// Third should be dropped since both existing routers have lifetime.
	ra3 := &nd6.RaMessage{}
	ra3.Header.SetRouterLifetime(100)
	_ = tr.ProcessReceivedRa(routerAddr(3), buildRa(t, ra3))

	if tr.GetRouterCount() != 2 {
		t.Errorf("count = %d, want 2 (table full)", tr.GetRouterCount())
	}
	if tr.FindRouter(routerAddr(3)) != nil {
		t.Error("router 3 should not be present")
	}
}

func TestMaxRoutersEvictionOfEmpty(t *testing.T) {
	tr := NewRxRaTracker(WithMaxRouters(2))

	// Router 1 with zero lifetime and no prefixes -> empty, evictable.
	ra1 := &nd6.RaMessage{}
	ra1.Header.SetRouterLifetime(0)
	_ = tr.ProcessReceivedRa(routerAddr(1), buildRa(t, ra1))

	// Router 2 with lifetime.
	ra2 := &nd6.RaMessage{}
	ra2.Header.SetRouterLifetime(100)
	_ = tr.ProcessReceivedRa(routerAddr(2), buildRa(t, ra2))

	if tr.GetRouterCount() != 2 {
		t.Fatalf("count = %d, want 2", tr.GetRouterCount())
	}

	// Router 3 should evict the empty router 1.
	ra3 := &nd6.RaMessage{}
	ra3.Header.SetRouterLifetime(200)
	_ = tr.ProcessReceivedRa(routerAddr(3), buildRa(t, ra3))

	if tr.GetRouterCount() != 2 {
		t.Fatalf("count = %d, want 2", tr.GetRouterCount())
	}
	if tr.FindRouter(routerAddr(1)) != nil {
		t.Error("router 1 should have been evicted")
	}
	if tr.FindRouter(routerAddr(3)) == nil {
		t.Error("router 3 should be present")
	}
}

// ---------------------------------------------------------------------------
// ExpireRouters
// ---------------------------------------------------------------------------

func TestExpireRouters(t *testing.T) {
	tr := NewRxRaTracker()
	var removedAddrs []ip6.Address
	tr.callback = func(event RaTrackerEvent, addr ip6.Address) {
		if event == EventRouterRemoved {
			removedAddrs = append(removedAddrs, addr)
		}
	}

	// Add two routers: one with lifetime, one without.
	ra1 := &nd6.RaMessage{}
	ra1.Header.SetRouterLifetime(0)
	_ = tr.ProcessReceivedRa(routerAddr(1), buildRa(t, ra1))

	ra2 := &nd6.RaMessage{}
	ra2.Header.SetRouterLifetime(600)
	_ = tr.ProcessReceivedRa(routerAddr(2), buildRa(t, ra2))

	removed := tr.ExpireRouters()
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if tr.GetRouterCount() != 1 {
		t.Errorf("count = %d, want 1", tr.GetRouterCount())
	}
	if len(removedAddrs) != 1 || removedAddrs[0] != routerAddr(1) {
		t.Error("expected router 1 removed callback")
	}
}

// ---------------------------------------------------------------------------
// GetDecisionFactors
// ---------------------------------------------------------------------------

func TestGetDecisionFactors(t *testing.T) {
	tr := NewRxRaTracker()

	// Router with lifetime + on-link prefix + stub flag.
	pio := &nd6.PrefixInfoOption{}
	pio.SetPrefixLength(64)
	pio.Prefix = testPrefix(1)
	pio.Flags = 0x80
	pio.ValidLifetime = 3600

	fe := &nd6.RaFlagsExtOption{}
	fe.SetFlag(StubRouterFlag)
	feBytes := fe.Marshal()

	ra := &nd6.RaMessage{}
	ra.Header.SetRouterLifetime(600)
	opts := marshalPIO(pio)
	opts = append(opts, feBytes[:]...)
	ra.Options = opts

	_ = tr.ProcessReceivedRa(routerAddr(1), buildRa(t, ra))

	df := tr.GetDecisionFactors()
	if !df.HasDefaultRouter {
		t.Error("expected HasDefaultRouter")
	}
	if df.DefaultRouterCount != 1 {
		t.Errorf("DefaultRouterCount = %d, want 1", df.DefaultRouterCount)
	}
	if !df.HasOnLinkPrefix {
		t.Error("expected HasOnLinkPrefix")
	}
	if !df.HasStubRouter {
		t.Error("expected HasStubRouter")
	}
	if df.HasRoutePrefix {
		t.Error("expected no route prefix")
	}
}

func TestGetDecisionFactorsEmpty(t *testing.T) {
	tr := NewRxRaTracker()
	df := tr.GetDecisionFactors()
	if df.HasDefaultRouter || df.HasOnLinkPrefix || df.HasRoutePrefix || df.HasNat64Prefix || df.HasStubRouter {
		t.Error("expected all false for empty tracker")
	}
	if df.DefaultRouterCount != 0 {
		t.Errorf("DefaultRouterCount = %d, want 0", df.DefaultRouterCount)
	}
}

// ---------------------------------------------------------------------------
// Self-RA detection
// ---------------------------------------------------------------------------

func TestSelfRaDetection(t *testing.T) {
	tr := NewRxRaTracker()
	payload := []byte{0x01, 0x02, 0x03, 0x04}

	tr.AddSelfRaHash(payload)

	// Same payload should be detected as self.
	if !tr.IsSelfGeneratedRa(payload) {
		t.Error("expected self-generated RA detected")
	}

	// After consumption, the hash is removed.
	if tr.IsSelfGeneratedRa(payload) {
		t.Error("expected hash consumed after first match")
	}
}

func TestSelfRaDetectionDifferentPayload(t *testing.T) {
	tr := NewRxRaTracker()
	tr.AddSelfRaHash([]byte{1, 2, 3})

	if tr.IsSelfGeneratedRa([]byte{4, 5, 6}) {
		t.Error("expected different payload not detected as self")
	}
}

func TestSelfRaHashDeduplication(t *testing.T) {
	tr := NewRxRaTracker()
	payload := []byte{0xAA}

	tr.AddSelfRaHash(payload)
	tr.AddSelfRaHash(payload) // duplicate

	if len(tr.selfRaHashes) != 1 {
		t.Errorf("hash count = %d, want 1 (no duplicates)", len(tr.selfRaHashes))
	}
}

func TestSelfRaHashEviction(t *testing.T) {
	tr := NewRxRaTracker()

	// Fill up to maxSelfRaHashes.
	for i := 0; i < maxSelfRaHashes; i++ {
		tr.AddSelfRaHash([]byte{byte(i)})
	}
	if len(tr.selfRaHashes) != maxSelfRaHashes {
		t.Fatalf("hash count = %d, want %d", len(tr.selfRaHashes), maxSelfRaHashes)
	}

	// Adding one more should evict the oldest (byte{0}).
	tr.AddSelfRaHash([]byte{0xFF})
	if len(tr.selfRaHashes) != maxSelfRaHashes {
		t.Errorf("hash count = %d after eviction, want %d", len(tr.selfRaHashes), maxSelfRaHashes)
	}

	// The oldest (0) should have been evicted.
	if tr.IsSelfGeneratedRa([]byte{0}) {
		t.Error("oldest hash should have been evicted")
	}
	// The newest should be present.
	if !tr.IsSelfGeneratedRa([]byte{0xFF}) {
		t.Error("newest hash should be present")
	}
}

// ---------------------------------------------------------------------------
// Callback events
// ---------------------------------------------------------------------------

func TestCallbackEvents(t *testing.T) {
	var events []RaTrackerEvent
	var addrs []ip6.Address

	tr := NewRxRaTracker(WithCallback(func(event RaTrackerEvent, addr ip6.Address) {
		events = append(events, event)
		addrs = append(addrs, addr)
	}))

	ra := &nd6.RaMessage{}
	ra.Header.SetRouterLifetime(100)
	src := routerAddr(1)

	// First RA -> EventRouterAdded.
	_ = tr.ProcessReceivedRa(src, buildRa(t, ra))
	if len(events) != 1 || events[0] != EventRouterAdded {
		t.Errorf("expected EventRouterAdded, got %v", events)
	}

	// Second RA from same router -> EventRouterUpdated.
	_ = tr.ProcessReceivedRa(src, buildRa(t, ra))
	if len(events) != 2 || events[1] != EventRouterUpdated {
		t.Errorf("expected EventRouterUpdated, got %v", events)
	}
}

// ---------------------------------------------------------------------------
// Clear
// ---------------------------------------------------------------------------

func TestClear(t *testing.T) {
	tr := NewRxRaTracker()
	ra := &nd6.RaMessage{}
	ra.Header.SetRouterLifetime(100)
	_ = tr.ProcessReceivedRa(routerAddr(1), buildRa(t, ra))
	_ = tr.ProcessReceivedRa(routerAddr(2), buildRa(t, ra))

	tr.Clear()
	if tr.GetRouterCount() != 0 {
		t.Errorf("count after clear = %d, want 0", tr.GetRouterCount())
	}
}

// ---------------------------------------------------------------------------
// GetRouters returns copy
// ---------------------------------------------------------------------------

func TestGetRoutersReturnsCopy(t *testing.T) {
	tr := NewRxRaTracker()
	ra := &nd6.RaMessage{}
	ra.Header.SetRouterLifetime(100)
	_ = tr.ProcessReceivedRa(routerAddr(1), buildRa(t, ra))

	routers := tr.GetRouters()
	if len(routers) != 1 {
		t.Fatalf("len = %d, want 1", len(routers))
	}

	// Modifying the copy should not affect the tracker.
	routers[0].RouterLifetime = 9999
	r := tr.FindRouter(routerAddr(1))
	if r.RouterLifetime == 9999 {
		t.Error("GetRouters should return a copy")
	}
}

// ---------------------------------------------------------------------------
// RouterEntry helpers
// ---------------------------------------------------------------------------

func TestRouterEntryIsDefaultRouter(t *testing.T) {
	r := RouterEntry{RouterLifetime: 100}
	if !r.IsDefaultRouter() {
		t.Error("expected default router with non-zero lifetime")
	}
	r.RouterLifetime = 0
	if r.IsDefaultRouter() {
		t.Error("expected not default router with zero lifetime")
	}
}

func TestRouterEntryIsEmpty(t *testing.T) {
	r := RouterEntry{RouterLifetime: 0}
	if !r.IsEmpty() {
		t.Error("expected empty with zero lifetime and no prefixes")
	}
	r.OnLinkPrefixes = []OnLinkPrefix{{ValidLifetime: 100}}
	if r.IsEmpty() {
		t.Error("expected not empty with valid on-link prefix")
	}
}

// ---------------------------------------------------------------------------
// Multiple options in one RA
// ---------------------------------------------------------------------------

func TestProcessReceivedRaMultipleOptions(t *testing.T) {
	tr := NewRxRaTracker()

	// Build RA with PIO + RIO.
	pio := &nd6.PrefixInfoOption{}
	pio.SetPrefixLength(64)
	pio.Prefix = testPrefix(1)
	pio.Flags = 0x80
	pio.ValidLifetime = 3600

	rio := &nd6.RouteInfoOption{}
	rio.SetPrefixLength(48)
	rio.SetPrefix(testPrefix(2))
	rio.SetRouteLifetime(7200)
	rio.SetRoutePreference(nd6.RoutePrefHigh)

	ra := &nd6.RaMessage{}
	ra.Header.SetRouterLifetime(600)
	opts := marshalPIO(pio)
	opts = append(opts, rio.Marshal()...)
	ra.Options = opts

	src := routerAddr(10)
	if err := tr.ProcessReceivedRa(src, buildRa(t, ra)); err != nil {
		t.Fatal(err)
	}
	r := tr.FindRouter(src)
	if r == nil {
		t.Fatal("router not found")
	}
	if len(r.OnLinkPrefixes) != 1 {
		t.Errorf("on-link = %d, want 1", len(r.OnLinkPrefixes))
	}
	if len(r.RoutePrefixes) != 1 {
		t.Errorf("route = %d, want 1", len(r.RoutePrefixes))
	}
}

// ---------------------------------------------------------------------------
// MaxOnLinkPrefixes capacity
// ---------------------------------------------------------------------------

func TestMaxOnLinkPrefixesCapacity(t *testing.T) {
	tr := NewRxRaTracker(WithMaxOnLinkPrefixes(1))
	src := routerAddr(11)

	// Two PIOs but only capacity for 1.
	pio1 := &nd6.PrefixInfoOption{}
	pio1.SetPrefixLength(64)
	pio1.Prefix = testPrefix(1)
	pio1.Flags = 0x80
	pio1.ValidLifetime = 100

	pio2 := &nd6.PrefixInfoOption{}
	pio2.SetPrefixLength(64)
	pio2.Prefix = testPrefix(2)
	pio2.Flags = 0x80
	pio2.ValidLifetime = 200

	ra := &nd6.RaMessage{}
	ra.Header.SetRouterLifetime(600)
	opts := marshalPIO(pio1)
	opts = append(opts, marshalPIO(pio2)...)
	ra.Options = opts

	_ = tr.ProcessReceivedRa(src, buildRa(t, ra))
	r := tr.FindRouter(src)
	if len(r.OnLinkPrefixes) != 1 {
		t.Errorf("on-link = %d, want 1 (capacity limit)", len(r.OnLinkPrefixes))
	}
}
