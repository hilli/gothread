// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package border

import (
	"github.com/hilli/gothread/crypto/sha256"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/nd6"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	// DefaultMaxRouters is the default maximum number of routers tracked.
	DefaultMaxRouters = 16

	// DefaultMaxOnLinkPrefixes is the default max on-link prefixes per router.
	DefaultMaxOnLinkPrefixes = 4

	// DefaultMaxRoutePrefixes is the default max route prefixes per router.
	DefaultMaxRoutePrefixes = 4

	// StubRouterFlag is the bit position in RA Flags Extension for stub router.
	StubRouterFlag uint = 5
)

// ---------------------------------------------------------------------------
// RaTrackerEvent — events emitted by the tracker
// ---------------------------------------------------------------------------

// RaTrackerEvent identifies an event type reported by the RxRaTracker.
type RaTrackerEvent int

const (
	// EventRouterAdded indicates a new router was discovered.
	EventRouterAdded RaTrackerEvent = iota
	// EventRouterUpdated indicates an existing router entry was updated.
	EventRouterUpdated
	// EventRouterRemoved indicates a router entry was removed (expired).
	EventRouterRemoved
)

// RaTrackerCallback is called when a router event occurs.
type RaTrackerCallback func(event RaTrackerEvent, addr ip6.Address)

// ---------------------------------------------------------------------------
// RouterEntry — tracks state from a single router
// ---------------------------------------------------------------------------

// RouterEntry holds the information learned from a single advertising router
// on the infrastructure link.
type RouterEntry struct {
	// Address is the source IPv6 address of the router.
	Address ip6.Address

	// OnLinkPrefixes are prefixes from PIOs with the On-Link flag.
	OnLinkPrefixes []OnLinkPrefix

	// RoutePrefixes are prefixes from RIOs.
	RoutePrefixes []RoutePrefix

	// Nat64Prefix is the NAT64 prefix from a PREF64 option, if present.
	Nat64Prefix *ip6.Prefix

	// Nat64Lifetime is the PREF64 prefix lifetime in seconds.
	Nat64Lifetime uint32

	// IsStubRouter indicates whether the RA Flags Extension marks this as a
	// stub router.
	IsStubRouter bool

	// DefaultRouterPreference from the RA header.
	DefaultRouterPreference RoutePreference

	// RouterLifetime from the RA header (seconds). Zero means not a default
	// router.
	RouterLifetime uint16

	// maxOnLinkPrefixes limits the per-router on-link prefix list.
	maxOnLinkPrefixes int

	// maxRoutePrefixes limits the per-router route prefix list.
	maxRoutePrefixes int
}

// newRouterEntry creates a RouterEntry with capacity limits.
func newRouterEntry(addr ip6.Address, maxOnLink, maxRoute int) RouterEntry {
	return RouterEntry{
		Address:           addr,
		OnLinkPrefixes:    make([]OnLinkPrefix, 0, maxOnLink),
		RoutePrefixes:     make([]RoutePrefix, 0, maxRoute),
		maxOnLinkPrefixes: maxOnLink,
		maxRoutePrefixes:  maxRoute,
	}
}

// IsDefaultRouter returns true if the router has a non-zero lifetime.
func (r *RouterEntry) IsDefaultRouter() bool {
	return r.RouterLifetime > 0
}

// HasAnyValidPrefix returns true if the router has at least one non-expired
// on-link prefix, route prefix, or NAT64 prefix.
func (r *RouterEntry) HasAnyValidPrefix() bool {
	for _, p := range r.OnLinkPrefixes {
		if !p.IsExpired() {
			return true
		}
	}
	for _, p := range r.RoutePrefixes {
		if !p.IsExpired() {
			return true
		}
	}
	if r.Nat64Prefix != nil && r.Nat64Lifetime > 0 {
		return true
	}
	return false
}

// updateOnLinkPrefix adds or updates an on-link prefix for this router.
func (r *RouterEntry) updateOnLinkPrefix(prefix ip6.Prefix, validLifetime uint32) {
	for i := range r.OnLinkPrefixes {
		if r.OnLinkPrefixes[i].Prefix.IsEqual(prefix) {
			r.OnLinkPrefixes[i].ValidLifetime = validLifetime
			return
		}
	}
	// Not found — add if capacity allows.
	if len(r.OnLinkPrefixes) < r.maxOnLinkPrefixes {
		r.OnLinkPrefixes = append(r.OnLinkPrefixes, OnLinkPrefix{
			Prefix:        prefix,
			ValidLifetime: validLifetime,
		})
	}
}

// updateRoutePrefix adds or updates a route prefix for this router.
func (r *RouterEntry) updateRoutePrefix(prefix ip6.Prefix, lifetime uint32, pref RoutePreference) {
	for i := range r.RoutePrefixes {
		if r.RoutePrefixes[i].Prefix.IsEqual(prefix) {
			r.RoutePrefixes[i].RouteLifetime = lifetime
			r.RoutePrefixes[i].RoutePreference = pref
			return
		}
	}
	if len(r.RoutePrefixes) < r.maxRoutePrefixes {
		r.RoutePrefixes = append(r.RoutePrefixes, RoutePrefix{
			Prefix:          prefix,
			RouteLifetime:   lifetime,
			RoutePreference: pref,
		})
	}
}

// removeExpiredPrefixes removes on-link and route prefixes with zero lifetime.
func (r *RouterEntry) removeExpiredPrefixes() {
	n := 0
	for _, p := range r.OnLinkPrefixes {
		if !p.IsExpired() {
			r.OnLinkPrefixes[n] = p
			n++
		}
	}
	r.OnLinkPrefixes = r.OnLinkPrefixes[:n]

	n = 0
	for _, p := range r.RoutePrefixes {
		if !p.IsExpired() {
			r.RoutePrefixes[n] = p
			n++
		}
	}
	r.RoutePrefixes = r.RoutePrefixes[:n]

	if r.Nat64Prefix != nil && r.Nat64Lifetime == 0 {
		r.Nat64Prefix = nil
	}
}

// IsEmpty returns true if the router has no remaining state worth tracking
// (no default router lifetime, no valid prefixes).
func (r *RouterEntry) IsEmpty() bool {
	return r.RouterLifetime == 0 && !r.HasAnyValidPrefix()
}

// ---------------------------------------------------------------------------
// DecisionFactors — summary of state across all tracked routers
// ---------------------------------------------------------------------------

// DecisionFactors summarizes state from all tracked routers. It is used by
// the border routing manager to make forwarding and prefix decisions.
type DecisionFactors struct {
	// HasDefaultRouter is true if any tracked router is a default router.
	HasDefaultRouter bool

	// HasOnLinkPrefix is true if any tracked on-link prefix is non-expired.
	HasOnLinkPrefix bool

	// HasRoutePrefix is true if any tracked route prefix is non-expired.
	HasRoutePrefix bool

	// HasNat64Prefix is true if any tracked NAT64 prefix is non-expired.
	HasNat64Prefix bool

	// HasStubRouter is true if any tracked router is a stub router.
	HasStubRouter bool

	// DefaultRouterCount is the number of routers with non-zero lifetime.
	DefaultRouterCount int
}

// ---------------------------------------------------------------------------
// RxRaTracker options (functional options pattern)
// ---------------------------------------------------------------------------

// RxRaTrackerOption configures the RxRaTracker.
type RxRaTrackerOption func(*RxRaTracker)

// WithMaxRouters sets the maximum number of routers to track.
func WithMaxRouters(n int) RxRaTrackerOption {
	return func(t *RxRaTracker) {
		if n > 0 {
			t.maxRouters = n
		}
	}
}

// WithMaxOnLinkPrefixes sets the per-router on-link prefix capacity.
func WithMaxOnLinkPrefixes(n int) RxRaTrackerOption {
	return func(t *RxRaTracker) {
		if n > 0 {
			t.maxOnLinkPrefixes = n
		}
	}
}

// WithMaxRoutePrefixes sets the per-router route prefix capacity.
func WithMaxRoutePrefixes(n int) RxRaTrackerOption {
	return func(t *RxRaTracker) {
		if n > 0 {
			t.maxRoutePrefixes = n
		}
	}
}

// WithCallback sets the event callback.
func WithCallback(cb RaTrackerCallback) RxRaTrackerOption {
	return func(t *RxRaTracker) {
		t.callback = cb
	}
}

// ---------------------------------------------------------------------------
// RxRaTracker — the main tracker
// ---------------------------------------------------------------------------

const (
	// maxSelfRaHashes is the maximum number of self-generated RA hashes kept.
	maxSelfRaHashes = 8
)

// RxRaTracker tracks routers discovered from received Router Advertisements
// on the infrastructure link.
type RxRaTracker struct {
	routers           []RouterEntry
	maxRouters        int
	maxOnLinkPrefixes int
	maxRoutePrefixes  int
	callback          RaTrackerCallback
	selfRaHashes      []sha256.Hash
}

// NewRxRaTracker creates a new RxRaTracker with the given options.
func NewRxRaTracker(opts ...RxRaTrackerOption) *RxRaTracker {
	t := &RxRaTracker{
		maxRouters:        DefaultMaxRouters,
		maxOnLinkPrefixes: DefaultMaxOnLinkPrefixes,
		maxRoutePrefixes:  DefaultMaxRoutePrefixes,
	}
	for _, o := range opts {
		o(t)
	}
	t.routers = make([]RouterEntry, 0, t.maxRouters)
	t.selfRaHashes = make([]sha256.Hash, 0, maxSelfRaHashes)
	return t
}

// GetRouters returns a copy of the current router list.
func (t *RxRaTracker) GetRouters() []RouterEntry {
	result := make([]RouterEntry, len(t.routers))
	copy(result, t.routers)
	return result
}

// GetRouterCount returns the number of tracked routers.
func (t *RxRaTracker) GetRouterCount() int {
	return len(t.routers)
}

// FindRouter returns a pointer to the router entry with the given address,
// or nil if not found.
func (t *RxRaTracker) FindRouter(addr ip6.Address) *RouterEntry {
	for i := range t.routers {
		if t.routers[i].Address == addr {
			return &t.routers[i]
		}
	}
	return nil
}

// Clear removes all tracked routers.
func (t *RxRaTracker) Clear() {
	t.routers = t.routers[:0]
}

// GetDecisionFactors computes the current decision factors from all tracked
// routers.
func (t *RxRaTracker) GetDecisionFactors() DecisionFactors {
	var df DecisionFactors
	for i := range t.routers {
		r := &t.routers[i]
		if r.IsDefaultRouter() {
			df.HasDefaultRouter = true
			df.DefaultRouterCount++
		}
		for _, p := range r.OnLinkPrefixes {
			if !p.IsExpired() {
				df.HasOnLinkPrefix = true
			}
		}
		for _, p := range r.RoutePrefixes {
			if !p.IsExpired() {
				df.HasRoutePrefix = true
			}
		}
		if r.Nat64Prefix != nil && r.Nat64Lifetime > 0 {
			df.HasNat64Prefix = true
		}
		if r.IsStubRouter {
			df.HasStubRouter = true
		}
	}
	return df
}

// ---------------------------------------------------------------------------
// Self-RA detection (via SHA-256 hash)
// ---------------------------------------------------------------------------

// AddSelfRaHash records the SHA-256 hash of a self-generated RA payload so
// that it can be recognized and ignored when received back on the infra link.
func (t *RxRaTracker) AddSelfRaHash(payload []byte) {
	h := sha256.Sum256(payload)
	// Avoid duplicates.
	for _, existing := range t.selfRaHashes {
		if existing == h {
			return
		}
	}
	if len(t.selfRaHashes) >= maxSelfRaHashes {
		// Evict the oldest entry.
		copy(t.selfRaHashes, t.selfRaHashes[1:])
		t.selfRaHashes = t.selfRaHashes[:len(t.selfRaHashes)-1]
	}
	t.selfRaHashes = append(t.selfRaHashes, h)
}

// IsSelfGeneratedRa returns true if the given RA payload matches a previously
// recorded self-RA hash. If found, the hash is consumed (removed).
func (t *RxRaTracker) IsSelfGeneratedRa(payload []byte) bool {
	h := sha256.Sum256(payload)
	for i, existing := range t.selfRaHashes {
		if existing == h {
			// Remove the matched entry.
			t.selfRaHashes = append(t.selfRaHashes[:i], t.selfRaHashes[i+1:]...)
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// ProcessReceivedRa — the main entry point for incoming RAs
// ---------------------------------------------------------------------------

// ProcessReceivedRa parses a received Router Advertisement and updates the
// tracker state. The rawRa is the full RA payload (starting from the RA header,
// after the ICMPv6 header). src is the source address of the advertising
// router.
func (t *RxRaTracker) ProcessReceivedRa(src ip6.Address, rawRa []byte) error {
	var ra nd6.RaMessage
	if err := ra.Unmarshal(rawRa); err != nil {
		return err
	}

	// Find or create router entry.
	entry := t.FindRouter(src)
	isNew := false
	if entry == nil {
		if len(t.routers) >= t.maxRouters {
			// Try to evict an empty entry.
			evicted := false
			for i := range t.routers {
				if t.routers[i].IsEmpty() {
					t.routers = append(t.routers[:i], t.routers[i+1:]...)
					evicted = true
					break
				}
			}
			if !evicted {
				// Table full, drop the RA.
				return nil
			}
		}
		re := newRouterEntry(src, t.maxOnLinkPrefixes, t.maxRoutePrefixes)
		t.routers = append(t.routers, re)
		entry = &t.routers[len(t.routers)-1]
		isNew = true
	}

	// Update header-level fields.
	entry.RouterLifetime = ra.Header.GetRouterLifetime()
	entry.DefaultRouterPreference = ra.Header.GetDefaultRouterPreference()

	// Process Prefix Information Options (on-link prefixes).
	pios := ra.FindPrefixInfoOptions()
	for i := range pios {
		pio := &pios[i]
		if !pio.IsOnLinkFlagSet() {
			continue
		}
		prefix := ip6.NewPrefix(pio.Prefix, pio.GetPrefixLength())
		entry.updateOnLinkPrefix(prefix, pio.ValidLifetime)
	}

	// Process Route Information Options.
	rios := ra.FindRouteInfoOptions()
	for i := range rios {
		rio := &rios[i]
		prefix := ip6.NewPrefix(rio.GetPrefix(), rio.GetPrefixLength())
		entry.updateRoutePrefix(prefix, rio.GetRouteLifetime(), rio.GetRoutePreference())
	}

	// Process NAT64 Prefix Option (PREF64).
	t.processNat64Options(entry, &ra)

	// Process RA Flags Extension for stub router flag.
	t.processRaFlagsExtension(entry, &ra)

	// Remove any prefixes that have been set to zero lifetime.
	entry.removeExpiredPrefixes()

	// Notify callback.
	if t.callback != nil {
		if isNew {
			t.callback(EventRouterAdded, src)
		} else {
			t.callback(EventRouterUpdated, src)
		}
	}

	return nil
}

// processNat64Options scans for PREF64 options and updates the entry.
func (t *RxRaTracker) processNat64Options(entry *RouterEntry, ra *nd6.RaMessage) {
	b := ra.Options
	for len(b) >= nd6.OptionHeaderSize {
		optType := b[0]
		optLen := b[1]
		if optLen == 0 {
			break
		}
		totalSize := int(optLen) * nd6.OptionLengthUnit
		if totalSize > len(b) {
			break
		}
		if optType == nd6.OptionTypeNat64Prefix {
			var opt nd6.Nat64PrefixOption
			if err := opt.Unmarshal(b[:totalSize]); err == nil {
				prefixLen := opt.GetPrefixLength()
				if prefixLen > 0 {
					prefix := ip6.NewPrefix(opt.GetPrefix(), prefixLen)
					entry.Nat64Prefix = &prefix
					entry.Nat64Lifetime = uint32(opt.GetLifetime())
				}
			}
		}
		b = b[totalSize:]
	}
}

// processRaFlagsExtension scans for RA Flags Extension options.
func (t *RxRaTracker) processRaFlagsExtension(entry *RouterEntry, ra *nd6.RaMessage) {
	b := ra.Options
	entry.IsStubRouter = false // Reset; set from RA Flags Extension if present.
	for len(b) >= nd6.OptionHeaderSize {
		optType := b[0]
		optLen := b[1]
		if optLen == 0 {
			break
		}
		totalSize := int(optLen) * nd6.OptionLengthUnit
		if totalSize > len(b) {
			break
		}
		if optType == nd6.OptionTypeRaFlagsExtension {
			var opt nd6.RaFlagsExtOption
			if err := opt.Unmarshal(b[:totalSize]); err == nil {
				entry.IsStubRouter = opt.IsFlagSet(StubRouterFlag)
			}
		}
		b = b[totalSize:]
	}
}

// ExpireRouters removes routers that have no default router lifetime and no
// valid prefixes. Returns the number of routers removed.
func (t *RxRaTracker) ExpireRouters() int {
	removed := 0
	n := 0
	for i := range t.routers {
		if t.routers[i].IsEmpty() {
			if t.callback != nil {
				t.callback(EventRouterRemoved, t.routers[i].Address)
			}
			removed++
		} else {
			t.routers[n] = t.routers[i]
			n++
		}
	}
	t.routers = t.routers[:n]
	return removed
}
