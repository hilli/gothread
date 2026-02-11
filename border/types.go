// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package border provides border router infrastructure types and services.
//
// This is a Go port of the border router types from OpenThread's
// src/core/border_router/ covering infrastructure interface management,
// prefix tracking, and received RA processing.
package border

import (
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/nd6"
)

// RoutePreference is an alias for nd6.RoutePreference for convenience.
type RoutePreference = nd6.RoutePreference

// Route preference constants re-exported for convenience.
const (
	RoutePrefMedium = nd6.RoutePrefMedium
	RoutePrefHigh   = nd6.RoutePrefHigh
	RoutePrefLow    = nd6.RoutePrefLow
)

// InfiniteLifetime is the special lifetime value meaning "infinite" (all ones).
const InfiniteLifetime uint32 = 0xFFFFFFFF

// ---------------------------------------------------------------------------
// LifetimedPrefix — a prefix with valid and preferred lifetimes.
// ---------------------------------------------------------------------------

// LifetimedPrefix pairs an IPv6 prefix with valid and preferred lifetimes
// as advertised in RA Prefix Information Options.
type LifetimedPrefix struct {
	Prefix            ip6.Prefix
	ValidLifetime     uint32
	PreferredLifetime uint32
}

// IsExpired returns true if the valid lifetime is zero.
func (p LifetimedPrefix) IsExpired() bool {
	return p.ValidLifetime == 0
}

// ---------------------------------------------------------------------------
// OnLinkPrefix — prefix from a PIO with the On-Link (L) flag set.
// ---------------------------------------------------------------------------

// OnLinkPrefix represents an on-link prefix discovered from a PIO.
type OnLinkPrefix struct {
	Prefix        ip6.Prefix
	ValidLifetime uint32
}

// IsExpired returns true if the valid lifetime is zero.
func (p OnLinkPrefix) IsExpired() bool {
	return p.ValidLifetime == 0
}

// ---------------------------------------------------------------------------
// RoutePrefix — prefix from a Route Information Option.
// ---------------------------------------------------------------------------

// RoutePrefix represents a route prefix discovered from a RIO.
type RoutePrefix struct {
	Prefix          ip6.Prefix
	RouteLifetime   uint32
	RoutePreference RoutePreference
}

// IsExpired returns true if the route lifetime is zero.
func (p RoutePrefix) IsExpired() bool {
	return p.RouteLifetime == 0
}

// ---------------------------------------------------------------------------
// OmrPrefix — Off-Mesh Routable prefix.
// ---------------------------------------------------------------------------

// OmrPrefix represents an Off-Mesh Routable (OMR) prefix.
type OmrPrefix struct {
	Prefix ip6.Prefix
}

// FavoredOmrPrefix is an OmrPrefix with an associated preference,
// used when comparing multiple OMR prefixes to pick the best one.
type FavoredOmrPrefix struct {
	OmrPrefix
	Preference RoutePreference
}

// IsFavoredOver returns true if this prefix is preferred over the other.
// A higher route preference wins; if equal, the lexicographically smaller
// prefix wins for determinism.
func (f FavoredOmrPrefix) IsFavoredOver(other FavoredOmrPrefix) bool {
	// Higher numeric preference value is NOT necessarily "better" —
	// RoutePrefHigh (1) > RoutePrefMedium (0) but RoutePrefLow (3) is worse.
	// Map to a comparable rank: High=2, Medium=1, Low=0.
	rank := func(p RoutePreference) int {
		switch p {
		case RoutePrefHigh:
			return 2
		case RoutePrefMedium:
			return 1
		case RoutePrefLow:
			return 0
		default:
			return 1 // treat unknown as medium
		}
	}

	r1 := rank(f.Preference)
	r2 := rank(other.Preference)

	if r1 != r2 {
		return r1 > r2
	}

	// Break tie with lexicographic prefix comparison.
	return other.Prefix.LessThan(f.Prefix)
}
