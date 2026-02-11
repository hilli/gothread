// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package border

import (
	"testing"

	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// LifetimedPrefix
// ---------------------------------------------------------------------------

func TestLifetimedPrefixIsExpired(t *testing.T) {
	lp := LifetimedPrefix{
		Prefix:            ip6.NewPrefix(ip6.Address{0x20, 0x01, 0x0d, 0xb8}, 64),
		ValidLifetime:     3600,
		PreferredLifetime: 1800,
	}
	if lp.IsExpired() {
		t.Error("expected not expired with non-zero valid lifetime")
	}

	lp.ValidLifetime = 0
	if !lp.IsExpired() {
		t.Error("expected expired with zero valid lifetime")
	}
}

// ---------------------------------------------------------------------------
// OnLinkPrefix
// ---------------------------------------------------------------------------

func TestOnLinkPrefixIsExpired(t *testing.T) {
	p := OnLinkPrefix{
		Prefix:        ip6.NewPrefix(ip6.Address{0x20, 0x01}, 32),
		ValidLifetime: 100,
	}
	if p.IsExpired() {
		t.Error("expected not expired")
	}
	p.ValidLifetime = 0
	if !p.IsExpired() {
		t.Error("expected expired")
	}
}

// ---------------------------------------------------------------------------
// RoutePrefix
// ---------------------------------------------------------------------------

func TestRoutePrefixIsExpired(t *testing.T) {
	p := RoutePrefix{
		Prefix:          ip6.NewPrefix(ip6.Address{0xfd, 0x00}, 48),
		RouteLifetime:   600,
		RoutePreference: RoutePrefHigh,
	}
	if p.IsExpired() {
		t.Error("expected not expired")
	}
	p.RouteLifetime = 0
	if !p.IsExpired() {
		t.Error("expected expired")
	}
}

// ---------------------------------------------------------------------------
// InfiniteLifetime
// ---------------------------------------------------------------------------

func TestInfiniteLifetimeValue(t *testing.T) {
	if InfiniteLifetime != 0xFFFFFFFF {
		t.Errorf("InfiniteLifetime = %d, want 0xFFFFFFFF", InfiniteLifetime)
	}
}

// ---------------------------------------------------------------------------
// FavoredOmrPrefix
// ---------------------------------------------------------------------------

func TestFavoredOmrPrefixHighBeatsLow(t *testing.T) {
	a := FavoredOmrPrefix{
		OmrPrefix:  OmrPrefix{Prefix: ip6.NewPrefix(ip6.Address{0xfd, 0x01}, 64)},
		Preference: RoutePrefHigh,
	}
	b := FavoredOmrPrefix{
		OmrPrefix:  OmrPrefix{Prefix: ip6.NewPrefix(ip6.Address{0xfd, 0x02}, 64)},
		Preference: RoutePrefLow,
	}
	if !a.IsFavoredOver(b) {
		t.Error("high preference should be favored over low")
	}
	if b.IsFavoredOver(a) {
		t.Error("low preference should not be favored over high")
	}
}

func TestFavoredOmrPrefixMediumBeatsLow(t *testing.T) {
	a := FavoredOmrPrefix{
		OmrPrefix:  OmrPrefix{Prefix: ip6.NewPrefix(ip6.Address{0xfd, 0x01}, 64)},
		Preference: RoutePrefMedium,
	}
	b := FavoredOmrPrefix{
		OmrPrefix:  OmrPrefix{Prefix: ip6.NewPrefix(ip6.Address{0xfd, 0x02}, 64)},
		Preference: RoutePrefLow,
	}
	if !a.IsFavoredOver(b) {
		t.Error("medium preference should be favored over low")
	}
}

func TestFavoredOmrPrefixTieBreakByPrefix(t *testing.T) {
	a := FavoredOmrPrefix{
		OmrPrefix:  OmrPrefix{Prefix: ip6.NewPrefix(ip6.Address{0xfd, 0x02}, 64)},
		Preference: RoutePrefMedium,
	}
	b := FavoredOmrPrefix{
		OmrPrefix:  OmrPrefix{Prefix: ip6.NewPrefix(ip6.Address{0xfd, 0x01}, 64)},
		Preference: RoutePrefMedium,
	}
	// When preferences are equal, the one whose opponent has a smaller prefix
	// loses (i.e., the larger prefix is favored, based on LessThan reversal).
	if !a.IsFavoredOver(b) {
		t.Error("a (fd02) should be favored over b (fd01) with equal preference")
	}
}

func TestRoutePreferenceConstants(t *testing.T) {
	if RoutePrefMedium != 0 {
		t.Errorf("RoutePrefMedium = %d, want 0", RoutePrefMedium)
	}
	if RoutePrefHigh != 1 {
		t.Errorf("RoutePrefHigh = %d, want 1", RoutePrefHigh)
	}
	if RoutePrefLow != 3 {
		t.Errorf("RoutePrefLow = %d, want 3", RoutePrefLow)
	}
}
