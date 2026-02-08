// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tmf

import "testing"

func TestPathForURIRoundtrip(t *testing.T) {
	t.Parallel()

	// Every URI constant (except URIUnknown) must have a non-empty path
	// and must roundtrip through URIFromPath.
	for u := URI(0); u < URIUnknown; u++ {
		path := PathForURI(u)
		if path == "" {
			t.Errorf("PathForURI(%d) returned empty string", u)
			continue
		}
		got := URIFromPath(path)
		if got != u {
			t.Errorf("URIFromPath(%q) = %d, want %d", path, got, u)
		}
	}
}

func TestPathForURIUnknown(t *testing.T) {
	t.Parallel()

	if got := PathForURI(URIUnknown); got != "" {
		t.Errorf("PathForURI(URIUnknown) = %q, want empty", got)
	}
}

func TestPathForURIOutOfRange(t *testing.T) {
	t.Parallel()

	if got := PathForURI(URIUnknown + 10); got != "" {
		t.Errorf("PathForURI(out-of-range) = %q, want empty", got)
	}
}

func TestURIFromPathUnknown(t *testing.T) {
	t.Parallel()

	if got := URIFromPath("x/unknown"); got != URIUnknown {
		t.Errorf("URIFromPath(unknown) = %d, want URIUnknown", got)
	}
}

func TestURIFromPathEmpty(t *testing.T) {
	t.Parallel()

	if got := URIFromPath(""); got != URIUnknown {
		t.Errorf("URIFromPath(empty) = %d, want URIUnknown", got)
	}
}

func TestAllPathsUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[string]URI)
	for u := URI(0); u < URIUnknown; u++ {
		path := PathForURI(u)
		if prev, ok := seen[path]; ok {
			t.Errorf("duplicate path %q: URI %d and %d", path, prev, u)
		}
		seen[path] = u
	}
}

func TestKnownPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		uri  URI
		path string
	}{
		{URIAddressError, "a/ae"},
		{URIAddressSolicit, "a/as"},
		{URIServerData, "a/sd"},
		{URIAnycastLocate, "a/yl"},
		{URIBackboneMlr, "b/bmr"},
		{URIActiveGet, "c/ag"},
		{URICommissionerPetition, "c/cp"},
		{URIJoinerFinalize, "c/jf"},
		{URIRelayRx, "c/rx"},
		{URIRelayTx, "c/tx"},
		{URIProxyRx, "c/ur"},
		{URIProxyTx, "c/ut"},
		{URIDiagnosticGetRequest, "d/dg"},
		{URIDiagnosticReset, "d/dr"},
		{URIHistoryQuery, "h/qy"},
		{URIDuaRegistrationNotify, "n/dn"},
		{URIMlr, "n/mr"},
	}

	for _, tt := range tests {
		if got := PathForURI(tt.uri); got != tt.path {
			t.Errorf("PathForURI(%d) = %q, want %q", tt.uri, got, tt.path)
		}
		if got := URIFromPath(tt.path); got != tt.uri {
			t.Errorf("URIFromPath(%q) = %d, want %d", tt.path, got, tt.uri)
		}
	}
}

func TestURICount(t *testing.T) {
	t.Parallel()

	// There should be 43 defined URIs (before URIUnknown).
	const expectedCount = 43
	if int(URIUnknown) != expectedCount {
		t.Errorf("URI count = %d, want %d", URIUnknown, expectedCount)
	}
}
