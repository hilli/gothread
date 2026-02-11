// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tmf

import "testing"

// ---------------------------------------------------------------------------
// URI path string constant tests
// ---------------------------------------------------------------------------

func TestUriPathConstants(t *testing.T) {
	t.Parallel()

	// Spot-check every URI path constant against the C++ reference values.
	tests := []struct {
		name string
		got  string
		want string
	}{
		// Address management
		{"AddressError", UriPathAddressError, "a/ae"},
		{"AddressNotify", UriPathAddressNotify, "a/an"},
		{"AddressQuery", UriPathAddressQuery, "a/aq"},
		{"AddressRelease", UriPathAddressRelease, "a/ar"},
		{"AddressSolicit", UriPathAddressSolicit, "a/as"},
		{"ServerData", UriPathServerData, "a/sd"},
		{"AnycastLocate", UriPathAnycastLocate, "a/yl"},

		// Backbone
		{"BackboneAnswer", UriPathBackboneAnswer, "b/ba"},
		{"BackboneMlr", UriPathBackboneMlr, "b/bmr"},
		{"BackboneQuery", UriPathBackboneQuery, "b/bq"},

		// Commissioner / Joiner / Management
		{"AnnounceBegin", UriPathAnnounceBegin, "c/ab"},
		{"ActiveGet", UriPathActiveGet, "c/ag"},
		{"ActiveReplace", UriPathActiveReplace, "c/ar"},
		{"ActiveSet", UriPathActiveSet, "c/as"},
		{"CommissionerKeepAlive", UriPathCommissionerKeepAlive, "c/ca"},
		{"CommissionerGet", UriPathCommissionerGet, "c/cg"},
		{"CommissionerPetition", UriPathCommissionerPetition, "c/cp"},
		{"CommissionerSet", UriPathCommissionerSet, "c/cs"},
		{"DatasetChanged", UriPathDatasetChanged, "c/dc"},
		{"EnergyReport", UriPathEnergyReport, "c/er"},
		{"EnergyScan", UriPathEnergyScan, "c/es"},
		{"JoinerEntrust", UriPathJoinerEntrust, "c/je"},
		{"JoinerFinalize", UriPathJoinerFinalize, "c/jf"},
		{"LeaderKeepAlive", UriPathLeaderKeepAlive, "c/la"},
		{"LeaderPetition", UriPathLeaderPetition, "c/lp"},
		{"PanIDConflict", UriPathPanIDConflict, "c/pc"},
		{"PendingGet", UriPathPendingGet, "c/pg"},
		{"PanIDQuery", UriPathPanIDQuery, "c/pq"},
		{"PendingSet", UriPathPendingSet, "c/ps"},
		{"RelayRx", UriPathRelayRx, "c/rx"},
		{"TcatEnable", UriPathTcatEnable, "c/te"},
		{"RelayTx", UriPathRelayTx, "c/tx"},
		{"ProxyRx", UriPathProxyRx, "c/ur"},
		{"ProxyTx", UriPathProxyTx, "c/ut"},

		// Diagnostics
		{"DiagnosticGetAnswer", UriPathDiagnosticGetAnswer, "d/da"},
		{"DiagnosticGetRequest", UriPathDiagnosticGetRequest, "d/dg"},
		{"DiagnosticGetQuery", UriPathDiagnosticGetQuery, "d/dq"},
		{"DiagnosticReset", UriPathDiagnosticReset, "d/dr"},

		// History
		{"HistoryAnswer", UriPathHistoryAnswer, "h/an"},
		{"HistoryQuery", UriPathHistoryQuery, "h/qy"},

		// Network-layer
		{"DuaRegistrationNotify", UriPathDuaRegistrationNotify, "n/dn"},
		{"DuaRegistrationRequest", UriPathDuaRegistrationRequest, "n/dr"},
		{"Mlr", UriPathMlr, "n/mr"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("UriPath%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestAllUriPathsCount(t *testing.T) {
	t.Parallel()

	// The C++ reference defines 43 URI paths (excluding kUriUnknown).
	const wantCount = 43
	if got := len(AllUriPaths); got != wantCount {
		t.Errorf("len(AllUriPaths) = %d, want %d", got, wantCount)
	}
}

func TestAllUriPathsNonEmpty(t *testing.T) {
	t.Parallel()

	for i, p := range AllUriPaths {
		if p == "" {
			t.Errorf("AllUriPaths[%d] is empty", i)
		}
	}
}

func TestAllUriPathsMatchEnum(t *testing.T) {
	t.Parallel()

	// Each entry in AllUriPaths should equal PathForURI(URI(index)),
	// verifying consistency between the string constants and the URI enum.
	// Note: uri.go has 44 URIs (includes URICommissionerData which is not in
	// the C++ reference), so we compare only the paths that exist in both.
	pathSet := make(map[string]bool, len(AllUriPaths))
	for _, p := range AllUriPaths {
		pathSet[p] = true
	}

	for u := URI(0); u < URIUnknown; u++ {
		path := PathForURI(u)
		if path == "" {
			continue
		}
		// "a/cd" (URICommissionerData) is a Go-only addition not in the C++
		// reference; skip it when checking against AllUriPaths.
		if path == "a/cd" {
			continue
		}
		if !pathSet[path] {
			t.Errorf("PathForURI(%d) = %q not found in AllUriPaths", u, path)
		}
	}
}

// ---------------------------------------------------------------------------
// Helper function tests
// ---------------------------------------------------------------------------

func TestPathToString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{"a/ae", "/a/ae"},
		{"c/ag", "/c/ag"},
		{"", "/"},
	}
	for _, tt := range tests {
		if got := PathToString(tt.input); got != tt.want {
			t.Errorf("PathToString(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestUriFromPathString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{"/a/ae", "a/ae"},
		{"/c/ag", "c/ag"},
		{"c/ag", "c/ag"},
		{"/", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := UriFromPathString(tt.input); got != tt.want {
			t.Errorf("UriFromPathString(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Version constant tests
// ---------------------------------------------------------------------------

func TestThreadVersionValues(t *testing.T) {
	t.Parallel()

	if ThreadVersion1p1 != 2 {
		t.Errorf("ThreadVersion1p1 = %d, want 2", ThreadVersion1p1)
	}
	if ThreadVersion1p2 != 3 {
		t.Errorf("ThreadVersion1p2 = %d, want 3", ThreadVersion1p2)
	}
	if ThreadVersion1p3 != 4 {
		t.Errorf("ThreadVersion1p3 = %d, want 4", ThreadVersion1p3)
	}
	if ThreadVersion1p3p1 != 5 {
		t.Errorf("ThreadVersion1p3p1 = %d, want 5", ThreadVersion1p3p1)
	}
	if ThreadVersion1p4 != 5 {
		t.Errorf("ThreadVersion1p4 = %d, want 5", ThreadVersion1p4)
	}
	// 1.3.1 and 1.4 share the same wire value.
	if ThreadVersion1p3p1 != ThreadVersion1p4 {
		t.Errorf("ThreadVersion1p3p1 (%d) != ThreadVersion1p4 (%d)", ThreadVersion1p3p1, ThreadVersion1p4)
	}
}

func TestThreadVersionCurrentAndMin(t *testing.T) {
	t.Parallel()

	if ThreadVersionCurrent != ThreadVersion1p4 {
		t.Errorf("ThreadVersionCurrent = %d, want %d", ThreadVersionCurrent, ThreadVersion1p4)
	}
	if ThreadVersionMin != ThreadVersion1p1 {
		t.Errorf("ThreadVersionMin = %d, want %d", ThreadVersionMin, ThreadVersion1p1)
	}
	if ThreadVersionMin > ThreadVersionCurrent {
		t.Errorf("ThreadVersionMin (%d) > ThreadVersionCurrent (%d)", ThreadVersionMin, ThreadVersionCurrent)
	}
}

func TestIsVersionSupported(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version uint16
		want    bool
	}{
		{0, false},
		{1, false},
		{ThreadVersion1p1, true},     // 2
		{ThreadVersion1p2, true},     // 3
		{ThreadVersion1p3, true},     // 4
		{ThreadVersion1p4, true},     // 5
		{ThreadVersionCurrent, true}, // same as 1p4
		{6, false},
		{0xFFFF, false},
	}
	for _, tt := range tests {
		if got := IsVersionSupported(tt.version); got != tt.want {
			t.Errorf("IsVersionSupported(%d) = %v, want %v", tt.version, got, tt.want)
		}
	}
}
