// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tmf

// TMF URI path string constants.
//
// Every Thread Management Framework resource is identified by a short CoAP URI
// path. These constants hold the raw path strings (without a leading slash) and
// are grouped by functional area, matching the canonical order from the
// OpenThread C++ implementation (uri_paths.hpp / uri_paths.cpp).

// Address management URIs (prefix "a/").
const (
	UriPathAddressError   = "a/ae" //nolint:revive // Preserve the exported API spelling for existing callers. Address Error
	UriPathAddressNotify  = "a/an" //nolint:revive // Preserve the exported API spelling for existing callers. Address Notification
	UriPathAddressQuery   = "a/aq" //nolint:revive // Preserve the exported API spelling for existing callers. Address Query
	UriPathAddressRelease = "a/ar" //nolint:revive // Preserve the exported API spelling for existing callers. Address Release
	UriPathAddressSolicit = "a/as" //nolint:revive // Preserve the exported API spelling for existing callers. Address Solicit
	UriPathServerData     = "a/sd" //nolint:revive // Preserve the exported API spelling for existing callers. Server Data Registration
	UriPathAnycastLocate  = "a/yl" //nolint:revive // Preserve the exported API spelling for existing callers. Anycast Locate
)

// Backbone URIs (prefix "b/", Thread 1.2+).
const (
	UriPathBackboneAnswer = "b/ba"  //nolint:revive // Preserve the exported API spelling for existing callers. Backbone Answer / Backbone Notification
	UriPathBackboneMlr    = "b/bmr" //nolint:revive // Preserve the exported API spelling for existing callers. Backbone Multicast Listener Report
	UriPathBackboneQuery  = "b/bq"  //nolint:revive // Preserve the exported API spelling for existing callers. Backbone Query
)

// Commissioner / Joiner / Management URIs (prefix "c/").
const (
	UriPathAnnounceBegin         = "c/ab" //nolint:revive // Preserve the exported API spelling for existing callers. Announce Begin
	UriPathActiveGet             = "c/ag" //nolint:revive // Preserve the exported API spelling for existing callers. MGMT_ACTIVE_GET
	UriPathActiveReplace         = "c/ar" //nolint:revive // Preserve the exported API spelling for existing callers. MGMT_ACTIVE_REPLACE
	UriPathActiveSet             = "c/as" //nolint:revive // Preserve the exported API spelling for existing callers. MGMT_ACTIVE_SET
	UriPathCommissionerKeepAlive = "c/ca" //nolint:revive // Preserve the exported API spelling for existing callers. Commissioner Keep-Alive
	UriPathCommissionerGet       = "c/cg" //nolint:revive // Preserve the exported API spelling for existing callers. MGMT_COMMISSIONER_GET
	UriPathCommissionerPetition  = "c/cp" //nolint:revive // Preserve the exported API spelling for existing callers. Commissioner Petition
	UriPathCommissionerSet       = "c/cs" //nolint:revive // Preserve the exported API spelling for existing callers. MGMT_COMMISSIONER_SET
	UriPathDatasetChanged        = "c/dc" //nolint:revive // Preserve the exported API spelling for existing callers. MGMT_DATASET_CHANGED
	UriPathEnergyReport          = "c/er" //nolint:revive // Preserve the exported API spelling for existing callers. Energy Report
	UriPathEnergyScan            = "c/es" //nolint:revive // Preserve the exported API spelling for existing callers. Energy Scan
	UriPathJoinerEntrust         = "c/je" //nolint:revive // Preserve the exported API spelling for existing callers. Joiner Entrust
	UriPathJoinerFinalize        = "c/jf" //nolint:revive // Preserve the exported API spelling for existing callers. Joiner Finalize
	UriPathLeaderKeepAlive       = "c/la" //nolint:revive // Preserve the exported API spelling for existing callers. Leader Keep-Alive
	UriPathLeaderPetition        = "c/lp" //nolint:revive // Preserve the exported API spelling for existing callers. Leader Petition
	UriPathPanIDConflict         = "c/pc" //nolint:revive // Preserve the exported API spelling for existing callers. PAN ID Conflict
	UriPathPendingGet            = "c/pg" //nolint:revive // Preserve the exported API spelling for existing callers. MGMT_PENDING_GET
	UriPathPanIDQuery            = "c/pq" //nolint:revive // Preserve the exported API spelling for existing callers. PAN ID Query
	UriPathPendingSet            = "c/ps" //nolint:revive // Preserve the exported API spelling for existing callers. MGMT_PENDING_SET
	UriPathRelayRx               = "c/rx" //nolint:revive // Preserve the exported API spelling for existing callers. Relay Receive
	UriPathTcatEnable            = "c/te" //nolint:revive // Preserve the exported API spelling for existing callers. TCAT Enable
	UriPathRelayTx               = "c/tx" //nolint:revive // Preserve the exported API spelling for existing callers. Relay Transmit
	UriPathProxyRx               = "c/ur" //nolint:revive // Preserve the exported API spelling for existing callers. Proxy Receive
	UriPathProxyTx               = "c/ut" //nolint:revive // Preserve the exported API spelling for existing callers. Proxy Transmit
)

// Network Diagnostic URIs (prefix "d/").
const (
	UriPathDiagnosticGetAnswer  = "d/da" //nolint:revive // Preserve the exported API spelling for existing callers. Diagnostic Get Answer
	UriPathDiagnosticGetRequest = "d/dg" //nolint:revive // Preserve the exported API spelling for existing callers. Diagnostic Get Request
	UriPathDiagnosticGetQuery   = "d/dq" //nolint:revive // Preserve the exported API spelling for existing callers. Diagnostic Get Query
	UriPathDiagnosticReset      = "d/dr" //nolint:revive // Preserve the exported API spelling for existing callers. Diagnostic Reset
)

// History URIs (prefix "h/").
const (
	UriPathHistoryAnswer = "h/an" //nolint:revive // Preserve the exported API spelling for existing callers. History Answer
	UriPathHistoryQuery  = "h/qy" //nolint:revive // Preserve the exported API spelling for existing callers. History Query
)

// Network-layer URIs (prefix "n/").
const (
	UriPathDuaRegistrationNotify  = "n/dn" //nolint:revive // Preserve the exported API spelling for existing callers. DUA Registration Notification
	UriPathDuaRegistrationRequest = "n/dr" //nolint:revive // Preserve the exported API spelling for existing callers. DUA Registration Request
	UriPathMlr                    = "n/mr" //nolint:revive // Preserve the exported API spelling for existing callers. Multicast Listener Registration
)

// AllUriPaths is the complete list of defined TMF URI path strings, sorted
// alphabetically (matching the canonical C++ order).
var AllUriPaths = [...]string{ //nolint:revive // Preserve the exported API spelling for existing callers.
	UriPathAddressError,
	UriPathAddressNotify,
	UriPathAddressQuery,
	UriPathAddressRelease,
	UriPathAddressSolicit,
	UriPathServerData,
	UriPathAnycastLocate,
	UriPathBackboneAnswer,
	UriPathBackboneMlr,
	UriPathBackboneQuery,
	UriPathAnnounceBegin,
	UriPathActiveGet,
	UriPathActiveReplace,
	UriPathActiveSet,
	UriPathCommissionerKeepAlive,
	UriPathCommissionerGet,
	UriPathCommissionerPetition,
	UriPathCommissionerSet,
	UriPathDatasetChanged,
	UriPathEnergyReport,
	UriPathEnergyScan,
	UriPathJoinerEntrust,
	UriPathJoinerFinalize,
	UriPathLeaderKeepAlive,
	UriPathLeaderPetition,
	UriPathPanIDConflict,
	UriPathPendingGet,
	UriPathPanIDQuery,
	UriPathPendingSet,
	UriPathRelayRx,
	UriPathTcatEnable,
	UriPathRelayTx,
	UriPathProxyRx,
	UriPathProxyTx,
	UriPathDiagnosticGetAnswer,
	UriPathDiagnosticGetRequest,
	UriPathDiagnosticGetQuery,
	UriPathDiagnosticReset,
	UriPathHistoryAnswer,
	UriPathHistoryQuery,
	UriPathDuaRegistrationNotify,
	UriPathDuaRegistrationRequest,
	UriPathMlr,
}

// PathToString returns the full URI path with a leading slash.
func PathToString(uri string) string {
	return "/" + uri
}

// UriFromPathString extracts the URI path by stripping a leading slash.
// If the path has no leading slash it is returned unchanged.
func UriFromPathString(path string) string { //nolint:revive // Preserve the exported API spelling for existing callers.
	if path != "" && path[0] == '/' {
		return path[1:]
	}
	return path
}
