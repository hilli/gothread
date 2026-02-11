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
	UriPathAddressError   = "a/ae" // Address Error
	UriPathAddressNotify  = "a/an" // Address Notification
	UriPathAddressQuery   = "a/aq" // Address Query
	UriPathAddressRelease = "a/ar" // Address Release
	UriPathAddressSolicit = "a/as" // Address Solicit
	UriPathServerData     = "a/sd" // Server Data Registration
	UriPathAnycastLocate  = "a/yl" // Anycast Locate
)

// Backbone URIs (prefix "b/", Thread 1.2+).
const (
	UriPathBackboneAnswer = "b/ba"  // Backbone Answer / Backbone Notification
	UriPathBackboneMlr    = "b/bmr" // Backbone Multicast Listener Report
	UriPathBackboneQuery  = "b/bq"  // Backbone Query
)

// Commissioner / Joiner / Management URIs (prefix "c/").
const (
	UriPathAnnounceBegin         = "c/ab" // Announce Begin
	UriPathActiveGet             = "c/ag" // MGMT_ACTIVE_GET
	UriPathActiveReplace         = "c/ar" // MGMT_ACTIVE_REPLACE
	UriPathActiveSet             = "c/as" // MGMT_ACTIVE_SET
	UriPathCommissionerKeepAlive = "c/ca" // Commissioner Keep-Alive
	UriPathCommissionerGet       = "c/cg" // MGMT_COMMISSIONER_GET
	UriPathCommissionerPetition  = "c/cp" // Commissioner Petition
	UriPathCommissionerSet       = "c/cs" // MGMT_COMMISSIONER_SET
	UriPathDatasetChanged        = "c/dc" // MGMT_DATASET_CHANGED
	UriPathEnergyReport          = "c/er" // Energy Report
	UriPathEnergyScan            = "c/es" // Energy Scan
	UriPathJoinerEntrust         = "c/je" // Joiner Entrust
	UriPathJoinerFinalize        = "c/jf" // Joiner Finalize
	UriPathLeaderKeepAlive       = "c/la" // Leader Keep-Alive
	UriPathLeaderPetition        = "c/lp" // Leader Petition
	UriPathPanIDConflict         = "c/pc" // PAN ID Conflict
	UriPathPendingGet            = "c/pg" // MGMT_PENDING_GET
	UriPathPanIDQuery            = "c/pq" // PAN ID Query
	UriPathPendingSet            = "c/ps" // MGMT_PENDING_SET
	UriPathRelayRx               = "c/rx" // Relay Receive
	UriPathTcatEnable            = "c/te" // TCAT Enable
	UriPathRelayTx               = "c/tx" // Relay Transmit
	UriPathProxyRx               = "c/ur" // Proxy Receive
	UriPathProxyTx               = "c/ut" // Proxy Transmit
)

// Network Diagnostic URIs (prefix "d/").
const (
	UriPathDiagnosticGetAnswer  = "d/da" // Diagnostic Get Answer
	UriPathDiagnosticGetRequest = "d/dg" // Diagnostic Get Request
	UriPathDiagnosticGetQuery   = "d/dq" // Diagnostic Get Query
	UriPathDiagnosticReset      = "d/dr" // Diagnostic Reset
)

// History URIs (prefix "h/").
const (
	UriPathHistoryAnswer = "h/an" // History Answer
	UriPathHistoryQuery  = "h/qy" // History Query
)

// Network-layer URIs (prefix "n/").
const (
	UriPathDuaRegistrationNotify  = "n/dn" // DUA Registration Notification
	UriPathDuaRegistrationRequest = "n/dr" // DUA Registration Request
	UriPathMlr                    = "n/mr" // Multicast Listener Registration
)

// AllUriPaths is the complete list of defined TMF URI path strings, sorted
// alphabetically (matching the canonical C++ order).
var AllUriPaths = [...]string{
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
func UriFromPathString(path string) string {
	if len(path) > 0 && path[0] == '/' {
		return path[1:]
	}
	return path
}
