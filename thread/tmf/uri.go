// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package tmf implements the Thread Management Framework (TMF) agent.
//
// TMF is a thin layer on top of CoAP that provides URI-based dispatch for
// Thread management messages, TMF-specific DSCP/priority mapping, and
// addressing validation for link-local and mesh-local scopes.
//
// This is a Go port of OpenThread's src/core/thread/tmf.hpp,
// src/core/thread/tmf.cpp, and src/core/thread/uri_paths.hpp/cpp.
package tmf

// ---------------------------------------------------------------------------
// URI enum
// ---------------------------------------------------------------------------

// URI identifies a Thread Management Framework resource path.
type URI uint8

const (
	// URIAddressError is the "a/ae" (Address Error) URI.
	URIAddressError URI = iota
	// URIAddressNotify is the "a/an" (Address Notification) URI.
	URIAddressNotify
	// URIAddressQuery is the "a/aq" (Address Query) URI.
	URIAddressQuery
	// URIAddressRelease is the "a/ar" (Address Release) URI.
	URIAddressRelease
	// URIAddressSolicit is the "a/as" (Address Solicit) URI.
	URIAddressSolicit
	// URIServerData is the "a/sd" (Server Data) URI.
	URIServerData
	// URICommissionerData is the "a/cd" (Commissioner Data) URI.
	URICommissionerData
	// URIAnycastLocate is the "a/yl" (Anycast Locate) URI.
	URIAnycastLocate

	// URIBackboneAnswer is the "b/ba" (Backbone Answer) URI.
	URIBackboneAnswer
	// URIBackboneMlr is the "b/bmr" (Backbone Multicast Listener Registration) URI.
	URIBackboneMlr
	// URIBackboneQuery is the "b/bq" (Backbone Query) URI.
	URIBackboneQuery

	// URIAnnounceBegin is the "c/ab" (Announce Begin) URI.
	URIAnnounceBegin
	// URIActiveGet is the "c/ag" (Active Get) URI.
	URIActiveGet
	// URIActiveReplace is the "c/ar" (Active Replace) URI.
	URIActiveReplace
	// URIActiveSet is the "c/as" (Active Set) URI.
	URIActiveSet
	// URICommissionerKeepAlive is the "c/ca" (Commissioner Keep-Alive) URI.
	URICommissionerKeepAlive
	// URICommissionerGet is the "c/cg" (Commissioner Get) URI.
	URICommissionerGet
	// URICommissionerPetition is the "c/cp" (Commissioner Petition) URI.
	URICommissionerPetition
	// URICommissionerSet is the "c/cs" (Commissioner Set) URI.
	URICommissionerSet
	// URIDatasetChanged is the "c/dc" (Dataset Changed) URI.
	URIDatasetChanged
	// URIEnergyReport is the "c/er" (Energy Report) URI.
	URIEnergyReport
	// URIEnergyScan is the "c/es" (Energy Scan) URI.
	URIEnergyScan
	// URIJoinerEntrust is the "c/je" (Joiner Entrust) URI.
	URIJoinerEntrust
	// URIJoinerFinalize is the "c/jf" (Joiner Finalize) URI.
	URIJoinerFinalize
	// URILeaderKeepAlive is the "c/la" (Leader Keep-Alive) URI.
	URILeaderKeepAlive
	// URILeaderPetition is the "c/lp" (Leader Petition) URI.
	URILeaderPetition
	// URIPanIDConflict is the "c/pc" (PAN ID Conflict) URI.
	URIPanIDConflict
	// URIPendingGet is the "c/pg" (Pending Get) URI.
	URIPendingGet
	// URIPanIDQuery is the "c/pq" (PAN ID Query) URI.
	URIPanIDQuery
	// URIPendingSet is the "c/ps" (Pending Set) URI.
	URIPendingSet
	// URIRelayRx is the "c/rx" (Relay Receive) URI.
	URIRelayRx
	// URITcatEnable is the "c/te" (TCAT Enable) URI.
	URITcatEnable
	// URIRelayTx is the "c/tx" (Relay Transmit) URI.
	URIRelayTx
	// URIProxyRx is the "c/ur" (Proxy Receive) URI.
	URIProxyRx
	// URIProxyTx is the "c/ut" (Proxy Transmit) URI.
	URIProxyTx

	// URIDiagnosticGetAnswer is the "d/da" (Diagnostic Get Answer) URI.
	URIDiagnosticGetAnswer
	// URIDiagnosticGetRequest is the "d/dg" (Diagnostic Get Request) URI.
	URIDiagnosticGetRequest
	// URIDiagnosticGetQuery is the "d/dq" (Diagnostic Get Query) URI.
	URIDiagnosticGetQuery
	// URIDiagnosticReset is the "d/dr" (Diagnostic Reset) URI.
	URIDiagnosticReset

	// URIHistoryAnswer is the "h/an" (History Answer) URI.
	URIHistoryAnswer
	// URIHistoryQuery is the "h/qy" (History Query) URI.
	URIHistoryQuery

	// URIDuaRegistrationNotify is the "n/dn" (DUA Registration Notify) URI.
	URIDuaRegistrationNotify
	// URIDuaRegistrationRequest is the "n/dr" (DUA Registration Request) URI.
	URIDuaRegistrationRequest
	// URIMlr is the "n/mr" (Multicast Listener Registration) URI.
	URIMlr

	// URIUnknown is the sentinel value for an unrecognized URI.
	URIUnknown
)

// ---------------------------------------------------------------------------
// URI ↔ path mapping
// ---------------------------------------------------------------------------

// uriPaths maps each URI constant to its CoAP path string. The index matches
// the URI enum value.
var uriPaths = [URIUnknown]string{
	URIAddressError:     "a/ae",
	URIAddressNotify:    "a/an",
	URIAddressQuery:     "a/aq",
	URIAddressRelease:   "a/ar",
	URIAddressSolicit:   "a/as",
	URIServerData:       "a/sd",
	URICommissionerData: "a/cd",
	URIAnycastLocate:    "a/yl",

	URIBackboneAnswer: "b/ba",
	URIBackboneMlr:    "b/bmr",
	URIBackboneQuery:  "b/bq",

	URIAnnounceBegin:         "c/ab",
	URIActiveGet:             "c/ag",
	URIActiveReplace:         "c/ar",
	URIActiveSet:             "c/as",
	URICommissionerKeepAlive: "c/ca",
	URICommissionerGet:       "c/cg",
	URICommissionerPetition:  "c/cp",
	URICommissionerSet:       "c/cs",
	URIDatasetChanged:        "c/dc",
	URIEnergyReport:          "c/er",
	URIEnergyScan:            "c/es",
	URIJoinerEntrust:         "c/je",
	URIJoinerFinalize:        "c/jf",
	URILeaderKeepAlive:       "c/la",
	URILeaderPetition:        "c/lp",
	URIPanIDConflict:         "c/pc",
	URIPendingGet:            "c/pg",
	URIPanIDQuery:            "c/pq",
	URIPendingSet:            "c/ps",
	URIRelayRx:               "c/rx",
	URITcatEnable:            "c/te",
	URIRelayTx:               "c/tx",
	URIProxyRx:               "c/ur",
	URIProxyTx:               "c/ut",

	URIDiagnosticGetAnswer:  "d/da",
	URIDiagnosticGetRequest: "d/dg",
	URIDiagnosticGetQuery:   "d/dq",
	URIDiagnosticReset:      "d/dr",

	URIHistoryAnswer: "h/an",
	URIHistoryQuery:  "h/qy",

	URIDuaRegistrationNotify:  "n/dn",
	URIDuaRegistrationRequest: "n/dr",
	URIMlr:                    "n/mr",
}

// pathToURI is the reverse lookup map from path string to URI enum.
var pathToURI map[string]URI

func init() {
	pathToURI = make(map[string]URI, len(uriPaths))
	for u, p := range &uriPaths {
		pathToURI[p] = URI(u)
	}
}

// PathForURI returns the CoAP path string for the given URI constant.
// It returns an empty string for URIUnknown or out-of-range values.
func PathForURI(u URI) string {
	if u >= URIUnknown {
		return ""
	}
	return uriPaths[u]
}

// URIFromPath returns the URI constant for the given CoAP path string.
// It returns URIUnknown if the path is not recognized.
func URIFromPath(path string) URI {
	if u, ok := pathToURI[path]; ok {
		return u
	}
	return URIUnknown
}
