// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package router

import (
	"github.com/hilli/gothread/border"
	"github.com/hilli/gothread/net/nd6"
)

// defaultPrefixLifetime is the default valid/preferred lifetime advertised
// for on-link prefix PIOs and OMR route RIOs (in seconds).
const defaultPrefixLifetime uint32 = 1800

// buildPrefixInfoOption constructs a PrefixInfoOption (PIO) for the given
// on-link prefix with On-Link and Auto Address Configuration (SLAAC) flags set.
func buildPrefixInfoOption(prefix [16]byte, prefixLen uint8) []byte {
	var pio nd6.PrefixInfoOption
	pio.SetPrefixLength(prefixLen)
	pio.SetOnLinkFlag()
	pio.SetAutoAddrConfigFlag()
	pio.SetValidLifetime(defaultPrefixLifetime)
	pio.SetPreferredLifetime(defaultPrefixLifetime)
	pio.SetPrefix(prefix)
	buf := pio.Marshal()
	return buf[:]
}

// buildRouteInfoOption constructs a RouteInfoOption (RIO) for the given
// OMR prefix.
func buildRouteInfoOption(omr OmrPrefix) []byte {
	var rio nd6.RouteInfoOption
	rio.SetPrefixLength(omr.PrefixLen)
	rio.SetRoutePreference(omr.Preference)
	rio.SetRouteLifetime(defaultPrefixLifetime)
	rio.SetPrefix(omr.Prefix)
	return rio.Marshal()
}

// buildRaFlagsExtOption constructs an RA Flags Extension Option (RFC 5175)
// with the stub router flag set.
func buildRaFlagsExtOption() []byte {
	var ext nd6.RaFlagsExtOption
	ext.SetFlag(border.StubRouterFlag)
	buf := ext.Marshal()
	return buf[:]
}
