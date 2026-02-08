// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package ip6

// IPv6 engine core types and standalone logic.
//
// This is a Go port of the portable parts of OpenThread's
// src/core/net/ip6.hpp and src/core/net/ip6.cpp.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// DefaultHopLimit is the default IPv6 hop limit used when not specified.
const DefaultHopLimit uint8 = 64

// MinimalMTU is the minimum IPv6 MTU per RFC 2460.
const MinimalMTU uint16 = 1280

// ---------------------------------------------------------------------------
// Priority
// ---------------------------------------------------------------------------

// Priority represents the message priority level.
type Priority uint8

const (
	// PriorityLow is the low priority level.
	PriorityLow Priority = 0
	// PriorityNormal is the normal priority level.
	PriorityNormal Priority = 1
	// PriorityHigh is the high priority level.
	PriorityHigh Priority = 2
	// PriorityNet is the network control priority level.
	PriorityNet Priority = 3
)

// ---------------------------------------------------------------------------
// DSCP ↔ Priority mapping
// ---------------------------------------------------------------------------

// dscpCsMask extracts the 3-bit Class Selector from a 6-bit DSCP value
// (bits 5:3).
const dscpCsMask Dscp = 0x38

// DscpToPriority maps a DSCP value to a message priority using the Class
// Selector bits.
//
//	CS1, CS2       → PriorityLow
//	CS0, CS3       → PriorityNormal
//	CS4, CS5, CS6, CS7 → PriorityHigh
//	anything else  → PriorityNormal
func DscpToPriority(dscp Dscp) Priority {
	cs := dscp & dscpCsMask
	switch cs {
	case DscpCs1, DscpCs2:
		return PriorityLow
	case DscpCs0, DscpCs3:
		return PriorityNormal
	case DscpCs4, DscpCs5, DscpCs6, DscpCs7:
		return PriorityHigh
	default:
		return PriorityNormal
	}
}

// PriorityToDscp maps a message priority to a canonical DSCP value.
func PriorityToDscp(p Priority) Dscp {
	switch p {
	case PriorityLow:
		return DscpCs1
	case PriorityNormal, PriorityNet:
		return DscpCs0
	case PriorityHigh:
		return DscpCs4
	default:
		return DscpCs0
	}
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

// IPProtoToString returns a human-readable name for the given IPv6 next
// header protocol number.
func IPProtoToString(proto uint8) string {
	switch proto {
	case ProtoHopOpts:
		return "HopOpts"
	case ProtoTCP:
		return "TCP"
	case ProtoUDP:
		return "UDP"
	case ProtoIPv6:
		return "IP6"
	case ProtoRouting:
		return "Routing"
	case ProtoFragment:
		return "Frag"
	case ProtoICMPv6:
		return "ICMP6"
	case ProtoNone:
		return "None"
	case ProtoDstOpts:
		return "DstOpts"
	default:
		return "Unknown"
	}
}

// EcnToString returns a short human-readable name for an ECN value.
func EcnToString(ecn Ecn) string {
	switch ecn {
	case EcnNotCapable:
		return "no"
	case EcnCapable0:
		return "e0"
	case EcnCapable1:
		return "e1"
	case EcnMarked:
		return "ce"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// SelectSourceAddress — RFC 6724 source address selection
// ---------------------------------------------------------------------------

// SelectSourceAddress selects the best source address for the given
// destination using the RFC 6724 source address selection algorithm applied
// to the unicast addresses on the provided Netif.
//
// It returns a pointer to the best matching Address, or nil if no suitable
// source address was found.
func SelectSourceAddress(netif *Netif, destination Address) *Address {
	destScope := destination.GetScope()
	destIsRloc := destination.GetIid().IsRoutingLocator()

	var bestAddr *UnicastAddress
	var bestMatchLen uint8

	addrs := netif.GetUnicastAddresses()
	for i := range addrs {
		addr := &addrs[i]

		// Skip anycast locator addresses.
		if addr.Address.GetIid().IsAnycastLocator() {
			continue
		}

		candidateMatchLen := destination.PrefixMatch(addr.Address)
		var overrideScope uint8

		if candidateMatchLen >= addr.PrefixLength {
			candidateMatchLen = addr.PrefixLength
			overrideScope = addr.GetScope()
		} else {
			overrideScope = destScope
		}

		// Rule 1: Prefer same address (exact match).
		if addr.Address == destination {
			return &addrs[i].Address
		}

		newAddrIsPreferred := false

		switch {
		case bestAddr == nil:
			newAddrIsPreferred = true
		case addr.GetScope() < bestAddr.GetScope():
			// Rule 2: Prefer appropriate scope — smaller scope wins if it
			// still covers the destination.
			newAddrIsPreferred = addr.GetScope() >= overrideScope
		case addr.GetScope() > bestAddr.GetScope():
			newAddrIsPreferred = bestAddr.GetScope() < overrideScope
		case addr.Preferred != bestAddr.Preferred:
			// Rule 3: Avoid deprecated addresses.
			newAddrIsPreferred = addr.Preferred
		case candidateMatchLen > bestMatchLen:
			// Rule 8: Use longest prefix matching.
			newAddrIsPreferred = true
		case candidateMatchLen == bestMatchLen &&
			(destIsRloc == addr.Address.GetIid().IsRoutingLocator()):
			// Additional: Prefer RLOC source for RLOC destination.
			newAddrIsPreferred = true
		}

		if newAddrIsPreferred {
			bestAddr = addr
			bestMatchLen = candidateMatchLen
			if bestMatchLen >= bestAddr.PrefixLength {
				destScope = bestAddr.GetScope()
			}
		}
	}

	if bestAddr != nil {
		return &bestAddr.Address
	}
	return nil
}
