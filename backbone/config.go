// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package backbone

// Config represents the BBR service parameters advertised in Thread Network Data.
//
// This is a Go port of the Config type and related constants from
// OpenThread's src/core/backbone_router/bbr_leader.hpp.
type Config struct {
	Server16            uint16 // RLOC16 of Primary BBR (0xFFFE = none)
	ReregistrationDelay uint16 // seconds
	MlrTimeout          uint32 // seconds
	SequenceNumber      uint8
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	// InvalidServer16 indicates that no Primary Backbone Router is present.
	InvalidServer16 uint16 = 0xFFFE

	// DefaultRegistrationDelay is the default re-registration delay in seconds.
	DefaultRegistrationDelay uint16 = 5

	// DefaultMlrTimeout is the default Multicast Listener Registration timeout in seconds.
	DefaultMlrTimeout uint32 = 3600

	// MinMlrTimeout is the minimum allowable MLR timeout in seconds.
	MinMlrTimeout uint32 = 300

	// MaxMlrTimeout is the maximum allowable MLR timeout in seconds (~24 days).
	// Matches OpenThread's 0x7fffffff / 1000.
	MaxMlrTimeout uint32 = 2147483

	// DefaultRegistrationJitter is the default registration jitter in seconds.
	DefaultRegistrationJitter uint8 = 5

	// ParentAggregateDelay is the parent aggregate delay in seconds.
	ParentAggregateDelay uint8 = 5

	// BackboneUDPPort is the UDP port used by the Backbone Router protocol.
	BackboneUDPPort uint16 = 61631
)

// HasPrimary reports whether the Config has a valid Primary Backbone Router.
func (c *Config) HasPrimary() bool {
	return c.Server16 != InvalidServer16
}

// ---------------------------------------------------------------------------
// DomainPrefixEvent
// ---------------------------------------------------------------------------

// DomainPrefixEvent indicates what happened to the domain prefix.
type DomainPrefixEvent uint8

const (
	// DomainPrefixAdded indicates a domain prefix was added.
	DomainPrefixAdded DomainPrefixEvent = 0
	// DomainPrefixRemoved indicates a domain prefix was removed.
	DomainPrefixRemoved DomainPrefixEvent = 1
	// DomainPrefixRefreshed indicates a domain prefix was refreshed (changed).
	DomainPrefixRefreshed DomainPrefixEvent = 2
	// DomainPrefixUnchanged indicates the domain prefix did not change.
	DomainPrefixUnchanged DomainPrefixEvent = 3
)
