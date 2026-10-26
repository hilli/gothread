// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package backbone

// Leader tracks the network-wide Primary Backbone Router from Thread Network Data.
//
// This is a Go port of the Leader from
// OpenThread's src/core/backbone_router/bbr_leader.{hpp,cpp}.

import (
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// LeaderState
// ---------------------------------------------------------------------------

// LeaderState represents the state transition of the primary BBR.
type LeaderState uint8

const (
	// LeaderStateNone indicates no Primary BBR exists.
	LeaderStateNone LeaderState = 0
	// LeaderStateAdded indicates the Primary BBR was newly added.
	LeaderStateAdded LeaderState = 1
	// LeaderStateRemoved indicates the Primary BBR was removed.
	LeaderStateRemoved LeaderState = 2
	// LeaderStateToTriggerRereg indicates RLOC16 or sequence number changed,
	// triggering re-registration.
	LeaderStateToTriggerRereg LeaderState = 3
	// LeaderStateRefreshed indicates only ReregistrationDelay or MlrTimeout changed.
	LeaderStateRefreshed LeaderState = 4
	// LeaderStateUnchanged indicates no change to the Primary BBR information.
	LeaderStateUnchanged LeaderState = 5
)

// ---------------------------------------------------------------------------
// LeaderCallbacks
// ---------------------------------------------------------------------------

// LeaderCallbacks is called when the BBR primary or domain prefix changes.
type LeaderCallbacks interface {
	OnPrimaryUpdated(state LeaderState, config Config)
	OnDomainPrefixUpdated(event DomainPrefixEvent, prefix ip6.Prefix)
}

// ---------------------------------------------------------------------------
// Leader
// ---------------------------------------------------------------------------

// Leader tracks the network-wide Primary Backbone Router from Thread Network Data.
type Leader struct {
	config          Config
	domainPrefix    ip6.Prefix
	hasDomainPrefix bool
	serviceID       uint8
	callbacks       LeaderCallbacks
}

// NewLeader creates a new Leader. The provided callbacks may be nil.
func NewLeader(callbacks LeaderCallbacks) *Leader {
	l := &Leader{
		callbacks: callbacks,
	}
	l.Reset()
	return l
}

// Reset clears the cached Primary BBR config and domain prefix.
func (l *Leader) Reset() {
	l.config = Config{Server16: InvalidServer16}
	l.domainPrefix = ip6.Prefix{}
	l.hasDomainPrefix = false
	l.serviceID = 0
}

// GetConfig returns the current Primary BBR configuration.
func (l *Leader) GetConfig() Config {
	return l.config
}

// HasPrimary reports whether a Primary BBR exists.
func (l *Leader) HasPrimary() bool {
	return l.config.Server16 != InvalidServer16
}

// GetServer16 returns the short address of the Primary BBR,
// or InvalidServer16 if none.
func (l *Leader) GetServer16() uint16 {
	return l.config.Server16
}

// GetServiceID returns the BBR service ID.
func (l *Leader) GetServiceID() uint8 {
	return l.serviceID
}

// SetServiceID sets the BBR service ID.
func (l *Leader) SetServiceID(id uint8) {
	l.serviceID = id
}

// GetDomainPrefix returns the current domain prefix.
func (l *Leader) GetDomainPrefix() ip6.Prefix {
	return l.domainPrefix
}

// HasDomainPrefix reports whether a domain prefix is configured.
func (l *Leader) HasDomainPrefix() bool {
	return l.hasDomainPrefix
}

// IsDomainUnicast checks whether addr matches the domain prefix and is a
// unicast address (not multicast).
func (l *Leader) IsDomainUnicast(addr [16]byte) bool {
	if !l.hasDomainPrefix {
		return false
	}
	a := ip6.Address(addr)
	return !a.IsMulticast() && a.MatchesPrefix(l.domainPrefix)
}

// UpdatePrimary compares a new config (or nil for removal) against the cached
// config and determines the appropriate LeaderState. The new config is stored
// and the OnPrimaryUpdated callback is invoked.
func (l *Leader) UpdatePrimary(newConfig *Config) {
	var state LeaderState
	var incoming Config

	if newConfig == nil {
		incoming = Config{Server16: InvalidServer16}
	} else {
		incoming = *newConfig
	}

	switch {
	case incoming.Server16 != l.config.Server16:
		switch {
		case incoming.Server16 == InvalidServer16:
			state = LeaderStateRemoved
		case l.config.Server16 == InvalidServer16:
			state = LeaderStateAdded
		default:
			// Server16 changed between two valid values.
			state = LeaderStateToTriggerRereg
		}
	case incoming.Server16 == InvalidServer16:
		// No primary all along.
		state = LeaderStateNone
	case incoming.SequenceNumber != l.config.SequenceNumber:
		state = LeaderStateToTriggerRereg
	case incoming.ReregistrationDelay != l.config.ReregistrationDelay ||
		incoming.MlrTimeout != l.config.MlrTimeout:
		state = LeaderStateRefreshed
	default:
		state = LeaderStateUnchanged
	}

	// Clamp MlrTimeout to valid range when a primary exists.
	if incoming.Server16 != InvalidServer16 {
		if incoming.MlrTimeout < MinMlrTimeout {
			incoming.MlrTimeout = MinMlrTimeout
		}
		if incoming.MlrTimeout > MaxMlrTimeout {
			incoming.MlrTimeout = MaxMlrTimeout
		}
	}

	l.config = incoming

	if l.callbacks != nil {
		l.callbacks.OnPrimaryUpdated(state, l.config)
	}
}

// UpdateDomainPrefix compares a new domain prefix (or nil for removal) against
// the cached prefix and determines the DomainPrefixEvent. The new prefix is
// stored and the OnDomainPrefixUpdated callback is invoked.
func (l *Leader) UpdateDomainPrefix(prefix *ip6.Prefix) {
	var event DomainPrefixEvent

	switch {
	case prefix == nil:
		if !l.hasDomainPrefix {
			// No prefix before, no prefix now — nothing to do.
			return
		}
		l.domainPrefix = ip6.Prefix{}
		l.hasDomainPrefix = false
		event = DomainPrefixRemoved
	case l.hasDomainPrefix && l.domainPrefix.IsEqual(*prefix):
		event = DomainPrefixUnchanged
	default:
		if l.hasDomainPrefix {
			event = DomainPrefixRefreshed
		} else {
			event = DomainPrefixAdded
		}
		l.domainPrefix = *prefix
		l.hasDomainPrefix = true
	}

	if l.callbacks != nil {
		l.callbacks.OnDomainPrefixUpdated(event, l.domainPrefix)
	}
}
