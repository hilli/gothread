// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package router

import (
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/nd6"
)

// ---------------------------------------------------------------------------
// RouteEntry — a single external route to publish in Thread Network Data
// ---------------------------------------------------------------------------

// RouteEntry represents an external route to be published into the Thread
// Network Data.
type RouteEntry struct {
	Prefix     [16]byte
	PrefixLen  uint8
	Preference nd6.RoutePreference
	Stable     bool
	NAT64      bool
}

// ---------------------------------------------------------------------------
// RoutePublisher options
// ---------------------------------------------------------------------------

const defaultMaxRoutes = 16

// RoutePublisherOption configures the RoutePublisher.
type RoutePublisherOption func(*RoutePublisher)

// WithMaxEntries sets the maximum number of routes the publisher will hold.
func WithMaxEntries(n int) RoutePublisherOption {
	return func(p *RoutePublisher) {
		if n > 0 {
			p.maxEntries = n
		}
	}
}

// ---------------------------------------------------------------------------
// RoutePublisher — publishes external routes into Thread Network Data
// ---------------------------------------------------------------------------

// RoutePublisher manages a set of external routes to be published into the
// Thread Network Data. It maintains an ordered list of route entries and
// enforces a maximum capacity.
type RoutePublisher struct {
	entries    []RouteEntry
	maxEntries int
}

// NewRoutePublisher creates a new RoutePublisher with the given options.
func NewRoutePublisher(opts ...RoutePublisherOption) *RoutePublisher {
	p := &RoutePublisher{
		maxEntries: defaultMaxRoutes,
	}
	for _, o := range opts {
		o(p)
	}
	p.entries = make([]RouteEntry, 0, p.maxEntries)
	return p
}

// AddRoute adds or updates an external route entry. If a route with the same
// prefix and prefix length already exists, its preference is updated. Returns
// ErrNoBufs if the table is full.
func (p *RoutePublisher) AddRoute(prefix [16]byte, prefixLen uint8, preference nd6.RoutePreference) error {
	// Check for existing entry with the same prefix.
	for i := range p.entries {
		if p.entries[i].PrefixLen == prefixLen && matchBits(p.entries[i].Prefix[:], prefix[:], prefixLen) {
			p.entries[i].Preference = preference
			return nil
		}
	}

	if len(p.entries) >= p.maxEntries {
		return errors.ErrNoBufs
	}

	p.entries = append(p.entries, RouteEntry{
		Prefix:     prefix,
		PrefixLen:  prefixLen,
		Preference: preference,
		Stable:     true,
	})
	return nil
}

// RemoveRoute removes the route matching the given prefix and prefix length.
// Returns true if a route was removed.
func (p *RoutePublisher) RemoveRoute(prefix [16]byte, prefixLen uint8) bool {
	for i := range p.entries {
		if p.entries[i].PrefixLen == prefixLen && matchBits(p.entries[i].Prefix[:], prefix[:], prefixLen) {
			p.entries = append(p.entries[:i], p.entries[i+1:]...)
			return true
		}
	}
	return false
}

// HasRoute returns true if a route matching the given prefix and length exists.
func (p *RoutePublisher) HasRoute(prefix [16]byte, prefixLen uint8) bool {
	for i := range p.entries {
		if p.entries[i].PrefixLen == prefixLen && matchBits(p.entries[i].Prefix[:], prefix[:], prefixLen) {
			return true
		}
	}
	return false
}

// GetRoutes returns a copy of all current route entries.
func (p *RoutePublisher) GetRoutes() []RouteEntry {
	result := make([]RouteEntry, len(p.entries))
	copy(result, p.entries)
	return result
}

// ClearRoutes removes all route entries.
func (p *RoutePublisher) ClearRoutes() {
	p.entries = p.entries[:0]
}

// Count returns the number of route entries.
func (p *RoutePublisher) Count() int {
	return len(p.entries)
}
