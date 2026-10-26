// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package addrresolver implements the Thread EID-to-RLOC16 address resolution
// cache and query mechanism.
//
// This is a Go port of the address resolver defined in OpenThread's
// src/core/thread/address_resolver.hpp and
// src/core/thread/address_resolver.cpp.
package addrresolver

import (
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
)

// Cache entry states.

// EntryState represents the state of a cache entry.
type EntryState uint8

const (
	// EntryStateQuery indicates an address query is in progress.
	EntryStateQuery EntryState = iota
	// EntryStateCached indicates the entry has a resolved RLOC16.
	EntryStateCached
	// EntryStateSnooped indicates the entry was learned by snooping traffic.
	EntryStateSnooped
	// EntryStateRetryQuery indicates the entry is waiting to retry a query.
	EntryStateRetryQuery
)

// String returns a human-readable name for the entry state.
func (s EntryState) String() string {
	switch s {
	case EntryStateQuery:
		return "Query"
	case EntryStateCached:
		return "Cached"
	case EntryStateSnooped:
		return "Snooped"
	case EntryStateRetryQuery:
		return "RetryQuery"
	default:
		return "Unknown"
	}
}

// Default cache and timing constants matching OpenThread.
const (
	// DefaultCacheEntries is the default number of cache entries.
	DefaultCacheEntries = 32

	// DefaultSnoopedEntries is the default number of snooped entries.
	DefaultSnoopedEntries = 16

	// InitialRetryDelay is the initial retry delay for address queries.
	InitialRetryDelay = 8 * time.Second

	// MaxRetryDelay is the maximum retry delay (exponential backoff cap).
	MaxRetryDelay = 120 * time.Second

	// CacheEntryTimeout is how long a cached entry remains valid.
	CacheEntryTimeout = 100 * time.Second

	// SnoopedEntryTimeout is how long a snooped entry remains valid.
	SnoopedEntryTimeout = 45 * time.Second

	// MaxQueryRetryAttempts is the maximum number of retry attempts for
	// address queries before giving up.
	MaxQueryRetryAttempts = 15

	// QueryTimeout is the timeout for a single address query round.
	QueryTimeout = 3 * time.Second
)

// CacheEntry is a single entry in the address resolution cache.
type CacheEntry struct {
	// Target is the IPv6 EID being resolved.
	Target ip6.Address
	// RLOC16 is the resolved short address (valid in Cached/Snooped states).
	RLOC16 uint16
	// MeshLocalIID is the mesh-local IID of the destination (valid in Cached state).
	MeshLocalIID ip6.InterfaceIdentifier
	// State is the current entry state.
	State EntryState
	// LastTransactionTime is when the entry was last updated or confirmed.
	LastTransactionTime time.Time
	// Timeout is when this entry expires.
	Timeout time.Time
	// RetryDelay is the current retry delay for query retries.
	RetryDelay time.Duration
	// RetryAttempts counts how many query retries have been made.
	RetryAttempts uint8
	// CanEvict indicates whether this entry can be evicted when the cache
	// is full.
	CanEvict bool
}

// IsValid reports whether the entry is in a state other than the zero value
// with a non-zero target address.
func (e *CacheEntry) IsValid() bool {
	return e.Target != (ip6.Address{})
}

// IsExpired reports whether the entry has expired relative to the given time.
func (e *CacheEntry) IsExpired(now time.Time) bool {
	return !e.Timeout.IsZero() && now.After(e.Timeout)
}

// QueryCallback is called when an address query needs to be sent for a
// target EID. The implementation should send an Address Query message to
// the Thread network.
type QueryCallback func(target ip6.Address)

// NotificationCallback is called when an address resolution completes
// (either successfully or with an error).
type NotificationCallback func(target ip6.Address, rloc16 uint16, err error)

// Resolver manages the EID-to-RLOC16 address cache and query mechanism.
type Resolver struct {
	cache   []CacheEntry
	snooped []CacheEntry

	queryCallback        QueryCallback
	notificationCallback NotificationCallback
}

// NewResolver creates a new address Resolver with the default cache sizes.
func NewResolver() *Resolver {
	return &Resolver{
		cache:   make([]CacheEntry, 0, DefaultCacheEntries),
		snooped: make([]CacheEntry, 0, DefaultSnoopedEntries),
	}
}

// NewResolverWithSize creates a new address Resolver with custom cache sizes.
func NewResolverWithSize(cacheSize, snoopedSize int) *Resolver {
	return &Resolver{
		cache:   make([]CacheEntry, 0, cacheSize),
		snooped: make([]CacheEntry, 0, snoopedSize),
	}
}

// SetQueryCallback sets the callback for sending address queries.
func (r *Resolver) SetQueryCallback(cb QueryCallback) {
	r.queryCallback = cb
}

// SetNotificationCallback sets the callback for address resolution
// notifications.
func (r *Resolver) SetNotificationCallback(cb NotificationCallback) {
	r.notificationCallback = cb
}

// Resolve looks up the target EID and returns the resolved RLOC16 if
// available. If the address is not yet resolved, it initiates a query and
// returns ErrAddressQuery. If the cache is full and no entry can be evicted,
// it returns ErrNoBufs.
func (r *Resolver) Resolve(target ip6.Address, now time.Time) (uint16, error) {
	// Check the main cache first.
	entry := r.findInCache(target)
	if entry != nil {
		switch entry.State {
		case EntryStateCached:
			if !entry.IsExpired(now) {
				return entry.RLOC16, nil
			}
			// Expired cached entry: re-query.
			entry.State = EntryStateQuery
			entry.RetryAttempts = 0
			entry.RetryDelay = InitialRetryDelay
			entry.Timeout = now.Add(QueryTimeout)
			r.sendQuery(target)
			return 0, goterrors.ErrAddressQuery

		case EntryStateQuery:
			return 0, goterrors.ErrAddressQuery

		case EntryStateRetryQuery:
			if now.After(entry.Timeout) {
				// Time to retry.
				entry.State = EntryStateQuery
				entry.Timeout = now.Add(QueryTimeout)
				r.sendQuery(target)
			}
			return 0, goterrors.ErrAddressQuery
		}
	}

	// Check snooped entries.
	snooped := r.findInSnooped(target)
	if snooped != nil && !snooped.IsExpired(now) {
		// Promote snooped entry to cache.
		rloc16 := snooped.RLOC16
		promoted := CacheEntry{
			Target:              target,
			RLOC16:              rloc16,
			MeshLocalIID:        snooped.MeshLocalIID,
			State:               EntryStateCached,
			LastTransactionTime: snooped.LastTransactionTime,
			Timeout:             now.Add(CacheEntryTimeout),
			CanEvict:            true,
		}
		r.removeSnoopedEntry(target)
		if !r.addCacheEntry(&promoted) {
			return 0, goterrors.ErrNoBufs
		}
		return rloc16, nil
	}

	// No entry found — create a query entry.
	queryEntry := CacheEntry{
		Target:        target,
		State:         EntryStateQuery,
		Timeout:       now.Add(QueryTimeout),
		RetryDelay:    InitialRetryDelay,
		RetryAttempts: 0,
		CanEvict:      true,
	}
	if !r.addCacheEntry(&queryEntry) {
		return 0, goterrors.ErrNoBufs
	}
	r.sendQuery(target)
	return 0, goterrors.ErrAddressQuery
}

// HandleAddressQueryResponse processes a successful address query response.
// It updates the cache entry for the target EID with the resolved RLOC16
// and mesh-local IID.
func (r *Resolver) HandleAddressQueryResponse(target ip6.Address, rloc16 uint16, meshLocalIID ip6.InterfaceIdentifier, lastTransactionTime, now time.Time) {
	entry := r.findInCache(target)
	if entry == nil {
		// No pending query — add as a cached entry.
		cached := CacheEntry{
			Target:              target,
			RLOC16:              rloc16,
			MeshLocalIID:        meshLocalIID,
			State:               EntryStateCached,
			LastTransactionTime: lastTransactionTime,
			Timeout:             now.Add(CacheEntryTimeout),
			CanEvict:            true,
		}
		r.addCacheEntry(&cached)
		r.notifyResolution(target, rloc16, nil)
		return
	}

	entry.RLOC16 = rloc16
	entry.MeshLocalIID = meshLocalIID
	entry.State = EntryStateCached
	entry.LastTransactionTime = lastTransactionTime
	entry.Timeout = now.Add(CacheEntryTimeout)
	entry.RetryAttempts = 0

	r.notifyResolution(target, rloc16, nil)
}

// HandleAddressError processes an Address Error notification for the given
// target. It removes the cache entry and notifies listeners.
func (r *Resolver) HandleAddressError(target ip6.Address, _ types.ExtAddress) {
	removed := r.removeCacheEntry(target)
	r.removeSnoopedEntry(target)
	if removed {
		r.notifyResolution(target, 0, goterrors.ErrDrop)
	}
}

// HandleAddressNotification processes a proactive Address Notification
// that may update or create a cached entry.
func (r *Resolver) HandleAddressNotification(target ip6.Address, rloc16 uint16, meshLocalIID ip6.InterfaceIdentifier, lastTransactionTime, now time.Time) {
	entry := r.findInCache(target)
	if entry != nil {
		// Update existing entry if notification is newer.
		if lastTransactionTime.After(entry.LastTransactionTime) || entry.State != EntryStateCached {
			entry.RLOC16 = rloc16
			entry.MeshLocalIID = meshLocalIID
			entry.State = EntryStateCached
			entry.LastTransactionTime = lastTransactionTime
			entry.Timeout = now.Add(CacheEntryTimeout)
			entry.RetryAttempts = 0
		}
		return
	}

	// Check snooped table.
	snooped := r.findInSnooped(target)
	if snooped != nil {
		snooped.RLOC16 = rloc16
		snooped.MeshLocalIID = meshLocalIID
		snooped.LastTransactionTime = lastTransactionTime
		snooped.Timeout = now.Add(SnoopedEntryTimeout)
		return
	}

	// Add as new cached entry.
	cached := CacheEntry{
		Target:              target,
		RLOC16:              rloc16,
		MeshLocalIID:        meshLocalIID,
		State:               EntryStateCached,
		LastTransactionTime: lastTransactionTime,
		Timeout:             now.Add(CacheEntryTimeout),
		CanEvict:            true,
	}
	r.addCacheEntry(&cached)
}

// UpdateSnoopedEntry adds or updates a snooped entry learned from
// observing traffic.
func (r *Resolver) UpdateSnoopedEntry(target ip6.Address, rloc16 uint16, now time.Time) {
	// Don't snoop if we already have a cache entry.
	if r.findInCache(target) != nil {
		return
	}

	snooped := r.findInSnooped(target)
	if snooped != nil {
		snooped.RLOC16 = rloc16
		snooped.LastTransactionTime = now
		snooped.Timeout = now.Add(SnoopedEntryTimeout)
		return
	}

	entry := CacheEntry{
		Target:              target,
		RLOC16:              rloc16,
		State:               EntryStateSnooped,
		LastTransactionTime: now,
		Timeout:             now.Add(SnoopedEntryTimeout),
		CanEvict:            true,
	}
	r.addSnoopedEntry(&entry)
}

// LookUp returns the cache entry for the given target, or nil if not found.
// It searches both the cache and snooped lists.
func (r *Resolver) LookUp(target ip6.Address) *CacheEntry {
	entry := r.findInCache(target)
	if entry != nil {
		return entry
	}
	return r.findInSnooped(target)
}

// HandleTimer processes timer ticks for the address resolver. It should be
// called periodically (e.g., every second). It handles:
//   - Expiring stale cached and snooped entries
//   - Retrying address queries with exponential backoff
//   - Giving up on queries that exceed MaxQueryRetryAttempts
func (r *Resolver) HandleTimer(now time.Time) {
	// Process cache entries.
	i := 0
	for i < len(r.cache) {
		entry := &r.cache[i]
		switch entry.State {
		case EntryStateCached:
			if entry.IsExpired(now) {
				r.cache = append(r.cache[:i], r.cache[i+1:]...)
				continue
			}

		case EntryStateQuery:
			if entry.IsExpired(now) {
				// Query timed out — schedule retry or give up.
				if entry.RetryAttempts >= MaxQueryRetryAttempts {
					target := entry.Target
					r.cache = append(r.cache[:i], r.cache[i+1:]...)
					r.notifyResolution(target, 0, goterrors.ErrDrop)
					continue
				}
				entry.State = EntryStateRetryQuery
				entry.Timeout = now.Add(entry.RetryDelay)
				entry.RetryAttempts++
				// Exponential backoff.
				entry.RetryDelay *= 2
				if entry.RetryDelay > MaxRetryDelay {
					entry.RetryDelay = MaxRetryDelay
				}
			}

		case EntryStateRetryQuery:
			if now.After(entry.Timeout) {
				// Time to retry.
				entry.State = EntryStateQuery
				entry.Timeout = now.Add(QueryTimeout)
				r.sendQuery(entry.Target)
			}

		case EntryStateSnooped:
			// Snooped entries in the main cache shouldn't happen,
			// but handle gracefully.
			if entry.IsExpired(now) {
				r.cache = append(r.cache[:i], r.cache[i+1:]...)
				continue
			}
		}
		i++
	}

	// Process snooped entries.
	j := 0
	for j < len(r.snooped) {
		if r.snooped[j].IsExpired(now) {
			r.snooped = append(r.snooped[:j], r.snooped[j+1:]...)
			continue
		}
		j++
	}
}

// Remove removes any cache or snooped entry for the given target.
func (r *Resolver) Remove(target ip6.Address) {
	r.removeCacheEntry(target)
	r.removeSnoopedEntry(target)
}

// Clear removes all cache and snooped entries.
func (r *Resolver) Clear() {
	r.cache = r.cache[:0]
	r.snooped = r.snooped[:0]
}

// GetCacheEntryCount returns the number of entries in the main cache.
func (r *Resolver) GetCacheEntryCount() int {
	return len(r.cache)
}

// GetSnoopedEntryCount returns the number of entries in the snooped list.
func (r *Resolver) GetSnoopedEntryCount() int {
	return len(r.snooped)
}

// --- Internal helpers ---

func (r *Resolver) findInCache(target ip6.Address) *CacheEntry {
	for i := range r.cache {
		if r.cache[i].Target == target {
			return &r.cache[i]
		}
	}
	return nil
}

func (r *Resolver) findInSnooped(target ip6.Address) *CacheEntry {
	for i := range r.snooped {
		if r.snooped[i].Target == target {
			return &r.snooped[i]
		}
	}
	return nil
}

func (r *Resolver) addCacheEntry(entry *CacheEntry) bool {
	if len(r.cache) < cap(r.cache) {
		r.cache = append(r.cache, *entry)
		return true
	}
	// Try to evict an expired or evictable entry.
	for i := range r.cache {
		if r.cache[i].CanEvict {
			r.cache[i] = *entry
			return true
		}
	}
	return false
}

func (r *Resolver) addSnoopedEntry(entry *CacheEntry) {
	if len(r.snooped) < cap(r.snooped) {
		r.snooped = append(r.snooped, *entry)
		return
	}
	// Evict oldest entry.
	if len(r.snooped) > 0 {
		oldest := 0
		for i := 1; i < len(r.snooped); i++ {
			if r.snooped[i].LastTransactionTime.Before(r.snooped[oldest].LastTransactionTime) {
				oldest = i
			}
		}
		r.snooped[oldest] = *entry
	}
}

func (r *Resolver) removeCacheEntry(target ip6.Address) bool {
	for i := range r.cache {
		if r.cache[i].Target == target {
			r.cache = append(r.cache[:i], r.cache[i+1:]...)
			return true
		}
	}
	return false
}

func (r *Resolver) removeSnoopedEntry(target ip6.Address) {
	for i := range r.snooped {
		if r.snooped[i].Target == target {
			r.snooped = append(r.snooped[:i], r.snooped[i+1:]...)
			return
		}
	}
}

func (r *Resolver) sendQuery(target ip6.Address) {
	if r.queryCallback != nil {
		r.queryCallback(target)
	}
}

func (r *Resolver) notifyResolution(target ip6.Address, rloc16 uint16, err error) {
	if r.notificationCallback != nil {
		r.notificationCallback(target, rloc16, err)
	}
}
