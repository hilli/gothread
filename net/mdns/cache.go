// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the
//    names of its contributors may be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package mdns

import (
	"strings"
	"sync"
	"time"
)

// CacheEntry stores a single cached DNS resource record with its
// receive timestamp for TTL-based expiry calculations.
type CacheEntry struct {
	Name        string
	Type        uint16
	Class       uint16
	TTL         uint32
	RData       []byte
	ReceiveTime time.Time
}

// IsExpired reports whether the cache entry has expired as of the given time.
func (e *CacheEntry) IsExpired(now time.Time) bool {
	if e.TTL == 0 {
		return true
	}
	return now.Sub(e.ReceiveTime) >= time.Duration(e.TTL)*time.Second
}

// RemainingTTL returns the remaining TTL in seconds. Returns 0 if expired.
func (e *CacheEntry) RemainingTTL(now time.Time) uint32 {
	elapsed := now.Sub(e.ReceiveTime)
	total := time.Duration(e.TTL) * time.Second
	if elapsed >= total {
		return 0
	}
	return uint32((total - elapsed).Seconds())
}

// Cache is a thread-safe store for received mDNS resource records.
// Records are keyed by (lowercased name, type) and expire based on TTL.
type Cache struct {
	mu      sync.RWMutex
	entries []CacheEntry
}

// NewCache creates a new empty cache.
func NewCache() *Cache {
	return &Cache{}
}

// Add inserts or updates a cache entry. If a record with the same
// name and type already exists, it is replaced. A record with TTL=0
// removes the matching entry (goodbye semantics per RFC 6762).
func (c *Cache) Add(entry CacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	nameLower := strings.ToLower(entry.Name)

	// Find existing entry with same name+type+rdata to update.
	for i := range c.entries {
		if strings.ToLower(c.entries[i].Name) == nameLower &&
			c.entries[i].Type == entry.Type &&
			rdataEqual(c.entries[i].RData, entry.RData) {
			if entry.TTL == 0 {
				// Goodbye: remove entry.
				c.entries = append(c.entries[:i], c.entries[i+1:]...)
			} else {
				c.entries[i] = entry
			}
			return
		}
	}

	// TTL=0 for a record that doesn't exist: nothing to do.
	if entry.TTL == 0 {
		return
	}

	c.entries = append(c.entries, entry)
}

// Lookup returns all non-expired cache entries matching the given name
// and record type. If rtype is TypeANY (255), all types are returned.
func (c *Cache) Lookup(name string, rtype uint16, now time.Time) []CacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	nameLower := strings.ToLower(name)
	var results []CacheEntry
	for _, e := range c.entries {
		if strings.ToLower(e.Name) == nameLower &&
			(rtype == TypeANY || e.Type == rtype) &&
			!e.IsExpired(now) {
			results = append(results, e)
		}
	}
	return results
}

// LookupAll returns all non-expired cache entries for the given name.
func (c *Cache) LookupAll(name string, now time.Time) []CacheEntry {
	return c.Lookup(name, TypeANY, now)
}

// Expire removes all entries whose TTL has elapsed as of the given time.
// Returns the number of entries removed.
func (c *Cache) Expire(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	removed := 0
	n := 0
	for _, e := range c.entries {
		if !e.IsExpired(now) {
			c.entries[n] = e
			n++
		} else {
			removed++
		}
	}
	c.entries = c.entries[:n]
	return removed
}

// Len returns the total number of entries in the cache.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Clear removes all entries from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = c.entries[:0]
}

// HasEntry checks whether the cache contains a non-expired entry with
// the given name, type, and matching rdata. Used for known-answer
// suppression per RFC 6762 Section 7.1.
func (c *Cache) HasEntry(name string, rtype uint16, rdata []byte, now time.Time) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	nameLower := strings.ToLower(name)
	for _, e := range c.entries {
		if strings.ToLower(e.Name) == nameLower &&
			e.Type == rtype &&
			rdataEqual(e.RData, rdata) &&
			!e.IsExpired(now) {
			return true
		}
	}
	return false
}

// rdataEqual compares two rdata byte slices for equality.
func rdataEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
