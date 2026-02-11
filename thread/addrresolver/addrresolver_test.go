// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package addrresolver

import (
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
)

var (
	testTarget1 = ip6.Address{0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	testTarget2 = ip6.Address{0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	testTarget3 = ip6.Address{0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}
	testIID = ip6.InterfaceIdentifier{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
)

func TestNewResolver(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	if r == nil {
		t.Fatal("NewResolver returned nil")
	}
	if r.GetCacheEntryCount() != 0 {
		t.Errorf("cache count = %d, want 0", r.GetCacheEntryCount())
	}
	if r.GetSnoopedEntryCount() != 0 {
		t.Errorf("snooped count = %d, want 0", r.GetSnoopedEntryCount())
	}
}

func TestNewResolverWithSize(t *testing.T) {
	t.Parallel()
	r := NewResolverWithSize(8, 4)
	if r == nil {
		t.Fatal("NewResolverWithSize returned nil")
	}
	if cap(r.cache) != 8 {
		t.Errorf("cache cap = %d, want 8", cap(r.cache))
	}
	if cap(r.snooped) != 4 {
		t.Errorf("snooped cap = %d, want 4", cap(r.snooped))
	}
}

func TestResolver_Resolve_InitiatesQuery(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	var queries []ip6.Address
	r.SetQueryCallback(func(target ip6.Address) {
		queries = append(queries, target)
	})

	rloc, err := r.Resolve(testTarget1, now)
	if err != goterrors.ErrAddressQuery {
		t.Errorf("err = %v, want ErrAddressQuery", err)
	}
	if rloc != 0 {
		t.Errorf("rloc = 0x%04X, want 0", rloc)
	}
	if len(queries) != 1 || queries[0] != testTarget1 {
		t.Errorf("queries = %v, want [%v]", queries, testTarget1)
	}
	if r.GetCacheEntryCount() != 1 {
		t.Errorf("cache count = %d, want 1", r.GetCacheEntryCount())
	}
}

func TestResolver_Resolve_ReturnsExistingQueryEntry(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	queryCount := 0
	r.SetQueryCallback(func(_ ip6.Address) {
		queryCount++
	})

	// First resolve creates a query.
	r.Resolve(testTarget1, now)
	// Second resolve for same target should not create a new query.
	_, err := r.Resolve(testTarget1, now)
	if err != goterrors.ErrAddressQuery {
		t.Errorf("err = %v, want ErrAddressQuery", err)
	}
	if queryCount != 1 {
		t.Errorf("queryCount = %d, want 1", queryCount)
	}
}

func TestResolver_HandleAddressQueryResponse(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	r.SetQueryCallback(func(_ ip6.Address) {})

	var notifications []ip6.Address
	r.SetNotificationCallback(func(target ip6.Address, _ uint16, _ error) {
		notifications = append(notifications, target)
	})

	// Initiate query.
	r.Resolve(testTarget1, now)

	// Handle response.
	r.HandleAddressQueryResponse(testTarget1, 0x0400, testIID, now, now)

	// Now resolve should return the cached RLOC16.
	rloc, err := r.Resolve(testTarget1, now)
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if rloc != 0x0400 {
		t.Errorf("rloc = 0x%04X, want 0x0400", rloc)
	}
	if len(notifications) != 1 || notifications[0] != testTarget1 {
		t.Errorf("notifications = %v, want [%v]", notifications, testTarget1)
	}
}

func TestResolver_HandleAddressQueryResponse_NoPendingQuery(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	// Response without a pending query should still create an entry.
	r.HandleAddressQueryResponse(testTarget1, 0x0400, testIID, now, now)

	entry := r.LookUp(testTarget1)
	if entry == nil {
		t.Fatal("LookUp returned nil")
	}
	if entry.State != EntryStateCached {
		t.Errorf("state = %v, want Cached", entry.State)
	}
	if entry.RLOC16 != 0x0400 {
		t.Errorf("RLOC16 = 0x%04X, want 0x0400", entry.RLOC16)
	}
}

func TestResolver_HandleAddressError(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	r.SetQueryCallback(func(_ ip6.Address) {})

	var notifyErr error
	r.SetNotificationCallback(func(_ ip6.Address, _ uint16, err error) {
		notifyErr = err
	})

	r.Resolve(testTarget1, now)
	r.HandleAddressError(testTarget1, types.ExtAddress{})

	if r.GetCacheEntryCount() != 0 {
		t.Errorf("cache count = %d, want 0", r.GetCacheEntryCount())
	}
	if notifyErr != goterrors.ErrDrop {
		t.Errorf("notifyErr = %v, want ErrDrop", notifyErr)
	}
}

func TestResolver_HandleAddressError_NoEntry(t *testing.T) {
	t.Parallel()
	r := NewResolver()

	notifyCalled := false
	r.SetNotificationCallback(func(_ ip6.Address, _ uint16, _ error) {
		notifyCalled = true
	})

	// Should be a no-op.
	r.HandleAddressError(testTarget1, types.ExtAddress{})
	if notifyCalled {
		t.Error("notification should not be called for non-existent entry")
	}
}

func TestResolver_UpdateSnoopedEntry(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	r.UpdateSnoopedEntry(testTarget1, 0x0800, now)

	if r.GetSnoopedEntryCount() != 1 {
		t.Errorf("snooped count = %d, want 1", r.GetSnoopedEntryCount())
	}

	entry := r.LookUp(testTarget1)
	if entry == nil {
		t.Fatal("LookUp returned nil")
	}
	if entry.State != EntryStateSnooped {
		t.Errorf("state = %v, want Snooped", entry.State)
	}
	if entry.RLOC16 != 0x0800 {
		t.Errorf("RLOC16 = 0x%04X, want 0x0800", entry.RLOC16)
	}
}

func TestResolver_UpdateSnoopedEntry_UpdatesExisting(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	r.UpdateSnoopedEntry(testTarget1, 0x0800, now)
	later := now.Add(time.Second)
	r.UpdateSnoopedEntry(testTarget1, 0x0C00, later)

	if r.GetSnoopedEntryCount() != 1 {
		t.Errorf("snooped count = %d, want 1", r.GetSnoopedEntryCount())
	}

	entry := r.LookUp(testTarget1)
	if entry.RLOC16 != 0x0C00 {
		t.Errorf("RLOC16 = 0x%04X, want 0x0C00", entry.RLOC16)
	}
}

func TestResolver_UpdateSnoopedEntry_SkipsIfCached(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	// Add a cached entry.
	r.HandleAddressQueryResponse(testTarget1, 0x0400, testIID, now, now)

	// Snooped update should be ignored.
	r.UpdateSnoopedEntry(testTarget1, 0x0800, now)

	if r.GetSnoopedEntryCount() != 0 {
		t.Errorf("snooped count = %d, want 0", r.GetSnoopedEntryCount())
	}
}

func TestResolver_Resolve_PromotesSnoopedEntry(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	// Add a snooped entry.
	r.UpdateSnoopedEntry(testTarget1, 0x0800, now)

	// Resolve should promote to cached.
	rloc, err := r.Resolve(testTarget1, now)
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if rloc != 0x0800 {
		t.Errorf("rloc = 0x%04X, want 0x0800", rloc)
	}
	if r.GetSnoopedEntryCount() != 0 {
		t.Errorf("snooped count = %d, want 0 after promotion", r.GetSnoopedEntryCount())
	}
	if r.GetCacheEntryCount() != 1 {
		t.Errorf("cache count = %d, want 1 after promotion", r.GetCacheEntryCount())
	}
}

func TestResolver_HandleAddressNotification_UpdatesExisting(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	// Add a cached entry.
	r.HandleAddressQueryResponse(testTarget1, 0x0400, testIID, now, now)

	// Notification with newer timestamp should update.
	later := now.Add(time.Second)
	newIID := ip6.InterfaceIdentifier{0xAA}
	r.HandleAddressNotification(testTarget1, 0x0800, newIID, later, later)

	entry := r.LookUp(testTarget1)
	if entry.RLOC16 != 0x0800 {
		t.Errorf("RLOC16 = 0x%04X, want 0x0800", entry.RLOC16)
	}
	if entry.MeshLocalIID != newIID {
		t.Error("MeshLocalIID not updated")
	}
}

func TestResolver_HandleAddressNotification_NewEntry(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	r.HandleAddressNotification(testTarget1, 0x0400, testIID, now, now)

	entry := r.LookUp(testTarget1)
	if entry == nil {
		t.Fatal("LookUp returned nil")
	}
	if entry.State != EntryStateCached {
		t.Errorf("state = %v, want Cached", entry.State)
	}
}

func TestResolver_HandleAddressNotification_UpdatesSnooped(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	r.UpdateSnoopedEntry(testTarget1, 0x0400, now)
	later := now.Add(time.Second)
	r.HandleAddressNotification(testTarget1, 0x0800, testIID, later, later)

	snooped := r.findInSnooped(testTarget1)
	if snooped == nil {
		t.Fatal("snooped entry removed unexpectedly")
	}
	if snooped.RLOC16 != 0x0800 {
		t.Errorf("RLOC16 = 0x%04X, want 0x0800", snooped.RLOC16)
	}
}

func TestResolver_LookUp(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	if r.LookUp(testTarget1) != nil {
		t.Error("expected nil for empty resolver")
	}

	r.HandleAddressQueryResponse(testTarget1, 0x0400, testIID, now, now)
	entry := r.LookUp(testTarget1)
	if entry == nil {
		t.Fatal("LookUp returned nil for cached entry")
	}
	if entry.RLOC16 != 0x0400 {
		t.Errorf("RLOC16 = 0x%04X, want 0x0400", entry.RLOC16)
	}
}

func TestResolver_LookUp_Snooped(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	r.UpdateSnoopedEntry(testTarget1, 0x0800, now)

	entry := r.LookUp(testTarget1)
	if entry == nil {
		t.Fatal("LookUp returned nil for snooped entry")
	}
	if entry.State != EntryStateSnooped {
		t.Errorf("state = %v, want Snooped", entry.State)
	}
}

func TestResolver_Remove(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	r.HandleAddressQueryResponse(testTarget1, 0x0400, testIID, now, now)
	r.UpdateSnoopedEntry(testTarget2, 0x0800, now)

	r.Remove(testTarget1)
	if r.LookUp(testTarget1) != nil {
		t.Error("cache entry should be removed")
	}

	r.Remove(testTarget2)
	if r.LookUp(testTarget2) != nil {
		t.Error("snooped entry should be removed")
	}
}

func TestResolver_Clear(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	r.HandleAddressQueryResponse(testTarget1, 0x0400, testIID, now, now)
	r.UpdateSnoopedEntry(testTarget2, 0x0800, now)

	r.Clear()

	if r.GetCacheEntryCount() != 0 {
		t.Errorf("cache count = %d, want 0", r.GetCacheEntryCount())
	}
	if r.GetSnoopedEntryCount() != 0 {
		t.Errorf("snooped count = %d, want 0", r.GetSnoopedEntryCount())
	}
}

func TestResolver_HandleTimer_ExpiresCachedEntries(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	r.HandleAddressQueryResponse(testTarget1, 0x0400, testIID, now, now)

	// Advance past timeout.
	later := now.Add(CacheEntryTimeout + time.Second)
	r.HandleTimer(later)

	if r.GetCacheEntryCount() != 0 {
		t.Errorf("cache count = %d, want 0 after expiry", r.GetCacheEntryCount())
	}
}

func TestResolver_HandleTimer_ExpiresSnoopedEntries(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	r.UpdateSnoopedEntry(testTarget1, 0x0800, now)

	later := now.Add(SnoopedEntryTimeout + time.Second)
	r.HandleTimer(later)

	if r.GetSnoopedEntryCount() != 0 {
		t.Errorf("snooped count = %d, want 0 after expiry", r.GetSnoopedEntryCount())
	}
}

func TestResolver_HandleTimer_QueryRetry(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	queryCount := 0
	r.SetQueryCallback(func(_ ip6.Address) {
		queryCount++
	})

	// Initiate query.
	r.Resolve(testTarget1, now)
	if queryCount != 1 {
		t.Fatalf("queryCount = %d, want 1", queryCount)
	}

	// Advance past query timeout — should move to RetryQuery.
	t1 := now.Add(QueryTimeout + time.Second)
	r.HandleTimer(t1)

	entry := r.LookUp(testTarget1)
	if entry == nil {
		t.Fatal("entry removed unexpectedly")
	}
	if entry.State != EntryStateRetryQuery {
		t.Errorf("state = %v, want RetryQuery", entry.State)
	}

	// Advance past retry delay — should re-query.
	t2 := t1.Add(InitialRetryDelay + time.Second)
	r.HandleTimer(t2)

	if queryCount != 2 {
		t.Errorf("queryCount = %d, want 2", queryCount)
	}

	entry = r.LookUp(testTarget1)
	if entry.State != EntryStateQuery {
		t.Errorf("state = %v, want Query after retry", entry.State)
	}
}

func TestResolver_HandleTimer_QueryGivesUp(t *testing.T) {
	t.Parallel()
	r := NewResolverWithSize(4, 4)
	now := time.Now()

	r.SetQueryCallback(func(_ ip6.Address) {})

	var dropTarget ip6.Address
	r.SetNotificationCallback(func(target ip6.Address, _ uint16, err error) {
		if err == goterrors.ErrDrop {
			dropTarget = target
		}
	})

	r.Resolve(testTarget1, now)

	// Simulate exceeding max retries.
	entry := r.findInCache(testTarget1)
	entry.RetryAttempts = MaxQueryRetryAttempts
	entry.Timeout = now // expired

	r.HandleTimer(now.Add(time.Millisecond))

	if r.GetCacheEntryCount() != 0 {
		t.Errorf("cache count = %d, want 0 after max retries", r.GetCacheEntryCount())
	}
	if dropTarget != testTarget1 {
		t.Errorf("dropTarget = %v, want %v", dropTarget, testTarget1)
	}
}

func TestResolver_Resolve_ExpiredCachedEntry(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	queryCount := 0
	r.SetQueryCallback(func(_ ip6.Address) {
		queryCount++
	})

	// Add a cached entry.
	r.HandleAddressQueryResponse(testTarget1, 0x0400, testIID, now, now)

	// Resolve after expiry should trigger a re-query.
	later := now.Add(CacheEntryTimeout + time.Second)
	_, err := r.Resolve(testTarget1, later)
	if err != goterrors.ErrAddressQuery {
		t.Errorf("err = %v, want ErrAddressQuery", err)
	}
	if queryCount != 1 {
		t.Errorf("queryCount = %d, want 1", queryCount)
	}
}

func TestResolver_CacheFull_Evicts(t *testing.T) {
	t.Parallel()
	r := NewResolverWithSize(2, 2)
	now := time.Now()

	r.SetQueryCallback(func(_ ip6.Address) {})

	// Fill cache.
	r.HandleAddressQueryResponse(testTarget1, 0x0400, testIID, now, now)
	r.HandleAddressQueryResponse(testTarget2, 0x0800, testIID, now, now)

	// Third entry should evict one (all are CanEvict=true).
	r.HandleAddressQueryResponse(testTarget3, 0x0C00, testIID, now, now)

	if r.GetCacheEntryCount() != 2 {
		t.Errorf("cache count = %d, want 2", r.GetCacheEntryCount())
	}
}

func TestResolver_SnoopedFull_EvictsOldest(t *testing.T) {
	t.Parallel()
	r := NewResolverWithSize(4, 2)
	now := time.Now()

	r.UpdateSnoopedEntry(testTarget1, 0x0400, now)
	r.UpdateSnoopedEntry(testTarget2, 0x0800, now.Add(time.Second))

	// Third should evict the oldest (testTarget1).
	r.UpdateSnoopedEntry(testTarget3, 0x0C00, now.Add(2*time.Second))

	if r.GetSnoopedEntryCount() != 2 {
		t.Errorf("snooped count = %d, want 2", r.GetSnoopedEntryCount())
	}
	if r.findInSnooped(testTarget1) != nil {
		t.Error("oldest entry should be evicted")
	}
	if r.findInSnooped(testTarget3) == nil {
		t.Error("newest entry should be present")
	}
}

func TestCacheEntry_IsValid(t *testing.T) {
	t.Parallel()
	e := CacheEntry{}
	if e.IsValid() {
		t.Error("zero entry should not be valid")
	}
	e.Target = testTarget1
	if !e.IsValid() {
		t.Error("entry with target should be valid")
	}
}

func TestCacheEntry_IsExpired(t *testing.T) {
	t.Parallel()
	now := time.Now()
	e := CacheEntry{
		Target:  testTarget1,
		Timeout: now.Add(10 * time.Second),
	}
	if e.IsExpired(now) {
		t.Error("entry should not be expired")
	}
	if !e.IsExpired(now.Add(11 * time.Second)) {
		t.Error("entry should be expired")
	}

	// Zero timeout never expires.
	e2 := CacheEntry{Target: testTarget1}
	if e2.IsExpired(now.Add(time.Hour)) {
		t.Error("zero timeout should never expire")
	}
}

func TestEntryState_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		state EntryState
		want  string
	}{
		{EntryStateQuery, "Query"},
		{EntryStateCached, "Cached"},
		{EntryStateSnooped, "Snooped"},
		{EntryStateRetryQuery, "RetryQuery"},
		{EntryState(99), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestResolver_NoCallbacksPanics(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	// These should not panic with no callbacks set.
	r.Resolve(testTarget1, now)
	r.HandleAddressQueryResponse(testTarget1, 0x0400, testIID, now, now)
	r.HandleAddressError(testTarget1, types.ExtAddress{})
	r.HandleAddressNotification(testTarget2, 0x0800, testIID, now, now)
	r.HandleTimer(now)
}

func TestResolver_Resolve_RetryQueryStateTriggersResend(t *testing.T) {
	t.Parallel()
	r := NewResolver()
	now := time.Now()

	queryCount := 0
	r.SetQueryCallback(func(_ ip6.Address) {
		queryCount++
	})

	// Create a query.
	r.Resolve(testTarget1, now)

	// Manually put the entry into RetryQuery state with an expired timeout.
	entry := r.findInCache(testTarget1)
	entry.State = EntryStateRetryQuery
	entry.Timeout = now.Add(-time.Second) // already expired

	// Resolve should trigger a re-send.
	_, err := r.Resolve(testTarget1, now)
	if err != goterrors.ErrAddressQuery {
		t.Errorf("err = %v, want ErrAddressQuery", err)
	}
	if queryCount != 2 {
		t.Errorf("queryCount = %d, want 2", queryCount)
	}
}
