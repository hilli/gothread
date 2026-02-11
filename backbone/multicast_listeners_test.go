// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package backbone

import (
	"testing"

	"github.com/hilli/gothread/errors"
)

// multicastAddr returns a multicast address with the given scope nibble.
// scope 4 = admin-local, 5 = site-local, etc.
func multicastAddr(scope byte) [16]byte {
	var addr [16]byte
	addr[0] = 0xff
	addr[1] = 0x00 | (scope & 0x0F)
	addr[15] = 1 // unique-ish suffix
	return addr
}

// multicastAddrN returns a multicast address with site-local scope (5) and
// a distinguishing byte in the last position.
func multicastAddrN(n byte) [16]byte {
	var addr [16]byte
	addr[0] = 0xff
	addr[1] = 0x05 // site-local
	addr[15] = n
	return addr
}

// ---------------------------------------------------------------------------
// Add
// ---------------------------------------------------------------------------

func TestMLT_AddSingle(t *testing.T) {
	tbl := NewMulticastListenersTable()
	addr := multicastAddrN(1)
	if err := tbl.Add(addr, 1000); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if tbl.Count() != 1 {
		t.Fatalf("Count = %d, want 1", tbl.Count())
	}
}

func TestMLT_AddDuplicateUpdatesExpire(t *testing.T) {
	tbl := NewMulticastListenersTable()
	addr := multicastAddrN(1)
	if err := tbl.Add(addr, 1000); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := tbl.Add(addr, 2000); err != nil {
		t.Fatalf("Add duplicate: %v", err)
	}
	if tbl.Count() != 1 {
		t.Fatalf("Count = %d, want 1 after duplicate add", tbl.Count())
	}
	all := tbl.GetAll()
	if all[0].ExpireTimeMs != 2000 {
		t.Fatalf("ExpireTimeMs = %d, want 2000", all[0].ExpireTimeMs)
	}
}

func TestMLT_AddBeyondCapacity(t *testing.T) {
	tbl := NewMulticastListenersTable(WithMaxListeners(3))
	for i := byte(0); i < 3; i++ {
		if err := tbl.Add(multicastAddrN(i+1), int64(i)*1000); err != nil {
			t.Fatalf("Add %d: %v", i, err)
		}
	}
	err := tbl.Add(multicastAddrN(99), 9000)
	if err != errors.ErrNoBufs {
		t.Fatalf("expected ErrNoBufs, got %v", err)
	}
}

func TestMLT_AddCallbackInvoked(t *testing.T) {
	var events []ListenerEvent
	tbl := NewMulticastListenersTable(WithListenerCallback(func(e ListenerEvent, _ [16]byte) {
		events = append(events, e)
	}))
	_ = tbl.Add(multicastAddrN(1), 1000)
	_ = tbl.Add(multicastAddrN(2), 2000)
	// Duplicate add should NOT invoke callback.
	_ = tbl.Add(multicastAddrN(1), 1500)
	if len(events) != 2 {
		t.Fatalf("callback invoked %d times, want 2", len(events))
	}
	for i, e := range events {
		if e != ListenerAdded {
			t.Fatalf("event[%d] = %d, want ListenerAdded", i, e)
		}
	}
}

// ---------------------------------------------------------------------------
// Remove
// ---------------------------------------------------------------------------

func TestMLT_RemoveExisting(t *testing.T) {
	tbl := NewMulticastListenersTable()
	addr := multicastAddrN(1)
	_ = tbl.Add(addr, 1000)
	if err := tbl.Remove(addr); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if tbl.Count() != 0 {
		t.Fatalf("Count = %d, want 0", tbl.Count())
	}
}

func TestMLT_RemoveNonExistent(t *testing.T) {
	tbl := NewMulticastListenersTable()
	err := tbl.Remove(multicastAddrN(42))
	if err != errors.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestMLT_RemoveCallbackInvoked(t *testing.T) {
	var removed int
	tbl := NewMulticastListenersTable(WithListenerCallback(func(e ListenerEvent, _ [16]byte) {
		if e == ListenerRemoved {
			removed++
		}
	}))
	addr := multicastAddrN(1)
	_ = tbl.Add(addr, 1000)
	_ = tbl.Remove(addr)
	if removed != 1 {
		t.Fatalf("removed callbacks = %d, want 1", removed)
	}
}

// ---------------------------------------------------------------------------
// Expire
// ---------------------------------------------------------------------------

func TestMLT_ExpireRemovesExpired(t *testing.T) {
	tbl := NewMulticastListenersTable()
	_ = tbl.Add(multicastAddrN(1), 100)
	_ = tbl.Add(multicastAddrN(2), 200)
	_ = tbl.Add(multicastAddrN(3), 300)

	n := tbl.Expire(150)
	if n != 1 {
		t.Fatalf("expired = %d, want 1", n)
	}
	if tbl.Count() != 2 {
		t.Fatalf("Count = %d, want 2", tbl.Count())
	}
}

func TestMLT_ExpireCallbackInvoked(t *testing.T) {
	var removed int
	tbl := NewMulticastListenersTable(WithListenerCallback(func(e ListenerEvent, _ [16]byte) {
		if e == ListenerRemoved {
			removed++
		}
	}))
	_ = tbl.Add(multicastAddrN(1), 100)
	_ = tbl.Add(multicastAddrN(2), 200)
	tbl.Expire(250)
	if removed != 2 {
		t.Fatalf("removed callbacks = %d, want 2", removed)
	}
}

func TestMLT_ExpireHeapOrdering(t *testing.T) {
	// Earliest expire should be removed first, regardless of insertion order.
	tbl := NewMulticastListenersTable()
	_ = tbl.Add(multicastAddrN(3), 300)
	_ = tbl.Add(multicastAddrN(1), 100)
	_ = tbl.Add(multicastAddrN(2), 200)

	var order []byte
	tbl.SetCallback(func(e ListenerEvent, addr [16]byte) {
		if e == ListenerRemoved {
			order = append(order, addr[15])
		}
	})

	tbl.Expire(250)
	if len(order) != 2 {
		t.Fatalf("expired = %d, want 2", len(order))
	}
	if order[0] != 1 || order[1] != 2 {
		t.Fatalf("expire order = %v, want [1, 2]", order)
	}
}

func TestMLT_ExpireNoneExpired(t *testing.T) {
	tbl := NewMulticastListenersTable()
	_ = tbl.Add(multicastAddrN(1), 500)
	n := tbl.Expire(100)
	if n != 0 {
		t.Fatalf("expired = %d, want 0", n)
	}
}

func TestMLT_ExpireSelective(t *testing.T) {
	tbl := NewMulticastListenersTable()
	for i := byte(1); i <= 10; i++ {
		_ = tbl.Add(multicastAddrN(i), int64(i)*100)
	}
	n := tbl.Expire(500)
	if n != 5 {
		t.Fatalf("expired = %d, want 5", n)
	}
	if tbl.Count() != 5 {
		t.Fatalf("Count = %d, want 5", tbl.Count())
	}
}

// ---------------------------------------------------------------------------
// Clear
// ---------------------------------------------------------------------------

func TestMLT_ClearInvokesCallback(t *testing.T) {
	var removed int
	tbl := NewMulticastListenersTable(WithListenerCallback(func(e ListenerEvent, _ [16]byte) {
		if e == ListenerRemoved {
			removed++
		}
	}))
	for i := byte(1); i <= 5; i++ {
		_ = tbl.Add(multicastAddrN(i), int64(i)*100)
	}
	tbl.Clear()
	if removed != 5 {
		t.Fatalf("removed callbacks = %d, want 5", removed)
	}
	if tbl.Count() != 0 {
		t.Fatalf("Count = %d, want 0 after Clear", tbl.Count())
	}
}

// ---------------------------------------------------------------------------
// SetCallback
// ---------------------------------------------------------------------------

func TestMLT_SetCallbackReplays(t *testing.T) {
	tbl := NewMulticastListenersTable()
	_ = tbl.Add(multicastAddrN(1), 100)
	_ = tbl.Add(multicastAddrN(2), 200)
	_ = tbl.Add(multicastAddrN(3), 300)

	var added int
	tbl.SetCallback(func(e ListenerEvent, _ [16]byte) {
		if e == ListenerAdded {
			added++
		}
	})
	if added != 3 {
		t.Fatalf("replay added = %d, want 3", added)
	}
}

// ---------------------------------------------------------------------------
// Contains
// ---------------------------------------------------------------------------

func TestMLT_Contains(t *testing.T) {
	tbl := NewMulticastListenersTable()
	addr := multicastAddrN(1)
	_ = tbl.Add(addr, 1000)
	if !tbl.Contains(addr) {
		t.Fatal("Contains = false, want true")
	}
	if tbl.Contains(multicastAddrN(99)) {
		t.Fatal("Contains = true for absent address")
	}
}

// ---------------------------------------------------------------------------
// GetAll
// ---------------------------------------------------------------------------

func TestMLT_GetAll(t *testing.T) {
	tbl := NewMulticastListenersTable()
	_ = tbl.Add(multicastAddrN(1), 100)
	_ = tbl.Add(multicastAddrN(2), 200)
	all := tbl.GetAll()
	if len(all) != 2 {
		t.Fatalf("len(GetAll) = %d, want 2", len(all))
	}
}

// ---------------------------------------------------------------------------
// Address validation
// ---------------------------------------------------------------------------

func TestMLT_RejectNonMulticast(t *testing.T) {
	tbl := NewMulticastListenersTable()
	var addr [16]byte // all-zero = not multicast
	err := tbl.Add(addr, 1000)
	if err != errors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs, got %v", err)
	}
}

func TestMLT_RejectRealmLocalScope(t *testing.T) {
	tbl := NewMulticastListenersTable()
	addr := multicastAddr(3) // scope 3 = realm-local
	err := tbl.Add(addr, 1000)
	if err != errors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs for realm-local scope, got %v", err)
	}
}

func TestMLT_RejectInterfaceLocalScope(t *testing.T) {
	tbl := NewMulticastListenersTable()
	addr := multicastAddr(1) // scope 1 = interface-local
	err := tbl.Add(addr, 1000)
	if err != errors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs for interface-local scope, got %v", err)
	}
}

func TestMLT_AcceptAdminLocalScope(t *testing.T) {
	tbl := NewMulticastListenersTable()
	addr := multicastAddr(4) // scope 4 = admin-local
	if err := tbl.Add(addr, 1000); err != nil {
		t.Fatalf("expected accept admin-local scope, got %v", err)
	}
}

func TestMLT_AcceptSiteLocalScope(t *testing.T) {
	tbl := NewMulticastListenersTable()
	addr := multicastAddr(5) // scope 5 = site-local
	if err := tbl.Add(addr, 1000); err != nil {
		t.Fatalf("expected accept site-local scope, got %v", err)
	}
}

func TestMLT_AcceptGlobalScope(t *testing.T) {
	tbl := NewMulticastListenersTable()
	addr := multicastAddr(0x0E) // scope 14 = global
	if err := tbl.Add(addr, 1000); err != nil {
		t.Fatalf("expected accept global scope, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Heap invariant stress test
// ---------------------------------------------------------------------------

func TestMLT_HeapInvariant(t *testing.T) {
	tbl := NewMulticastListenersTable(WithMaxListeners(100))
	// Insert in reverse order.
	for i := byte(100); i >= 1; i-- {
		if err := tbl.Add(multicastAddrN(i), int64(i)*10); err != nil {
			t.Fatalf("Add %d: %v", i, err)
		}
	}
	// Expire one-by-one, verifying order.
	prev := int64(0)
	for tbl.Count() > 0 {
		all := tbl.GetAll()
		root := all[0].ExpireTimeMs
		if root < prev {
			t.Fatalf("heap violated: root %d < prev %d", root, prev)
		}
		prev = root
		tbl.Expire(root)
	}
}

func TestMLT_RemoveMiddleMaintainsHeap(t *testing.T) {
	tbl := NewMulticastListenersTable()
	_ = tbl.Add(multicastAddrN(1), 100)
	_ = tbl.Add(multicastAddrN(2), 200)
	_ = tbl.Add(multicastAddrN(3), 300)
	_ = tbl.Add(multicastAddrN(4), 400)
	_ = tbl.Add(multicastAddrN(5), 500)

	// Remove the middle entry.
	_ = tbl.Remove(multicastAddrN(3))

	// Expire everything and verify monotonic order.
	prev := int64(0)
	for tbl.Count() > 0 {
		all := tbl.GetAll()
		root := all[0].ExpireTimeMs
		if root < prev {
			t.Fatalf("heap violated after Remove: root %d < prev %d", root, prev)
		}
		prev = root
		tbl.Expire(root)
	}
}

func TestMLT_UpdateExpireTimeMaintainsHeap(t *testing.T) {
	tbl := NewMulticastListenersTable()
	_ = tbl.Add(multicastAddrN(1), 100)
	_ = tbl.Add(multicastAddrN(2), 200)
	_ = tbl.Add(multicastAddrN(3), 300)

	// Update entry 1 to have the latest expire time.
	_ = tbl.Add(multicastAddrN(1), 400)

	// The root should now be entry 2 (200).
	all := tbl.GetAll()
	if all[0].ExpireTimeMs != 200 {
		t.Fatalf("root expire = %d, want 200 after update", all[0].ExpireTimeMs)
	}
}

func TestMLT_EmptyExpire(t *testing.T) {
	tbl := NewMulticastListenersTable()
	n := tbl.Expire(9999)
	if n != 0 {
		t.Fatalf("expired = %d on empty table, want 0", n)
	}
}

func TestMLT_ClearOnEmpty(t *testing.T) {
	tbl := NewMulticastListenersTable()
	tbl.Clear() // should not panic
	if tbl.Count() != 0 {
		t.Fatalf("Count = %d, want 0", tbl.Count())
	}
}
