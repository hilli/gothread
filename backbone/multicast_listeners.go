// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package backbone

// Multicast Listeners Table — a min-heap ordered by expiration time.
//
// This is a Go port of the Multicast Listeners Table from
// OpenThread's src/core/backbone_router/multicast_listeners_table.{hpp,cpp}.

import (
	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// DefaultMaxListeners is the minimum table size required by Thread 1.2.
const DefaultMaxListeners = 75

// ---------------------------------------------------------------------------
// ListenerEvent
// ---------------------------------------------------------------------------

// ListenerEvent describes what happened to a multicast listener entry.
type ListenerEvent uint8

const (
	// ListenerAdded indicates a listener was added to the table.
	ListenerAdded ListenerEvent = 0
	// ListenerRemoved indicates a listener was removed from the table.
	ListenerRemoved ListenerEvent = 1
)

// ListenerCallback is invoked when a listener is added or removed.
type ListenerCallback func(event ListenerEvent, address [16]byte)

// ---------------------------------------------------------------------------
// ListenerInfo — exported read-only snapshot
// ---------------------------------------------------------------------------

// ListenerInfo is a read-only snapshot of a listener entry.
type ListenerInfo struct {
	Address      [16]byte
	ExpireTimeMs int64
}

// ---------------------------------------------------------------------------
// Listener — internal heap element
// ---------------------------------------------------------------------------

// listener is a single entry in the min-heap.
type listener struct {
	address    [16]byte // IPv6 multicast address
	expireTime int64    // unix timestamp in milliseconds
}

// ---------------------------------------------------------------------------
// Option — functional options
// ---------------------------------------------------------------------------

// ListenerOption configures a MulticastListenersTable.
type ListenerOption func(*MulticastListenersTable)

// WithMaxListeners sets the maximum number of listeners the table can hold.
func WithMaxListeners(n int) ListenerOption {
	return func(t *MulticastListenersTable) {
		if n > 0 {
			t.maxSize = n
		}
	}
}

// WithListenerCallback sets the callback invoked on add/remove events.
func WithListenerCallback(fn ListenerCallback) ListenerOption {
	return func(t *MulticastListenersTable) {
		t.callback = fn
	}
}

// ---------------------------------------------------------------------------
// MulticastListenersTable
// ---------------------------------------------------------------------------

// MulticastListenersTable maintains multicast listener registrations in a
// min-heap ordered by expiration time.
type MulticastListenersTable struct {
	listeners []listener // heap-ordered slice
	maxSize   int
	callback  ListenerCallback
}

// NewMulticastListenersTable creates a new table with the given options.
func NewMulticastListenersTable(opts ...ListenerOption) *MulticastListenersTable {
	t := &MulticastListenersTable{
		maxSize: DefaultMaxListeners,
	}
	for _, o := range opts {
		o(t)
	}
	return t
}

// isMulticastLargerThanRealmLocal checks that the address is a multicast
// address with scope strictly greater than realm-local (scope > 3).
func isMulticastLargerThanRealmLocal(addr [16]byte) bool {
	if addr[0] != 0xff {
		return false
	}
	scope := addr[1] & 0x0F
	return scope > 3
}

// Add inserts or updates a multicast listener.
//
// If the address already exists its expire time is updated. If the table is
// full, errors.ErrNoBufs is returned. If the address is not a valid
// multicast address with scope > realm-local, errors.ErrInvalidArgs is
// returned.
func (t *MulticastListenersTable) Add(address [16]byte, expireTimeMs int64) error {
	if !isMulticastLargerThanRealmLocal(address) {
		return errors.ErrInvalidArgs
	}

	// Update existing entry.
	for i := range t.listeners {
		if t.listeners[i].address == address {
			t.listeners[i].expireTime = expireTimeMs
			t.fixHeap(i)
			return nil
		}
	}

	// Insert new entry.
	if len(t.listeners) >= t.maxSize {
		return errors.ErrNoBufs
	}

	t.listeners = append(t.listeners, listener{
		address:    address,
		expireTime: expireTimeMs,
	})
	t.siftUp(len(t.listeners) - 1)

	if t.callback != nil {
		t.callback(ListenerAdded, address)
	}

	return nil
}

// Remove removes a listener by address. Returns errors.ErrNotFound if the
// address is not in the table.
func (t *MulticastListenersTable) Remove(address [16]byte) error {
	for i := range t.listeners {
		if t.listeners[i].address != address {
			continue
		}
		addr := t.listeners[i].address
		last := len(t.listeners) - 1
		if i != last {
			t.listeners[i] = t.listeners[last]
		}
		t.listeners = t.listeners[:last]
		if i < len(t.listeners) {
			t.fixHeap(i)
		}
		if t.callback != nil {
			t.callback(ListenerRemoved, addr)
		}
		return nil
	}
	return errors.ErrNotFound
}

// Expire removes all listeners whose expireTime <= nowMs. It invokes the
// callback for each removed entry and returns the count of expired entries.
func (t *MulticastListenersTable) Expire(nowMs int64) int {
	count := 0
	for len(t.listeners) > 0 && t.listeners[0].expireTime <= nowMs {
		addr := t.listeners[0].address
		last := len(t.listeners) - 1
		if last > 0 {
			t.listeners[0] = t.listeners[last]
		}
		t.listeners = t.listeners[:last]
		if len(t.listeners) > 0 {
			t.fixHeap(0)
		}
		if t.callback != nil {
			t.callback(ListenerRemoved, addr)
		}
		count++
	}
	return count
}

// Count returns the number of listeners in the table.
func (t *MulticastListenersTable) Count() int {
	return len(t.listeners)
}

// Clear removes all listeners, invoking the callback for each.
func (t *MulticastListenersTable) Clear() {
	if t.callback != nil {
		for i := range t.listeners {
			t.callback(ListenerRemoved, t.listeners[i].address)
		}
	}
	t.listeners = t.listeners[:0]
}

// SetCallback sets the listener callback. When set, it replays a
// ListenerAdded event for every current entry.
func (t *MulticastListenersTable) SetCallback(fn ListenerCallback) {
	t.callback = fn
	if t.callback != nil {
		for i := range t.listeners {
			t.callback(ListenerAdded, t.listeners[i].address)
		}
	}
}

// Contains reports whether the table has a listener for the given address.
func (t *MulticastListenersTable) Contains(address [16]byte) bool {
	for i := range t.listeners {
		if t.listeners[i].address == address {
			return true
		}
	}
	return false
}

// GetAll returns a snapshot of all current listener entries.
func (t *MulticastListenersTable) GetAll() []ListenerInfo {
	out := make([]ListenerInfo, len(t.listeners))
	for i, l := range t.listeners {
		out[i] = ListenerInfo{
			Address:      l.address,
			ExpireTimeMs: l.expireTime,
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Min-heap helpers
// ---------------------------------------------------------------------------

// fixHeap restores the heap property at the given index by trying siftDown
// first and falling back to siftUp.
func (t *MulticastListenersTable) fixHeap(i int) {
	if !t.siftDown(i) {
		t.siftUp(i)
	}
}

// siftDown moves element at index i down the heap until the heap property is
// restored. Returns true if the element was moved.
func (t *MulticastListenersTable) siftDown(i int) bool {
	n := len(t.listeners)
	saved := t.listeners[i]
	idx := i

	for {
		child := 2*idx + 1
		if child >= n || child <= idx { // overflow guard
			break
		}
		// Pick the smaller child.
		if child+1 < n && t.listeners[child+1].expireTime < t.listeners[child].expireTime {
			child++
		}
		if t.listeners[child].expireTime >= saved.expireTime {
			break
		}
		t.listeners[idx] = t.listeners[child]
		idx = child
	}

	if idx > i {
		t.listeners[idx] = saved
		return true
	}
	return false
}

// siftUp moves element at index i up the heap until the heap property is
// restored.
func (t *MulticastListenersTable) siftUp(i int) {
	saved := t.listeners[i]
	idx := i

	for idx > 0 {
		parent := (idx - 1) / 2
		if saved.expireTime >= t.listeners[parent].expireTime {
			break
		}
		t.listeners[idx] = t.listeners[parent]
		idx = parent
	}

	if idx < i {
		t.listeners[idx] = saved
	}
}
