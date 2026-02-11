// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file implements the NeighborTable type, which provides unified
// management of child and router neighbors with event callbacks.
//
// This is a Go port of the neighbor table defined in OpenThread's
// src/core/thread/neighbor_table.hpp and src/core/thread/neighbor_table.cpp.

package mle

import (
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
)

// MaxRouterTableSize is the number of entries in the router array.
// Indices 0..MaxRouterID are usable; index InvalidRouterID (63) is unused.
const MaxRouterTableSize = int(InvalidRouterID) + 1

// NeighborTableEvent represents a neighbor table event.
type NeighborTableEvent uint8

const (
	// NeighborTableEventChildAdded indicates a child was added to the table.
	NeighborTableEventChildAdded NeighborTableEvent = iota
	// NeighborTableEventChildRemoved indicates a child was removed from the table.
	NeighborTableEventChildRemoved
	// NeighborTableEventChildModeChanged indicates a child's mode changed.
	NeighborTableEventChildModeChanged
	// NeighborTableEventRouterAdded indicates a router was added to the table.
	NeighborTableEventRouterAdded
	// NeighborTableEventRouterRemoved indicates a router was removed from the table.
	NeighborTableEventRouterRemoved
)

// NeighborTableCallback is called when the neighbor table changes.
type NeighborTableCallback func(event NeighborTableEvent, neighbor *Neighbor)

// NeighborTable provides unified neighbor management over children and routers,
// with optional event callbacks.
//
// It composes the existing ChildTable for child management and maintains a
// fixed-size router array indexed by router ID.
type NeighborTable struct {
	children ChildTable
	routers  [MaxRouterTableSize]Router
	callback NeighborTableCallback
}

// NewNeighborTable creates a new NeighborTable with all entries in StateInvalid.
func NewNeighborTable() *NeighborTable {
	nt := &NeighborTable{}
	for i := range nt.routers {
		nt.routers[i] = NewRouter()
	}
	return nt
}

// RegisterCallback sets the callback for neighbor table events. Only one
// callback is supported; setting a new one replaces the previous.
func (nt *NeighborTable) RegisterCallback(cb NeighborTableCallback) {
	nt.callback = cb
}

// signal emits an event to the registered callback if one is set.
func (nt *NeighborTable) signal(event NeighborTableEvent, neighbor *Neighbor) {
	if nt.callback != nil {
		nt.callback(event, neighbor)
	}
}

// --- Child operations (delegate to embedded ChildTable) ---

// GetChildTable returns a pointer to the underlying ChildTable.
func (nt *NeighborTable) GetChildTable() *ChildTable {
	return &nt.children
}

// FindChildByExtAddress returns the child matching the given extended address,
// or nil if not found.
func (nt *NeighborTable) FindChildByExtAddress(extAddr types.ExtAddress) *Child {
	return nt.children.FindChild(extAddr)
}

// FindChildByRLOC16 returns the child matching the given RLOC16, or nil.
func (nt *NeighborTable) FindChildByRLOC16(rloc16 uint16) *Child {
	return nt.children.FindChildByRLOC16(rloc16)
}

// FindChildByIP6Address returns the child that has the given IPv6 address
// registered. Returns nil if no child matches.
func (nt *NeighborTable) FindChildByIP6Address(addr ip6.Address) *Child {
	var found *Child
	nt.children.ForEach(func(child *Child) bool {
		if child.HasIP6Address(addr) {
			found = child
			return false // stop iteration
		}
		return true
	})
	return found
}

// FindChildByMeshLocalIID returns the child matching the given mesh-local
// interface identifier. Returns nil if no child matches.
func (nt *NeighborTable) FindChildByMeshLocalIID(iid ip6.InterfaceIdentifier) *Child {
	var found *Child
	nt.children.ForEach(func(child *Child) bool {
		if child.MeshLocalIID == iid {
			found = child
			return false
		}
		return true
	})
	return found
}

// GetNewChild allocates a free child entry and signals EventChildAdded.
// Returns the child entry, or nil if the table is full. The caller must
// set the child's state to a non-Invalid value after populating it.
func (nt *NeighborTable) GetNewChild() *Child {
	return nt.children.GetNewChild()
}

// SignalChildAdded should be called after a new child entry is fully
// populated to signal the EventChildAdded event.
func (nt *NeighborTable) SignalChildAdded(child *Child) {
	nt.signal(NeighborTableEventChildAdded, &child.Neighbor)
}

// RemoveChild invalidates the given child and signals EventChildRemoved.
func (nt *NeighborTable) RemoveChild(child *Child) {
	nt.signal(NeighborTableEventChildRemoved, &child.Neighbor)
	child.State = StateInvalid
}

// SignalChildModeChanged signals EventChildModeChanged for the given child.
func (nt *NeighborTable) SignalChildModeChanged(child *Child) {
	nt.signal(NeighborTableEventChildModeChanged, &child.Neighbor)
}

// GetChildCount returns the number of children in a non-Invalid state.
func (nt *NeighborTable) GetChildCount() int {
	return nt.children.GetChildCount()
}

// GetValidChildCount returns the number of children in StateValid.
func (nt *NeighborTable) GetValidChildCount() int {
	return nt.children.GetValidChildCount()
}

// --- Router operations ---

// GetRouter returns a pointer to the router entry for the given router ID.
// Returns nil if the router ID is invalid (> MaxRouterID).
func (nt *NeighborTable) GetRouter(routerID uint8) *Router {
	if routerID > MaxRouterID {
		return nil
	}
	return &nt.routers[routerID]
}

// GetRouterByRLOC16 returns the router entry whose RLOC16 is the given
// value, or nil if the RLOC16 doesn't correspond to a router or the entry
// is invalid.
func (nt *NeighborTable) GetRouterByRLOC16(rloc16 uint16) *Router {
	if !IsRouterRLOC16(rloc16) {
		return nil
	}
	routerID := RouterIDFromRLOC16(rloc16)
	if routerID > MaxRouterID {
		return nil
	}
	r := &nt.routers[routerID]
	if r.State == StateInvalid {
		return nil
	}
	return r
}

// FindRouterByExtAddress returns the router matching the given extended
// address, or nil if not found.
func (nt *NeighborTable) FindRouterByExtAddress(extAddr types.ExtAddress) *Router {
	for i := uint8(0); i <= MaxRouterID; i++ {
		r := &nt.routers[i]
		if r.State != StateInvalid && r.MacAddr == extAddr {
			return r
		}
	}
	return nil
}

// AllocateRouter marks the router entry for the given router ID as in-use
// by setting its RLOC16 and signals EventRouterAdded. The entry's state
// should be set by the caller after populating fields.
func (nt *NeighborTable) AllocateRouter(routerID uint8) *Router {
	if routerID > MaxRouterID {
		return nil
	}
	r := &nt.routers[routerID]
	r.RLOC16 = RLOC16FromRouterID(routerID)
	return r
}

// SignalRouterAdded should be called after a new router entry is fully
// populated to signal the EventRouterAdded event.
func (nt *NeighborTable) SignalRouterAdded(router *Router) {
	nt.signal(NeighborTableEventRouterAdded, &router.Neighbor)
}

// ReleaseRouter invalidates the router entry for the given router ID
// and signals EventRouterRemoved.
func (nt *NeighborTable) ReleaseRouter(routerID uint8) {
	if routerID > MaxRouterID {
		return
	}
	r := &nt.routers[routerID]
	if r.State == StateInvalid {
		return
	}
	nt.signal(NeighborTableEventRouterRemoved, &r.Neighbor)
	nt.routers[routerID] = NewRouter()
}

// GetActiveRouterCount returns the number of routers in a non-Invalid state.
func (nt *NeighborTable) GetActiveRouterCount() int {
	count := 0
	for i := uint8(0); i <= MaxRouterID; i++ {
		if nt.routers[i].State != StateInvalid {
			count++
		}
	}
	return count
}

// GetValidRouterCount returns the number of routers in StateValid.
func (nt *NeighborTable) GetValidRouterCount() int {
	count := 0
	for i := uint8(0); i <= MaxRouterID; i++ {
		if nt.routers[i].State == StateValid {
			count++
		}
	}
	return count
}

// ForEachRouter calls fn for every router in a non-Invalid state.
// If fn returns false, iteration stops early.
func (nt *NeighborTable) ForEachRouter(fn func(router *Router) bool) {
	for i := uint8(0); i <= MaxRouterID; i++ {
		if nt.routers[i].State != StateInvalid {
			if !fn(&nt.routers[i]) {
				return
			}
		}
	}
}

// --- Unified neighbor lookup ---

// FindNeighborByExtAddress searches both the child table and router table
// for a neighbor matching the given extended address. Children are searched
// first. Returns nil if no match is found.
func (nt *NeighborTable) FindNeighborByExtAddress(extAddr types.ExtAddress) *Neighbor {
	child := nt.children.FindChild(extAddr)
	if child != nil {
		return &child.Neighbor
	}
	router := nt.FindRouterByExtAddress(extAddr)
	if router != nil {
		return &router.Neighbor
	}
	return nil
}

// FindNeighborByRLOC16 searches both the child table and router table
// for a neighbor matching the given RLOC16. Returns nil if no match.
func (nt *NeighborTable) FindNeighborByRLOC16(rloc16 uint16) *Neighbor {
	child := nt.children.FindChildByRLOC16(rloc16)
	if child != nil {
		return &child.Neighbor
	}
	if IsRouterRLOC16(rloc16) {
		routerID := RouterIDFromRLOC16(rloc16)
		if routerID <= MaxRouterID {
			r := &nt.routers[routerID]
			if r.State != StateInvalid && r.RLOC16 == rloc16 {
				return &r.Neighbor
			}
		}
	}
	return nil
}

// --- Table-wide operations ---

// Clear invalidates all child and router entries. No events are signaled.
func (nt *NeighborTable) Clear() {
	nt.children.Clear()
	for i := range nt.routers {
		nt.routers[i] = NewRouter()
	}
}

// ClearRouters invalidates all router entries. No events are signaled.
func (nt *NeighborTable) ClearRouters() {
	for i := range nt.routers {
		nt.routers[i] = NewRouter()
	}
}
