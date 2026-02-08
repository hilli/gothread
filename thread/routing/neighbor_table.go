// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package routing

import (
	mac_types "github.com/hilli/gothread/mac/types"
)

// Event represents a neighbor table event.
type Event uint8

const (
	// EventChildAdded indicates a child was added to the table.
	EventChildAdded Event = 0
	// EventChildRemoved indicates a child was removed from the table.
	EventChildRemoved Event = 1
	// EventChildModeChanged indicates a child's mode changed.
	EventChildModeChanged Event = 2
	// EventRouterAdded indicates a router was added to the table.
	EventRouterAdded Event = 3
	// EventRouterRemoved indicates a router was removed from the table.
	EventRouterRemoved Event = 4
)

// Callback is called when the neighbor table changes.
type Callback func(Event, *Neighbor)

// NeighborTable provides unified lookup across RouterTable, ChildTable,
// and Parent.
type NeighborTable struct {
	routerTable *RouterTable
	childTable  *ChildTable
	parent      *Parent
	callback    Callback
}

// NewNeighborTable creates a new NeighborTable that searches across the
// given router and child tables.
func NewNeighborTable(rt *RouterTable, ct *ChildTable) *NeighborTable {
	return &NeighborTable{
		routerTable: rt,
		childTable:  ct,
	}
}

// SetParent sets the parent to include in neighbor lookups.
func (nt *NeighborTable) SetParent(parent *Parent) {
	nt.parent = parent
}

// RegisterCallback registers a callback for neighbor table events.
func (nt *NeighborTable) RegisterCallback(cb Callback) {
	nt.callback = cb
}

// FindNeighborByShortAddress searches for a neighbor by short address (RLOC16)
// across the router table, child table, and parent.
func (nt *NeighborTable) FindNeighborByShortAddress(addr uint16, filter StateFilter) *Neighbor {
	// Search routers.
	if nt.routerTable != nil {
		for i := range nt.routerTable.routers {
			r := &nt.routerTable.routers[i]
			if r.RLOC16 == addr && r.State.MatchesFilter(filter) {
				return &r.Neighbor
			}
		}
	}

	// Search children.
	if nt.childTable != nil {
		child := nt.childTable.FindChildByRLOC16(addr, filter)
		if child != nil {
			return &child.Neighbor
		}
	}

	// Check parent.
	if nt.parent != nil && nt.parent.RLOC16 == addr &&
		nt.parent.State.MatchesFilter(filter) {
		return &nt.parent.Neighbor
	}

	return nil
}

// FindNeighborByExtAddress searches for a neighbor by extended address across
// the router table, child table, and parent.
func (nt *NeighborTable) FindNeighborByExtAddress(addr mac_types.ExtAddress, filter StateFilter) *Neighbor {
	// Search routers.
	if nt.routerTable != nil {
		for i := range nt.routerTable.routers {
			r := &nt.routerTable.routers[i]
			if r.ExtAddress == addr && r.State.MatchesFilter(filter) {
				return &r.Neighbor
			}
		}
	}

	// Search children.
	if nt.childTable != nil {
		child := nt.childTable.FindChildByExtAddress(addr, filter)
		if child != nil {
			return &child.Neighbor
		}
	}

	// Check parent.
	if nt.parent != nil && nt.parent.ExtAddress == addr &&
		nt.parent.State.MatchesFilter(filter) {
		return &nt.parent.Neighbor
	}

	return nil
}

// Signal emits an event to the registered callback.
func (nt *NeighborTable) Signal(event Event, neighbor *Neighbor) {
	if nt.callback != nil {
		nt.callback(event, neighbor)
	}
}
