// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package routing

import (
	"math/rand/v2"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/thread/link"
	"github.com/hilli/gothread/thread/mle"
)

// Router table timing constants.
const (
	// RouterIDReuseDelay is the number of seconds before a released router ID
	// can be reallocated.
	RouterIDReuseDelay uint8 = 100
	// RouterIDSequencePeriod is the period in seconds between router ID
	// sequence number increments.
	RouterIDSequencePeriod uint8 = 10
)

// RouterIDMap internal flags.
const (
	routerIDAllocatedFlag uint8 = 0x80
	routerIDIndexMask     uint8 = 0x7F
)

// RouterIDMap maps Router IDs (0-62) to indices in the router array.
// The high bit indicates whether the ID is allocated; the low 7 bits hold
// either the index into the router array (when allocated) or a reuse delay
// countdown (when released).
type RouterIDMap struct {
	indexes [MaxRouterID + 1]uint8 // 63 entries
}

// IsAllocated returns true if the given router ID is currently allocated.
func (m *RouterIDMap) IsAllocated(routerID uint8) bool {
	if routerID > MaxRouterID {
		return false
	}
	return m.indexes[routerID]&routerIDAllocatedFlag != 0
}

// GetIndex returns the router array index for the given router ID.
// Only valid when IsAllocated returns true.
func (m *RouterIDMap) GetIndex(routerID uint8) uint8 {
	return m.indexes[routerID] & routerIDIndexMask
}

// SetIndex marks the router ID as allocated and sets its array index.
func (m *RouterIDMap) SetIndex(routerID, index uint8) {
	m.indexes[routerID] = routerIDAllocatedFlag | (index & routerIDIndexMask)
}

// CanAllocate returns true if the given router ID can be allocated (not
// currently allocated and no remaining reuse delay).
func (m *RouterIDMap) CanAllocate(routerID uint8) bool {
	if routerID > MaxRouterID {
		return false
	}
	return m.indexes[routerID] == 0
}

// Release marks the router ID as released and sets the reuse delay.
func (m *RouterIDMap) Release(routerID uint8) {
	if routerID > MaxRouterID {
		return
	}
	m.indexes[routerID] = RouterIDReuseDelay
}

// GetRouterIDSet returns an mle.RouterIDSet with bits set for all currently
// allocated router IDs.
func (m *RouterIDMap) GetRouterIDSet() mle.RouterIDSet {
	var set mle.RouterIDSet
	for id := uint8(0); id <= MaxRouterID; id++ {
		if m.IsAllocated(id) {
			set.Add(id)
		}
	}
	return set
}

// HandleTimeTick decrements the reuse delay counters for released router IDs.
func (m *RouterIDMap) HandleTimeTick() {
	for id := uint8(0); id <= MaxRouterID; id++ {
		v := m.indexes[id]
		if v != 0 && v&routerIDAllocatedFlag == 0 {
			m.indexes[id] = v - 1
		}
	}
}

// Clear resets all entries to zero (unallocated, no delay).
func (m *RouterIDMap) Clear() {
	m.indexes = [MaxRouterID + 1]uint8{}
}

// RouterTable manages the set of known Thread routers.
type RouterTable struct {
	routers                     []Router
	routerIDMap                 RouterIDMap
	routerIDSequence            uint8
	routerIDSequenceLastUpdated uint32 // milliseconds
}

// NewRouterTable creates a new empty RouterTable.
func NewRouterTable() *RouterTable {
	return &RouterTable{
		routers: make([]Router, 0, MaxRouters),
	}
}

// Clear resets the router table, removing all routers.
func (rt *RouterTable) Clear() {
	rt.routers = rt.routers[:0]
	rt.routerIDMap.Clear()
	rt.routerIDSequence = 0
	rt.routerIDSequenceLastUpdated = 0
}

// ClearNeighbors resets all router states to StateInvalid without removing
// them from the table.
func (rt *RouterTable) ClearNeighbors() {
	for i := range rt.routers {
		rt.routers[i].State = StateInvalid
		rt.routers[i].SetNextHopToInvalid()
	}
}

// Allocate allocates a new router with a random available ID.
// Returns the router, assigned ID, and an error if allocation fails.
func (rt *RouterTable) Allocate() (*Router, uint8, error) {
	if len(rt.routers) >= int(MaxRouters) {
		return nil, InvalidRouterID, goterrors.ErrNoBufs
	}

	// Collect available IDs.
	var available []uint8
	for id := uint8(0); id <= MaxRouterID; id++ {
		if rt.routerIDMap.CanAllocate(id) {
			available = append(available, id)
		}
	}
	if len(available) == 0 {
		return nil, InvalidRouterID, goterrors.ErrNoBufs
	}

	chosen := available[rand.IntN(len(available))]
	router, err := rt.AllocateWithID(chosen)
	if err != nil {
		return nil, InvalidRouterID, err
	}
	return router, chosen, nil
}

// AllocateWithID allocates a router with a specific ID.
func (rt *RouterTable) AllocateWithID(routerID uint8) (*Router, error) {
	if routerID > MaxRouterID {
		return nil, goterrors.ErrInvalidArgs
	}
	if rt.routerIDMap.IsAllocated(routerID) {
		return nil, goterrors.ErrAlready
	}
	if !rt.routerIDMap.CanAllocate(routerID) {
		return nil, goterrors.ErrInvalidState
	}
	if len(rt.routers) >= int(MaxRouters) {
		return nil, goterrors.ErrNoBufs
	}

	index := uint8(len(rt.routers))
	rt.routers = append(rt.routers, Router{})
	r := &rt.routers[index]
	r.State = StateInvalid
	r.NextHop = InvalidRouterID
	r.Cost = 0
	r.RLOC16 = mle.RLOC16FromRouterID(routerID)
	rt.routerIDMap.SetIndex(routerID, index)
	rt.routerIDSequence++

	return r, nil
}

// Release releases a router ID back to the pool.
func (rt *RouterTable) Release(routerID uint8) error {
	if routerID > MaxRouterID {
		return goterrors.ErrInvalidArgs
	}
	if !rt.routerIDMap.IsAllocated(routerID) {
		return goterrors.ErrNotFound
	}

	index := rt.routerIDMap.GetIndex(routerID)
	lastIndex := uint8(len(rt.routers) - 1)

	if index != lastIndex {
		// Move the last router into the released slot.
		rt.routers[index] = rt.routers[lastIndex]
		// Update the ID map for the moved router.
		movedID := mle.RouterIDFromRLOC16(rt.routers[index].RLOC16)
		rt.routerIDMap.SetIndex(movedID, index)
	}

	rt.routers = rt.routers[:lastIndex]
	rt.routerIDMap.Release(routerID)
	rt.routerIDSequence++

	return nil
}

// GetActiveRouterCount returns the number of routers in StateValid.
func (rt *RouterTable) GetActiveRouterCount() int {
	count := 0
	for i := range rt.routers {
		if rt.routers[i].State == StateValid {
			count++
		}
	}
	return count
}

// FindRouterByID returns the router with the given router ID, or nil.
func (rt *RouterTable) FindRouterByID(routerID uint8) *Router {
	if routerID > MaxRouterID {
		return nil
	}
	if !rt.routerIDMap.IsAllocated(routerID) {
		return nil
	}
	index := rt.routerIDMap.GetIndex(routerID)
	if int(index) >= len(rt.routers) {
		return nil
	}
	return &rt.routers[index]
}

// FindRouterByRLOC16 returns the router with the given RLOC16, or nil.
func (rt *RouterTable) FindRouterByRLOC16(rloc16 uint16) *Router {
	routerID := mle.RouterIDFromRLOC16(rloc16)
	return rt.FindRouterByID(routerID)
}

// FindNextHopOf returns the next-hop router for the given router, or nil
// if the next hop is invalid.
func (rt *RouterTable) FindNextHopOf(router *Router) *Router {
	if router == nil || router.NextHop == InvalidRouterID {
		return nil
	}
	return rt.FindRouterByID(router.NextHop)
}

// GetRouterIDSequence returns the current router ID sequence number.
func (rt *RouterTable) GetRouterIDSequence() uint8 {
	return rt.routerIDSequence
}

// IsAllocated returns true if the given router ID is allocated.
func (rt *RouterTable) IsAllocated(routerID uint8) bool {
	return rt.routerIDMap.IsAllocated(routerID)
}

// GetLinkCost returns the link cost to the given router based on its
// two-way link quality. Returns MaxRouteCost if the router is nil or
// not in a valid state.
func (rt *RouterTable) GetLinkCost(router *Router) uint8 {
	if router == nil || router.State != StateValid {
		return MaxRouteCost
	}
	return link.CostForQuality(router.GetTwoWayLinkQuality())
}

// GetNextHopAndPathCost computes the next hop RLOC16 and total path cost
// to the given destination RLOC16. Returns (destRLOC16, 0) for direct
// neighbors with a valid link, or the next hop and accumulated cost through
// the routing table.
func (rt *RouterTable) GetNextHopAndPathCost(destRLOC16 uint16) (nextHopRLOC16 uint16, pathCost uint8) {
	destRouterID := mle.RouterIDFromRLOC16(destRLOC16)
	router := rt.FindRouterByID(destRouterID)
	if router == nil {
		return mle.InvalidRLOC16, MaxRouteCost
	}

	if router.NextHop == InvalidRouterID {
		return mle.InvalidRLOC16, MaxRouteCost
	}

	// Direct link.
	if router.NextHop == destRouterID {
		linkCost := rt.GetLinkCost(router)
		return router.RLOC16, linkCost
	}

	// Multi-hop: cost = router's cost through its next hop.
	nextHop := rt.FindRouterByID(router.NextHop)
	if nextHop == nil {
		return mle.InvalidRLOC16, MaxRouteCost
	}

	return nextHop.RLOC16, router.Cost
}

// Contains returns true if the given neighbor belongs to a router in this
// table.
func (rt *RouterTable) Contains(neighbor *Neighbor) bool {
	if neighbor == nil || len(rt.routers) == 0 {
		return false
	}
	for i := range rt.routers {
		if &rt.routers[i].Neighbor == neighbor {
			return true
		}
	}
	return false
}

// HandleTimeTick advances timers in the router ID map (reuse delays).
func (rt *RouterTable) HandleTimeTick() {
	rt.routerIDMap.HandleTimeTick()
}

// Routers returns the slice of routers for iteration.
func (rt *RouterTable) Routers() []Router {
	return rt.routers
}
