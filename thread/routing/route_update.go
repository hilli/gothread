// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package routing

import (
	"github.com/hilli/gothread/thread/mle"
)

// Route update constants.
const (
	// MaxRoutersInRouteTlvForLinkAccept is the maximum number of routers
	// included in a Route64 TLV for a Link Accept message. When the router
	// count exceeds this, entries are trimmed.
	MaxRoutersInRouteTlvForLinkAccept = 20

	// LinkAcceptSequenceRollback is the value subtracted from the router ID
	// sequence when building a trimmed Route64 TLV for Link Accept.
	LinkAcceptSequenceRollback uint8 = 64
)

// UpdateRouterIDSet synchronizes the local router table with a received
// Router ID set and sequence number. Two-pass: first remove deallocated
// routers, then add new ones. Returns true if any routes changed.
//
// This is called when a more recent Router ID sequence is received from
// MLE Advertisements or Link Accept messages.
func (rt *RouterTable) UpdateRouterIDSet(sequence uint8, idSet mle.RouterIDSet, nowMs uint32) bool {
	rt.routerIDSequence = sequence
	rt.routerIDSequenceLastUpdated = nowMs

	changed := false

	// Pass 1: Remove routers that are locally allocated but NOT in the new set.
	for id := uint8(0); id <= mle.MaxRouterID; id++ {
		if rt.routerIDMap.IsAllocated(id) && !idSet.Contains(id) {
			router := rt.FindRouterByID(id)
			if router != nil {
				router.SetNextHopToInvalid()
				rt.RemoveRouterLink(router)
			}
			rt.removeRouter(id)
			changed = true
		}
	}

	// Pass 2: Add routers that are in the new set but NOT locally allocated.
	for id := uint8(0); id <= mle.MaxRouterID; id++ {
		if !rt.routerIDMap.IsAllocated(id) && idSet.Contains(id) {
			rt.addRouter(id)
			changed = true
		}
	}

	return changed
}

// removeRouter removes a router by ID using swap-with-last for O(1) removal.
// This is the internal version that bypasses the reuse delay (the caller is
// responsible for that if needed).
func (rt *RouterTable) removeRouter(routerID uint8) {
	if !rt.routerIDMap.IsAllocated(routerID) {
		return
	}

	index := rt.routerIDMap.GetIndex(routerID)
	lastIndex := uint8(len(rt.routers) - 1)

	if index != lastIndex {
		rt.routers[index] = rt.routers[lastIndex]
		movedID := mle.RouterIDFromRLOC16(rt.routers[index].RLOC16)
		rt.routerIDMap.SetIndex(movedID, index)
	}

	rt.routers = rt.routers[:lastIndex]
	// Clear the ID map entry (no reuse delay since this is driven by the
	// leader's ID set — the leader manages reuse delays).
	rt.routerIDMap.indexes[routerID] = 0
}

// addRouter adds a new router entry for the given ID.
func (rt *RouterTable) addRouter(routerID uint8) {
	if len(rt.routers) >= int(MaxRouters) {
		return
	}

	index := uint8(len(rt.routers))
	rt.routers = append(rt.routers, Router{})
	r := &rt.routers[index]
	r.State = StateInvalid
	r.NextHop = InvalidRouterID
	r.Cost = 0
	r.RLOC16 = mle.RLOC16FromRouterID(routerID)
	rt.routerIDMap.SetIndex(routerID, index)
}

// UpdateRoutes performs a Bellman-Ford distance-vector routing update from
// a received Route64 TLV sent by the given neighbor. Returns true if any
// route reachability changed (for triggering advertisement resets).
//
// Algorithm (matches OpenThread's RouterTable::UpdateRoutes):
//  1. Snapshot which Router IDs currently have a finite path cost.
//  2. Find our own entry in the received TLV — its LinkQualityIn becomes
//     our LinkQualityOut to the sender.
//  3. For each Router ID in the TLV (skip self, skip sender):
//     apply Bellman-Ford relaxation.
//  4. Compare reachable set before/after.
func (rt *RouterTable) UpdateRoutes(routeTlv *RouteTlvData, neighborID uint8, selfRouterID uint8) bool {
	// Phase 1: Snapshot reachable set.
	var beforeReachable [mle.MaxRouterID + 1]bool
	for id := uint8(0); id <= mle.MaxRouterID; id++ {
		if router := rt.FindRouterByID(id); router != nil {
			_, cost := rt.GetNextHopAndPathCost(router.RLOC16)
			beforeReachable[id] = cost < MaxRouteCost
		}
	}

	// Phase 2: Update our outgoing link quality to the sender.
	neighbor := rt.FindRouterByID(neighborID)
	if neighbor == nil {
		return false
	}

	if selfEntry := routeTlv.GetEntryForRouterID(selfRouterID); selfEntry != nil {
		neighbor.LinkQualityOut = selfEntry.LinkQualityIn
	}

	linkCostToNeighbor := rt.GetLinkCost(neighbor)

	// Phase 3: Bellman-Ford relaxation.
	for i := 0; i < routeTlv.GetRouterCount(); i++ {
		routerID := routeTlv.GetRouterIDForIndex(i)
		if routerID == selfRouterID || routerID == neighborID {
			continue
		}

		router := rt.FindRouterByID(routerID)
		if router == nil {
			continue
		}

		entry := &routeTlv.Entries[i]
		routeCost := entry.Cost
		if routeCost == 0 {
			routeCost = MaxRouteCost
		}

		switch router.NextHop {
		case InvalidRouterID, neighborID:
			// Case A: No existing next hop, or next hop IS the sender.
			newCost := routeCost + linkCostToNeighbor
			if newCost < uint8(MaxRouteCost) {
				router.SetNextHopAndCost(neighborID, routeCost)
			} else if router.NextHop == neighborID {
				router.SetNextHopToInvalid()
			}

		default:
			// Case B: Existing next hop is a different router.
			currentNextHop := rt.FindRouterByID(router.NextHop)
			currentLinkCost := rt.GetLinkCost(currentNextHop)

			var currentCost uint8
			if router.Cost+currentLinkCost < MaxRouteCost {
				currentCost = router.Cost + currentLinkCost
			} else {
				currentCost = MaxRouteCost
			}

			newCost := routeCost + linkCostToNeighbor
			if newCost < currentCost {
				router.SetNextHopAndCost(neighborID, routeCost)
			}
		}
	}

	// Phase 4: Compare reachable sets.
	for id := uint8(0); id <= mle.MaxRouterID; id++ {
		router := rt.FindRouterByID(id)
		if router == nil {
			continue
		}
		_, cost := rt.GetNextHopAndPathCost(router.RLOC16)
		afterReachable := cost < MaxRouteCost
		if beforeReachable[id] != afterReachable {
			return true
		}
	}

	return false
}

// UpdateRouterOnFtdChild performs a simplified route update for an FTD child.
// All routes go through the parent. The parentID is the Router ID of the
// parent router.
func (rt *RouterTable) UpdateRouterOnFtdChild(routeTlv *RouteTlvData, parentID uint8) {
	for i := 0; i < routeTlv.GetRouterCount(); i++ {
		routerID := routeTlv.GetRouterIDForIndex(i)
		if routerID == parentID {
			continue
		}

		router := rt.FindRouterByID(routerID)
		if router == nil {
			continue
		}

		entry := &routeTlv.Entries[i]
		if entry.Cost == 0 {
			router.SetNextHopToInvalid()
		} else {
			router.SetNextHopAndCost(parentID, entry.Cost)
		}
	}
}

// FillRouteTlv builds a RouteTlvData from the current routing table state
// for inclusion in an outgoing MLE message. If neighbor is non-nil and the
// router count exceeds MaxRoutersInRouteTlvForLinkAccept, the entry set is
// trimmed to keep only selfRouterID, the neighbor's ID, and leaderRouterID,
// with the sequence rolled back by LinkAcceptSequenceRollback.
func (rt *RouterTable) FillRouteTlv(selfRouterID, leaderRouterID uint8, neighbor *Router) *RouteTlvData {
	data := &RouteTlvData{
		Sequence:     rt.routerIDSequence,
		RouterIDMask: rt.routerIDMap.GetRouterIDSet(),
	}

	routerCount := int(data.RouterIDMask.GetAllocatedCount())

	// Trim for Link Accept if too many routers.
	if neighbor != nil && routerCount > MaxRoutersInRouteTlvForLinkAccept {
		neighborID := mle.RouterIDFromRLOC16(neighbor.RLOC16)
		data.Sequence -= LinkAcceptSequenceRollback
		var trimmedMask mle.RouterIDSet
		trimmedMask.Add(selfRouterID)
		trimmedMask.Add(neighborID)
		trimmedMask.Add(leaderRouterID)
		data.RouterIDMask = trimmedMask
	}

	// Build entries in Router ID order.
	for id := uint8(0); id <= mle.MaxRouterID; id++ {
		if !data.RouterIDMask.Contains(id) {
			continue
		}

		if id == selfRouterID {
			// Self: cost=1, zero link qualities.
			data.Entries = append(data.Entries, mle.Route64Entry{
				LinkQualityOut: 0,
				LinkQualityIn:  0,
				Cost:           1,
			})
			continue
		}

		router := rt.FindRouterByID(id)
		if router == nil {
			data.Entries = append(data.Entries, mle.Route64Entry{})
			continue
		}

		pathCost := rt.GetPathCost(router.RLOC16)
		cost := pathCost
		if cost >= MaxRouteCost {
			cost = 0
		}

		data.Entries = append(data.Entries, mle.Route64Entry{
			LinkQualityOut: router.LinkQualityOut,
			LinkQualityIn:  router.LinkInfo.GetQualityIn(),
			Cost:           cost,
		})
	}

	return data
}
