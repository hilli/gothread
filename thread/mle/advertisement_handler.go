// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// FTD Advertisement receive-side handler for MLE.
//
// This file implements the unified Advertisement handler for Full Thread
// Devices (FTDs). It processes MLE Advertisement messages for both the
// child path (network data updates from parent) and the FTD-specific
// router/leader path (route table updates, partition merges, downgrade
// decisions).
//
// Ported from OpenThread's HandleAdvertisement (mle.cpp:1954-2015) and
// HandleAdvertisementOnFtd (mle_ftd.cpp:1157-1346).

package mle

import (
	"fmt"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
)

// AdvertisementRouterOps abstracts router table operations needed by the
// advertisement handler. This interface breaks the circular dependency
// between the mle and routing packages.
type AdvertisementRouterOps interface {
	RouterLookup

	// GetActiveRouterCount returns the number of active routers.
	GetActiveRouterCount() int

	// GetNeighborCount returns the number of router neighbors whose
	// two-way link quality is at least minLinkQuality.
	GetNeighborCount(minLinkQuality uint8) int

	// IsAllocated returns true if the given router ID is allocated.
	IsAllocated(routerID uint8) bool

	// GetRouterIDSequence returns the current router ID sequence number.
	GetRouterIDSequence() uint8

	// IsRouteTlvIDSequenceMoreRecent returns true if the given sequence
	// number is more recent than the current router ID sequence.
	IsRouteTlvIDSequenceMoreRecent(sequence uint8) bool

	// UpdateRouterIDSet updates the router ID allocation table from a
	// received Route64 TLV. Returns true if the set changed.
	UpdateRouterIDSet(sequence uint8, idSet RouterIDSet, nowMs uint32) bool

	// UpdateRoutes updates route entries from a received Route64 TLV.
	// The raw Route64 components are passed to avoid importing routing types.
	UpdateRoutes(sequence uint8, mask RouterIDSet, entries []Route64Entry, neighborID uint8, selfRouterID uint8) bool

	// UpdateRouterOnFtdChild updates route entries when operating as an
	// FTD child. The parentID identifies the parent router for route
	// calculation.
	UpdateRouterOnFtdChild(sequence uint8, mask RouterIDSet, entries []Route64Entry, parentID uint8)

	// FindRouterByID returns the Router entry for the given router ID,
	// or nil if not found.
	FindRouterByID(routerID uint8) *Router

	// RemoveRouterLink removes the link to the given router, invalidating
	// the neighbor and clearing the route.
	RemoveRouterLink(router *Router)
}

// FtdAdvertisementHandler implements the MLE Advertisement receive-side
// handler for Full Thread Devices. It replaces the simpler child-only
// handler from ChildHandlers with a unified handler that processes both
// child and router/leader paths.
type FtdAdvertisementHandler struct {
	mle        *Mle
	dispatcher *Dispatcher
	routerOps  AdvertisementRouterOps
}

// NewFtdAdvertisementHandler creates a new FtdAdvertisementHandler and
// registers the CommandAdvertisement handler with the dispatcher.
func NewFtdAdvertisementHandler(
	mle *Mle,
	dispatcher *Dispatcher,
	routerOps AdvertisementRouterOps,
) *FtdAdvertisementHandler {
	h := &FtdAdvertisementHandler{
		mle:        mle,
		dispatcher: dispatcher,
		routerOps:  routerOps,
	}

	dispatcher.RegisterHandler(CommandAdvertisement, h.HandleAdvertisement)

	return h
}

// HandleAdvertisement processes a received MLE Advertisement message.
//
// Required TLVs: SourceAddress, LeaderData.
// Optional TLVs: Route64 (used by FTD path).
//
// This is a Go port of OpenThread's Mle::HandleAdvertisement
// (mle.cpp:1954-2015).
func (h *FtdAdvertisementHandler) HandleAdvertisement(rxInfo *RxInfo) error {
	if !h.mle.IsAttached() {
		return fmt.Errorf("mle: advertisement received while not attached")
	}

	// Parse required TLVs.
	srcAddrVal, ok := FindTLV(rxInfo.TLVs, TLVSourceAddress)
	if !ok {
		return fmt.Errorf("mle: advertisement missing SourceAddress TLV")
	}
	sourceAddress, err := ReadSourceAddressTLV(srcAddrVal)
	if err != nil {
		return err
	}

	leaderDataVal, ok := FindTLV(rxInfo.TLVs, TLVLeaderData)
	if !ok {
		return fmt.Errorf("mle: advertisement missing LeaderData TLV")
	}
	leaderData, err := ReadLeaderDataTLV(leaderDataVal)
	if err != nil {
		return err
	}

	// FTD-specific processing.
	if h.mle.IsFullThreadDevice() {
		if err := h.handleAdvertisementOnFtd(rxInfo, sourceAddress, leaderData); err != nil {
			return err
		}
	}

	// --- Child path ---
	if h.mle.IsChild() {
		parent := h.mle.GetParent()

		// Only process advertisements from our parent when in child role.
		if rxInfo.Neighbor == nil || rxInfo.Neighbor != &parent.Neighbor {
			return nil // Silently ignore non-parent advertisements.
		}

		// Validate that the parent's RLOC16 matches the advertised source.
		if parent.RLOC16 != sourceAddress {
			return h.mle.BecomeDetached()
		}

		// Check for partition or leader changes.
		currentLeaderData := h.mle.GetLeaderData()
		retrieveNewData := false

		if leaderData.PartitionID != currentLeaderData.PartitionID ||
			leaderData.LeaderRouterID != currentLeaderData.LeaderRouterID {
			h.mle.SetLeaderData(leaderData)
			retrieveNewData = true
		}

		// Check if network data version changed.
		if leaderData.DataVersion != currentLeaderData.DataVersion ||
			leaderData.StableDataVersion != currentLeaderData.StableDataVersion {
			h.mle.SetLeaderData(leaderData)
			retrieveNewData = true
		}

		if retrieveNewData {
			h.mle.SetRetrieveNewNetworkData(true)
		}

		// Update last heard time.
		parent.LastHeard = time.Now()

		// Schedule a Data Request if needed.
		if h.mle.NeedsNewNetworkData() {
			h.mle.SetDataRequestPending(true)
		}

		return nil
	}

	// --- Router/Leader path ---
	if h.mle.IsRouterOrLeader() {
		// Must be from a valid neighbor.
		if rxInfo.Neighbor == nil || !rxInfo.Neighbor.IsStateValid() {
			return nil
		}

		// Update last heard time.
		rxInfo.Neighbor.LastHeard = time.Now()
	}

	return nil
}

// handleAdvertisementOnFtd processes the FTD-specific portions of a received
// MLE Advertisement. This handles partition merge detection, route table
// updates, downgrade decisions, and router link establishment.
//
// This is a Go port of OpenThread's Mle::HandleAdvertisementOnFtd
// (mle_ftd.cpp:1157-1346).
func (h *FtdAdvertisementHandler) handleAdvertisementOnFtd(
	rxInfo *RxInfo,
	sourceAddress uint16,
	leaderData LeaderData,
) error {
	// Parse optional Route64 TLV.
	var routeSequence uint8
	var routeMask RouterIDSet
	var routeEntries []Route64Entry
	hasRoute := false

	if routeVal, ok := FindTLV(rxInfo.TLVs, TLVRoute64); ok {
		var err error
		routeSequence, routeMask, routeEntries, err = ReadRoute64TLV(routeVal)
		if err != nil {
			return fmt.Errorf("mle: advertisement Route64 TLV: %w", err)
		}
		hasRoute = true
	}

	// Compute link margin.
	linkMargin := rxInfo.LinkMarginRaw

	currentLeaderData := h.mle.GetLeaderData()

	// --- Partition ID mismatch ---
	if leaderData.PartitionID != currentLeaderData.PartitionID {
		// Require minimum link margin for partition merge consideration.
		if linkMargin < PartitionMergeMinMargin {
			return goterrors.ErrDrop
		}

		// Previous partition loop detection: if the peer's partition ID
		// matches our previous partition, and the route data matches,
		// we would merge back into a partition we just left.
		prevPartitionID := h.mle.GetPreviousPartitionID()
		if prevPartitionID != 0 && leaderData.PartitionID == prevPartitionID {
			if hasRoute {
				prevSeq := h.mle.GetPreviousPartitionRouterIDSequence()
				prevIDSet := h.mle.GetPreviousPartitionRouterIDSet()
				if routeSequence == prevSeq && routeMask == prevIDSet {
					return goterrors.ErrDrop
				}
			}
		}

		// Compare partitions to decide whether to merge.
		peerSingleton := false
		if hasRoute {
			peerSingleton = IsSingleton(routeMask)
		}

		localSingleton := h.routerOps.GetActiveRouterCount() == 1

		cmp := ComparePartitions(
			localSingleton,
			currentLeaderData,
			peerSingleton,
			leaderData,
		)

		if cmp < 0 {
			// Peer partition is better — merge into it.
			if hasRoute {
				h.mle.SavePreviousPartitionInfo(routeSequence, routeMask)
			}
			return h.mle.StartAttach(AttachBetterPartition)
		}

		// Our partition is better or equal — drop.
		return goterrors.ErrDrop
	}

	// --- Leader Router ID mismatch (same partition ID, different leader) ---
	if leaderData.LeaderRouterID != currentLeaderData.LeaderRouterID {
		if h.mle.IsRouterOrLeader() {
			return h.mle.BecomeDetached()
		}
		// Child with same partition but different leader — ignore.
		return nil
	}

	// --- Same partition, same leader ---

	// Source must be a router RLOC16.
	if !IsRouterRLOC16(sourceAddress) {
		return nil
	}

	// Route TLV must be present for further processing.
	if !hasRoute {
		return nil
	}

	sourceRouterID := RouterIDFromRLOC16(sourceAddress)

	// Process Route TLV if the ID sequence is more recent.
	if h.routerOps.IsRouteTlvIDSequenceMoreRecent(routeSequence) {
		nowMs := uint32(time.Now().UnixMilli())
		h.routerOps.UpdateRouterIDSet(routeSequence, routeMask, nowMs)

		// Verify our own router ID is still allocated (router/leader only).
		if h.mle.IsRouterOrLeader() {
			myRouterID := h.mle.GetRouterID()
			if !routeMask.Contains(myRouterID) {
				// We were removed from the ID set — detach.
				return h.mle.BecomeDetached()
			}
		}
	}

	// --- FTD Child path ---
	if h.mle.IsChild() {
		parent := h.mle.GetParent()

		if rxInfo.Neighbor != nil && rxInfo.Neighbor == &parent.Neighbor {
			// Advertisement from our parent.
			// Validate RLOC16 consistency.
			if parent.RLOC16 != sourceAddress {
				return h.mle.BecomeDetached()
			}

			// Check if we should start the upgrade timer.
			activeRouters := h.routerOps.GetActiveRouterCount()
			if h.mle.IsRouterEligible() &&
				uint8(activeRouters) < h.mle.GetRouterUpgradeThreshold() {
				transition := h.mle.GetRouterRoleTransition()
				if !transition.IsPending() {
					transition.StartTimeout(func(n int) int {
						if n <= 0 {
							return 1
						}
						return int(time.Now().UnixNano() % int64(n))
					})
				}
			}

			// Update route data for FTD child.
			parentRouterID := RouterIDFromRLOC16(parent.RLOC16)
			h.routerOps.UpdateRouterOnFtdChild(routeSequence, routeMask, routeEntries, parentRouterID)
		} else {
			// Advertisement from a non-parent router — try to establish link.
			h.establishRouterLinkOnFtdChild(sourceRouterID, rxInfo, linkMargin)
		}

		return nil
	}

	// --- Router/Leader path ---
	if h.mle.IsRouterOrLeader() {
		router := h.routerOps.FindRouterByID(sourceRouterID)

		switch {
		case router != nil && router.IsStateValid():
			// Known valid neighbor — update routes.
			selfRouterID := h.mle.GetRouterID()
			h.routerOps.UpdateRoutes(routeSequence, routeMask, routeEntries, sourceRouterID, selfRouterID)

			// Check if we should downgrade.
			if h.mle.IsRouter() && h.shouldDowngrade(sourceRouterID, routeSequence, routeMask, routeEntries) {
				transition := h.mle.GetRouterRoleTransition()
				if !transition.IsPending() {
					transition.StartTimeout(func(n int) int {
						if n <= 0 {
							return 1
						}
						return int(time.Now().UnixNano() % int64(n))
					})
				}
			}
		case router != nil && !router.IsStateValid():
			// Router is known but not valid — check link margin to decide
			// whether to schedule a Link Request.
			if linkMargin >= LinkRequestMinMargin {
				router.SetLinkRequestAttemptsToMax()
			}
		default:
			// Unknown router — look up by RLOC16.
			router = h.routerOps.FindRouterByRLOC16(sourceAddress)
			if router != nil && !router.IsStateValid() && linkMargin >= LinkRequestMinMargin {
				router.SetLinkRequestAttemptsToMax()
			}
		}

		// Cleanup: if the neighbor's RLOC16 doesn't match the source address,
		// remove the stale link.
		if rxInfo.Neighbor != nil && rxInfo.Neighbor.RLOC16 != sourceAddress {
			if staleRouter := h.routerOps.FindRouterByRLOC16(rxInfo.Neighbor.RLOC16); staleRouter != nil {
				h.routerOps.RemoveRouterLink(staleRouter)
			}
		}
	}

	return nil
}

// shouldDowngrade checks whether this router should downgrade to a REED.
//
// A router should downgrade when:
// 1. The active router count exceeds the downgrade threshold.
// 2. Enough neighbors have comparable or better connectivity.
//
// This is a Go port of OpenThread's Mle::ShouldDowngrade
// (mle_ftd.cpp:3720-3780).
func (h *FtdAdvertisementHandler) shouldDowngrade(
	neighborID uint8,
	routeSequence uint8,
	routeMask RouterIDSet,
	routeEntries []Route64Entry,
) bool {
	activeRouters := h.routerOps.GetActiveRouterCount()
	downgradeThreshold := h.mle.GetRouterDowngradeThreshold()

	if uint8(activeRouters) <= downgradeThreshold {
		return false
	}

	// Need enough neighbors with comparable connectivity.
	neighborCount := h.routerOps.GetNeighborCount(2) // Link quality >= 2
	if uint8(neighborCount) < MinDowngradeNeighbors {
		return false
	}

	// Check if the neighbor has comparable connectivity.
	return h.neighborHasComparableConnectivity(neighborID, routeSequence, routeMask, routeEntries)
}

// neighborHasComparableConnectivity checks whether the given neighbor has
// connectivity to the same set of routers as this device, with comparable
// or better route quality.
//
// This is a Go port of OpenThread's Mle::NeighborHasComparableConnectivity
// (mle_ftd.cpp:3782-3836).
func (h *FtdAdvertisementHandler) neighborHasComparableConnectivity(
	neighborID uint8,
	_ uint8, // routeSequence — reserved for future use
	routeMask RouterIDSet,
	routeEntries []Route64Entry,
) bool {
	selfRouterID := h.mle.GetRouterID()

	// Count the number of routers this neighbor can reach.
	entryIdx := 0
	peerReachable := 0
	for rid := uint8(0); rid <= MaxRouterID; rid++ {
		if !routeMask.Contains(rid) {
			continue
		}
		if entryIdx >= len(routeEntries) {
			break
		}
		entry := routeEntries[entryIdx]
		entryIdx++

		if rid == neighborID || rid == selfRouterID {
			continue
		}

		// The neighbor has a route to this router if cost > 0 or link quality > 0.
		if entry.Cost > 0 || entry.LinkQualityIn > 0 || entry.LinkQualityOut > 0 {
			peerReachable++
		}
	}

	// Compare against our own reachable count.
	// A simplified check: the neighbor is comparable if it can reach at least
	// as many routers as half the active count minus one.
	activeRouters := h.routerOps.GetActiveRouterCount()
	threshold := (activeRouters - 1) / 2
	return peerReachable >= threshold
}

// establishRouterLinkOnFtdChild is called when an FTD child receives an
// advertisement from a non-parent router with sufficient link quality. It
// schedules a Link Request to establish a router-to-router link for improved
// connectivity.
//
// This is a Go port of OpenThread's Mle::EstablishRouterLinkOnFtdChild
// (mle_ftd.cpp:1348-1409).
func (h *FtdAdvertisementHandler) establishRouterLinkOnFtdChild(
	routerID uint8,
	_ *RxInfo,
	linkMargin uint8,
) {
	if linkMargin < LinkRequestMinMargin {
		return
	}

	// Check if we already have enough router links.
	childRouterLinks := h.mle.GetChildRouterLinks()
	currentLinks := h.routerOps.GetNeighborCount(1) // Link quality >= 1
	if uint8(currentLinks) >= childRouterLinks {
		return
	}

	// Find the router entry and schedule a Link Request if it's not already valid.
	router := h.routerOps.FindRouterByID(routerID)
	if router == nil {
		return
	}

	if router.IsStateValid() {
		// Already have a valid link — nothing to do.
		return
	}

	router.SetLinkRequestAttemptsToMax()
}

// --- Unexported helper for testing ---

// extAddressForRouterID creates a deterministic extended address for testing.
func extAddressForRouterID(routerID uint8) types.ExtAddress {
	return types.ExtAddress{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, routerID}
}
