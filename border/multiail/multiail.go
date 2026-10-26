// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package multiail implements a Multi-AIL (Active Internet Link) detector
// for Thread Border Routers.
//
// This is a Go port of the multi-AIL detection logic from OpenThread's
// src/core/border_router/routing_manager.cpp. It tracks the mapping from
// router IDs to infrastructure link IDs and determines whether multiple
// distinct active internet links are present in the Thread network.
package multiail

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

// Detector tracks router-to-infra-link-ID mappings and determines whether
// the Thread network spans multiple active internet links.
type Detector struct {
	// routerLinks maps router IDs to their associated infra link IDs.
	routerLinks map[uint8]uint32
}

// NewDetector creates a new Multi-AIL detector.
func NewDetector() *Detector {
	return &Detector{
		routerLinks: make(map[uint8]uint32),
	}
}

// HandleRouterIdUpdated updates the infra link ID associated with a
// router ID. If the router ID is new, it is added; if it already
// exists, its link ID is updated.
func (d *Detector) HandleRouterIdUpdated(routerID uint8, infraLinkID uint32) { //nolint:revive // Retain the established public API spelling for source compatibility.
	d.routerLinks[routerID] = infraLinkID
}

// HandleRouterRemoved removes a router ID from the tracker.
// Returns true if the router was present and removed.
func (d *Detector) HandleRouterRemoved(routerID uint8) bool {
	_, found := d.routerLinks[routerID]
	if found {
		delete(d.routerLinks, routerID)
	}
	return found
}

// IsMultiAil returns true if more than one unique infra link ID is
// present among the tracked routers. This indicates that the Thread
// network spans multiple active internet links.
func (d *Detector) IsMultiAil() bool {
	return d.GetInfraLinkCount() > 1
}

// GetInfraLinkCount returns the number of distinct infra link IDs
// among all tracked routers.
func (d *Detector) GetInfraLinkCount() int {
	seen := make(map[uint32]struct{})
	for _, linkID := range d.routerLinks {
		seen[linkID] = struct{}{}
	}
	return len(seen)
}

// GetRouterCount returns the total number of tracked routers.
func (d *Detector) GetRouterCount() int {
	return len(d.routerLinks)
}

// GetLinkIdForRouter returns the infra link ID for a given router ID
// and whether the router is being tracked.
func (d *Detector) GetLinkIdForRouter(routerID uint8) (uint32, bool) { //nolint:revive // Retain the established public API spelling for source compatibility.
	id, ok := d.routerLinks[routerID]
	return id, ok
}

// Clear removes all router-to-link-ID mappings.
func (d *Detector) Clear() {
	d.routerLinks = make(map[uint8]uint32)
}
