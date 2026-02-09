// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package routing

import (
	"github.com/hilli/gothread/thread/mle"
)

// RouteTlvData holds a parsed Route64 TLV for use in router table updates.
// It maps between entry indices and Router IDs using the router ID bitmask.
type RouteTlvData struct {
	// Sequence is the Router ID sequence number.
	Sequence uint8

	// RouterIDMask is the set of allocated router IDs.
	RouterIDMask mle.RouterIDSet

	// Entries contains one entry per set bit in RouterIDMask, in order.
	Entries []mle.Route64Entry
}

// GetRouterCount returns the number of route entries.
func (r *RouteTlvData) GetRouterCount() int {
	return len(r.Entries)
}

// GetRouterIDForIndex maps a route entry index to the corresponding Router ID
// by counting set bits in the RouterIDMask. Returns InvalidRouterID if the
// index is out of range.
func (r *RouteTlvData) GetRouterIDForIndex(index int) uint8 {
	if index < 0 || index >= len(r.Entries) {
		return InvalidRouterID
	}
	count := 0
	for id := uint8(0); id <= mle.MaxRouterID; id++ {
		if r.RouterIDMask.Contains(id) {
			if count == index {
				return id
			}
			count++
		}
	}
	return InvalidRouterID
}

// GetIndexForRouterID maps a Router ID to its entry index by counting set bits
// before it in the RouterIDMask. Returns -1 if the Router ID is not in the mask.
func (r *RouteTlvData) GetIndexForRouterID(routerID uint8) int {
	if routerID > mle.MaxRouterID || !r.RouterIDMask.Contains(routerID) {
		return -1
	}
	count := 0
	for id := uint8(0); id < routerID; id++ {
		if r.RouterIDMask.Contains(id) {
			count++
		}
	}
	return count
}

// GetEntryForRouterID returns the Route64Entry for the given Router ID,
// or nil if the Router ID is not in the mask.
func (r *RouteTlvData) GetEntryForRouterID(routerID uint8) *mle.Route64Entry {
	idx := r.GetIndexForRouterID(routerID)
	if idx < 0 || idx >= len(r.Entries) {
		return nil
	}
	return &r.Entries[idx]
}
