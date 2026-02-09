// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tmf

import (
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/routing"
)

// RouterTableAdapter wraps a routing.RouterTable to satisfy the
// LeaderRouterTable interface required by LeaderService. It bridges the
// routing package's Router-pointer-based API into the RLOC16-based API
// expected by the TMF leader handlers.
//
// Ported from OpenThread's Mle::RouterTable / tmf integration.
type RouterTableAdapter struct {
	rt *routing.RouterTable
}

// NewRouterTableAdapter creates a new adapter wrapping the given
// routing.RouterTable.
func NewRouterTableAdapter(rt *routing.RouterTable) *RouterTableAdapter {
	return &RouterTableAdapter{rt: rt}
}

// ---------------------------------------------------------------------------
// mle.RouterTableOps (embedded in LeaderRouterTable)
// ---------------------------------------------------------------------------

// Clear resets the router table, releasing all allocated router IDs.
func (a *RouterTableAdapter) Clear() {
	a.rt.Clear()
}

// AllocateWithID allocates a specific router ID and returns its RLOC16.
func (a *RouterTableAdapter) AllocateWithID(routerID uint8) (uint16, error) {
	r, err := a.rt.AllocateWithID(routerID)
	if err != nil {
		return 0, err
	}
	return r.RLOC16, nil
}

// Allocate picks a random available router ID and returns (routerID, rloc16).
func (a *RouterTableAdapter) Allocate() (uint8, uint16, error) {
	r, routerID, err := a.rt.Allocate()
	if err != nil {
		return 0, 0, err
	}
	return routerID, r.RLOC16, nil
}

// GetActiveRouterCount returns the number of routers in StateValid.
func (a *RouterTableAdapter) GetActiveRouterCount() int {
	return a.rt.GetActiveRouterCount()
}

// GetRouterIDSet returns the set of currently allocated router IDs.
func (a *RouterTableAdapter) GetRouterIDSet() mle.RouterIDSet {
	return a.rt.GetRouterIDSet()
}

// GetRouterIDSequence returns the current router ID sequence number.
func (a *RouterTableAdapter) GetRouterIDSequence() uint8 {
	return a.rt.GetRouterIDSequence()
}

// ---------------------------------------------------------------------------
// LeaderRouterTable extensions
// ---------------------------------------------------------------------------

// AllocateWithIDForRouter allocates a specific router ID and associates it
// with the given extended address. Returns the allocated RLOC16.
func (a *RouterTableAdapter) AllocateWithIDForRouter(routerID uint8, extAddr types.ExtAddress) (uint16, error) {
	r, err := a.rt.AllocateWithID(routerID)
	if err != nil {
		return 0, err
	}
	r.ExtAddress = extAddr
	return r.RLOC16, nil
}

// AllocateForRouter picks a random available router ID, associates it with
// the given extended address, and returns (routerID, rloc16).
func (a *RouterTableAdapter) AllocateForRouter(extAddr types.ExtAddress) (uint8, uint16, error) {
	r, routerID, err := a.rt.Allocate()
	if err != nil {
		return 0, 0, err
	}
	r.ExtAddress = extAddr
	return routerID, r.RLOC16, nil
}

// FindRLOC16ByExtAddress searches for a router with the given extended
// address and returns its RLOC16 if found.
func (a *RouterTableAdapter) FindRLOC16ByExtAddress(addr types.ExtAddress) (uint16, bool) {
	r := a.rt.FindRouterByExtAddress(addr)
	if r == nil {
		return 0, false
	}
	return r.RLOC16, true
}

// Release deallocates the given router ID.
func (a *RouterTableAdapter) Release(routerID uint8) error {
	return a.rt.Release(routerID)
}

// ValidateOwnership checks that the router identified by rloc16 is owned by
// the device with the given extended address.
func (a *RouterTableAdapter) ValidateOwnership(rloc16 uint16, extAddr types.ExtAddress) bool {
	r := a.rt.FindRouterByRLOC16(rloc16)
	if r == nil {
		return false
	}
	return r.ExtAddress == extAddr
}
