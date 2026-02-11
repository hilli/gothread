// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file adds accessor methods to Neighbor, Child, ChildTable, and
// NeighborTable that were not included in the initial port.
//
// These correspond to various getters/setters from OpenThread's
// src/core/thread/neighbor.hpp, child_table.hpp, and neighbor_table.hpp.

package mle

import (
	"time"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Neighbor accessors
// ---------------------------------------------------------------------------

// GetRloc16 returns the neighbor's RLOC16 short address.
func (n *Neighbor) GetRloc16() uint16 {
	return n.RLOC16
}

// SetRloc16 sets the neighbor's RLOC16 short address.
func (n *Neighbor) SetRloc16(rloc16 uint16) {
	n.RLOC16 = rloc16
}

// GetExtAddress returns the neighbor's extended (EUI-64) MAC address.
func (n *Neighbor) GetExtAddress() types.ExtAddress {
	return n.MacAddr
}

// SetExtAddress sets the neighbor's extended (EUI-64) MAC address.
func (n *Neighbor) SetExtAddress(addr types.ExtAddress) {
	n.MacAddr = addr
}

// GetState returns the neighbor's current connection state.
func (n *Neighbor) GetState() NeighborState {
	return n.State
}

// SetState sets the neighbor's connection state.
func (n *Neighbor) SetState(state NeighborState) {
	n.State = state
}

// GetLinkFrameCounters returns the neighbor's link layer frame counters.
func (n *Neighbor) GetLinkFrameCounters() uint32 {
	return n.Counters.LinkFrameCounter
}

// GetMleFrameCounters returns the neighbor's MLE frame counter.
func (n *Neighbor) GetMleFrameCounters() uint32 {
	return n.Counters.MleFrameCounter
}

// GetAge returns the duration since the neighbor was last heard.
func (n *Neighbor) GetAge() time.Duration {
	if n.LastHeard.IsZero() {
		return 0
	}
	return time.Since(n.LastHeard)
}

// ResetAge sets LastHeard to the current time.
func (n *Neighbor) ResetAge() {
	n.LastHeard = time.Now()
}

// GetLastHeard returns the time the neighbor was last heard.
func (n *Neighbor) GetLastHeard() time.Time {
	return n.LastHeard
}

// SetLinkQualityIn overrides the incoming link quality value directly.
// Quality values are 0-3.
func (n *Neighbor) SetLinkQualityIn(quality uint8) {
	n.LinkInfo.SetQualityIn(quality)
}

// ---------------------------------------------------------------------------
// Child accessors
// ---------------------------------------------------------------------------

// GetNetworkDataVersion returns the child's network data version.
func (c *Child) GetNetworkDataVersion() uint8 {
	return c.NetworkDataVersion
}

// SetNetworkDataVersion sets the child's network data version.
func (c *Child) SetNetworkDataVersion(version uint8) {
	c.NetworkDataVersion = version
}

// RemoveIP6Address removes an IPv6 address from the child's registration list.
// Returns true if the address was found and removed.
func (c *Child) RemoveIP6Address(addr ip6.Address) bool {
	for i := uint8(0); i < c.IP6AddressCount; i++ {
		if c.IP6Addresses[i] == addr {
			// Shift remaining entries down.
			for j := i; j < c.IP6AddressCount-1; j++ {
				c.IP6Addresses[j] = c.IP6Addresses[j+1]
			}
			c.IP6AddressCount--
			c.IP6Addresses[c.IP6AddressCount] = ip6.Address{}
			return true
		}
	}
	return false
}

// GetTimeout returns the child's keep-alive timeout in seconds.
func (c *Child) GetTimeout() uint32 {
	return c.Timeout
}

// SetTimeout sets the child's keep-alive timeout in seconds.
func (c *Child) SetTimeout(timeout uint32) {
	c.Timeout = timeout
}

// GetCSLPeriod returns the child's CSL period.
func (c *Child) GetCSLPeriod() uint16 {
	return c.CSLPeriod
}

// SetCSLPeriod sets the child's CSL period.
func (c *Child) SetCSLPeriod(period uint16) {
	c.CSLPeriod = period
}

// GetCSLPhase returns the child's CSL phase.
func (c *Child) GetCSLPhase() uint16 {
	return c.CSLPhase
}

// SetCSLPhase sets the child's CSL phase.
func (c *Child) SetCSLPhase(phase uint16) {
	c.CSLPhase = phase
}

// ---------------------------------------------------------------------------
// ChildTable accessors
// ---------------------------------------------------------------------------

// GetMaxChildren returns the maximum number of children the table can hold.
func (ct *ChildTable) GetMaxChildren() int {
	return MaxChildren
}

// GetChildAtIndex returns a pointer to the child at the given index.
// Returns nil if the index is out of bounds.
func (ct *ChildTable) GetChildAtIndex(index int) *Child {
	if index < 0 || index >= MaxChildren {
		return nil
	}
	return &ct.children[index]
}

// GetNumChildren returns the number of children matching the given state
// filter. If stateFilter is StateInvalid, all non-invalid children are
// counted (same as GetChildCount). Otherwise, only children in that
// specific state are counted.
func (ct *ChildTable) GetNumChildren(stateFilter NeighborState) int {
	count := 0
	for i := range ct.children {
		if stateFilter == StateInvalid {
			if ct.children[i].State != StateInvalid {
				count++
			}
		} else {
			if ct.children[i].State == stateFilter {
				count++
			}
		}
	}
	return count
}

// HasChildrenWithState reports whether any children are in the given state.
// If stateFilter is StateInvalid, it checks for any non-invalid children.
func (ct *ChildTable) HasChildrenWithState(stateFilter NeighborState) bool {
	for i := range ct.children {
		if stateFilter == StateInvalid {
			if ct.children[i].State != StateInvalid {
				return true
			}
		} else {
			if ct.children[i].State == stateFilter {
				return true
			}
		}
	}
	return false
}

// FreeChild invalidates the given child entry, returning it to the pool.
func (ct *ChildTable) FreeChild(child *Child) {
	child.State = StateInvalid
}

// ---------------------------------------------------------------------------
// NeighborTable accessors
// ---------------------------------------------------------------------------

// GetNeighborCount returns the total number of active neighbors (children
// in any non-invalid state plus routers in any non-invalid state).
func (nt *NeighborTable) GetNeighborCount() int {
	return nt.children.GetChildCount() + nt.GetActiveRouterCount()
}
