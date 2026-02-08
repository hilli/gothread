// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package routing

import (
	goterrors "github.com/hilli/gothread/errors"
	mac_types "github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/thread/mle"
)

// Child table capacity and ID limits.
const (
	// MaxChildren is the default maximum number of children
	// (OPENTHREAD_CONFIG_MLE_MAX_CHILDREN).
	MaxChildren = 10
	// MinChildID is the minimum child ID.
	MinChildID uint16 = 1
	// MaxChildID is the maximum child ID.
	MaxChildID uint16 = 511
)

// ChildTable manages the set of known Thread children.
type ChildTable struct {
	children           [MaxChildren]Child
	nextChildID        uint16
	maxChildrenAllowed uint16
}

// NewChildTable creates a new ChildTable with default settings.
func NewChildTable() *ChildTable {
	ct := &ChildTable{
		nextChildID:        MinChildID,
		maxChildrenAllowed: MaxChildren,
	}
	return ct
}

// Clear resets all children to the invalid state and resets the child ID
// counter.
func (ct *ChildTable) Clear() {
	for i := range ct.children {
		ct.children[i] = Child{}
	}
	ct.nextChildID = MinChildID
}

// GetNewChild returns a pointer to the first child entry in StateInvalid,
// or nil if the table is full.
func (ct *ChildTable) GetNewChild() *Child {
	for i := uint16(0); i < ct.maxChildrenAllowed; i++ {
		if ct.children[i].State == StateInvalid {
			return &ct.children[i]
		}
	}
	return nil
}

// AllocateNewChildRLOC16 allocates a new child RLOC16 for the given router
// RLOC16 by assigning the next available child ID.
func (ct *ChildTable) AllocateNewChildRLOC16(routerRLOC16 uint16) uint16 {
	id := ct.nextChildID
	ct.nextChildID++
	if ct.nextChildID > MaxChildID {
		ct.nextChildID = MinChildID
	}
	return routerRLOC16 | id
}

// FindChildByRLOC16 finds a child by RLOC16 matching the given state filter.
// Returns nil if no match is found.
func (ct *ChildTable) FindChildByRLOC16(rloc16 uint16, filter StateFilter) *Child {
	for i := uint16(0); i < ct.maxChildrenAllowed; i++ {
		c := &ct.children[i]
		if c.RLOC16 == rloc16 && c.State.MatchesFilter(filter) {
			return c
		}
	}
	return nil
}

// FindChildByExtAddress finds a child by extended address matching the given
// state filter. Returns nil if no match is found.
func (ct *ChildTable) FindChildByExtAddress(addr mac_types.ExtAddress, filter StateFilter) *Child {
	for i := uint16(0); i < ct.maxChildrenAllowed; i++ {
		c := &ct.children[i]
		if c.ExtAddress == addr && c.State.MatchesFilter(filter) {
			return c
		}
	}
	return nil
}

// HasChildren returns true if the table contains at least one child matching
// the given state filter.
func (ct *ChildTable) HasChildren(filter StateFilter) bool {
	for i := uint16(0); i < ct.maxChildrenAllowed; i++ {
		if ct.children[i].State.MatchesFilter(filter) {
			return true
		}
	}
	return false
}

// GetNumChildren returns the number of children matching the given state
// filter.
func (ct *ChildTable) GetNumChildren(filter StateFilter) int {
	count := 0
	for i := uint16(0); i < ct.maxChildrenAllowed; i++ {
		if ct.children[i].State.MatchesFilter(filter) {
			count++
		}
	}
	return count
}

// GetMaxChildren returns the maximum table capacity.
func (ct *ChildTable) GetMaxChildren() int {
	return MaxChildren
}

// GetMaxChildrenAllowed returns the current maximum number of children
// allowed.
func (ct *ChildTable) GetMaxChildrenAllowed() int {
	return int(ct.maxChildrenAllowed)
}

// SetMaxChildrenAllowed sets the maximum number of children allowed.
// Returns ErrInvalidArgs if max is zero or exceeds MaxChildren, or
// ErrInvalidState if there are currently more children than the new limit.
func (ct *ChildTable) SetMaxChildrenAllowed(maxAllowed int) error {
	if maxAllowed == 0 || maxAllowed > MaxChildren {
		return goterrors.ErrInvalidArgs
	}
	// Check that no children beyond the new limit are active.
	for i := maxAllowed; i < MaxChildren; i++ {
		if ct.children[i].State != StateInvalid {
			return goterrors.ErrInvalidState
		}
	}
	ct.maxChildrenAllowed = uint16(maxAllowed)
	return nil
}

// GetChildIndex returns the index of the given child in the table.
// Returns -1 if the child is not in the table.
func (ct *ChildTable) GetChildIndex(child *Child) int {
	for i := range ct.children {
		if &ct.children[i] == child {
			return i
		}
	}
	return -1
}

// GetChildAtIndex returns a pointer to the child at the given index,
// or nil if the index is out of bounds.
func (ct *ChildTable) GetChildAtIndex(index int) *Child {
	if index < 0 || index >= MaxChildren {
		return nil
	}
	return &ct.children[index]
}

// Children returns a slice of pointers to children matching the given state
// filter.
func (ct *ChildTable) Children(filter StateFilter) []*Child {
	var result []*Child
	for i := uint16(0); i < ct.maxChildrenAllowed; i++ {
		if ct.children[i].State.MatchesFilter(filter) {
			result = append(result, &ct.children[i])
		}
	}
	return result
}

// Contains returns true if the given neighbor belongs to a child in this
// table.
func (ct *ChildTable) Contains(neighbor *Neighbor) bool {
	if neighbor == nil {
		return false
	}
	for i := range ct.children {
		if &ct.children[i].Neighbor == neighbor {
			return true
		}
	}
	return false
}

// ChildIDFromRLOC16 extracts the child ID portion from an RLOC16.
func ChildIDFromRLOC16(rloc16 uint16) uint16 {
	return mle.ChildIDFromRLOC16(rloc16)
}
