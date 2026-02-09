// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file implements the ChildTable type, which manages the set of children
// attached to a router or leader.
//
// This is a Go port of the child table defined in OpenThread's
// src/core/thread/child_table.hpp and src/core/thread/child_table.cpp.

package mle

import (
	"github.com/hilli/gothread/mac/types"
)

// MaxChildren is the maximum number of children that a router/leader can
// support simultaneously. This matches OpenThread's default.
const MaxChildren = 10

// ChildTable manages the child entries for a Thread router or leader.
type ChildTable struct {
	children [MaxChildren]Child
}

// NewChildTable creates a new empty ChildTable. All entries start in
// StateInvalid.
func NewChildTable() *ChildTable {
	return &ChildTable{}
}

// FindChild returns the child entry matching the given extended address,
// or nil if no such child exists. Only entries in a state other than
// StateInvalid are searched.
func (ct *ChildTable) FindChild(extAddr types.ExtAddress) *Child {
	for i := range ct.children {
		if ct.children[i].State != StateInvalid && ct.children[i].MacAddr == extAddr {
			return &ct.children[i]
		}
	}
	return nil
}

// FindChildByRLOC16 returns the child entry matching the given RLOC16, or
// nil if not found. Only entries in a state other than StateInvalid are
// searched.
func (ct *ChildTable) FindChildByRLOC16(rloc16 uint16) *Child {
	for i := range ct.children {
		if ct.children[i].State != StateInvalid && ct.children[i].RLOC16 == rloc16 {
			return &ct.children[i]
		}
	}
	return nil
}

// GetNewChild allocates a free child entry (one in StateInvalid). Returns
// the child entry, or nil if the table is full.
func (ct *ChildTable) GetNewChild() *Child {
	for i := range ct.children {
		if ct.children[i].State == StateInvalid {
			return &ct.children[i]
		}
	}
	return nil
}

// GetChildCount returns the number of children in a state other than
// StateInvalid.
func (ct *ChildTable) GetChildCount() int {
	count := 0
	for i := range ct.children {
		if ct.children[i].State != StateInvalid {
			count++
		}
	}
	return count
}

// GetValidChildCount returns the number of children in StateValid.
func (ct *ChildTable) GetValidChildCount() int {
	count := 0
	for i := range ct.children {
		if ct.children[i].State == StateValid {
			count++
		}
	}
	return count
}

// ForEach calls fn for every child in a state other than StateInvalid.
// If fn returns false, iteration stops early.
func (ct *ChildTable) ForEach(fn func(child *Child) bool) {
	for i := range ct.children {
		if ct.children[i].State != StateInvalid {
			if !fn(&ct.children[i]) {
				return
			}
		}
	}
}

// ForEachValid calls fn for every child in StateValid.
// If fn returns false, iteration stops early.
func (ct *ChildTable) ForEachValid(fn func(child *Child) bool) {
	for i := range ct.children {
		if ct.children[i].State == StateValid {
			if !fn(&ct.children[i]) {
				return
			}
		}
	}
}

// Clear invalidates all entries in the child table.
func (ct *ChildTable) Clear() {
	for i := range ct.children {
		ct.children[i].State = StateInvalid
	}
}

// HasChildren reports whether any entries are in a state other than
// StateInvalid.
func (ct *ChildTable) HasChildren() bool {
	for i := range ct.children {
		if ct.children[i].State != StateInvalid {
			return true
		}
	}
	return false
}

// GetChildren returns a slice of pointers to all non-invalid children.
// The returned slice references the internal entries directly.
func (ct *ChildTable) GetChildren() []*Child {
	var result []*Child
	for i := range ct.children {
		if ct.children[i].State != StateInvalid {
			result = append(result, &ct.children[i])
		}
	}
	return result
}

// AllocateChildRLOC16 finds the next unused child ID for the given router
// RLOC16 and returns the resulting child RLOC16. The child ID is chosen
// starting from MinChildID and skipping any IDs already in use by
// non-invalid children whose RLOC16 shares the same router ID.
//
// Returns 0 and false if no child ID is available.
func (ct *ChildTable) AllocateChildRLOC16(routerRLOC16 uint16) (uint16, bool) {
	routerBase := routerRLOC16 & ^uint16(MaxChildID)

	for id := MinChildID; id <= MaxChildID; id++ {
		candidate := routerBase | id
		used := false
		for i := range ct.children {
			if ct.children[i].State != StateInvalid && ct.children[i].RLOC16 == candidate {
				used = true
				break
			}
		}
		if !used {
			return candidate, true
		}
	}
	return 0, false
}
