// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file implements the ChildMask bitset type, which tracks a set of
// children by their table index.
//
// This is a Go port of the child mask defined in OpenThread's
// src/core/thread/child_mask.hpp.

package mle

import "math/bits"

// childMaskBytes is the number of bytes needed to hold MaxChildren bits.
const childMaskBytes = (MaxChildren + 7) / 8

// ChildMask is a fixed-size bitset indexed by child table position
// (0 through MaxChildren-1).
type ChildMask [childMaskBytes]byte

// Set marks the bit at the given index.
// Indices outside [0, MaxChildren) are ignored.
func (m *ChildMask) Set(index int) {
	if index < 0 || index >= MaxChildren {
		return
	}
	m[index/8] |= 1 << (uint(index) % 8)
}

// Clear clears the bit at the given index.
// Indices outside [0, MaxChildren) are ignored.
func (m *ChildMask) Clear(index int) {
	if index < 0 || index >= MaxChildren {
		return
	}
	m[index/8] &^= 1 << (uint(index) % 8)
}

// Has reports whether the bit at the given index is set.
// Returns false for indices outside [0, MaxChildren).
func (m *ChildMask) Has(index int) bool {
	if index < 0 || index >= MaxChildren {
		return false
	}
	return m[index/8]&(1<<(uint(index)%8)) != 0
}

// IsEmpty reports whether all bits are clear.
func (m *ChildMask) IsEmpty() bool {
	for _, b := range m {
		if b != 0 {
			return false
		}
	}
	return true
}

// Count returns the number of set bits.
func (m *ChildMask) Count() int {
	n := 0
	for _, b := range m {
		n += bits.OnesCount8(b)
	}
	return n
}

// ClearAll clears all bits.
func (m *ChildMask) ClearAll() {
	*m = ChildMask{}
}

// GetFirstSet returns the index of the lowest set bit and true.
// If no bits are set it returns (0, false).
func (m *ChildMask) GetFirstSet() (int, bool) {
	for i := 0; i < MaxChildren; i++ {
		if m[i/8]&(1<<(uint(i)%8)) != 0 {
			return i, true
		}
	}
	return 0, false
}
