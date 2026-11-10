// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package bbr

// HasAddressesToRegister observes intent without changing registration state
// or allocating a copied entry list. The native producer checks this before
// requesting entropy for a new transaction.
func (m *MlrManager) HasAddressesToRegister() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mlrPending {
		return false
	}
	for _, entry := range m.entries {
		if entry.State == MlrStateToRegister {
			return true
		}
	}
	return false
}
