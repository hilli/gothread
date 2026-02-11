// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package router

import (
	"github.com/hilli/gothread/crypto/sha256"
)

// ---------------------------------------------------------------------------
// OnLinkPrefixManager — manages the on-link prefix advertised in RAs
// ---------------------------------------------------------------------------

// OnLinkPrefixManager manages the on-link prefix that this border router
// advertises via Router Advertisement Prefix Information Options on the
// infrastructure link. Hosts on the infrastructure link use this prefix for
// SLAAC address configuration.
type OnLinkPrefixManager struct {
	localPrefix       [16]byte
	localPrefixLen    uint8
	hasLocalPrefix    bool
	isAdvertising     bool
	favoredDiscovered bool // a favored on-link prefix was discovered via RA
}

// NewOnLinkPrefixManager creates a new OnLinkPrefixManager.
func NewOnLinkPrefixManager() *OnLinkPrefixManager {
	return &OnLinkPrefixManager{}
}

// GenerateLocalPrefix generates a ULA /48 on-link prefix from the given
// extended address using SHA-256.
//
// The algorithm:
//  1. Compute hash = SHA-256(extAddr).
//  2. Set prefix byte 0 = 0xfd (ULA).
//  3. Copy hash bytes 5..9 into prefix bytes 1..5 (40 bits of hash).
//     We use bytes 5..9 of the hash to avoid collision with the OMR prefix
//     which uses bytes 0..4.
//  4. Set prefix bytes 6..15 = 0.
//  5. Prefix length = 48.
func (m *OnLinkPrefixManager) GenerateLocalPrefix(extAddr [8]byte) error {
	var s sha256.Sha256
	s.Start()
	s.Update(extAddr[:])
	var h sha256.Hash
	s.Finish(&h)

	var prefix [16]byte
	prefix[0] = 0xfd
	copy(prefix[1:6], h[5:10])
	// prefix[6:16] are already zero.

	m.localPrefix = prefix
	m.localPrefixLen = 48
	m.hasLocalPrefix = true
	return nil
}

// Evaluate re-evaluates whether the local on-link prefix should be
// advertised. If a favored on-link prefix has been discovered from another
// router on the infrastructure link, this router should stop advertising
// its own. Returns true if the advertising decision changed.
func (m *OnLinkPrefixManager) Evaluate(hasDiscoveredOnLink bool) bool {
	oldAdvertising := m.isAdvertising
	m.favoredDiscovered = hasDiscoveredOnLink

	if !m.hasLocalPrefix {
		m.isAdvertising = false
		return oldAdvertising != m.isAdvertising
	}

	// If another router is providing an on-link prefix, we should not
	// advertise ours.
	if hasDiscoveredOnLink {
		m.isAdvertising = false
	} else {
		m.isAdvertising = true
	}

	return oldAdvertising != m.isAdvertising
}

// GetLocalPrefix returns the locally generated on-link prefix bytes, prefix
// length, and whether a local prefix has been generated.
func (m *OnLinkPrefixManager) GetLocalPrefix() ([16]byte, uint8, bool) {
	return m.localPrefix, m.localPrefixLen, m.hasLocalPrefix
}

// ShouldAdvertise returns true if the local on-link prefix should currently
// be advertised in Router Advertisements.
func (m *OnLinkPrefixManager) ShouldAdvertise() bool {
	return m.isAdvertising
}

// IsAdvertising returns true if currently advertising.
func (m *OnLinkPrefixManager) IsAdvertising() bool {
	return m.isAdvertising
}

// SetAdvertising sets the advertising state.
func (m *OnLinkPrefixManager) SetAdvertising(advertising bool) {
	m.isAdvertising = advertising
}
