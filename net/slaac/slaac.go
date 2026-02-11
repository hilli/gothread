// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package slaac implements IPv6 Stateless Address Autoconfiguration (SLAAC)
// for Thread networks.
//
// It generates and manages global unicast addresses from on-mesh prefixes
// advertised in Thread Network Data. Interface Identifiers are generated
// using SHA-256 per RFC 7217 (Semantically Opaque IIDs).
//
// This is a Go port of the SLAAC address management in OpenThread's
// src/core/utils/slaac_address.hpp and src/core/utils/slaac_address.cpp.
package slaac

import (
	"github.com/hilli/gothread/crypto/sha256"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// DefaultMaxAddresses is the default maximum number of SLAAC addresses the
// manager will maintain simultaneously.
const DefaultMaxAddresses = 4

// MaxDADCounter is the maximum value of the DAD (Duplicate Address Detection)
// counter before address generation is considered failed.
const MaxDADCounter = 255

// ---------------------------------------------------------------------------
// Prefix flags (from Thread Network Data border router entries)
// ---------------------------------------------------------------------------

const (
	// FlagOnMesh indicates the prefix is on-mesh.
	FlagOnMesh uint8 = 1 << 0
	// FlagSlaac indicates SLAAC addresses should be generated for this prefix.
	FlagSlaac uint8 = 1 << 1
	// FlagDhcp indicates DHCPv6 is available for this prefix.
	FlagDhcp uint8 = 1 << 2
	// FlagConfigure indicates DHCPv6 is available for other configuration.
	FlagConfigure uint8 = 1 << 3
	// FlagDefaultRoute indicates the prefix should be used as a default route.
	FlagDefaultRoute uint8 = 1 << 4
	// FlagPreferred indicates the prefix is preferred for source address
	// selection.
	FlagPreferred uint8 = 1 << 5
)

// ---------------------------------------------------------------------------
// Prefix — on-mesh prefix descriptor
// ---------------------------------------------------------------------------

// Prefix describes an on-mesh prefix from Thread Network Data along with the
// flags that control how it should be used.
type Prefix struct {
	Prefix [16]byte
	Length uint8
	Flags  uint8
}

// HasFlag returns true if the given flag bit is set.
func (p Prefix) HasFlag(flag uint8) bool {
	return (p.Flags & flag) != 0
}

// IsSlaacAllowed returns true if this prefix should generate SLAAC addresses
// (OnMesh + Slaac flags set, DHCP flag not set).
func (p Prefix) IsSlaacAllowed() bool {
	return p.HasFlag(FlagOnMesh) && p.HasFlag(FlagSlaac) && !p.HasFlag(FlagDhcp)
}

// toIP6Prefix converts a slaac.Prefix to an ip6.Prefix for address matching.
func (p Prefix) toIP6Prefix() ip6.Prefix {
	return ip6.NewPrefix(p.Prefix, p.Length)
}

// prefixesMatch returns true if two prefixes have the same prefix bytes
// (up to the prefix length) and the same length.
func prefixesMatch(a, b Prefix) bool {
	return a.toIP6Prefix().IsEqual(b.toIP6Prefix())
}

// ---------------------------------------------------------------------------
// SlaacAddress — a generated SLAAC address
// ---------------------------------------------------------------------------

// SlaacAddress represents a SLAAC-generated IPv6 address.
type SlaacAddress struct {
	// Address is the full 128-bit IPv6 address.
	Address ip6.Address
	// Prefix is the on-mesh prefix this address was generated from.
	Prefix Prefix
	// Valid indicates whether this address entry is in use.
	Valid bool
	// DadCounter is the Duplicate Address Detection attempt counter used
	// during IID generation.
	DadCounter uint8
}

// ---------------------------------------------------------------------------
// IIDGenerator — interface for generating Interface Identifiers
// ---------------------------------------------------------------------------

// IIDGenerator generates 64-bit Interface Identifiers for SLAAC addresses.
type IIDGenerator interface {
	// GenerateIID produces an 8-byte IID for the given prefix and DAD
	// counter. Implementations should return a deterministic but
	// unpredictable IID per RFC 7217.
	GenerateIID(prefix [16]byte, prefixLen uint8, dadCounter uint8) ([8]byte, error)
}

// ---------------------------------------------------------------------------
// DefaultIIDGenerator — SHA-256 based IID generation per RFC 7217
// ---------------------------------------------------------------------------

// DefaultIIDGenerator produces semantically opaque Interface Identifiers
// using SHA-256 as described in RFC 7217.
type DefaultIIDGenerator struct {
	secretKey [32]byte
	extAddr   [8]byte
}

// NewDefaultIIDGenerator creates a new IID generator with the given secret
// key and extended MAC address.
func NewDefaultIIDGenerator(secretKey [32]byte, extAddr [8]byte) *DefaultIIDGenerator {
	return &DefaultIIDGenerator{
		secretKey: secretKey,
		extAddr:   extAddr,
	}
}

// GenerateIID computes an IID by hashing:
//
//	SHA-256(prefix || extAddr || dadCounter || secretKey)
//
// The first 8 bytes of the hash are taken as the IID, with bit 6
// (the universal/local bit) of the first byte cleared to indicate a
// locally-administered identifier.
func (g *DefaultIIDGenerator) GenerateIID(prefix [16]byte, prefixLen uint8, dadCounter uint8) ([8]byte, error) {
	var hasher sha256.Sha256
	hasher.Start()
	hasher.Update(prefix[:])
	hasher.Update([]byte{prefixLen})
	hasher.Update(g.extAddr[:])
	hasher.Update([]byte{dadCounter})
	hasher.Update(g.secretKey[:])

	var hash sha256.Hash
	hasher.Finish(&hash)

	var iid [8]byte
	copy(iid[:], hash[:8])

	// Clear bit 6 (universal/local bit) in the first byte.
	// Bit 6 is 0x02 in network byte order.
	iid[0] &^= 0x02

	return iid, nil
}

// ---------------------------------------------------------------------------
// Option — functional options for Manager
// ---------------------------------------------------------------------------

// Option configures a Manager.
type Option func(*Manager)

// WithMaxAddresses sets the maximum number of SLAAC addresses the manager
// will maintain. Values less than 1 are clamped to 1.
func WithMaxAddresses(n int) Option {
	return func(m *Manager) {
		if n < 1 {
			n = 1
		}
		m.maxAddresses = n
		// Resize the backing slice if needed.
		if len(m.addresses) < n {
			grown := make([]SlaacAddress, n)
			copy(grown, m.addresses)
			m.addresses = grown
		} else {
			m.addresses = m.addresses[:n]
		}
	}
}

// WithIIDGenerator overrides the IID generator used by the manager.
func WithIIDGenerator(gen IIDGenerator) Option {
	return func(m *Manager) {
		m.iidGenerator = gen
	}
}

// ---------------------------------------------------------------------------
// Manager — SLAAC address manager
// ---------------------------------------------------------------------------

// Manager manages SLAAC addresses derived from on-mesh prefixes in the
// Thread Network Data.
type Manager struct {
	addresses    []SlaacAddress
	maxAddresses int
	iidGenerator IIDGenerator
	enabled      bool
}

// NewManager creates a new SLAAC address manager. A non-nil IIDGenerator
// must be provided. Additional behaviour can be configured via options.
func NewManager(generator IIDGenerator, opts ...Option) *Manager {
	m := &Manager{
		maxAddresses: DefaultMaxAddresses,
		iidGenerator: generator,
		enabled:      false,
	}
	m.addresses = make([]SlaacAddress, m.maxAddresses)
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Enable enables SLAAC address generation.
func (m *Manager) Enable() {
	m.enabled = true
}

// Disable disables SLAAC address generation and removes all existing
// SLAAC addresses.
func (m *Manager) Disable() {
	m.enabled = false
	for i := range m.addresses {
		m.addresses[i] = SlaacAddress{}
	}
}

// IsEnabled returns true if the manager is enabled.
func (m *Manager) IsEnabled() bool {
	return m.enabled
}

// Update is called when the Thread Network Data changes. It adds SLAAC
// addresses for new on-mesh prefixes that have the SLAAC flag set, and
// removes addresses whose prefixes are no longer present.
func (m *Manager) Update(prefixes []Prefix) {
	if !m.enabled {
		return
	}

	// Step 1: Remove addresses whose prefix is no longer in the list.
	m.removeStale(prefixes)

	// Step 2: Add addresses for new SLAAC-eligible prefixes.
	for _, p := range prefixes {
		if !p.IsSlaacAllowed() {
			continue
		}
		if m.hasPrefixAddress(p) {
			continue
		}
		m.addAddress(p)
	}
}

// GetAddresses returns a slice of all valid SLAAC addresses.
func (m *Manager) GetAddresses() []SlaacAddress {
	var result []SlaacAddress
	for i := range m.addresses {
		if m.addresses[i].Valid {
			result = append(result, m.addresses[i])
		}
	}
	return result
}

// FindAddress looks up a SLAAC address matching the given prefix bytes and
// length. Returns the address and true if found, or a zero SlaacAddress
// and false otherwise.
func (m *Manager) FindAddress(prefix [16]byte, prefixLen uint8) (SlaacAddress, bool) {
	target := Prefix{Prefix: prefix, Length: prefixLen}
	for i := range m.addresses {
		if m.addresses[i].Valid && prefixesMatch(m.addresses[i].Prefix, target) {
			return m.addresses[i], true
		}
	}
	return SlaacAddress{}, false
}

// SignalDADFailure is called when Duplicate Address Detection fails for a
// SLAAC address. It increments the DAD counter and regenerates the IID.
// Returns errors.ErrNotFound if no matching address exists, or
// errors.ErrFailed if the DAD counter has been exhausted.
func (m *Manager) SignalDADFailure(prefix [16]byte, prefixLen uint8) error {
	target := Prefix{Prefix: prefix, Length: prefixLen}
	for i := range m.addresses {
		if !m.addresses[i].Valid {
			continue
		}
		if !prefixesMatch(m.addresses[i].Prefix, target) {
			continue
		}

		if m.addresses[i].DadCounter >= MaxDADCounter {
			// Exhausted DAD retries; remove the address.
			m.addresses[i] = SlaacAddress{}
			return errors.ErrFailed
		}

		m.addresses[i].DadCounter++
		addr, err := m.generateAddress(m.addresses[i].Prefix, m.addresses[i].DadCounter)
		if err != nil {
			m.addresses[i] = SlaacAddress{}
			return errors.ErrFailed
		}
		m.addresses[i].Address = addr
		return nil
	}
	return errors.ErrNotFound
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// removeStale invalidates addresses whose prefix is no longer present in
// the given prefix list (or no longer SLAAC-eligible).
func (m *Manager) removeStale(prefixes []Prefix) {
	for i := range m.addresses {
		if !m.addresses[i].Valid {
			continue
		}
		if !m.prefixStillPresent(m.addresses[i].Prefix, prefixes) {
			m.addresses[i] = SlaacAddress{}
		}
	}
}

// prefixStillPresent returns true if a matching SLAAC-eligible prefix
// exists in the list.
func (m *Manager) prefixStillPresent(p Prefix, prefixes []Prefix) bool {
	for _, candidate := range prefixes {
		if candidate.IsSlaacAllowed() && prefixesMatch(p, candidate) {
			return true
		}
	}
	return false
}

// hasPrefixAddress returns true if there is already a valid address for
// the given prefix.
func (m *Manager) hasPrefixAddress(p Prefix) bool {
	for i := range m.addresses {
		if m.addresses[i].Valid && prefixesMatch(m.addresses[i].Prefix, p) {
			return true
		}
	}
	return false
}

// addAddress generates and stores a SLAAC address for the given prefix.
// If no free slot is available the prefix is silently skipped.
func (m *Manager) addAddress(p Prefix) {
	idx := m.findFreeSlot()
	if idx < 0 {
		return // No room.
	}

	addr, err := m.generateAddress(p, 0)
	if err != nil {
		return
	}

	m.addresses[idx] = SlaacAddress{
		Address:    addr,
		Prefix:     p,
		Valid:      true,
		DadCounter: 0,
	}
}

// findFreeSlot returns the index of the first unused address slot, or -1
// if all slots are occupied.
func (m *Manager) findFreeSlot() int {
	for i := range m.addresses {
		if !m.addresses[i].Valid {
			return i
		}
	}
	return -1
}

// generateAddress combines a prefix with a generated IID to produce a
// full 128-bit IPv6 address.
func (m *Manager) generateAddress(p Prefix, dadCounter uint8) (ip6.Address, error) {
	iid, err := m.iidGenerator.GenerateIID(p.Prefix, p.Length, dadCounter)
	if err != nil {
		return ip6.Address{}, err
	}

	var addr ip6.Address

	// Copy prefix bits into the address.
	fullBytes := int(p.Length) / 8
	for i := 0; i < fullBytes && i < 16; i++ {
		addr[i] = p.Prefix[i]
	}
	// Handle partial byte at the boundary.
	remainBits := p.Length % 8
	if remainBits > 0 && fullBytes < 16 {
		mask := byte(0xff << (8 - remainBits))
		addr[fullBytes] = (p.Prefix[fullBytes] & mask) | (iid[fullBytes-fullBytes] & ^mask)
	}

	// Copy IID into the last 8 bytes. For a /64 prefix (the common case)
	// this fills bytes 8-15. For shorter prefixes the IID bits that fall
	// within the prefix range are overridden by the prefix above.
	copy(addr[8:], iid[:])

	return addr, nil
}
