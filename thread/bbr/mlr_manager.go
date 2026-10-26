// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package bbr

import (
	"sync"

	"github.com/hilli/gothread/backbone"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// MLR Registration Status Codes (Thread 1.2 spec)
// ---------------------------------------------------------------------------

const (
	// MlrStatusSuccess indicates successful MLR registration.
	MlrStatusSuccess uint8 = 0
	// MlrStatusInvalid indicates the address is not a valid multicast address (fatal).
	MlrStatusInvalid uint8 = 2
	// MlrStatusNoResources indicates BBR resource shortage (non-fatal).
	MlrStatusNoResources uint8 = 4
	// MlrStatusNotPrimary indicates the BBR is not primary (non-fatal).
	MlrStatusNotPrimary uint8 = 5
	// MlrStatusGeneralFailure indicates an unspecified failure (non-fatal).
	MlrStatusGeneralFailure uint8 = 6
)

// ---------------------------------------------------------------------------
// Default limits
// ---------------------------------------------------------------------------

const (
	// defaultMaxMlrEntries is the default maximum number of tracked multicast
	// addresses.
	defaultMaxMlrEntries = 15
)

// ---------------------------------------------------------------------------
// MlrState
// ---------------------------------------------------------------------------

// MlrState represents the registration state of a multicast address entry.
type MlrState uint8

const (
	// MlrStateIdle indicates no registration action is needed.
	MlrStateIdle MlrState = iota
	// MlrStateToRegister indicates the address needs to be registered.
	MlrStateToRegister
	// MlrStateRegistering indicates a registration request is in progress.
	MlrStateRegistering
	// MlrStateRegistered indicates the address is successfully registered.
	MlrStateRegistered
)

// String returns a human-readable name for the MLR state.
func (s MlrState) String() string {
	switch s {
	case MlrStateIdle:
		return "Idle"
	case MlrStateToRegister:
		return "ToRegister"
	case MlrStateRegistering:
		return "Registering"
	case MlrStateRegistered:
		return "Registered"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// MlrEntry
// ---------------------------------------------------------------------------

// MlrEntry tracks a single multicast address and its registration state.
type MlrEntry struct {
	Address ip6.Address
	State   MlrState
	Timeout uint32 // MLR timeout in seconds from the BBR config
}

// ---------------------------------------------------------------------------
// ChildMulticastInfo — for FTD aggregation
// ---------------------------------------------------------------------------

// ChildMulticastInfo describes multicast addresses belonging to a child.
type ChildMulticastInfo struct {
	ChildID   uint16
	Addresses []ip6.Address
}

// ---------------------------------------------------------------------------
// MlrManager
// ---------------------------------------------------------------------------

// MlrManager handles Multicast Listener Registration with the Primary
// Backbone Router.
type MlrManager struct {
	mu sync.Mutex

	entries    []MlrEntry
	maxEntries int
	leader     LeaderProvider

	// Registration tracking.
	pendingAddresses    [][16]byte
	reregistrationDelay uint32
	sendDelay           uint16
	mlrPending          bool

	// FTD aggregation: child-to-multicast address mapping.
	childMulticast []ChildMulticastInfo
}

// ---------------------------------------------------------------------------
// Functional options
// ---------------------------------------------------------------------------

// MlrOption configures an MlrManager.
type MlrOption func(*MlrManager)

// WithMaxEntries sets the maximum number of tracked multicast addresses.
func WithMaxEntries(n int) MlrOption {
	return func(m *MlrManager) {
		if n > 0 {
			m.maxEntries = n
		}
	}
}

// WithMlrLeaderProvider sets the LeaderProvider dependency.
func WithMlrLeaderProvider(lp LeaderProvider) MlrOption {
	return func(m *MlrManager) { m.leader = lp }
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

// NewMlrManager creates an MlrManager with the given options.
func NewMlrManager(opts ...MlrOption) *MlrManager {
	m := &MlrManager{
		maxEntries: defaultMaxMlrEntries,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// ---------------------------------------------------------------------------
// Address management
// ---------------------------------------------------------------------------

// AddAddress adds a multicast address to track. The address must be multicast
// with scope larger than realm-local (scope > 3). Returns:
//   - ErrInvalidArgs if the address is not a valid larger-than-realm-local multicast address
//   - ErrAlready     if the address is already tracked
//   - ErrNoBufs      if the entry table is full
func (m *MlrManager) AddAddress(addr [16]byte) error {
	a := ip6.Address(addr)
	if !a.IsMulticast() || a.GetScope() <= 3 {
		return errors.ErrInvalidArgs
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.entries {
		if m.entries[i].Address == a {
			return errors.ErrAlready
		}
	}
	if len(m.entries) >= m.maxEntries {
		return errors.ErrNoBufs
	}

	timeout := uint32(0)
	if m.leader != nil {
		timeout = m.leader.GetConfig().MlrTimeout
	}

	m.entries = append(m.entries, MlrEntry{
		Address: a,
		State:   MlrStateToRegister,
		Timeout: timeout,
	})
	return nil
}

// RemoveAddress stops tracking the given multicast address.
func (m *MlrManager) RemoveAddress(addr [16]byte) {
	a := ip6.Address(addr)
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.entries {
		if m.entries[i].Address == a {
			m.entries = append(m.entries[:i], m.entries[i+1:]...)
			return
		}
	}
}

// GetRegisteredAddresses returns a slice of addresses that are currently
// in the MlrStateRegistered state.
func (m *MlrManager) GetRegisteredAddresses() [][16]byte {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result [][16]byte
	for _, e := range m.entries {
		if e.State == MlrStateRegistered {
			result = append(result, [16]byte(e.Address))
		}
	}
	return result
}

// GetEntries returns a copy of all tracked MLR entries. This is useful for
// testing and inspection.
func (m *MlrManager) GetEntries() []MlrEntry {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]MlrEntry, len(m.entries))
	copy(out, m.entries)
	return out
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

// UpdateRegistration checks all tracked multicast addresses and collects
// those in ToRegister state for registration. Returns the list of addresses
// that should be sent in an MLR.req message. Transitions them to
// MlrStateRegistering.
func (m *MlrManager) UpdateRegistration() [][16]byte {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.mlrPending {
		return nil
	}
	if m.leader == nil || !m.leader.HasPrimary() {
		return nil
	}

	var addrs [][16]byte
	for i := range m.entries {
		if m.entries[i].State == MlrStateToRegister {
			addrs = append(addrs, [16]byte(m.entries[i].Address))
			m.entries[i].State = MlrStateRegistering
		}
	}
	if len(addrs) > 0 {
		m.pendingAddresses = addrs
		m.mlrPending = true
	}
	return addrs
}

// RegisterMulticastListeners initiates an MLR.req with the given addresses.
// Returns ErrInvalidArgs if addresses is empty, ErrBusy if a registration is
// already in progress, or ErrInvalidState if no Primary BBR exists.
func (m *MlrManager) RegisterMulticastListeners(addresses [][16]byte) error {
	if len(addresses) == 0 {
		return errors.ErrInvalidArgs
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.mlrPending {
		return errors.ErrBusy
	}
	if m.leader == nil || !m.leader.HasPrimary() {
		return errors.ErrInvalidState
	}

	// Transition matching entries to Registering.
	matched := 0
	for _, addr := range addresses {
		a := ip6.Address(addr)
		for i := range m.entries {
			if m.entries[i].Address == a {
				m.entries[i].State = MlrStateRegistering
				matched++
				break
			}
		}
	}
	if matched == 0 {
		return errors.ErrNotFound
	}

	m.pendingAddresses = make([][16]byte, len(addresses))
	copy(m.pendingAddresses, addresses)
	m.mlrPending = true
	return nil
}

// HandleMlrResponse processes the status code and failed addresses from an
// MLR.rsp received from the BBR.
func (m *MlrManager) HandleMlrResponse(status uint8, failedAddresses [][16]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.mlrPending = false

	failedSet := make(map[[16]byte]bool, len(failedAddresses))
	for _, fa := range failedAddresses {
		failedSet[fa] = true
	}

	for i := range m.entries {
		if m.entries[i].State != MlrStateRegistering {
			continue
		}

		addrKey := [16]byte(m.entries[i].Address)

		if status == MlrStatusSuccess && !failedSet[addrKey] {
			m.entries[i].State = MlrStateRegistered
			if m.leader != nil {
				m.entries[i].Timeout = m.leader.GetConfig().MlrTimeout
			}
		} else {
			m.entries[i].State = MlrStateToRegister
		}
	}

	m.pendingAddresses = nil

	// On failure, schedule re-registration.
	if status != MlrStatusSuccess {
		m.scheduleReregistration()
	}
}

// scheduleReregistration sets the reregistration delay from the BBR config.
// Caller must hold mu.
func (m *MlrManager) scheduleReregistration() {
	if m.leader == nil {
		return
	}
	cfg := m.leader.GetConfig()
	delay := cfg.ReregistrationDelay
	if delay == 0 {
		delay = 1
	}
	chosen := uint32(randomUint16InRange(1, delay))
	if m.reregistrationDelay == 0 || chosen < m.reregistrationDelay {
		m.reregistrationDelay = chosen
	}
}

// ---------------------------------------------------------------------------
// BBR Update Handler
// ---------------------------------------------------------------------------

// HandleBackboneRouterPrimaryUpdate should be called when the Primary BBR
// changes. When a new BBR is added or a re-registration trigger occurs, all
// registered addresses are reset to ToRegister.
func (m *MlrManager) HandleBackboneRouterPrimaryUpdate(state backbone.LeaderState) {
	m.mu.Lock()
	defer m.mu.Unlock()

	needRereg := state == backbone.LeaderStateAdded || state == backbone.LeaderStateToTriggerRereg

	if needRereg {
		// Reset all registered addresses to ToRegister.
		for i := range m.entries {
			if m.entries[i].State == MlrStateRegistered {
				m.entries[i].State = MlrStateToRegister
			}
		}
		m.scheduleReregistration()
	}
}

// ---------------------------------------------------------------------------
// Timer
// ---------------------------------------------------------------------------

// HandleTimer should be called once per second. It decrements delay counters
// and returns true when a registration attempt should be made.
func (m *MlrManager) HandleTimer() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	attempt := false

	if m.sendDelay > 0 {
		m.sendDelay--
		if m.sendDelay == 0 {
			attempt = true
		}
	}

	if m.reregistrationDelay > 0 {
		m.reregistrationDelay--
		if m.reregistrationDelay == 0 {
			// Mark all registered addresses for re-registration.
			for i := range m.entries {
				if m.entries[i].State == MlrStateRegistered {
					m.entries[i].State = MlrStateToRegister
				}
			}
			attempt = true
		}
	}

	return attempt
}

// ---------------------------------------------------------------------------
// FTD Aggregation (Child Multicast)
// ---------------------------------------------------------------------------

// AddChildMulticast registers multicast addresses belonging to a child.
// New addresses that are not already tracked are added to the entry table
// (subject to the max entries limit). Addresses already registered are
// marked as such for the child.
func (m *MlrManager) AddChildMulticast(childID uint16, addresses []ip6.Address) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store the child-to-address mapping.
	found := false
	for i := range m.childMulticast {
		if m.childMulticast[i].ChildID == childID {
			m.childMulticast[i].Addresses = addresses
			found = true
			break
		}
	}
	if !found {
		m.childMulticast = append(m.childMulticast, ChildMulticastInfo{
			ChildID:   childID,
			Addresses: addresses,
		})
	}

	// Ensure every child address is tracked.
	for _, addr := range addresses {
		if !addr.IsMulticast() || addr.GetScope() <= 3 {
			continue
		}
		tracked := false
		for j := range m.entries {
			if m.entries[j].Address == addr {
				tracked = true
				break
			}
		}
		if !tracked && len(m.entries) < m.maxEntries {
			timeout := uint32(0)
			if m.leader != nil {
				timeout = m.leader.GetConfig().MlrTimeout
			}
			m.entries = append(m.entries, MlrEntry{
				Address: addr,
				State:   MlrStateToRegister,
				Timeout: timeout,
			})
		}
	}
}

// RemoveChildMulticast removes the multicast address associations for a child.
// Addresses that are no longer referenced by any child (and were not added
// directly) may be cleaned up by the caller.
func (m *MlrManager) RemoveChildMulticast(childID uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var removed []ip6.Address
	for i := range m.childMulticast {
		if m.childMulticast[i].ChildID == childID {
			removed = m.childMulticast[i].Addresses
			m.childMulticast = append(m.childMulticast[:i], m.childMulticast[i+1:]...)
			break
		}
	}

	// For each removed address, check if any other child still references it.
	for _, addr := range removed {
		stillReferenced := false
		for _, ci := range m.childMulticast {
			for _, ca := range ci.Addresses {
				if ca == addr {
					stillReferenced = true
					break
				}
			}
			if stillReferenced {
				break
			}
		}
		if !stillReferenced {
			// Remove from entries.
			for j := range m.entries {
				if m.entries[j].Address == addr {
					m.entries = append(m.entries[:j], m.entries[j+1:]...)
					break
				}
			}
		}
	}
}

// GetChildMulticast returns the multicast addresses associated with a child.
func (m *MlrManager) GetChildMulticast(childID uint16) []ip6.Address {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, ci := range m.childMulticast {
		if ci.ChildID == childID {
			out := make([]ip6.Address, len(ci.Addresses))
			copy(out, ci.Addresses)
			return out
		}
	}
	return nil
}
