// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package bbr implements the DUA Manager and MLR Manager for Thread 1.2
// Backbone Border Router operation.
//
// This is a Go port of the DUA and MLR management from OpenThread's
// src/core/thread/dua_manager.{hpp,cpp} and
// src/core/thread/mlr_manager.{hpp,cpp}.
package bbr

import (
	"crypto/rand"
	"encoding/binary"
	"sync"

	"github.com/hilli/gothread/backbone"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// DUA Registration Status Codes (Thread 1.2 spec)
// ---------------------------------------------------------------------------

const (
	// DuaStatusSuccess indicates successful DUA registration.
	DuaStatusSuccess uint8 = 0
	// DuaStatusReRegister indicates registration accepted but immediate
	// re-registration is required.
	DuaStatusReRegister uint8 = 1
	// DuaStatusInvalid indicates the target EID is not a valid DUA (fatal).
	DuaStatusInvalid uint8 = 2
	// DuaStatusDuplicate indicates the DUA is already in use (fatal).
	DuaStatusDuplicate uint8 = 3
	// DuaStatusNoResources indicates BBR resource shortage (non-fatal).
	DuaStatusNoResources uint8 = 4
	// DuaStatusNotPrimary indicates the BBR is not primary (non-fatal).
	DuaStatusNotPrimary uint8 = 5
	// DuaStatusGeneralFailure indicates an unspecified failure (non-fatal).
	DuaStatusGeneralFailure uint8 = 6
)

// ---------------------------------------------------------------------------
// DUA Timing Constants
// ---------------------------------------------------------------------------

const (
	// duaDadPeriod is the DAD wait time for the DUA to become "Preferred" (seconds).
	duaDadPeriod uint32 = 100
	// duaNoBufDelay is the retry delay when message buffers are exhausted (seconds).
	duaNoBufDelay uint8 = 5
	// duaResponseTimeoutDelay is the retry delay after a response timeout (seconds).
	duaResponseTimeoutDelay uint8 = 30
	// duaNewRouterRegistrationDelay is the delay for new routers to establish links (seconds).
	duaNewRouterRegistrationDelay uint8 = 3
	// duaNewDuaRegistrationDelay is the delay for newly added DUA (seconds).
	duaNewDuaRegistrationDelay uint8 = 1
	// defaultMaxDadCounter is the default maximum DAD attempts before giving up.
	defaultMaxDadCounter uint8 = 3
)

// ---------------------------------------------------------------------------
// DuaState
// ---------------------------------------------------------------------------

// DuaState represents the registration state of a Domain Unicast Address.
type DuaState uint8

const (
	// DuaStateIdle indicates no DUA is configured.
	DuaStateIdle DuaState = iota
	// DuaStateToRegister indicates the DUA needs to be registered.
	DuaStateToRegister
	// DuaStateRegistering indicates a registration request is in progress.
	DuaStateRegistering
	// DuaStateRegistered indicates the DUA is successfully registered.
	DuaStateRegistered
)

// String returns a human-readable name for the DUA state.
func (s DuaState) String() string {
	switch s {
	case DuaStateIdle:
		return "Idle"
	case DuaStateToRegister:
		return "ToRegister"
	case DuaStateRegistering:
		return "Registering"
	case DuaStateRegistered:
		return "Registered"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// LeaderProvider interface
// ---------------------------------------------------------------------------

// LeaderProvider abstracts access to the Primary Backbone Router state.
// It is implemented by backbone.Leader (or a mock in tests).
type LeaderProvider interface {
	// HasPrimary reports whether a Primary BBR exists.
	HasPrimary() bool
	// GetConfig returns the current BBR configuration.
	GetConfig() backbone.Config
	// GetDomainPrefix returns the domain prefix and whether one is configured.
	GetDomainPrefix() (ip6.Prefix, bool)
	// IsDomainUnicast checks whether addr matches the domain prefix and is unicast.
	IsDomainUnicast(addr [16]byte) bool
}

// ---------------------------------------------------------------------------
// IIDGenerator interface
// ---------------------------------------------------------------------------

// IIDGenerator generates an Interface Identifier for a DUA.
// Implementations may use SLAAC semantics, fixed values, or random data.
type IIDGenerator interface {
	GenerateIID(prefix ip6.Prefix, dadCounter uint8) (ip6.InterfaceIdentifier, error)
}

// defaultIIDGenerator produces a random IID.
type defaultIIDGenerator struct{}

func (d *defaultIIDGenerator) GenerateIID(_ ip6.Prefix, _ uint8) (ip6.InterfaceIdentifier, error) {
	var iid ip6.InterfaceIdentifier
	if _, err := rand.Read(iid[:]); err != nil {
		return iid, errors.ErrFailed
	}
	// Clear the "universal" bit so the IID is locally administered, matching
	// how SLAAC-generated IIDs work for Thread DUA.
	iid[0] &^= 0x02
	return iid, nil
}

// ---------------------------------------------------------------------------
// DuaManager
// ---------------------------------------------------------------------------

// DuaManager handles Domain Unicast Address registration with the Primary
// Backbone Router.
type DuaManager struct {
	mu sync.Mutex

	state      DuaState
	duaAddress ip6.Address
	hasDua     bool

	lastRegistrationTime uint32 // seconds (monotonic counter)
	dadCounter           uint8
	maxDadCounter        uint8

	// Timing delays (seconds). Zero means "not active".
	registrationDelay   uint16
	reregistrationDelay uint16
	checkDelay          uint8

	// Dependencies (injected).
	leader       LeaderProvider
	iidGenerator IIDGenerator

	// fixedIID, if non-zero, overrides the generated IID.
	fixedIID    ip6.InterfaceIdentifier
	hasFixedIID bool

	// Elapsed time since the DUA was added (used for DAD period tracking).
	elapsedSinceAdd uint32
}

// ---------------------------------------------------------------------------
// Functional options
// ---------------------------------------------------------------------------

// DuaOption configures a DuaManager.
type DuaOption func(*DuaManager)

// WithLeaderProvider sets the LeaderProvider dependency.
func WithLeaderProvider(lp LeaderProvider) DuaOption {
	return func(m *DuaManager) { m.leader = lp }
}

// WithIIDGenerator sets a custom IID generator.
func WithIIDGenerator(g IIDGenerator) DuaOption {
	return func(m *DuaManager) { m.iidGenerator = g }
}

// WithMaxDadCounter sets the maximum DAD attempts.
func WithMaxDadCounter(n uint8) DuaOption {
	return func(m *DuaManager) { m.maxDadCounter = n }
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

// NewDuaManager creates a DuaManager with the given options.
func NewDuaManager(opts ...DuaOption) *DuaManager {
	m := &DuaManager{
		state:         DuaStateIdle,
		maxDadCounter: defaultMaxDadCounter,
		iidGenerator:  &defaultIIDGenerator{},
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

// GetState returns the current DUA registration state.
func (m *DuaManager) GetState() DuaState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// GetDuaAddress returns the current DUA and whether one is configured.
func (m *DuaManager) GetDuaAddress() ([16]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return [16]byte(m.duaAddress), m.hasDua
}

// ---------------------------------------------------------------------------
// Domain prefix / address management
// ---------------------------------------------------------------------------

// UpdateDomainUnicastAddress is called when network data changes. It
// generates (or regenerates) the DUA from the current domain prefix and the
// IID (fixed or generated).
func (m *DuaManager) UpdateDomainUnicastAddress() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.leader == nil {
		return
	}

	prefix, ok := m.leader.GetDomainPrefix()
	if !ok {
		m.removeDua()
		return
	}

	var addr ip6.Address
	prefixBytes := prefix.GetBytes()
	copy(addr[:], prefixBytes[:])

	if m.hasFixedIID {
		addr.SetIid(m.fixedIID)
	} else {
		iid, err := m.iidGenerator.GenerateIID(prefix, m.dadCounter)
		if err != nil {
			return
		}
		addr.SetIid(iid)
	}

	m.duaAddress = addr
	m.hasDua = true
	m.state = DuaStateToRegister
	m.elapsedSinceAdd = 0
	m.lastRegistrationTime = 0
}

// SetFixedIID sets a manually specified Interface Identifier for the DUA.
// Returns ErrInvalidArgs if the IID is all zeros (reserved).
func (m *DuaManager) SetFixedIID(iid ip6.InterfaceIdentifier) error {
	if iid == (ip6.InterfaceIdentifier{}) {
		return errors.ErrInvalidArgs
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fixedIID = iid
	m.hasFixedIID = true

	// If DUA already exists, regenerate it with the new IID.
	if m.hasDua {
		m.duaAddress.SetIid(iid)
		m.state = DuaStateToRegister
	}
	return nil
}

// ClearFixedIID removes the manually specified IID and regenerates the DUA.
func (m *DuaManager) ClearFixedIID() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.hasFixedIID {
		return
	}
	m.hasFixedIID = false
	m.fixedIID = ip6.InterfaceIdentifier{}

	if m.hasDua && m.leader != nil {
		prefix, ok := m.leader.GetDomainPrefix()
		if !ok {
			m.removeDua()
			return
		}
		iid, err := m.iidGenerator.GenerateIID(prefix, m.dadCounter)
		if err != nil {
			m.removeDua()
			return
		}
		m.duaAddress.SetIid(iid)
		m.state = DuaStateToRegister
	}
}

// removeDua is the internal helper that clears the DUA and resets state.
// Caller must hold mu.
func (m *DuaManager) removeDua() {
	m.hasDua = false
	m.duaAddress = ip6.Address{}
	m.state = DuaStateIdle
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

// Register starts the DUA registration process. It transitions the state
// from ToRegister to Registering. Returns an error if registration cannot
// proceed (no DUA, no BBR, wrong state, etc.).
func (m *DuaManager) Register() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.hasDua {
		return errors.ErrInvalidState
	}
	if m.leader == nil || !m.leader.HasPrimary() {
		return errors.ErrInvalidState
	}
	if m.state != DuaStateToRegister {
		return errors.ErrInvalidState
	}
	if m.registrationDelay > 0 {
		return errors.ErrBusy
	}

	m.state = DuaStateRegistering
	m.lastRegistrationTime = 0
	return nil
}

// HandleDuaResponse processes the status code from a DUA.rsp received from
// the BBR.
func (m *DuaManager) HandleDuaResponse(status uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch status {
	case DuaStatusSuccess:
		m.state = DuaStateRegistered
		m.lastRegistrationTime = 0
		m.elapsedSinceAdd = 0

	case DuaStatusReRegister:
		// Immediate re-registration required.
		if m.hasDua {
			m.state = DuaStateToRegister
		}

	case DuaStatusInvalid:
		// Fatal: domain prefix may be invalid.
		m.removeDua()

	case DuaStatusDuplicate:
		// Fatal: DUA collision. Increment DAD counter and regenerate.
		m.dadCounter++
		if m.dadCounter > m.maxDadCounter {
			m.removeDua()
			return
		}
		m.regenerateDua()

	case DuaStatusNoResources, DuaStatusNotPrimary, DuaStatusGeneralFailure:
		// Non-fatal: schedule re-registration.
		m.updateReregistrationDelay()
	}
}

// regenerateDua re-generates the DUA after a DAD collision.
// Caller must hold mu.
func (m *DuaManager) regenerateDua() {
	if m.leader == nil {
		m.removeDua()
		return
	}
	prefix, ok := m.leader.GetDomainPrefix()
	if !ok {
		m.removeDua()
		return
	}
	iid, err := m.iidGenerator.GenerateIID(prefix, m.dadCounter)
	if err != nil {
		m.removeDua()
		return
	}
	var addr ip6.Address
	prefixBytes := prefix.GetBytes()
	copy(addr[:], prefixBytes[:])
	addr.SetIid(iid)
	m.duaAddress = addr
	m.hasDua = true
	m.state = DuaStateToRegister
	m.elapsedSinceAdd = 0
}

// updateReregistrationDelay sets the reregistration delay based on the BBR config.
// Caller must hold mu.
func (m *DuaManager) updateReregistrationDelay() {
	if m.leader == nil {
		return
	}
	cfg := m.leader.GetConfig()
	delay := cfg.ReregistrationDelay
	if delay == 0 {
		delay = 1
	}

	// Pick a random value in [1, delay].
	chosen := randomUint16InRange(1, delay)

	if m.reregistrationDelay == 0 || chosen < m.reregistrationDelay {
		m.reregistrationDelay = chosen
	}

	if m.hasDua && m.state == DuaStateRegistering {
		m.state = DuaStateToRegister
	}
}

// ---------------------------------------------------------------------------
// BBR / Prefix Update Handlers
// ---------------------------------------------------------------------------

// HandleBackboneRouterPrimaryUpdate should be called when the Primary BBR
// changes. It triggers re-registration via the reregistration delay.
func (m *DuaManager) HandleBackboneRouterPrimaryUpdate(state backbone.LeaderState) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if state == backbone.LeaderStateAdded || state == backbone.LeaderStateToTriggerRereg {
		m.updateReregistrationDelay()
	}
}

// HandleDomainPrefixUpdate should be called when the domain prefix changes.
func (m *DuaManager) HandleDomainPrefixUpdate(event backbone.DomainPrefixEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch event {
	case backbone.DomainPrefixRemoved, backbone.DomainPrefixRefreshed:
		m.removeDua()
		if event == backbone.DomainPrefixRemoved {
			return
		}
		// For refreshed, fall through to re-generate below.
		fallthrough
	case backbone.DomainPrefixAdded, backbone.DomainPrefixUnchanged:
		if m.leader == nil {
			return
		}
		prefix, ok := m.leader.GetDomainPrefix()
		if !ok {
			return
		}
		var addr ip6.Address
		prefixBytes := prefix.GetBytes()
		copy(addr[:], prefixBytes[:])

		if m.hasFixedIID {
			addr.SetIid(m.fixedIID)
		} else {
			iid, err := m.iidGenerator.GenerateIID(prefix, m.dadCounter)
			if err != nil {
				return
			}
			addr.SetIid(iid)
		}
		m.duaAddress = addr
		m.hasDua = true
		m.state = DuaStateToRegister
		m.elapsedSinceAdd = 0
	}
}

// ---------------------------------------------------------------------------
// Timer
// ---------------------------------------------------------------------------

// HandleTimer should be called once per second. It decrements delay counters
// and returns true when registration should be attempted.
func (m *DuaManager) HandleTimer() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	attempt := false

	if m.hasDua {
		m.elapsedSinceAdd++
	}

	if m.registrationDelay > 0 {
		m.registrationDelay--
		if m.registrationDelay == 0 {
			attempt = true
		}
	}

	if m.checkDelay > 0 {
		m.checkDelay--
		if m.checkDelay == 0 {
			attempt = true
		}
	}

	if m.reregistrationDelay > 0 {
		m.reregistrationDelay--
		if m.reregistrationDelay == 0 {
			if m.hasDua && m.state != DuaStateIdle {
				m.state = DuaStateToRegister
			}
			attempt = true
		}
	}

	return attempt
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// randomUint16InRange returns a random uint16 in [min, max]. If min >= max
// it returns min.
func randomUint16InRange(min, max uint16) uint16 {
	if min >= max {
		return min
	}
	var buf [2]byte
	_, _ = rand.Read(buf[:])
	v := binary.LittleEndian.Uint16(buf[:])
	return min + v%(max-min+1)
}
