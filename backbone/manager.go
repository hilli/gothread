// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package backbone

// Manager coordinates the Backbone Router subsystem: Leader tracking,
// Local service management, Multicast Listener Registration (MLR),
// DUA registration (ND proxy), and Backbone Query/Answer handling.
//
// This is a Go port of the Manager from
// OpenThread's src/core/backbone_router/bbr_manager.{hpp,cpp}.

import (
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// MLR status codes
// ---------------------------------------------------------------------------

const (
	// MlrStatusSuccess indicates the MLR was successful.
	MlrStatusSuccess uint8 = 0
	// MlrStatusInvalid indicates an invalid MLR request.
	MlrStatusInvalid uint8 = 2
	// MlrStatusNoResources indicates the server has no resources.
	MlrStatusNoResources uint8 = 4
	// MlrStatusNotPrimary indicates this device is not the Primary BBR.
	MlrStatusNotPrimary uint8 = 5
	// MlrStatusGeneralFailure indicates a general MLR failure.
	MlrStatusGeneralFailure uint8 = 6
)

// ---------------------------------------------------------------------------
// DUA status codes
// ---------------------------------------------------------------------------

const (
	// DuaStatusSuccess indicates the DUA registration was successful.
	DuaStatusSuccess uint8 = 0
	// DuaStatusReregistration indicates re-registration is required.
	DuaStatusReregistration uint8 = 1
	// DuaStatusInvalid indicates an invalid DUA request.
	DuaStatusInvalid uint8 = 2
	// DuaStatusDuplicateAddress indicates the DUA is already in use.
	DuaStatusDuplicateAddress uint8 = 3
	// DuaStatusNoResources indicates the server has no resources.
	DuaStatusNoResources uint8 = 4
	// DuaStatusNotPrimary indicates this device is not the Primary BBR.
	DuaStatusNotPrimary uint8 = 5
	// DuaStatusGeneralFailure indicates a general DUA failure.
	DuaStatusGeneralFailure uint8 = 6
)

// ---------------------------------------------------------------------------
// BackboneAnswer
// ---------------------------------------------------------------------------

// BackboneAnswer carries the response to a Backbone Query.
type BackboneAnswer struct {
	TargetIid       [8]byte
	MeshLocalIid    [8]byte
	TimeSinceLastTx uint32
	Rloc16          uint16
}

// ---------------------------------------------------------------------------
// ManagerDeps
// ---------------------------------------------------------------------------

// ManagerDeps provides the external dependencies that the Manager requires.
type ManagerDeps interface {
	// GetRloc16 returns this device's RLOC16.
	GetRloc16() uint16
	// IsPrimary reports whether this device is the Primary BBR.
	IsPrimary() bool
	// GetDomainPrefix returns the current domain prefix and whether one is set.
	GetDomainPrefix() (ip6.Prefix, bool)
}

// ---------------------------------------------------------------------------
// ManagerOption
// ---------------------------------------------------------------------------

// ManagerOption configures a Manager.
type ManagerOption func(*Manager)

// WithManagerLeaderCallbacks sets the LeaderCallbacks on the Manager's Leader.
func WithManagerLeaderCallbacks(cb LeaderCallbacks) ManagerOption {
	return func(m *Manager) {
		m.leaderCallbacks = cb
	}
}

// WithManagerLocalCallbacks sets the LocalCallbacks on the Manager's Local.
func WithManagerLocalCallbacks(cb LocalCallbacks) ManagerOption {
	return func(m *Manager) {
		m.localCallbacks = cb
	}
}

// WithManagerListenerOptions passes options through to the MulticastListenersTable.
func WithManagerListenerOptions(opts ...ListenerOption) ManagerOption {
	return func(m *Manager) {
		m.listenerOpts = opts
	}
}

// WithManagerNdProxyOptions passes options through to the NdProxyTable.
func WithManagerNdProxyOptions(opts ...NdProxyOption) ManagerOption {
	return func(m *Manager) {
		m.ndProxyOpts = opts
	}
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

// Manager coordinates the Backbone Router subsystem.
type Manager struct {
	leader    *Leader
	local     *Local
	listeners *MulticastListenersTable
	ndproxy   *NdProxyTable
	deps      ManagerDeps
	running   bool

	// Options collected before sub-component creation.
	leaderCallbacks LeaderCallbacks
	localCallbacks  LocalCallbacks
	listenerOpts    []ListenerOption
	ndProxyOpts     []NdProxyOption
}

// NewManager creates a new Manager with the given dependencies and options.
// All sub-components (Leader, Local, MulticastListenersTable, NdProxyTable)
// are created during construction.
func NewManager(deps ManagerDeps, opts ...ManagerOption) *Manager {
	m := &Manager{
		deps: deps,
	}

	for _, o := range opts {
		o(m)
	}

	m.leader = NewLeader(m.leaderCallbacks)
	m.local = NewLocal(m.localCallbacks)
	m.listeners = NewMulticastListenersTable(m.listenerOpts...)
	m.ndproxy = NewNdProxyTable(m.ndProxyOpts...)

	return m
}

// GetLeader returns the Leader sub-component.
func (m *Manager) GetLeader() *Leader {
	return m.leader
}

// GetLocal returns the Local sub-component.
func (m *Manager) GetLocal() *Local {
	return m.local
}

// GetMulticastListenersTable returns the multicast listeners table.
func (m *Manager) GetMulticastListenersTable() *MulticastListenersTable {
	return m.listeners
}

// GetNdProxyTable returns the ND proxy table.
func (m *Manager) GetNdProxyTable() *NdProxyTable {
	return m.ndproxy
}

// IsRunning reports whether the Manager has been started.
func (m *Manager) IsRunning() bool {
	return m.running
}

// Start activates the Manager. If the local BBR is not already enabled,
// Start enables it.
func (m *Manager) Start() {
	if m.running {
		return
	}
	m.running = true
	if !m.local.IsEnabled() {
		m.local.SetEnabled(true)
	}
}

// Stop deactivates the Manager and clears all tables.
func (m *Manager) Stop() {
	if !m.running {
		return
	}
	m.running = false
	m.local.SetEnabled(false)
	m.listeners.Clear()
	m.ndproxy.Clear()
	m.leader.Reset()
}

// HandleTimer processes time-dependent state: expires multicast listeners
// and progresses ND proxy DAD.
func (m *Manager) HandleTimer(nowMs int64) {
	m.listeners.Expire(nowMs)
	m.ndproxy.HandleTimer(nowMs)
}

// HandleMulticastListenerRegistration processes an MLR request containing
// one or more multicast addresses. It returns the list of addresses that
// failed to register and the overall status code.
//
// Addresses are registered with an expiry of nowMs + timeoutSec*1000.
// If timeoutSec is 0, the address is removed from the table.
func (m *Manager) HandleMulticastListenerRegistration(addresses [][16]byte, timeoutSec uint32, nowMs int64) (failedAddrs [][16]byte, status uint8) {
	if !m.deps.IsPrimary() {
		return addresses, MlrStatusNotPrimary
	}

	if len(addresses) == 0 {
		return nil, MlrStatusInvalid
	}

	var failed [][16]byte

	for _, addr := range addresses {
		if timeoutSec == 0 {
			// Timeout of 0 means removal.
			_ = m.listeners.Remove(addr)
			continue
		}

		expireMs := nowMs + int64(timeoutSec)*1000
		if err := m.listeners.Add(addr, expireMs); err != nil {
			failed = append(failed, addr)
		}
	}

	if len(failed) > 0 {
		return failed, MlrStatusNoResources
	}
	return nil, MlrStatusSuccess
}

// HandleDuaRegistration processes a DUA registration request and returns
// the status code.
func (m *Manager) HandleDuaRegistration(targetIid, meshLocalIid [8]byte, rloc16 uint16, timeSinceLastTx *uint32, nowMs int64) uint8 {
	if !m.deps.IsPrimary() {
		return DuaStatusNotPrimary
	}

	err := m.ndproxy.Register(targetIid, meshLocalIid, rloc16, timeSinceLastTx, nowMs)
	if err != nil {
		switch err.Error() {
		case "received a duplicated frame":
			return DuaStatusDuplicateAddress
		case "insufficient buffers":
			return DuaStatusNoResources
		default:
			return DuaStatusGeneralFailure
		}
	}

	return DuaStatusSuccess
}

// HandleBackboneQuery looks up a DUA by its target IID in the ND proxy
// table and returns a BackboneAnswer if found, or nil if not.
func (m *Manager) HandleBackboneQuery(targetIid [8]byte) *BackboneAnswer {
	info := m.ndproxy.ResolveDua(targetIid)
	if info == nil {
		return nil
	}

	return &BackboneAnswer{
		TargetIid:       targetIid,
		MeshLocalIid:    info.MeshLocalIid,
		TimeSinceLastTx: info.TimeSinceLastTxSec,
		Rloc16:          info.Rloc16,
	}
}

// HandleBackboneAnswer processes a Backbone Answer message. If the target
// IID is found in the ND proxy table, the entry is marked as duplicated
// (DAD failed). If rloc16 is non-nil, the proactive address notification
// information is stored.
func (m *Manager) HandleBackboneAnswer(targetIid, meshLocalIid [8]byte, rloc16 *uint16, timeSinceLastTxSec uint32, nowMs int64) {
	// A Backbone Answer for an address we have in our ND proxy table means
	// another BBR already owns it — mark as duplicated.
	info := m.ndproxy.GetInfo(targetIid)
	if info != nil {
		m.ndproxy.NotifyDadComplete(targetIid, true)
		return
	}

	// If the answer includes an RLOC16, this is a proactive notification.
	// Register it in our ND proxy table for forwarding.
	if rloc16 != nil {
		tsltt := timeSinceLastTxSec
		_ = m.ndproxy.Register(targetIid, meshLocalIid, *rloc16, &tsltt, nowMs)
	}
}
