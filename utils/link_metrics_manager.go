// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"sync"
	"time"

	mac_types "github.com/hilli/gothread/mac/types"

	"github.com/hilli/gothread/errors"
)

// LinkMetricsManager configuration constants.
const (
	// LinkMetricsTimeBeforeStart is the delay before starting link metrics
	// management after attachment.
	LinkMetricsTimeBeforeStart = 5 * time.Second

	// LinkMetricsStateUpdateInterval is the interval between state updates
	// for configured link metrics subjects.
	LinkMetricsStateUpdateInterval = 150 * time.Second

	// LinkMetricsMaxConfigAttempts is the maximum number of attempts to
	// configure Enhanced ACK probing for a subject.
	LinkMetricsMaxConfigAttempts uint8 = 3

	// LinkMetricsMaxSubjects is the maximum number of subjects that can be
	// tracked simultaneously.
	LinkMetricsMaxSubjects = 128
)

// SubjectState represents the current state of a link metrics subject.
type SubjectState uint8

// Subject state values.
const (
	SubjectNotConfigured SubjectState = iota
	SubjectConfiguring
	SubjectActive
	SubjectRenewing
	SubjectNotSupported
)

// LinkMetricsData holds the link quality metrics for a subject.
type LinkMetricsData struct {
	Lqi        uint8 // Link Quality Indicator [0, 255].
	Rssi       int8  // Receive Signal Strength Indicator [-128, 0].
	LinkMargin uint8 // Link Margin in dB [0, 130].
}

// LinkMetricsSubject represents a neighbor being tracked for link metrics.
type LinkMetricsSubject struct {
	ExtAddress     mac_types.ExtAddress
	State          SubjectState
	Attempts       uint8
	LastUpdateTime time.Time
	Data           LinkMetricsData
}

// LinkMetricsStatusCode represents the status returned by link metrics
// management operations.
type LinkMetricsStatusCode uint8

// Link metrics management status codes.
const (
	LinkMetricsStatusSuccess LinkMetricsStatusCode = 0
)

// NeighborProvider supplies the list of current neighbors for the link
// metrics manager to track.
type NeighborProvider interface {
	// GetNeighborExtAddresses returns the extended addresses of all
	// current neighbors.
	GetNeighborExtAddresses() []mac_types.ExtAddress
}

// EapConfigurator handles the Enhanced ACK-Based Probing configuration
// for link metrics subjects.
type EapConfigurator interface {
	// ConfigureEap sends a management request to configure Enhanced ACK
	// probing with the given neighbor. Returns nil on success.
	ConfigureEap(extAddr mac_types.ExtAddress) error

	// UnregisterEap sends a management request to clear Enhanced ACK
	// probing with the given neighbor. Returns nil on success.
	UnregisterEap(extAddr mac_types.ExtAddress) error
}

// LinkMetricsManager manages link quality metrics for Thread neighbors
// using Enhanced ACK-Based Probing.
//
// Reference: openthread/src/core/utils/link_metrics_manager.hpp
type LinkMetricsManager struct {
	mu           sync.Mutex
	subjects     []*LinkMetricsSubject
	neighbors    NeighborProvider
	configurator EapConfigurator
	enabled      bool
	started      bool
}

// NewLinkMetricsManager creates a new LinkMetricsManager with the given
// dependencies.
func NewLinkMetricsManager(neighbors NeighborProvider, configurator EapConfigurator) *LinkMetricsManager {
	return &LinkMetricsManager{
		neighbors:    neighbors,
		configurator: configurator,
	}
}

// IsEnabled returns whether the link metrics manager is enabled.
func (m *LinkMetricsManager) IsEnabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enabled
}

// SetEnabled enables or disables the link metrics manager.
// When enabled, it starts tracking neighbors. When disabled, it
// unregisters all subjects and clears the tracking list.
func (m *LinkMetricsManager) SetEnabled(enable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.enabled == enable {
		return
	}
	m.enabled = enable

	if enable {
		m.startLocked()
	} else {
		m.stopLocked()
	}
}

// Start begins link metrics management. Should be called when the
// device attaches to a Thread network.
func (m *LinkMetricsManager) Start() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startLocked()
}

func (m *LinkMetricsManager) startLocked() {
	if !m.enabled {
		return
	}
	m.started = true
}

// Stop halts link metrics management. Should be called when the
// device detaches from the Thread network.
func (m *LinkMetricsManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
}

func (m *LinkMetricsManager) stopLocked() {
	m.started = false
	m.unregisterAllLocked()
	m.releaseAllLocked()
}

// HandleTimer should be called periodically to update link metrics state.
// It discovers new neighbors and manages EAP configuration state.
func (m *LinkMetricsManager) HandleTimer() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.enabled || !m.started {
		return
	}

	m.updateSubjectsLocked()
	m.updateStatesLocked()
}

// GetMetricsByExtAddress returns the link metrics data for a neighbor
// identified by its extended address.
func (m *LinkMetricsManager) GetMetricsByExtAddress(extAddr mac_types.ExtAddress) (*LinkMetricsData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	subject := m.findSubjectLocked(extAddr)
	if subject == nil {
		return nil, errors.ErrNotFound
	}
	if subject.State != SubjectActive && subject.State != SubjectRenewing {
		return nil, errors.ErrInvalidState
	}

	// Return a copy
	data := subject.Data
	return &data, nil
}

// HandleMgmtResponse processes a management response for EAP configuration.
// A successful status transitions the subject to active state.
func (m *LinkMetricsManager) HandleMgmtResponse(extAddr mac_types.ExtAddress, status LinkMetricsStatusCode) {
	m.mu.Lock()
	defer m.mu.Unlock()

	subject := m.findSubjectLocked(extAddr)
	if subject == nil {
		return
	}

	if status == LinkMetricsStatusSuccess {
		subject.State = SubjectActive
	} else {
		subject.State = SubjectNotConfigured
	}
}

// HandleEnhAckIe processes an Enhanced ACK Information Element received
// from a neighbor, updating the subject's link metrics data.
func (m *LinkMetricsManager) HandleEnhAckIe(extAddr mac_types.ExtAddress, rssi int8, linkMargin uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()

	subject := m.findSubjectLocked(extAddr)
	if subject == nil {
		return
	}

	if subject.State != SubjectActive && subject.State != SubjectRenewing {
		return
	}

	subject.LastUpdateTime = time.Now()
	subject.Data.Rssi = rssi
	subject.Data.LinkMargin = linkMargin
}

// GetSubjects returns a copy of all currently tracked subjects.
func (m *LinkMetricsManager) GetSubjects() []LinkMetricsSubject {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]LinkMetricsSubject, len(m.subjects))
	for i, s := range m.subjects {
		result[i] = *s
	}
	return result
}

// SubjectCount returns the number of currently tracked subjects.
func (m *LinkMetricsManager) SubjectCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.subjects)
}

func (m *LinkMetricsManager) findSubjectLocked(extAddr mac_types.ExtAddress) *LinkMetricsSubject {
	for _, s := range m.subjects {
		if s.ExtAddress == extAddr {
			return s
		}
	}
	return nil
}

func (m *LinkMetricsManager) updateSubjectsLocked() {
	if m.neighbors == nil {
		return
	}

	addrs := m.neighbors.GetNeighborExtAddresses()
	for _, addr := range addrs {
		if m.findSubjectLocked(addr) == nil {
			if len(m.subjects) >= LinkMetricsMaxSubjects {
				return
			}
			m.subjects = append(m.subjects, &LinkMetricsSubject{
				ExtAddress: addr,
				State:      SubjectNotConfigured,
			})
		}
	}
}

func (m *LinkMetricsManager) updateStatesLocked() {
	// Update states and remove stale subjects
	alive := m.subjects[:0]
	for _, subject := range m.subjects {
		stale := m.updateSubjectStateLocked(subject)
		if !stale {
			alive = append(alive, subject)
		}
	}
	// Clear remaining references to help GC
	for i := len(alive); i < len(m.subjects); i++ {
		m.subjects[i] = nil
	}
	m.subjects = alive
}

// updateSubjectStateLocked updates a single subject's state and attempts
// EAP configuration if needed. Returns true if the subject should be removed.
func (m *LinkMetricsManager) updateSubjectStateLocked(subject *LinkMetricsSubject) bool {
	shouldConfigure := false

	switch subject.State {
	case SubjectNotConfigured, SubjectConfiguring, SubjectRenewing:
		if subject.Attempts >= LinkMetricsMaxConfigAttempts {
			subject.State = SubjectNotSupported
		} else {
			shouldConfigure = true
		}
	case SubjectActive:
		elapsed := time.Since(subject.LastUpdateTime)
		if elapsed >= LinkMetricsStateUpdateInterval {
			shouldConfigure = true
		}
	case SubjectNotSupported:
		// Subject is not capable; mark for removal.
		return true
	}

	if shouldConfigure && m.configurator != nil {
		err := m.configurator.ConfigureEap(subject.ExtAddress)
		if err != nil {
			// If the neighbor is unknown, mark for removal.
			if err == errors.ErrUnknownNeighbor {
				return true
			}
			return false
		}
		if subject.State == SubjectActive {
			subject.State = SubjectRenewing
		} else {
			subject.State = SubjectConfiguring
		}
		subject.Attempts++
	}

	return false
}

func (m *LinkMetricsManager) unregisterAllLocked() {
	if m.configurator == nil {
		return
	}
	for _, subject := range m.subjects {
		_ = m.configurator.UnregisterEap(subject.ExtAddress)
	}
}

func (m *LinkMetricsManager) releaseAllLocked() {
	m.subjects = nil
}
