// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package radioselector implements multi-radio link selection for Thread.
//
// When a Thread device has multiple radio interfaces (IEEE 802.15.4 and TREL),
// the Selector chooses the optimal radio link for each neighbor based on
// frame error rate metrics. The selection strategy prefers TREL when its
// error rate is low, and falls back to IEEE 802.15.4 (which is more power
// efficient) otherwise.
//
// This is a Go port of the radio selection logic in OpenThread's
// src/core/thread/radio_selector.hpp and radio_selector.cpp.
package radioselector

import "sync"

// ---------------------------------------------------------------------------
// RadioType
// ---------------------------------------------------------------------------

// RadioType represents a radio link type.
type RadioType uint8

const (
	// RadioType154 is the IEEE 802.15.4 radio.
	RadioType154 RadioType = iota
	// RadioTypeTrel is the Thread Radio Encapsulation Link.
	RadioTypeTrel
)

// String returns a human-readable name for the radio type.
func (r RadioType) String() string {
	switch r {
	case RadioType154:
		return "IEEE 802.15.4"
	case RadioTypeTrel:
		return "TREL"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	// FrameErrorRateThreshold is the frame error rate below which TREL is
	// preferred over IEEE 802.15.4. The value 400 corresponds to
	// approximately 0.6% (400 / 65535 ≈ 0.0061).
	FrameErrorRateThreshold uint16 = 400
)

// ---------------------------------------------------------------------------
// RadioPreference
// ---------------------------------------------------------------------------

// RadioPreference stores per-neighbor radio preference and link quality
// metrics.
type RadioPreference struct {
	// ExtAddress is the neighbor's IEEE 802.15.4 extended address.
	ExtAddress [8]byte
	// PreferredRadio is the currently selected radio for this neighbor.
	PreferredRadio RadioType
	// Radio154Available indicates whether the IEEE 802.15.4 link is available.
	Radio154Available bool
	// RadioTrelAvailable indicates whether the TREL link is available.
	RadioTrelAvailable bool
	// FrameErrorRate154 is the frame error rate for IEEE 802.15.4 (0–65535).
	FrameErrorRate154 uint16
	// FrameErrorRateTrel is the frame error rate for TREL (0–65535).
	FrameErrorRateTrel uint16
	// MessageErrorRate154 is the message error rate for IEEE 802.15.4 (0–65535).
	MessageErrorRate154 uint16
	// MessageErrorRateTrel is the message error rate for TREL (0–65535).
	MessageErrorRateTrel uint16
}

// ---------------------------------------------------------------------------
// Selector
// ---------------------------------------------------------------------------

// Selector chooses the optimal radio link for each neighbor based on
// link quality metrics. It is safe for concurrent use.
type Selector struct {
	mu          sync.Mutex
	preferences map[[8]byte]*RadioPreference
}

// NewSelector creates a new radio Selector.
func NewSelector() *Selector {
	return &Selector{
		preferences: make(map[[8]byte]*RadioPreference),
	}
}

// FindPreference looks up the radio preference for a neighbor identified
// by its extended address. Returns the preference and true if found,
// or nil and false otherwise.
func (s *Selector) FindPreference(extAddr [8]byte) (*RadioPreference, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.preferences[extAddr]
	if !ok {
		return nil, false
	}
	cp := *p
	return &cp, true
}

// ensurePreference returns the preference for extAddr, creating it if needed.
// Caller must hold s.mu.
func (s *Selector) ensurePreference(extAddr [8]byte) *RadioPreference {
	p, ok := s.preferences[extAddr]
	if !ok {
		p = &RadioPreference{ExtAddress: extAddr}
		s.preferences[extAddr] = p
	}
	return p
}

// UpdatePreference updates the radio availability for a neighbor on the
// given radio type. If the preference does not exist yet it is created.
func (s *Selector) UpdatePreference(extAddr [8]byte, radioType RadioType, available bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p := s.ensurePreference(extAddr)

	switch radioType {
	case RadioType154:
		p.Radio154Available = available
	case RadioTypeTrel:
		p.RadioTrelAvailable = available
	}

	p.PreferredRadio = selectBest(p)
}

// SetFrameErrorRate sets the frame error rate for a neighbor on a specific
// radio. The rate is in the range 0–65535.
func (s *Selector) SetFrameErrorRate(extAddr [8]byte, radioType RadioType, rate uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p := s.ensurePreference(extAddr)

	switch radioType {
	case RadioType154:
		p.FrameErrorRate154 = rate
	case RadioTypeTrel:
		p.FrameErrorRateTrel = rate
	}

	p.PreferredRadio = selectBest(p)
}

// SetMessageErrorRate sets the message error rate for a neighbor on a
// specific radio. The rate is in the range 0–65535.
func (s *Selector) SetMessageErrorRate(extAddr [8]byte, radioType RadioType, rate uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p := s.ensurePreference(extAddr)

	switch radioType {
	case RadioType154:
		p.MessageErrorRate154 = rate
	case RadioTypeTrel:
		p.MessageErrorRateTrel = rate
	}

	p.PreferredRadio = selectBest(p)
}

// SelectRadio returns the best radio for communicating with the given
// neighbor. If no preference exists for the neighbor, IEEE 802.15.4 is
// returned as the default.
func (s *Selector) SelectRadio(extAddr [8]byte) RadioType {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.preferences[extAddr]
	if !ok {
		return RadioType154
	}
	return p.PreferredRadio
}

// RemovePreference removes the radio preference for a neighbor.
func (s *Selector) RemovePreference(extAddr [8]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.preferences, extAddr)
}

// GetPreferences returns a copy of all current radio preferences.
func (s *Selector) GetPreferences() []RadioPreference {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]RadioPreference, 0, len(s.preferences))
	for _, p := range s.preferences {
		result = append(result, *p)
	}
	return result
}

// ---------------------------------------------------------------------------
// Selection logic
// ---------------------------------------------------------------------------

// selectBest determines the best radio for a neighbor based on the current
// preference state.
//
// Rules:
//  1. If only one radio is available, use it.
//  2. If both are available and TREL's frame error rate is below the
//     threshold, prefer TREL.
//  3. Otherwise prefer IEEE 802.15.4 (more power efficient).
func selectBest(p *RadioPreference) RadioType {
	has154 := p.Radio154Available
	hasTrel := p.RadioTrelAvailable

	switch {
	case has154 && !hasTrel:
		return RadioType154
	case !has154 && hasTrel:
		return RadioTypeTrel
	case has154 && hasTrel:
		if p.FrameErrorRateTrel < FrameErrorRateThreshold {
			return RadioTypeTrel
		}
		return RadioType154
	default:
		// Neither available — default to 802.15.4.
		return RadioType154
	}
}
