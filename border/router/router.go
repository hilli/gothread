// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package router implements the Border Router Routing Manager.
//
// This is a Go port of the routing manager from OpenThread's
// src/core/border_router/routing_manager.hpp and routing_manager.cpp.
// It coordinates OMR prefix management, on-link prefix management, and
// external route publishing for a Thread Border Router.
package router

import (
	"github.com/hilli/gothread/border"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/nd6"
)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

// State represents the routing manager operational state.
type State uint8

const (
	// StateDisabled means the routing manager is explicitly disabled.
	StateDisabled State = iota
	// StateUninitialized means the routing manager has not been initialized.
	StateUninitialized
	// StateRunning means the routing manager is actively operating.
	StateRunning
)

// String returns a human-readable state name.
func (s State) String() string {
	switch s {
	case StateDisabled:
		return "Disabled"
	case StateUninitialized:
		return "Uninitialized"
	case StateRunning:
		return "Running"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// Default RA constants
// ---------------------------------------------------------------------------

const (
	// DefaultRaSendInterval is the default Router Advertisement send interval
	// in seconds.
	DefaultRaSendInterval uint32 = 600

	// MinRaSendInterval is the minimum RA send interval in seconds.
	MinRaSendInterval uint32 = 200

	// MaxRaSendInterval is the maximum RA send interval in seconds.
	MaxRaSendInterval uint32 = 1800
)

// ---------------------------------------------------------------------------
// RoutingManager options
// ---------------------------------------------------------------------------

// RoutingManagerOption configures the RoutingManager.
type RoutingManagerOption func(*RoutingManager)

// WithRaSendInterval sets the RA send interval in seconds.
func WithRaSendInterval(seconds uint32) RoutingManagerOption {
	return func(m *RoutingManager) {
		if seconds >= MinRaSendInterval && seconds <= MaxRaSendInterval {
			m.raSendInterval = seconds
		}
	}
}

// WithRoutePublisherOptions passes options through to the route publisher.
func WithRoutePublisherOptions(opts ...RoutePublisherOption) RoutingManagerOption {
	return func(m *RoutingManager) {
		m.rpOpts = append(m.rpOpts, opts...)
	}
}

// WithRxRaTracker sets the received-RA tracker used to learn about other
// routers on the infrastructure link.
func WithRxRaTracker(tracker *border.RxRaTracker) RoutingManagerOption {
	return func(m *RoutingManager) {
		m.raTracker = tracker
	}
}

// WithInfraIf sets the infrastructure interface used to send Router
// Advertisements.
func WithInfraIf(infraIf *border.InfraIf) RoutingManagerOption {
	return func(m *RoutingManager) {
		m.infraIf = infraIf
	}
}

// ---------------------------------------------------------------------------
// RoutingManager — main routing manager coordinator
// ---------------------------------------------------------------------------

// RoutingManager coordinates the border router's routing behaviour. It
// manages the OMR prefix, on-link prefix, and external route publishing,
// responding to infrastructure interface state changes and periodic timers.
type RoutingManager struct {
	state          State
	enabled        bool // desired enabled state
	omrManager     *OmrPrefixManager
	onLinkManager  *OnLinkPrefixManager
	routePublisher *RoutePublisher
	raTracker      *border.RxRaTracker // tracks routers on the infra link
	infraIf        *border.InfraIf     // infrastructure interface for sending RAs
	infraIfRunning bool
	isRaEnabled    bool
	raSendInterval uint32
	rpOpts         []RoutePublisherOption
}

// NewRoutingManager creates a new RoutingManager with the given options.
// The manager starts in StateUninitialized.
func NewRoutingManager(opts ...RoutingManagerOption) *RoutingManager {
	m := &RoutingManager{
		state:          StateUninitialized,
		raSendInterval: DefaultRaSendInterval,
	}
	for _, o := range opts {
		o(m)
	}
	m.omrManager = NewOmrPrefixManager()
	m.onLinkManager = NewOnLinkPrefixManager()
	m.routePublisher = NewRoutePublisher(m.rpOpts...)
	return m
}

// Init initializes the routing manager, generating the local OMR and on-link
// prefixes from the given extended address. Must be called before SetEnabled.
func (m *RoutingManager) Init(extAddr [8]byte) error {
	if m.state == StateRunning {
		return errors.ErrInvalidState
	}

	if err := m.omrManager.GenerateLocalPrefix(extAddr); err != nil {
		return err
	}
	if err := m.onLinkManager.GenerateLocalPrefix(extAddr); err != nil {
		return err
	}

	m.state = StateDisabled
	return nil
}

// SetEnabled enables or disables the routing manager. When enabled, the
// manager transitions to StateRunning if the infrastructure interface is
// running; otherwise it waits. When disabled, it transitions to StateDisabled
// and clears published routes.
func (m *RoutingManager) SetEnabled(enabled bool) error {
	if m.state == StateUninitialized {
		return errors.ErrInvalidState
	}

	m.enabled = enabled

	if enabled {
		if m.infraIfRunning {
			m.start()
		}
	} else {
		m.stop()
	}

	return nil
}

// GetState returns the current state of the routing manager.
func (m *RoutingManager) GetState() State {
	return m.state
}

// HandleInfraIfStateChanged is called when the infrastructure interface's
// link state changes. If the interface comes up and the manager is enabled,
// routing begins. If it goes down, routing stops.
func (m *RoutingManager) HandleInfraIfStateChanged(running bool) {
	m.infraIfRunning = running

	if m.state == StateUninitialized {
		return
	}

	if running && m.enabled {
		m.start()
	} else if !running && m.state == StateRunning {
		m.stop()
	}
}

// EvaluateRoutingPolicy is called periodically and on state changes to
// re-evaluate prefix selection and advertising decisions.
func (m *RoutingManager) EvaluateRoutingPolicy() {
	if m.state != StateRunning {
		return
	}

	m.evaluateOmrPrefix()
	m.evaluateOnLinkPrefix()
}

// GetOmrPrefix returns the currently favored OMR prefix, or false if none.
func (m *RoutingManager) GetOmrPrefix() (OmrPrefix, bool) {
	return m.omrManager.GetFavoredPrefix()
}

// GetOnLinkPrefix returns the on-link prefix being advertised, or false if
// none is being advertised.
func (m *RoutingManager) GetOnLinkPrefix() ([16]byte, uint8, bool) {
	if !m.onLinkManager.ShouldAdvertise() {
		return [16]byte{}, 0, false
	}
	return m.onLinkManager.GetLocalPrefix()
}

// GetRoutePublisher returns the route publisher for direct route management.
func (m *RoutingManager) GetRoutePublisher() *RoutePublisher {
	return m.routePublisher
}

// HandleTimer handles periodic timer expiry. It triggers RA sending and
// routing policy evaluation.
func (m *RoutingManager) HandleTimer() {
	if m.state != StateRunning {
		return
	}
	m.EvaluateRoutingPolicy()
}

// GetRaSendInterval returns the current RA send interval in seconds.
func (m *RoutingManager) GetRaSendInterval() uint32 {
	return m.raSendInterval
}

// IsRunning returns true if the manager is in the Running state.
func (m *RoutingManager) IsRunning() bool {
	return m.state == StateRunning
}

// ---------------------------------------------------------------------------
// Internal methods
// ---------------------------------------------------------------------------

// start transitions to StateRunning and performs initial evaluation.
func (m *RoutingManager) start() {
	if m.state == StateRunning {
		return
	}
	m.state = StateRunning
	m.isRaEnabled = true
	m.EvaluateRoutingPolicy()
}

// stop transitions to StateDisabled and clears transient state.
func (m *RoutingManager) stop() {
	m.state = StateDisabled
	m.isRaEnabled = false
	m.onLinkManager.SetAdvertising(false)
	m.routePublisher.ClearRoutes()
	m.omrManager.SetAddedInNetData(false)
}

// evaluateOmrPrefix re-evaluates the OMR prefix selection.
// When an RxRaTracker is configured, OMR-eligible route prefixes from other
// routers on the infrastructure link are included in the evaluation.
func (m *RoutingManager) evaluateOmrPrefix() {
	var networkPrefixes []OmrPrefix

	if m.raTracker != nil {
		routers := m.raTracker.GetRouters()
		for i := range routers {
			for _, rp := range routers[i].RoutePrefixes {
				if rp.IsExpired() {
					continue
				}
				prefixBytes := rp.Prefix.GetBytes()
				prefixLen := rp.Prefix.GetLength()

				// Only consider OMR-eligible prefixes.
				if err := ValidateOmrPrefix(prefixBytes, prefixLen); err != nil {
					continue
				}

				networkPrefixes = append(networkPrefixes, OmrPrefix{
					Prefix:     prefixBytes,
					PrefixLen:  prefixLen,
					Preference: mapBorderToNd6Pref(rp.RoutePreference),
					IsLocal:    false,
				})
			}
		}
	}

	m.omrManager.Evaluate(networkPrefixes)
}

// evaluateOnLinkPrefix re-evaluates whether the on-link prefix should be
// advertised. When an RxRaTracker is configured, it checks whether another
// router on the infrastructure link is already providing an on-link prefix.
func (m *RoutingManager) evaluateOnLinkPrefix() {
	hasDiscoveredOnLink := false
	if m.raTracker != nil {
		hasDiscoveredOnLink = m.raTracker.GetDecisionFactors().HasOnLinkPrefix
	}
	m.onLinkManager.Evaluate(hasDiscoveredOnLink)
}

// mapBorderToNd6Pref converts the nd6.RoutePreference used in the border
// package back to the same nd6.RoutePreference type. This is a no-op since
// they are the same type via the alias in border/types.go, but is kept
// explicit for clarity.
func mapBorderToNd6Pref(pref nd6.RoutePreference) nd6.RoutePreference {
	return pref
}

// SendRouterAdvertisement constructs and sends a Router Advertisement on the
// infrastructure link based on the current prefix state. If no InfraIf is
// configured, this is a no-op. Returns the marshalled RA payload (after the
// ICMPv6 header) or nil if no RA was sent.
func (m *RoutingManager) SendRouterAdvertisement() ([]byte, error) {
	if m.infraIf == nil || m.state != StateRunning {
		return nil, nil
	}

	payload := m.buildRaPayload()
	if payload == nil {
		return nil, nil
	}

	// Send to all-nodes multicast (ff02::1).
	dest := ip6.Address{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	if err := m.infraIf.SendIcmp6Nd(dest, payload); err != nil {
		return nil, err
	}

	// Register hash so we can identify this as our own if received back.
	if m.raTracker != nil {
		m.raTracker.AddSelfRaHash(payload)
	}

	return payload, nil
}

// buildRaPayload constructs the RA message payload (header + options).
func (m *RoutingManager) buildRaPayload() []byte {
	var ra nd6.RaMessage

	// Header: zero hop limit (unspecified), no router lifetime (we are
	// not advertising as a default router on the infra link).
	ra.Header.SetRouterLifetime(0)

	// Build options.
	var opts []byte

	// PIO: on-link prefix for SLAAC (if advertising).
	if m.onLinkManager.ShouldAdvertise() {
		prefix, prefixLen, ok := m.onLinkManager.GetLocalPrefix()
		if ok {
			opts = append(opts, buildPrefixInfoOption(prefix, prefixLen)...)
		}
	}

	// RIO: favored OMR prefix.
	if fp, ok := m.omrManager.GetFavoredPrefix(); ok {
		opts = append(opts, buildRouteInfoOption(fp)...)
	}

	// RA Flags Extension: set stub router flag to indicate this border
	// router does not forward between the Thread mesh and the infra link
	// at the IP layer — it only provides prefix and route information.
	opts = append(opts, buildRaFlagsExtOption()...)

	if len(opts) == 0 {
		return nil
	}

	ra.Options = opts
	return ra.Marshal()
}
