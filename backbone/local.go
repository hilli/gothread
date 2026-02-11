// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package backbone

// Local manages this device's Backbone Router service.
//
// This is a Go port of the Local from
// OpenThread's src/core/backbone_router/bbr_local.{hpp,cpp}.

import (
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// LocalState
// ---------------------------------------------------------------------------

// LocalState represents this device's BBR state.
type LocalState uint8

const (
	// LocalStateDisabled indicates the Backbone Router function is disabled.
	LocalStateDisabled LocalState = 0
	// LocalStateSecondary indicates this device is a Secondary Backbone Router.
	LocalStateSecondary LocalState = 1
	// LocalStatePrimary indicates this device is the Primary Backbone Router.
	LocalStatePrimary LocalState = 2
)

// ---------------------------------------------------------------------------
// LocalCallbacks
// ---------------------------------------------------------------------------

// LocalCallbacks is called when the local BBR state changes.
type LocalCallbacks interface {
	OnLocalStateChanged(oldState, newState LocalState)
	OnServiceAdded(config Config)
	OnServiceRemoved()
	OnDomainPrefixAdded(prefix ip6.Prefix)
	OnDomainPrefixRemoved(prefix ip6.Prefix)
}

// ---------------------------------------------------------------------------
// Local
// ---------------------------------------------------------------------------

// Local manages this device's Backbone Router service.
type Local struct {
	state          LocalState
	sequenceNumber uint8
	reregDelay     uint16
	mlrTimeout     uint32
	regJitter      uint8
	isServiceAdded bool
	domainPrefix   *ip6.Prefix
	callbacks      LocalCallbacks
}

// NewLocal creates a new Local with default values.
// The callbacks may be nil.
func NewLocal(callbacks LocalCallbacks) *Local {
	return &Local{
		state:          LocalStateDisabled,
		sequenceNumber: 0,
		reregDelay:     DefaultRegistrationDelay,
		mlrTimeout:     DefaultMlrTimeout,
		regJitter:      DefaultRegistrationJitter,
		callbacks:      callbacks,
	}
}

// SetEnabled enables or disables the BBR function.
// Enabling transitions from Disabled to Secondary;
// disabling transitions to Disabled.
func (l *Local) SetEnabled(enabled bool) {
	if enabled == l.IsEnabled() {
		return
	}

	if enabled {
		l.setState(LocalStateSecondary)
	} else {
		if l.isServiceAdded {
			l.RemoveService()
		}
		l.setState(LocalStateDisabled)
	}
}

// IsEnabled reports whether the BBR function is enabled (Secondary or Primary).
func (l *Local) IsEnabled() bool {
	return l.state != LocalStateDisabled
}

// GetState returns the current BBR state.
func (l *Local) GetState() LocalState {
	return l.state
}

// IsPrimary reports whether this device is the Primary Backbone Router.
func (l *Local) IsPrimary() bool {
	return l.state == LocalStatePrimary
}

// GetConfig builds and returns a Config from the local fields.
func (l *Local) GetConfig() Config {
	return Config{
		SequenceNumber:      l.sequenceNumber,
		ReregistrationDelay: l.reregDelay,
		MlrTimeout:          l.mlrTimeout,
	}
}

// SetConfig updates the local sequence number, re-registration delay, and
// MLR timeout from the given config.
func (l *Local) SetConfig(config Config) {
	l.sequenceNumber = config.SequenceNumber
	l.reregDelay = config.ReregistrationDelay
	l.mlrTimeout = config.MlrTimeout
}

// GetSequenceNumber returns the current sequence number.
func (l *Local) GetSequenceNumber() uint8 {
	return l.sequenceNumber
}

// SetSequenceNumber sets the sequence number.
func (l *Local) SetSequenceNumber(seq uint8) {
	l.sequenceNumber = seq
}

// GetReregistrationDelay returns the re-registration delay in seconds.
func (l *Local) GetReregistrationDelay() uint16 {
	return l.reregDelay
}

// SetReregistrationDelay sets the re-registration delay in seconds.
func (l *Local) SetReregistrationDelay(delay uint16) {
	l.reregDelay = delay
}

// GetMlrTimeout returns the MLR timeout in seconds.
func (l *Local) GetMlrTimeout() uint32 {
	return l.mlrTimeout
}

// SetMlrTimeout sets the MLR timeout in seconds.
func (l *Local) SetMlrTimeout(timeout uint32) {
	l.mlrTimeout = timeout
}

// GetRegistrationJitter returns the registration jitter in seconds.
func (l *Local) GetRegistrationJitter() uint8 {
	return l.regJitter
}

// SetRegistrationJitter sets the registration jitter in seconds.
func (l *Local) SetRegistrationJitter(jitter uint8) {
	l.regJitter = jitter
}

// Reset removes the service and transitions back to defaults. If the device
// was Primary it transitions to Secondary; if Disabled, this is a no-op.
func (l *Local) Reset() {
	if l.state == LocalStateDisabled {
		return
	}

	if l.isServiceAdded {
		l.RemoveService()
	}

	if l.state == LocalStatePrimary {
		l.IncrementSequenceNumber()
		l.setState(LocalStateSecondary)
	}
}

// AddService marks the service as added and returns the config to publish.
// The OnServiceAdded callback is invoked.
func (l *Local) AddService() Config {
	l.isServiceAdded = true
	cfg := l.GetConfig()
	if l.callbacks != nil {
		l.callbacks.OnServiceAdded(cfg)
	}
	return cfg
}

// RemoveService marks the service as removed. The OnServiceRemoved callback
// is invoked.
func (l *Local) RemoveService() {
	l.isServiceAdded = false
	if l.callbacks != nil {
		l.callbacks.OnServiceRemoved()
	}
}

// IsServiceAdded reports whether the service has been added.
func (l *Local) IsServiceAdded() bool {
	return l.isServiceAdded
}

// HandleBackboneRouterPrimaryUpdate transitions between Secondary and Primary
// based on the network-wide primary BBR state and whether this device's
// RLOC16 matches.
//
// The rloc16 parameter is this device's own RLOC16.
func (l *Local) HandleBackboneRouterPrimaryUpdate(state LeaderState, config Config, rloc16 uint16) {
	if !l.IsEnabled() {
		return
	}

	if config.Server16 == InvalidServer16 {
		// No primary exists — we may attempt to register (handled externally).
		return
	}

	if config.Server16 != rloc16 {
		// Someone else is primary — if we were primary, step down.
		if l.state == LocalStatePrimary {
			l.Reset()
		}
		return
	}

	// Our RLOC16 matches the primary.
	if !l.isServiceAdded {
		// Restore: adopt config, increment seq, re-add service.
		l.sequenceNumber = config.SequenceNumber
		l.reregDelay = config.ReregistrationDelay
		l.mlrTimeout = config.MlrTimeout
		l.IncrementSequenceNumber()
		l.AddService()
		return
	}

	l.setState(LocalStatePrimary)
}

// SetDomainPrefix stores the domain prefix and invokes OnDomainPrefixAdded.
func (l *Local) SetDomainPrefix(prefix ip6.Prefix) {
	p := prefix
	l.domainPrefix = &p
	if l.callbacks != nil {
		l.callbacks.OnDomainPrefixAdded(prefix)
	}
}

// RemoveDomainPrefix clears the domain prefix and invokes OnDomainPrefixRemoved.
func (l *Local) RemoveDomainPrefix() {
	if l.domainPrefix == nil {
		return
	}
	old := *l.domainPrefix
	l.domainPrefix = nil
	if l.callbacks != nil {
		l.callbacks.OnDomainPrefixRemoved(old)
	}
}

// GetDomainPrefix returns the stored domain prefix and whether one is set.
func (l *Local) GetDomainPrefix() (ip6.Prefix, bool) {
	if l.domainPrefix == nil {
		return ip6.Prefix{}, false
	}
	return *l.domainPrefix, true
}

// IncrementSequenceNumber increments with special wrap-around per Thread spec:
//
//	0–125 → +1
//	126 or 127 → 0
//	128–253 → +1
//	254 or 255 → 128
func (l *Local) IncrementSequenceNumber() {
	switch l.sequenceNumber {
	case 126, 127:
		l.sequenceNumber = 0
	case 254, 255:
		l.sequenceNumber = 128
	default:
		l.sequenceNumber++
	}
}

// setState changes the state and invokes the OnLocalStateChanged callback
// if the state actually changed.
func (l *Local) setState(newState LocalState) {
	if l.state == newState {
		return
	}
	old := l.state
	l.state = newState
	if l.callbacks != nil {
		l.callbacks.OnLocalStateChanged(old, newState)
	}
}
