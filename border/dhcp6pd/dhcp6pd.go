// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package dhcp6pd provides a border-router-layer wrapper around the
// net/dhcp6 PD client. It manages the enable/disable lifecycle and
// exposes delegated prefix state to the border router routing manager.
//
// This is a Go port of the DHCPv6 PD integration from OpenThread's
// src/core/border_router/routing_manager_dhcp6pd.cpp.
package dhcp6pd

import (
	"github.com/hilli/gothread/net/dhcp6"
)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

// State represents the high-level state of the DHCPv6 PD component.
type State uint8

const (
	// StateDisabled means DHCPv6 PD is explicitly disabled.
	StateDisabled State = iota
	// StateStopped means DHCPv6 PD is enabled but not actively running.
	StateStopped
	// StateRunning means DHCPv6 PD is actively running and may have a prefix.
	StateRunning
)

// String returns a human-readable state name.
func (s State) String() string {
	switch s {
	case StateDisabled:
		return "Disabled"
	case StateStopped:
		return "Stopped"
	case StateRunning:
		return "Running"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// PrefixEntry
// ---------------------------------------------------------------------------

// PrefixEntry represents a delegated prefix with its metadata.
type PrefixEntry struct {
	Prefix            [16]byte
	PrefixLength      uint8
	PreferredLifetime uint32
	ValidLifetime     uint32
	AcquireTimeMs     int64
}

// IsValid returns true if this entry contains a valid prefix.
func (e PrefixEntry) IsValid() bool {
	return e.PrefixLength != 0
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// Config holds the static configuration for the DHCPv6 PD component.
type Config struct {
	Enabled bool
}

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

// StateCallback is called when the component state changes.
type StateCallback func(state State)

// PrefixCallback is called when the delegated prefix changes.
type PrefixCallback func(entry PrefixEntry)

// ---------------------------------------------------------------------------
// Platform interface
// ---------------------------------------------------------------------------

// Platform abstracts the network transport for DHCPv6 messages.
type Platform interface {
	// SendDhcp6 sends a DHCPv6 message to the given destination.
	SendDhcp6(payload []byte, dst [16]byte) error
	// SetDhcp6ListeningEnabled enables or disables listening for DHCPv6 messages.
	SetDhcp6ListeningEnabled(enabled bool)
}

// ---------------------------------------------------------------------------
// Client options
// ---------------------------------------------------------------------------

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithClock sets a custom clock for testability.
func WithClock(c dhcp6.PdClientClock) ClientOption {
	return func(cl *Client) {
		cl.clock = c
	}
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client wraps a net/dhcp6.PdClient with border-router-layer lifecycle
// management (enable/disable/start/stop) and prefix change notification.
type Client struct {
	state         State
	config        Config
	pdClient      *dhcp6.PdClient
	platform      Platform
	stateCallback StateCallback
	prefixCb      PrefixCallback
	prefix        *PrefixEntry
	extAddr       [8]byte
	clock         dhcp6.PdClientClock
}

// NewClient creates a new DHCPv6 PD border-router client.
func NewClient(platform Platform, extAddr [8]byte, opts ...ClientOption) *Client {
	cl := &Client{
		state:    StateDisabled,
		platform: platform,
		extAddr:  extAddr,
	}
	for _, o := range opts {
		o(cl)
	}
	return cl
}

// Enable enables the DHCPv6 PD component. If it was disabled, it transitions
// to StateStopped, ready to be started. Returns true if the state changed.
func (c *Client) Enable() bool {
	if c.state != StateDisabled {
		return false
	}
	c.config.Enabled = true
	c.setState(StateStopped)
	return true
}

// Disable disables the DHCPv6 PD component. If running, it stops first.
// Returns true if the state changed.
func (c *Client) Disable() bool {
	if c.state == StateDisabled {
		return false
	}
	if c.state == StateRunning {
		c.stopInternal()
	}
	c.config.Enabled = false
	c.setState(StateDisabled)
	return true
}

// IsEnabled returns true if the DHCPv6 PD component is enabled.
func (c *Client) IsEnabled() bool {
	return c.config.Enabled
}

// Start starts the PD client, beginning the DHCPv6 Solicit process.
// The component must be enabled and stopped. Returns true if started.
func (c *Client) Start() bool {
	if c.state != StateStopped {
		return false
	}
	c.ensurePdClient()
	c.pdClient.Start()
	c.setState(StateRunning)
	return true
}

// Stop stops the PD client. Returns true if stopped.
func (c *Client) Stop() bool {
	if c.state != StateRunning {
		return false
	}
	c.stopInternal()
	c.setState(StateStopped)
	return true
}

// GetState returns the current state of the DHCPv6 PD component.
func (c *Client) GetState() State {
	return c.state
}

// GetPrefix returns the current delegated prefix, or nil if none.
func (c *Client) GetPrefix() *PrefixEntry {
	if c.prefix != nil && c.prefix.IsValid() {
		cp := *c.prefix
		return &cp
	}
	return nil
}

// SetStateCallback registers a callback for state changes.
func (c *Client) SetStateCallback(cb StateCallback) {
	c.stateCallback = cb
}

// SetPrefixCallback registers a callback for prefix changes.
func (c *Client) SetPrefixCallback(cb PrefixCallback) {
	c.prefixCb = cb
}

// HandleReceive forwards an incoming DHCPv6 message to the underlying
// PD client for processing.
func (c *Client) HandleReceive(payload []byte, src [16]byte) {
	if c.state != StateRunning || c.pdClient == nil {
		return
	}
	c.pdClient.HandleReceive(payload, src)
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

func (c *Client) ensurePdClient() {
	if c.pdClient != nil {
		return
	}

	var opts []dhcp6.PdClientOption
	if c.clock != nil {
		opts = append(opts, dhcp6.WithPdClock(c.clock))
	}

	c.pdClient = dhcp6.NewPdClient(c.platform, c.handlePrefixChanged, c.extAddr, opts...)
}

func (c *Client) stopInternal() {
	if c.pdClient != nil {
		c.pdClient.Stop()
	}
	c.clearPrefix()
}

func (c *Client) setState(s State) {
	if c.state == s {
		return
	}
	c.state = s
	if c.stateCallback != nil {
		c.stateCallback(s)
	}
}

func (c *Client) handlePrefixChanged(dp *dhcp6.DelegatedPrefix) {
	if dp == nil {
		c.clearPrefix()
		return
	}

	entry := PrefixEntry{
		Prefix:            dp.AdjustedPrefix,
		PrefixLength:      dp.AdjustedLength,
		PreferredLifetime: dp.PreferredLifetime,
		ValidLifetime:     dp.ValidLifetime,
		AcquireTimeMs:     dp.UpdateTimeMs,
	}

	if entry.PreferredLifetime == 0 && entry.ValidLifetime == 0 {
		c.clearPrefix()
		return
	}

	c.prefix = &entry
	if c.prefixCb != nil {
		c.prefixCb(entry)
	}
}

func (c *Client) clearPrefix() {
	if c.prefix != nil && c.prefix.IsValid() {
		cleared := PrefixEntry{
			Prefix:       c.prefix.Prefix,
			PrefixLength: c.prefix.PrefixLength,
		}
		c.prefix = nil
		if c.prefixCb != nil {
			c.prefixCb(cleared)
		}
	} else {
		c.prefix = nil
	}
}

// ---------------------------------------------------------------------------
// GenerateDUID
// ---------------------------------------------------------------------------

// GenerateDUID creates a DHCPv6 DUID-LL from an EUI-64 extended address.
// The returned bytes are the wire-format DUID suitable for use in a
// Client Identifier option.
func GenerateDUID(extAddr [8]byte) []byte {
	var duid dhcp6.Eui64DUID
	duid.Init(extAddr)
	data, err := duid.MarshalBinary()
	if err != nil {
		return nil
	}
	return data
}

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

type dhcp6pdError string

func (e dhcp6pdError) Error() string { return string(e) }

const (
	// ErrNotEnabled is returned when an operation requires the component to be enabled.
	ErrNotEnabled dhcp6pdError = "dhcp6pd: not enabled"
	// ErrNotRunning is returned when an operation requires the component to be running.
	ErrNotRunning dhcp6pdError = "dhcp6pd: not running"
	// ErrAlreadyRunning is returned when starting an already-running component.
	ErrAlreadyRunning dhcp6pdError = "dhcp6pd: already running"
)
