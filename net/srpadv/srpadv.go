// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package srpadv implements an SRP Advertising Proxy that processes SRP
// server updates and registers/unregisters hosts and services through a
// DNS-SD platform interface.
//
// This is a Go port of the SRP advertising proxy in OpenThread's
// src/core/net/srp_advertising_proxy.hpp and
// src/core/net/srp_advertising_proxy.cpp.
package srpadv

import (
	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

// State represents the running state of the advertising proxy.
type State uint8

const (
	// StateStopped indicates the proxy is not running.
	StateStopped State = iota
	// StateRunning indicates the proxy is actively processing updates.
	StateRunning
)

// ---------------------------------------------------------------------------
// HostInfo
// ---------------------------------------------------------------------------

// HostInfo describes a host registered via SRP.
type HostInfo struct {
	// Name is the host name.
	Name string
	// Addresses is the list of IPv6 addresses for the host.
	Addresses [][16]byte
	// TTL is the time-to-live in seconds.
	TTL uint32
	// Deleted indicates whether the host has been deleted.
	Deleted bool
}

// ---------------------------------------------------------------------------
// ServiceInfo
// ---------------------------------------------------------------------------

// ServiceInfo describes a service registered via SRP.
type ServiceInfo struct {
	// InstanceName is the service instance name (e.g., "My Printer").
	InstanceName string
	// ServiceType is the service type (e.g., "_http._tcp").
	ServiceType string
	// SubTypes lists service subtypes.
	SubTypes []string
	// Port is the service port.
	Port uint16
	// TxtData is the TXT record data.
	TxtData []byte
	// TTL is the time-to-live in seconds.
	TTL uint32
	// Deleted indicates whether the service has been deleted.
	Deleted bool
}

// ---------------------------------------------------------------------------
// DnssdPlatform
// ---------------------------------------------------------------------------

// DnssdPlatform is the interface that platform-specific DNS-SD
// implementations must provide for the advertising proxy.
type DnssdPlatform interface {
	// RegisterService registers a service with DNS-SD.
	RegisterService(instanceName, serviceType string, port uint16, txtData []byte, subTypes []string) error
	// UnregisterService unregisters a service from DNS-SD.
	UnregisterService(serviceType, instanceName string) error
	// RegisterHost registers a host with DNS-SD.
	RegisterHost(name string, addresses [][16]byte) error
	// UnregisterHost unregisters a host from DNS-SD.
	UnregisterHost(name string) error
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

// Counters tracks statistics for the advertising proxy.
type Counters struct {
	// Total is the total number of SRP updates processed.
	Total uint32
	// Succeeded is the number of updates that succeeded.
	Succeeded uint32
	// Failed is the number of updates that failed.
	Failed uint32
	// Rejected is the number of updates that were rejected.
	Rejected uint32
}

// ---------------------------------------------------------------------------
// AdvProxy
// ---------------------------------------------------------------------------

// AdvProxy is the SRP Advertising Proxy. It processes SRP server updates
// and publishes hosts and services through a DnssdPlatform.
type AdvProxy struct {
	platform DnssdPlatform
	state    State
	counters Counters
}

// NewAdvProxy creates a new advertising proxy backed by the given platform.
func NewAdvProxy(platform DnssdPlatform) *AdvProxy {
	return &AdvProxy{
		platform: platform,
		state:    StateStopped,
	}
}

// Start starts the advertising proxy. Returns ErrInvalidState if already
// running, or ErrInvalidArgs if no platform was provided.
func (p *AdvProxy) Start() error {
	if p.platform == nil {
		return errors.ErrInvalidArgs
	}
	if p.state == StateRunning {
		return errors.ErrInvalidState
	}
	p.state = StateRunning
	return nil
}

// Stop stops the advertising proxy.
func (p *AdvProxy) Stop() {
	p.state = StateStopped
}

// GetState returns the current state of the proxy.
func (p *AdvProxy) GetState() State {
	return p.state
}

// GetCounters returns a copy of the current counters.
func (p *AdvProxy) GetCounters() Counters {
	return p.counters
}

// ClearCounters resets all counters to zero.
func (p *AdvProxy) ClearCounters() {
	p.counters = Counters{}
}

// HandleSrpUpdate processes an SRP server update. For each host and
// service, it either registers or unregisters depending on the Deleted
// flag.
func (p *AdvProxy) HandleSrpUpdate(host HostInfo, services []ServiceInfo) {
	if p.state != StateRunning {
		p.counters.Total++
		p.counters.Rejected++
		return
	}

	p.counters.Total++

	failed := false

	// Process host.
	if host.Deleted {
		if err := p.platform.UnregisterHost(host.Name); err != nil {
			failed = true
		}
	} else {
		if err := p.platform.RegisterHost(host.Name, host.Addresses); err != nil {
			failed = true
		}
	}

	// Process services.
	for _, svc := range services {
		if svc.Deleted {
			if err := p.platform.UnregisterService(svc.ServiceType, svc.InstanceName); err != nil {
				failed = true
			}
		} else {
			if err := p.platform.RegisterService(svc.InstanceName, svc.ServiceType, svc.Port, svc.TxtData, svc.SubTypes); err != nil {
				failed = true
			}
		}
	}

	if failed {
		p.counters.Failed++
	} else {
		p.counters.Succeeded++
	}
}
