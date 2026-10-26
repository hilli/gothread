// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package dnssd provides a DNS-SD (DNS-based Service Discovery, RFC 6763)
// abstraction layer for registering and browsing services.
//
// This is a Go port of the DNS-SD module in OpenThread's
// src/core/net/dnssd.hpp and src/core/net/dnssd.cpp. It defines types and
// interfaces; the actual mDNS/DNS-SD transport is a separate concern provided
// through the Platform interface.
package dnssd

import (
	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

// ServiceType identifies the type of DNS-SD operation.
type ServiceType uint8

const (
	// ServiceTypeBrowse browses for service instances.
	ServiceTypeBrowse ServiceType = iota
	// ServiceTypeResolve resolves a service instance.
	ServiceTypeResolve
	// ServiceTypeResolveHost resolves a host address.
	ServiceTypeResolveHost
)

// RequestState tracks the state of a DNS-SD request.
type RequestState uint8

const (
	// RequestStateIdle means no request is outstanding.
	RequestStateIdle RequestState = iota
	// RequestStatePending means the request has been submitted but not yet active.
	RequestStatePending
	// RequestStateActive means the request is actively being processed.
	RequestStateActive
)

// ---------------------------------------------------------------------------
// Registration descriptors
// ---------------------------------------------------------------------------

// ServiceInfo describes a service to register with DNS-SD.
type ServiceInfo struct {
	InstanceName string     // Service instance name (e.g., "My Printer").
	ServiceType  string     // Service type (e.g., "_http._tcp").
	HostName     string     // Host name (e.g., "myhost").
	Port         uint16     // Service port.
	TxtData      []byte     // TXT record data (length-prefixed key=value pairs).
	Priority     uint16     // SRV priority.
	Weight       uint16     // SRV weight.
	TTL          uint32     // TTL in seconds (0 = use default).
	Addresses    [][16]byte // Host addresses (IPv6).
	SubTypes     []string   // Service subtypes.
}

// HostInfo describes a host to register with DNS-SD.
type HostInfo struct {
	HostName  string     // Host name.
	Addresses [][16]byte // Host addresses (IPv6).
	TTL       uint32     // TTL in seconds (0 = use default).
}

// KeyRecord describes a KEY DNS record to register.
type KeyRecord struct {
	Name    string // Owner name of the KEY record.
	KeyData []byte // KEY RDATA.
	TTL     uint32 // TTL in seconds (0 = use default).
}

// ---------------------------------------------------------------------------
// Browse / Resolve results
// ---------------------------------------------------------------------------

// BrowseResult is returned when browsing for services.
type BrowseResult struct {
	InstanceName string // Discovered instance name.
	ServiceType  string // Service type that was browsed.
	TTL          uint32 // Time-to-live in seconds.
}

// ResolveResult is returned when resolving a service instance.
type ResolveResult struct {
	InstanceName string // Resolved instance name.
	ServiceType  string // Service type.
	HostName     string // Target host name.
	Port         uint16 // Service port.
	Priority     uint16 // SRV priority.
	Weight       uint16 // SRV weight.
	TxtData      []byte // TXT record data.
	TTL          uint32 // Time-to-live in seconds.
}

// HostResolveResult is returned when resolving a host.
type HostResolveResult struct {
	HostName  string     // Resolved host name.
	Addresses [][16]byte // Resolved IPv6 addresses.
	TTL       uint32     // Time-to-live in seconds.
}

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

// BrowseCallback is called with browse results.
type BrowseCallback func(result BrowseResult)

// ResolveCallback is called with resolve results.
type ResolveCallback func(result ResolveResult)

// HostResolveCallback is called with host resolve results.
type HostResolveCallback func(result HostResolveResult)

// ---------------------------------------------------------------------------
// Platform interface
// ---------------------------------------------------------------------------

// Platform is the interface that platform-specific DNS-SD implementations
// must provide. Each method either starts/stops a discovery operation or
// registers/unregisters a resource on the infrastructure network.
type Platform interface {
	RegisterService(info ServiceInfo) error
	UnregisterService(instanceName, serviceType string) error
	RegisterHost(info HostInfo) error
	UnregisterHost(hostName string) error
	RegisterKey(record KeyRecord) error
	UnregisterKey(name string) error
	StartBrowse(serviceType string) error
	StopBrowse(serviceType string) error
	StartResolve(instanceName, serviceType string) error
	StopResolve(instanceName, serviceType string) error
	StartResolveHost(hostName string) error
	StopResolveHost(hostName string) error
}

// ---------------------------------------------------------------------------
// Internal request types
// ---------------------------------------------------------------------------

type browseRequest struct {
	serviceType string
	callback    BrowseCallback
}

type resolveRequest struct {
	instanceName string
	serviceType  string
	callback     ResolveCallback
}

type hostResolveRequest struct {
	hostName string
	callback HostResolveCallback
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

// Option configures a Module.
type Option func(*Module)

// WithMaxServices sets the maximum number of registered services.
// Default is 8.
func WithMaxServices(n int) Option {
	return func(m *Module) {
		if n > 0 {
			m.maxServices = n
		}
	}
}

// WithMaxHosts sets the maximum number of registered hosts.
// Default is 4.
func WithMaxHosts(n int) Option {
	return func(m *Module) {
		if n > 0 {
			m.maxHosts = n
		}
	}
}

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

const (
	defaultMaxServices = 8
	defaultMaxHosts    = 4
)

// Module manages DNS-SD operations. It tracks registered services, hosts,
// and key records, and dispatches browse/resolve requests through a
// Platform implementation.
type Module struct {
	platform        Platform
	services        []ServiceInfo
	hosts           []HostInfo
	keys            []KeyRecord
	browseRequests  []browseRequest
	resolveRequests []resolveRequest
	hostResolves    []hostResolveRequest
	maxServices     int
	maxHosts        int
}

// NewModule creates a new DNS-SD module backed by the given Platform
// implementation. Options can override default limits.
func NewModule(platform Platform, opts ...Option) *Module {
	m := &Module{
		platform:    platform,
		maxServices: defaultMaxServices,
		maxHosts:    defaultMaxHosts,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// ---------------------------------------------------------------------------
// Service registration
// ---------------------------------------------------------------------------

// RegisterService registers or updates a service. If the service (identified
// by instance name + service type) already exists it is updated in place.
// Returns errors.ErrNoBufs if the maximum number of services is reached,
// errors.ErrInvalidArgs if required fields are missing.
//
//nolint:gocritic // Keep the value-parameter signature required by the public API.
func (m *Module) RegisterService(info ServiceInfo) error {
	if info.InstanceName == "" || info.ServiceType == "" {
		return errors.ErrInvalidArgs
	}

	// Update existing entry.
	for i := range m.services {
		if m.services[i].InstanceName == info.InstanceName &&
			m.services[i].ServiceType == info.ServiceType {
			m.services[i] = info
			return m.platform.RegisterService(info)
		}
	}

	if len(m.services) >= m.maxServices {
		return errors.ErrNoBufs
	}

	m.services = append(m.services, info)
	return m.platform.RegisterService(info)
}

// UnregisterService removes a previously registered service.
// Returns errors.ErrNotFound if the service is not registered.
func (m *Module) UnregisterService(instanceName, serviceType string) error {
	for i := range m.services {
		if m.services[i].InstanceName == instanceName &&
			m.services[i].ServiceType == serviceType {
			m.services = append(m.services[:i], m.services[i+1:]...)
			return m.platform.UnregisterService(instanceName, serviceType)
		}
	}
	return errors.ErrNotFound
}

// ---------------------------------------------------------------------------
// Host registration
// ---------------------------------------------------------------------------

// RegisterHost registers or updates a host. Returns errors.ErrNoBufs if the
// maximum number of hosts is reached, errors.ErrInvalidArgs if required
// fields are missing.
func (m *Module) RegisterHost(info HostInfo) error {
	if info.HostName == "" {
		return errors.ErrInvalidArgs
	}

	for i := range m.hosts {
		if m.hosts[i].HostName == info.HostName {
			m.hosts[i] = info
			return m.platform.RegisterHost(info)
		}
	}

	if len(m.hosts) >= m.maxHosts {
		return errors.ErrNoBufs
	}

	m.hosts = append(m.hosts, info)
	return m.platform.RegisterHost(info)
}

// UnregisterHost removes a previously registered host.
// Returns errors.ErrNotFound if the host is not registered.
func (m *Module) UnregisterHost(hostName string) error {
	for i := range m.hosts {
		if m.hosts[i].HostName == hostName {
			m.hosts = append(m.hosts[:i], m.hosts[i+1:]...)
			return m.platform.UnregisterHost(hostName)
		}
	}
	return errors.ErrNotFound
}

// ---------------------------------------------------------------------------
// Key registration
// ---------------------------------------------------------------------------

// RegisterKey registers or updates a KEY record.
// Returns errors.ErrInvalidArgs if the name is empty.
func (m *Module) RegisterKey(record KeyRecord) error {
	if record.Name == "" {
		return errors.ErrInvalidArgs
	}

	for i := range m.keys {
		if m.keys[i].Name == record.Name {
			m.keys[i] = record
			return m.platform.RegisterKey(record)
		}
	}

	m.keys = append(m.keys, record)
	return m.platform.RegisterKey(record)
}

// UnregisterKey removes a previously registered KEY record.
// Returns errors.ErrNotFound if the key is not registered.
func (m *Module) UnregisterKey(name string) error {
	for i := range m.keys {
		if m.keys[i].Name == name {
			m.keys = append(m.keys[:i], m.keys[i+1:]...)
			return m.platform.UnregisterKey(name)
		}
	}
	return errors.ErrNotFound
}

// ---------------------------------------------------------------------------
// Browse
// ---------------------------------------------------------------------------

// Browse starts browsing for service instances of the given type.
// The callback is invoked for each result delivered via HandleBrowseResult.
// Returns errors.ErrAlready if a browse for the same service type is active.
func (m *Module) Browse(serviceType string, cb BrowseCallback) error {
	if serviceType == "" || cb == nil {
		return errors.ErrInvalidArgs
	}

	for _, r := range m.browseRequests {
		if r.serviceType == serviceType {
			return errors.ErrAlready
		}
	}

	if err := m.platform.StartBrowse(serviceType); err != nil {
		return err
	}

	m.browseRequests = append(m.browseRequests, browseRequest{
		serviceType: serviceType,
		callback:    cb,
	})
	return nil
}

// StopBrowse stops a previously started browse operation.
// Returns errors.ErrNotFound if no browse is active for the given type.
func (m *Module) StopBrowse(serviceType string) error {
	for i, r := range m.browseRequests {
		if r.serviceType == serviceType {
			m.browseRequests = append(m.browseRequests[:i], m.browseRequests[i+1:]...)
			return m.platform.StopBrowse(serviceType)
		}
	}
	return errors.ErrNotFound
}

// ---------------------------------------------------------------------------
// Resolve (service instance)
// ---------------------------------------------------------------------------

// Resolve starts resolving a service instance. The callback is invoked for
// each result delivered via HandleResolveResult.
// Returns errors.ErrAlready if a resolve for the same instance is active.
func (m *Module) Resolve(instanceName, serviceType string, cb ResolveCallback) error {
	if instanceName == "" || serviceType == "" || cb == nil {
		return errors.ErrInvalidArgs
	}

	for _, r := range m.resolveRequests {
		if r.instanceName == instanceName && r.serviceType == serviceType {
			return errors.ErrAlready
		}
	}

	if err := m.platform.StartResolve(instanceName, serviceType); err != nil {
		return err
	}

	m.resolveRequests = append(m.resolveRequests, resolveRequest{
		instanceName: instanceName,
		serviceType:  serviceType,
		callback:     cb,
	})
	return nil
}

// StopResolve stops a previously started resolve operation.
// Returns errors.ErrNotFound if no resolve is active for the given instance.
func (m *Module) StopResolve(instanceName, serviceType string) error {
	for i, r := range m.resolveRequests {
		if r.instanceName == instanceName && r.serviceType == serviceType {
			m.resolveRequests = append(m.resolveRequests[:i], m.resolveRequests[i+1:]...)
			return m.platform.StopResolve(instanceName, serviceType)
		}
	}
	return errors.ErrNotFound
}

// ---------------------------------------------------------------------------
// Resolve (host)
// ---------------------------------------------------------------------------

// ResolveHost starts resolving a host name to addresses.
// Returns errors.ErrAlready if a resolve for the same host is active.
func (m *Module) ResolveHost(hostName string, cb HostResolveCallback) error {
	if hostName == "" || cb == nil {
		return errors.ErrInvalidArgs
	}

	for _, r := range m.hostResolves {
		if r.hostName == hostName {
			return errors.ErrAlready
		}
	}

	if err := m.platform.StartResolveHost(hostName); err != nil {
		return err
	}

	m.hostResolves = append(m.hostResolves, hostResolveRequest{
		hostName: hostName,
		callback: cb,
	})
	return nil
}

// StopResolveHost stops a previously started host resolve.
// Returns errors.ErrNotFound if no resolve is active for the given host.
func (m *Module) StopResolveHost(hostName string) error {
	for i, r := range m.hostResolves {
		if r.hostName == hostName {
			m.hostResolves = append(m.hostResolves[:i], m.hostResolves[i+1:]...)
			return m.platform.StopResolveHost(hostName)
		}
	}
	return errors.ErrNotFound
}

// ---------------------------------------------------------------------------
// Result handlers (called from platform)
// ---------------------------------------------------------------------------

// HandleBrowseResult dispatches a browse result to the matching callback.
func (m *Module) HandleBrowseResult(result BrowseResult) {
	for _, r := range m.browseRequests {
		if r.serviceType == result.ServiceType {
			r.callback(result)
			return
		}
	}
}

// HandleResolveResult dispatches a resolve result to the matching callback.
//
//nolint:gocritic // Preserve the public value-parameter API used by platform integrations.
func (m *Module) HandleResolveResult(result ResolveResult) {
	for _, r := range m.resolveRequests {
		if r.instanceName == result.InstanceName && r.serviceType == result.ServiceType {
			r.callback(result)
			return
		}
	}
}

// HandleHostResolveResult dispatches a host resolve result to the matching
// callback.
func (m *Module) HandleHostResolveResult(result HostResolveResult) {
	for _, r := range m.hostResolves {
		if r.hostName == result.HostName {
			r.callback(result)
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

// GetRegisteredServices returns a copy of all registered services.
func (m *Module) GetRegisteredServices() []ServiceInfo {
	out := make([]ServiceInfo, len(m.services))
	copy(out, m.services)
	return out
}

// GetRegisteredHosts returns a copy of all registered hosts.
func (m *Module) GetRegisteredHosts() []HostInfo {
	out := make([]HostInfo, len(m.hosts))
	copy(out, m.hosts)
	return out
}

// IsServiceRegistered reports whether a service with the given instance name
// and service type is currently registered.
func (m *Module) IsServiceRegistered(instanceName, serviceType string) bool {
	for i := range m.services {
		s := &m.services[i]
		if s.InstanceName == instanceName && s.ServiceType == serviceType {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// TXT record helpers
// ---------------------------------------------------------------------------

// EncodeTxtData encodes key-value pairs into DNS TXT record format.
// Each entry is length-prefixed: [len][key=value]. Keys with nil values
// are encoded as [len][key] (boolean flag). The iteration order over the
// map is non-deterministic.
func EncodeTxtData(kvPairs map[string][]byte) []byte {
	var buf []byte
	for k, v := range kvPairs {
		buf = AppendTxtEntry(buf, k, v)
	}
	return buf
}

// DecodeTxtData decodes DNS TXT record format into key-value pairs.
// Returns errors.ErrParse if the data is malformed.
func DecodeTxtData(data []byte) (map[string][]byte, error) {
	result := make(map[string][]byte)
	offset := 0

	for offset < len(data) {
		entryLen := int(data[offset])
		offset++

		if offset+entryLen > len(data) {
			return nil, errors.ErrParse
		}

		entry := data[offset : offset+entryLen]
		offset += entryLen

		if entryLen == 0 {
			// Empty TXT entry; skip.
			continue
		}

		// Split on first '='.
		eqIdx := -1
		for i, b := range entry {
			if b == '=' {
				eqIdx = i
				break
			}
		}

		if eqIdx < 0 {
			// Boolean key, no value.
			key := string(entry)
			if key == "" {
				return nil, errors.ErrParse
			}
			result[key] = nil
		} else {
			key := string(entry[:eqIdx])
			if key == "" {
				return nil, errors.ErrParse
			}
			value := make([]byte, len(entry[eqIdx+1:]))
			copy(value, entry[eqIdx+1:])
			result[key] = value
		}
	}

	return result, nil
}

// AppendTxtEntry appends a single TXT entry to buf. If value is nil the
// entry is encoded as a boolean flag: [len][key]. Otherwise it is encoded
// as [len][key=value].
func AppendTxtEntry(buf []byte, key string, value []byte) []byte {
	var entryLen int
	if value == nil {
		entryLen = len(key)
	} else {
		entryLen = len(key) + 1 + len(value) // key + '=' + value
	}

	if entryLen > 255 {
		// TXT entries are limited to 255 bytes per RFC 6763.
		entryLen = 255
	}

	buf = append(buf, byte(entryLen))
	buf = append(buf, key...)
	if value != nil {
		buf = append(buf, '=')
		remaining := entryLen - len(key) - 1
		if remaining > len(value) {
			remaining = len(value)
		}
		buf = append(buf, value[:remaining]...)
	}

	return buf
}
