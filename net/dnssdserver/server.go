// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package dnssdserver implements a DNS-SD query server that answers DNS queries
// for Thread services over the mesh network. It is used by border routers to
// provide DNS-SD proxy functionality.
//
// This is a Go port of the DNS-SD server in OpenThread's
// src/core/net/dnssd_server.hpp and src/core/net/dnssd_server.cpp.
package dnssdserver

import (
	"strings"
	"sync"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// DefaultDomain is the default DNS-SD domain for Thread networks.
const DefaultDomain = "default.service.arpa."

// ServicesDnssdUdp is the well-known name for DNS-SD service type enumeration.
const ServicesDnssdUdp = "_services._dns-sd._udp" //nolint:revive // Preserve the exported API spelling for existing callers.

// ServicesDnssdUdpFull is the fully-qualified service type enumeration name.
const ServicesDnssdUdpFull = ServicesDnssdUdp + "." + DefaultDomain //nolint:revive // Preserve the exported API spelling for existing callers.

// Port is the default DNS server port.
const Port uint16 = 53

// ---------------------------------------------------------------------------
// Query types
// ---------------------------------------------------------------------------

// QueryType specifies the type of DNS-SD query.
type QueryType uint8

const (
	// QueryTypeNone indicates an unspecified query type.
	QueryTypeNone QueryType = iota
	// QueryTypeBrowse browses for service instances (PTR query).
	QueryTypeBrowse
	// QueryTypeResolve resolves a service instance (SRV/TXT query).
	QueryTypeResolve
	// QueryTypeResolveHost resolves a host name (AAAA query).
	QueryTypeResolveHost
)

// ---------------------------------------------------------------------------
// Response codes
// ---------------------------------------------------------------------------

// DNS response codes (RCODE).
const (
	RCodeSuccess        uint8 = 0
	RCodeFormatError    uint8 = 1
	RCodeServerFailure  uint8 = 2
	RCodeNameError      uint8 = 3 // NXDOMAIN
	RCodeNotImplemented uint8 = 4
	RCodeRefused        uint8 = 5
)

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

// ServiceInstanceInfo describes a discovered service instance.
type ServiceInstanceInfo struct {
	FullName  string     // e.g., "My Service._http._tcp.default.service.arpa."
	HostName  string     // e.g., "my-host.default.service.arpa."
	Port      uint16     // Service port.
	Priority  uint16     // SRV priority.
	Weight    uint16     // SRV weight.
	TxtData   []byte     // TXT record data.
	Addresses [][16]byte // Host IPv6 addresses.
	TTL       uint32     // Time-to-live in seconds.
}

// HostInfo describes a discovered host.
type HostInfo struct {
	FullName  string     // Fully-qualified host name.
	Addresses [][16]byte // IPv6 addresses.
	TTL       uint32     // Time-to-live in seconds.
}

// BrowseResult describes the result of browsing a service type.
type BrowseResult struct {
	ServiceType string   // Service type queried.
	Instances   []string // List of instance names.
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

// Counters tracks DNS-SD server statistics.
type Counters struct {
	TotalQueries     uint32
	SuccessResponses uint32
	ServerFailures   uint32
	FormatErrors     uint32
	NameErrors       uint32
	NotImplemented   uint32
	BrowseQueries    uint32
	ResolveQueries   uint32
	HostQueries      uint32
}

// ---------------------------------------------------------------------------
// ServiceResolver interface
// ---------------------------------------------------------------------------

// ServiceResolver is the interface used by the server to look up service
// registrations. An implementation might back this with the SRP server
// or a platform DNS-SD layer.
type ServiceResolver interface {
	// BrowseServices returns instance names for a given service type.
	BrowseServices(serviceType string) ([]string, error)

	// ResolveService resolves a specific service instance.
	ResolveService(instanceName, serviceType string) (*ServiceInstanceInfo, error)

	// ResolveHost resolves a host name to addresses.
	ResolveHost(hostname string) (*HostInfo, error)

	// GetAllServiceTypes returns all registered service types.
	GetAllServiceTypes() ([]string, error)
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

// Server implements a DNS-SD query server. It processes DNS queries and
// answers them by consulting a ServiceResolver.
type Server struct {
	mu       sync.Mutex
	resolver ServiceResolver
	enabled  bool
	running  bool
	counters Counters
}

// NewServer creates a new DNS-SD server backed by the given resolver.
func NewServer(resolver ServiceResolver) *Server {
	return &Server{
		resolver: resolver,
	}
}

// Start starts the DNS-SD server.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}
	s.running = true
	s.enabled = true
	return nil
}

// Stop stops the DNS-SD server.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.running = false
}

// IsRunning reports whether the server is currently running.
func (s *Server) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// SetEnabled enables or disables the server.
func (s *Server) SetEnabled(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = enabled
	if !enabled {
		s.running = false
	}
}

// IsEnabled reports whether the server is enabled.
func (s *Server) IsEnabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enabled
}

// GetCounters returns a snapshot of the server counters.
func (s *Server) GetCounters() Counters {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counters
}

// ResetCounters resets all counters to zero.
func (s *Server) ResetCounters() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counters = Counters{}
}

// HandleQuery processes a DNS query and returns a DNS response.
func (s *Server) HandleQuery(queryData []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.counters.TotalQueries++

	query, err := ParseDnsQuery(queryData)
	if err != nil {
		s.counters.FormatErrors++
		return s.buildErrorResponse(queryData, RCodeFormatError)
	}

	if len(query.Questions) == 0 {
		s.counters.FormatErrors++
		return s.buildErrorResponse(queryData, RCodeFormatError)
	}

	// Process each question. We handle the first question to determine
	// the response; additional questions are included in the question
	// section but answered based on the first.
	q := query.Questions[0]

	var answers []DnsRecord
	var additional []DnsRecord
	var rcode uint8

	switch {
	case isServiceTypeEnumeration(q.Name):
		s.counters.BrowseQueries++
		answers, rcode = s.handleServiceTypeEnumeration(q)

	case q.Type == TypePTR || (q.Type == TypeANY && isServiceQuery(q.Name)):
		s.counters.BrowseQueries++
		answers, additional, rcode = s.handleBrowse(q)

	case q.Type == TypeSRV || q.Type == TypeTXT:
		s.counters.ResolveQueries++
		answers, additional, rcode = s.handleResolve(q)

	case q.Type == TypeAAAA:
		s.counters.HostQueries++
		answers, rcode = s.handleHostResolve(q)

	case q.Type == TypeANY:
		// ANY query for a name — try to resolve as service instance first,
		// then as host.
		answers, additional, rcode = s.handleAnyQuery(q)

	default:
		rcode = RCodeNotImplemented
	}

	s.updateCounters(rcode)

	resp, err := BuildDnsResponse(query, answers, nil, additional, rcode)
	if err != nil {
		s.counters.ServerFailures++
		return s.buildErrorResponse(queryData, RCodeServerFailure)
	}
	return resp, nil
}

// HandleDnsQueryOverCoap processes a DNS query received via CoAP transport.
// The payload is treated as a standard DNS query message.
func (s *Server) HandleDnsQueryOverCoap(message []byte) ([]byte, error) { //nolint:revive // Preserve the exported API spelling for existing callers.
	return s.HandleQuery(message)
}

// ---------------------------------------------------------------------------
// Internal query handlers
// ---------------------------------------------------------------------------

// isServiceTypeEnumeration checks if the query name matches the
// DNS-SD service type enumeration name.
func isServiceTypeEnumeration(name string) bool {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	target := strings.ToLower(strings.TrimSuffix(ServicesDnssdUdpFull, "."))
	return n == target
}

// isServiceQuery checks if a name looks like a service type query
// (contains labels starting with underscore).
func isServiceQuery(name string) bool {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(labels) >= 2 {
		return strings.HasPrefix(labels[0], "_") && strings.HasPrefix(labels[1], "_")
	}
	return false
}

// extractServiceType extracts the service type from a query name by
// stripping the domain suffix.
func extractServiceType(name string) string {
	n := strings.TrimSuffix(name, ".")
	domain := strings.TrimSuffix(DefaultDomain, ".")
	n = strings.TrimSuffix(n, "."+domain)
	return n
}

// extractInstanceAndServiceType splits a fully-qualified instance name
// into instance label and service type.
// e.g., "My Service._http._tcp.default.service.arpa." → "My Service", "_http._tcp"
func extractInstanceAndServiceType(name string) (instance, serviceType string, ok bool) {
	n := strings.TrimSuffix(name, ".")
	domain := strings.TrimSuffix(DefaultDomain, ".")

	if !strings.HasSuffix(n, "."+domain) {
		return "", "", false
	}
	n = strings.TrimSuffix(n, "."+domain)

	// Find the first underscore-prefixed label — that's the start of
	// the service type.
	labels := strings.Split(n, ".")
	if len(labels) < 3 {
		return "", "", false
	}

	// Walk from the end to find where the service type starts (two
	// underscore-prefixed labels: _tcp/_udp and _servicename).
	for i := len(labels) - 1; i >= 1; i-- {
		if strings.HasPrefix(labels[i], "_") && strings.HasPrefix(labels[i-1], "_") {
			instance = strings.Join(labels[:i-1], ".")
			serviceType = strings.Join(labels[i-1:], ".")
			if instance == "" {
				return "", "", false
			}
			return instance, serviceType, true
		}
	}
	return "", "", false
}

// extractHostName extracts the host name from a query for the default domain.
func extractHostName(name string) string {
	return strings.TrimSuffix(name, ".")
}

func (s *Server) handleServiceTypeEnumeration(q DnsQuestion) (records []DnsRecord, responseCode uint8) {
	types, err := s.resolver.GetAllServiceTypes()
	if err != nil {
		return nil, RCodeServerFailure
	}

	var answers []DnsRecord
	for _, svcType := range types {
		fullServiceName := svcType + "." + DefaultDomain
		answers = append(answers, DnsRecord{
			Name:  q.Name,
			Type:  TypePTR,
			Class: ClassIN,
			TTL:   4500,
			RData: EncodePtrRData(fullServiceName),
		})
	}
	return answers, RCodeSuccess
}

func (s *Server) handleBrowse(q DnsQuestion) (answers, additional []DnsRecord, rcode uint8) {
	serviceType := extractServiceType(q.Name)

	instances, err := s.resolver.BrowseServices(serviceType)
	if err != nil {
		return nil, nil, RCodeNameError
	}

	for _, inst := range instances {
		fullInstanceName := inst + "." + serviceType + "." + DefaultDomain
		answers = append(answers, DnsRecord{
			Name:  q.Name,
			Type:  TypePTR,
			Class: ClassIN,
			TTL:   4500,
			RData: EncodePtrRData(fullInstanceName),
		})
	}

	// Append SRV/TXT/AAAA in additional section when there is a single
	// instance (per RFC 6763 recommendation).
	if len(instances) == 1 {
		info, err := s.resolver.ResolveService(instances[0], serviceType)
		if err == nil && info != nil {
			additional = appendServiceRecords(additional, info)
		}
	}

	return answers, additional, RCodeSuccess
}

func (s *Server) handleResolve(q DnsQuestion) (answers, additional []DnsRecord, rcode uint8) {
	instance, serviceType, ok := extractInstanceAndServiceType(q.Name)
	if !ok {
		return nil, nil, RCodeNameError
	}

	info, err := s.resolver.ResolveService(instance, serviceType)
	if err != nil || info == nil {
		return nil, nil, RCodeNameError
	}

	if q.Type == TypeSRV || q.Type == TypeANY {
		answers = append(answers, DnsRecord{
			Name:  q.Name,
			Type:  TypeSRV,
			Class: ClassIN,
			TTL:   info.TTL,
			RData: EncodeSrvRData(info.Priority, info.Weight, info.Port, info.HostName),
		})

		// Add AAAA records in additional section.
		for _, addr := range info.Addresses {
			additional = append(additional, DnsRecord{
				Name:  info.HostName,
				Type:  TypeAAAA,
				Class: ClassIN,
				TTL:   info.TTL,
				RData: EncodeAAAARData(addr),
			})
		}
	}

	if q.Type == TypeTXT || q.Type == TypeANY {
		answers = append(answers, DnsRecord{
			Name:  q.Name,
			Type:  TypeTXT,
			Class: ClassIN,
			TTL:   info.TTL,
			RData: EncodeTxtRData(info.TxtData),
		})
	}

	return answers, additional, RCodeSuccess
}

func (s *Server) handleHostResolve(q DnsQuestion) (records []DnsRecord, responseCode uint8) {
	hostName := extractHostName(q.Name)

	host, err := s.resolver.ResolveHost(hostName)
	if err != nil || host == nil {
		return nil, RCodeNameError
	}

	var answers []DnsRecord
	for _, addr := range host.Addresses {
		answers = append(answers, DnsRecord{
			Name:  q.Name,
			Type:  TypeAAAA,
			Class: ClassIN,
			TTL:   host.TTL,
			RData: EncodeAAAARData(addr),
		})
	}

	return answers, RCodeSuccess
}

func (s *Server) handleAnyQuery(q DnsQuestion) (answers, additional []DnsRecord, rcode uint8) {
	// Try service instance resolve first.
	instance, serviceType, ok := extractInstanceAndServiceType(q.Name)
	if ok {
		info, err := s.resolver.ResolveService(instance, serviceType)
		if err == nil && info != nil {
			answers = append(answers, DnsRecord{
				Name:  q.Name,
				Type:  TypeSRV,
				Class: ClassIN,
				TTL:   info.TTL,
				RData: EncodeSrvRData(info.Priority, info.Weight, info.Port, info.HostName),
			}, DnsRecord{
				Name:  q.Name,
				Type:  TypeTXT,
				Class: ClassIN,
				TTL:   info.TTL,
				RData: EncodeTxtRData(info.TxtData),
			})
			for _, addr := range info.Addresses {
				additional = append(additional, DnsRecord{
					Name:  info.HostName,
					Type:  TypeAAAA,
					Class: ClassIN,
					TTL:   info.TTL,
					RData: EncodeAAAARData(addr),
				})
			}
			s.counters.ResolveQueries++
			return answers, additional, RCodeSuccess
		}
	}

	// Try host resolve.
	hostName := extractHostName(q.Name)
	host, err := s.resolver.ResolveHost(hostName)
	if err == nil && host != nil {
		for _, addr := range host.Addresses {
			answers = append(answers, DnsRecord{
				Name:  q.Name,
				Type:  TypeAAAA,
				Class: ClassIN,
				TTL:   host.TTL,
				RData: EncodeAAAARData(addr),
			})
		}
		s.counters.HostQueries++
		return answers, nil, RCodeSuccess
	}

	return nil, nil, RCodeNameError
}

// appendServiceRecords appends SRV, TXT and AAAA records for a
// service instance to the given slice.
func appendServiceRecords(records []DnsRecord, info *ServiceInstanceInfo) []DnsRecord {
	records = append(records, DnsRecord{
		Name:  info.FullName,
		Type:  TypeSRV,
		Class: ClassIN,
		TTL:   info.TTL,
		RData: EncodeSrvRData(info.Priority, info.Weight, info.Port, info.HostName),
	}, DnsRecord{
		Name:  info.FullName,
		Type:  TypeTXT,
		Class: ClassIN,
		TTL:   info.TTL,
		RData: EncodeTxtRData(info.TxtData),
	})
	for _, addr := range info.Addresses {
		records = append(records, DnsRecord{
			Name:  info.HostName,
			Type:  TypeAAAA,
			Class: ClassIN,
			TTL:   info.TTL,
			RData: EncodeAAAARData(addr),
		})
	}
	return records
}

func (s *Server) updateCounters(rcode uint8) {
	switch rcode {
	case RCodeSuccess:
		s.counters.SuccessResponses++
	case RCodeServerFailure:
		s.counters.ServerFailures++
	case RCodeFormatError:
		s.counters.FormatErrors++
	case RCodeNameError:
		s.counters.NameErrors++
	case RCodeNotImplemented:
		s.counters.NotImplemented++
	}
}

// buildErrorResponse builds a minimal DNS error response. If the query
// data can be parsed for an ID, it is used; otherwise ID 0 is used.
func (s *Server) buildErrorResponse(queryData []byte, rcode uint8) ([]byte, error) {
	var id uint16
	if len(queryData) >= 2 {
		id = uint16(queryData[0])<<8 | uint16(queryData[1])
	}
	q := &DnsQuery{ID: id}
	return BuildDnsResponse(q, nil, nil, nil, rcode)
}
