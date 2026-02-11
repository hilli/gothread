// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the
//    names of its contributors may be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

// Package mdns implements Multicast DNS (mDNS) per RFC 6762.
//
// This is a Go port of the Multicast DNS implementation in OpenThread's
// src/core/net/mdns.hpp and src/core/net/mdns.cpp.
//
// It provides host, service, and key registration with probing and
// announcement state machines, active browsing and resolving of services,
// a record cache with TTL-based expiry, conflict detection, known-answer
// suppression, and DNS wire format encoding/decoding with name compression.
package mdns

import (
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Error sentinels
// ---------------------------------------------------------------------------

var (
	errInvalidName  = errors.New("mdns: invalid DNS name")
	errInvalidState = errors.New("mdns: invalid state")
	errInvalidArgs  = errors.New("mdns: invalid arguments")
	errAlready      = errors.New("mdns: already registered or browsing")
	errNotFound     = errors.New("mdns: not found")
	errTruncated    = errors.New("mdns: message truncated")
	errNoSpace      = errors.New("mdns: no space in message")
	errDuplicated   = errors.New("mdns: name conflict detected")
	errNotEnabled   = errors.New("mdns: module not enabled")
)

// ---------------------------------------------------------------------------
// Record type constants
// ---------------------------------------------------------------------------

const (
	TypeA    uint16 = 1   // IPv4 host address.
	TypePTR  uint16 = 12  // Domain name pointer.
	TypeTXT  uint16 = 16  // Text strings.
	TypeKey  uint16 = 25  // Public key.
	TypeAAAA uint16 = 28  // IPv6 host address.
	TypeSRV  uint16 = 33  // Service locator.
	TypeNSEC uint16 = 47  // NSEC denial of existence.
	TypeANY  uint16 = 255 // Wildcard match.
)

// ---------------------------------------------------------------------------
// Class constants
// ---------------------------------------------------------------------------

const (
	ClassInternet  uint16 = 1      // Internet class (IN).
	CacheFlushFlag uint16 = 0x8000 // Cache-flush flag (RFC 6762 Section 10.2).
	classMask      uint16 = 0x7FFF // Mask to strip cache-flush bit.
)

// ---------------------------------------------------------------------------
// State represents the registration state of a host, service, or key.
// ---------------------------------------------------------------------------

// State is the registration state of an entry.
type State uint8

const (
	// StateProbing indicates the entry is being probed for uniqueness.
	StateProbing State = iota
	// StateRegistered indicates the entry has been successfully registered.
	StateRegistered
	// StateConflict indicates a name conflict was detected.
	StateConflict
)

func (s State) String() string {
	switch s {
	case StateProbing:
		return "probing"
	case StateRegistered:
		return "registered"
	case StateConflict:
		return "conflict"
	default:
		return "unknown"
	}
}

// ---------------------------------------------------------------------------
// Timing constants (RFC 6762)
// ---------------------------------------------------------------------------

const (
	defaultPort    uint16 = 5353
	defaultMaxSize        = 1200

	probeCount    = 3                      // Number of probes before claiming.
	probeInterval = 250 * time.Millisecond // Interval between probes.

	announceCount    = 2               // Number of announcements after probing.
	announceInterval = 1 * time.Second // Interval between announcements.

	defaultAddrTTL    uint32 = 120  // Default TTL for address records (2 min).
	defaultServiceTTL uint32 = 4500 // Default TTL for SRV/TXT/PTR records (75 min).
	defaultKeyTTL     uint32 = 4500 // Default TTL for KEY records.
	nsecTTL           uint32 = 4500 // TTL for NSEC records.
	servicesPtrTTL    uint32 = 4500 // TTL for _services._dns-sd PTR records.

	localDomain        = "local"
	servicesDNSSDLabel = "_services._dns-sd._udp"
)

// ---------------------------------------------------------------------------
// Platform interface — abstracts network I/O for testability.
// ---------------------------------------------------------------------------

// Platform defines the interface for sending/receiving mDNS packets.
type Platform interface {
	// SendMulticast sends a packet to the mDNS multicast group.
	SendMulticast(data []byte) error
	// SendUnicast sends a packet to a specific destination.
	SendUnicast(data []byte, dst net.IP, port uint16) error
	// SetReceiveCallback sets the callback for incoming mDNS packets.
	SetReceiveCallback(cb func(data []byte, src net.IP, srcPort uint16))
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// Config holds the configuration for the mDNS core.
type Config struct {
	// MulticastAddress is the mDNS multicast group address.
	// Default: "ff02::fb" (IPv6 mDNS multicast).
	MulticastAddress string
	// Port is the mDNS port. Default: 5353.
	Port uint16
	// HostName is the local hostname (without ".local" suffix).
	HostName string
	// MaxMessageSize limits the outgoing message size. Default: 1200.
	MaxMessageSize int
}

func (cfg *Config) applyDefaults() {
	if cfg.Port == 0 {
		cfg.Port = defaultPort
	}
	if cfg.MulticastAddress == "" {
		cfg.MulticastAddress = "ff02::fb"
	}
	if cfg.MaxMessageSize <= 0 {
		cfg.MaxMessageSize = defaultMaxSize
	}
}

// ---------------------------------------------------------------------------
// HostInfo — host registration info
// ---------------------------------------------------------------------------

// HostInfo describes a host to register on mDNS.
type HostInfo struct {
	Name      string   // Host name (without ".local" suffix).
	Addresses []net.IP // IPv6 addresses to advertise.
	TTL       uint32   // TTL in seconds. 0 means use default.
}

func (h *HostInfo) effectiveTTL() uint32 {
	if h.TTL == 0 {
		return defaultAddrTTL
	}
	return h.TTL
}

func (h *HostInfo) fqdn() string {
	return h.Name + "." + localDomain
}

// ---------------------------------------------------------------------------
// ServiceInfo — service registration info
// ---------------------------------------------------------------------------

// ServiceInfo describes a service to register on mDNS.
type ServiceInfo struct {
	ServiceType  string   // e.g. "_http._tcp"
	SubTypes     []string // Sub-type labels (optional).
	InstanceName string   // Service instance label (may contain dots).
	HostName     string   // Host providing this service (without ".local").
	Port         uint16
	Priority     uint16
	Weight       uint16
	TxtData      []byte
	TTL          uint32 // 0 means use default.
}

func (s *ServiceInfo) effectiveTTL() uint32 {
	if s.TTL == 0 {
		return defaultServiceTTL
	}
	return s.TTL
}

// serviceFQDN returns e.g. "_http._tcp.local"
func (s *ServiceInfo) serviceFQDN() string {
	return s.ServiceType + "." + localDomain
}

// instanceFQDN returns e.g. "My Web Server._http._tcp.local"
func (s *ServiceInfo) instanceFQDN() string {
	return s.InstanceName + "." + s.ServiceType + "." + localDomain
}

// hostFQDN returns e.g. "myhost.local"
func (s *ServiceInfo) hostFQDN() string {
	return s.HostName + "." + localDomain
}

// ---------------------------------------------------------------------------
// KeyRecord — key registration info
// ---------------------------------------------------------------------------

// KeyRecord describes a key record to register on mDNS.
type KeyRecord struct {
	Name        string // Host name or service instance label.
	KeyData     []byte // Key record data.
	ServiceType string // If non-empty, this is a service key record.
}

func (k *KeyRecord) fqdn() string {
	if k.ServiceType != "" {
		return k.Name + "." + k.ServiceType + "." + localDomain
	}
	return k.Name + "." + localDomain
}

func (k *KeyRecord) isServiceKey() bool {
	return k.ServiceType != ""
}

// ---------------------------------------------------------------------------
// Result types for browsers and resolvers
// ---------------------------------------------------------------------------

// BrowseResult is delivered to browser callbacks when a service instance
// is discovered or removed (TTL=0).
type BrowseResult struct {
	ServiceType  string
	InstanceName string
	TTL          uint32
}

// SrvResult is delivered when an SRV record is resolved.
type SrvResult struct {
	InstanceName string
	HostName     string
	Port         uint16
	Priority     uint16
	Weight       uint16
	TTL          uint32
}

// TxtResult is delivered when a TXT record is resolved.
type TxtResult struct {
	InstanceName string
	TxtData      []byte
	TTL          uint32
}

// AddressResult is delivered when an address record is resolved.
type AddressResult struct {
	HostName string
	Address  net.IP
	TTL      uint32
}

// ---------------------------------------------------------------------------
// Host — registered host state machine
// ---------------------------------------------------------------------------

type host struct {
	info          HostInfo
	state         State
	probeCount    int
	announceCount int
	nextAction    time.Time
}

// ---------------------------------------------------------------------------
// ServiceEntry — registered service state machine
// ---------------------------------------------------------------------------

type serviceEntry struct {
	info          ServiceInfo
	state         State
	probeCount    int
	announceCount int
	nextAction    time.Time
}

// ---------------------------------------------------------------------------
// keyEntry — registered key state machine
// ---------------------------------------------------------------------------

type keyEntry struct {
	info          KeyRecord
	state         State
	probeCount    int
	announceCount int
	nextAction    time.Time
}

// ---------------------------------------------------------------------------
// Browser — active service browser
// ---------------------------------------------------------------------------

// Browser tracks an active service browse operation. It queries for PTR
// records of the form "_type._tcp.local" and delivers discovered instances
// via callback.
type Browser struct {
	serviceType string // e.g. "_http._tcp"
	callback    func(BrowseResult)
	nextQuery   time.Time
	queryCount  int
	active      bool
}

// ServiceType returns the service type being browsed.
func (b *Browser) ServiceType() string { return b.serviceType }

// ---------------------------------------------------------------------------
// Resolvers
// ---------------------------------------------------------------------------

// SrvResolver resolves SRV records for a specific service instance.
type SrvResolver struct {
	instanceName string
	serviceType  string
	callback     func(SrvResult)
	nextQuery    time.Time
	queryCount   int
	active       bool
}

// TxtResolver resolves TXT records for a specific service instance.
type TxtResolver struct {
	instanceName string
	serviceType  string
	callback     func(TxtResult)
	nextQuery    time.Time
	queryCount   int
	active       bool
}

// AddressResolver resolves AAAA records for a hostname.
type AddressResolver struct {
	hostName   string
	callback   func(AddressResult)
	nextQuery  time.Time
	queryCount int
	active     bool
}

// ---------------------------------------------------------------------------
// ConflictCallback
// ---------------------------------------------------------------------------

// ConflictCallback is called when a name conflict is detected.
type ConflictCallback func(name, serviceType string)

// ---------------------------------------------------------------------------
// Core — the main mDNS engine
// ---------------------------------------------------------------------------

// Core is the main mDNS engine. It manages registration of hosts, services,
// and keys; active browsers and resolvers; query/response processing; and
// the probing/announcement state machines defined in RFC 6762.
type Core struct {
	mu       sync.Mutex
	platform Platform
	config   Config
	enabled  bool

	// Registration state.
	hosts    map[string]*host         // keyed by lowercase hostname
	services map[string]*serviceEntry // keyed by lowercase "instance.servicetype"
	keys     map[string]*keyEntry     // keyed by lowercase FQDN

	// Browsers and resolvers.
	browsers         []*Browser
	srvResolvers     []*SrvResolver
	txtResolvers     []*TxtResolver
	addressResolvers []*AddressResolver

	// Cache for received records.
	cache *Cache

	// Conflict callback.
	conflictCB ConflictCallback
}

// NewCore creates a new mDNS engine with the given platform and configuration.
func NewCore(platform Platform, config Config) *Core {
	config.applyDefaults()
	c := &Core{
		platform: platform,
		config:   config,
		hosts:    make(map[string]*host),
		services: make(map[string]*serviceEntry),
		keys:     make(map[string]*keyEntry),
		cache:    NewCache(),
		enabled:  true,
	}
	platform.SetReceiveCallback(func(data []byte, src net.IP, srcPort uint16) {
		c.HandleMessage(data, src, srcPort)
	})
	return c
}

// SetConflictCallback sets the callback invoked on name conflicts.
func (c *Core) SetConflictCallback(cb ConflictCallback) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conflictCB = cb
}

// SetEnabled enables or disables the mDNS module.
func (c *Core) SetEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = enabled
	if !enabled {
		c.hosts = make(map[string]*host)
		c.services = make(map[string]*serviceEntry)
		c.keys = make(map[string]*keyEntry)
		c.browsers = nil
		c.srvResolvers = nil
		c.txtResolvers = nil
		c.addressResolvers = nil
		c.cache.Clear()
	}
}

// IsEnabled reports whether the mDNS module is enabled.
func (c *Core) IsEnabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enabled
}

// Cache returns the internal record cache.
func (c *Core) Cache() *Cache {
	return c.cache
}

// ---------------------------------------------------------------------------
// Host registration
// ---------------------------------------------------------------------------

// RegisterHost registers or updates a host entry. The host enters the
// probing state and will transition to registered after successful probing.
func (c *Core) RegisterHost(info HostInfo) error {
	if info.Name == "" {
		return errInvalidArgs
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return errNotEnabled
	}

	key := strings.ToLower(info.Name)
	existing := c.hosts[key]

	if existing != nil && existing.state == StateRegistered {
		// Update: send goodbye for removed addresses, then re-announce.
		c.sendHostGoodbyeLocked(existing)
	}

	now := time.Now()
	c.hosts[key] = &host{
		info:       info,
		state:      StateProbing,
		probeCount: 0,
		nextAction: now,
	}
	return nil
}

// UnregisterHost unregisters a host, sending goodbye announcements (TTL=0).
func (c *Core) UnregisterHost(name string) error {
	if name == "" {
		return errInvalidArgs
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return errNotEnabled
	}

	key := strings.ToLower(name)
	h, ok := c.hosts[key]
	if !ok {
		return nil // Not registered; no action.
	}

	c.sendHostGoodbyeLocked(h)
	delete(c.hosts, key)
	return nil
}

// GetHostState returns the registration state of a host.
func (c *Core) GetHostState(name string) (State, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := strings.ToLower(name)
	h, ok := c.hosts[key]
	if !ok {
		return 0, false
	}
	return h.state, true
}

func (c *Core) sendHostGoodbyeLocked(h *host) {
	if h.state != StateRegistered {
		return
	}
	fqdn := h.info.fqdn()
	mb := newMessageBuilder(c.config.MaxMessageSize)
	mb.setResponse()
	for _, addr := range h.info.Addresses {
		ip := addr.To16()
		if ip == nil {
			continue
		}
		rdata := buildAAAARData(ip)
		if rdata != nil {
			_ = mb.addAnswer(fqdn, TypeAAAA, ClassInternet, 0, rdata)
		}
	}
	if !mb.isEmpty() {
		_ = c.platform.SendMulticast(mb.build())
	}
}

// ---------------------------------------------------------------------------
// Service registration
// ---------------------------------------------------------------------------

// RegisterService registers or updates a service entry.
func (c *Core) RegisterService(info ServiceInfo) error {
	if info.InstanceName == "" || info.ServiceType == "" {
		return errInvalidArgs
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return errNotEnabled
	}

	key := serviceKey(info.InstanceName, info.ServiceType)
	existing := c.services[key]

	if existing != nil && existing.state == StateRegistered {
		c.sendServiceGoodbyeLocked(existing)
	}

	now := time.Now()
	c.services[key] = &serviceEntry{
		info:       info,
		state:      StateProbing,
		probeCount: 0,
		nextAction: now,
	}
	return nil
}

// UnregisterService unregisters a service, sending goodbye announcements.
func (c *Core) UnregisterService(serviceType, instanceName string) error {
	if instanceName == "" || serviceType == "" {
		return errInvalidArgs
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return errNotEnabled
	}

	key := serviceKey(instanceName, serviceType)
	svc, ok := c.services[key]
	if !ok {
		return nil
	}

	c.sendServiceGoodbyeLocked(svc)
	delete(c.services, key)
	return nil
}

// GetServiceState returns the registration state of a service.
func (c *Core) GetServiceState(serviceType, instanceName string) (State, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := serviceKey(instanceName, serviceType)
	svc, ok := c.services[key]
	if !ok {
		return 0, false
	}
	return svc.state, true
}

func (c *Core) sendServiceGoodbyeLocked(svc *serviceEntry) {
	if svc.state != StateRegistered {
		return
	}
	info := &svc.info
	mb := newMessageBuilder(c.config.MaxMessageSize)
	mb.setResponse()

	// PTR goodbye.
	ptrRData, err := buildPTRRData(info.instanceFQDN())
	if err == nil {
		_ = mb.addAnswer(info.serviceFQDN(), TypePTR, ClassInternet, 0, ptrRData)
	}

	// SRV goodbye.
	srvRData, err := buildSRVRData(info.Priority, info.Weight, info.Port, info.hostFQDN())
	if err == nil {
		_ = mb.addAnswer(info.instanceFQDN(), TypeSRV, ClassInternet|CacheFlushFlag, 0, srvRData)
	}

	// TXT goodbye.
	txtRData := buildTXTRData(info.TxtData)
	_ = mb.addAnswer(info.instanceFQDN(), TypeTXT, ClassInternet|CacheFlushFlag, 0, txtRData)

	// Sub-type PTR goodbyes.
	for _, sub := range info.SubTypes {
		subFQDN := sub + "._sub." + info.ServiceType + "." + localDomain
		subPTR, err := buildPTRRData(info.instanceFQDN())
		if err == nil {
			_ = mb.addAnswer(subFQDN, TypePTR, ClassInternet, 0, subPTR)
		}
	}

	if !mb.isEmpty() {
		_ = c.platform.SendMulticast(mb.build())
	}
}

func serviceKey(instanceName, serviceType string) string {
	return strings.ToLower(instanceName + "." + serviceType)
}

// ---------------------------------------------------------------------------
// Key registration
// ---------------------------------------------------------------------------

// RegisterKey registers or updates a key record.
func (c *Core) RegisterKey(key KeyRecord) error {
	if key.Name == "" || len(key.KeyData) == 0 {
		return errInvalidArgs
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return errNotEnabled
	}

	k := strings.ToLower(key.fqdn())
	existing := c.keys[k]

	if existing != nil && existing.state == StateRegistered {
		c.sendKeyGoodbyeLocked(existing)
	}

	now := time.Now()
	c.keys[k] = &keyEntry{
		info:       key,
		state:      StateProbing,
		probeCount: 0,
		nextAction: now,
	}
	return nil
}

// UnregisterKey unregisters a key record, sending goodbye.
func (c *Core) UnregisterKey(name string) error {
	if name == "" {
		return errInvalidArgs
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return errNotEnabled
	}

	// Try as host key first, then iterate to find service keys.
	fqdn := strings.ToLower(name + "." + localDomain)
	if ke, ok := c.keys[fqdn]; ok {
		c.sendKeyGoodbyeLocked(ke)
		delete(c.keys, fqdn)
		return nil
	}

	// Not found as host key; search all keys.
	for k, ke := range c.keys {
		if strings.ToLower(ke.info.Name) == strings.ToLower(name) {
			c.sendKeyGoodbyeLocked(ke)
			delete(c.keys, k)
			return nil
		}
	}

	return nil
}

func (c *Core) sendKeyGoodbyeLocked(ke *keyEntry) {
	if ke.state != StateRegistered {
		return
	}
	fqdn := ke.info.fqdn()
	rdata := buildKeyRData(ke.info.KeyData)
	mb := newMessageBuilder(c.config.MaxMessageSize)
	mb.setResponse()
	_ = mb.addAnswer(fqdn, TypeKey, ClassInternet|CacheFlushFlag, 0, rdata)
	if !mb.isEmpty() {
		_ = c.platform.SendMulticast(mb.build())
	}
}

// ---------------------------------------------------------------------------
// Browser
// ---------------------------------------------------------------------------

// StartBrowser starts an active service browser for the given service type.
// The callback is invoked whenever service instances are discovered or removed.
func (c *Core) StartBrowser(serviceType string, cb func(BrowseResult)) (*Browser, error) {
	if serviceType == "" || cb == nil {
		return nil, errInvalidArgs
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return nil, errNotEnabled
	}

	// Check for duplicate.
	for _, b := range c.browsers {
		if strings.EqualFold(b.serviceType, serviceType) {
			return nil, errAlready
		}
	}

	browser := &Browser{
		serviceType: serviceType,
		callback:    cb,
		nextQuery:   time.Now(),
		active:      true,
	}
	c.browsers = append(c.browsers, browser)

	// Deliver cached results immediately.
	fqdn := serviceType + "." + localDomain
	cached := c.cache.Lookup(fqdn, TypePTR, time.Now())
	for _, entry := range cached {
		instanceName, err := parsePTRRData(entry.RData)
		if err == nil {
			// Strip the service suffix to get instance name.
			suffix := "." + serviceType + "." + localDomain
			inst := strings.TrimSuffix(instanceName, suffix)
			cb(BrowseResult{
				ServiceType:  serviceType,
				InstanceName: inst,
				TTL:          entry.RemainingTTL(time.Now()),
			})
		}
	}

	return browser, nil
}

// StopBrowser stops an active browser.
func (c *Core) StopBrowser(browser *Browser) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, b := range c.browsers {
		if b == browser {
			b.active = false
			c.browsers = append(c.browsers[:i], c.browsers[i+1:]...)
			return
		}
	}
}

// ---------------------------------------------------------------------------
// SRV Resolver
// ---------------------------------------------------------------------------

// StartSrvResolver starts resolving SRV records for a specific service instance.
func (c *Core) StartSrvResolver(instanceName, serviceType string, cb func(SrvResult)) (*SrvResolver, error) {
	if instanceName == "" || serviceType == "" || cb == nil {
		return nil, errInvalidArgs
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return nil, errNotEnabled
	}

	resolver := &SrvResolver{
		instanceName: instanceName,
		serviceType:  serviceType,
		callback:     cb,
		nextQuery:    time.Now(),
		active:       true,
	}
	c.srvResolvers = append(c.srvResolvers, resolver)

	// Deliver cached SRV records.
	fqdn := instanceName + "." + serviceType + "." + localDomain
	cached := c.cache.Lookup(fqdn, TypeSRV, time.Now())
	for _, entry := range cached {
		priority, weight, port, target, err := parseSRVRData(entry.RData)
		if err == nil {
			cb(SrvResult{
				InstanceName: instanceName,
				HostName:     strings.TrimSuffix(target, "."+localDomain),
				Port:         port,
				Priority:     priority,
				Weight:       weight,
				TTL:          entry.RemainingTTL(time.Now()),
			})
		}
	}

	return resolver, nil
}

// StopSrvResolver stops an active SRV resolver.
func (c *Core) StopSrvResolver(resolver *SrvResolver) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, r := range c.srvResolvers {
		if r == resolver {
			r.active = false
			c.srvResolvers = append(c.srvResolvers[:i], c.srvResolvers[i+1:]...)
			return
		}
	}
}

// ---------------------------------------------------------------------------
// TXT Resolver
// ---------------------------------------------------------------------------

// StartTxtResolver starts resolving TXT records for a specific service instance.
func (c *Core) StartTxtResolver(instanceName, serviceType string, cb func(TxtResult)) (*TxtResolver, error) {
	if instanceName == "" || serviceType == "" || cb == nil {
		return nil, errInvalidArgs
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return nil, errNotEnabled
	}

	resolver := &TxtResolver{
		instanceName: instanceName,
		serviceType:  serviceType,
		callback:     cb,
		nextQuery:    time.Now(),
		active:       true,
	}
	c.txtResolvers = append(c.txtResolvers, resolver)

	// Deliver cached TXT records.
	fqdn := instanceName + "." + serviceType + "." + localDomain
	cached := c.cache.Lookup(fqdn, TypeTXT, time.Now())
	for _, entry := range cached {
		cb(TxtResult{
			InstanceName: instanceName,
			TxtData:      entry.RData,
			TTL:          entry.RemainingTTL(time.Now()),
		})
	}

	return resolver, nil
}

// StopTxtResolver stops an active TXT resolver.
func (c *Core) StopTxtResolver(resolver *TxtResolver) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, r := range c.txtResolvers {
		if r == resolver {
			r.active = false
			c.txtResolvers = append(c.txtResolvers[:i], c.txtResolvers[i+1:]...)
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Address Resolver
// ---------------------------------------------------------------------------

// StartAddressResolver starts resolving AAAA records for a hostname.
func (c *Core) StartAddressResolver(hostName string, cb func(AddressResult)) (*AddressResolver, error) {
	if hostName == "" || cb == nil {
		return nil, errInvalidArgs
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return nil, errNotEnabled
	}

	resolver := &AddressResolver{
		hostName:  hostName,
		callback:  cb,
		nextQuery: time.Now(),
		active:    true,
	}
	c.addressResolvers = append(c.addressResolvers, resolver)

	// Deliver cached AAAA records.
	fqdn := hostName + "." + localDomain
	cached := c.cache.Lookup(fqdn, TypeAAAA, time.Now())
	for _, entry := range cached {
		if len(entry.RData) == 16 {
			cb(AddressResult{
				HostName: hostName,
				Address:  net.IP(entry.RData),
				TTL:      entry.RemainingTTL(time.Now()),
			})
		}
	}

	return resolver, nil
}

// StopAddressResolver stops an active address resolver.
func (c *Core) StopAddressResolver(resolver *AddressResolver) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, r := range c.addressResolvers {
		if r == resolver {
			r.active = false
			c.addressResolvers = append(c.addressResolvers[:i], c.addressResolvers[i+1:]...)
			return
		}
	}
}

// ---------------------------------------------------------------------------
// HandleMessage — process incoming mDNS packets
// ---------------------------------------------------------------------------

// HandleMessage processes an incoming mDNS message. It handles both queries
// (by generating responses) and responses (by updating the cache and
// notifying browsers/resolvers).
func (c *Core) HandleMessage(data []byte, src net.IP, srcPort uint16) {
	msg, err := parseMessage(data)
	if err != nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.enabled {
		return
	}

	if msg.Header.isQuery() {
		c.processQueryLocked(msg, src, srcPort)
	} else {
		c.processResponseLocked(msg)
	}
}

// ---------------------------------------------------------------------------
// Query processing — respond to incoming questions
// ---------------------------------------------------------------------------

func (c *Core) processQueryLocked(msg *parsedMessage, src net.IP, srcPort uint16) {
	mb := newMessageBuilder(c.config.MaxMessageSize)
	mb.setResponse()

	// Collect known answers for suppression.
	knownAnswers := msg.Answers

	for _, q := range msg.Questions {
		qname := strings.ToLower(q.Name)
		qtype := q.Type
		qclass := q.Class & classMask

		if qclass != ClassInternet && qclass != uint16(255) { // 255 = ANY class
			continue
		}

		// Check if this is a probe (questions with authority section records).
		isProbe := len(msg.Authorities) > 0

		if isProbe {
			c.handleProbeLocked(msg, qname)
		}

		// Answer from registered hosts.
		for _, h := range c.hosts {
			if h.state != StateRegistered {
				continue
			}
			fqdn := strings.ToLower(h.info.fqdn())
			if qname == fqdn && (qtype == TypeAAAA || qtype == TypeANY) {
				for _, addr := range h.info.Addresses {
					ip := addr.To16()
					if ip == nil {
						continue
					}
					rdata := buildAAAARData(ip)
					if rdata == nil {
						continue
					}
					if !isKnownAnswer(knownAnswers, fqdn, TypeAAAA, rdata) {
						_ = mb.addAnswer(h.info.fqdn(), TypeAAAA, ClassInternet|CacheFlushFlag,
							h.info.effectiveTTL(), rdata)
					}
				}
			}
			if qname == fqdn && (qtype == TypeKey || qtype == TypeANY) {
				// Check for associated key.
				if ke, ok := c.keys[fqdn]; ok && ke.state == StateRegistered {
					rdata := buildKeyRData(ke.info.KeyData)
					if !isKnownAnswer(knownAnswers, fqdn, TypeKey, rdata) {
						_ = mb.addAnswer(ke.info.fqdn(), TypeKey, ClassInternet|CacheFlushFlag,
							defaultKeyTTL, rdata)
					}
				}
			}
		}

		// Answer from registered services.
		for _, svc := range c.services {
			if svc.state != StateRegistered {
				continue
			}
			info := &svc.info
			serviceFQDN := strings.ToLower(info.serviceFQDN())
			instanceFQDN := strings.ToLower(info.instanceFQDN())

			// PTR query for service type.
			if qname == serviceFQDN && (qtype == TypePTR || qtype == TypeANY) {
				ptrRData, err := buildPTRRData(info.instanceFQDN())
				if err == nil && !isKnownAnswer(knownAnswers, serviceFQDN, TypePTR, ptrRData) {
					_ = mb.addAnswer(info.serviceFQDN(), TypePTR, ClassInternet,
						info.effectiveTTL(), ptrRData)
				}
			}

			// Sub-type PTR queries.
			for _, sub := range info.SubTypes {
				subFQDN := strings.ToLower(sub + "._sub." + info.ServiceType + "." + localDomain)
				if qname == subFQDN && (qtype == TypePTR || qtype == TypeANY) {
					ptrRData, err := buildPTRRData(info.instanceFQDN())
					if err == nil && !isKnownAnswer(knownAnswers, subFQDN, TypePTR, ptrRData) {
						_ = mb.addAnswer(sub+"._sub."+info.ServiceType+"."+localDomain,
							TypePTR, ClassInternet, info.effectiveTTL(), ptrRData)
					}
				}
			}

			// SRV query for instance.
			if qname == instanceFQDN && (qtype == TypeSRV || qtype == TypeANY) {
				srvRData, err := buildSRVRData(info.Priority, info.Weight, info.Port, info.hostFQDN())
				if err == nil && !isKnownAnswer(knownAnswers, instanceFQDN, TypeSRV, srvRData) {
					_ = mb.addAnswer(info.instanceFQDN(), TypeSRV, ClassInternet|CacheFlushFlag,
						info.effectiveTTL(), srvRData)
				}
			}

			// TXT query for instance.
			if qname == instanceFQDN && (qtype == TypeTXT || qtype == TypeANY) {
				txtRData := buildTXTRData(info.TxtData)
				if !isKnownAnswer(knownAnswers, instanceFQDN, TypeTXT, txtRData) {
					_ = mb.addAnswer(info.instanceFQDN(), TypeTXT, ClassInternet|CacheFlushFlag,
						info.effectiveTTL(), txtRData)
				}
			}
		}

		// Answer from registered keys.
		for _, ke := range c.keys {
			if ke.state != StateRegistered {
				continue
			}
			fqdn := strings.ToLower(ke.info.fqdn())
			if qname == fqdn && (qtype == TypeKey || qtype == TypeANY) {
				rdata := buildKeyRData(ke.info.KeyData)
				if !isKnownAnswer(knownAnswers, fqdn, TypeKey, rdata) {
					_ = mb.addAnswer(ke.info.fqdn(), TypeKey, ClassInternet|CacheFlushFlag,
						defaultKeyTTL, rdata)
				}
			}
		}

		// _services._dns-sd._udp.local PTR query.
		dnssdFQDN := strings.ToLower(servicesDNSSDLabel + "." + localDomain)
		if qname == dnssdFQDN && (qtype == TypePTR || qtype == TypeANY) {
			// Return PTR records for each unique registered service type.
			seen := make(map[string]bool)
			for _, svc := range c.services {
				if svc.state != StateRegistered {
					continue
				}
				st := strings.ToLower(svc.info.ServiceType)
				if seen[st] {
					continue
				}
				seen[st] = true
				ptrRData, err := buildPTRRData(svc.info.serviceFQDN())
				if err == nil {
					_ = mb.addAnswer(servicesDNSSDLabel+"."+localDomain,
						TypePTR, ClassInternet, servicesPtrTTL, ptrRData)
				}
			}
		}
	}

	if mb.totalRecords() > 0 {
		data := mb.build()
		if srcPort == c.config.Port {
			_ = c.platform.SendMulticast(data)
		} else {
			// Legacy unicast response to non-standard port.
			_ = c.platform.SendUnicast(data, src, srcPort)
		}
	}
}

// handleProbeLocked checks for conflict with incoming probes during our
// own probing phase.
func (c *Core) handleProbeLocked(msg *parsedMessage, qname string) {
	// Check hosts in probing state.
	for _, h := range c.hosts {
		if h.state != StateProbing {
			continue
		}
		fqdn := strings.ToLower(h.info.fqdn())
		if qname == fqdn {
			// Another host is probing for the same name — conflict.
			h.state = StateConflict
			if c.conflictCB != nil {
				c.conflictCB(h.info.Name, "")
			}
		}
	}

	// Check services in probing state.
	for _, svc := range c.services {
		if svc.state != StateProbing {
			continue
		}
		instanceFQDN := strings.ToLower(svc.info.instanceFQDN())
		if qname == instanceFQDN {
			svc.state = StateConflict
			if c.conflictCB != nil {
				c.conflictCB(svc.info.InstanceName, svc.info.ServiceType)
			}
		}
	}

	// Check keys in probing state.
	for _, ke := range c.keys {
		if ke.state != StateProbing {
			continue
		}
		fqdn := strings.ToLower(ke.info.fqdn())
		if qname == fqdn {
			ke.state = StateConflict
			if c.conflictCB != nil {
				c.conflictCB(ke.info.Name, ke.info.ServiceType)
			}
		}
	}
}

// isKnownAnswer checks if a record is already in the known-answer list
// for suppression per RFC 6762 Section 7.1.
func isKnownAnswer(answers []resourceRecord, name string, rtype uint16, rdata []byte) bool {
	nameLower := strings.ToLower(name)
	for _, a := range answers {
		if strings.ToLower(a.Name) == nameLower &&
			a.Type == rtype &&
			a.TTL > 0 &&
			rdataEqual(a.RData, rdata) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Response processing — update cache, notify browsers/resolvers, detect conflicts
// ---------------------------------------------------------------------------

func (c *Core) processResponseLocked(msg *parsedMessage) {
	now := time.Now()

	allRecords := make([]resourceRecord, 0, len(msg.Answers)+len(msg.Additionals))
	allRecords = append(allRecords, msg.Answers...)
	allRecords = append(allRecords, msg.Additionals...)

	for _, rr := range allRecords {
		rrClass := rr.Class & classMask
		if rrClass != ClassInternet {
			continue
		}

		// Check for conflicts with our registered entries.
		c.checkConflictLocked(rr)

		// Update cache.
		c.cache.Add(CacheEntry{
			Name:        rr.Name,
			Type:        rr.Type,
			Class:       rrClass,
			TTL:         rr.TTL,
			RData:       rr.RData,
			ReceiveTime: now,
		})

		// Notify browsers.
		c.notifyBrowsersLocked(rr, now)

		// Notify SRV resolvers.
		c.notifySrvResolversLocked(rr, now)

		// Notify TXT resolvers.
		c.notifyTxtResolversLocked(rr, now)

		// Notify address resolvers.
		c.notifyAddrResolversLocked(rr, now)
	}
}

func (c *Core) checkConflictLocked(rr resourceRecord) {
	rrName := strings.ToLower(rr.Name)

	// Check host conflicts: if we receive an authoritative AAAA record
	// for our hostname with different data while we are probing.
	for _, h := range c.hosts {
		if h.state != StateProbing {
			continue
		}
		fqdn := strings.ToLower(h.info.fqdn())
		if rrName == fqdn && (rr.Type == TypeAAAA || rr.Type == TypeA) &&
			(rr.Class&CacheFlushFlag) != 0 {
			h.state = StateConflict
			if c.conflictCB != nil {
				c.conflictCB(h.info.Name, "")
			}
		}
	}

	// Check service conflicts.
	for _, svc := range c.services {
		if svc.state != StateProbing {
			continue
		}
		instanceFQDN := strings.ToLower(svc.info.instanceFQDN())
		if rrName == instanceFQDN && rr.Type == TypeSRV &&
			(rr.Class&CacheFlushFlag) != 0 {
			svc.state = StateConflict
			if c.conflictCB != nil {
				c.conflictCB(svc.info.InstanceName, svc.info.ServiceType)
			}
		}
	}

	// Check key conflicts.
	for _, ke := range c.keys {
		if ke.state != StateProbing {
			continue
		}
		fqdn := strings.ToLower(ke.info.fqdn())
		if rrName == fqdn && rr.Type == TypeKey &&
			(rr.Class&CacheFlushFlag) != 0 {
			ke.state = StateConflict
			if c.conflictCB != nil {
				c.conflictCB(ke.info.Name, ke.info.ServiceType)
			}
		}
	}
}

func (c *Core) notifyBrowsersLocked(rr resourceRecord, now time.Time) {
	if rr.Type != TypePTR {
		return
	}

	rrName := strings.ToLower(rr.Name)
	for _, b := range c.browsers {
		if !b.active {
			continue
		}
		serviceFQDN := strings.ToLower(b.serviceType + "." + localDomain)
		if rrName != serviceFQDN {
			continue
		}
		instanceFull, err := parsePTRRData(rr.RData)
		if err != nil {
			continue
		}
		suffix := "." + b.serviceType + "." + localDomain
		inst := strings.TrimSuffix(instanceFull, suffix)
		b.callback(BrowseResult{
			ServiceType:  b.serviceType,
			InstanceName: inst,
			TTL:          rr.TTL,
		})
	}
}

func (c *Core) notifySrvResolversLocked(rr resourceRecord, now time.Time) {
	if rr.Type != TypeSRV {
		return
	}

	rrName := strings.ToLower(rr.Name)
	for _, r := range c.srvResolvers {
		if !r.active {
			continue
		}
		fqdn := strings.ToLower(r.instanceName + "." + r.serviceType + "." + localDomain)
		if rrName != fqdn {
			continue
		}
		priority, weight, port, target, err := parseSRVRData(rr.RData)
		if err != nil {
			continue
		}
		r.callback(SrvResult{
			InstanceName: r.instanceName,
			HostName:     strings.TrimSuffix(target, "."+localDomain),
			Port:         port,
			Priority:     priority,
			Weight:       weight,
			TTL:          rr.TTL,
		})
	}
}

func (c *Core) notifyTxtResolversLocked(rr resourceRecord, now time.Time) {
	if rr.Type != TypeTXT {
		return
	}

	rrName := strings.ToLower(rr.Name)
	for _, r := range c.txtResolvers {
		if !r.active {
			continue
		}
		fqdn := strings.ToLower(r.instanceName + "." + r.serviceType + "." + localDomain)
		if rrName != fqdn {
			continue
		}
		r.callback(TxtResult{
			InstanceName: r.instanceName,
			TxtData:      rr.RData,
			TTL:          rr.TTL,
		})
	}
}

func (c *Core) notifyAddrResolversLocked(rr resourceRecord, now time.Time) {
	if rr.Type != TypeAAAA {
		return
	}
	if len(rr.RData) != 16 {
		return
	}

	rrName := strings.ToLower(rr.Name)
	for _, r := range c.addressResolvers {
		if !r.active {
			continue
		}
		fqdn := strings.ToLower(r.hostName + "." + localDomain)
		if rrName != fqdn {
			continue
		}
		addr := make(net.IP, 16)
		copy(addr, rr.RData)
		r.callback(AddressResult{
			HostName: r.hostName,
			Address:  addr,
			TTL:      rr.TTL,
		})
	}
}

// ---------------------------------------------------------------------------
// Process — advance state machines
// ---------------------------------------------------------------------------

// Process advances all state machines (probing, announcing, browsing,
// resolving) and returns the duration until the next required wakeup.
// The caller should call Process again after this duration elapses.
func (c *Core) Process(now time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.enabled {
		return time.Hour
	}

	nextWakeup := now.Add(time.Hour) // far future default

	// Process host entries.
	for _, h := range c.hosts {
		next := c.processHostLocked(h, now)
		if next.Before(nextWakeup) {
			nextWakeup = next
		}
	}

	// Process service entries.
	for _, svc := range c.services {
		next := c.processServiceLocked(svc, now)
		if next.Before(nextWakeup) {
			nextWakeup = next
		}
	}

	// Process key entries.
	for _, ke := range c.keys {
		next := c.processKeyLocked(ke, now)
		if next.Before(nextWakeup) {
			nextWakeup = next
		}
	}

	// Process browsers — send periodic queries.
	for _, b := range c.browsers {
		if !b.active {
			continue
		}
		next := c.processBrowserLocked(b, now)
		if next.Before(nextWakeup) {
			nextWakeup = next
		}
	}

	// Process SRV resolvers.
	for _, r := range c.srvResolvers {
		if !r.active {
			continue
		}
		next := c.processSrvResolverLocked(r, now)
		if next.Before(nextWakeup) {
			nextWakeup = next
		}
	}

	// Process TXT resolvers.
	for _, r := range c.txtResolvers {
		if !r.active {
			continue
		}
		next := c.processTxtResolverLocked(r, now)
		if next.Before(nextWakeup) {
			nextWakeup = next
		}
	}

	// Process address resolvers.
	for _, r := range c.addressResolvers {
		if !r.active {
			continue
		}
		next := c.processAddrResolverLocked(r, now)
		if next.Before(nextWakeup) {
			nextWakeup = next
		}
	}

	// Expire stale cache entries.
	c.cache.Expire(now)

	if nextWakeup.Before(now) {
		return 0
	}
	return nextWakeup.Sub(now)
}

// processHostLocked handles the host probing/announcing state machine.
func (c *Core) processHostLocked(h *host, now time.Time) time.Time {
	switch h.state {
	case StateProbing:
		if now.Before(h.nextAction) {
			return h.nextAction
		}
		if h.probeCount < probeCount {
			c.sendHostProbeLocked(h)
			h.probeCount++
			h.nextAction = now.Add(probeInterval)
			return h.nextAction
		}
		// Probing complete — transition to registered.
		h.state = StateRegistered
		h.announceCount = 0
		h.nextAction = now
		return c.processHostLocked(h, now)

	case StateRegistered:
		if h.announceCount < announceCount {
			if now.Before(h.nextAction) {
				return h.nextAction
			}
			c.sendHostAnnounceLocked(h)
			h.announceCount++
			h.nextAction = now.Add(announceInterval)
			return h.nextAction
		}
		return now.Add(time.Hour) // Done announcing.

	case StateConflict:
		return now.Add(time.Hour) // Nothing to do.
	}
	return now.Add(time.Hour)
}

func (c *Core) sendHostProbeLocked(h *host) {
	fqdn := h.info.fqdn()
	mb := newMessageBuilder(c.config.MaxMessageSize)
	// Probe: query with authority records.
	_ = mb.addQuestion(fqdn, TypeANY, ClassInternet)

	// Add our records in the authority section.
	for _, addr := range h.info.Addresses {
		ip := addr.To16()
		if ip == nil {
			continue
		}
		rdata := buildAAAARData(ip)
		if rdata != nil {
			_ = mb.addAuthority(fqdn, TypeAAAA, ClassInternet, h.info.effectiveTTL(), rdata)
		}
	}
	if !mb.isEmpty() {
		_ = c.platform.SendMulticast(mb.build())
	}
}

func (c *Core) sendHostAnnounceLocked(h *host) {
	fqdn := h.info.fqdn()
	mb := newMessageBuilder(c.config.MaxMessageSize)
	mb.setResponse()
	for _, addr := range h.info.Addresses {
		ip := addr.To16()
		if ip == nil {
			continue
		}
		rdata := buildAAAARData(ip)
		if rdata != nil {
			_ = mb.addAnswer(fqdn, TypeAAAA, ClassInternet|CacheFlushFlag,
				h.info.effectiveTTL(), rdata)
		}
	}
	if !mb.isEmpty() {
		_ = c.platform.SendMulticast(mb.build())
	}
}

// processServiceLocked handles the service probing/announcing state machine.
func (c *Core) processServiceLocked(svc *serviceEntry, now time.Time) time.Time {
	switch svc.state {
	case StateProbing:
		if now.Before(svc.nextAction) {
			return svc.nextAction
		}
		if svc.probeCount < probeCount {
			c.sendServiceProbeLocked(svc)
			svc.probeCount++
			svc.nextAction = now.Add(probeInterval)
			return svc.nextAction
		}
		svc.state = StateRegistered
		svc.announceCount = 0
		svc.nextAction = now
		return c.processServiceLocked(svc, now)

	case StateRegistered:
		if svc.announceCount < announceCount {
			if now.Before(svc.nextAction) {
				return svc.nextAction
			}
			c.sendServiceAnnounceLocked(svc)
			svc.announceCount++
			svc.nextAction = now.Add(announceInterval)
			return svc.nextAction
		}
		return now.Add(time.Hour)

	case StateConflict:
		return now.Add(time.Hour)
	}
	return now.Add(time.Hour)
}

func (c *Core) sendServiceProbeLocked(svc *serviceEntry) {
	info := &svc.info
	instanceFQDN := info.instanceFQDN()
	mb := newMessageBuilder(c.config.MaxMessageSize)
	_ = mb.addQuestion(instanceFQDN, TypeANY, ClassInternet)

	// Authority: SRV record.
	srvRData, err := buildSRVRData(info.Priority, info.Weight, info.Port, info.hostFQDN())
	if err == nil {
		_ = mb.addAuthority(instanceFQDN, TypeSRV, ClassInternet, info.effectiveTTL(), srvRData)
	}

	if !mb.isEmpty() {
		_ = c.platform.SendMulticast(mb.build())
	}
}

func (c *Core) sendServiceAnnounceLocked(svc *serviceEntry) {
	info := &svc.info
	mb := newMessageBuilder(c.config.MaxMessageSize)
	mb.setResponse()

	// PTR record: service type -> instance.
	ptrRData, err := buildPTRRData(info.instanceFQDN())
	if err == nil {
		_ = mb.addAnswer(info.serviceFQDN(), TypePTR, ClassInternet, info.effectiveTTL(), ptrRData)
	}

	// SRV record.
	srvRData, err := buildSRVRData(info.Priority, info.Weight, info.Port, info.hostFQDN())
	if err == nil {
		_ = mb.addAnswer(info.instanceFQDN(), TypeSRV, ClassInternet|CacheFlushFlag,
			info.effectiveTTL(), srvRData)
	}

	// TXT record.
	txtRData := buildTXTRData(info.TxtData)
	_ = mb.addAnswer(info.instanceFQDN(), TypeTXT, ClassInternet|CacheFlushFlag,
		info.effectiveTTL(), txtRData)

	// Sub-type PTR records.
	for _, sub := range info.SubTypes {
		subFQDN := sub + "._sub." + info.ServiceType + "." + localDomain
		subPTR, err := buildPTRRData(info.instanceFQDN())
		if err == nil {
			_ = mb.addAnswer(subFQDN, TypePTR, ClassInternet, info.effectiveTTL(), subPTR)
		}
	}

	// _services._dns-sd._udp.local PTR.
	svcPTR, err := buildPTRRData(info.serviceFQDN())
	if err == nil {
		_ = mb.addAdditional(servicesDNSSDLabel+"."+localDomain, TypePTR,
			ClassInternet, servicesPtrTTL, svcPTR)
	}

	if !mb.isEmpty() {
		_ = c.platform.SendMulticast(mb.build())
	}
}

// processKeyLocked handles the key probing/announcing state machine.
func (c *Core) processKeyLocked(ke *keyEntry, now time.Time) time.Time {
	switch ke.state {
	case StateProbing:
		if now.Before(ke.nextAction) {
			return ke.nextAction
		}
		if ke.probeCount < probeCount {
			c.sendKeyProbeLocked(ke)
			ke.probeCount++
			ke.nextAction = now.Add(probeInterval)
			return ke.nextAction
		}
		ke.state = StateRegistered
		ke.announceCount = 0
		ke.nextAction = now
		return c.processKeyLocked(ke, now)

	case StateRegistered:
		if ke.announceCount < announceCount {
			if now.Before(ke.nextAction) {
				return ke.nextAction
			}
			c.sendKeyAnnounceLocked(ke)
			ke.announceCount++
			ke.nextAction = now.Add(announceInterval)
			return ke.nextAction
		}
		return now.Add(time.Hour)

	case StateConflict:
		return now.Add(time.Hour)
	}
	return now.Add(time.Hour)
}

func (c *Core) sendKeyProbeLocked(ke *keyEntry) {
	fqdn := ke.info.fqdn()
	mb := newMessageBuilder(c.config.MaxMessageSize)
	_ = mb.addQuestion(fqdn, TypeANY, ClassInternet)

	rdata := buildKeyRData(ke.info.KeyData)
	_ = mb.addAuthority(fqdn, TypeKey, ClassInternet, defaultKeyTTL, rdata)

	if !mb.isEmpty() {
		_ = c.platform.SendMulticast(mb.build())
	}
}

func (c *Core) sendKeyAnnounceLocked(ke *keyEntry) {
	fqdn := ke.info.fqdn()
	mb := newMessageBuilder(c.config.MaxMessageSize)
	mb.setResponse()
	rdata := buildKeyRData(ke.info.KeyData)
	_ = mb.addAnswer(fqdn, TypeKey, ClassInternet|CacheFlushFlag, defaultKeyTTL, rdata)
	if !mb.isEmpty() {
		_ = c.platform.SendMulticast(mb.build())
	}
}

// processBrowserLocked sends periodic PTR queries for the browser.
func (c *Core) processBrowserLocked(b *Browser, now time.Time) time.Time {
	if now.Before(b.nextQuery) {
		return b.nextQuery
	}

	fqdn := b.serviceType + "." + localDomain
	mb := newMessageBuilder(c.config.MaxMessageSize)
	_ = mb.addQuestion(fqdn, TypePTR, ClassInternet)

	// Add known answers for suppression.
	cached := c.cache.Lookup(fqdn, TypePTR, now)
	for _, entry := range cached {
		remaining := entry.RemainingTTL(now)
		if remaining > 0 {
			_ = mb.addAnswer(fqdn, TypePTR, ClassInternet, remaining, entry.RData)
		}
	}

	data := mb.build()
	_ = c.platform.SendMulticast(data)

	b.queryCount++
	// Exponential backoff for query interval: 1s, 2s, 4s, ... up to 1 hour.
	interval := time.Second
	for i := 0; i < b.queryCount && interval < time.Hour; i++ {
		interval *= 2
	}
	if interval > time.Hour {
		interval = time.Hour
	}
	b.nextQuery = now.Add(interval)
	return b.nextQuery
}

// processSrvResolverLocked sends periodic SRV queries.
func (c *Core) processSrvResolverLocked(r *SrvResolver, now time.Time) time.Time {
	if now.Before(r.nextQuery) {
		return r.nextQuery
	}

	fqdn := r.instanceName + "." + r.serviceType + "." + localDomain
	mb := newMessageBuilder(c.config.MaxMessageSize)
	_ = mb.addQuestion(fqdn, TypeSRV, ClassInternet)
	_ = c.platform.SendMulticast(mb.build())

	r.queryCount++
	interval := queryInterval(r.queryCount)
	r.nextQuery = now.Add(interval)
	return r.nextQuery
}

// processTxtResolverLocked sends periodic TXT queries.
func (c *Core) processTxtResolverLocked(r *TxtResolver, now time.Time) time.Time {
	if now.Before(r.nextQuery) {
		return r.nextQuery
	}

	fqdn := r.instanceName + "." + r.serviceType + "." + localDomain
	mb := newMessageBuilder(c.config.MaxMessageSize)
	_ = mb.addQuestion(fqdn, TypeTXT, ClassInternet)
	_ = c.platform.SendMulticast(mb.build())

	r.queryCount++
	interval := queryInterval(r.queryCount)
	r.nextQuery = now.Add(interval)
	return r.nextQuery
}

// processAddrResolverLocked sends periodic AAAA queries.
func (c *Core) processAddrResolverLocked(r *AddressResolver, now time.Time) time.Time {
	if now.Before(r.nextQuery) {
		return r.nextQuery
	}

	fqdn := r.hostName + "." + localDomain
	mb := newMessageBuilder(c.config.MaxMessageSize)
	_ = mb.addQuestion(fqdn, TypeAAAA, ClassInternet)
	_ = c.platform.SendMulticast(mb.build())

	r.queryCount++
	interval := queryInterval(r.queryCount)
	r.nextQuery = now.Add(interval)
	return r.nextQuery
}

// queryInterval returns the query retry interval with exponential backoff.
func queryInterval(count int) time.Duration {
	interval := time.Second
	for i := 1; i < count && interval < time.Hour; i++ {
		interval *= 2
	}
	if interval > time.Hour {
		interval = time.Hour
	}
	return interval
}
