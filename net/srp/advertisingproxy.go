// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the conditions in the
// LICENSE file are met.

package srp

import (
	"bytes"
	"strings"
	"time"

	"github.com/hilli/gothread/net/ip6"
)

// -------------------------------------------------------
// DnsSdPlatform interface
// -------------------------------------------------------

// DnsSdPlatform is the interface for advertising host/service registrations
// on the infrastructure network via a DNS-SD platform (e.g., mDNS, a DNS-SD
// API). The platform calls AdvertisingProxy.HandleRegistered when each
// operation completes.
type DnsSdPlatform interface {
	RegisterHost(requestID uint32, name string, addresses []ip6.Address, ttl uint32)
	UnregisterHost(requestID uint32, name string)
	RegisterService(requestID uint32, hostName string, instanceName string, serviceType string, port uint16, priority uint16, weight uint16, txtData []byte, subTypes []string, ttl uint32)
	UnregisterService(requestID uint32, instanceName string, serviceType string)
	RegisterKey(requestID uint32, name string, serviceType string, keyData []byte, ttl uint32)
	UnregisterKey(requestID uint32, name string, serviceType string)
}

// -------------------------------------------------------
// Advertising Proxy counters
// -------------------------------------------------------

// AdvCounters holds statistics for the advertising proxy.
type AdvCounters struct {
	AdvTotal      uint32 // Total calls to Advertise().
	AdvReplaced   uint32 // Advertisements replaced by a newer one.
	AdvSkipped    uint32 // Advertisements skipped (proxy not running).
	AdvSuccessful uint32 // Successful advertisements.
	AdvRejected   uint32 // Rejected advertisements.
	AdvTimeout    uint32 // Timed-out advertisements.
	StateChanges  uint32 // Number of state changes.
}

// -------------------------------------------------------
// Advertising proxy state
// -------------------------------------------------------

// AdvProxyState represents the current state of the advertising proxy.
type AdvProxyState uint8

const (
	AdvProxyStopped AdvProxyState = iota
	AdvProxyRunning
)

// -------------------------------------------------------
// Per-entry advertising state, keyed by *RegHost/*RegService pointer.
// Each distinct host/service object gets its own entry, matching the
// C++ pattern where flags are stored directly on Host/Service objects.
// -------------------------------------------------------

// advEntry tracks the advertising state of a single host or service.
type advEntry struct {
	isRegistered    bool
	isKeyRegistered bool
	isReplaced      bool
	advID           uint32 // outstanding registration request ID, 0 = none
	keyAdvID        uint32 // outstanding key registration request ID, 0 = none
}

// -------------------------------------------------------
// advInfo: in-flight advertisement batch
// -------------------------------------------------------

// advInfo tracks a single in-flight advertisement request for a host and
// all its services.
type advInfo struct {
	host        *RegHost
	err         error
	expireTime  time.Time
	blockingAdv *advInfo // newer blocked by older for ordering
	requestIDs  map[uint32]bool
	hostName    string // cached host full name
}

// isCompleted returns true when there are no outstanding request IDs
// (or there is an error) and not blocked by an earlier adv.
func (a *advInfo) isCompleted() bool {
	if a.blockingAdv != nil {
		return false
	}
	return a.err != nil || len(a.requestIDs) == 0
}

// -------------------------------------------------------
// AdvertisingProxy
// -------------------------------------------------------

const (
	defaultAdvTimeout = 5 * time.Second
	invalidRequestID  = uint32(0)
)

// AdvertisingProxy watches SRP server host/service registrations and
// advertises them on the infrastructure network via a DnsSdPlatform.
type AdvertisingProxy struct {
	state    AdvProxyState
	server   *Server
	platform DnsSdPlatform

	advInfoList []*advInfo

	// Per-object advertising state, keyed by pointer.
	hostEntries    map[*RegHost]*advEntry
	serviceEntries map[*RegService]*advEntry

	nextRequestID uint32
	advTimeout    time.Duration
	counters      AdvCounters
	timer         Timer

	// Dependency injection for testing.
	now       func() time.Time
	afterFunc func(time.Duration, func()) Timer
}

// AdvProxyOption is a functional option for configuring an AdvertisingProxy.
type AdvProxyOption func(*AdvertisingProxy)

// WithAdvProxyNow injects a clock function for testing.
func WithAdvProxyNow(fn func() time.Time) AdvProxyOption {
	return func(p *AdvertisingProxy) { p.now = fn }
}

// WithAdvProxyAfterFunc injects a timer factory for testing.
func WithAdvProxyAfterFunc(fn func(time.Duration, func()) Timer) AdvProxyOption {
	return func(p *AdvertisingProxy) { p.afterFunc = fn }
}

// WithAdvProxyTimeout sets the advertisement timeout.
func WithAdvProxyTimeout(d time.Duration) AdvProxyOption {
	return func(p *AdvertisingProxy) {
		if d >= defaultAdvTimeout {
			p.advTimeout = d
		}
	}
}

// NewAdvertisingProxy creates a new advertising proxy.
func NewAdvertisingProxy(server *Server, platform DnsSdPlatform, opts ...AdvProxyOption) *AdvertisingProxy {
	p := &AdvertisingProxy{
		state:          AdvProxyStopped,
		server:         server,
		platform:       platform,
		hostEntries:    make(map[*RegHost]*advEntry),
		serviceEntries: make(map[*RegService]*advEntry),
		advTimeout:     defaultAdvTimeout,
		now:            time.Now,
		afterFunc: func(d time.Duration, f func()) Timer {
			return &realTimer{timer: time.AfterFunc(d, f)}
		},
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// realTimer wraps time.Timer to satisfy the Timer interface.
type realTimer struct {
	timer *time.Timer
}

func (t *realTimer) Stop() bool {
	return t.timer.Stop()
}

// -------------------------------------------------------
// Lifecycle
// -------------------------------------------------------

// IsRunning returns true if the proxy is running.
func (p *AdvertisingProxy) IsRunning() bool {
	return p.state == AdvProxyRunning
}

// GetCounters returns the current counters.
func (p *AdvertisingProxy) GetCounters() AdvCounters {
	return p.counters
}

// ResetCounters resets all counters to zero.
func (p *AdvertisingProxy) ResetCounters() {
	p.counters = AdvCounters{}
}

// Start starts the advertising proxy. If already running, this is a no-op.
// When starting, it advertises all existing committed hosts on the server.
func (p *AdvertisingProxy) Start() {
	if p.state == AdvProxyRunning {
		return
	}

	p.state = AdvProxyRunning
	p.counters.StateChanges++

	// Advertise all existing committed hosts.
	for _, host := range p.server.hosts {
		p.advertiseHost(host)
	}
}

// Stop stops the advertising proxy. Outstanding advertisements are rejected.
// Already-registered hosts/services are unregistered.
func (p *AdvertisingProxy) Stop() {
	if p.state == AdvProxyStopped {
		return
	}

	p.state = AdvProxyStopped
	p.counters.StateChanges++

	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}

	// Reject all outstanding advertisements.
	for _, adv := range p.advInfoList {
		p.counters.AdvRejected++
		p.unregisterHostAndServices(adv.host)
		adv.requestIDs = nil
		adv.blockingAdv = nil
	}
	p.advInfoList = nil

	// Unregister all committed hosts.
	for _, host := range p.server.hosts {
		p.unregisterHostAndServices(host)
	}

	// Clear all tracking state.
	p.hostEntries = make(map[*RegHost]*advEntry)
	p.serviceEntries = make(map[*RegService]*advEntry)
}

// -------------------------------------------------------
// Advertise: handle new SRP update for a host
// -------------------------------------------------------

// Advertise processes a newly committed host registration and advertises
// it via the DNS-SD platform. This is called from the server's
// OnCommitHandler.
func (p *AdvertisingProxy) Advertise(host *RegHost) {
	p.counters.AdvTotal++

	if p.state != AdvProxyRunning {
		p.counters.AdvSkipped++
		return
	}

	adv := &advInfo{
		host:       host,
		expireTime: p.now().Add(p.advTimeout),
		requestIDs: make(map[uint32]bool),
		hostName:   host.FullName,
	}
	p.advInfoList = append(p.advInfoList, adv)

	// Compare against outstanding advertisements for the same host.
	for _, existingAdv := range p.advInfoList {
		if existingAdv == adv {
			continue
		}
		if !strings.EqualFold(existingAdv.hostName, host.FullName) {
			continue
		}
		if p.compareAndUpdateHostAndServices(host, existingAdv.host) {
			if adv.blockingAdv == nil {
				p.counters.AdvReplaced++
				adv.blockingAdv = existingAdv
			}
		}
	}

	// Compare against already committed hosts on the server.
	for _, existingHost := range p.server.hosts {
		if existingHost == host {
			continue
		}
		if strings.EqualFold(existingHost.FullName, host.FullName) {
			p.compareAndUpdateHostAndServices(host, existingHost)
			break
		}
	}

	// Perform the actual registration calls.
	p.advertiseHost(host)

	// Check completion or schedule timer.
	if adv.isCompleted() {
		p.handleCompletedAdvs()
	} else {
		p.scheduleTimer()
	}
}

// AdvertiseRemovalOf advertises removal of an already-committed host
// due to lease expiration. Any outstanding advertisement for the same
// host is rejected to prevent re-adding an expired entry.
func (p *AdvertisingProxy) AdvertiseRemovalOf(host *RegHost) {
	if p.state != AdvProxyRunning {
		return
	}

	// Reject any outstanding AdvInfo that matches this host.
	for _, adv := range p.advInfoList {
		if !strings.EqualFold(adv.hostName, host.FullName) {
			continue
		}
		if adv.host.IsDeleted() {
			continue
		}
		adv.err = errAdvAborted
		adv.requestIDs = nil
		adv.blockingAdv = nil
	}

	// Unregister host on platform if it was registered.
	he := p.hostEntries[host]
	if he != nil && he.isRegistered {
		p.platform.UnregisterHost(0, stripDomain(host.FullName, p.server.domain))
		he.isRegistered = false
		he.advID = 0
	}

	// Unregister services on platform if registered.
	for _, svc := range host.Services {
		se := p.serviceEntries[svc]
		if se != nil && se.isRegistered {
			p.platform.UnregisterService(0, svc.InstanceLabel, stripDomain(svc.ServiceName, p.server.domain))
			se.isRegistered = false
			se.advID = 0
		}
	}

	// Unregister keys if key-lease is 0.
	if host.KeyLease == 0 {
		if he != nil && he.isKeyRegistered {
			p.platform.UnregisterKey(0, stripDomain(host.FullName, p.server.domain), "")
			he.isKeyRegistered = false
			he.keyAdvID = 0
		}
		for _, svc := range host.Services {
			se := p.serviceEntries[svc]
			if se != nil && se.isKeyRegistered {
				p.platform.UnregisterKey(0, svc.InstanceLabel, stripDomain(svc.ServiceName, p.server.domain))
				se.isKeyRegistered = false
				se.keyAdvID = 0
			}
		}
	}

	p.handleCompletedAdvs()
}

// AdvertiseRemovalOfService advertises removal of a single service due to
// lease expiration. If an outstanding advertisement is re-adding the service,
// the removal is skipped to ensure the service stays registered.
func (p *AdvertisingProxy) AdvertiseRemovalOfService(svc *RegService, hostFullName string) {
	if p.state != AdvProxyRunning {
		return
	}

	// Check if any outstanding AdvInfo is re-adding this service.
	for _, adv := range p.advInfoList {
		if !strings.EqualFold(adv.hostName, hostFullName) {
			continue
		}
		if adv.host.IsDeleted() {
			continue
		}
		if advSvc := adv.host.FindService(svc.InstanceName); advSvc != nil && !advSvc.IsDeleted {
			return
		}
	}

	se := p.serviceEntries[svc]
	if se != nil && se.isRegistered {
		p.platform.UnregisterService(0, svc.InstanceLabel, stripDomain(svc.ServiceName, p.server.domain))
		se.isRegistered = false
		se.advID = 0
	}

	if svc.KeyLease == 0 && se != nil && se.isKeyRegistered {
		p.platform.UnregisterKey(0, svc.InstanceLabel, stripDomain(svc.ServiceName, p.server.domain))
		se.isKeyRegistered = false
		se.keyAdvID = 0
	}
}

// -------------------------------------------------------
// HandleRegistered: callback from DNS-SD platform
// -------------------------------------------------------

// errAdvAborted is a sentinel error for aborted advertisements.
var errAdvAborted = &advError{"advertisement aborted"}

// errAdvTimeout is a sentinel error for timed-out advertisements.
var errAdvTimeout = &advError{"advertisement timed out"}

// advError is a simple error type for advertising proxy errors.
type advError struct {
	msg string
}

func (e *advError) Error() string { return e.msg }

// HandleRegistered is called by the DNS-SD platform when a registration
// request completes. The requestID matches the ID passed to the platform
// in a Register* call.
func (p *AdvertisingProxy) HandleRegistered(requestID uint32, err error) {
	if p.state != AdvProxyRunning {
		return
	}
	if requestID == invalidRequestID {
		return
	}

	// Update state for all tracked entries.
	p.handleRegisteredOnEntries(requestID, err)

	// Update advInfo entries.
	for _, adv := range p.advInfoList {
		if adv.requestIDs[requestID] {
			delete(adv.requestIDs, requestID)
			if adv.err == nil && err != nil {
				adv.err = err
			}
		}
	}

	p.handleCompletedAdvs()
}

// handleRegisteredOnEntries processes a registration callback across all entries.
func (p *AdvertisingProxy) handleRegisteredOnEntries(requestID uint32, err error) {
	for _, he := range p.hostEntries {
		if he.advID == requestID {
			he.advID = 0
			he.isRegistered = (err == nil)
		}
		if he.keyAdvID == requestID {
			he.keyAdvID = 0
			he.isKeyRegistered = true
		}
	}
	for _, se := range p.serviceEntries {
		if se.advID == requestID {
			se.advID = 0
			se.isRegistered = (err == nil)
		}
		if se.keyAdvID == requestID {
			se.keyAdvID = 0
			se.isKeyRegistered = true
		}
	}
}

// -------------------------------------------------------
// Internal: compare and update
// -------------------------------------------------------

// compareAndUpdateHostAndServices compares a new host against an existing
// host and updates advertising flags. Returns true if the new host
// replaced any entries.
func (p *AdvertisingProxy) compareAndUpdateHostAndServices(newHost, existingHost *RegHost) bool {
	if newHost == existingHost {
		return false
	}

	replaced := p.compareAndUpdateHostEntry(newHost, existingHost)

	for _, svc := range newHost.Services {
		if existingSvc := existingHost.FindService(svc.InstanceName); existingSvc != nil {
			replaced = p.compareAndUpdateServiceEntry(svc, existingSvc, newHost) || replaced
		}
	}

	return replaced
}

// compareAndUpdateHostEntry compares host-level entries and returns true
// if the existing host was replaced.
func (p *AdvertisingProxy) compareAndUpdateHostEntry(newHost, existingHost *RegHost) bool {
	newE := p.getOrCreateHostEntry(newHost)
	existE := p.getOrCreateHostEntry(existingHost)

	// Update key registration status.
	updateKeyRegistrationStatus(newE, existE, newHost.KeyLease)

	if !newHost.IsDeleted() {
		return p.compareAndUpdateEntry(newE, existE,
			func() bool { return hostsMatch(newHost, existingHost) })
	}

	// newHost is removing the host.
	if existingHost.IsDeleted() {
		return false
	}

	// Transfer registration status so decideToAdvertiseHost knows the host
	// was registered and needs unregistration.
	if existE.isRegistered {
		newE.isRegistered = true
	}

	existE.isReplaced = true
	if existE.advID != invalidRequestID {
		existE.advID = invalidRequestID
	}
	return true
}

// compareAndUpdateServiceEntry compares service-level entries and returns true
// if the existing service was replaced.
func (p *AdvertisingProxy) compareAndUpdateServiceEntry(newSvc, existingSvc *RegService, newHost *RegHost) bool {
	newE := p.getOrCreateServiceEntry(newSvc)
	existE := p.getOrCreateServiceEntry(existingSvc)

	// Update key registration status.
	updateKeyRegistrationStatus(newE, existE, newSvc.KeyLease)

	if !newSvc.IsDeleted {
		return p.compareAndUpdateEntry(newE, existE,
			func() bool { return servicesMatch(newSvc, existingSvc) })
	}

	// newSvc is removing the service.
	if existingSvc.IsDeleted {
		return false
	}

	// Transfer registration status so decideToAdvertiseService knows the
	// service was registered and needs unregistration.
	if existE.isRegistered {
		newE.isRegistered = true
	}

	existE.isReplaced = true
	if existE.advID != invalidRequestID {
		existE.advID = invalidRequestID
	}
	return true
}

// compareAndUpdateEntry is the generic compare-and-update logic.
// matchFn returns true if the new entry matches the existing entry.
func (p *AdvertisingProxy) compareAndUpdateEntry(newE, existE *advEntry, matchFn func() bool) bool {
	if newE.isRegistered {
		return false
	}

	if newE.advID != invalidRequestID || existE.isReplaced || !matchFn() {
		// Entries differ or existing is already replaced — mark as replaced.
		existE.isReplaced = true

		if newE.advID == invalidRequestID {
			newE.advID = p.allocateNextRequestID()
		}

		if existE.advID != invalidRequestID {
			existE.advID = newE.advID
		}

		return true
	}

	// Entries match and existing is not replaced.
	if newE.advID != invalidRequestID {
		return false
	}

	if existE.isRegistered {
		newE.isRegistered = true
	} else if existE.advID != invalidRequestID {
		newE.advID = existE.advID
	} else {
		// Previously failed — retry.
		newE.advID = p.allocateNextRequestID()
		existE.isReplaced = true
	}

	return false
}

// -------------------------------------------------------
// Internal: host/service entry match functions
// -------------------------------------------------------

// hostsMatch returns true if the two hosts have the same advertising-relevant data.
func hostsMatch(a, b *RegHost) bool {
	if a.IsDeleted() != b.IsDeleted() {
		return false
	}
	if a.IsDeleted() {
		return true
	}
	if len(a.Addresses) != len(b.Addresses) {
		return false
	}
	for _, addr := range a.Addresses {
		found := false
		for _, bAddr := range b.Addresses {
			if addr == bAddr {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// servicesMatch returns true if the two services have the same advertising-relevant data.
func servicesMatch(a, b *RegService) bool {
	if a.IsDeleted != b.IsDeleted {
		return false
	}
	if a.IsDeleted {
		return true
	}
	if a.Port != b.Port || a.Weight != b.Weight || a.Priority != b.Priority || a.TTL != b.TTL {
		return false
	}
	if len(a.SubTypes) != len(b.SubTypes) {
		return false
	}
	for _, sub := range a.SubTypes {
		found := false
		for _, bSub := range b.SubTypes {
			if strings.EqualFold(sub, bSub) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if !bytes.Equal(a.TxtData, b.TxtData) {
		return false
	}
	return true
}

// -------------------------------------------------------
// Internal: key registration status
// -------------------------------------------------------

func updateKeyRegistrationStatus(newE, existE *advEntry, keyLease uint32) {
	if keyLease == 0 {
		// Even when key lease is 0 (unregister), transfer the registered
		// status so the caller knows keys need to be unregistered.
		if existE.isKeyRegistered {
			newE.isKeyRegistered = true
		}
		return
	}
	if newE.isKeyRegistered || newE.keyAdvID != invalidRequestID {
		return
	}
	if existE.isKeyRegistered {
		newE.isKeyRegistered = true
	} else {
		newE.keyAdvID = existE.keyAdvID
	}
}

// -------------------------------------------------------
// Internal: advertise host and services
// -------------------------------------------------------

// advertiseHost performs the actual platform registration calls for a host
// and its services.
func (p *AdvertisingProxy) advertiseHost(host *RegHost) {
	he := p.getOrCreateHostEntry(host)
	domain := p.server.domain

	shouldUnregisterHost := host.IsDeleted()
	shouldUnregisterKeys := host.KeyLease == 0

	// Determine what needs to be registered for the host.
	hostNeedsRegister, hostNeedsKeyRegister := p.decideToAdvertiseHost(he, host)

	// Determine what needs to be registered for each service.
	type svcAction struct {
		svc              *RegService
		se               *advEntry
		needsRegister    bool
		needsKeyRegister bool
	}
	var svcActions []svcAction
	for _, svc := range host.Services {
		se := p.getOrCreateServiceEntry(svc)
		nr, nkr := p.decideToAdvertiseService(se, svc, shouldUnregisterHost, shouldUnregisterKeys)
		svcActions = append(svcActions, svcAction{svc: svc, se: se, needsRegister: nr, needsKeyRegister: nkr})
	}

	// Find the current advInfo for this host (if any).
	var currentAdv *advInfo
	for i := len(p.advInfoList) - 1; i >= 0; i-- {
		if p.advInfoList[i].host == host {
			currentAdv = p.advInfoList[i]
			break
		}
	}

	// Register key for host.
	if shouldUnregisterKeys {
		if he.isKeyRegistered {
			p.platform.UnregisterKey(0, stripDomain(host.FullName, domain), "")
			he.isKeyRegistered = false
			he.keyAdvID = invalidRequestID
		}
	} else if hostNeedsKeyRegister {
		keyData := marshalKeyData(host)
		p.platform.RegisterKey(he.keyAdvID, stripDomain(host.FullName, domain), "", keyData, host.TTL)
		if currentAdv != nil {
			currentAdv.requestIDs[he.keyAdvID] = true
		}
	}

	// Register host (before services if registering, after if unregistering).
	if hostNeedsRegister && !shouldUnregisterHost {
		p.platform.RegisterHost(he.advID, stripDomain(host.FullName, domain), host.Addresses, host.TTL)
		if currentAdv != nil {
			currentAdv.requestIDs[he.advID] = true
		}
	}

	// Register/unregister services.
	for _, sa := range svcActions {
		if shouldUnregisterKeys {
			if sa.se.isKeyRegistered {
				p.platform.UnregisterKey(0, sa.svc.InstanceLabel, stripDomain(sa.svc.ServiceName, domain))
				sa.se.isKeyRegistered = false
				sa.se.keyAdvID = invalidRequestID
			}
		} else if sa.needsKeyRegister {
			keyData := marshalKeyData(host)
			p.platform.RegisterKey(sa.se.keyAdvID, sa.svc.InstanceLabel, stripDomain(sa.svc.ServiceName, domain), keyData, sa.svc.TTL)
			if currentAdv != nil {
				currentAdv.requestIDs[sa.se.keyAdvID] = true
			}
		}

		if sa.needsRegister {
			if shouldUnregisterHost || sa.svc.IsDeleted {
				p.platform.UnregisterService(0, sa.svc.InstanceLabel, stripDomain(sa.svc.ServiceName, domain))
				sa.se.isRegistered = false
				sa.se.advID = invalidRequestID
			} else {
				p.platform.RegisterService(sa.se.advID, stripDomain(host.FullName, domain),
					sa.svc.InstanceLabel, stripDomain(sa.svc.ServiceName, domain),
					sa.svc.Port, sa.svc.Priority, sa.svc.Weight, sa.svc.TxtData,
					sa.svc.SubTypes, sa.svc.TTL)
				if currentAdv != nil {
					currentAdv.requestIDs[sa.se.advID] = true
				}
			}
		}
	}

	// Unregister host (after services if unregistering).
	if hostNeedsRegister && shouldUnregisterHost {
		p.platform.UnregisterHost(0, stripDomain(host.FullName, domain))
		he.isRegistered = false
		he.advID = invalidRequestID
	}
}

// decideToAdvertiseHost determines if a host needs registration and key
// registration. Returns (needsRegister, needsKeyRegister).
func (p *AdvertisingProxy) decideToAdvertiseHost(he *advEntry, host *RegHost) (bool, bool) {
	needsKeyRegister := false
	if !he.isKeyRegistered && he.keyAdvID == invalidRequestID && host.KeyLease != 0 {
		he.keyAdvID = p.allocateNextRequestID()
		needsKeyRegister = true
	}

	needsRegister := false
	if host.IsDeleted() {
		needsRegister = he.isRegistered
	} else if !he.isRegistered && he.advID == invalidRequestID {
		he.advID = p.allocateNextRequestID()
		needsRegister = true
	} else if !he.isRegistered && he.advID != invalidRequestID {
		// advID was already allocated by compareAndUpdateEntry (update case).
		needsRegister = true
	}

	return needsRegister, needsKeyRegister
}

// decideToAdvertiseService determines if a service needs registration and key
// registration. Returns (needsRegister, needsKeyRegister).
func (p *AdvertisingProxy) decideToAdvertiseService(se *advEntry, svc *RegService,
	shouldUnregisterHost, shouldUnregisterKeys bool) (bool, bool) {

	needsKeyRegister := false
	if !shouldUnregisterKeys && !se.isKeyRegistered && se.keyAdvID == invalidRequestID && svc.KeyLease != 0 {
		se.keyAdvID = p.allocateNextRequestID()
		needsKeyRegister = true
	}

	needsRegister := false
	if shouldUnregisterHost || svc.IsDeleted {
		needsRegister = se.isRegistered
	} else if !se.isRegistered && se.advID == invalidRequestID {
		se.advID = p.allocateNextRequestID()
		needsRegister = true
	} else if !se.isRegistered && se.advID != invalidRequestID {
		// advID was already allocated by compareAndUpdateEntry (update case).
		needsRegister = true
	}

	return needsRegister, needsKeyRegister
}

// -------------------------------------------------------
// Internal: unregister host and all its services/keys
// -------------------------------------------------------

func (p *AdvertisingProxy) unregisterHostAndServices(host *RegHost) {
	domain := p.server.domain

	for _, svc := range host.Services {
		se := p.serviceEntries[svc]
		if se == nil {
			continue
		}
		if se.isKeyRegistered {
			p.platform.UnregisterKey(0, svc.InstanceLabel, stripDomain(svc.ServiceName, domain))
			se.isKeyRegistered = false
		}
		if se.isRegistered {
			p.platform.UnregisterService(0, svc.InstanceLabel, stripDomain(svc.ServiceName, domain))
			se.isRegistered = false
		}
		se.advID = invalidRequestID
		se.keyAdvID = invalidRequestID
	}

	he := p.hostEntries[host]
	if he == nil {
		return
	}
	if he.isKeyRegistered {
		p.platform.UnregisterKey(0, stripDomain(host.FullName, domain), "")
		he.isKeyRegistered = false
	}
	if he.isRegistered {
		p.platform.UnregisterHost(0, stripDomain(host.FullName, domain))
		he.isRegistered = false
	}
	he.advID = invalidRequestID
	he.keyAdvID = invalidRequestID
}

// -------------------------------------------------------
// Internal: completion handling
// -------------------------------------------------------

// handleCompletedAdvs checks for completed advInfos and signals completion.
func (p *AdvertisingProxy) handleCompletedAdvs() {
	for {
		found := false
		for i := 0; i < len(p.advInfoList); i++ {
			adv := p.advInfoList[i]
			if !adv.isCompleted() {
				continue
			}
			// Remove from list.
			p.advInfoList = append(p.advInfoList[:i], p.advInfoList[i+1:]...)
			i--
			found = true

			// Unblock any adv that was blocked by this one.
			for _, other := range p.advInfoList {
				if other.blockingAdv == adv {
					other.blockingAdv = nil
				}
			}

			// Update counters.
			switch {
			case adv.err == nil:
				p.counters.AdvSuccessful++
			case adv.err == errAdvTimeout:
				p.counters.AdvTimeout++
			default:
				p.counters.AdvRejected++
			}
		}
		if !found {
			break
		}
	}

	p.scheduleTimer()
}

// handleTimer is called when the advertisement timeout fires.
func (p *AdvertisingProxy) handleTimer() {
	if p.state != AdvProxyRunning {
		return
	}

	now := p.now()

	for _, adv := range p.advInfoList {
		if !adv.expireTime.After(now) {
			adv.err = errAdvTimeout
			adv.requestIDs = nil
			adv.blockingAdv = nil
		}
	}

	p.handleCompletedAdvs()
}

// scheduleTimer sets the timer to the earliest expiring advInfo.
func (p *AdvertisingProxy) scheduleTimer() {
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}

	if len(p.advInfoList) == 0 {
		return
	}

	earliest := p.advInfoList[0].expireTime
	for _, adv := range p.advInfoList[1:] {
		if adv.expireTime.Before(earliest) {
			earliest = adv.expireTime
		}
	}

	delay := earliest.Sub(p.now())
	if delay <= 0 {
		p.handleTimer()
		return
	}

	p.timer = p.afterFunc(delay, p.handleTimer)
}

// -------------------------------------------------------
// Internal: helpers
// -------------------------------------------------------

func (p *AdvertisingProxy) allocateNextRequestID() uint32 {
	p.nextRequestID++
	if p.nextRequestID == invalidRequestID {
		p.nextRequestID++
	}
	return p.nextRequestID
}

func (p *AdvertisingProxy) getOrCreateHostEntry(host *RegHost) *advEntry {
	if e, ok := p.hostEntries[host]; ok {
		return e
	}
	e := &advEntry{}
	p.hostEntries[host] = e
	return e
}

func (p *AdvertisingProxy) getOrCreateServiceEntry(svc *RegService) *advEntry {
	if e, ok := p.serviceEntries[svc]; ok {
		return e
	}
	e := &advEntry{}
	p.serviceEntries[svc] = e
	return e
}

// stripDomain removes the domain suffix from a full name.
// e.g., "myhost.default.service.arpa." with domain "default.service.arpa."
// yields "myhost".
func stripDomain(fullName, domain string) string {
	lower := strings.ToLower(fullName)
	domLower := strings.ToLower(domain)
	if strings.HasSuffix(lower, "."+domLower) {
		return fullName[:len(fullName)-len(domain)-1]
	}
	if strings.HasSuffix(lower, domLower) {
		return fullName[:len(fullName)-len(domain)]
	}
	return fullName
}

// marshalKeyData encodes the host's public key as a DNS KEY record data
// section (flags + protocol + algorithm + key material). This is a
// simplified encoding for advertising purposes.
func marshalKeyData(host *RegHost) []byte {
	// Encode as: flags(2) + protocol(1) + algorithm(1) + key(64)
	data := make([]byte, 4+64)
	data[0] = 0x01 // flags: auth, conf permitted
	data[1] = 0x00
	data[2] = 3  // DNSSEC protocol
	data[3] = 13 // ECDSA P-256 with SHA-256
	copy(data[4:], host.Key[:])
	return data
}
