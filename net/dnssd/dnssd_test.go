// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package dnssd

import (
	"bytes"
	"sort"
	"testing"

	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Mock platform
// ---------------------------------------------------------------------------

type mockPlatform struct {
	registeredServices   []ServiceInfo
	unregisteredServices [][2]string // [instanceName, serviceType]
	registeredHosts      []HostInfo
	unregisteredHosts    []string
	registeredKeys       []KeyRecord
	unregisteredKeys     []string
	browsing             []string
	stoppedBrowses       []string
	resolving            [][2]string // [instanceName, serviceType]
	stoppedResolves      [][2]string
	resolvingHosts       []string
	stoppedHostResolves  []string

	// Controls for error injection.
	registerServiceErr   error
	unregisterServiceErr error
	registerHostErr      error
	unregisterHostErr    error
	registerKeyErr       error
	unregisterKeyErr     error
	startBrowseErr       error
	stopBrowseErr        error
	startResolveErr      error
	stopResolveErr       error
	startResolveHostErr  error
	stopResolveHostErr   error
}

func newMockPlatform() *mockPlatform { return &mockPlatform{} }

//nolint:gocritic // Keep the value-parameter signature required by the public API.
func (p *mockPlatform) RegisterService(info ServiceInfo) error {
	if p.registerServiceErr != nil {
		return p.registerServiceErr
	}
	p.registeredServices = append(p.registeredServices, info)
	return nil
}

func (p *mockPlatform) UnregisterService(instanceName, serviceType string) error {
	if p.unregisterServiceErr != nil {
		return p.unregisterServiceErr
	}
	p.unregisteredServices = append(p.unregisteredServices, [2]string{instanceName, serviceType})
	return nil
}

func (p *mockPlatform) RegisterHost(info HostInfo) error {
	if p.registerHostErr != nil {
		return p.registerHostErr
	}
	p.registeredHosts = append(p.registeredHosts, info)
	return nil
}

func (p *mockPlatform) UnregisterHost(hostName string) error {
	if p.unregisterHostErr != nil {
		return p.unregisterHostErr
	}
	p.unregisteredHosts = append(p.unregisteredHosts, hostName)
	return nil
}

func (p *mockPlatform) RegisterKey(record KeyRecord) error {
	if p.registerKeyErr != nil {
		return p.registerKeyErr
	}
	p.registeredKeys = append(p.registeredKeys, record)
	return nil
}

func (p *mockPlatform) UnregisterKey(name string) error {
	if p.unregisterKeyErr != nil {
		return p.unregisterKeyErr
	}
	p.unregisteredKeys = append(p.unregisteredKeys, name)
	return nil
}

func (p *mockPlatform) StartBrowse(serviceType string) error {
	if p.startBrowseErr != nil {
		return p.startBrowseErr
	}
	p.browsing = append(p.browsing, serviceType)
	return nil
}

func (p *mockPlatform) StopBrowse(serviceType string) error {
	if p.stopBrowseErr != nil {
		return p.stopBrowseErr
	}
	p.stoppedBrowses = append(p.stoppedBrowses, serviceType)
	return nil
}

func (p *mockPlatform) StartResolve(instanceName, serviceType string) error {
	if p.startResolveErr != nil {
		return p.startResolveErr
	}
	p.resolving = append(p.resolving, [2]string{instanceName, serviceType})
	return nil
}

func (p *mockPlatform) StopResolve(instanceName, serviceType string) error {
	if p.stopResolveErr != nil {
		return p.stopResolveErr
	}
	p.stoppedResolves = append(p.stoppedResolves, [2]string{instanceName, serviceType})
	return nil
}

func (p *mockPlatform) StartResolveHost(hostName string) error {
	if p.startResolveHostErr != nil {
		return p.startResolveHostErr
	}
	p.resolvingHosts = append(p.resolvingHosts, hostName)
	return nil
}

func (p *mockPlatform) StopResolveHost(hostName string) error {
	if p.stopResolveHostErr != nil {
		return p.stopResolveHostErr
	}
	p.stoppedHostResolves = append(p.stoppedHostResolves, hostName)
	return nil
}

// ---------------------------------------------------------------------------
// Constructor tests
// ---------------------------------------------------------------------------

func TestNewModuleDefaults(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	if m.maxServices != defaultMaxServices {
		t.Errorf("maxServices = %d, want %d", m.maxServices, defaultMaxServices)
	}
	if m.maxHosts != defaultMaxHosts {
		t.Errorf("maxHosts = %d, want %d", m.maxHosts, defaultMaxHosts)
	}
	if len(m.GetRegisteredServices()) != 0 {
		t.Error("expected no registered services initially")
	}
	if len(m.GetRegisteredHosts()) != 0 {
		t.Error("expected no registered hosts initially")
	}
}

func TestNewModuleWithOptions(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p, WithMaxServices(16), WithMaxHosts(8))

	if m.maxServices != 16 {
		t.Errorf("maxServices = %d, want 16", m.maxServices)
	}
	if m.maxHosts != 8 {
		t.Errorf("maxHosts = %d, want 8", m.maxHosts)
	}
}

func TestOptionIgnoresNonPositive(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p, WithMaxServices(0), WithMaxHosts(-1))

	if m.maxServices != defaultMaxServices {
		t.Errorf("maxServices = %d, want %d", m.maxServices, defaultMaxServices)
	}
	if m.maxHosts != defaultMaxHosts {
		t.Errorf("maxHosts = %d, want %d", m.maxHosts, defaultMaxHosts)
	}
}

// ---------------------------------------------------------------------------
// Service registration tests
// ---------------------------------------------------------------------------

func TestRegisterService(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	info := ServiceInfo{
		InstanceName: "My Printer",
		ServiceType:  "_http._tcp",
		HostName:     "myhost",
		Port:         80,
		Priority:     0,
		Weight:       0,
		TTL:          120,
	}

	if err := m.RegisterService(info); err != nil {
		t.Fatalf("RegisterService: %v", err)
	}

	if len(p.registeredServices) != 1 {
		t.Fatalf("platform saw %d registrations, want 1", len(p.registeredServices))
	}
	if p.registeredServices[0].InstanceName != "My Printer" {
		t.Error("platform did not receive correct instance name")
	}
	if !m.IsServiceRegistered("My Printer", "_http._tcp") {
		t.Error("service should be registered")
	}
}

func TestRegisterServiceUpdate(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	info := ServiceInfo{
		InstanceName: "My Printer",
		ServiceType:  "_http._tcp",
		Port:         80,
	}
	if err := m.RegisterService(info); err != nil {
		t.Fatalf("initial register: %v", err)
	}

	// Update same service with new port.
	info.Port = 8080
	if err := m.RegisterService(info); err != nil {
		t.Fatalf("update register: %v", err)
	}

	// Should still have only one service entry.
	svcs := m.GetRegisteredServices()
	if len(svcs) != 1 {
		t.Fatalf("got %d services, want 1", len(svcs))
	}
	if svcs[0].Port != 8080 {
		t.Errorf("port = %d, want 8080", svcs[0].Port)
	}
	// Platform should have been called twice.
	if len(p.registeredServices) != 2 {
		t.Errorf("platform registrations = %d, want 2", len(p.registeredServices))
	}
}

func TestRegisterServiceInvalidArgs(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	if err := m.RegisterService(ServiceInfo{}); err != errors.ErrInvalidArgs {
		t.Errorf("got %v, want ErrInvalidArgs", err)
	}
	if err := m.RegisterService(ServiceInfo{InstanceName: "x"}); err != errors.ErrInvalidArgs {
		t.Errorf("got %v, want ErrInvalidArgs for missing ServiceType", err)
	}
	if err := m.RegisterService(ServiceInfo{ServiceType: "_tcp"}); err != errors.ErrInvalidArgs {
		t.Errorf("got %v, want ErrInvalidArgs for missing InstanceName", err)
	}
}

func TestRegisterServiceNoBufs(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p, WithMaxServices(2))

	for i := 0; i < 2; i++ {
		info := ServiceInfo{
			InstanceName: string(rune('A' + i)),
			ServiceType:  "_http._tcp",
		}
		if err := m.RegisterService(info); err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
	}

	err := m.RegisterService(ServiceInfo{
		InstanceName: "C",
		ServiceType:  "_http._tcp",
	})
	if err != errors.ErrNoBufs {
		t.Errorf("got %v, want ErrNoBufs", err)
	}
}

func TestUnregisterService(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	info := ServiceInfo{
		InstanceName: "My Printer",
		ServiceType:  "_http._tcp",
	}
	_ = m.RegisterService(info)

	if err := m.UnregisterService("My Printer", "_http._tcp"); err != nil {
		t.Fatalf("UnregisterService: %v", err)
	}

	if m.IsServiceRegistered("My Printer", "_http._tcp") {
		t.Error("service should not be registered after unregister")
	}
	if len(p.unregisteredServices) != 1 {
		t.Fatalf("platform saw %d unregistrations", len(p.unregisteredServices))
	}
}

func TestUnregisterServiceNotFound(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	if err := m.UnregisterService("nope", "_tcp"); err != errors.ErrNotFound {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

func TestRegisterServicePlatformError(t *testing.T) {
	p := newMockPlatform()
	p.registerServiceErr = errors.ErrFailed
	m := NewModule(p)

	err := m.RegisterService(ServiceInfo{
		InstanceName: "svc",
		ServiceType:  "_tcp",
	})
	if err != errors.ErrFailed {
		t.Errorf("got %v, want ErrFailed", err)
	}
}

// ---------------------------------------------------------------------------
// Host registration tests
// ---------------------------------------------------------------------------

func TestRegisterHost(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	info := HostInfo{
		HostName:  "myhost",
		Addresses: [][16]byte{{1}},
		TTL:       300,
	}
	if err := m.RegisterHost(info); err != nil {
		t.Fatalf("RegisterHost: %v", err)
	}

	hosts := m.GetRegisteredHosts()
	if len(hosts) != 1 || hosts[0].HostName != "myhost" {
		t.Error("host not registered correctly")
	}
}

func TestRegisterHostUpdate(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	_ = m.RegisterHost(HostInfo{HostName: "h", TTL: 100})
	_ = m.RegisterHost(HostInfo{HostName: "h", TTL: 200})

	hosts := m.GetRegisteredHosts()
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(hosts))
	}
	if hosts[0].TTL != 200 {
		t.Errorf("TTL = %d, want 200", hosts[0].TTL)
	}
}

func TestRegisterHostInvalidArgs(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	if err := m.RegisterHost(HostInfo{}); err != errors.ErrInvalidArgs {
		t.Errorf("got %v, want ErrInvalidArgs", err)
	}
}

func TestRegisterHostNoBufs(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p, WithMaxHosts(1))

	_ = m.RegisterHost(HostInfo{HostName: "h1"})
	err := m.RegisterHost(HostInfo{HostName: "h2"})
	if err != errors.ErrNoBufs {
		t.Errorf("got %v, want ErrNoBufs", err)
	}
}

func TestUnregisterHost(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	_ = m.RegisterHost(HostInfo{HostName: "h1"})

	if err := m.UnregisterHost("h1"); err != nil {
		t.Fatalf("UnregisterHost: %v", err)
	}
	if len(m.GetRegisteredHosts()) != 0 {
		t.Error("host should have been removed")
	}
}

func TestUnregisterHostNotFound(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	if err := m.UnregisterHost("nope"); err != errors.ErrNotFound {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// Key registration tests
// ---------------------------------------------------------------------------

func TestRegisterKey(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	rec := KeyRecord{Name: "myhost._device", KeyData: []byte{1, 2, 3}, TTL: 600}
	if err := m.RegisterKey(rec); err != nil {
		t.Fatalf("RegisterKey: %v", err)
	}
	if len(p.registeredKeys) != 1 {
		t.Fatalf("platform saw %d key registrations", len(p.registeredKeys))
	}
}

func TestRegisterKeyUpdate(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	_ = m.RegisterKey(KeyRecord{Name: "k", KeyData: []byte{1}})
	_ = m.RegisterKey(KeyRecord{Name: "k", KeyData: []byte{2}})

	// Platform called twice, but module stores only one key.
	if len(p.registeredKeys) != 2 {
		t.Errorf("platform calls = %d, want 2", len(p.registeredKeys))
	}
}

func TestRegisterKeyInvalidArgs(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	if err := m.RegisterKey(KeyRecord{}); err != errors.ErrInvalidArgs {
		t.Errorf("got %v, want ErrInvalidArgs", err)
	}
}

func TestUnregisterKey(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	_ = m.RegisterKey(KeyRecord{Name: "k", KeyData: []byte{1}})
	if err := m.UnregisterKey("k"); err != nil {
		t.Fatalf("UnregisterKey: %v", err)
	}
	if len(p.unregisteredKeys) != 1 {
		t.Fatal("platform not called for unregister")
	}
}

func TestUnregisterKeyNotFound(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	if err := m.UnregisterKey("nope"); err != errors.ErrNotFound {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// Browse tests
// ---------------------------------------------------------------------------

func TestBrowse(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	var results []BrowseResult
	cb := func(r BrowseResult) { results = append(results, r) }

	if err := m.Browse("_http._tcp", cb); err != nil {
		t.Fatalf("Browse: %v", err)
	}
	if len(p.browsing) != 1 || p.browsing[0] != "_http._tcp" {
		t.Error("platform browse not started correctly")
	}

	// Simulate a result from the platform.
	m.HandleBrowseResult(BrowseResult{
		InstanceName: "printer",
		ServiceType:  "_http._tcp",
		TTL:          120,
	})
	if len(results) != 1 || results[0].InstanceName != "printer" {
		t.Error("browse callback not invoked correctly")
	}
}

func TestBrowseAlready(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	_ = m.Browse("_http._tcp", func(BrowseResult) {})
	err := m.Browse("_http._tcp", func(BrowseResult) {})
	if err != errors.ErrAlready {
		t.Errorf("got %v, want ErrAlready", err)
	}
}

func TestBrowseInvalidArgs(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	if err := m.Browse("", func(BrowseResult) {}); err != errors.ErrInvalidArgs {
		t.Errorf("got %v, want ErrInvalidArgs for empty service type", err)
	}
	if err := m.Browse("_tcp", nil); err != errors.ErrInvalidArgs {
		t.Errorf("got %v, want ErrInvalidArgs for nil callback", err)
	}
}

func TestBrowsePlatformError(t *testing.T) {
	p := newMockPlatform()
	p.startBrowseErr = errors.ErrFailed
	m := NewModule(p)

	err := m.Browse("_http._tcp", func(BrowseResult) {})
	if err != errors.ErrFailed {
		t.Errorf("got %v, want ErrFailed", err)
	}
}

func TestStopBrowse(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	_ = m.Browse("_http._tcp", func(BrowseResult) {})
	if err := m.StopBrowse("_http._tcp"); err != nil {
		t.Fatalf("StopBrowse: %v", err)
	}
	if len(p.stoppedBrowses) != 1 {
		t.Error("platform stop not called")
	}

	// After stopping, the result should not be dispatched.
	m.HandleBrowseResult(BrowseResult{ServiceType: "_http._tcp"})
}

func TestStopBrowseNotFound(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	if err := m.StopBrowse("_tcp"); err != errors.ErrNotFound {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// Resolve tests
// ---------------------------------------------------------------------------

func TestResolve(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	var results []ResolveResult
	cb := func(r ResolveResult) { results = append(results, r) }

	if err := m.Resolve("printer", "_http._tcp", cb); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	m.HandleResolveResult(ResolveResult{
		InstanceName: "printer",
		ServiceType:  "_http._tcp",
		HostName:     "printerhost",
		Port:         80,
	})
	if len(results) != 1 || results[0].HostName != "printerhost" {
		t.Error("resolve callback not invoked correctly")
	}
}

func TestResolveAlready(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	_ = m.Resolve("a", "_tcp", func(ResolveResult) {})
	err := m.Resolve("a", "_tcp", func(ResolveResult) {})
	if err != errors.ErrAlready {
		t.Errorf("got %v, want ErrAlready", err)
	}
}

func TestResolveInvalidArgs(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	if err := m.Resolve("", "_tcp", func(ResolveResult) {}); err != errors.ErrInvalidArgs {
		t.Errorf("got %v, want ErrInvalidArgs", err)
	}
	if err := m.Resolve("a", "", func(ResolveResult) {}); err != errors.ErrInvalidArgs {
		t.Errorf("got %v, want ErrInvalidArgs", err)
	}
	if err := m.Resolve("a", "_tcp", nil); err != errors.ErrInvalidArgs {
		t.Errorf("got %v, want ErrInvalidArgs", err)
	}
}

func TestStopResolve(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	_ = m.Resolve("a", "_tcp", func(ResolveResult) {})
	if err := m.StopResolve("a", "_tcp"); err != nil {
		t.Fatalf("StopResolve: %v", err)
	}
	if len(p.stoppedResolves) != 1 {
		t.Error("platform stop not called")
	}
}

func TestStopResolveNotFound(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	if err := m.StopResolve("a", "_tcp"); err != errors.ErrNotFound {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// Host resolve tests
// ---------------------------------------------------------------------------

func TestResolveHost(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	var results []HostResolveResult
	cb := func(r HostResolveResult) { results = append(results, r) }

	if err := m.ResolveHost("myhost", cb); err != nil {
		t.Fatalf("ResolveHost: %v", err)
	}

	addr := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	m.HandleHostResolveResult(HostResolveResult{
		HostName:  "myhost",
		Addresses: [][16]byte{addr},
		TTL:       60,
	})
	if len(results) != 1 || results[0].Addresses[0] != addr {
		t.Error("host resolve callback not invoked correctly")
	}
}

func TestResolveHostAlready(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	_ = m.ResolveHost("h", func(HostResolveResult) {})
	err := m.ResolveHost("h", func(HostResolveResult) {})
	if err != errors.ErrAlready {
		t.Errorf("got %v, want ErrAlready", err)
	}
}

func TestResolveHostInvalidArgs(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	if err := m.ResolveHost("", func(HostResolveResult) {}); err != errors.ErrInvalidArgs {
		t.Errorf("got %v, want ErrInvalidArgs", err)
	}
	if err := m.ResolveHost("h", nil); err != errors.ErrInvalidArgs {
		t.Errorf("got %v, want ErrInvalidArgs", err)
	}
}

func TestStopResolveHost(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	_ = m.ResolveHost("h", func(HostResolveResult) {})
	if err := m.StopResolveHost("h"); err != nil {
		t.Fatalf("StopResolveHost: %v", err)
	}
}

func TestStopResolveHostNotFound(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	if err := m.StopResolveHost("nope"); err != errors.ErrNotFound {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// Handle result with no matching request (should not panic)
// ---------------------------------------------------------------------------

func TestHandleResultsNoMatch(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	// These should be no-ops, not panics.
	m.HandleBrowseResult(BrowseResult{ServiceType: "_tcp"})
	m.HandleResolveResult(ResolveResult{InstanceName: "a", ServiceType: "_tcp"})
	m.HandleHostResolveResult(HostResolveResult{HostName: "h"})
}

// ---------------------------------------------------------------------------
// GetRegisteredServices / GetRegisteredHosts return copies
// ---------------------------------------------------------------------------

func TestGetRegisteredServicesReturnsCopy(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	_ = m.RegisterService(ServiceInfo{InstanceName: "a", ServiceType: "_tcp"})

	svcs := m.GetRegisteredServices()
	svcs[0].InstanceName = "MODIFIED"

	// Original should be unchanged.
	if m.GetRegisteredServices()[0].InstanceName != "a" {
		t.Error("GetRegisteredServices did not return a copy")
	}
}

func TestGetRegisteredHostsReturnsCopy(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	_ = m.RegisterHost(HostInfo{HostName: "h"})

	hosts := m.GetRegisteredHosts()
	hosts[0].HostName = "MODIFIED"

	if m.GetRegisteredHosts()[0].HostName != "h" {
		t.Error("GetRegisteredHosts did not return a copy")
	}
}

// ---------------------------------------------------------------------------
// TXT record helper tests
// ---------------------------------------------------------------------------

func TestEncodeTxtDataSingle(t *testing.T) {
	data := EncodeTxtData(map[string][]byte{
		"key": []byte("value"),
	})

	decoded, err := DecodeTxtData(data)
	if err != nil {
		t.Fatalf("DecodeTxtData: %v", err)
	}
	if !bytes.Equal(decoded["key"], []byte("value")) {
		t.Errorf("decoded[key] = %q, want %q", decoded["key"], "value")
	}
}

func TestEncodeTxtDataMultiple(t *testing.T) {
	input := map[string][]byte{
		"name":  []byte("printer"),
		"paper": []byte("A4"),
	}
	data := EncodeTxtData(input)
	decoded, err := DecodeTxtData(data)
	if err != nil {
		t.Fatalf("DecodeTxtData: %v", err)
	}
	if len(decoded) != 2 {
		t.Fatalf("got %d entries, want 2", len(decoded))
	}
	if !bytes.Equal(decoded["name"], []byte("printer")) {
		t.Error("name mismatch")
	}
	if !bytes.Equal(decoded["paper"], []byte("A4")) {
		t.Error("paper mismatch")
	}
}

func TestEncodeTxtDataBooleanFlag(t *testing.T) {
	data := EncodeTxtData(map[string][]byte{
		"flag": nil,
	})
	decoded, err := DecodeTxtData(data)
	if err != nil {
		t.Fatalf("DecodeTxtData: %v", err)
	}
	val, ok := decoded["flag"]
	if !ok {
		t.Fatal("flag key not found")
	}
	if val != nil {
		t.Errorf("boolean flag value = %v, want nil", val)
	}
}

func TestEncodeTxtDataEmpty(t *testing.T) {
	data := EncodeTxtData(map[string][]byte{})
	if len(data) != 0 {
		t.Errorf("expected empty data, got %d bytes", len(data))
	}

	decoded, err := DecodeTxtData(data)
	if err != nil {
		t.Fatalf("DecodeTxtData: %v", err)
	}
	if len(decoded) != 0 {
		t.Error("expected empty map")
	}
}

func TestEncodeTxtDataEmptyValue(t *testing.T) {
	data := EncodeTxtData(map[string][]byte{
		"key": {},
	})
	decoded, err := DecodeTxtData(data)
	if err != nil {
		t.Fatalf("DecodeTxtData: %v", err)
	}
	val, ok := decoded["key"]
	if !ok {
		t.Fatal("key not found")
	}
	if len(val) != 0 {
		t.Errorf("expected empty value, got %q", val)
	}
}

func TestDecodeTxtDataMalformed(t *testing.T) {
	// Length byte says 10 but only 2 bytes follow.
	data := []byte{10, 'a', 'b'}
	_, err := DecodeTxtData(data)
	if err != errors.ErrParse {
		t.Errorf("got %v, want ErrParse", err)
	}
}

func TestDecodeTxtDataEmptyKey(t *testing.T) {
	// Entry "=value" has an empty key.
	data := []byte{6, '=', 'v', 'a', 'l', 'u', 'e'}
	_, err := DecodeTxtData(data)
	if err != errors.ErrParse {
		t.Errorf("got %v, want ErrParse for empty key", err)
	}
}

func TestAppendTxtEntry(t *testing.T) {
	buf := AppendTxtEntry(nil, "key", []byte("val"))
	// Should be: [7] k e y = v a l
	if len(buf) != 8 {
		t.Fatalf("len = %d, want 8", len(buf))
	}
	if buf[0] != 7 {
		t.Errorf("length byte = %d, want 7", buf[0])
	}
	if string(buf[1:]) != "key=val" {
		t.Errorf("entry = %q, want %q", string(buf[1:]), "key=val")
	}
}

func TestAppendTxtEntryBooleanFlag(t *testing.T) {
	buf := AppendTxtEntry(nil, "flag", nil)
	// Should be: [4] f l a g
	if len(buf) != 5 {
		t.Fatalf("len = %d, want 5", len(buf))
	}
	if buf[0] != 4 {
		t.Errorf("length byte = %d, want 4", buf[0])
	}
	if string(buf[1:]) != "flag" {
		t.Errorf("entry = %q, want %q", string(buf[1:]), "flag")
	}
}

func TestAppendTxtEntryChaining(t *testing.T) {
	var buf []byte
	buf = AppendTxtEntry(buf, "a", []byte("1"))
	buf = AppendTxtEntry(buf, "b", []byte("2"))

	decoded, err := DecodeTxtData(buf)
	if err != nil {
		t.Fatalf("DecodeTxtData: %v", err)
	}
	if !bytes.Equal(decoded["a"], []byte("1")) {
		t.Error("a mismatch")
	}
	if !bytes.Equal(decoded["b"], []byte("2")) {
		t.Error("b mismatch")
	}
}

func TestDecodeTxtDataSkipsEmptyEntry(t *testing.T) {
	// An entry with length 0 should be skipped.
	var buf []byte
	buf = append(buf, 0) // empty entry
	buf = AppendTxtEntry(buf, "key", []byte("val"))

	decoded, err := DecodeTxtData(buf)
	if err != nil {
		t.Fatalf("DecodeTxtData: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("got %d entries, want 1", len(decoded))
	}
	if !bytes.Equal(decoded["key"], []byte("val")) {
		t.Error("key mismatch")
	}
}

// ---------------------------------------------------------------------------
// Encode/Decode round-trip with sorted keys for deterministic comparison
// ---------------------------------------------------------------------------

func TestTxtRoundTrip(t *testing.T) {
	input := map[string][]byte{
		"vendor": []byte("ACME"),
		"model":  []byte("X100"),
		"color":  nil,
	}

	encoded := EncodeTxtData(input)
	decoded, err := DecodeTxtData(encoded)
	if err != nil {
		t.Fatalf("round-trip decode: %v", err)
	}

	// Collect sorted keys for deterministic comparison.
	inKeys := sortedKeys(input)
	outKeys := sortedKeys(decoded)

	if len(inKeys) != len(outKeys) {
		t.Fatalf("key count %d != %d", len(inKeys), len(outKeys))
	}
	for i, k := range inKeys {
		if k != outKeys[i] {
			t.Errorf("key mismatch: %q != %q", k, outKeys[i])
		}
		if !bytes.Equal(input[k], decoded[k]) {
			t.Errorf("value mismatch for %q: %v != %v", k, input[k], decoded[k])
		}
	}
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---------------------------------------------------------------------------
// Enum values
// ---------------------------------------------------------------------------

func TestServiceTypeValues(t *testing.T) {
	if ServiceTypeBrowse != 0 {
		t.Errorf("ServiceTypeBrowse = %d, want 0", ServiceTypeBrowse)
	}
	if ServiceTypeResolve != 1 {
		t.Errorf("ServiceTypeResolve = %d, want 1", ServiceTypeResolve)
	}
	if ServiceTypeResolveHost != 2 {
		t.Errorf("ServiceTypeResolveHost = %d, want 2", ServiceTypeResolveHost)
	}
}

func TestRequestStateValues(t *testing.T) {
	if RequestStateIdle != 0 {
		t.Errorf("RequestStateIdle = %d, want 0", RequestStateIdle)
	}
	if RequestStatePending != 1 {
		t.Errorf("RequestStatePending = %d, want 1", RequestStatePending)
	}
	if RequestStateActive != 2 {
		t.Errorf("RequestStateActive = %d, want 2", RequestStateActive)
	}
}

// ---------------------------------------------------------------------------
// Platform error propagation
// ---------------------------------------------------------------------------

func TestUnregisterServicePlatformError(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	_ = m.RegisterService(ServiceInfo{InstanceName: "s", ServiceType: "_tcp"})
	p.unregisterServiceErr = errors.ErrFailed

	err := m.UnregisterService("s", "_tcp")
	if err != errors.ErrFailed {
		t.Errorf("got %v, want ErrFailed", err)
	}
}

func TestRegisterHostPlatformError(t *testing.T) {
	p := newMockPlatform()
	p.registerHostErr = errors.ErrFailed
	m := NewModule(p)

	err := m.RegisterHost(HostInfo{HostName: "h"})
	if err != errors.ErrFailed {
		t.Errorf("got %v, want ErrFailed", err)
	}
}

func TestUnregisterHostPlatformError(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	_ = m.RegisterHost(HostInfo{HostName: "h"})
	p.unregisterHostErr = errors.ErrFailed

	err := m.UnregisterHost("h")
	if err != errors.ErrFailed {
		t.Errorf("got %v, want ErrFailed", err)
	}
}

func TestRegisterKeyPlatformError(t *testing.T) {
	p := newMockPlatform()
	p.registerKeyErr = errors.ErrFailed
	m := NewModule(p)

	err := m.RegisterKey(KeyRecord{Name: "k"})
	if err != errors.ErrFailed {
		t.Errorf("got %v, want ErrFailed", err)
	}
}

func TestUnregisterKeyPlatformError(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	_ = m.RegisterKey(KeyRecord{Name: "k"})
	p.unregisterKeyErr = errors.ErrFailed

	err := m.UnregisterKey("k")
	if err != errors.ErrFailed {
		t.Errorf("got %v, want ErrFailed", err)
	}
}

func TestResolveHostPlatformError(t *testing.T) {
	p := newMockPlatform()
	p.startResolveHostErr = errors.ErrFailed
	m := NewModule(p)

	err := m.ResolveHost("h", func(HostResolveResult) {})
	if err != errors.ErrFailed {
		t.Errorf("got %v, want ErrFailed", err)
	}
}

func TestResolvePlatformError(t *testing.T) {
	p := newMockPlatform()
	p.startResolveErr = errors.ErrFailed
	m := NewModule(p)

	err := m.Resolve("a", "_tcp", func(ResolveResult) {})
	if err != errors.ErrFailed {
		t.Errorf("got %v, want ErrFailed", err)
	}
}

// ---------------------------------------------------------------------------
// Multiple browse results
// ---------------------------------------------------------------------------

func TestBrowseMultipleResults(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	var results []BrowseResult
	_ = m.Browse("_http._tcp", func(r BrowseResult) {
		results = append(results, r)
	})

	for i := 0; i < 5; i++ {
		m.HandleBrowseResult(BrowseResult{
			InstanceName: string(rune('a' + i)),
			ServiceType:  "_http._tcp",
			TTL:          uint32(i * 10),
		})
	}

	if len(results) != 5 {
		t.Errorf("got %d results, want 5", len(results))
	}
}

// ---------------------------------------------------------------------------
// Multiple independent browses
// ---------------------------------------------------------------------------

func TestMultipleBrowseDifferentTypes(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	var httpResults, ippResults []BrowseResult
	_ = m.Browse("_http._tcp", func(r BrowseResult) { httpResults = append(httpResults, r) })
	_ = m.Browse("_ipp._tcp", func(r BrowseResult) { ippResults = append(ippResults, r) })

	m.HandleBrowseResult(BrowseResult{InstanceName: "web", ServiceType: "_http._tcp"})
	m.HandleBrowseResult(BrowseResult{InstanceName: "printer", ServiceType: "_ipp._tcp"})
	m.HandleBrowseResult(BrowseResult{InstanceName: "web2", ServiceType: "_http._tcp"})

	if len(httpResults) != 2 {
		t.Errorf("http results = %d, want 2", len(httpResults))
	}
	if len(ippResults) != 1 {
		t.Errorf("ipp results = %d, want 1", len(ippResults))
	}
}

// ---------------------------------------------------------------------------
// ServiceInfo with subtypes and addresses
// ---------------------------------------------------------------------------

func TestServiceInfoWithSubTypesAndAddresses(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	addr := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	info := ServiceInfo{
		InstanceName: "My Service",
		ServiceType:  "_http._tcp",
		HostName:     "host",
		Port:         8080,
		TxtData:      []byte{3, 'a', '=', 'b'},
		Priority:     10,
		Weight:       20,
		TTL:          300,
		Addresses:    [][16]byte{addr},
		SubTypes:     []string{"_printer", "_scanner"},
	}

	if err := m.RegisterService(info); err != nil {
		t.Fatalf("RegisterService: %v", err)
	}

	svcs := m.GetRegisteredServices()
	if len(svcs) != 1 {
		t.Fatalf("got %d services", len(svcs))
	}
	s := svcs[0]
	if len(s.SubTypes) != 2 || s.SubTypes[0] != "_printer" {
		t.Error("subtypes mismatch")
	}
	if len(s.Addresses) != 1 || s.Addresses[0] != addr {
		t.Error("addresses mismatch")
	}
	if s.Priority != 10 || s.Weight != 20 {
		t.Error("priority/weight mismatch")
	}
}

// ---------------------------------------------------------------------------
// IsServiceRegistered
// ---------------------------------------------------------------------------

func TestIsServiceRegistered(t *testing.T) {
	p := newMockPlatform()
	m := NewModule(p)

	if m.IsServiceRegistered("a", "_tcp") {
		t.Error("should not be registered before adding")
	}

	_ = m.RegisterService(ServiceInfo{InstanceName: "a", ServiceType: "_tcp"})
	if !m.IsServiceRegistered("a", "_tcp") {
		t.Error("should be registered after adding")
	}

	// Different service type should not match.
	if m.IsServiceRegistered("a", "_udp") {
		t.Error("should not match different service type")
	}
}
