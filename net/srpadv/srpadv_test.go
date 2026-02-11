// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package srpadv

import (
	"fmt"
	"testing"
)

// ---------------------------------------------------------------------------
// Mock platform
// ---------------------------------------------------------------------------

type mockPlatform struct {
	registeredHosts    map[string][][16]byte
	registeredServices map[string]mockService
	failNext           bool
}

type mockService struct {
	instanceName string
	serviceType  string
	port         uint16
	txtData      []byte
	subTypes     []string
}

func newMockPlatform() *mockPlatform {
	return &mockPlatform{
		registeredHosts:    make(map[string][][16]byte),
		registeredServices: make(map[string]mockService),
	}
}

func serviceKey(serviceType, instanceName string) string {
	return serviceType + "/" + instanceName
}

func (m *mockPlatform) RegisterService(instanceName, serviceType string, port uint16, txtData []byte, subTypes []string) error {
	if m.failNext {
		m.failNext = false
		return fmt.Errorf("mock error")
	}
	m.registeredServices[serviceKey(serviceType, instanceName)] = mockService{
		instanceName: instanceName,
		serviceType:  serviceType,
		port:         port,
		txtData:      txtData,
		subTypes:     subTypes,
	}
	return nil
}

func (m *mockPlatform) UnregisterService(serviceType, instanceName string) error {
	if m.failNext {
		m.failNext = false
		return fmt.Errorf("mock error")
	}
	delete(m.registeredServices, serviceKey(serviceType, instanceName))
	return nil
}

func (m *mockPlatform) RegisterHost(name string, addresses [][16]byte) error {
	if m.failNext {
		m.failNext = false
		return fmt.Errorf("mock error")
	}
	m.registeredHosts[name] = addresses
	return nil
}

func (m *mockPlatform) UnregisterHost(name string) error {
	if m.failNext {
		m.failNext = false
		return fmt.Errorf("mock error")
	}
	delete(m.registeredHosts, name)
	return nil
}

// ---------------------------------------------------------------------------
// Lifecycle tests
// ---------------------------------------------------------------------------

func TestStartStop(t *testing.T) {
	t.Parallel()

	mp := newMockPlatform()
	p := NewAdvProxy(mp)

	if p.GetState() != StateStopped {
		t.Errorf("initial state = %d, want StateStopped", p.GetState())
	}

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if p.GetState() != StateRunning {
		t.Errorf("state after Start = %d, want StateRunning", p.GetState())
	}

	// Double start should fail.
	if err := p.Start(); err == nil {
		t.Error("expected error on double Start")
	}

	p.Stop()
	if p.GetState() != StateStopped {
		t.Errorf("state after Stop = %d, want StateStopped", p.GetState())
	}

	// Should be able to restart.
	if err := p.Start(); err != nil {
		t.Fatalf("Restart: %v", err)
	}
}

func TestStartNilPlatform(t *testing.T) {
	t.Parallel()

	p := NewAdvProxy(nil)
	if err := p.Start(); err == nil {
		t.Error("expected error when platform is nil")
	}
}

// ---------------------------------------------------------------------------
// Host registration
// ---------------------------------------------------------------------------

func TestHandleHostRegistration(t *testing.T) {
	t.Parallel()

	mp := newMockPlatform()
	p := NewAdvProxy(mp)
	_ = p.Start()

	addr1 := [16]byte{0: 0xfe, 1: 0x80, 15: 0x01}
	host := HostInfo{
		Name:      "myhost",
		Addresses: [][16]byte{addr1},
		TTL:       120,
	}

	p.HandleSrpUpdate(host, nil)

	if _, ok := mp.registeredHosts["myhost"]; !ok {
		t.Error("host should be registered")
	}

	c := p.GetCounters()
	if c.Total != 1 || c.Succeeded != 1 {
		t.Errorf("counters = %+v, want Total=1 Succeeded=1", c)
	}
}

func TestHandleHostDeletion(t *testing.T) {
	t.Parallel()

	mp := newMockPlatform()
	p := NewAdvProxy(mp)
	_ = p.Start()

	addr1 := [16]byte{15: 1}
	host := HostInfo{Name: "myhost", Addresses: [][16]byte{addr1}}
	p.HandleSrpUpdate(host, nil)

	// Now delete the host.
	host.Deleted = true
	p.HandleSrpUpdate(host, nil)

	if _, ok := mp.registeredHosts["myhost"]; ok {
		t.Error("host should be unregistered after deletion")
	}

	c := p.GetCounters()
	if c.Total != 2 || c.Succeeded != 2 {
		t.Errorf("counters = %+v, want Total=2 Succeeded=2", c)
	}
}

// ---------------------------------------------------------------------------
// Service registration
// ---------------------------------------------------------------------------

func TestHandleServiceRegistration(t *testing.T) {
	t.Parallel()

	mp := newMockPlatform()
	p := NewAdvProxy(mp)
	_ = p.Start()

	host := HostInfo{Name: "myhost", Addresses: [][16]byte{{15: 1}}}
	services := []ServiceInfo{
		{
			InstanceName: "My Printer",
			ServiceType:  "_ipp._tcp",
			Port:         631,
			TxtData:      []byte{4, 'k', '=', 'v', 0},
			SubTypes:     []string{"_print"},
		},
	}

	p.HandleSrpUpdate(host, services)

	key := serviceKey("_ipp._tcp", "My Printer")
	svc, ok := mp.registeredServices[key]
	if !ok {
		t.Fatal("service should be registered")
	}
	if svc.port != 631 {
		t.Errorf("port = %d, want 631", svc.port)
	}
	if len(svc.subTypes) != 1 || svc.subTypes[0] != "_print" {
		t.Errorf("subtypes = %v, want [_print]", svc.subTypes)
	}
}

func TestHandleServiceDeletion(t *testing.T) {
	t.Parallel()

	mp := newMockPlatform()
	p := NewAdvProxy(mp)
	_ = p.Start()

	host := HostInfo{Name: "myhost", Addresses: [][16]byte{{15: 1}}}
	services := []ServiceInfo{
		{InstanceName: "My Web", ServiceType: "_http._tcp", Port: 80},
	}
	p.HandleSrpUpdate(host, services)

	// Delete the service.
	services[0].Deleted = true
	p.HandleSrpUpdate(host, services)

	key := serviceKey("_http._tcp", "My Web")
	if _, ok := mp.registeredServices[key]; ok {
		t.Error("service should be unregistered after deletion")
	}
}

func TestHandleMultipleServicesPerHost(t *testing.T) {
	t.Parallel()

	mp := newMockPlatform()
	p := NewAdvProxy(mp)
	_ = p.Start()

	host := HostInfo{Name: "multihost", Addresses: [][16]byte{{15: 1}}}
	services := []ServiceInfo{
		{InstanceName: "Svc1", ServiceType: "_http._tcp", Port: 80},
		{InstanceName: "Svc2", ServiceType: "_ssh._tcp", Port: 22},
		{InstanceName: "Svc3", ServiceType: "_ipp._tcp", Port: 631},
	}

	p.HandleSrpUpdate(host, services)

	if len(mp.registeredServices) != 3 {
		t.Errorf("registered services = %d, want 3", len(mp.registeredServices))
	}

	c := p.GetCounters()
	if c.Total != 1 || c.Succeeded != 1 {
		t.Errorf("counters = %+v, want Total=1 Succeeded=1", c)
	}
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

func TestHandlePlatformError(t *testing.T) {
	t.Parallel()

	mp := newMockPlatform()
	p := NewAdvProxy(mp)
	_ = p.Start()

	mp.failNext = true
	host := HostInfo{Name: "failhost", Addresses: [][16]byte{{15: 1}}}
	p.HandleSrpUpdate(host, nil)

	c := p.GetCounters()
	if c.Failed != 1 {
		t.Errorf("Failed = %d, want 1", c.Failed)
	}
	if c.Succeeded != 0 {
		t.Errorf("Succeeded = %d, want 0", c.Succeeded)
	}
}

func TestHandleServicePlatformError(t *testing.T) {
	t.Parallel()

	mp := newMockPlatform()
	p := NewAdvProxy(mp)
	_ = p.Start()

	host := HostInfo{Name: "okhost", Addresses: [][16]byte{{15: 1}}}
	services := []ServiceInfo{
		{InstanceName: "Bad Svc", ServiceType: "_fail._tcp", Port: 9999},
	}

	// Host registration succeeds, service registration fails.
	// Use a platform that always fails service registrations.
	mp2 := &failServicePlatform{mockPlatform: newMockPlatform()}
	p2 := NewAdvProxy(mp2)
	_ = p2.Start()
	p2.HandleSrpUpdate(host, services)

	c2 := p2.GetCounters()
	if c2.Failed != 1 {
		t.Errorf("Failed = %d, want 1", c2.Failed)
	}
}

// failServicePlatform fails all service registrations.
type failServicePlatform struct {
	*mockPlatform
}

func (f *failServicePlatform) RegisterService(_, _ string, _ uint16, _ []byte, _ []string) error {
	return fmt.Errorf("service registration failed")
}

// ---------------------------------------------------------------------------
// Rejected (not running)
// ---------------------------------------------------------------------------

func TestHandleWhenStopped(t *testing.T) {
	t.Parallel()

	mp := newMockPlatform()
	p := NewAdvProxy(mp)
	// Not started.

	host := HostInfo{Name: "myhost", Addresses: [][16]byte{{15: 1}}}
	p.HandleSrpUpdate(host, nil)

	c := p.GetCounters()
	if c.Rejected != 1 {
		t.Errorf("Rejected = %d, want 1", c.Rejected)
	}
	if c.Succeeded != 0 {
		t.Errorf("Succeeded = %d, want 0", c.Succeeded)
	}
	if _, ok := mp.registeredHosts["myhost"]; ok {
		t.Error("host should not be registered when proxy is stopped")
	}
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

func TestCounterTracking(t *testing.T) {
	t.Parallel()

	mp := newMockPlatform()
	p := NewAdvProxy(mp)
	_ = p.Start()

	host := HostInfo{Name: "host1", Addresses: [][16]byte{{15: 1}}}

	// 3 successful updates.
	for i := 0; i < 3; i++ {
		p.HandleSrpUpdate(host, nil)
	}

	// 1 failed update.
	mp.failNext = true
	p.HandleSrpUpdate(host, nil)

	c := p.GetCounters()
	if c.Total != 4 {
		t.Errorf("Total = %d, want 4", c.Total)
	}
	if c.Succeeded != 3 {
		t.Errorf("Succeeded = %d, want 3", c.Succeeded)
	}
	if c.Failed != 1 {
		t.Errorf("Failed = %d, want 1", c.Failed)
	}
}

func TestClearCounters(t *testing.T) {
	t.Parallel()

	mp := newMockPlatform()
	p := NewAdvProxy(mp)
	_ = p.Start()

	host := HostInfo{Name: "host1", Addresses: [][16]byte{{15: 1}}}
	p.HandleSrpUpdate(host, nil)

	p.ClearCounters()
	c := p.GetCounters()
	if c.Total != 0 || c.Succeeded != 0 || c.Failed != 0 || c.Rejected != 0 {
		t.Errorf("counters after clear = %+v, want all zeros", c)
	}
}
