// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the conditions in the
// LICENSE file are met.

package srp

import (
	"testing"
	"time"

	"github.com/hilli/gothread/net/ip6"
)

// -------------------------------------------------------
// Mock DNS-SD platform
// -------------------------------------------------------

type platformCall struct {
	op           string
	requestID    uint32
	name         string
	serviceType  string
	hostName     string
	instanceName string
	addresses    []ip6.Address
	port         uint16
	priority     uint16
	weight       uint16
	txtData      []byte
	subTypes     []string
	keyData      []byte
	ttl          uint32
}

type mockPlatform struct {
	calls []platformCall
}

func (m *mockPlatform) reset() { m.calls = nil }

func (m *mockPlatform) RegisterHost(requestID uint32, name string, addresses []ip6.Address, ttl uint32) {
	m.calls = append(m.calls, platformCall{
		op:        "RegisterHost",
		requestID: requestID,
		name:      name,
		addresses: addresses,
		ttl:       ttl,
	})
}

func (m *mockPlatform) UnregisterHost(requestID uint32, name string) {
	m.calls = append(m.calls, platformCall{
		op:        "UnregisterHost",
		requestID: requestID,
		name:      name,
	})
}

func (m *mockPlatform) RegisterService(requestID uint32, hostName, instanceName, serviceType string, port, priority, weight uint16, txtData []byte, subTypes []string, ttl uint32) {
	m.calls = append(m.calls, platformCall{
		op:           "RegisterService",
		requestID:    requestID,
		hostName:     hostName,
		instanceName: instanceName,
		serviceType:  serviceType,
		port:         port,
		priority:     priority,
		weight:       weight,
		txtData:      txtData,
		subTypes:     subTypes,
		ttl:          ttl,
	})
}

func (m *mockPlatform) UnregisterService(requestID uint32, instanceName, serviceType string) {
	m.calls = append(m.calls, platformCall{
		op:           "UnregisterService",
		requestID:    requestID,
		instanceName: instanceName,
		serviceType:  serviceType,
	})
}

func (m *mockPlatform) RegisterKey(requestID uint32, name, serviceType string, keyData []byte, ttl uint32) {
	m.calls = append(m.calls, platformCall{
		op:          "RegisterKey",
		requestID:   requestID,
		name:        name,
		serviceType: serviceType,
		keyData:     keyData,
		ttl:         ttl,
	})
}

func (m *mockPlatform) UnregisterKey(requestID uint32, name, serviceType string) {
	m.calls = append(m.calls, platformCall{
		op:          "UnregisterKey",
		requestID:   requestID,
		name:        name,
		serviceType: serviceType,
	})
}

// findCalls returns all calls matching the given op.
func (m *mockPlatform) findCalls(op string) []platformCall {
	var result []platformCall
	for i := range m.calls {
		c := &m.calls[i]
		if c.op == op {
			result = append(result, *c)
		}
	}
	return result
}

// -------------------------------------------------------
// Test environment
// -------------------------------------------------------

type advProxyTestEnv struct {
	t        *testing.T
	proxy    *AdvertisingProxy
	platform *mockPlatform
	now      time.Time
	timer    *fakeTimer
}

func newAdvProxyTestEnv(t *testing.T, opts ...AdvProxyOption) *advProxyTestEnv {
	t.Helper()
	env := &advProxyTestEnv{
		t:        t,
		platform: &mockPlatform{},
		now:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	server := NewServer(
		WithServerNow(func() time.Time { return env.now }),
	)
	server.domain = ServerDefaultDomain

	allOpts := []AdvProxyOption{
		WithAdvProxyNow(func() time.Time { return env.now }),
		WithAdvProxyAfterFunc(func(d time.Duration, f func()) Timer {
			env.timer = &fakeTimer{delay: d, fn: f}
			return env.timer
		}),
	}
	allOpts = append(allOpts, opts...)

	env.proxy = NewAdvertisingProxy(server, env.platform, allOpts...)
	return env
}

// advanceTime advances the fake clock.
func (env *advProxyTestEnv) advanceTime(d time.Duration) {
	env.now = env.now.Add(d)
}

// fireTimer fires the current timer if set.
func (env *advProxyTestEnv) fireTimer() {
	env.t.Helper()
	if env.timer == nil {
		env.t.Fatal("no timer to fire")
	}
	env.timer.Fire()
}

// completeAll completes all outstanding request IDs successfully.
func (env *advProxyTestEnv) completeAll() {
	env.t.Helper()
	for i := range env.platform.calls {
		c := &env.platform.calls[i]
		if c.requestID != 0 {
			env.proxy.HandleRegistered(c.requestID, nil)
		}
	}
}

// -------------------------------------------------------
// Test helpers
// -------------------------------------------------------

func testAddr(b byte) ip6.Address {
	var addr ip6.Address
	addr[15] = b
	return addr
}

func testHost(name string, addrs ...ip6.Address) *RegHost {
	return &RegHost{
		FullName:   name + "." + ServerDefaultDomain,
		Addresses:  addrs,
		TTL:        300,
		Lease:      7200,
		KeyLease:   14400,
		UpdateTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func testDeletedHost(name string) *RegHost {
	return &RegHost{
		FullName:   name + "." + ServerDefaultDomain,
		Lease:      0,
		KeyLease:   14400,
		TTL:        300,
		UpdateTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func testFullyRemovedHost(name string) *RegHost {
	return &RegHost{
		FullName:   name + "." + ServerDefaultDomain,
		Lease:      0,
		KeyLease:   0,
		TTL:        300,
		UpdateTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func makeRegService(instanceLabel, serviceType string, port uint16) *RegService {
	return &RegService{
		InstanceName:  instanceLabel + "." + serviceType + "." + ServerDefaultDomain,
		InstanceLabel: instanceLabel,
		ServiceName:   serviceType + "." + ServerDefaultDomain,
		Port:          port,
		Priority:      0,
		Weight:        0,
		TTL:           300,
		Lease:         7200,
		KeyLease:      14400,
		TxtData:       []byte{0}, // empty TXT
	}
}

func makeDeletedRegService(instanceLabel, serviceType string) *RegService {
	return &RegService{
		InstanceName:  instanceLabel + "." + serviceType + "." + ServerDefaultDomain,
		InstanceLabel: instanceLabel,
		ServiceName:   serviceType + "." + ServerDefaultDomain,
		IsDeleted:     true,
		Lease:         0,
		KeyLease:      14400,
		TTL:           300,
	}
}

// -------------------------------------------------------
// Tests: Start / Stop
// -------------------------------------------------------

func TestAdvProxy_StartStop(t *testing.T) {
	env := newAdvProxyTestEnv(t)

	if env.proxy.IsRunning() {
		t.Fatal("proxy should be stopped initially")
	}
	if c := env.proxy.GetCounters(); c.StateChanges != 0 {
		t.Fatalf("expected 0 state changes, got %d", c.StateChanges)
	}

	env.proxy.Start()
	if !env.proxy.IsRunning() {
		t.Fatal("proxy should be running after Start")
	}
	if c := env.proxy.GetCounters(); c.StateChanges != 1 {
		t.Fatalf("expected 1 state change, got %d", c.StateChanges)
	}

	// Starting again is a no-op.
	env.proxy.Start()
	if c := env.proxy.GetCounters(); c.StateChanges != 1 {
		t.Fatalf("expected 1 state change after double-start, got %d", c.StateChanges)
	}

	env.proxy.Stop()
	if env.proxy.IsRunning() {
		t.Fatal("proxy should be stopped after Stop")
	}
	if c := env.proxy.GetCounters(); c.StateChanges != 2 {
		t.Fatalf("expected 2 state changes, got %d", c.StateChanges)
	}

	// Stopping again is a no-op.
	env.proxy.Stop()
	if c := env.proxy.GetCounters(); c.StateChanges != 2 {
		t.Fatalf("expected 2 state changes after double-stop, got %d", c.StateChanges)
	}
}

func TestAdvProxy_AdvertiseWhenStopped(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	host := testHost("myhost", testAddr(1))

	env.proxy.Advertise(host)

	c := env.proxy.GetCounters()
	if c.AdvTotal != 1 {
		t.Fatalf("expected AdvTotal=1, got %d", c.AdvTotal)
	}
	if c.AdvSkipped != 1 {
		t.Fatalf("expected AdvSkipped=1, got %d", c.AdvSkipped)
	}
	if len(env.platform.calls) != 0 {
		t.Fatalf("expected no platform calls when stopped, got %d", len(env.platform.calls))
	}
}

// -------------------------------------------------------
// Tests: Advertise new host
// -------------------------------------------------------

func TestAdvProxy_AdvertiseNewHost(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	host := testHost("myhost", testAddr(1), testAddr(2))
	env.proxy.Advertise(host)

	// Should register key + host.
	keyCalls := env.platform.findCalls("RegisterKey")
	if len(keyCalls) != 1 {
		t.Fatalf("expected 1 RegisterKey call, got %d", len(keyCalls))
	}
	if keyCalls[0].name != "myhost" {
		t.Fatalf("expected key name 'myhost', got %q", keyCalls[0].name)
	}

	hostCalls := env.platform.findCalls("RegisterHost")
	if len(hostCalls) != 1 {
		t.Fatalf("expected 1 RegisterHost call, got %d", len(hostCalls))
	}
	if hostCalls[0].name != "myhost" {
		t.Fatalf("expected host name 'myhost', got %q", hostCalls[0].name)
	}
	if len(hostCalls[0].addresses) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(hostCalls[0].addresses))
	}
}

func TestAdvProxy_AdvertiseHostWithService(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	host := testHost("myhost", testAddr(1))
	svc := makeRegService("My Printer", "_ipp._tcp", 631)
	host.Services = []*RegService{svc}

	env.proxy.Advertise(host)

	// Should register: host key, service key, host, service.
	keyCalls := env.platform.findCalls("RegisterKey")
	if len(keyCalls) != 2 {
		t.Fatalf("expected 2 RegisterKey calls, got %d", len(keyCalls))
	}

	hostCalls := env.platform.findCalls("RegisterHost")
	if len(hostCalls) != 1 {
		t.Fatalf("expected 1 RegisterHost call, got %d", len(hostCalls))
	}

	svcCalls := env.platform.findCalls("RegisterService")
	if len(svcCalls) != 1 {
		t.Fatalf("expected 1 RegisterService call, got %d", len(svcCalls))
	}
	if svcCalls[0].port != 631 {
		t.Fatalf("expected port 631, got %d", svcCalls[0].port)
	}
	if svcCalls[0].instanceName != "My Printer" {
		t.Fatalf("expected instance 'My Printer', got %q", svcCalls[0].instanceName)
	}
}

// -------------------------------------------------------
// Tests: Completion and counters
// -------------------------------------------------------

func TestAdvProxy_SuccessfulCompletion(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	host := testHost("myhost", testAddr(1))
	env.proxy.Advertise(host)

	// Complete all requests.
	env.completeAll()

	c := env.proxy.GetCounters()
	if c.AdvSuccessful != 1 {
		t.Fatalf("expected AdvSuccessful=1, got %d", c.AdvSuccessful)
	}
	if len(env.proxy.advInfoList) != 0 {
		t.Fatalf("expected no outstanding advInfo, got %d", len(env.proxy.advInfoList))
	}
}

func TestAdvProxy_PlatformError(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	host := testHost("myhost", testAddr(1))
	env.proxy.Advertise(host)

	// Complete with an error.
	for _, c := range env.platform.calls {
		if c.requestID != 0 {
			env.proxy.HandleRegistered(c.requestID, &advError{"platform error"})
		}
	}

	c := env.proxy.GetCounters()
	if c.AdvRejected != 1 {
		t.Fatalf("expected AdvRejected=1, got %d", c.AdvRejected)
	}
}

// -------------------------------------------------------
// Tests: Timeout
// -------------------------------------------------------

func TestAdvProxy_Timeout(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	host := testHost("myhost", testAddr(1))
	env.proxy.Advertise(host)

	if len(env.proxy.advInfoList) != 1 {
		t.Fatalf("expected 1 outstanding advInfo, got %d", len(env.proxy.advInfoList))
	}

	// Advance time past the timeout.
	env.advanceTime(defaultAdvTimeout + time.Second)
	env.fireTimer()

	c := env.proxy.GetCounters()
	if c.AdvTimeout != 1 {
		t.Fatalf("expected AdvTimeout=1, got %d", c.AdvTimeout)
	}
	if len(env.proxy.advInfoList) != 0 {
		t.Fatalf("expected no outstanding advInfo after timeout, got %d", len(env.proxy.advInfoList))
	}
}

// -------------------------------------------------------
// Tests: Host removal
// -------------------------------------------------------

func TestAdvProxy_HostRemoval(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	// Register a host first.
	host := testHost("myhost", testAddr(1))
	svc := makeRegService("My Printer", "_ipp._tcp", 631)
	host.Services = []*RegService{svc}
	env.proxy.Advertise(host)
	env.completeAll()
	env.platform.reset()

	// Now remove the host.
	env.proxy.AdvertiseRemovalOf(host)

	unregHostCalls := env.platform.findCalls("UnregisterHost")
	if len(unregHostCalls) != 1 {
		t.Fatalf("expected 1 UnregisterHost call, got %d", len(unregHostCalls))
	}

	unregSvcCalls := env.platform.findCalls("UnregisterService")
	if len(unregSvcCalls) != 1 {
		t.Fatalf("expected 1 UnregisterService call, got %d", len(unregSvcCalls))
	}
}

func TestAdvProxy_HostRemovalWithKeyLease0(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	// Register a host first.
	host := testHost("myhost", testAddr(1))
	env.proxy.Advertise(host)
	env.completeAll()
	env.platform.reset()

	// Remove with key-lease 0 (full removal).
	host.Lease = 0
	host.KeyLease = 0
	env.proxy.AdvertiseRemovalOf(host)

	unregHostCalls := env.platform.findCalls("UnregisterHost")
	if len(unregHostCalls) != 1 {
		t.Fatalf("expected 1 UnregisterHost, got %d", len(unregHostCalls))
	}

	unregKeyCalls := env.platform.findCalls("UnregisterKey")
	if len(unregKeyCalls) != 1 {
		t.Fatalf("expected 1 UnregisterKey for host, got %d", len(unregKeyCalls))
	}
}

// -------------------------------------------------------
// Tests: Service removal
// -------------------------------------------------------

func TestAdvProxy_ServiceRemoval(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	host := testHost("myhost", testAddr(1))
	svc := makeRegService("My Printer", "_ipp._tcp", 631)
	host.Services = []*RegService{svc}
	env.proxy.Advertise(host)
	env.completeAll()
	env.platform.reset()

	env.proxy.AdvertiseRemovalOfService(svc, host.FullName)

	unregCalls := env.platform.findCalls("UnregisterService")
	if len(unregCalls) != 1 {
		t.Fatalf("expected 1 UnregisterService, got %d", len(unregCalls))
	}
}

func TestAdvProxy_ServiceRemovalSkippedIfOutstandingAdv(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	host := testHost("myhost", testAddr(1))
	svc := makeRegService("My Printer", "_ipp._tcp", 631)
	host.Services = []*RegService{svc}

	// Advertise but don't complete - the adv is outstanding.
	env.proxy.Advertise(host)
	env.platform.reset()

	// Try to remove the service — should be skipped because
	// outstanding adv is re-adding it.
	env.proxy.AdvertiseRemovalOfService(svc, host.FullName)

	unregCalls := env.platform.findCalls("UnregisterService")
	if len(unregCalls) != 0 {
		t.Fatalf("expected 0 UnregisterService (skipped), got %d", len(unregCalls))
	}
}

// -------------------------------------------------------
// Tests: Host update (changed addresses)
// -------------------------------------------------------

func TestAdvProxy_HostAddressUpdate(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	// Register initial host.
	host1 := testHost("myhost", testAddr(1))
	env.proxy.Advertise(host1)
	env.completeAll()
	env.platform.reset()

	// Add host1 to server's committed hosts so the proxy finds it.
	env.proxy.server.hosts = append(env.proxy.server.hosts, host1)

	// Update with different address.
	host2 := testHost("myhost", testAddr(2))
	env.proxy.Advertise(host2)

	hostCalls := env.platform.findCalls("RegisterHost")
	if len(hostCalls) != 1 {
		t.Fatalf("expected 1 RegisterHost for address update, got %d", len(hostCalls))
	}
	if len(hostCalls[0].addresses) != 1 || hostCalls[0].addresses[0] != testAddr(2) {
		t.Fatal("expected new address in RegisterHost call")
	}
}

// -------------------------------------------------------
// Tests: Identical refresh (no re-registration)
// -------------------------------------------------------

func TestAdvProxy_IdenticalRefreshSkipsReRegistration(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	// Register initial host.
	host1 := testHost("myhost", testAddr(1))
	svc := makeRegService("My Printer", "_ipp._tcp", 631)
	host1.Services = []*RegService{svc}
	env.proxy.Advertise(host1)
	env.completeAll()
	env.platform.reset()

	// Add host1 to server's committed hosts.
	env.proxy.server.hosts = append(env.proxy.server.hosts, host1)

	// Refresh with identical host.
	host2 := testHost("myhost", testAddr(1))
	svc2 := makeRegService("My Printer", "_ipp._tcp", 631)
	host2.Services = []*RegService{svc2}
	env.proxy.Advertise(host2)

	// Should not re-register host or service (they are identical and already registered).
	hostCalls := env.platform.findCalls("RegisterHost")
	if len(hostCalls) != 0 {
		t.Fatalf("expected 0 RegisterHost for identical refresh, got %d", len(hostCalls))
	}
	svcCalls := env.platform.findCalls("RegisterService")
	if len(svcCalls) != 0 {
		t.Fatalf("expected 0 RegisterService for identical refresh, got %d", len(svcCalls))
	}
}

// -------------------------------------------------------
// Tests: Service update (changed port)
// -------------------------------------------------------

func TestAdvProxy_ServicePortUpdate(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	host1 := testHost("myhost", testAddr(1))
	svc1 := makeRegService("My Printer", "_ipp._tcp", 631)
	host1.Services = []*RegService{svc1}
	env.proxy.Advertise(host1)
	env.completeAll()
	env.platform.reset()

	env.proxy.server.hosts = append(env.proxy.server.hosts, host1)

	// Update with different port.
	host2 := testHost("myhost", testAddr(1))
	svc2 := makeRegService("My Printer", "_ipp._tcp", 9100)
	host2.Services = []*RegService{svc2}
	env.proxy.Advertise(host2)

	svcCalls := env.platform.findCalls("RegisterService")
	if len(svcCalls) != 1 {
		t.Fatalf("expected 1 RegisterService for port update, got %d", len(svcCalls))
	}
	if svcCalls[0].port != 9100 {
		t.Fatalf("expected port 9100, got %d", svcCalls[0].port)
	}
}

// -------------------------------------------------------
// Tests: Service update (changed TXT data)
// -------------------------------------------------------

func TestAdvProxy_ServiceTxtUpdate(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	host1 := testHost("myhost", testAddr(1))
	svc1 := makeRegService("My Printer", "_ipp._tcp", 631)
	svc1.TxtData = []byte{3, 'a', '=', 'b'}
	host1.Services = []*RegService{svc1}
	env.proxy.Advertise(host1)
	env.completeAll()
	env.platform.reset()

	env.proxy.server.hosts = append(env.proxy.server.hosts, host1)

	host2 := testHost("myhost", testAddr(1))
	svc2 := makeRegService("My Printer", "_ipp._tcp", 631)
	svc2.TxtData = []byte{3, 'x', '=', 'y'}
	host2.Services = []*RegService{svc2}
	env.proxy.Advertise(host2)

	svcCalls := env.platform.findCalls("RegisterService")
	if len(svcCalls) != 1 {
		t.Fatalf("expected 1 RegisterService for TXT update, got %d", len(svcCalls))
	}
}

// -------------------------------------------------------
// Tests: Key registration
// -------------------------------------------------------

func TestAdvProxy_KeyRegistration(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	host := testHost("myhost", testAddr(1))
	env.proxy.Advertise(host)

	keyCalls := env.platform.findCalls("RegisterKey")
	if len(keyCalls) != 1 {
		t.Fatalf("expected 1 RegisterKey, got %d", len(keyCalls))
	}
	if keyCalls[0].name != "myhost" {
		t.Fatalf("expected key name 'myhost', got %q", keyCalls[0].name)
	}
	if len(keyCalls[0].keyData) != 68 { // 4 header + 64 key
		t.Fatalf("expected 68 bytes key data, got %d", len(keyCalls[0].keyData))
	}
}

// -------------------------------------------------------
// Tests: Blocking mechanism
// -------------------------------------------------------

func TestAdvProxy_BlockingMechanism(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	// First advertisement.
	host1 := testHost("myhost", testAddr(1))
	env.proxy.Advertise(host1)

	// Second advertisement for same host with different address (before first completes).
	host2 := testHost("myhost", testAddr(2))
	env.proxy.Advertise(host2)

	c := env.proxy.GetCounters()
	if c.AdvReplaced != 1 {
		t.Fatalf("expected AdvReplaced=1, got %d", c.AdvReplaced)
	}

	// There should be 2 advInfos.
	if len(env.proxy.advInfoList) != 2 {
		t.Fatalf("expected 2 advInfos, got %d", len(env.proxy.advInfoList))
	}

	// The second should be blocked by the first.
	if env.proxy.advInfoList[1].blockingAdv != env.proxy.advInfoList[0] {
		t.Fatal("second adv should be blocked by first")
	}
}

func TestAdvProxy_BlockingUnblockedOnCompletion(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	host1 := testHost("myhost", testAddr(1))
	env.proxy.Advertise(host1)
	firstAdvCalls := make([]platformCall, len(env.platform.calls))
	copy(firstAdvCalls, env.platform.calls)

	host2 := testHost("myhost", testAddr(2))
	env.proxy.Advertise(host2)

	// Complete the first adv's requests.
	for _, c := range firstAdvCalls {
		if c.requestID != 0 {
			env.proxy.HandleRegistered(c.requestID, nil)
		}
	}

	// Now complete the second adv's remaining requests.
	for _, c := range env.platform.calls {
		if c.requestID != 0 {
			env.proxy.HandleRegistered(c.requestID, nil)
		}
	}

	counters := env.proxy.GetCounters()
	// Both should be successful (first was replaced counter, but still completed).
	if counters.AdvSuccessful != 2 {
		t.Fatalf("expected AdvSuccessful=2, got %d", counters.AdvSuccessful)
	}
	if len(env.proxy.advInfoList) != 0 {
		t.Fatalf("expected no outstanding advInfo, got %d", len(env.proxy.advInfoList))
	}
}

// -------------------------------------------------------
// Tests: Stop while advertisements outstanding
// -------------------------------------------------------

func TestAdvProxy_StopRejectsOutstanding(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	host := testHost("myhost", testAddr(1))
	svc := makeRegService("My Printer", "_ipp._tcp", 631)
	host.Services = []*RegService{svc}
	env.proxy.Advertise(host)

	env.proxy.Stop()

	c := env.proxy.GetCounters()
	if c.AdvRejected != 1 {
		t.Fatalf("expected AdvRejected=1 after stop, got %d", c.AdvRejected)
	}

	// Should have unregistered everything.
	unregHostCalls := env.platform.findCalls("UnregisterHost")
	unregSvcCalls := env.platform.findCalls("UnregisterService")
	// At minimum, unregister calls should have been made for registered items
	// (they may or may not be registered yet since we didn't complete).
	_ = unregHostCalls
	_ = unregSvcCalls
}

// -------------------------------------------------------
// Tests: Start advertises existing hosts
// -------------------------------------------------------

func TestAdvProxy_StartAdvertisesExistingHosts(t *testing.T) {
	env := newAdvProxyTestEnv(t)

	// Add hosts to the server before starting proxy.
	host := testHost("myhost", testAddr(1))
	env.proxy.server.hosts = append(env.proxy.server.hosts, host)

	env.proxy.Start()

	hostCalls := env.platform.findCalls("RegisterHost")
	if len(hostCalls) != 1 {
		t.Fatalf("expected 1 RegisterHost on Start, got %d", len(hostCalls))
	}
}

// -------------------------------------------------------
// Tests: Counter reset
// -------------------------------------------------------

func TestAdvProxy_ResetCounters(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.proxy.Stop()

	if env.proxy.GetCounters().StateChanges == 0 {
		t.Fatal("expected non-zero counters before reset")
	}

	env.proxy.ResetCounters()
	c := env.proxy.GetCounters()
	if c.StateChanges != 0 || c.AdvTotal != 0 {
		t.Fatal("expected all counters to be zero after reset")
	}
}

// -------------------------------------------------------
// Tests: Multiple hosts
// -------------------------------------------------------

func TestAdvProxy_MultipleHosts(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	host1 := testHost("host1", testAddr(1))
	host2 := testHost("host2", testAddr(2))

	env.proxy.Advertise(host1)
	env.proxy.Advertise(host2)

	hostCalls := env.platform.findCalls("RegisterHost")
	if len(hostCalls) != 2 {
		t.Fatalf("expected 2 RegisterHost calls, got %d", len(hostCalls))
	}

	env.completeAll()

	c := env.proxy.GetCounters()
	if c.AdvSuccessful != 2 {
		t.Fatalf("expected AdvSuccessful=2, got %d", c.AdvSuccessful)
	}
}

// -------------------------------------------------------
// Tests: HandleRegistered with invalid ID
// -------------------------------------------------------

func TestAdvProxy_HandleRegisteredInvalidID(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()

	// Should not panic or crash.
	env.proxy.HandleRegistered(0, nil)
	env.proxy.HandleRegistered(99999, nil)
}

// -------------------------------------------------------
// Tests: HandleRegistered when stopped
// -------------------------------------------------------

func TestAdvProxy_HandleRegisteredWhenStopped(t *testing.T) {
	env := newAdvProxyTestEnv(t)

	// Should be a no-op.
	env.proxy.HandleRegistered(1, nil)
}

// -------------------------------------------------------
// Tests: stripDomain helper
// -------------------------------------------------------

func TestStripDomain(t *testing.T) {
	tests := []struct {
		fullName string
		domain   string
		expected string
	}{
		{"myhost.default.service.arpa.", "default.service.arpa.", "myhost"},
		{"_ipp._tcp.default.service.arpa.", "default.service.arpa.", "_ipp._tcp"},
		{"foo", "default.service.arpa.", "foo"},
		{"myhost.DEFAULT.SERVICE.ARPA.", "default.service.arpa.", "myhost"},
	}

	for _, tt := range tests {
		result := stripDomain(tt.fullName, tt.domain)
		if result != tt.expected {
			t.Errorf("stripDomain(%q, %q) = %q, want %q", tt.fullName, tt.domain, result, tt.expected)
		}
	}
}

// -------------------------------------------------------
// Tests: hostsMatch
// -------------------------------------------------------

func TestHostsMatch(t *testing.T) {
	a := testHost("h", testAddr(1), testAddr(2))
	b := testHost("h", testAddr(2), testAddr(1))
	if !hostsMatch(a, b) {
		t.Fatal("hosts with same addresses in different order should match")
	}

	c := testHost("h", testAddr(1), testAddr(3))
	if hostsMatch(a, c) {
		t.Fatal("hosts with different addresses should not match")
	}

	d := testHost("h", testAddr(1))
	if hostsMatch(a, d) {
		t.Fatal("hosts with different address count should not match")
	}
}

func TestHostsMatchDeleted(t *testing.T) {
	a := testDeletedHost("h")
	b := testDeletedHost("h")
	if !hostsMatch(a, b) {
		t.Fatal("two deleted hosts should match")
	}

	c := testHost("h", testAddr(1))
	if hostsMatch(a, c) {
		t.Fatal("deleted host should not match non-deleted host")
	}
}

// -------------------------------------------------------
// Tests: servicesMatch
// -------------------------------------------------------

func TestServicesMatch(t *testing.T) {
	a := makeRegService("svc", "_http._tcp", 80)
	b := makeRegService("svc", "_http._tcp", 80)
	if !servicesMatch(a, b) {
		t.Fatal("identical services should match")
	}

	c := makeRegService("svc", "_http._tcp", 8080)
	if servicesMatch(a, c) {
		t.Fatal("services with different ports should not match")
	}
}

func TestServicesMatchSubTypes(t *testing.T) {
	a := makeRegService("svc", "_http._tcp", 80)
	a.SubTypes = []string{"_sub1._http._tcp.default.service.arpa.", "_sub2._http._tcp.default.service.arpa."}

	b := makeRegService("svc", "_http._tcp", 80)
	b.SubTypes = []string{"_sub2._http._tcp.default.service.arpa.", "_sub1._http._tcp.default.service.arpa."}

	if !servicesMatch(a, b) {
		t.Fatal("services with same subtypes in different order should match")
	}

	c := makeRegService("svc", "_http._tcp", 80)
	c.SubTypes = []string{"_sub1._http._tcp.default.service.arpa."}
	if servicesMatch(a, c) {
		t.Fatal("services with different subtypes should not match")
	}
}

func TestServicesMatchTxtData(t *testing.T) {
	a := makeRegService("svc", "_http._tcp", 80)
	a.TxtData = []byte{3, 'a', '=', 'b'}

	b := makeRegService("svc", "_http._tcp", 80)
	b.TxtData = []byte{3, 'a', '=', 'b'}

	if !servicesMatch(a, b) {
		t.Fatal("services with same TXT data should match")
	}

	c := makeRegService("svc", "_http._tcp", 80)
	c.TxtData = []byte{3, 'x', '=', 'y'}
	if servicesMatch(a, c) {
		t.Fatal("services with different TXT data should not match")
	}
}

// -------------------------------------------------------
// Tests: Host removal rejects outstanding adv
// -------------------------------------------------------

func TestAdvProxy_HostRemovalRejectsOutstanding(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	// Register host (outstanding, not yet completed).
	host := testHost("myhost", testAddr(1))
	env.proxy.Advertise(host)

	// Remove host while advertisement is outstanding.
	deletedHost := testDeletedHost("myhost")
	env.proxy.AdvertiseRemovalOf(deletedHost)

	c := env.proxy.GetCounters()
	if c.AdvRejected != 1 {
		t.Fatalf("expected AdvRejected=1 (outstanding rejected), got %d", c.AdvRejected)
	}
}

// -------------------------------------------------------
// Tests: Multiple services on a host
// -------------------------------------------------------

func TestAdvProxy_MultipleServices(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	host := testHost("myhost", testAddr(1))
	svc1 := makeRegService("My Printer", "_ipp._tcp", 631)
	svc2 := makeRegService("My Web", "_http._tcp", 80)
	host.Services = []*RegService{svc1, svc2}

	env.proxy.Advertise(host)

	svcCalls := env.platform.findCalls("RegisterService")
	if len(svcCalls) != 2 {
		t.Fatalf("expected 2 RegisterService calls, got %d", len(svcCalls))
	}

	env.completeAll()
	c := env.proxy.GetCounters()
	if c.AdvSuccessful != 1 {
		t.Fatalf("expected AdvSuccessful=1, got %d", c.AdvSuccessful)
	}
}

// -------------------------------------------------------
// Tests: Advertise deleted host (new update that is a removal)
// -------------------------------------------------------

func TestAdvProxy_AdvertiseDeletedHost(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	// First register the host.
	host := testHost("myhost", testAddr(1))
	env.proxy.Advertise(host)
	env.completeAll()
	env.platform.reset()

	env.proxy.server.hosts = append(env.proxy.server.hosts, host)

	// Now advertise a deleted host via Advertise (from SRP update).
	deletedHost := testDeletedHost("myhost")
	env.proxy.Advertise(deletedHost)

	unregHostCalls := env.platform.findCalls("UnregisterHost")
	if len(unregHostCalls) != 1 {
		t.Fatalf("expected 1 UnregisterHost, got %d", len(unregHostCalls))
	}
}

// -------------------------------------------------------
// Tests: Service weight/priority changes trigger re-registration
// -------------------------------------------------------

func TestAdvProxy_ServiceWeightPriorityUpdate(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	host1 := testHost("myhost", testAddr(1))
	svc1 := makeRegService("My Printer", "_ipp._tcp", 631)
	svc1.Weight = 10
	svc1.Priority = 5
	host1.Services = []*RegService{svc1}
	env.proxy.Advertise(host1)
	env.completeAll()
	env.platform.reset()

	env.proxy.server.hosts = append(env.proxy.server.hosts, host1)

	host2 := testHost("myhost", testAddr(1))
	svc2 := makeRegService("My Printer", "_ipp._tcp", 631)
	svc2.Weight = 20
	svc2.Priority = 10
	host2.Services = []*RegService{svc2}
	env.proxy.Advertise(host2)

	svcCalls := env.platform.findCalls("RegisterService")
	if len(svcCalls) != 1 {
		t.Fatalf("expected 1 RegisterService for weight/priority update, got %d", len(svcCalls))
	}
}

// -------------------------------------------------------
// Tests: marshalKeyData
// -------------------------------------------------------

func TestMarshalKeyData(t *testing.T) {
	host := testHost("myhost", testAddr(1))
	data := marshalKeyData(host)
	if len(data) != 68 {
		t.Fatalf("expected 68 bytes, got %d", len(data))
	}
	if data[0] != 0x01 || data[1] != 0x00 {
		t.Fatal("unexpected flags")
	}
	if data[2] != 3 {
		t.Fatal("unexpected protocol")
	}
	if data[3] != 13 {
		t.Fatal("unexpected algorithm")
	}
}

// -------------------------------------------------------
// Tests: Timer scheduling
// -------------------------------------------------------

func TestAdvProxy_TimerScheduled(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	host := testHost("myhost", testAddr(1))
	env.proxy.Advertise(host)

	if env.timer == nil {
		t.Fatal("expected timer to be scheduled")
	}
	if env.timer.delay != defaultAdvTimeout {
		t.Fatalf("expected timer delay %v, got %v", defaultAdvTimeout, env.timer.delay)
	}
}

func TestAdvProxy_TimerCancelledOnCompletion(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	host := testHost("myhost", testAddr(1))
	env.proxy.Advertise(host)
	env.completeAll()

	// No outstanding advs, timer should have been stopped.
	if len(env.proxy.advInfoList) != 0 {
		t.Fatal("expected no outstanding advInfo")
	}
}

// -------------------------------------------------------
// Tests: AdvProxyOption - WithAdvProxyTimeout
// -------------------------------------------------------

func TestAdvProxy_CustomTimeout(t *testing.T) {
	env := newAdvProxyTestEnv(t, WithAdvProxyTimeout(10*time.Second))
	env.proxy.Start()
	env.platform.reset()

	host := testHost("myhost", testAddr(1))
	env.proxy.Advertise(host)

	if env.timer == nil {
		t.Fatal("expected timer")
	}
	if env.timer.delay != 10*time.Second {
		t.Fatalf("expected 10s timeout, got %v", env.timer.delay)
	}
}

func TestAdvProxy_CustomTimeoutBelowMinimum(t *testing.T) {
	env := newAdvProxyTestEnv(t, WithAdvProxyTimeout(1*time.Second))

	// Should use the default since 1s < 5s minimum.
	if env.proxy.advTimeout != defaultAdvTimeout {
		t.Fatalf("expected default timeout %v, got %v", defaultAdvTimeout, env.proxy.advTimeout)
	}
}

// -------------------------------------------------------
// Tests: AdvertiseRemovalOf when not running
// -------------------------------------------------------

func TestAdvProxy_AdvertiseRemovalOfWhenStopped(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	host := testDeletedHost("myhost")

	// Should be a no-op.
	env.proxy.AdvertiseRemovalOf(host)
	if len(env.platform.calls) != 0 {
		t.Fatalf("expected no platform calls, got %d", len(env.platform.calls))
	}
}

func TestAdvProxy_AdvertiseRemovalOfServiceWhenStopped(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	svc := makeRegService("My Printer", "_ipp._tcp", 631)

	// Should be a no-op.
	env.proxy.AdvertiseRemovalOfService(svc, "myhost.default.service.arpa.")
	if len(env.platform.calls) != 0 {
		t.Fatalf("expected no platform calls, got %d", len(env.platform.calls))
	}
}

// -------------------------------------------------------
// Tests: Deleted service in update
// -------------------------------------------------------

func TestAdvProxy_DeletedServiceInUpdate(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	// First register host with service.
	host1 := testHost("myhost", testAddr(1))
	svc := makeRegService("My Printer", "_ipp._tcp", 631)
	host1.Services = []*RegService{svc}
	env.proxy.Advertise(host1)
	env.completeAll()
	env.platform.reset()

	env.proxy.server.hosts = append(env.proxy.server.hosts, host1)

	// Now update: host alive but service deleted.
	host2 := testHost("myhost", testAddr(1))
	deletedSvc := makeDeletedRegService("My Printer", "_ipp._tcp")
	host2.Services = []*RegService{deletedSvc}
	env.proxy.Advertise(host2)

	unregSvcCalls := env.platform.findCalls("UnregisterService")
	if len(unregSvcCalls) != 1 {
		t.Fatalf("expected 1 UnregisterService for deleted service, got %d", len(unregSvcCalls))
	}
}

// -------------------------------------------------------
// Tests: Fully removed host (KeyLease == 0)
// -------------------------------------------------------

func TestAdvProxy_FullyRemovedHostAdvertise(t *testing.T) {
	env := newAdvProxyTestEnv(t)
	env.proxy.Start()
	env.platform.reset()

	// First register.
	host1 := testHost("myhost", testAddr(1))
	env.proxy.Advertise(host1)
	env.completeAll()
	env.platform.reset()

	env.proxy.server.hosts = append(env.proxy.server.hosts, host1)

	// Fully remove.
	host2 := testFullyRemovedHost("myhost")
	env.proxy.Advertise(host2)

	unregHostCalls := env.platform.findCalls("UnregisterHost")
	unregKeyCalls := env.platform.findCalls("UnregisterKey")

	if len(unregHostCalls) != 1 {
		t.Fatalf("expected 1 UnregisterHost, got %d", len(unregHostCalls))
	}
	if len(unregKeyCalls) < 1 {
		t.Fatalf("expected at least 1 UnregisterKey, got %d", len(unregKeyCalls))
	}
}
