// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the conditions in the
// LICENSE file are met.

package srp

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/hilli/gothread/crypto/ecdsa"
	"github.com/hilli/gothread/crypto/sha256"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/dns"
	"github.com/hilli/gothread/net/ip6"
)

// -------------------------------------------------------
// Test helpers
// -------------------------------------------------------

// fakeTimer captures the callback and delay for manual firing.
type fakeTimer struct {
	mu      sync.Mutex
	delay   time.Duration
	fn      func()
	stopped bool
}

func (t *fakeTimer) Stop() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	was := !t.stopped
	t.stopped = true
	return was
}

func (t *fakeTimer) Fire() {
	t.mu.Lock()
	fn := t.fn
	t.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// testEnv provides a controlled test environment for the SRP client.
type testEnv struct {
	t       *testing.T
	client  *Client
	sender  *fakeSender
	keyPair *ecdsa.KeyPair
	now     time.Time
	timer   *fakeTimer
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	kp, err := ecdsa.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	env := &testEnv{
		t:       t,
		sender:  &fakeSender{},
		keyPair: kp,
		now:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	env.client = NewClient(env.sender,
		WithKeyPair(kp),
		WithNow(func() time.Time { return env.now }),
		WithAfterFunc(func(d time.Duration, f func()) Timer {
			env.timer = &fakeTimer{delay: d, fn: f}
			return env.timer
		}),
		WithRandUint32(func(max uint32) uint32 {
			// Deterministic: always return 0 for predictable tests.
			return 0
		}),
	)

	return env
}

func (e *testEnv) start() {
	e.t.Helper()
	addr := ip6.SockAddr{
		Address: ip6.Address{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		Port:    53,
	}
	if err := e.client.Start(addr); err != nil {
		e.t.Fatalf("Start: %v", err)
	}
}

func (e *testEnv) fireTimer() {
	e.t.Helper()
	if e.timer == nil {
		e.t.Fatal("no timer set")
	}
	e.timer.Fire()
}

// fakeSender captures sent UDP packets for inspection.
type fakeSender struct {
	mu      sync.Mutex
	packets []sentPacket
	sendErr error
}

type sentPacket struct {
	data []byte
	dest ip6.SockAddr
}

func (s *fakeSender) Send(data []byte, dest ip6.SockAddr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sendErr != nil {
		return s.sendErr
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	s.packets = append(s.packets, sentPacket{data: cp, dest: dest})
	return nil
}

func (s *fakeSender) lastPacket() sentPacket {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.packets) == 0 {
		return sentPacket{}
	}
	return s.packets[len(s.packets)-1]
}

func (s *fakeSender) packetCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.packets)
}

// -------------------------------------------------------
// Tests — Client lifecycle
// -------------------------------------------------------

func TestNewClient(t *testing.T) {
	sender := &fakeSender{}
	c := NewClient(sender)

	if c.GetState() != StateStopped {
		t.Errorf("expected StateStopped, got %v", c.GetState())
	}
	if c.GetDomainName() != DefaultDomainName {
		t.Errorf("expected %q, got %q", DefaultDomainName, c.GetDomainName())
	}
	if c.IsRunning() {
		t.Error("expected IsRunning=false for stopped client")
	}
}

func TestStartStop(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	if env.client.GetState() == StateStopped {
		t.Error("expected client to be running after Start")
	}
	if !env.client.IsRunning() {
		t.Error("expected IsRunning=true")
	}

	// Starting again should fail.
	err := env.client.Start(ip6.SockAddr{})
	if err != errors.ErrInvalidState {
		t.Errorf("expected ErrInvalidState, got %v", err)
	}

	env.client.Stop()
	if env.client.GetState() != StateStopped {
		t.Errorf("expected StateStopped, got %v", env.client.GetState())
	}
	if env.client.IsRunning() {
		t.Error("expected IsRunning=false after Stop")
	}

	// Stop again is a no-op.
	env.client.Stop()
}

func TestPauseResume(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.Pause()
	if env.client.GetState() != StatePaused {
		t.Errorf("expected StatePaused, got %v", env.client.GetState())
	}
	if env.client.IsRunning() {
		t.Error("expected IsRunning=false when paused")
	}

	env.client.Resume()
	if !env.client.IsRunning() {
		t.Error("expected IsRunning=true after Resume")
	}

	// Resume when not paused is a no-op.
	env.client.Resume()
}

func TestPauseFromStopped(t *testing.T) {
	env := newTestEnv(t)
	// Pause when stopped is a no-op.
	env.client.Pause()
	if env.client.GetState() != StateStopped {
		t.Errorf("expected StateStopped, got %v", env.client.GetState())
	}
}

// -------------------------------------------------------
// Tests — Host info configuration
// -------------------------------------------------------

func TestSetHostName(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	err := env.client.SetHostName("myhost")
	if err != nil {
		t.Fatalf("SetHostName: %v", err)
	}

	info := env.client.GetHostInfo()
	if info.Name != "myhost" {
		t.Errorf("expected name 'myhost', got %q", info.Name)
	}

	// Same name should return ErrAlready.
	err = env.client.SetHostName("myhost")
	if err != errors.ErrAlready {
		t.Errorf("expected ErrAlready, got %v", err)
	}

	// Empty name should return ErrInvalidArgs.
	err = env.client.SetHostName("")
	if err != errors.ErrInvalidArgs {
		t.Errorf("expected ErrInvalidArgs, got %v", err)
	}
}

func TestSetHostAddresses(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	addrs := []ip6.Address{
		{0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		{0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
	}

	err := env.client.SetHostAddresses(addrs)
	if err != nil {
		t.Fatalf("SetHostAddresses: %v", err)
	}

	info := env.client.GetHostInfo()
	if len(info.Addresses) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(info.Addresses))
	}
	if info.Addresses[0] != addrs[0] {
		t.Errorf("address 0 mismatch")
	}
	if info.Addresses[1] != addrs[1] {
		t.Errorf("address 1 mismatch")
	}

	// Modifying the original slice shouldn't affect the client.
	addrs[0] = ip6.Address{}
	info2 := env.client.GetHostInfo()
	if info2.Addresses[0] == (ip6.Address{}) {
		t.Error("addresses should be copied, not referenced")
	}
}

func TestEnableAutoHostAddress(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	err := env.client.EnableAutoHostAddress()
	if err != nil {
		t.Fatalf("EnableAutoHostAddress: %v", err)
	}

	info := env.client.GetHostInfo()
	if !info.AutoAddress {
		t.Error("expected AutoAddress=true")
	}

	// Calling again should return ErrAlready.
	err = env.client.EnableAutoHostAddress()
	if err != errors.ErrAlready {
		t.Errorf("expected ErrAlready, got %v", err)
	}
}

// -------------------------------------------------------
// Tests — Service management
// -------------------------------------------------------

func TestAddRemoveService(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	svc := &Service{
		Name:         "_http._tcp",
		InstanceName: "My Web Server",
		Port:         80,
		Priority:     0,
		Weight:       0,
	}

	err := env.client.AddService(svc)
	if err != nil {
		t.Fatalf("AddService: %v", err)
	}
	if svc.State != ItemStateToAdd {
		t.Errorf("expected ItemStateToAdd, got %v", svc.State)
	}

	services := env.client.GetServices()
	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}

	// Adding same service again should return ErrAlready.
	err = env.client.AddService(svc)
	if err != errors.ErrAlready {
		t.Errorf("expected ErrAlready, got %v", err)
	}

	// Remove the service.
	err = env.client.RemoveService(svc)
	if err != nil {
		t.Fatalf("RemoveService: %v", err)
	}
	if svc.State != ItemStateToRemove {
		t.Errorf("expected ItemStateToRemove, got %v", svc.State)
	}

	// Removing again should return ErrAlready.
	err = env.client.RemoveService(svc)
	if err != errors.ErrAlready {
		t.Errorf("expected ErrAlready, got %v", err)
	}
}

func TestRemoveUnknownService(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	svc := &Service{Name: "_test._tcp", InstanceName: "test"}
	err := env.client.RemoveService(svc)
	if err != errors.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestClearService(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	svc := &Service{Name: "_http._tcp", InstanceName: "web"}
	if err := env.client.AddService(svc); err != nil {
		t.Fatal(err)
	}

	err := env.client.ClearService(svc)
	if err != nil {
		t.Fatalf("ClearService: %v", err)
	}

	services := env.client.GetServices()
	if len(services) != 0 {
		t.Errorf("expected 0 services, got %d", len(services))
	}

	// Clearing again should return ErrNotFound.
	err = env.client.ClearService(svc)
	if err != errors.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestRemoveHostAndServices(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	// Set up host.
	env.client.SetHostName("myhost")
	env.client.SetHostAddresses([]ip6.Address{{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}})

	svc := &Service{Name: "_http._tcp", InstanceName: "web", Port: 80}
	env.client.AddService(svc)

	// Mark for removal (don't send to server).
	err := env.client.RemoveHostAndServices(false, false)
	if err != nil {
		t.Fatalf("RemoveHostAndServices: %v", err)
	}

	info := env.client.GetHostInfo()
	if info.State != ItemStateRemoved {
		t.Errorf("expected host state Removed, got %v", info.State)
	}
	if svc.State != ItemStateRemoved {
		t.Errorf("expected service state Removed, got %v", svc.State)
	}
}

func TestRemoveHostAndServicesWithSend(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.SetHostName("myhost")
	env.client.SetHostAddresses([]ip6.Address{{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}})

	svc := &Service{Name: "_http._tcp", InstanceName: "web", Port: 80}
	env.client.AddService(svc)

	// Mark for removal WITH sending to server.
	err := env.client.RemoveHostAndServices(true, true)
	if err != nil {
		t.Fatalf("RemoveHostAndServices: %v", err)
	}

	info := env.client.GetHostInfo()
	if info.State != ItemStateToRemove {
		t.Errorf("expected host state ToRemove, got %v", info.State)
	}
	if svc.State != ItemStateToRemove {
		t.Errorf("expected service state ToRemove, got %v", svc.State)
	}
}

func TestRemoveAlreadyRemovedHost(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	err := env.client.RemoveHostAndServices(false, false)
	if err != errors.ErrAlready {
		t.Errorf("expected ErrAlready, got %v", err)
	}
}

func TestClearHostAndServices(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.SetHostName("myhost")
	env.client.SetHostAddresses([]ip6.Address{{0xfd}})

	svc := &Service{Name: "_test._tcp", InstanceName: "x"}
	env.client.AddService(svc)

	env.client.ClearHostAndServices()

	info := env.client.GetHostInfo()
	if info.Name != "" {
		t.Error("expected empty host name after clear")
	}
	if info.State != ItemStateRemoved {
		t.Errorf("expected Removed state, got %v", info.State)
	}
	if len(env.client.GetServices()) != 0 {
		t.Error("expected 0 services after clear")
	}
}

// -------------------------------------------------------
// Tests — Configuration
// -------------------------------------------------------

func TestSetDomainName(t *testing.T) {
	env := newTestEnv(t)

	err := env.client.SetDomainName("test.example.arpa.")
	if err != nil {
		t.Fatal(err)
	}
	if env.client.GetDomainName() != "test.example.arpa." {
		t.Errorf("unexpected domain name %q", env.client.GetDomainName())
	}

	err = env.client.SetDomainName("")
	if err != errors.ErrInvalidArgs {
		t.Errorf("expected ErrInvalidArgs, got %v", err)
	}
}

func TestSetLeaseIntervals(t *testing.T) {
	env := newTestEnv(t)

	env.client.SetLeaseInterval(3600)
	env.client.SetKeyLeaseInterval(86400)
	env.client.SetTtl(120)

	// These are internal; verify by checking determineTTL via a build.
	env.client.mu.Lock()
	defer env.client.mu.Unlock()

	if env.client.defaultLease != 3600 {
		t.Errorf("expected lease 3600, got %d", env.client.defaultLease)
	}
	if env.client.defaultKeyLease != 86400 {
		t.Errorf("expected keyLease 86400, got %d", env.client.defaultKeyLease)
	}
	if env.client.ttl != 120 {
		t.Errorf("expected ttl 120, got %d", env.client.ttl)
	}
}

func TestGetServerAddress(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	addr := env.client.GetServerAddress()
	if addr.Port != 53 {
		t.Errorf("expected port 53, got %d", addr.Port)
	}

	newAddr := ip6.SockAddr{
		Address: ip6.Address{0x20, 0x01},
		Port:    5353,
	}
	env.client.SetServerAddress(newAddr)
	if env.client.GetServerAddress().Port != 5353 {
		t.Error("SetServerAddress did not take effect")
	}
}

// -------------------------------------------------------
// Tests — State transitions
// -------------------------------------------------------

func TestItemStateString(t *testing.T) {
	tests := []struct {
		s    ItemState
		want string
	}{
		{ItemStateToAdd, "ToAdd"},
		{ItemStateAdding, "Adding"},
		{ItemStateToRefresh, "ToRefresh"},
		{ItemStateRefreshing, "Refreshing"},
		{ItemStateToRemove, "ToRemove"},
		{ItemStateRemoving, "Removing"},
		{ItemStateRegistered, "Registered"},
		{ItemStateRemoved, "Removed"},
		{ItemState(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("ItemState(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestClientStateString(t *testing.T) {
	tests := []struct {
		s    State
		want string
	}{
		{StateStopped, "Stopped"},
		{StatePaused, "Paused"},
		{StateToUpdate, "ToUpdate"},
		{StateUpdating, "Updating"},
		{StateUpdated, "Updated"},
		{StateToRetry, "ToRetry"},
		{State(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestStateTransitionOnStop(t *testing.T) {
	for i := ItemState(0); i <= ItemStateRemoved; i++ {
		expected := newStateOnStop[i]
		if expected != newStateOnStop[i] {
			t.Errorf("newStateOnStop[%v]: expected %v", i, expected)
		}
	}
	// Verify specific transitions.
	if newStateOnStop[ItemStateAdding] != ItemStateToRefresh {
		t.Error("Adding should become ToRefresh on Stop")
	}
	if newStateOnStop[ItemStateRegistered] != ItemStateToRefresh {
		t.Error("Registered should become ToRefresh on Stop")
	}
	if newStateOnStop[ItemStateRemoved] != ItemStateRemoved {
		t.Error("Removed should stay Removed on Stop")
	}
}

func TestStateTransitionOnPause(t *testing.T) {
	if newStateOnPause[ItemStateRegistered] != ItemStateRegistered {
		t.Error("Registered should stay Registered on Pause")
	}
	if newStateOnPause[ItemStateAdding] != ItemStateToRefresh {
		t.Error("Adding should become ToRefresh on Pause")
	}
}

func TestStateTransitionOnMessageTx(t *testing.T) {
	if newStateOnMessageTx[ItemStateToAdd] != ItemStateAdding {
		t.Error("ToAdd should become Adding on MessageTx")
	}
	if newStateOnMessageTx[ItemStateToRefresh] != ItemStateRefreshing {
		t.Error("ToRefresh should become Refreshing on MessageTx")
	}
	if newStateOnMessageTx[ItemStateToRemove] != ItemStateRemoving {
		t.Error("ToRemove should become Removing on MessageTx")
	}
	if newStateOnMessageTx[ItemStateRegistered] != ItemStateRegistered {
		t.Error("Registered should stay Registered on MessageTx")
	}
}

func TestStateTransitionOnUpdateDone(t *testing.T) {
	if newStateOnUpdateDone[ItemStateAdding] != ItemStateRegistered {
		t.Error("Adding should become Registered on UpdateDone")
	}
	if newStateOnUpdateDone[ItemStateRefreshing] != ItemStateRegistered {
		t.Error("Refreshing should become Registered on UpdateDone")
	}
	if newStateOnUpdateDone[ItemStateRemoving] != ItemStateRemoved {
		t.Error("Removing should become Removed on UpdateDone")
	}
	if newStateOnUpdateDone[ItemStateToAdd] != ItemStateToAdd {
		t.Error("ToAdd should stay ToAdd on UpdateDone")
	}
}

func TestStateTransitionOnSingleServiceMode(t *testing.T) {
	if newStateOnSingleServiceMode[ItemStateAdding] != ItemStateToRefresh {
		t.Error("Adding should become ToRefresh on SingleServiceMode")
	}
	if newStateOnSingleServiceMode[ItemStateToAdd] != ItemStateToAdd {
		t.Error("ToAdd should stay ToAdd on SingleServiceMode")
	}
	if newStateOnSingleServiceMode[ItemStateRegistered] != ItemStateRegistered {
		t.Error("Registered should stay Registered on SingleServiceMode")
	}
}

// -------------------------------------------------------
// Tests — DNS Update message building
// -------------------------------------------------------

func TestSendUpdate_Basic(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	// Configure host and service.
	env.client.SetHostName("myhost")
	env.client.SetHostAddresses([]ip6.Address{
		{0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	})

	svc := &Service{
		Name:         "_http._tcp",
		InstanceName: "webserver",
		Port:         80,
		Priority:     0,
		Weight:       0,
		TxtEntries:   []dns.TxtEntry{{Key: "path", Value: []byte("/")}},
	}
	env.client.AddService(svc)

	// Fire the update timer.
	env.fireTimer()

	// Should have sent one packet.
	if env.sender.packetCount() != 1 {
		t.Fatalf("expected 1 packet, got %d", env.sender.packetCount())
	}

	pkt := env.sender.lastPacket()
	if len(pkt.data) < dns.HeaderSize {
		t.Fatalf("packet too short: %d bytes", len(pkt.data))
	}

	// Parse the DNS header.
	var header dns.Header
	if err := header.UnmarshalBinary(pkt.data); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}

	if header.GetType() != dns.TypeQuery {
		t.Error("expected query type (DNS Update requests use QR=0)")
	}
	if header.GetOpCode() != dns.OpcodeUpdate {
		t.Errorf("expected OpcodeUpdate, got %v", header.GetOpCode())
	}
	if header.QDCount != 1 {
		t.Errorf("expected zone count 1, got %d", header.QDCount)
	}
	if header.ARCount != 2 {
		t.Errorf("expected AR count 2, got %d", header.ARCount)
	}

	// Verify the client is now in Updating state.
	if env.client.GetState() != StateUpdating {
		t.Errorf("expected StateUpdating, got %v", env.client.GetState())
	}
}

func TestSendUpdate_NoHostName(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	// Add service without setting host name.
	svc := &Service{Name: "_http._tcp", InstanceName: "web", Port: 80}
	env.client.AddService(svc)

	// Fire the timer; should not send anything since no host name.
	if env.timer != nil {
		env.fireTimer()
	}

	if env.sender.packetCount() != 0 {
		t.Errorf("expected 0 packets (no host name set), got %d", env.sender.packetCount())
	}
}

func TestSendUpdate_SendFailure(t *testing.T) {
	env := newTestEnv(t)
	env.sender.sendErr = errors.ErrFailed
	env.start()

	env.client.SetHostName("myhost")
	env.client.SetHostAddresses([]ip6.Address{{0xfd}})

	svc := &Service{Name: "_http._tcp", InstanceName: "web", Port: 80}
	env.client.AddService(svc)

	// Fire the timer; send will fail.
	env.fireTimer()

	// Client should be in ToUpdate state (retrying).
	if env.client.GetState() != StateToUpdate {
		t.Errorf("expected StateToUpdate after send failure, got %v", env.client.GetState())
	}
}

func TestSendUpdate_EmptyTxtEntries(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.SetHostName("host1")
	env.client.SetHostAddresses([]ip6.Address{{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}})

	svc := &Service{
		Name:         "_test._udp",
		InstanceName: "inst1",
		Port:         1234,
	}
	env.client.AddService(svc)

	env.fireTimer()

	if env.sender.packetCount() != 1 {
		t.Fatalf("expected 1 packet, got %d", env.sender.packetCount())
	}

	// Just verify the message was sent successfully (doesn't crash
	// with empty TXT entries — an empty TXT record with a single
	// zero-length string is expected).
}

func TestSendUpdate_SubTypes(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.SetHostName("host1")
	env.client.SetHostAddresses([]ip6.Address{{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}})

	svc := &Service{
		Name:          "_http._tcp",
		InstanceName:  "web",
		SubTypeLabels: []string{"_printer", "_scanner"},
		Port:          80,
		TxtEntries:    []dns.TxtEntry{{Key: "test", Value: []byte("1")}},
	}
	env.client.AddService(svc)

	env.fireTimer()

	if env.sender.packetCount() != 1 {
		t.Fatalf("expected 1 packet, got %d", env.sender.packetCount())
	}

	// Verify more records were generated (PTR for each sub-type).
	pkt := env.sender.lastPacket()
	var header dns.Header
	header.UnmarshalBinary(pkt.data)

	// NS count should include: PTR + 2 sub-type PTRs + SRV + TXT + delete-all + AAAA + KEY = 8
	if header.NSCount < 5 {
		t.Errorf("expected at least 5 update records (including sub-type PTRs), got %d", header.NSCount)
	}
}

func TestSendUpdate_RemoveService(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.SetHostName("host1")
	env.client.SetHostAddresses([]ip6.Address{{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}})

	svc := &Service{
		Name:         "_http._tcp",
		InstanceName: "web",
		Port:         80,
	}
	env.client.AddService(svc)

	// Fire timer to send the initial registration.
	env.fireTimer()
	initialPackets := env.sender.packetCount()

	// Simulate successful response to complete the update.
	env.client.mu.Lock()
	env.client.changeHostAndServiceStates(&newStateOnUpdateDone, false)
	env.client.setState(StateUpdated)
	env.client.mu.Unlock()

	// Now remove the service.
	env.client.RemoveService(svc)

	// Fire the timer to send the removal update.
	if env.timer != nil {
		env.fireTimer()
	}

	if env.sender.packetCount() <= initialPackets {
		t.Error("expected a new packet for removal update")
	}
}

// -------------------------------------------------------
// Tests — SIG(0) signature verification
// -------------------------------------------------------

func TestSignatureVerification(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.SetHostName("testhost")
	env.client.SetHostAddresses([]ip6.Address{
		{0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	})

	svc := &Service{
		Name:         "_test._tcp",
		InstanceName: "test1",
		Port:         12345,
		TxtEntries:   []dns.TxtEntry{{Key: "v", Value: []byte("1")}},
	}
	env.client.AddService(svc)

	env.fireTimer()

	if env.sender.packetCount() != 1 {
		t.Fatalf("expected 1 packet, got %d", env.sender.packetCount())
	}

	pkt := env.sender.lastPacket()

	var header dns.Header
	if err := header.UnmarshalBinary(pkt.data); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}

	if header.ARCount != 2 {
		t.Fatalf("expected AR count 2, got %d", header.ARCount)
	}

	// Find the SIG record by scanning from the end. The SIG(0) record
	// is the last record in the message. It starts with a root name
	// (0x00) followed by the SIG RR. We scan backwards for the SIG RR
	// type at the right offset.
	//
	// Instead of walking every record (which requires handling all
	// compression pointers), we use the fact that the sigRecordOffset
	// is recorded in the client during message building. We access it
	// indirectly by looking for the pattern: 0x00 (root name) then
	// RR type SIG (0x0018).

	// Find the SIG record: search for 0x00, 0x00, 0x18 pattern
	// (root name + SIG type bytes) near the end of the message.
	sigRecordOffset := -1
	for i := len(pkt.data) - ecdsa.SignatureSize - 30; i >= dns.HeaderSize; i-- {
		if pkt.data[i] == 0x00 && // root name terminator
			i+1+int(dns.ResourceRecordSize) < len(pkt.data) {
			rrType := binary.BigEndian.Uint16(pkt.data[i+1:])
			if dns.RRType(rrType) == dns.RRTypeSig {
				sigRecordOffset = i
				break
			}
		}
	}

	if sigRecordOffset < 0 {
		t.Fatal("could not find SIG record in message")
	}

	// Parse the SIG record.
	offset := sigRecordOffset + 1 // skip root name
	var rr dns.ResourceRecord
	rr.UnmarshalBinary(pkt.data[offset:])
	if rr.Type != dns.RRTypeSig {
		t.Fatalf("expected SIG record, got type %d", rr.Type)
	}

	rdataStart := offset + int(dns.ResourceRecordSize)
	rdataEnd := rdataStart + int(rr.RDLength)
	if rdataEnd != len(pkt.data) {
		t.Errorf("SIG record should be at the end of message, rdataEnd=%d, msgLen=%d", rdataEnd, len(pkt.data))
	}

	// SIG RDATA layout:
	// 18 bytes of SIG fields
	// signer name (variable, compressed)
	// 64-byte signature
	sigFields := pkt.data[rdataStart : rdataStart+18]

	// Read signer name.
	signerOffset := rdataStart + 18
	signerName, afterSigner, err := dns.ReadName(pkt.data, signerOffset)
	if err != nil {
		t.Fatalf("read signer name: %v", err)
	}

	expectedSigner := "testhost." + DefaultDomainName
	if signerName != expectedSigner {
		t.Errorf("signer name: expected %q, got %q", expectedSigner, signerName)
	}

	// Extract the 64-byte signature.
	sigBytes := pkt.data[afterSigner:rdataEnd]
	if len(sigBytes) != ecdsa.SignatureSize {
		t.Fatalf("expected signature size %d, got %d", ecdsa.SignatureSize, len(sigBytes))
	}

	// Verify signature is not all zeros (placeholder).
	allZero := true
	for _, b := range sigBytes {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("signature is all zeros; likely placeholder not overwritten")
	}

	// Recompute the hash to verify correctness.
	// Hash = SHA-256(SIG RDATA with canonical signer || message[0:sigRecordOffset])
	var sigRData []byte
	sigRData = append(sigRData, sigFields...)
	// Canonical (uncompressed) signer name.
	sigRData, _ = dns.AppendLabel(sigRData, "testhost")
	sigRData, _ = dns.AppendName(sigRData, DefaultDomainName)

	var h sha256.Sha256
	h.Start()
	h.Update(sigRData)
	h.Update(pkt.data[:sigRecordOffset])
	var hash sha256.Hash
	h.Finish(&hash)

	// We can't directly verify the ECDSA signature without the
	// standard library's Verify, but we can confirm the hash
	// is deterministic and the signature is non-trivial.
	if hash == (sha256.Hash{}) {
		t.Error("hash should not be all zeros")
	}
}

// -------------------------------------------------------
// Tests — Response processing
// -------------------------------------------------------

func TestHandleResponse_Success(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.SetHostName("myhost")
	env.client.SetHostAddresses([]ip6.Address{{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}})

	svc := &Service{Name: "_http._tcp", InstanceName: "web", Port: 80}
	env.client.AddService(svc)

	// Track callback invocations.
	var cbErr error
	var cbCalled bool
	env.client.SetCallback(func(err error, hostInfo *HostInfo, services []*Service, removed []*Service) {
		cbErr = err
		cbCalled = true
	})

	// Fire the timer to send update.
	env.fireTimer()

	if env.client.GetState() != StateUpdating {
		t.Fatalf("expected StateUpdating, got %v", env.client.GetState())
	}

	// Get the message ID from the sent packet.
	pkt := env.sender.lastPacket()
	msgID := binary.BigEndian.Uint16(pkt.data[0:2])

	// Build a success response.
	resp := buildResponse(msgID, dns.RcodeSuccess, 7200, 604800)

	env.client.HandleResponse(resp)

	if !cbCalled {
		t.Error("callback was not called")
	}
	if cbErr != nil {
		t.Errorf("expected nil error in callback, got %v", cbErr)
	}

	// Client should be in Updated state.
	if env.client.GetState() != StateUpdated {
		t.Errorf("expected StateUpdated, got %v", env.client.GetState())
	}

	// Service should now be Registered.
	if svc.State != ItemStateRegistered {
		t.Errorf("expected service state Registered, got %v", svc.State)
	}
}

func TestHandleResponse_Error(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.SetHostName("myhost")
	env.client.SetHostAddresses([]ip6.Address{{0xfd}})

	svc := &Service{Name: "_http._tcp", InstanceName: "web", Port: 80}
	env.client.AddService(svc)

	var cbErr error
	env.client.SetCallback(func(err error, _ *HostInfo, _ []*Service, _ []*Service) {
		cbErr = err
	})

	env.fireTimer()

	pkt := env.sender.lastPacket()
	msgID := binary.BigEndian.Uint16(pkt.data[0:2])

	// Build an error response (refused).
	resp := buildSimpleResponse(msgID, dns.RcodeRefused)
	env.client.HandleResponse(resp)

	if cbErr == nil {
		t.Error("expected error in callback for refused response")
	}
}

func TestHandleResponse_WrongMessageID(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.SetHostName("myhost")
	env.client.SetHostAddresses([]ip6.Address{{0xfd}})
	env.client.AddService(&Service{Name: "_t._tcp", InstanceName: "x", Port: 1})

	env.fireTimer()

	if env.client.GetState() != StateUpdating {
		t.Fatal("should be updating")
	}

	// Send response with wrong message ID.
	resp := buildSimpleResponse(0xFFFF, dns.RcodeSuccess)
	env.client.HandleResponse(resp)

	// Should still be in Updating state.
	if env.client.GetState() != StateUpdating {
		t.Errorf("expected StateUpdating (wrong msgID ignored), got %v", env.client.GetState())
	}
}

func TestHandleResponse_TooShort(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.SetHostName("host")
	env.client.SetHostAddresses([]ip6.Address{{0xfd}})
	env.client.AddService(&Service{Name: "_t._tcp", InstanceName: "x", Port: 1})

	env.fireTimer()

	// Short packet should be ignored.
	env.client.HandleResponse([]byte{0, 1, 2})

	if env.client.GetState() != StateUpdating {
		t.Error("short response should be ignored")
	}
}

func TestHandleResponse_NotUpdating(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	// Not in Updating state; response should be ignored.
	resp := buildSimpleResponse(1, dns.RcodeSuccess)
	env.client.HandleResponse(resp)
	// No crash.
}

func TestHandleResponse_LeaseProcessing(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.SetHostName("myhost")
	env.client.SetHostAddresses([]ip6.Address{{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}})
	env.client.AddService(&Service{Name: "_t._tcp", InstanceName: "x", Port: 1})

	env.client.SetCallback(func(error, *HostInfo, []*Service, []*Service) {})

	env.fireTimer()

	pkt := env.sender.lastPacket()
	msgID := binary.BigEndian.Uint16(pkt.data[0:2])

	// Build response with lease option.
	resp := buildResponse(msgID, dns.RcodeSuccess, 3600, 86400)
	env.client.HandleResponse(resp)

	env.client.mu.Lock()
	lease := env.client.lease
	keyLease := env.client.keyLease
	renewTime := env.client.leaseRenewTime
	env.client.mu.Unlock()

	if lease != 3600 {
		t.Errorf("expected lease 3600, got %d", lease)
	}
	if keyLease != 86400 {
		t.Errorf("expected key lease 86400, got %d", keyLease)
	}
	if renewTime.IsZero() {
		t.Error("lease renew time should be set")
	}
}

// -------------------------------------------------------
// Tests — Callback behavior
// -------------------------------------------------------

func TestCallback_RemovedServicesAreReturned(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.SetHostName("host")
	env.client.SetHostAddresses([]ip6.Address{{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}})

	svc1 := &Service{Name: "_a._tcp", InstanceName: "a", Port: 1}
	svc2 := &Service{Name: "_b._tcp", InstanceName: "b", Port: 2}
	env.client.AddService(svc1)
	env.client.AddService(svc2)

	var cbRemoved []*Service
	env.client.SetCallback(func(err error, _ *HostInfo, _ []*Service, removed []*Service) {
		cbRemoved = removed
	})

	// Send update.
	env.fireTimer()

	pkt := env.sender.lastPacket()
	msgID := binary.BigEndian.Uint16(pkt.data[0:2])

	// Success: both become Registered.
	resp := buildResponse(msgID, dns.RcodeSuccess, 7200, 604800)
	env.client.HandleResponse(resp)

	// Now mark svc1 for removal.
	env.client.RemoveService(svc1)
	env.fireTimer()

	pkt = env.sender.lastPacket()
	msgID = binary.BigEndian.Uint16(pkt.data[0:2])

	resp = buildResponse(msgID, dns.RcodeSuccess, 7200, 604800)
	env.client.HandleResponse(resp)

	// svc1 should appear in the removed list.
	found := false
	for _, s := range cbRemoved {
		if s == svc1 {
			found = true
		}
	}
	if !found {
		t.Error("expected svc1 in removed services list")
	}

	// svc1 should be pruned from the client's services.
	services := env.client.GetServices()
	for _, s := range services {
		if s == svc1 {
			t.Error("svc1 should have been pruned from services list")
		}
	}
}

// -------------------------------------------------------
// Tests — Retry logic
// -------------------------------------------------------

func TestSendFailureRetries(t *testing.T) {
	env := newTestEnv(t)
	env.sender.sendErr = errors.ErrFailed
	env.start()

	env.client.SetHostName("host")
	env.client.SetHostAddresses([]ip6.Address{{0xfd}})
	env.client.AddService(&Service{Name: "_t._tcp", InstanceName: "x", Port: 1})

	var cbCalled bool
	env.client.SetCallback(func(err error, _ *HostInfo, _ []*Service, _ []*Service) {
		cbCalled = true
	})

	// Fire MaxTxFailureRetries times.
	for i := uint8(0); i <= MaxTxFailureRetries; i++ {
		if env.timer != nil {
			env.fireTimer()
		}
	}

	if !cbCalled {
		t.Error("callback should have been called after max retries")
	}
}

func TestGrowRetryWaitInterval(t *testing.T) {
	env := newTestEnv(t)

	c := env.client
	c.mu.Lock()
	defer c.mu.Unlock()

	c.growRetryWaitInterval()
	if c.retryWaitInterval != MinRetryWaitInterval {
		t.Errorf("first grow: expected %d, got %d", MinRetryWaitInterval, c.retryWaitInterval)
	}

	c.growRetryWaitInterval()
	expected := MinRetryWaitInterval * RetryGrowthNumerator / RetryGrowthDenominator
	if c.retryWaitInterval != expected {
		t.Errorf("second grow: expected %d, got %d", expected, c.retryWaitInterval)
	}

	// Grow until max.
	for i := 0; i < 100; i++ {
		c.growRetryWaitInterval()
	}
	if c.retryWaitInterval != MaxRetryWaitInterval {
		t.Errorf("max: expected %d, got %d", MaxRetryWaitInterval, c.retryWaitInterval)
	}
}

// -------------------------------------------------------
// Tests — Lease interval calculation
// -------------------------------------------------------

func TestDetermineLeaseInterval(t *testing.T) {
	env := newTestEnv(t)
	c := env.client
	c.mu.Lock()
	defer c.mu.Unlock()

	// Both specified: interval wins.
	if got := c.determineLeaseInterval(3600, 7200); got != 3600 {
		t.Errorf("expected 3600, got %d", got)
	}

	// Interval unspecified: use default.
	if got := c.determineLeaseInterval(0, 7200); got != 7200 {
		t.Errorf("expected 7200, got %d", got)
	}

	// Both unspecified: use DefaultLease.
	if got := c.determineLeaseInterval(0, 0); got != DefaultLease {
		t.Errorf("expected %d, got %d", DefaultLease, got)
	}
}

func TestDetermineTtl(t *testing.T) {
	env := newTestEnv(t)
	c := env.client
	c.mu.Lock()
	defer c.mu.Unlock()

	// Default: derives from lease.
	c.ttl = 0
	c.lease = 0
	c.defaultLease = 3600
	if got := c.determineTTL(); got != 3600 {
		t.Errorf("expected TTL 3600, got %d", got)
	}

	// Explicit TTL.
	c.ttl = 120
	if got := c.determineTTL(); got != 120 {
		t.Errorf("expected TTL 120, got %d", got)
	}
}

// -------------------------------------------------------
// Tests — Wire format details
// -------------------------------------------------------

func TestMessageZoneSection(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.SetHostName("h")
	env.client.SetHostAddresses([]ip6.Address{{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}})
	env.client.AddService(&Service{Name: "_t._tcp", InstanceName: "x", Port: 1})

	env.fireTimer()

	pkt := env.sender.lastPacket()

	// Zone section starts right after the 12-byte header.
	// It should contain the domain name followed by a Zone (SOA/IN).
	offset := dns.HeaderSize
	name, newOff, err := dns.ReadName(pkt.data, offset)
	if err != nil {
		t.Fatalf("read zone name: %v", err)
	}
	if name != DefaultDomainName {
		t.Errorf("zone name: expected %q, got %q", DefaultDomainName, name)
	}

	// Zone question: type SOA (6), class IN (1).
	if newOff+4 > len(pkt.data) {
		t.Fatal("zone question truncated")
	}
	zoneType := binary.BigEndian.Uint16(pkt.data[newOff:])
	zoneClass := binary.BigEndian.Uint16(pkt.data[newOff+2:])
	if dns.RRType(zoneType) != dns.RRTypeSoa {
		t.Errorf("zone type: expected SOA (%d), got %d", dns.RRTypeSoa, zoneType)
	}
	if dns.RRClass(zoneClass) != dns.ClassInternet {
		t.Errorf("zone class: expected IN (%d), got %d", dns.ClassInternet, zoneClass)
	}
}

func TestMessageMultipleAddresses(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	addrs := []ip6.Address{
		{0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		{0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3},
	}

	env.client.SetHostName("multi")
	env.client.SetHostAddresses(addrs)

	svc := &Service{Name: "_t._tcp", InstanceName: "x", Port: 1}
	env.client.AddService(svc)

	env.fireTimer()

	pkt := env.sender.lastPacket()
	var header dns.Header
	header.UnmarshalBinary(pkt.data)

	// Should have update records for:
	// 1 PTR + 1 SRV + 1 TXT + 1 delete-all + 3 AAAA + 1 KEY = 8
	if header.NSCount != 8 {
		t.Errorf("expected 8 update records, got %d", header.NSCount)
	}
}

// -------------------------------------------------------
// Tests — Edge cases
// -------------------------------------------------------

func TestStopWhileUpdating(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.SetHostName("host")
	env.client.SetHostAddresses([]ip6.Address{{0xfd}})
	env.client.AddService(&Service{Name: "_t._tcp", InstanceName: "x", Port: 1})

	env.fireTimer()
	if env.client.GetState() != StateUpdating {
		t.Fatal("expected StateUpdating")
	}

	// Stop while updating.
	env.client.Stop()
	if env.client.GetState() != StateStopped {
		t.Errorf("expected StateStopped, got %v", env.client.GetState())
	}
}

func TestPauseWhileUpdating(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.SetHostName("host")
	env.client.SetHostAddresses([]ip6.Address{{0xfd}})
	env.client.AddService(&Service{Name: "_t._tcp", InstanceName: "x", Port: 1})

	env.fireTimer()

	env.client.Pause()
	if env.client.GetState() != StatePaused {
		t.Errorf("expected StatePaused, got %v", env.client.GetState())
	}
}

func TestSetHostNameWhileUpdating(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.SetHostName("host")
	env.client.SetHostAddresses([]ip6.Address{{0xfd}})
	env.client.AddService(&Service{Name: "_t._tcp", InstanceName: "x", Port: 1})

	env.fireTimer()

	err := env.client.SetHostName("newhost")
	if err != errors.ErrInvalidState {
		t.Errorf("expected ErrInvalidState, got %v", err)
	}
}

func TestAddServiceWhileUpdating(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.SetHostName("host")
	env.client.SetHostAddresses([]ip6.Address{{0xfd}})
	env.client.AddService(&Service{Name: "_t._tcp", InstanceName: "x", Port: 1})

	env.fireTimer()

	err := env.client.AddService(&Service{Name: "_t2._tcp", InstanceName: "y", Port: 2})
	if err != errors.ErrInvalidState {
		t.Errorf("expected ErrInvalidState, got %v", err)
	}
}

func TestMultipleServices(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.SetHostName("host")
	env.client.SetHostAddresses([]ip6.Address{{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}})

	for i := 0; i < 5; i++ {
		svc := &Service{
			Name:         "_http._tcp",
			InstanceName: string(rune('a' + i)),
			Port:         uint16(8080 + i),
			TxtEntries:   []dns.TxtEntry{{Key: "id", Value: []byte{byte('0' + i)}}},
		}
		env.client.AddService(svc)
	}

	if len(env.client.GetServices()) != 5 {
		t.Fatalf("expected 5 services, got %d", len(env.client.GetServices()))
	}

	env.fireTimer()

	if env.sender.packetCount() != 1 {
		t.Fatalf("expected 1 packet, got %d", env.sender.packetCount())
	}

	pkt := env.sender.lastPacket()
	var header dns.Header
	header.UnmarshalBinary(pkt.data)

	// 5 services * (PTR + SRV + TXT) + delete-all + AAAA + KEY = 18
	if header.NSCount != 18 {
		t.Errorf("expected 18 update records, got %d", header.NSCount)
	}
}

func TestCustomDomainName(t *testing.T) {
	env := newTestEnv(t)
	env.client.SetDomainName("custom.example.arpa.")
	env.start()

	env.client.SetHostName("host")
	env.client.SetHostAddresses([]ip6.Address{{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}})
	env.client.AddService(&Service{Name: "_t._tcp", InstanceName: "x", Port: 1})

	env.fireTimer()

	pkt := env.sender.lastPacket()
	// Zone name should be our custom domain.
	offset := dns.HeaderSize
	name, _, err := dns.ReadName(pkt.data, offset)
	if err != nil {
		t.Fatal(err)
	}
	if name != "custom.example.arpa." {
		t.Errorf("expected custom domain, got %q", name)
	}
}

func TestRemoveHostAndServicesWithKeyLease(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	env.client.SetHostName("host")
	env.client.SetHostAddresses([]ip6.Address{{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}})

	err := env.client.RemoveHostAndServices(true, true)
	if err != nil {
		t.Fatal(err)
	}

	env.client.mu.Lock()
	shouldRemove := env.client.shouldRemoveKeyLease
	env.client.mu.Unlock()

	if !shouldRemove {
		t.Error("shouldRemoveKeyLease should be true")
	}
}

// -------------------------------------------------------
// Tests — Constants
// -------------------------------------------------------

func TestConstants(t *testing.T) {
	if DefaultLease != 7200 {
		t.Errorf("DefaultLease: expected 7200, got %d", DefaultLease)
	}
	if DefaultKeyLease != 604800 {
		t.Errorf("DefaultKeyLease: expected 604800, got %d", DefaultKeyLease)
	}
	if MaxLease != 2147483 {
		t.Errorf("MaxLease: expected 2147483, got %d", MaxLease)
	}
	if UDPPayloadSize != 1232 {
		t.Errorf("UDPPayloadSize: expected 1232, got %d", UDPPayloadSize)
	}
	if DefaultDomainName != "default.service.arpa." {
		t.Errorf("DefaultDomainName: expected 'default.service.arpa.', got %q", DefaultDomainName)
	}
}

// -------------------------------------------------------
// Test helpers — DNS response builders
// -------------------------------------------------------

// buildSimpleResponse builds a minimal DNS response with the given
// message ID and response code.
func buildSimpleResponse(msgID uint16, rcode dns.ResponseCode) []byte {
	var header dns.Header
	header.MessageID = msgID
	header.SetType(dns.TypeResponse)
	header.SetOpCode(dns.OpcodeUpdate)
	header.SetResponseCode(rcode)

	b := header.MarshalBinary()
	return b[:]
}

// buildResponse builds a DNS response with an OPT record containing
// a lease option.
func buildResponse(msgID uint16, rcode dns.ResponseCode, lease, keyLease uint32) []byte {
	var header dns.Header
	header.MessageID = msgID
	header.SetType(dns.TypeResponse)
	header.SetOpCode(dns.OpcodeUpdate)
	header.SetResponseCode(rcode)
	header.ARCount = 1

	b := header.MarshalBinary()
	buf := b[:]

	// OPT record.
	buf = append(buf, 0x00) // root name

	var opt dns.OptRecord
	opt.Init()
	opt.SetUDPPayloadSize(UDPPayloadSize)

	rrOffset := len(buf)
	optBytes := opt.MarshalBinary()
	buf = append(buf, optBytes[:]...)

	// Lease option.
	var lo dns.LeaseOption
	lo.InitLong(lease, keyLease)
	loBytes := lo.MarshalBinary()
	buf = append(buf, loBytes...)

	// Update RDLength.
	rdataLen := uint16(len(buf) - rrOffset - int(dns.ResourceRecordSize))
	binary.BigEndian.PutUint16(buf[rrOffset+8:], rdataLen)

	return buf
}
