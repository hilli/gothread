// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tmf

import (
	"sync"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/thread/mle"
)

// ---------------------------------------------------------------------------
// Mock router table
// ---------------------------------------------------------------------------

type routerEntry struct {
	rloc16  uint16
	extAddr types.ExtAddress
}

type mockLeaderRouterTable struct {
	mu              sync.Mutex
	routers         map[uint8]routerEntry // routerID -> entry
	idSequence      uint8
	allocateErr     error // force allocation failure
	nextRandomID    uint8 // control random allocation
	nextRandomErr   error // force random allocation failure
	releaseCalled   bool
	releaseArg      uint8
	releaseErr      error
	allocateWithErr error // force AllocateWithID error on base interface
}

func newMockLeaderRouterTable() *mockLeaderRouterTable {
	return &mockLeaderRouterTable{
		routers: make(map[uint8]routerEntry),
	}
}

// --- RouterTableOps base interface ---

func (m *mockLeaderRouterTable) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routers = make(map[uint8]routerEntry)
}

func (m *mockLeaderRouterTable) AllocateWithID(routerID uint8) (uint16, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.allocateWithErr != nil {
		return 0, m.allocateWithErr
	}
	if _, exists := m.routers[routerID]; exists {
		return 0, goterrors.ErrNoBufs
	}
	rloc16 := mle.RLOC16FromRouterID(routerID)
	m.routers[routerID] = routerEntry{rloc16: rloc16}
	return rloc16, nil
}

func (m *mockLeaderRouterTable) Allocate() (routerID uint8, address uint16, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.allocateErr != nil {
		return 0, 0, m.allocateErr
	}
	id := m.nextRandomID
	rloc16 := mle.RLOC16FromRouterID(id)
	m.routers[id] = routerEntry{rloc16: rloc16}
	return id, rloc16, nil
}

func (m *mockLeaderRouterTable) GetActiveRouterCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.routers)
}

func (m *mockLeaderRouterTable) GetRouterIDSet() mle.RouterIDSet {
	m.mu.Lock()
	defer m.mu.Unlock()
	var set mle.RouterIDSet
	for id := range m.routers {
		set.Add(id)
	}
	return set
}

func (m *mockLeaderRouterTable) GetRouterIDSequence() uint8 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.idSequence
}

// --- LeaderRouterTable extensions ---

func (m *mockLeaderRouterTable) AllocateWithIDForRouter(routerID uint8, extAddr types.ExtAddress) (uint16, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.allocateWithErr != nil {
		return 0, m.allocateWithErr
	}
	if _, exists := m.routers[routerID]; exists {
		return 0, goterrors.ErrNoBufs
	}
	rloc16 := mle.RLOC16FromRouterID(routerID)
	m.routers[routerID] = routerEntry{rloc16: rloc16, extAddr: extAddr}
	return rloc16, nil
}

func (m *mockLeaderRouterTable) AllocateForRouter(extAddr types.ExtAddress) (routerID uint8, address uint16, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nextRandomErr != nil {
		return 0, 0, m.nextRandomErr
	}
	id := m.nextRandomID
	if _, exists := m.routers[id]; exists {
		return 0, 0, goterrors.ErrNoBufs
	}
	rloc16 := mle.RLOC16FromRouterID(id)
	m.routers[id] = routerEntry{rloc16: rloc16, extAddr: extAddr}
	return id, rloc16, nil
}

func (m *mockLeaderRouterTable) FindRLOC16ByExtAddress(addr types.ExtAddress) (uint16, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, entry := range m.routers {
		if entry.extAddr == addr {
			return entry.rloc16, true
		}
	}
	return 0, false
}

func (m *mockLeaderRouterTable) Release(routerID uint8) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releaseCalled = true
	m.releaseArg = routerID
	if m.releaseErr != nil {
		return m.releaseErr
	}
	delete(m.routers, routerID)
	return nil
}

func (m *mockLeaderRouterTable) ValidateOwnership(rloc16 uint16, extAddr types.ExtAddress) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	routerID := mle.RouterIDFromRLOC16(rloc16)
	entry, exists := m.routers[routerID]
	if !exists {
		return false
	}
	return entry.extAddr == extAddr
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// tmfInfo returns a coap.MessageInfo with link-local addresses suitable
// for the TMF interceptor.
func tmfInfo() coap.MessageInfo {
	return coap.MessageInfo{
		LocalAddr: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		PeerAddr:  [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		PeerPort:  Port,
	}
}

func buildAddrSolicitCON(msgID uint16, token []byte, req *AddrSolicitRequest) []byte {
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, msgID)
	_ = msg.SetToken(token)
	_ = msg.AppendURIPathOptions(PathForURI(URIAddressSolicit))
	payload := MarshalAddrSolicitRequest(req)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)
	return msg.GetBytes()
}

func buildAddrReleaseCON(msgID uint16, token []byte, req *AddrReleaseRequest) []byte {
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, msgID)
	_ = msg.SetToken(token)
	_ = msg.AppendURIPathOptions(PathForURI(URIAddressRelease))
	payload := MarshalAddrReleaseRequest(req)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)
	return msg.GetBytes()
}

// parseResponsePayload extracts the Address Solicit response from the
// first captured message in the mock sender.
func parseResponsePayload(t *testing.T, ms *mockSender) *AddrSolicitResponse {
	t.Helper()
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if len(ms.sent) == 0 {
		t.Fatal("no response was sent")
	}
	respMsg, err := coap.ParseMessage(ms.sent[0])
	if err != nil {
		t.Fatalf("failed to parse response message: %v", err)
	}
	payload := respMsg.GetPayload()
	resp, err := ParseAddrSolicitResponse(payload)
	if err != nil {
		t.Fatalf("failed to parse AddrSolicitResponse: %v", err)
	}
	return resp
}

// ---------------------------------------------------------------------------
// Address Solicit tests
// ---------------------------------------------------------------------------

func TestLeaderServiceAddrSolicitSuccess(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	rt.nextRandomID = 5
	rt.idSequence = 10

	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 16)
	defer ls.Stop()

	req := &AddrSolicitRequest{
		ExtAddress: types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		Status:     mle.UpgradeReasonTooFewRouters,
	}

	engine.Receive(buildAddrSolicitCON(1000, []byte{0xAA}, req), tmfInfo())

	resp := parseResponsePayload(t, ms)
	if resp.Status != AddrSolicitSuccess {
		t.Errorf("Status = %v, want Success", resp.Status)
	}
	if !resp.HasRLOC16 {
		t.Fatal("expected HasRLOC16 = true")
	}
	if resp.RLOC16 != mle.RLOC16FromRouterID(5) {
		t.Errorf("RLOC16 = 0x%04X, want 0x%04X", resp.RLOC16, mle.RLOC16FromRouterID(5))
	}
	if !resp.HasRouterMask {
		t.Fatal("expected HasRouterMask = true")
	}
	if resp.RouterIDSequence != 10 {
		t.Errorf("RouterIDSequence = %d, want 10", resp.RouterIDSequence)
	}
}

func TestLeaderServiceAddrSolicitWithRequestedID(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	rt.idSequence = 7

	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 16)
	defer ls.Stop()

	req := &AddrSolicitRequest{
		ExtAddress: types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		HasRLOC16:  true,
		RLOC16:     mle.RLOC16FromRouterID(10),
		Status:     mle.UpgradeReasonTooFewRouters,
	}

	engine.Receive(buildAddrSolicitCON(1001, []byte{0xBB}, req), tmfInfo())

	resp := parseResponsePayload(t, ms)
	if resp.Status != AddrSolicitSuccess {
		t.Errorf("Status = %v, want Success", resp.Status)
	}
	if resp.RLOC16 != mle.RLOC16FromRouterID(10) {
		t.Errorf("RLOC16 = 0x%04X, want 0x%04X (router ID 10)", resp.RLOC16, mle.RLOC16FromRouterID(10))
	}
}

func TestLeaderServiceAddrSolicitReregistration(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	rt.idSequence = 3

	// Pre-allocate a router with a known ExtAddress.
	extAddr := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	_, _ = rt.AllocateWithIDForRouter(20, extAddr)

	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 16)
	defer ls.Stop()

	req := &AddrSolicitRequest{
		ExtAddress: extAddr,
		Status:     mle.UpgradeReasonTooFewRouters,
	}

	engine.Receive(buildAddrSolicitCON(1002, []byte{0xCC}, req), tmfInfo())

	resp := parseResponsePayload(t, ms)
	if resp.Status != AddrSolicitSuccess {
		t.Errorf("Status = %v, want Success (re-registration)", resp.Status)
	}
	if resp.RLOC16 != mle.RLOC16FromRouterID(20) {
		t.Errorf("RLOC16 = 0x%04X, want 0x%04X (same as before)", resp.RLOC16, mle.RLOC16FromRouterID(20))
	}
}

func TestLeaderServiceAddrSolicitTooFewRoutersRejected(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	// Fill the table up to the threshold.
	for i := uint8(0); i < 16; i++ {
		_, _ = rt.AllocateWithIDForRouter(i, types.ExtAddress{i})
	}
	rt.idSequence = 5

	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 16)
	defer ls.Stop()

	req := &AddrSolicitRequest{
		ExtAddress: types.ExtAddress{0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		Status:     mle.UpgradeReasonTooFewRouters,
	}

	engine.Receive(buildAddrSolicitCON(1003, []byte{0xDD}, req), tmfInfo())

	resp := parseResponsePayload(t, ms)
	if resp.Status != AddrSolicitNoAddressAvailable {
		t.Errorf("Status = %v, want NoAddressAvailable", resp.Status)
	}
	if resp.HasRLOC16 {
		t.Error("expected HasRLOC16 = false for rejection")
	}
}

func TestLeaderServiceAddrSolicitHaveChildIDRequestAlwaysAllowed(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	// Fill the table above the threshold.
	for i := uint8(0); i < 20; i++ {
		_, _ = rt.AllocateWithIDForRouter(i, types.ExtAddress{i})
	}
	rt.nextRandomID = 30
	rt.idSequence = 12

	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 16)
	defer ls.Stop()

	req := &AddrSolicitRequest{
		ExtAddress: types.ExtAddress{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7},
		Status:     mle.UpgradeReasonHaveChildIDRequest,
	}

	engine.Receive(buildAddrSolicitCON(1004, []byte{0xEE}, req), tmfInfo())

	resp := parseResponsePayload(t, ms)
	if resp.Status != AddrSolicitSuccess {
		t.Errorf("Status = %v, want Success (HaveChildIDRequest bypasses threshold)", resp.Status)
	}
}

func TestLeaderServiceAddrSolicitParentPartitionChangeAlwaysAllowed(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	for i := uint8(0); i < 20; i++ {
		_, _ = rt.AllocateWithIDForRouter(i, types.ExtAddress{i})
	}
	rt.nextRandomID = 31
	rt.idSequence = 8

	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 16)
	defer ls.Stop()

	req := &AddrSolicitRequest{
		ExtAddress: types.ExtAddress{0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7},
		Status:     mle.UpgradeReasonParentPartitionChange,
	}

	engine.Receive(buildAddrSolicitCON(1005, []byte{0xFF}, req), tmfInfo())

	resp := parseResponsePayload(t, ms)
	if resp.Status != AddrSolicitSuccess {
		t.Errorf("Status = %v, want Success (ParentPartitionChange bypasses threshold)", resp.Status)
	}
}

func TestLeaderServiceAddrSolicitBorderRouterRequestAllowed(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	for i := uint8(0); i < 20; i++ {
		_, _ = rt.AllocateWithIDForRouter(i, types.ExtAddress{i})
	}
	rt.nextRandomID = 32
	rt.idSequence = 9

	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 16)
	defer ls.Stop()

	req := &AddrSolicitRequest{
		ExtAddress: types.ExtAddress{0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7},
		Status:     mle.UpgradeReasonBorderRouterRequest,
	}

	engine.Receive(buildAddrSolicitCON(1006, []byte{0x01}, req), tmfInfo())

	resp := parseResponsePayload(t, ms)
	if resp.Status != AddrSolicitSuccess {
		t.Errorf("Status = %v, want Success (BorderRouterRequest bypasses threshold)", resp.Status)
	}
}

func TestLeaderServiceAddrSolicitUnrecognizedReason(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	rt.idSequence = 1

	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 16)
	defer ls.Stop()

	req := &AddrSolicitRequest{
		ExtAddress: types.ExtAddress{0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7},
		Status:     mle.RouterUpgradeReason(99), // Unknown reason
	}

	engine.Receive(buildAddrSolicitCON(1007, []byte{0x02}, req), tmfInfo())

	resp := parseResponsePayload(t, ms)
	if resp.Status != AddrSolicitUnrecognizedReason {
		t.Errorf("Status = %v, want UnrecognizedReason", resp.Status)
	}
}

func TestLeaderServiceAddrSolicitNoIDsAvailable(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	rt.nextRandomErr = goterrors.ErrNoBufs
	rt.idSequence = 2

	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 16)
	defer ls.Stop()

	req := &AddrSolicitRequest{
		ExtAddress: types.ExtAddress{0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7},
		Status:     mle.UpgradeReasonTooFewRouters,
	}

	engine.Receive(buildAddrSolicitCON(1008, []byte{0x03}, req), tmfInfo())

	resp := parseResponsePayload(t, ms)
	if resp.Status != AddrSolicitNoAddressAvailable {
		t.Errorf("Status = %v, want NoAddressAvailable", resp.Status)
	}
}

func TestLeaderServiceAddrSolicitRequestedIDUnavailableFallsBackToRandom(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	// Pre-allocate router ID 10 so the requested ID is unavailable.
	_, _ = rt.AllocateWithIDForRouter(10, types.ExtAddress{0x99})
	rt.nextRandomID = 25
	rt.idSequence = 4

	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 16)
	defer ls.Stop()

	req := &AddrSolicitRequest{
		ExtAddress: types.ExtAddress{0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7},
		HasRLOC16:  true,
		RLOC16:     mle.RLOC16FromRouterID(10), // Occupied
		Status:     mle.UpgradeReasonTooFewRouters,
	}

	engine.Receive(buildAddrSolicitCON(1009, []byte{0x04}, req), tmfInfo())

	resp := parseResponsePayload(t, ms)
	if resp.Status != AddrSolicitSuccess {
		t.Errorf("Status = %v, want Success (fallback to random)", resp.Status)
	}
	if resp.RLOC16 != mle.RLOC16FromRouterID(25) {
		t.Errorf("RLOC16 = 0x%04X, want 0x%04X (random fallback ID 25)", resp.RLOC16, mle.RLOC16FromRouterID(25))
	}
}

func TestLeaderServiceAddrSolicitIgnoresNonConfirmable(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 16)
	defer ls.Stop()

	req := &AddrSolicitRequest{
		ExtAddress: types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		Status:     mle.UpgradeReasonTooFewRouters,
	}

	// Build a NON POST instead of CON.
	msg := coap.NewMessage(coap.TypeNonConfirmable, coap.CodePost, 2000)
	_ = msg.SetToken([]byte{0x05})
	_ = msg.AppendURIPathOptions(PathForURI(URIAddressSolicit))
	payload := MarshalAddrSolicitRequest(req)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)

	engine.Receive(msg.GetBytes(), tmfInfo())

	ms.mu.Lock()
	sentCount := len(ms.sent)
	ms.mu.Unlock()
	if sentCount != 0 {
		t.Errorf("expected no response for NON request, got %d messages sent", sentCount)
	}
}

func TestLeaderServiceAddrSolicitIgnoresInvalidPayload(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 16)
	defer ls.Stop()

	// Build a CON POST with garbage payload.
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 2001)
	_ = msg.SetToken([]byte{0x06})
	_ = msg.AppendURIPathOptions(PathForURI(URIAddressSolicit))
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload([]byte{0xFF, 0xFE}) // Invalid TLV

	engine.Receive(msg.GetBytes(), tmfInfo())

	ms.mu.Lock()
	sentCount := len(ms.sent)
	ms.mu.Unlock()
	if sentCount != 0 {
		t.Errorf("expected no response for invalid payload, got %d messages sent", sentCount)
	}
}

func TestLeaderServiceAddrSolicitResponseFormat(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	rt.nextRandomID = 3
	rt.idSequence = 42

	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 16)
	defer ls.Stop()

	req := &AddrSolicitRequest{
		ExtAddress: types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		Status:     mle.UpgradeReasonTooFewRouters,
	}

	engine.Receive(buildAddrSolicitCON(3000, []byte{0x07}, req), tmfInfo())

	ms.mu.Lock()
	defer ms.mu.Unlock()
	if len(ms.sent) == 0 {
		t.Fatal("no response was sent")
	}
	respMsg, err := coap.ParseMessage(ms.sent[0])
	if err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Verify it's an ACK with code 2.04 Changed.
	if respMsg.GetType() != coap.TypeAck {
		t.Errorf("response type = %d, want ACK", respMsg.GetType())
	}
	if respMsg.GetCode() != coap.CodeChanged {
		t.Errorf("response code = %d, want CodeChanged", respMsg.GetCode())
	}
	if respMsg.GetMessageID() != 3000 {
		t.Errorf("response message ID = %d, want 3000", respMsg.GetMessageID())
	}
}

// ---------------------------------------------------------------------------
// Address Release tests
// ---------------------------------------------------------------------------

func TestLeaderServiceAddrReleaseValid(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	extAddr := types.ExtAddress{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00, 0x01}
	_, _ = rt.AllocateWithIDForRouter(10, extAddr)

	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 16)
	defer ls.Stop()

	req := &AddrReleaseRequest{
		RLOC16:     mle.RLOC16FromRouterID(10),
		ExtAddress: extAddr,
	}

	engine.Receive(buildAddrReleaseCON(2000, []byte{0x10}, req), tmfInfo())

	// Should have sent an ACK.
	ms.mu.Lock()
	sentCount := len(ms.sent)
	ms.mu.Unlock()
	if sentCount == 0 {
		t.Fatal("expected an ACK response")
	}

	// Verify the router was released.
	rt.mu.Lock()
	_, exists := rt.routers[10]
	released := rt.releaseCalled
	releaseID := rt.releaseArg
	rt.mu.Unlock()

	if exists {
		t.Error("router ID 10 should have been released")
	}
	if !released {
		t.Error("Release should have been called")
	}
	if releaseID != 10 {
		t.Errorf("Release called with ID %d, want 10", releaseID)
	}
}

func TestLeaderServiceAddrReleaseInvalidOwnership(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	ownerAddr := types.ExtAddress{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00, 0x01}
	_, _ = rt.AllocateWithIDForRouter(10, ownerAddr)

	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 16)
	defer ls.Stop()

	// Try to release with a different ExtAddress.
	wrongAddr := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	req := &AddrReleaseRequest{
		RLOC16:     mle.RLOC16FromRouterID(10),
		ExtAddress: wrongAddr,
	}

	engine.Receive(buildAddrReleaseCON(2001, []byte{0x11}, req), tmfInfo())

	// No ACK should be sent (ownership mismatch).
	ms.mu.Lock()
	sentCount := len(ms.sent)
	ms.mu.Unlock()
	if sentCount != 0 {
		t.Errorf("expected no response for ownership mismatch, got %d messages sent", sentCount)
	}

	// Router should still be allocated.
	rt.mu.Lock()
	_, exists := rt.routers[10]
	rt.mu.Unlock()
	if !exists {
		t.Error("router ID 10 should NOT have been released")
	}
}

func TestLeaderServiceAddrReleaseNonExistentRLOC16(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 16)
	defer ls.Stop()

	req := &AddrReleaseRequest{
		RLOC16:     mle.RLOC16FromRouterID(50),
		ExtAddress: types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}

	engine.Receive(buildAddrReleaseCON(2002, []byte{0x12}, req), tmfInfo())

	// No ACK should be sent (non-existent).
	ms.mu.Lock()
	sentCount := len(ms.sent)
	ms.mu.Unlock()
	if sentCount != 0 {
		t.Errorf("expected no response for non-existent RLOC16, got %d messages sent", sentCount)
	}
}

func TestLeaderServiceAddrReleaseIgnoresNonConfirmable(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	extAddr := types.ExtAddress{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00, 0x01}
	_, _ = rt.AllocateWithIDForRouter(10, extAddr)

	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 16)
	defer ls.Stop()

	// Build a NON POST.
	req := &AddrReleaseRequest{
		RLOC16:     mle.RLOC16FromRouterID(10),
		ExtAddress: extAddr,
	}
	msg := coap.NewMessage(coap.TypeNonConfirmable, coap.CodePost, 2003)
	_ = msg.SetToken([]byte{0x13})
	_ = msg.AppendURIPathOptions(PathForURI(URIAddressRelease))
	payload := MarshalAddrReleaseRequest(req)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)

	engine.Receive(msg.GetBytes(), tmfInfo())

	ms.mu.Lock()
	sentCount := len(ms.sent)
	ms.mu.Unlock()
	if sentCount != 0 {
		t.Errorf("expected no response for NON request, got %d messages sent", sentCount)
	}

	// Router should still be allocated.
	rt.mu.Lock()
	_, exists := rt.routers[10]
	rt.mu.Unlock()
	if !exists {
		t.Error("router ID 10 should NOT have been released by NON request")
	}
}

// ---------------------------------------------------------------------------
// Handler registration / Stop tests
// ---------------------------------------------------------------------------

func TestLeaderServiceHandlerRegistration(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	rt.nextRandomID = 1
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 16)
	defer ls.Stop()

	// Verify handlers are registered by sending requests to both URIs.
	solicitReq := &AddrSolicitRequest{
		ExtAddress: types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		Status:     mle.UpgradeReasonTooFewRouters,
	}
	engine.Receive(buildAddrSolicitCON(4000, []byte{0x20}, solicitReq), tmfInfo())

	ms.mu.Lock()
	solicitSent := len(ms.sent)
	ms.mu.Unlock()
	if solicitSent == 0 {
		t.Error("Address Solicit handler not registered: no response sent")
	}

	// Reset sender.
	ms.mu.Lock()
	ms.sent = nil
	ms.mu.Unlock()

	extAddr := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	// The router was allocated above; set the extAddr so release can validate.
	rt.mu.Lock()
	if entry, ok := rt.routers[1]; ok {
		entry.extAddr = extAddr
		rt.routers[1] = entry
	}
	rt.mu.Unlock()

	releaseReq := &AddrReleaseRequest{
		RLOC16:     mle.RLOC16FromRouterID(1),
		ExtAddress: extAddr,
	}
	engine.Receive(buildAddrReleaseCON(4001, []byte{0x21}, releaseReq), tmfInfo())

	ms.mu.Lock()
	releaseSent := len(ms.sent)
	ms.mu.Unlock()
	if releaseSent == 0 {
		t.Error("Address Release handler not registered: no response sent")
	}
}

func TestLeaderServiceStop(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 16)

	// Stop unregisters handlers.
	ls.Stop()

	// After Stop, sending to a/as should get a 4.04 from the agent (not the leader handler).
	req := &AddrSolicitRequest{
		ExtAddress: types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		Status:     mle.UpgradeReasonTooFewRouters,
	}
	engine.Receive(buildAddrSolicitCON(5000, []byte{0x30}, req), tmfInfo())

	ms.mu.Lock()
	defer ms.mu.Unlock()
	if len(ms.sent) == 0 {
		t.Fatal("expected a 4.04 response after Stop")
	}

	respMsg, err := coap.ParseMessage(ms.sent[0])
	if err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if respMsg.GetCode() != coap.CodeNotFound {
		t.Errorf("response code = %d, want CodeNotFound (4.04)", respMsg.GetCode())
	}
}

func TestLeaderServiceSetRouterUpgradeThreshold(t *testing.T) {
	t.Parallel()

	rt := newMockLeaderRouterTable()
	// Pre-allocate 10 routers.
	for i := uint8(0); i < 10; i++ {
		_, _ = rt.AllocateWithIDForRouter(i, types.ExtAddress{i})
	}
	rt.nextRandomID = 20

	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	ls := NewLeaderService(agent, rt, 10) // Use a router upgrade threshold of 10.
	defer ls.Stop()

	req := &AddrSolicitRequest{
		ExtAddress: types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		Status:     mle.UpgradeReasonTooFewRouters,
	}

	// Should be rejected (10 >= 10).
	engine.Receive(buildAddrSolicitCON(6000, []byte{0x40}, req), tmfInfo())
	resp := parseResponsePayload(t, ms)
	if resp.Status != AddrSolicitNoAddressAvailable {
		t.Errorf("before threshold change: Status = %v, want NoAddressAvailable", resp.Status)
	}

	// Raise threshold and retry.
	ls.SetRouterUpgradeThreshold(20)
	ms.mu.Lock()
	ms.sent = nil
	ms.mu.Unlock()

	engine.Receive(buildAddrSolicitCON(6001, []byte{0x41}, req), tmfInfo())
	resp = parseResponsePayload(t, ms)
	if resp.Status != AddrSolicitSuccess {
		t.Errorf("after threshold change: Status = %v, want Success", resp.Status)
	}
}

// ---------------------------------------------------------------------------
// Interface satisfaction compile-time check
// ---------------------------------------------------------------------------

var _ LeaderRouterTable = (*mockLeaderRouterTable)(nil)
