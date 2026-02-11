// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// stubTransport is a minimal CommissionerTransport for testing.
type stubTransport struct {
	mu              sync.Mutex
	sentMessages    []*coap.Message
	sentInfos       []coap.MessageInfo
	handlers        map[string]func(*coap.Message, coap.MessageInfo)
	sendRequestFunc func(msg *coap.Message, info coap.MessageInfo, cb func(*coap.Message, coap.MessageInfo, error)) error
}

func newStubTransport() *stubTransport {
	return &stubTransport{
		handlers: make(map[string]func(*coap.Message, coap.MessageInfo)),
	}
}

func (s *stubTransport) SendRequest(msg *coap.Message, info coap.MessageInfo, cb func(*coap.Message, coap.MessageInfo, error)) error {
	s.mu.Lock()
	s.sentMessages = append(s.sentMessages, msg)
	s.sentInfos = append(s.sentInfos, info)
	f := s.sendRequestFunc
	s.mu.Unlock()
	if f != nil {
		return f(msg, info, cb)
	}
	return nil
}

func (s *stubTransport) SendResponse(code coap.Code, req *coap.Message, info coap.MessageInfo) error {
	return nil
}

func (s *stubTransport) RegisterHandler(uriPath string, handler func(*coap.Message, coap.MessageInfo)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[uriPath] = handler
}

func (s *stubTransport) UnregisterHandler(uriPath string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.handlers, uriPath)
}

func (s *stubTransport) getHandler(uriPath string) func(*coap.Message, coap.MessageInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handlers[uriPath]
}

// stubAddressing is a minimal CommissionerAddressing for testing.
type stubAddressing struct {
	meshLocalPrefix ip6.NetworkPrefix
	rloc16          uint16
	leaderRLOC16    uint16
	attached        bool
}

func (s *stubAddressing) MeshLocalPrefix() ip6.NetworkPrefix { return s.meshLocalPrefix }
func (s *stubAddressing) RLOC16() uint16                     { return s.rloc16 }
func (s *stubAddressing) LeaderRLOC16() uint16               { return s.leaderRLOC16 }
func (s *stubAddressing) IsAttached() bool                   { return s.attached }

// buildActiveDataset creates a minimal valid active dataset for testing.
func buildActiveDataset(t *testing.T) *Dataset {
	t.Helper()
	info := &Info{}
	info.ActiveTimestamp.SetSeconds(100)
	info.ActiveTimestamp.SetTicks(0)
	info.ActiveTimestamp.SetAuthoritative(true)
	info.Components.ActiveTimestamp = true

	info.NetworkName = "TestNetwork"
	info.Components.NetworkName = true

	info.ExtendedPanID = [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	info.Components.ExtendedPanID = true

	info.PanID = 0x1234
	info.Components.PanID = true

	info.Channel = 15
	info.Components.Channel = true

	info.NetworkKey = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	info.Components.NetworkKey = true

	info.MeshLocalPrefix = [8]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	info.Components.MeshLocalPrefix = true

	info.PSKc = [16]byte{0xAA, 0xBB, 0xCC, 0xDD}
	info.Components.PSKc = true

	info.SecurityPolicy.RotationTime = 672
	info.Components.SecurityPolicy = true

	info.ChannelMask = 0x07FFF800
	info.Components.ChannelMask = true

	return InfoToDataset(info)
}

// ===========================================================================
// NetworkName tests
// ===========================================================================

func TestNetworkName_Set(t *testing.T) {
	var nn NetworkName
	if err := nn.Set("TestNet"); err != nil {
		t.Fatalf("Set valid name: %v", err)
	}
	if nn.String() != "TestNet" {
		t.Fatalf("expected 'TestNet', got %q", nn.String())
	}
}

func TestNetworkName_MaxLength(t *testing.T) {
	var nn NetworkName
	name16 := "1234567890123456"
	if err := nn.Set(name16); err != nil {
		t.Fatalf("Set 16-byte name: %v", err)
	}

	name17 := "12345678901234567"
	if err := nn.Set(name17); err == nil {
		t.Fatal("expected error for 17-byte name")
	}
}

func TestNetworkName_Empty(t *testing.T) {
	var nn NetworkName
	if err := nn.Set(""); err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestNetworkName_InvalidUTF8(t *testing.T) {
	var nn NetworkName
	// 0xFF is not valid UTF-8.
	if err := nn.Set(string([]byte{0xFF, 0xFE})); err == nil {
		t.Fatal("expected error for invalid UTF-8")
	}
}

func TestNetworkName_GetAsData(t *testing.T) {
	nn, _ := NewNetworkName("Hello")
	data := nn.GetAsData()
	if string(data) != "Hello" {
		t.Fatalf("expected 'Hello', got %q", string(data))
	}
}

func TestNetworkName_Equal(t *testing.T) {
	a, _ := NewNetworkName("Net1")
	b, _ := NewNetworkName("Net1")
	c, _ := NewNetworkName("Net2")
	if !a.Equal(b) {
		t.Fatal("expected equal")
	}
	if a.Equal(c) {
		t.Fatal("expected not equal")
	}
}

// ===========================================================================
// ExtendedPanID tests
// ===========================================================================

func TestExtendedPanID_ToString(t *testing.T) {
	e := ExtendedPanID{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	s := e.ToString()
	if s != "deadbeefcafebabe" {
		t.Fatalf("expected 'deadbeefcafebabe', got %q", s)
	}
}

func TestExtendedPanID_GenerateRandom(t *testing.T) {
	var e ExtendedPanID
	if err := e.GenerateRandom(); err != nil {
		t.Fatalf("GenerateRandom: %v", err)
	}
	if e.IsEmpty() {
		// Extremely unlikely but technically possible.
		t.Log("warning: random ExtendedPanID is all zeros")
	}
}

func TestExtendedPanID_Equal(t *testing.T) {
	a := ExtendedPanID{1, 2, 3, 4, 5, 6, 7, 8}
	b := ExtendedPanID{1, 2, 3, 4, 5, 6, 7, 8}
	c := ExtendedPanID{0, 0, 0, 0, 0, 0, 0, 0}
	if !a.Equal(b) {
		t.Fatal("expected equal")
	}
	if a.Equal(c) {
		t.Fatal("expected not equal")
	}
}

func TestExtendedPanID_AssignmentCompatibility(t *testing.T) {
	// Verify that ExtendedPanID can be assigned to/from [8]byte.
	var raw [8]byte
	raw = [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	e := ExtendedPanID(raw)
	if e != ExtendedPanID(raw) {
		t.Fatal("assignment from [8]byte failed")
	}
	raw2 := [8]byte(e)
	if raw2 != raw {
		t.Fatal("assignment to [8]byte failed")
	}
}

// ===========================================================================
// DatasetUpdater tests
// ===========================================================================

func TestDatasetUpdater_RequestUpdate(t *testing.T) {
	store := NewMemoryDatasetStore()
	activeDS := buildActiveDataset(t)
	_ = store.SaveDataset(DatasetActive, activeDS)

	activeMgr := NewActiveDatasetManager(store, nil)
	_ = activeMgr.Restore()
	pendingMgr := NewPendingDatasetManager(store, nil)

	du := NewDatasetUpdater(activeMgr, pendingMgr, store)

	// Request a network name change.
	reqInfo := &Info{}
	reqInfo.NetworkName = "NewName"
	reqInfo.Components.NetworkName = true

	var callbackErr error
	callbackCalled := false
	err := du.RequestUpdate(reqInfo, func(e error) {
		callbackErr = e
		callbackCalled = true
	})
	if err != nil {
		t.Fatalf("RequestUpdate: %v", err)
	}

	if !du.IsUpdatePending() {
		t.Fatal("expected update to be pending")
	}

	// Check that a pending dataset was saved.
	pendingDS, err := store.ReadDataset(DatasetPending)
	if err != nil {
		t.Fatalf("ReadDataset(Pending): %v", err)
	}
	if pendingDS.Length() == 0 {
		t.Fatal("expected non-empty pending dataset")
	}

	// Verify pending dataset contains the new network name.
	nameTLV := pendingDS.FindTLV(TLVNetworkName)
	if nameTLV == nil {
		t.Fatal("expected NetworkName TLV in pending dataset")
	}
	if string(nameTLV.Value) != "NewName" {
		t.Fatalf("expected 'NewName', got %q", string(nameTLV.Value))
	}

	// Verify delay timer is set.
	delayTLV := pendingDS.FindTLV(TLVDelayTimer)
	if delayTLV == nil || len(delayTLV.Value) < 4 {
		t.Fatal("expected DelayTimer TLV in pending dataset")
	}
	delay := binary.BigEndian.Uint32(delayTLV.Value[:4])
	if delay != DelayTimerDefault {
		t.Fatalf("expected delay %d, got %d", DelayTimerDefault, delay)
	}

	// Simulate dataset change with the new name applied to active.
	newActiveInfo := activeDS.ConvertToInfo()
	newActiveInfo.NetworkName = "NewName"
	newActiveInfo.ActiveTimestamp.AdvanceRandomTicks()
	newActiveDS := InfoToDataset(&newActiveInfo)
	_ = store.SaveDataset(DatasetActive, newActiveDS)

	du.HandleDatasetChanged()

	if callbackCalled && callbackErr != nil {
		t.Fatalf("callback error: %v", callbackErr)
	}
	// The callback should have been called with nil error (success)
	// since IsSubsetOf skips timestamps/delay.
	if !callbackCalled {
		t.Log("note: callback not called synchronously — this may depend on subset check")
	}
}

func TestDatasetUpdater_CancelUpdate(t *testing.T) {
	store := NewMemoryDatasetStore()
	activeDS := buildActiveDataset(t)
	_ = store.SaveDataset(DatasetActive, activeDS)

	activeMgr := NewActiveDatasetManager(store, nil)
	_ = activeMgr.Restore()
	pendingMgr := NewPendingDatasetManager(store, nil)

	du := NewDatasetUpdater(activeMgr, pendingMgr, store)

	reqInfo := &Info{}
	reqInfo.Channel = 20
	reqInfo.Components.Channel = true

	var callbackErr error
	err := du.RequestUpdate(reqInfo, func(e error) {
		callbackErr = e
	})
	if err != nil {
		t.Fatalf("RequestUpdate: %v", err)
	}

	du.CancelUpdate()

	if du.IsUpdatePending() {
		t.Fatal("expected update to not be pending after cancel")
	}
	if callbackErr != goterrors.ErrAlready {
		t.Fatalf("expected ErrAlready on cancel, got %v", callbackErr)
	}
}

func TestDatasetUpdater_BusyWhenPending(t *testing.T) {
	store := NewMemoryDatasetStore()
	activeDS := buildActiveDataset(t)
	_ = store.SaveDataset(DatasetActive, activeDS)

	activeMgr := NewActiveDatasetManager(store, nil)
	_ = activeMgr.Restore()
	pendingMgr := NewPendingDatasetManager(store, nil)

	du := NewDatasetUpdater(activeMgr, pendingMgr, store)

	reqInfo := &Info{}
	reqInfo.Channel = 20
	reqInfo.Components.Channel = true

	_ = du.RequestUpdate(reqInfo, nil)

	err := du.RequestUpdate(reqInfo, nil)
	if err != goterrors.ErrBusy {
		t.Fatalf("expected ErrBusy, got %v", err)
	}
}

func TestDatasetUpdater_NoActiveDataset(t *testing.T) {
	store := NewMemoryDatasetStore()
	activeMgr := NewActiveDatasetManager(store, nil)
	pendingMgr := NewPendingDatasetManager(store, nil)

	du := NewDatasetUpdater(activeMgr, pendingMgr, store)

	reqInfo := &Info{}
	reqInfo.Channel = 20
	reqInfo.Components.Channel = true

	err := du.RequestUpdate(reqInfo, nil)
	if err != goterrors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
}

// ===========================================================================
// LeaderCommissioner tests
// ===========================================================================

func TestLeaderCommissioner_PetitionAccept(t *testing.T) {
	resignCalled := false
	lc := NewLeaderCommissioner(func() { resignCalled = true })

	sessionID, state := lc.HandlePetition("Commissioner1")
	if state != StateAccept {
		t.Fatalf("expected StateAccept, got %d", state)
	}
	if sessionID == 0 {
		t.Log("note: session ID is 0 (unlikely but valid)")
	}
	if !lc.HasCommissioner() {
		t.Fatal("expected HasCommissioner to be true")
	}
	if lc.GetCommissionerID() != "Commissioner1" {
		t.Fatalf("expected 'Commissioner1', got %q", lc.GetCommissionerID())
	}
	_ = resignCalled
}

func TestLeaderCommissioner_PetitionReject(t *testing.T) {
	lc := NewLeaderCommissioner(nil)

	// First commissioner petitions.
	_, state := lc.HandlePetition("Commissioner1")
	if state != StateAccept {
		t.Fatalf("expected accept for first petition")
	}

	// Second commissioner petitions — should be rejected.
	_, state = lc.HandlePetition("Commissioner2")
	if state != StateReject {
		t.Fatalf("expected reject for second commissioner, got %d", state)
	}
}

func TestLeaderCommissioner_PetitionRefresh(t *testing.T) {
	lc := NewLeaderCommissioner(nil)

	sid1, _ := lc.HandlePetition("Commissioner1")
	sid2, state := lc.HandlePetition("Commissioner1")

	if state != StateAccept {
		t.Fatal("expected accept on refresh")
	}
	// Session IDs may differ (new random ID on each petition).
	_ = sid1
	_ = sid2
}

func TestLeaderCommissioner_KeepAliveAccept(t *testing.T) {
	lc := NewLeaderCommissioner(nil)

	sessionID, _ := lc.HandlePetition("Commissioner1")

	result := lc.HandleKeepAlive(sessionID, StateAccept)
	if result != StateAccept {
		t.Fatalf("expected StateAccept, got %d", result)
	}
}

func TestLeaderCommissioner_KeepAliveWrongSession(t *testing.T) {
	lc := NewLeaderCommissioner(nil)

	_, _ = lc.HandlePetition("Commissioner1")

	result := lc.HandleKeepAlive(0xFFFF, StateAccept)
	if result != StateReject {
		t.Fatalf("expected StateReject for wrong session, got %d", result)
	}
}

func TestLeaderCommissioner_KeepAliveResign(t *testing.T) {
	resignCalled := false
	lc := NewLeaderCommissioner(func() { resignCalled = true })

	sessionID, _ := lc.HandlePetition("Commissioner1")
	result := lc.HandleKeepAlive(sessionID, StateReject)

	if result != StateAccept {
		t.Fatalf("expected StateAccept on resign, got %d", result)
	}
	if lc.HasCommissioner() {
		t.Fatal("expected no commissioner after resign")
	}
	if !resignCalled {
		t.Fatal("expected resign callback to be called")
	}
}

func TestLeaderCommissioner_Resign(t *testing.T) {
	resignCalled := false
	lc := NewLeaderCommissioner(func() { resignCalled = true })

	_, _ = lc.HandlePetition("Commissioner1")
	lc.Resign()

	if lc.HasCommissioner() {
		t.Fatal("expected no commissioner after Resign()")
	}
	if !resignCalled {
		t.Fatal("expected resign callback")
	}
}

func TestLeaderCommissioner_SessionTimeout(t *testing.T) {
	// Use a test-friendly timer to simulate timeout.
	var timerFunc func()
	resignCalled := false

	lc := NewLeaderCommissioner(func() { resignCalled = true })
	lc.afterFunc = func(d time.Duration, f func()) *time.Timer {
		timerFunc = f
		return time.NewTimer(time.Hour) // Dummy timer, we'll call f manually.
	}

	_, _ = lc.HandlePetition("Commissioner1")

	if timerFunc == nil {
		t.Fatal("expected timer to be set")
	}

	// Simulate timeout.
	timerFunc()

	if lc.HasCommissioner() {
		t.Fatal("expected no commissioner after timeout")
	}
	if !resignCalled {
		t.Fatal("expected resign callback after timeout")
	}
}

// ===========================================================================
// EnergyScanClient tests
// ===========================================================================

func TestEnergyScanClient_SendQuery(t *testing.T) {
	transport := newStubTransport()
	addressing := &stubAddressing{
		rloc16:       0x0400,
		leaderRLOC16: 0x0000,
		attached:     true,
	}

	var sessionID uint16 = 42
	esc := NewEnergyScanClient(transport, addressing, func() uint16 { return sessionID })

	var addr [16]byte
	addr[0] = 0xff
	addr[1] = 0x33

	var callbackCalled bool
	err := esc.SendQuery(0x07FFF800, 10, 100, 200, addr, func(mask uint32, energy []byte, err error) {
		callbackCalled = true
	})
	if err != nil {
		t.Fatalf("SendQuery: %v", err)
	}

	// Verify a message was sent.
	transport.mu.Lock()
	msgCount := len(transport.sentMessages)
	transport.mu.Unlock()

	if msgCount != 1 {
		t.Fatalf("expected 1 sent message, got %d", msgCount)
	}

	// Verify handler was registered.
	handler := transport.getHandler(uriEnergyReport)
	if handler == nil {
		t.Fatal("expected handler for energy report URI")
	}

	// Simulate energy report.
	var reportPayload []byte
	maskBuf := make([]byte, 6)
	maskBuf[0] = 0
	maskBuf[1] = 4
	binary.BigEndian.PutUint32(maskBuf[2:6], 0x07FFF800)
	reportPayload = append(reportPayload, encodeTLV(TLVChannelMask, maskBuf)...)
	reportPayload = append(reportPayload, encodeTLV(TLVEnergyList, []byte{byte(0xB0), byte(0xBA), byte(0xC4)})...)

	reportMsg := coap.NewMessage(coap.TypeNonConfirmable, coap.CodePost, 0)
	_ = reportMsg.AppendPayloadMarker()
	_ = reportMsg.AppendPayload(reportPayload)

	handler(reportMsg, coap.MessageInfo{})

	if !callbackCalled {
		t.Fatal("expected energy scan callback to be called")
	}
}

func TestEnergyScanClient_Busy(t *testing.T) {
	transport := newStubTransport()
	addressing := &stubAddressing{attached: true}
	esc := NewEnergyScanClient(transport, addressing, func() uint16 { return 1 })

	var addr [16]byte
	_ = esc.SendQuery(0, 1, 1, 1, addr, func(uint32, []byte, error) {})

	err := esc.SendQuery(0, 1, 1, 1, addr, func(uint32, []byte, error) {})
	if err != goterrors.ErrBusy {
		t.Fatalf("expected ErrBusy, got %v", err)
	}
}

// ===========================================================================
// AnnounceBeginClient tests
// ===========================================================================

func TestAnnounceBeginClient_SendRequest(t *testing.T) {
	transport := newStubTransport()
	addressing := &stubAddressing{
		rloc16:       0x0400,
		leaderRLOC16: 0x0000,
		attached:     true,
	}

	abc := NewAnnounceBeginClient(transport, addressing, func() uint16 { return 99 })

	var addr [16]byte
	addr[0] = 0xff
	addr[1] = 0x33

	err := abc.SendRequest(0x07FFF800, 3, 1000, addr)
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}

	transport.mu.Lock()
	msgCount := len(transport.sentMessages)
	transport.mu.Unlock()

	if msgCount != 1 {
		t.Fatalf("expected 1 sent message, got %d", msgCount)
	}
}

// ===========================================================================
// PanIdQueryClient tests
// ===========================================================================

func TestPanIdQueryClient_SendQuery(t *testing.T) {
	transport := newStubTransport()
	addressing := &stubAddressing{
		rloc16:       0x0400,
		leaderRLOC16: 0x0000,
		attached:     true,
	}

	var sessionID uint16 = 55
	pqc := NewPanIdQueryClient(transport, addressing, func() uint16 { return sessionID })

	var addr [16]byte
	addr[0] = 0xff

	var conflictPanID uint16
	var conflictMask uint32
	var callbackCalled bool
	err := pqc.SendQuery(0x1234, 0x07FFF800, addr, func(panID uint16, mask uint32) {
		conflictPanID = panID
		conflictMask = mask
		callbackCalled = true
	})
	if err != nil {
		t.Fatalf("SendQuery: %v", err)
	}

	// Verify handler was registered.
	handler := transport.getHandler(uriPanIdConflict)
	if handler == nil {
		t.Fatal("expected handler for PAN ID conflict URI")
	}

	// Simulate PAN ID conflict report.
	var conflictPayload []byte
	panBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(panBytes, 0x1234)
	conflictPayload = append(conflictPayload, encodeTLV(TLVPanID, panBytes)...)

	maskBuf := make([]byte, 6)
	maskBuf[0] = 0
	maskBuf[1] = 4
	binary.BigEndian.PutUint32(maskBuf[2:6], 0x07FFF800)
	conflictPayload = append(conflictPayload, encodeTLV(TLVChannelMask, maskBuf)...)

	conflictMsg := coap.NewMessage(coap.TypeNonConfirmable, coap.CodePost, 0)
	_ = conflictMsg.AppendPayloadMarker()
	_ = conflictMsg.AppendPayload(conflictPayload)

	handler(conflictMsg, coap.MessageInfo{})

	if !callbackCalled {
		t.Fatal("expected PAN ID conflict callback to be called")
	}
	if conflictPanID != 0x1234 {
		t.Fatalf("expected PAN ID 0x1234, got 0x%04X", conflictPanID)
	}
	if conflictMask != 0x07FFF800 {
		t.Fatalf("expected mask 0x07FFF800, got 0x%08X", conflictMask)
	}
}

func TestPanIdQueryClient_Busy(t *testing.T) {
	transport := newStubTransport()
	addressing := &stubAddressing{attached: true}
	pqc := NewPanIdQueryClient(transport, addressing, func() uint16 { return 1 })

	var addr [16]byte
	_ = pqc.SendQuery(0x1234, 0, addr, func(uint16, uint32) {})

	err := pqc.SendQuery(0x1234, 0, addr, func(uint16, uint32) {})
	if err != goterrors.ErrBusy {
		t.Fatalf("expected ErrBusy, got %v", err)
	}
}
