// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package border

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Mock types
// ---------------------------------------------------------------------------

// mockTransport records sent messages and registered handlers.
type mockTransport struct {
	sentMessages []sentMsg
	sentRequests []sentReq
	handlers     map[string]func(*coap.Message, coap.MessageInfo)
}

type sentMsg struct {
	msg  *coap.Message
	info coap.MessageInfo
}

type sentReq struct {
	msg  *coap.Message
	info coap.MessageInfo
	cb   func(*coap.Message, coap.MessageInfo, error)
}

func newMockTransport() *mockTransport {
	return &mockTransport{
		handlers: make(map[string]func(*coap.Message, coap.MessageInfo)),
	}
}

func (m *mockTransport) SendMessage(msg *coap.Message, info coap.MessageInfo) error {
	m.sentMessages = append(m.sentMessages, sentMsg{msg: msg, info: info})
	return nil
}

func (m *mockTransport) SendRequest(msg *coap.Message, info coap.MessageInfo, cb func(*coap.Message, coap.MessageInfo, error)) error {
	m.sentRequests = append(m.sentRequests, sentReq{msg: msg, info: info, cb: cb})
	return nil
}

func (m *mockTransport) RegisterHandler(uriPath string, handler func(*coap.Message, coap.MessageInfo)) {
	m.handlers[uriPath] = handler
}

func (m *mockTransport) UnregisterHandler(uriPath string) {
	delete(m.handlers, uriPath)
}

// mockSecureSession records DTLS-side operations.
type mockSecureSession struct {
	connected      bool
	sentMessages   []*coap.Message
	defaultHandler func(*coap.Message, coap.MessageInfo)
	connectHandler func(bool)
	pskc           [16]byte
	disconnected   bool
	setPSKcCount   int
}

func newMockSecureSession() *mockSecureSession {
	return &mockSecureSession{}
}

func (m *mockSecureSession) IsConnected() bool { return m.connected }
func (m *mockSecureSession) SendMessage(msg *coap.Message) error {
	m.sentMessages = append(m.sentMessages, msg)
	return nil
}
func (m *mockSecureSession) SetDefaultHandler(h func(*coap.Message, coap.MessageInfo)) {
	m.defaultHandler = h
}
func (m *mockSecureSession) SetConnectHandler(h func(bool)) {
	m.connectHandler = h
}
func (m *mockSecureSession) Disconnect() {
	m.disconnected = true
	m.connected = false
}
func (m *mockSecureSession) SetPSKc(pskc [16]byte) {
	m.pskc = pskc
	m.setPSKcCount++
}

// mockAddressing provides network addressing info.
type mockAddressing struct {
	meshLocalPrefix ip6.NetworkPrefix
	rloc16          uint16
	leaderALOC16    uint16
	attached        bool
}

func (m *mockAddressing) MeshLocalPrefix() ip6.NetworkPrefix { return m.meshLocalPrefix }
func (m *mockAddressing) RLOC16() uint16                     { return m.rloc16 }
func (m *mockAddressing) LeaderALOC16() uint16               { return m.leaderALOC16 }
func (m *mockAddressing) IsAttached() bool                   { return m.attached }

// mockKeyManager provides PSKc.
type mockKeyManager struct {
	pskc [16]byte
}

func (m *mockKeyManager) GetPSKc() [16]byte { return m.pskc }

// mockDatasetReader provides test datasets.
type mockDatasetReader struct {
	activeDataset  *meshcop.Dataset
	pendingDataset *meshcop.Dataset
	activeErr      error
	pendingErr     error
}

func (m *mockDatasetReader) ReadActiveDataset() (meshcop.Dataset, error) {
	if m.activeErr != nil {
		return meshcop.Dataset{}, m.activeErr
	}
	if m.activeDataset != nil {
		return *m.activeDataset, nil
	}
	return meshcop.Dataset{}, nil
}

func (m *mockDatasetReader) ReadPendingDataset() (meshcop.Dataset, error) {
	if m.pendingErr != nil {
		return meshcop.Dataset{}, m.pendingErr
	}
	if m.pendingDataset != nil {
		return *m.pendingDataset, nil
	}
	return meshcop.Dataset{}, nil
}

// mockNetworkInfo records unicast address operations.
type mockNetworkInfo struct {
	addedAddresses   [][16]byte
	removedAddresses [][16]byte
}

func (m *mockNetworkInfo) AddUnicastAddress(addr [16]byte) {
	m.addedAddresses = append(m.addedAddresses, addr)
}

func (m *mockNetworkInfo) RemoveUnicastAddress(addr [16]byte) {
	m.removedAddresses = append(m.removedAddresses, addr)
}

// mockTimer records Stop calls.
type mockTimer struct {
	stopped bool
}

func (m *mockTimer) Stop() bool {
	was := !m.stopped
	m.stopped = true
	return was
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

type testHarness struct {
	agent     *Agent
	transport *mockTransport
	session   *mockSecureSession
	addr      *mockAddressing
	keys      *mockKeyManager
	datasets  *mockDatasetReader
	netInfo   *mockNetworkInfo
	timers    []*mockTimer
	timerCBs  []func()
}

func newTestHarness() *testHarness {
	tr := newMockTransport()
	ss := newMockSecureSession()
	addr := &mockAddressing{
		meshLocalPrefix: ip6.NetworkPrefix{0xfd, 0x00, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00},
		rloc16:          0x0400,
		leaderALOC16:    0xfc00,
		attached:        true,
	}
	keys := &mockKeyManager{
		pskc: [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
	}
	ds := &mockDatasetReader{}
	ni := &mockNetworkInfo{}

	agent := NewAgent(tr, ss, addr, keys, ds, ni)

	h := &testHarness{
		agent:     agent,
		transport: tr,
		session:   ss,
		addr:      addr,
		keys:      keys,
		datasets:  ds,
		netInfo:   ni,
	}

	// Inject deterministic timer.
	agent.afterFunc = func(d time.Duration, f func()) Timer {
		mt := &mockTimer{}
		h.timers = append(h.timers, mt)
		h.timerCBs = append(h.timerCBs, f)
		return mt
	}

	return h
}

// startAgent enables the agent, sets attached=true, and triggers HandleAttachStateChanged.
// This causes the agent to start (register handlers, configure session).
func (h *testHarness) startAgent() {
	h.addr.attached = true
	h.agent.SetEnabled(true)
	h.agent.HandleAttachStateChanged()
}

// simulateConnect simulates a DTLS connection from the Commissioner.
func (h *testHarness) simulateConnect() {
	h.session.connected = true
	if h.session.connectHandler != nil {
		h.session.connectHandler(true)
	}
}

// simulateDisconnect simulates a DTLS disconnection.
func (h *testHarness) simulateDisconnect() {
	h.session.connected = false
	if h.session.connectHandler != nil {
		h.session.connectHandler(false)
	}
}

// buildSecureRequest builds a CoAP POST request with the given URI path and payload,
// simulating a request from the Commissioner over DTLS.
func buildSecureRequest(uriPath string, payload []byte, token []byte) *coap.Message {
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 0x1234)
	if token != nil {
		_ = msg.SetToken(token)
	}
	_ = msg.AppendURIPathOptions(uriPath)
	if len(payload) > 0 {
		_ = msg.AppendPayloadMarker()
		_ = msg.AppendPayload(payload)
	}
	return msg
}

// buildPetitionAcceptResponse builds a Leader response accepting a petition.
func buildPetitionAcceptResponse(sessionID uint16) *coap.Message {
	var payload []byte
	payload = append(payload, encodeTLV(meshcop.TLVState, []byte{meshcop.StateAccept})...)
	sidBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sidBytes, sessionID)
	payload = append(payload, encodeTLV(meshcop.TLVCommissionerSessionID, sidBytes)...)

	resp := coap.NewMessage(coap.TypeNonConfirmable, coap.CodeChanged, 0)
	_ = resp.AppendPayloadMarker()
	_ = resp.AppendPayload(payload)
	return resp
}

// buildPetitionRejectResponse builds a Leader response rejecting a petition.
func buildPetitionRejectResponse() *coap.Message {
	payload := encodeTLV(meshcop.TLVState, []byte{meshcop.StateReject})
	resp := coap.NewMessage(coap.TypeNonConfirmable, coap.CodeChanged, 0)
	_ = resp.AppendPayloadMarker()
	_ = resp.AppendPayload(payload)
	return resp
}

// ---------------------------------------------------------------------------
// Tests: construction and defaults
// ---------------------------------------------------------------------------

func TestNewAgent_Defaults(t *testing.T) {
	h := newTestHarness()

	if !h.agent.IsEnabled() {
		t.Error("expected agent to be enabled by default")
	}
	if h.agent.IsStarted() {
		t.Error("expected agent not to be started before attach")
	}
	if h.agent.IsCommissionerConnected() {
		t.Error("expected no commissioner connected by default")
	}
	if port := h.agent.GetUDPPort(); port != DefaultUDPPort {
		t.Errorf("expected UDP port %d, got %d", DefaultUDPPort, port)
	}
}

func TestSetEnabled(t *testing.T) {
	h := newTestHarness()
	h.agent.SetEnabled(false)
	if h.agent.IsEnabled() {
		t.Error("expected agent to be disabled")
	}
	h.agent.SetEnabled(true)
	if !h.agent.IsEnabled() {
		t.Error("expected agent to be enabled")
	}
}

func TestSetUDPPort(t *testing.T) {
	h := newTestHarness()
	h.agent.SetUDPPort(12345)
	if port := h.agent.GetUDPPort(); port != 12345 {
		t.Errorf("expected port 12345, got %d", port)
	}
}

// ---------------------------------------------------------------------------
// Tests: start/stop state machine
// ---------------------------------------------------------------------------

func TestStartWhenEnabledAndAttached(t *testing.T) {
	h := newTestHarness()
	h.startAgent()

	if !h.agent.IsStarted() {
		t.Error("expected agent to be started")
	}

	// Should have registered "c/rx" handler on transport.
	if _, ok := h.transport.handlers["c/rx"]; !ok {
		t.Error("expected 'c/rx' handler to be registered")
	}

	// Should have set PSKc on secure session.
	if h.session.pskc != h.keys.pskc {
		t.Error("expected PSKc to be set on secure session")
	}

	// Should have set default and connect handlers.
	if h.session.defaultHandler == nil {
		t.Error("expected default handler to be set")
	}
	if h.session.connectHandler == nil {
		t.Error("expected connect handler to be set")
	}
}

func TestDoNotStartWhenDisabled(t *testing.T) {
	h := newTestHarness()
	h.agent.SetEnabled(false)
	h.agent.HandleAttachStateChanged()

	if h.agent.IsStarted() {
		t.Error("expected agent not to be started when disabled")
	}
}

func TestDoNotStartWhenNotAttached(t *testing.T) {
	h := newTestHarness()
	h.addr.attached = false
	h.agent.HandleAttachStateChanged()

	if h.agent.IsStarted() {
		t.Error("expected agent not to be started when not attached")
	}
}

func TestStopWhenDetached(t *testing.T) {
	h := newTestHarness()
	h.startAgent()

	if !h.agent.IsStarted() {
		t.Fatal("agent should be started")
	}

	// Detach.
	h.addr.attached = false
	h.agent.HandleAttachStateChanged()

	if h.agent.IsStarted() {
		t.Error("expected agent to be stopped after detach")
	}

	// Handler should be unregistered.
	if _, ok := h.transport.handlers["c/rx"]; ok {
		t.Error("expected 'c/rx' handler to be unregistered")
	}

	// Secure session should be disconnected.
	if !h.session.disconnected {
		t.Error("expected secure session to be disconnected")
	}
}

func TestStopWhenDisabled(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.agent.SetEnabled(false)

	if h.agent.IsStarted() {
		t.Error("expected agent to be stopped after disable")
	}
}

func TestStartIsIdempotent(t *testing.T) {
	h := newTestHarness()
	h.startAgent()

	pskCount := h.session.setPSKcCount
	h.agent.HandleAttachStateChanged() // trigger start again
	if h.session.setPSKcCount != pskCount {
		t.Error("start should be idempotent — PSKc should not be set again")
	}
}

// ---------------------------------------------------------------------------
// Tests: PSKc changed
// ---------------------------------------------------------------------------

func TestHandlePSKcChanged(t *testing.T) {
	h := newTestHarness()
	h.startAgent()

	newPSKc := [16]byte{0xAA, 0xBB, 0xCC}
	h.keys.pskc = newPSKc
	h.agent.HandlePSKcChanged()

	if h.session.pskc != newPSKc {
		t.Error("expected PSKc to be updated on secure session")
	}
}

func TestHandlePSKcChangedWhenNotStarted(t *testing.T) {
	h := newTestHarness()
	// Agent not started.
	initialCount := h.session.setPSKcCount
	h.agent.HandlePSKcChanged()
	if h.session.setPSKcCount != initialCount {
		t.Error("PSKc should not be set when agent is not started")
	}
}

// ---------------------------------------------------------------------------
// Tests: session connect/disconnect
// ---------------------------------------------------------------------------

func TestSessionConnect_ResetsKeepAliveTimer(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	if len(h.timers) == 0 {
		t.Fatal("expected a keep-alive timer to be created")
	}
}

func TestSessionDisconnect_RevokesCommissioner(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	// Set commissioner as connected.
	h.agent.mu.Lock()
	h.agent.commissionerConnected = true
	h.agent.commissionerSessionID = 5
	h.agent.mu.Unlock()

	h.simulateDisconnect()

	if h.agent.IsCommissionerConnected() {
		t.Error("expected commissioner to be disconnected")
	}
}

func TestSessionDisconnect_StopsKeepAliveTimer(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	if len(h.timers) == 0 {
		t.Fatal("expected timer")
	}
	timer := h.timers[len(h.timers)-1]

	h.simulateDisconnect()

	if !timer.stopped {
		t.Error("expected keep-alive timer to be stopped on disconnect")
	}
}

// ---------------------------------------------------------------------------
// Tests: keep-alive timeout
// ---------------------------------------------------------------------------

func TestKeepAliveTimeout_RevokesAndDisconnects(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	// Mark commissioner as connected.
	h.agent.mu.Lock()
	h.agent.commissionerConnected = true
	h.agent.commissionerSessionID = 1
	h.agent.mu.Unlock()

	if len(h.timerCBs) == 0 {
		t.Fatal("expected timer callback")
	}

	// Fire the timer callback.
	h.timerCBs[len(h.timerCBs)-1]()

	if h.agent.IsCommissionerConnected() {
		t.Error("expected commissioner to be revoked after timeout")
	}
	if !h.session.disconnected {
		t.Error("expected session to be disconnected after timeout")
	}
}

// ---------------------------------------------------------------------------
// Tests: Commissioner Petition (c/cp → c/lp)
// ---------------------------------------------------------------------------

func TestPetition_ForwardsToLeader(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	token := []byte{0xAA, 0xBB}
	payload := encodeTLV(meshcop.TLVCommissionerID, []byte("TestCommissioner"))
	msg := buildSecureRequest("c/cp", payload, token)

	h.session.defaultHandler(msg, coap.MessageInfo{})

	if len(h.transport.sentRequests) != 1 {
		t.Fatalf("expected 1 request to leader, got %d", len(h.transport.sentRequests))
	}

	// The forwarded request should use "c/lp" URI.
	req := h.transport.sentRequests[0]
	fwdURI := extractURIPath(req.msg)
	if fwdURI != "c/lp" {
		t.Errorf("expected forwarded URI 'c/lp', got %q", fwdURI)
	}
}

func TestPetition_AcceptSetsCommissioner(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	token := []byte{0xAA, 0xBB}
	msg := buildSecureRequest("c/cp", nil, token)
	h.session.defaultHandler(msg, coap.MessageInfo{})

	if len(h.transport.sentRequests) != 1 {
		t.Fatal("expected 1 request to leader")
	}

	// Simulate Leader accepting the petition.
	var sessionID uint16 = 42
	resp := buildPetitionAcceptResponse(sessionID)
	h.transport.sentRequests[0].cb(resp, coap.MessageInfo{}, nil)

	if !h.agent.IsCommissionerConnected() {
		t.Error("expected commissioner to be connected after accept")
	}

	// Check that Commissioner ALOC was added.
	expectedALOC16 := commissionerALOCBase + (sessionID % 8)
	if len(h.netInfo.addedAddresses) != 1 {
		t.Fatalf("expected 1 ALOC added, got %d", len(h.netInfo.addedAddresses))
	}
	alocAddr := h.netInfo.addedAddresses[0]
	// Check ALOC16 is in bytes 14-15 of the address.
	gotALOC16 := binary.BigEndian.Uint16(alocAddr[14:16])
	if gotALOC16 != expectedALOC16 {
		t.Errorf("expected ALOC16 0x%04X, got 0x%04X", expectedALOC16, gotALOC16)
	}
}

func TestPetition_RejectDoesNotSetCommissioner(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	msg := buildSecureRequest("c/cp", nil, []byte{0x01})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	resp := buildPetitionRejectResponse()
	h.transport.sentRequests[0].cb(resp, coap.MessageInfo{}, nil)

	if h.agent.IsCommissionerConnected() {
		t.Error("expected commissioner NOT to be connected after reject")
	}
}

func TestPetition_ResponseRelayedToCommissioner(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	token := []byte{0xDE, 0xAD}
	msg := buildSecureRequest("c/cp", nil, token)
	h.session.defaultHandler(msg, coap.MessageInfo{})

	resp := buildPetitionAcceptResponse(10)
	h.transport.sentRequests[0].cb(resp, coap.MessageInfo{}, nil)

	// Check that a response was sent to the Commissioner via DTLS.
	if len(h.session.sentMessages) != 1 {
		t.Fatalf("expected 1 message to commissioner, got %d", len(h.session.sentMessages))
	}

	commResp := h.session.sentMessages[0]
	// Check that the original token was preserved.
	gotToken := commResp.GetToken()
	if len(gotToken) != 2 || gotToken[0] != 0xDE || gotToken[1] != 0xAD {
		t.Errorf("expected token [DE AD], got %X", gotToken)
	}
}

func TestPetition_NilResponseIgnored(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	msg := buildSecureRequest("c/cp", nil, []byte{0x01})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	// Nil response (timeout).
	h.transport.sentRequests[0].cb(nil, coap.MessageInfo{}, nil)

	if h.agent.IsCommissionerConnected() {
		t.Error("commissioner should not be connected on nil response")
	}
	if len(h.session.sentMessages) != 0 {
		t.Error("no message should be sent to commissioner on nil response")
	}
}

func TestPetition_ForwardContextCleaned(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	msg := buildSecureRequest("c/cp", nil, []byte{0x01})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	h.agent.mu.Lock()
	ctxCount := len(h.agent.forwardContexts)
	h.agent.mu.Unlock()
	if ctxCount != 1 {
		t.Fatalf("expected 1 forward context, got %d", ctxCount)
	}

	resp := buildPetitionAcceptResponse(1)
	h.transport.sentRequests[0].cb(resp, coap.MessageInfo{}, nil)

	h.agent.mu.Lock()
	ctxCount = len(h.agent.forwardContexts)
	h.agent.mu.Unlock()
	if ctxCount != 0 {
		t.Errorf("expected forward contexts to be cleared, got %d", ctxCount)
	}
}

// ---------------------------------------------------------------------------
// Tests: Commissioner Keep-Alive (c/ca → c/la)
// ---------------------------------------------------------------------------

func TestKeepAlive_ForwardsToLeader(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	payload := encodeTLV(meshcop.TLVState, []byte{meshcop.StateAccept})
	sidBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sidBytes, 1)
	payload = append(payload, encodeTLV(meshcop.TLVCommissionerSessionID, sidBytes)...)

	msg := buildSecureRequest("c/ca", payload, []byte{0x01})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	if len(h.transport.sentRequests) != 1 {
		t.Fatalf("expected 1 request to leader, got %d", len(h.transport.sentRequests))
	}

	fwdURI := extractURIPath(h.transport.sentRequests[0].msg)
	if fwdURI != "c/la" {
		t.Errorf("expected 'c/la', got %q", fwdURI)
	}
}

func TestKeepAlive_ResetsTimer(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()
	timerCountBefore := len(h.timers)

	payload := encodeTLV(meshcop.TLVState, []byte{meshcop.StateAccept})
	msg := buildSecureRequest("c/ca", payload, []byte{0x01})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	if len(h.timers) <= timerCountBefore {
		t.Error("expected a new timer to be created for keep-alive")
	}
}

func TestKeepAlive_ResignRevokesCommissioner(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	// Set commissioner as connected.
	h.agent.mu.Lock()
	h.agent.commissionerConnected = true
	h.agent.commissionerSessionID = 3
	h.agent.mu.Unlock()

	// Send keep-alive with State=Reject (resign).
	payload := encodeTLV(meshcop.TLVState, []byte{meshcop.StateReject})
	msg := buildSecureRequest("c/ca", payload, []byte{0x01})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	if h.agent.IsCommissionerConnected() {
		t.Error("expected commissioner to be revoked after resign")
	}

	// Should still forward to leader.
	if len(h.transport.sentRequests) != 1 {
		t.Errorf("expected 1 forward to leader, got %d", len(h.transport.sentRequests))
	}
}

func TestKeepAliveResponse_RejectRevokesCommissioner(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	// Make commissioner connected.
	h.agent.mu.Lock()
	h.agent.commissionerConnected = true
	h.agent.commissionerSessionID = 5
	h.agent.mu.Unlock()

	// Send normal keep-alive.
	payload := encodeTLV(meshcop.TLVState, []byte{meshcop.StateAccept})
	msg := buildSecureRequest("c/ca", payload, []byte{0x01})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	// Leader responds with reject.
	resp := buildPetitionRejectResponse()
	h.transport.sentRequests[0].cb(resp, coap.MessageInfo{}, nil)

	if h.agent.IsCommissionerConnected() {
		t.Error("expected commissioner to be revoked when leader rejects keep-alive")
	}
}

// ---------------------------------------------------------------------------
// Tests: RelayTx (c/tx)
// ---------------------------------------------------------------------------

func TestRelayTx_ForwardsToJoinerRouter(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	// Make commissioner connected.
	h.agent.mu.Lock()
	h.agent.commissionerConnected = true
	h.agent.mu.Unlock()

	// Build payload with JoinerRouterLocator TLV (RLOC16 = 0x0800).
	var joinerRLOC uint16 = 0x0800
	rlocBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(rlocBytes, joinerRLOC)
	payload := encodeTLV(meshcop.TLVJoinerRouterLocator, rlocBytes)
	payload = append(payload, encodeTLV(meshcop.TLVJoinerDTLSEncapsulation, []byte{0x01, 0x02})...)

	msg := buildSecureRequest("c/tx", payload, []byte{0x01})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	if len(h.transport.sentMessages) != 1 {
		t.Fatalf("expected 1 message to joiner router, got %d", len(h.transport.sentMessages))
	}

	sent := h.transport.sentMessages[0]

	// Check destination port is TMF port.
	if sent.info.PeerPort != tmfPort {
		t.Errorf("expected peer port %d, got %d", tmfPort, sent.info.PeerPort)
	}

	// Check the URI of forwarded message is "c/tx".
	fwdURI := extractURIPath(sent.msg)
	if fwdURI != "c/tx" {
		t.Errorf("expected 'c/tx', got %q", fwdURI)
	}

	// Check destination RLOC16 is in the address.
	gotRLOC16 := binary.BigEndian.Uint16(sent.info.PeerAddr[14:16])
	if gotRLOC16 != joinerRLOC {
		t.Errorf("expected RLOC16 0x%04X in dest addr, got 0x%04X", joinerRLOC, gotRLOC16)
	}
}

func TestRelayTx_IgnoredWhenNoCommissioner(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	// Commissioner NOT connected.
	rlocBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(rlocBytes, 0x0800)
	payload := encodeTLV(meshcop.TLVJoinerRouterLocator, rlocBytes)

	msg := buildSecureRequest("c/tx", payload, []byte{0x01})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	if len(h.transport.sentMessages) != 0 {
		t.Error("expected no message when commissioner not connected")
	}
}

func TestRelayTx_IgnoredWithNilPayload(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	h.agent.mu.Lock()
	h.agent.commissionerConnected = true
	h.agent.mu.Unlock()

	msg := buildSecureRequest("c/tx", nil, []byte{0x01})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	if len(h.transport.sentMessages) != 0 {
		t.Error("expected no message with nil payload")
	}
}

func TestRelayTx_IgnoredWithMissingJoinerRouterLocator(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	h.agent.mu.Lock()
	h.agent.commissionerConnected = true
	h.agent.mu.Unlock()

	// Payload without JoinerRouterLocator.
	payload := encodeTLV(meshcop.TLVJoinerDTLSEncapsulation, []byte{0x01})
	msg := buildSecureRequest("c/tx", payload, []byte{0x01})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	if len(h.transport.sentMessages) != 0 {
		t.Error("expected no message without JoinerRouterLocator TLV")
	}
}

// ---------------------------------------------------------------------------
// Tests: RelayRx (mesh "c/rx" → Commissioner DTLS)
// ---------------------------------------------------------------------------

func TestRelayRx_ForwardsToCommissioner(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	// Build a mesh-side RelayRx message with some payload.
	relayPayload := []byte{0x01, 0x02, 0x03, 0x04}
	meshMsg := buildSecureRequest("c/rx", relayPayload, []byte{0xAB})

	handler, ok := h.transport.handlers["c/rx"]
	if !ok {
		t.Fatal("expected 'c/rx' handler to be registered")
	}
	handler(meshMsg, coap.MessageInfo{})

	if len(h.session.sentMessages) != 1 {
		t.Fatalf("expected 1 message to commissioner, got %d", len(h.session.sentMessages))
	}

	fwdMsg := h.session.sentMessages[0]
	fwdURI := extractURIPath(fwdMsg)
	if fwdURI != "c/rx" {
		t.Errorf("expected 'c/rx', got %q", fwdURI)
	}
}

func TestRelayRx_IgnoredWhenNotConnected(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	// Session not connected.

	handler := h.transport.handlers["c/rx"]
	msg := buildSecureRequest("c/rx", []byte{0x01}, []byte{0x01})
	handler(msg, coap.MessageInfo{})

	if len(h.session.sentMessages) != 0 {
		t.Error("expected no message when session not connected")
	}
}

func TestRelayRx_IgnoredWithNilPayload(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	handler := h.transport.handlers["c/rx"]
	msg := buildSecureRequest("c/rx", nil, []byte{0x01})
	handler(msg, coap.MessageInfo{})

	if len(h.session.sentMessages) != 0 {
		t.Error("expected no message with nil payload")
	}
}

// ---------------------------------------------------------------------------
// Tests: Dataset Get (c/cg, c/ag, c/pg)
// ---------------------------------------------------------------------------

func TestDatasetGetActive(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	// Set up an active dataset with some TLVs.
	ds := &meshcop.Dataset{}
	tlvData := encodeTLV(meshcop.TLVNetworkName, []byte("TestNet"))
	tlvData = append(tlvData, encodeTLV(meshcop.TLVPanID, []byte{0x12, 0x34})...)
	_ = ds.SetFrom(tlvData)
	h.datasets.activeDataset = ds

	msg := buildSecureRequest("c/ag", nil, []byte{0xCC})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	if len(h.session.sentMessages) != 1 {
		t.Fatalf("expected 1 response, got %d", len(h.session.sentMessages))
	}

	resp := h.session.sentMessages[0]
	respPayload := resp.GetPayload()
	if respPayload == nil {
		t.Fatal("expected non-nil payload")
	}

	// Should contain the dataset TLVs.
	nameTLV := findTLVInBytes(respPayload, meshcop.TLVNetworkName)
	if nameTLV == nil || string(nameTLV) != "TestNet" {
		t.Errorf("expected NetworkName 'TestNet', got %q", string(nameTLV))
	}
}

func TestDatasetGetPending(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	ds := &meshcop.Dataset{}
	tlvData := encodeTLV(meshcop.TLVNetworkName, []byte("PendingNet"))
	_ = ds.SetFrom(tlvData)
	h.datasets.pendingDataset = ds

	msg := buildSecureRequest("c/pg", nil, []byte{0xDD})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	if len(h.session.sentMessages) != 1 {
		t.Fatal("expected 1 response")
	}

	resp := h.session.sentMessages[0]
	respPayload := resp.GetPayload()
	nameTLV := findTLVInBytes(respPayload, meshcop.TLVNetworkName)
	if nameTLV == nil || string(nameTLV) != "PendingNet" {
		t.Errorf("expected 'PendingNet', got %q", string(nameTLV))
	}
}

func TestDatasetGetWithFilter(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	ds := &meshcop.Dataset{}
	tlvData := encodeTLV(meshcop.TLVNetworkName, []byte("TestNet"))
	tlvData = append(tlvData, encodeTLV(meshcop.TLVPanID, []byte{0x12, 0x34})...)
	tlvData = append(tlvData, encodeTLV(meshcop.TLVChannel, []byte{0x00, 0x0F})...)
	_ = ds.SetFrom(tlvData)
	h.datasets.activeDataset = ds

	// Request only NetworkName and Channel.
	getPayload := encodeTLV(meshcop.TLVGet, []byte{byte(meshcop.TLVNetworkName), byte(meshcop.TLVChannel)})
	msg := buildSecureRequest("c/ag", getPayload, []byte{0xEE})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	if len(h.session.sentMessages) != 1 {
		t.Fatal("expected 1 response")
	}

	resp := h.session.sentMessages[0]
	respPayload := resp.GetPayload()

	// NetworkName should be present.
	nameTLV := findTLVInBytes(respPayload, meshcop.TLVNetworkName)
	if nameTLV == nil {
		t.Error("expected NetworkName in response")
	}

	// Channel should be present.
	chanTLV := findTLVInBytes(respPayload, meshcop.TLVChannel)
	if chanTLV == nil {
		t.Error("expected Channel in response")
	}

	// PanID should NOT be present (not in Get TLV).
	panTLV := findTLVInBytes(respPayload, meshcop.TLVPanID)
	if panTLV != nil {
		t.Error("PanID should not be in filtered response")
	}
}

func TestDatasetGetError(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	h.datasets.activeErr = errDatasetNotFound
	msg := buildSecureRequest("c/ag", nil, []byte{0xFF})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	if len(h.session.sentMessages) != 1 {
		t.Fatal("expected 1 response even on error")
	}

	// Response should have no payload (empty error response).
	resp := h.session.sentMessages[0]
	if len(resp.GetPayload()) != 0 {
		t.Error("expected empty payload on error")
	}
}

func TestDatasetGetCommissioner(t *testing.T) {
	// "c/cg" should also read active dataset.
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	ds := &meshcop.Dataset{}
	tlvData := encodeTLV(meshcop.TLVNetworkName, []byte("CommDS"))
	_ = ds.SetFrom(tlvData)
	h.datasets.activeDataset = ds

	msg := buildSecureRequest("c/cg", nil, []byte{0x01})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	if len(h.session.sentMessages) != 1 {
		t.Fatal("expected 1 response")
	}

	resp := h.session.sentMessages[0]
	respPayload := resp.GetPayload()
	nameTLV := findTLVInBytes(respPayload, meshcop.TLVNetworkName)
	if string(nameTLV) != "CommDS" {
		t.Errorf("expected 'CommDS', got %q", string(nameTLV))
	}
}

// ---------------------------------------------------------------------------
// Tests: ProxyTx (c/ut)
// ---------------------------------------------------------------------------

func TestProxyTx_SendsToDestination(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	// Build UDPEncapsulation TLV: srcPort(2) + dstPort(2) + payload.
	srcPort := uint16(1234)
	dstPort := uint16(5678)
	udpPayload := []byte{0xCA, 0xFE}
	var udpEnc []byte
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, srcPort)
	udpEnc = append(udpEnc, portBuf...)
	binary.BigEndian.PutUint16(portBuf, dstPort)
	udpEnc = append(udpEnc, portBuf...)
	udpEnc = append(udpEnc, udpPayload...)

	// Build IPv6 Address TLV: 16-byte destination.
	destIP := [16]byte{0xfd, 0x00, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xfe, 0, 0x08, 0x00}

	var payload []byte
	// UDPEncapsulation uses extended TLV format for large payloads, but also
	// works with short form. Use short form here.
	payload = append(payload, encodeTLV(meshcop.TLVUDPEncapsulation, udpEnc)...)
	payload = append(payload, encodeTLV(meshcop.TLVIP6Address, destIP[:])...)

	msg := buildSecureRequest("c/ut", payload, []byte{0x01})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	if len(h.transport.sentMessages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(h.transport.sentMessages))
	}

	sent := h.transport.sentMessages[0]
	if sent.info.PeerPort != dstPort {
		t.Errorf("expected dest port %d, got %d", dstPort, sent.info.PeerPort)
	}
	if sent.info.PeerAddr != destIP {
		t.Errorf("expected dest addr %X, got %X", destIP, sent.info.PeerAddr)
	}
}

func TestProxyTx_IgnoredWithNilPayload(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	msg := buildSecureRequest("c/ut", nil, []byte{0x01})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	if len(h.transport.sentMessages) != 0 {
		t.Error("expected no message with nil payload")
	}
}

func TestProxyTx_IgnoredWithMissingUDPEncapsulation(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	// Only IP6Address, no UDPEncapsulation.
	destIP := [16]byte{0xfd, 0x00}
	payload := encodeTLV(meshcop.TLVIP6Address, destIP[:])
	msg := buildSecureRequest("c/ut", payload, []byte{0x01})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	if len(h.transport.sentMessages) != 0 {
		t.Error("expected no message without UDPEncapsulation TLV")
	}
}

func TestProxyTx_IgnoredWithMissingIP6Address(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	// Only UDPEncapsulation, no IP6Address.
	udpEnc := make([]byte, 6) // srcPort + dstPort + 2 bytes payload
	payload := encodeTLV(meshcop.TLVUDPEncapsulation, udpEnc)
	msg := buildSecureRequest("c/ut", payload, []byte{0x01})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	if len(h.transport.sentMessages) != 0 {
		t.Error("expected no message without IP6Address TLV")
	}
}

// ---------------------------------------------------------------------------
// Tests: Commissioner revocation
// ---------------------------------------------------------------------------

func TestRevokeCommissioner_RemovesALOC(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	// Petition and accept to set up commissioner.
	msg := buildSecureRequest("c/cp", nil, []byte{0x01})
	h.session.defaultHandler(msg, coap.MessageInfo{})
	resp := buildPetitionAcceptResponse(7)
	h.transport.sentRequests[0].cb(resp, coap.MessageInfo{}, nil)

	if !h.agent.IsCommissionerConnected() {
		t.Fatal("commissioner should be connected")
	}
	if len(h.netInfo.addedAddresses) != 1 {
		t.Fatal("expected 1 ALOC added")
	}

	// Now disconnect to trigger revocation.
	h.simulateDisconnect()

	if h.agent.IsCommissionerConnected() {
		t.Error("expected commissioner revoked")
	}
	if len(h.netInfo.removedAddresses) != 1 {
		t.Fatal("expected 1 ALOC removed")
	}

	// The removed address should match the added address.
	if h.netInfo.removedAddresses[0] != h.netInfo.addedAddresses[0] {
		t.Error("removed ALOC should match added ALOC")
	}
}

// ---------------------------------------------------------------------------
// Tests: Unknown URI
// ---------------------------------------------------------------------------

func TestUnknownURI_Ignored(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	msg := buildSecureRequest("c/unknown", nil, []byte{0x01})
	h.session.defaultHandler(msg, coap.MessageInfo{})

	// Nothing should happen.
	if len(h.transport.sentMessages) != 0 {
		t.Error("expected no messages for unknown URI")
	}
	if len(h.transport.sentRequests) != 0 {
		t.Error("expected no requests for unknown URI")
	}
	if len(h.session.sentMessages) != 0 {
		t.Error("expected no session messages for unknown URI")
	}
}

// ---------------------------------------------------------------------------
// Tests: Dispatch when not started
// ---------------------------------------------------------------------------

func TestDispatch_IgnoredWhenNotStarted(t *testing.T) {
	h := newTestHarness()
	// Don't start the agent — but manually set a default handler to simulate
	// receiving a message when stopped.
	h.agent.mu.Lock()
	h.agent.started = false
	h.agent.mu.Unlock()

	// Directly invoke the handler.
	msg := buildSecureRequest("c/cp", nil, []byte{0x01})
	h.agent.handleSecureRequest(msg, coap.MessageInfo{})

	if len(h.transport.sentRequests) != 0 {
		t.Error("expected no forwarding when not started")
	}
}

// ---------------------------------------------------------------------------
// Tests: Full flow
// ---------------------------------------------------------------------------

func TestFullFlow_PetitionRelayKeepAliveTimeout(t *testing.T) {
	h := newTestHarness()
	h.startAgent()
	h.simulateConnect()

	// 1. Petition.
	petMsg := buildSecureRequest("c/cp", nil, []byte{0x01, 0x02})
	h.session.defaultHandler(petMsg, coap.MessageInfo{})
	if len(h.transport.sentRequests) != 1 {
		t.Fatal("expected petition forwarded")
	}

	// 2. Petition accepted.
	resp := buildPetitionAcceptResponse(100)
	h.transport.sentRequests[0].cb(resp, coap.MessageInfo{}, nil)
	if !h.agent.IsCommissionerConnected() {
		t.Fatal("commissioner should be connected")
	}

	// 3. RelayTx.
	rlocBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(rlocBytes, 0x0C00)
	relayPayload := encodeTLV(meshcop.TLVJoinerRouterLocator, rlocBytes)
	relayPayload = append(relayPayload, encodeTLV(meshcop.TLVJoinerDTLSEncapsulation, []byte{0xAB, 0xCD})...)
	relayMsg := buildSecureRequest("c/tx", relayPayload, []byte{0x03})
	h.session.defaultHandler(relayMsg, coap.MessageInfo{})
	if len(h.transport.sentMessages) != 1 {
		t.Fatal("expected relay message forwarded")
	}

	// 4. Keep-Alive.
	kaPayload := encodeTLV(meshcop.TLVState, []byte{meshcop.StateAccept})
	kaMsg := buildSecureRequest("c/ca", kaPayload, []byte{0x04})
	h.session.defaultHandler(kaMsg, coap.MessageInfo{})
	if len(h.transport.sentRequests) != 2 {
		t.Fatalf("expected 2 requests (petition + keep-alive), got %d", len(h.transport.sentRequests))
	}

	// 5. Keep-Alive timeout fires.
	lastCB := h.timerCBs[len(h.timerCBs)-1]
	lastCB()

	if h.agent.IsCommissionerConnected() {
		t.Error("commissioner should be revoked after timeout")
	}
	if !h.session.disconnected {
		t.Error("session should be disconnected after timeout")
	}
}

// ---------------------------------------------------------------------------
// Tests: helper functions
// ---------------------------------------------------------------------------

func TestExtractURIPath(t *testing.T) {
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 0)
	_ = msg.AppendURIPathOptions("c/cp")

	path := extractURIPath(msg)
	if path != "c/cp" {
		t.Errorf("expected 'c/cp', got %q", path)
	}
}

func TestExtractURIPath_MultiSegment(t *testing.T) {
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 0)
	_ = msg.AppendURIPathOptions("a/b/c")

	path := extractURIPath(msg)
	if path != "a/b/c" {
		t.Errorf("expected 'a/b/c', got %q", path)
	}
}

func TestExtractURIPath_Empty(t *testing.T) {
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 0)
	path := extractURIPath(msg)
	if path != "" {
		t.Errorf("expected empty path, got %q", path)
	}
}

func TestEncodeTLV(t *testing.T) {
	data := encodeTLV(meshcop.TLVState, []byte{meshcop.StateAccept})
	if len(data) != 3 {
		t.Fatalf("expected 3 bytes, got %d", len(data))
	}
	if data[0] != byte(meshcop.TLVState) {
		t.Errorf("expected type %d, got %d", meshcop.TLVState, data[0])
	}
	if data[1] != 1 {
		t.Errorf("expected length 1, got %d", data[1])
	}
	if data[2] != meshcop.StateAccept {
		t.Errorf("expected value 0x%02X, got 0x%02X", meshcop.StateAccept, data[2])
	}
}

func TestFindTLVInBytes(t *testing.T) {
	var data []byte
	data = append(data, encodeTLV(meshcop.TLVState, []byte{meshcop.StateAccept})...)
	sidBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sidBytes, 42)
	data = append(data, encodeTLV(meshcop.TLVCommissionerSessionID, sidBytes)...)

	val := findTLVInBytes(data, meshcop.TLVState)
	if val == nil || len(val) != 1 || val[0] != meshcop.StateAccept {
		t.Errorf("expected StateAccept, got %v", val)
	}

	val = findTLVInBytes(data, meshcop.TLVCommissionerSessionID)
	if val == nil || len(val) != 2 {
		t.Fatalf("expected 2-byte session ID, got %v", val)
	}
	if binary.BigEndian.Uint16(val) != 42 {
		t.Errorf("expected session ID 42, got %d", binary.BigEndian.Uint16(val))
	}

	val = findTLVInBytes(data, meshcop.TLVNetworkName)
	if val != nil {
		t.Error("expected nil for missing TLV")
	}
}

func TestFindTLVInBytes_Nil(t *testing.T) {
	val := findTLVInBytes(nil, meshcop.TLVState)
	if val != nil {
		t.Error("expected nil for nil data")
	}
}

func TestFindTLVInBytesExtended(t *testing.T) {
	// Short form.
	data := encodeTLV(meshcop.TLVUDPEncapsulation, []byte{0x01, 0x02, 0x03, 0x04, 0x05})
	val := findTLVInBytesExtended(data, meshcop.TLVUDPEncapsulation)
	if val == nil || len(val) != 5 {
		t.Fatalf("expected 5-byte value, got %v", val)
	}

	// Extended form: type(1) + 0xFF(1) + length16(2) + value.
	extData := []byte{byte(meshcop.TLVUDPEncapsulation), 0xFF, 0x00, 0x03, 0xAA, 0xBB, 0xCC}
	val = findTLVInBytesExtended(extData, meshcop.TLVUDPEncapsulation)
	if val == nil || len(val) != 3 {
		t.Fatalf("expected 3-byte extended value, got %v", val)
	}
	if val[0] != 0xAA || val[1] != 0xBB || val[2] != 0xCC {
		t.Errorf("expected [AA BB CC], got %X", val)
	}
}

func TestCopySlice(t *testing.T) {
	orig := []byte{1, 2, 3}
	c := copySlice(orig)
	if len(c) != 3 || c[0] != 1 || c[1] != 2 || c[2] != 3 {
		t.Errorf("expected [1 2 3], got %v", c)
	}
	// Mutating the copy should not affect original.
	c[0] = 99
	if orig[0] != 1 {
		t.Error("copy should not alias original")
	}
}

func TestCopySlice_Nil(t *testing.T) {
	c := copySlice(nil)
	if c != nil {
		t.Error("expected nil for nil input")
	}
}

func TestRlocAddr(t *testing.T) {
	prefix := ip6.NetworkPrefix{0xfd, 0x00, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00}
	var rloc16 uint16 = 0x0400

	addr := rlocAddr(prefix, rloc16)

	// Check prefix.
	for i := 0; i < 8; i++ {
		if addr[i] != prefix[i] {
			t.Errorf("byte %d: expected 0x%02X, got 0x%02X", i, prefix[i], addr[i])
		}
	}

	// Check IID: 00:00:00:ff:fe:00 + RLOC16.
	if addr[8] != 0x00 || addr[9] != 0x00 || addr[10] != 0x00 {
		t.Errorf("IID bytes 8-10 wrong: %X", addr[8:11])
	}
	if addr[11] != 0xff || addr[12] != 0xfe || addr[13] != 0x00 {
		t.Errorf("IID bytes 11-13 wrong: %X", addr[11:14])
	}
	gotRLOC := binary.BigEndian.Uint16(addr[14:16])
	if gotRLOC != rloc16 {
		t.Errorf("expected RLOC16 0x%04X, got 0x%04X", rloc16, gotRLOC)
	}
}

// ---------------------------------------------------------------------------
// Sentinel error for dataset read failures.
// ---------------------------------------------------------------------------

type datasetError string

func (e datasetError) Error() string { return string(e) }

const errDatasetNotFound = datasetError("dataset not found")
