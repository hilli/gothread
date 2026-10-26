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
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Mock transport
// ---------------------------------------------------------------------------

// mockTransport is a stub CommissionerTransport for testing.
type mockTransport struct {
	mu            sync.Mutex
	sentRequests  []mockSentRequest
	sentResponses []mockSentResponse
	handlers      map[string]func(*coap.Message, coap.MessageInfo)
	sendErr       error
}

type mockSentRequest struct {
	Msg  *coap.Message
	Info coap.MessageInfo
	CB   func(*coap.Message, coap.MessageInfo, error)
}

type mockSentResponse struct {
	Code coap.Code
	Req  *coap.Message
	Info coap.MessageInfo
}

func newMockTransport() *mockTransport {
	return &mockTransport{
		handlers: make(map[string]func(*coap.Message, coap.MessageInfo)),
	}
}

func (m *mockTransport) SendRequest(msg *coap.Message, info coap.MessageInfo, cb func(*coap.Message, coap.MessageInfo, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentRequests = append(m.sentRequests, mockSentRequest{Msg: msg, Info: info, CB: cb})
	return m.sendErr
}

func (m *mockTransport) SendResponse(code coap.Code, req *coap.Message, info coap.MessageInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentResponses = append(m.sentResponses, mockSentResponse{Code: code, Req: req, Info: info})
	return nil
}

func (m *mockTransport) RegisterHandler(uriPath string, handler func(*coap.Message, coap.MessageInfo)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[uriPath] = handler
}

func (m *mockTransport) UnregisterHandler(uriPath string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.handlers, uriPath)
}

func (m *mockTransport) requestCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sentRequests)
}

func (m *mockTransport) lastRequest() mockSentRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sentRequests[len(m.sentRequests)-1]
}

func (m *mockTransport) getRequest(i int) mockSentRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sentRequests[i]
}

func (m *mockTransport) responseCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sentResponses)
}

func (m *mockTransport) lastResponse() mockSentResponse {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sentResponses[len(m.sentResponses)-1]
}

func (m *mockTransport) hasHandler(uriPath string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.handlers[uriPath]
	return ok
}

func (m *mockTransport) getHandler(uriPath string) func(*coap.Message, coap.MessageInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.handlers[uriPath]
}

// ---------------------------------------------------------------------------
// Mock addressing
// ---------------------------------------------------------------------------

type mockAddressing struct {
	meshLocalPrefix ip6.NetworkPrefix
	rloc16          uint16
	leaderRLOC16    uint16
	isAttached      bool
}

func newMockAddressing() *mockAddressing {
	return &mockAddressing{
		meshLocalPrefix: ip6.NetworkPrefix{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		rloc16:          0x0400,
		leaderRLOC16:    0x0000,
		isAttached:      true,
	}
}

func (m *mockAddressing) MeshLocalPrefix() ip6.NetworkPrefix { return m.meshLocalPrefix }
func (m *mockAddressing) RLOC16() uint16                     { return m.rloc16 }
func (m *mockAddressing) LeaderRLOC16() uint16               { return m.leaderRLOC16 }
func (m *mockAddressing) IsAttached() bool                   { return m.isAttached }

// ---------------------------------------------------------------------------
// Test helper: build petition-accept response
// ---------------------------------------------------------------------------

func buildPetitionAcceptResponse(sessionID uint16) *coap.Message {
	var payload []byte
	payload = append(payload, encodeTLV(TLVState, []byte{StateAccept})...)
	sidBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sidBytes, sessionID)
	payload = append(payload, encodeTLV(TLVCommissionerSessionID, sidBytes)...)

	msg := coap.NewMessage(coap.TypeAck, coap.CodeChanged, 1)
	_ = msg.SetToken([]byte{0x01, 0x02, 0x03, 0x04})
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)
	return msg
}

func buildPetitionRejectResponse() *coap.Message {
	var payload []byte
	payload = append(payload, encodeTLV(TLVState, []byte{StateReject})...)
	sidBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sidBytes, 0)
	payload = append(payload, encodeTLV(TLVCommissionerSessionID, sidBytes)...)

	msg := coap.NewMessage(coap.TypeAck, coap.CodeChanged, 1)
	_ = msg.SetToken([]byte{0x01, 0x02, 0x03, 0x04})
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)
	return msg
}

func buildKeepAliveAcceptResponse() *coap.Message {
	payload := encodeTLV(TLVState, []byte{StateAccept})
	msg := coap.NewMessage(coap.TypeAck, coap.CodeChanged, 2)
	_ = msg.SetToken([]byte{0x01, 0x02, 0x03, 0x04})
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)
	return msg
}

func buildKeepAliveRejectResponse() *coap.Message {
	payload := encodeTLV(TLVState, []byte{StateReject})
	msg := coap.NewMessage(coap.TypeAck, coap.CodeChanged, 2)
	_ = msg.SetToken([]byte{0x01, 0x02, 0x03, 0x04})
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)
	return msg
}

// petitionAndActivate starts a commissioner, then manually drives the
// petition to Active state. Injected afterFunc captures timer funcs for
// deterministic testing. The first captured func is the keep-alive timer.
func petitionAndActivate(t *testing.T, c *Commissioner, tr *mockTransport) {
	t.Helper()
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Manually deliver the petition accept response.
	req := tr.lastRequest()
	resp := buildPetitionAcceptResponse(0x1234)
	req.CB(resp, req.Info, nil)
	if c.GetState() != CommissionerActive {
		t.Fatalf("expected Active, got %v", c.GetState())
	}
}

// createActiveCommissioner creates a commissioner in the Active state.
// Uses manual petition callback delivery (no goroutines) so state is
// deterministic after return.
func createActiveCommissioner(t *testing.T) (*Commissioner, *mockTransport, *mockAddressing) {
	t.Helper()
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)
	// Replace afterFunc so keep-alive timers don't fire in background.
	c.afterFunc = func(d time.Duration, f func()) *time.Timer {
		return time.NewTimer(time.Hour) // dummy, won't fire
	}
	petitionAndActivate(t, c, tr)
	return c, tr, addr
}

// ---------------------------------------------------------------------------
// Tests: NewCommissioner defaults
// ---------------------------------------------------------------------------

func TestNewCommissioner_Defaults(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)

	if c.GetState() != CommissionerDisabled {
		t.Fatalf("expected Disabled, got %v", c.GetState())
	}
	if c.GetID() != DefaultCommissionerID {
		t.Fatalf("expected %q, got %q", DefaultCommissionerID, c.GetID())
	}
	if !c.IsDisabled() {
		t.Fatal("expected IsDisabled")
	}
	if c.IsActive() {
		t.Fatal("expected not IsActive")
	}
	if c.GetSessionID() != 0 {
		t.Fatalf("expected sessionID=0, got %d", c.GetSessionID())
	}
	if c.GetProvisioningURL() != "" {
		t.Fatalf("expected empty provisioning URL, got %q", c.GetProvisioningURL())
	}
	if c.JoinerCount() != 0 {
		t.Fatalf("expected 0 joiners, got %d", c.JoinerCount())
	}
}

// ---------------------------------------------------------------------------
// Tests: SetID
// ---------------------------------------------------------------------------

func TestSetID_WhileDisabled(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)

	if err := c.SetID("MyCommissioner"); err != nil {
		t.Fatalf("SetID: %v", err)
	}
	if c.GetID() != "MyCommissioner" {
		t.Fatalf("expected MyCommissioner, got %q", c.GetID())
	}
}

func TestSetID_EmptyString(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)

	if err := c.SetID(""); err != goterrors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs, got %v", err)
	}
}

func TestSetID_TooLong(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)

	long := make([]byte, MaxCommissionerIDLength+1)
	for i := range long {
		long[i] = 'a'
	}
	if err := c.SetID(string(long)); err != goterrors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs, got %v", err)
	}
}

func TestSetID_WhileActive(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)
	if err := c.SetID("NewID"); err != goterrors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests: SetProvisioningURL
// ---------------------------------------------------------------------------

func TestSetProvisioningURL_WhileDisabled(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)

	if err := c.SetProvisioningURL("http://example.com"); err != nil {
		t.Fatalf("SetProvisioningURL: %v", err)
	}
	if c.GetProvisioningURL() != "http://example.com" {
		t.Fatalf("expected http://example.com, got %q", c.GetProvisioningURL())
	}
}

func TestSetProvisioningURL_TooLong(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)

	long := make([]byte, MaxProvisioningURLLength+1)
	for i := range long {
		long[i] = 'a'
	}
	if err := c.SetProvisioningURL(string(long)); err != goterrors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs, got %v", err)
	}
}

func TestSetProvisioningURL_WhileActive(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)
	if err := c.SetProvisioningURL("foo"); err != goterrors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests: Start
// ---------------------------------------------------------------------------

func TestStart_NotAttached(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	addr.isAttached = false
	c := NewCommissioner(tr, addr, nil, nil)

	if err := c.Start(); err != goterrors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
}

func TestStart_AlreadyStarted(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)
	if err := c.Start(); err != goterrors.ErrAlready {
		t.Fatalf("expected ErrAlready, got %v", err)
	}
}

func TestStart_SendsPetition(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)

	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if c.GetState() != CommissionerPetition {
		t.Fatalf("expected Petition state, got %v", c.GetState())
	}

	if tr.requestCount() != 1 {
		t.Fatalf("expected 1 request, got %d", tr.requestCount())
	}

	// Verify the petition payload contains CommissionerID TLV.
	req := tr.lastRequest()
	payload := req.Msg.GetPayload()
	idTLV := findTLVInBytes(payload, TLVCommissionerID)
	if idTLV == nil {
		t.Fatal("expected CommissionerID TLV in petition")
	}
	if string(idTLV) != DefaultCommissionerID {
		t.Fatalf("expected %q, got %q", DefaultCommissionerID, string(idTLV))
	}
}

// ---------------------------------------------------------------------------
// Tests: Petition flow
// ---------------------------------------------------------------------------

func TestPetition_Accepted(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()

	var states []CommissionerState
	c := NewCommissioner(tr, addr, func(s CommissionerState) {
		states = append(states, s)
	}, nil)
	// Prevent real timers from firing.
	c.afterFunc = func(d time.Duration, f func()) *time.Timer {
		return time.NewTimer(time.Hour)
	}

	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Simulate the leader accepting the petition.
	req := tr.lastRequest()
	resp := buildPetitionAcceptResponse(0xABCD)
	req.CB(resp, req.Info, nil)

	if c.GetState() != CommissionerActive {
		t.Fatalf("expected Active, got %v", c.GetState())
	}
	if c.GetSessionID() != 0xABCD {
		t.Fatalf("expected sessionID=0xABCD, got 0x%04X", c.GetSessionID())
	}
	// State transitions: Disabled→Petition, Petition→Active
	if len(states) != 2 || states[0] != CommissionerPetition || states[1] != CommissionerActive {
		t.Fatalf("unexpected state transitions: %v", states)
	}
}

func TestPetition_Rejected(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()

	var states []CommissionerState
	c := NewCommissioner(tr, addr, func(s CommissionerState) {
		states = append(states, s)
	}, nil)

	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	req := tr.lastRequest()
	resp := buildPetitionRejectResponse()
	req.CB(resp, req.Info, nil)

	if c.GetState() != CommissionerDisabled {
		t.Fatalf("expected Disabled, got %v", c.GetState())
	}
	// Petition→Disabled after reject
	if len(states) < 2 || states[len(states)-1] != CommissionerDisabled {
		t.Fatalf("unexpected state transitions: %v", states)
	}
}

func TestPetition_ErrorRetries(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()

	// Use synchronous afterFunc to capture timer funcs.
	var timerFuncs []func()
	c := NewCommissioner(tr, addr, nil, nil)
	c.afterFunc = func(d time.Duration, f func()) *time.Timer {
		timerFuncs = append(timerFuncs, f)
		return time.NewTimer(time.Hour)
	}

	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// First attempt fails with error.
	req := tr.getRequest(0)
	req.CB(nil, req.Info, goterrors.ErrFailed)

	// A retry timer should have been scheduled.
	if len(timerFuncs) != 1 {
		t.Fatalf("expected 1 timer func, got %d", len(timerFuncs))
	}

	// Fire the retry timer.
	timerFuncs[0]()

	// Second attempt also fails.
	if tr.requestCount() < 2 {
		t.Fatalf("expected at least 2 requests, got %d", tr.requestCount())
	}
	req = tr.getRequest(1)
	req.CB(nil, req.Info, goterrors.ErrFailed)

	// After petitionRetryCount attempts, should go Disabled.
	if c.GetState() != CommissionerDisabled {
		t.Fatalf("expected Disabled after retries, got %v", c.GetState())
	}
}

func TestPetition_SendFailureRetries(t *testing.T) {
	tr := newMockTransport()
	tr.sendErr = goterrors.ErrFailed
	c := NewCommissioner(tr, newMockAddressing(), nil, nil)
	var retry func()
	c.afterFunc = func(d time.Duration, f func()) *time.Timer {
		retry = f
		timer := time.NewTimer(time.Hour)
		t.Cleanup(func() { timer.Stop() })
		return timer
	}

	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if c.GetState() != CommissionerPetition || retry == nil {
		t.Fatal("failed petition send should schedule a retry")
	}
	retry()
	if c.GetState() != CommissionerDisabled {
		t.Fatalf("expected Disabled after failed sends, got %v", c.GetState())
	}
	if tr.requestCount() != petitionRetryCount {
		t.Fatalf("expected %d attempts, got %d", petitionRetryCount, tr.requestCount())
	}
}

func TestKeepAlive_SendFailureDisablesCommissioner(t *testing.T) {
	c, tr, _ := createActiveCommissioner(t)
	t.Cleanup(func() { c.stop(false) })
	if err := c.AddJoinerAny("J01NME", time.Minute); err != nil {
		t.Fatalf("AddJoinerAny: %v", err)
	}
	tr.sendErr = goterrors.ErrFailed
	c.mu.Lock()
	c.sendKeepAliveLocked(c.sessionID, StateAccept)
	c.mu.Unlock()

	if c.GetState() != CommissionerDisabled {
		t.Fatalf("expected Disabled after failed keep-alive send, got %v", c.GetState())
	}
	for _, joiner := range c.joiners {
		if joiner.Type != JoinerTypeUnused {
			t.Fatal("failed keep-alive send should clear joiners")
		}
	}
	if c.commissionerTimer != nil {
		t.Fatal("failed keep-alive send should stop the commissioner timer")
	}
}

func TestPetition_NilResponse(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()

	var timerFuncs []func()
	c := NewCommissioner(tr, addr, nil, nil)
	c.afterFunc = func(d time.Duration, f func()) *time.Timer {
		timerFuncs = append(timerFuncs, f)
		return time.NewTimer(time.Hour)
	}

	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	req := tr.getRequest(0)
	req.CB(nil, req.Info, nil) // nil response, no error

	// Should schedule retry.
	if len(timerFuncs) != 1 {
		t.Fatalf("expected 1 timer func, got %d", len(timerFuncs))
	}
}

func TestPetition_WrongResponseCode(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()

	var timerFuncs []func()
	c := NewCommissioner(tr, addr, nil, nil)
	c.afterFunc = func(d time.Duration, f func()) *time.Timer {
		timerFuncs = append(timerFuncs, f)
		return time.NewTimer(time.Hour)
	}

	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Respond with wrong code.
	resp := coap.NewMessage(coap.TypeAck, coap.CodeContent, 1)
	req := tr.getRequest(0)
	req.CB(resp, req.Info, nil)

	// Should schedule retry.
	if len(timerFuncs) != 1 {
		t.Fatalf("expected 1 timer func, got %d", len(timerFuncs))
	}
}

func TestPetition_ResponseAfterStop(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)

	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	req := tr.getRequest(0)

	// Stop before response arrives.
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// Late response should be ignored.
	resp := buildPetitionAcceptResponse(0x5678)
	req.CB(resp, req.Info, nil)

	if c.GetState() != CommissionerDisabled {
		t.Fatalf("expected Disabled after Stop, got %v", c.GetState())
	}
}

// ---------------------------------------------------------------------------
// Tests: Stop
// ---------------------------------------------------------------------------

func TestStop_WhenDisabled(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)

	if err := c.Stop(); err != goterrors.ErrAlready {
		t.Fatalf("expected ErrAlready, got %v", err)
	}
}

func TestStop_WhenActive_SendsResignKeepAlive(t *testing.T) {
	c, tr, _ := createActiveCommissioner(t)
	initialCount := tr.requestCount()

	var states []CommissionerState
	c.stateCallback = func(s CommissionerState) {
		states = append(states, s)
	}

	if err := c.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if c.GetState() != CommissionerDisabled {
		t.Fatalf("expected Disabled, got %v", c.GetState())
	}

	// Should have sent a keep-alive with Reject state.
	if tr.requestCount() <= initialCount {
		t.Fatal("expected resign keep-alive to be sent")
	}

	// Verify the resign payload contains State=Reject.
	lastReq := tr.lastRequest()
	payload := lastReq.Msg.GetPayload()
	stateTLV := findTLVInBytes(payload, TLVState)
	if len(stateTLV) == 0 || stateTLV[0] != StateReject {
		t.Fatalf("expected State=Reject in resign keep-alive")
	}
}

func TestStop_WhenPetitioning(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)

	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if c.GetState() != CommissionerPetition {
		t.Fatalf("expected Petition, got %v", c.GetState())
	}

	initialCount := tr.requestCount()
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if c.GetState() != CommissionerDisabled {
		t.Fatalf("expected Disabled, got %v", c.GetState())
	}

	// Should NOT send resign keep-alive when not Active.
	if tr.requestCount() != initialCount {
		t.Fatal("should not send resign keep-alive when petitioning")
	}
}

// ---------------------------------------------------------------------------
// Tests: Keep-alive flow
// ---------------------------------------------------------------------------

func TestKeepAlive_AcceptedAfterPetition(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()

	var timerFuncs []func()
	c := NewCommissioner(tr, addr, nil, nil)
	c.afterFunc = func(d time.Duration, f func()) *time.Timer {
		timerFuncs = append(timerFuncs, f)
		return time.NewTimer(time.Hour)
	}

	petitionAndActivate(t, c, tr)

	// The petition accept triggers startKeepAliveTimer, so we should have
	// a timer func captured.
	if len(timerFuncs) == 0 {
		t.Fatal("keep-alive timer was not scheduled")
	}
	kaTimerFunc := timerFuncs[len(timerFuncs)-1]

	// Fire the keep-alive timer.
	kaTimerFunc()

	// Verify keep-alive was sent.
	lastReq := tr.lastRequest()
	payload := lastReq.Msg.GetPayload()
	stateTLV := findTLVInBytes(payload, TLVState)
	if len(stateTLV) == 0 || stateTLV[0] != StateAccept {
		t.Fatal("expected State=Accept in keep-alive")
	}
	sessionTLV := findTLVInBytes(payload, TLVCommissionerSessionID)
	if sessionTLV == nil || binary.BigEndian.Uint16(sessionTLV) != 0x1234 {
		t.Fatal("expected SessionID=0x1234 in keep-alive")
	}

	// Respond with Accept — should stay Active.
	resp := buildKeepAliveAcceptResponse()
	lastReq.CB(resp, lastReq.Info, nil)

	if c.GetState() != CommissionerActive {
		t.Fatalf("expected Active after keep-alive accept, got %v", c.GetState())
	}
}

func TestKeepAlive_Rejected(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()

	var timerFuncs []func()
	c := NewCommissioner(tr, addr, nil, nil)
	c.afterFunc = func(d time.Duration, f func()) *time.Timer {
		timerFuncs = append(timerFuncs, f)
		return time.NewTimer(time.Hour)
	}

	petitionAndActivate(t, c, tr)

	// Fire keep-alive timer.
	kaTimerFunc := timerFuncs[len(timerFuncs)-1]
	kaTimerFunc()

	// Respond with Reject.
	lastReq := tr.lastRequest()
	resp := buildKeepAliveRejectResponse()
	lastReq.CB(resp, lastReq.Info, nil)

	if c.GetState() != CommissionerDisabled {
		t.Fatalf("expected Disabled after keep-alive reject, got %v", c.GetState())
	}
}

func TestKeepAlive_Error(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()

	var timerFuncs []func()
	c := NewCommissioner(tr, addr, nil, nil)
	c.afterFunc = func(d time.Duration, f func()) *time.Timer {
		timerFuncs = append(timerFuncs, f)
		return time.NewTimer(time.Hour)
	}

	petitionAndActivate(t, c, tr)

	// Fire keep-alive timer.
	kaTimerFunc := timerFuncs[len(timerFuncs)-1]
	kaTimerFunc()

	// Respond with error.
	lastReq := tr.lastRequest()
	lastReq.CB(nil, lastReq.Info, goterrors.ErrFailed)

	if c.GetState() != CommissionerDisabled {
		t.Fatalf("expected Disabled after keep-alive error, got %v", c.GetState())
	}
}

// ---------------------------------------------------------------------------
// Tests: Joiner management
// ---------------------------------------------------------------------------

func TestAddJoiner_NotActive(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)

	if err := c.AddJoinerAny("PSKD1234", time.Minute); err != goterrors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
}

func TestAddJoiner_EmptyPSKd(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)
	if err := c.AddJoinerAny("", time.Minute); err != goterrors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs, got %v", err)
	}
}

func TestAddJoiner_PSKdTooLong(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)
	long := make([]byte, MaxJoinerPSKdLength+1)
	for i := range long {
		long[i] = 'A'
	}
	if err := c.AddJoinerAny(string(long), time.Minute); err != goterrors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs, got %v", err)
	}
}

func TestAddJoinerAny(t *testing.T) {
	c, tr, _ := createActiveCommissioner(t)
	initialReqCount := tr.requestCount()

	if err := c.AddJoinerAny("PSKD1234", time.Minute); err != nil {
		t.Fatalf("AddJoinerAny: %v", err)
	}

	if c.JoinerCount() != 1 {
		t.Fatalf("expected 1 joiner, got %d", c.JoinerCount())
	}

	joiners := c.GetJoiners()
	if len(joiners) != 1 {
		t.Fatalf("expected 1 joiner info, got %d", len(joiners))
	}
	if joiners[0].Type != JoinerTypeAny {
		t.Fatalf("expected JoinerTypeAny, got %v", joiners[0].Type)
	}
	if joiners[0].PSKd != "PSKD1234" {
		t.Fatalf("expected PSKD1234, got %q", joiners[0].PSKd)
	}

	// Should have sent commissioner set.
	if tr.requestCount() <= initialReqCount {
		t.Fatal("expected commissioner set to be sent")
	}
}

func TestAddJoinerEUI64(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)

	eui64 := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if err := c.AddJoinerEUI64(eui64, "MYPSKD", time.Minute); err != nil {
		t.Fatalf("AddJoinerEUI64: %v", err)
	}

	joiners := c.GetJoiners()
	if len(joiners) != 1 || joiners[0].Type != JoinerTypeEUI64 {
		t.Fatalf("unexpected joiners: %v", joiners)
	}
	if joiners[0].EUI64 != eui64 {
		t.Fatalf("expected EUI64=%v, got %v", eui64, joiners[0].EUI64)
	}
}

func TestAddJoinerDiscerner(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)

	disc := JoinerDiscerner{Value: 0xDEAD, BitLength: 16}
	if err := c.AddJoinerDiscerner(disc, "DISC_PSK", time.Minute); err != nil {
		t.Fatalf("AddJoinerDiscerner: %v", err)
	}

	joiners := c.GetJoiners()
	if len(joiners) != 1 || joiners[0].Type != JoinerTypeDiscerner {
		t.Fatalf("unexpected joiners: %v", joiners)
	}
	if joiners[0].Discerner != disc {
		t.Fatalf("expected discerner=%v, got %v", disc, joiners[0].Discerner)
	}
}

func TestAddJoiner_UpdateExisting(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)

	if err := c.AddJoinerAny("PSK1", time.Minute); err != nil {
		t.Fatalf("AddJoinerAny: %v", err)
	}

	// Add again with a different PSKd — should update, not add a second entry.
	if err := c.AddJoinerAny("PSK2", 2*time.Minute); err != nil {
		t.Fatalf("AddJoinerAny: %v", err)
	}

	if c.JoinerCount() != 1 {
		t.Fatalf("expected 1 joiner after update, got %d", c.JoinerCount())
	}
	joiners := c.GetJoiners()
	if joiners[0].PSKd != "PSK2" {
		t.Fatalf("expected PSK2, got %q", joiners[0].PSKd)
	}
}

func TestAddJoiner_TableFull(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)

	for i := 0; i < MaxJoinerEntries; i++ {
		eui := types.ExtAddress{byte(i + 1)}
		if err := c.AddJoinerEUI64(eui, "PSK", time.Minute); err != nil {
			t.Fatalf("AddJoinerEUI64[%d]: %v", i, err)
		}
	}

	if c.JoinerCount() != MaxJoinerEntries {
		t.Fatalf("expected %d joiners, got %d", MaxJoinerEntries, c.JoinerCount())
	}

	// One more should fail.
	extra := types.ExtAddress{0xFF}
	if err := c.AddJoinerEUI64(extra, "PSK", time.Minute); err != goterrors.ErrNoBufs {
		t.Fatalf("expected ErrNoBufs, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests: Remove joiners
// ---------------------------------------------------------------------------

func TestRemoveJoinerAny(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)
	_ = c.AddJoinerAny("PSK", time.Minute)

	if err := c.RemoveJoinerAny(0); err != nil {
		t.Fatalf("RemoveJoinerAny: %v", err)
	}
	if c.JoinerCount() != 0 {
		t.Fatalf("expected 0 joiners, got %d", c.JoinerCount())
	}
}

func TestRemoveJoinerEUI64(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)
	eui := types.ExtAddress{0x11, 0x22}
	_ = c.AddJoinerEUI64(eui, "PSK", time.Minute)

	if err := c.RemoveJoinerEUI64(eui, 0); err != nil {
		t.Fatalf("RemoveJoinerEUI64: %v", err)
	}
	if c.JoinerCount() != 0 {
		t.Fatalf("expected 0 joiners, got %d", c.JoinerCount())
	}
}

func TestRemoveJoiner_NotFound(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)
	if err := c.RemoveJoinerAny(0); err != goterrors.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestRemoveJoiner_NotActive(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)

	if err := c.RemoveJoinerAny(0); err != goterrors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
}

func TestRemoveJoiner_WithDelay(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)
	_ = c.AddJoinerAny("PSK", time.Hour)

	// Remove with 5-minute delay — entry stays but expiration is updated.
	if err := c.RemoveJoinerAny(5 * time.Minute); err != nil {
		t.Fatalf("RemoveJoinerAny with delay: %v", err)
	}

	// Entry should still exist.
	if c.JoinerCount() != 1 {
		t.Fatalf("expected 1 joiner (delayed removal), got %d", c.JoinerCount())
	}
}

func TestRemoveJoiner_WithCallback(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()

	var events []JoinerEvent
	c := NewCommissioner(tr, addr, nil, func(event JoinerEvent, info *JoinerInfo) {
		events = append(events, event)
	})
	c.afterFunc = func(d time.Duration, f func()) *time.Timer {
		return time.NewTimer(time.Hour)
	}
	petitionAndActivate(t, c, tr)

	_ = c.AddJoinerAny("PSK", time.Minute)
	_ = c.RemoveJoinerAny(0)

	// Should have signaled JoinerEventRemoved.
	found := false
	for _, e := range events {
		if e == JoinerEventRemoved {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected JoinerEventRemoved, events: %v", events)
	}
}

// ---------------------------------------------------------------------------
// Tests: ClearJoiners
// ---------------------------------------------------------------------------

func TestClearJoiners(t *testing.T) {
	c, tr, _ := createActiveCommissioner(t)
	_ = c.AddJoinerAny("PSK1", time.Minute)
	_ = c.AddJoinerEUI64(types.ExtAddress{0x01}, "PSK2", time.Minute)
	initialReqCount := tr.requestCount()

	c.ClearJoiners()

	if c.JoinerCount() != 0 {
		t.Fatalf("expected 0 joiners, got %d", c.JoinerCount())
	}

	// Should send commissioner set with empty steering data.
	if tr.requestCount() <= initialReqCount {
		t.Fatal("expected commissioner set after ClearJoiners")
	}
}

func TestClearJoiners_Callbacks(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()

	var removedCount int
	c := NewCommissioner(tr, addr, nil, func(event JoinerEvent, info *JoinerInfo) {
		if event == JoinerEventRemoved {
			removedCount++
		}
	})
	c.afterFunc = func(d time.Duration, f func()) *time.Timer {
		return time.NewTimer(time.Hour)
	}
	petitionAndActivate(t, c, tr)

	_ = c.AddJoinerAny("PSK1", time.Minute)
	_ = c.AddJoinerEUI64(types.ExtAddress{0x01}, "PSK2", time.Minute)
	removedCount = 0

	c.ClearJoiners()

	if removedCount != 2 {
		t.Fatalf("expected 2 JoinerEventRemoved callbacks, got %d", removedCount)
	}
}

// ---------------------------------------------------------------------------
// Tests: FindBestMatchingJoiner
// ---------------------------------------------------------------------------

func TestFindBestMatchingJoiner_ExactEUI64(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)

	eui := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	_ = c.AddJoinerAny("PSK_ANY", time.Minute)
	_ = c.AddJoinerEUI64(eui, "PSK_EUI", time.Minute)

	j := c.FindBestMatchingJoiner([8]byte(eui))
	if j == nil {
		t.Fatal("expected a match")
	}
	if j.Type != JoinerTypeEUI64 {
		t.Fatalf("expected EUI64 match, got %v", j.Type)
	}
	if j.PSKd != "PSK_EUI" {
		t.Fatalf("expected PSK_EUI, got %q", j.PSKd)
	}
}

func TestFindBestMatchingJoiner_AnyFallback(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)
	_ = c.AddJoinerAny("PSK_ANY", time.Minute)

	j := c.FindBestMatchingJoiner([8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11})
	if j == nil {
		t.Fatal("expected any match")
	}
	if j.Type != JoinerTypeAny {
		t.Fatalf("expected Any match, got %v", j.Type)
	}
}

func TestFindBestMatchingJoiner_DiscernerMatch(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)

	disc := JoinerDiscerner{Value: 0x42, BitLength: 8}
	_ = c.AddJoinerDiscerner(disc, "PSK_DISC", time.Minute)
	_ = c.AddJoinerAny("PSK_ANY", time.Minute)

	joinerID := [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42}
	j := c.FindBestMatchingJoiner(joinerID)
	if j == nil {
		t.Fatal("expected discerner match")
	}
	if j.Type != JoinerTypeDiscerner {
		t.Fatalf("expected Discerner match, got %v", j.Type)
	}
}

func TestFindBestMatchingJoiner_LongestDiscernerWins(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)

	disc8 := JoinerDiscerner{Value: 0x42, BitLength: 8}
	disc16 := JoinerDiscerner{Value: 0x0042, BitLength: 16}
	_ = c.AddJoinerDiscerner(disc8, "PSK_8", time.Minute)
	_ = c.AddJoinerDiscerner(disc16, "PSK_16", time.Minute)

	joinerID := [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42}
	j := c.FindBestMatchingJoiner(joinerID)
	if j == nil {
		t.Fatal("expected discerner match")
	}
	if j.PSKd != "PSK_16" {
		t.Fatalf("expected longest discerner (PSK_16), got %q", j.PSKd)
	}
}

func TestFindBestMatchingJoiner_NoMatch(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)

	eui := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	_ = c.AddJoinerEUI64(eui, "PSK_EUI", time.Minute)

	j := c.FindBestMatchingJoiner([8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	if j != nil {
		t.Fatal("expected no match")
	}
}

// ---------------------------------------------------------------------------
// Tests: ComputeBloomFilter
// ---------------------------------------------------------------------------

func TestComputeBloomFilter_NoJoiners(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)

	sd := c.ComputeBloomFilter()
	if !sd.IsEmpty() {
		t.Fatal("expected empty bloom filter with no joiners")
	}
}

func TestComputeBloomFilter_AnyJoiner(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)
	_ = c.AddJoinerAny("PSK", time.Minute)

	sd := c.ComputeBloomFilter()
	if !sd.PermitsAllJoiners() {
		t.Fatal("expected permit-all with Any joiner")
	}
}

func TestComputeBloomFilter_EUI64Joiner(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)
	eui := types.ExtAddress{0x18, 0xB4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x01}
	_ = c.AddJoinerEUI64(eui, "PSK", time.Minute)

	sd := c.ComputeBloomFilter()
	if sd.IsEmpty() {
		t.Fatal("expected non-empty bloom filter")
	}
	if sd.PermitsAllJoiners() {
		t.Fatal("expected non-permit-all bloom filter")
	}

	joinerID := computeJoinerID(eui)
	if !sd.Contains(joinerID) {
		t.Fatal("bloom filter should contain the joiner ID")
	}
}

// ---------------------------------------------------------------------------
// Tests: Commissioner Set
// ---------------------------------------------------------------------------

func TestCommissionerSet_PayloadContainsSessionIDAndSteeringData(t *testing.T) {
	c, tr, _ := createActiveCommissioner(t)

	beforeCount := tr.requestCount()
	_ = c.AddJoinerAny("PSK", time.Minute)

	if tr.requestCount() <= beforeCount {
		t.Fatal("expected commissioner set request")
	}

	req := tr.lastRequest()
	payload := req.Msg.GetPayload()

	sessionTLV := findTLVInBytes(payload, TLVCommissionerSessionID)
	if sessionTLV == nil {
		t.Fatal("expected CommissionerSessionID TLV in commissioner set")
	}

	sdTLV := findTLVInBytes(payload, TLVSteeringData)
	if sdTLV == nil {
		t.Fatal("expected SteeringData TLV in commissioner set")
	}
}

// ---------------------------------------------------------------------------
// Tests: Commissioner Get
// ---------------------------------------------------------------------------

func TestSendMgmtCommissionerGetRequest_NotActive(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)

	if err := c.SendMgmtCommissionerGetRequest(nil, nil); err != goterrors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
}

func TestSendMgmtCommissionerGetRequest_Success(t *testing.T) {
	c, tr, _ := createActiveCommissioner(t)
	beforeCount := tr.requestCount()

	var gotPayload []byte
	var gotErr error
	err := c.SendMgmtCommissionerGetRequest([]byte{byte(TLVSteeringData), byte(TLVCommissionerSessionID)},
		func(payload []byte, err error) {
			gotPayload = payload
			gotErr = err
		})
	if err != nil {
		t.Fatalf("SendMgmtCommissionerGetRequest: %v", err)
	}

	if tr.requestCount() <= beforeCount {
		t.Fatal("expected get request to be sent")
	}

	// Simulate response.
	lastReq := tr.lastRequest()
	resp := coap.NewMessage(coap.TypeAck, coap.CodeChanged, 3)
	_ = resp.SetToken([]byte{0x01, 0x02, 0x03, 0x04})
	respPayload := encodeTLV(TLVSteeringData, []byte{0xFF})
	_ = resp.AppendPayloadMarker()
	_ = resp.AppendPayload(respPayload)
	lastReq.CB(resp, lastReq.Info, nil)

	if gotErr != nil {
		t.Fatalf("unexpected error in callback: %v", gotErr)
	}
	if gotPayload == nil {
		t.Fatal("expected payload in callback")
	}
}

// ---------------------------------------------------------------------------
// Tests: RegisterHandlers / UnregisterHandlers
// ---------------------------------------------------------------------------

func TestRegisterHandlers(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)

	c.RegisterHandlers()

	if !tr.hasHandler("c/rx") {
		t.Fatal("expected c/rx handler")
	}
	if !tr.hasHandler("c/dc") {
		t.Fatal("expected c/dc handler")
	}
}

func TestUnregisterHandlers(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)

	c.RegisterHandlers()
	c.UnregisterHandlers()

	if tr.hasHandler("c/rx") {
		t.Fatal("expected c/rx handler to be removed")
	}
	if tr.hasHandler("c/dc") {
		t.Fatal("expected c/dc handler to be removed")
	}
}

// ---------------------------------------------------------------------------
// Tests: handleRelayRx
// ---------------------------------------------------------------------------

func buildRelayRxPayload(joinerPort uint16, joinerIID [8]byte, routerRLOC uint16, dtlsData []byte) []byte {
	var payload []byte
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, joinerPort)
	payload = append(payload, encodeTLV(TLVJoinerUDPPort, portBytes)...)
	payload = append(payload, encodeTLV(TLVJoinerIID, joinerIID[:])...)
	rlocBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(rlocBytes, routerRLOC)
	payload = append(payload, encodeTLV(TLVJoinerRouterLocator, rlocBytes)...)
	payload = append(payload, encodeTLV(TLVJoinerDTLSEncapsulation, dtlsData)...)
	return payload
}

func TestHandleRelayRx_MatchesJoiner(t *testing.T) {
	c, tr, _ := createActiveCommissioner(t)

	var events []JoinerEvent
	c.joinerCallback = func(event JoinerEvent, info *JoinerInfo) {
		events = append(events, event)
	}

	c.RegisterHandlers()
	handler := tr.getHandler("c/rx")

	eui := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	_ = c.AddJoinerEUI64(eui, "PSK", time.Minute)

	payload := buildRelayRxPayload(1234, [8]byte(eui), 0x0800, []byte{0xAA, 0xBB})
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 10)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)

	handler(msg, coap.MessageInfo{})

	foundStart := false
	for _, e := range events {
		if e == JoinerEventStart {
			foundStart = true
		}
	}
	if !foundStart {
		t.Fatalf("expected JoinerEventStart, events: %v", events)
	}
}

func TestHandleRelayRx_NoMatch(t *testing.T) {
	c, tr, _ := createActiveCommissioner(t)

	var events []JoinerEvent
	c.joinerCallback = func(event JoinerEvent, info *JoinerInfo) {
		events = append(events, event)
	}

	c.RegisterHandlers()
	handler := tr.getHandler("c/rx")

	payload := buildRelayRxPayload(1234, [8]byte{0xAA}, 0x0800, []byte{0xCC})
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 10)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)

	handler(msg, coap.MessageInfo{})

	if len(events) != 0 {
		t.Fatalf("expected no events, got %v", events)
	}
}

func TestHandleRelayRx_MissingTLV(t *testing.T) {
	c, tr, _ := createActiveCommissioner(t)

	c.RegisterHandlers()
	handler := tr.getHandler("c/rx")

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 1234)
	payload := encodeTLV(TLVJoinerUDPPort, portBytes)
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 10)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)

	// Should not panic.
	handler(msg, coap.MessageInfo{})
}

func TestHandleRelayRx_NotActive(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()

	var events []JoinerEvent
	c := NewCommissioner(tr, addr, nil, func(event JoinerEvent, info *JoinerInfo) {
		events = append(events, event)
	})

	c.RegisterHandlers()
	handler := tr.getHandler("c/rx")

	payload := buildRelayRxPayload(1234, [8]byte{0xAA}, 0x0800, []byte{0xCC})
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 10)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)

	handler(msg, coap.MessageInfo{})

	if len(events) != 0 {
		t.Fatalf("expected no events when not active, got %v", events)
	}
}

// ---------------------------------------------------------------------------
// Tests: handleDatasetChanged
// ---------------------------------------------------------------------------

func TestHandleDatasetChanged_ACKsConfirmable(t *testing.T) {
	c, tr, _ := createActiveCommissioner(t)

	c.RegisterHandlers()
	handler := tr.getHandler("c/dc")

	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 20)
	handler(msg, coap.MessageInfo{PeerPort: 61631})

	if tr.responseCount() != 1 {
		t.Fatalf("expected 1 response (ACK), got %d", tr.responseCount())
	}
	resp := tr.lastResponse()
	if resp.Code != coap.CodeChanged {
		t.Fatalf("expected CodeChanged in ACK, got %v", resp.Code)
	}
}

func TestHandleDatasetChanged_IgnoresNonConfirmable(t *testing.T) {
	c, tr, _ := createActiveCommissioner(t)

	c.RegisterHandlers()
	handler := tr.getHandler("c/dc")

	msg := coap.NewMessage(coap.TypeNonConfirmable, coap.CodePost, 20)
	handler(msg, coap.MessageInfo{})

	if tr.responseCount() != 0 {
		t.Fatalf("expected 0 responses for non-confirmable, got %d", tr.responseCount())
	}
}

func TestHandleDatasetChanged_NotActive(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)

	c.RegisterHandlers()
	handler := tr.getHandler("c/dc")

	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 20)
	handler(msg, coap.MessageInfo{})

	if tr.responseCount() != 0 {
		t.Fatalf("expected 0 responses when not active, got %d", tr.responseCount())
	}
}

// ---------------------------------------------------------------------------
// Tests: HandleJoinerFinalize
// ---------------------------------------------------------------------------

func TestHandleJoinerFinalize_Accept(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)

	var events []JoinerEvent
	c.joinerCallback = func(event JoinerEvent, info *JoinerInfo) {
		events = append(events, event)
	}

	result := c.HandleJoinerFinalize(nil)
	if result != StateAccept {
		t.Fatalf("expected StateAccept, got 0x%02X", result)
	}

	foundFinalize := false
	for _, e := range events {
		if e == JoinerEventFinalize {
			foundFinalize = true
		}
	}
	if !foundFinalize {
		t.Fatalf("expected JoinerEventFinalize, events: %v", events)
	}
}

func TestHandleJoinerFinalize_RejectsWrongProvisioningURL(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)

	_ = c.SetProvisioningURL("http://correct.url")

	c.afterFunc = func(d time.Duration, f func()) *time.Timer {
		return time.NewTimer(time.Hour)
	}
	petitionAndActivate(t, c, tr)

	payload := encodeTLV(TLVProvisioningURL, []byte("http://wrong.url"))
	result := c.HandleJoinerFinalize(payload)
	if result != StateReject {
		t.Fatalf("expected StateReject, got 0x%02X", result)
	}
}

func TestHandleJoinerFinalize_AcceptsMatchingProvisioningURL(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)

	_ = c.SetProvisioningURL("http://my.device")

	c.afterFunc = func(d time.Duration, f func()) *time.Timer {
		return time.NewTimer(time.Hour)
	}
	petitionAndActivate(t, c, tr)

	payload := encodeTLV(TLVProvisioningURL, []byte("http://my.device"))
	result := c.HandleJoinerFinalize(payload)
	if result != StateAccept {
		t.Fatalf("expected StateAccept, got 0x%02X", result)
	}
}

func TestHandleJoinerFinalize_NotActive(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	c := NewCommissioner(tr, addr, nil, nil)

	result := c.HandleJoinerFinalize(nil)
	if result != StateReject {
		t.Fatalf("expected StateReject when not active, got 0x%02X", result)
	}
}

func TestHandleJoinerFinalize_SchedulesDelayedRemoval(t *testing.T) {
	c, tr, _ := createActiveCommissioner(t)

	var scheduledFuncs []func()
	c.afterFunc = func(d time.Duration, f func()) *time.Timer {
		scheduledFuncs = append(scheduledFuncs, f)
		return time.NewTimer(time.Hour)
	}

	eui := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	_ = c.AddJoinerEUI64(eui, "PSK", time.Minute)

	c.RegisterHandlers()
	handler := tr.getHandler("c/rx")

	payload := buildRelayRxPayload(1234, [8]byte(eui), 0x0800, []byte{0xAA})
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 10)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)
	handler(msg, coap.MessageInfo{})

	// Now finalize.
	scheduledFuncs = nil
	result := c.HandleJoinerFinalize(nil)
	if result != StateAccept {
		t.Fatalf("expected StateAccept, got 0x%02X", result)
	}

	if len(scheduledFuncs) == 0 {
		t.Fatal("expected delayed removal to be scheduled")
	}

	// Fire the delayed removal.
	scheduledFuncs[0]()

	found := false
	for _, j := range c.GetJoiners() {
		if j.Type == JoinerTypeEUI64 && j.EUI64 == eui {
			found = true
		}
	}
	if found {
		t.Fatal("expected EUI64 joiner to be removed after delayed removal")
	}
}

// ---------------------------------------------------------------------------
// Tests: Joiner expiration
// ---------------------------------------------------------------------------

func TestJoinerExpiration(t *testing.T) {
	c, _, _ := createActiveCommissioner(t)

	now := time.Now()
	c.nowFunc = func() time.Time { return now }

	var scheduledFuncs []func()
	c.afterFunc = func(d time.Duration, f func()) *time.Timer {
		scheduledFuncs = append(scheduledFuncs, f)
		return time.NewTimer(time.Hour)
	}

	var removedCount int
	c.joinerCallback = func(event JoinerEvent, info *JoinerInfo) {
		if event == JoinerEventRemoved {
			removedCount++
		}
	}

	_ = c.AddJoinerAny("PSK", 1*time.Second)
	if c.JoinerCount() != 1 {
		t.Fatalf("expected 1 joiner, got %d", c.JoinerCount())
	}

	// Advance time past expiration.
	now = now.Add(2 * time.Second)

	if len(scheduledFuncs) == 0 {
		t.Fatal("expected expiration timer to be scheduled")
	}
	scheduledFuncs[len(scheduledFuncs)-1]()

	if c.JoinerCount() != 0 {
		t.Fatalf("expected 0 joiners after expiration, got %d", c.JoinerCount())
	}
	if removedCount != 1 {
		t.Fatalf("expected 1 JoinerEventRemoved, got %d", removedCount)
	}
}

// ---------------------------------------------------------------------------
// Tests: Joiner session timeout
// ---------------------------------------------------------------------------

func TestJoinerSessionTimeout(t *testing.T) {
	c, tr, _ := createActiveCommissioner(t)

	var scheduledFuncs []func()
	c.afterFunc = func(d time.Duration, f func()) *time.Timer {
		scheduledFuncs = append(scheduledFuncs, f)
		return time.NewTimer(time.Hour)
	}

	var events []JoinerEvent
	c.joinerCallback = func(event JoinerEvent, info *JoinerInfo) {
		events = append(events, event)
	}

	eui := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	_ = c.AddJoinerEUI64(eui, "PSK", time.Minute)

	c.RegisterHandlers()
	handler := tr.getHandler("c/rx")

	payload := buildRelayRxPayload(1234, [8]byte(eui), 0x0800, []byte{0xDD})
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 10)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)
	handler(msg, coap.MessageInfo{})

	if len(scheduledFuncs) == 0 {
		t.Fatal("expected session timer to be scheduled")
	}
	scheduledFuncs[len(scheduledFuncs)-1]()

	foundEnd := false
	for _, e := range events {
		if e == JoinerEventEnd {
			foundEnd = true
		}
	}
	if !foundEnd {
		t.Fatalf("expected JoinerEventEnd, events: %v", events)
	}
}

// ---------------------------------------------------------------------------
// Tests: TLV helper functions
// ---------------------------------------------------------------------------

func TestEncodeTLV(t *testing.T) {
	buf := encodeTLV(TLVState, []byte{StateAccept})
	if len(buf) != 3 {
		t.Fatalf("expected 3 bytes, got %d", len(buf))
	}
	if buf[0] != byte(TLVState) || buf[1] != 1 || buf[2] != StateAccept {
		t.Fatalf("unexpected encoded TLV: %v", buf)
	}
}

func TestFindTLVInBytes(t *testing.T) {
	var data []byte
	data = append(data, encodeTLV(TLVState, []byte{StateAccept})...)
	sidBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sidBytes, 0x1234)
	data = append(data, encodeTLV(TLVCommissionerSessionID, sidBytes)...)

	val := findTLVInBytes(data, TLVState)
	if len(val) != 1 || val[0] != StateAccept {
		t.Fatalf("expected StateAccept, got %v", val)
	}

	val = findTLVInBytes(data, TLVCommissionerSessionID)
	if len(val) != 2 {
		t.Fatalf("expected 2-byte session ID, got %v", val)
	}
	if binary.BigEndian.Uint16(val) != 0x1234 {
		t.Fatalf("expected 0x1234, got 0x%04X", binary.BigEndian.Uint16(val))
	}

	val = findTLVInBytes(data, TLVSteeringData)
	if val != nil {
		t.Fatalf("expected nil for missing TLV, got %v", val)
	}
}

func TestFindTLVInBytes_Truncated(t *testing.T) {
	data := []byte{byte(TLVState), 5}
	val := findTLVInBytes(data, TLVState)
	if val != nil {
		t.Fatalf("expected nil for truncated TLV, got %v", val)
	}
}

func TestFindTLVInBytes_EmptyData(t *testing.T) {
	val := findTLVInBytes(nil, TLVState)
	if val != nil {
		t.Fatalf("expected nil for empty data, got %v", val)
	}
}

// ---------------------------------------------------------------------------
// Tests: parsePetitionResponse
// ---------------------------------------------------------------------------

func TestParsePetitionResponse_Valid(t *testing.T) {
	var payload []byte
	payload = append(payload, encodeTLV(TLVState, []byte{StateAccept})...)
	sidBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sidBytes, 0xBEEF)
	payload = append(payload, encodeTLV(TLVCommissionerSessionID, sidBytes)...)

	state, sessionID, ok := parsePetitionResponse(payload)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if state != StateAccept {
		t.Fatalf("expected StateAccept, got 0x%02X", state)
	}
	if sessionID != 0xBEEF {
		t.Fatalf("expected 0xBEEF, got 0x%04X", sessionID)
	}
}

func TestParsePetitionResponse_MissingState(t *testing.T) {
	sidBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sidBytes, 0x1234)
	payload := encodeTLV(TLVCommissionerSessionID, sidBytes)

	_, _, ok := parsePetitionResponse(payload)
	if ok {
		t.Fatal("expected ok=false for missing State")
	}
}

func TestParsePetitionResponse_MissingSessionID(t *testing.T) {
	payload := encodeTLV(TLVState, []byte{StateAccept})

	_, _, ok := parsePetitionResponse(payload)
	if ok {
		t.Fatal("expected ok=false for missing SessionID")
	}
}

func TestParsePetitionResponse_EmptyPayload(t *testing.T) {
	_, _, ok := parsePetitionResponse(nil)
	if ok {
		t.Fatal("expected ok=false for empty payload")
	}
}

// ---------------------------------------------------------------------------
// Tests: discernerMatchesEUI64
// ---------------------------------------------------------------------------

func TestDiscernerMatchesEUI64(t *testing.T) {
	tests := []struct {
		name    string
		disc    JoinerDiscerner
		id      [8]byte
		matches bool
	}{
		{
			name:    "8-bit match",
			disc:    JoinerDiscerner{Value: 0x42, BitLength: 8},
			id:      [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42},
			matches: true,
		},
		{
			name:    "8-bit no match",
			disc:    JoinerDiscerner{Value: 0x42, BitLength: 8},
			id:      [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43},
			matches: false,
		},
		{
			name:    "16-bit match",
			disc:    JoinerDiscerner{Value: 0xBEEF, BitLength: 16},
			id:      [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF},
			matches: true,
		},
		{
			name:    "64-bit match",
			disc:    JoinerDiscerner{Value: 0x0102030405060708, BitLength: 64},
			id:      [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			matches: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := discernerMatchesEUI64(tc.disc, tc.id)
			if got != tc.matches {
				t.Fatalf("expected %v, got %v", tc.matches, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: computeJoinerID
// ---------------------------------------------------------------------------

func TestComputeJoinerID(t *testing.T) {
	eui := types.ExtAddress{0x18, 0xB4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x01}
	id := computeJoinerID(eui)
	expected := eui
	expected[0] ^= 0x02
	if id != [8]byte(expected) {
		t.Fatalf("expected %v, got %v", expected, id)
	}
}

// ---------------------------------------------------------------------------
// Tests: buildCONPost
// ---------------------------------------------------------------------------

func TestBuildCONPost(t *testing.T) {
	msg := buildCONPost("c/lp", []byte{0x01, 0x02})
	if msg.GetType() != coap.TypeConfirmable {
		t.Fatalf("expected Confirmable, got %v", msg.GetType())
	}
	if msg.GetCode() != coap.CodePost {
		t.Fatalf("expected POST, got %v", msg.GetCode())
	}
	payload := msg.GetPayload()
	if len(payload) != 2 || payload[0] != 0x01 || payload[1] != 0x02 {
		t.Fatalf("unexpected payload: %v", payload)
	}
}

func TestBuildCONPost_EmptyPayload(t *testing.T) {
	msg := buildCONPost("c/la", nil)
	if msg.GetType() != coap.TypeConfirmable {
		t.Fatalf("expected Confirmable, got %v", msg.GetType())
	}
	payload := msg.GetPayload()
	if len(payload) != 0 {
		t.Fatalf("expected empty payload, got %v", payload)
	}
}

// ---------------------------------------------------------------------------
// Tests: rlocAddr
// ---------------------------------------------------------------------------

func TestRlocAddr(t *testing.T) {
	prefix := ip6.NetworkPrefix{0xfd, 0x00, 0xab, 0xcd, 0x00, 0x00, 0x00, 0x00}
	addr := rlocAddr(prefix, 0x0400)

	for i := 0; i < 8; i++ {
		if addr[i] != prefix[i] {
			t.Fatalf("prefix byte %d: expected 0x%02X, got 0x%02X", i, prefix[i], addr[i])
		}
	}

	expectedIID := [8]byte{0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x04, 0x00}
	for i := 0; i < 8; i++ {
		if addr[8+i] != expectedIID[i] {
			t.Fatalf("IID byte %d: expected 0x%02X, got 0x%02X", i, expectedIID[i], addr[8+i])
		}
	}
}

// ---------------------------------------------------------------------------
// Tests: CommissionerState String
// ---------------------------------------------------------------------------

func TestCommissionerState_String(t *testing.T) {
	tests := []struct {
		state CommissionerState
		want  string
	}{
		{CommissionerDisabled, "Disabled"},
		{CommissionerPetition, "Petition"},
		{CommissionerActive, "Active"},
		{CommissionerState(99), "Unknown"},
	}
	for _, tc := range tests {
		if got := tc.state.String(); got != tc.want {
			t.Errorf("CommissionerState(%d).String() = %q, want %q", tc.state, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests: JoinerEvent String
// ---------------------------------------------------------------------------

func TestJoinerEvent_String(t *testing.T) {
	tests := []struct {
		event JoinerEvent
		want  string
	}{
		{JoinerEventStart, "Start"},
		{JoinerEventConnected, "Connected"},
		{JoinerEventFinalize, "Finalize"},
		{JoinerEventEnd, "End"},
		{JoinerEventRemoved, "Removed"},
		{JoinerEvent(99), "Unknown"},
	}
	for _, tc := range tests {
		if got := tc.event.String(); got != tc.want {
			t.Errorf("JoinerEvent(%d).String() = %q, want %q", tc.event, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests: leaderCoapInfo
// ---------------------------------------------------------------------------

func TestLeaderCoapInfo(t *testing.T) {
	tr := newMockTransport()
	addr := newMockAddressing()
	addr.meshLocalPrefix = ip6.NetworkPrefix{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	addr.rloc16 = 0x0400
	addr.leaderRLOC16 = 0x0000
	c := NewCommissioner(tr, addr, nil, nil)

	info := c.leaderCoapInfo()

	if info.PeerPort != 61631 {
		t.Fatalf("expected PeerPort=61631, got %d", info.PeerPort)
	}

	expectedPeer := rlocAddr(addr.meshLocalPrefix, addr.leaderRLOC16)
	if info.PeerAddr != [16]byte(expectedPeer) {
		t.Fatalf("unexpected PeerAddr")
	}

	expectedLocal := rlocAddr(addr.meshLocalPrefix, addr.rloc16)
	if info.LocalAddr != [16]byte(expectedLocal) {
		t.Fatalf("unexpected LocalAddr")
	}
}
