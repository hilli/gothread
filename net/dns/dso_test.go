// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// mockTransport records calls for testing.
type mockTransport struct {
	mu           sync.Mutex
	connectCalls []mockConnectCall
	sendCalls    [][]byte
	disconnCalls []DisconnectMode
	connectErr   error
	sendErr      error
}

type mockConnectCall struct {
	addr ip6.Address
	port uint16
}

func (m *mockTransport) Connect(addr ip6.Address, port uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectCalls = append(m.connectCalls, mockConnectCall{addr, port})
	return m.connectErr
}

func (m *mockTransport) Send(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	m.sendCalls = append(m.sendCalls, cp)
	return m.sendErr
}

func (m *mockTransport) Disconnect(mode DisconnectMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disconnCalls = append(m.disconnCalls, mode)
	return nil
}

func (m *mockTransport) getSentMessages() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([][]byte, len(m.sendCalls))
	copy(result, m.sendCalls)
	return result
}

func (m *mockTransport) getLastSent() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sendCalls) == 0 {
		return nil
	}
	return m.sendCalls[len(m.sendCalls)-1]
}

// fakeTimer is a no-op timer for testing.
type fakeTimer struct{ stopped bool }

func (f *fakeTimer) Stop() bool {
	old := !f.stopped
	f.stopped = true
	return old
}

// fakeClock provides a controllable time source.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(t time.Time) *fakeClock {
	return &fakeClock{t: t}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newTestConnection creates a DSOConnection with mock transport and fake clock.
func newTestConnection(isServer bool, clock *fakeClock) (*DSOConnection, *mockTransport) {
	transport := &mockTransport{}
	peerAddr := ip6.Address{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	conn := NewDSOConnection(DSOConnectionConfig{
		Transport: transport,
		PeerAddr:  peerAddr,
		PeerPort:  853,
		IsServer:  isServer,
		Now:       clock.Now,
		AfterFunc: func(d time.Duration, f func()) Timer {
			return &fakeTimer{}
		},
	})
	return conn, transport
}

// parseHeader parses a DNS header from raw message bytes.
func parseHeader(t *testing.T, data []byte) Header {
	t.Helper()
	if len(data) < HeaderSize {
		t.Fatalf("message too short: %d bytes", len(data))
	}
	var hdr Header
	if err := hdr.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	return hdr
}

// ---------------------------------------------------------------------------
// DSO TLV marshal/unmarshal tests
// ---------------------------------------------------------------------------

func TestDSOTlv_MarshalUnmarshal(t *testing.T) {
	tlv := DSOTlv{Type: DSOTlvKeepAlive, Length: 8}
	buf := tlv.MarshalBinary()

	if binary.BigEndian.Uint16(buf[0:2]) != uint16(DSOTlvKeepAlive) {
		t.Errorf("type: got %d, want %d", binary.BigEndian.Uint16(buf[0:2]), DSOTlvKeepAlive)
	}
	if binary.BigEndian.Uint16(buf[2:4]) != 8 {
		t.Errorf("length: got %d, want 8", binary.BigEndian.Uint16(buf[2:4]))
	}

	var tlv2 DSOTlv
	if err := tlv2.UnmarshalBinary(buf[:]); err != nil {
		t.Fatal(err)
	}
	if tlv2.Type != DSOTlvKeepAlive || tlv2.Length != 8 {
		t.Errorf("unmarshal: got type=%d len=%d, want type=%d len=8", tlv2.Type, tlv2.Length, DSOTlvKeepAlive)
	}
}

func TestDSOTlv_UnmarshalTooShort(t *testing.T) {
	var tlv DSOTlv
	if err := tlv.UnmarshalBinary([]byte{0, 1}); err == nil {
		t.Error("expected error for short data")
	}
}

func TestKeepAliveTlvData_MarshalUnmarshal(t *testing.T) {
	ka := KeepAliveTlvData{InactivityTimeout: 15000, KeepAliveInterval: 10000}
	buf := ka.MarshalBinary()

	if binary.BigEndian.Uint32(buf[0:4]) != 15000 {
		t.Errorf("inactivity: got %d, want 15000", binary.BigEndian.Uint32(buf[0:4]))
	}
	if binary.BigEndian.Uint32(buf[4:8]) != 10000 {
		t.Errorf("keepalive: got %d, want 10000", binary.BigEndian.Uint32(buf[4:8]))
	}

	var ka2 KeepAliveTlvData
	if err := ka2.UnmarshalBinary(buf[:]); err != nil {
		t.Fatal(err)
	}
	if ka2.InactivityTimeout != 15000 || ka2.KeepAliveInterval != 10000 {
		t.Errorf("unmarshal: got %+v, want {15000, 10000}", ka2)
	}
}

func TestKeepAliveTlvData_UnmarshalTooShort(t *testing.T) {
	var ka KeepAliveTlvData
	if err := ka.UnmarshalBinary([]byte{0, 0, 0, 1}); err == nil {
		t.Error("expected error for short data")
	}
}

func TestRetryDelayTlvData_MarshalUnmarshal(t *testing.T) {
	rd := RetryDelayTlvData{RetryDelay: 60000}
	buf := rd.MarshalBinary()

	if binary.BigEndian.Uint32(buf[0:4]) != 60000 {
		t.Errorf("retry: got %d, want 60000", binary.BigEndian.Uint32(buf[0:4]))
	}

	var rd2 RetryDelayTlvData
	if err := rd2.UnmarshalBinary(buf[:]); err != nil {
		t.Fatal(err)
	}
	if rd2.RetryDelay != 60000 {
		t.Errorf("unmarshal: got %d, want 60000", rd2.RetryDelay)
	}
}

func TestRetryDelayTlvData_UnmarshalTooShort(t *testing.T) {
	var rd RetryDelayTlvData
	if err := rd.UnmarshalBinary([]byte{0, 0}); err == nil {
		t.Error("expected error for short data")
	}
}

// ---------------------------------------------------------------------------
// Connection state machine tests
// ---------------------------------------------------------------------------

func TestDSOConnection_InitialState(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	if conn.GetState() != DSOStateDisconnected {
		t.Errorf("initial state: got %d, want %d", conn.GetState(), DSOStateDisconnected)
	}
}

func TestDSOConnection_ClientConnectFlow(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, transport := newTestConnection(false, clock)

	// Connect.
	if err := conn.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if conn.GetState() != DSOStateConnecting {
		t.Errorf("after Connect: got %d, want %d", conn.GetState(), DSOStateConnecting)
	}
	if len(transport.connectCalls) != 1 {
		t.Fatalf("expected 1 connect call, got %d", len(transport.connectCalls))
	}

	// Simulate TCP connected.
	conn.HandleConnected()
	if conn.GetState() != DSOStateConnectedButSessionless {
		t.Errorf("after HandleConnected: got %d, want %d", conn.GetState(), DSOStateConnectedButSessionless)
	}

	// Send a request → should transition to EstablishingSession.
	payload := buildTestKeepAliveTlv(15000, 10000)
	msgID, err := conn.SendRequestMessage(payload, 0)
	if err != nil {
		t.Fatalf("SendRequestMessage: %v", err)
	}
	if msgID != 1 {
		t.Errorf("messageID: got %d, want 1", msgID)
	}
	if conn.GetState() != DSOStateEstablishingSession {
		t.Errorf("after SendRequestMessage: got %d, want %d", conn.GetState(), DSOStateEstablishingSession)
	}

	// Simulate successful response → should transition to SessionEstablished.
	resp := buildDSOResponse(msgID, RcodeSuccess, payload)
	conn.HandleReceive(resp)
	if conn.GetState() != DSOStateSessionEstablished {
		t.Errorf("after response: got %d, want %d", conn.GetState(), DSOStateSessionEstablished)
	}
}

func TestDSOConnection_ServerAcceptFlow(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(true, clock)

	sessionEstablished := false
	conn.callbacks.OnSessionEstablished = func(c *DSOConnection) {
		sessionEstablished = true
	}

	// Accept connection.
	if err := conn.AcceptConnection(); err != nil {
		t.Fatalf("AcceptConnection: %v", err)
	}
	if conn.GetState() != DSOStateConnectedButSessionless {
		t.Errorf("after AcceptConnection: got %d, want %d", conn.GetState(), DSOStateConnectedButSessionless)
	}

	// Receive a KeepAlive request from client.
	kaPayload := buildTestKeepAliveTlv(15000, 10000)
	req := buildDSORequest(1, kaPayload)
	conn.HandleReceive(req)

	if conn.GetState() != DSOStateSessionEstablished {
		t.Errorf("after receiving KeepAlive request: got %d, want %d", conn.GetState(), DSOStateSessionEstablished)
	}
	if !sessionEstablished {
		t.Error("OnSessionEstablished callback not called")
	}
}

func TestDSOConnection_ConnectWhenNotDisconnected(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)
	_ = conn.Connect()
	if err := conn.Connect(); err == nil {
		t.Error("expected error when connecting from non-disconnected state")
	}
}

func TestDSOConnection_ServerCannotConnect(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(true, clock)
	if err := conn.Connect(); err == nil {
		t.Error("expected error for server calling Connect")
	}
}

// ---------------------------------------------------------------------------
// SendRequestMessage tests
// ---------------------------------------------------------------------------

func TestDSOConnection_SendRequestMessage_Header(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, transport := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()

	payload := buildTestKeepAliveTlv(15000, 10000)
	msgID, err := conn.SendRequestMessage(payload, 0)
	if err != nil {
		t.Fatalf("SendRequestMessage: %v", err)
	}

	sent := transport.getLastSent()
	hdr := parseHeader(t, sent)

	if hdr.GetType() != TypeQuery {
		t.Errorf("QR: got %d, want %d (query)", hdr.GetType(), TypeQuery)
	}
	if hdr.GetOpCode() != OpcodeDso {
		t.Errorf("OpCode: got %d, want %d (DSO)", hdr.GetOpCode(), OpcodeDso)
	}
	if hdr.MessageID != msgID {
		t.Errorf("MessageID: got %d, want %d", hdr.MessageID, msgID)
	}
	if hdr.QDCount != 0 || hdr.ANCount != 0 || hdr.NSCount != 0 || hdr.ARCount != 0 {
		t.Error("section counts should all be zero for DSO")
	}
}

func TestDSOConnection_SendUnidirectionalMessage_Header(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, transport := newTestConnection(true, clock)

	_ = conn.AcceptConnection()
	_ = conn.MarkSessionEstablished()

	payload := buildTestKeepAliveTlv(15000, 10000)
	if err := conn.SendUnidirectionalMessage(payload); err != nil {
		t.Fatalf("SendUnidirectionalMessage: %v", err)
	}

	sent := transport.getLastSent()
	hdr := parseHeader(t, sent)

	if hdr.GetType() != TypeQuery {
		t.Errorf("QR: got %d, want %d (query)", hdr.GetType(), TypeQuery)
	}
	if hdr.MessageID != 0 {
		t.Errorf("MessageID: got %d, want 0", hdr.MessageID)
	}
	if hdr.GetOpCode() != OpcodeDso {
		t.Errorf("OpCode: got %d, want %d (DSO)", hdr.GetOpCode(), OpcodeDso)
	}
}

func TestDSOConnection_SendResponseMessage_Header(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, transport := newTestConnection(true, clock)

	_ = conn.AcceptConnection()

	payload := buildTestKeepAliveTlv(15000, 10000)
	if err := conn.SendResponseMessage(payload, 42, RcodeSuccess); err != nil {
		t.Fatalf("SendResponseMessage: %v", err)
	}

	sent := transport.getLastSent()
	hdr := parseHeader(t, sent)

	if hdr.GetType() != TypeResponse {
		t.Errorf("QR: got %d, want %d (response)", hdr.GetType(), TypeResponse)
	}
	if hdr.MessageID != 42 {
		t.Errorf("MessageID: got %d, want 42", hdr.MessageID)
	}
	if hdr.GetResponseCode() != RcodeSuccess {
		t.Errorf("RCODE: got %d, want %d", hdr.GetResponseCode(), RcodeSuccess)
	}
}

// ---------------------------------------------------------------------------
// HandleReceive dispatch tests
// ---------------------------------------------------------------------------

func TestDSOConnection_HandleReceive_RequestCallback(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(true, clock)

	var gotMsgID uint16
	var gotPrimaryType DSOTlvType
	conn.callbacks.OnRequestMessage = func(c *DSOConnection, messageID uint16, data []byte, primaryTlvType DSOTlvType) error {
		gotMsgID = messageID
		gotPrimaryType = primaryTlvType
		return nil
	}

	_ = conn.AcceptConnection()
	_ = conn.MarkSessionEstablished()

	// Build a request with a custom TLV type (100).
	customTlvPayload := buildCustomTlv(100, []byte{0x01, 0x02})
	req := buildDSORequest(5, customTlvPayload)
	conn.HandleReceive(req)

	if gotMsgID != 5 {
		t.Errorf("callback messageID: got %d, want 5", gotMsgID)
	}
	if gotPrimaryType != 100 {
		t.Errorf("callback primaryTlvType: got %d, want 100", gotPrimaryType)
	}
}

func TestDSOConnection_HandleReceive_UnidirectionalCallback(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	var gotPrimaryType DSOTlvType
	conn.callbacks.OnUnidirectionalMessage = func(c *DSOConnection, data []byte, primaryTlvType DSOTlvType) error {
		gotPrimaryType = primaryTlvType
		return nil
	}

	_ = conn.Connect()
	conn.HandleConnected()
	_ = conn.MarkSessionEstablished()

	customTlvPayload := buildCustomTlv(200, []byte{0xAA})
	msg := buildDSOUnidirectional(customTlvPayload)
	conn.HandleReceive(msg)

	if gotPrimaryType != 200 {
		t.Errorf("callback primaryTlvType: got %d, want 200", gotPrimaryType)
	}
}

func TestDSOConnection_HandleReceive_ResponseCallback(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	var gotRequestType DSOTlvType
	conn.callbacks.OnResponseMessage = func(c *DSOConnection, header Header, data []byte, responseTlvType DSOTlvType, requestTlvType DSOTlvType) error {
		gotRequestType = requestTlvType
		return nil
	}

	_ = conn.Connect()
	conn.HandleConnected()
	_ = conn.MarkSessionEstablished()

	// Send a request with custom TLV type 150.
	customPayload := buildCustomTlv(150, []byte{0x01})
	msgID, _ := conn.SendRequestMessage(customPayload, 0)

	// Simulate a response.
	respPayload := buildCustomTlv(150, []byte{0x02})
	resp := buildDSOResponse(msgID, RcodeSuccess, respPayload)
	conn.HandleReceive(resp)

	if gotRequestType != 150 {
		t.Errorf("response callback requestTlvType: got %d, want 150", gotRequestType)
	}
}

// ---------------------------------------------------------------------------
// KeepAlive message exchange
// ---------------------------------------------------------------------------

func TestDSOConnection_KeepAliveExchange(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	// Set up client.
	clientConn, clientTransport := newTestConnection(false, clock)
	_ = clientConn.Connect()
	clientConn.HandleConnected()

	// Client sends KeepAlive request to establish session.
	kaPayload := buildTestKeepAliveTlv(15000, 10000)
	msgID, err := clientConn.SendRequestMessage(kaPayload, 0)
	if err != nil {
		t.Fatalf("SendRequestMessage: %v", err)
	}

	// Verify the sent message has KeepAlive TLV.
	sent := clientTransport.getLastSent()
	if len(sent) < HeaderSize+DSOTlvHeaderSize {
		t.Fatal("sent message too short")
	}
	sentTlvType := DSOTlvType(binary.BigEndian.Uint16(sent[HeaderSize : HeaderSize+2]))
	if sentTlvType != DSOTlvKeepAlive {
		t.Errorf("sent TLV type: got %d, want %d", sentTlvType, DSOTlvKeepAlive)
	}

	// Server responds with success.
	respPayload := buildTestKeepAliveTlv(20000, 12000)
	resp := buildDSOResponse(msgID, RcodeSuccess, respPayload)
	clientConn.HandleReceive(resp)

	if clientConn.GetState() != DSOStateSessionEstablished {
		t.Errorf("client state: got %d, want %d", clientConn.GetState(), DSOStateSessionEstablished)
	}

	// Client should have updated its timeouts from the response.
	if clientConn.GetInactivityTimeout() != 20000 {
		t.Errorf("inactivity timeout: got %d, want 20000", clientConn.GetInactivityTimeout())
	}
	if clientConn.GetKeepAliveInterval() != 12000 {
		t.Errorf("keep-alive interval: got %d, want 12000", clientConn.GetKeepAliveInterval())
	}
}

func TestDSOConnection_SendKeepAliveMessage_Client(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, transport := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()
	_ = conn.MarkSessionEstablished()

	if err := conn.SendKeepAliveMessage(); err != nil {
		t.Fatalf("SendKeepAliveMessage: %v", err)
	}

	sent := transport.getLastSent()
	hdr := parseHeader(t, sent)

	// Client sends keepalive as a request (QR=0, ID≠0).
	if hdr.GetType() != TypeQuery {
		t.Errorf("QR: got %d, want %d", hdr.GetType(), TypeQuery)
	}
	if hdr.MessageID == 0 {
		t.Error("client keepalive should have non-zero message ID")
	}
}

func TestDSOConnection_SendKeepAliveMessage_Server(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, transport := newTestConnection(true, clock)

	_ = conn.AcceptConnection()
	_ = conn.MarkSessionEstablished()

	if err := conn.SendKeepAliveMessage(); err != nil {
		t.Fatalf("SendKeepAliveMessage: %v", err)
	}

	sent := transport.getLastSent()
	hdr := parseHeader(t, sent)

	// Server sends keepalive as unidirectional (QR=0, ID=0).
	if hdr.GetType() != TypeQuery {
		t.Errorf("QR: got %d, want %d", hdr.GetType(), TypeQuery)
	}
	if hdr.MessageID != 0 {
		t.Errorf("server keepalive should have message ID 0, got %d", hdr.MessageID)
	}
}

// ---------------------------------------------------------------------------
// RetryDelay handling
// ---------------------------------------------------------------------------

func TestDSOConnection_RetryDelay_ClientDisconnects(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	disconnected := false
	conn.callbacks.OnDisconnected = func(c *DSOConnection) {
		disconnected = true
	}

	_ = conn.Connect()
	conn.HandleConnected()
	_ = conn.MarkSessionEstablished()

	// Build a RetryDelay unidirectional message from server.
	rdPayload := buildRetryDelayTlv(60000)
	msg := buildDSOUnidirectional(rdPayload)
	conn.HandleReceive(msg)

	if conn.GetState() != DSOStateDisconnected {
		t.Errorf("state: got %d, want %d", conn.GetState(), DSOStateDisconnected)
	}
	if conn.GetDisconnectReason() != DisconnectReasonServerRetryDelayRequest {
		t.Errorf("reason: got %d, want %d", conn.GetDisconnectReason(), DisconnectReasonServerRetryDelayRequest)
	}
	if conn.GetRetryDelay() != 60000 {
		t.Errorf("retry delay: got %d, want 60000", conn.GetRetryDelay())
	}
	if !disconnected {
		t.Error("OnDisconnected not called")
	}
}

func TestDSOConnection_SendRetryDelayMessage_Server(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, transport := newTestConnection(true, clock)

	_ = conn.AcceptConnection()
	_ = conn.MarkSessionEstablished()

	if err := conn.SendRetryDelayMessage(30000, RcodeRefused); err != nil {
		t.Fatalf("SendRetryDelayMessage: %v", err)
	}

	// Should have sent a message and disconnected.
	if len(transport.getSentMessages()) == 0 {
		t.Error("expected at least one sent message")
	}
	if conn.GetState() != DSOStateDisconnected {
		t.Errorf("state: got %d, want %d", conn.GetState(), DSOStateDisconnected)
	}
}

func TestDSOConnection_SendRetryDelayMessage_ClientCannotSend(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()
	_ = conn.MarkSessionEstablished()

	if err := conn.SendRetryDelayMessage(30000, RcodeRefused); err == nil {
		t.Error("expected error for client sending RetryDelay")
	}
}

// ---------------------------------------------------------------------------
// Pending request tracking
// ---------------------------------------------------------------------------

func TestDSOConnection_PendingRequests_MaxExceeded(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()

	// Send dsoMaxPendingRequests requests.
	payload := buildCustomTlv(100, []byte{0x01})
	for i := 0; i < dsoMaxPendingRequests; i++ {
		if _, err := conn.SendRequestMessage(payload, 0); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}

	// Next should fail.
	if _, err := conn.SendRequestMessage(payload, 0); err == nil {
		t.Error("expected error when exceeding max pending requests")
	}
}

func TestDSOConnection_PendingRequests_MatchAndRemove(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	conn.callbacks.OnResponseMessage = func(c *DSOConnection, header Header, data []byte, responseTlvType DSOTlvType, requestTlvType DSOTlvType) error {
		return nil
	}

	_ = conn.Connect()
	conn.HandleConnected()
	_ = conn.MarkSessionEstablished()

	payload := buildCustomTlv(100, []byte{0x01})
	msgID1, _ := conn.SendRequestMessage(payload, 0)
	msgID2, _ := conn.SendRequestMessage(payload, 0)

	// Respond to first request.
	resp := buildDSOResponse(msgID1, RcodeSuccess, payload)
	conn.HandleReceive(resp)

	// Now the pending list should have only msgID2.
	conn.mu.Lock()
	pendingCount := len(conn.pendingReqs)
	conn.mu.Unlock()

	if pendingCount != 1 {
		t.Errorf("pending count: got %d, want 1", pendingCount)
	}

	// Respond to second request.
	resp2 := buildDSOResponse(msgID2, RcodeSuccess, payload)
	conn.HandleReceive(resp2)

	conn.mu.Lock()
	pendingCount = len(conn.pendingReqs)
	conn.mu.Unlock()

	if pendingCount != 0 {
		t.Errorf("pending count after both: got %d, want 0", pendingCount)
	}
}

// ---------------------------------------------------------------------------
// Timeout tests
// ---------------------------------------------------------------------------

func TestDSOConnection_SetTimeouts(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()
	_ = conn.MarkSessionEstablished()

	conn.SetTimeouts(30000, 15000)

	if conn.GetInactivityTimeout() != 30000 {
		t.Errorf("inactivity: got %d, want 30000", conn.GetInactivityTimeout())
	}
	if conn.GetKeepAliveInterval() != 15000 {
		t.Errorf("keepalive: got %d, want 15000", conn.GetKeepAliveInterval())
	}
}

func TestDSOConnection_SetTimeouts_ClampsMinKeepAlive(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()
	_ = conn.MarkSessionEstablished()

	conn.SetTimeouts(15000, 5000) // 5000 < dsoMinKeepAliveInterval (10000)

	if conn.GetKeepAliveInterval() != dsoMinKeepAliveInterval {
		t.Errorf("keepalive: got %d, want %d", conn.GetKeepAliveInterval(), dsoMinKeepAliveInterval)
	}
}

func TestDSOConnection_LongLivedOperation_SuppressesInactivity(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()
	_ = conn.MarkSessionEstablished()

	conn.SetTimeouts(1000, dsoInfiniteTimeout) // 1 sec inactivity, no keepalive
	conn.SetLongLivedOperation(true)

	// Advance past inactivity timeout.
	clock.Advance(2 * time.Second)

	// HandleTimer should NOT disconnect because longLivedOperation is set.
	conn.HandleTimer()

	if conn.GetState() != DSOStateSessionEstablished {
		t.Errorf("state: got %d, want %d (session established)", conn.GetState(), DSOStateSessionEstablished)
	}
}

func TestDSOConnection_InactivityTimeout_ClientGraceful(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()
	_ = conn.MarkSessionEstablished()

	conn.SetTimeouts(1000, dsoInfiniteTimeout) // 1 sec inactivity

	clock.Advance(2 * time.Second)
	conn.HandleTimer()

	if conn.GetState() != DSOStateDisconnected {
		t.Errorf("state: got %d, want %d", conn.GetState(), DSOStateDisconnected)
	}
	if conn.GetDisconnectReason() != DisconnectReasonInactivityTimeout {
		t.Errorf("reason: got %d, want %d", conn.GetDisconnectReason(), DisconnectReasonInactivityTimeout)
	}
}

func TestDSOConnection_InactivityTimeout_ServerForcible(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, transport := newTestConnection(true, clock)

	_ = conn.AcceptConnection()
	_ = conn.MarkSessionEstablished()

	conn.SetTimeouts(1000, dsoInfiniteTimeout)

	clock.Advance(2 * time.Second)
	conn.HandleTimer()

	if conn.GetState() != DSOStateDisconnected {
		t.Errorf("state: got %d, want %d", conn.GetState(), DSOStateDisconnected)
	}
	if conn.GetDisconnectReason() != DisconnectReasonInactivityTimeout {
		t.Errorf("reason: got %d, want %d", conn.GetDisconnectReason(), DisconnectReasonInactivityTimeout)
	}

	// Server should have used ForciblyAbort.
	transport.mu.Lock()
	foundForcible := false
	for _, m := range transport.disconnCalls {
		if m == DisconnectForciblyAbort {
			foundForcible = true
		}
	}
	transport.mu.Unlock()
	if !foundForcible {
		t.Error("server should forcibly abort on inactivity timeout")
	}
}

func TestDSOConnection_ConnectTimeout(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	_ = conn.Connect()

	// Advance past connecting timeout.
	clock.Advance(time.Duration(dsoConnectingTimeout+1000) * time.Millisecond)
	conn.HandleTimer()

	if conn.GetState() != DSOStateDisconnected {
		t.Errorf("state: got %d, want %d", conn.GetState(), DSOStateDisconnected)
	}
	if conn.GetDisconnectReason() != DisconnectReasonFailedToConnect {
		t.Errorf("reason: got %d, want %d", conn.GetDisconnectReason(), DisconnectReasonFailedToConnect)
	}
}

func TestDSOConnection_ResponseTimeout(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()

	payload := buildCustomTlv(100, []byte{0x01})
	_, _ = conn.SendRequestMessage(payload, 5000) // 5 second timeout

	clock.Advance(6 * time.Second)
	conn.HandleTimer()

	if conn.GetState() != DSOStateDisconnected {
		t.Errorf("state: got %d, want %d", conn.GetState(), DSOStateDisconnected)
	}
	if conn.GetDisconnectReason() != DisconnectReasonResponseTimeout {
		t.Errorf("reason: got %d, want %d", conn.GetDisconnectReason(), DisconnectReasonResponseTimeout)
	}
}

func TestDSOConnection_KeepAliveTimeout_ServerAborts(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(true, clock)

	_ = conn.AcceptConnection()
	_ = conn.MarkSessionEstablished()

	conn.SetTimeouts(dsoInfiniteTimeout, 10000) // no inactivity, 10 sec keepalive (min allowed)

	clock.Advance(11 * time.Second)
	conn.HandleTimer()

	if conn.GetState() != DSOStateDisconnected {
		t.Errorf("state: got %d, want %d", conn.GetState(), DSOStateDisconnected)
	}
	if conn.GetDisconnectReason() != DisconnectReasonKeepAliveTimeout {
		t.Errorf("reason: got %d, want %d", conn.GetDisconnectReason(), DisconnectReasonKeepAliveTimeout)
	}
}

// ---------------------------------------------------------------------------
// Error handling tests
// ---------------------------------------------------------------------------

func TestDSOConnection_HandleReceive_NonDSOQuery(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, transport := newTestConnection(true, clock)

	_ = conn.AcceptConnection()

	// Send a standard DNS query (non-DSO, with QDCount=1).
	var hdr Header
	hdr.SetType(TypeQuery)
	hdr.SetOpCode(OpcodeQuery)
	hdr.MessageID = 10
	hdr.QDCount = 1
	hdrBytes := hdr.MarshalBinary()

	conn.HandleReceive(hdrBytes[:])

	// Should have sent an error response (RCODE=NotImplemented).
	sent := transport.getLastSent()
	if sent == nil {
		t.Fatal("expected error response to be sent")
	}
	respHdr := parseHeader(t, sent)
	if respHdr.GetResponseCode() != RcodeNotImplemented {
		t.Errorf("RCODE: got %d, want %d", respHdr.GetResponseCode(), RcodeNotImplemented)
	}
	if respHdr.MessageID != 10 {
		t.Errorf("response ID: got %d, want 10", respHdr.MessageID)
	}
}

func TestDSOConnection_HandleReceive_UnmatchedResponse(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()
	_ = conn.MarkSessionEstablished()

	// Send a response with no matching request.
	resp := buildDSOResponse(999, RcodeSuccess, nil)
	conn.HandleReceive(resp)

	if conn.GetState() != DSOStateDisconnected {
		t.Errorf("state: got %d, want %d", conn.GetState(), DSOStateDisconnected)
	}
	if conn.GetDisconnectReason() != DisconnectReasonPeerMisbehavior {
		t.Errorf("reason: got %d, want %d", conn.GetDisconnectReason(), DisconnectReasonPeerMisbehavior)
	}
}

func TestDSOConnection_HandleReceive_PeerDoesNotSupportDSO(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()

	// Send first request to transition to EstablishingSession.
	payload := buildTestKeepAliveTlv(15000, 10000)
	msgID, _ := conn.SendRequestMessage(payload, 0)

	// Response with RCODE=DsoNotImpl.
	resp := buildDSOResponse(msgID, RcodeDsoNotImpl, nil)
	conn.HandleReceive(resp)

	if conn.GetState() != DSOStateDisconnected {
		t.Errorf("state: got %d, want %d", conn.GetState(), DSOStateDisconnected)
	}
	if conn.GetDisconnectReason() != DisconnectReasonPeerDoesNotSupportDso {
		t.Errorf("reason: got %d, want %d", conn.GetDisconnectReason(), DisconnectReasonPeerDoesNotSupportDso)
	}
}

func TestDSOConnection_HandleReceive_TooShort(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()

	conn.HandleReceive([]byte{0, 1, 2}) // Too short for DNS header.

	if conn.GetState() != DSOStateDisconnected {
		t.Errorf("state: got %d, want %d", conn.GetState(), DSOStateDisconnected)
	}
}

func TestDSOConnection_HandleReceive_UnidirectionalBeforeSession(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()

	// Unidirectional before session established.
	payload := buildCustomTlv(200, []byte{0x01})
	msg := buildDSOUnidirectional(payload)
	conn.HandleReceive(msg)

	if conn.GetState() != DSOStateDisconnected {
		t.Errorf("state: got %d, want %d", conn.GetState(), DSOStateDisconnected)
	}
	if conn.GetDisconnectReason() != DisconnectReasonPeerMisbehavior {
		t.Errorf("reason: got %d, want %d", conn.GetDisconnectReason(), DisconnectReasonPeerMisbehavior)
	}
}

// ---------------------------------------------------------------------------
// Encryption padding tests
// ---------------------------------------------------------------------------

func TestDSOConnection_EncryptionPadding(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, transport := newTestConnection(true, clock)

	_ = conn.AcceptConnection()
	_ = conn.MarkSessionEstablished()

	payload := buildTestKeepAliveTlv(15000, 10000)
	_ = conn.SendUnidirectionalMessage(payload)

	sent := transport.getLastSent()
	if len(sent) <= HeaderSize+len(payload) {
		t.Error("expected message to include padding TLV")
	}

	// Find the padding TLV after the payload.
	offset := HeaderSize + len(payload)
	if offset+DSOTlvHeaderSize > len(sent) {
		t.Fatal("not enough room for padding TLV header")
	}

	padType := DSOTlvType(binary.BigEndian.Uint16(sent[offset : offset+2]))
	if padType != DSOTlvEncryptionPadding {
		t.Errorf("padding TLV type: got %d, want %d", padType, DSOTlvEncryptionPadding)
	}

	padLen := binary.BigEndian.Uint16(sent[offset+2 : offset+4])
	// Verify all padding bytes are zero.
	for i := 0; i < int(padLen); i++ {
		if sent[offset+DSOTlvHeaderSize+i] != 0 {
			t.Errorf("padding byte %d is non-zero: %d", i, sent[offset+DSOTlvHeaderSize+i])
		}
	}
}

// ---------------------------------------------------------------------------
// DSO manager tests
// ---------------------------------------------------------------------------

func TestDSO_FindClientConnection(t *testing.T) {
	dso := NewDSO()
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	addr1 := ip6.Address{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	addr2 := ip6.Address{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	conn1 := NewDSOConnection(DSOConnectionConfig{
		Transport: &mockTransport{},
		PeerAddr:  addr1,
		PeerPort:  853,
		Now:       clock.Now,
		AfterFunc: func(d time.Duration, f func()) Timer { return &fakeTimer{} },
	})
	conn2 := NewDSOConnection(DSOConnectionConfig{
		Transport: &mockTransport{},
		PeerAddr:  addr2,
		PeerPort:  853,
		Now:       clock.Now,
		AfterFunc: func(d time.Duration, f func()) Timer { return &fakeTimer{} },
	})

	dso.AddClientConnection(conn1)
	dso.AddClientConnection(conn2)

	found := dso.FindClientConnection(addr1, 853)
	if found != conn1 {
		t.Error("FindClientConnection did not find conn1")
	}

	found = dso.FindClientConnection(addr2, 853)
	if found != conn2 {
		t.Error("FindClientConnection did not find conn2")
	}

	// Not found.
	notFound := dso.FindClientConnection(addr1, 9999)
	if notFound != nil {
		t.Error("expected nil for unknown port")
	}
}

func TestDSO_FindServerConnection(t *testing.T) {
	dso := NewDSO()
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	addr := ip6.Address{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}

	conn := NewDSOConnection(DSOConnectionConfig{
		Transport: &mockTransport{},
		PeerAddr:  addr,
		PeerPort:  853,
		IsServer:  true,
		Now:       clock.Now,
		AfterFunc: func(d time.Duration, f func()) Timer { return &fakeTimer{} },
	})

	dso.StartListening(func(peerAddr ip6.Address, peerPort uint16) *DSOConnection {
		return conn
	})

	accepted := dso.AcceptConnection(addr, 853)
	if accepted != conn {
		t.Error("AcceptConnection did not return the connection")
	}

	found := dso.FindServerConnection(addr, 853)
	if found != conn {
		t.Error("FindServerConnection did not find the accepted connection")
	}
}

func TestDSO_AcceptConnection_NotListening(t *testing.T) {
	dso := NewDSO()
	addr := ip6.Address{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4}

	result := dso.AcceptConnection(addr, 853)
	if result != nil {
		t.Error("expected nil when not listening")
	}
}

func TestDSO_StopListening(t *testing.T) {
	dso := NewDSO()
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	addr := ip6.Address{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}

	conn := NewDSOConnection(DSOConnectionConfig{
		Transport: &mockTransport{},
		PeerAddr:  addr,
		PeerPort:  853,
		IsServer:  true,
		Now:       clock.Now,
		AfterFunc: func(d time.Duration, f func()) Timer { return &fakeTimer{} },
	})
	_ = conn.AcceptConnection()

	dso.StartListening(func(peerAddr ip6.Address, peerPort uint16) *DSOConnection {
		return conn
	})
	dso.AcceptConnection(addr, 853)

	dso.StopListening()

	// Should no longer accept.
	result := dso.AcceptConnection(addr, 853)
	if result != nil {
		t.Error("expected nil after StopListening")
	}

	// Server connections should be cleared.
	if len(dso.GetServerConnections()) != 0 {
		t.Errorf("expected 0 server connections, got %d", len(dso.GetServerConnections()))
	}
}

func TestDSO_RemoveClientConnection(t *testing.T) {
	dso := NewDSO()
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	addr := ip6.Address{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6}
	conn := NewDSOConnection(DSOConnectionConfig{
		Transport: &mockTransport{},
		PeerAddr:  addr,
		PeerPort:  853,
		Now:       clock.Now,
		AfterFunc: func(d time.Duration, f func()) Timer { return &fakeTimer{} },
	})

	dso.AddClientConnection(conn)
	if len(dso.GetClientConnections()) != 1 {
		t.Fatal("expected 1 client connection")
	}

	dso.RemoveClientConnection(conn)
	if len(dso.GetClientConnections()) != 0 {
		t.Errorf("expected 0 client connections after remove, got %d", len(dso.GetClientConnections()))
	}
}

// ---------------------------------------------------------------------------
// Disconnect tests
// ---------------------------------------------------------------------------

func TestDSOConnection_Disconnect(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, transport := newTestConnection(false, clock)

	disconnected := false
	conn.callbacks.OnDisconnected = func(c *DSOConnection) {
		disconnected = true
	}

	_ = conn.Connect()
	conn.HandleConnected()

	conn.Disconnect(DisconnectGracefullyClose, DisconnectReasonUnknown)

	if conn.GetState() != DSOStateDisconnected {
		t.Errorf("state: got %d, want %d", conn.GetState(), DSOStateDisconnected)
	}
	if !disconnected {
		t.Error("OnDisconnected not called")
	}
	transport.mu.Lock()
	if len(transport.disconnCalls) == 0 {
		t.Error("transport.Disconnect not called")
	}
	transport.mu.Unlock()
}

func TestDSOConnection_Disconnect_DoubleDisconnect(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	callCount := 0
	conn.callbacks.OnDisconnected = func(c *DSOConnection) {
		callCount++
	}

	_ = conn.Connect()
	conn.HandleConnected()

	conn.Disconnect(DisconnectGracefullyClose, DisconnectReasonUnknown)
	conn.Disconnect(DisconnectGracefullyClose, DisconnectReasonUnknown)

	if callCount != 1 {
		t.Errorf("OnDisconnected called %d times, want 1", callCount)
	}
}

func TestDSOConnection_HandleDisconnected_PeerClosed(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()

	conn.HandleDisconnected(DisconnectGracefullyClose)

	if conn.GetDisconnectReason() != DisconnectReasonPeerClosed {
		t.Errorf("reason: got %d, want %d", conn.GetDisconnectReason(), DisconnectReasonPeerClosed)
	}
}

func TestDSOConnection_HandleDisconnected_PeerAborted(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()

	conn.HandleDisconnected(DisconnectForciblyAbort)

	if conn.GetDisconnectReason() != DisconnectReasonPeerAborted {
		t.Errorf("reason: got %d, want %d", conn.GetDisconnectReason(), DisconnectReasonPeerAborted)
	}
}

// ---------------------------------------------------------------------------
// MarkSessionEstablished tests
// ---------------------------------------------------------------------------

func TestDSOConnection_MarkSessionEstablished(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()

	sessionEstablished := false
	conn.callbacks.OnSessionEstablished = func(c *DSOConnection) {
		sessionEstablished = true
	}

	if err := conn.MarkSessionEstablished(); err != nil {
		t.Fatalf("MarkSessionEstablished: %v", err)
	}
	if conn.GetState() != DSOStateSessionEstablished {
		t.Errorf("state: got %d, want %d", conn.GetState(), DSOStateSessionEstablished)
	}
	if !sessionEstablished {
		t.Error("OnSessionEstablished callback not called")
	}
}

func TestDSOConnection_MarkSessionEstablished_InvalidState(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	// Should fail from Disconnected state.
	if err := conn.MarkSessionEstablished(); err == nil {
		t.Error("expected error from Disconnected state")
	}
}

// ---------------------------------------------------------------------------
// Message ID management
// ---------------------------------------------------------------------------

func TestDSOConnection_MessageIDIncrement(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()
	_ = conn.MarkSessionEstablished()

	payload := buildCustomTlv(100, []byte{0x01})

	ids := make([]uint16, 3)
	for i := range ids {
		var err error
		ids[i], err = conn.SendRequestMessage(payload, 30000)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}

	if ids[0] != 1 || ids[1] != 2 || ids[2] != 3 {
		t.Errorf("message IDs: got %v, want [1 2 3]", ids)
	}
}

func TestDSOConnection_MessageIDSkipsZero(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()
	_ = conn.MarkSessionEstablished()

	// Set nextMessageID to 65535 to test wrap-around.
	conn.mu.Lock()
	conn.nextMessageID = 65535
	conn.mu.Unlock()

	payload := buildCustomTlv(100, []byte{0x01})

	id1, _ := conn.SendRequestMessage(payload, 30000)
	if id1 != 65535 {
		t.Errorf("first ID: got %d, want 65535", id1)
	}

	// Clear pending requests so we can send another.
	conn.mu.Lock()
	conn.pendingReqs = nil
	conn.mu.Unlock()

	id2, _ := conn.SendRequestMessage(payload, 30000)
	if id2 != 1 {
		t.Errorf("wrapped ID: got %d, want 1 (should skip 0)", id2)
	}
}

// ---------------------------------------------------------------------------
// Getters
// ---------------------------------------------------------------------------

func TestDSOConnection_Getters(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(true, clock)

	if !conn.IsServer() {
		t.Error("IsServer: got false, want true")
	}

	addr := conn.GetPeerAddr()
	if addr[0] != 0x20 || addr[1] != 0x01 {
		t.Errorf("PeerAddr: unexpected %v", addr)
	}

	if conn.GetPeerPort() != 853 {
		t.Errorf("PeerPort: got %d, want 853", conn.GetPeerPort())
	}
}

// ---------------------------------------------------------------------------
// KeepAlive request from server to client (KeepAlive TLV validation)
// ---------------------------------------------------------------------------

func TestDSOConnection_KeepAliveRequest_RefusedForBadInterval(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, transport := newTestConnection(true, clock)

	_ = conn.AcceptConnection()
	_ = conn.MarkSessionEstablished()

	// Send a KeepAlive request with interval < minimum.
	kaPayload := buildTestKeepAliveTlv(15000, 5000) // 5000 < 10000 min
	req := buildDSORequest(7, kaPayload)
	conn.HandleReceive(req)

	// Should get a Refused response.
	sent := transport.getLastSent()
	if sent == nil {
		t.Fatal("expected response to be sent")
	}
	respHdr := parseHeader(t, sent)
	if respHdr.GetResponseCode() != RcodeRefused {
		t.Errorf("RCODE: got %d, want %d", respHdr.GetResponseCode(), RcodeRefused)
	}
}

// ---------------------------------------------------------------------------
// dsoTimeout tests
// ---------------------------------------------------------------------------

func TestDSOTimeout_Infinite(t *testing.T) {
	var to dsoTimeout
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to.reset(dsoInfiniteTimeout, now)

	if !to.isInfinite {
		t.Error("expected isInfinite=true")
	}
	if to.isExpired(now.Add(time.Hour)) {
		t.Error("infinite timeout should never expire")
	}
}

func TestDSOTimeout_Normal(t *testing.T) {
	var to dsoTimeout
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to.reset(1000, now) // 1 second

	if to.isInfinite {
		t.Error("expected isInfinite=false")
	}
	if to.isExpired(now.Add(500 * time.Millisecond)) {
		t.Error("should not be expired at 500ms")
	}
	if !to.isExpired(now.Add(1001 * time.Millisecond)) {
		t.Error("should be expired at 1001ms")
	}
}

// ---------------------------------------------------------------------------
// AdjustInactivityTimeout test
// ---------------------------------------------------------------------------

func TestDSOConnection_AdjustInactivityTimeout(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()
	_ = conn.MarkSessionEstablished()

	// Set initial inactivity timeout to 10 seconds.
	conn.SetTimeouts(10000, dsoInfiniteTimeout)

	// Advance 4 seconds.
	clock.Advance(4 * time.Second)

	// Reduce timeout to 8 seconds. Since 4s elapsed, we should have 4s remaining.
	conn.SetTimeouts(8000, dsoInfiniteTimeout)

	// Advance another 3.9 seconds — should still be active (4-3.9=0.1s remaining).
	clock.Advance(3900 * time.Millisecond)
	conn.HandleTimer()

	if conn.GetState() != DSOStateSessionEstablished {
		t.Errorf("should still be established, got state %d", conn.GetState())
	}

	// Advance past the remaining 0.1s.
	clock.Advance(200 * time.Millisecond)
	conn.HandleTimer()

	if conn.GetState() != DSOStateDisconnected {
		t.Errorf("should be disconnected, got state %d", conn.GetState())
	}
}

// ---------------------------------------------------------------------------
// ServerInactivityWaitTime test
// ---------------------------------------------------------------------------

func TestDSOConnection_ServerInactivityWaitTime(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(true, clock)

	_ = conn.AcceptConnection()
	_ = conn.MarkSessionEstablished()

	// With default timeout (15000), server wait = max(2*15000, 5000) = 30000.
	conn.mu.Lock()
	wait := conn.calculateServerInactivityWaitTime()
	conn.mu.Unlock()

	if wait != 30000 {
		t.Errorf("wait: got %d, want 30000", wait)
	}

	// With very small timeout (1000), server wait = max(2*1000, 5000) = 5000.
	conn.SetTimeouts(1000, dsoMinKeepAliveInterval)
	conn.mu.Lock()
	wait = conn.calculateServerInactivityWaitTime()
	conn.mu.Unlock()

	if wait != 5000 {
		t.Errorf("wait: got %d, want 5000", wait)
	}
}

// ---------------------------------------------------------------------------
// SendRequestMessage in invalid states
// ---------------------------------------------------------------------------

func TestDSOConnection_SendRequestMessage_InvalidState(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	payload := buildCustomTlv(100, []byte{0x01})
	_, err := conn.SendRequestMessage(payload, 0)
	if err == nil {
		t.Error("expected error from Disconnected state")
	}
}

func TestDSOConnection_SendUnidirectionalMessage_InvalidState(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	_ = conn.Connect()
	conn.HandleConnected()
	// Not yet session established.

	payload := buildCustomTlv(100, []byte{0x01})
	if err := conn.SendUnidirectionalMessage(payload); err == nil {
		t.Error("expected error when session not established")
	}
}

// ---------------------------------------------------------------------------
// HandleReceive in wrong states
// ---------------------------------------------------------------------------

func TestDSOConnection_HandleReceive_WhileDisconnected(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, transport := newTestConnection(false, clock)

	// Should be a no-op.
	msg := buildDSORequest(1, buildCustomTlv(100, nil))
	conn.HandleReceive(msg)

	if len(transport.getSentMessages()) != 0 {
		t.Error("should not send anything while disconnected")
	}
}

// ---------------------------------------------------------------------------
// OnConnected callback
// ---------------------------------------------------------------------------

func TestDSOConnection_OnConnectedCallback(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	connectedCalled := false
	conn.callbacks.OnConnected = func(c *DSOConnection) {
		connectedCalled = true
	}

	_ = conn.Connect()
	conn.HandleConnected()

	if !connectedCalled {
		t.Error("OnConnected callback not called")
	}
}

// ---------------------------------------------------------------------------
// HandleConnected when not in Connecting state
// ---------------------------------------------------------------------------

func TestDSOConnection_HandleConnected_WrongState(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	conn, _ := newTestConnection(false, clock)

	// Should be a no-op (state is Disconnected, not Connecting).
	conn.HandleConnected()

	if conn.GetState() != DSOStateDisconnected {
		t.Errorf("state: got %d, want %d", conn.GetState(), DSOStateDisconnected)
	}
}

// ---------------------------------------------------------------------------
// Helper functions for building test messages
// ---------------------------------------------------------------------------

func buildTestKeepAliveTlv(inactivity, keepAlive uint32) []byte {
	var tlvHdr DSOTlv
	tlvHdr.Type = DSOTlvKeepAlive
	tlvHdr.Length = KeepAliveTlvDataSize
	hdrBytes := tlvHdr.MarshalBinary()

	var ka KeepAliveTlvData
	ka.InactivityTimeout = inactivity
	ka.KeepAliveInterval = keepAlive
	kaBytes := ka.MarshalBinary()

	buf := make([]byte, 0, DSOTlvHeaderSize+KeepAliveTlvDataSize)
	buf = append(buf, hdrBytes[:]...)
	buf = append(buf, kaBytes[:]...)
	return buf
}

func buildRetryDelayTlv(delayMs uint32) []byte {
	var tlvHdr DSOTlv
	tlvHdr.Type = DSOTlvRetryDelay
	tlvHdr.Length = RetryDelayTlvDataSize
	hdrBytes := tlvHdr.MarshalBinary()

	var rd RetryDelayTlvData
	rd.RetryDelay = delayMs
	rdBytes := rd.MarshalBinary()

	buf := make([]byte, 0, DSOTlvHeaderSize+RetryDelayTlvDataSize)
	buf = append(buf, hdrBytes[:]...)
	buf = append(buf, rdBytes[:]...)
	return buf
}

func buildCustomTlv(tlvType uint16, value []byte) []byte {
	buf := make([]byte, DSOTlvHeaderSize+len(value))
	binary.BigEndian.PutUint16(buf[0:2], tlvType)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(value)))
	copy(buf[DSOTlvHeaderSize:], value)
	return buf
}

func buildDSORequest(messageID uint16, payload []byte) []byte {
	var hdr Header
	hdr.SetType(TypeQuery)
	hdr.SetOpCode(OpcodeDso)
	hdr.MessageID = messageID

	hdrBytes := hdr.MarshalBinary()
	msg := make([]byte, 0, HeaderSize+len(payload))
	msg = append(msg, hdrBytes[:]...)
	msg = append(msg, payload...)
	return msg
}

func buildDSOResponse(messageID uint16, rcode ResponseCode, payload []byte) []byte {
	var hdr Header
	hdr.SetType(TypeResponse)
	hdr.SetOpCode(OpcodeDso)
	hdr.MessageID = messageID
	hdr.SetResponseCode(rcode)

	hdrBytes := hdr.MarshalBinary()
	msg := make([]byte, 0, HeaderSize+len(payload))
	msg = append(msg, hdrBytes[:]...)
	msg = append(msg, payload...)
	return msg
}

func buildDSOUnidirectional(payload []byte) []byte {
	return buildDSORequest(0, payload) // Unidirectional = QR=0, ID=0.
}
