// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tmf

import (
	"encoding/binary"
	"errors"
	"sync"
	"testing"

	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/thread/netdata"
	"github.com/hilli/gothread/tlv"
)

// ---------------------------------------------------------------------------
// Mock network data leader
// ---------------------------------------------------------------------------

type mockNetworkDataLeader struct {
	mu          sync.Mutex
	lastRLOC16  uint16
	lastData    []byte
	callCount   int
	returnError error
}

func (m *mockNetworkDataLeader) RegisterNetworkData(rloc16 uint16, incoming []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastRLOC16 = rloc16
	m.lastData = make([]byte, len(incoming))
	copy(m.lastData, incoming)
	m.callCount++
	return m.returnError
}

// Compile-time interface check.
var _ NetworkDataLeader = (*mockNetworkDataLeader)(nil)

// Also verify the real netdata.Leader satisfies the interface.
var _ NetworkDataLeader = (*netdata.Leader)(nil)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func buildServerDataCON(msgID uint16, token []byte, req *ServerDataRequest) []byte {
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, msgID)
	_ = msg.SetToken(token)
	_ = msg.AppendURIPathOptions(PathForURI(URIServerData))
	payload := MarshalServerDataRequest(req)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)
	return msg.GetBytes()
}

func buildServerDataNON(msgID uint16, token []byte, req *ServerDataRequest) []byte {
	msg := coap.NewMessage(coap.TypeNonConfirmable, coap.CodePost, msgID)
	_ = msg.SetToken(token)
	_ = msg.AppendURIPathOptions(PathForURI(URIServerData))
	payload := MarshalServerDataRequest(req)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)
	return msg.GetBytes()
}

// ---------------------------------------------------------------------------
// ServerDataRequest TLV roundtrip tests
// ---------------------------------------------------------------------------

func TestServerDataRequestRoundtrip(t *testing.T) {
	t.Parallel()

	req := &ServerDataRequest{
		RLOC16:      0x5400,
		NetworkData: []byte{0x01, 0x02, 0x03, 0x04},
	}

	data := MarshalServerDataRequest(req)
	parsed, err := ParseServerDataRequest(data)
	if err != nil {
		t.Fatalf("ParseServerDataRequest: %v", err)
	}

	if parsed.RLOC16 != req.RLOC16 {
		t.Errorf("RLOC16 = 0x%04X, want 0x%04X", parsed.RLOC16, req.RLOC16)
	}
	if len(parsed.NetworkData) != len(req.NetworkData) {
		t.Fatalf("NetworkData len = %d, want %d", len(parsed.NetworkData), len(req.NetworkData))
	}
	for i, b := range parsed.NetworkData {
		if b != req.NetworkData[i] {
			t.Errorf("NetworkData[%d] = 0x%02X, want 0x%02X", i, b, req.NetworkData[i])
		}
	}
}

func TestServerDataRequestRoundtripEmptyNetworkData(t *testing.T) {
	t.Parallel()

	req := &ServerDataRequest{
		RLOC16:      0x1000,
		NetworkData: nil,
	}

	data := MarshalServerDataRequest(req)
	parsed, err := ParseServerDataRequest(data)
	if err != nil {
		t.Fatalf("ParseServerDataRequest: %v", err)
	}

	if parsed.RLOC16 != req.RLOC16 {
		t.Errorf("RLOC16 = 0x%04X, want 0x%04X", parsed.RLOC16, req.RLOC16)
	}
	if len(parsed.NetworkData) != 0 {
		t.Errorf("NetworkData len = %d, want 0", len(parsed.NetworkData))
	}
}

func TestServerDataRequestMissingRLOC16(t *testing.T) {
	t.Parallel()

	// Build a payload with only a NetworkData TLV, no RLOC16.
	payload := tlv.TLV{
		Type:  ThreadTLVNetworkData,
		Value: []byte{0x01},
	}.Marshal()

	_, err := ParseServerDataRequest(payload)
	if err == nil {
		t.Fatal("expected error for missing RLOC16 TLV")
	}
}

func TestServerDataRequestInvalidTLV(t *testing.T) {
	t.Parallel()

	// Truncated TLV data.
	_, err := ParseServerDataRequest([]byte{0x02})
	if err == nil {
		t.Fatal("expected error for truncated TLV data")
	}
}

func TestServerDataRequestRLOC16WrongLength(t *testing.T) {
	t.Parallel()

	// RLOC16 TLV with 3 bytes instead of 2.
	payload := tlv.TLV{
		Type:  ThreadTLVRLOC16,
		Value: []byte{0x01, 0x02, 0x03},
	}.Marshal()

	_, err := ParseServerDataRequest(payload)
	if err == nil {
		t.Fatal("expected error for wrong-length RLOC16 TLV")
	}
}

// ---------------------------------------------------------------------------
// ServerDataService handler tests
// ---------------------------------------------------------------------------

func TestServerDataServiceSuccess(t *testing.T) {
	t.Parallel()

	leader := &mockNetworkDataLeader{}
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	svc := NewServerDataService(agent, leader)
	defer svc.Stop()

	nd := []byte{0xAA, 0xBB, 0xCC}
	req := &ServerDataRequest{
		RLOC16:      0x5400,
		NetworkData: nd,
	}

	engine.Receive(buildServerDataCON(2000, []byte{0x01}, req), tmfInfo())

	// Verify leader was called.
	leader.mu.Lock()
	defer leader.mu.Unlock()
	if leader.callCount != 1 {
		t.Fatalf("RegisterNetworkData call count = %d, want 1", leader.callCount)
	}
	if leader.lastRLOC16 != 0x5400 {
		t.Errorf("RLOC16 = 0x%04X, want 0x5400", leader.lastRLOC16)
	}
	if len(leader.lastData) != len(nd) {
		t.Fatalf("NetworkData len = %d, want %d", len(leader.lastData), len(nd))
	}
	for i, b := range leader.lastData {
		if b != nd[i] {
			t.Errorf("NetworkData[%d] = 0x%02X, want 0x%02X", i, b, nd[i])
		}
	}

	// Verify response: should be ACK + CodeChanged.
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if len(ms.sent) != 1 {
		t.Fatalf("sent count = %d, want 1", len(ms.sent))
	}
	resp, err := coap.ParseMessage(ms.sent[0])
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if resp.GetType() != coap.TypeAck {
		t.Errorf("response type = %d, want ACK (%d)", resp.GetType(), coap.TypeAck)
	}
	if resp.GetCode() != coap.CodeChanged {
		t.Errorf("response code = 0x%02X, want CodeChanged (0x%02X)", resp.GetCode(), coap.CodeChanged)
	}
	if resp.GetMessageID() != 2000 {
		t.Errorf("response message ID = %d, want 2000", resp.GetMessageID())
	}
}

func TestServerDataServiceEmptyNetworkData(t *testing.T) {
	t.Parallel()

	leader := &mockNetworkDataLeader{}
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	svc := NewServerDataService(agent, leader)
	defer svc.Stop()

	req := &ServerDataRequest{
		RLOC16:      0x1000,
		NetworkData: nil,
	}

	engine.Receive(buildServerDataCON(3000, []byte{0x02}, req), tmfInfo())

	leader.mu.Lock()
	defer leader.mu.Unlock()
	if leader.callCount != 1 {
		t.Fatalf("RegisterNetworkData call count = %d, want 1", leader.callCount)
	}
	if leader.lastRLOC16 != 0x1000 {
		t.Errorf("RLOC16 = 0x%04X, want 0x1000", leader.lastRLOC16)
	}
	if len(leader.lastData) != 0 {
		t.Errorf("NetworkData len = %d, want 0", len(leader.lastData))
	}

	// Should still get CodeChanged.
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if len(ms.sent) != 1 {
		t.Fatalf("sent count = %d, want 1", len(ms.sent))
	}
	resp, err := coap.ParseMessage(ms.sent[0])
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if resp.GetCode() != coap.CodeChanged {
		t.Errorf("response code = 0x%02X, want CodeChanged", resp.GetCode())
	}
}

func TestServerDataServiceRegistrationError(t *testing.T) {
	t.Parallel()

	leader := &mockNetworkDataLeader{
		returnError: errors.New("validation failed"),
	}
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	svc := NewServerDataService(agent, leader)
	defer svc.Stop()

	req := &ServerDataRequest{
		RLOC16:      0x5400,
		NetworkData: []byte{0xFF},
	}

	engine.Receive(buildServerDataCON(4000, []byte{0x03}, req), tmfInfo())

	// Leader was still called.
	leader.mu.Lock()
	defer leader.mu.Unlock()
	if leader.callCount != 1 {
		t.Fatalf("RegisterNetworkData call count = %d, want 1", leader.callCount)
	}

	// Should get a 5.00 Internal Server Error (not CodeChanged).
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if len(ms.sent) != 1 {
		t.Fatalf("sent count = %d, want 1", len(ms.sent))
	}
	resp, err := coap.ParseMessage(ms.sent[0])
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if resp.GetType() != coap.TypeAck {
		t.Errorf("response type = %d, want ACK", resp.GetType())
	}
	if resp.GetCode() != coap.CodeInternalError {
		t.Errorf("response code = 0x%02X, want CodeInternalError (0x%02X)", resp.GetCode(), coap.CodeInternalError)
	}
	if resp.GetMessageID() != 4000 {
		t.Errorf("response message ID = %d, want 4000", resp.GetMessageID())
	}
}

func TestServerDataServiceIgnoresNonConfirmable(t *testing.T) {
	t.Parallel()

	leader := &mockNetworkDataLeader{}
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	svc := NewServerDataService(agent, leader)
	defer svc.Stop()

	req := &ServerDataRequest{
		RLOC16:      0x5400,
		NetworkData: []byte{0x01},
	}

	engine.Receive(buildServerDataNON(5000, []byte{0x04}, req), tmfInfo())

	leader.mu.Lock()
	defer leader.mu.Unlock()
	if leader.callCount != 0 {
		t.Errorf("RegisterNetworkData call count = %d, want 0", leader.callCount)
	}

	ms.mu.Lock()
	defer ms.mu.Unlock()
	if len(ms.sent) != 0 {
		t.Errorf("sent count = %d, want 0", len(ms.sent))
	}
}

func TestServerDataServiceIgnoresInvalidPayload(t *testing.T) {
	t.Parallel()

	leader := &mockNetworkDataLeader{}
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	svc := NewServerDataService(agent, leader)
	defer svc.Stop()

	// Build a CON POST with garbage payload (not valid TLVs).
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 6000)
	_ = msg.SetToken([]byte{0x05})
	_ = msg.AppendURIPathOptions(PathForURI(URIServerData))
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload([]byte{0x02}) // truncated TLV
	engine.Receive(msg.GetBytes(), tmfInfo())

	leader.mu.Lock()
	defer leader.mu.Unlock()
	if leader.callCount != 0 {
		t.Errorf("RegisterNetworkData call count = %d, want 0", leader.callCount)
	}

	ms.mu.Lock()
	defer ms.mu.Unlock()
	if len(ms.sent) != 0 {
		t.Errorf("sent count = %d, want 0", len(ms.sent))
	}
}

func TestServerDataServiceStopUnregisters(t *testing.T) {
	t.Parallel()

	leader := &mockNetworkDataLeader{}
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	svc := NewServerDataService(agent, leader)
	svc.Stop()

	req := &ServerDataRequest{
		RLOC16:      0x5400,
		NetworkData: []byte{0x01},
	}

	engine.Receive(buildServerDataCON(7000, []byte{0x06}, req), tmfInfo())

	leader.mu.Lock()
	defer leader.mu.Unlock()
	if leader.callCount != 0 {
		t.Errorf("RegisterNetworkData call count = %d, want 0 after Stop", leader.callCount)
	}

	// After Stop, the engine should return 4.04 Not Found for unrecognized
	// URIs. Check that no CodeChanged was sent.
	ms.mu.Lock()
	defer ms.mu.Unlock()
	for _, raw := range ms.sent {
		resp, err := coap.ParseMessage(raw)
		if err != nil {
			continue
		}
		if resp.GetCode() == coap.CodeChanged {
			t.Error("received CodeChanged response after Stop")
		}
	}
}

func TestServerDataServiceHandlerRegistered(t *testing.T) {
	t.Parallel()

	leader := &mockNetworkDataLeader{}
	engine, _ := newTestEngine()
	agent := NewAgent(engine)
	svc := NewServerDataService(agent, leader)
	defer svc.Stop()

	// Verify the handler is registered by checking the agent's handler map.
	agent.mu.Lock()
	_, ok := agent.handlers[URIServerData]
	agent.mu.Unlock()
	if !ok {
		t.Error("URIServerData handler not registered")
	}
}

func TestServerDataServiceResponseMatchesMsgID(t *testing.T) {
	t.Parallel()

	leader := &mockNetworkDataLeader{}
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	svc := NewServerDataService(agent, leader)
	defer svc.Stop()

	// Send two requests with different message IDs.
	req := &ServerDataRequest{
		RLOC16:      0x2000,
		NetworkData: []byte{0xDE, 0xAD},
	}

	engine.Receive(buildServerDataCON(8001, []byte{0x10}, req), tmfInfo())
	engine.Receive(buildServerDataCON(8002, []byte{0x11}, req), tmfInfo())

	ms.mu.Lock()
	defer ms.mu.Unlock()
	if len(ms.sent) < 2 {
		t.Fatalf("sent count = %d, want >= 2", len(ms.sent))
	}

	resp1, err := coap.ParseMessage(ms.sent[0])
	if err != nil {
		t.Fatalf("ParseMessage[0]: %v", err)
	}
	resp2, err := coap.ParseMessage(ms.sent[1])
	if err != nil {
		t.Fatalf("ParseMessage[1]: %v", err)
	}

	if resp1.GetMessageID() != 8001 {
		t.Errorf("response[0] message ID = %d, want 8001", resp1.GetMessageID())
	}
	if resp2.GetMessageID() != 8002 {
		t.Errorf("response[1] message ID = %d, want 8002", resp2.GetMessageID())
	}
}

func TestServerDataServiceIgnoresGETRequest(t *testing.T) {
	t.Parallel()

	leader := &mockNetworkDataLeader{}
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	svc := NewServerDataService(agent, leader)
	defer svc.Stop()

	// Build a CON GET (not POST).
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 9000)
	_ = msg.SetToken([]byte{0x20})
	_ = msg.AppendURIPathOptions(PathForURI(URIServerData))
	rloc := [2]byte{}
	binary.BigEndian.PutUint16(rloc[:], 0x5400)
	payload := tlv.TLV{Type: ThreadTLVRLOC16, Value: rloc[:]}.Marshal()
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)
	engine.Receive(msg.GetBytes(), tmfInfo())

	leader.mu.Lock()
	defer leader.mu.Unlock()
	if leader.callCount != 0 {
		t.Errorf("RegisterNetworkData call count = %d, want 0 for GET", leader.callCount)
	}

	ms.mu.Lock()
	defer ms.mu.Unlock()
	// Handler should not have sent any response (the engine might send
	// its own 4.05 for unsupported method, but not CodeChanged).
	for _, raw := range ms.sent {
		resp, err := coap.ParseMessage(raw)
		if err != nil {
			continue
		}
		if resp.GetCode() == coap.CodeChanged {
			t.Error("received CodeChanged for GET request")
		}
	}
}

func TestServerDataServiceMissingPayload(t *testing.T) {
	t.Parallel()

	leader := &mockNetworkDataLeader{}
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	svc := NewServerDataService(agent, leader)
	defer svc.Stop()

	// CON POST with no payload at all.
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 9500)
	_ = msg.SetToken([]byte{0x30})
	_ = msg.AppendURIPathOptions(PathForURI(URIServerData))
	engine.Receive(msg.GetBytes(), tmfInfo())

	leader.mu.Lock()
	defer leader.mu.Unlock()
	if leader.callCount != 0 {
		t.Errorf("RegisterNetworkData call count = %d, want 0 for empty payload", leader.callCount)
	}

	ms.mu.Lock()
	defer ms.mu.Unlock()
	// No CodeChanged response expected.
	for _, raw := range ms.sent {
		resp, err := coap.ParseMessage(raw)
		if err != nil {
			continue
		}
		if resp.GetCode() == coap.CodeChanged {
			t.Error("received CodeChanged for request with no payload")
		}
	}
}
