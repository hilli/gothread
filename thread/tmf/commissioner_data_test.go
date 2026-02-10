// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tmf

import (
	"errors"
	"sync"
	"testing"

	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/thread/netdata"
)

// ---------------------------------------------------------------------------
// Mock commissioning data leader
// ---------------------------------------------------------------------------

type mockCommissioningDataLeader struct {
	mu          sync.Mutex
	lastData    []byte
	callCount   int
	returnError error
}

func (m *mockCommissioningDataLeader) SetCommissioningData(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if data != nil {
		m.lastData = make([]byte, len(data))
		copy(m.lastData, data)
	} else {
		m.lastData = nil
	}
	m.callCount++
	return m.returnError
}

// Compile-time interface checks.
var _ CommissioningDataLeader = (*mockCommissioningDataLeader)(nil)
var _ CommissioningDataLeader = (*netdata.Leader)(nil)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func buildCommissionerDataCON(msgID uint16, token, payload []byte) []byte {
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, msgID)
	_ = msg.SetToken(token)
	_ = msg.AppendURIPathOptions(PathForURI(URICommissionerData))
	if len(payload) > 0 {
		_ = msg.AppendPayloadMarker()
		_ = msg.AppendPayload(payload)
	}
	return msg.GetBytes()
}

func buildCommissionerDataNON(msgID uint16, token, payload []byte) []byte {
	msg := coap.NewMessage(coap.TypeNonConfirmable, coap.CodePost, msgID)
	_ = msg.SetToken(token)
	_ = msg.AppendURIPathOptions(PathForURI(URICommissionerData))
	if len(payload) > 0 {
		_ = msg.AppendPayloadMarker()
		_ = msg.AppendPayload(payload)
	}
	return msg.GetBytes()
}

// ---------------------------------------------------------------------------
// CommissionerDataService handler tests
// ---------------------------------------------------------------------------

func TestCommissionerDataServiceSuccess(t *testing.T) {
	t.Parallel()

	leader := &mockCommissioningDataLeader{}
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	svc := NewCommissionerDataService(agent, leader)
	defer svc.Stop()

	meshCop := []byte{0x0B, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	engine.Receive(buildCommissionerDataCON(2000, []byte{0x01}, meshCop), tmfInfo())

	// Verify leader was called with the raw MeshCoP bytes.
	leader.mu.Lock()
	defer leader.mu.Unlock()
	if leader.callCount != 1 {
		t.Fatalf("SetCommissioningData call count = %d, want 1", leader.callCount)
	}
	if len(leader.lastData) != len(meshCop) {
		t.Fatalf("lastData len = %d, want %d", len(leader.lastData), len(meshCop))
	}
	for i, b := range leader.lastData {
		if b != meshCop[i] {
			t.Errorf("lastData[%d] = 0x%02X, want 0x%02X", i, b, meshCop[i])
		}
	}

	// Verify response: ACK + CodeChanged.
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

func TestCommissionerDataServiceEmptyPayload(t *testing.T) {
	t.Parallel()

	leader := &mockCommissioningDataLeader{}
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	svc := NewCommissionerDataService(agent, leader)
	defer svc.Stop()

	// CON POST with no payload.
	engine.Receive(buildCommissionerDataCON(3000, []byte{0x02}, nil), tmfInfo())

	leader.mu.Lock()
	defer leader.mu.Unlock()
	if leader.callCount != 1 {
		t.Fatalf("SetCommissioningData call count = %d, want 1", leader.callCount)
	}
	if len(leader.lastData) != 0 {
		t.Errorf("lastData len = %d, want 0", len(leader.lastData))
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

func TestCommissionerDataServiceError(t *testing.T) {
	t.Parallel()

	leader := &mockCommissioningDataLeader{
		returnError: errors.New("storage full"),
	}
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	svc := NewCommissionerDataService(agent, leader)
	defer svc.Stop()

	engine.Receive(buildCommissionerDataCON(4000, []byte{0x03}, []byte{0xFF}), tmfInfo())

	// Leader was still called.
	leader.mu.Lock()
	defer leader.mu.Unlock()
	if leader.callCount != 1 {
		t.Fatalf("SetCommissioningData call count = %d, want 1", leader.callCount)
	}

	// Should get a 5.00 Internal Server Error.
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

func TestCommissionerDataServiceIgnoresNonConfirmable(t *testing.T) {
	t.Parallel()

	leader := &mockCommissioningDataLeader{}
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	svc := NewCommissionerDataService(agent, leader)
	defer svc.Stop()

	engine.Receive(buildCommissionerDataNON(5000, []byte{0x04}, []byte{0x01}), tmfInfo())

	leader.mu.Lock()
	defer leader.mu.Unlock()
	if leader.callCount != 0 {
		t.Errorf("SetCommissioningData call count = %d, want 0", leader.callCount)
	}

	ms.mu.Lock()
	defer ms.mu.Unlock()
	if len(ms.sent) != 0 {
		t.Errorf("sent count = %d, want 0", len(ms.sent))
	}
}

func TestCommissionerDataServiceIgnoresGET(t *testing.T) {
	t.Parallel()

	leader := &mockCommissioningDataLeader{}
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	svc := NewCommissionerDataService(agent, leader)
	defer svc.Stop()

	// Build a CON GET (not POST).
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodeGet, 9000)
	_ = msg.SetToken([]byte{0x20})
	_ = msg.AppendURIPathOptions(PathForURI(URICommissionerData))
	engine.Receive(msg.GetBytes(), tmfInfo())

	leader.mu.Lock()
	defer leader.mu.Unlock()
	if leader.callCount != 0 {
		t.Errorf("SetCommissioningData call count = %d, want 0 for GET", leader.callCount)
	}

	ms.mu.Lock()
	defer ms.mu.Unlock()
	// Handler should not have sent CodeChanged.
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

func TestCommissionerDataServiceStopUnregisters(t *testing.T) {
	t.Parallel()

	leader := &mockCommissioningDataLeader{}
	engine, ms := newTestEngine()
	agent := NewAgent(engine)
	svc := NewCommissionerDataService(agent, leader)
	svc.Stop()

	engine.Receive(buildCommissionerDataCON(7000, []byte{0x06}, []byte{0x01}), tmfInfo())

	leader.mu.Lock()
	defer leader.mu.Unlock()
	if leader.callCount != 0 {
		t.Errorf("SetCommissioningData call count = %d, want 0 after Stop", leader.callCount)
	}

	// No CodeChanged response expected.
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

func TestCommissionerDataServiceHandlerRegistered(t *testing.T) {
	t.Parallel()

	leader := &mockCommissioningDataLeader{}
	engine, _ := newTestEngine()
	agent := NewAgent(engine)
	svc := NewCommissionerDataService(agent, leader)
	defer svc.Stop()

	// Verify the handler is registered.
	agent.mu.Lock()
	_, ok := agent.handlers[URICommissionerData]
	agent.mu.Unlock()
	if !ok {
		t.Error("URICommissionerData handler not registered")
	}
}
