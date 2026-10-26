// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"sync"
	"testing"
	"time"

	"github.com/hilli/gothread/errors"
)

// =========================================================================
// Mock transport implementations
// =========================================================================

// mockClientTransport is a mock HTClientTransport for testing the client.
type mockClientTransport struct {
	mu             sync.Mutex
	answerHandler  func(payload []byte, senderRloc16 uint16)
	lastPeerRloc16 uint16
	lastURIPath    string
	lastPayload    []byte
	sendErr        error
	sendCount      int
}

func (m *mockClientTransport) SendNonPost(peerRloc16 uint16, uriPath string, payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastPeerRloc16 = peerRloc16
	m.lastURIPath = uriPath
	m.lastPayload = make([]byte, len(payload))
	copy(m.lastPayload, payload)
	m.sendCount++
	return m.sendErr
}

func (m *mockClientTransport) RegisterAnswerHandler(handler func(payload []byte, senderRloc16 uint16)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.answerHandler = handler
}

func (m *mockClientTransport) UnregisterAnswerHandler() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.answerHandler = nil
}

// deliverAnswer simulates receiving an answer from the remote device.
func (m *mockClientTransport) deliverAnswer(payload []byte, senderRloc16 uint16) {
	m.mu.Lock()
	h := m.answerHandler
	m.mu.Unlock()
	if h != nil {
		h(payload, senderRloc16)
	}
}

// mockServerTransport is a mock HTServerTransport for testing the server.
type mockServerTransport struct {
	mu           sync.Mutex
	queryHandler func(payload []byte, senderRloc16 uint16)
	sentAnswers  []mockSentAnswer
	sendErr      error
}

type mockSentAnswer struct {
	PeerRloc16  uint16
	URIPath     string
	Payload     []byte
	RespHandler func(err error, peerRloc16 uint16)
}

func (m *mockServerTransport) RegisterQueryHandler(handler func(payload []byte, senderRloc16 uint16)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queryHandler = handler
}

func (m *mockServerTransport) UnregisterQueryHandler() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queryHandler = nil
}

func (m *mockServerTransport) SendConPost(peerRloc16 uint16, uriPath string, payload []byte,
	responseHandler func(err error, peerRloc16 uint16)) error {

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sendErr != nil {
		return m.sendErr
	}
	p := make([]byte, len(payload))
	copy(p, payload)
	m.sentAnswers = append(m.sentAnswers, mockSentAnswer{
		PeerRloc16:  peerRloc16,
		URIPath:     uriPath,
		Payload:     p,
		RespHandler: responseHandler,
	})
	return nil
}

func (m *mockServerTransport) deliverQuery(payload []byte, senderRloc16 uint16) {
	m.mu.Lock()
	h := m.queryHandler
	m.mu.Unlock()
	if h != nil {
		h(payload, senderRloc16)
	}
}

// mockHistoryProvider provides canned history data for the server.
type mockHistoryProvider struct {
	entries []HistoryNetworkInfoEntry
}

func (p *mockHistoryProvider) IterateNetworkInfo() []HistoryNetworkInfoEntry {
	return p.entries
}

// =========================================================================
// Helper: build a complete answer payload
// =========================================================================

func buildAnswerPayload(queryID, answerIndex uint16, isLast bool, entries []*NetworkInfoTlv) []byte {
	var buf []byte
	buf = append(buf, MarshalQueryIDTlv(queryID)...)
	buf = append(buf, MarshalAnswerTlv(&AnswerTlv{Index: answerIndex, IsLast: isLast})...)
	for _, e := range entries {
		buf = append(buf, MarshalNetworkInfoTlv(e)...)
	}
	if isLast {
		buf = append(buf, MarshalEmptyNetworkInfoTlv()...)
	}
	return buf
}

// =========================================================================
// Client tests
// =========================================================================

func TestHTClientQueryNetInfo(t *testing.T) {
	t.Parallel()

	transport := &mockClientTransport{}
	client := NewHTClient(transport)
	defer client.Close()

	var received []*NetworkInfoTlv
	var finalErr error
	done := make(chan struct{})

	err := client.QueryNetInfo(0x1234, 10, 5000, func(err error, info *NetworkInfoTlv, entryAge uint32) {
		if err == errors.ErrPending {
			received = append(received, info)
			return
		}
		finalErr = err
		close(done)
	})

	if err != nil {
		t.Fatalf("QueryNetInfo() error = %v", err)
	}

	if !client.IsActive() {
		t.Fatal("client should be active after query")
	}

	// Verify transport was called correctly.
	transport.mu.Lock()
	if transport.lastURIPath != "h/qy" {
		t.Errorf("expected URI path h/qy, got %s", transport.lastURIPath)
	}
	if transport.lastPeerRloc16 != 0x1234 {
		t.Errorf("expected peer RLOC16 0x1234, got 0x%04x", transport.lastPeerRloc16)
	}
	transport.mu.Unlock()

	// Build and deliver an answer with 2 entries.
	entries := []*NetworkInfoTlv{
		{EntryAge: 1000, Role: 2, Mode: 0x0F, Rloc16: 0x1234, PartitionId: 42},
		{EntryAge: 2000, Role: 1, Mode: 0x0E, Rloc16: 0x1234, PartitionId: 42},
	}
	// Read the queryID from the transport payload.
	qidTlvType, qidValue, _, _ := ParseHTTlv(transport.lastPayload)
	if qidTlvType != HTTlvQueryID {
		t.Fatalf("expected QueryID TLV, got type %d", qidTlvType)
	}
	queryID, _ := ParseQueryIDTlv(qidValue)

	answer := buildAnswerPayload(queryID, 0, true, entries)
	transport.deliverAnswer(answer, 0x1234)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for callback")
	}

	if finalErr != nil {
		t.Errorf("expected nil final error, got %v", finalErr)
	}
	if len(received) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(received))
	}
	if received[0].EntryAge != 1000 {
		t.Errorf("entry[0].EntryAge = %d, want 1000", received[0].EntryAge)
	}
	if received[1].Role != 1 {
		t.Errorf("entry[1].Role = %d, want 1", received[1].Role)
	}
}

func TestHTClientQueryBusy(t *testing.T) {
	t.Parallel()

	transport := &mockClientTransport{}
	client := NewHTClient(transport)
	defer client.Close()

	// First query — succeeds.
	err := client.QueryNetInfo(0x1000, 0, 0, func(error, *NetworkInfoTlv, uint32) {})
	if err != nil {
		t.Fatalf("first QueryNetInfo() error = %v", err)
	}

	// Second query — should fail with ErrBusy.
	err = client.QueryNetInfo(0x2000, 0, 0, func(error, *NetworkInfoTlv, uint32) {})
	if err != errors.ErrBusy {
		t.Errorf("expected ErrBusy, got %v", err)
	}
}

func TestHTClientQueryTransportError(t *testing.T) {
	t.Parallel()

	transport := &mockClientTransport{sendErr: errors.ErrNoBufs}
	client := NewHTClient(transport)
	defer client.Close()

	err := client.QueryNetInfo(0x1000, 0, 0, func(error, *NetworkInfoTlv, uint32) {})
	if err != errors.ErrNoBufs {
		t.Errorf("expected ErrNoBufs, got %v", err)
	}

	// Should not be active since send failed.
	if client.IsActive() {
		t.Error("client should not be active after send failure")
	}
}

func TestHTClientTimeout(t *testing.T) {
	t.Parallel()

	transport := &mockClientTransport{}
	client := NewHTClient(transport)
	defer client.Close()

	var finalErr error
	done := make(chan struct{})

	err := client.QueryNetInfo(0x1000, 0, 0, func(err error, info *NetworkInfoTlv, entryAge uint32) {
		if err != errors.ErrPending {
			finalErr = err
			close(done)
		}
	})
	if err != nil {
		t.Fatalf("QueryNetInfo() error = %v", err)
	}

	// Override the timer to fire quickly for testing.
	client.mu.Lock()
	if client.timer != nil {
		client.timer.Stop()
	}
	client.timer = time.AfterFunc(10*time.Millisecond, client.handleTimer)
	client.mu.Unlock()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for timeout callback")
	}

	if finalErr != errors.ErrResponseTimeout {
		t.Errorf("expected ErrResponseTimeout, got %v", finalErr)
	}

	if client.IsActive() {
		t.Error("client should not be active after timeout")
	}
}

func TestHTClientCancelQuery(t *testing.T) {
	t.Parallel()

	transport := &mockClientTransport{}
	client := NewHTClient(transport)
	defer client.Close()

	err := client.QueryNetInfo(0x1000, 0, 0, func(error, *NetworkInfoTlv, uint32) {
		t.Error("callback should not be called after cancel")
	})
	if err != nil {
		t.Fatalf("QueryNetInfo() error = %v", err)
	}

	if !client.IsActive() {
		t.Fatal("client should be active")
	}

	client.CancelQuery()

	if client.IsActive() {
		t.Error("client should not be active after cancel")
	}
}

func TestHTClientWrongSender(t *testing.T) {
	t.Parallel()

	transport := &mockClientTransport{}
	client := NewHTClient(transport)
	defer client.Close()

	callbackCalled := false
	err := client.QueryNetInfo(0x1000, 0, 0, func(err error, info *NetworkInfoTlv, entryAge uint32) {
		callbackCalled = true
	})
	if err != nil {
		t.Fatalf("QueryNetInfo() error = %v", err)
	}

	// Read queryID from the sent payload.
	_, qidValue, _, _ := ParseHTTlv(transport.lastPayload)
	queryID, _ := ParseQueryIDTlv(qidValue)

	// Deliver answer from wrong RLOC16 — should be ignored.
	answer := buildAnswerPayload(queryID, 0, true, nil)
	transport.deliverAnswer(answer, 0x2000)

	// Client should still be active.
	if !client.IsActive() {
		t.Error("client should still be active after wrong-sender answer")
	}
	if callbackCalled {
		t.Error("callback should not have been called")
	}
}

func TestHTClientWrongQueryID(t *testing.T) {
	t.Parallel()

	transport := &mockClientTransport{}
	client := NewHTClient(transport)
	defer client.Close()

	callbackCalled := false
	err := client.QueryNetInfo(0x1000, 0, 0, func(err error, info *NetworkInfoTlv, entryAge uint32) {
		callbackCalled = true
	})
	if err != nil {
		t.Fatalf("QueryNetInfo() error = %v", err)
	}

	// Deliver answer with wrong queryID — should be ignored.
	answer := buildAnswerPayload(0xFFFF, 0, true, nil)
	transport.deliverAnswer(answer, 0x1000)

	if !client.IsActive() {
		t.Error("client should still be active after wrong-queryID answer")
	}
	if callbackCalled {
		t.Error("callback should not have been called")
	}
}

func TestHTClientWrongAnswerIndex(t *testing.T) {
	t.Parallel()

	transport := &mockClientTransport{}
	client := NewHTClient(transport)
	defer client.Close()

	var finalErr error
	done := make(chan struct{})

	err := client.QueryNetInfo(0x1000, 0, 0, func(err error, info *NetworkInfoTlv, entryAge uint32) {
		if err != errors.ErrPending {
			finalErr = err
			close(done)
		}
	})
	if err != nil {
		t.Fatalf("QueryNetInfo() error = %v", err)
	}

	_, qidValue, _, _ := ParseHTTlv(transport.lastPayload)
	queryID, _ := ParseQueryIDTlv(qidValue)

	// Deliver answer with wrong index (1 instead of expected 0).
	answer := buildAnswerPayload(queryID, 1, true, nil)
	transport.deliverAnswer(answer, 0x1000)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}

	if finalErr != errors.ErrResponseTimeout {
		t.Errorf("expected ErrResponseTimeout on wrong index, got %v", finalErr)
	}
}

func TestHTClientMultipleAnswers(t *testing.T) {
	t.Parallel()

	transport := &mockClientTransport{}
	client := NewHTClient(transport)
	defer client.Close()

	var received []*NetworkInfoTlv
	var finalErr error
	done := make(chan struct{})

	err := client.QueryNetInfo(0x1000, 0, 0, func(err error, info *NetworkInfoTlv, entryAge uint32) {
		if err == errors.ErrPending {
			received = append(received, info)
			return
		}
		finalErr = err
		close(done)
	})
	if err != nil {
		t.Fatalf("QueryNetInfo() error = %v", err)
	}

	_, qidValue, _, _ := ParseHTTlv(transport.lastPayload)
	queryID, _ := ParseQueryIDTlv(qidValue)

	// Answer 0: one entry, not last.
	entry1 := &NetworkInfoTlv{EntryAge: 100, Role: 2, Mode: 0x0F, Rloc16: 0x1000, PartitionId: 1}
	ans0 := buildAnswerPayload(queryID, 0, false, []*NetworkInfoTlv{entry1})
	transport.deliverAnswer(ans0, 0x1000)

	// Answer 1: one entry, last.
	entry2 := &NetworkInfoTlv{EntryAge: 200, Role: 1, Mode: 0x0E, Rloc16: 0x1000, PartitionId: 1}
	ans1 := buildAnswerPayload(queryID, 1, true, []*NetworkInfoTlv{entry2})
	transport.deliverAnswer(ans1, 0x1000)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}

	if finalErr != nil {
		t.Errorf("expected nil final error, got %v", finalErr)
	}
	if len(received) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(received))
	}
	if received[0].EntryAge != 100 {
		t.Errorf("entry[0].EntryAge = %d, want 100", received[0].EntryAge)
	}
	if received[1].EntryAge != 200 {
		t.Errorf("entry[1].EntryAge = %d, want 200", received[1].EntryAge)
	}
}

func TestHTClientParseError(t *testing.T) {
	t.Parallel()

	transport := &mockClientTransport{}
	client := NewHTClient(transport)
	defer client.Close()

	var finalErr error
	done := make(chan struct{})

	err := client.QueryNetInfo(0x1000, 0, 0, func(err error, info *NetworkInfoTlv, entryAge uint32) {
		if err != errors.ErrPending {
			finalErr = err
			close(done)
		}
	})
	if err != nil {
		t.Fatalf("QueryNetInfo() error = %v", err)
	}

	// Deliver malformed answer: valid header TLVs but truncated NetworkInfo.
	_, qidValue, _, _ := ParseHTTlv(transport.lastPayload)
	queryID, _ := ParseQueryIDTlv(qidValue)

	var buf []byte
	buf = append(buf, MarshalQueryIDTlv(queryID)...)
	buf = append(buf, MarshalAnswerTlv(&AnswerTlv{Index: 0, IsLast: true})...)
	// Append a NetworkInfoTlv header with length 12 but only 5 bytes of data.
	buf = append(buf, HTTlvNetworkInfo, 12, 0, 0, 0, 0, 0)
	transport.deliverAnswer(buf, 0x1000)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}

	if finalErr != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", finalErr)
	}
}

func TestHTClientEmptyAnswer(t *testing.T) {
	t.Parallel()

	transport := &mockClientTransport{}
	client := NewHTClient(transport)
	defer client.Close()

	var received []*NetworkInfoTlv
	var finalErr error
	done := make(chan struct{})

	err := client.QueryNetInfo(0x1000, 0, 0, func(err error, info *NetworkInfoTlv, entryAge uint32) {
		if err == errors.ErrPending {
			received = append(received, info)
			return
		}
		finalErr = err
		close(done)
	})
	if err != nil {
		t.Fatalf("QueryNetInfo() error = %v", err)
	}

	_, qidValue, _, _ := ParseHTTlv(transport.lastPayload)
	queryID, _ := ParseQueryIDTlv(qidValue)

	// Answer with only the empty terminator — no entries.
	answer := buildAnswerPayload(queryID, 0, true, nil)
	transport.deliverAnswer(answer, 0x1000)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}

	if finalErr != nil {
		t.Errorf("expected nil final error, got %v", finalErr)
	}
	if len(received) != 0 {
		t.Errorf("expected 0 entries, got %d", len(received))
	}
}

func TestHTClientClose(t *testing.T) {
	t.Parallel()

	transport := &mockClientTransport{}
	client := NewHTClient(transport)

	err := client.QueryNetInfo(0x1000, 0, 0, func(error, *NetworkInfoTlv, uint32) {})
	if err != nil {
		t.Fatalf("QueryNetInfo() error = %v", err)
	}

	client.Close()

	if client.IsActive() {
		t.Error("client should not be active after Close")
	}

	// Handler should be unregistered.
	transport.mu.Lock()
	if transport.answerHandler != nil {
		t.Error("answer handler should be nil after Close")
	}
	transport.mu.Unlock()
}

// =========================================================================
// Server tests
// =========================================================================

func TestHTServerBasicQuery(t *testing.T) {
	t.Parallel()

	transport := &mockServerTransport{}
	provider := &mockHistoryProvider{
		entries: []HistoryNetworkInfoEntry{
			{Info: NetworkInfoTlv{EntryAge: 100, Role: 2, Mode: 0x0F, Rloc16: 0xABCD, PartitionId: 1}, EntryAge: 100},
			{Info: NetworkInfoTlv{EntryAge: 200, Role: 1, Mode: 0x0E, Rloc16: 0xABCD, PartitionId: 1}, EntryAge: 200},
		},
	}
	server := NewHTServer(transport, provider)
	defer server.Close()

	// Build query payload: QueryID + Request for NetworkInfo.
	var query []byte
	query = append(query, MarshalQueryIDTlv(42)...)
	query = append(query, MarshalRequestTlv(&RequestTlv{TlvType: HTTlvNetworkInfo, NumEntries: 0, MaxEntryAge: 0})...)

	// Deliver the query.
	transport.deliverQuery(query, 0x5678)

	// Server should have sent one answer.
	transport.mu.Lock()
	if len(transport.sentAnswers) != 1 {
		t.Fatalf("expected 1 sent answer, got %d", len(transport.sentAnswers))
	}
	ans := transport.sentAnswers[0]
	transport.mu.Unlock()

	if ans.PeerRloc16 != 0x5678 {
		t.Errorf("answer peer RLOC16 = 0x%04x, want 0x5678", ans.PeerRloc16)
	}
	if ans.URIPath != "h/an" {
		t.Errorf("answer URI path = %q, want h/an", ans.URIPath)
	}

	// Parse the answer payload.
	offset := 0
	var foundQueryID bool
	var answerTlv *AnswerTlv
	var netInfoEntries []*NetworkInfoTlv
	var foundTerminator bool

	for offset < len(ans.Payload) {
		tlvType, value, consumed, err := ParseHTTlv(ans.Payload[offset:])
		if err != nil {
			t.Fatalf("ParseHTTlv at offset %d: %v", offset, err)
		}
		offset += consumed

		switch tlvType {
		case HTTlvQueryID:
			qid, _ := ParseQueryIDTlv(value)
			if qid != 42 {
				t.Errorf("QueryID = %d, want 42", qid)
			}
			foundQueryID = true
		case HTTlvAnswer:
			a, _ := ParseAnswerTlv(value)
			answerTlv = a
		case HTTlvNetworkInfo:
			if len(value) == 0 {
				foundTerminator = true
			} else {
				info, _ := ParseNetworkInfoTlv(value)
				netInfoEntries = append(netInfoEntries, info)
			}
		}
	}

	if !foundQueryID {
		t.Error("expected QueryID TLV in answer")
	}
	if answerTlv == nil {
		t.Fatal("expected AnswerTlv in answer")
	}
	if !answerTlv.IsLast {
		t.Error("expected IsLast=true in single answer")
	}
	if !foundTerminator {
		t.Error("expected empty NetworkInfo terminator TLV")
	}
	if len(netInfoEntries) != 2 {
		t.Fatalf("expected 2 NetworkInfo entries, got %d", len(netInfoEntries))
	}
	if netInfoEntries[0].EntryAge != 100 {
		t.Errorf("entry[0].EntryAge = %d, want 100", netInfoEntries[0].EntryAge)
	}
	if netInfoEntries[1].Role != 1 {
		t.Errorf("entry[1].Role = %d, want 1", netInfoEntries[1].Role)
	}
}

func TestHTServerMaxEntries(t *testing.T) {
	t.Parallel()

	transport := &mockServerTransport{}
	provider := &mockHistoryProvider{
		entries: []HistoryNetworkInfoEntry{
			{Info: NetworkInfoTlv{EntryAge: 100}, EntryAge: 100},
			{Info: NetworkInfoTlv{EntryAge: 200}, EntryAge: 200},
			{Info: NetworkInfoTlv{EntryAge: 300}, EntryAge: 300},
		},
	}
	server := NewHTServer(transport, provider)
	defer server.Close()

	// Request only 2 entries.
	var query []byte
	query = append(query, MarshalRequestTlv(&RequestTlv{TlvType: HTTlvNetworkInfo, NumEntries: 2, MaxEntryAge: 0})...)

	transport.deliverQuery(query, 0x1000)

	transport.mu.Lock()
	if len(transport.sentAnswers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(transport.sentAnswers))
	}
	ans := transport.sentAnswers[0]
	transport.mu.Unlock()

	// Count NetworkInfo entries in the answer.
	offset := 0
	count := 0
	for offset < len(ans.Payload) {
		tlvType, value, consumed, err := ParseHTTlv(ans.Payload[offset:])
		if err != nil {
			break
		}
		offset += consumed
		if tlvType == HTTlvNetworkInfo && len(value) > 0 {
			count++
		}
	}

	if count != 2 {
		t.Errorf("expected 2 entries (maxEntries=2), got %d", count)
	}
}

func TestHTServerMaxEntryAge(t *testing.T) {
	t.Parallel()

	transport := &mockServerTransport{}
	provider := &mockHistoryProvider{
		entries: []HistoryNetworkInfoEntry{
			{Info: NetworkInfoTlv{EntryAge: 100}, EntryAge: 100},
			{Info: NetworkInfoTlv{EntryAge: 500}, EntryAge: 500},
			{Info: NetworkInfoTlv{EntryAge: 1000}, EntryAge: 1000},
		},
	}
	server := NewHTServer(transport, provider)
	defer server.Close()

	// Request entries with max age 600ms.
	var query []byte
	query = append(query, MarshalRequestTlv(&RequestTlv{TlvType: HTTlvNetworkInfo, NumEntries: 0, MaxEntryAge: 600})...)

	transport.deliverQuery(query, 0x1000)

	transport.mu.Lock()
	if len(transport.sentAnswers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(transport.sentAnswers))
	}
	ans := transport.sentAnswers[0]
	transport.mu.Unlock()

	offset := 0
	count := 0
	for offset < len(ans.Payload) {
		tlvType, value, consumed, err := ParseHTTlv(ans.Payload[offset:])
		if err != nil {
			break
		}
		offset += consumed
		if tlvType == HTTlvNetworkInfo && len(value) > 0 {
			count++
		}
	}

	if count != 2 {
		t.Errorf("expected 2 entries (maxAge=600), got %d", count)
	}
}

func TestHTServerNoQueryID(t *testing.T) {
	t.Parallel()

	transport := &mockServerTransport{}
	provider := &mockHistoryProvider{
		entries: []HistoryNetworkInfoEntry{
			{Info: NetworkInfoTlv{EntryAge: 100}, EntryAge: 100},
		},
	}
	server := NewHTServer(transport, provider)
	defer server.Close()

	// Query without QueryID TLV.
	var query []byte
	query = append(query, MarshalRequestTlv(&RequestTlv{TlvType: HTTlvNetworkInfo, NumEntries: 0, MaxEntryAge: 0})...)

	transport.deliverQuery(query, 0x1000)

	transport.mu.Lock()
	if len(transport.sentAnswers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(transport.sentAnswers))
	}
	ans := transport.sentAnswers[0]
	transport.mu.Unlock()

	// Should NOT contain a QueryID TLV.
	offset := 0
	foundQueryID := false
	for offset < len(ans.Payload) {
		tlvType, _, consumed, err := ParseHTTlv(ans.Payload[offset:])
		if err != nil {
			break
		}
		offset += consumed
		if tlvType == HTTlvQueryID {
			foundQueryID = true
		}
	}

	if foundQueryID {
		t.Error("answer should not contain QueryID when query didn't have one")
	}
}

func TestHTServerEmptyHistory(t *testing.T) {
	t.Parallel()

	transport := &mockServerTransport{}
	provider := &mockHistoryProvider{entries: nil}
	server := NewHTServer(transport, provider)
	defer server.Close()

	var query []byte
	query = append(query, MarshalQueryIDTlv(99)...)
	query = append(query, MarshalRequestTlv(&RequestTlv{TlvType: HTTlvNetworkInfo, NumEntries: 0, MaxEntryAge: 0})...)

	transport.deliverQuery(query, 0x1000)

	transport.mu.Lock()
	if len(transport.sentAnswers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(transport.sentAnswers))
	}
	ans := transport.sentAnswers[0]
	transport.mu.Unlock()

	// Should contain empty terminator but no data entries.
	offset := 0
	dataCount := 0
	terminatorFound := false
	for offset < len(ans.Payload) {
		tlvType, value, consumed, err := ParseHTTlv(ans.Payload[offset:])
		if err != nil {
			break
		}
		offset += consumed
		if tlvType == HTTlvNetworkInfo {
			if len(value) == 0 {
				terminatorFound = true
			} else {
				dataCount++
			}
		}
	}

	if dataCount != 0 {
		t.Errorf("expected 0 data entries, got %d", dataCount)
	}
	if !terminatorFound {
		t.Error("expected empty NetworkInfo terminator")
	}
}

func TestHTServerAnswerChaining(t *testing.T) {
	t.Parallel()

	transport := &mockServerTransport{}

	// Create enough entries that the answer should split.
	// Each NetworkInfoTlv is 14 bytes. With threshold 800, we need
	// about 800/14 ≈ 58 entries (plus some header overhead).
	var entries []HistoryNetworkInfoEntry
	for i := 0; i < 80; i++ {
		entries = append(entries, HistoryNetworkInfoEntry{
			Info: NetworkInfoTlv{
				EntryAge:    uint32(i * 100),
				Role:        2,
				Mode:        0x0F,
				Rloc16:      0x1000,
				PartitionId: 42,
			},
			EntryAge: uint32(i * 100),
		})
	}

	provider := &mockHistoryProvider{entries: entries}
	server := NewHTServer(transport, provider)
	defer server.Close()

	var query []byte
	query = append(query, MarshalQueryIDTlv(7)...)
	query = append(query, MarshalRequestTlv(&RequestTlv{TlvType: HTTlvNetworkInfo, NumEntries: 0, MaxEntryAge: 0})...)

	transport.deliverQuery(query, 0x2000)

	// The first answer is sent immediately.
	transport.mu.Lock()
	if len(transport.sentAnswers) < 1 {
		t.Fatalf("expected at least 1 sent answer, got %d", len(transport.sentAnswers))
	}

	firstAnswer := transport.sentAnswers[0]
	transport.mu.Unlock()

	// The first answer should NOT be marked as last.
	offset := 0
	var firstAnswerTlv *AnswerTlv
	for offset < len(firstAnswer.Payload) {
		tlvType, value, consumed, err := ParseHTTlv(firstAnswer.Payload[offset:])
		if err != nil {
			break
		}
		offset += consumed
		if tlvType == HTTlvAnswer {
			a, _ := ParseAnswerTlv(value)
			firstAnswerTlv = a
		}
	}

	if firstAnswerTlv == nil {
		t.Fatal("expected AnswerTlv in first answer")
	}
	if firstAnswerTlv.IsLast {
		t.Error("first answer should NOT be marked as last when there are many entries")
	}
	if firstAnswerTlv.Index != 0 {
		t.Errorf("first answer index = %d, want 0", firstAnswerTlv.Index)
	}

	// Simulate successful ACK — trigger sending the next answer.
	firstAnswer.RespHandler(nil, 0x2000)

	transport.mu.Lock()
	totalAnswers := len(transport.sentAnswers)
	transport.mu.Unlock()

	if totalAnswers < 2 {
		t.Errorf("expected at least 2 answers after ACK, got %d", totalAnswers)
	}
}

func TestHTServerAnswerChainError(t *testing.T) {
	t.Parallel()

	transport := &mockServerTransport{}

	// Create enough entries to split.
	var entries []HistoryNetworkInfoEntry
	for i := 0; i < 80; i++ {
		entries = append(entries, HistoryNetworkInfoEntry{
			Info:     NetworkInfoTlv{EntryAge: uint32(i * 100), Role: 2, Rloc16: 0x1000, PartitionId: 1},
			EntryAge: uint32(i * 100),
		})
	}

	provider := &mockHistoryProvider{entries: entries}
	server := NewHTServer(transport, provider)
	defer server.Close()

	var query []byte
	query = append(query, MarshalQueryIDTlv(8)...)
	query = append(query, MarshalRequestTlv(&RequestTlv{TlvType: HTTlvNetworkInfo})...)

	transport.deliverQuery(query, 0x3000)

	transport.mu.Lock()
	if len(transport.sentAnswers) < 1 {
		t.Fatalf("expected at least 1 answer, got %d", len(transport.sentAnswers))
	}
	firstAnswer := transport.sentAnswers[0]
	transport.mu.Unlock()

	// Simulate error response — remaining answers should be abandoned.
	firstAnswer.RespHandler(errors.ErrResponseTimeout, 0x3000)

	transport.mu.Lock()
	// Only the first answer should have been sent; no more after error.
	totalAfterError := len(transport.sentAnswers)
	transport.mu.Unlock()

	if totalAfterError != 1 {
		t.Errorf("expected only 1 answer after error (no more chained), got %d", totalAfterError)
	}
}

func TestHTServerClose(t *testing.T) {
	t.Parallel()

	transport := &mockServerTransport{}
	provider := &mockHistoryProvider{}
	server := NewHTServer(transport, provider)

	server.Close()

	transport.mu.Lock()
	if transport.queryHandler != nil {
		t.Error("query handler should be nil after Close")
	}
	transport.mu.Unlock()
}

// =========================================================================
// Integration test: client + server via loopback
// =========================================================================

// loopbackTransport connects a client and server transport together.
type loopbackTransport struct {
	mu            sync.Mutex
	answerHandler func(payload []byte, senderRloc16 uint16)
	queryHandler  func(payload []byte, senderRloc16 uint16)
	localRloc16   uint16
	sendConErr    error
}

func (l *loopbackTransport) SendNonPost(peerRloc16 uint16, uriPath string, payload []byte) error {
	if uriPath == "h/qy" {
		l.mu.Lock()
		h := l.queryHandler
		l.mu.Unlock()
		if h != nil {
			// Simulate async delivery.
			go h(payload, l.localRloc16)
		}
	}
	return nil
}

func (l *loopbackTransport) RegisterAnswerHandler(handler func(payload []byte, senderRloc16 uint16)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.answerHandler = handler
}

func (l *loopbackTransport) UnregisterAnswerHandler() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.answerHandler = nil
}

func (l *loopbackTransport) RegisterQueryHandler(handler func(payload []byte, senderRloc16 uint16)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.queryHandler = handler
}

func (l *loopbackTransport) UnregisterQueryHandler() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.queryHandler = nil
}

func (l *loopbackTransport) SendConPost(peerRloc16 uint16, uriPath string, payload []byte,
	responseHandler func(err error, peerRloc16 uint16)) error {

	l.mu.Lock()
	sendErr := l.sendConErr
	l.mu.Unlock()

	if sendErr != nil {
		return sendErr
	}

	if uriPath == "h/an" {
		l.mu.Lock()
		h := l.answerHandler
		l.mu.Unlock()
		if h != nil {
			// Deliver the answer to the client.
			h(payload, l.localRloc16)
		}
		// Simulate ACK with CodeChanged.
		if responseHandler != nil {
			go responseHandler(nil, peerRloc16)
		}
	}
	return nil
}

func TestHTClientServerIntegration(t *testing.T) {
	t.Parallel()

	serverRloc16 := uint16(0xABCD)
	lb := &loopbackTransport{localRloc16: serverRloc16}

	provider := &mockHistoryProvider{
		entries: []HistoryNetworkInfoEntry{
			{Info: NetworkInfoTlv{EntryAge: 500, Role: 2, Mode: 0x0F, Rloc16: serverRloc16, PartitionId: 99}, EntryAge: 500},
			{Info: NetworkInfoTlv{EntryAge: 1500, Role: 1, Mode: 0x0E, Rloc16: serverRloc16, PartitionId: 99}, EntryAge: 1500},
			{Info: NetworkInfoTlv{EntryAge: 3000, Role: 3, Mode: 0x0D, Rloc16: serverRloc16, PartitionId: 99}, EntryAge: 3000},
		},
	}

	server := NewHTServer(lb, provider)
	defer server.Close()

	client := NewHTClient(lb)
	defer client.Close()

	var received []*NetworkInfoTlv
	var finalErr error
	done := make(chan struct{})

	err := client.QueryNetInfo(serverRloc16, 0, 0, func(err error, info *NetworkInfoTlv, entryAge uint32) {
		if err == errors.ErrPending {
			cp := *info
			received = append(received, &cp)
			return
		}
		finalErr = err
		close(done)
	})

	if err != nil {
		t.Fatalf("QueryNetInfo() error = %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("integration test timed out")
	}

	if finalErr != nil {
		t.Errorf("expected nil final error, got %v", finalErr)
	}
	if len(received) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(received))
	}
	if received[0].EntryAge != 500 {
		t.Errorf("entry[0].EntryAge = %d, want 500", received[0].EntryAge)
	}
	if received[1].Role != 1 {
		t.Errorf("entry[1].Role = %d, want 1", received[1].Role)
	}
	if received[2].PartitionId != 99 {
		t.Errorf("entry[2].PartitionId = %d, want 99", received[2].PartitionId)
	}
}

func TestHTClientServerIntegrationWithMaxEntries(t *testing.T) {
	t.Parallel()

	serverRloc16 := uint16(0x5000)
	lb := &loopbackTransport{localRloc16: serverRloc16}

	provider := &mockHistoryProvider{
		entries: []HistoryNetworkInfoEntry{
			{Info: NetworkInfoTlv{EntryAge: 100}, EntryAge: 100},
			{Info: NetworkInfoTlv{EntryAge: 200}, EntryAge: 200},
			{Info: NetworkInfoTlv{EntryAge: 300}, EntryAge: 300},
			{Info: NetworkInfoTlv{EntryAge: 400}, EntryAge: 400},
			{Info: NetworkInfoTlv{EntryAge: 500}, EntryAge: 500},
		},
	}

	server := NewHTServer(lb, provider)
	defer server.Close()

	client := NewHTClient(lb)
	defer client.Close()

	var received []*NetworkInfoTlv
	var finalErr error
	done := make(chan struct{})

	// Request only 3 entries.
	err := client.QueryNetInfo(serverRloc16, 3, 0, func(err error, info *NetworkInfoTlv, entryAge uint32) {
		if err == errors.ErrPending {
			cp := *info
			received = append(received, &cp)
			return
		}
		finalErr = err
		close(done)
	})

	if err != nil {
		t.Fatalf("QueryNetInfo() error = %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("integration test timed out")
	}

	if finalErr != nil {
		t.Errorf("expected nil final error, got %v", finalErr)
	}
	if len(received) != 3 {
		t.Fatalf("expected 3 entries (maxEntries=3), got %d", len(received))
	}
}

func TestHTClientServerIntegrationLargeHistory(t *testing.T) {
	t.Parallel()

	serverRloc16 := uint16(0x6000)
	lb := &loopbackTransport{localRloc16: serverRloc16}

	// Create 100 entries — enough to trigger answer splitting.
	var entries []HistoryNetworkInfoEntry
	for i := 0; i < 100; i++ {
		entries = append(entries, HistoryNetworkInfoEntry{
			Info: NetworkInfoTlv{
				EntryAge:    uint32(i * 100),
				Role:        2,
				Mode:        0x0F,
				Rloc16:      serverRloc16,
				PartitionId: 42,
			},
			EntryAge: uint32(i * 100),
		})
	}

	provider := &mockHistoryProvider{entries: entries}

	server := NewHTServer(lb, provider)
	defer server.Close()

	client := NewHTClient(lb)
	defer client.Close()

	var received []*NetworkInfoTlv
	var finalErr error
	done := make(chan struct{})

	err := client.QueryNetInfo(serverRloc16, 0, 0, func(err error, info *NetworkInfoTlv, entryAge uint32) {
		if err == errors.ErrPending {
			cp := *info
			received = append(received, &cp)
			return
		}
		finalErr = err
		close(done)
	})

	if err != nil {
		t.Fatalf("QueryNetInfo() error = %v", err)
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("integration test timed out")
	}

	if finalErr != nil {
		t.Errorf("expected nil final error, got %v", finalErr)
	}
	if len(received) != 100 {
		t.Fatalf("expected 100 entries, got %d", len(received))
	}

	// Verify ordering is preserved.
	for i, entry := range received {
		expectedAge := uint32(i * 100)
		if entry.EntryAge != expectedAge {
			t.Errorf("entry[%d].EntryAge = %d, want %d", i, entry.EntryAge, expectedAge)
			break
		}
	}
}
