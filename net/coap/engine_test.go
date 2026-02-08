// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package coap

import (
	"sync"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// fakeClock provides a controllable time source for tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// sentMessage records a message sent via the test sender.
type sentMessage struct {
	data []byte
	info MessageInfo
}

// testSender collects sent messages.
type testSender struct {
	mu       sync.Mutex
	messages []sentMessage
}

func (s *testSender) Send(data []byte, info MessageInfo) error {
	cp := make([]byte, len(data))
	copy(cp, data)
	s.mu.Lock()
	s.messages = append(s.messages, sentMessage{data: cp, info: info})
	s.mu.Unlock()
	return nil
}

func (s *testSender) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

func (s *testSender) Last() sentMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.messages[len(s.messages)-1]
}

func (s *testSender) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = nil
}

func (s *testSender) All() []sentMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]sentMessage, len(s.messages))
	copy(cp, s.messages)
	return cp
}

// peerInfo returns a test MessageInfo with a given last-byte address.
func peerInfo(lastByte byte) MessageInfo {
	var addr [16]byte
	addr[15] = lastByte
	return MessageInfo{PeerAddr: addr, PeerPort: 5683}
}

// buildCONRequest builds a CON GET request with the given token and URI path.
func buildCONRequest(token []byte, uriPath string) *Message {
	msg := NewMessage(TypeConfirmable, CodeGet, 0)
	if len(token) > 0 {
		_ = msg.SetToken(token)
	}
	if uriPath != "" {
		_ = msg.AppendURIPathOptions(uriPath)
	}
	return msg
}

// buildNONRequest builds a NON GET request with the given token and URI path.
func buildNONRequest(token []byte, uriPath string) *Message {
	msg := NewMessage(TypeNonConfirmable, CodeGet, 0)
	if len(token) > 0 {
		_ = msg.SetToken(token)
	}
	if uriPath != "" {
		_ = msg.AppendURIPathOptions(uriPath)
	}
	return msg
}

// newTestEngine creates an Engine wired to a testSender and fakeClock.
func newTestEngine() (*Engine, *testSender, *fakeClock) {
	s := &testSender{}
	e := NewEngine(s.Send)
	c := newFakeClock()
	e.nowFunc = c.Now
	// Pin message ID for deterministic tests.
	e.messageID = 1000
	return e, s, c
}

// ---------------------------------------------------------------------------
// TxParameters tests
// ---------------------------------------------------------------------------

func TestDefaultTxParameters(t *testing.T) {
	p := DefaultTxParameters()
	if p.AckTimeout != 2000 {
		t.Errorf("AckTimeout = %d, want 2000", p.AckTimeout)
	}
	if p.AckRandomFactorNumerator != 3 {
		t.Errorf("Numerator = %d, want 3", p.AckRandomFactorNumerator)
	}
	if p.AckRandomFactorDenominator != 2 {
		t.Errorf("Denominator = %d, want 2", p.AckRandomFactorDenominator)
	}
	if p.MaxRetransmit != 4 {
		t.Errorf("MaxRetransmit = %d, want 4", p.MaxRetransmit)
	}
}

func TestTxParametersValidate(t *testing.T) {
	tests := []struct {
		name          string
		params        TxParameters
		isConfirmable bool
		wantErr       bool
	}{
		{
			name:          "default CON",
			params:        DefaultTxParameters(),
			isConfirmable: true,
			wantErr:       false,
		},
		{
			name:          "default NON",
			params:        DefaultTxParameters(),
			isConfirmable: false,
			wantErr:       false,
		},
		{
			name:          "zero denominator",
			params:        TxParameters{AckTimeout: 2000, AckRandomFactorNumerator: 3, AckRandomFactorDenominator: 0, MaxRetransmit: 4},
			isConfirmable: true,
			wantErr:       true,
		},
		{
			name:          "numerator less than denominator",
			params:        TxParameters{AckTimeout: 2000, AckRandomFactorNumerator: 1, AckRandomFactorDenominator: 2, MaxRetransmit: 4},
			isConfirmable: true,
			wantErr:       true,
		},
		{
			name:          "timeout too low CON",
			params:        TxParameters{AckTimeout: 500, AckRandomFactorNumerator: 3, AckRandomFactorDenominator: 2, MaxRetransmit: 4},
			isConfirmable: true,
			wantErr:       true,
		},
		{
			name:          "timeout low allowed for NON",
			params:        TxParameters{AckTimeout: 500, AckRandomFactorNumerator: 3, AckRandomFactorDenominator: 2, MaxRetransmit: 4},
			isConfirmable: false,
			wantErr:       false,
		},
		{
			name:          "retransmit too high",
			params:        TxParameters{AckTimeout: 2000, AckRandomFactorNumerator: 3, AckRandomFactorDenominator: 2, MaxRetransmit: 31},
			isConfirmable: true,
			wantErr:       true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.params.Validate(tc.isConfirmable)
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestTxParametersCalculateInitialRetxTimeout(t *testing.T) {
	p := DefaultTxParameters()

	lower := time.Duration(p.AckTimeout) * time.Millisecond
	// upper = AckTimeout * Numerator/Denominator + 1ms = 2000*3/2+1 = 3001ms
	upper := time.Duration(uint64(p.AckTimeout)*uint64(p.AckRandomFactorNumerator)/uint64(p.AckRandomFactorDenominator)+1) * time.Millisecond

	for range 100 {
		d := p.CalculateInitialRetxTimeout()
		if d < lower || d >= upper {
			t.Errorf("timeout %v out of range [%v, %v)", d, lower, upper)
		}
	}
}

func TestTxParametersCalculateExchangeLifetime(t *testing.T) {
	p := DefaultTxParameters()
	life := p.CalculateExchangeLifetime()
	// Should be > 200 seconds (2*MAX_LATENCY alone is 200s).
	if life < 200*time.Second {
		t.Errorf("exchange lifetime %v too short", life)
	}
}

func TestTxParametersCalculateMaxTransmitWait(t *testing.T) {
	p := DefaultTxParameters()
	wait := p.CalculateMaxTransmitWait()
	// Should be > 0 and < exchange lifetime.
	if wait <= 0 {
		t.Errorf("max transmit wait %v should be > 0", wait)
	}
	life := p.CalculateExchangeLifetime()
	if wait >= life {
		t.Errorf("max transmit wait %v should be < exchange lifetime %v", wait, life)
	}
}

// ---------------------------------------------------------------------------
// MessageInfo tests
// ---------------------------------------------------------------------------

func TestMessageInfoHasSamePeerAddrAndPort(t *testing.T) {
	a := peerInfo(1)
	b := peerInfo(1)
	c := peerInfo(2)

	if !a.HasSamePeerAddrAndPort(b) {
		t.Error("expected same peer for identical info")
	}
	if a.HasSamePeerAddrAndPort(c) {
		t.Error("expected different peer for different addr")
	}

	d := a
	d.PeerPort = 9999
	if a.HasSamePeerAddrAndPort(d) {
		t.Error("expected different peer for different port")
	}
}

// ---------------------------------------------------------------------------
// Resource management tests
// ---------------------------------------------------------------------------

func TestAddRemoveResource(t *testing.T) {
	e, _, _ := newTestEngine()

	handler := func(_ *Message, _ MessageInfo) {}

	e.AddResource(&Resource{URIPath: "ot/cli", Handler: handler})
	e.AddResource(&Resource{URIPath: "ot/diag", Handler: handler})

	if r := e.findResource("ot/cli"); r == nil {
		t.Error("expected to find ot/cli")
	}
	if r := e.findResource("ot/diag"); r == nil {
		t.Error("expected to find ot/diag")
	}
	if r := e.findResource("ot/unknown"); r != nil {
		t.Error("expected nil for unknown path")
	}

	e.RemoveResource("ot/cli")
	if r := e.findResource("ot/cli"); r != nil {
		t.Error("expected nil after removal")
	}
	// ot/diag should still exist.
	if r := e.findResource("ot/diag"); r == nil {
		t.Error("expected ot/diag to still exist")
	}
}

func TestAddResourceReplace(t *testing.T) {
	e, _, _ := newTestEngine()

	called := ""
	e.AddResource(&Resource{URIPath: "a/b", Handler: func(_ *Message, _ MessageInfo) {
		called = "first"
	}})
	e.AddResource(&Resource{URIPath: "a/b", Handler: func(_ *Message, _ MessageInfo) {
		called = "second"
	}})

	r := e.findResource("a/b")
	if r == nil {
		t.Fatal("expected to find resource")
	}
	r.Handler(nil, MessageInfo{})
	if called != "second" {
		t.Errorf("expected second handler, got %q", called)
	}
}

// ---------------------------------------------------------------------------
// Engine send tests
// ---------------------------------------------------------------------------

func TestSendCONRequest(t *testing.T) {
	e, s, _ := newTestEngine()

	handlerCalled := false
	msg := buildCONRequest([]byte{0xAB, 0xCD}, "test/path")
	err := e.SendMessage(msg, peerInfo(1), nil, func(_ *Message, _ MessageInfo, _ error) {
		handlerCalled = true
	})
	if err != nil {
		t.Fatalf("SendMessage() = %v", err)
	}
	if s.Count() != 1 {
		t.Fatalf("expected 1 sent message, got %d", s.Count())
	}

	// Verify message was sent with assigned ID.
	sent := s.Last()
	parsed, err := ParseMessage(sent.data)
	if err != nil {
		t.Fatalf("ParseMessage() = %v", err)
	}
	if parsed.GetMessageID() != 1000 {
		t.Errorf("message ID = %d, want 1000", parsed.GetMessageID())
	}
	if parsed.GetType() != TypeConfirmable {
		t.Errorf("type = %d, want CON", parsed.GetType())
	}

	// Verify pending request was created.
	e.mu.Lock()
	if len(e.pending) != 1 {
		t.Errorf("pending count = %d, want 1", len(e.pending))
	}
	e.mu.Unlock()

	if handlerCalled {
		t.Error("handler should not be called yet")
	}
}

func TestSendNONRequestWithHandler(t *testing.T) {
	e, s, _ := newTestEngine()

	msg := buildNONRequest([]byte{0x01}, "test")
	err := e.SendMessage(msg, peerInfo(1), nil, func(_ *Message, _ MessageInfo, _ error) {})
	if err != nil {
		t.Fatalf("SendMessage() = %v", err)
	}
	if s.Count() != 1 {
		t.Fatalf("expected 1 sent, got %d", s.Count())
	}

	e.mu.Lock()
	if len(e.pending) != 1 {
		t.Errorf("pending count = %d, want 1 (NON with handler)", len(e.pending))
	}
	if e.pending[0].confirmable {
		t.Error("expected confirmable=false for NON")
	}
	e.mu.Unlock()
}

func TestSendNONRequestWithoutHandler(t *testing.T) {
	e, s, _ := newTestEngine()

	msg := buildNONRequest(nil, "test")
	err := e.SendMessage(msg, peerInfo(1), nil, nil)
	if err != nil {
		t.Fatalf("SendMessage() = %v", err)
	}
	if s.Count() != 1 {
		t.Fatalf("expected 1 sent, got %d", s.Count())
	}

	e.mu.Lock()
	if len(e.pending) != 0 {
		t.Errorf("pending count = %d, want 0 (NON without handler)", len(e.pending))
	}
	e.mu.Unlock()
}

func TestSendMessageIDIncrement(t *testing.T) {
	e, s, _ := newTestEngine()

	for i := range 3 {
		msg := buildNONRequest(nil, "")
		_ = e.SendMessage(msg, peerInfo(1), nil, nil)
		sent := s.All()[i]
		parsed, _ := ParseMessage(sent.data)
		expectedID := uint16(1000 + i)
		if parsed.GetMessageID() != expectedID {
			t.Errorf("message %d: ID = %d, want %d", i, parsed.GetMessageID(), expectedID)
		}
	}
}

// ---------------------------------------------------------------------------
// Request dispatch tests
// ---------------------------------------------------------------------------

func TestReceiveCONRequestMatchesResource(t *testing.T) {
	e, _, _ := newTestEngine()

	var received bool
	e.AddResource(&Resource{
		URIPath: "test/path",
		Handler: func(_ *Message, _ MessageInfo) {
			received = true
		},
	})

	// Build a CON GET request for "test/path".
	req := NewMessage(TypeConfirmable, CodeGet, 5000)
	_ = req.SetToken([]byte{0x01})
	_ = req.AppendURIPathOptions("test/path")

	e.Receive(req.GetBytes(), peerInfo(1))
	if !received {
		t.Error("resource handler was not called")
	}
}

func TestReceiveCONRequestDefaultHandler(t *testing.T) {
	e, _, _ := newTestEngine()

	var received bool
	e.SetDefaultHandler(func(_ *Message, _ MessageInfo) {
		received = true
	})

	req := NewMessage(TypeConfirmable, CodeGet, 5000)
	_ = req.AppendURIPathOptions("unknown/path")
	e.Receive(req.GetBytes(), peerInfo(1))
	if !received {
		t.Error("default handler was not called")
	}
}

func TestReceiveCONRequestNoHandler(t *testing.T) {
	e, s, _ := newTestEngine()

	req := NewMessage(TypeConfirmable, CodeGet, 5000)
	_ = req.AppendURIPathOptions("unknown/path")
	e.Receive(req.GetBytes(), peerInfo(1))

	// Should send 4.04 Not Found.
	if s.Count() != 1 {
		t.Fatalf("expected 1 sent (4.04), got %d", s.Count())
	}
	resp, err := ParseMessage(s.Last().data)
	if err != nil {
		t.Fatalf("ParseMessage() = %v", err)
	}
	if resp.GetType() != TypeAck {
		t.Errorf("type = %d, want ACK", resp.GetType())
	}
	if resp.GetCode() != CodeNotFound {
		t.Errorf("code = 0x%02x, want 0x%02x (4.04)", resp.GetCode(), CodeNotFound)
	}
	if resp.GetMessageID() != 5000 {
		t.Errorf("message ID = %d, want 5000", resp.GetMessageID())
	}
}

func TestReceiveNONRequestMatchesResource(t *testing.T) {
	e, s, _ := newTestEngine()

	var received bool
	e.AddResource(&Resource{
		URIPath: "test",
		Handler: func(_ *Message, _ MessageInfo) {
			received = true
		},
	})

	req := NewMessage(TypeNonConfirmable, CodeGet, 6000)
	_ = req.AppendURIPathOptions("test")
	e.Receive(req.GetBytes(), peerInfo(1))

	if !received {
		t.Error("resource handler was not called for NON request")
	}
	// No ACK should be sent for NON.
	if s.Count() != 0 {
		t.Errorf("expected 0 sent messages for NON, got %d", s.Count())
	}
}

// ---------------------------------------------------------------------------
// Response matching tests
// ---------------------------------------------------------------------------

func TestReceiveACKMatchesPendingRequest(t *testing.T) {
	e, s, _ := newTestEngine()

	var gotMsg *Message
	var gotErr error
	msg := buildCONRequest([]byte{0xAA}, "test")
	_ = e.SendMessage(msg, peerInfo(1), nil, func(respMsg *Message, _ MessageInfo, respErr error) {
		gotMsg = respMsg
		gotErr = respErr
	})

	// Build piggybacked ACK response with matching message ID.
	ack := NewMessage(TypeAck, CodeContent, 1000)
	_ = ack.SetToken([]byte{0xAA})
	_ = ack.AppendPayloadMarker()
	_ = ack.AppendPayload([]byte("hello"))

	s.Reset()
	e.Receive(ack.GetBytes(), peerInfo(1))

	if gotErr != nil {
		t.Errorf("handler err = %v, want nil", gotErr)
	}
	if gotMsg == nil {
		t.Fatal("handler msg is nil, want non-nil")
	}
	if gotMsg.GetCode() != CodeContent {
		t.Errorf("response code = 0x%02x, want Content", gotMsg.GetCode())
	}

	// Pending should be cleared.
	e.mu.Lock()
	if len(e.pending) != 0 {
		t.Errorf("pending count = %d, want 0", len(e.pending))
	}
	e.mu.Unlock()
}

func TestReceiveRSTAbortsPendingRequest(t *testing.T) {
	e, _, _ := newTestEngine()

	var gotErr error
	msg := buildCONRequest([]byte{0xBB}, "test")
	_ = e.SendMessage(msg, peerInfo(1), nil, func(_ *Message, _ MessageInfo, respErr error) {
		gotErr = respErr
	})

	rst := NewMessage(TypeReset, CodeEmpty, 1000)
	e.Receive(rst.GetBytes(), peerInfo(1))

	if gotErr != goterrors.ErrAbort {
		t.Errorf("handler err = %v, want ErrAbort", gotErr)
	}
}

func TestReceiveEmptyACKStopsRetransmission(t *testing.T) {
	e, _, _ := newTestEngine()

	msg := buildCONRequest([]byte{0xCC}, "test")
	_ = e.SendMessage(msg, peerInfo(1), nil, func(_ *Message, _ MessageInfo, _ error) {})

	// Send empty ACK (separate response pattern).
	ack := NewMessage(TypeAck, CodeEmpty, 1000)
	e.Receive(ack.GetBytes(), peerInfo(1))

	e.mu.Lock()
	if len(e.pending) != 1 {
		t.Fatalf("pending count = %d, want 1 (still waiting for response)", len(e.pending))
	}
	if !e.pending[0].acknowledged {
		t.Error("expected acknowledged=true after empty ACK")
	}
	e.mu.Unlock()
}

func TestReceiveCONResponseSendsACK(t *testing.T) {
	e, s, _ := newTestEngine()

	var gotMsg *Message
	msg := buildCONRequest([]byte{0xDD}, "test")
	_ = e.SendMessage(msg, peerInfo(1), nil, func(respMsg *Message, _ MessageInfo, _ error) {
		gotMsg = respMsg
	})
	s.Reset()

	// Peer sends a CON response with matching token.
	conResp := NewMessage(TypeConfirmable, CodeContent, 7000)
	_ = conResp.SetToken([]byte{0xDD})
	e.Receive(conResp.GetBytes(), peerInfo(1))

	if gotMsg == nil {
		t.Fatal("handler not called")
	}

	// Should have sent an ACK for the CON response.
	if s.Count() != 1 {
		t.Fatalf("expected 1 ACK sent, got %d", s.Count())
	}
	ackMsg, _ := ParseMessage(s.Last().data)
	if ackMsg.GetType() != TypeAck {
		t.Errorf("expected ACK, got type %d", ackMsg.GetType())
	}
	if ackMsg.GetMessageID() != 7000 {
		t.Errorf("ACK message ID = %d, want 7000", ackMsg.GetMessageID())
	}
}

func TestReceiveUnmatchedCONResponseSendsRST(t *testing.T) {
	e, s, _ := newTestEngine()

	// No pending requests. Receive a CON response.
	conResp := NewMessage(TypeConfirmable, CodeContent, 8000)
	_ = conResp.SetToken([]byte{0xEE})
	e.Receive(conResp.GetBytes(), peerInfo(1))

	if s.Count() != 1 {
		t.Fatalf("expected 1 RST sent, got %d", s.Count())
	}
	rstMsg, _ := ParseMessage(s.Last().data)
	if rstMsg.GetType() != TypeReset {
		t.Errorf("expected RST, got type %d", rstMsg.GetType())
	}
	if rstMsg.GetMessageID() != 8000 {
		t.Errorf("RST message ID = %d, want 8000", rstMsg.GetMessageID())
	}
}

func TestReceiveNONResponseMatchesByToken(t *testing.T) {
	e, _, _ := newTestEngine()

	var gotMsg *Message
	msg := buildCONRequest([]byte{0xFF}, "test")
	_ = e.SendMessage(msg, peerInfo(1), nil, func(respMsg *Message, _ MessageInfo, _ error) {
		gotMsg = respMsg
	})

	// Send empty ACK first.
	ack := NewMessage(TypeAck, CodeEmpty, 1000)
	e.Receive(ack.GetBytes(), peerInfo(1))

	// Then send NON response with matching token.
	nonResp := NewMessage(TypeNonConfirmable, CodeContent, 9000)
	_ = nonResp.SetToken([]byte{0xFF})
	e.Receive(nonResp.GetBytes(), peerInfo(1))

	if gotMsg == nil {
		t.Fatal("handler not called for NON response")
	}
	if gotMsg.GetCode() != CodeContent {
		t.Errorf("code = 0x%02x, want Content", gotMsg.GetCode())
	}
}

// ---------------------------------------------------------------------------
// Retransmission tests
// ---------------------------------------------------------------------------

func TestRetransmissionOnTimeout(t *testing.T) {
	e, s, clk := newTestEngine()

	// Use short fixed timeout for test.
	txp := TxParameters{
		AckTimeout:                 1000,
		AckRandomFactorNumerator:   1,
		AckRandomFactorDenominator: 1,
		MaxRetransmit:              2,
	}

	msg := buildCONRequest([]byte{0x01}, "test")
	_ = e.SendMessage(msg, peerInfo(1), &txp, func(_ *Message, _ MessageInfo, _ error) {})

	// Initial send.
	if s.Count() != 1 {
		t.Fatalf("expected 1 send, got %d", s.Count())
	}

	// Advance past first retx timeout and trigger manually.
	clk.Advance(1100 * time.Millisecond)
	e.handleRetransmissionTimer()

	if s.Count() != 2 {
		t.Fatalf("expected 2 sends after 1st retx, got %d", s.Count())
	}

	// Advance past second retx timeout (doubled: 2000ms).
	clk.Advance(2100 * time.Millisecond)
	e.handleRetransmissionTimer()

	if s.Count() != 3 {
		t.Fatalf("expected 3 sends after 2nd retx, got %d", s.Count())
	}
}

func TestRetransmissionExhaustedCallsHandler(t *testing.T) {
	e, _, clk := newTestEngine()

	txp := TxParameters{
		AckTimeout:                 1000,
		AckRandomFactorNumerator:   1,
		AckRandomFactorDenominator: 1,
		MaxRetransmit:              1,
	}

	var gotErr error
	msg := buildCONRequest([]byte{0x02}, "test")
	_ = e.SendMessage(msg, peerInfo(1), &txp, func(_ *Message, _ MessageInfo, respErr error) {
		gotErr = respErr
	})

	// 1st retx.
	clk.Advance(1100 * time.Millisecond)
	e.handleRetransmissionTimer()

	// After retx exhausted, next timer fire should timeout.
	clk.Advance(2100 * time.Millisecond)
	e.handleRetransmissionTimer()

	if gotErr != goterrors.ErrResponseTimeout {
		t.Errorf("handler err = %v, want ErrResponseTimeout", gotErr)
	}

	e.mu.Lock()
	if len(e.pending) != 0 {
		t.Errorf("pending = %d, want 0", len(e.pending))
	}
	e.mu.Unlock()
}

func TestACKStopsRetransmission(t *testing.T) {
	e, s, clk := newTestEngine()

	txp := TxParameters{
		AckTimeout:                 1000,
		AckRandomFactorNumerator:   1,
		AckRandomFactorDenominator: 1,
		MaxRetransmit:              4,
	}

	msg := buildCONRequest([]byte{0x03}, "test")
	_ = e.SendMessage(msg, peerInfo(1), &txp, func(_ *Message, _ MessageInfo, _ error) {})

	// Receive empty ACK.
	ack := NewMessage(TypeAck, CodeEmpty, 1000)
	e.Receive(ack.GetBytes(), peerInfo(1))

	sendsBefore := s.Count()

	// Advance way past timeout — should NOT retransmit.
	clk.Advance(10 * time.Second)
	e.handleRetransmissionTimer()

	if s.Count() != sendsBefore {
		t.Errorf("sent count changed from %d to %d after ACK", sendsBefore, s.Count())
	}
}

// ---------------------------------------------------------------------------
// Response cache tests
// ---------------------------------------------------------------------------

func TestDuplicateCONRequestReturnsCachedResponse(t *testing.T) {
	e, s, _ := newTestEngine()

	// Register a handler that sends a response.
	e.AddResource(&Resource{
		URIPath: "cached",
		Handler: func(reqMsg *Message, reqInfo MessageInfo) {
			_ = e.SendHeaderResponse(CodeContent, reqMsg, reqInfo)
		},
	})

	req := NewMessage(TypeConfirmable, CodeGet, 5000)
	_ = req.AppendURIPathOptions("cached")

	// First request.
	e.Receive(req.GetBytes(), peerInfo(1))
	firstCount := s.Count()

	// Duplicate request.
	e.Receive(req.GetBytes(), peerInfo(1))

	if s.Count() != firstCount+1 {
		t.Errorf("expected %d sends (1 extra for cached), got %d", firstCount+1, s.Count())
	}

	// The cached response should have the same message ID.
	cached, _ := ParseMessage(s.Last().data)
	if cached.GetMessageID() != 5000 {
		t.Errorf("cached response ID = %d, want 5000", cached.GetMessageID())
	}
}

func TestResponseCacheExpiration(t *testing.T) {
	e, s, clk := newTestEngine()

	e.AddResource(&Resource{
		URIPath: "expiry",
		Handler: func(reqMsg *Message, reqInfo MessageInfo) {
			_ = e.SendHeaderResponse(CodeContent, reqMsg, reqInfo)
		},
	})

	req := NewMessage(TypeConfirmable, CodeGet, 5100)
	_ = req.AppendURIPathOptions("expiry")

	// First request — caches the response.
	e.Receive(req.GetBytes(), peerInfo(1))
	handlerCount := s.Count()

	// Advance far past cache lifetime.
	clk.Advance(300 * time.Second)

	// Send duplicate — cache expired, so handler should be called again.
	e.Receive(req.GetBytes(), peerInfo(1))
	if s.Count() <= handlerCount {
		t.Error("expected handler to be called again after cache expiry")
	}
}

// ---------------------------------------------------------------------------
// ClearAllRequestsAndResponses tests
// ---------------------------------------------------------------------------

func TestClearAllRequestsAndResponses(t *testing.T) {
	e, _, _ := newTestEngine()

	var aborted int
	for range 3 {
		msg := buildCONRequest([]byte{0x10}, "test")
		_ = e.SendMessage(msg, peerInfo(1), nil, func(_ *Message, _ MessageInfo, respErr error) {
			if respErr == goterrors.ErrAbort {
				aborted++
			}
		})
	}

	e.ClearAllRequestsAndResponses()

	if aborted != 3 {
		t.Errorf("aborted = %d, want 3", aborted)
	}

	e.mu.Lock()
	if len(e.pending) != 0 {
		t.Errorf("pending = %d, want 0", len(e.pending))
	}
	if len(e.cache) != 0 {
		t.Errorf("cache = %d, want 0", len(e.cache))
	}
	e.mu.Unlock()
}

// ---------------------------------------------------------------------------
// getURIPath helper tests
// ---------------------------------------------------------------------------

func TestGetURIPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"single segment", "test", "test"},
		{"two segments", "ot/cli", "ot/cli"},
		{"three segments", "a/b/c", "a/b/c"},
		{"empty", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := NewMessage(TypeConfirmable, CodeGet, 0)
			if tc.path != "" {
				_ = msg.AppendURIPathOptions(tc.path)
			}
			got := getURIPath(msg)
			if got != tc.want {
				t.Errorf("getURIPath() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// tokensEqual tests
// ---------------------------------------------------------------------------

func TestTokensEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b []byte
		want bool
	}{
		{"both nil", nil, nil, true},
		{"both empty", []byte{}, []byte{}, true},
		{"nil vs empty", nil, []byte{}, true},
		{"equal", []byte{1, 2, 3}, []byte{1, 2, 3}, true},
		{"different length", []byte{1, 2}, []byte{1, 2, 3}, false},
		{"different content", []byte{1, 2, 3}, []byte{1, 2, 4}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tokensEqual(tc.a, tc.b)
			if got != tc.want {
				t.Errorf("tokensEqual(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SendReset and SendAck tests
// ---------------------------------------------------------------------------

func TestSendReset(t *testing.T) {
	e, s, _ := newTestEngine()
	err := e.SendReset(1234, peerInfo(1))
	if err != nil {
		t.Fatalf("SendReset() = %v", err)
	}
	if s.Count() != 1 {
		t.Fatalf("expected 1 sent, got %d", s.Count())
	}
	msg, _ := ParseMessage(s.Last().data)
	if msg.GetType() != TypeReset {
		t.Errorf("type = %d, want RST", msg.GetType())
	}
	if msg.GetMessageID() != 1234 {
		t.Errorf("ID = %d, want 1234", msg.GetMessageID())
	}
}

func TestSendAck(t *testing.T) {
	e, s, _ := newTestEngine()
	err := e.SendAck(5678, peerInfo(1))
	if err != nil {
		t.Fatalf("SendAck() = %v", err)
	}
	if s.Count() != 1 {
		t.Fatalf("expected 1 sent, got %d", s.Count())
	}
	msg, _ := ParseMessage(s.Last().data)
	if msg.GetType() != TypeAck {
		t.Errorf("type = %d, want ACK", msg.GetType())
	}
	if msg.GetMessageID() != 5678 {
		t.Errorf("ID = %d, want 5678", msg.GetMessageID())
	}
}

// ---------------------------------------------------------------------------
// Interceptor test
// ---------------------------------------------------------------------------

func TestInterceptorConsumesMessage(t *testing.T) {
	e, _, _ := newTestEngine()

	intercepted := false
	e.SetInterceptor(func(_ *Message, _ MessageInfo) error {
		intercepted = true
		return goterrors.ErrDrop
	})

	resourceCalled := false
	e.AddResource(&Resource{
		URIPath: "test",
		Handler: func(_ *Message, _ MessageInfo) {
			resourceCalled = true
		},
	})

	req := NewMessage(TypeConfirmable, CodeGet, 5000)
	_ = req.AppendURIPathOptions("test")
	e.Receive(req.GetBytes(), peerInfo(1))

	if !intercepted {
		t.Error("interceptor was not called")
	}
	if resourceCalled {
		t.Error("resource handler should not be called when interceptor consumed message")
	}
}
