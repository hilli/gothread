// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tmf

import (
	"sync"
	"testing"

	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// DSCP ↔ Priority mapping tests
// ---------------------------------------------------------------------------

func TestPriorityToDscp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		priority ip6.Priority
		dscp     ip6.Dscp
	}{
		{ip6.PriorityNet, ip6.DscpTmfNetPriority},
		{ip6.PriorityNormal, ip6.DscpTmfNormalPriority},
		{ip6.PriorityLow, ip6.DscpTmfLowPriority},
		{ip6.PriorityHigh, ip6.DscpTmfNetPriority}, // High maps to Net
	}

	for _, tt := range tests {
		if got := PriorityToDscp(tt.priority); got != tt.dscp {
			t.Errorf("PriorityToDscp(%d) = %d, want %d", tt.priority, got, tt.dscp)
		}
	}
}

func TestDscpToPriority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		dscp     ip6.Dscp
		priority ip6.Priority
	}{
		{ip6.DscpTmfNetPriority, ip6.PriorityNet},
		{ip6.DscpTmfNormalPriority, ip6.PriorityNormal},
		{ip6.DscpTmfLowPriority, ip6.PriorityLow},
		{ip6.Dscp(0), ip6.PriorityNet},  // Unknown defaults to Net
		{ip6.Dscp(63), ip6.PriorityNet}, // Unknown defaults to Net
	}

	for _, tt := range tests {
		if got := DscpToPriority(tt.dscp); got != tt.priority {
			t.Errorf("DscpToPriority(%d) = %d, want %d", tt.dscp, got, tt.priority)
		}
	}
}

func TestDscpPriorityRoundtrip(t *testing.T) {
	t.Parallel()

	// Net, Normal, Low should roundtrip.
	for _, p := range []ip6.Priority{ip6.PriorityNet, ip6.PriorityNormal, ip6.PriorityLow} {
		dscp := PriorityToDscp(p)
		got := DscpToPriority(dscp)
		if got != p {
			t.Errorf("DscpToPriority(PriorityToDscp(%d)) = %d, want %d", p, got, p)
		}
	}
}

// ---------------------------------------------------------------------------
// IsTmfMessage tests
// ---------------------------------------------------------------------------

func mustAddr(s string) ip6.Address {
	a, err := ip6.AddressFromString(s)
	if err != nil {
		panic("bad test address: " + s)
	}
	return a
}

func TestIsTmfMessageLinkLocal(t *testing.T) {
	t.Parallel()

	llSrc := mustAddr("fe80::1")
	llDst := mustAddr("fe80::2")
	llMcast := mustAddr("ff02::1")

	// Link-local src → link-local dst: valid.
	if !IsTmfMessage(llSrc, llDst, Port) {
		t.Error("link-local src → link-local dst should be TMF")
	}

	// Link-local src → link-local multicast: valid.
	if !IsTmfMessage(llSrc, llMcast, Port) {
		t.Error("link-local src → link-local multicast should be TMF")
	}

	// Link-local src → mesh-local dst: invalid.
	mlDst := mustAddr("fd00::1")
	if IsTmfMessage(llSrc, mlDst, Port) {
		t.Error("link-local src → mesh-local dst should NOT be TMF")
	}

	// Link-local src → realm-local multicast: invalid.
	rlMcast := mustAddr("ff03::1")
	if IsTmfMessage(llSrc, rlMcast, Port) {
		t.Error("link-local src → realm-local multicast should NOT be TMF")
	}
}

func TestIsTmfMessageMeshLocal(t *testing.T) {
	t.Parallel()

	mlSrc := mustAddr("fd00:db8::1")
	mlDst := mustAddr("fd00:db8::2")
	llMcast := mustAddr("ff02::1")
	rlMcast := mustAddr("ff03::1")

	// Mesh-local src → mesh-local dst: valid.
	if !IsTmfMessage(mlSrc, mlDst, Port) {
		t.Error("mesh-local src → mesh-local dst should be TMF")
	}

	// Mesh-local src → link-local multicast: valid.
	if !IsTmfMessage(mlSrc, llMcast, Port) {
		t.Error("mesh-local src → link-local multicast should be TMF")
	}

	// Mesh-local src → realm-local multicast: valid.
	if !IsTmfMessage(mlSrc, rlMcast, Port) {
		t.Error("mesh-local src → realm-local multicast should be TMF")
	}

	// Mesh-local src → global dst: invalid.
	globalDst := mustAddr("2001:db8::1")
	if IsTmfMessage(mlSrc, globalDst, Port) {
		t.Error("mesh-local src → global dst should NOT be TMF")
	}
}

func TestIsTmfMessageWrongPort(t *testing.T) {
	t.Parallel()

	llSrc := mustAddr("fe80::1")
	llDst := mustAddr("fe80::2")

	if IsTmfMessage(llSrc, llDst, 5683) {
		t.Error("wrong port should NOT be TMF")
	}
}

func TestIsTmfMessageGlobalSource(t *testing.T) {
	t.Parallel()

	globalSrc := mustAddr("2001:db8::1")
	mlDst := mustAddr("fd00::2")

	// Global source should not be TMF.
	if IsTmfMessage(globalSrc, mlDst, Port) {
		t.Error("global source should NOT be TMF")
	}
}

// ---------------------------------------------------------------------------
// Agent tests
// ---------------------------------------------------------------------------

// mockSender captures sent data for test inspection.
type mockSender struct {
	mu   sync.Mutex
	sent [][]byte
}

func (ms *mockSender) send(data []byte, _ coap.MessageInfo) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	ms.sent = append(ms.sent, cp)
	return nil
}

func (ms *mockSender) count() int {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	return len(ms.sent)
}

func newTestEngine() (*coap.Engine, *mockSender) {
	ms := &mockSender{}
	return coap.NewEngine(ms.send), ms
}

func TestAgentRegisterAndDispatch(t *testing.T) {
	t.Parallel()

	engine, _ := newTestEngine()
	agent := NewAgent(engine)

	var received struct {
		mu   sync.Mutex
		uri  URI
		code coap.Code
	}

	agent.RegisterHandler(URIAddressSolicit, func(uri URI, msg *coap.Message, _ ip6.MessageInfo) {
		received.mu.Lock()
		defer received.mu.Unlock()
		received.uri = uri
		received.code = msg.GetCode()
	})

	// Build a CON POST to "a/as" from a link-local source.
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 1)
	_ = msg.AppendURIPathOptions("a/as")

	info := coap.MessageInfo{
		LocalAddr: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		PeerAddr:  [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		PeerPort:  Port,
	}

	engine.Receive(msg.GetBytes(), info)

	received.mu.Lock()
	defer received.mu.Unlock()
	if received.uri != URIAddressSolicit {
		t.Errorf("handler received URI %d, want %d", received.uri, URIAddressSolicit)
	}
	if received.code != coap.CodePost {
		t.Errorf("handler received code %d, want POST", received.code)
	}
}

func TestAgentInterceptorRejectsNonTmf(t *testing.T) {
	t.Parallel()

	engine, _ := newTestEngine()
	_ = NewAgent(engine)

	var handlerCalled bool

	// Register a handler — it should NOT be called for non-TMF messages.
	engine.AddResource(&coap.Resource{
		URIPath: "a/as",
		Handler: func(_ *coap.Message, _ coap.MessageInfo) {
			handlerCalled = true
		},
	})

	// Build a CON POST from global source → should be rejected by TMF filter.
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 1)
	_ = msg.AppendURIPathOptions("a/as")

	info := coap.MessageInfo{
		LocalAddr: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		PeerAddr:  [16]byte{0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		PeerPort:  Port,
	}

	engine.Receive(msg.GetBytes(), info)

	if handlerCalled {
		t.Error("handler should not be called for non-TMF message")
	}
}

func TestAgentUnregisterHandler(t *testing.T) {
	t.Parallel()

	engine, ms := newTestEngine()
	agent := NewAgent(engine)

	called := false
	agent.RegisterHandler(URIAddressSolicit, func(_ URI, _ *coap.Message, _ ip6.MessageInfo) {
		called = true
	})

	agent.UnregisterHandler(URIAddressSolicit)

	// Send a valid TMF message — handler should not be called, should get 4.04.
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 1)
	_ = msg.AppendURIPathOptions("a/as")

	info := coap.MessageInfo{
		LocalAddr: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		PeerAddr:  [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		PeerPort:  Port,
	}

	engine.Receive(msg.GetBytes(), info)

	if called {
		t.Error("unregistered handler should not be called")
	}

	// A 4.04 response should have been sent.
	if ms.count() == 0 {
		t.Error("expected a 4.04 response to be sent")
	}
}

func TestAgentUnknownURISends404(t *testing.T) {
	t.Parallel()

	engine, ms := newTestEngine()
	_ = NewAgent(engine)

	// Send a CON POST to an unknown URI path from link-local.
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 1)
	_ = msg.AppendURIPathOptions("x/unknown")

	info := coap.MessageInfo{
		LocalAddr: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		PeerAddr:  [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		PeerPort:  Port,
	}

	engine.Receive(msg.GetBytes(), info)

	// Should have sent a response (4.04).
	if ms.count() == 0 {
		t.Error("expected a 4.04 response for unknown URI")
	}
}

func TestAgentStop(t *testing.T) {
	t.Parallel()

	engine, _ := newTestEngine()
	agent := NewAgent(engine)
	// Stop should not panic.
	agent.Stop()
}

// ---------------------------------------------------------------------------
// AgentMessageInfo tests
// ---------------------------------------------------------------------------

func TestNewAgentMessageInfo(t *testing.T) {
	t.Parallel()

	mi := NewAgentMessageInfo()
	if mi.PeerPort != Port {
		t.Errorf("NewAgentMessageInfo().PeerPort = %d, want %d", mi.PeerPort, Port)
	}
}

func TestAgentMessageInfoSetSockAddrToRLOC(t *testing.T) {
	t.Parallel()

	mi := NewAgentMessageInfo()
	prefix := ip6.NetworkPrefix{0xfd, 0x00, 0xab, 0xcd, 0x00, 0x00, 0x00, 0x00}
	mi.SetSockAddrToRLOC(prefix, 0x0400)

	// Verify prefix bytes.
	for i := 0; i < 8; i++ {
		if mi.SockAddr[i] != prefix[i] {
			t.Errorf("SockAddr prefix byte %d = 0x%02x, want 0x%02x", i, mi.SockAddr[i], prefix[i])
		}
	}

	// Verify RLOC IID pattern: 0000:00ff:fe00:0400
	expectedIID := [8]byte{0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x04, 0x00}
	for i := 0; i < 8; i++ {
		if mi.SockAddr[8+i] != expectedIID[i] {
			t.Errorf("SockAddr IID byte %d = 0x%02x, want 0x%02x", i, mi.SockAddr[8+i], expectedIID[i])
		}
	}

	if mi.SockPort != Port {
		t.Errorf("SockPort = %d, want %d", mi.SockPort, Port)
	}
}

func TestAgentMessageInfoSetPeerAddrToRLOC(t *testing.T) {
	t.Parallel()

	mi := NewAgentMessageInfo()
	prefix := ip6.NetworkPrefix{0xfd, 0x00, 0xab, 0xcd, 0x00, 0x00, 0x00, 0x00}
	mi.SetPeerAddrToRLOC(prefix, 0xFC00)

	// Verify prefix bytes.
	for i := 0; i < 8; i++ {
		if mi.PeerAddr[i] != prefix[i] {
			t.Errorf("PeerAddr prefix byte %d = 0x%02x, want 0x%02x", i, mi.PeerAddr[i], prefix[i])
		}
	}

	// Verify RLOC IID pattern: 0000:00ff:fe00:fc00
	expectedIID := [8]byte{0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0xfc, 0x00}
	for i := 0; i < 8; i++ {
		if mi.PeerAddr[8+i] != expectedIID[i] {
			t.Errorf("PeerAddr IID byte %d = 0x%02x, want 0x%02x", i, mi.PeerAddr[8+i], expectedIID[i])
		}
	}

	if mi.PeerPort != Port {
		t.Errorf("PeerPort = %d, want %d", mi.PeerPort, Port)
	}
}

func TestRlocAddress(t *testing.T) {
	t.Parallel()

	prefix := ip6.NetworkPrefix{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	// RLOC16 0x0400: high byte 0x04 < 0xfc, and 0x04 & 0x02 == 0 → valid RLOC.
	addr := rlocAddress(prefix, 0x0400)

	// Check it's a routing locator.
	if !addr.IsRoutingLocator() {
		t.Error("rlocAddress should produce a routing locator address")
	}

	// Check the IID locator value.
	iid := addr.GetIid()
	if iid.GetLocator() != 0x0400 {
		t.Errorf("IID locator = 0x%04x, want 0x0400", iid.GetLocator())
	}
}

func TestPortConstant(t *testing.T) {
	t.Parallel()

	if Port != 61631 {
		t.Errorf("Port = %d, want 61631", Port)
	}
}
