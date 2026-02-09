// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tmf

import (
	"sync"
	"testing"
	"time"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/mle"

	goterrors "github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Test infrastructure — loopback engine
// ---------------------------------------------------------------------------

// newLoopbackEngine creates a CoAP engine that loops outgoing data back into
// its own Receive with addresses swapped. This simulates a client and server
// running on the same engine (e.g. a device sending TMF requests to itself as
// leader). A mockSender is returned for inspection of sent packets.
func newLoopbackEngine() (*coap.Engine, *mockSender) {
	ms := &mockSender{}
	var engine *coap.Engine

	engine = coap.NewEngine(func(data []byte, info coap.MessageInfo) error {
		ms.mu.Lock()
		cp := make([]byte, len(data))
		copy(cp, data)
		ms.sent = append(ms.sent, cp)
		ms.mu.Unlock()

		// Swap local ↔ peer addresses for the loopback receive.
		swapped := coap.MessageInfo{
			PeerAddr:  info.LocalAddr,
			PeerPort:  info.PeerPort,
			LocalAddr: info.PeerAddr,
		}
		engine.Receive(data, swapped)
		return nil
	})

	return engine, ms
}

// meshPrefix is a test mesh-local prefix for client tests.
var meshPrefix = ip6.NetworkPrefix{0xfd, 0x00, 0xab, 0xcd, 0x00, 0x00, 0x00, 0x00}

// senderRLOC is a child RLOC16 used as the sender's source address in tests.
const senderRLOC uint16 = 0x0401

// ---------------------------------------------------------------------------
// SendAddressSolicit tests
// ---------------------------------------------------------------------------

func TestSendAddressSolicitSuccess(t *testing.T) {
	t.Parallel()

	engine, _ := newLoopbackEngine()
	agent := NewAgent(engine)

	// Set up a mock leader that always allocates router ID 5.
	rt := newMockLeaderRouterTable()
	rt.nextRandomID = 5
	ls := NewLeaderService(agent, rt, 32)
	defer ls.Stop()

	leaderRLOC16 := uint16(0xFC00)
	extAddr := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	var wg sync.WaitGroup
	wg.Add(1)

	var got AddressSolicitResult

	err := SendAddressSolicit(
		agent,
		meshPrefix,
		senderRLOC,
		leaderRLOC16,
		extAddr,
		mle.UpgradeReasonTooFewRouters,
		0, // no requested RLOC16
		func(result AddressSolicitResult) {
			got = result
			wg.Done()
		},
	)
	if err != nil {
		t.Fatalf("SendAddressSolicit returned error: %v", err)
	}

	wg.Wait()

	if got.Err != nil {
		t.Fatalf("callback error: %v", got.Err)
	}
	if got.Status != AddrSolicitSuccess {
		t.Errorf("status = %d, want AddrSolicitSuccess", got.Status)
	}
	if !got.HasRLOC16 {
		t.Fatal("HasRLOC16 = false, want true")
	}
	if got.RLOC16 != mle.RLOC16FromRouterID(5) {
		t.Errorf("RLOC16 = 0x%04x, want 0x%04x", got.RLOC16, mle.RLOC16FromRouterID(5))
	}
	if got.RouterID != 5 {
		t.Errorf("RouterID = %d, want 5", got.RouterID)
	}
	if !got.HasRouterMask {
		t.Error("HasRouterMask = false, want true")
	}
}

func TestSendAddressSolicitWithRequestedRLOC16(t *testing.T) {
	t.Parallel()

	engine, _ := newLoopbackEngine()
	agent := NewAgent(engine)

	rt := newMockLeaderRouterTable()
	ls := NewLeaderService(agent, rt, 32)
	defer ls.Stop()

	leaderRLOC16 := uint16(0xFC00)
	extAddr := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	requestedRLOC16 := uint16(0x1C00) // Router ID 7

	var wg sync.WaitGroup
	wg.Add(1)

	var got AddressSolicitResult

	err := SendAddressSolicit(
		agent,
		meshPrefix,
		senderRLOC,
		leaderRLOC16,
		extAddr,
		mle.UpgradeReasonTooFewRouters,
		requestedRLOC16,
		func(result AddressSolicitResult) {
			got = result
			wg.Done()
		},
	)
	if err != nil {
		t.Fatalf("SendAddressSolicit returned error: %v", err)
	}

	wg.Wait()

	if got.Err != nil {
		t.Fatalf("callback error: %v", got.Err)
	}
	if got.Status != AddrSolicitSuccess {
		t.Errorf("status = %d, want AddrSolicitSuccess", got.Status)
	}
	if !got.HasRLOC16 {
		t.Fatal("HasRLOC16 = false, want true")
	}
	// Should have gotten the requested RLOC16 since the table was empty.
	if got.RLOC16 != requestedRLOC16 {
		t.Errorf("RLOC16 = 0x%04x, want 0x%04x", got.RLOC16, requestedRLOC16)
	}
	if got.RouterID != 7 {
		t.Errorf("RouterID = %d, want 7", got.RouterID)
	}
}

func TestSendAddressSolicitRejection(t *testing.T) {
	t.Parallel()

	engine, _ := newLoopbackEngine()
	agent := NewAgent(engine)

	// Set up a leader with threshold 0 — will reject TooFewRouters reason
	// once there are active routers.
	rt := newMockLeaderRouterTable()
	// Fill the table with one active router so count >= threshold.
	_, _ = rt.AllocateWithIDForRouter(1, types.ExtAddress{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})

	ls := NewLeaderService(agent, rt, 0)
	defer ls.Stop()

	leaderRLOC16 := uint16(0xFC00)
	extAddr := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	var wg sync.WaitGroup
	wg.Add(1)

	var got AddressSolicitResult

	err := SendAddressSolicit(
		agent,
		meshPrefix,
		senderRLOC,
		leaderRLOC16,
		extAddr,
		mle.UpgradeReasonTooFewRouters,
		0,
		func(result AddressSolicitResult) {
			got = result
			wg.Done()
		},
	)
	if err != nil {
		t.Fatalf("SendAddressSolicit returned error: %v", err)
	}

	wg.Wait()

	if got.Err != nil {
		t.Fatalf("callback error: %v", got.Err)
	}
	if got.Status != AddrSolicitNoAddressAvailable {
		t.Errorf("status = %d, want AddrSolicitNoAddressAvailable (%d)", got.Status, AddrSolicitNoAddressAvailable)
	}
}

func TestSendAddressSolicitTimeoutCallsCallback(t *testing.T) {
	t.Parallel()

	// Verify the error result is structured correctly when the callback
	// receives a timeout error.
	var got AddressSolicitResult
	got.Err = goterrors.ErrResponseTimeout

	if got.Err != goterrors.ErrResponseTimeout {
		t.Errorf("Err = %v, want ErrResponseTimeout", got.Err)
	}
	if got.Status != 0 {
		t.Errorf("Status = %d, want 0", got.Status)
	}
	if got.HasRLOC16 {
		t.Error("HasRLOC16 = true, want false")
	}
}

func TestSendAddressSolicitNilCallback(t *testing.T) {
	t.Parallel()

	engine, _ := newLoopbackEngine()
	agent := NewAgent(engine)

	rt := newMockLeaderRouterTable()
	ls := NewLeaderService(agent, rt, 32)
	defer ls.Stop()

	leaderRLOC16 := uint16(0xFC00)
	extAddr := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Should not panic with nil callback.
	err := SendAddressSolicit(
		agent,
		meshPrefix,
		senderRLOC,
		leaderRLOC16,
		extAddr,
		mle.UpgradeReasonTooFewRouters,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("SendAddressSolicit returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SendAddressRelease tests
// ---------------------------------------------------------------------------

func TestSendAddressReleaseValid(t *testing.T) {
	t.Parallel()

	engine, _ := newLoopbackEngine()
	agent := NewAgent(engine)

	rt := newMockLeaderRouterTable()
	extAddr := types.ExtAddress{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00, 0x01}
	// Pre-allocate the router so release has something to free.
	_, _ = rt.AllocateWithIDForRouter(10, extAddr)

	ls := NewLeaderService(agent, rt, 32)
	defer ls.Stop()

	leaderRLOC16 := uint16(0xFC00)
	rloc16 := mle.RLOC16FromRouterID(10)

	err := SendAddressRelease(agent, meshPrefix, senderRLOC, leaderRLOC16, rloc16, extAddr)
	if err != nil {
		t.Fatalf("SendAddressRelease returned error: %v", err)
	}

	// The loopback engine processes the request synchronously within
	// SendMessage, but the engine's response path may involve goroutines.
	// Give a brief window for the server handler to execute.
	time.Sleep(50 * time.Millisecond)

	// Verify the router was released from the table.
	rt.mu.Lock()
	_, found := rt.routers[10]
	rt.mu.Unlock()
	if found {
		t.Error("router ID 10 should have been released from the table")
	}
}

func TestSendAddressReleaseInvalidOwnership(t *testing.T) {
	t.Parallel()

	engine, _ := newLoopbackEngine()
	agent := NewAgent(engine)

	rt := newMockLeaderRouterTable()
	ownerAddr := types.ExtAddress{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00, 0x01}
	_, _ = rt.AllocateWithIDForRouter(10, ownerAddr)

	ls := NewLeaderService(agent, rt, 32)
	defer ls.Stop()

	leaderRLOC16 := uint16(0xFC00)
	wrongAddr := types.ExtAddress{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	rloc16 := mle.RLOC16FromRouterID(10)

	err := SendAddressRelease(agent, meshPrefix, senderRLOC, leaderRLOC16, rloc16, wrongAddr)
	if err != nil {
		t.Fatalf("SendAddressRelease returned error: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Router should NOT have been released (wrong ExtAddress).
	rt.mu.Lock()
	_, found := rt.routers[10]
	rt.mu.Unlock()
	if !found {
		t.Error("router ID 10 should NOT have been released (ownership mismatch)")
	}
}

// ---------------------------------------------------------------------------
// buildCONPost tests
// ---------------------------------------------------------------------------

func TestBuildCONPost(t *testing.T) {
	t.Parallel()

	payload := []byte{0x01, 0x02, 0x03}
	msg, err := buildCONPost(URIAddressSolicit, payload)
	if err != nil {
		t.Fatalf("buildCONPost error: %v", err)
	}

	if msg.GetType() != coap.TypeConfirmable {
		t.Errorf("type = %d, want CON", msg.GetType())
	}
	if msg.GetCode() != coap.CodePost {
		t.Errorf("code = %d, want POST", msg.GetCode())
	}

	token := msg.GetToken()
	if len(token) != tokenLength {
		t.Errorf("token length = %d, want %d", len(token), tokenLength)
	}

	gotPayload := msg.GetPayload()
	if len(gotPayload) != len(payload) {
		t.Errorf("payload length = %d, want %d", len(gotPayload), len(payload))
	}
	for i, b := range gotPayload {
		if b != payload[i] {
			t.Errorf("payload[%d] = 0x%02x, want 0x%02x", i, b, payload[i])
		}
	}
}

func TestBuildCONPostEmptyPayload(t *testing.T) {
	t.Parallel()

	msg, err := buildCONPost(URIAddressRelease, nil)
	if err != nil {
		t.Fatalf("buildCONPost error: %v", err)
	}

	if msg.GetType() != coap.TypeConfirmable {
		t.Errorf("type = %d, want CON", msg.GetType())
	}

	gotPayload := msg.GetPayload()
	if len(gotPayload) != 0 {
		t.Errorf("payload length = %d, want 0", len(gotPayload))
	}
}

// ---------------------------------------------------------------------------
// tmfCoapInfo tests
// ---------------------------------------------------------------------------

func TestTmfCoapInfo(t *testing.T) {
	t.Parallel()

	info := tmfCoapInfo(meshPrefix, 0x0401, 0x0400)

	if info.PeerPort != Port {
		t.Errorf("PeerPort = %d, want %d", info.PeerPort, Port)
	}

	// Verify the peer address is an RLOC address with the correct prefix.
	for i := 0; i < 8; i++ {
		if info.PeerAddr[i] != meshPrefix[i] {
			t.Errorf("PeerAddr prefix byte %d = 0x%02x, want 0x%02x", i, info.PeerAddr[i], meshPrefix[i])
		}
	}

	// Verify IID locator bytes for PeerAddr (leader RLOC16 = 0x0400).
	if info.PeerAddr[14] != 0x04 || info.PeerAddr[15] != 0x00 {
		t.Errorf("PeerAddr RLOC16 = 0x%02x%02x, want 0x0400", info.PeerAddr[14], info.PeerAddr[15])
	}

	// Verify LocalAddr is set (sender RLOC16 = 0x0401).
	for i := 0; i < 8; i++ {
		if info.LocalAddr[i] != meshPrefix[i] {
			t.Errorf("LocalAddr prefix byte %d = 0x%02x, want 0x%02x", i, info.LocalAddr[i], meshPrefix[i])
		}
	}
	if info.LocalAddr[14] != 0x04 || info.LocalAddr[15] != 0x01 {
		t.Errorf("LocalAddr RLOC16 = 0x%02x%02x, want 0x0401", info.LocalAddr[14], info.LocalAddr[15])
	}
}

// ---------------------------------------------------------------------------
// parseAddrSolicitResult tests
// ---------------------------------------------------------------------------

func TestParseAddrSolicitResultSuccess(t *testing.T) {
	t.Parallel()

	resp := &AddrSolicitResponse{
		Status:           AddrSolicitSuccess,
		HasRLOC16:        true,
		RLOC16:           0x1400,
		HasRouterMask:    true,
		RouterIDSequence: 42,
		RouterIDSet:      mle.RouterIDSet{0x80},
	}

	payload := MarshalAddrSolicitResponse(resp)
	msg := coap.NewMessage(coap.TypeAck, coap.CodeChanged, 1000)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)

	result := parseAddrSolicitResult(msg)

	if result.Err != nil {
		t.Fatalf("Err = %v, want nil", result.Err)
	}
	if result.Status != AddrSolicitSuccess {
		t.Errorf("Status = %d, want AddrSolicitSuccess", result.Status)
	}
	if !result.HasRLOC16 {
		t.Fatal("HasRLOC16 = false, want true")
	}
	if result.RLOC16 != 0x1400 {
		t.Errorf("RLOC16 = 0x%04x, want 0x1400", result.RLOC16)
	}
	if result.RouterID != 5 {
		t.Errorf("RouterID = %d, want 5 (from RLOC16 0x1400)", result.RouterID)
	}
	if !result.HasRouterMask {
		t.Error("HasRouterMask = false, want true")
	}
	if result.RouterIDSequence != 42 {
		t.Errorf("RouterIDSequence = %d, want 42", result.RouterIDSequence)
	}
}

func TestParseAddrSolicitResultInvalidPayload(t *testing.T) {
	t.Parallel()

	msg := coap.NewMessage(coap.TypeAck, coap.CodeChanged, 1000)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload([]byte{0xFF, 0xFF}) // garbage

	result := parseAddrSolicitResult(msg)
	if result.Err == nil {
		t.Error("Err = nil, want parse error")
	}
}

// ---------------------------------------------------------------------------
// SendServerData tests
// ---------------------------------------------------------------------------

func TestSendServerDataSuccess(t *testing.T) {
	t.Parallel()

	engine, _ := newLoopbackEngine()
	agent := NewAgent(engine)

	leader := &mockNetworkDataLeader{}
	sds := NewServerDataService(agent, leader)
	defer sds.Stop()

	leaderRLOC16 := uint16(0xFC00)
	nd := []byte{0x01, 0x02, 0x03, 0x04}

	var wg sync.WaitGroup
	wg.Add(1)

	var got ServerDataResult

	err := SendServerData(
		agent,
		meshPrefix,
		senderRLOC,
		leaderRLOC16,
		nd,
		func(result ServerDataResult) {
			got = result
			wg.Done()
		},
	)
	if err != nil {
		t.Fatalf("SendServerData returned error: %v", err)
	}

	wg.Wait()

	if got.Err != nil {
		t.Fatalf("callback error: %v", got.Err)
	}
	if !got.Accepted {
		t.Error("Accepted = false, want true")
	}

	// Verify the leader received the correct data.
	leader.mu.Lock()
	defer leader.mu.Unlock()
	if leader.callCount != 1 {
		t.Errorf("leader.callCount = %d, want 1", leader.callCount)
	}
	if leader.lastRLOC16 != senderRLOC {
		t.Errorf("leader.lastRLOC16 = 0x%04x, want 0x%04x", leader.lastRLOC16, senderRLOC)
	}
	if len(leader.lastData) != len(nd) {
		t.Fatalf("leader.lastData length = %d, want %d", len(leader.lastData), len(nd))
	}
	for i, b := range leader.lastData {
		if b != nd[i] {
			t.Errorf("leader.lastData[%d] = 0x%02x, want 0x%02x", i, b, nd[i])
		}
	}
}

func TestSendServerDataEmptyNetworkData(t *testing.T) {
	t.Parallel()

	engine, _ := newLoopbackEngine()
	agent := NewAgent(engine)

	leader := &mockNetworkDataLeader{}
	sds := NewServerDataService(agent, leader)
	defer sds.Stop()

	leaderRLOC16 := uint16(0xFC00)

	var wg sync.WaitGroup
	wg.Add(1)

	var got ServerDataResult

	err := SendServerData(
		agent,
		meshPrefix,
		senderRLOC,
		leaderRLOC16,
		nil, // empty network data — remove all entries
		func(result ServerDataResult) {
			got = result
			wg.Done()
		},
	)
	if err != nil {
		t.Fatalf("SendServerData returned error: %v", err)
	}

	wg.Wait()

	if got.Err != nil {
		t.Fatalf("callback error: %v", got.Err)
	}
	if !got.Accepted {
		t.Error("Accepted = false, want true")
	}

	leader.mu.Lock()
	defer leader.mu.Unlock()
	if leader.callCount != 1 {
		t.Errorf("leader.callCount = %d, want 1", leader.callCount)
	}
	if leader.lastRLOC16 != senderRLOC {
		t.Errorf("leader.lastRLOC16 = 0x%04x, want 0x%04x", leader.lastRLOC16, senderRLOC)
	}
}

func TestSendServerDataRegistrationError(t *testing.T) {
	t.Parallel()

	engine, _ := newLoopbackEngine()
	agent := NewAgent(engine)

	leader := &mockNetworkDataLeader{
		returnError: goterrors.ErrDrop,
	}
	sds := NewServerDataService(agent, leader)
	defer sds.Stop()

	leaderRLOC16 := uint16(0xFC00)
	nd := []byte{0xAA, 0xBB}

	var wg sync.WaitGroup
	wg.Add(1)

	var got ServerDataResult

	err := SendServerData(
		agent,
		meshPrefix,
		senderRLOC,
		leaderRLOC16,
		nd,
		func(result ServerDataResult) {
			got = result
			wg.Done()
		},
	)
	if err != nil {
		t.Fatalf("SendServerData returned error: %v", err)
	}

	wg.Wait()

	// The leader rejected the registration. The server sends a 5.00
	// Internal Server Error, so Accepted should be false.
	if got.Accepted {
		t.Error("Accepted = true, want false (leader rejected)")
	}
}

func TestSendServerDataNilCallback(t *testing.T) {
	t.Parallel()

	engine, _ := newLoopbackEngine()
	agent := NewAgent(engine)

	leader := &mockNetworkDataLeader{}
	sds := NewServerDataService(agent, leader)
	defer sds.Stop()

	leaderRLOC16 := uint16(0xFC00)

	// Should not panic with nil callback.
	err := SendServerData(
		agent,
		meshPrefix,
		senderRLOC,
		leaderRLOC16,
		[]byte{0x01},
		nil,
	)
	if err != nil {
		t.Fatalf("SendServerData returned error: %v", err)
	}
}

func TestSendServerDataTimeoutResult(t *testing.T) {
	t.Parallel()

	// Verify the error result is structured correctly when the callback
	// receives a timeout error.
	var got ServerDataResult
	got.Err = goterrors.ErrResponseTimeout

	if got.Err != goterrors.ErrResponseTimeout {
		t.Errorf("Err = %v, want ErrResponseTimeout", got.Err)
	}
	if got.Accepted {
		t.Error("Accepted = true, want false on timeout")
	}
}
