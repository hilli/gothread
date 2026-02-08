// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"testing"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/key"
)

// --- mock types for Dispatcher testing ---

type mockTransport struct {
	sentMessages []sentMessage
	extAddr      types.ExtAddress
	linkLocal    ip6.Address
	meshLocal    ip6.Address
	allRouters   ip6.Address
}

type sentMessage struct {
	data []byte
	dst  ip6.Address
}

func (m *mockTransport) SendMLE(msg []byte, dst ip6.Address) error {
	cp := make([]byte, len(msg))
	copy(cp, msg)
	m.sentMessages = append(m.sentMessages, sentMessage{data: cp, dst: dst})
	return nil
}

func (m *mockTransport) GetExtAddress() types.ExtAddress  { return m.extAddr }
func (m *mockTransport) GetLinkLocalAddress() ip6.Address { return m.linkLocal }
func (m *mockTransport) GetMeshLocalAddress() ip6.Address { return m.meshLocal }
func (m *mockTransport) GetLinkLocalAllRoutersMulticast() ip6.Address {
	return m.allRouters
}

// mockKeyProvider implements KeyProvider for testing.
type mockKeyProvider struct {
	currentSeq      uint32
	currentKey      key.MleKey
	mleFrameCounter uint32
	macFrameCounter uint32
	seqUpdates      []seqUpdate
}

type seqUpdate struct {
	seq   uint32
	flags key.SeqUpdateFlag
}

func (m *mockKeyProvider) GetCurrentKeySequence() uint32 { return m.currentSeq }
func (m *mockKeyProvider) GetCurrentMleKey() key.MleKey  { return m.currentKey }
func (m *mockKeyProvider) GetTemporaryMleKey(_ uint32) key.MleKey {
	return m.currentKey // Simplified for testing
}
func (m *mockKeyProvider) GetMleFrameCounter() uint32 { return m.mleFrameCounter }
func (m *mockKeyProvider) IncrementMleFrameCounter()  { m.mleFrameCounter++ }
func (m *mockKeyProvider) GetMacFrameCounter() uint32 { return m.macFrameCounter }
func (m *mockKeyProvider) SetCurrentKeySequence(seq uint32, flags key.SeqUpdateFlag) {
	m.currentSeq = seq
	m.seqUpdates = append(m.seqUpdates, seqUpdate{seq: seq, flags: flags})
}

// newTestDispatcher creates a Dispatcher with mock dependencies for testing.
func newTestDispatcher() (*Dispatcher, *mockTransport, *mockKeyProvider) {
	mle := NewMle()
	_ = mle.Enable()

	transport := &mockTransport{
		extAddr: types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		linkLocal: ip6.Address{
			0xfe, 0x80, 0, 0, 0, 0, 0, 0,
			0x03, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		},
	}

	keyMgr := &mockKeyProvider{
		currentSeq: 1,
		currentKey: key.MleKey{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
			0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00},
	}

	d := NewDispatcher(mle, keyMgr, transport)
	return d, transport, keyMgr
}

// --- Dispatcher tests ---

func TestNewDispatcher(t *testing.T) {
	t.Parallel()

	d, _, _ := newTestDispatcher()
	if d == nil {
		t.Fatal("NewDispatcher returned nil")
	}
	if d.handlers == nil {
		t.Error("handlers map is nil")
	}
}

func TestDispatcherRegisterHandler(t *testing.T) {
	t.Parallel()

	d, _, _ := newTestDispatcher()

	called := false
	d.RegisterHandler(CommandParentResponse, func(_ *RxInfo) error {
		called = true
		return nil
	})

	h, ok := d.handlers[CommandParentResponse]
	if !ok {
		t.Fatal("handler not registered")
	}
	if err := h(nil); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if !called {
		t.Error("handler was not called")
	}
}

func TestDispatcherSetNeighborLookup(t *testing.T) {
	t.Parallel()

	d, _, _ := newTestDispatcher()

	n := &Neighbor{MacAddr: types.ExtAddress{0x11}, State: StateValid}
	d.SetNeighborLookup(func(_ types.ExtAddress) *Neighbor {
		return n
	})

	if d.lookupNeighbor == nil {
		t.Error("lookupNeighbor is nil after SetNeighborLookup")
	}
}

func TestResolveKey_Current(t *testing.T) {
	t.Parallel()

	d, _, keyMgr := newTestDispatcher()
	keyMgr.currentSeq = 5

	mleKey, err := d.resolveKey(5) // Current sequence
	if err != nil {
		t.Fatalf("resolveKey(current) error: %v", err)
	}
	if mleKey != keyMgr.currentKey {
		t.Error("resolveKey(current) returned wrong key")
	}
}

func TestResolveKey_Next(t *testing.T) {
	t.Parallel()

	d, _, keyMgr := newTestDispatcher()
	keyMgr.currentSeq = 5

	_, err := d.resolveKey(6) // Next sequence
	if err != nil {
		t.Fatalf("resolveKey(next) error: %v", err)
	}
}

func TestResolveKey_Previous(t *testing.T) {
	t.Parallel()

	d, _, keyMgr := newTestDispatcher()
	keyMgr.currentSeq = 5

	_, err := d.resolveKey(4) // Previous sequence
	if err != nil {
		t.Fatalf("resolveKey(previous) error: %v", err)
	}
}

func TestResolveKey_TooFar(t *testing.T) {
	t.Parallel()

	d, _, keyMgr := newTestDispatcher()
	keyMgr.currentSeq = 5

	_, err := d.resolveKey(10) // Too far
	if err == nil {
		t.Error("resolveKey(too far) should have returned error")
	}
}

func TestValidateFrameCounter_Replay(t *testing.T) {
	t.Parallel()

	d, _, keyMgr := newTestDispatcher()
	keyMgr.currentSeq = 1

	n := &Neighbor{
		State:    StateValid,
		Counters: FrameCounters{MleFrameCounter: 100},
	}

	rxInfo := &RxInfo{
		Neighbor:     n,
		KeySequence:  1,
		FrameCounter: 50, // Replay: less than last seen
	}

	err := d.validateFrameCounter(rxInfo)
	if err == nil {
		t.Error("validateFrameCounter should reject replay")
	}
}

func TestValidateFrameCounter_Equal(t *testing.T) {
	t.Parallel()

	d, _, keyMgr := newTestDispatcher()
	keyMgr.currentSeq = 1

	n := &Neighbor{
		State:    StateValid,
		Counters: FrameCounters{MleFrameCounter: 100},
	}

	rxInfo := &RxInfo{
		Neighbor:     n,
		KeySequence:  1,
		FrameCounter: 100, // Equal: also a replay
	}

	err := d.validateFrameCounter(rxInfo)
	if err == nil {
		t.Error("validateFrameCounter should reject equal frame counter")
	}
}

func TestValidateFrameCounter_Valid(t *testing.T) {
	t.Parallel()

	d, _, keyMgr := newTestDispatcher()
	keyMgr.currentSeq = 1

	n := &Neighbor{
		State:    StateValid,
		Counters: FrameCounters{MleFrameCounter: 100},
	}

	rxInfo := &RxInfo{
		Neighbor:     n,
		KeySequence:  1,
		FrameCounter: 101, // Valid: greater than last seen
	}

	err := d.validateFrameCounter(rxInfo)
	if err != nil {
		t.Errorf("validateFrameCounter should accept valid counter: %v", err)
	}
}

func TestValidateFrameCounter_NewerKeySequence(t *testing.T) {
	t.Parallel()

	d, _, keyMgr := newTestDispatcher()
	keyMgr.currentSeq = 1

	n := &Neighbor{
		State:    StateValid,
		Counters: FrameCounters{MleFrameCounter: 100},
	}

	rxInfo := &RxInfo{
		Neighbor:     n,
		KeySequence:  2, // Newer key sequence
		FrameCounter: 1, // Any counter is acceptable
	}

	err := d.validateFrameCounter(rxInfo)
	if err != nil {
		t.Errorf("validateFrameCounter should accept any counter with newer key sequence: %v", err)
	}
}

func TestClassifyMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		cmd  Command
		want messageClass
	}{
		{CommandAdvertisement, messageClassAuthoritative},
		{CommandDataResponse, messageClassAuthoritative},
		{CommandParentResponse, messageClassAuthoritative},
		{CommandChildIDResponse, messageClassAuthoritative},
		{CommandChildUpdateResponse, messageClassAuthoritative},
		{CommandLinkAccept, messageClassPeer},
		{CommandLinkAcceptAndRequest, messageClassPeer},
		{CommandParentRequest, messageClassUnknown},
		{CommandChildIDRequest, messageClassUnknown},
		{CommandDataRequest, messageClassUnknown},
	}

	for _, tt := range tests {
		got := classifyMessage(tt.cmd)
		if got != tt.want {
			t.Errorf("classifyMessage(%d) = %d, want %d", tt.cmd, got, tt.want)
		}
	}
}

func TestProcessKeySequence_NewerAuthoritative(t *testing.T) {
	t.Parallel()

	d, _, keyMgr := newTestDispatcher()
	keyMgr.currentSeq = 5

	n := &Neighbor{State: StateValid}

	rxInfo := &RxInfo{
		Neighbor:     n,
		KeySequence:  7,
		FrameCounter: 42,
		Command:      CommandAdvertisement, // Authoritative
	}

	d.processKeySequence(rxInfo)

	if keyMgr.currentSeq != 7 {
		t.Errorf("key sequence not advanced: got %d, want 7", keyMgr.currentSeq)
	}
	if n.Counters.MleFrameCounter != 42 {
		t.Errorf("frame counter not updated: got %d, want 42", n.Counters.MleFrameCounter)
	}

	// Verify flags.
	if len(keyMgr.seqUpdates) != 1 {
		t.Fatalf("expected 1 seq update, got %d", len(keyMgr.seqUpdates))
	}
	expectedFlags := key.ForceUpdate | key.ResetGuardTimer
	if keyMgr.seqUpdates[0].flags != expectedFlags {
		t.Errorf("seq update flags = %v, want %v", keyMgr.seqUpdates[0].flags, expectedFlags)
	}
}

func TestProcessKeySequence_NewerPeer(t *testing.T) {
	t.Parallel()

	d, _, keyMgr := newTestDispatcher()
	keyMgr.currentSeq = 5

	n := &Neighbor{State: StateValid}

	rxInfo := &RxInfo{
		Neighbor:     n,
		KeySequence:  6,
		FrameCounter: 10,
		Command:      CommandLinkAccept, // Peer
	}

	d.processKeySequence(rxInfo)

	if keyMgr.currentSeq != 6 {
		t.Errorf("key sequence not advanced: got %d, want 6", keyMgr.currentSeq)
	}

	expectedFlags := key.ApplySwitchGuard | key.ResetGuardTimer
	if keyMgr.seqUpdates[0].flags != expectedFlags {
		t.Errorf("seq update flags = %v, want %v", keyMgr.seqUpdates[0].flags, expectedFlags)
	}
}

func TestProcessKeySequence_OlderIgnored(t *testing.T) {
	t.Parallel()

	d, _, keyMgr := newTestDispatcher()
	keyMgr.currentSeq = 5

	n := &Neighbor{State: StateValid}

	rxInfo := &RxInfo{
		Neighbor:     n,
		KeySequence:  3,
		FrameCounter: 10,
		Command:      CommandAdvertisement,
	}

	d.processKeySequence(rxInfo)

	if keyMgr.currentSeq != 5 {
		t.Errorf("key sequence should not have changed: got %d", keyMgr.currentSeq)
	}
	if len(keyMgr.seqUpdates) != 0 {
		t.Error("should have no seq updates for older sequence")
	}
}

func TestProcessKeySequence_NilNeighbor(t *testing.T) {
	t.Parallel()

	d, _, keyMgr := newTestDispatcher()
	keyMgr.currentSeq = 5

	rxInfo := &RxInfo{
		Neighbor:     nil,
		KeySequence:  7,
		FrameCounter: 10,
		Command:      CommandAdvertisement,
	}

	// Should not panic.
	d.processKeySequence(rxInfo)

	if keyMgr.currentSeq != 5 {
		t.Error("key sequence should not change with nil neighbor")
	}
}

func TestSendMessage_IncrementsMleFrameCounter(t *testing.T) {
	t.Parallel()

	d, transport, keyMgr := newTestDispatcher()
	keyMgr.mleFrameCounter = 0

	msg := NewMessage(CommandParentRequest)
	msg.AppendModeTLV(NewDeviceMode(ModeRxOnWhenIdle | ModeFullThreadDevice))

	dst := ip6.Address{0xfe, 0x80}
	err := d.SendMessage(msg, dst)
	if err != nil {
		t.Fatalf("SendMessage error: %v", err)
	}

	if keyMgr.mleFrameCounter != 1 {
		t.Errorf("MLE frame counter = %d, want 1", keyMgr.mleFrameCounter)
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
	}
	if transport.sentMessages[0].dst != dst {
		t.Error("sent to wrong destination")
	}
}
