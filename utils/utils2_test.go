// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"testing"

	"github.com/hilli/gothread/errors"
)

// ===========================================================================
// Test helpers / mocks
// ===========================================================================

// mockIcmpSender implements IcmpSender for tests.
type mockIcmpSender struct {
	sent []icmpSendRecord
	err  error
}

type icmpSendRecord struct {
	dest     [16]byte
	source   [16]byte
	payload  []byte
	hopLimit uint8
	sequence uint16
}

func (m *mockIcmpSender) SendEchoRequest(dest, source [16]byte, payload []byte, hopLimit uint8, sequence uint16) error {
	p := make([]byte, len(payload))
	copy(p, payload)
	m.sent = append(m.sent, icmpSendRecord{
		dest:     dest,
		source:   source,
		payload:  p,
		hopLimit: hopLimit,
		sequence: sequence,
	})
	return m.err
}

// mockPingCallback implements PingCallback for tests.
type mockPingCallback struct {
	replies []PingReply
	done    []PingStatistics
}

func (m *mockPingCallback) HandleReply(reply PingReply) {
	m.replies = append(m.replies, reply)
}

func (m *mockPingCallback) HandleDone(stats PingStatistics) {
	m.done = append(m.done, stats)
}

// mockDiagSender implements DiagSender for tests.
type mockDiagSender struct {
	sent []diagSendRecord
	err  error
}

type diagSendRecord struct {
	dest     [16]byte
	tlvTypes []uint8
}

func (m *mockDiagSender) SendDiagnosticGet(dest [16]byte, tlvTypes []uint8) error {
	t := make([]uint8, len(tlvTypes))
	copy(t, tlvTypes)
	m.sent = append(m.sent, diagSendRecord{
		dest:     dest,
		tlvTypes: t,
	})
	return m.err
}

// ===========================================================================
// History Tracker tests
// ===========================================================================

func TestNewTracker(t *testing.T) {
	t.Parallel()

	tr := NewTracker()
	if tr == nil {
		t.Fatal("NewTracker returned nil")
	}
	if !tr.IsEnabled() {
		t.Error("tracker should be enabled by default")
	}
	if len(tr.GetAllEvents()) != 0 {
		t.Error("new tracker should have no events")
	}
}

func TestTracker_WithMaxEvents(t *testing.T) {
	t.Parallel()

	tr := NewTracker(WithMaxEvents(10))
	if tr.maxEvents != 10 {
		t.Errorf("maxEvents = %d, want 10", tr.maxEvents)
	}
}

func TestTracker_WithMaxEvents_Invalid(t *testing.T) {
	t.Parallel()

	tr := NewTracker(WithMaxEvents(0))
	if tr.maxEvents != DefaultMaxEvents {
		t.Errorf("maxEvents = %d, want %d for invalid input", tr.maxEvents, DefaultMaxEvents)
	}

	tr = NewTracker(WithMaxEvents(-5))
	if tr.maxEvents != DefaultMaxEvents {
		t.Errorf("maxEvents = %d, want %d for negative input", tr.maxEvents, DefaultMaxEvents)
	}
}

func TestTracker_RecordAndGetAll(t *testing.T) {
	t.Parallel()

	tr := NewTracker(WithMaxEvents(4))

	tr.RecordEvent(EventTypeNetworkInfo, NetworkInfoEvent{Role: 1, Rloc16: 0x0400})
	tr.RecordEvent(EventTypeTxMessage, MessageEvent{Length: 64})
	tr.RecordEvent(EventTypeNeighborChanged, NeighborEvent{Event: "added"})

	events := tr.GetAllEvents()
	if len(events) != 3 {
		t.Fatalf("len = %d, want 3", len(events))
	}

	// Newest first.
	if events[0].Type != EventTypeNeighborChanged {
		t.Errorf("events[0].Type = %d, want %d", events[0].Type, EventTypeNeighborChanged)
	}
	if events[1].Type != EventTypeTxMessage {
		t.Errorf("events[1].Type = %d, want %d", events[1].Type, EventTypeTxMessage)
	}
	if events[2].Type != EventTypeNetworkInfo {
		t.Errorf("events[2].Type = %d, want %d", events[2].Type, EventTypeNetworkInfo)
	}
}

func TestTracker_CircularBuffer(t *testing.T) {
	t.Parallel()

	tr := NewTracker(WithMaxEvents(3))

	// Write 5 events into a buffer of size 3.
	tr.RecordEvent(EventTypeNetworkInfo, NetworkInfoEvent{Rloc16: 1})
	tr.RecordEvent(EventTypeNetworkInfo, NetworkInfoEvent{Rloc16: 2})
	tr.RecordEvent(EventTypeNetworkInfo, NetworkInfoEvent{Rloc16: 3})
	tr.RecordEvent(EventTypeNetworkInfo, NetworkInfoEvent{Rloc16: 4})
	tr.RecordEvent(EventTypeNetworkInfo, NetworkInfoEvent{Rloc16: 5})

	events := tr.GetAllEvents()
	if len(events) != 3 {
		t.Fatalf("len = %d, want 3", len(events))
	}

	// Should have the 3 most recent events, newest first.
	got0 := events[0].Data.(NetworkInfoEvent).Rloc16
	got1 := events[1].Data.(NetworkInfoEvent).Rloc16
	got2 := events[2].Data.(NetworkInfoEvent).Rloc16

	if got0 != 5 || got1 != 4 || got2 != 3 {
		t.Errorf("events = [%d, %d, %d], want [5, 4, 3]", got0, got1, got2)
	}
}

func TestTracker_GetEvents_Filtered(t *testing.T) {
	t.Parallel()

	tr := NewTracker()

	tr.RecordEvent(EventTypeNetworkInfo, nil)
	tr.RecordEvent(EventTypeTxMessage, nil)
	tr.RecordEvent(EventTypeNetworkInfo, nil)
	tr.RecordEvent(EventTypeRxMessage, nil)
	tr.RecordEvent(EventTypeNetworkInfo, nil)

	events := tr.GetEvents(EventTypeNetworkInfo)
	if len(events) != 3 {
		t.Fatalf("len = %d, want 3", len(events))
	}
	for i, e := range events {
		if e.Type != EventTypeNetworkInfo {
			t.Errorf("events[%d].Type = %d, want %d", i, e.Type, EventTypeNetworkInfo)
		}
	}
}

func TestTracker_GetEventCount(t *testing.T) {
	t.Parallel()

	tr := NewTracker()

	tr.RecordEvent(EventTypeRxMessage, nil)
	tr.RecordEvent(EventTypeTxMessage, nil)
	tr.RecordEvent(EventTypeRxMessage, nil)

	if got := tr.GetEventCount(EventTypeRxMessage); got != 2 {
		t.Errorf("count = %d, want 2", got)
	}
	if got := tr.GetEventCount(EventTypeTxMessage); got != 1 {
		t.Errorf("count = %d, want 1", got)
	}
	if got := tr.GetEventCount(EventTypeRouterInfo); got != 0 {
		t.Errorf("count = %d, want 0", got)
	}
}

func TestTracker_Clear(t *testing.T) {
	t.Parallel()

	tr := NewTracker()
	tr.RecordEvent(EventTypeNetworkInfo, nil)
	tr.RecordEvent(EventTypeTxMessage, nil)

	tr.Clear()
	if len(tr.GetAllEvents()) != 0 {
		t.Error("events should be empty after Clear")
	}
}

func TestTracker_EnableDisable(t *testing.T) {
	t.Parallel()

	tr := NewTracker()
	if !tr.IsEnabled() {
		t.Error("should be enabled initially")
	}

	tr.Disable()
	if tr.IsEnabled() {
		t.Error("should be disabled after Disable")
	}

	// Events are dropped when disabled.
	tr.RecordEvent(EventTypeNetworkInfo, nil)
	if len(tr.GetAllEvents()) != 0 {
		t.Error("no events should be recorded when disabled")
	}

	tr.Enable()
	if !tr.IsEnabled() {
		t.Error("should be enabled after Enable")
	}

	tr.RecordEvent(EventTypeNetworkInfo, nil)
	if len(tr.GetAllEvents()) != 1 {
		t.Error("events should be recorded when re-enabled")
	}
}

func TestTracker_Timestamp(t *testing.T) {
	t.Parallel()

	tr := NewTracker()
	tr.RecordEvent(EventTypeNetworkInfo, nil)
	tr.RecordEvent(EventTypeTxMessage, nil)
	tr.RecordEvent(EventTypeRxMessage, nil)

	events := tr.GetAllEvents()
	if len(events) != 3 {
		t.Fatalf("len = %d, want 3", len(events))
	}

	// Newest first: timestamps should be decreasing.
	if events[0].Timestamp <= events[1].Timestamp {
		t.Errorf("ts[0]=%d should be > ts[1]=%d", events[0].Timestamp, events[1].Timestamp)
	}
	if events[1].Timestamp <= events[2].Timestamp {
		t.Errorf("ts[1]=%d should be > ts[2]=%d", events[1].Timestamp, events[2].Timestamp)
	}
}

func TestTracker_EventData(t *testing.T) {
	t.Parallel()

	tr := NewTracker()

	netInfo := NetworkInfoEvent{Role: 3, Mode: 0x0f, Rloc16: 0x4400, PartitionID: 12345}
	tr.RecordEvent(EventTypeNetworkInfo, netInfo)

	events := tr.GetEvents(EventTypeNetworkInfo)
	if len(events) != 1 {
		t.Fatalf("len = %d, want 1", len(events))
	}

	got := events[0].Data.(NetworkInfoEvent)
	if got.Role != 3 {
		t.Errorf("Role = %d, want 3", got.Role)
	}
	if got.Rloc16 != 0x4400 {
		t.Errorf("Rloc16 = 0x%04x, want 0x4400", got.Rloc16)
	}
	if got.PartitionID != 12345 {
		t.Errorf("PartitionID = %d, want 12345", got.PartitionID)
	}
}

func TestTracker_MessageEventData(t *testing.T) {
	t.Parallel()

	tr := NewTracker()

	msg := MessageEvent{
		Source:      [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		Destination: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		Length:      128,
		Checksum:    0xabcd,
		Type:        58, // ICMPv6
		Security:    true,
	}
	tr.RecordEvent(EventTypeRxMessage, msg)

	events := tr.GetEvents(EventTypeRxMessage)
	if len(events) != 1 {
		t.Fatalf("len = %d, want 1", len(events))
	}

	got := events[0].Data.(MessageEvent)
	if got.Length != 128 {
		t.Errorf("Length = %d, want 128", got.Length)
	}
	if got.Type != 58 {
		t.Errorf("Type = %d, want 58", got.Type)
	}
	if !got.Security {
		t.Error("Security should be true")
	}
}

func TestTracker_NeighborEventData(t *testing.T) {
	t.Parallel()

	tr := NewTracker()

	ne := NeighborEvent{
		ExtAddress: [8]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11},
		Rloc16:     0x0c01,
		IsChild:    true,
		IsRouter:   false,
		Event:      "added",
	}
	tr.RecordEvent(EventTypeNeighborChanged, ne)

	events := tr.GetEvents(EventTypeNeighborChanged)
	if len(events) != 1 {
		t.Fatalf("len = %d, want 1", len(events))
	}

	got := events[0].Data.(NeighborEvent)
	if got.Rloc16 != 0x0c01 {
		t.Errorf("Rloc16 = 0x%04x, want 0x0c01", got.Rloc16)
	}
	if got.Event != "added" {
		t.Errorf("Event = %q, want %q", got.Event, "added")
	}
	if !got.IsChild {
		t.Error("IsChild should be true")
	}
}

// ===========================================================================
// PingSender tests
// ===========================================================================

func TestNewPingSender(t *testing.T) {
	t.Parallel()

	sender := &mockIcmpSender{}
	ps := NewPingSender(sender)
	if ps == nil {
		t.Fatal("NewPingSender returned nil")
	}
	if ps.IsActive() {
		t.Error("should not be active before Start")
	}
}

func TestPingSender_StartStop(t *testing.T) {
	t.Parallel()

	sender := &mockIcmpSender{}
	cb := &mockPingCallback{}
	ps := NewPingSender(sender)

	config := PingConfig{
		Destination: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		Count:       5,
	}

	err := ps.Start(config, cb)
	if err != nil {
		t.Fatalf("Start = %v, want nil", err)
	}
	if !ps.IsActive() {
		t.Error("should be active after Start")
	}

	ps.Stop()
	if ps.IsActive() {
		t.Error("should not be active after Stop")
	}

	// HandleDone should have been called.
	if len(cb.done) != 1 {
		t.Errorf("HandleDone called %d times, want 1", len(cb.done))
	}
}

func TestPingSender_DoubleStart(t *testing.T) {
	t.Parallel()

	sender := &mockIcmpSender{}
	cb := &mockPingCallback{}
	ps := NewPingSender(sender)

	config := PingConfig{
		Destination: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	}

	_ = ps.Start(config, cb)

	// Second start should return ErrInvalidState.
	err := ps.Start(config, cb)
	if err != errors.ErrInvalidState {
		t.Errorf("Start = %v, want ErrInvalidState", err)
	}

	ps.Stop()
}

func TestPingSender_StartNilCallback(t *testing.T) {
	t.Parallel()

	sender := &mockIcmpSender{}
	ps := NewPingSender(sender)

	config := PingConfig{
		Destination: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	}

	err := ps.Start(config, nil)
	if err != errors.ErrInvalidArgs {
		t.Errorf("Start = %v, want ErrInvalidArgs", err)
	}
}

func TestPingSender_StartZeroDest(t *testing.T) {
	t.Parallel()

	sender := &mockIcmpSender{}
	cb := &mockPingCallback{}
	ps := NewPingSender(sender)

	config := PingConfig{
		Destination: [16]byte{},
	}

	err := ps.Start(config, cb)
	if err != errors.ErrInvalidArgs {
		t.Errorf("Start = %v, want ErrInvalidArgs", err)
	}
}

func TestPingSender_StartNilSender(t *testing.T) {
	t.Parallel()

	ps := NewPingSender(nil)
	cb := &mockPingCallback{}

	config := PingConfig{
		Destination: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	}

	err := ps.Start(config, cb)
	if err != errors.ErrInvalidArgs {
		t.Errorf("Start = %v, want ErrInvalidArgs", err)
	}
}

func TestPingSender_HandleTimer(t *testing.T) {
	t.Parallel()

	sender := &mockIcmpSender{}
	cb := &mockPingCallback{}
	ps := NewPingSender(sender)

	dest := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	config := PingConfig{
		Destination: dest,
		Count:       3,
		Size:        16,
	}

	_ = ps.Start(config, cb)

	// Send 3 pings.
	ps.HandleTimer()
	ps.HandleTimer()
	ps.HandleTimer()

	if len(sender.sent) != 3 {
		t.Fatalf("sent = %d, want 3", len(sender.sent))
	}

	// Verify destinations.
	for i, rec := range sender.sent {
		if rec.dest != dest {
			t.Errorf("sent[%d].dest mismatch", i)
		}
		if len(rec.payload) != 16 {
			t.Errorf("sent[%d].payload len = %d, want 16", i, len(rec.payload))
		}
		if rec.sequence != uint16(i) {
			t.Errorf("sent[%d].sequence = %d, want %d", i, rec.sequence, i)
		}
	}

	// Statistics should show 3 sent.
	stats := ps.GetStatistics()
	if stats.Sent != 3 {
		t.Errorf("Sent = %d, want 3", stats.Sent)
	}

	// Next timer call should finish the session.
	ps.HandleTimer()
	if ps.IsActive() {
		t.Error("should not be active after all pings sent")
	}
	if len(cb.done) != 1 {
		t.Errorf("HandleDone called %d times, want 1", len(cb.done))
	}
}

func TestPingSender_HandleTimer_NotActive(t *testing.T) {
	t.Parallel()

	sender := &mockIcmpSender{}
	ps := NewPingSender(sender)

	// Should not panic.
	ps.HandleTimer()
	if len(sender.sent) != 0 {
		t.Error("should not send when not active")
	}
}

func TestPingSender_HandleEchoReply(t *testing.T) {
	t.Parallel()

	sender := &mockIcmpSender{}
	cb := &mockPingCallback{}
	ps := NewPingSender(sender)

	dest := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	config := PingConfig{
		Destination: dest,
		Count:       3,
		Size:        8,
	}

	_ = ps.Start(config, cb)

	// Send pings.
	ps.HandleTimer()
	ps.HandleTimer()
	ps.HandleTimer()

	// Handle replies.
	ps.HandleEchoReply(dest, 0, 64, 1000) // 1000 us
	ps.HandleEchoReply(dest, 1, 64, 3000) // 3000 us
	ps.HandleEchoReply(dest, 2, 64, 2000) // 2000 us

	if len(cb.replies) != 3 {
		t.Fatalf("replies = %d, want 3", len(cb.replies))
	}

	// Check reply values.
	if cb.replies[0].RoundTripTime != 1000 {
		t.Errorf("reply[0].RTT = %d, want 1000", cb.replies[0].RoundTripTime)
	}
	if cb.replies[1].Sequence != 1 {
		t.Errorf("reply[1].Sequence = %d, want 1", cb.replies[1].Sequence)
	}

	stats := ps.GetStatistics()
	if stats.Sent != 3 {
		t.Errorf("Sent = %d, want 3", stats.Sent)
	}
	if stats.Received != 3 {
		t.Errorf("Received = %d, want 3", stats.Received)
	}
	if stats.Lost != 0 {
		t.Errorf("Lost = %d, want 0", stats.Lost)
	}
	if stats.MinRtt != 1000 {
		t.Errorf("MinRtt = %d, want 1000", stats.MinRtt)
	}
	if stats.MaxRtt != 3000 {
		t.Errorf("MaxRtt = %d, want 3000", stats.MaxRtt)
	}
	if stats.AvgRtt != 2000 {
		t.Errorf("AvgRtt = %d, want 2000", stats.AvgRtt)
	}
}

func TestPingSender_HandleEchoReply_NotActive(t *testing.T) {
	t.Parallel()

	sender := &mockIcmpSender{}
	ps := NewPingSender(sender)

	// Should not panic when not active.
	ps.HandleEchoReply([16]byte{}, 0, 64, 1000)
}

func TestPingSender_Defaults(t *testing.T) {
	t.Parallel()

	sender := &mockIcmpSender{}
	cb := &mockPingCallback{}
	ps := NewPingSender(sender)

	config := PingConfig{
		Destination: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	}

	_ = ps.Start(config, cb)

	// HandleTimer to send one ping.
	ps.HandleTimer()

	if len(sender.sent) != 1 {
		t.Fatalf("sent = %d, want 1", len(sender.sent))
	}

	// Verify default payload size.
	if len(sender.sent[0].payload) != int(DefaultPingSize) {
		t.Errorf("payload size = %d, want %d", len(sender.sent[0].payload), DefaultPingSize)
	}

	// Default hop limit should be 64.
	if sender.sent[0].hopLimit != 64 {
		t.Errorf("hopLimit = %d, want 64", sender.sent[0].hopLimit)
	}

	ps.Stop()
}

func TestPingSender_PartialLoss(t *testing.T) {
	t.Parallel()

	sender := &mockIcmpSender{}
	cb := &mockPingCallback{}
	ps := NewPingSender(sender)

	dest := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	config := PingConfig{
		Destination: dest,
		Count:       5,
	}

	_ = ps.Start(config, cb)

	// Send all 5 pings.
	for i := 0; i < 5; i++ {
		ps.HandleTimer()
	}

	// Only reply to 3 of 5.
	ps.HandleEchoReply(dest, 0, 64, 1000)
	ps.HandleEchoReply(dest, 2, 64, 2000)
	ps.HandleEchoReply(dest, 4, 64, 3000)

	stats := ps.GetStatistics()
	if stats.Sent != 5 {
		t.Errorf("Sent = %d, want 5", stats.Sent)
	}
	if stats.Received != 3 {
		t.Errorf("Received = %d, want 3", stats.Received)
	}
	if stats.Lost != 2 {
		t.Errorf("Lost = %d, want 2", stats.Lost)
	}

	ps.Stop()
}

func TestPingSender_DoubleStop(t *testing.T) {
	t.Parallel()

	sender := &mockIcmpSender{}
	cb := &mockPingCallback{}
	ps := NewPingSender(sender)

	config := PingConfig{
		Destination: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		Count:       1,
	}

	_ = ps.Start(config, cb)
	ps.Stop()
	ps.Stop() // should not panic or double-call HandleDone

	if len(cb.done) != 1 {
		t.Errorf("HandleDone called %d times, want 1", len(cb.done))
	}
}

func TestPingSender_StopBeforeSend(t *testing.T) {
	t.Parallel()

	sender := &mockIcmpSender{}
	cb := &mockPingCallback{}
	ps := NewPingSender(sender)

	config := PingConfig{
		Destination: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		Count:       5,
	}

	_ = ps.Start(config, cb)
	ps.Stop()

	// Stats should show 0 sent.
	if len(cb.done) != 1 {
		t.Fatalf("HandleDone called %d times, want 1", len(cb.done))
	}
	if cb.done[0].Sent != 0 {
		t.Errorf("Sent = %d, want 0", cb.done[0].Sent)
	}
}

func TestPingSender_SendError(t *testing.T) {
	t.Parallel()

	sender := &mockIcmpSender{err: errors.ErrFailed}
	cb := &mockPingCallback{}
	ps := NewPingSender(sender)

	dest := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	config := PingConfig{
		Destination: dest,
		Count:       3,
	}

	_ = ps.Start(config, cb)
	ps.HandleTimer()

	// Sent counter should not increase on error.
	stats := ps.GetStatistics()
	if stats.Sent != 0 {
		t.Errorf("Sent = %d, want 0 on send error", stats.Sent)
	}

	ps.Stop()
}

func TestPingSender_HopLimitZero(t *testing.T) {
	t.Parallel()

	sender := &mockIcmpSender{}
	cb := &mockPingCallback{}
	ps := NewPingSender(sender)

	config := PingConfig{
		Destination:       [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		Count:             1,
		HopLimit:          0,
		AllowZeroHopLimit: true,
	}

	_ = ps.Start(config, cb)
	ps.HandleTimer()

	if len(sender.sent) != 1 {
		t.Fatalf("sent = %d, want 1", len(sender.sent))
	}
	if sender.sent[0].hopLimit != 0 {
		t.Errorf("hopLimit = %d, want 0 with AllowZeroHopLimit", sender.sent[0].hopLimit)
	}

	ps.Stop()
}

// ===========================================================================
// MeshDiag tests
// ===========================================================================

func TestNewMeshDiag(t *testing.T) {
	t.Parallel()

	sender := &mockDiagSender{}
	md := NewMeshDiag(sender)
	if md == nil {
		t.Fatal("NewMeshDiag returned nil")
	}
	if md.IsActive() {
		t.Error("should not be active before DiscoverTopology")
	}
}

func TestMeshDiag_DiscoverTopology(t *testing.T) {
	t.Parallel()

	sender := &mockDiagSender{}
	md := NewMeshDiag(sender)

	called := false
	err := md.DiscoverTopology(func(info RouterInfo, err error) {
		called = true
	})
	if err != nil {
		t.Fatalf("DiscoverTopology = %v, want nil", err)
	}
	if !md.IsActive() {
		t.Error("should be active after DiscoverTopology")
	}
	if called {
		t.Error("callback should not be called yet")
	}
}

func TestMeshDiag_DiscoverTopology_DoubleStart(t *testing.T) {
	t.Parallel()

	sender := &mockDiagSender{}
	md := NewMeshDiag(sender)

	_ = md.DiscoverTopology(func(info RouterInfo, err error) {})

	err := md.DiscoverTopology(func(info RouterInfo, err error) {})
	if err != errors.ErrInvalidState {
		t.Errorf("DiscoverTopology = %v, want ErrInvalidState", err)
	}
}

func TestMeshDiag_DiscoverTopology_NilCallback(t *testing.T) {
	t.Parallel()

	sender := &mockDiagSender{}
	md := NewMeshDiag(sender)

	err := md.DiscoverTopology(nil)
	if err != errors.ErrInvalidArgs {
		t.Errorf("DiscoverTopology = %v, want ErrInvalidArgs", err)
	}
}

func TestMeshDiag_DiscoverTopology_NilSender(t *testing.T) {
	t.Parallel()

	md := NewMeshDiag(nil)

	err := md.DiscoverTopology(func(info RouterInfo, err error) {})
	if err != errors.ErrInvalidArgs {
		t.Errorf("DiscoverTopology = %v, want ErrInvalidArgs", err)
	}
}

func TestMeshDiag_HandleDiagnosticResponse(t *testing.T) {
	t.Parallel()

	sender := &mockDiagSender{}
	md := NewMeshDiag(sender)

	var results []RouterInfo
	_ = md.DiscoverTopology(func(info RouterInfo, err error) {
		if err == nil {
			results = append(results, info)
		}
	})

	// Build a diagnostic response with ExtAddress and Version TLVs.
	source := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x00}

	var data []byte
	// ExtAddress TLV: type=0, len=8
	data = append(data,
		DiagTLVExtAddress, 8, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		// Version TLV: type=24, len=2
		// version 4
		DiagTLVVersion, 2, 0x00, 0x04,
	)

	md.HandleDiagnosticResponse(source, data)

	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}

	r := results[0]
	if r.Rloc16 != 0x0400 {
		t.Errorf("Rloc16 = 0x%04x, want 0x0400", r.Rloc16)
	}
	if r.Version != 4 {
		t.Errorf("Version = %d, want 4", r.Version)
	}
	expectedExt := [8]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	if r.ExtAddress != expectedExt {
		t.Errorf("ExtAddress = %v, want %v", r.ExtAddress, expectedExt)
	}
}

func TestMeshDiag_HandleDiagnosticResponse_NotActive(t *testing.T) {
	t.Parallel()

	sender := &mockDiagSender{}
	md := NewMeshDiag(sender)

	// Should not panic when not active.
	md.HandleDiagnosticResponse([16]byte{}, []byte{})

	routers := md.GetDiscoveredRouters()
	if routers != nil {
		t.Error("should have no discovered routers")
	}
}

func TestMeshDiag_Cancel(t *testing.T) {
	t.Parallel()

	sender := &mockDiagSender{}
	md := NewMeshDiag(sender)

	_ = md.DiscoverTopology(func(info RouterInfo, err error) {})

	md.Cancel()
	if md.IsActive() {
		t.Error("should not be active after Cancel")
	}

	// Double cancel is safe.
	md.Cancel()
}

func TestMeshDiag_GetDiscoveredRouters(t *testing.T) {
	t.Parallel()

	sender := &mockDiagSender{}
	md := NewMeshDiag(sender)

	_ = md.DiscoverTopology(func(info RouterInfo, err error) {})

	// Inject two router responses.
	src1 := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x00}
	src2 := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00}

	md.HandleDiagnosticResponse(src1, nil)
	md.HandleDiagnosticResponse(src2, nil)

	routers := md.GetDiscoveredRouters()
	if len(routers) != 2 {
		t.Fatalf("routers = %d, want 2", len(routers))
	}

	if routers[0].Rloc16 != 0x0400 {
		t.Errorf("routers[0].Rloc16 = 0x%04x, want 0x0400", routers[0].Rloc16)
	}
	if routers[1].Rloc16 != 0x0800 {
		t.Errorf("routers[1].Rloc16 = 0x%04x, want 0x0800", routers[1].Rloc16)
	}
}

func TestMeshDiag_GetDiscoveredRouters_IsACopy(t *testing.T) {
	t.Parallel()

	sender := &mockDiagSender{}
	md := NewMeshDiag(sender)

	_ = md.DiscoverTopology(func(info RouterInfo, err error) {})

	src := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x00}
	md.HandleDiagnosticResponse(src, nil)

	routers := md.GetDiscoveredRouters()
	routers[0].Rloc16 = 0xFFFF // mutate the copy

	// Original should be unaffected.
	original := md.GetDiscoveredRouters()
	if original[0].Rloc16 == 0xFFFF {
		t.Error("GetDiscoveredRouters should return a copy")
	}
}

func TestMeshDiag_ParseAddress16TLV(t *testing.T) {
	t.Parallel()

	sender := &mockDiagSender{}
	md := NewMeshDiag(sender)

	var results []RouterInfo
	_ = md.DiscoverTopology(func(info RouterInfo, err error) {
		if err == nil {
			results = append(results, info)
		}
	})

	source := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x00}

	// Address16 TLV overrides the RLOC from source.
	var data []byte
	data = append(data, DiagTLVAddress16, 2, 0x0C, 0x00)

	md.HandleDiagnosticResponse(source, data)

	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if results[0].Rloc16 != 0x0C00 {
		t.Errorf("Rloc16 = 0x%04x, want 0x0C00", results[0].Rloc16)
	}
}

func TestMeshDiag_ParseIPv6AddrListTLV(t *testing.T) {
	t.Parallel()

	sender := &mockDiagSender{}
	md := NewMeshDiag(sender)

	var results []RouterInfo
	_ = md.DiscoverTopology(func(info RouterInfo, err error) {
		if err == nil {
			results = append(results, info)
		}
	})

	source := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x00}

	// IPv6 address list TLV with 2 addresses (32 bytes).
	var data []byte
	data = append(data, DiagTLVIPv6AddrList, 32)
	// First address: fe80::1
	addr1 := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	data = append(data, addr1[:]...)
	// Second address: fe80::2
	addr2 := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	data = append(data, addr2[:]...)

	md.HandleDiagnosticResponse(source, data)

	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if len(results[0].IPv6Addresses) != 2 {
		t.Fatalf("IPv6Addresses = %d, want 2", len(results[0].IPv6Addresses))
	}
	if results[0].IPv6Addresses[0] != addr1 {
		t.Errorf("addr[0] = %v, want %v", results[0].IPv6Addresses[0], addr1)
	}
	if results[0].IPv6Addresses[1] != addr2 {
		t.Errorf("addr[1] = %v, want %v", results[0].IPv6Addresses[1], addr2)
	}
}

func TestMeshDiag_ParseChildTableTLV(t *testing.T) {
	t.Parallel()

	sender := &mockDiagSender{}
	md := NewMeshDiag(sender)

	var results []RouterInfo
	_ = md.DiscoverTopology(func(info RouterInfo, err error) {
		if err == nil {
			results = append(results, info)
		}
	})

	source := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x00}

	// Child table TLV with 4 child entries (3 bytes each = 12 bytes).
	var data []byte
	data = append(data, DiagTLVChildTable, 12)
	data = append(data, make([]byte, 12)...)

	md.HandleDiagnosticResponse(source, data)

	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if results[0].ChildCount != 4 {
		t.Errorf("ChildCount = %d, want 4", results[0].ChildCount)
	}
}

func TestMeshDiag_ParseTruncatedData(t *testing.T) {
	t.Parallel()

	sender := &mockDiagSender{}
	md := NewMeshDiag(sender)

	var results []RouterInfo
	_ = md.DiscoverTopology(func(info RouterInfo, err error) {
		if err == nil {
			results = append(results, info)
		}
	})

	source := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x00}

	// Truncated data: TLV says length 8 but only 3 bytes available.
	data := []byte{DiagTLVExtAddress, 8, 0xaa, 0xbb, 0xcc}
	md.HandleDiagnosticResponse(source, data)

	// Should still produce a result (with default values).
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
}

func TestMeshDiag_ParseEmptyData(t *testing.T) {
	t.Parallel()

	sender := &mockDiagSender{}
	md := NewMeshDiag(sender)

	var results []RouterInfo
	_ = md.DiscoverTopology(func(info RouterInfo, err error) {
		if err == nil {
			results = append(results, info)
		}
	})

	source := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x00}
	md.HandleDiagnosticResponse(source, nil)

	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if results[0].Rloc16 != 0x0400 {
		t.Errorf("Rloc16 = 0x%04x, want 0x0400", results[0].Rloc16)
	}
}

// ===========================================================================
// Diagnostic TLV constant tests
// ===========================================================================

func TestDiagTLVConstants(t *testing.T) {
	t.Parallel()

	if DiagTLVExtAddress != 0 {
		t.Errorf("DiagTLVExtAddress = %d, want 0", DiagTLVExtAddress)
	}
	if DiagTLVAddress16 != 1 {
		t.Errorf("DiagTLVAddress16 = %d, want 1", DiagTLVAddress16)
	}
	if DiagTLVChildTable != 14 {
		t.Errorf("DiagTLVChildTable = %d, want 14", DiagTLVChildTable)
	}
	if DiagTLVVersion != 24 {
		t.Errorf("DiagTLVVersion = %d, want 24", DiagTLVVersion)
	}
}

// ===========================================================================
// Ping default constant tests
// ===========================================================================

func TestPingDefaultConstants(t *testing.T) {
	t.Parallel()

	if DefaultPingSize != 8 {
		t.Errorf("DefaultPingSize = %d, want 8", DefaultPingSize)
	}
	if DefaultPingCount != 1 {
		t.Errorf("DefaultPingCount = %d, want 1", DefaultPingCount)
	}
	if DefaultPingInterval != 1000 {
		t.Errorf("DefaultPingInterval = %d, want 1000", DefaultPingInterval)
	}
	if DefaultPingTimeout != 3000 {
		t.Errorf("DefaultPingTimeout = %d, want 3000", DefaultPingTimeout)
	}
}

// ===========================================================================
// EventType constant tests
// ===========================================================================

func TestEventTypeConstants(t *testing.T) {
	t.Parallel()

	if EventTypeNetworkInfo != 0 {
		t.Errorf("EventTypeNetworkInfo = %d, want 0", EventTypeNetworkInfo)
	}
	if EventTypeExternalRoute != 7 {
		t.Errorf("EventTypeExternalRoute = %d, want 7", EventTypeExternalRoute)
	}
}

func TestDefaultMaxEvents(t *testing.T) {
	t.Parallel()

	if DefaultMaxEvents != 64 {
		t.Errorf("DefaultMaxEvents = %d, want 64", DefaultMaxEvents)
	}
}
