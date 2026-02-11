// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package ndagent

import (
	"testing"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

// mockChecker implements AddressChecker with a set of known Thread addresses.
type mockChecker struct {
	addresses map[ip6.Address]bool
}

func newMockChecker(addrs ...ip6.Address) *mockChecker {
	m := &mockChecker{addresses: make(map[ip6.Address]bool)}
	for _, a := range addrs {
		m.addresses[a] = true
	}
	return m
}

func (m *mockChecker) HasAddress(addr ip6.Address) bool {
	return m.addresses[addr]
}

// mockSender implements NaSender and records every NA that was sent.
type mockSender struct {
	calls   []naSent
	sendErr error
}

type naSent struct {
	target      ip6.Address
	destination ip6.Address
}

func (m *mockSender) SendNeighborAdvert(target ip6.Address, destination ip6.Address) error {
	m.calls = append(m.calls, naSent{target: target, destination: destination})
	return m.sendErr
}

// ---------------------------------------------------------------------------
// Test addresses
// ---------------------------------------------------------------------------

var (
	// A Thread device's global address.
	threadAddr1 = ip6.Address{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	// Another Thread device's address.
	threadAddr2 = ip6.Address{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	}
	// An address NOT belonging to any Thread device.
	nonThreadAddr = ip6.Address{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
	}
	// A link-local source address (typical NS sender).
	linkLocalSrc = ip6.Address{
		0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x01,
	}
	// Another source address.
	linkLocalSrc2 = ip6.Address{
		0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x02,
	}
)

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestNewAgentStartsDisabled(t *testing.T) {
	checker := newMockChecker()
	sender := &mockSender{}
	agent := NewAgent(checker, sender)

	if agent.IsEnabled() {
		t.Error("expected agent to start disabled")
	}
}

func TestEnableDisable(t *testing.T) {
	checker := newMockChecker()
	sender := &mockSender{}
	agent := NewAgent(checker, sender)

	agent.Enable()
	if !agent.IsEnabled() {
		t.Error("expected agent to be enabled")
	}

	agent.Disable()
	if agent.IsEnabled() {
		t.Error("expected agent to be disabled")
	}
}

func TestHandleNSWhenDisabled(t *testing.T) {
	checker := newMockChecker(threadAddr1)
	sender := &mockSender{}
	agent := NewAgent(checker, sender)
	// Agent is disabled by default.

	err := agent.HandleNeighborSolicitation(threadAddr1, linkLocalSrc)
	if err != errors.ErrInvalidState {
		t.Errorf("expected ErrInvalidState, got %v", err)
	}
	if len(sender.calls) != 0 {
		t.Error("expected no NA to be sent when disabled")
	}
}

func TestHandleNSForNonThreadAddress(t *testing.T) {
	checker := newMockChecker(threadAddr1)
	sender := &mockSender{}
	agent := NewAgent(checker, sender)
	agent.Enable()

	err := agent.HandleNeighborSolicitation(nonThreadAddr, linkLocalSrc)
	if err != errors.ErrDrop {
		t.Errorf("expected ErrDrop, got %v", err)
	}
	if len(sender.calls) != 0 {
		t.Error("expected no NA for non-Thread address")
	}
}

func TestHandleNSForThreadAddress(t *testing.T) {
	checker := newMockChecker(threadAddr1)
	sender := &mockSender{}
	agent := NewAgent(checker, sender)
	agent.Enable()

	err := agent.HandleNeighborSolicitation(threadAddr1, linkLocalSrc)
	if err != nil {
		t.Fatalf("HandleNeighborSolicitation: %v", err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("expected 1 NA sent, got %d", len(sender.calls))
	}
	na := sender.calls[0]
	if na.target != threadAddr1 {
		t.Errorf("NA target = %v, want %v", na.target, threadAddr1)
	}
	if na.destination != linkLocalSrc {
		t.Errorf("NA destination = %v, want %v (NS source)", na.destination, linkLocalSrc)
	}
}

func TestHandleNSFromUnspecifiedSource(t *testing.T) {
	// When source is :: (DAD case), NA destination should be ff02::1.
	checker := newMockChecker(threadAddr1)
	sender := &mockSender{}
	agent := NewAgent(checker, sender)
	agent.Enable()

	err := agent.HandleNeighborSolicitation(threadAddr1, unspecified)
	if err != nil {
		t.Fatalf("HandleNeighborSolicitation: %v", err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("expected 1 NA sent, got %d", len(sender.calls))
	}
	na := sender.calls[0]
	if na.target != threadAddr1 {
		t.Errorf("NA target = %v, want %v", na.target, threadAddr1)
	}
	if na.destination != allNodesMulticast {
		t.Errorf("NA destination = %v, want %v (all-nodes multicast)", na.destination, allNodesMulticast)
	}
}

func TestHandleNSMultipleAddresses(t *testing.T) {
	checker := newMockChecker(threadAddr1, threadAddr2)
	sender := &mockSender{}
	agent := NewAgent(checker, sender)
	agent.Enable()

	// NS for threadAddr1.
	if err := agent.HandleNeighborSolicitation(threadAddr1, linkLocalSrc); err != nil {
		t.Fatalf("NS for addr1: %v", err)
	}
	// NS for threadAddr2.
	if err := agent.HandleNeighborSolicitation(threadAddr2, linkLocalSrc2); err != nil {
		t.Fatalf("NS for addr2: %v", err)
	}

	if len(sender.calls) != 2 {
		t.Fatalf("expected 2 NAs sent, got %d", len(sender.calls))
	}
	if sender.calls[0].target != threadAddr1 {
		t.Errorf("first NA target mismatch")
	}
	if sender.calls[0].destination != linkLocalSrc {
		t.Errorf("first NA destination mismatch")
	}
	if sender.calls[1].target != threadAddr2 {
		t.Errorf("second NA target mismatch")
	}
	if sender.calls[1].destination != linkLocalSrc2 {
		t.Errorf("second NA destination mismatch")
	}
}

func TestHandleNSSenderError(t *testing.T) {
	checker := newMockChecker(threadAddr1)
	sender := &mockSender{sendErr: errors.ErrFailed}
	agent := NewAgent(checker, sender)
	agent.Enable()

	err := agent.HandleNeighborSolicitation(threadAddr1, linkLocalSrc)
	if err != errors.ErrFailed {
		t.Errorf("expected ErrFailed from sender, got %v", err)
	}
}

func TestHandleNSAfterDisable(t *testing.T) {
	checker := newMockChecker(threadAddr1)
	sender := &mockSender{}
	agent := NewAgent(checker, sender)

	agent.Enable()
	// Successfully handle one NS.
	if err := agent.HandleNeighborSolicitation(threadAddr1, linkLocalSrc); err != nil {
		t.Fatalf("first NS: %v", err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("expected 1 NA, got %d", len(sender.calls))
	}

	// Disable and try again.
	agent.Disable()
	err := agent.HandleNeighborSolicitation(threadAddr1, linkLocalSrc)
	if err != errors.ErrInvalidState {
		t.Errorf("expected ErrInvalidState after disable, got %v", err)
	}
	if len(sender.calls) != 1 {
		t.Error("expected no additional NA after disable")
	}
}

func TestHandleNeighborAdvertisementNoOp(t *testing.T) {
	checker := newMockChecker(threadAddr1)
	sender := &mockSender{}
	agent := NewAgent(checker, sender)
	agent.Enable()

	// Should not panic or have side effects.
	agent.HandleNeighborAdvertisement(threadAddr1, linkLocalSrc)

	if len(sender.calls) != 0 {
		t.Error("HandleNeighborAdvertisement should not send anything")
	}
}

func TestHandleNSEmptyChecker(t *testing.T) {
	// Checker with no addresses — everything should be dropped.
	checker := newMockChecker()
	sender := &mockSender{}
	agent := NewAgent(checker, sender)
	agent.Enable()

	err := agent.HandleNeighborSolicitation(threadAddr1, linkLocalSrc)
	if err != errors.ErrDrop {
		t.Errorf("expected ErrDrop, got %v", err)
	}
}

func TestHandleNSReEnable(t *testing.T) {
	checker := newMockChecker(threadAddr1)
	sender := &mockSender{}
	agent := NewAgent(checker, sender)

	agent.Enable()
	agent.Disable()
	agent.Enable()

	err := agent.HandleNeighborSolicitation(threadAddr1, linkLocalSrc)
	if err != nil {
		t.Fatalf("expected success after re-enable, got %v", err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("expected 1 NA, got %d", len(sender.calls))
	}
}
