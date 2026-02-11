// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package dhcp6

import (
	"testing"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Mock transport
// ---------------------------------------------------------------------------

type mockClientTransport struct {
	lastPayload []byte
	lastDst     ip6.Address
	lastDstPort uint16
	sendErr     error
	sendCount   int
}

func (m *mockClientTransport) Send(payload []byte, dst ip6.Address, dstPort uint16) error {
	m.sendCount++
	if m.sendErr != nil {
		return m.sendErr
	}
	m.lastPayload = make([]byte, len(payload))
	copy(m.lastPayload, payload)
	m.lastDst = dst
	m.lastDstPort = dstPort
	return nil
}

// ---------------------------------------------------------------------------
// TestNewClient
// ---------------------------------------------------------------------------

func TestNewClient(t *testing.T) {
	tr := &mockClientTransport{}
	extAddr := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	c := NewClient(tr, extAddr)

	if c == nil {
		t.Fatal("NewClient returned nil")
	}
	if c.IsRunning() {
		t.Error("client should not be running before Start")
	}
	if len(c.GetIdentityAssociations()) != 0 {
		t.Error("expected 0 identity associations")
	}
}

// ---------------------------------------------------------------------------
// TestClientStartStop
// ---------------------------------------------------------------------------

func TestClientStartStop(t *testing.T) {
	tr := &mockClientTransport{}
	c := NewClient(tr, types.ExtAddress{})

	if err := c.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if !c.IsRunning() {
		t.Error("client should be running after Start")
	}

	// Starting again should return ErrAlready.
	if err := c.Start(); err != errors.ErrAlready {
		t.Errorf("expected ErrAlready, got %v", err)
	}

	c.Stop()
	if c.IsRunning() {
		t.Error("client should not be running after Stop")
	}
}

// ---------------------------------------------------------------------------
// TestClientUpdateAddresses
// ---------------------------------------------------------------------------

func TestClientUpdateAddresses(t *testing.T) {
	tr := &mockClientTransport{}
	extAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	c := NewClient(tr, extAddr)

	prefix1 := ip6.NetworkPrefix{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00}
	prefix2 := ip6.NetworkPrefix{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00}

	c.UpdateAddresses([]PrefixInfo{
		{Prefix: prefix1, PrefixLength: 64, AgentRloc: 0x0400},
		{Prefix: prefix2, PrefixLength: 64, AgentRloc: 0x0800},
	})

	ias := c.GetIdentityAssociations()
	if len(ias) != 2 {
		t.Fatalf("expected 2 IAs, got %d", len(ias))
	}
	if ias[0].Prefix != prefix1 || ias[0].Status != IaStatusSolicit {
		t.Errorf("IA[0] mismatch: %+v", ias[0])
	}
	if ias[1].Prefix != prefix2 || ias[1].Status != IaStatusSolicit {
		t.Errorf("IA[1] mismatch: %+v", ias[1])
	}
}

func TestClientUpdateAddressesRemovesOld(t *testing.T) {
	tr := &mockClientTransport{}
	c := NewClient(tr, types.ExtAddress{})

	prefix1 := ip6.NetworkPrefix{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00}
	prefix2 := ip6.NetworkPrefix{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00}

	// Add two prefixes.
	c.UpdateAddresses([]PrefixInfo{
		{Prefix: prefix1, PrefixLength: 64},
		{Prefix: prefix2, PrefixLength: 64},
	})
	if len(c.GetIdentityAssociations()) != 2 {
		t.Fatalf("expected 2 IAs")
	}

	// Remove prefix1 by only including prefix2.
	c.UpdateAddresses([]PrefixInfo{
		{Prefix: prefix2, PrefixLength: 64},
	})

	// Only prefix2 should remain.
	ias := c.GetIdentityAssociations()
	found := false
	for _, ia := range ias {
		if ia.Status != IaStatusInvalid && ia.Prefix == prefix1 {
			t.Error("prefix1 should be invalidated")
		}
		if ia.Status != IaStatusInvalid && ia.Prefix == prefix2 {
			found = true
		}
	}
	if !found {
		t.Error("prefix2 should still be valid")
	}
}

// ---------------------------------------------------------------------------
// TestClientSolicit
// ---------------------------------------------------------------------------

func TestClientSolicit(t *testing.T) {
	tr := &mockClientTransport{}
	extAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	c := NewClient(tr, extAddr)

	prefix := ip6.NetworkPrefix{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00}
	c.UpdateAddresses([]PrefixInfo{
		{Prefix: prefix, PrefixLength: 64, AgentRloc: 0x0400},
	})

	// Start the client, which should trigger a Solicit.
	if err := c.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if tr.sendCount != 1 {
		t.Fatalf("expected 1 send, got %d", tr.sendCount)
	}

	// Verify the Solicit message.
	payload := tr.lastPayload
	if len(payload) < HeaderSize {
		t.Fatal("payload too short")
	}

	var hdr Header
	if err := hdr.UnmarshalBinary(payload); err != nil {
		t.Fatalf("UnmarshalBinary header failed: %v", err)
	}
	if hdr.Type != MsgTypeSolicit {
		t.Errorf("expected Solicit, got %d", hdr.Type)
	}

	// Parse options.
	opts, err := ParseOptions(payload[HeaderSize:])
	if err != nil {
		t.Fatalf("ParseOptions failed: %v", err)
	}

	// Should have ElapsedTime, ClientID, IaNa, RapidCommit.
	if FindOption(opts, OptionCodeElapsedTime) == nil {
		t.Error("missing ElapsedTime option")
	}
	clientIDOpt := FindOption(opts, OptionCodeClientID)
	if clientIDOpt == nil {
		t.Error("missing ClientID option")
	} else {
		var duid Eui64DUID
		if err := duid.UnmarshalBinary(clientIDOpt.Data); err != nil {
			t.Fatalf("bad ClientID: %v", err)
		}
		if duid.ExtAddress != extAddr {
			t.Errorf("ClientID ExtAddress mismatch")
		}
	}
	if FindOption(opts, OptionCodeIaNa) == nil {
		t.Error("missing IaNa option")
	}
	if !HasRapidCommit(opts) {
		t.Error("missing RapidCommit option")
	}

	// Destination should be all-DHCP multicast.
	if tr.lastDst != AllDHCPRelayAgentsAndServers {
		t.Errorf("destination mismatch: got %v", tr.lastDst)
	}
	if tr.lastDstPort != ServerPort {
		t.Errorf("port mismatch: got %d, want %d", tr.lastDstPort, ServerPort)
	}

	// IA should now be in Soliciting state.
	ias := c.GetIdentityAssociations()
	if ias[0].Status != IaStatusSoliciting {
		t.Errorf("expected IaStatusSoliciting, got %d", ias[0].Status)
	}
}

// ---------------------------------------------------------------------------
// TestClientHandleReceiveReply
// ---------------------------------------------------------------------------

func TestClientHandleReceiveReply(t *testing.T) {
	tr := &mockClientTransport{}
	clientExtAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	serverExtAddr := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	c := NewClient(tr, clientExtAddr)

	prefix := ip6.NetworkPrefix{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00}
	c.UpdateAddresses([]PrefixInfo{
		{Prefix: prefix, PrefixLength: 64},
	})
	_ = c.Start()

	// Build a Reply message matching the client's transaction ID.
	reply := buildTestReply(t, c.transactionID, serverExtAddr, clientExtAddr, prefix)

	msgInfo := &ip6.MessageInfo{
		PeerAddr: ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	}

	err := c.HandleReceive(reply, msgInfo)
	if err != nil {
		t.Fatalf("HandleReceive failed: %v", err)
	}

	// IA should now be in SolicitReplied state with an assigned address.
	ias := c.GetIdentityAssociations()
	if ias[0].Status != IaStatusSolicitReplied {
		t.Errorf("expected IaStatusSolicitReplied, got %d", ias[0].Status)
	}
	if ias[0].Address == (ip6.Address{}) {
		t.Error("expected a non-zero assigned address")
	}
	if ias[0].PreferredLifetime != InfiniteLifetime {
		t.Errorf("preferred lifetime: got %d, want %d", ias[0].PreferredLifetime, InfiniteLifetime)
	}
	if ias[0].ValidLifetime != InfiniteLifetime {
		t.Errorf("valid lifetime: got %d, want %d", ias[0].ValidLifetime, InfiniteLifetime)
	}
}

// buildTestReply constructs a valid Reply message for testing.
func buildTestReply(t *testing.T, txnID TransactionID, serverExt, clientExt types.ExtAddress, prefix ip6.NetworkPrefix) []byte {
	t.Helper()

	hdr := Header{
		Type:          MsgTypeReply,
		TransactionID: txnID,
	}
	hdrBytes, err := hdr.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary header failed: %v", err)
	}

	var buf []byte
	buf = append(buf, hdrBytes...)

	// Server ID.
	var serverDUID Eui64DUID
	serverDUID.Init(serverExt)
	buf = AppendServerIDOption(buf, &serverDUID)

	// Client ID.
	var clientDUID Eui64DUID
	clientDUID.Init(clientExt)
	buf = AppendClientIDOption(buf, &clientDUID)

	// IA_NA with IA Address sub-option.
	addr := MakeAddressFromPrefixEUI64(prefix, clientExt)
	iaAddr := IaAddress{
		Address:           addr,
		PreferredLifetime: InfiniteLifetime,
		ValidLifetime:     InfiniteLifetime,
	}
	var subOpts []byte
	subOpts = AppendStatusCodeOption(subOpts, StatusSuccess)
	subOpts = AppendIaAddressOption(subOpts, &iaAddr)

	iaNa := IaNa{
		IAID:       iaidFromPrefix(prefix),
		SubOptions: subOpts,
	}
	buf = AppendIaNaOption(buf, &iaNa)

	// Rapid Commit.
	buf = AppendRapidCommitOption(buf)

	return buf
}

// ---------------------------------------------------------------------------
// TestClientHandleReceiveWrongTransactionID
// ---------------------------------------------------------------------------

func TestClientHandleReceiveWrongTransactionID(t *testing.T) {
	tr := &mockClientTransport{}
	c := NewClient(tr, types.ExtAddress{0x01})

	prefix := ip6.NetworkPrefix{0x20, 0x01}
	c.UpdateAddresses([]PrefixInfo{{Prefix: prefix, PrefixLength: 64}})
	_ = c.Start()

	// Build a reply with a different transaction ID.
	wrongTxn := TransactionID{0xFF, 0xFF, 0xFF}
	reply := buildTestReply(t, wrongTxn, types.ExtAddress{0xAA}, types.ExtAddress{0x01}, prefix)

	err := c.HandleReceive(reply, &ip6.MessageInfo{})
	if err != errors.ErrDrop {
		t.Errorf("expected ErrDrop, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestClientHandleReceiveNonReply
// ---------------------------------------------------------------------------

func TestClientHandleReceiveNonReply(t *testing.T) {
	tr := &mockClientTransport{}
	c := NewClient(tr, types.ExtAddress{})
	_ = c.Start()

	// Send a Solicit message instead of a Reply.
	hdr := Header{Type: MsgTypeSolicit}
	payload, _ := hdr.MarshalBinary()

	err := c.HandleReceive(payload, &ip6.MessageInfo{})
	if err != errors.ErrDrop {
		t.Errorf("expected ErrDrop, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestClientHandleReceiveNotRunning
// ---------------------------------------------------------------------------

func TestClientHandleReceiveNotRunning(t *testing.T) {
	tr := &mockClientTransport{}
	c := NewClient(tr, types.ExtAddress{})

	err := c.HandleReceive(make([]byte, HeaderSize), &ip6.MessageInfo{})
	if err != errors.ErrInvalidState {
		t.Errorf("expected ErrInvalidState, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestClientHandleReceiveShortPayload
// ---------------------------------------------------------------------------

func TestClientHandleReceiveShortPayload(t *testing.T) {
	tr := &mockClientTransport{}
	c := NewClient(tr, types.ExtAddress{})
	_ = c.Start()

	err := c.HandleReceive([]byte{0x07}, &ip6.MessageInfo{})
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestClientHandleReceiveMissingRapidCommit
// ---------------------------------------------------------------------------

func TestClientHandleReceiveMissingRapidCommit(t *testing.T) {
	tr := &mockClientTransport{}
	clientExtAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	c := NewClient(tr, clientExtAddr)

	prefix := ip6.NetworkPrefix{0x20, 0x01}
	c.UpdateAddresses([]PrefixInfo{{Prefix: prefix, PrefixLength: 64}})
	_ = c.Start()

	// Build a Reply without Rapid Commit.
	hdr := Header{Type: MsgTypeReply, TransactionID: c.transactionID}
	hdrBytes, _ := hdr.MarshalBinary()
	var buf []byte
	buf = append(buf, hdrBytes...)

	var serverDUID Eui64DUID
	serverDUID.Init(types.ExtAddress{0xAA})
	buf = AppendServerIDOption(buf, &serverDUID)

	var clientDUID Eui64DUID
	clientDUID.Init(clientExtAddr)
	buf = AppendClientIDOption(buf, &clientDUID)
	// No RapidCommit appended.

	err := c.HandleReceive(buf, &ip6.MessageInfo{})
	if err != errors.ErrDrop {
		t.Errorf("expected ErrDrop, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestClientMultipleIAs
// ---------------------------------------------------------------------------

func TestClientMultipleIAs(t *testing.T) {
	tr := &mockClientTransport{}
	clientExtAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	serverExtAddr := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	c := NewClient(tr, clientExtAddr)

	prefix1 := ip6.NetworkPrefix{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00}
	prefix2 := ip6.NetworkPrefix{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00}

	c.UpdateAddresses([]PrefixInfo{
		{Prefix: prefix1, PrefixLength: 64},
		{Prefix: prefix2, PrefixLength: 64},
	})
	_ = c.Start()

	// First send should be for prefix1.
	if tr.sendCount != 1 {
		t.Fatalf("expected 1 send, got %d", tr.sendCount)
	}

	ias := c.GetIdentityAssociations()
	if ias[0].Status != IaStatusSoliciting {
		t.Errorf("IA[0] should be Soliciting, got %d", ias[0].Status)
	}
	if ias[1].Status != IaStatusSolicit {
		t.Errorf("IA[1] should be Solicit, got %d", ias[1].Status)
	}

	// Reply for prefix1.
	reply1 := buildTestReply(t, c.transactionID, serverExtAddr, clientExtAddr, prefix1)
	err := c.HandleReceive(reply1, &ip6.MessageInfo{})
	if err != nil {
		t.Fatalf("HandleReceive reply1 failed: %v", err)
	}

	// After processing reply1, prefix1 should be SolicitReplied,
	// and prefix2 should now be Soliciting (a new Solicit sent).
	ias = c.GetIdentityAssociations()
	if ias[0].Status != IaStatusSolicitReplied {
		t.Errorf("IA[0] should be SolicitReplied, got %d", ias[0].Status)
	}
	if ias[1].Status != IaStatusSoliciting {
		t.Errorf("IA[1] should be Soliciting, got %d", ias[1].Status)
	}
	if tr.sendCount != 2 {
		t.Errorf("expected 2 sends, got %d", tr.sendCount)
	}

	// Reply for prefix2.
	reply2 := buildTestReply(t, c.transactionID, serverExtAddr, clientExtAddr, prefix2)
	err = c.HandleReceive(reply2, &ip6.MessageInfo{})
	if err != nil {
		t.Fatalf("HandleReceive reply2 failed: %v", err)
	}

	ias = c.GetIdentityAssociations()
	if ias[1].Status != IaStatusSolicitReplied {
		t.Errorf("IA[1] should be SolicitReplied, got %d", ias[1].Status)
	}
}

// ---------------------------------------------------------------------------
// TestClientSendFailure
// ---------------------------------------------------------------------------

func TestClientSendFailure(t *testing.T) {
	tr := &mockClientTransport{sendErr: errors.ErrFailed}
	c := NewClient(tr, types.ExtAddress{})

	prefix := ip6.NetworkPrefix{0x20, 0x01}
	c.UpdateAddresses([]PrefixInfo{{Prefix: prefix, PrefixLength: 64}})
	_ = c.Start()

	// The IA should remain in Solicit state (not transition to Soliciting)
	// because the send failed.
	ias := c.GetIdentityAssociations()
	if ias[0].Status != IaStatusSolicit {
		t.Errorf("expected IaStatusSolicit after send failure, got %d", ias[0].Status)
	}
}
