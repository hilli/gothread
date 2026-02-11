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
// Mock server transport
// ---------------------------------------------------------------------------

type mockServerTransport struct {
	lastPayload []byte
	lastDst     ip6.Address
	lastDstPort uint16
	sendErr     error
	sendCount   int
}

func (m *mockServerTransport) Send(payload []byte, dst ip6.Address, dstPort uint16) error {
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
// TestNewServer
// ---------------------------------------------------------------------------

func TestNewServer(t *testing.T) {
	tr := &mockServerTransport{}
	extAddr := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	s := NewServer(tr, extAddr)

	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	if s.IsRunning() {
		t.Error("server should not be running before Start")
	}
	if len(s.GetPrefixAgents()) != 0 {
		t.Error("expected 0 prefix agents")
	}
}

// ---------------------------------------------------------------------------
// TestServerStartStop
// ---------------------------------------------------------------------------

func TestServerStartStop(t *testing.T) {
	tr := &mockServerTransport{}
	s := NewServer(tr, types.ExtAddress{})

	if err := s.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if !s.IsRunning() {
		t.Error("server should be running after Start")
	}

	if err := s.Start(); err != errors.ErrAlready {
		t.Errorf("expected ErrAlready, got %v", err)
	}

	s.Stop()
	if s.IsRunning() {
		t.Error("server should not be running after Stop")
	}
}

// ---------------------------------------------------------------------------
// TestServerAddRemovePrefix
// ---------------------------------------------------------------------------

func TestServerAddRemovePrefix(t *testing.T) {
	tr := &mockServerTransport{}
	s := NewServer(tr, types.ExtAddress{})

	prefix := ip6.NetworkPrefix{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00}

	if err := s.AddPrefix(prefix, 64); err != nil {
		t.Fatalf("AddPrefix failed: %v", err)
	}
	if !s.HasPrefix(prefix) {
		t.Error("server should have the prefix")
	}

	// Duplicate add.
	if err := s.AddPrefix(prefix, 64); err != errors.ErrAlready {
		t.Errorf("expected ErrAlready, got %v", err)
	}

	// Remove.
	if err := s.RemovePrefix(prefix); err != nil {
		t.Fatalf("RemovePrefix failed: %v", err)
	}
	if s.HasPrefix(prefix) {
		t.Error("server should not have the prefix after removal")
	}

	// Remove again.
	if err := s.RemovePrefix(prefix); err != errors.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	// Re-add should work (reactivate).
	if err := s.AddPrefix(prefix, 64); err != nil {
		t.Fatalf("re-AddPrefix failed: %v", err)
	}
	if !s.HasPrefix(prefix) {
		t.Error("server should have the prefix after re-add")
	}
}

// ---------------------------------------------------------------------------
// TestServerHandleSolicit
// ---------------------------------------------------------------------------

func TestServerHandleSolicit(t *testing.T) {
	tr := &mockServerTransport{}
	serverExtAddr := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	s := NewServer(tr, serverExtAddr)
	_ = s.Start()

	prefix := ip6.NetworkPrefix{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00}
	_ = s.AddPrefix(prefix, 64)

	// Build a Solicit message.
	clientExtAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	solicit := buildTestSolicit(t, clientExtAddr, prefix)

	peerAddr := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42}
	msgInfo := &ip6.MessageInfo{
		PeerAddr: peerAddr,
		PeerPort: ClientPort,
	}

	err := s.HandleReceive(solicit, msgInfo)
	if err != nil {
		t.Fatalf("HandleReceive failed: %v", err)
	}

	// Server should have sent a Reply.
	if tr.sendCount != 1 {
		t.Fatalf("expected 1 send, got %d", tr.sendCount)
	}

	// Verify the Reply.
	reply := tr.lastPayload
	if len(reply) < HeaderSize {
		t.Fatal("reply too short")
	}

	var hdr Header
	if err := hdr.UnmarshalBinary(reply); err != nil {
		t.Fatalf("UnmarshalBinary header failed: %v", err)
	}
	if hdr.Type != MsgTypeReply {
		t.Errorf("expected Reply, got %d", hdr.Type)
	}

	// Parse reply options.
	opts, err := ParseOptions(reply[HeaderSize:])
	if err != nil {
		t.Fatalf("ParseOptions failed: %v", err)
	}

	// Should have ServerID.
	serverIDOpt := FindOption(opts, OptionCodeServerID)
	if serverIDOpt == nil {
		t.Error("missing ServerID option")
	} else {
		var duid Eui64DUID
		if err := duid.UnmarshalBinary(serverIDOpt.Data); err != nil {
			t.Fatalf("bad ServerID: %v", err)
		}
		if duid.ExtAddress != serverExtAddr {
			t.Errorf("ServerID ExtAddress mismatch")
		}
	}

	// Should have ClientID.
	clientIDOpt := FindOption(opts, OptionCodeClientID)
	if clientIDOpt == nil {
		t.Error("missing ClientID option")
	} else {
		var duid Eui64DUID
		if err := duid.UnmarshalBinary(clientIDOpt.Data); err != nil {
			t.Fatalf("bad ClientID: %v", err)
		}
		if duid.ExtAddress != clientExtAddr {
			t.Errorf("ClientID ExtAddress mismatch")
		}
	}

	// Should have IaNa with IA Address.
	iaNaOpt := FindOption(opts, OptionCodeIaNa)
	if iaNaOpt == nil {
		t.Fatal("missing IaNa option")
	}
	var iaNa IaNa
	if err := iaNa.UnmarshalBinary(iaNaOpt.Data); err != nil {
		t.Fatalf("bad IaNa: %v", err)
	}

	subOpts, err := ParseOptions(iaNa.SubOptions)
	if err != nil {
		t.Fatalf("ParseOptions sub failed: %v", err)
	}

	// Should have StatusCode = Success.
	scOpt := FindOption(subOpts, OptionCodeStatusCode)
	if scOpt == nil {
		t.Error("missing StatusCode in IaNa sub-options")
	} else {
		var sc StatusCode
		if err := sc.UnmarshalBinary(scOpt.Data); err != nil {
			t.Fatalf("bad StatusCode: %v", err)
		}
		if sc.Code != StatusSuccess {
			t.Errorf("expected StatusSuccess, got %d", sc.Code)
		}
	}

	// Should have IA Address.
	iaAddrOpt := FindOption(subOpts, OptionCodeIaAddress)
	if iaAddrOpt == nil {
		t.Fatal("missing IaAddress in IaNa sub-options")
	}
	var iaAddr IaAddress
	if err := iaAddr.UnmarshalBinary(iaAddrOpt.Data); err != nil {
		t.Fatalf("bad IaAddress: %v", err)
	}

	// Verify the address is prefix + modified client EUI-64.
	expectedAddr := MakeAddressFromPrefixEUI64(prefix, clientExtAddr)
	if iaAddr.Address != expectedAddr {
		t.Errorf("address mismatch: got %v, want %v", iaAddr.Address, expectedAddr)
	}
	if iaAddr.PreferredLifetime != InfiniteLifetime {
		t.Errorf("preferred lifetime: got %d", iaAddr.PreferredLifetime)
	}
	if iaAddr.ValidLifetime != InfiniteLifetime {
		t.Errorf("valid lifetime: got %d", iaAddr.ValidLifetime)
	}

	// Should have RapidCommit.
	if !HasRapidCommit(opts) {
		t.Error("missing RapidCommit in reply")
	}

	// Reply should be sent to the client's address.
	if tr.lastDst != peerAddr {
		t.Errorf("reply dst: got %v, want %v", tr.lastDst, peerAddr)
	}
	if tr.lastDstPort != ClientPort {
		t.Errorf("reply port: got %d, want %d", tr.lastDstPort, ClientPort)
	}
}

// buildTestSolicit constructs a valid Solicit message for testing.
func buildTestSolicit(t *testing.T, clientExt types.ExtAddress, prefix ip6.NetworkPrefix) []byte {
	t.Helper()

	var txnID TransactionID
	_ = txnID.GenerateRandom()

	hdr := Header{
		Type:          MsgTypeSolicit,
		TransactionID: txnID,
	}
	hdrBytes, err := hdr.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary header failed: %v", err)
	}

	var buf []byte
	buf = append(buf, hdrBytes...)

	// Elapsed Time.
	buf = AppendElapsedTimeOption(buf, 0)

	// Client ID.
	var clientDUID Eui64DUID
	clientDUID.Init(clientExt)
	buf = AppendClientIDOption(buf, &clientDUID)

	// IA_NA.
	iaNa := IaNa{
		IAID: iaidFromPrefix(prefix),
	}
	buf = AppendIaNaOption(buf, &iaNa)

	// Rapid Commit.
	buf = AppendRapidCommitOption(buf)

	return buf
}

// ---------------------------------------------------------------------------
// TestServerRejectNonSolicit
// ---------------------------------------------------------------------------

func TestServerRejectNonSolicit(t *testing.T) {
	tr := &mockServerTransport{}
	s := NewServer(tr, types.ExtAddress{})
	_ = s.Start()

	// Send a Reply message (not a Solicit).
	hdr := Header{Type: MsgTypeReply}
	payload, _ := hdr.MarshalBinary()

	err := s.HandleReceive(payload, &ip6.MessageInfo{})
	if err != errors.ErrDrop {
		t.Errorf("expected ErrDrop, got %v", err)
	}
	if tr.sendCount != 0 {
		t.Errorf("server should not send anything, got %d sends", tr.sendCount)
	}
}

// ---------------------------------------------------------------------------
// TestServerNotRunning
// ---------------------------------------------------------------------------

func TestServerNotRunning(t *testing.T) {
	tr := &mockServerTransport{}
	s := NewServer(tr, types.ExtAddress{})

	err := s.HandleReceive(make([]byte, HeaderSize), &ip6.MessageInfo{})
	if err != errors.ErrInvalidState {
		t.Errorf("expected ErrInvalidState, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestServerShortPayload
// ---------------------------------------------------------------------------

func TestServerShortPayload(t *testing.T) {
	tr := &mockServerTransport{}
	s := NewServer(tr, types.ExtAddress{})
	_ = s.Start()

	err := s.HandleReceive([]byte{0x01}, &ip6.MessageInfo{})
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestServerRejectSolicitWithServerID
// ---------------------------------------------------------------------------

func TestServerRejectSolicitWithServerID(t *testing.T) {
	tr := &mockServerTransport{}
	s := NewServer(tr, types.ExtAddress{})
	_ = s.Start()

	// Build a Solicit that contains a ServerID (not allowed).
	var txnID TransactionID
	_ = txnID.GenerateRandom()
	hdr := Header{Type: MsgTypeSolicit, TransactionID: txnID}
	hdrBytes, _ := hdr.MarshalBinary()

	var buf []byte
	buf = append(buf, hdrBytes...)

	var clientDUID Eui64DUID
	clientDUID.Init(types.ExtAddress{0x11})
	buf = AppendClientIDOption(buf, &clientDUID)

	var serverDUID Eui64DUID
	serverDUID.Init(types.ExtAddress{0xAA})
	buf = AppendServerIDOption(buf, &serverDUID)

	buf = AppendRapidCommitOption(buf)

	err := s.HandleReceive(buf, &ip6.MessageInfo{})
	if err != errors.ErrDrop {
		t.Errorf("expected ErrDrop for Solicit with ServerID, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestServerRejectSolicitWithoutRapidCommit
// ---------------------------------------------------------------------------

func TestServerRejectSolicitWithoutRapidCommit(t *testing.T) {
	tr := &mockServerTransport{}
	s := NewServer(tr, types.ExtAddress{})
	_ = s.Start()

	var txnID TransactionID
	_ = txnID.GenerateRandom()
	hdr := Header{Type: MsgTypeSolicit, TransactionID: txnID}
	hdrBytes, _ := hdr.MarshalBinary()

	var buf []byte
	buf = append(buf, hdrBytes...)

	var clientDUID Eui64DUID
	clientDUID.Init(types.ExtAddress{0x11})
	buf = AppendClientIDOption(buf, &clientDUID)
	// No RapidCommit.

	iaNa := IaNa{IAID: 1}
	buf = AppendIaNaOption(buf, &iaNa)

	err := s.HandleReceive(buf, &ip6.MessageInfo{})
	if err != errors.ErrDrop {
		t.Errorf("expected ErrDrop for Solicit without RapidCommit, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestServerMultiplePrefixes
// ---------------------------------------------------------------------------

func TestServerMultiplePrefixes(t *testing.T) {
	tr := &mockServerTransport{}
	serverExtAddr := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	s := NewServer(tr, serverExtAddr)
	_ = s.Start()

	prefix1 := ip6.NetworkPrefix{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00}
	prefix2 := ip6.NetworkPrefix{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00}
	_ = s.AddPrefix(prefix1, 64)
	_ = s.AddPrefix(prefix2, 64)

	clientExtAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	solicit := buildTestSolicit(t, clientExtAddr, prefix1)

	err := s.HandleReceive(solicit, &ip6.MessageInfo{
		PeerAddr: ip6.Address{0xfe, 0x80},
	})
	if err != nil {
		t.Fatalf("HandleReceive failed: %v", err)
	}

	// The reply should contain IA Addresses for both prefixes.
	reply := tr.lastPayload
	var hdr Header
	_ = hdr.UnmarshalBinary(reply)

	opts, _ := ParseOptions(reply[HeaderSize:])
	iaNaOpt := FindOption(opts, OptionCodeIaNa)
	if iaNaOpt == nil {
		t.Fatal("missing IaNa option in reply")
	}

	var iaNa IaNa
	_ = iaNa.UnmarshalBinary(iaNaOpt.Data)
	subOpts, _ := ParseOptions(iaNa.SubOptions)

	// Count IA Address options.
	addrCount := 0
	for i := range subOpts {
		if subOpts[i].Header.Code == OptionCodeIaAddress {
			addrCount++
		}
	}
	if addrCount != 2 {
		t.Errorf("expected 2 IA Addresses, got %d", addrCount)
	}
}

// ---------------------------------------------------------------------------
// TestClientServerIntegration
// ---------------------------------------------------------------------------

func TestClientServerIntegration(t *testing.T) {
	// End-to-end test: client sends Solicit, server processes it,
	// client processes the Reply.

	clientExtAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	serverExtAddr := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	prefix := ip6.NetworkPrefix{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00}

	clientTr := &mockClientTransport{}
	serverTr := &mockServerTransport{}

	client := NewClient(clientTr, clientExtAddr)
	server := NewServer(serverTr, serverExtAddr)

	_ = server.Start()
	_ = server.AddPrefix(prefix, 64)

	client.UpdateAddresses([]PrefixInfo{
		{Prefix: prefix, PrefixLength: 64, AgentRloc: 0x0400},
	})
	_ = client.Start()

	// Client should have sent a Solicit.
	if clientTr.sendCount != 1 {
		t.Fatalf("expected 1 client send, got %d", clientTr.sendCount)
	}

	// Feed the Solicit to the server.
	clientAddr := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42}
	serverMsgInfo := &ip6.MessageInfo{
		PeerAddr: clientAddr,
		PeerPort: ClientPort,
	}
	err := server.HandleReceive(clientTr.lastPayload, serverMsgInfo)
	if err != nil {
		t.Fatalf("server HandleReceive failed: %v", err)
	}

	// Server should have sent a Reply.
	if serverTr.sendCount != 1 {
		t.Fatalf("expected 1 server send, got %d", serverTr.sendCount)
	}

	// Feed the Reply to the client.
	clientMsgInfo := &ip6.MessageInfo{
		PeerAddr: ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},
	}
	err = client.HandleReceive(serverTr.lastPayload, clientMsgInfo)
	if err != nil {
		t.Fatalf("client HandleReceive failed: %v", err)
	}

	// Client's IA should be in SolicitReplied state with the correct address.
	ias := client.GetIdentityAssociations()
	if len(ias) != 1 {
		t.Fatalf("expected 1 IA, got %d", len(ias))
	}
	if ias[0].Status != IaStatusSolicitReplied {
		t.Errorf("expected IaStatusSolicitReplied, got %d", ias[0].Status)
	}

	expectedAddr := MakeAddressFromPrefixEUI64(prefix, clientExtAddr)
	if ias[0].Address != expectedAddr {
		t.Errorf("address mismatch: got %v, want %v", ias[0].Address, expectedAddr)
	}
}
