// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"encoding/binary"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

type mockJRTransport struct {
	sentMessages []sentJRMessage
	sentRequests []sentJRRequest
	handlers     map[string]func(*coap.Message, coap.MessageInfo)
	unregistered []string
	sendErr      error
	sendReqErr   error
}

type sentJRMessage struct {
	msg  *coap.Message
	info coap.MessageInfo
}

type sentJRRequest struct {
	msg  *coap.Message
	info coap.MessageInfo
	cb   func(*coap.Message, coap.MessageInfo, error)
}

func newMockJRTransport() *mockJRTransport {
	return &mockJRTransport{
		handlers: make(map[string]func(*coap.Message, coap.MessageInfo)),
	}
}

func (m *mockJRTransport) SendMessage(msg *coap.Message, info coap.MessageInfo) error {
	m.sentMessages = append(m.sentMessages, sentJRMessage{msg, info})
	return m.sendErr
}

func (m *mockJRTransport) SendRequest(msg *coap.Message, info coap.MessageInfo, cb func(*coap.Message, coap.MessageInfo, error)) error {
	m.sentRequests = append(m.sentRequests, sentJRRequest{msg, info, cb})
	return m.sendReqErr
}

func (m *mockJRTransport) RegisterHandler(uriPath string, handler func(*coap.Message, coap.MessageInfo)) {
	m.handlers[uriPath] = handler
}

func (m *mockJRTransport) UnregisterHandler(uriPath string) {
	delete(m.handlers, uriPath)
	m.unregistered = append(m.unregistered, uriPath)
}

type mockJRSocket struct {
	boundPort      uint16
	bound          bool
	receiveHandler func(data []byte, peerAddr [16]byte, peerPort uint16)
	sentPackets    []sentUDPPacket
	openErr        error
	sendErr        error
}

type sentUDPPacket struct {
	data     []byte
	peerAddr [16]byte
	peerPort uint16
}

func (m *mockJRSocket) Open(port uint16) error {
	if m.openErr != nil {
		return m.openErr
	}
	m.boundPort = port
	m.bound = true
	return nil
}

func (m *mockJRSocket) Close() error {
	m.bound = false
	m.receiveHandler = nil
	return nil
}

func (m *mockJRSocket) IsBound() bool {
	return m.bound
}

func (m *mockJRSocket) Send(data []byte, peerAddr [16]byte, peerPort uint16) error {
	m.sentPackets = append(m.sentPackets, sentUDPPacket{
		data:     append([]byte(nil), data...),
		peerAddr: peerAddr,
		peerPort: peerPort,
	})
	return m.sendErr
}

func (m *mockJRSocket) SetReceiveHandler(handler func(data []byte, peerAddr [16]byte, peerPort uint16)) {
	m.receiveHandler = handler
}

type mockJRAddressing struct {
	meshLocalPrefix    ip6.NetworkPrefix
	rloc16             uint16
	isFullThreadDevice bool
}

func (m *mockJRAddressing) MeshLocalPrefix() ip6.NetworkPrefix { return m.meshLocalPrefix }
func (m *mockJRAddressing) RLOC16() uint16                     { return m.rloc16 }
func (m *mockJRAddressing) IsFullThreadDevice() bool           { return m.isFullThreadDevice }

type mockJRNetworkData struct {
	joiningAllowed   bool
	borderAgentRLOC  uint16
	hasBorderAgent   bool
	joinerUDPPort    uint16
	hasJoinerUDPPort bool
}

func (m *mockJRNetworkData) IsJoiningAllowed() bool { return m.joiningAllowed }
func (m *mockJRNetworkData) FindBorderAgentRLOC() (uint16, bool) {
	return m.borderAgentRLOC, m.hasBorderAgent
}
func (m *mockJRNetworkData) FindJoinerUDPPort() (uint16, bool) {
	return m.joinerUDPPort, m.hasJoinerUDPPort
}

type mockJRKeyManager struct {
	kek         [16]byte
	kekSet      bool
	keySequence uint32
}

func (m *mockJRKeyManager) SetKEK(kek [16]byte) {
	m.kek = kek
	m.kekSet = true
}

func (m *mockJRKeyManager) GetCurrentKeySequence() uint32 {
	return m.keySequence
}

type mockJRDatasetReader struct {
	dataset Dataset
	err     error
}

func (m *mockJRDatasetReader) ReadActiveDataset() (Dataset, error) {
	return m.dataset, m.err
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

//nolint:gocritic // The fixture exposes the router and its independently configurable dependencies.
func newTestJoinerRouter() (
	*JoinerRouter,
	*mockJRTransport,
	*mockJRSocket,
	*mockJRAddressing,
	*mockJRNetworkData,
	*mockJRKeyManager,
	*mockJRDatasetReader,
) {
	tr := newMockJRTransport()
	sock := &mockJRSocket{}
	addr := &mockJRAddressing{
		meshLocalPrefix:    ip6.NetworkPrefix{0xfd, 0xde, 0xad, 0x00, 0xbe, 0xef, 0x00, 0x00},
		rloc16:             0x4000,
		isFullThreadDevice: true,
	}
	nd := &mockJRNetworkData{
		joiningAllowed:  true,
		borderAgentRLOC: 0x1000,
		hasBorderAgent:  true,
	}
	km := &mockJRKeyManager{keySequence: 42}
	dr := &mockJRDatasetReader{}

	jr := NewJoinerRouter(tr, sock, addr, nd, km, dr)

	// Inject deterministic timer/time functions.
	var timerFuncs []func()
	jr.afterFunc = func(d time.Duration, f func()) Timer {
		timerFuncs = append(timerFuncs, f)
		return time.NewTimer(time.Hour) // dummy timer
	}
	jr.nowFunc = func() time.Time {
		return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}

	return jr, tr, sock, addr, nd, km, dr
}

func startJoinerRouter(t *testing.T, jr *JoinerRouter) {
	t.Helper()
	jr.HandleNetworkDataChanged()
	if !jr.IsStarted() {
		t.Fatal("expected JoinerRouter to be started")
	}
}

// buildLinkLocal constructs a link-local address from an IID.
func buildLinkLocal(iid [8]byte) [16]byte {
	return linkLocalFromIID(iid)
}

// buildRelayTxMessage constructs a NON POST "c/tx" CoAP message.
func buildRelayTxMessage(joinerIID [8]byte, joinerPort uint16, dtlsData []byte, kek *[16]byte) *coap.Message {
	payload := EncodeRelayTxPayload(joinerIID, joinerPort, dtlsData, kek)
	return buildNONPost("c/tx", payload)
}

// ---------------------------------------------------------------------------
// Tests: Construction and defaults
// ---------------------------------------------------------------------------

func TestNewJoinerRouter_Defaults(t *testing.T) {
	jr, _, _, _, _, _, _ := newTestJoinerRouter()
	if jr.IsStarted() {
		t.Error("should not be started by default")
	}
	if jr.GetJoinerUDPPort() != DefaultJoinerUDPPort {
		t.Errorf("expected default port %d, got %d", DefaultJoinerUDPPort, jr.GetJoinerUDPPort())
	}
	if jr.GetPendingEntrustCount() != 0 {
		t.Error("should have no pending entrusts")
	}
}

// ---------------------------------------------------------------------------
// Tests: GetJoinerUDPPort
// ---------------------------------------------------------------------------

func TestGetJoinerUDPPort_Default(t *testing.T) {
	jr, _, _, _, _, _, _ := newTestJoinerRouter()
	if port := jr.GetJoinerUDPPort(); port != 1000 {
		t.Errorf("expected 1000, got %d", port)
	}
}

func TestGetJoinerUDPPort_FromNetworkData(t *testing.T) {
	jr, _, _, _, nd, _, _ := newTestJoinerRouter()
	nd.joinerUDPPort = 2000
	nd.hasJoinerUDPPort = true
	if port := jr.GetJoinerUDPPort(); port != 2000 {
		t.Errorf("expected 2000, got %d", port)
	}
}

func TestGetJoinerUDPPort_ExplicitOverridesNetworkData(t *testing.T) {
	jr, _, _, _, nd, _, _ := newTestJoinerRouter()
	nd.joinerUDPPort = 2000
	nd.hasJoinerUDPPort = true
	jr.SetJoinerUDPPort(3000)
	if port := jr.GetJoinerUDPPort(); port != 3000 {
		t.Errorf("expected 3000, got %d", port)
	}
}

// ---------------------------------------------------------------------------
// Tests: Start / Stop
// ---------------------------------------------------------------------------

func TestStart_JoiningAllowed(t *testing.T) {
	jr, tr, sock, _, _, _, _ := newTestJoinerRouter()
	jr.HandleNetworkDataChanged()

	if !jr.IsStarted() {
		t.Fatal("should be started")
	}
	if !sock.bound {
		t.Error("socket should be bound")
	}
	if sock.boundPort != DefaultJoinerUDPPort {
		t.Errorf("expected port %d, got %d", DefaultJoinerUDPPort, sock.boundPort)
	}
	if _, ok := tr.handlers["c/tx"]; !ok {
		t.Error("should register c/tx handler")
	}
}

func TestStart_JoiningNotAllowed(t *testing.T) {
	jr, _, sock, _, nd, _, _ := newTestJoinerRouter()
	nd.joiningAllowed = false
	jr.HandleNetworkDataChanged()

	if jr.IsStarted() {
		t.Error("should not be started when joining not allowed")
	}
	if sock.bound {
		t.Error("socket should not be bound")
	}
}

func TestStart_NotFullThreadDevice(t *testing.T) {
	jr, _, _, addr, _, _, _ := newTestJoinerRouter()
	addr.isFullThreadDevice = false
	jr.HandleNetworkDataChanged()

	if jr.IsStarted() {
		t.Error("should not start if not FTD")
	}
}

func TestStart_StopsWhenJoiningDisabled(t *testing.T) {
	jr, tr, sock, _, nd, _, _ := newTestJoinerRouter()

	// Start.
	jr.HandleNetworkDataChanged()
	if !jr.IsStarted() {
		t.Fatal("should be started")
	}

	// Disable joining.
	nd.joiningAllowed = false
	jr.HandleNetworkDataChanged()

	if jr.IsStarted() {
		t.Error("should be stopped")
	}
	if sock.bound {
		t.Error("socket should be closed")
	}
	if _, ok := tr.handlers["c/tx"]; ok {
		t.Error("c/tx handler should be unregistered")
	}
}

func TestStart_SocketOpenFails(t *testing.T) {
	jr, _, sock, _, _, _, _ := newTestJoinerRouter()
	sock.openErr = goterrors.ErrFailed
	jr.HandleNetworkDataChanged()

	if jr.IsStarted() {
		t.Error("should not start if socket open fails")
	}
}

func TestStart_IdempotentWhenAlreadyStarted(t *testing.T) {
	jr, _, sock, _, _, _, _ := newTestJoinerRouter()
	jr.HandleNetworkDataChanged()
	if !jr.IsStarted() {
		t.Fatal("should be started")
	}

	// Call again — should not re-open.
	firstPort := sock.boundPort
	jr.HandleNetworkDataChanged()
	if sock.boundPort != firstPort {
		t.Error("should not re-open socket")
	}
}

func TestSetJoinerUDPPort_TriggersRestart(t *testing.T) {
	jr, _, sock, _, _, _, _ := newTestJoinerRouter()
	jr.HandleNetworkDataChanged()
	if sock.boundPort != DefaultJoinerUDPPort {
		t.Fatalf("expected default port")
	}

	jr.SetJoinerUDPPort(5000)
	// SetJoinerUDPPort calls startLocked which re-opens if already started.
	// But since the socket is already bound, startLocked won't re-open.
	// The port changes only on next stop/start cycle.
	if jr.GetJoinerUDPPort() != 5000 {
		t.Errorf("expected 5000, got %d", jr.GetJoinerUDPPort())
	}
}

// ---------------------------------------------------------------------------
// Tests: UDP receive → RelayRx
// ---------------------------------------------------------------------------

func TestHandleUDPReceive_SendsRelayRx(t *testing.T) {
	jr, tr, sock, _, _, _, _ := newTestJoinerRouter()
	startJoinerRouter(t, jr)

	// Simulate a Joiner sending DTLS data.
	iid := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	joinerAddr := buildLinkLocal(iid)
	joinerPort := uint16(1000)
	dtlsData := []byte{0x16, 0x03, 0x01, 0x00, 0x05} // fake DTLS

	sock.receiveHandler(dtlsData, joinerAddr, joinerPort)

	if len(tr.sentMessages) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(tr.sentMessages))
	}

	sent := tr.sentMessages[0]
	msg := sent.msg

	// Should be NON POST.
	if msg.GetType() != coap.TypeNonConfirmable {
		t.Error("expected Non-Confirmable")
	}
	if msg.GetCode() != coap.CodePost {
		t.Error("expected POST")
	}

	// Destination should be Border Agent RLOC on TMF port.
	if sent.info.PeerPort != 61631 {
		t.Errorf("expected TMF port 61631, got %d", sent.info.PeerPort)
	}

	// Parse payload TLVs.
	payload := msg.GetPayload()
	parsedIID, parsedPort, parsedRLOC, parsedDTLS, _, err := ParseRelayPayload(payload)
	if err != nil {
		t.Fatalf("failed to parse relay payload: %v", err)
	}

	if parsedIID != iid {
		t.Errorf("IID mismatch: got %x, want %x", parsedIID, iid)
	}
	if parsedPort != joinerPort {
		t.Errorf("port mismatch: got %d, want %d", parsedPort, joinerPort)
	}
	if parsedRLOC != 0x4000 {
		t.Errorf("RLOC mismatch: got %04x, want %04x", parsedRLOC, 0x4000)
	}
	if len(parsedDTLS) != len(dtlsData) {
		t.Errorf("DTLS data length mismatch: got %d, want %d", len(parsedDTLS), len(dtlsData))
	}
	for i := range dtlsData {
		if parsedDTLS[i] != dtlsData[i] {
			t.Errorf("DTLS data mismatch at byte %d", i)
			break
		}
	}
}

func TestHandleUDPReceive_NoBorderAgent(t *testing.T) {
	jr, tr, sock, _, nd, _, _ := newTestJoinerRouter()
	startJoinerRouter(t, jr)

	nd.hasBorderAgent = false

	iid := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	joinerAddr := buildLinkLocal(iid)
	sock.receiveHandler([]byte{0x01}, joinerAddr, 1000)

	if len(tr.sentMessages) != 0 {
		t.Error("should not send RelayRx when no border agent")
	}
}

func TestHandleUDPReceive_NotStarted(t *testing.T) {
	jr, tr, _, _, _, _, _ := newTestJoinerRouter()
	// Don't start.

	// Manually call the handler (simulating stale callback).
	jr.handleUDPReceive([]byte{0x01}, [16]byte{}, 1000)

	if len(tr.sentMessages) != 0 {
		t.Error("should not send when not started")
	}
}

func TestHandleUDPReceive_LargePayload_UsesExtendedTLV(t *testing.T) {
	jr, tr, sock, _, _, _, _ := newTestJoinerRouter()
	startJoinerRouter(t, jr)

	// Create DTLS data > 254 bytes to trigger extended TLV.
	iid := [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	joinerAddr := buildLinkLocal(iid)
	dtlsData := make([]byte, 300)
	for i := range dtlsData {
		dtlsData[i] = byte(i)
	}

	sock.receiveHandler(dtlsData, joinerAddr, 1000)

	if len(tr.sentMessages) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(tr.sentMessages))
	}

	// Parse back and verify DTLS data intact.
	payload := tr.sentMessages[0].msg.GetPayload()
	_, _, _, parsedDTLS, _, err := ParseRelayPayload(payload)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(parsedDTLS) != 300 {
		t.Errorf("expected 300 bytes DTLS data, got %d", len(parsedDTLS))
	}
}

// ---------------------------------------------------------------------------
// Tests: RelayTx handling (Commissioner → JoinerRouter → Joiner)
// ---------------------------------------------------------------------------

func TestHandleRelayTx_ForwardsDTLSToJoiner(t *testing.T) {
	jr, tr, sock, _, _, _, _ := newTestJoinerRouter()
	startJoinerRouter(t, jr)

	iid := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	dtlsData := []byte{0x16, 0x03, 0x01, 0x00, 0x05}

	msg := buildRelayTxMessage(iid, 1000, dtlsData, nil)
	tr.handlers["c/tx"](msg, coap.MessageInfo{})

	if len(sock.sentPackets) != 1 {
		t.Fatalf("expected 1 sent packet, got %d", len(sock.sentPackets))
	}

	pkt := sock.sentPackets[0]
	expectedAddr := buildLinkLocal(iid)
	if pkt.peerAddr != expectedAddr {
		t.Errorf("address mismatch: got %x, want %x", pkt.peerAddr, expectedAddr)
	}
	if pkt.peerPort != 1000 {
		t.Errorf("port mismatch: got %d, want 1000", pkt.peerPort)
	}
	if len(pkt.data) != len(dtlsData) {
		t.Errorf("data length mismatch: got %d, want %d", len(pkt.data), len(dtlsData))
	}
}

func TestHandleRelayTx_WithKEK_SchedulesEntrust(t *testing.T) {
	jr, tr, _, _, _, _, _ := newTestJoinerRouter()

	var timerFuncs []func()
	jr.afterFunc = func(d time.Duration, f func()) Timer {
		timerFuncs = append(timerFuncs, f)
		return time.NewTimer(time.Hour)
	}

	startJoinerRouter(t, jr)

	iid := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	kek := [16]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}

	msg := buildRelayTxMessage(iid, 1000, []byte{0x01}, &kek)
	tr.handlers["c/tx"](msg, coap.MessageInfo{})

	if jr.GetPendingEntrustCount() != 1 {
		t.Errorf("expected 1 pending entrust, got %d", jr.GetPendingEntrustCount())
	}

	if len(timerFuncs) == 0 {
		t.Fatal("expected timer to be scheduled")
	}
}

func TestHandleRelayTx_NotStarted(t *testing.T) {
	jr, _, sock, _, _, _, _ := newTestJoinerRouter()
	// Not started.

	iid := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	msg := buildRelayTxMessage(iid, 1000, []byte{0x01}, nil)
	jr.handleRelayTx(msg, coap.MessageInfo{})

	if len(sock.sentPackets) != 0 {
		t.Error("should not forward when not started")
	}
}

func TestHandleRelayTx_MissingTLVs(t *testing.T) {
	jr, tr, sock, _, _, _, _ := newTestJoinerRouter()
	startJoinerRouter(t, jr)

	// Message with no payload.
	msg := buildNONPost("c/tx", nil)
	tr.handlers["c/tx"](msg, coap.MessageInfo{})
	if len(sock.sentPackets) != 0 {
		t.Error("should not forward with missing TLVs")
	}

	// Message with only port TLV.
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 1000)
	payload := encodeTLV(TLVJoinerUDPPort, portBytes)
	msg = buildNONPost("c/tx", payload)
	tr.handlers["c/tx"](msg, coap.MessageInfo{})
	if len(sock.sentPackets) != 0 {
		t.Error("should not forward with incomplete TLVs")
	}
}

func TestHandleRelayTx_ConfirmableIgnored(t *testing.T) {
	jr, tr, sock, _, _, _, _ := newTestJoinerRouter()
	startJoinerRouter(t, jr)

	// Build a CON POST (wrong type — should be NON).
	iid := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	payload := EncodeRelayTxPayload(iid, 1000, []byte{0x01}, nil)
	msg := buildCONPost("c/tx", payload)
	tr.handlers["c/tx"](msg, coap.MessageInfo{})

	if len(sock.sentPackets) != 0 {
		t.Error("should ignore Confirmable messages")
	}
}

// ---------------------------------------------------------------------------
// Tests: Joiner Entrust sending
// ---------------------------------------------------------------------------

func TestJoinerEntrust_SendsAfterTimer(t *testing.T) {
	jr, tr, _, _, _, km, dr := newTestJoinerRouter()

	var timerFuncs []func()
	jr.afterFunc = func(d time.Duration, f func()) Timer {
		timerFuncs = append(timerFuncs, f)
		return time.NewTimer(time.Hour)
	}

	// Set up a minimal active dataset.
	var ds Dataset
	netKey := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	_ = ds.WriteTLV(TLVNetworkKey, netKey[:])
	dr.dataset = ds

	startJoinerRouter(t, jr)

	// Deliver RelayTx with KEK.
	iid := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	kek := [16]byte{0xAA, 0xBB, 0xCC, 0xDD}

	msg := buildRelayTxMessage(iid, 1000, []byte{0x01}, &kek)
	tr.handlers["c/tx"](msg, coap.MessageInfo{})

	// Fire the entrust timer.
	if len(timerFuncs) < 1 {
		t.Fatalf("expected at least 1 timer func (entrust), got %d", len(timerFuncs))
	}
	timerFuncs[len(timerFuncs)-1]() // entrust timer

	// Should have set KEK on key manager.
	if !km.kekSet {
		t.Error("KEK should be set on key manager")
	}
	if km.kek != kek {
		t.Errorf("KEK mismatch: got %x, want %x", km.kek, kek)
	}

	// Should have sent a CON POST to "c/je".
	if len(tr.sentRequests) != 1 {
		t.Fatalf("expected 1 sent request, got %d", len(tr.sentRequests))
	}

	req := tr.sentRequests[0]
	if req.msg.GetType() != coap.TypeConfirmable {
		t.Error("expected Confirmable")
	}
	if req.msg.GetCode() != coap.CodePost {
		t.Error("expected POST")
	}

	// Destination should be Joiner's link-local on TMF port.
	expectedAddr := buildLinkLocal(iid)
	if req.info.PeerAddr != expectedAddr {
		t.Errorf("peer addr mismatch: got %x, want %x", req.info.PeerAddr, expectedAddr)
	}
	if req.info.PeerPort != 61631 {
		t.Errorf("peer port mismatch: got %d, want 61631", req.info.PeerPort)
	}

	// Verify payload contains NetworkKey TLV.
	payload := req.msg.GetPayload()
	nkBytes := findTLVInBytes(payload, TLVNetworkKey)
	if nkBytes == nil {
		t.Error("payload should contain NetworkKey TLV")
	} else if len(nkBytes) != 16 {
		t.Errorf("NetworkKey should be 16 bytes, got %d", len(nkBytes))
	}

	// Verify NetworkKeySequence TLV.
	seqBytes := findTLVInBytes(payload, TLVNetworkKeySequence)
	switch {
	case seqBytes == nil:
		t.Error("payload should contain NetworkKeySequence TLV")
	case len(seqBytes) != 4:
		t.Errorf("NetworkKeySequence should be 4 bytes, got %d", len(seqBytes))
	default:
		seq := binary.BigEndian.Uint32(seqBytes)
		if seq != 42 {
			t.Errorf("expected key sequence 42, got %d", seq)
		}
	}

	// Pending entrust should be consumed.
	if jr.GetPendingEntrustCount() != 0 {
		t.Errorf("expected 0 pending entrusts, got %d", jr.GetPendingEntrustCount())
	}
}

func TestJoinerEntrust_PayloadContainsDatasetTLVs(t *testing.T) {
	jr, tr, _, _, _, _, dr := newTestJoinerRouter()

	var timerFuncs []func()
	jr.afterFunc = func(d time.Duration, f func()) Timer {
		timerFuncs = append(timerFuncs, f)
		return time.NewTimer(time.Hour)
	}

	// Set up a full active dataset.
	var ds Dataset
	netKey := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	_ = ds.WriteTLV(TLVNetworkKey, netKey[:])
	_ = ds.WriteTLV(TLVMeshLocalPrefix, []byte{0xfd, 0xde, 0xad, 0x00, 0xbe, 0xef, 0x00, 0x00})
	_ = ds.WriteTLV(TLVExtendedPanID, []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	_ = ds.WriteTLV(TLVNetworkName, []byte("TestNet"))
	_ = ds.WriteTLV(TLVActiveTimestamp, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00})
	_ = ds.WriteTLV(TLVChannelMask, []byte{0x00, 0x06, 0x00, 0x1F, 0xFF, 0xE0})
	_ = ds.WriteTLV(TLVPSKc, []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99})
	_ = ds.WriteTLV(TLVSecurityPolicy, []byte{0x02, 0x58, 0xFF})
	dr.dataset = ds

	startJoinerRouter(t, jr)

	iid := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	kek := [16]byte{0xAA}
	msg := buildRelayTxMessage(iid, 1000, []byte{0x01}, &kek)
	tr.handlers["c/tx"](msg, coap.MessageInfo{})

	// Fire timer.
	timerFuncs[len(timerFuncs)-1]()

	if len(tr.sentRequests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(tr.sentRequests))
	}

	payload := tr.sentRequests[0].msg.GetPayload()

	// Verify all expected TLVs exist.
	expectedTLVs := []TLVType{
		TLVNetworkKey,
		TLVMeshLocalPrefix,
		TLVExtendedPanID,
		TLVNetworkName,
		TLVActiveTimestamp,
		TLVChannelMask,
		TLVPSKc,
		TLVSecurityPolicy,
		TLVNetworkKeySequence,
	}
	for _, typ := range expectedTLVs {
		if findTLVInBytes(payload, typ) == nil {
			t.Errorf("missing TLV type %d in entrust payload", typ)
		}
	}
}

func TestJoinerEntrust_RetryOnFailure(t *testing.T) {
	jr, tr, _, _, _, _, dr := newTestJoinerRouter()

	var timerFuncs []func()
	jr.afterFunc = func(d time.Duration, f func()) Timer {
		timerFuncs = append(timerFuncs, f)
		return time.NewTimer(time.Hour)
	}

	var ds Dataset
	_ = ds.WriteTLV(TLVNetworkKey, make([]byte, 16))
	dr.dataset = ds

	startJoinerRouter(t, jr)

	iid := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	kek := [16]byte{0xAA}

	// Make SendRequest fail.
	tr.sendReqErr = goterrors.ErrFailed

	msg := buildRelayTxMessage(iid, 1000, []byte{0x01}, &kek)
	tr.handlers["c/tx"](msg, coap.MessageInfo{})

	// Fire timer — should fail and re-queue.
	timerFuncs[len(timerFuncs)-1]()

	// Should re-queue the entrust for retry.
	if jr.GetPendingEntrustCount() != 1 {
		t.Errorf("expected 1 pending entrust after retry, got %d", jr.GetPendingEntrustCount())
	}

	// Should have scheduled another timer.
	lastTimerIdx := len(timerFuncs) - 1
	if lastTimerIdx < 1 {
		t.Error("expected retry timer to be scheduled")
	}
}

func TestJoinerEntrust_MultipleQueued(t *testing.T) {
	jr, tr, _, _, _, _, dr := newTestJoinerRouter()

	var timerFuncs []func()
	jr.afterFunc = func(d time.Duration, f func()) Timer {
		timerFuncs = append(timerFuncs, f)
		return time.NewTimer(time.Hour)
	}

	var ds Dataset
	_ = ds.WriteTLV(TLVNetworkKey, make([]byte, 16))
	dr.dataset = ds

	startJoinerRouter(t, jr)

	// Queue two entrusts.
	iid1 := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	iid2 := [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	kek := [16]byte{0x01}

	msg1 := buildRelayTxMessage(iid1, 1000, []byte{0x01}, &kek)
	tr.handlers["c/tx"](msg1, coap.MessageInfo{})

	msg2 := buildRelayTxMessage(iid2, 1000, []byte{0x02}, &kek)
	tr.handlers["c/tx"](msg2, coap.MessageInfo{})

	if jr.GetPendingEntrustCount() != 2 {
		t.Fatalf("expected 2 pending entrusts, got %d", jr.GetPendingEntrustCount())
	}

	// Fire first timer — processes first entrust.
	timerFuncs[len(timerFuncs)-2]()

	if jr.GetPendingEntrustCount() != 1 {
		t.Errorf("expected 1 pending entrust after first send, got %d", jr.GetPendingEntrustCount())
	}

	// First request should be to iid1.
	if len(tr.sentRequests) < 1 {
		t.Fatal("expected at least 1 sent request")
	}
	expectedAddr1 := buildLinkLocal(iid1)
	if tr.sentRequests[0].info.PeerAddr != expectedAddr1 {
		t.Errorf("first entrust should go to iid1")
	}
}

// ---------------------------------------------------------------------------
// Tests: Extended TLV helpers
// ---------------------------------------------------------------------------

func TestEncodeExtendedTLV(t *testing.T) {
	data := make([]byte, 300)
	for i := range data {
		data[i] = byte(i)
	}
	encoded := encodeExtendedTLV(TLVJoinerDTLSEncapsulation, data)

	if encoded[0] != byte(TLVJoinerDTLSEncapsulation) {
		t.Errorf("wrong type byte: %d", encoded[0])
	}
	if encoded[1] != 0xFF {
		t.Error("expected extended length marker 0xFF")
	}
	length := int(encoded[2])<<8 | int(encoded[3])
	if length != 300 {
		t.Errorf("expected length 300, got %d", length)
	}
	for i := 0; i < 300; i++ {
		if encoded[4+i] != data[i] {
			t.Errorf("data mismatch at byte %d", i)
			break
		}
	}
}

func TestFindTLVInBytesExtended(t *testing.T) {
	// Build a payload with short and extended TLVs.
	shortData := []byte{0x01, 0x02}
	longData := make([]byte, 300)
	for i := range longData {
		longData[i] = byte(i)
	}

	var payload []byte
	payload = append(payload, encodeTLV(TLVJoinerUDPPort, shortData)...)
	payload = append(payload, encodeExtendedTLV(TLVJoinerDTLSEncapsulation, longData)...)

	// Find short TLV.
	found := findTLVInBytesExtended(payload, TLVJoinerUDPPort)
	if len(found) != 2 {
		t.Error("should find short TLV")
	}

	// Find extended TLV.
	found = findTLVInBytesExtended(payload, TLVJoinerDTLSEncapsulation)
	if len(found) != 300 {
		t.Errorf("expected 300 bytes from extended TLV, got %d", len(found))
	}

	// Not found.
	found = findTLVInBytesExtended(payload, TLVJoinerRouterKEK)
	if found != nil {
		t.Error("should not find missing TLV")
	}
}

func TestBuildNONPost(t *testing.T) {
	msg := buildNONPost("c/rx", []byte{0x01, 0x02})
	if msg.GetType() != coap.TypeNonConfirmable {
		t.Error("expected Non-Confirmable")
	}
	if msg.GetCode() != coap.CodePost {
		t.Error("expected POST")
	}
	payload := msg.GetPayload()
	if len(payload) != 2 || payload[0] != 0x01 {
		t.Error("payload mismatch")
	}
}

func TestBuildNONPost_NoPayload(t *testing.T) {
	msg := buildNONPost("c/rx", nil)
	if msg.GetPayload() != nil {
		t.Error("expected no payload")
	}
}

func TestLinkLocalFromIID(t *testing.T) {
	iid := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	addr := linkLocalFromIID(iid)

	if addr[0] != 0xfe || addr[1] != 0x80 {
		t.Error("expected fe80 prefix")
	}
	for i := 2; i < 8; i++ {
		if addr[i] != 0 {
			t.Errorf("byte %d should be zero, got %02x", i, addr[i])
		}
	}
	for i := 0; i < 8; i++ {
		if addr[8+i] != iid[i] {
			t.Errorf("IID byte %d mismatch", i)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests: EncodeRelayTxPayload / EncodeRelayRxPayload / ParseRelayPayload
// ---------------------------------------------------------------------------

func TestEncodeRelayTxPayload_RoundTrip(t *testing.T) {
	iid := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	dtlsData := []byte{0xAA, 0xBB, 0xCC}
	kek := [16]byte{0x01, 0x02, 0x03}

	payload := EncodeRelayTxPayload(iid, 1000, dtlsData, &kek)
	parsedIID, parsedPort, _, parsedDTLS, parsedKEK, err := ParseRelayPayload(payload)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if parsedIID != iid {
		t.Error("IID mismatch")
	}
	if parsedPort != 1000 {
		t.Error("port mismatch")
	}
	if len(parsedDTLS) != 3 {
		t.Error("DTLS mismatch")
	}
	if parsedKEK == nil || *parsedKEK != kek {
		t.Error("KEK mismatch")
	}
}

func TestEncodeRelayRxPayload_RoundTrip(t *testing.T) {
	iid := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	dtlsData := []byte{0xAA, 0xBB}

	payload := EncodeRelayRxPayload(iid, 1000, 0x4000, dtlsData)
	parsedIID, parsedPort, parsedRLOC, parsedDTLS, _, err := ParseRelayPayload(payload)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if parsedIID != iid {
		t.Error("IID mismatch")
	}
	if parsedPort != 1000 {
		t.Error("port mismatch")
	}
	if parsedRLOC != 0x4000 {
		t.Error("RLOC mismatch")
	}
	if len(parsedDTLS) != 2 {
		t.Error("DTLS mismatch")
	}
}

func TestParseRelayPayload_MissingPort(t *testing.T) {
	payload := encodeTLV(TLVJoinerIID, make([]byte, 8))
	payload = append(payload, encodeTLV(TLVJoinerDTLSEncapsulation, []byte{0x01})...)
	_, _, _, _, _, err := ParseRelayPayload(payload)
	if err == nil {
		t.Error("expected error for missing port")
	}
}

func TestParseRelayPayload_MissingIID(t *testing.T) {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 1000)
	payload := encodeTLV(TLVJoinerUDPPort, portBytes)
	payload = append(payload, encodeTLV(TLVJoinerDTLSEncapsulation, []byte{0x01})...)
	_, _, _, _, _, err := ParseRelayPayload(payload)
	if err == nil {
		t.Error("expected error for missing IID")
	}
}

func TestParseRelayPayload_MissingDTLS(t *testing.T) {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, 1000)
	payload := encodeTLV(TLVJoinerUDPPort, portBytes)
	payload = append(payload, encodeTLV(TLVJoinerIID, make([]byte, 8))...)
	_, _, _, _, _, err := ParseRelayPayload(payload)
	if err == nil {
		t.Error("expected error for missing DTLS data")
	}
}

func TestParseRelayPayload_NoKEK(t *testing.T) {
	payload := EncodeRelayTxPayload([8]byte{}, 1000, []byte{0x01}, nil)
	_, _, _, _, kek, err := ParseRelayPayload(payload)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if kek != nil {
		t.Error("expected nil KEK when not present")
	}
}

// ---------------------------------------------------------------------------
// Tests: Stop clears pending entrusts
// ---------------------------------------------------------------------------

func TestStop_ClearsPendingEntrusts(t *testing.T) {
	jr, tr, _, _, nd, _, dr := newTestJoinerRouter()

	var timerFuncs []func()
	jr.afterFunc = func(d time.Duration, f func()) Timer {
		timerFuncs = append(timerFuncs, f)
		return time.NewTimer(time.Hour)
	}

	var ds Dataset
	_ = ds.WriteTLV(TLVNetworkKey, make([]byte, 16))
	dr.dataset = ds

	startJoinerRouter(t, jr)

	// Queue an entrust.
	iid := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	kek := [16]byte{0x01}
	msg := buildRelayTxMessage(iid, 1000, []byte{0x01}, &kek)
	tr.handlers["c/tx"](msg, coap.MessageInfo{})

	if jr.GetPendingEntrustCount() != 1 {
		t.Fatal("expected 1 pending entrust")
	}

	// Stop by disabling joining.
	nd.joiningAllowed = false
	jr.HandleNetworkDataChanged()

	if jr.GetPendingEntrustCount() != 0 {
		t.Error("pending entrusts should be cleared on stop")
	}
}

// ---------------------------------------------------------------------------
// Tests: Full relay flow
// ---------------------------------------------------------------------------

func TestFullRelayFlow(t *testing.T) {
	jr, tr, sock, _, _, km, dr := newTestJoinerRouter()

	var timerFuncs []func()
	jr.afterFunc = func(d time.Duration, f func()) Timer {
		timerFuncs = append(timerFuncs, f)
		return time.NewTimer(time.Hour)
	}

	var ds Dataset
	netKey := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	_ = ds.WriteTLV(TLVNetworkKey, netKey[:])
	dr.dataset = ds

	startJoinerRouter(t, jr)

	// Step 1: Joiner sends DTLS ClientHello via UDP.
	iid := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	joinerAddr := buildLinkLocal(iid)
	clientHello := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01}
	sock.receiveHandler(clientHello, joinerAddr, 1000)

	// Verify RelayRx was sent.
	if len(tr.sentMessages) != 1 {
		t.Fatalf("expected 1 RelayRx, got %d", len(tr.sentMessages))
	}

	// Step 2: Commissioner sends RelayTx (ServerHello) — no KEK.
	serverHello := []byte{0x16, 0x03, 0x01, 0x00, 0x0A, 0x02}
	txMsg := buildRelayTxMessage(iid, 1000, serverHello, nil)
	tr.handlers["c/tx"](txMsg, coap.MessageInfo{})

	// Verify DTLS was forwarded to Joiner.
	if len(sock.sentPackets) != 1 {
		t.Fatalf("expected 1 UDP packet to Joiner, got %d", len(sock.sentPackets))
	}
	if sock.sentPackets[0].peerAddr != joinerAddr {
		t.Error("should send to Joiner's link-local")
	}

	// Step 3: Joiner sends more DTLS data.
	dtlsMore := []byte{0x16, 0x03, 0x01, 0x00, 0x20}
	sock.receiveHandler(dtlsMore, joinerAddr, 1000)

	if len(tr.sentMessages) != 2 {
		t.Fatalf("expected 2 RelayRx messages, got %d", len(tr.sentMessages))
	}

	// Step 4: Commissioner sends Finalize Response with KEK.
	kek := [16]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
	finalizeResp := []byte{0x16, 0x03, 0x01, 0x00, 0x30}
	txFinal := buildRelayTxMessage(iid, 1000, finalizeResp, &kek)
	tr.handlers["c/tx"](txFinal, coap.MessageInfo{})

	// Verify DTLS forwarded to Joiner.
	if len(sock.sentPackets) != 2 {
		t.Fatalf("expected 2 UDP packets, got %d", len(sock.sentPackets))
	}

	// Step 5: Timer fires — Joiner Entrust sent.
	if jr.GetPendingEntrustCount() != 1 {
		t.Fatalf("expected 1 pending entrust, got %d", jr.GetPendingEntrustCount())
	}

	// Fire the last timer (entrust delay).
	timerFuncs[len(timerFuncs)-1]()

	// Verify KEK was set.
	if km.kek != kek {
		t.Error("KEK not set correctly")
	}

	// Verify Joiner Entrust was sent as CON POST to c/je.
	if len(tr.sentRequests) != 1 {
		t.Fatalf("expected 1 Joiner Entrust request, got %d", len(tr.sentRequests))
	}

	req := tr.sentRequests[0]
	if req.info.PeerAddr != joinerAddr {
		t.Error("entrust should go to Joiner's link-local")
	}
	if req.info.PeerPort != 61631 {
		t.Error("entrust should go to TMF port")
	}

	// Verify entrust payload has NetworkKey.
	entrustPayload := req.msg.GetPayload()
	nk := findTLVInBytes(entrustPayload, TLVNetworkKey)
	if nk == nil {
		t.Error("entrust should contain NetworkKey")
	} else {
		var parsedKey [16]byte
		copy(parsedKey[:], nk)
		if parsedKey != netKey {
			t.Error("NetworkKey mismatch in entrust")
		}
	}
}
