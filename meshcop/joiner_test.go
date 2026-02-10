// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/coap"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

type mockJoinerTransport struct {
	// Connect
	connectAddr [16]byte
	connectPort uint16
	connectPSKd string
	connectCB   func(connected bool)
	connectErr  error

	// Send
	sentData [][]byte
	sendErr  error

	// Receive handler
	receiveHandler func(data []byte)

	// Registered handlers
	handlers map[string]func(msg *coap.Message, info coap.MessageInfo)

	// Responses
	responses []struct {
		code coap.Code
		msg  *coap.Message
		info coap.MessageInfo
	}

	disconnected bool
}

func newMockJoinerTransport() *mockJoinerTransport {
	return &mockJoinerTransport{
		handlers: make(map[string]func(msg *coap.Message, info coap.MessageInfo)),
	}
}

func (t *mockJoinerTransport) Connect(addr [16]byte, port uint16, pskd string, cb func(connected bool)) error {
	t.connectAddr = addr
	t.connectPort = port
	t.connectPSKd = pskd
	t.connectCB = cb
	t.disconnected = false
	return t.connectErr
}

func (t *mockJoinerTransport) Send(data []byte) error {
	cp := make([]byte, len(data))
	copy(cp, data)
	t.sentData = append(t.sentData, cp)
	return t.sendErr
}

func (t *mockJoinerTransport) SetReceiveHandler(handler func(data []byte)) {
	t.receiveHandler = handler
}

func (t *mockJoinerTransport) Disconnect() {
	t.disconnected = true
}

func (t *mockJoinerTransport) RegisterHandler(uri string, handler func(msg *coap.Message, info coap.MessageInfo)) {
	t.handlers[uri] = handler
}

func (t *mockJoinerTransport) UnregisterHandler(uri string) {
	delete(t.handlers, uri)
}

func (t *mockJoinerTransport) SendResponse(code coap.Code, req *coap.Message, info coap.MessageInfo) {
	t.responses = append(t.responses, struct {
		code coap.Code
		msg  *coap.Message
		info coap.MessageInfo
	}{code, req, info})
}

type mockJoinerRadio struct {
	eui64   types.ExtAddress
	channel uint8
	panID   uint16
}

func (r *mockJoinerRadio) GetIeeeEUI64() types.ExtAddress { return r.eui64 }
func (r *mockJoinerRadio) SetChannel(ch uint8)            { r.channel = ch }
func (r *mockJoinerRadio) SetPanID(pid uint16)            { r.panID = pid }
func (r *mockJoinerRadio) GetChannel() uint8              { return r.channel }
func (r *mockJoinerRadio) GetPanID() uint16               { return r.panID }

type mockJoinerScanner struct {
	started  bool
	stopped  bool
	callback func(result *JoinerScanResult)
	startErr error
}

func (s *mockJoinerScanner) StartScan(callback func(result *JoinerScanResult)) error {
	if s.startErr != nil {
		return s.startErr
	}
	s.started = true
	s.stopped = false
	s.callback = callback
	return nil
}

func (s *mockJoinerScanner) StopScan() {
	s.stopped = true
}

type mockDatasetSaver struct {
	savedInfo *Info
	saveErr   error
}

func (d *mockDatasetSaver) SaveDataset(info Info) error {
	saved := info
	d.savedInfo = &saved
	return d.saveErr
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var testEUI64 = types.ExtAddress{0x18, 0xB4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x01}

const testPSKd = "J01NME"

func newTestJoinerClient() (*JoinerClient, *mockJoinerTransport, *mockJoinerRadio, *mockJoinerScanner, *mockDatasetSaver) {
	tr := newMockJoinerTransport()
	radio := &mockJoinerRadio{eui64: testEUI64, channel: 11, panID: 0xABCD}
	scanner := &mockJoinerScanner{}
	saver := &mockDatasetSaver{}
	jc := NewJoinerClient(tr, radio, scanner, saver)
	// Inject dummy afterFunc to prevent real timers
	jc.afterFunc = func(d time.Duration, f func()) Timer {
		return time.NewTimer(time.Hour)
	}
	return jc, tr, radio, scanner, saver
}

func startJoinerClient(t *testing.T, jc *JoinerClient) *bool {
	t.Helper()
	completed := false
	err := jc.Start(
		testPSKd,
		"",                   // provisioningURL
		"GoThread",           // vendorName
		"TestDevice",         // vendorModel
		"1.0.0",              // vendorSWVersion
		"",                   // vendorData
		VendorStackVersion{}, // stackVersion
		func(err error) { completed = true },
	)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	return &completed
}

func buildScanResult(channel uint8, panID uint16, port uint16, ext types.ExtAddress, permitsAll bool) *JoinerScanResult {
	result := &JoinerScanResult{
		ExtAddress:    ext,
		PanID:         panID,
		JoinerUDPPort: port,
		Channel:       channel,
	}
	sd := &result.SteeringData
	_ = sd.Init(16)
	if permitsAll {
		sd.SetToPermitAllJoiners()
	}
	return result
}

func buildScanResultWithJoinerID(channel uint8, panID uint16, port uint16, ext types.ExtAddress, joinerID [8]byte) *JoinerScanResult {
	result := &JoinerScanResult{
		ExtAddress:    ext,
		PanID:         panID,
		JoinerUDPPort: port,
		Channel:       channel,
	}
	sd := &result.SteeringData
	_ = sd.Init(16)
	sd.UpdateBloomFilter(joinerID)
	return result
}

func buildFinalizeAcceptResponse(msgID uint16) []byte {
	// State TLV: Accept (1)
	payload := encodeTLV(TLVState, []byte{StateAccept})
	msg := coap.NewMessage(coap.TypeAck, coap.CodeChanged, msgID)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)
	return msg.GetBytes()
}

func buildFinalizeRejectResponse(msgID uint16) []byte {
	payload := encodeTLV(TLVState, []byte{StateReject})
	msg := coap.NewMessage(coap.TypeAck, coap.CodeChanged, msgID)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)
	return msg.GetBytes()
}

func buildEntrustMessage(networkKey [16]byte) (*coap.Message, coap.MessageInfo) {
	payload := encodeTLV(TLVNetworkKey, networkKey[:])
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 0x5678)
	_ = msg.AppendURIPathOptions(joinerEntrustURI)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)
	info := coap.MessageInfo{PeerPort: 61631}
	return msg, info
}

func buildEntrustMessageWithOptionals(networkKey [16]byte, networkName string, extPanID [8]byte) (*coap.Message, coap.MessageInfo) {
	var payload []byte
	payload = append(payload, encodeTLV(TLVNetworkKey, networkKey[:])...)
	payload = append(payload, encodeTLV(TLVNetworkName, []byte(networkName))...)
	payload = append(payload, encodeTLV(TLVExtendedPanID, extPanID[:])...)
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 0x5678)
	_ = msg.AppendURIPathOptions(joinerEntrustURI)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)
	info := coap.MessageInfo{PeerPort: 61631}
	return msg, info
}

// driveToConnected starts a JoinerClient, feeds it a scan result,
// completes the scan, and simulates a successful DTLS handshake.
// Returns the transport for further interaction.
func driveToConnected(t *testing.T, jc *JoinerClient, tr *mockJoinerTransport, scanner *mockJoinerScanner) {
	t.Helper()
	startJoinerClient(t, jc)

	// Feed one scan result (permits all).
	ext := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	result := buildScanResult(15, 0x1234, 1000, ext, true)
	scanner.callback(result)

	// Signal scan complete.
	scanner.callback(nil)

	// Simulate successful DTLS handshake.
	if tr.connectCB == nil {
		t.Fatal("expected connect callback to be set")
	}
	tr.connectCB(true)

	if jc.GetState() != JoinerStateConnected {
		t.Fatalf("expected Connected state, got %s", jc.GetState())
	}
}

// ---------------------------------------------------------------------------
// Tests: Defaults and Identity
// ---------------------------------------------------------------------------

func TestNewJoinerClient_Defaults(t *testing.T) {
	jc, _, _, _, _ := newTestJoinerClient()

	if jc.GetState() != JoinerStateIdle {
		t.Errorf("expected Idle, got %s", jc.GetState())
	}

	// Joiner ID should be derived from EUI-64.
	id := jc.GetID()
	expected := ComputeJoinerIDFromEUI64(testEUI64)
	if id != expected {
		t.Errorf("JoinerID mismatch: got %x, want %x", id, expected)
	}

	// No discerner by default.
	if d := jc.GetDiscerner(); d != nil {
		t.Errorf("expected nil discerner, got %+v", d)
	}
}

func TestSetDiscerner(t *testing.T) {
	jc, _, _, _, _ := newTestJoinerClient()

	d := JoinerDiscerner{Value: 0xABCD, BitLength: 16}
	if err := jc.SetDiscerner(d); err != nil {
		t.Fatalf("SetDiscerner failed: %v", err)
	}

	got := jc.GetDiscerner()
	if got == nil || got.Value != 0xABCD || got.BitLength != 16 {
		t.Errorf("discerner mismatch: got %+v", got)
	}

	// Joiner ID should now be derived from discerner.
	id := jc.GetID()
	expected := generateJoinerIDFromDiscerner(d)
	if id != expected {
		t.Errorf("JoinerID from discerner mismatch: got %x, want %x", id, expected)
	}
}

func TestSetDiscerner_InvalidBitLength(t *testing.T) {
	jc, _, _, _, _ := newTestJoinerClient()

	err := jc.SetDiscerner(JoinerDiscerner{Value: 1, BitLength: 0})
	if err != errors.ErrInvalidArgs {
		t.Errorf("expected ErrInvalidArgs, got %v", err)
	}

	err = jc.SetDiscerner(JoinerDiscerner{Value: 1, BitLength: 65})
	if err != errors.ErrInvalidArgs {
		t.Errorf("expected ErrInvalidArgs for BitLength=65, got %v", err)
	}
}

func TestSetDiscerner_WhileActive(t *testing.T) {
	jc, _, _, scanner, _ := newTestJoinerClient()
	startJoinerClient(t, jc)

	_ = scanner // keep scanner alive
	err := jc.SetDiscerner(JoinerDiscerner{Value: 1, BitLength: 8})
	if err != errors.ErrInvalidState {
		t.Errorf("expected ErrInvalidState, got %v", err)
	}
}

func TestClearDiscerner(t *testing.T) {
	jc, _, _, _, _ := newTestJoinerClient()

	_ = jc.SetDiscerner(JoinerDiscerner{Value: 0xABCD, BitLength: 16})
	if err := jc.ClearDiscerner(); err != nil {
		t.Fatalf("ClearDiscerner failed: %v", err)
	}

	if d := jc.GetDiscerner(); d != nil {
		t.Errorf("expected nil discerner after clear, got %+v", d)
	}

	// ID should revert to EUI-64 based.
	id := jc.GetID()
	expected := ComputeJoinerIDFromEUI64(testEUI64)
	if id != expected {
		t.Errorf("JoinerID after clear: got %x, want %x", id, expected)
	}
}

// ---------------------------------------------------------------------------
// Tests: PSKd Validation
// ---------------------------------------------------------------------------

func TestValidateJoinerPSKd_Valid(t *testing.T) {
	valid := []string{"J01NME", "ABCDEF123456", "AAAAAA", "ABCDEFGHJKLMNPRSTUVWXY0123456789"}
	for _, pskd := range valid {
		if err := ValidateJoinerPSKd(pskd); err != nil {
			t.Errorf("PSKd %q should be valid, got %v", pskd, err)
		}
	}
}

func TestValidateJoinerPSKd_Invalid(t *testing.T) {
	invalid := []string{
		"",                                  // too short
		"ABCDE",                             // 5 chars, < 6 min
		"abcdef",                            // lowercase
		"ABCDEFI",                           // contains I
		"ABCDEFO",                           // contains O
		"ABCDEFQ",                           // contains Q
		"ABCDEFZ",                           // contains Z
		"ABCDEFGHJKLMNPRSTUVWXY01234567890", // 33 chars, > 32 max
	}
	for _, pskd := range invalid {
		if err := ValidateJoinerPSKd(pskd); err == nil {
			t.Errorf("PSKd %q should be invalid", pskd)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests: Start
// ---------------------------------------------------------------------------

func TestStart_Success(t *testing.T) {
	jc, _, _, scanner, _ := newTestJoinerClient()
	startJoinerClient(t, jc)

	if jc.GetState() != JoinerStateDiscover {
		t.Errorf("expected Discover state, got %s", jc.GetState())
	}
	if !scanner.started {
		t.Error("scanner should have been started")
	}
}

func TestStart_InvalidState(t *testing.T) {
	jc, _, _, _, _ := newTestJoinerClient()
	startJoinerClient(t, jc)

	// Try starting again.
	err := jc.Start(testPSKd, "", "V", "M", "1.0", "", VendorStackVersion{}, nil)
	if err != errors.ErrInvalidState {
		t.Errorf("expected ErrInvalidState, got %v", err)
	}
}

func TestStart_InvalidPSKd(t *testing.T) {
	jc, _, _, _, _ := newTestJoinerClient()

	err := jc.Start("bad", "", "V", "M", "1.0", "", VendorStackVersion{}, nil)
	if err != errors.ErrInvalidArgs {
		t.Errorf("expected ErrInvalidArgs for short PSKd, got %v", err)
	}
}

func TestStart_EmptyVendorName(t *testing.T) {
	jc, _, _, _, _ := newTestJoinerClient()

	err := jc.Start(testPSKd, "", "", "M", "1.0", "", VendorStackVersion{}, nil)
	if err != errors.ErrInvalidArgs {
		t.Errorf("expected ErrInvalidArgs for empty vendor name, got %v", err)
	}
}

func TestStart_ScanFails(t *testing.T) {
	jc, _, _, scanner, _ := newTestJoinerClient()
	scanner.startErr = errors.ErrFailed

	err := jc.Start(testPSKd, "", "V", "M", "1.0", "", VendorStackVersion{}, nil)
	if err != errors.ErrFailed {
		t.Errorf("expected ErrFailed, got %v", err)
	}
	if jc.GetState() != JoinerStateIdle {
		t.Errorf("expected Idle after scan failure, got %s", jc.GetState())
	}
}

func TestStart_ProvisioningURLTooLong(t *testing.T) {
	jc, _, _, _, _ := newTestJoinerClient()

	longURL := make([]byte, MaxProvisioningURLLength+1)
	for i := range longURL {
		longURL[i] = 'A'
	}
	err := jc.Start(testPSKd, string(longURL), "V", "M", "1.0", "", VendorStackVersion{}, nil)
	if err != errors.ErrInvalidArgs {
		t.Errorf("expected ErrInvalidArgs, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests: Stop
// ---------------------------------------------------------------------------

func TestStop_WhenIdle(t *testing.T) {
	jc, _, _, _, _ := newTestJoinerClient()

	err := jc.Stop()
	if err != errors.ErrInvalidState {
		t.Errorf("expected ErrInvalidState, got %v", err)
	}
}

func TestStop_WhenDiscovering(t *testing.T) {
	jc, _, _, scanner, _ := newTestJoinerClient()
	completed := false
	_ = jc.Start(testPSKd, "", "V", "M", "1.0", "", VendorStackVersion{},
		func(err error) { completed = true })

	err := jc.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if jc.GetState() != JoinerStateIdle {
		t.Errorf("expected Idle after Stop, got %s", jc.GetState())
	}
	if completed {
		t.Error("completion callback should NOT be called on Stop")
	}
	if !scanner.stopped {
		t.Error("scanner should have been stopped")
	}
}

func TestStop_WhenConnected(t *testing.T) {
	jc, tr, _, scanner, _ := newTestJoinerClient()
	driveToConnected(t, jc, tr, scanner)

	err := jc.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if !tr.disconnected {
		t.Error("transport should have been disconnected")
	}
	if jc.GetState() != JoinerStateIdle {
		t.Errorf("expected Idle, got %s", jc.GetState())
	}
}

// ---------------------------------------------------------------------------
// Tests: Scan evaluation
// ---------------------------------------------------------------------------

func TestScanResult_PermitsAll(t *testing.T) {
	jc, _, _, scanner, _ := newTestJoinerClient()
	startJoinerClient(t, jc)

	ext := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	result := buildScanResult(15, 0x1234, 1000, ext, true)
	scanner.callback(result)

	candidates := jc.GetCandidates()
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}
	if candidates[0].Priority != 100 {
		t.Errorf("expected priority 100 (non-preferred), got %d", candidates[0].Priority)
	}
}

func TestScanResult_SpecificJoinerID(t *testing.T) {
	jc, _, _, scanner, _ := newTestJoinerClient()
	startJoinerClient(t, jc)

	joinerID := jc.GetID()
	ext := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	result := buildScanResultWithJoinerID(15, 0x1234, 1000, ext, joinerID)
	scanner.callback(result)

	candidates := jc.GetCandidates()
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}
	if candidates[0].Priority != 200 {
		t.Errorf("expected priority 200 (preferred), got %d", candidates[0].Priority)
	}
}

func TestScanResult_NoMatch(t *testing.T) {
	jc, _, _, scanner, _ := newTestJoinerClient()
	startJoinerClient(t, jc)

	ext := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	// Create a scan result with a specific joiner ID that doesn't match ours.
	otherID := [8]byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8}
	result := buildScanResultWithJoinerID(15, 0x1234, 1000, ext, otherID)
	scanner.callback(result)

	candidates := jc.GetCandidates()
	if len(candidates) != 0 {
		t.Errorf("expected 0 candidates, got %d", len(candidates))
	}
}

func TestScanResult_InvalidPort(t *testing.T) {
	jc, _, _, scanner, _ := newTestJoinerClient()
	startJoinerClient(t, jc)

	ext := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	result := buildScanResult(15, 0x1234, 0, ext, true) // port=0 is invalid
	scanner.callback(result)

	candidates := jc.GetCandidates()
	if len(candidates) != 0 {
		t.Errorf("expected 0 candidates for port=0, got %d", len(candidates))
	}
}

func TestScanResult_PreferredOverNonPreferred(t *testing.T) {
	jc, _, _, scanner, _ := newTestJoinerClient()
	startJoinerClient(t, jc)

	joinerID := jc.GetID()

	// Add non-preferred first.
	ext1 := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	result1 := buildScanResult(11, 0x1111, 1000, ext1, true)
	scanner.callback(result1)

	// Add preferred.
	ext2 := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	result2 := buildScanResultWithJoinerID(15, 0x2222, 1000, ext2, joinerID)
	scanner.callback(result2)

	// Complete scan. Candidates should be sorted: preferred first.
	scanner.callback(nil)

	candidates := jc.GetCandidates()
	if len(candidates) < 2 {
		t.Fatalf("expected at least 2 candidates, got %d", len(candidates))
	}
	if candidates[0].Priority < candidates[1].Priority {
		t.Error("first candidate should have higher or equal priority")
	}
}

// ---------------------------------------------------------------------------
// Tests: Scan completion and connection
// ---------------------------------------------------------------------------

func TestScanComplete_NoCandidates(t *testing.T) {
	jc, _, _, scanner, _ := newTestJoinerClient()
	completed := false
	var completionErr error
	_ = jc.Start(testPSKd, "", "V", "M", "1.0", "", VendorStackVersion{},
		func(err error) {
			completed = true
			completionErr = err
		})

	// Signal scan complete with no results.
	scanner.callback(nil)

	if !completed {
		t.Error("completion callback should have been called")
	}
	if completionErr != errors.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", completionErr)
	}
	if jc.GetState() != JoinerStateIdle {
		t.Errorf("expected Idle, got %s", jc.GetState())
	}
}

func TestScanComplete_ConnectsToCandidate(t *testing.T) {
	jc, tr, radio, scanner, _ := newTestJoinerClient()
	startJoinerClient(t, jc)

	ext := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	result := buildScanResult(15, 0x1234, 1000, ext, true)
	scanner.callback(result)
	scanner.callback(nil) // scan complete

	// Radio should be configured.
	if radio.channel != 15 {
		t.Errorf("expected channel 15, got %d", radio.channel)
	}
	if radio.panID != 0x1234 {
		t.Errorf("expected panID 0x1234, got 0x%04x", radio.panID)
	}

	// Transport should have been asked to connect.
	expectedAddr := linkLocalFromExtAddr(ext)
	if tr.connectAddr != expectedAddr {
		t.Errorf("connect address mismatch")
	}
	if tr.connectPort != 1000 {
		t.Errorf("expected port 1000, got %d", tr.connectPort)
	}
	if tr.connectPSKd != testPSKd {
		t.Errorf("PSKd mismatch")
	}

	if jc.GetState() != JoinerStateConnect {
		t.Errorf("expected Connect state, got %s", jc.GetState())
	}
}

// ---------------------------------------------------------------------------
// Tests: DTLS connection
// ---------------------------------------------------------------------------

func TestDTLS_ConnectSuccess(t *testing.T) {
	jc, tr, _, scanner, _ := newTestJoinerClient()
	driveToConnected(t, jc, tr, scanner)

	if jc.GetState() != JoinerStateConnected {
		t.Errorf("expected Connected, got %s", jc.GetState())
	}

	// Should have sent JOINER_FINALIZE.
	if len(tr.sentData) == 0 {
		t.Fatal("expected JOINER_FINALIZE to be sent")
	}
}

func TestDTLS_ConnectFailed_TriesNext(t *testing.T) {
	jc, tr, _, scanner, _ := newTestJoinerClient()
	startJoinerClient(t, jc)

	// Add two candidates.
	ext1 := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	ext2 := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	scanner.callback(buildScanResult(11, 0x1111, 1000, ext1, true))
	scanner.callback(buildScanResult(15, 0x2222, 1001, ext2, true))
	scanner.callback(nil) // scan complete

	// First connect should be in progress.
	if tr.connectCB == nil {
		t.Fatal("expected connect callback")
	}

	// Simulate DTLS failure.
	firstCB := tr.connectCB
	firstCB(false)

	// Should try next candidate - transport should have a new connectCB.
	if jc.GetState() == JoinerStateIdle {
		t.Error("should not be Idle yet, should try next candidate")
	}
}

func TestDTLS_AllCandidatesFailed(t *testing.T) {
	jc, tr, _, scanner, _ := newTestJoinerClient()
	completed := false
	var completionErr error
	_ = jc.Start(testPSKd, "", "V", "M", "1.0", "", VendorStackVersion{},
		func(err error) {
			completed = true
			completionErr = err
		})

	// Add one candidate.
	ext := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	scanner.callback(buildScanResult(11, 0x1111, 1000, ext, true))
	scanner.callback(nil)

	// Simulate DTLS failure.
	tr.connectCB(false)

	if !completed {
		t.Error("completion callback should have been called")
	}
	if completionErr != errors.ErrSecurity {
		t.Errorf("expected ErrSecurity, got %v", completionErr)
	}
}

// ---------------------------------------------------------------------------
// Tests: JOINER_FINALIZE payload
// ---------------------------------------------------------------------------

func TestFinalizePayload_ContainsRequiredTLVs(t *testing.T) {
	jc, tr, _, scanner, _ := newTestJoinerClient()
	driveToConnected(t, jc, tr, scanner)

	if len(tr.sentData) == 0 {
		t.Fatal("no data sent")
	}

	// Parse the sent CoAP message.
	msg, err := coap.ParseMessage(tr.sentData[0])
	if err != nil {
		t.Fatalf("failed to parse sent message: %v", err)
	}

	if msg.GetType() != coap.TypeConfirmable {
		t.Errorf("expected CON, got %v", msg.GetType())
	}
	if msg.GetCode() != coap.CodePost {
		t.Errorf("expected POST, got %v", msg.GetCode())
	}

	payload := msg.GetPayload()

	// Check State TLV
	state := findTLVInBytes(payload, TLVState)
	if state == nil || state[0] != StateAccept {
		t.Errorf("missing or wrong State TLV")
	}

	// Check Vendor Name
	vn := findTLVInBytes(payload, TLVVendorName)
	if vn == nil || string(vn) != "GoThread" {
		t.Errorf("missing or wrong VendorName TLV: %q", vn)
	}

	// Check Vendor Model
	vm := findTLVInBytes(payload, TLVVendorModel)
	if vm == nil || string(vm) != "TestDevice" {
		t.Errorf("missing or wrong VendorModel TLV: %q", vm)
	}

	// Check Vendor SW Version
	vs := findTLVInBytes(payload, TLVVendorSWVersion)
	if vs == nil || string(vs) != "1.0.0" {
		t.Errorf("missing or wrong VendorSWVersion TLV: %q", vs)
	}

	// Check Vendor Stack Version (6 bytes)
	vstk := findTLVInBytes(payload, TLVVendorStackVersion)
	if vstk == nil || len(vstk) != 6 {
		t.Errorf("missing or wrong VendorStackVersion TLV: %x", vstk)
	}
}

func TestFinalizePayload_WithOptionals(t *testing.T) {
	jc, tr, _, scanner, _ := newTestJoinerClient()
	tr2 := tr
	scanner2 := scanner

	_ = jc.Start(
		testPSKd,
		"https://example.com", // provisioningURL
		"GoThread",
		"TestDevice",
		"1.0.0",
		"custom-data",
		VendorStackVersion{},
		func(err error) {},
	)

	ext := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	scanner2.callback(buildScanResult(15, 0x1234, 1000, ext, true))
	scanner2.callback(nil)
	tr2.connectCB(true)

	if len(tr2.sentData) == 0 {
		t.Fatal("no data sent")
	}

	msg, _ := coap.ParseMessage(tr2.sentData[0])
	payload := msg.GetPayload()

	// Check Provisioning URL
	purl := findTLVInBytes(payload, TLVProvisioningURL)
	if purl == nil || string(purl) != "https://example.com" {
		t.Errorf("missing or wrong ProvisioningURL TLV")
	}

	// Check Vendor Data
	vd := findTLVInBytes(payload, TLVVendorData)
	if vd == nil || string(vd) != "custom-data" {
		t.Errorf("missing or wrong VendorData TLV")
	}
}

// ---------------------------------------------------------------------------
// Tests: JOINER_FINALIZE response
// ---------------------------------------------------------------------------

func TestFinalizeResponse_Accepted(t *testing.T) {
	jc, tr, _, scanner, _ := newTestJoinerClient()
	driveToConnected(t, jc, tr, scanner)

	// Deliver accept response.
	resp := buildFinalizeAcceptResponse(0x0001)
	tr.receiveHandler(resp)

	if jc.GetState() != JoinerStateEntrust {
		t.Errorf("expected Entrust, got %s", jc.GetState())
	}

	// DTLS should be disconnected.
	if !tr.disconnected {
		t.Error("DTLS should have been disconnected after finalize accept")
	}

	// Entrust handler should be registered.
	if _, ok := tr.handlers[joinerEntrustURI]; !ok {
		t.Error("entrust handler should be registered")
	}
}

func TestFinalizeResponse_Rejected(t *testing.T) {
	jc, tr, _, scanner, _ := newTestJoinerClient()
	completed := false
	var completionErr error
	_ = jc.Start(testPSKd, "", "V", "M", "1.0", "", VendorStackVersion{},
		func(err error) {
			completed = true
			completionErr = err
		})

	ext := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	scanner.callback(buildScanResult(15, 0x1234, 1000, ext, true))
	scanner.callback(nil)
	tr.connectCB(true)

	resp := buildFinalizeRejectResponse(0x0001)
	tr.receiveHandler(resp)

	if !completed {
		t.Error("completion callback should have been called")
	}
	if completionErr != errors.ErrRejected {
		t.Errorf("expected ErrRejected, got %v", completionErr)
	}
}

func TestFinalizeResponse_WrongCode_Ignored(t *testing.T) {
	jc, tr, _, scanner, _ := newTestJoinerClient()
	driveToConnected(t, jc, tr, scanner)

	// Send a response with wrong code (Content instead of Changed).
	payload := encodeTLV(TLVState, []byte{StateAccept})
	msg := coap.NewMessage(coap.TypeAck, coap.CodeContent, 0x0001)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)
	tr.receiveHandler(msg.GetBytes())

	// Should still be in Connected (wrong code ignored).
	if jc.GetState() != JoinerStateConnected {
		t.Errorf("expected Connected (wrong code ignored), got %s", jc.GetState())
	}
}

func TestFinalizeResponse_MissingStateTLV(t *testing.T) {
	jc, tr, _, scanner, _ := newTestJoinerClient()
	completed := false
	var completionErr error
	_ = jc.Start(testPSKd, "", "V", "M", "1.0", "", VendorStackVersion{},
		func(err error) {
			completed = true
			completionErr = err
		})
	ext := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	scanner.callback(buildScanResult(15, 0x1234, 1000, ext, true))
	scanner.callback(nil)
	tr.connectCB(true)

	// Response with no State TLV — valid ACK 2.04 with no payload.
	msg := coap.NewMessage(coap.TypeAck, coap.CodeChanged, 0x0001)
	tr.receiveHandler(msg.GetBytes())

	if !completed {
		t.Error("should have completed with parse error")
	}
	if completionErr != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", completionErr)
	}
}

func TestFinalizeResponse_AfterStop_Ignored(t *testing.T) {
	jc, tr, _, scanner, _ := newTestJoinerClient()
	driveToConnected(t, jc, tr, scanner)

	jc.Stop()

	// Try delivering a response after stop. Should not panic.
	resp := buildFinalizeAcceptResponse(0x0001)
	if tr.receiveHandler != nil {
		tr.receiveHandler(resp) // Should be a no-op since state is Idle.
	}

	if jc.GetState() != JoinerStateIdle {
		t.Errorf("expected Idle, got %s", jc.GetState())
	}
}

// ---------------------------------------------------------------------------
// Tests: JOINER_ENTRUST
// ---------------------------------------------------------------------------

func TestEntrust_ReceivesNetworkKey(t *testing.T) {
	jc, tr, radio, scanner, saver := newTestJoinerClient()
	radio.channel = 15
	radio.panID = 0x1234

	driveToConnected(t, jc, tr, scanner)

	// Simulate finalize accept.
	resp := buildFinalizeAcceptResponse(0x0001)
	tr.receiveHandler(resp)

	if jc.GetState() != JoinerStateEntrust {
		t.Fatalf("expected Entrust, got %s", jc.GetState())
	}

	// Deliver JOINER_ENTRUST.
	netKey := [16]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}
	entrustMsg, entrustInfo := buildEntrustMessage(netKey)

	handler := tr.handlers[joinerEntrustURI]
	if handler == nil {
		t.Fatal("entrust handler not registered")
	}
	handler(entrustMsg, entrustInfo)

	// Verify dataset was saved.
	if saver.savedInfo == nil {
		t.Fatal("dataset was not saved")
	}
	if saver.savedInfo.NetworkKey != netKey {
		t.Errorf("network key mismatch")
	}
	if !saver.savedInfo.Components.NetworkKey {
		t.Error("NetworkKey component should be present")
	}
	if saver.savedInfo.Channel != 15 {
		t.Errorf("expected channel 15, got %d", saver.savedInfo.Channel)
	}
	if saver.savedInfo.PanID != 0x1234 {
		t.Errorf("expected panID 0x1234, got 0x%04x", saver.savedInfo.PanID)
	}

	// Should have sent ACK response.
	if len(tr.responses) == 0 {
		t.Error("expected a CoAP response to be sent")
	} else if tr.responses[0].code != coap.CodeChanged {
		t.Errorf("expected CodeChanged, got %v", tr.responses[0].code)
	}

	// State should be Joined (waiting for post-join delay).
	if jc.GetState() != JoinerStateJoined {
		t.Errorf("expected Joined, got %s", jc.GetState())
	}
}

func TestEntrust_WithOptionalTLVs(t *testing.T) {
	jc, tr, _, scanner, saver := newTestJoinerClient()
	driveToConnected(t, jc, tr, scanner)

	resp := buildFinalizeAcceptResponse(0x0001)
	tr.receiveHandler(resp)

	netKey := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	extPanID := [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}

	entrustMsg, entrustInfo := buildEntrustMessageWithOptionals(netKey, "MyThread", extPanID)
	tr.handlers[joinerEntrustURI](entrustMsg, entrustInfo)

	if saver.savedInfo == nil {
		t.Fatal("dataset was not saved")
	}
	if saver.savedInfo.NetworkName != "MyThread" {
		t.Errorf("network name mismatch: got %q", saver.savedInfo.NetworkName)
	}
	if !saver.savedInfo.Components.NetworkName {
		t.Error("NetworkName component should be present")
	}
	if saver.savedInfo.ExtendedPanID != extPanID {
		t.Error("ExtendedPanID mismatch")
	}
}

func TestEntrust_NotActive_Ignored(t *testing.T) {
	jc, tr, _, _, _ := newTestJoinerClient()

	// Deliver entrust while idle.
	netKey := [16]byte{0x01}
	entrustMsg, entrustInfo := buildEntrustMessage(netKey)
	tr.RegisterHandler(joinerEntrustURI, jc.handleJoinerEntrust)
	tr.handlers[joinerEntrustURI](entrustMsg, entrustInfo)

	// Should still be Idle.
	if jc.GetState() != JoinerStateIdle {
		t.Errorf("expected Idle, got %s", jc.GetState())
	}
}

func TestEntrust_WrongType_Ignored(t *testing.T) {
	jc, tr, _, scanner, saver := newTestJoinerClient()
	driveToConnected(t, jc, tr, scanner)

	resp := buildFinalizeAcceptResponse(0x0001)
	tr.receiveHandler(resp)

	// Send non-confirmable entrust (should be ignored).
	netKey := [16]byte{0x01}
	payload := encodeTLV(TLVNetworkKey, netKey[:])
	msg := coap.NewMessage(coap.TypeNonConfirmable, coap.CodePost, 0x5678)
	_ = msg.AppendURIPathOptions(joinerEntrustURI)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload(payload)
	info := coap.MessageInfo{}

	tr.handlers[joinerEntrustURI](msg, info)

	if saver.savedInfo != nil {
		t.Error("non-confirmable entrust should be ignored")
	}
}

func TestEntrust_MissingNetworkKey_Ignored(t *testing.T) {
	jc, tr, _, scanner, saver := newTestJoinerClient()
	driveToConnected(t, jc, tr, scanner)

	resp := buildFinalizeAcceptResponse(0x0001)
	tr.receiveHandler(resp)

	// Entrust without network key.
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 0x5678)
	_ = msg.AppendURIPathOptions(joinerEntrustURI)
	_ = msg.AppendPayloadMarker()
	_ = msg.AppendPayload([]byte{})
	info := coap.MessageInfo{}

	tr.handlers[joinerEntrustURI](msg, info)

	if saver.savedInfo != nil {
		t.Error("entrust without network key should be ignored")
	}
}

// ---------------------------------------------------------------------------
// Tests: Finalize timeout
// ---------------------------------------------------------------------------

func TestFinalizeTimeout(t *testing.T) {
	jc, tr, _, scanner, _ := newTestJoinerClient()
	var timerFuncs []func()
	jc.afterFunc = func(d time.Duration, f func()) Timer {
		timerFuncs = append(timerFuncs, f)
		return time.NewTimer(time.Hour)
	}

	completed := false
	var completionErr error
	_ = jc.Start(testPSKd, "", "V", "M", "1.0", "", VendorStackVersion{},
		func(err error) {
			completed = true
			completionErr = err
		})

	ext := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	scanner.callback(buildScanResult(15, 0x1234, 1000, ext, true))
	scanner.callback(nil)
	tr.connectCB(true)

	// Fire the finalize timeout timer.
	if len(timerFuncs) == 0 {
		t.Fatal("no timer registered")
	}
	timerFuncs[len(timerFuncs)-1]()

	if !completed {
		t.Error("completion callback should have been called")
	}
	if completionErr != errors.ErrResponseTimeout {
		t.Errorf("expected ErrResponseTimeout, got %v", completionErr)
	}
}

// ---------------------------------------------------------------------------
// Tests: Entrust timeout
// ---------------------------------------------------------------------------

func TestEntrustTimeout(t *testing.T) {
	jc, tr, _, scanner, _ := newTestJoinerClient()
	var timerFuncs []func()
	jc.afterFunc = func(d time.Duration, f func()) Timer {
		timerFuncs = append(timerFuncs, f)
		return time.NewTimer(time.Hour)
	}

	completed := false
	var completionErr error
	_ = jc.Start(testPSKd, "", "V", "M", "1.0", "", VendorStackVersion{},
		func(err error) {
			completed = true
			completionErr = err
		})

	ext := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	scanner.callback(buildScanResult(15, 0x1234, 1000, ext, true))
	scanner.callback(nil)
	tr.connectCB(true)

	// Deliver accept response.
	resp := buildFinalizeAcceptResponse(0x0001)
	tr.receiveHandler(resp)

	// Fire the entrust timeout (should be the latest timer).
	timerFuncs[len(timerFuncs)-1]()

	if !completed {
		t.Error("completion callback should have been called")
	}
	if completionErr != errors.ErrResponseTimeout {
		t.Errorf("expected ErrResponseTimeout, got %v", completionErr)
	}
}

// ---------------------------------------------------------------------------
// Tests: Post-join delay and completion
// ---------------------------------------------------------------------------

func TestPostJoinDelay_Completion(t *testing.T) {
	jc, tr, _, scanner, _ := newTestJoinerClient()
	var timerFuncs []func()
	jc.afterFunc = func(d time.Duration, f func()) Timer {
		timerFuncs = append(timerFuncs, f)
		return time.NewTimer(time.Hour)
	}

	completed := false
	var completionErr error
	_ = jc.Start(testPSKd, "", "V", "M", "1.0", "", VendorStackVersion{},
		func(err error) {
			completed = true
			completionErr = err
		})

	ext := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	scanner.callback(buildScanResult(15, 0x1234, 1000, ext, true))
	scanner.callback(nil)
	tr.connectCB(true)

	// Finalize accept.
	resp := buildFinalizeAcceptResponse(0x0001)
	tr.receiveHandler(resp)

	// Deliver entrust.
	netKey := [16]byte{0xDE, 0xAD}
	entrustMsg, entrustInfo := buildEntrustMessage(netKey)
	tr.handlers[joinerEntrustURI](entrustMsg, entrustInfo)

	if jc.GetState() != JoinerStateJoined {
		t.Fatalf("expected Joined, got %s", jc.GetState())
	}

	// Fire the post-join delay timer (latest).
	timerFuncs[len(timerFuncs)-1]()

	if !completed {
		t.Error("completion callback should have been called")
	}
	if completionErr != nil {
		t.Errorf("expected nil error (success), got %v", completionErr)
	}
	if jc.GetState() != JoinerStateIdle {
		t.Errorf("expected Idle after completion, got %s", jc.GetState())
	}
}

// ---------------------------------------------------------------------------
// Tests: Full join flow (end-to-end)
// ---------------------------------------------------------------------------

func TestFullJoinFlow(t *testing.T) {
	jc, tr, radio, scanner, saver := newTestJoinerClient()
	radio.channel = 11
	radio.panID = 0xFFFF

	var timerFuncs []func()
	jc.afterFunc = func(d time.Duration, f func()) Timer {
		timerFuncs = append(timerFuncs, f)
		return time.NewTimer(time.Hour)
	}

	completed := false
	var completionErr error
	err := jc.Start(
		testPSKd,
		"",
		"GoThread",
		"TestRouter",
		"2.0.0",
		"",
		VendorStackVersion{OUI: [3]byte{0x00, 0x12, 0x34}, Major: 1, Minor: 0, Build: 42},
		func(err error) {
			completed = true
			completionErr = err
		},
	)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// 1. Discover
	if jc.GetState() != JoinerStateDiscover {
		t.Fatalf("expected Discover, got %s", jc.GetState())
	}

	ext := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	scanner.callback(buildScanResult(25, 0x4567, 1000, ext, true))
	scanner.callback(nil) // scan complete

	// 2. Connect
	if jc.GetState() != JoinerStateConnect {
		t.Fatalf("expected Connect, got %s", jc.GetState())
	}
	if radio.channel != 25 {
		t.Errorf("expected channel 25, got %d", radio.channel)
	}
	if radio.panID != 0x4567 {
		t.Errorf("expected panID 0x4567, got 0x%04x", radio.panID)
	}

	// 3. DTLS handshake success
	tr.connectCB(true)
	if jc.GetState() != JoinerStateConnected {
		t.Fatalf("expected Connected, got %s", jc.GetState())
	}
	if len(tr.sentData) == 0 {
		t.Fatal("JOINER_FINALIZE should have been sent")
	}

	// 4. Finalize accept
	resp := buildFinalizeAcceptResponse(0x0001)
	tr.receiveHandler(resp)
	if jc.GetState() != JoinerStateEntrust {
		t.Fatalf("expected Entrust, got %s", jc.GetState())
	}

	// 5. Entrust
	netKey := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	entrustMsg, entrustInfo := buildEntrustMessage(netKey)
	tr.handlers[joinerEntrustURI](entrustMsg, entrustInfo)
	if jc.GetState() != JoinerStateJoined {
		t.Fatalf("expected Joined, got %s", jc.GetState())
	}

	// 6. Post-join delay
	timerFuncs[len(timerFuncs)-1]()

	if !completed {
		t.Fatal("completion callback not called")
	}
	if completionErr != nil {
		t.Fatalf("expected success, got %v", completionErr)
	}
	if jc.GetState() != JoinerStateIdle {
		t.Errorf("expected Idle, got %s", jc.GetState())
	}

	// Verify saved dataset.
	if saver.savedInfo == nil {
		t.Fatal("dataset not saved")
	}
	if saver.savedInfo.NetworkKey != netKey {
		t.Error("saved network key mismatch")
	}
	if saver.savedInfo.Channel != 25 {
		t.Errorf("saved channel: got %d, want 25", saver.savedInfo.Channel)
	}
	if saver.savedInfo.PanID != 0x4567 {
		t.Errorf("saved panID: got 0x%04x, want 0x4567", saver.savedInfo.PanID)
	}
}

// ---------------------------------------------------------------------------
// Tests: JoinerState.String
// ---------------------------------------------------------------------------

func TestJoinerState_String(t *testing.T) {
	tests := []struct {
		state JoinerState
		want  string
	}{
		{JoinerStateIdle, "Idle"},
		{JoinerStateDiscover, "Discover"},
		{JoinerStateConnect, "Connecting"},
		{JoinerStateConnected, "Connected"},
		{JoinerStateEntrust, "Entrust"},
		{JoinerStateJoined, "Joined"},
		{JoinerState(99), "Unknown"},
	}
	for _, tc := range tests {
		if got := tc.state.String(); got != tc.want {
			t.Errorf("JoinerState(%d).String() = %q, want %q", tc.state, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests: ComputeJoinerIDFromEUI64
// ---------------------------------------------------------------------------

func TestComputeJoinerIDFromEUI64(t *testing.T) {
	eui := types.ExtAddress{0x18, 0xB4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x01}
	id := ComputeJoinerIDFromEUI64(eui)

	// The Local bit should be set.
	if id[0]&0x02 == 0 {
		t.Error("Local bit should be set in Joiner ID")
	}

	// Should be deterministic.
	id2 := ComputeJoinerIDFromEUI64(eui)
	if id != id2 {
		t.Error("ComputeJoinerIDFromEUI64 should be deterministic")
	}

	// Different EUI should give different ID.
	eui2 := types.ExtAddress{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
	id3 := ComputeJoinerIDFromEUI64(eui2)
	if id == id3 {
		t.Error("different EUI should give different Joiner ID")
	}
}

// ---------------------------------------------------------------------------
// Tests: generateJoinerIDFromDiscerner
// ---------------------------------------------------------------------------

func TestGenerateJoinerIDFromDiscerner(t *testing.T) {
	d := JoinerDiscerner{Value: 0xABCD, BitLength: 16}
	id := generateJoinerIDFromDiscerner(d)

	// Local bit should be set.
	if id[0]&0x02 == 0 {
		t.Error("Local bit should be set")
	}

	// Last 2 bytes should contain 0xABCD.
	lastTwo := binary.BigEndian.Uint16(id[6:8])
	if lastTwo != 0xABCD {
		t.Errorf("last 2 bytes: got 0x%04X, want 0xABCD", lastTwo)
	}
}

// ---------------------------------------------------------------------------
// Tests: linkLocalFromExtAddr
// ---------------------------------------------------------------------------

func TestLinkLocalFromExtAddr(t *testing.T) {
	ext := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	addr := linkLocalFromExtAddr(ext)

	// Check prefix.
	if addr[0] != 0xFE || addr[1] != 0x80 {
		t.Errorf("wrong prefix: %x %x", addr[0], addr[1])
	}

	// Check IID (U/L bit toggled).
	if addr[8] != (0x11 ^ 0x02) {
		t.Errorf("U/L bit not toggled: got 0x%02x, want 0x%02x", addr[8], 0x11^0x02)
	}
	if addr[9] != 0x22 || addr[15] != 0x88 {
		t.Error("IID bytes mismatch")
	}
}

// ---------------------------------------------------------------------------
// Tests: VendorStackVersion.Encode
// ---------------------------------------------------------------------------

func TestVendorStackVersion_Encode(t *testing.T) {
	v := VendorStackVersion{
		OUI:      [3]byte{0x00, 0x12, 0x34},
		Major:    1,
		Minor:    2,
		Revision: 3,
		Build:    100,
	}
	encoded := v.Encode()

	if len(encoded) != 6 {
		t.Fatalf("expected 6 bytes, got %d", len(encoded))
	}

	// OUI
	if encoded[0] != 0x00 || encoded[1] != 0x12 || encoded[2] != 0x34 {
		t.Errorf("OUI mismatch: %x", encoded[0:3])
	}

	// Build(12):Revision(4)
	br := binary.BigEndian.Uint16(encoded[3:5])
	build := br >> 4
	rev := br & 0x0F
	if build != 100 {
		t.Errorf("Build: got %d, want 100", build)
	}
	if rev != 3 {
		t.Errorf("Revision: got %d, want 3", rev)
	}

	// Minor(4):Major(4)
	minor := encoded[5] >> 4
	major := encoded[5] & 0x0F
	if major != 1 {
		t.Errorf("Major: got %d, want 1", major)
	}
	if minor != 2 {
		t.Errorf("Minor: got %d, want 2", minor)
	}
}

// ---------------------------------------------------------------------------
// Tests: Candidate management
// ---------------------------------------------------------------------------

func TestCandidateTable_Full(t *testing.T) {
	jc, _, _, scanner, _ := newTestJoinerClient()
	startJoinerClient(t, jc)

	// Fill all candidate slots.
	for i := 0; i < MaxJoinerCandidates+2; i++ {
		ext := types.ExtAddress{byte(i), 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		result := buildScanResult(uint8(11+i), 0x1000+uint16(i), 1000, ext, true)
		scanner.callback(result)
	}

	candidates := jc.GetCandidates()
	if len(candidates) > MaxJoinerCandidates {
		t.Errorf("candidates should be limited to %d, got %d", MaxJoinerCandidates, len(candidates))
	}
}

func TestCandidateTable_HigherPriorityReplacesLower(t *testing.T) {
	jc, _, _, scanner, _ := newTestJoinerClient()
	startJoinerClient(t, jc)
	joinerID := jc.GetID()

	// Fill all slots with non-preferred (priority=100).
	for i := 0; i < MaxJoinerCandidates; i++ {
		ext := types.ExtAddress{byte(i), 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		result := buildScanResult(uint8(11+i), 0x1000+uint16(i), 1000, ext, true)
		scanner.callback(result)
	}

	// Add a preferred candidate (priority=200). Should replace lowest.
	extPreferred := types.ExtAddress{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8}
	result := buildScanResultWithJoinerID(25, 0x9999, 1000, extPreferred, joinerID)
	scanner.callback(result)

	candidates := jc.GetCandidates()
	found := false
	for _, c := range candidates {
		if c.PanID == 0x9999 && c.Priority == 200 {
			found = true
			break
		}
	}
	if !found {
		t.Error("preferred candidate should have replaced a lower-priority one")
	}
}

// ---------------------------------------------------------------------------
// Tests: Connect failure cascade
// ---------------------------------------------------------------------------

func TestConnectFailure_ImmediateError(t *testing.T) {
	jc, tr, _, scanner, _ := newTestJoinerClient()
	completed := false
	var completionErr error
	_ = jc.Start(testPSKd, "", "V", "M", "1.0", "", VendorStackVersion{},
		func(err error) {
			completed = true
			completionErr = err
		})

	ext := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	scanner.callback(buildScanResult(11, 0x1111, 1000, ext, true))
	scanner.callback(nil)

	// First connect succeeds (in progress). Now make DTLS fail.
	tr.connectCB(false)

	// No more candidates.
	if !completed {
		t.Error("completion callback should have been called")
	}
	if completionErr != errors.ErrSecurity {
		t.Errorf("expected ErrSecurity, got %v", completionErr)
	}
}

// ---------------------------------------------------------------------------
// Tests: Discerner-based scan evaluation
// ---------------------------------------------------------------------------

func TestScanResult_DiscernerMatch(t *testing.T) {
	jc, _, _, scanner, _ := newTestJoinerClient()

	d := JoinerDiscerner{Value: 0xABCD, BitLength: 16}
	_ = jc.SetDiscerner(d)

	startJoinerClient(t, jc)

	// Build steering data that contains the discerner.
	ext := types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	result := &JoinerScanResult{
		ExtAddress:    ext,
		PanID:         0x1234,
		JoinerUDPPort: 1000,
		Channel:       15,
	}
	_ = result.SteeringData.Init(16)
	result.SteeringData.UpdateBloomFilterWithDiscerner(d.Value, d.BitLength)
	scanner.callback(result)

	candidates := jc.GetCandidates()
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}
	if candidates[0].Priority != 200 {
		t.Errorf("expected priority 200 (preferred), got %d", candidates[0].Priority)
	}
}

// ---------------------------------------------------------------------------
// Tests: Restart after completion
// ---------------------------------------------------------------------------

func TestRestartAfterCompletion(t *testing.T) {
	jc, tr, _, scanner, _ := newTestJoinerClient()
	var timerFuncs []func()
	jc.afterFunc = func(d time.Duration, f func()) Timer {
		timerFuncs = append(timerFuncs, f)
		return time.NewTimer(time.Hour)
	}

	// Complete a full join.
	_ = jc.Start(testPSKd, "", "V", "M", "1.0", "", VendorStackVersion{}, func(err error) {})
	ext := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	scanner.callback(buildScanResult(15, 0x1234, 1000, ext, true))
	scanner.callback(nil)
	tr.connectCB(true)
	tr.receiveHandler(buildFinalizeAcceptResponse(0x0001))
	netKey := [16]byte{0x01}
	entrustMsg, entrustInfo := buildEntrustMessage(netKey)
	tr.handlers[joinerEntrustURI](entrustMsg, entrustInfo)
	timerFuncs[len(timerFuncs)-1]() // post-join delay

	if jc.GetState() != JoinerStateIdle {
		t.Fatalf("expected Idle, got %s", jc.GetState())
	}

	// Should be able to start again.
	err := jc.Start(testPSKd, "", "V", "M", "1.0", "", VendorStackVersion{}, func(err error) {})
	if err != nil {
		t.Fatalf("restart failed: %v", err)
	}
	if jc.GetState() != JoinerStateDiscover {
		t.Errorf("expected Discover on restart, got %s", jc.GetState())
	}
}
