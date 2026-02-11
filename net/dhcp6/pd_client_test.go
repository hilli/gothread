// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package dhcp6

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

type mockPdTransport struct {
	sentPayloads [][]byte
	sentDsts     [][16]byte
	sendErr      error
	listening    bool
}

func (m *mockPdTransport) SendDhcp6(payload []byte, dst [16]byte) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	m.sentPayloads = append(m.sentPayloads, cp)
	m.sentDsts = append(m.sentDsts, dst)
	return nil
}

func (m *mockPdTransport) SetDhcp6ListeningEnabled(enabled bool) {
	m.listening = enabled
}

func (m *mockPdTransport) lastPayload() []byte {
	if len(m.sentPayloads) == 0 {
		return nil
	}
	return m.sentPayloads[len(m.sentPayloads)-1]
}

func (m *mockPdTransport) lastDst() [16]byte {
	if len(m.sentDsts) == 0 {
		return [16]byte{}
	}
	return m.sentDsts[len(m.sentDsts)-1]
}

type mockPdClock struct {
	nowMs     int64
	randVal   int64
	timers    []*mockPdTimerEntry
	randCalls int
}

type mockPdTimerEntry struct {
	fn       func()
	duration time.Duration
	stopped  bool
}

func (c *mockPdClock) NowMs() int64 {
	return c.nowMs
}

func (c *mockPdClock) NewTimer(fn func()) PdTimer {
	entry := &mockPdTimerEntry{fn: fn}
	c.timers = append(c.timers, entry)
	return entry
}

func (c *mockPdClock) RandomInt63n(n int64) int64 {
	c.randCalls++
	if n <= 0 {
		return 0
	}
	v := c.randVal % n
	c.randVal++ // auto-increment so successive TID generations differ
	return v
}

func (t *mockPdTimerEntry) Reset(d time.Duration) {
	t.duration = d
	t.stopped = false
}

func (t *mockPdTimerEntry) Stop() bool {
	was := !t.stopped
	t.stopped = true
	return was
}

func (t *mockPdTimerEntry) fire() {
	if !t.stopped {
		t.fn()
	}
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func testExtAddr() [8]byte {
	return [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
}

func testServerDuid() []byte {
	return []byte{0x00, 0x03, 0x00, 0x1B, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
}

func testPrefix48() [16]byte {
	return [16]byte{0x20, 0x01, 0x0d, 0xb8, 0xAB, 0xCD}
}

func testPrefix64() [16]byte {
	return [16]byte{0x20, 0x01, 0x0d, 0xb8, 0xAB, 0xCD, 0xEF, 0x01}
}

func testSrcAddr() [16]byte {
	return [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
}

func newTestPdClient(clock *mockPdClock) (*PdClient, *mockPdTransport, *mockPdClock, *[]*DelegatedPrefix) {
	transport := &mockPdTransport{}
	if clock == nil {
		clock = &mockPdClock{nowMs: 1000000, randVal: 1}
	}
	var callbacks []*DelegatedPrefix
	callback := func(dp *DelegatedPrefix) {
		cp := *dp
		callbacks = append(callbacks, &cp)
	}
	pc := NewPdClient(transport, callback, testExtAddr(), WithPdClock(clock))
	return pc, transport, clock, &callbacks
}

// extractTransactionID extracts the transaction ID from a sent Solicit/Request/etc payload.
func extractTransactionID(payload []byte) TransactionID {
	var tid TransactionID
	if len(payload) >= HeaderSize {
		copy(tid[:], payload[1:4])
	}
	return tid
}

// buildReplyMsg builds a minimal DHCPv6 Advertise or Reply message.
func buildReplyMsg(msgType MsgType, tid TransactionID, clientExtAddr [8]byte, serverDuid []byte, opts []byte) []byte {
	hdr := Header{Type: msgType, TransactionID: tid}
	hdrBytes, _ := hdr.MarshalBinary()
	buf := append([]byte(nil), hdrBytes...)

	// Client ID option.
	var clientDUID Eui64DUID
	clientDUID.Init(clientExtAddr)
	buf = AppendClientIDOption(buf, &clientDUID)

	// Server ID option.
	buf = AppendServerIDOptionRaw(buf, serverDuid)

	// Additional options.
	buf = append(buf, opts...)
	return buf
}

// buildIaPdOption builds an IA_PD option with a single IA_Prefix sub-option.
func buildIaPdOption(iaid, t1, t2, preferred, valid uint32, prefixLen uint8, prefix [16]byte) []byte {
	iap := IaPrefix{
		PreferredLifetime: preferred,
		ValidLifetime:     valid,
		PrefixLength:      prefixLen,
		Prefix:            prefix,
	}
	subOpts := AppendIaPrefixOption(nil, &iap)

	iapd := IaPd{
		IAID:       iaid,
		T1:         t1,
		T2:         t2,
		SubOptions: subOpts,
	}
	return AppendIaPdOption(nil, &iapd)
}

// buildIaPdWithStatus builds an IA_PD option containing a Status Code sub-option.
func buildIaPdWithStatus(iaid uint32, status StatusCodeValue) []byte {
	subOpts := AppendStatusCodeOption(nil, status)

	iapd := IaPd{
		IAID:       iaid,
		SubOptions: subOpts,
	}
	return AppendIaPdOption(nil, &iapd)
}

// ---------------------------------------------------------------------------
// Wire format tests: IaPd, IaPrefix, SolMaxRt
// ---------------------------------------------------------------------------

func TestIaPdMarshalUnmarshal(t *testing.T) {
	iapd := IaPd{IAID: 42, T1: 3600, T2: 5400}
	fixed := iapd.Marshal()
	if len(fixed) != IaPdSize {
		t.Fatalf("expected %d bytes, got %d", IaPdSize, len(fixed))
	}

	var iapd2 IaPd
	if err := iapd2.Unmarshal(fixed[:]); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if iapd2.IAID != 42 || iapd2.T1 != 3600 || iapd2.T2 != 5400 {
		t.Errorf("IaPd mismatch: %+v", iapd2)
	}
}

func TestIaPdWithSubOptions(t *testing.T) {
	subOpts := []byte{0x00, 0x1A, 0x00, 0x02, 0xAA, 0xBB} // fake sub-option
	iapd := IaPd{IAID: 1, SubOptions: subOpts}
	data, err := iapd.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	if len(data) != IaPdSize+len(subOpts) {
		t.Fatalf("expected %d bytes, got %d", IaPdSize+len(subOpts), len(data))
	}
	var iapd2 IaPd
	if err := iapd2.Unmarshal(data); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if !bytes.Equal(iapd2.SubOptions, subOpts) {
		t.Errorf("SubOptions mismatch")
	}
}

func TestIaPdUnmarshalShort(t *testing.T) {
	var iapd IaPd
	if err := iapd.Unmarshal(make([]byte, 8)); err == nil {
		t.Error("expected error for short data")
	}
}

func TestIaPrefixMarshalUnmarshal(t *testing.T) {
	prefix := testPrefix48()
	iap := IaPrefix{
		PreferredLifetime: 1800,
		ValidLifetime:     3600,
		PrefixLength:      48,
		Prefix:            prefix,
	}
	fixed := iap.Marshal()
	if len(fixed) != IaPrefixSize {
		t.Fatalf("expected %d bytes, got %d", IaPrefixSize, len(fixed))
	}

	var iap2 IaPrefix
	if err := iap2.Unmarshal(fixed[:]); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if iap2.PreferredLifetime != 1800 || iap2.ValidLifetime != 3600 {
		t.Errorf("lifetime mismatch: %+v", iap2)
	}
	if iap2.PrefixLength != 48 {
		t.Errorf("prefix length mismatch: got %d", iap2.PrefixLength)
	}
	if iap2.Prefix != prefix {
		t.Errorf("prefix mismatch")
	}
}

func TestIaPrefixUnmarshalShort(t *testing.T) {
	var iap IaPrefix
	if err := iap.Unmarshal(make([]byte, 20)); err == nil {
		t.Error("expected error for short data")
	}
}

func TestIaPrefixMarshalBinary(t *testing.T) {
	iap := IaPrefix{PreferredLifetime: 100, ValidLifetime: 200, PrefixLength: 64}
	data, err := iap.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	if len(data) != IaPrefixSize {
		t.Fatalf("expected %d bytes, got %d", IaPrefixSize, len(data))
	}
}

func TestSolMaxRtMarshalUnmarshal(t *testing.T) {
	smr := SolMaxRt{Value: 3600}
	fixed := smr.Marshal()
	if len(fixed) != SolMaxRtSize {
		t.Fatalf("expected %d bytes, got %d", SolMaxRtSize, len(fixed))
	}

	var smr2 SolMaxRt
	if err := smr2.Unmarshal(fixed[:]); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if smr2.Value != 3600 {
		t.Errorf("value mismatch: got %d", smr2.Value)
	}
}

func TestSolMaxRtUnmarshalShort(t *testing.T) {
	var smr SolMaxRt
	if err := smr.Unmarshal(make([]byte, 2)); err == nil {
		t.Error("expected error for short data")
	}
}

func TestSolMaxRtIsValid(t *testing.T) {
	tests := []struct {
		val  uint32
		want bool
	}{
		{59, false},
		{60, true},
		{3600, true},
		{86400, true},
		{86401, false},
	}
	for _, tt := range tests {
		smr := SolMaxRt{Value: tt.val}
		if smr.IsValid() != tt.want {
			t.Errorf("SolMaxRt{%d}.IsValid() = %v, want %v", tt.val, smr.IsValid(), tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Wire format tests: Append helpers
// ---------------------------------------------------------------------------

func TestAppendServerIDOptionRaw(t *testing.T) {
	duid := testServerDuid()
	buf := AppendServerIDOptionRaw(nil, duid)
	opt := FindOptionInBytes(buf, OptionCodeServerID)
	if opt == nil {
		t.Fatal("ServerID option not found")
	}
	if !bytes.Equal(opt.Data, duid) {
		t.Errorf("DUID mismatch: got %x, want %x", opt.Data, duid)
	}
}

func TestAppendIaPdOption(t *testing.T) {
	iapd := IaPd{IAID: 0, T1: 100, T2: 200}
	buf := AppendIaPdOption(nil, &iapd)
	opt := FindOptionInBytes(buf, OptionCodeIaPd)
	if opt == nil {
		t.Fatal("IA_PD option not found")
	}
	var iapd2 IaPd
	if err := iapd2.Unmarshal(opt.Data); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if iapd2.IAID != 0 || iapd2.T1 != 100 || iapd2.T2 != 200 {
		t.Errorf("IA_PD mismatch: %+v", iapd2)
	}
}

func TestAppendIaPrefixOption(t *testing.T) {
	prefix := testPrefix64()
	iap := IaPrefix{
		PreferredLifetime: 1800,
		ValidLifetime:     3600,
		PrefixLength:      64,
		Prefix:            prefix,
	}
	buf := AppendIaPrefixOption(nil, &iap)
	opt := FindOptionInBytes(buf, OptionCodeIaPrefix)
	if opt == nil {
		t.Fatal("IA_Prefix option not found")
	}
	var iap2 IaPrefix
	if err := iap2.Unmarshal(opt.Data); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if iap2.PrefixLength != 64 || iap2.Prefix != prefix {
		t.Errorf("IA_Prefix mismatch: %+v", iap2)
	}
}

// ---------------------------------------------------------------------------
// PD Client: Start / Stop
// ---------------------------------------------------------------------------

func TestPdClientStartEntersToSolicit(t *testing.T) {
	pc, transport, _, _ := newTestPdClient(nil)
	pc.Start()
	if pc.GetState() != PdStateToSolicit {
		t.Errorf("expected ToSolicit, got %d", pc.GetState())
	}
	if !transport.listening {
		t.Error("expected listening to be enabled")
	}
}

func TestPdClientStopFromStopped(t *testing.T) {
	pc, _, _, _ := newTestPdClient(nil)
	pc.Stop() // no-op
	if pc.GetState() != PdStateStopped {
		t.Errorf("expected Stopped, got %d", pc.GetState())
	}
}

func TestPdClientStopFromSoliciting(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()

	// Fire timer to go to Soliciting.
	clock.timers[0].fire()
	if pc.GetState() != PdStateSoliciting {
		t.Fatalf("expected Soliciting, got %d", pc.GetState())
	}

	pc.Stop()
	if pc.GetState() != PdStateStopped {
		t.Errorf("expected Stopped after Stop(), got %d", pc.GetState())
	}
	if transport.listening {
		t.Error("expected listening to be disabled")
	}
}

func TestPdClientGetDelegatedPrefixNilWhenStopped(t *testing.T) {
	pc, _, _, _ := newTestPdClient(nil)
	if dp := pc.GetDelegatedPrefix(); dp != nil {
		t.Error("expected nil delegated prefix when stopped")
	}
}

// ---------------------------------------------------------------------------
// PD Client: ToSolicit timer fires → Soliciting
// ---------------------------------------------------------------------------

func TestPdClientToSolicitTimerFiresSolicit(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()

	if pc.GetState() != PdStateToSolicit {
		t.Fatalf("expected ToSolicit, got %d", pc.GetState())
	}

	// Fire the timer.
	clock.timers[0].fire()
	if pc.GetState() != PdStateSoliciting {
		t.Fatalf("expected Soliciting, got %d", pc.GetState())
	}

	// Should have sent a Solicit.
	if len(transport.sentPayloads) == 0 {
		t.Fatal("expected at least one sent payload")
	}

	payload := transport.lastPayload()
	if payload[0] != byte(MsgTypeSolicit) {
		t.Errorf("expected Solicit message type, got %d", payload[0])
	}

	// Should be sent to all DHCP relay agents and servers.
	dst := transport.lastDst()
	var expected [16]byte
	copy(expected[:], AllDHCPRelayAgentsAndServers[:])
	if dst != expected {
		t.Errorf("expected multicast dst, got %x", dst)
	}
}

// ---------------------------------------------------------------------------
// PD Client: Soliciting → Advertise handling
// ---------------------------------------------------------------------------

func TestPdClientAdvertiseWithPreference255(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire() // → Soliciting

	if len(transport.sentPayloads) == 0 {
		t.Fatal("no Solicit sent")
	}
	tid := extractTransactionID(transport.lastPayload())

	// Build Advertise with preference 255 and a valid prefix.
	prefix := testPrefix48()
	var opts []byte
	opts = append(opts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	// Add preference option.
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	opts = AppendOption(opts, OptionCodePreference, prefData)
	// Status success (implicit, no status option = success).

	msg := buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), opts)
	pc.HandleReceive(msg, testSrcAddr())

	// With preference 255, should immediately enter Requesting.
	if pc.GetState() != PdStateRequesting {
		t.Errorf("expected Requesting, got %d", pc.GetState())
	}
}

func TestPdClientAdvertiseWithoutPreference255WaitsForTimer(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire() // → Soliciting

	tid := extractTransactionID(transport.lastPayload())

	// Advertise without preference 255 but on first attempt.
	prefix := testPrefix48()
	var opts []byte
	opts = append(opts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	msg := buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), opts)
	pc.HandleReceive(msg, testSrcAddr())

	// Since it's the first attempt and no preference 255, should stay Soliciting
	// (prefix is saved, but will enter Requesting on next timer fire).
	if pc.GetState() != PdStateSoliciting {
		t.Errorf("expected Soliciting (waiting for timer), got %d", pc.GetState())
	}

	// Fire the timer again → should enter Requesting.
	clock.timers[0].fire()
	if pc.GetState() != PdStateRequesting {
		t.Errorf("expected Requesting after timer fire, got %d", pc.GetState())
	}
}

// ---------------------------------------------------------------------------
// PD Client: Requesting → Reply handling
// ---------------------------------------------------------------------------

func TestPdClientRequestingReply(t *testing.T) {
	pc, transport, clock, callbacks := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire() // → Soliciting

	tid := extractTransactionID(transport.lastPayload())

	// Send Advertise with preference 255 to go to Requesting.
	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)
	advMsg := buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts)
	pc.HandleReceive(advMsg, testSrcAddr())

	if pc.GetState() != PdStateRequesting {
		t.Fatalf("expected Requesting, got %d", pc.GetState())
	}

	// Now the Request was sent; get its transaction ID.
	reqTid := extractTransactionID(transport.lastPayload())

	// Build Reply with the same prefix.
	var replyOpts []byte
	replyOpts = append(replyOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	replyMsg := buildReplyMsg(MsgTypeReply, reqTid, testExtAddr(), testServerDuid(), replyOpts)
	pc.HandleReceive(replyMsg, testSrcAddr())

	// Should now be in ToRenew state.
	if pc.GetState() != PdStateToRenew {
		t.Errorf("expected ToRenew, got %d", pc.GetState())
	}

	// Should have received a callback for the committed prefix.
	if len(*callbacks) == 0 {
		t.Fatal("expected callback for committed prefix")
	}
	dp := (*callbacks)[len(*callbacks)-1]
	if dp.PrefixLength != 48 {
		t.Errorf("expected prefix length 48, got %d", dp.PrefixLength)
	}
	if dp.AdjustedLength != 64 {
		t.Errorf("expected adjusted length 64, got %d", dp.AdjustedLength)
	}
	if dp.PreferredLifetime == 0 {
		t.Error("expected non-zero preferred lifetime")
	}

	// GetDelegatedPrefix should return the prefix.
	got := pc.GetDelegatedPrefix()
	if got == nil {
		t.Fatal("expected delegated prefix")
	}
	if got.PrefixLength != 48 {
		t.Errorf("delegated prefix length mismatch: got %d", got.PrefixLength)
	}
}

func TestPdClientRequestingReplyNoPrefixAvail(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire() // → Soliciting

	tid := extractTransactionID(transport.lastPayload())

	// Advertise with preference 255.
	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)
	advMsg := buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts)
	pc.HandleReceive(advMsg, testSrcAddr())

	reqTid := extractTransactionID(transport.lastPayload())

	// Reply with NoPrefixAvail status in IA_PD.
	var replyOpts []byte
	replyOpts = append(replyOpts, buildIaPdWithStatus(0, StatusNoPrefixAvail)...)
	replyMsg := buildReplyMsg(MsgTypeReply, reqTid, testExtAddr(), testServerDuid(), replyOpts)
	pc.HandleReceive(replyMsg, testSrcAddr())

	// Should go back to ToSolicit.
	if pc.GetState() != PdStateToSolicit {
		t.Errorf("expected ToSolicit after NoPrefixAvail, got %d", pc.GetState())
	}
}

// ---------------------------------------------------------------------------
// PD Client: Renew / Rebind
// ---------------------------------------------------------------------------

func TestPdClientRenewFlow(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire() // → Soliciting

	tid := extractTransactionID(transport.lastPayload())

	// Get to ToRenew via Advertise(pref=255) → Reply.
	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)
	advMsg := buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts)
	pc.HandleReceive(advMsg, testSrcAddr())

	reqTid := extractTransactionID(transport.lastPayload())

	var replyOpts []byte
	replyOpts = append(replyOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	replyMsg := buildReplyMsg(MsgTypeReply, reqTid, testExtAddr(), testServerDuid(), replyOpts)
	pc.HandleReceive(replyMsg, testSrcAddr())

	if pc.GetState() != PdStateToRenew {
		t.Fatalf("expected ToRenew, got %d", pc.GetState())
	}

	// Fire timer to enter Renewing.
	clock.timers[0].fire()
	if pc.GetState() != PdStateRenewing {
		t.Fatalf("expected Renewing, got %d", pc.GetState())
	}

	// Should have sent a Renew message.
	renewPayload := transport.lastPayload()
	if renewPayload[0] != byte(MsgTypeRenew) {
		t.Errorf("expected Renew message type, got %d", renewPayload[0])
	}

	// Reply to Renew with the same prefix.
	renewTid := extractTransactionID(renewPayload)
	var renewReplyOpts []byte
	renewReplyOpts = append(renewReplyOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	renewReplyMsg := buildReplyMsg(MsgTypeReply, renewTid, testExtAddr(), testServerDuid(), renewReplyOpts)
	pc.HandleReceive(renewReplyMsg, testSrcAddr())

	// Should go back to ToRenew.
	if pc.GetState() != PdStateToRenew {
		t.Errorf("expected ToRenew after Renew reply, got %d", pc.GetState())
	}
}

// ---------------------------------------------------------------------------
// PD Client: Stop from bound state → Releasing
// ---------------------------------------------------------------------------

func TestPdClientStopFromBoundEntersReleasing(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire() // → Soliciting

	tid := extractTransactionID(transport.lastPayload())

	// Advertise with pref=255 → Requesting.
	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)
	pc.HandleReceive(buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts), testSrcAddr())

	reqTid := extractTransactionID(transport.lastPayload())

	// Reply → ToRenew.
	var replyOpts []byte
	replyOpts = append(replyOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pc.HandleReceive(buildReplyMsg(MsgTypeReply, reqTid, testExtAddr(), testServerDuid(), replyOpts), testSrcAddr())

	if pc.GetState() != PdStateToRenew {
		t.Fatalf("expected ToRenew, got %d", pc.GetState())
	}

	// Stop should enter Releasing.
	pc.Stop()
	if pc.GetState() != PdStateReleasing {
		t.Errorf("expected Releasing, got %d", pc.GetState())
	}

	// Should have sent a Release message.
	releasePayload := transport.lastPayload()
	if releasePayload[0] != byte(MsgTypeRelease) {
		t.Errorf("expected Release message type, got %d", releasePayload[0])
	}
}

func TestPdClientReleasingReplyCompletes(t *testing.T) {
	pc, transport, clock, callbacks := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire()

	tid := extractTransactionID(transport.lastPayload())

	// Get to ToRenew.
	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)
	pc.HandleReceive(buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts), testSrcAddr())

	reqTid := extractTransactionID(transport.lastPayload())
	var replyOpts []byte
	replyOpts = append(replyOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pc.HandleReceive(buildReplyMsg(MsgTypeReply, reqTid, testExtAddr(), testServerDuid(), replyOpts), testSrcAddr())

	callbacksBefore := len(*callbacks)

	// Stop → Releasing.
	pc.Stop()
	releaseTid := extractTransactionID(transport.lastPayload())

	// Reply to Release.
	releaseReplyMsg := buildReplyMsg(MsgTypeReply, releaseTid, testExtAddr(), testServerDuid(), nil)
	pc.HandleReceive(releaseReplyMsg, testSrcAddr())

	if pc.GetState() != PdStateStopped {
		t.Errorf("expected Stopped after Release reply, got %d", pc.GetState())
	}
	if transport.listening {
		t.Error("expected listening disabled after release")
	}

	// Callback should have been called for prefix removal (during enterState Releasing).
	if len(*callbacks) <= callbacksBefore {
		t.Error("expected removal callback")
	}
}

// ---------------------------------------------------------------------------
// PD Client: Transaction ID mismatch ignored
// ---------------------------------------------------------------------------

func TestPdClientIgnoresWrongTransactionID(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire() // → Soliciting

	wrongTid := TransactionID{0xFF, 0xFF, 0xFF}

	prefix := testPrefix48()
	var opts []byte
	opts = append(opts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	msg := buildReplyMsg(MsgTypeAdvertise, wrongTid, testExtAddr(), testServerDuid(), opts)
	pc.HandleReceive(msg, testSrcAddr())

	// Should still be Soliciting (message ignored).
	if pc.GetState() != PdStateSoliciting {
		t.Errorf("expected Soliciting (wrong tid ignored), got %d", pc.GetState())
	}
	_ = transport
}

// ---------------------------------------------------------------------------
// PD Client: Wrong message type for state ignored
// ---------------------------------------------------------------------------

func TestPdClientIgnoresReplyInSoliciting(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire() // → Soliciting

	tid := extractTransactionID(transport.lastPayload())

	// Send a Reply when we're Soliciting (only Advertise expected).
	prefix := testPrefix48()
	var opts []byte
	opts = append(opts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	msg := buildReplyMsg(MsgTypeReply, tid, testExtAddr(), testServerDuid(), opts)
	pc.HandleReceive(msg, testSrcAddr())

	// Should still be Soliciting.
	if pc.GetState() != PdStateSoliciting {
		t.Errorf("expected Soliciting, got %d", pc.GetState())
	}
}

func TestPdClientIgnoresAdvertiseInRequesting(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire() // → Soliciting

	tid := extractTransactionID(transport.lastPayload())

	// Get to Requesting via Advertise(pref=255).
	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)
	pc.HandleReceive(buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts), testSrcAddr())

	reqTid := extractTransactionID(transport.lastPayload())

	// Send another Advertise while Requesting (should be ignored).
	msg := buildReplyMsg(MsgTypeAdvertise, reqTid, testExtAddr(), testServerDuid(), advOpts)
	pc.HandleReceive(msg, testSrcAddr())

	// Still Requesting.
	if pc.GetState() != PdStateRequesting {
		t.Errorf("expected Requesting, got %d", pc.GetState())
	}
}

// ---------------------------------------------------------------------------
// PD Client: Messages ignored when stopped/ToSolicit
// ---------------------------------------------------------------------------

func TestPdClientIgnoresMessagesWhenStopped(t *testing.T) {
	pc, _, _, _ := newTestPdClient(nil)
	msg := buildReplyMsg(MsgTypeReply, TransactionID{}, testExtAddr(), testServerDuid(), nil)
	pc.HandleReceive(msg, testSrcAddr())
	if pc.GetState() != PdStateStopped {
		t.Errorf("expected Stopped, got %d", pc.GetState())
	}
}

func TestPdClientIgnoresMessagesInToSolicit(t *testing.T) {
	pc, _, _, _ := newTestPdClient(nil)
	pc.Start()
	msg := buildReplyMsg(MsgTypeAdvertise, TransactionID{}, testExtAddr(), testServerDuid(), nil)
	pc.HandleReceive(msg, testSrcAddr())
	if pc.GetState() != PdStateToSolicit {
		t.Errorf("expected ToSolicit, got %d", pc.GetState())
	}
}

// ---------------------------------------------------------------------------
// PD Client: Client ID mismatch
// ---------------------------------------------------------------------------

func TestPdClientIgnoresWrongClientID(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire() // → Soliciting

	tid := extractTransactionID(transport.lastPayload())

	// Build Advertise with wrong client ID (different ext addr).
	wrongExt := [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	prefix := testPrefix48()
	var opts []byte
	opts = append(opts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	msg := buildReplyMsg(MsgTypeAdvertise, tid, wrongExt, testServerDuid(), opts)
	pc.HandleReceive(msg, testSrcAddr())

	// Should still be Soliciting.
	if pc.GetState() != PdStateSoliciting {
		t.Errorf("expected Soliciting, got %d", pc.GetState())
	}
}

// ---------------------------------------------------------------------------
// PD Client: Prefix length > 64 rejected
// ---------------------------------------------------------------------------

func TestPdClientRejectsPrefix96(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire() // → Soliciting

	tid := extractTransactionID(transport.lastPayload())

	// Advertise with a /96 prefix (too long for PD, > 64).
	prefix := testPrefix48()
	var opts []byte
	opts = append(opts, buildIaPdOption(0, 0, 0, 1800, 3600, 96, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	opts = AppendOption(opts, OptionCodePreference, prefData)
	msg := buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), opts)
	pc.HandleReceive(msg, testSrcAddr())

	// Should still be Soliciting (prefix rejected).
	if pc.GetState() != PdStateSoliciting {
		t.Errorf("expected Soliciting (prefix > 64 rejected), got %d", pc.GetState())
	}
}

// ---------------------------------------------------------------------------
// PD Client: Prefix with short preferred lifetime rejected
// ---------------------------------------------------------------------------

func TestPdClientRejectsShortPreferredLifetime(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire() // → Soliciting

	tid := extractTransactionID(transport.lastPayload())

	// Advertise with preferred lifetime < 30 minutes (pdMinPreferredLifetime = 1800).
	prefix := testPrefix48()
	var opts []byte
	opts = append(opts, buildIaPdOption(0, 0, 0, 60, 120, 48, prefix)...) // 60 sec preferred
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	opts = AppendOption(opts, OptionCodePreference, prefData)
	msg := buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), opts)
	pc.HandleReceive(msg, testSrcAddr())

	// selectFavoredPrefix requires PreferredLifetime >= pdMinPreferredLifetime (1800).
	// Since 60 < 1800, no favored prefix is selected.
	if pc.GetState() != PdStateSoliciting {
		t.Errorf("expected Soliciting (short preferred rejected), got %d", pc.GetState())
	}
}

// ---------------------------------------------------------------------------
// PD Client: UseMulticast handling
// ---------------------------------------------------------------------------

func TestPdClientHandlesUseMulticast(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire() // → Soliciting

	tid := extractTransactionID(transport.lastPayload())

	// Get to Requesting.
	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)

	// Also include a server unicast option to set the unicast address.
	unicastAddr := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	advOpts = AppendOption(advOpts, OptionCodeServerUnicast, unicastAddr[:])

	pc.HandleReceive(buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts), testSrcAddr())

	if pc.GetState() != PdStateRequesting {
		t.Fatalf("expected Requesting, got %d", pc.GetState())
	}

	reqTid := extractTransactionID(transport.lastPayload())
	sendCountBefore := len(transport.sentPayloads)

	// Reply with UseMulticast status.
	var replyOpts []byte
	replyOpts = AppendStatusCodeOption(replyOpts, StatusUseMulticast)
	replyMsg := buildReplyMsg(MsgTypeReply, reqTid, testExtAddr(), testServerDuid(), replyOpts)
	pc.HandleReceive(replyMsg, testSrcAddr())

	// Should have resent the message (sendMessage called again).
	if len(transport.sentPayloads) <= sendCountBefore {
		t.Error("expected resend after UseMulticast")
	}

	// The new message should go to multicast.
	latestDst := transport.lastDst()
	var multicast [16]byte
	copy(multicast[:], AllDHCPRelayAgentsAndServers[:])
	if latestDst != multicast {
		t.Errorf("expected multicast dst after UseMulticast, got %x", latestDst)
	}
}

// ---------------------------------------------------------------------------
// PD Client: UnspecFail reply ignored
// ---------------------------------------------------------------------------

func TestPdClientIgnoresUnspecFailReply(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire()

	tid := extractTransactionID(transport.lastPayload())

	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)
	pc.HandleReceive(buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts), testSrcAddr())

	reqTid := extractTransactionID(transport.lastPayload())

	var replyOpts []byte
	replyOpts = AppendStatusCodeOption(replyOpts, StatusUnspecFail)
	replyMsg := buildReplyMsg(MsgTypeReply, reqTid, testExtAddr(), testServerDuid(), replyOpts)
	pc.HandleReceive(replyMsg, testSrcAddr())

	// Should still be Requesting (UnspecFail ignored).
	if pc.GetState() != PdStateRequesting {
		t.Errorf("expected Requesting after UnspecFail, got %d", pc.GetState())
	}
}

// ---------------------------------------------------------------------------
// PD Client: Retransmission exhaustion fallback
// ---------------------------------------------------------------------------

func TestPdClientRequestingExhaustedFallsBackToSoliciting(t *testing.T) {
	clock := &mockPdClock{nowMs: 1000000, randVal: 0}
	pc, transport, _, _ := newTestPdClient(clock)
	pc.Start()
	clock.timers[0].fire() // → Soliciting

	tid := extractTransactionID(transport.lastPayload())

	// Advertise pref=255 → Requesting.
	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)
	pc.HandleReceive(buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts), testSrcAddr())

	if pc.GetState() != PdStateRequesting {
		t.Fatalf("expected Requesting, got %d", pc.GetState())
	}

	// Exhaust retransmissions (pdMaxRequestRetxCount = 10).
	for i := 0; i < 15; i++ {
		clock.nowMs += 2000
		clock.timers[0].fire()
		if pc.GetState() == PdStateSoliciting {
			return // good
		}
	}

	t.Error("expected to fall back to Soliciting after retransmission exhaustion")
}

// ---------------------------------------------------------------------------
// PD Client: SOL_MAX_RT processing
// ---------------------------------------------------------------------------

func TestPdClientSolMaxRtUpdated(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire() // → Soliciting

	tid := extractTransactionID(transport.lastPayload())

	// Build Advertise with SOL_MAX_RT option = 600 seconds.
	prefix := testPrefix48()
	var opts []byte
	opts = append(opts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)

	// Add SOL_MAX_RT option.
	smr := SolMaxRt{Value: 600}
	smrBuf := smr.Marshal()
	opts = AppendOption(opts, OptionCodeSolMaxRt, smrBuf[:])

	msg := buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), opts)
	pc.HandleReceive(msg, testSrcAddr())

	// The maxSolicitTimeout should be updated to 600 * 1000 = 600000 ms.
	if pc.maxSolicitTimeout != 600*1000 {
		t.Errorf("expected maxSolicitTimeout 600000, got %d", pc.maxSolicitTimeout)
	}
}

func TestPdClientSolMaxRtInvalidIgnored(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire()

	tid := extractTransactionID(transport.lastPayload())

	prefix := testPrefix48()
	var opts []byte
	opts = append(opts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)

	// SOL_MAX_RT = 50 (< 60, invalid)
	smr := SolMaxRt{Value: 50}
	smrBuf := smr.Marshal()
	opts = AppendOption(opts, OptionCodeSolMaxRt, smrBuf[:])

	msg := buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), opts)
	pc.HandleReceive(msg, testSrcAddr())

	// Should remain at default.
	if pc.maxSolicitTimeout != pdDefaultMaxSolicitTimeout {
		t.Errorf("expected default maxSolicitTimeout, got %d", pc.maxSolicitTimeout)
	}
}

// ---------------------------------------------------------------------------
// PD Client: Prefix adjusted to /64
// ---------------------------------------------------------------------------

func TestPdClientPrefixAdjustedTo64(t *testing.T) {
	pc, transport, clock, callbacks := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire()

	tid := extractTransactionID(transport.lastPayload())

	// Advertise with /48 prefix.
	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)
	pc.HandleReceive(buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts), testSrcAddr())

	reqTid := extractTransactionID(transport.lastPayload())

	// Reply with the same prefix.
	var replyOpts []byte
	replyOpts = append(replyOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pc.HandleReceive(buildReplyMsg(MsgTypeReply, reqTid, testExtAddr(), testServerDuid(), replyOpts), testSrcAddr())

	if len(*callbacks) == 0 {
		t.Fatal("expected callback")
	}
	dp := (*callbacks)[len(*callbacks)-1]
	if dp.AdjustedLength != 64 {
		t.Errorf("expected adjusted length 64, got %d", dp.AdjustedLength)
	}
	if dp.PrefixLength != 48 {
		t.Errorf("expected original prefix length 48, got %d", dp.PrefixLength)
	}
}

// ---------------------------------------------------------------------------
// PD Client: Lifetime T1/T2 defaults
// ---------------------------------------------------------------------------

func TestPdClientLifetimeT1T2Defaults(t *testing.T) {
	pc, transport, clock, callbacks := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire()

	tid := extractTransactionID(transport.lastPayload())

	// Advertise with T1=0, T2=0 to trigger defaults.
	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)
	pc.HandleReceive(buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts), testSrcAddr())

	reqTid := extractTransactionID(transport.lastPayload())

	var replyOpts []byte
	replyOpts = append(replyOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pc.HandleReceive(buildReplyMsg(MsgTypeReply, reqTid, testExtAddr(), testServerDuid(), replyOpts), testSrcAddr())

	if len(*callbacks) == 0 {
		t.Fatal("expected callback")
	}
	dp := (*callbacks)[len(*callbacks)-1]

	// Default T1 = preferred * 0.5 = 900, clamped to [pdMinT1, preferred - pdMinT1Margin].
	// pdMinT1 = 300, pdMinT1MarginBeforePreferredLifetime = 900
	// So T1 clamped to [300, 1800-900=900] → 900.
	if dp.T1 != 900 {
		t.Errorf("expected T1=900 (default 50%% of 1800), got %d", dp.T1)
	}

	// Default T2 = preferred * 0.8 = 1440, clamped to [T1, preferred - pdMinT2Margin].
	// pdMinT2MarginBeforePreferredLifetime = 360
	// So T2 clamped to [900, 1800-360=1440] → 1440.
	if dp.T2 != 1440 {
		t.Errorf("expected T2=1440 (default 80%% of 1800), got %d", dp.T2)
	}
}

// ---------------------------------------------------------------------------
// PD Client: Advertise with failed status ignored
// ---------------------------------------------------------------------------

func TestPdClientAdvertiseWithFailedStatusIgnored(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire()

	tid := extractTransactionID(transport.lastPayload())

	prefix := testPrefix48()
	var opts []byte
	opts = append(opts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	// Add top-level status = UnspecFail.
	opts = AppendStatusCodeOption(opts, StatusUnspecFail)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	opts = AppendOption(opts, OptionCodePreference, prefData)

	msg := buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), opts)
	pc.HandleReceive(msg, testSrcAddr())

	// Should still be Soliciting.
	if pc.GetState() != PdStateSoliciting {
		t.Errorf("expected Soliciting after failed status, got %d", pc.GetState())
	}
}

// ---------------------------------------------------------------------------
// PD Client: No ServerID → ignored
// ---------------------------------------------------------------------------

func TestPdClientAdvertiseWithoutServerIDIgnored(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire()

	tid := extractTransactionID(transport.lastPayload())

	// Build a malformed Advertise without Server ID.
	hdr := Header{Type: MsgTypeAdvertise, TransactionID: tid}
	hdrBytes, _ := hdr.MarshalBinary()
	buf := append([]byte(nil), hdrBytes...)

	var clientDUID Eui64DUID
	clientDUID.Init(testExtAddr())
	buf = AppendClientIDOption(buf, &clientDUID)
	// No Server ID option.

	prefix := testPrefix48()
	buf = append(buf, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)

	pc.HandleReceive(buf, testSrcAddr())

	// Should still be Soliciting.
	if pc.GetState() != PdStateSoliciting {
		t.Errorf("expected Soliciting, got %d", pc.GetState())
	}
	_ = transport
}

// ---------------------------------------------------------------------------
// PD Client: Short payload ignored
// ---------------------------------------------------------------------------

func TestPdClientIgnoresShortPayload(t *testing.T) {
	pc, _, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire() // → Soliciting

	pc.HandleReceive([]byte{0x02}, testSrcAddr()) // too short
	if pc.GetState() != PdStateSoliciting {
		t.Errorf("expected Soliciting, got %d", pc.GetState())
	}
}

// ---------------------------------------------------------------------------
// PD Client: Rebinding after renew exhaustion
// ---------------------------------------------------------------------------

func TestPdClientRenewExhaustedGoesToRebinding(t *testing.T) {
	clock := &mockPdClock{nowMs: 1000000, randVal: 0}
	pc, transport, _, callbacks := newTestPdClient(clock)
	pc.Start()
	clock.timers[0].fire() // → Soliciting

	tid := extractTransactionID(transport.lastPayload())

	// Get to ToRenew.
	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)
	pc.HandleReceive(buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts), testSrcAddr())

	reqTid := extractTransactionID(transport.lastPayload())
	var replyOpts []byte
	replyOpts = append(replyOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pc.HandleReceive(buildReplyMsg(MsgTypeReply, reqTid, testExtAddr(), testServerDuid(), replyOpts), testSrcAddr())

	if pc.GetState() != PdStateToRenew {
		t.Fatalf("expected ToRenew, got %d", pc.GetState())
	}

	// Enter Renewing.
	clock.timers[0].fire()
	if pc.GetState() != PdStateRenewing {
		t.Fatalf("expected Renewing, got %d", pc.GetState())
	}

	// Exhaust renew by advancing past T2 endTime.
	dp := pc.GetDelegatedPrefix()
	if dp == nil {
		t.Fatal("expected delegated prefix")
	}
	t2TimeMs := dp.UpdateTimeMs + int64(dp.T2)*1000

	// Advance time past T2.
	clock.nowMs = t2TimeMs + 1000

	// Fire timer → should hit isExhausted() and go to Rebinding.
	clock.timers[0].fire()
	if pc.GetState() != PdStateRebinding {
		t.Errorf("expected Rebinding after renew exhaustion, got %d", pc.GetState())
	}

	_ = callbacks
}

// ---------------------------------------------------------------------------
// PD Client: Renewing with NoBinding → Rebinding
// ---------------------------------------------------------------------------

func TestPdClientRenewingNoBindingGoesToRebinding(t *testing.T) {
	clock := &mockPdClock{nowMs: 1000000, randVal: 0}
	pc, transport, _, _ := newTestPdClient(clock)
	pc.Start()
	clock.timers[0].fire()

	tid := extractTransactionID(transport.lastPayload())

	// Get to Renewing.
	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)
	pc.HandleReceive(buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts), testSrcAddr())

	reqTid := extractTransactionID(transport.lastPayload())
	var replyOpts []byte
	replyOpts = append(replyOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pc.HandleReceive(buildReplyMsg(MsgTypeReply, reqTid, testExtAddr(), testServerDuid(), replyOpts), testSrcAddr())

	clock.timers[0].fire() // → Renewing

	if pc.GetState() != PdStateRenewing {
		t.Fatalf("expected Renewing, got %d", pc.GetState())
	}

	renewTid := extractTransactionID(transport.lastPayload())

	// Reply with NoBinding status in IA_PD.
	var renewReplyOpts []byte
	renewReplyOpts = append(renewReplyOpts, buildIaPdWithStatus(0, StatusNoBinding)...)
	renewReplyMsg := buildReplyMsg(MsgTypeReply, renewTid, testExtAddr(), testServerDuid(), renewReplyOpts)
	pc.HandleReceive(renewReplyMsg, testSrcAddr())

	if pc.GetState() != PdStateRebinding {
		t.Errorf("expected Rebinding after NoBinding reply, got %d", pc.GetState())
	}
}

// ---------------------------------------------------------------------------
// PD Client: Rebinding exhausted → Soliciting
// ---------------------------------------------------------------------------

func TestPdClientRebindingExhaustedGoesToSoliciting(t *testing.T) {
	clock := &mockPdClock{nowMs: 1000000, randVal: 0}
	pc, transport, _, _ := newTestPdClient(clock)
	pc.Start()
	clock.timers[0].fire()

	tid := extractTransactionID(transport.lastPayload())

	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)
	pc.HandleReceive(buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts), testSrcAddr())

	reqTid := extractTransactionID(transport.lastPayload())
	var replyOpts []byte
	replyOpts = append(replyOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pc.HandleReceive(buildReplyMsg(MsgTypeReply, reqTid, testExtAddr(), testServerDuid(), replyOpts), testSrcAddr())

	dp := pc.GetDelegatedPrefix()
	if dp == nil {
		t.Fatal("expected prefix")
	}

	// Enter Renewing, then advance past T2 to enter Rebinding.
	clock.timers[0].fire() // → Renewing
	t2Ms := dp.UpdateTimeMs + int64(dp.T2)*1000
	clock.nowMs = t2Ms + 1000
	clock.timers[0].fire() // → Rebinding

	if pc.GetState() != PdStateRebinding {
		t.Fatalf("expected Rebinding, got %d", pc.GetState())
	}

	// Advance past preferred lifetime to exhaust rebinding.
	prefMs := dp.UpdateTimeMs + int64(dp.PreferredLifetime)*1000
	clock.nowMs = prefMs + 1000
	clock.timers[0].fire()

	if pc.GetState() != PdStateSoliciting {
		t.Errorf("expected Soliciting after rebinding exhaustion, got %d", pc.GetState())
	}
}

// ---------------------------------------------------------------------------
// PD Client: Releasing exhausted → Stopped
// ---------------------------------------------------------------------------

func TestPdClientReleasingExhaustedGoesToStopped(t *testing.T) {
	clock := &mockPdClock{nowMs: 1000000, randVal: 0}
	pc, transport, _, _ := newTestPdClient(clock)
	pc.Start()
	clock.timers[0].fire()

	tid := extractTransactionID(transport.lastPayload())

	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)
	pc.HandleReceive(buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts), testSrcAddr())

	reqTid := extractTransactionID(transport.lastPayload())
	var replyOpts []byte
	replyOpts = append(replyOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pc.HandleReceive(buildReplyMsg(MsgTypeReply, reqTid, testExtAddr(), testServerDuid(), replyOpts), testSrcAddr())

	pc.Stop() // → Releasing

	if pc.GetState() != PdStateReleasing {
		t.Fatalf("expected Releasing, got %d", pc.GetState())
	}

	// Exhaust release retransmissions (pdMaxReleaseRetxCount = 4).
	for i := 0; i < 10; i++ {
		clock.nowMs += 2000
		clock.timers[0].fire()
		if pc.GetState() == PdStateStopped {
			return
		}
	}

	t.Error("expected Stopped after release retransmission exhaustion")
}

// ---------------------------------------------------------------------------
// PD Client: Start from Releasing restarts
// ---------------------------------------------------------------------------

func TestPdClientStartFromReleasing(t *testing.T) {
	clock := &mockPdClock{nowMs: 1000000, randVal: 0}
	pc, transport, _, _ := newTestPdClient(clock)
	pc.Start()
	clock.timers[0].fire()

	tid := extractTransactionID(transport.lastPayload())

	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)
	pc.HandleReceive(buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts), testSrcAddr())

	reqTid := extractTransactionID(transport.lastPayload())
	var replyOpts []byte
	replyOpts = append(replyOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pc.HandleReceive(buildReplyMsg(MsgTypeReply, reqTid, testExtAddr(), testServerDuid(), replyOpts), testSrcAddr())

	pc.Stop() // → Releasing
	if pc.GetState() != PdStateReleasing {
		t.Fatalf("expected Releasing, got %d", pc.GetState())
	}

	// Start again from Releasing → ToSolicit.
	pc.Start()
	if pc.GetState() != PdStateToSolicit {
		t.Errorf("expected ToSolicit, got %d", pc.GetState())
	}
}

// ---------------------------------------------------------------------------
// PD Client: IA_PD with T1 > T2 skipped
// ---------------------------------------------------------------------------

func TestPdClientIaPdT1GreaterThanT2Skipped(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire()

	tid := extractTransactionID(transport.lastPayload())

	// Build IA_PD with T1 > T2 (both non-zero).
	prefix := testPrefix48()
	var opts []byte
	opts = append(opts, buildIaPdOption(0, 1000, 500, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	opts = AppendOption(opts, OptionCodePreference, prefData)

	msg := buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), opts)
	pc.HandleReceive(msg, testSrcAddr())

	// Should still be Soliciting (T1 > T2 causes IA_PD to be skipped).
	if pc.GetState() != PdStateSoliciting {
		t.Errorf("expected Soliciting (T1>T2 skipped), got %d", pc.GetState())
	}
}

// ---------------------------------------------------------------------------
// PD Client: IA_PD with preferred > valid skipped
// ---------------------------------------------------------------------------

func TestPdClientIaPrefixPreferredGreaterThanValidSkipped(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire()

	tid := extractTransactionID(transport.lastPayload())

	// Build IA_PD with preferred > valid.
	prefix := testPrefix48()
	var opts []byte
	opts = append(opts, buildIaPdOption(0, 0, 0, 5000, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	opts = AppendOption(opts, OptionCodePreference, prefData)

	msg := buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), opts)
	pc.HandleReceive(msg, testSrcAddr())

	// Should still be Soliciting.
	if pc.GetState() != PdStateSoliciting {
		t.Errorf("expected Soliciting (preferred > valid skipped), got %d", pc.GetState())
	}
}

// ---------------------------------------------------------------------------
// PD Client: Preferred lifetime clamped to max
// ---------------------------------------------------------------------------

func TestPdClientPreferredLifetimeClampedToMax(t *testing.T) {
	pc, transport, clock, callbacks := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire()

	tid := extractTransactionID(transport.lastPayload())

	// Advertise with very large preferred lifetime (> pdMaxPreferredLifetime = 4h = 14400).
	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 86400, 100000, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)
	pc.HandleReceive(buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts), testSrcAddr())

	reqTid := extractTransactionID(transport.lastPayload())
	var replyOpts []byte
	replyOpts = append(replyOpts, buildIaPdOption(0, 0, 0, 86400, 100000, 48, prefix)...)
	pc.HandleReceive(buildReplyMsg(MsgTypeReply, reqTid, testExtAddr(), testServerDuid(), replyOpts), testSrcAddr())

	if len(*callbacks) == 0 {
		t.Fatal("expected callback")
	}
	dp := (*callbacks)[len(*callbacks)-1]

	// Preferred lifetime should be clamped to pdMaxPreferredLifetime = 14400.
	if dp.PreferredLifetime != 14400 {
		t.Errorf("expected preferred lifetime clamped to 14400, got %d", dp.PreferredLifetime)
	}

	// Valid lifetime should be preferred + pdMaxValidMarginAfterPreferredLifetime = 14400 + 120 = 14520.
	if dp.ValidLifetime != 14520 {
		t.Errorf("expected valid lifetime 14520, got %d", dp.ValidLifetime)
	}
}

// ---------------------------------------------------------------------------
// PD Client: Solicit message contents
// ---------------------------------------------------------------------------

func TestPdClientSolicitMessageContents(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire() // → Soliciting

	if len(transport.sentPayloads) == 0 {
		t.Fatal("no Solicit sent")
	}
	payload := transport.sentPayloads[0]

	// Parse header.
	var hdr Header
	if err := hdr.UnmarshalBinary(payload); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if hdr.Type != MsgTypeSolicit {
		t.Errorf("expected Solicit, got %d", hdr.Type)
	}

	optionData := payload[HeaderSize:]

	// Client ID option should be present.
	clientIDOpt := FindOptionInBytes(optionData, OptionCodeClientID)
	if clientIDOpt == nil {
		t.Fatal("Client ID option not found")
	}

	// Elapsed Time option should be present.
	etOpt := FindOptionInBytes(optionData, OptionCodeElapsedTime)
	if etOpt == nil {
		t.Fatal("Elapsed Time option not found")
	}

	// Option Request option should contain SOL_MAX_RT.
	oroOpt := FindOptionInBytes(optionData, OptionCodeOptionReq)
	if oroOpt == nil {
		t.Fatal("Option Request option not found")
	}
	if len(oroOpt.Data) < 2 {
		t.Fatal("Option Request data too short")
	}
	requestedCode := OptionCode(binary.BigEndian.Uint16(oroOpt.Data[0:2]))
	if requestedCode != OptionCodeSolMaxRt {
		t.Errorf("expected SOL_MAX_RT in ORO, got %d", requestedCode)
	}

	// IA_PD option should be present.
	iapdOpt := FindOptionInBytes(optionData, OptionCodeIaPd)
	if iapdOpt == nil {
		t.Fatal("IA_PD option not found")
	}
}

// ---------------------------------------------------------------------------
// PD Client: Server DUID mismatch in Requesting → ignored
// ---------------------------------------------------------------------------

func TestPdClientServerDuidMismatchInRequestingIgnored(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire()

	tid := extractTransactionID(transport.lastPayload())

	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)
	pc.HandleReceive(buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts), testSrcAddr())

	reqTid := extractTransactionID(transport.lastPayload())

	// Reply with a different server DUID.
	differentServerDuid := []byte{0x00, 0x03, 0x00, 0x1B, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	var replyOpts []byte
	replyOpts = append(replyOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	replyMsg := buildReplyMsg(MsgTypeReply, reqTid, testExtAddr(), differentServerDuid, replyOpts)
	pc.HandleReceive(replyMsg, testSrcAddr())

	// Should still be Requesting.
	if pc.GetState() != PdStateRequesting {
		t.Errorf("expected Requesting (server DUID mismatch), got %d", pc.GetState())
	}
}

// ---------------------------------------------------------------------------
// PD Client: Callback on prefix removal
// ---------------------------------------------------------------------------

func TestPdClientCallbackOnPrefixRemoval(t *testing.T) {
	pc, transport, clock, callbacks := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire()

	tid := extractTransactionID(transport.lastPayload())

	// Get to ToRenew.
	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)
	pc.HandleReceive(buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts), testSrcAddr())

	reqTid := extractTransactionID(transport.lastPayload())
	var replyOpts []byte
	replyOpts = append(replyOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pc.HandleReceive(buildReplyMsg(MsgTypeReply, reqTid, testExtAddr(), testServerDuid(), replyOpts), testSrcAddr())

	commitCallbackIdx := len(*callbacks) - 1

	// Stop should cause a removal callback.
	pc.Stop()

	if len(*callbacks) <= commitCallbackIdx+1 {
		t.Fatal("expected removal callback")
	}

	// The removal callback should have zero lifetimes.
	removal := (*callbacks)[len(*callbacks)-1]
	if removal.PreferredLifetime != 0 || removal.ValidLifetime != 0 || removal.T1 != 0 || removal.T2 != 0 {
		t.Errorf("expected zero lifetimes in removal callback, got T1=%d T2=%d P=%d V=%d",
			removal.T1, removal.T2, removal.PreferredLifetime, removal.ValidLifetime)
	}
}

// ---------------------------------------------------------------------------
// PD Client: Double start is no-op
// ---------------------------------------------------------------------------

func TestPdClientDoubleStartIsNoop(t *testing.T) {
	pc, _, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire() // → Soliciting

	pc.Start() // should be no-op
	if pc.GetState() != PdStateSoliciting {
		t.Errorf("expected Soliciting, got %d", pc.GetState())
	}
}

// ---------------------------------------------------------------------------
// PD Client: Transport send failure → retry
// ---------------------------------------------------------------------------

func TestPdClientSendFailureRetries(t *testing.T) {
	clock := &mockPdClock{nowMs: 1000000, randVal: 0}
	pc, transport, _, _ := newTestPdClient(clock)

	// Start will enable listening and enter ToSolicit.
	pc.Start()

	// Set send error before going to Soliciting.
	transport.sendErr = errSendFailed
	clock.timers[0].fire() // → Soliciting, but sendMessage fails

	if pc.GetState() != PdStateSoliciting {
		t.Fatalf("expected Soliciting, got %d", pc.GetState())
	}

	// No payload should have been successfully sent.
	if len(transport.sentPayloads) != 0 {
		t.Errorf("expected 0 sent payloads on failure, got %d", len(transport.sentPayloads))
	}

	// Timer should have been reset with pdRetxDelayOnFailedTx.
	// Clear error and fire timer → should succeed.
	transport.sendErr = nil
	clock.timers[0].fire()

	if len(transport.sentPayloads) == 0 {
		t.Error("expected payload after retry")
	}
}

var errSendFailed = &testError{"send failed"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

// ---------------------------------------------------------------------------
// retxTracker tests
// ---------------------------------------------------------------------------

func TestRetxTrackerBasic(t *testing.T) {
	// randVal must be non-zero so generateTransactionID produces a TID
	// different from the zero-initialized old value (avoiding an infinite loop).
	clock := &mockPdClock{nowMs: 5000, randVal: 1}
	r := &retxTracker{clock: clock}
	r.start(1000, 30000, 10, nil)

	if r.count != 0 {
		t.Errorf("expected count=0, got %d", r.count)
	}
	if r.isExhausted() {
		t.Error("should not be exhausted at start")
	}

	// Get the first timeout.
	d := r.nextTimeout()
	if d == 0 {
		t.Error("expected non-zero timeout")
	}
	if r.count != 1 {
		t.Errorf("expected count=1 after first nextTimeout, got %d", r.count)
	}

	// Elapsed time after advancing the clock.
	clock.nowMs = 5500
	hundredths := r.elapsedTimeHundredths()
	if hundredths != 50 { // 500ms = 50 hundredths
		t.Errorf("expected 50 hundredths, got %d", hundredths)
	}
}

func TestRetxTrackerExhaustedByCount(t *testing.T) {
	clock := &mockPdClock{nowMs: 1000, randVal: 1}
	r := &retxTracker{clock: clock}
	r.start(100, 1000, 3, nil)

	for i := 0; i < 3; i++ {
		r.nextTimeout()
	}

	if !r.isExhausted() {
		t.Error("should be exhausted after maxCount attempts")
	}
}

func TestRetxTrackerExhaustedByEndTime(t *testing.T) {
	clock := &mockPdClock{nowMs: 1000, randVal: 1}
	r := &retxTracker{clock: clock}
	endTime := int64(3000)
	r.start(500, 5000, 0, &endTime)

	clock.nowMs = 3001
	if !r.isExhausted() {
		t.Error("should be exhausted after endTime")
	}
}

func TestRetxTrackerFirstAttempt(t *testing.T) {
	clock := &mockPdClock{nowMs: 1000, randVal: 1}
	r := &retxTracker{clock: clock}
	r.start(1000, 10000, 0, nil)

	// Before any nextTimeout, count is 0 → isFirstAttempt true.
	if !r.isFirstAttempt() {
		t.Error("expected first attempt before any nextTimeout")
	}

	r.nextTimeout() // count becomes 1
	if !r.isFirstAttempt() {
		t.Error("expected first attempt at count=1")
	}

	r.nextTimeout() // count becomes 2
	if r.isFirstAttempt() {
		t.Error("expected not first attempt at count=2")
	}
}

// ---------------------------------------------------------------------------
// pdPrefix tests
// ---------------------------------------------------------------------------

func TestPdPrefixIsValidAndClear(t *testing.T) {
	p := &pdPrefix{}
	if p.isValid() {
		t.Error("empty prefix should not be valid")
	}

	p.PrefixLength = 48
	if !p.isValid() {
		t.Error("prefix with length should be valid")
	}

	p.clear()
	if p.isValid() {
		t.Error("cleared prefix should not be valid")
	}
}

func TestPdPrefixMatches(t *testing.T) {
	p1 := &pdPrefix{}
	p1.Prefix = testPrefix48()
	p1.PrefixLength = 48

	p2 := &pdPrefix{}
	p2.Prefix = testPrefix48()
	p2.PrefixLength = 48

	if !p1.matches(p2) {
		t.Error("identical prefixes should match")
	}

	p2.PrefixLength = 64
	if p1.matches(p2) {
		t.Error("different prefix lengths should not match")
	}
}

func TestPdPrefixTimeCalculations(t *testing.T) {
	p := &pdPrefix{}
	p.UpdateTimeMs = 10000
	p.T1 = 300
	p.T2 = 600
	p.PreferredLifetime = 1800

	if p.determineT1TimeMs() != 10000+300*1000 {
		t.Errorf("T1 time: got %d, want %d", p.determineT1TimeMs(), 10000+300000)
	}
	if p.determineT2TimeMs() != 10000+600*1000 {
		t.Errorf("T2 time: got %d, want %d", p.determineT2TimeMs(), 10000+600000)
	}
	if p.determinePreferredTimeMs() != 10000+1800*1000 {
		t.Errorf("preferred time: got %d, want %d", p.determinePreferredTimeMs(), 10000+1800000)
	}
}

// ---------------------------------------------------------------------------
// Helper tests
// ---------------------------------------------------------------------------

func TestPrefixLessThan(t *testing.T) {
	a := [16]byte{0x20, 0x01, 0x0d, 0xb8}
	b := [16]byte{0x20, 0x01, 0x0d, 0xb9}
	if !prefixLessThan(a, b) {
		t.Error("a should be less than b")
	}
	if prefixLessThan(b, a) {
		t.Error("b should not be less than a")
	}
	if prefixLessThan(a, a) {
		t.Error("a should not be less than itself")
	}
}

func TestClampUint32(t *testing.T) {
	if clampUint32(5, 1, 10) != 5 {
		t.Error("value in range should be unchanged")
	}
	if clampUint32(0, 1, 10) != 1 {
		t.Error("below min should be clamped to min")
	}
	if clampUint32(15, 1, 10) != 10 {
		t.Error("above max should be clamped to max")
	}
}

func TestTidyPrefix(t *testing.T) {
	// A /48 prefix with some bits set in bytes 6-7.
	prefix := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0xAB, 0xCD, 0xFF, 0xFF}
	tidyPrefix(&prefix, 48, 64)
	// Bytes 6-7 should be zeroed (bits 48-63).
	if prefix[6] != 0 || prefix[7] != 0 {
		t.Errorf("expected bytes 6-7 zeroed, got %x %x", prefix[6], prefix[7])
	}
	// Bytes 0-5 should be unchanged.
	if prefix[0] != 0x20 || prefix[4] != 0xAB || prefix[5] != 0xCD {
		t.Error("prefix bytes 0-5 should be unchanged")
	}
}

// ---------------------------------------------------------------------------
// PD Client: IAID mismatch in IA_PD
// ---------------------------------------------------------------------------

func TestPdClientIaidMismatchSkipped(t *testing.T) {
	pc, transport, clock, _ := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire()

	tid := extractTransactionID(transport.lastPayload())

	// IA_PD with IAID=1 (expected is 0).
	prefix := testPrefix48()
	var opts []byte
	opts = append(opts, buildIaPdOption(1, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	opts = AppendOption(opts, OptionCodePreference, prefData)

	msg := buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), opts)
	pc.HandleReceive(msg, testSrcAddr())

	if pc.GetState() != PdStateSoliciting {
		t.Errorf("expected Soliciting (IAID mismatch), got %d", pc.GetState())
	}
}

// ---------------------------------------------------------------------------
// PD Client: Multiple prefixes, selects numerically smaller
// ---------------------------------------------------------------------------

func TestPdClientSelectsSmallerPrefix(t *testing.T) {
	pc, transport, clock, callbacks := newTestPdClient(nil)
	pc.Start()
	clock.timers[0].fire()

	tid := extractTransactionID(transport.lastPayload())

	// Build IA_PD with two prefixes: one bigger, one smaller.
	bigPrefix := [16]byte{0x20, 0x02, 0x0d, 0xb8, 0, 0, 0, 0}
	smallPrefix := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0}

	iap1 := IaPrefix{PreferredLifetime: 1800, ValidLifetime: 3600, PrefixLength: 48, Prefix: bigPrefix}
	iap2 := IaPrefix{PreferredLifetime: 1800, ValidLifetime: 3600, PrefixLength: 48, Prefix: smallPrefix}
	subOpts := AppendIaPrefixOption(nil, &iap1)
	subOpts = AppendIaPrefixOption(subOpts, &iap2)

	iapd := IaPd{IAID: 0, SubOptions: subOpts}
	var opts []byte
	opts = AppendIaPdOption(opts, &iapd)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	opts = AppendOption(opts, OptionCodePreference, prefData)

	msg := buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), opts)
	pc.HandleReceive(msg, testSrcAddr())

	if pc.GetState() != PdStateRequesting {
		t.Fatalf("expected Requesting, got %d", pc.GetState())
	}

	reqTid := extractTransactionID(transport.lastPayload())

	// Reply with the same two prefixes.
	var replyOpts []byte
	replyOpts = AppendIaPdOption(replyOpts, &iapd)
	pc.HandleReceive(buildReplyMsg(MsgTypeReply, reqTid, testExtAddr(), testServerDuid(), replyOpts), testSrcAddr())

	if len(*callbacks) == 0 {
		t.Fatal("expected callback")
	}
	dp := (*callbacks)[len(*callbacks)-1]

	// Should have selected the numerically smaller prefix (0x2001...).
	if dp.Prefix != smallPrefix {
		t.Errorf("expected smaller prefix, got %x", dp.Prefix)
	}
}

// ---------------------------------------------------------------------------
// PD Client: Renewing reply with matching prefix updates lifetimes
// ---------------------------------------------------------------------------

func TestPdClientRenewingReplyUpdatesLifetimes(t *testing.T) {
	clock := &mockPdClock{nowMs: 1000000, randVal: 0}
	pc, transport, _, callbacks := newTestPdClient(clock)
	pc.Start()
	clock.timers[0].fire()

	tid := extractTransactionID(transport.lastPayload())

	prefix := testPrefix48()
	var advOpts []byte
	advOpts = append(advOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pref := Preference{Value: 255}
	prefData, _ := pref.MarshalBinary()
	advOpts = AppendOption(advOpts, OptionCodePreference, prefData)
	pc.HandleReceive(buildReplyMsg(MsgTypeAdvertise, tid, testExtAddr(), testServerDuid(), advOpts), testSrcAddr())

	reqTid := extractTransactionID(transport.lastPayload())
	var replyOpts []byte
	replyOpts = append(replyOpts, buildIaPdOption(0, 0, 0, 1800, 3600, 48, prefix)...)
	pc.HandleReceive(buildReplyMsg(MsgTypeReply, reqTid, testExtAddr(), testServerDuid(), replyOpts), testSrcAddr())

	// Enter Renewing.
	clock.timers[0].fire()
	renewTid := extractTransactionID(transport.lastPayload())

	// Reply to Renew with updated lifetimes.
	clock.nowMs += 100000
	var renewReplyOpts []byte
	renewReplyOpts = append(renewReplyOpts, buildIaPdOption(0, 0, 0, 2400, 4800, 48, prefix)...)
	pc.HandleReceive(buildReplyMsg(MsgTypeReply, renewTid, testExtAddr(), testServerDuid(), renewReplyOpts), testSrcAddr())

	if pc.GetState() != PdStateToRenew {
		t.Errorf("expected ToRenew, got %d", pc.GetState())
	}

	// Last callback should have updated lifetimes.
	dp := (*callbacks)[len(*callbacks)-1]
	// PreferredLifetime is clamped by adjustLifetimesT1AndT2.
	// 2400 < pdMaxPreferredLifetime (14400), so not clamped.
	if dp.PreferredLifetime != 2400 {
		t.Errorf("expected preferred=2400, got %d", dp.PreferredLifetime)
	}
}
