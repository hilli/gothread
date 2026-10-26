// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package sntp

import (
	"testing"
	"time"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Header tests
// ---------------------------------------------------------------------------

func TestHeaderInit(t *testing.T) {
	var h Header
	h.Init()

	if h.GetVersion() != 4 {
		t.Errorf("expected version 4, got %d", h.GetVersion())
	}
	if h.GetMode() != ModeClient {
		t.Errorf("expected mode client (%d), got %d", ModeClient, h.GetMode())
	}
	if h.GetLeapIndicator() != 0 {
		t.Errorf("expected leap indicator 0, got %d", h.GetLeapIndicator())
	}
	if h.GetStratum() != 0 {
		t.Errorf("expected stratum 0, got %d", h.GetStratum())
	}

	// Expected flags byte: version=4 shifted left 3, mode=3 shifted left 0.
	// 4 << 3 | 3 << 0 = 32 | 3 = 35 = 0x23.
	expectedFlags := uint8(0x23)
	if h.GetFlags() != expectedFlags {
		t.Errorf("expected flags 0x%02x, got 0x%02x", expectedFlags, h.GetFlags())
	}
}

func TestHeaderScalarFields(t *testing.T) {
	var h Header
	h.Init()

	h.SetStratum(2)
	if h.GetStratum() != 2 {
		t.Errorf("expected stratum 2, got %d", h.GetStratum())
	}

	h.SetPoll(6)
	if h.GetPoll() != 6 {
		t.Errorf("expected poll 6, got %d", h.GetPoll())
	}

	h.SetPrecision(0xEC)
	if h.GetPrecision() != 0xEC {
		t.Errorf("expected precision 0xEC, got 0x%02x", h.GetPrecision())
	}
}

func TestHeaderRootDelay(t *testing.T) {
	var h Header
	h.SetRootDelay(0x01020304)
	if h.GetRootDelay() != 0x01020304 {
		t.Errorf("expected root delay 0x01020304, got 0x%08x", h.GetRootDelay())
	}
}

func TestHeaderRootDispersion(t *testing.T) {
	var h Header
	h.SetRootDispersion(0xAABBCCDD)
	if h.GetRootDispersion() != 0xAABBCCDD {
		t.Errorf("expected root dispersion 0xAABBCCDD, got 0x%08x", h.GetRootDispersion())
	}
}

func TestHeaderReferenceID(t *testing.T) {
	var h Header
	h.SetReferenceID(0xDEADBEEF)
	if h.GetReferenceID() != 0xDEADBEEF {
		t.Errorf("expected reference ID 0xDEADBEEF, got 0x%08x", h.GetReferenceID())
	}
}

func TestHeaderKissCode(t *testing.T) {
	var h Header
	// Set reference ID to ASCII "RATE" = 0x52415445.
	h.SetReferenceID(0x52415445)
	code := h.GetKissCode()
	if code != "RATE" {
		t.Errorf("expected kiss code \"RATE\", got %q", code)
	}
}

func TestHeaderReferenceTimestamp(t *testing.T) {
	var h Header
	h.SetReferenceTimestampSeconds(0x12345678)
	h.SetReferenceTimestampFraction(0xABCDEF01)

	if h.GetReferenceTimestampSeconds() != 0x12345678 {
		t.Errorf("ref ts seconds: expected 0x12345678, got 0x%08x", h.GetReferenceTimestampSeconds())
	}
	if h.GetReferenceTimestampFraction() != 0xABCDEF01 {
		t.Errorf("ref ts fraction: expected 0xABCDEF01, got 0x%08x", h.GetReferenceTimestampFraction())
	}
}

func TestHeaderOriginateTimestamp(t *testing.T) {
	var h Header
	h.SetOriginateTimestampSeconds(0x11111111)
	h.SetOriginateTimestampFraction(0x22222222)

	if h.GetOriginateTimestampSeconds() != 0x11111111 {
		t.Errorf("originate ts seconds: expected 0x11111111, got 0x%08x", h.GetOriginateTimestampSeconds())
	}
	if h.GetOriginateTimestampFraction() != 0x22222222 {
		t.Errorf("originate ts fraction: expected 0x22222222, got 0x%08x", h.GetOriginateTimestampFraction())
	}
}

func TestHeaderReceiveTimestamp(t *testing.T) {
	var h Header
	h.SetReceiveTimestampSeconds(0x33333333)
	h.SetReceiveTimestampFraction(0x44444444)

	if h.GetReceiveTimestampSeconds() != 0x33333333 {
		t.Errorf("receive ts seconds: expected 0x33333333, got 0x%08x", h.GetReceiveTimestampSeconds())
	}
	if h.GetReceiveTimestampFraction() != 0x44444444 {
		t.Errorf("receive ts fraction: expected 0x44444444, got 0x%08x", h.GetReceiveTimestampFraction())
	}
}

func TestHeaderTransmitTimestamp(t *testing.T) {
	var h Header
	h.SetTransmitTimestampSeconds(0x55555555)
	h.SetTransmitTimestampFraction(0x66666666)

	if h.GetTransmitTimestampSeconds() != 0x55555555 {
		t.Errorf("transmit ts seconds: expected 0x55555555, got 0x%08x", h.GetTransmitTimestampSeconds())
	}
	if h.GetTransmitTimestampFraction() != 0x66666666 {
		t.Errorf("transmit ts fraction: expected 0x66666666, got 0x%08x", h.GetTransmitTimestampFraction())
	}
}

func TestHeaderMarshalUnmarshal(t *testing.T) {
	var h Header
	h.Init()
	h.SetStratum(3)
	h.SetPoll(4)
	h.SetPrecision(0xE8)
	h.SetRootDelay(0x00010000)
	h.SetRootDispersion(0x00020000)
	h.SetReferenceID(0x4E495354) // "NIST"
	h.SetTransmitTimestampSeconds(0xDEADBEEF)
	h.SetTransmitTimestampFraction(0xCAFEBABE)

	data := h.Marshal()
	if len(data) != HeaderSize {
		t.Fatalf("marshal length: expected %d, got %d", HeaderSize, len(data))
	}

	var h2 Header
	if err := h2.Unmarshal(data); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if h != h2 {
		t.Error("unmarshalled header does not match original")
	}
}

func TestHeaderUnmarshalTooShort(t *testing.T) {
	var h Header
	err := h.Unmarshal(make([]byte, 10))
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

func TestHeaderModeValues(t *testing.T) {
	// Verify the mode constants.
	if ModeClient != 3 {
		t.Errorf("ModeClient = %d, want 3", ModeClient)
	}
	if ModeServer != 4 {
		t.Errorf("ModeServer = %d, want 4", ModeServer)
	}
}

func TestHeaderSetFlags(t *testing.T) {
	var h Header
	// Set to server mode with version 4, leap indicator 0.
	// flags = (0 << 6) | (4 << 3) | (4 << 0) = 0 | 32 | 4 = 36 = 0x24
	h.SetFlags(0x24)
	if h.GetMode() != ModeServer {
		t.Errorf("expected mode server (%d), got %d", ModeServer, h.GetMode())
	}
	if h.GetVersion() != 4 {
		t.Errorf("expected version 4, got %d", h.GetVersion())
	}
}

// ---------------------------------------------------------------------------
// Constants tests
// ---------------------------------------------------------------------------

func TestConstants(t *testing.T) {
	if NtpPort != 123 {
		t.Errorf("NtpPort = %d, want 123", NtpPort)
	}
	if ServerPort != 123 {
		t.Errorf("ServerPort = %d, want 123", ServerPort)
	}
	if HeaderSize != 48 {
		t.Errorf("HeaderSize = %d, want 48", HeaderSize)
	}
	if KissCodeLength != 4 {
		t.Errorf("KissCodeLength = %d, want 4", KissCodeLength)
	}
	if ntpEpochOffset != 2208988800 {
		t.Errorf("ntpEpochOffset = %d, want 2208988800", ntpEpochOffset)
	}
}

// ---------------------------------------------------------------------------
// Client tests — helpers
// ---------------------------------------------------------------------------

// fakeClock returns a fixed-time now function and a way to advance it.
type fakeClock struct {
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock {
	return &fakeClock{now: t}
}

func (fc *fakeClock) Now() time.Time {
	return fc.now
}

func (fc *fakeClock) Advance(d time.Duration) {
	fc.now = fc.now.Add(d)
}

// capturedSend records sent messages.
type capturedSend struct {
	payload     []byte
	messageInfo *ip6.MessageInfo
}

func makeSendCapture() (SendFunc, *[]capturedSend) {
	var sends []capturedSend
	fn := func(payload []byte, messageInfo *ip6.MessageInfo) error {
		cp := make([]byte, len(payload))
		copy(cp, payload)
		sends = append(sends, capturedSend{payload: cp, messageInfo: messageInfo})
		return nil
	}
	return fn, &sends
}

func makeSendError(err error) SendFunc {
	return func(_ []byte, _ *ip6.MessageInfo) error { return err }
}

// buildResponse builds a server response header that matches a request.
func buildResponse(request []byte, ntpTimeSec, ntpTimeFrac uint32) []byte {
	var req Header
	_ = req.Unmarshal(request)

	var resp Header
	// Server mode, version 4.
	resp.SetFlags(ntpVersion<<versionOffset | uint8(ModeServer)<<modeOffset)
	resp.SetStratum(2)
	// Copy the transmit timestamp from the request as the originate timestamp.
	resp.SetOriginateTimestampSeconds(req.GetTransmitTimestampSeconds())
	resp.SetOriginateTimestampFraction(req.GetTransmitTimestampFraction())
	resp.SetTransmitTimestampSeconds(ntpTimeSec)
	resp.SetTransmitTimestampFraction(ntpTimeFrac)
	resp.SetReceiveTimestampSeconds(ntpTimeSec)
	resp.SetReceiveTimestampFraction(ntpTimeFrac)

	return resp.Marshal()
}

// ---------------------------------------------------------------------------
// Client.SendQuery tests
// ---------------------------------------------------------------------------

func TestClientSendQuery(t *testing.T) {
	sendFn, sends := makeSendCapture()
	clock := newFakeClock(time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC))

	client := NewClient(sendFn)
	client.nowFunc = clock.Now

	dest := ip6.SockAddr{
		Address: ip6.Address{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		Port:    NtpPort,
	}

	handlerCalled := false
	handler := func(unixTime uint64, err error) {
		handlerCalled = true
	}

	err := client.SendQuery(dest, handler)
	if err != nil {
		t.Fatalf("SendQuery failed: %v", err)
	}

	if len(*sends) != 1 {
		t.Fatalf("expected 1 send, got %d", len(*sends))
	}

	sent := (*sends)[0]
	if len(sent.payload) != HeaderSize {
		t.Errorf("sent payload length: expected %d, got %d", HeaderSize, len(sent.payload))
	}

	// Verify the sent message is a valid NTP client request.
	var sentHeader Header
	_ = sentHeader.Unmarshal(sent.payload)
	if sentHeader.GetMode() != ModeClient {
		t.Errorf("sent mode: expected %d, got %d", ModeClient, sentHeader.GetMode())
	}
	if sentHeader.GetVersion() != 4 {
		t.Errorf("sent version: expected 4, got %d", sentHeader.GetVersion())
	}
	if sentHeader.GetTransmitTimestampSeconds() == 0 {
		t.Error("transmit timestamp should not be zero")
	}

	// Verify destination info.
	if sent.messageInfo.PeerAddr != dest.Address {
		t.Errorf("destination address mismatch")
	}
	if sent.messageInfo.PeerPort != NtpPort {
		t.Errorf("destination port: expected %d, got %d", NtpPort, sent.messageInfo.PeerPort)
	}

	// Query should be pending.
	if client.GetPendingQueryCount() != 1 {
		t.Errorf("expected 1 pending query, got %d", client.GetPendingQueryCount())
	}

	if handlerCalled {
		t.Error("handler should not be called yet")
	}
}

func TestClientSendQueryNilSendFunc(t *testing.T) {
	client := NewClient(nil)

	err := client.SendQuery(ip6.SockAddr{Port: NtpPort}, func(uint64, error) {})
	if err != errors.ErrInvalidArgs {
		t.Errorf("expected ErrInvalidArgs, got %v", err)
	}
}

func TestClientSendQueryNilHandler(t *testing.T) {
	sendFn, _ := makeSendCapture()
	client := NewClient(sendFn)

	err := client.SendQuery(ip6.SockAddr{Port: NtpPort}, nil)
	if err != errors.ErrInvalidArgs {
		t.Errorf("expected ErrInvalidArgs, got %v", err)
	}
}

func TestClientSendQuerySendError(t *testing.T) {
	client := NewClient(makeSendError(errors.ErrNoBufs))

	err := client.SendQuery(ip6.SockAddr{Port: NtpPort}, func(uint64, error) {})
	if err != errors.ErrNoBufs {
		t.Errorf("expected ErrNoBufs, got %v", err)
	}

	// No query should be pending after send failure.
	if client.GetPendingQueryCount() != 0 {
		t.Errorf("expected 0 pending queries, got %d", client.GetPendingQueryCount())
	}
}

// ---------------------------------------------------------------------------
// Client.HandleResponse tests
// ---------------------------------------------------------------------------

func TestClientHandleResponse(t *testing.T) {
	sendFn, sends := makeSendCapture()
	// Unix time 1705320000 = Jan 15, 2024 12:00:00 UTC
	clock := newFakeClock(time.Unix(1705320000, 0))

	client := NewClient(sendFn)
	client.nowFunc = clock.Now

	dest := ip6.SockAddr{
		Address: ip6.Address{0x20, 0x01, 0x0d, 0xb8},
		Port:    NtpPort,
	}

	var gotTime uint64
	var gotErr error
	handler := func(unixTime uint64, err error) {
		gotTime = unixTime
		gotErr = err
	}

	_ = client.SendQuery(dest, handler)

	// Build a response with a known NTP timestamp.
	// NTP time for Jan 15, 2024 12:00:00 UTC = Unix + offset
	// = 1705320000 + 2208988800 = 3914308800
	ntpTime := uint32(1705320000 + ntpEpochOffset)
	responsePayload := buildResponse((*sends)[0].payload, ntpTime, 0x80000000)

	err := client.HandleResponse(responsePayload, &ip6.MessageInfo{})
	if err != nil {
		t.Fatalf("HandleResponse failed: %v", err)
	}

	if gotErr != nil {
		t.Errorf("handler received error: %v", gotErr)
	}
	if gotTime != 1705320000 {
		t.Errorf("expected unix time 1705320000, got %d", gotTime)
	}
	if client.GetPendingQueryCount() != 0 {
		t.Errorf("expected 0 pending queries, got %d", client.GetPendingQueryCount())
	}
}

func TestClientHandleResponseNoMatch(t *testing.T) {
	sendFn, _ := makeSendCapture()
	client := NewClient(sendFn)

	// Fabricate a response with no matching query.
	var resp Header
	resp.SetFlags(ntpVersion<<versionOffset | uint8(ModeServer)<<modeOffset)
	resp.SetStratum(2)
	resp.SetOriginateTimestampSeconds(0x99999999)
	resp.SetTransmitTimestampSeconds(0xAAAAAAAA)
	resp.SetTransmitTimestampFraction(1)

	err := client.HandleResponse(resp.Marshal(), &ip6.MessageInfo{})
	if err != errors.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestClientHandleResponseTooShort(t *testing.T) {
	client := NewClient(func(_ []byte, _ *ip6.MessageInfo) error { return nil })

	err := client.HandleResponse([]byte{1, 2, 3}, &ip6.MessageInfo{})
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

func TestClientHandleResponseWrongMode(t *testing.T) {
	sendFn, sends := makeSendCapture()
	clock := newFakeClock(time.Unix(1705320000, 0))

	client := NewClient(sendFn)
	client.nowFunc = clock.Now

	var gotErr error
	handler := func(_ uint64, err error) { gotErr = err }

	_ = client.SendQuery(ip6.SockAddr{Port: NtpPort}, handler)

	// Build a response with client mode instead of server mode.
	var req Header
	_ = req.Unmarshal((*sends)[0].payload)

	var resp Header
	resp.SetFlags(ntpVersion<<versionOffset | uint8(ModeClient)<<modeOffset) // wrong mode
	resp.SetStratum(2)
	resp.SetOriginateTimestampSeconds(req.GetTransmitTimestampSeconds())
	resp.SetTransmitTimestampSeconds(0xAABBCCDD)
	resp.SetTransmitTimestampFraction(1)

	err := client.HandleResponse(resp.Marshal(), &ip6.MessageInfo{})
	if err != errors.ErrFailed {
		t.Errorf("expected ErrFailed, got %v", err)
	}
	if gotErr != errors.ErrFailed {
		t.Errorf("handler should have received ErrFailed, got %v", gotErr)
	}
	if client.GetPendingQueryCount() != 0 {
		t.Errorf("query should have been removed")
	}
}

func TestClientHandleResponseKissOfDeath(t *testing.T) {
	sendFn, sends := makeSendCapture()
	clock := newFakeClock(time.Unix(1705320000, 0))

	client := NewClient(sendFn)
	client.nowFunc = clock.Now

	var gotErr error
	handler := func(_ uint64, err error) { gotErr = err }

	_ = client.SendQuery(ip6.SockAddr{Port: NtpPort}, handler)

	// Build a kiss-o'-death response (stratum = 0).
	var req Header
	_ = req.Unmarshal((*sends)[0].payload)

	var resp Header
	resp.SetFlags(ntpVersion<<versionOffset | uint8(ModeServer)<<modeOffset)
	resp.SetStratum(0)              // Kiss-o'-death
	resp.SetReferenceID(0x52415445) // "RATE"
	resp.SetOriginateTimestampSeconds(req.GetTransmitTimestampSeconds())
	resp.SetTransmitTimestampSeconds(0xAABBCCDD)
	resp.SetTransmitTimestampFraction(1)

	err := client.HandleResponse(resp.Marshal(), &ip6.MessageInfo{})
	if err != errors.ErrBusy {
		t.Errorf("expected ErrBusy, got %v", err)
	}
	if gotErr != errors.ErrBusy {
		t.Errorf("handler should have received ErrBusy, got %v", gotErr)
	}
}

func TestClientHandleResponseZeroTransmitTimestamp(t *testing.T) {
	sendFn, sends := makeSendCapture()
	clock := newFakeClock(time.Unix(1705320000, 0))

	client := NewClient(sendFn)
	client.nowFunc = clock.Now

	var gotErr error
	handler := func(_ uint64, err error) { gotErr = err }

	_ = client.SendQuery(ip6.SockAddr{Port: NtpPort}, handler)

	var req Header
	_ = req.Unmarshal((*sends)[0].payload)

	var resp Header
	resp.SetFlags(ntpVersion<<versionOffset | uint8(ModeServer)<<modeOffset)
	resp.SetStratum(2)
	resp.SetOriginateTimestampSeconds(req.GetTransmitTimestampSeconds())
	// Zero transmit timestamp — should fail.
	resp.SetTransmitTimestampSeconds(0)
	resp.SetTransmitTimestampFraction(0)

	err := client.HandleResponse(resp.Marshal(), &ip6.MessageInfo{})
	if err != errors.ErrFailed {
		t.Errorf("expected ErrFailed, got %v", err)
	}
	if gotErr != errors.ErrFailed {
		t.Errorf("handler should have received ErrFailed, got %v", gotErr)
	}
}

// ---------------------------------------------------------------------------
// Client.HandleTimer tests
// ---------------------------------------------------------------------------

func TestClientHandleTimerRetransmission(t *testing.T) {
	sendFn, sends := makeSendCapture()
	clock := newFakeClock(time.Unix(1705320000, 0))

	client := NewClient(sendFn)
	client.nowFunc = clock.Now

	_ = client.SendQuery(ip6.SockAddr{Port: NtpPort}, func(uint64, error) {},
		WithMaxRetries(2), WithTimeout(3*time.Second))

	if len(*sends) != 1 {
		t.Fatalf("expected 1 send after query, got %d", len(*sends))
	}

	// Advance past the first timeout.
	clock.Advance(4 * time.Second)
	d := client.HandleTimer()

	// Should have retransmitted.
	if len(*sends) != 2 {
		t.Fatalf("expected 2 sends after first timer, got %d", len(*sends))
	}
	// Query should still be pending.
	if client.GetPendingQueryCount() != 1 {
		t.Errorf("expected 1 pending query, got %d", client.GetPendingQueryCount())
	}
	// Returned duration should be > 0 (next deadline).
	if d <= 0 {
		t.Errorf("expected positive duration, got %v", d)
	}
}

func TestClientHandleTimerTimeout(t *testing.T) {
	sendFn, _ := makeSendCapture()
	clock := newFakeClock(time.Unix(1705320000, 0))

	client := NewClient(sendFn)
	client.nowFunc = clock.Now

	var gotErr error
	handler := func(_ uint64, err error) { gotErr = err }

	_ = client.SendQuery(ip6.SockAddr{Port: NtpPort}, handler,
		WithMaxRetries(1), WithTimeout(2*time.Second))

	// Advance past first timeout — triggers retransmission.
	clock.Advance(3 * time.Second)
	client.HandleTimer()

	// Advance past second timeout — should timeout (max retries = 1).
	clock.Advance(3 * time.Second)
	client.HandleTimer()

	if gotErr != errors.ErrResponseTimeout {
		t.Errorf("expected ErrResponseTimeout, got %v", gotErr)
	}
	if client.GetPendingQueryCount() != 0 {
		t.Errorf("expected 0 pending queries, got %d", client.GetPendingQueryCount())
	}
}

func TestClientHandleTimerNoQueries(t *testing.T) {
	client := NewClient(func(_ []byte, _ *ip6.MessageInfo) error { return nil })
	d := client.HandleTimer()
	if d != 0 {
		t.Errorf("expected duration 0 for no queries, got %v", d)
	}
}

func TestClientHandleTimerNotYetDue(t *testing.T) {
	sendFn, sends := makeSendCapture()
	clock := newFakeClock(time.Unix(1705320000, 0))

	client := NewClient(sendFn)
	client.nowFunc = clock.Now

	_ = client.SendQuery(ip6.SockAddr{Port: NtpPort}, func(uint64, error) {},
		WithTimeout(10*time.Second))

	// Advance only 1 second — not yet due.
	clock.Advance(1 * time.Second)
	d := client.HandleTimer()

	// Should not have retransmitted.
	if len(*sends) != 1 {
		t.Errorf("expected 1 send (no retransmission), got %d", len(*sends))
	}
	if d <= 0 {
		t.Errorf("expected positive duration, got %v", d)
	}
}

// ---------------------------------------------------------------------------
// Client.Stop tests
// ---------------------------------------------------------------------------

func TestClientStop(t *testing.T) {
	sendFn, _ := makeSendCapture()
	clock := newFakeClock(time.Unix(1705320000, 0))

	client := NewClient(sendFn)
	client.nowFunc = clock.Now

	var errs []error
	for i := 0; i < 3; i++ {
		_ = client.SendQuery(ip6.SockAddr{Port: NtpPort},
			func(_ uint64, err error) { errs = append(errs, err) })
	}

	if client.GetPendingQueryCount() != 3 {
		t.Fatalf("expected 3 pending queries, got %d", client.GetPendingQueryCount())
	}

	client.Stop()

	if client.GetPendingQueryCount() != 0 {
		t.Errorf("expected 0 pending queries after stop, got %d", client.GetPendingQueryCount())
	}
	if len(errs) != 3 {
		t.Fatalf("expected 3 handler calls, got %d", len(errs))
	}
	for i, err := range errs {
		if err != errors.ErrAbort {
			t.Errorf("handler %d: expected ErrAbort, got %v", i, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Client functional options tests
// ---------------------------------------------------------------------------

func TestClientWithOptions(t *testing.T) {
	sendFn, _ := makeSendCapture()
	clock := newFakeClock(time.Unix(1705320000, 0))

	client := NewClient(sendFn)
	client.nowFunc = clock.Now

	_ = client.SendQuery(ip6.SockAddr{Port: NtpPort}, func(uint64, error) {},
		WithMaxRetries(10), WithTimeout(30*time.Second))

	// Verify the query uses the custom settings by checking that it does
	// not time out after the default period.
	clock.Advance(6 * time.Second) // > default 5s timeout
	client.HandleTimer()

	// Should still be pending (custom timeout is 30s).
	if client.GetPendingQueryCount() != 1 {
		t.Errorf("expected 1 pending query with custom timeout, got %d", client.GetPendingQueryCount())
	}
}

// ---------------------------------------------------------------------------
// NTP <-> Unix timestamp conversion tests
// ---------------------------------------------------------------------------

func TestNtpToUnixEra0(t *testing.T) {
	sendFn, sends := makeSendCapture()
	clock := newFakeClock(time.Unix(1705320000, 0))

	client := NewClient(sendFn)
	client.nowFunc = clock.Now
	client.SetUnixEra(0)

	var gotTime uint64
	_ = client.SendQuery(ip6.SockAddr{Port: NtpPort}, func(unixTime uint64, _ error) {
		gotTime = unixTime
	})

	// NTP timestamp for Unix 1705320000 = 1705320000 + 2208988800 = 3914308800
	ntpTime := uint32(1705320000 + ntpEpochOffset)
	resp := buildResponse((*sends)[0].payload, ntpTime, 1)

	_ = client.HandleResponse(resp, &ip6.MessageInfo{})

	if gotTime != 1705320000 {
		t.Errorf("expected 1705320000, got %d", gotTime)
	}
}

func TestNtpToUnixEra1(t *testing.T) {
	sendFn, sends := makeSendCapture()
	clock := newFakeClock(time.Unix(1705320000, 0))

	client := NewClient(sendFn)
	client.nowFunc = clock.Now
	client.SetUnixEra(1)

	if client.GetUnixEra() != 1 {
		t.Fatalf("expected era 1, got %d", client.GetUnixEra())
	}

	var gotTime uint64
	_ = client.SendQuery(ip6.SockAddr{Port: NtpPort}, func(unixTime uint64, _ error) {
		gotTime = unixTime
	})

	// In era 1, NTP timestamp wraps around. Simulate a small NTP value
	// (less than ntpEpochOffset), which means we're past 2036.
	// NTP seconds = 100 (a small value after wrap)
	ntpTime := uint32(100)
	resp := buildResponse((*sends)[0].payload, ntpTime, 1)

	_ = client.HandleResponse(resp, &ip6.MessageInfo{})

	// Expected: era * 2^32 + (ntpTime + 2^32 - ntpEpochOffset)
	// = 1 * 4294967296 + (100 + 4294967296 - 2208988800)
	// = 4294967296 + 2085978596 = 6380945892
	expected := uint64(1)*(1<<32) + uint64(100) + (1 << 32) - uint64(ntpEpochOffset)
	if gotTime != expected {
		t.Errorf("expected %d, got %d", expected, gotTime)
	}
}

// ---------------------------------------------------------------------------
// Multiple concurrent queries
// ---------------------------------------------------------------------------

func TestClientMultipleQueries(t *testing.T) {
	sendFn, sends := makeSendCapture()

	// Each query needs a distinct timestamp, so we advance the clock slightly.
	baseTime := time.Unix(1705320000, 0)
	clock := newFakeClock(baseTime)

	client := NewClient(sendFn)
	client.nowFunc = clock.Now

	results := make([]uint64, 3)
	for i := 0; i < 3; i++ {
		idx := i
		_ = client.SendQuery(ip6.SockAddr{Port: NtpPort}, func(unixTime uint64, _ error) {
			results[idx] = unixTime
		})
		clock.Advance(1 * time.Second) // ensure different transmit timestamps
	}

	if client.GetPendingQueryCount() != 3 {
		t.Fatalf("expected 3 pending queries, got %d", client.GetPendingQueryCount())
	}

	// Respond to them in reverse order.
	for i := 2; i >= 0; i-- {
		unixSec := uint64(1705320000 + i*1000)
		ntpSec := uint32(unixSec) + ntpEpochOffset
		resp := buildResponse((*sends)[i].payload, ntpSec, 1)
		err := client.HandleResponse(resp, &ip6.MessageInfo{})
		if err != nil {
			t.Fatalf("HandleResponse for query %d failed: %v", i, err)
		}
	}

	if client.GetPendingQueryCount() != 0 {
		t.Errorf("expected 0 pending queries, got %d", client.GetPendingQueryCount())
	}

	for i, r := range results {
		expected := uint64(1705320000 + i*1000)
		if r != expected {
			t.Errorf("result[%d] = %d, expected %d", i, r, expected)
		}
	}
}

// ---------------------------------------------------------------------------
// Header big-endian encoding verification
// ---------------------------------------------------------------------------

func TestHeaderBigEndianLayout(t *testing.T) {
	var h Header
	h.Init()

	// Set root delay to 0x01020304 and verify the wire bytes directly.
	h.SetRootDelay(0x01020304)
	if h[4] != 0x01 || h[5] != 0x02 || h[6] != 0x03 || h[7] != 0x04 {
		t.Errorf("root delay bytes: expected [01 02 03 04], got [%02x %02x %02x %02x]",
			h[4], h[5], h[6], h[7])
	}

	// Set transmit timestamp seconds to 0xDEADBEEF and verify wire order.
	h.SetTransmitTimestampSeconds(0xDEADBEEF)
	if h[40] != 0xDE || h[41] != 0xAD || h[42] != 0xBE || h[43] != 0xEF {
		t.Errorf("transmit ts bytes: expected [DE AD BE EF], got [%02x %02x %02x %02x]",
			h[40], h[41], h[42], h[43])
	}
}

// ---------------------------------------------------------------------------
// Response with response that arrives after retransmission
// ---------------------------------------------------------------------------

func TestClientResponseAfterRetransmit(t *testing.T) {
	sendFn, sends := makeSendCapture()
	clock := newFakeClock(time.Unix(1705320000, 0))

	client := NewClient(sendFn)
	client.nowFunc = clock.Now

	var gotTime uint64
	var gotErr error
	_ = client.SendQuery(ip6.SockAddr{Port: NtpPort}, func(unixTime uint64, err error) {
		gotTime = unixTime
		gotErr = err
	}, WithMaxRetries(3), WithTimeout(2*time.Second))

	// Trigger one retransmission.
	clock.Advance(3 * time.Second)
	client.HandleTimer()

	if len(*sends) != 2 {
		t.Fatalf("expected 2 sends, got %d", len(*sends))
	}

	// Now respond to the original request (both retransmissions have the
	// same transmit timestamp, so matching still works).
	ntpTime := uint32(1705320000 + ntpEpochOffset)
	resp := buildResponse((*sends)[0].payload, ntpTime, 1)
	err := client.HandleResponse(resp, &ip6.MessageInfo{})
	if err != nil {
		t.Fatalf("HandleResponse failed: %v", err)
	}

	if gotErr != nil {
		t.Errorf("expected no error, got %v", gotErr)
	}
	if gotTime != 1705320000 {
		t.Errorf("expected 1705320000, got %d", gotTime)
	}
}
