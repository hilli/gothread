// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package icmp6

import (
	"testing"

	"github.com/hilli/gothread/net/ip6"
)

func TestHeaderSize(t *testing.T) {
	if HeaderSize != 8 {
		t.Fatalf("expected HeaderSize == 8, got %d", HeaderSize)
	}
}

func TestHeaderTypeCode(t *testing.T) {
	var h Header

	h.SetType(TypeEchoRequest)
	if got := h.GetType(); got != TypeEchoRequest {
		t.Fatalf("expected type %d, got %d", TypeEchoRequest, got)
	}

	h.SetCode(CodeDstUnreachProhibited)
	if got := h.GetCode(); got != CodeDstUnreachProhibited {
		t.Fatalf("expected code %d, got %d", CodeDstUnreachProhibited, got)
	}

	// Set a different type and verify code is unchanged.
	h.SetType(TypeDstUnreach)
	if got := h.GetType(); got != TypeDstUnreach {
		t.Fatalf("expected type %d, got %d", TypeDstUnreach, got)
	}
	if got := h.GetCode(); got != CodeDstUnreachProhibited {
		t.Fatalf("expected code %d after type change, got %d", CodeDstUnreachProhibited, got)
	}
}

func TestHeaderIsError(t *testing.T) {
	tests := []struct {
		typ     Type
		isError bool
	}{
		{TypeDstUnreach, true},
		{TypePacketTooBig, true},
		{TypeTimeExceeded, true},
		{TypeParameterProblem, true},
		{TypeEchoRequest, false},
		{TypeEchoReply, false},
		{TypeRouterSolicit, false},
		{TypeRouterAdvert, false},
		{TypeNeighborSolicit, false},
		{TypeNeighborAdvert, false},
	}
	for _, tc := range tests {
		var h Header
		h.SetType(tc.typ)
		if got := h.IsError(); got != tc.isError {
			t.Errorf("type %d: IsError() = %v, want %v", tc.typ, got, tc.isError)
		}
	}
}

func TestHeaderChecksum(t *testing.T) {
	var h Header

	// Set a checksum and verify big-endian encoding.
	h.SetChecksum(0xABCD)
	if got := h.GetChecksum(); got != 0xABCD {
		t.Fatalf("expected checksum 0xABCD, got 0x%04X", got)
	}

	// Verify the raw bytes are big-endian.
	raw := h.MarshalBinary()
	if raw[ChecksumFieldOffset] != 0xAB || raw[ChecksumFieldOffset+1] != 0xCD {
		t.Fatalf("expected big-endian bytes [0xAB, 0xCD], got [0x%02X, 0x%02X]",
			raw[ChecksumFieldOffset], raw[ChecksumFieldOffset+1])
	}

	// Zero checksum.
	h.SetChecksum(0)
	if got := h.GetChecksum(); got != 0 {
		t.Fatalf("expected checksum 0, got 0x%04X", got)
	}
}

func TestHeaderIDSequence(t *testing.T) {
	var h Header

	h.SetID(0x1234)
	if got := h.GetID(); got != 0x1234 {
		t.Fatalf("expected ID 0x1234, got 0x%04X", got)
	}

	h.SetSequence(0x5678)
	if got := h.GetSequence(); got != 0x5678 {
		t.Fatalf("expected sequence 0x5678, got 0x%04X", got)
	}

	// Verify ID is still correct after setting sequence.
	if got := h.GetID(); got != 0x1234 {
		t.Fatalf("expected ID 0x1234 after SetSequence, got 0x%04X", got)
	}

	// Verify raw bytes are big-endian.
	raw := h.MarshalBinary()
	if raw[DataFieldOffset] != 0x12 || raw[DataFieldOffset+1] != 0x34 {
		t.Fatalf("expected ID bytes [0x12, 0x34], got [0x%02X, 0x%02X]",
			raw[DataFieldOffset], raw[DataFieldOffset+1])
	}
	if raw[DataFieldOffset+2] != 0x56 || raw[DataFieldOffset+3] != 0x78 {
		t.Fatalf("expected seq bytes [0x56, 0x78], got [0x%02X, 0x%02X]",
			raw[DataFieldOffset+2], raw[DataFieldOffset+3])
	}
}

func TestHeaderClear(t *testing.T) {
	var h Header
	h.SetType(TypeEchoRequest)
	h.SetCode(CodeDstUnreachProhibited)
	h.SetChecksum(0xFFFF)
	h.SetID(0x1234)
	h.SetSequence(0x5678)

	h.Clear()

	raw := h.MarshalBinary()
	for i, b := range raw {
		if b != 0 {
			t.Fatalf("after Clear(), byte %d = 0x%02X, want 0x00", i, b)
		}
	}
}

func TestHeaderMarshalUnmarshal(t *testing.T) {
	var h Header
	h.SetType(TypeEchoReply)
	h.SetCode(0)
	h.SetChecksum(0xBEEF)
	h.SetID(0x0042)
	h.SetSequence(0x0001)

	raw := h.MarshalBinary()
	if len(raw) != HeaderSize {
		t.Fatalf("MarshalBinary returned %d bytes, want %d", len(raw), HeaderSize)
	}

	var h2 Header
	if err := h2.UnmarshalBinary(raw); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if h2.GetType() != TypeEchoReply {
		t.Fatalf("round-trip type: got %d, want %d", h2.GetType(), TypeEchoReply)
	}
	if h2.GetChecksum() != 0xBEEF {
		t.Fatalf("round-trip checksum: got 0x%04X, want 0xBEEF", h2.GetChecksum())
	}
	if h2.GetID() != 0x0042 {
		t.Fatalf("round-trip ID: got 0x%04X, want 0x0042", h2.GetID())
	}
	if h2.GetSequence() != 0x0001 {
		t.Fatalf("round-trip sequence: got 0x%04X, want 0x0001", h2.GetSequence())
	}

	// Verify that modifying the returned slice does not affect the header.
	raw[0] = 0xFF
	if h.GetType() != TypeEchoReply {
		t.Fatalf("modifying MarshalBinary output affected original header")
	}
}

func TestHeaderUnmarshalTooShort(t *testing.T) {
	var h Header
	for length := 0; length < HeaderSize; length++ {
		buf := make([]byte, length)
		if err := h.UnmarshalBinary(buf); err == nil {
			t.Fatalf("UnmarshalBinary with %d bytes should fail, but returned nil", length)
		}
	}

	// Exactly HeaderSize should succeed.
	buf := make([]byte, HeaderSize)
	if err := h.UnmarshalBinary(buf); err != nil {
		t.Fatalf("UnmarshalBinary with %d bytes should succeed, got: %v", HeaderSize, err)
	}

	// Longer than HeaderSize should also succeed (extra bytes ignored).
	buf = make([]byte, HeaderSize+10)
	buf[0] = byte(TypePacketTooBig)
	if err := h.UnmarshalBinary(buf); err != nil {
		t.Fatalf("UnmarshalBinary with %d bytes should succeed, got: %v", len(buf), err)
	}
	if h.GetType() != TypePacketTooBig {
		t.Fatalf("expected type %d after unmarshal of longer buffer, got %d",
			TypePacketTooBig, h.GetType())
	}
}

func TestEchoMode(t *testing.T) {
	tests := []struct {
		mode EchoMode
		val  uint8
	}{
		{EchoModeDisabled, 0},
		{EchoModeUnicastOnly, 1},
		{EchoModeMulticastOnly, 2},
		{EchoModeAll, 3},
		{EchoModeRlocAlocOnly, 4},
	}
	for _, tc := range tests {
		if uint8(tc.mode) != tc.val {
			t.Errorf("EchoMode %d: expected value %d, got %d", tc.mode, tc.val, uint8(tc.mode))
		}
	}
}

func TestIcmpNew(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
	if m.GetEchoSequence() != 1 {
		t.Fatalf("initial echo sequence: got %d, want 1", m.GetEchoSequence())
	}
	if m.GetEchoMode() != EchoModeAll {
		t.Fatalf("initial echo mode: got %d, want %d", m.GetEchoMode(), EchoModeAll)
	}
}

func TestRegisterHandler(t *testing.T) {
	m := New()

	called := false
	h := NewHandler(func(_ *ip6.MessageInfo, _ *Header) {
		called = true
	})

	// First registration should succeed.
	if err := m.RegisterHandler(h); err != nil {
		t.Fatalf("first RegisterHandler failed: %v", err)
	}

	// Duplicate registration should return ErrAlready.
	if err := m.RegisterHandler(h); err == nil {
		t.Fatal("duplicate RegisterHandler should return error")
	}

	// A different handler should succeed.
	h2 := NewHandler(func(_ *ip6.MessageInfo, _ *Header) {})
	if err := m.RegisterHandler(h2); err != nil {
		t.Fatalf("second handler RegisterHandler failed: %v", err)
	}

	// Verify we suppressed the unused variable warning.
	_ = called
}

func TestShouldHandleEchoRequest(t *testing.T) {
	m := New()

	// Unicast address: fe80::1
	unicast, err := ip6.AddressFromString("fe80::1")
	if err != nil {
		t.Fatalf("failed to parse unicast address: %v", err)
	}

	// Multicast address: ff02::1
	multicast, err := ip6.AddressFromString("ff02::1")
	if err != nil {
		t.Fatalf("failed to parse multicast address: %v", err)
	}

	// RLOC address: has IID 0000:00ff:fe00:xxxx where byte[6] < 0xfc
	// fd00::ff:fe00:0400
	var rlocAddr ip6.Address
	rlocAddr[0] = 0xfd
	// bytes 1-7: 0
	rlocAddr[8] = 0x00
	rlocAddr[9] = 0x00
	rlocAddr[10] = 0x00
	rlocAddr[11] = 0xff
	rlocAddr[12] = 0xfe
	rlocAddr[13] = 0x00
	rlocAddr[14] = 0x04
	rlocAddr[15] = 0x00

	tests := []struct {
		name     string
		mode     EchoMode
		addr     ip6.Address
		expected bool
	}{
		{"disabled-unicast", EchoModeDisabled, unicast, false},
		{"disabled-multicast", EchoModeDisabled, multicast, false},
		{"unicast-only-unicast", EchoModeUnicastOnly, unicast, true},
		{"unicast-only-multicast", EchoModeUnicastOnly, multicast, false},
		{"multicast-only-unicast", EchoModeMulticastOnly, unicast, false},
		{"multicast-only-multicast", EchoModeMulticastOnly, multicast, true},
		{"all-unicast", EchoModeAll, unicast, true},
		{"all-multicast", EchoModeAll, multicast, true},
		{"rloc-aloc-unicast", EchoModeRlocAlocOnly, unicast, false},
		{"rloc-aloc-multicast", EchoModeRlocAlocOnly, multicast, false},
		{"rloc-aloc-rloc", EchoModeRlocAlocOnly, rlocAddr, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m.SetEchoMode(tc.mode)
			if got := m.ShouldHandleEchoRequest(tc.addr); got != tc.expected {
				t.Errorf("ShouldHandleEchoRequest(%s) = %v, want %v", tc.name, got, tc.expected)
			}
		})
	}
}

func TestGetSetEchoSequence(t *testing.T) {
	m := New()

	// Verify initial value.
	if got := m.GetEchoSequence(); got != 1 {
		t.Fatalf("initial echo sequence: got %d, want 1", got)
	}

	// Verify mode changes do not affect sequence.
	m.SetEchoMode(EchoModeDisabled)
	if got := m.GetEchoSequence(); got != 1 {
		t.Fatalf("echo sequence after mode change: got %d, want 1", got)
	}

	m.SetEchoMode(EchoModeMulticastOnly)
	if got := m.GetEchoMode(); got != EchoModeMulticastOnly {
		t.Fatalf("echo mode: got %d, want %d", got, EchoModeMulticastOnly)
	}
	if got := m.GetEchoSequence(); got != 1 {
		t.Fatalf("echo sequence after second mode change: got %d, want 1", got)
	}
}

func TestHandleMessageDispatchesAll(t *testing.T) {
	m := New()

	var called1, called2 bool
	var gotType1 Type
	var gotCode1 Code
	var gotInfo1 *ip6.MessageInfo

	h1 := NewHandler(func(mi *ip6.MessageInfo, hdr *Header) {
		called1 = true
		gotType1 = hdr.GetType()
		gotCode1 = hdr.GetCode()
		gotInfo1 = mi
	})
	h2 := NewHandler(func(mi *ip6.MessageInfo, hdr *Header) {
		called2 = true
	})

	m.RegisterHandler(h1)
	m.RegisterHandler(h2)

	// Build a valid ICMPv6 echo request payload (8 bytes).
	var echoHdr Header
	echoHdr.SetType(TypeEchoRequest)
	echoHdr.SetCode(0)
	echoHdr.SetChecksum(0)
	echoHdr.SetID(0x0001)
	echoHdr.SetSequence(0x0001)
	payload := echoHdr.MarshalBinary()

	srcIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dstIP := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	mi := &ip6.MessageInfo{
		PeerAddr: srcIP,
		SockAddr: dstIP,
		HopLimit: 64,
	}

	m.HandleMessage(payload, mi)

	if !called1 {
		t.Error("handler 1 should have been called")
	}
	if !called2 {
		t.Error("handler 2 should have been called")
	}
	if gotType1 != TypeEchoRequest {
		t.Errorf("handler 1 got type %d, want %d", gotType1, TypeEchoRequest)
	}
	if gotCode1 != 0 {
		t.Errorf("handler 1 got code %d, want 0", gotCode1)
	}
	if gotInfo1.PeerAddr != srcIP {
		t.Errorf("handler 1 PeerAddr = %v, want %v", gotInfo1.PeerAddr, srcIP)
	}
	if gotInfo1.SockAddr != dstIP {
		t.Errorf("handler 1 SockAddr = %v, want %v", gotInfo1.SockAddr, dstIP)
	}
	if gotInfo1.HopLimit != 64 {
		t.Errorf("handler 1 HopLimit = %d, want 64", gotInfo1.HopLimit)
	}
}

func TestHandleMessageTooShort(t *testing.T) {
	m := New()

	called := false
	h := NewHandler(func(mi *ip6.MessageInfo, hdr *Header) {
		called = true
	})
	m.RegisterHandler(h)

	// Payload shorter than 8 bytes — handler should not be called.
	mi := &ip6.MessageInfo{}
	m.HandleMessage([]byte{0x80, 0x00, 0x00}, mi)

	if called {
		t.Error("handler should not be called for payload shorter than 8 bytes")
	}
}

func TestHandleMessageNilHandler(t *testing.T) {
	m := New()

	// Manually append a nil handler and a handler with nil callback.
	m.handlers = append(m.handlers, nil)
	m.handlers = append(m.handlers, &Handler{callback: nil})

	// Build a valid 8-byte ICMPv6 payload.
	var echoHdr Header
	echoHdr.SetType(TypeEchoRequest)
	payload := echoHdr.MarshalBinary()

	mi := &ip6.MessageInfo{}

	// Should not panic.
	m.HandleMessage(payload, mi)
}
