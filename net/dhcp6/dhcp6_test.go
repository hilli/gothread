// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package dhcp6

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// TestHeaderMarshalUnmarshal
// ---------------------------------------------------------------------------

func TestHeaderMarshalUnmarshal(t *testing.T) {
	h := Header{
		Type:          MsgTypeSolicit,
		TransactionID: TransactionID{0xAB, 0xCD, 0xEF},
	}

	data, err := h.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	if len(data) != HeaderSize {
		t.Fatalf("expected %d bytes, got %d", HeaderSize, len(data))
	}
	if data[0] != byte(MsgTypeSolicit) {
		t.Errorf("expected msg type %d, got %d", MsgTypeSolicit, data[0])
	}
	if data[1] != 0xAB || data[2] != 0xCD || data[3] != 0xEF {
		t.Errorf("transaction ID mismatch: %x", data[1:4])
	}

	var h2 Header
	if err := h2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}
	if h2.Type != h.Type {
		t.Errorf("type mismatch: got %d, want %d", h2.Type, h.Type)
	}
	if h2.TransactionID != h.TransactionID {
		t.Errorf("transaction ID mismatch: got %v, want %v", h2.TransactionID, h.TransactionID)
	}
}

func TestHeaderUnmarshalShort(t *testing.T) {
	var h Header
	err := h.UnmarshalBinary([]byte{0x01, 0x02})
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestOptionHeaderMarshalUnmarshal
// ---------------------------------------------------------------------------

func TestOptionHeaderMarshalUnmarshal(t *testing.T) {
	oh := OptionHeader{
		Code:   OptionCodeClientID,
		Length: 12,
	}

	data, err := oh.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	if len(data) != OptionHeaderSize {
		t.Fatalf("expected %d bytes, got %d", OptionHeaderSize, len(data))
	}

	code := binary.BigEndian.Uint16(data[0:2])
	length := binary.BigEndian.Uint16(data[2:4])
	if OptionCode(code) != OptionCodeClientID {
		t.Errorf("code mismatch: got %d, want %d", code, OptionCodeClientID)
	}
	if length != 12 {
		t.Errorf("length mismatch: got %d, want 12", length)
	}

	var oh2 OptionHeader
	if err := oh2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}
	if oh2.Code != oh.Code || oh2.Length != oh.Length {
		t.Errorf("mismatch: got {%d, %d}, want {%d, %d}", oh2.Code, oh2.Length, oh.Code, oh.Length)
	}
}

func TestOptionHeaderUnmarshalShort(t *testing.T) {
	var oh OptionHeader
	err := oh.UnmarshalBinary([]byte{0x00})
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestOptionMarshalUnmarshal
// ---------------------------------------------------------------------------

func TestOptionMarshalUnmarshal(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	opt := BuildOption(OptionCodeElapsedTime, payload)

	data, err := opt.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	if len(data) != OptionHeaderSize+len(payload) {
		t.Fatalf("expected %d bytes, got %d", OptionHeaderSize+len(payload), len(data))
	}

	var opt2 Option
	if err := opt2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}
	if opt2.Header.Code != OptionCodeElapsedTime {
		t.Errorf("code mismatch: got %d, want %d", opt2.Header.Code, OptionCodeElapsedTime)
	}
	if !bytes.Equal(opt2.Data, payload) {
		t.Errorf("data mismatch: got %x, want %x", opt2.Data, payload)
	}
}

func TestOptionUnmarshalTruncated(t *testing.T) {
	// Option header says length=10, but only 2 data bytes provided.
	buf := make([]byte, OptionHeaderSize+2)
	binary.BigEndian.PutUint16(buf[0:2], uint16(OptionCodeClientID))
	binary.BigEndian.PutUint16(buf[2:4], 10)

	var opt Option
	err := opt.UnmarshalBinary(buf)
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestParseOptions
// ---------------------------------------------------------------------------

func TestParseOptions(t *testing.T) {
	// Build two options back to back.
	var buf []byte
	buf = AppendOption(buf, OptionCodeClientID, []byte{0x01, 0x02})
	buf = AppendOption(buf, OptionCodeElapsedTime, []byte{0x03, 0x04})

	opts, err := ParseOptions(buf)
	if err != nil {
		t.Fatalf("ParseOptions failed: %v", err)
	}
	if len(opts) != 2 {
		t.Fatalf("expected 2 options, got %d", len(opts))
	}
	if opts[0].Header.Code != OptionCodeClientID {
		t.Errorf("first option code: got %d, want %d", opts[0].Header.Code, OptionCodeClientID)
	}
	if opts[1].Header.Code != OptionCodeElapsedTime {
		t.Errorf("second option code: got %d, want %d", opts[1].Header.Code, OptionCodeElapsedTime)
	}
}

func TestFindOption(t *testing.T) {
	var buf []byte
	buf = AppendOption(buf, OptionCodeClientID, []byte{0x01})
	buf = AppendOption(buf, OptionCodeElapsedTime, []byte{0x02, 0x03})
	buf = AppendOption(buf, OptionCodeRapidCommit, nil)

	opts, _ := ParseOptions(buf)

	// Found.
	found := FindOption(opts, OptionCodeElapsedTime)
	if found == nil {
		t.Fatal("expected to find ElapsedTime option")
	}
	if found.Header.Code != OptionCodeElapsedTime {
		t.Errorf("code mismatch: got %d", found.Header.Code)
	}

	// Not found.
	notFound := FindOption(opts, OptionCodeServerID)
	if notFound != nil {
		t.Error("expected nil for missing option")
	}
}

func TestFindOptionInBytes(t *testing.T) {
	var buf []byte
	buf = AppendRapidCommitOption(buf)

	found := FindOptionInBytes(buf, OptionCodeRapidCommit)
	if found == nil {
		t.Fatal("expected to find RapidCommit option")
	}

	notFound := FindOptionInBytes(buf, OptionCodeServerID)
	if notFound != nil {
		t.Error("expected nil for missing option")
	}
}

// ---------------------------------------------------------------------------
// TestEui64DUID
// ---------------------------------------------------------------------------

func TestEui64DUIDInitAndValid(t *testing.T) {
	extAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	var duid Eui64DUID
	duid.Init(extAddr)

	if !duid.IsValid() {
		t.Error("DUID should be valid after Init")
	}
	if duid.Type != DUIDTypeLinkLayer {
		t.Errorf("expected DUIDTypeLinkLayer, got %d", duid.Type)
	}
	if duid.HardwareType != HardwareTypeEUI64 {
		t.Errorf("expected HardwareTypeEUI64, got %d", duid.HardwareType)
	}
	if duid.ExtAddress != extAddr {
		t.Errorf("ExtAddress mismatch")
	}
}

func TestEui64DUIDMarshalUnmarshal(t *testing.T) {
	extAddr := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	var duid Eui64DUID
	duid.Init(extAddr)

	data, err := duid.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	if len(data) != Eui64DUIDSize {
		t.Fatalf("expected %d bytes, got %d", Eui64DUIDSize, len(data))
	}

	var duid2 Eui64DUID
	if err := duid2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}
	if duid2 != duid {
		t.Errorf("DUID mismatch: got %+v, want %+v", duid2, duid)
	}
}

func TestEui64DUIDUnmarshalShort(t *testing.T) {
	var duid Eui64DUID
	err := duid.UnmarshalBinary([]byte{0x00, 0x03, 0x00, 0x1B})
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

func TestEui64DUIDInvalid(t *testing.T) {
	duid := Eui64DUID{
		Type:         DUIDTypeEnterprise,
		HardwareType: HardwareTypeEUI64,
	}
	if duid.IsValid() {
		t.Error("DUID with wrong type should not be valid")
	}
}

// ---------------------------------------------------------------------------
// TestIaNa
// ---------------------------------------------------------------------------

func TestIaNaMarshalUnmarshal(t *testing.T) {
	ia := IaNa{
		IAID: 0x12345678,
		T1:   3600,
		T2:   5400,
	}

	data, err := ia.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	if len(data) != IaNaSize {
		t.Fatalf("expected %d bytes, got %d", IaNaSize, len(data))
	}

	var ia2 IaNa
	if err := ia2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}
	if ia2.IAID != ia.IAID || ia2.T1 != ia.T1 || ia2.T2 != ia.T2 {
		t.Errorf("IaNa mismatch: got %+v, want %+v", ia2, ia)
	}
	if ia2.SubOptions != nil {
		t.Error("SubOptions should be nil when no sub-options present")
	}
}

func TestIaNaWithSubOptions(t *testing.T) {
	subOpts := []byte{0x00, 0x05, 0x00, 0x02, 0xAA, 0xBB}
	ia := IaNa{
		IAID:       1,
		T1:         0,
		T2:         0,
		SubOptions: subOpts,
	}

	data, err := ia.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	if len(data) != IaNaSize+len(subOpts) {
		t.Fatalf("expected %d bytes, got %d", IaNaSize+len(subOpts), len(data))
	}

	var ia2 IaNa
	if err := ia2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}
	if !bytes.Equal(ia2.SubOptions, subOpts) {
		t.Errorf("SubOptions mismatch: got %x, want %x", ia2.SubOptions, subOpts)
	}
}

func TestIaNaUnmarshalShort(t *testing.T) {
	var ia IaNa
	err := ia.UnmarshalBinary(make([]byte, 8))
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestIaAddress
// ---------------------------------------------------------------------------

func TestIaAddressMarshalUnmarshal(t *testing.T) {
	addr := ip6.Address{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	ia := IaAddress{
		Address:           addr,
		PreferredLifetime: InfiniteLifetime,
		ValidLifetime:     InfiniteLifetime,
	}

	data, err := ia.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	if len(data) != IaAddressSize {
		t.Fatalf("expected %d bytes, got %d", IaAddressSize, len(data))
	}

	var ia2 IaAddress
	if err := ia2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}
	if ia2.Address != addr {
		t.Errorf("address mismatch")
	}
	if ia2.PreferredLifetime != InfiniteLifetime {
		t.Errorf("preferred lifetime mismatch: got %d", ia2.PreferredLifetime)
	}
	if ia2.ValidLifetime != InfiniteLifetime {
		t.Errorf("valid lifetime mismatch: got %d", ia2.ValidLifetime)
	}
}

func TestIaAddressUnmarshalShort(t *testing.T) {
	var ia IaAddress
	err := ia.UnmarshalBinary(make([]byte, 20))
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestStatusCode
// ---------------------------------------------------------------------------

func TestStatusCodeMarshalUnmarshal(t *testing.T) {
	sc := StatusCode{
		Code:    StatusSuccess,
		Message: "OK",
	}

	data, err := sc.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	if len(data) != StatusCodeSize+2 { // 2 bytes code + 2 bytes "OK"
		t.Fatalf("expected %d bytes, got %d", StatusCodeSize+2, len(data))
	}

	var sc2 StatusCode
	if err := sc2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}
	if sc2.Code != StatusSuccess {
		t.Errorf("code mismatch: got %d", sc2.Code)
	}
	if sc2.Message != "OK" {
		t.Errorf("message mismatch: got %q", sc2.Message)
	}
}

func TestStatusCodeNoMessage(t *testing.T) {
	sc := StatusCode{Code: StatusNoAddrsAvail}
	data, _ := sc.MarshalBinary()

	var sc2 StatusCode
	if err := sc2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}
	if sc2.Code != StatusNoAddrsAvail {
		t.Errorf("code mismatch: got %d", sc2.Code)
	}
	if sc2.Message != "" {
		t.Errorf("expected empty message, got %q", sc2.Message)
	}
}

func TestStatusCodeUnmarshalShort(t *testing.T) {
	var sc StatusCode
	err := sc.UnmarshalBinary([]byte{0x00})
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

func TestReadStatusFrom(t *testing.T) {
	// No StatusCode option present => StatusSuccess.
	code, err := ReadStatusFrom(nil)
	if err != nil {
		t.Fatalf("ReadStatusFrom(nil) failed: %v", err)
	}
	if code != StatusSuccess {
		t.Errorf("expected StatusSuccess, got %d", code)
	}

	// StatusCode option present with NoAddrsAvail.
	var buf []byte
	buf = AppendStatusCodeOption(buf, StatusNoAddrsAvail)
	code, err = ReadStatusFrom(buf)
	if err != nil {
		t.Fatalf("ReadStatusFrom failed: %v", err)
	}
	if code != StatusNoAddrsAvail {
		t.Errorf("expected StatusNoAddrsAvail, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// TestElapsedTime
// ---------------------------------------------------------------------------

func TestElapsedTimeMarshalUnmarshal(t *testing.T) {
	et := ElapsedTime{ElapsedTime: 1234}

	data, err := et.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	if len(data) != ElapsedTimeSize {
		t.Fatalf("expected %d bytes, got %d", ElapsedTimeSize, len(data))
	}

	var et2 ElapsedTime
	if err := et2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}
	if et2.ElapsedTime != 1234 {
		t.Errorf("elapsed time mismatch: got %d", et2.ElapsedTime)
	}
}

func TestElapsedTimeUnmarshalShort(t *testing.T) {
	var et ElapsedTime
	err := et.UnmarshalBinary([]byte{0x00})
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestRapidCommit
// ---------------------------------------------------------------------------

func TestHasRapidCommit(t *testing.T) {
	var buf []byte
	buf = AppendOption(buf, OptionCodeClientID, []byte{0x01})
	buf = AppendRapidCommitOption(buf)

	opts, _ := ParseOptions(buf)
	if !HasRapidCommit(opts) {
		t.Error("expected Rapid Commit to be found")
	}

	// Without rapid commit.
	var buf2 []byte
	buf2 = AppendOption(buf2, OptionCodeClientID, []byte{0x01})
	opts2, _ := ParseOptions(buf2)
	if HasRapidCommit(opts2) {
		t.Error("expected Rapid Commit to not be found")
	}
}

func TestHasRapidCommitInBytes(t *testing.T) {
	var buf []byte
	buf = AppendRapidCommitOption(buf)
	if !HasRapidCommitInBytes(buf) {
		t.Error("expected Rapid Commit in bytes")
	}
	if HasRapidCommitInBytes(nil) {
		t.Error("expected no Rapid Commit in nil bytes")
	}
}

// ---------------------------------------------------------------------------
// TestPreference
// ---------------------------------------------------------------------------

func TestPreferenceMarshalUnmarshal(t *testing.T) {
	p := Preference{Value: 255}
	data, err := p.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	if len(data) != PreferenceSize {
		t.Fatalf("expected %d bytes, got %d", PreferenceSize, len(data))
	}

	var p2 Preference
	if err := p2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}
	if p2.Value != 255 {
		t.Errorf("value mismatch: got %d", p2.Value)
	}
}

func TestPreferenceUnmarshalShort(t *testing.T) {
	var p Preference
	err := p.UnmarshalBinary(nil)
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestTransactionIDGenerateRandom
// ---------------------------------------------------------------------------

func TestTransactionIDGenerateRandom(t *testing.T) {
	var tid1, tid2 TransactionID
	if err := tid1.GenerateRandom(); err != nil {
		t.Fatalf("GenerateRandom failed: %v", err)
	}
	if err := tid2.GenerateRandom(); err != nil {
		t.Fatalf("GenerateRandom failed: %v", err)
	}
	// Extremely unlikely to be equal.
	if tid1 == tid2 {
		t.Error("two random transaction IDs should not be equal")
	}
	// Should not be all zeros (extremely unlikely).
	zero := TransactionID{}
	if tid1 == zero && tid2 == zero {
		t.Error("both transaction IDs are zero, randomness failure")
	}
}

// ---------------------------------------------------------------------------
// TestBuildOption
// ---------------------------------------------------------------------------

func TestBuildOption(t *testing.T) {
	opt := BuildOption(OptionCodeServerID, []byte{0xDE, 0xAD})
	if opt.Header.Code != OptionCodeServerID {
		t.Errorf("code mismatch: got %d", opt.Header.Code)
	}
	if opt.Header.Length != 2 {
		t.Errorf("length mismatch: got %d", opt.Header.Length)
	}
	if !bytes.Equal(opt.Data, []byte{0xDE, 0xAD}) {
		t.Errorf("data mismatch")
	}
}

// ---------------------------------------------------------------------------
// TestAppendHelpers
// ---------------------------------------------------------------------------

func TestAppendElapsedTimeOption(t *testing.T) {
	buf := AppendElapsedTimeOption(nil, 500)
	opt := FindOptionInBytes(buf, OptionCodeElapsedTime)
	if opt == nil {
		t.Fatal("ElapsedTime option not found")
	}
	var et ElapsedTime
	if err := et.UnmarshalBinary(opt.Data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}
	if et.ElapsedTime != 500 {
		t.Errorf("elapsed time: got %d, want 500", et.ElapsedTime)
	}
}

func TestAppendClientIDOption(t *testing.T) {
	extAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	var duid Eui64DUID
	duid.Init(extAddr)

	buf := AppendClientIDOption(nil, &duid)
	opt := FindOptionInBytes(buf, OptionCodeClientID)
	if opt == nil {
		t.Fatal("ClientID option not found")
	}

	var duid2 Eui64DUID
	if err := duid2.UnmarshalBinary(opt.Data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}
	if duid2 != duid {
		t.Errorf("DUID mismatch")
	}
}

func TestAppendServerIDOption(t *testing.T) {
	extAddr := types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	var duid Eui64DUID
	duid.Init(extAddr)

	buf := AppendServerIDOption(nil, &duid)
	opt := FindOptionInBytes(buf, OptionCodeServerID)
	if opt == nil {
		t.Fatal("ServerID option not found")
	}
}

func TestAppendIaNaOption(t *testing.T) {
	ia := IaNa{IAID: 42, T1: 100, T2: 200}
	buf := AppendIaNaOption(nil, &ia)
	opt := FindOptionInBytes(buf, OptionCodeIaNa)
	if opt == nil {
		t.Fatal("IaNa option not found")
	}

	var ia2 IaNa
	if err := ia2.UnmarshalBinary(opt.Data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}
	if ia2.IAID != 42 || ia2.T1 != 100 || ia2.T2 != 200 {
		t.Errorf("IaNa mismatch: %+v", ia2)
	}
}

func TestAppendIaAddressOption(t *testing.T) {
	iaAddr := IaAddress{
		Address:           ip6.Address{0x20, 0x01, 0x0d, 0xb8},
		PreferredLifetime: 3600,
		ValidLifetime:     7200,
	}
	buf := AppendIaAddressOption(nil, &iaAddr)
	opt := FindOptionInBytes(buf, OptionCodeIaAddress)
	if opt == nil {
		t.Fatal("IaAddress option not found")
	}

	var iaAddr2 IaAddress
	if err := iaAddr2.UnmarshalBinary(opt.Data); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}
	if iaAddr2.PreferredLifetime != 3600 || iaAddr2.ValidLifetime != 7200 {
		t.Errorf("lifetime mismatch: %+v", iaAddr2)
	}
}

// ---------------------------------------------------------------------------
// TestMakeAddressFromPrefixEUI64
// ---------------------------------------------------------------------------

func TestMakeAddressFromPrefixEUI64(t *testing.T) {
	prefix := ip6.NetworkPrefix{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00}
	extAddr := types.ExtAddress{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}

	addr := MakeAddressFromPrefixEUI64(prefix, extAddr)

	// First 8 bytes should be the prefix.
	for i := 0; i < 8; i++ {
		if addr[i] != prefix[i] {
			t.Errorf("prefix byte %d: got 0x%02x, want 0x%02x", i, addr[i], prefix[i])
		}
	}

	// Byte 8 should be extAddr[0] ^ 0x02 = 0x02 ^ 0x02 = 0x00.
	if addr[8] != 0x00 {
		t.Errorf("IID byte 0: got 0x%02x, want 0x00", addr[8])
	}

	// Remaining IID bytes should match extAddr[1:].
	for i := 1; i < 8; i++ {
		if addr[8+i] != extAddr[i] {
			t.Errorf("IID byte %d: got 0x%02x, want 0x%02x", i, addr[8+i], extAddr[i])
		}
	}
}

// ---------------------------------------------------------------------------
// TestConstants
// ---------------------------------------------------------------------------

func TestConstants(t *testing.T) {
	if ClientPort != 546 {
		t.Errorf("ClientPort: got %d, want 546", ClientPort)
	}
	if ServerPort != 547 {
		t.Errorf("ServerPort: got %d, want 547", ServerPort)
	}
	if InfiniteLifetime != 0xFFFFFFFF {
		t.Errorf("InfiniteLifetime: got %d", InfiniteLifetime)
	}
}

func TestMsgTypeValues(t *testing.T) {
	tests := []struct {
		name string
		val  MsgType
		want uint8
	}{
		{"Solicit", MsgTypeSolicit, 1},
		{"Advertise", MsgTypeAdvertise, 2},
		{"Request", MsgTypeRequest, 3},
		{"Reply", MsgTypeReply, 7},
		{"RelayForward", MsgTypeRelayForward, 12},
		{"LeaseQuery", MsgTypeLeaseQuery, 14},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if uint8(tt.val) != tt.want {
				t.Errorf("%s: got %d, want %d", tt.name, tt.val, tt.want)
			}
		})
	}
}

func TestOptionCodeValues(t *testing.T) {
	tests := []struct {
		name string
		val  OptionCode
		want uint16
	}{
		{"ClientID", OptionCodeClientID, 1},
		{"ServerID", OptionCodeServerID, 2},
		{"IaNa", OptionCodeIaNa, 3},
		{"IaAddress", OptionCodeIaAddress, 5},
		{"ElapsedTime", OptionCodeElapsedTime, 8},
		{"StatusCode", OptionCodeStatusCode, 13},
		{"RapidCommit", OptionCodeRapidCommit, 14},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if uint16(tt.val) != tt.want {
				t.Errorf("%s: got %d, want %d", tt.name, tt.val, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestAllDHCPRelayAgentsAndServers
// ---------------------------------------------------------------------------

func TestAllDHCPRelayAgentsAndServers(t *testing.T) {
	expected := ip6.Address{
		0xff, 0x02, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0x01, 0, 0x02,
	}
	if AllDHCPRelayAgentsAndServers != expected {
		t.Errorf("AllDHCPRelayAgentsAndServers mismatch")
	}
}

// ---------------------------------------------------------------------------
// TestOptionTotalLength
// ---------------------------------------------------------------------------

func TestOptionTotalLength(t *testing.T) {
	opt := BuildOption(OptionCodeClientID, []byte{1, 2, 3})
	if opt.TotalLength() != OptionHeaderSize+3 {
		t.Errorf("TotalLength: got %d, want %d", opt.TotalLength(), OptionHeaderSize+3)
	}

	optEmpty := BuildOption(OptionCodeRapidCommit, nil)
	if optEmpty.TotalLength() != OptionHeaderSize {
		t.Errorf("TotalLength: got %d, want %d", optEmpty.TotalLength(), OptionHeaderSize)
	}
}

// ---------------------------------------------------------------------------
// TestParseOptionsEmpty
// ---------------------------------------------------------------------------

func TestParseOptionsEmpty(t *testing.T) {
	opts, err := ParseOptions(nil)
	if err != nil {
		t.Fatalf("ParseOptions(nil) failed: %v", err)
	}
	if len(opts) != 0 {
		t.Errorf("expected 0 options, got %d", len(opts))
	}

	opts2, err := ParseOptions([]byte{})
	if err != nil {
		t.Fatalf("ParseOptions([]) failed: %v", err)
	}
	if len(opts2) != 0 {
		t.Errorf("expected 0 options, got %d", len(opts2))
	}
}

// ---------------------------------------------------------------------------
// TestParseOptionsTrailingBytes
// ---------------------------------------------------------------------------

func TestParseOptionsTrailingBytes(t *testing.T) {
	// An option followed by < 4 trailing bytes should stop parsing
	// without error.
	var buf []byte
	buf = AppendOption(buf, OptionCodeClientID, []byte{0x01})
	buf = append(buf, 0x00, 0x00) // trailing garbage < OptionHeaderSize

	opts, err := ParseOptions(buf)
	if err != nil {
		t.Fatalf("ParseOptions failed: %v", err)
	}
	if len(opts) != 1 {
		t.Errorf("expected 1 option, got %d", len(opts))
	}
}
