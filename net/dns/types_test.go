// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"encoding/binary"
	"testing"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// ResponseCodeToError
// ---------------------------------------------------------------------------

func TestResponseCodeToError(t *testing.T) {
	tests := []struct {
		code ResponseCode
		want error
	}{
		{RcodeSuccess, nil},
		{RcodeFormatError, errors.ErrParse},
		{RcodeBadName, errors.ErrParse},
		{RcodeBadTruncation, errors.ErrParse},
		{RcodeNotZone, errors.ErrParse},
		{RcodeServerFailure, errors.ErrFailed},
		{RcodeNameError, errors.ErrNotFound},
		{RcodeRecordNotExists, errors.ErrNotFound},
		{RcodeNotImplemented, errors.ErrNotImplemented},
		{RcodeDsoNotImpl, errors.ErrNotImplemented},
		{RcodeBadAlg, errors.ErrNotCapable},
		{RcodeNameExists, errors.ErrDuplicated},
		{RcodeRecordExists, errors.ErrDuplicated},
		{RcodeRefused, errors.ErrSecurity},
		{RcodeNotAuth, errors.ErrSecurity},
		{ResponseCode(99), errors.ErrFailed}, // unknown code
	}
	for _, tt := range tests {
		got := ResponseCodeToError(tt.code)
		if got != tt.want {
			t.Errorf("ResponseCodeToError(%d): got %v, want %v", tt.code, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// RRTypeToString
// ---------------------------------------------------------------------------

func TestRRTypeToString(t *testing.T) {
	if got := RRTypeToString(RRTypeA); got != "A" {
		t.Errorf("RRTypeToString(A): got %q", got)
	}
	if got := RRTypeToString(RRTypeAaaa); got != "AAAA" {
		t.Errorf("RRTypeToString(AAAA): got %q", got)
	}
	if got := RRTypeToString(RRTypeSrv); got != "SRV" {
		t.Errorf("RRTypeToString(SRV): got %q", got)
	}
	if got := RRTypeToString(RRType(999)); got != "UNKNOWN" {
		t.Errorf("RRTypeToString(999): got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

func TestHeaderMarshalUnmarshal(t *testing.T) {
	var h Header
	h.MessageID = 0x1234
	h.SetType(TypeResponse)
	h.SetOpCode(OpcodeUpdate)
	h.SetAuthoritativeAnswer(true)
	h.SetTruncated(false)
	h.SetRecursionDesired(true)
	h.SetRecursionAvailable(true)
	h.SetResponseCode(RcodeRefused)
	h.QDCount = 1
	h.ANCount = 2
	h.NSCount = 3
	h.ARCount = 4

	buf := h.MarshalBinary()
	if len(buf) != HeaderSize {
		t.Fatalf("MarshalBinary: got %d bytes, want %d", len(buf), HeaderSize)
	}

	// Verify wire format bytes directly.
	if binary.BigEndian.Uint16(buf[0:2]) != 0x1234 {
		t.Error("MessageID mismatch in wire")
	}

	var h2 Header
	if err := h2.UnmarshalBinary(buf[:]); err != nil {
		t.Fatal(err)
	}

	if h2.MessageID != 0x1234 {
		t.Errorf("MessageID: got 0x%04x", h2.MessageID)
	}
	if h2.GetType() != TypeResponse {
		t.Error("Type: expected TypeResponse")
	}
	if h2.GetOpCode() != OpcodeUpdate {
		t.Errorf("OpCode: got %d, want %d", h2.GetOpCode(), OpcodeUpdate)
	}
	if !h2.IsAuthoritativeAnswer() {
		t.Error("AA flag not set")
	}
	if h2.IsTruncated() {
		t.Error("TC flag should not be set")
	}
	if !h2.IsRecursionDesired() {
		t.Error("RD flag not set")
	}
	if !h2.IsRecursionAvailable() {
		t.Error("RA flag not set")
	}
	if h2.GetResponseCode() != RcodeRefused {
		t.Errorf("RCODE: got %d, want %d", h2.GetResponseCode(), RcodeRefused)
	}
	if h2.QDCount != 1 || h2.ANCount != 2 || h2.NSCount != 3 || h2.ARCount != 4 {
		t.Errorf("Section counts mismatch: %d %d %d %d", h2.QDCount, h2.ANCount, h2.NSCount, h2.ARCount)
	}
}

func TestHeaderFlags(t *testing.T) {
	var h Header

	// Default: all flags clear.
	if h.GetType() != TypeQuery {
		t.Error("default should be TypeQuery")
	}
	if h.GetOpCode() != OpcodeQuery {
		t.Error("default OpCode should be OpcodeQuery")
	}
	if h.IsAuthoritativeAnswer() || h.IsTruncated() || h.IsRecursionDesired() || h.IsRecursionAvailable() {
		t.Error("default flags should all be clear")
	}
	if h.GetResponseCode() != RcodeSuccess {
		t.Error("default RCODE should be RcodeSuccess")
	}

	// Toggle each flag independently.
	h.SetType(TypeResponse)
	if h.GetType() != TypeResponse {
		t.Error("SetType(TypeResponse) failed")
	}
	h.SetType(TypeQuery)
	if h.GetType() != TypeQuery {
		t.Error("SetType(TypeQuery) failed")
	}

	h.SetTruncated(true)
	if !h.IsTruncated() {
		t.Error("SetTruncated(true) failed")
	}
	h.SetTruncated(false)
	if h.IsTruncated() {
		t.Error("SetTruncated(false) failed")
	}

	h.SetRecursionDesired(true)
	if !h.IsRecursionDesired() {
		t.Error("SetRecursionDesired(true) failed")
	}

	h.SetRecursionAvailable(true)
	if !h.IsRecursionAvailable() {
		t.Error("SetRecursionAvailable(true) failed")
	}
}

func TestHeaderOpCodes(t *testing.T) {
	codes := []OpCode{OpcodeQuery, OpcodeInverse, OpcodeStatus, OpcodeNotify, OpcodeUpdate, OpcodeDso}
	for _, oc := range codes {
		var h Header
		h.SetOpCode(oc)
		if h.GetOpCode() != oc {
			t.Errorf("SetOpCode(%d)/GetOpCode() mismatch: got %d", oc, h.GetOpCode())
		}
		// Verify other flags are unaffected.
		if h.GetType() != TypeQuery {
			t.Error("SetOpCode affected QR flag")
		}
	}
}

func TestHeaderResponseCodes(t *testing.T) {
	codes := []ResponseCode{RcodeSuccess, RcodeFormatError, RcodeServerFailure, RcodeNameError, RcodeRefused}
	for _, rc := range codes {
		var h Header
		h.SetResponseCode(rc)
		if h.GetResponseCode() != rc {
			t.Errorf("SetResponseCode(%d)/GetResponseCode() mismatch: got %d", rc, h.GetResponseCode())
		}
	}
}

func TestHeaderUnmarshalTooShort(t *testing.T) {
	var h Header
	if err := h.UnmarshalBinary(make([]byte, 5)); err != errors.ErrParse {
		t.Errorf("expected ErrParse for short data, got %v", err)
	}
}

func TestHeaderWireFormatKnownBytes(t *testing.T) {
	// Build a known wire-format header and verify decoding.
	var buf [HeaderSize]byte
	binary.BigEndian.PutUint16(buf[0:2], 0xABCD) // MessageID
	buf[2] = 0x80 | (5 << 3) | 0x04 | 0x01       // QR=1, OpCode=5(Update), AA=1, RD=1
	buf[3] = 0x80 | 0x05                         // RA=1, RCODE=5(Refused)
	binary.BigEndian.PutUint16(buf[4:6], 10)     // QDCount
	binary.BigEndian.PutUint16(buf[6:8], 20)     // ANCount
	binary.BigEndian.PutUint16(buf[8:10], 30)    // NSCount
	binary.BigEndian.PutUint16(buf[10:12], 40)   // ARCount

	var h Header
	if err := h.UnmarshalBinary(buf[:]); err != nil {
		t.Fatal(err)
	}

	if h.MessageID != 0xABCD {
		t.Errorf("MessageID: got 0x%04x", h.MessageID)
	}
	if h.GetType() != TypeResponse {
		t.Error("expected TypeResponse")
	}
	if h.GetOpCode() != OpcodeUpdate {
		t.Errorf("OpCode: got %d", h.GetOpCode())
	}
	if !h.IsAuthoritativeAnswer() {
		t.Error("AA not set")
	}
	if h.IsTruncated() {
		t.Error("TC should not be set")
	}
	if !h.IsRecursionDesired() {
		t.Error("RD not set")
	}
	if !h.IsRecursionAvailable() {
		t.Error("RA not set")
	}
	if h.GetResponseCode() != RcodeRefused {
		t.Errorf("RCODE: got %d", h.GetResponseCode())
	}
	if h.QDCount != 10 || h.ANCount != 20 || h.NSCount != 30 || h.ARCount != 40 {
		t.Error("section counts mismatch")
	}
}

// ---------------------------------------------------------------------------
// UpdateHeader
// ---------------------------------------------------------------------------

func TestUpdateHeader(t *testing.T) {
	uh := NewUpdateHeader()
	if uh.GetOpCode() != OpcodeUpdate {
		t.Errorf("OpCode: got %d, want %d", uh.GetOpCode(), OpcodeUpdate)
	}

	uh.SetZoneCount(1)
	uh.SetPrerequisiteCount(2)
	uh.SetUpdateCount(3)
	uh.ARCount = 4

	if uh.ZoneCount() != 1 {
		t.Errorf("ZoneCount: got %d", uh.ZoneCount())
	}
	if uh.PrerequisiteCount() != 2 {
		t.Errorf("PrerequisiteCount: got %d", uh.PrerequisiteCount())
	}
	if uh.UpdateCount() != 3 {
		t.Errorf("UpdateCount: got %d", uh.UpdateCount())
	}
	if uh.ARCount != 4 {
		t.Errorf("ARCount: got %d", uh.ARCount)
	}

	// Verify aliases map correctly.
	if uh.QDCount != 1 {
		t.Error("ZoneCount alias mismatch with QDCount")
	}
	if uh.ANCount != 2 {
		t.Error("PrerequisiteCount alias mismatch with ANCount")
	}
	if uh.NSCount != 3 {
		t.Error("UpdateCount alias mismatch with NSCount")
	}
}

// ---------------------------------------------------------------------------
// Question / Zone
// ---------------------------------------------------------------------------

func TestQuestionMarshalUnmarshal(t *testing.T) {
	q := Question{Type: RRTypeAaaa, Class: ClassInternet}
	buf := q.MarshalBinary()
	if len(buf) != QuestionSize {
		t.Fatalf("Question size: got %d", len(buf))
	}

	var q2 Question
	if err := q2.UnmarshalBinary(buf[:]); err != nil {
		t.Fatal(err)
	}
	if q2.Type != RRTypeAaaa || q2.Class != ClassInternet {
		t.Errorf("Question mismatch: type=%d class=%d", q2.Type, q2.Class)
	}
}

func TestQuestionUnmarshalTooShort(t *testing.T) {
	var q Question
	if err := q.UnmarshalBinary(make([]byte, 3)); err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

func TestZone(t *testing.T) {
	z := NewZone()
	if z.Type != RRTypeSoa {
		t.Errorf("Zone type: got %d, want %d", z.Type, RRTypeSoa)
	}
	if z.Class != ClassInternet {
		t.Errorf("Zone class: got %d, want %d", z.Class, ClassInternet)
	}
}

// ---------------------------------------------------------------------------
// ResourceRecord
// ---------------------------------------------------------------------------

func TestResourceRecordMarshalUnmarshal(t *testing.T) {
	var rr ResourceRecord
	rr.Init(RRTypeTxt, ClassInternet)
	rr.TTL = 3600
	rr.RDLength = 42

	buf := rr.MarshalBinary()
	if len(buf) != ResourceRecordSize {
		t.Fatalf("RR size: got %d", len(buf))
	}

	var rr2 ResourceRecord
	if err := rr2.UnmarshalBinary(buf[:]); err != nil {
		t.Fatal(err)
	}
	if rr2.Type != RRTypeTxt || rr2.Class != ClassInternet {
		t.Errorf("RR type/class mismatch")
	}
	if rr2.TTL != 3600 {
		t.Errorf("TTL: got %d", rr2.TTL)
	}
	if rr2.RDLength != 42 {
		t.Errorf("RDLength: got %d", rr2.RDLength)
	}
}

func TestResourceRecordMatches(t *testing.T) {
	var rr ResourceRecord
	rr.Init(RRTypeA, ClassInternet)
	if !rr.Matches(RRTypeA, ClassInternet) {
		t.Error("Matches should return true")
	}
	if rr.Matches(RRTypeAaaa, ClassInternet) {
		t.Error("Matches should return false for wrong type")
	}
}

func TestResourceRecordGetSize(t *testing.T) {
	var rr ResourceRecord
	rr.RDLength = 16
	if rr.GetSize() != ResourceRecordSize+16 {
		t.Errorf("GetSize: got %d, want %d", rr.GetSize(), ResourceRecordSize+16)
	}
}

func TestResourceRecordUnmarshalTooShort(t *testing.T) {
	var rr ResourceRecord
	if err := rr.UnmarshalBinary(make([]byte, 9)); err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// ARecord
// ---------------------------------------------------------------------------

func TestARecordMarshalUnmarshal(t *testing.T) {
	var r ARecord
	r.Init()
	r.Address = [4]byte{192, 168, 1, 1}

	buf := r.MarshalBinary()
	if len(buf) != ResourceRecordSize+ARecordRDataSize {
		t.Fatalf("ARecord size: got %d", len(buf))
	}

	var r2 ARecord
	if err := r2.UnmarshalBinary(buf); err != nil {
		t.Fatal(err)
	}
	if r2.Type != RRTypeA {
		t.Errorf("Type: got %d", r2.Type)
	}
	if r2.Class != ClassInternet {
		t.Errorf("Class: got %d", r2.Class)
	}
	if r2.RDLength != ARecordRDataSize {
		t.Errorf("RDLength: got %d", r2.RDLength)
	}
	if r2.Address != [4]byte{192, 168, 1, 1} {
		t.Errorf("Address: got %v", r2.Address)
	}
}

func TestARecordUnmarshalTooShort(t *testing.T) {
	var r ARecord
	buf := make([]byte, ResourceRecordSize+2)
	binary.BigEndian.PutUint16(buf[0:2], uint16(RRTypeA))
	binary.BigEndian.PutUint16(buf[2:4], uint16(ClassInternet))
	binary.BigEndian.PutUint32(buf[4:8], 0)
	binary.BigEndian.PutUint16(buf[8:10], 4)
	if err := r.UnmarshalBinary(buf); err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// AaaaRecord
// ---------------------------------------------------------------------------

func TestAaaaRecordMarshalUnmarshal(t *testing.T) {
	var r AaaaRecord
	r.Init()
	r.Address = ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	buf := r.MarshalBinary()
	if len(buf) != ResourceRecordSize+AaaaRecordRDataSize {
		t.Fatalf("AaaaRecord size: got %d", len(buf))
	}

	var r2 AaaaRecord
	if err := r2.UnmarshalBinary(buf); err != nil {
		t.Fatal(err)
	}
	if !r2.IsValid() {
		t.Error("IsValid() should return true")
	}
	if r2.Address != r.Address {
		t.Errorf("Address mismatch")
	}
}

func TestAaaaRecordIsValid(t *testing.T) {
	var r AaaaRecord
	r.Init()
	if !r.IsValid() {
		t.Error("freshly Init'd AAAA should be valid")
	}

	r.Type = RRTypeA // wrong type
	if r.IsValid() {
		t.Error("wrong type should be invalid")
	}

	r.Type = RRTypeAaaa
	r.RDLength = 8 // wrong length
	if r.IsValid() {
		t.Error("wrong RDLength should be invalid")
	}
}

// ---------------------------------------------------------------------------
// PtrRecord
// ---------------------------------------------------------------------------

func TestPtrRecordReadPtrName(t *testing.T) {
	// Build a message buffer with an encoded name "example.com."
	var buf []byte
	var err error
	buf, err = AppendName(buf, "example.com")
	if err != nil {
		t.Fatal(err)
	}

	var r PtrRecord
	r.Init(ClassInternet)
	r.RDLength = uint16(len(buf))

	name, endOffset, err := r.ReadPtrName(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if name != "example.com." {
		t.Errorf("PTR name: got %q", name)
	}
	if endOffset != len(buf) {
		t.Errorf("endOffset: got %d, want %d", endOffset, len(buf))
	}
}

// ---------------------------------------------------------------------------
// CnameRecord
// ---------------------------------------------------------------------------

func TestCnameRecordReadCanonicalName(t *testing.T) {
	var buf []byte
	var err error
	buf, err = AppendName(buf, "www.example.com")
	if err != nil {
		t.Fatal(err)
	}

	var r CnameRecord
	r.Init(ClassInternet)
	r.RDLength = uint16(len(buf))

	name, endOffset, err := r.ReadCanonicalName(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if name != "www.example.com." {
		t.Errorf("CNAME: got %q", name)
	}
	if endOffset != len(buf) {
		t.Errorf("endOffset: got %d, want %d", endOffset, len(buf))
	}
}

// ---------------------------------------------------------------------------
// TxtRecord / VerifyTxtData
// ---------------------------------------------------------------------------

func TestVerifyTxtDataValid(t *testing.T) {
	// "key=val" => length 7.
	data := []byte{7, 'k', 'e', 'y', '=', 'v', 'a', 'l'}
	if !VerifyTxtData(data, false) {
		t.Error("valid TXT data rejected")
	}
}

func TestVerifyTxtDataMultipleEntries(t *testing.T) {
	data := []byte{3, 'a', '=', 'b', 4, 'c', '=', 'd', 'e'}
	if !VerifyTxtData(data, false) {
		t.Error("valid multi-entry TXT data rejected")
	}
}

func TestVerifyTxtDataEmpty(t *testing.T) {
	if VerifyTxtData(nil, false) {
		t.Error("empty TXT data should be rejected when allowEmpty=false")
	}
	if !VerifyTxtData(nil, true) {
		t.Error("empty TXT data should be accepted when allowEmpty=true")
	}
}

func TestVerifyTxtDataInvalid(t *testing.T) {
	// Length byte says 10, but only 3 bytes follow.
	data := []byte{10, 'a', 'b', 'c'}
	if VerifyTxtData(data, false) {
		t.Error("invalid TXT data accepted")
	}
}

func TestTxtRecordReadTxtData(t *testing.T) {
	txtData := []byte{3, 'a', '=', 'b', 5, 'c', '=', 'd', 'e', 'f'}
	var r TxtRecord
	r.Init(ClassInternet)
	r.RDLength = uint16(len(txtData))

	got, endOffset, err := r.ReadTxtData(txtData, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(txtData) {
		t.Errorf("ReadTxtData: got %d bytes, want %d", len(got), len(txtData))
	}
	if endOffset != len(txtData) {
		t.Errorf("endOffset: got %d, want %d", endOffset, len(txtData))
	}
}

func TestTxtRecordReadTxtDataTruncated(t *testing.T) {
	var r TxtRecord
	r.Init(ClassInternet)
	r.RDLength = 100 // exceeds data
	_, _, err := r.ReadTxtData(make([]byte, 10), 0)
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// SrvRecord
// ---------------------------------------------------------------------------

func TestSrvRecordMarshalUnmarshal(t *testing.T) {
	var r SrvRecord
	r.Init(ClassInternet)
	r.Priority = 10
	r.Weight = 20
	r.Port = 8080

	buf := r.MarshalBinary()
	if len(buf) != ResourceRecordSize+SrvRecordFixedSize {
		t.Fatalf("SrvRecord size: got %d", len(buf))
	}

	var r2 SrvRecord
	if err := r2.UnmarshalBinary(buf); err != nil {
		t.Fatal(err)
	}
	if r2.Priority != 10 || r2.Weight != 20 || r2.Port != 8080 {
		t.Errorf("SRV fields: priority=%d weight=%d port=%d", r2.Priority, r2.Weight, r2.Port)
	}
}

func TestSrvRecordReadTargetHostName(t *testing.T) {
	// Build SRV RDATA: priority(2) + weight(2) + port(2) + encoded name.
	var rdata []byte
	rdata = binary.BigEndian.AppendUint16(rdata, 0)    // priority
	rdata = binary.BigEndian.AppendUint16(rdata, 0)    // weight
	rdata = binary.BigEndian.AppendUint16(rdata, 5353) // port

	name, err := AppendName(rdata, "server.local")
	if err != nil {
		t.Fatal(err)
	}
	rdata = name

	var r SrvRecord
	r.Init(ClassInternet)
	r.RDLength = uint16(len(rdata))
	r.Port = 5353

	hostname, err := r.ReadTargetHostName(rdata, 0)
	if err != nil {
		t.Fatal(err)
	}
	if hostname != "server.local." {
		t.Errorf("target hostname: got %q", hostname)
	}
}

func TestSrvRecordUnmarshalTooShort(t *testing.T) {
	var r SrvRecord
	buf := make([]byte, ResourceRecordSize+2)
	binary.BigEndian.PutUint16(buf[0:2], uint16(RRTypeSrv))
	binary.BigEndian.PutUint16(buf[2:4], uint16(ClassInternet))
	if err := r.UnmarshalBinary(buf); err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// KeyRecord
// ---------------------------------------------------------------------------

func TestKeyRecordMarshalUnmarshal(t *testing.T) {
	var r KeyRecord
	r.Init(ClassInternet)
	r.SetFlags(KeyUseAuthPermitted, KeyOwnerZone, KeySignatoryFlagZone|KeySignatoryFlagGeneral)
	r.Protocol = KeyProtocolDnsSec
	r.Algorithm = KeyAlgorithmEcdsaP256Sha256

	buf := r.MarshalBinary()
	if len(buf) != ResourceRecordSize+KeyRecordFixedSize {
		t.Fatalf("KeyRecord size: got %d", len(buf))
	}

	var r2 KeyRecord
	if err := r2.UnmarshalBinary(buf); err != nil {
		t.Fatal(err)
	}
	if !r2.IsValid() {
		t.Error("should be valid")
	}
	if r2.GetUseFlags() != KeyUseAuthPermitted {
		t.Errorf("UseFlags: got 0x%02x", r2.GetUseFlags())
	}
	if r2.GetOwnerFlags() != KeyOwnerZone {
		t.Errorf("OwnerFlags: got 0x%02x", r2.GetOwnerFlags())
	}
	if r2.GetSignatoryFlags() != KeySignatoryFlagZone|KeySignatoryFlagGeneral {
		t.Errorf("SignatoryFlags: got 0x%02x", r2.GetSignatoryFlags())
	}
	if r2.Protocol != KeyProtocolDnsSec {
		t.Errorf("Protocol: got %d", r2.Protocol)
	}
	if r2.Algorithm != KeyAlgorithmEcdsaP256Sha256 {
		t.Errorf("Algorithm: got %d", r2.Algorithm)
	}
}

func TestKeyRecordFlags(t *testing.T) {
	var r KeyRecord
	r.Init(ClassInternet)

	// Test all use flags.
	for _, uf := range []KeyUseFlags{KeyUseAuthConfidPermitted, KeyUseAuthPermitted, KeyUseConfidPermitted, KeyUseNoKey} {
		r.SetFlags(uf, KeyOwnerUser, 0)
		if r.GetUseFlags() != uf {
			t.Errorf("UseFlags: set 0x%02x, got 0x%02x", uf, r.GetUseFlags())
		}
	}

	// Test all owner flags.
	for _, of := range []KeyOwnerFlags{KeyOwnerUser, KeyOwnerZone, KeyOwnerNonZone, KeyOwnerReserved} {
		r.SetFlags(KeyUseAuthConfidPermitted, of, 0)
		if r.GetOwnerFlags() != of {
			t.Errorf("OwnerFlags: set 0x%02x, got 0x%02x", of, r.GetOwnerFlags())
		}
	}

	// Test signatory flags.
	sigFlags := KeySignatoryFlagZone | KeySignatoryFlagStrong | KeySignatoryFlagUnique | KeySignatoryFlagGeneral
	r.SetFlags(KeyUseAuthConfidPermitted, KeyOwnerUser, sigFlags)
	if r.GetSignatoryFlags() != sigFlags {
		t.Errorf("SignatoryFlags: got 0x%02x, want 0x%02x", r.GetSignatoryFlags(), sigFlags)
	}
}

func TestKeyRecordUnmarshalTooShort(t *testing.T) {
	var r KeyRecord
	buf := make([]byte, ResourceRecordSize+2)
	binary.BigEndian.PutUint16(buf[0:2], uint16(RRTypeKey))
	binary.BigEndian.PutUint16(buf[2:4], uint16(ClassInternet))
	if err := r.UnmarshalBinary(buf); err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Ecdsa256KeyRecord
// ---------------------------------------------------------------------------

func TestEcdsa256KeyRecordMarshalUnmarshal(t *testing.T) {
	var r Ecdsa256KeyRecord
	r.Init()
	for i := range r.Key {
		r.Key[i] = byte(i)
	}

	buf := r.MarshalBinary()
	expectedSize := ResourceRecordSize + KeyRecordFixedSize + Ecdsa256KeySize
	if len(buf) != expectedSize {
		t.Fatalf("Ecdsa256KeyRecord size: got %d, want %d", len(buf), expectedSize)
	}

	var r2 Ecdsa256KeyRecord
	if err := r2.UnmarshalBinary(buf); err != nil {
		t.Fatal(err)
	}
	if !r2.IsValid() {
		t.Error("should be valid")
	}
	if r2.Key != r.Key {
		t.Error("key mismatch")
	}
	if r2.Algorithm != KeyAlgorithmEcdsaP256Sha256 {
		t.Errorf("Algorithm: got %d", r2.Algorithm)
	}
}

func TestEcdsa256KeyRecordIsValid(t *testing.T) {
	var r Ecdsa256KeyRecord
	r.Init()
	if !r.IsValid() {
		t.Error("freshly Init'd should be valid")
	}

	r.Algorithm = KeyAlgorithmEd25519
	if r.IsValid() {
		t.Error("wrong algorithm should be invalid")
	}

	r.Algorithm = KeyAlgorithmEcdsaP256Sha256
	r.RDLength = 10
	if r.IsValid() {
		t.Error("wrong RDLength should be invalid")
	}
}

func TestEcdsa256KeyRecordUnmarshalTooShort(t *testing.T) {
	var r Ecdsa256KeyRecord
	buf := make([]byte, ResourceRecordSize+KeyRecordFixedSize+10)
	binary.BigEndian.PutUint16(buf[0:2], uint16(RRTypeKey))
	binary.BigEndian.PutUint16(buf[2:4], uint16(ClassInternet))
	if err := r.UnmarshalBinary(buf); err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// SigRecord
// ---------------------------------------------------------------------------

func TestSigRecordMarshalUnmarshal(t *testing.T) {
	var r SigRecord
	r.Init(ClassAny) // SIG(0)
	r.TypeCovered = 0
	r.Algorithm = KeyAlgorithmEcdsaP256Sha256
	r.Labels = 3
	r.OriginalTTL = 86400
	r.Expiration = 1700000000
	r.Inception = 1699000000
	r.KeyTag = 12345
	r.RDLength = SigRecordFixedSize + 20 // 18 fixed + some name/sig

	buf := r.MarshalBinary()
	if len(buf) != ResourceRecordSize+SigRecordFixedSize {
		t.Fatalf("SigRecord marshal size: got %d", len(buf))
	}

	var r2 SigRecord
	if err := r2.UnmarshalBinary(buf); err != nil {
		t.Fatal(err)
	}
	if r2.TypeCovered != 0 {
		t.Errorf("TypeCovered: got %d", r2.TypeCovered)
	}
	if r2.Algorithm != KeyAlgorithmEcdsaP256Sha256 {
		t.Errorf("Algorithm: got %d", r2.Algorithm)
	}
	if r2.Labels != 3 {
		t.Errorf("Labels: got %d", r2.Labels)
	}
	if r2.OriginalTTL != 86400 {
		t.Errorf("OriginalTTL: got %d", r2.OriginalTTL)
	}
	if r2.Expiration != 1700000000 {
		t.Errorf("Expiration: got %d", r2.Expiration)
	}
	if r2.Inception != 1699000000 {
		t.Errorf("Inception: got %d", r2.Inception)
	}
	if r2.KeyTag != 12345 {
		t.Errorf("KeyTag: got %d", r2.KeyTag)
	}
}

func TestSigRecordIsValid(t *testing.T) {
	var r SigRecord
	r.Init(ClassAny)
	r.RDLength = SigRecordFixedSize
	if !r.IsValid() {
		t.Error("should be valid with RDLength >= 18")
	}

	r.RDLength = SigRecordFixedSize - 1
	if r.IsValid() {
		t.Error("should be invalid with RDLength < 18")
	}

	r.RDLength = SigRecordFixedSize
	r.Type = RRTypeA
	if r.IsValid() {
		t.Error("should be invalid with wrong type")
	}
}

func TestSigRecordReadSignerName(t *testing.T) {
	// Build RDATA: 18 fixed bytes + encoded name "example.com." + signature.
	rdata := make([]byte, SigRecordFixedSize)
	var err error
	rdata, err = AppendName(rdata, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Append some fake signature bytes.
	rdata = append(rdata, 0xAA, 0xBB, 0xCC)

	var r SigRecord
	r.Init(ClassAny)
	r.RDLength = uint16(len(rdata))

	name, sigOffset, err := r.ReadSignerName(rdata, 0)
	if err != nil {
		t.Fatal(err)
	}
	if name != "example.com." {
		t.Errorf("signer name: got %q", name)
	}
	// sigOffset should point to the signature data (after the name).
	if sigOffset >= len(rdata) {
		t.Errorf("sigOffset %d >= rdata length %d", sigOffset, len(rdata))
	}
}

func TestSigRecordUnmarshalTooShort(t *testing.T) {
	var r SigRecord
	buf := make([]byte, ResourceRecordSize+10)
	binary.BigEndian.PutUint16(buf[0:2], uint16(RRTypeSig))
	binary.BigEndian.PutUint16(buf[2:4], uint16(ClassAny))
	if err := r.UnmarshalBinary(buf); err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// OptRecord
// ---------------------------------------------------------------------------

func TestOptRecordInit(t *testing.T) {
	var r OptRecord
	r.Init()
	if r.Type != RRTypeOpt {
		t.Errorf("Type: got %d", r.Type)
	}
	if r.TTL != 0 {
		t.Error("TTL should be zero after Init")
	}
}

func TestOptRecordUDPPayloadSize(t *testing.T) {
	var r OptRecord
	r.Init()
	r.SetUDPPayloadSize(4096)
	if r.GetUDPPayloadSize() != 4096 {
		t.Errorf("UDPPayloadSize: got %d", r.GetUDPPayloadSize())
	}
}

func TestOptRecordExtendedResponseCode(t *testing.T) {
	var r OptRecord
	r.Init()
	r.SetExtendedResponseCode(0xAB)
	if r.GetExtendedResponseCode() != 0xAB {
		t.Errorf("ExtRCode: got 0x%02x", r.GetExtendedResponseCode())
	}
	// Verify other TTL bytes are unaffected.
	if r.GetVersion() != 0 {
		t.Error("Version should still be 0")
	}
}

func TestOptRecordVersion(t *testing.T) {
	var r OptRecord
	r.Init()
	r.SetVersion(1)
	if r.GetVersion() != 1 {
		t.Errorf("Version: got %d", r.GetVersion())
	}
}

func TestOptRecordDnsSecOK(t *testing.T) {
	var r OptRecord
	r.Init()
	if r.IsDnsSecOK() {
		t.Error("DNSSEC OK should be false initially")
	}
	r.SetDnsSecOK(true)
	if !r.IsDnsSecOK() {
		t.Error("DNSSEC OK should be true")
	}
	r.SetDnsSecOK(false)
	if r.IsDnsSecOK() {
		t.Error("DNSSEC OK should be false after clearing")
	}
}

func TestOptRecordTTLFieldIsolation(t *testing.T) {
	// Verify that setting individual TTL sub-fields doesn't corrupt others.
	var r OptRecord
	r.Init()
	r.SetExtendedResponseCode(0x12)
	r.SetVersion(0x34)
	r.SetDnsSecOK(true)

	if r.GetExtendedResponseCode() != 0x12 {
		t.Errorf("ExtRCode: got 0x%02x", r.GetExtendedResponseCode())
	}
	if r.GetVersion() != 0x34 {
		t.Errorf("Version: got 0x%02x", r.GetVersion())
	}
	if !r.IsDnsSecOK() {
		t.Error("DNSSEC OK should be set")
	}
}

func TestOptRecordMarshalUnmarshal(t *testing.T) {
	var r OptRecord
	r.Init()
	r.SetUDPPayloadSize(1232)
	r.SetExtendedResponseCode(0x10)
	r.SetVersion(0)
	r.SetDnsSecOK(true)

	buf := r.MarshalBinary()

	var r2 OptRecord
	if err := r2.UnmarshalBinary(buf[:]); err != nil {
		t.Fatal(err)
	}
	if r2.Type != RRTypeOpt {
		t.Errorf("Type: got %d", r2.Type)
	}
	if r2.GetUDPPayloadSize() != 1232 {
		t.Errorf("UDPPayloadSize: got %d", r2.GetUDPPayloadSize())
	}
	if r2.GetExtendedResponseCode() != 0x10 {
		t.Errorf("ExtRCode: got 0x%02x", r2.GetExtendedResponseCode())
	}
	if !r2.IsDnsSecOK() {
		t.Error("DNSSEC OK should be set")
	}
}

// ---------------------------------------------------------------------------
// Option
// ---------------------------------------------------------------------------

func TestOptionMarshalUnmarshal(t *testing.T) {
	o := Option{Code: 10, Length: 20}
	buf := o.MarshalBinary()
	if len(buf) != OptionSize {
		t.Fatalf("Option size: got %d", len(buf))
	}

	var o2 Option
	if err := o2.UnmarshalBinary(buf[:]); err != nil {
		t.Fatal(err)
	}
	if o2.Code != 10 || o2.Length != 20 {
		t.Errorf("Option mismatch: code=%d length=%d", o2.Code, o2.Length)
	}
	if o2.GetSize() != OptionSize+20 {
		t.Errorf("GetSize: got %d", o2.GetSize())
	}
}

func TestOptionUnmarshalTooShort(t *testing.T) {
	var o Option
	if err := o.UnmarshalBinary(make([]byte, 3)); err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// LeaseOption
// ---------------------------------------------------------------------------

func TestLeaseOptionShort(t *testing.T) {
	var lo LeaseOption
	lo.InitShort(3600)

	if lo.Code != OptionCodeUpdateLease {
		t.Errorf("Code: got %d", lo.Code)
	}
	if !lo.IsShortVariant() {
		t.Error("should be short variant")
	}
	if !lo.IsValid() {
		t.Error("should be valid")
	}
	if lo.LeaseInterval != 3600 {
		t.Errorf("LeaseInterval: got %d", lo.LeaseInterval)
	}
	if lo.KeyLeaseInterval != 3600 {
		t.Errorf("KeyLeaseInterval: got %d (should equal LeaseInterval for short)", lo.KeyLeaseInterval)
	}

	buf := lo.MarshalBinary()
	if len(buf) != OptionSize+4 {
		t.Fatalf("short LeaseOption size: got %d", len(buf))
	}

	var lo2 LeaseOption
	if err := lo2.UnmarshalBinary(buf); err != nil {
		t.Fatal(err)
	}
	if lo2.LeaseInterval != 3600 {
		t.Errorf("LeaseInterval: got %d", lo2.LeaseInterval)
	}
	if lo2.KeyLeaseInterval != 3600 {
		t.Errorf("KeyLeaseInterval: got %d", lo2.KeyLeaseInterval)
	}
}

func TestLeaseOptionLong(t *testing.T) {
	var lo LeaseOption
	lo.InitLong(3600, 7200)

	if lo.IsShortVariant() {
		t.Error("should be long variant")
	}
	if !lo.IsValid() {
		t.Error("should be valid")
	}
	if lo.LeaseInterval != 3600 {
		t.Errorf("LeaseInterval: got %d", lo.LeaseInterval)
	}
	if lo.KeyLeaseInterval != 7200 {
		t.Errorf("KeyLeaseInterval: got %d", lo.KeyLeaseInterval)
	}

	buf := lo.MarshalBinary()
	if len(buf) != OptionSize+8 {
		t.Fatalf("long LeaseOption size: got %d", len(buf))
	}

	var lo2 LeaseOption
	if err := lo2.UnmarshalBinary(buf); err != nil {
		t.Fatal(err)
	}
	if lo2.LeaseInterval != 3600 || lo2.KeyLeaseInterval != 7200 {
		t.Errorf("LeaseOption mismatch: lease=%d keyLease=%d", lo2.LeaseInterval, lo2.KeyLeaseInterval)
	}
}

func TestLeaseOptionIsValid(t *testing.T) {
	tests := []struct {
		name     string
		length   uint16
		lease    uint32
		keyLease uint32
		valid    bool
	}{
		{"short valid", 4, 3600, 3600, true},
		{"long valid equal", 8, 3600, 3600, true},
		{"long valid lease<key", 8, 3600, 7200, true},
		{"long invalid lease>key", 8, 7200, 3600, false},
		{"invalid length 3", 3, 0, 0, false},
		{"invalid length 5", 5, 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lo := LeaseOption{
				Option:           Option{Code: OptionCodeUpdateLease, Length: tt.length},
				LeaseInterval:    tt.lease,
				KeyLeaseInterval: tt.keyLease,
			}
			if lo.IsValid() != tt.valid {
				t.Errorf("IsValid(): got %v, want %v", lo.IsValid(), tt.valid)
			}
		})
	}
}

func TestLeaseOptionUnmarshalTooShort(t *testing.T) {
	// Valid header but not enough data for lease interval.
	buf := make([]byte, OptionSize+2)
	binary.BigEndian.PutUint16(buf[0:2], OptionCodeUpdateLease)
	binary.BigEndian.PutUint16(buf[2:4], 4) // length=4 but only 2 bytes of data
	var lo LeaseOption
	if err := lo.UnmarshalBinary(buf); err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// FindLeaseOption
// ---------------------------------------------------------------------------

func TestFindLeaseOption(t *testing.T) {
	// Build OPT RDATA with a non-lease option followed by a lease option.
	var rdata []byte

	// Option 1: code=99, length=2, data=[0xAA, 0xBB].
	rdata = binary.BigEndian.AppendUint16(rdata, 99)
	rdata = binary.BigEndian.AppendUint16(rdata, 2)
	rdata = append(rdata, 0xAA, 0xBB)

	// Option 2: UpdateLease, long variant.
	var lo LeaseOption
	lo.InitLong(1800, 3600)
	rdata = append(rdata, lo.MarshalBinary()...)

	found, err := FindLeaseOption(rdata)
	if err != nil {
		t.Fatal(err)
	}
	if found == nil {
		t.Fatal("expected to find lease option")
	}
	if found.LeaseInterval != 1800 || found.KeyLeaseInterval != 3600 {
		t.Errorf("lease=%d keyLease=%d", found.LeaseInterval, found.KeyLeaseInterval)
	}
}

func TestFindLeaseOptionNotFound(t *testing.T) {
	// Build OPT RDATA with only non-lease options.
	var rdata []byte
	rdata = binary.BigEndian.AppendUint16(rdata, 99)
	rdata = binary.BigEndian.AppendUint16(rdata, 2)
	rdata = append(rdata, 0xAA, 0xBB)

	_, err := FindLeaseOption(rdata)
	if err != errors.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestFindLeaseOptionEmpty(t *testing.T) {
	_, err := FindLeaseOption(nil)
	if err != errors.ErrNotFound {
		t.Errorf("expected ErrNotFound for empty data, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// NsecRecord
// ---------------------------------------------------------------------------

func TestNsecRecordInit(t *testing.T) {
	var r NsecRecord
	r.Init(ClassInternet)
	if r.Type != RRTypeNsec {
		t.Errorf("Type: got %d", r.Type)
	}
}

// ---------------------------------------------------------------------------
// TypeBitMap
// ---------------------------------------------------------------------------

func TestTypeBitMapAddAndContains(t *testing.T) {
	var tbm TypeBitMap
	tbm.BlockNumber = 0

	// Add some types.
	tbm.AddType(RRTypeA)    // 1
	tbm.AddType(RRTypeAaaa) // 28
	tbm.AddType(RRTypeSrv)  // 33
	tbm.AddType(RRTypeTxt)  // 16
	tbm.AddType(RRTypePtr)  // 12

	// Verify they are present.
	for _, rt := range []RRType{RRTypeA, RRTypeAaaa, RRTypeSrv, RRTypeTxt, RRTypePtr} {
		if !tbm.ContainsType(rt) {
			t.Errorf("ContainsType(%d): expected true", rt)
		}
	}

	// Verify absent types.
	for _, rt := range []RRType{RRTypeSoa, RRTypeMx, RRTypeNs} {
		if tbm.ContainsType(rt) {
			t.Errorf("ContainsType(%d): expected false", rt)
		}
	}
}

func TestTypeBitMapBlockNumber(t *testing.T) {
	var tbm TypeBitMap
	tbm.BlockNumber = 0

	// Type 256 is in block 1, should be ignored for block 0.
	tbm.AddType(RRType(256))
	if tbm.BitmapLength != 0 {
		t.Error("adding type from wrong block should have no effect")
	}

	// Type 256 in block 1.
	tbm.BlockNumber = 1
	tbm.AddType(RRType(256))
	if !tbm.ContainsType(RRType(256)) {
		t.Error("ContainsType(256) should be true in block 1")
	}
}

func TestTypeBitMapBitmapLength(t *testing.T) {
	var tbm TypeBitMap
	tbm.BlockNumber = 0

	// Type A (1) is bit 1 in byte 0 => BitmapLength = 1.
	tbm.AddType(RRTypeA)
	if tbm.BitmapLength != 1 {
		t.Errorf("BitmapLength after adding A: got %d, want 1", tbm.BitmapLength)
	}

	// Type SRV (33) is bit 1 in byte 4 => BitmapLength = 5.
	tbm.AddType(RRTypeSrv)
	if tbm.BitmapLength != 5 {
		t.Errorf("BitmapLength after adding SRV: got %d, want 5", tbm.BitmapLength)
	}
}

func TestTypeBitMapBitOrdering(t *testing.T) {
	var tbm TypeBitMap
	tbm.BlockNumber = 0

	// Type 0 should be bit 7 of byte 0 (mask 0x80).
	tbm.AddType(RRType(0))
	if tbm.Bitmaps[0] != 0x80 {
		t.Errorf("Type 0: byte[0] = 0x%02x, want 0x80", tbm.Bitmaps[0])
	}

	// Type 7 should be bit 0 of byte 0 (mask 0x01).
	tbm.AddType(RRType(7))
	if tbm.Bitmaps[0] != 0x81 {
		t.Errorf("Type 0+7: byte[0] = 0x%02x, want 0x81", tbm.Bitmaps[0])
	}

	// Type 8 should be bit 7 of byte 1 (mask 0x80).
	tbm.AddType(RRType(8))
	if tbm.Bitmaps[1] != 0x80 {
		t.Errorf("Type 8: byte[1] = 0x%02x, want 0x80", tbm.Bitmaps[1])
	}
}

func TestTypeBitMapMarshalUnmarshal(t *testing.T) {
	var tbm TypeBitMap
	tbm.BlockNumber = 0
	tbm.AddType(RRTypeA)
	tbm.AddType(RRTypeAaaa)
	tbm.AddType(RRTypeSrv)

	buf := tbm.MarshalBinary()
	expectedSize := 2 + int(tbm.BitmapLength)
	if len(buf) != expectedSize {
		t.Fatalf("TypeBitMap size: got %d, want %d", len(buf), expectedSize)
	}
	if buf[0] != 0 {
		t.Errorf("BlockNumber: got %d", buf[0])
	}

	var tbm2 TypeBitMap
	if err := tbm2.UnmarshalBinary(buf); err != nil {
		t.Fatal(err)
	}
	if tbm2.BlockNumber != 0 {
		t.Errorf("BlockNumber: got %d", tbm2.BlockNumber)
	}
	for _, rt := range []RRType{RRTypeA, RRTypeAaaa, RRTypeSrv} {
		if !tbm2.ContainsType(rt) {
			t.Errorf("ContainsType(%d): expected true after unmarshal", rt)
		}
	}
	if tbm2.ContainsType(RRTypeTxt) {
		t.Error("ContainsType(TXT): expected false after unmarshal")
	}
}

func TestTypeBitMapUnmarshalTooShort(t *testing.T) {
	var tbm TypeBitMap
	if err := tbm.UnmarshalBinary([]byte{0}); err != errors.ErrParse {
		t.Errorf("expected ErrParse for 1-byte data, got %v", err)
	}
}

func TestTypeBitMapUnmarshalZeroLength(t *testing.T) {
	var tbm TypeBitMap
	if err := tbm.UnmarshalBinary([]byte{0, 0}); err != errors.ErrParse {
		t.Errorf("expected ErrParse for zero BitmapLength, got %v", err)
	}
}

func TestTypeBitMapUnmarshalTruncated(t *testing.T) {
	var tbm TypeBitMap
	// BitmapLength=5 but only 2 bytes of bitmap.
	if err := tbm.UnmarshalBinary([]byte{0, 5, 0xFF, 0xFF}); err != errors.ErrParse {
		t.Errorf("expected ErrParse for truncated bitmap, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TxtEntry
// ---------------------------------------------------------------------------

func TestTxtEntryAppendToKeyValue(t *testing.T) {
	e := TxtEntry{Key: "name", Value: []byte("GoThread")}
	buf, err := e.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Expected: len("name=GoThread") = 13, so [13, 'n', 'a', 'm', 'e', '=', 'G', 'o', ...]
	if len(buf) == 0 {
		t.Fatal("empty buffer")
	}
	if buf[0] != 13 {
		t.Errorf("length byte: got %d, want 13", buf[0])
	}
	if string(buf[1:]) != "name=GoThread" {
		t.Errorf("entry: got %q", string(buf[1:]))
	}
}

func TestTxtEntryAppendToBoolean(t *testing.T) {
	e := TxtEntry{Key: "enabled", Value: nil}
	buf, err := e.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	if buf[0] != 7 {
		t.Errorf("length byte: got %d, want 7", buf[0])
	}
	if string(buf[1:]) != "enabled" {
		t.Errorf("entry: got %q", string(buf[1:]))
	}
}

func TestTxtEntryAppendToEmptyValue(t *testing.T) {
	e := TxtEntry{Key: "key", Value: []byte{}}
	buf, err := e.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	// "key=" => length 4.
	if buf[0] != 4 {
		t.Errorf("length byte: got %d, want 4", buf[0])
	}
	if string(buf[1:]) != "key=" {
		t.Errorf("entry: got %q", string(buf[1:]))
	}
}

func TestTxtEntryAppendToPreEncoded(t *testing.T) {
	preEncoded := []byte{3, 'a', '=', 'b'}
	e := TxtEntry{Key: "", Value: preEncoded}
	buf, err := e.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(buf) != len(preEncoded) {
		t.Errorf("pre-encoded length: got %d, want %d", len(buf), len(preEncoded))
	}
}

func TestTxtEntryAppendToEmptyKey(t *testing.T) {
	e := TxtEntry{Key: "", Value: nil}
	buf, err := e.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Empty key + nil value => nothing appended.
	if len(buf) != 0 {
		t.Errorf("expected empty buffer, got %d bytes", len(buf))
	}
}

func TestAppendTxtEntriesEmpty(t *testing.T) {
	buf, err := AppendTxtEntries(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Should produce a single zero byte per RFC 6763.
	if len(buf) != 1 || buf[0] != 0 {
		t.Errorf("expected single zero byte, got %v", buf)
	}
}

func TestAppendTxtEntriesMultiple(t *testing.T) {
	entries := []TxtEntry{
		{Key: "a", Value: []byte("1")},
		{Key: "b", Value: []byte("2")},
	}
	buf, err := AppendTxtEntries(nil, entries)
	if err != nil {
		t.Fatal(err)
	}
	// "a=1" => [3, 'a', '=', '1'], "b=2" => [3, 'b', '=', '2']
	if len(buf) != 8 {
		t.Errorf("expected 8 bytes, got %d", len(buf))
	}
	if !VerifyTxtData(buf, false) {
		t.Error("TXT data verification failed")
	}
}

// ---------------------------------------------------------------------------
// TxtIterator
// ---------------------------------------------------------------------------

func TestTxtIteratorKeyValue(t *testing.T) {
	data := []byte{3, 'a', '=', 'b', 5, 'c', '=', 'd', 'e', 'f'}
	it := NewTxtIterator(data)

	e1, err := it.Next()
	if err != nil {
		t.Fatal(err)
	}
	if e1.Key != "a" || string(e1.Value) != "b" {
		t.Errorf("entry 1: key=%q value=%q", e1.Key, string(e1.Value))
	}

	e2, err := it.Next()
	if err != nil {
		t.Fatal(err)
	}
	if e2.Key != "c" || string(e2.Value) != "def" {
		t.Errorf("entry 2: key=%q value=%q", e2.Key, string(e2.Value))
	}

	_, err = it.Next()
	if err != errors.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestTxtIteratorBoolean(t *testing.T) {
	data := []byte{4, 'f', 'l', 'a', 'g'}
	it := NewTxtIterator(data)

	e, err := it.Next()
	if err != nil {
		t.Fatal(err)
	}
	if e.Key != "flag" || e.Value != nil {
		t.Errorf("boolean entry: key=%q value=%v", e.Key, e.Value)
	}
}

func TestTxtIteratorSkipsEmpty(t *testing.T) {
	// Empty entry (length 0) followed by a real entry.
	data := []byte{0, 3, 'a', '=', 'b'}
	it := NewTxtIterator(data)

	e, err := it.Next()
	if err != nil {
		t.Fatal(err)
	}
	if e.Key != "a" {
		t.Errorf("key: got %q", e.Key)
	}
}

func TestTxtIteratorSkipsLeadingEquals(t *testing.T) {
	// Entry starting with '=' followed by a real entry.
	data := []byte{2, '=', 'x', 3, 'a', '=', 'b'}
	it := NewTxtIterator(data)

	e, err := it.Next()
	if err != nil {
		t.Fatal(err)
	}
	if e.Key != "a" {
		t.Errorf("key: got %q", e.Key)
	}
}

func TestTxtIteratorTruncated(t *testing.T) {
	// Length byte says 10, but only 3 bytes follow.
	data := []byte{10, 'a', 'b', 'c'}
	it := NewTxtIterator(data)

	_, err := it.Next()
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

func TestTxtIteratorEmpty(t *testing.T) {
	it := NewTxtIterator(nil)
	_, err := it.Next()
	if err != errors.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestTxtIteratorRoundTrip(t *testing.T) {
	entries := []TxtEntry{
		{Key: "name", Value: []byte("GoThread")},
		{Key: "version", Value: []byte("1.0")},
		{Key: "debug", Value: nil},      // boolean
		{Key: "empty", Value: []byte{}}, // empty value
	}

	buf, err := AppendTxtEntries(nil, entries)
	if err != nil {
		t.Fatal(err)
	}

	it := NewTxtIterator(buf)

	e1, err := it.Next()
	if err != nil {
		t.Fatal(err)
	}
	if e1.Key != "name" || string(e1.Value) != "GoThread" {
		t.Errorf("entry 1: key=%q value=%q", e1.Key, string(e1.Value))
	}

	e2, err := it.Next()
	if err != nil {
		t.Fatal(err)
	}
	if e2.Key != "version" || string(e2.Value) != "1.0" {
		t.Errorf("entry 2: key=%q value=%q", e2.Key, string(e2.Value))
	}

	e3, err := it.Next()
	if err != nil {
		t.Fatal(err)
	}
	if e3.Key != "debug" || e3.Value != nil {
		t.Errorf("entry 3: key=%q value=%v", e3.Key, e3.Value)
	}

	e4, err := it.Next()
	if err != nil {
		t.Fatal(err)
	}
	if e4.Key != "empty" || len(e4.Value) != 0 {
		t.Errorf("entry 4: key=%q value=%q", e4.Key, string(e4.Value))
	}

	_, err = it.Next()
	if err != errors.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// SkipName
// ---------------------------------------------------------------------------

func TestSkipName(t *testing.T) {
	// Encode "example.com" and verify SkipName returns correct offset.
	var buf []byte
	buf, err := AppendName(buf, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Append some trailing data.
	buf = append(buf, 0xDE, 0xAD)

	offset, err := SkipName(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	// offset should point past the name terminator.
	expectedLen := len(buf) - 2 // trailing 2 bytes not part of name
	if offset != expectedLen {
		t.Errorf("SkipName offset: got %d, want %d", offset, expectedLen)
	}
}

func TestSkipNameWithPointer(t *testing.T) {
	// Build: "com." at offset 0, then pointer to offset 0 at offset 5.
	var buf []byte
	buf, _ = AppendName(buf, "com")
	// Now buf = [3, 'c', 'o', 'm', 0].
	// Append a label "foo" then pointer to offset 0 (the "com." part).
	buf, _ = AppendLabel(buf, "foo")
	buf, _ = AppendPointerLabel(buf, 0)

	// Skip the second name starting at offset 5.
	offset, err := SkipName(buf, 5)
	if err != nil {
		t.Fatal(err)
	}
	// The second name is: [3, 'f', 'o', 'o', 0xC0, 0x00] => 6 bytes.
	if offset != 5+6 {
		t.Errorf("SkipName with pointer: got %d, want %d", offset, 5+6)
	}
}

func TestSkipNameInvalidOffset(t *testing.T) {
	_, err := SkipName([]byte{0}, 5)
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// ParseRecords
// ---------------------------------------------------------------------------

func TestParseRecords(t *testing.T) {
	// Build a message with 2 records:
	// Record 1: name="a.com", type=A, class=IN, TTL=0, RDLength=4, RDATA=4 bytes
	// Record 2: name="b.com", type=AAAA, class=IN, TTL=0, RDLength=16, RDATA=16 bytes
	var buf []byte

	// Record 1.
	buf, _ = AppendName(buf, "a.com")
	rr1 := ResourceRecord{Type: RRTypeA, Class: ClassInternet, TTL: 0, RDLength: 4}
	b1 := rr1.MarshalBinary()
	buf = append(buf, b1[:]...)
	buf = append(buf, 1, 2, 3, 4) // RDATA

	// Record 2.
	buf, _ = AppendName(buf, "b.com")
	rr2 := ResourceRecord{Type: RRTypeAaaa, Class: ClassInternet, TTL: 0, RDLength: 16}
	b2 := rr2.MarshalBinary()
	buf = append(buf, b2[:]...)
	buf = append(buf, make([]byte, 16)...) // RDATA

	offset, err := ParseRecords(buf, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if offset != len(buf) {
		t.Errorf("ParseRecords offset: got %d, want %d", offset, len(buf))
	}
}

func TestParseRecordsTruncated(t *testing.T) {
	// Build one record but claim there are 2.
	var buf []byte
	buf, _ = AppendName(buf, "a.com")
	rr := ResourceRecord{Type: RRTypeA, Class: ClassInternet, TTL: 0, RDLength: 4}
	b := rr.MarshalBinary()
	buf = append(buf, b[:]...)
	buf = append(buf, 1, 2, 3, 4)

	_, err := ParseRecords(buf, 0, 2)
	if err == nil {
		t.Error("expected error for truncated records")
	}
}

// ---------------------------------------------------------------------------
// Constants coverage
// ---------------------------------------------------------------------------

func TestRRTypeConstants(t *testing.T) {
	types := map[RRType]uint16{
		RRTypeZero: 0, RRTypeA: 1, RRTypeNs: 2, RRTypeCname: 5,
		RRTypeSoa: 6, RRTypePtr: 12, RRTypeMx: 15, RRTypeTxt: 16,
		RRTypeRp: 17, RRTypeAfsdb: 18, RRTypeRt: 21, RRTypeSig: 24,
		RRTypeKey: 25, RRTypePx: 26, RRTypeAaaa: 28, RRTypeSrv: 33,
		RRTypeKx: 36, RRTypeDname: 39, RRTypeOpt: 41, RRTypeNsec: 47,
		RRTypeAny: 255,
	}
	for k, v := range types {
		if uint16(k) != v {
			t.Errorf("RRType %d != expected %d", k, v)
		}
	}
}

func TestClassConstants(t *testing.T) {
	if ClassInternet != 1 || ClassNone != 254 || ClassAny != 255 {
		t.Error("class constants mismatch")
	}
}

func TestKeyProtocolConstants(t *testing.T) {
	if KeyProtocolTls != 1 || KeyProtocolDnsSec != 3 {
		t.Error("key protocol constants mismatch")
	}
}

func TestKeyAlgorithmConstants(t *testing.T) {
	if KeyAlgorithmEcdsaP256Sha256 != 13 || KeyAlgorithmEcdsaP384Sha384 != 14 ||
		KeyAlgorithmEd25519 != 15 || KeyAlgorithmEd448 != 16 {
		t.Error("key algorithm constants mismatch")
	}
}
