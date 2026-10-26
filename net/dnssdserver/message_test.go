// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package dnssdserver

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// ParseDnsQuery tests
// ---------------------------------------------------------------------------

func TestParseDnsQueryTooShort(t *testing.T) {
	for _, size := range []int{0, 1, 6, 11} {
		data := make([]byte, size)
		_, err := ParseDnsQuery(data)
		if err == nil {
			t.Errorf("ParseDnsQuery(len=%d): expected error, got nil", size)
		}
	}
}

func TestParseDnsQueryRejectsResponse(t *testing.T) {
	// Build a header with QR bit set (response).
	var header [headerSize]byte
	binary.BigEndian.PutUint16(header[2:4], flagQR)
	_, err := ParseDnsQuery(header[:])
	if err == nil {
		t.Error("expected error for response message, got nil")
	}
}

func TestParseDnsQueryRecursionDesired(t *testing.T) {
	tests := []struct {
		name string
		rd   bool
	}{
		{"with RD", true},
		{"without RD", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var header [headerSize]byte
			flags := uint16(0)
			if tt.rd {
				flags |= flagRD
			}
			binary.BigEndian.PutUint16(header[2:4], flags)
			// Zero questions.
			q, err := ParseDnsQuery(header[:])
			if err != nil {
				t.Fatalf("ParseDnsQuery: %v", err)
			}
			if q.IsRecursionDesired != tt.rd {
				t.Errorf("IsRecursionDesired = %v, want %v", q.IsRecursionDesired, tt.rd)
			}
		})
	}
}

func TestParseDnsQueryTruncatedQuestion(t *testing.T) {
	// Header claiming 1 question but no question data.
	var header [headerSize]byte
	binary.BigEndian.PutUint16(header[4:6], 1) // qdCount = 1
	_, err := ParseDnsQuery(header[:])
	if err == nil {
		t.Error("expected error for truncated question")
	}
}

func TestParseDnsQueryTruncatedQuestionFields(t *testing.T) {
	// Header + valid name but missing type/class fields.
	var header [headerSize]byte
	binary.BigEndian.PutUint16(header[4:6], 1)
	name := EncodeDnsName("example.com.")
	data := append(header[:], name...)
	// Add only 2 bytes instead of 4 for type+class.
	data = append(data, 0x00, 0x01)

	_, err := ParseDnsQuery(data)
	if err == nil {
		t.Error("expected error for truncated question type/class fields")
	}
}

func TestParseDnsQueryPreservesID(t *testing.T) {
	ids := []uint16{0x0000, 0xFFFF, 0x1234, 0xABCD}
	for _, id := range ids {
		var header [headerSize]byte
		binary.BigEndian.PutUint16(header[0:2], id)
		q, err := ParseDnsQuery(header[:])
		if err != nil {
			t.Fatalf("ParseDnsQuery(id=0x%04X): %v", id, err)
		}
		if q.ID != id {
			t.Errorf("ID = 0x%04X, want 0x%04X", q.ID, id)
		}
	}
}

// ---------------------------------------------------------------------------
// EncodeDnsName tests
// ---------------------------------------------------------------------------

func TestEncodeDnsNameTrailingDot(t *testing.T) {
	// With and without trailing dot should produce the same encoding.
	a := EncodeDnsName("example.com.")
	b := EncodeDnsName("example.com")
	if !bytes.Equal(a, b) {
		t.Errorf("encoding differs for trailing dot:\n  with:    %v\n  without: %v", a, b)
	}
}

func TestEncodeDnsNameRootOnly(t *testing.T) {
	encoded := EncodeDnsName(".")
	// Trailing dot removed → empty name → single zero byte.
	if !bytes.Equal(encoded, []byte{0}) {
		t.Errorf("EncodeDnsName(\".\") = %v, want [0]", encoded)
	}
}

func TestEncodeDnsNameSingleLabel(t *testing.T) {
	encoded := EncodeDnsName("localhost")
	// Expected: [9, 'l','o','c','a','l','h','o','s','t', 0]
	expected := append([]byte{9}, []byte("localhost")...)
	expected = append(expected, 0)
	if !bytes.Equal(encoded, expected) {
		t.Errorf("EncodeDnsName(\"localhost\") = %v, want %v", encoded, expected)
	}
}

func TestEncodeDnsNameMaxLabelLength(t *testing.T) {
	label := strings.Repeat("x", 63)
	encoded := EncodeDnsName(label + ".com.")
	if encoded[0] != 63 {
		t.Errorf("first label length byte = %d, want 63", encoded[0])
	}
}

func TestEncodeDnsNameServiceInstance(t *testing.T) {
	name := "My Printer._ipp._tcp.default.service.arpa."
	encoded := EncodeDnsName(name)
	// Verify first label is "My Printer" (length 10).
	if encoded[0] != 10 {
		t.Errorf("first label length = %d, want 10", encoded[0])
	}
	if string(encoded[1:11]) != "My Printer" {
		t.Errorf("first label = %q, want %q", string(encoded[1:11]), "My Printer")
	}
	// Must end with a zero byte.
	if encoded[len(encoded)-1] != 0 {
		t.Error("encoded name must end with zero byte")
	}
}

// ---------------------------------------------------------------------------
// DecodeDnsName tests
// ---------------------------------------------------------------------------

func TestDecodeDnsNameOutOfBounds(t *testing.T) {
	_, _, err := DecodeDnsName([]byte{}, 0)
	if err == nil {
		t.Error("expected error for empty data")
	}

	_, _, err = DecodeDnsName([]byte{0}, 5)
	if err == nil {
		t.Error("expected error for offset beyond data")
	}
}

func TestDecodeDnsNameInvalidLabelType(t *testing.T) {
	// 0x40 and 0x80 are reserved label types (not pointer 0xC0).
	for _, b := range []byte{0x40, 0x80} {
		data := []byte{b, 0x00}
		_, _, err := DecodeDnsName(data, 0)
		if err == nil {
			t.Errorf("expected error for label type 0x%02X", b)
		}
	}
}

func TestDecodeDnsNameTruncatedPointer(t *testing.T) {
	// Pointer byte but no second byte.
	data := []byte{0xC0}
	_, _, err := DecodeDnsName(data, 0)
	if err == nil {
		t.Error("expected error for truncated pointer")
	}
}

func TestDecodeDnsNameMultipleLabels(t *testing.T) {
	data := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	name, end, err := DecodeDnsName(data, 0)
	if err != nil {
		t.Fatalf("DecodeDnsName: %v", err)
	}
	if name != "www.example.com." {
		t.Errorf("name = %q, want %q", name, "www.example.com.")
	}
	if end != len(data) {
		t.Errorf("end = %d, want %d", end, len(data))
	}
}

func TestDecodeDnsNameAtOffset(t *testing.T) {
	// Place some padding before the name.
	padding := []byte{0xFF, 0xFF, 0xFF}
	name := EncodeDnsName("test.local.")
	data := append([]byte{0xFF, 0xFF, 0xFF}, name...)

	decoded, end, err := DecodeDnsName(data, len(padding))
	if err != nil {
		t.Fatalf("DecodeDnsName at offset: %v", err)
	}
	if decoded != "test.local." {
		t.Errorf("decoded = %q, want %q", decoded, "test.local.")
	}
	if end != len(data) {
		t.Errorf("end = %d, want %d", end, len(data))
	}
}

func TestDecodeDnsNamePointerToMiddle(t *testing.T) {
	// Build: "example.com." then a pointer that points to "com." portion.
	data := []byte{
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // offset 0: "example"
		3, 'c', 'o', 'm', // offset 8: "com"
		0,                // offset 12: root
		3, 'f', 'o', 'o', // offset 13: "foo"
		0xC0, 8, // offset 17: pointer to offset 8 ("com.")
	}

	name, end, err := DecodeDnsName(data, 13)
	if err != nil {
		t.Fatalf("DecodeDnsName: %v", err)
	}
	if name != "foo.com." {
		t.Errorf("name = %q, want %q", name, "foo.com.")
	}
	if end != 19 {
		t.Errorf("end = %d, want 19", end)
	}
}

func TestDecodeDnsNameChainedPointers(t *testing.T) {
	// offset 0: "com." (label + root)
	// offset 5: pointer to 0 ("com.")
	// offset 7: "foo" + pointer to 5 → resolves to "foo.com."
	data := []byte{
		3, 'c', 'o', 'm', 0, // offset 0-4
		0xC0, 0x00, // offset 5-6: ptr → 0
		3, 'f', 'o', 'o', 0xC0, 0x05, // offset 7-12: "foo" + ptr → 5
	}

	name, end, err := DecodeDnsName(data, 7)
	if err != nil {
		t.Fatalf("DecodeDnsName: %v", err)
	}
	if name != "foo.com." {
		t.Errorf("name = %q, want %q", name, "foo.com.")
	}
	if end != 13 {
		t.Errorf("end = %d, want 13", end)
	}
}

func TestDecodeDnsNameMutualPointerLoop(t *testing.T) {
	// Two pointers pointing at each other.
	data := []byte{0xC0, 0x02, 0xC0, 0x00}
	_, _, err := DecodeDnsName(data, 0)
	if err == nil {
		t.Error("expected error for mutual pointer loop")
	}
}

func TestDecodeDnsNameTruncatedLabel(t *testing.T) {
	// Label says length 5 but only 3 bytes follow.
	data := []byte{5, 'a', 'b', 'c'}
	_, _, err := DecodeDnsName(data, 0)
	if err == nil {
		t.Error("expected error for truncated label data")
	}
}

// ---------------------------------------------------------------------------
// Encode/Decode round-trip tests
// ---------------------------------------------------------------------------

func TestDnsNameRoundTripVariousNames(t *testing.T) {
	names := []string{
		"a.b.c.d.e.",
		"_http._tcp.local.",
		"My Device._matter._tcp.default.service.arpa.",
		strings.Repeat("a", 10) + "." + strings.Repeat("b", 20) + "." + strings.Repeat("c", 30) + ".",
	}
	for _, name := range names {
		encoded := EncodeDnsName(name)
		decoded, end, err := DecodeDnsName(encoded, 0)
		if err != nil {
			t.Errorf("round-trip %q: decode error: %v", name, err)
			continue
		}
		if decoded != name {
			t.Errorf("round-trip: decoded %q, want %q", decoded, name)
		}
		if end != len(encoded) {
			t.Errorf("round-trip %q: end = %d, want %d", name, end, len(encoded))
		}
	}
}

// ---------------------------------------------------------------------------
// BuildDnsResponse tests
// ---------------------------------------------------------------------------

func TestBuildDnsResponseEmptyAnswers(t *testing.T) {
	q := &DnsQuery{
		ID: 0x0001,
		Questions: []DnsQuestion{
			{Name: "test.local.", Type: TypeAAAA, Class: ClassIN},
		},
	}
	resp, err := BuildDnsResponse(q, nil, nil, nil, RCodeNameError)
	if err != nil {
		t.Fatalf("BuildDnsResponse: %v", err)
	}
	if len(resp) < headerSize {
		t.Fatalf("response too short: %d", len(resp))
	}

	// Verify header.
	id := binary.BigEndian.Uint16(resp[0:2])
	flags := binary.BigEndian.Uint16(resp[2:4])
	anCount := binary.BigEndian.Uint16(resp[6:8])
	rcode := uint8(flags & flagRCode)

	if id != 0x0001 {
		t.Errorf("id = 0x%04X, want 0x0001", id)
	}
	if flags&flagQR == 0 {
		t.Error("QR bit not set")
	}
	if flags&flagAA == 0 {
		t.Error("AA bit not set")
	}
	if rcode != RCodeNameError {
		t.Errorf("rcode = %d, want %d", rcode, RCodeNameError)
	}
	if anCount != 0 {
		t.Errorf("anCount = %d, want 0", anCount)
	}
}

func TestBuildDnsResponseRecursionDesiredEcho(t *testing.T) {
	q := &DnsQuery{
		ID:                 0x0002,
		IsRecursionDesired: true,
		Questions: []DnsQuestion{
			{Name: "a.local.", Type: TypeA, Class: ClassIN},
		},
	}
	resp, err := BuildDnsResponse(q, nil, nil, nil, RCodeSuccess)
	if err != nil {
		t.Fatalf("BuildDnsResponse: %v", err)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&flagRD == 0 {
		t.Error("RD bit not echoed in response")
	}

	// Without RD.
	q.IsRecursionDesired = false
	resp, err = BuildDnsResponse(q, nil, nil, nil, RCodeSuccess)
	if err != nil {
		t.Fatalf("BuildDnsResponse: %v", err)
	}
	flags = binary.BigEndian.Uint16(resp[2:4])
	if flags&flagRD != 0 {
		t.Error("RD bit should not be set when not desired")
	}
}

func TestBuildDnsResponseSectionCounts(t *testing.T) {
	q := &DnsQuery{
		ID: 0x0003,
		Questions: []DnsQuestion{
			{Name: "a.local.", Type: TypePTR, Class: ClassIN},
			{Name: "b.local.", Type: TypePTR, Class: ClassIN},
		},
	}
	answers := []DnsRecord{
		{Name: "a.local.", Type: TypePTR, Class: ClassIN, TTL: 60, RData: EncodePtrRData("svc.a.local.")},
	}
	authorities := []DnsRecord{
		{Name: "local.", Type: TypeNS, Class: ClassIN, TTL: 60, RData: EncodeDnsName("ns.local.")},
		{Name: "local.", Type: TypeNS, Class: ClassIN, TTL: 60, RData: EncodeDnsName("ns2.local.")},
	}
	additional := []DnsRecord{
		{Name: "ns.local.", Type: TypeAAAA, Class: ClassIN, TTL: 60, RData: make([]byte, 16)},
		{Name: "ns2.local.", Type: TypeAAAA, Class: ClassIN, TTL: 60, RData: make([]byte, 16)},
		{Name: "svc.a.local.", Type: TypeAAAA, Class: ClassIN, TTL: 60, RData: make([]byte, 16)},
	}

	resp, err := BuildDnsResponse(q, answers, authorities, additional, RCodeSuccess)
	if err != nil {
		t.Fatalf("BuildDnsResponse: %v", err)
	}

	qdCount := binary.BigEndian.Uint16(resp[4:6])
	anCount := binary.BigEndian.Uint16(resp[6:8])
	nsCount := binary.BigEndian.Uint16(resp[8:10])
	arCount := binary.BigEndian.Uint16(resp[10:12])

	if qdCount != 2 {
		t.Errorf("qdCount = %d, want 2", qdCount)
	}
	if anCount != 1 {
		t.Errorf("anCount = %d, want 1", anCount)
	}
	if nsCount != 2 {
		t.Errorf("nsCount = %d, want 2", nsCount)
	}
	if arCount != 3 {
		t.Errorf("arCount = %d, want 3", arCount)
	}
}

func TestBuildDnsResponseRCodeValues(t *testing.T) {
	q := &DnsQuery{ID: 0x0004}
	for _, rc := range []uint8{RCodeSuccess, RCodeFormatError, RCodeServerFailure, RCodeNameError, RCodeNotImplemented, RCodeRefused} {
		resp, err := BuildDnsResponse(q, nil, nil, nil, rc)
		if err != nil {
			t.Fatalf("BuildDnsResponse(rcode=%d): %v", rc, err)
		}
		flags := binary.BigEndian.Uint16(resp[2:4])
		got := uint8(flags & flagRCode)
		if got != rc {
			t.Errorf("rcode = %d, want %d", got, rc)
		}
	}
}

func TestBuildDnsResponseRDataIntegrity(t *testing.T) {
	q := &DnsQuery{
		ID: 0x0005,
		Questions: []DnsQuestion{
			{Name: "svc.local.", Type: TypeSRV, Class: ClassIN},
		},
	}
	srvRData := EncodeSrvRData(0, 0, 443, "host.local.")
	answers := []DnsRecord{
		{Name: "svc.local.", Type: TypeSRV, Class: ClassIN, TTL: 300, RData: srvRData},
	}
	resp, err := BuildDnsResponse(q, answers, nil, nil, RCodeSuccess)
	if err != nil {
		t.Fatalf("BuildDnsResponse: %v", err)
	}

	// Parse past header and question to find the answer record.
	offset := headerSize
	// Skip question: name + 4 bytes (type+class).
	_, offset, err = DecodeDnsName(resp, offset)
	if err != nil {
		t.Fatalf("skip question name: %v", err)
	}
	offset += 4 // type + class

	// Parse answer name.
	_, offset, err = DecodeDnsName(resp, offset)
	if err != nil {
		t.Fatalf("decode answer name: %v", err)
	}

	// type(2) + class(2) + ttl(4) + rdlength(2)
	aType := binary.BigEndian.Uint16(resp[offset : offset+2])
	aClass := binary.BigEndian.Uint16(resp[offset+2 : offset+4])
	aTTL := binary.BigEndian.Uint32(resp[offset+4 : offset+8])
	rdLen := binary.BigEndian.Uint16(resp[offset+8 : offset+10])
	offset += 10

	if aType != TypeSRV {
		t.Errorf("answer type = %d, want %d", aType, TypeSRV)
	}
	if aClass != ClassIN {
		t.Errorf("answer class = %d, want %d", aClass, ClassIN)
	}
	if aTTL != 300 {
		t.Errorf("answer TTL = %d, want 300", aTTL)
	}
	if int(rdLen) != len(srvRData) {
		t.Errorf("rdlength = %d, want %d", rdLen, len(srvRData))
	}

	rdata := resp[offset : offset+int(rdLen)]
	if !bytes.Equal(rdata, srvRData) {
		t.Errorf("rdata mismatch")
	}
}

// ---------------------------------------------------------------------------
// EncodePtrRData tests
// ---------------------------------------------------------------------------

func TestEncodePtrRData(t *testing.T) {
	target := "my-service._tcp.local."
	data := EncodePtrRData(target)
	expected := EncodeDnsName(target)
	if !bytes.Equal(data, expected) {
		t.Errorf("EncodePtrRData output differs from EncodeDnsName")
	}

	// Verify round-trip through decode.
	name, _, err := DecodeDnsName(data, 0)
	if err != nil {
		t.Fatalf("DecodeDnsName: %v", err)
	}
	if name != target {
		t.Errorf("decoded = %q, want %q", name, target)
	}
}

// ---------------------------------------------------------------------------
// EncodeSrvRData tests
// ---------------------------------------------------------------------------

func TestEncodeSrvRDataFields(t *testing.T) {
	tests := []struct {
		priority, weight, port uint16
		target                 string
	}{
		{0, 0, 80, "a.local."},
		{10, 20, 443, "secure.host.example.com."},
		{0xFFFF, 0xFFFF, 0xFFFF, "max.values."},
	}
	for _, tt := range tests {
		data := EncodeSrvRData(tt.priority, tt.weight, tt.port, tt.target)
		if len(data) < 6 {
			t.Fatalf("SRV RDATA too short for target %q", tt.target)
		}
		gotP := binary.BigEndian.Uint16(data[0:2])
		gotW := binary.BigEndian.Uint16(data[2:4])
		gotPort := binary.BigEndian.Uint16(data[4:6])
		if gotP != tt.priority {
			t.Errorf("priority = %d, want %d", gotP, tt.priority)
		}
		if gotW != tt.weight {
			t.Errorf("weight = %d, want %d", gotW, tt.weight)
		}
		if gotPort != tt.port {
			t.Errorf("port = %d, want %d", gotPort, tt.port)
		}

		name, _, err := DecodeDnsName(data, 6)
		if err != nil {
			t.Fatalf("decode target: %v", err)
		}
		if name != tt.target {
			t.Errorf("target = %q, want %q", name, tt.target)
		}
	}
}

// ---------------------------------------------------------------------------
// EncodeAAAARData tests
// ---------------------------------------------------------------------------

func TestEncodeAAAARDataLength(t *testing.T) {
	data := EncodeAAAARData([16]byte{})
	if len(data) != 16 {
		t.Errorf("len = %d, want 16", len(data))
	}
}

func TestEncodeAAAARDataPreservesBytes(t *testing.T) {
	addr := [16]byte{
		0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x1b, 0x63, 0xff, 0xfe, 0xa4, 0x3e, 0x01,
	}
	data := EncodeAAAARData(addr)
	for i := range addr {
		if data[i] != addr[i] {
			t.Errorf("byte[%d] = 0x%02x, want 0x%02x", i, data[i], addr[i])
		}
	}
}

func TestEncodeAAAARDataIsCopy(t *testing.T) {
	addr := [16]byte{1, 2, 3}
	data := EncodeAAAARData(addr)
	data[0] = 0xFF
	if addr[0] == 0xFF {
		t.Error("EncodeAAAARData should return a copy, not a reference")
	}
}

// ---------------------------------------------------------------------------
// EncodeTxtRData tests
// ---------------------------------------------------------------------------

func TestEncodeTxtRDataNonEmpty(t *testing.T) {
	txt := []byte{3, 'k', '=', 'v', 5, 'h', 'e', 'l', 'l', 'o'}
	data := EncodeTxtRData(txt)
	if !bytes.Equal(data, txt) {
		t.Errorf("TXT RDATA = %v, want %v", data, txt)
	}
}

func TestEncodeTxtRDataEmpty(t *testing.T) {
	data := EncodeTxtRData(nil)
	if !bytes.Equal(data, []byte{0}) {
		t.Errorf("TXT RDATA for nil = %v, want [0]", data)
	}
	data = EncodeTxtRData([]byte{})
	if !bytes.Equal(data, []byte{0}) {
		t.Errorf("TXT RDATA for empty = %v, want [0]", data)
	}
}

func TestEncodeTxtRDataIsCopy(t *testing.T) {
	txt := []byte{1, 'a'}
	data := EncodeTxtRData(txt)
	data[0] = 0xFF
	if txt[0] == 0xFF {
		t.Error("EncodeTxtRData should return a copy, not a reference")
	}
}

// ---------------------------------------------------------------------------
// Parse → Build round-trip
// ---------------------------------------------------------------------------

func TestParseThenBuildRoundTrip(t *testing.T) {
	// Build a query, parse it, then build a response and verify structure.
	questions := []DnsQuestion{
		{Name: "_http._tcp.default.service.arpa.", Type: TypePTR, Class: ClassIN},
		{Name: "host.default.service.arpa.", Type: TypeAAAA, Class: ClassIN},
	}

	var header [headerSize]byte
	binary.BigEndian.PutUint16(header[0:2], 0xBEEF)
	binary.BigEndian.PutUint16(header[2:4], flagRD)
	binary.BigEndian.PutUint16(header[4:6], uint16(len(questions)))
	queryBuf := append([]byte{}, header[:]...)
	for _, q := range questions {
		queryBuf = append(queryBuf, EncodeDnsName(q.Name)...)
		var qf [4]byte
		binary.BigEndian.PutUint16(qf[0:2], q.Type)
		binary.BigEndian.PutUint16(qf[2:4], q.Class)
		queryBuf = append(queryBuf, qf[:]...)
	}

	parsed, err := ParseDnsQuery(queryBuf)
	if err != nil {
		t.Fatalf("ParseDnsQuery: %v", err)
	}

	answers := []DnsRecord{
		{Name: "_http._tcp.default.service.arpa.", Type: TypePTR, Class: ClassIN, TTL: 120, RData: EncodePtrRData("svc._http._tcp.default.service.arpa.")},
	}

	resp, err := BuildDnsResponse(parsed, answers, nil, nil, RCodeSuccess)
	if err != nil {
		t.Fatalf("BuildDnsResponse: %v", err)
	}

	// Verify response header.
	respID := binary.BigEndian.Uint16(resp[0:2])
	respFlags := binary.BigEndian.Uint16(resp[2:4])
	respQD := binary.BigEndian.Uint16(resp[4:6])
	respAN := binary.BigEndian.Uint16(resp[6:8])

	if respID != 0xBEEF {
		t.Errorf("response ID = 0x%04X, want 0xBEEF", respID)
	}
	if respFlags&flagQR == 0 {
		t.Error("QR bit not set in response")
	}
	if respFlags&flagRD == 0 {
		t.Error("RD bit not echoed in response")
	}
	if respQD != 2 {
		t.Errorf("qdCount = %d, want 2", respQD)
	}
	if respAN != 1 {
		t.Errorf("anCount = %d, want 1", respAN)
	}
}

// ---------------------------------------------------------------------------
// DNS type/class constants
// ---------------------------------------------------------------------------

func TestDnsTypeConstants(t *testing.T) {
	expected := map[string]uint16{
		"A":    1,
		"NS":   2,
		"SOA":  6,
		"PTR":  12,
		"TXT":  16,
		"AAAA": 28,
		"SRV":  33,
		"NSEC": 47,
		"ANY":  255,
	}
	actual := map[string]uint16{
		"A": TypeA, "NS": TypeNS, "SOA": TypeSOA, "PTR": TypePTR,
		"TXT": TypeTXT, "AAAA": TypeAAAA, "SRV": TypeSRV, "NSEC": TypeNSEC,
		"ANY": TypeANY,
	}
	for name, want := range expected {
		if got := actual[name]; got != want {
			t.Errorf("Type%s = %d, want %d", name, got, want)
		}
	}
}

func TestClassINConstant(t *testing.T) {
	if ClassIN != 1 {
		t.Errorf("ClassIN = %d, want 1", ClassIN)
	}
}
