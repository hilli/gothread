// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package dns_test

import (
	"bytes"
	"testing"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/dns"
)

// --- Constants ---

func TestConstants(t *testing.T) {
	if dns.MaxNameSize != 255 {
		t.Errorf("MaxNameSize = %d, want 255", dns.MaxNameSize)
	}
	if dns.MaxLabelSize != 64 {
		t.Errorf("MaxLabelSize = %d, want 64", dns.MaxLabelSize)
	}
}

// --- AppendName / encoding tests ---
// Vectors from OpenThread tests/unit/test_dns.cpp TestDnsName()

func TestAppendName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
	}{
		{"example.com", "example.com", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		{"example.com.", "example.com.", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		{"foo.a.bb.edu", "foo.a.bb.edu", []byte{3, 'f', 'o', 'o', 1, 'a', 2, 'b', 'b', 3, 'e', 'd', 'u', 0}},
		{"foo.a.bb.edu.", "foo.a.bb.edu.", []byte{3, 'f', 'o', 'o', 1, 'a', 2, 'b', 'b', 3, 'e', 'd', 'u', 0}},
		{"foundation", "foundation", []byte{10, 'f', 'o', 'u', 'n', 'd', 'a', 't', 'i', 'o', 'n', 0}},
		{"foundation.", "foundation.", []byte{10, 'f', 'o', 'u', 'n', 'd', 'a', 't', 'i', 'o', 'n', 0}},
		{"empty string", "", []byte{0}},
		{"root dot", ".", []byte{0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dns.AppendName(nil, tt.input)
			if err != nil {
				t.Fatalf("AppendName(nil, %q) returned error: %v", tt.input, err)
			}
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("AppendName(nil, %q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestAppendNameMaxLength(t *testing.T) {
	// Max length name with trailing dot (254 chars + dot = 255 = kMaxNameLength)
	maxWithDot := "HereIsSomeoneHidden.MyHoldFromMeTaken.FromSelfHasMeDriven.MyLeadFromMeTaken." +
		"HereIsSomeoneHidden.AsLifeSweeterThanLife.TakesMeToGardenOfSoul.MyFortFromMeTaken." +
		"HereIsSomeoneHidden.LikeSugarInSugarCane.ASweetSugarTrader.MyShopFromMeTaken." +
		"SorcererAndMagicia."

	// Same without trailing dot (253 chars)
	maxWithoutDot := "HereIsSomeoneHidden.MyHoldFromMeTaken.FromSelfHasMeDriven.MyLeadFromMeTaken." +
		"HereIsSomeoneHidden.AsLifeSweeterThanLife.TakesMeToGardenOfSoul.MyFortFromMeTaken." +
		"HereIsSomeoneHidden.LikeSugarInSugarCane.ASweetSugarTrader.MyShopFromMeTaken." +
		"SorcererAndMagicia"

	for _, name := range []string{maxWithDot, maxWithoutDot} {
		got, err := dns.AppendName(nil, name)
		if err != nil {
			t.Errorf("AppendName(nil, maxName) returned error: %v", err)
		}
		if len(got) != dns.MaxNameSize {
			t.Errorf("AppendName(nil, maxName) encoded length = %d, want %d", len(got), dns.MaxNameSize)
		}
	}
}

func TestAppendNameInvalid(t *testing.T) {
	invalidNames := []struct {
		name  string
		input string
	}{
		{"consecutive dots", "foo..bar"},
		{"double dots", ".."},
		{"trailing double dot", "a.."},
		{"leading double dot", "..b"},
		{"long label", "a.an-invalid-very-long-label-string-with-more-than-sixty-four-characters.com"},
		{
			"long name over 255",
			"HereIsSomeoneHidden.MyHoldFromMeTaken.FromSelfHasMeDriven.MyLeadFromMeTaken." +
				"HereIsSomeoneHidden.AsLifeSweeterThanLife.TakesMeToGardenOfSoul.MyFortFromMeTaken." +
				"HereIsSomeoneHidden.LikeSugarInSugarCane.ASweetSugarTrader.MyShopFromMeTaken." +
				"SorcererAndMagician.NoEyesCanEverSee.AnArtfulConjurer.MySenseFromMeTaken." +
				"MyEyesWillNeverSee.BeautiesOfTheWholeWorld.BeholdWhoseVisionFine.MySightFromMeTaken" +
				"PoemByRumiMolana",
		},
		{
			"255 chars ending with dot",
			"HereIsSomeoneHidden.MyHoldFromMeTaken.FromSelfHasMeDriven.MyLeadFromMeTaken." +
				"HereIsSomeoneHidden.AsLifeSweeterThanLife.TakesMeToGardenOfSoul.MyFortFromMeTaken." +
				"HereIsSomeoneHidden.LikeSugarInSugarCane.ASweetSugarTrader.MyShopFromMeTaken." +
				"SorcererAndMagician.",
		},
		{
			"254 chars no dot",
			"HereIsSomeoneHidden.MyHoldFromMeTaken.FromSelfHasMeDriven.MyLeadFromMeTaken." +
				"HereIsSomeoneHidden.AsLifeSweeterThanLife.TakesMeToGardenOfSoul.MyFortFromMeTaken." +
				"HereIsSomeoneHidden.LikeSugarInSugarCane.ASweetSugarTrader.MyShopFromMeTaken." +
				"SorcererAndMagician",
		},
	}

	for _, tt := range invalidNames {
		t.Run(tt.name, func(t *testing.T) {
			_, err := dns.AppendName(nil, tt.input)
			if err == nil {
				t.Errorf("AppendName(nil, %q) should have returned error", tt.input)
			}
		})
	}
}

// --- AppendLabel ---

func TestAppendLabel(t *testing.T) {
	tests := []struct {
		name     string
		label    string
		expected []byte
	}{
		{"simple", "example", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e'}},
		{"single char", "a", []byte{1, 'a'}},
		{"with dot", "Name.With.Dot", []byte{13, 'N', 'a', 'm', 'e', '.', 'W', 'i', 't', 'h', '.', 'D', 'o', 't'}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dns.AppendLabel(nil, tt.label)
			if err != nil {
				t.Fatalf("AppendLabel(nil, %q) error: %v", tt.label, err)
			}
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("AppendLabel(nil, %q) = %v, want %v", tt.label, got, tt.expected)
			}
		})
	}
}

func TestAppendLabelInvalid(t *testing.T) {
	// Empty label
	_, err := dns.AppendLabel(nil, "")
	if err == nil {
		t.Error("AppendLabel(nil, \"\") should return error")
	}

	// Label with 64 chars (max is 63)
	longLabel := "0123456789012345678901234567890123456789012345678901234567890123"
	if len(longLabel) != 64 {
		t.Fatalf("test setup: longLabel has %d chars, want 64", len(longLabel))
	}
	_, err = dns.AppendLabel(nil, longLabel)
	if err == nil {
		t.Error("AppendLabel with 64-char label should return error")
	}
}

// --- AppendTerminator ---

func TestAppendTerminator(t *testing.T) {
	got := dns.AppendTerminator(nil)
	if !bytes.Equal(got, []byte{0}) {
		t.Errorf("AppendTerminator(nil) = %v, want [0]", got)
	}

	buf := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e'}
	got = dns.AppendTerminator(buf)
	expected := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}
	if !bytes.Equal(got, expected) {
		t.Errorf("AppendTerminator(buf) = %v, want %v", got, expected)
	}
}

// --- AppendPointerLabel ---

func TestAppendPointerLabel(t *testing.T) {
	tests := []struct {
		name     string
		offset   uint16
		expected []byte
	}{
		{"offset 0", 0, []byte{0xC0, 0x00}},
		{"offset 20", 20, []byte{0xC0, 20}},
		{"offset 0x3FFF", 0x3FFF, []byte{0xFF, 0xFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dns.AppendPointerLabel(nil, tt.offset)
			if err != nil {
				t.Fatalf("AppendPointerLabel(nil, %d) error: %v", tt.offset, err)
			}
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("AppendPointerLabel(nil, %d) = %v, want %v", tt.offset, got, tt.expected)
			}
		})
	}
}

func TestAppendPointerLabelInvalid(t *testing.T) {
	_, err := dns.AppendPointerLabel(nil, 0x4000)
	if err == nil {
		t.Error("AppendPointerLabel with offset >= 0x4000 should return error")
	}
}

// --- ReadName ---
// Vectors from OpenThread tests/unit/test_dns.cpp

func TestReadName(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		offset       int
		expectedName string
		expectedOff  int
	}{
		{
			"example.com",
			[]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			0,
			"example.com.",
			13,
		},
		{
			"foo.a.bb.edu",
			[]byte{3, 'f', 'o', 'o', 1, 'a', 2, 'b', 'b', 3, 'e', 'd', 'u', 0},
			0,
			"foo.a.bb.edu.",
			14,
		},
		{
			"foundation",
			[]byte{10, 'f', 'o', 'u', 'n', 'd', 'a', 't', 'i', 'o', 'n', 0},
			0,
			"foundation.",
			12,
		},
		{
			"root",
			[]byte{0},
			0,
			".",
			1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, newOff, err := dns.ReadName(tt.data, tt.offset)
			if err != nil {
				t.Fatalf("ReadName() error: %v", err)
			}
			if name != tt.expectedName {
				t.Errorf("ReadName() name = %q, want %q", name, tt.expectedName)
			}
			if newOff != tt.expectedOff {
				t.Errorf("ReadName() offset = %d, want %d", newOff, tt.expectedOff)
			}
		})
	}
}

func TestReadNameCompressed(t *testing.T) {
	// Build a message that has:
	// offset 0: "F.ISI.ARPA" encoded = {1,'F', 3,'I','S','I', 4,'A','R','P','A', 0}
	// offset 12: "FOO" + pointer to offset 0 = {3,'F','O','O', 0xC0, 0x00}
	// offset 18: pointer to offset 2 (ISI.ARPA) = {0xC0, 0x02}
	data := []byte{
		// offset 0: F.ISI.ARPA
		1, 'F', 3, 'I', 'S', 'I', 4, 'A', 'R', 'P', 'A', 0,
		// offset 12: FOO -> pointer to 0
		3, 'F', 'O', 'O', 0xC0, 0x00,
		// offset 18: pointer to 2 (ISI.ARPA)
		0xC0, 0x02,
	}

	tests := []struct {
		name         string
		offset       int
		expectedName string
		expectedOff  int
	}{
		{"F.ISI.ARPA", 0, "F.ISI.ARPA.", 12},
		{"FOO.F.ISI.ARPA", 12, "FOO.F.ISI.ARPA.", 18},
		{"ISI.ARPA", 18, "ISI.ARPA.", 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, newOff, err := dns.ReadName(data, tt.offset)
			if err != nil {
				t.Fatalf("ReadName() error: %v", err)
			}
			if name != tt.expectedName {
				t.Errorf("ReadName() name = %q, want %q", name, tt.expectedName)
			}
			if newOff != tt.expectedOff {
				t.Errorf("ReadName() offset = %d, want %d", newOff, tt.expectedOff)
			}
		})
	}
}

func TestReadNameWithDotInFirstLabel(t *testing.T) {
	// "Human.Readable" as a single label + pointer to F.ISI.ARPA at offset 0
	data := []byte{
		// offset 0: F.ISI.ARPA
		1, 'F', 3, 'I', 'S', 'I', 4, 'A', 'R', 'P', 'A', 0,
		// offset 12: "Human.Readable" (14 chars) as single label + pointer to 0
		14, 'H', 'u', 'm', 'a', 'n', '.', 'R', 'e', 'a', 'd', 'a', 'b', 'l', 'e',
		0xC0, 0x00,
	}

	name, newOff, err := dns.ReadName(data, 12)
	if err != nil {
		t.Fatalf("ReadName() error: %v", err)
	}
	if name != "Human.Readable.F.ISI.ARPA." {
		t.Errorf("ReadName() = %q, want %q", name, "Human.Readable.F.ISI.ARPA.")
	}
	if newOff != 29 {
		t.Errorf("ReadName() offset = %d, want %d", newOff, 29)
	}
}

func TestReadNameErrors(t *testing.T) {
	// Truncated data
	_, _, err := dns.ReadName([]byte{3, 'f', 'o'}, 0)
	if err == nil {
		t.Error("ReadName with truncated data should return error")
	}

	// Empty data
	_, _, err = dns.ReadName(nil, 0)
	if err == nil {
		t.Error("ReadName with nil data should return error")
	}

	// Forward pointer (should be rejected)
	data := []byte{0xC0, 0x02, 1, 'a', 0}
	_, _, err = dns.ReadName(data, 0)
	if err == nil {
		t.Error("ReadName with forward pointer should return error")
	}

	// Self-referencing pointer (loop)
	data = []byte{0xC0, 0x00}
	_, _, err = dns.ReadName(data, 0)
	if err == nil {
		t.Error("ReadName with self-referencing pointer should return error")
	}
}

// --- ReadLabel ---

func TestReadLabel(t *testing.T) {
	data := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}

	// Read first label
	label, newOff, isPtr, err := dns.ReadLabel(data, 0)
	if err != nil {
		t.Fatalf("ReadLabel() error: %v", err)
	}
	if label != "example" {
		t.Errorf("ReadLabel() label = %q, want %q", label, "example")
	}
	if newOff != 8 {
		t.Errorf("ReadLabel() offset = %d, want 8", newOff)
	}
	if isPtr {
		t.Error("ReadLabel() isPointer should be false")
	}

	// Read second label
	label, newOff, isPtr, err = dns.ReadLabel(data, 8)
	if err != nil {
		t.Fatalf("ReadLabel() error: %v", err)
	}
	if label != "com" {
		t.Errorf("ReadLabel() label = %q, want %q", label, "com")
	}
	if newOff != 12 {
		t.Errorf("ReadLabel() offset = %d, want 12", newOff)
	}
	if isPtr {
		t.Error("ReadLabel() isPointer should be false")
	}

	// Read terminator (end of name)
	_, _, _, err = dns.ReadLabel(data, 12)
	if err == nil {
		t.Error("ReadLabel at terminator should return error (end of name)")
	}
}

func TestReadLabelPointer(t *testing.T) {
	data := []byte{
		1, 'F', 3, 'I', 'S', 'I', 4, 'A', 'R', 'P', 'A', 0,
		3, 'F', 'O', 'O', 0xC0, 0x00,
	}

	// Read "FOO" label at offset 12
	label, newOff, isPtr, err := dns.ReadLabel(data, 12)
	if err != nil {
		t.Fatalf("ReadLabel() error: %v", err)
	}
	if label != "FOO" {
		t.Errorf("ReadLabel() label = %q, want %q", label, "FOO")
	}
	if newOff != 16 {
		t.Errorf("ReadLabel() offset = %d, want 16", newOff)
	}
	if isPtr {
		t.Error("ReadLabel() isPointer should be false for text label")
	}

	// Read pointer label at offset 16
	_, newOff, isPtr, err = dns.ReadLabel(data, 16)
	if err != nil {
		t.Fatalf("ReadLabel() at pointer error: %v", err)
	}
	if !isPtr {
		t.Error("ReadLabel() isPointer should be true for pointer label")
	}
	if newOff != 0 {
		t.Errorf("ReadLabel() pointer target = %d, want 0", newOff)
	}
}

// --- CompareName ---

func TestCompareName(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		offset      int
		compareTo   string
		shouldMatch bool
		expectedOff int
	}{
		{
			"exact match",
			[]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			0, "example.com.", true, 13,
		},
		{
			"case insensitive",
			[]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			0, "EXAMPLE.COM.", true, 13,
		},
		{
			"without trailing dot",
			[]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			0, "example.com", true, 13,
		},
		{
			"mismatch",
			[]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			0, "bad.name", false, 13,
		},
		{
			"root match",
			[]byte{0},
			0, ".", true, 1,
		},
		{
			"root match empty",
			[]byte{0},
			0, "", true, 1,
		},
		{
			"partial mismatch advances offset",
			[]byte{3, 'f', 'o', 'o', 1, 'a', 2, 'b', 'b', 3, 'e', 'd', 'u', 0},
			0, "bad.name", false, 14,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, newOff, err := dns.CompareName(tt.data, tt.offset, tt.compareTo)
			if err != nil {
				t.Fatalf("CompareName() error: %v", err)
			}
			if match != tt.shouldMatch {
				t.Errorf("CompareName() match = %v, want %v", match, tt.shouldMatch)
			}
			if newOff != tt.expectedOff {
				t.Errorf("CompareName() offset = %d, want %d", newOff, tt.expectedOff)
			}
		})
	}
}

func TestCompareNameCompressed(t *testing.T) {
	data := []byte{
		1, 'F', 3, 'I', 'S', 'I', 4, 'A', 'R', 'P', 'A', 0,
		3, 'F', 'O', 'O', 0xC0, 0x00,
		0xC0, 0x02,
	}

	tests := []struct {
		name        string
		offset      int
		compareTo   string
		shouldMatch bool
		expectedOff int
	}{
		{"name1 match", 0, "F.ISI.ARPA.", true, 12},
		{"name2 match", 12, "FOO.F.ISI.ARPA.", true, 18},
		{"name3 match", 18, "ISI.ARPA.", true, 20},
		{"name1 mismatch", 0, "bad.name", false, 12},
		{"name2 mismatch", 12, "bad.name", false, 18},
		{"name3 mismatch", 18, "bad.name", false, 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, newOff, err := dns.CompareName(data, tt.offset, tt.compareTo)
			if err != nil {
				t.Fatalf("CompareName() error: %v", err)
			}
			if match != tt.shouldMatch {
				t.Errorf("CompareName() match = %v, want %v", match, tt.shouldMatch)
			}
			if newOff != tt.expectedOff {
				t.Errorf("CompareName() offset = %d, want %d", newOff, tt.expectedOff)
			}
		})
	}
}

// --- CompareLabel ---

func TestCompareLabel(t *testing.T) {
	tests := []struct {
		name  string
		a     string
		b     string
		match bool
	}{
		{"same", "example", "example", true},
		{"case insensitive", "example", "EXAMPLE", true},
		{"mixed case", "ExAmPle", "eXaMpLE", true},
		{"different", "foo", "bar", false},
		{"different length", "foo", "fooo", false},
		{"empty both", "", "", true},
		{"one empty", "foo", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dns.CompareLabel(tt.a, tt.b)
			if got != tt.match {
				t.Errorf("CompareLabel(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.match)
			}
		})
	}
}

// --- IsSubDomainOf ---
// Vectors from OpenThread tests/unit/test_dns.cpp

func TestIsSubDomainOf(t *testing.T) {
	tests := []struct {
		name   string
		sub    string
		domain string
		expect bool
	}{
		{"basic", "my-service._ipps._tcp.local.", "local.", true},
		{"no trailing dot on name", "my-service._ipps._tcp.local", "local.", true},
		{"no trailing dot on domain", "my-service._ipps._tcp.local.", "local", true},
		{"no trailing dots", "my-service._ipps._tcp.local", "local", true},
		{"deeper domain", "my-service._ipps._tcp.default.service.arpa.", "default.service.arpa.", true},
		{"mid domain", "my-service._ipps._tcp.default.service.arpa.", "service.arpa.", true},
		{"partial label no match", "my-service._ipps._tcp.default.service.arpa.", "vice.arpa.", false},
		{"case insensitive", "my-service._ipps._tcp.local.", "LOCAL.", true},
		{"case insensitive no dot name", "my-service._ipps._tcp.local", "LOCAL.", true},
		{"case insensitive no dot domain", "my-service._ipps._tcp.local.", "LOCAL", true},
		{"case insensitive no dots", "my-service._ipps._tcp.local", "LOCAL", true},
		{"mixed case deeper", "my-service._ipps._tcp.Default.Service.ARPA.", "dEFAULT.Service.arpa.", true},
		{"mixed case mid", "my-service._ipps._tcp.default.service.ARpa.", "SeRvIcE.arPA.", true},
		{"partial label case insensitive", "my-service._ipps._tcp.default.service.arpa.", "Vice.arpa.", false},
		{"same domain is not subdomain", "local.", "local.", false},
		{"same domain no dots", "local", "local", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dns.IsSubDomainOf(tt.sub, tt.domain)
			if got != tt.expect {
				t.Errorf("IsSubDomainOf(%q, %q) = %v, want %v", tt.sub, tt.domain, got, tt.expect)
			}
		})
	}
}

// --- IsSameDomain ---

func TestIsSameDomain(t *testing.T) {
	tests := []struct {
		name   string
		a      string
		b      string
		expect bool
	}{
		{"same with dots", "example.com.", "example.com.", true},
		{"a with dot", "example.com.", "example.com", true},
		{"case insensitive", "example.com.", "ExAmPlE.cOm", true},
		{"both no dot case", "example.com", "ExAmPlE.cOm", true},
		{"both dots case", "example.com.", "ExAmPlE.cOm.", true},
		{"different prefix", "example.com.", "aExAmPlE.cOm.", false},
		{"shorter", "example.com.", "cOm.", false},
		{"mismatch labels", "example.", "example.com.", false},
		{"leading dot", "example.com.", ".example.com.", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dns.IsSameDomain(tt.a, tt.b)
			if got != tt.expect {
				t.Errorf("IsSameDomain(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.expect)
			}
		})
	}
}

// --- ValidateName ---

func TestValidateName(t *testing.T) {
	valid := []string{
		"a",
		"a.b.c",
		"a.b.c.",
		"a.b.012345678901234567890123456789012345678901234567890123456789012.",
		".",
	}
	for _, name := range valid {
		t.Run("valid_"+name, func(t *testing.T) {
			if err := dns.ValidateName(name); err != nil {
				t.Errorf("ValidateName(%q) = %v, want nil", name, err)
			}
		})
	}

	invalid := []string{
		"",
		"a..b",
		".a.b",
		"a.b..",
		// Long label (64 chars)
		"a.b.0123456789012345678901234567890123456789012345678901234567890123.",
		// Long name (4 × 63-char labels + dots = 4*63 + 3 = 255 chars without final dot, 256 encoded)
		"012345678901234567890123456789012345678901234567890123456789012." +
			"012345678901234567890123456789012345678901234567890123456789012." +
			"012345678901234567890123456789012345678901234567890123456789012." +
			"012345678901234567890123456789012345678901234567890123456789012",
	}
	for _, name := range invalid {
		t.Run("invalid_"+name, func(t *testing.T) {
			if err := dns.ValidateName(name); err == nil {
				t.Errorf("ValidateName(%q) = nil, want error", name)
			}
		})
	}
}

// --- ValidateLabel ---

func TestValidateLabel(t *testing.T) {
	// Valid labels
	if err := dns.ValidateLabel("a"); err != nil {
		t.Errorf("ValidateLabel(\"a\") = %v, want nil", err)
	}
	if err := dns.ValidateLabel("hello"); err != nil {
		t.Errorf("ValidateLabel(\"hello\") = %v, want nil", err)
	}
	// 63 chars
	label63 := "012345678901234567890123456789012345678901234567890123456789012"
	if len(label63) != 63 {
		t.Fatalf("test setup: label63 has %d chars", len(label63))
	}
	if err := dns.ValidateLabel(label63); err != nil {
		t.Errorf("ValidateLabel(63chars) = %v, want nil", err)
	}

	// Invalid: 64 chars
	label64 := "0123456789012345678901234567890123456789012345678901234567890123"
	if len(label64) != 64 {
		t.Fatalf("test setup: label64 has %d chars", len(label64))
	}
	if err := dns.ValidateLabel(label64); err == nil {
		t.Error("ValidateLabel(64chars) = nil, want error")
	}

	// Invalid: empty
	if err := dns.ValidateLabel(""); err == nil {
		t.Error("ValidateLabel(\"\") = nil, want error")
	}
}

// --- ExtractLabels ---
// Vectors from OpenThread tests/unit/test_dns.cpp

func TestExtractLabels(t *testing.T) {
	tests := []struct {
		name     string
		fullName string
		suffix   string
		labels   string
		wantErr  bool
	}{
		{"basic", "my-service._ipps._tcp.default.service.arpa.", "default.service.arpa.", "my-service._ipps._tcp", false},
		{"no dots", "my-service._ipps._tcp.default.service.arpa", "default.service.arpa", "my-service._ipps._tcp", false},
		{"middle suffix", "my.service._ipps._tcp.default.service.arpa.", "_ipps._tcp.default.service.arpa.", "my.service", false},
		{"case insensitive", "my-service._ipps._tcp.default.service.arpa.", "DeFault.SerVice.ARPA.", "my-service._ipps._tcp", false},
		{"case no dot", "my-service._ipps._tcp.default.service.arpa", "DeFault.SerVice.ARPA", "my-service._ipps._tcp", false},

		// Error cases: mismatched dot suffixes
		{"mismatch dot 1", "my-service._ipps._tcp.default.service.arpa", "default.service.arpa.", "", true},
		{"mismatch dot 2", "my-service._ipps._tcp.default.service.arpa.", "default.service.arpa", "", true},
		{"partial label", "my-service._ipps._tcp.default.service.arpa.", "efault.service.arpa.", "", true},
		{"partial no dot", "my-service._ipps._tcp.default.service.arpa", "efault.service.arpa", "", true},
		{"extra prefix", "my-service._ipps._tcp.default.service.arpa.", "xdefault.service.arpa.", "", true},
		{"leading dot suffix", "my-service._ipps._tcp.default.service.arpa.", ".default.service.arpa.", "", true},
		{"shorter suffix", "my-service._ipps._tcp.default.service.arpa.", "default.service.arp.", "", true},
		{"same name", "default.service.arpa.", "default.service.arpa.", "", true},
		{"same no dot", "default.service.arpa", "default.service.arpa", "", true},
		{"shorter name", "efault.service.arpa.", "default.service.arpa.", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dns.ExtractLabels(tt.fullName, tt.suffix)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ExtractLabels(%q, %q) = %q, want error", tt.fullName, tt.suffix, got)
				}
			} else {
				if err != nil {
					t.Fatalf("ExtractLabels(%q, %q) error: %v", tt.fullName, tt.suffix, err)
				}
				if got != tt.labels {
					t.Errorf("ExtractLabels(%q, %q) = %q, want %q", tt.fullName, tt.suffix, got, tt.labels)
				}
			}
		})
	}
}

// --- Encode then decode round-trip ---

func TestEncodeDecodeRoundTrip(t *testing.T) {
	names := []string{
		"example.com",
		"example.com.",
		"foo.a.bb.edu",
		"foundation",
		".",
		"",
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			encoded, err := dns.AppendName(nil, name)
			if err != nil {
				t.Fatalf("AppendName() error: %v", err)
			}
			decoded, off, err := dns.ReadName(encoded, 0)
			if err != nil {
				t.Fatalf("ReadName() error: %v", err)
			}
			if off != len(encoded) {
				t.Errorf("ReadName offset = %d, want %d", off, len(encoded))
			}
			// Verify CompareName matches
			match, _, err := dns.CompareName(encoded, 0, name)
			if err != nil {
				t.Fatalf("CompareName() error: %v", err)
			}
			if !match {
				t.Errorf("CompareName(encoded, %q) = false, want true", name)
			}
			// Verify decoded name matches encoded
			match, _, err = dns.CompareName(encoded, 0, decoded)
			if err != nil {
				t.Fatalf("CompareName(decoded) error: %v", err)
			}
			if !match {
				t.Errorf("CompareName(encoded, decoded=%q) = false, want true", decoded)
			}
		})
	}
}

// --- AppendLabel per-label then terminate encoding ---

func TestAppendLabelsAndTerminator(t *testing.T) {
	// Build "example.com" by appending labels individually
	var buf []byte
	var err error

	buf, err = dns.AppendLabel(buf, "example")
	if err != nil {
		t.Fatalf("AppendLabel(example) error: %v", err)
	}
	buf, err = dns.AppendLabel(buf, "com")
	if err != nil {
		t.Fatalf("AppendLabel(com) error: %v", err)
	}
	buf = dns.AppendTerminator(buf)

	expected := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	if !bytes.Equal(buf, expected) {
		t.Errorf("label-by-label encoding = %v, want %v", buf, expected)
	}
}

// Verify the errors module integration
func TestErrorTypes(t *testing.T) {
	// AppendName with invalid name should return an errors.Error
	_, err := dns.AppendName(nil, "foo..bar")
	if err == nil {
		t.Fatal("expected error for invalid name")
	}
	var otErr *errors.Error
	switch e := err.(type) {
	case *errors.Error:
		otErr = e
	default:
		t.Fatalf("expected *errors.Error, got %T", err)
	}
	if otErr.Code != errors.ErrInvalidArgs.Code {
		t.Errorf("error code = %d, want %d (ErrInvalidArgs)", otErr.Code, errors.ErrInvalidArgs.Code)
	}
}

// --- ReadName with offset in middle ---

func TestReadNameWithNonZeroOffset(t *testing.T) {
	// Some garbage at the front, then the name
	garbage := []byte{0xFF, 0xFF, 0xFF}
	name := []byte{3, 'f', 'o', 'o', 3, 'b', 'a', 'r', 0}
	data := make([]byte, 0, len(garbage)+len(name))
	data = append(data, garbage...)
	data = append(data, name...)

	got, newOff, err := dns.ReadName(data, 3)
	if err != nil {
		t.Fatalf("ReadName() error: %v", err)
	}
	if got != "foo.bar." {
		t.Errorf("ReadName() = %q, want %q", got, "foo.bar.")
	}
	if newOff != 12 {
		t.Errorf("ReadName() offset = %d, want 12", newOff)
	}
}
