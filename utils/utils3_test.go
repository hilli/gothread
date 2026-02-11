// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"math"
	"testing"
	"time"

	mac_types "github.com/hilli/gothread/mac/types"

	"github.com/hilli/gothread/errors"
)

// ============================================================================
// Verhoeff Checksum Tests
// ============================================================================

func TestVerhoeffCalculateBasic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected byte
	}{
		{"0", '4'},
		{"123456789", '0'},
		{"236", '3'},
		{"12345678901234567890", '1'},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			result, err := VerhoeffCalculate(tc.input)
			if err != nil {
				t.Fatalf("VerhoeffCalculate(%q) error: %v", tc.input, err)
			}
			if result != tc.expected {
				t.Errorf("VerhoeffCalculate(%q) = %q, want %q", tc.input, string(result), string(tc.expected))
			}
		})
	}
}

func TestVerhoeffValidateBasic(t *testing.T) {
	t.Parallel()

	// Calculate then validate round-trip
	inputs := []string{"0", "123456789", "236", "999", "1"}
	for _, input := range inputs {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			checksum, err := VerhoeffCalculate(input)
			if err != nil {
				t.Fatalf("VerhoeffCalculate(%q) error: %v", input, err)
			}
			withChecksum := input + string(checksum)
			if err := VerhoeffValidate(withChecksum); err != nil {
				t.Errorf("VerhoeffValidate(%q) error: %v", withChecksum, err)
			}
		})
	}
}

func TestVerhoeffValidateInvalidChecksum(t *testing.T) {
	t.Parallel()

	// "1234567891" should fail validation (wrong checksum digit; correct is '0')
	err := VerhoeffValidate("1234567891")
	if err == nil {
		t.Error("expected validation failure for wrong checksum")
	}
}

func TestVerhoeffEmptyString(t *testing.T) {
	t.Parallel()

	_, err := VerhoeffCalculate("")
	if err != errors.ErrInvalidArgs {
		t.Errorf("VerhoeffCalculate(\"\") = %v, want ErrInvalidArgs", err)
	}

	err = VerhoeffValidate("")
	if err != errors.ErrInvalidArgs {
		t.Errorf("VerhoeffValidate(\"\") = %v, want ErrInvalidArgs", err)
	}
}

func TestVerhoeffNonDigit(t *testing.T) {
	t.Parallel()

	_, err := VerhoeffCalculate("12a4")
	if err != errors.ErrInvalidArgs {
		t.Errorf("VerhoeffCalculate with non-digit = %v, want ErrInvalidArgs", err)
	}

	err = VerhoeffValidate("12a4")
	if err != errors.ErrInvalidArgs {
		t.Errorf("VerhoeffValidate with non-digit = %v, want ErrInvalidArgs", err)
	}
}

func TestVerhoeffMaxLength(t *testing.T) {
	t.Parallel()

	// Exactly at max length should work
	maxStr := make([]byte, MaxVerhoeffStringLength)
	for i := range maxStr {
		maxStr[i] = '1'
	}
	_, err := VerhoeffCalculate(string(maxStr))
	if err != nil {
		t.Errorf("VerhoeffCalculate at max length error: %v", err)
	}

	// Over max length should fail
	overStr := make([]byte, MaxVerhoeffStringLength+1)
	for i := range overStr {
		overStr[i] = '1'
	}
	_, err = VerhoeffCalculate(string(overStr))
	if err != errors.ErrInvalidArgs {
		t.Errorf("VerhoeffCalculate over max length = %v, want ErrInvalidArgs", err)
	}
}

func TestVerhoeffSingleDigits(t *testing.T) {
	t.Parallel()

	// All single-digit inputs should produce valid checksums
	for d := byte('0'); d <= '9'; d++ {
		d := d
		t.Run(string(d), func(t *testing.T) {
			t.Parallel()
			checksum, err := VerhoeffCalculate(string(d))
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if checksum < '0' || checksum > '9' {
				t.Errorf("checksum %q not a digit", string(checksum))
			}
			if err := VerhoeffValidate(string(d) + string(checksum)); err != nil {
				t.Errorf("round-trip validation failed: %v", err)
			}
		})
	}
}

// ============================================================================
// Parse Command Line Tests
// ============================================================================

func TestParseAsUint8(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  uint8
		err   bool
	}{
		{"0", 0, false},
		{"255", 255, false},
		{"0xff", 255, false},
		{"0xFF", 255, false},
		{"256", 0, true},
		{"", 0, true},
		{"abc", 0, true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			v, err := ParseAsUint8(tc.input)
			if tc.err && err == nil {
				t.Error("expected error")
			}
			if !tc.err && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tc.err && v != tc.want {
				t.Errorf("got %d, want %d", v, tc.want)
			}
		})
	}
}

func TestParseAsUint16(t *testing.T) {
	t.Parallel()

	v, err := ParseAsUint16("0xFFFF")
	if err != nil || v != 65535 {
		t.Errorf("ParseAsUint16(\"0xFFFF\") = %d, %v", v, err)
	}

	_, err = ParseAsUint16("65536")
	if err == nil {
		t.Error("expected error for overflow")
	}
}

func TestParseAsUint32(t *testing.T) {
	t.Parallel()

	v, err := ParseAsUint32("4294967295")
	if err != nil || v != math.MaxUint32 {
		t.Errorf("ParseAsUint32 max = %d, %v", v, err)
	}

	_, err = ParseAsUint32("4294967296")
	if err == nil {
		t.Error("expected error for overflow")
	}
}

func TestParseAsUint64(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  uint64
		err   bool
	}{
		{"0", 0, false},
		{"18446744073709551615", 18446744073709551615, false},
		{"0xdeadbeef", 0xdeadbeef, false},
		{"0X1A2B", 0x1a2b, false},
		{"", 0, true},
		{"0x", 0, true},
		{"-1", 0, true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			v, err := ParseAsUint64(tc.input)
			if tc.err && err == nil {
				t.Error("expected error")
			}
			if !tc.err && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tc.err && v != tc.want {
				t.Errorf("got %d, want %d", v, tc.want)
			}
		})
	}
}

func TestParseAsInt8(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  int8
		err   bool
	}{
		{"0", 0, false},
		{"127", 127, false},
		{"-128", -128, false},
		{"+100", 100, false},
		{"128", 0, true},
		{"-129", 0, true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			v, err := ParseAsInt8(tc.input)
			if tc.err && err == nil {
				t.Error("expected error")
			}
			if !tc.err && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tc.err && v != tc.want {
				t.Errorf("got %d, want %d", v, tc.want)
			}
		})
	}
}

func TestParseAsInt16(t *testing.T) {
	t.Parallel()

	v, err := ParseAsInt16("-32768")
	if err != nil || v != math.MinInt16 {
		t.Errorf("ParseAsInt16 min = %d, %v", v, err)
	}

	v, err = ParseAsInt16("32767")
	if err != nil || v != math.MaxInt16 {
		t.Errorf("ParseAsInt16 max = %d, %v", v, err)
	}

	_, err = ParseAsInt16("32768")
	if err == nil {
		t.Error("expected error for overflow")
	}
}

func TestParseAsInt32(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  int32
		err   bool
	}{
		{"0", 0, false},
		{"-2147483648", math.MinInt32, false},
		{"2147483647", math.MaxInt32, false},
		{"+42", 42, false},
		{"-0x10", -16, false},
		{"2147483648", 0, true},
		{"", 0, true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			v, err := ParseAsInt32(tc.input)
			if tc.err && err == nil {
				t.Error("expected error")
			}
			if !tc.err && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tc.err && v != tc.want {
				t.Errorf("got %d, want %d", v, tc.want)
			}
		})
	}
}

func TestParseAsBool(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  bool
		err   bool
	}{
		{"0", false, false},
		{"1", true, false},
		{"42", true, false},
		{"abc", false, true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			v, err := ParseAsBool(tc.input)
			if tc.err && err == nil {
				t.Error("expected error")
			}
			if !tc.err {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if v != tc.want {
					t.Errorf("got %v, want %v", v, tc.want)
				}
			}
		})
	}
}

func TestParseAsIP6Address(t *testing.T) {
	t.Parallel()

	addr, err := ParseAsIP6Address("fe80::1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr[0] != 0xfe || addr[1] != 0x80 || addr[15] != 0x01 {
		t.Errorf("unexpected address: %x", addr)
	}

	_, err = ParseAsIP6Address("")
	if err == nil {
		t.Error("expected error for empty string")
	}

	_, err = ParseAsIP6Address("192.168.1.1")
	if err == nil {
		t.Error("expected error for IPv4 address")
	}
}

func TestParseAsIP6Prefix(t *testing.T) {
	t.Parallel()

	addr, bits, err := ParseAsIP6Prefix("2001:db8::/32")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr[0] != 0x20 || addr[1] != 0x01 || bits != 32 {
		t.Errorf("unexpected prefix: %x/%d", addr, bits)
	}

	_, _, err = ParseAsIP6Prefix("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

func TestParseAsHexString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  []byte
		err   bool
	}{
		{"AABBCC", []byte{0xAA, 0xBB, 0xCC}, false},
		{"aabbcc", []byte{0xAA, 0xBB, 0xCC}, false},
		{"123", []byte{0x01, 0x23}, false}, // Odd length
		{"AABBCCDD", []byte{0xAA, 0xBB, 0xCC, 0xDD}, false},
		{"", nil, true},
		{"GG", nil, true}, // Invalid hex
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			buf, err := ParseAsHexString(tc.input)
			if tc.err && err == nil {
				t.Error("expected error")
			}
			if !tc.err {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(buf) != len(tc.want) {
					t.Fatalf("got len %d, want %d", len(buf), len(tc.want))
				}
				for i := range buf {
					if buf[i] != tc.want[i] {
						t.Errorf("byte %d: got 0x%02x, want 0x%02x", i, buf[i], tc.want[i])
					}
				}
			}
		})
	}
}

func TestParseAsHexStringExact(t *testing.T) {
	t.Parallel()

	buf, err := ParseAsHexStringExact("AABB", 2)
	if err != nil || len(buf) != 2 {
		t.Errorf("unexpected result: %v, %v", buf, err)
	}

	_, err = ParseAsHexStringExact("AABB", 3)
	if err == nil {
		t.Error("expected error for size mismatch")
	}
}

func TestParseCmdBasic(t *testing.T) {
	t.Parallel()

	args, err := ParseCmd("hello world foo", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 3 {
		t.Fatalf("expected 3 args, got %d", len(args))
	}
	if args[0].String() != "hello" || args[1].String() != "world" || args[2].String() != "foo" {
		t.Errorf("unexpected args: %v", args)
	}
}

func TestParseCmdWhitespace(t *testing.T) {
	t.Parallel()

	args, err := ParseCmd("  hello\t\tworld  \n  foo\r\n", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 3 {
		t.Fatalf("expected 3 args, got %d", len(args))
	}
}

func TestParseCmdEscape(t *testing.T) {
	t.Parallel()

	// Backslash-space should be treated as part of the argument
	args, err := ParseCmd(`hello\ world foo`, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 {
		t.Fatalf("expected 2 args, got %d", len(args))
	}
	if args[0].String() != "hello world" {
		t.Errorf("expected 'hello world', got %q", args[0].String())
	}
}

func TestParseCmdEscapeBackslash(t *testing.T) {
	t.Parallel()

	args, err := ParseCmd(`hello\\ world`, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 {
		t.Fatalf("expected 2 args, got %d", len(args))
	}
	if args[0].String() != `hello\` {
		t.Errorf("expected 'hello\\', got %q", args[0].String())
	}
}

func TestParseCmdTooManyArgs(t *testing.T) {
	t.Parallel()

	_, err := ParseCmd("a b c d", 3)
	if err != errors.ErrInvalidArgs {
		t.Errorf("expected ErrInvalidArgs, got %v", err)
	}
}

func TestParseCmdEmpty(t *testing.T) {
	t.Parallel()

	args, err := ParseCmd("", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 0 {
		t.Errorf("expected 0 args, got %d", len(args))
	}

	args, err = ParseCmd("   ", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 0 {
		t.Errorf("expected 0 args for whitespace-only, got %d", len(args))
	}
}

func TestArgMethods(t *testing.T) {
	t.Parallel()

	// Non-empty arg
	arg := NewArg("42")
	if arg.IsEmpty() {
		t.Error("expected not empty")
	}
	if arg.String() != "42" {
		t.Errorf("String() = %q", arg.String())
	}
	if arg.Length() != 2 {
		t.Errorf("Length() = %d", arg.Length())
	}
	if !arg.Equals("42") {
		t.Error("expected Equals(\"42\")")
	}
	if arg.Equals("43") {
		t.Error("unexpected Equals(\"43\")")
	}

	v8, err := arg.ParseAsUint8()
	if err != nil || v8 != 42 {
		t.Errorf("ParseAsUint8 = %d, %v", v8, err)
	}

	v16, err := arg.ParseAsUint16()
	if err != nil || v16 != 42 {
		t.Errorf("ParseAsUint16 = %d, %v", v16, err)
	}

	v32, err := arg.ParseAsUint32()
	if err != nil || v32 != 42 {
		t.Errorf("ParseAsUint32 = %d, %v", v32, err)
	}

	v64, err := arg.ParseAsUint64()
	if err != nil || v64 != 42 {
		t.Errorf("ParseAsUint64 = %d, %v", v64, err)
	}

	b, err := arg.ParseAsBool()
	if err != nil || !b {
		t.Errorf("ParseAsBool = %v, %v", b, err)
	}

	// Empty arg
	empty := EmptyArg()
	if !empty.IsEmpty() {
		t.Error("expected empty")
	}
	if empty.String() != "" {
		t.Errorf("empty String() = %q", empty.String())
	}
	if empty.Length() != 0 {
		t.Errorf("empty Length() = %d", empty.Length())
	}
	if empty.Equals("anything") {
		t.Error("empty should not equal anything")
	}

	_, err = empty.ParseAsUint8()
	if err != errors.ErrInvalidArgs {
		t.Errorf("empty ParseAsUint8 = %v", err)
	}
}

func TestArgParseInt(t *testing.T) {
	t.Parallel()

	arg := NewArg("-42")
	v8, err := arg.ParseAsInt8()
	if err != nil || v8 != -42 {
		t.Errorf("ParseAsInt8 = %d, %v", v8, err)
	}

	v16, err := arg.ParseAsInt16()
	if err != nil || v16 != -42 {
		t.Errorf("ParseAsInt16 = %d, %v", v16, err)
	}

	v32, err := arg.ParseAsInt32()
	if err != nil || v32 != -42 {
		t.Errorf("ParseAsInt32 = %d, %v", v32, err)
	}

	empty := EmptyArg()
	_, err = empty.ParseAsInt8()
	if err != errors.ErrInvalidArgs {
		t.Errorf("empty ParseAsInt8 = %v", err)
	}
	_, err = empty.ParseAsInt16()
	if err != errors.ErrInvalidArgs {
		t.Errorf("empty ParseAsInt16 = %v", err)
	}
	_, err = empty.ParseAsInt32()
	if err != errors.ErrInvalidArgs {
		t.Errorf("empty ParseAsInt32 = %v", err)
	}
}

func TestArgParseHex(t *testing.T) {
	t.Parallel()

	arg := NewArg("AABB")
	buf, err := arg.ParseAsHexString()
	if err != nil || len(buf) != 2 || buf[0] != 0xAA || buf[1] != 0xBB {
		t.Errorf("ParseAsHexString = %x, %v", buf, err)
	}

	empty := EmptyArg()
	_, err = empty.ParseAsHexString()
	if err != errors.ErrInvalidArgs {
		t.Errorf("empty ParseAsHexString = %v", err)
	}

	_, err = empty.ParseAsBool()
	if err != errors.ErrInvalidArgs {
		t.Errorf("empty ParseAsBool = %v", err)
	}

	_, err = empty.ParseAsUint16()
	if err != errors.ErrInvalidArgs {
		t.Errorf("empty ParseAsUint16 = %v", err)
	}
	_, err = empty.ParseAsUint32()
	if err != errors.ErrInvalidArgs {
		t.Errorf("empty ParseAsUint32 = %v", err)
	}
	_, err = empty.ParseAsUint64()
	if err != errors.ErrInvalidArgs {
		t.Errorf("empty ParseAsUint64 = %v", err)
	}
}

func TestArgsLength(t *testing.T) {
	t.Parallel()

	args := []Arg{NewArg("a"), NewArg("b"), EmptyArg(), NewArg("c")}
	if ArgsLength(args) != 2 {
		t.Errorf("ArgsLength = %d, want 2", ArgsLength(args))
	}

	if ArgsLength(nil) != 0 {
		t.Errorf("ArgsLength(nil) = %d, want 0", ArgsLength(nil))
	}
}

// ============================================================================
// Link Metrics Manager Tests
// ============================================================================

type mockNeighborProvider struct {
	addrs []mac_types.ExtAddress
}

func (m *mockNeighborProvider) GetNeighborExtAddresses() []mac_types.ExtAddress {
	return m.addrs
}

type mockEapConfigurator struct {
	configuredAddrs   []mac_types.ExtAddress
	unregisteredAddrs []mac_types.ExtAddress
	configureErr      error
}

func (m *mockEapConfigurator) ConfigureEap(extAddr mac_types.ExtAddress) error {
	if m.configureErr != nil {
		return m.configureErr
	}
	m.configuredAddrs = append(m.configuredAddrs, extAddr)
	return nil
}

func (m *mockEapConfigurator) UnregisterEap(extAddr mac_types.ExtAddress) error {
	m.unregisteredAddrs = append(m.unregisteredAddrs, extAddr)
	return nil
}

func makeExtAddr(b byte) mac_types.ExtAddress {
	return mac_types.ExtAddress{b, b, b, b, b, b, b, b}
}

func TestLinkMetricsManagerCreation(t *testing.T) {
	t.Parallel()

	neighbors := &mockNeighborProvider{}
	configurator := &mockEapConfigurator{}
	mgr := NewLinkMetricsManager(neighbors, configurator)

	if mgr.IsEnabled() {
		t.Error("expected disabled by default")
	}
	if mgr.SubjectCount() != 0 {
		t.Error("expected 0 subjects")
	}
}

func TestLinkMetricsManagerEnableDisable(t *testing.T) {
	t.Parallel()

	neighbors := &mockNeighborProvider{
		addrs: []mac_types.ExtAddress{makeExtAddr(1), makeExtAddr(2)},
	}
	configurator := &mockEapConfigurator{}
	mgr := NewLinkMetricsManager(neighbors, configurator)

	mgr.SetEnabled(true)
	if !mgr.IsEnabled() {
		t.Error("expected enabled")
	}

	// Timer should discover neighbors
	mgr.HandleTimer()
	if mgr.SubjectCount() != 2 {
		t.Errorf("expected 2 subjects, got %d", mgr.SubjectCount())
	}

	// Disable should clear everything
	mgr.SetEnabled(false)
	if mgr.IsEnabled() {
		t.Error("expected disabled")
	}
	if mgr.SubjectCount() != 0 {
		t.Errorf("expected 0 subjects after disable, got %d", mgr.SubjectCount())
	}
	// Should have unregistered both
	if len(configurator.unregisteredAddrs) != 2 {
		t.Errorf("expected 2 unregisters, got %d", len(configurator.unregisteredAddrs))
	}
}

func TestLinkMetricsManagerDoubleEnable(t *testing.T) {
	t.Parallel()

	mgr := NewLinkMetricsManager(&mockNeighborProvider{}, &mockEapConfigurator{})
	mgr.SetEnabled(true)
	mgr.SetEnabled(true) // Should be no-op
	if !mgr.IsEnabled() {
		t.Error("expected still enabled")
	}
}

func TestLinkMetricsManagerHandleTimer(t *testing.T) {
	t.Parallel()

	addr1 := makeExtAddr(0x11)
	addr2 := makeExtAddr(0x22)
	neighbors := &mockNeighborProvider{
		addrs: []mac_types.ExtAddress{addr1, addr2},
	}
	configurator := &mockEapConfigurator{}
	mgr := NewLinkMetricsManager(neighbors, configurator)

	// Timer before enable should be no-op
	mgr.HandleTimer()
	if mgr.SubjectCount() != 0 {
		t.Error("expected 0 subjects before enable")
	}

	mgr.SetEnabled(true)
	mgr.HandleTimer()

	// Should have discovered and attempted to configure both
	if mgr.SubjectCount() != 2 {
		t.Errorf("expected 2 subjects, got %d", mgr.SubjectCount())
	}
	if len(configurator.configuredAddrs) != 2 {
		t.Errorf("expected 2 configure calls, got %d", len(configurator.configuredAddrs))
	}
}

func TestLinkMetricsManagerMgmtResponse(t *testing.T) {
	t.Parallel()

	addr := makeExtAddr(0xAA)
	neighbors := &mockNeighborProvider{addrs: []mac_types.ExtAddress{addr}}
	configurator := &mockEapConfigurator{}
	mgr := NewLinkMetricsManager(neighbors, configurator)

	mgr.SetEnabled(true)
	mgr.HandleTimer()

	// Simulate successful response
	mgr.HandleMgmtResponse(addr, LinkMetricsStatusSuccess)

	subjects := mgr.GetSubjects()
	if len(subjects) != 1 {
		t.Fatalf("expected 1 subject, got %d", len(subjects))
	}
	if subjects[0].State != SubjectActive {
		t.Errorf("expected Active state, got %d", subjects[0].State)
	}
}

func TestLinkMetricsManagerMgmtResponseFailure(t *testing.T) {
	t.Parallel()

	addr := makeExtAddr(0xBB)
	neighbors := &mockNeighborProvider{addrs: []mac_types.ExtAddress{addr}}
	configurator := &mockEapConfigurator{}
	mgr := NewLinkMetricsManager(neighbors, configurator)

	mgr.SetEnabled(true)
	mgr.HandleTimer()

	// Simulate failed response
	mgr.HandleMgmtResponse(addr, LinkMetricsStatusCode(254))

	subjects := mgr.GetSubjects()
	if len(subjects) != 1 {
		t.Fatalf("expected 1 subject, got %d", len(subjects))
	}
	if subjects[0].State != SubjectNotConfigured {
		t.Errorf("expected NotConfigured state, got %d", subjects[0].State)
	}
}

func TestLinkMetricsManagerEnhAckIe(t *testing.T) {
	t.Parallel()

	addr := makeExtAddr(0xCC)
	neighbors := &mockNeighborProvider{addrs: []mac_types.ExtAddress{addr}}
	configurator := &mockEapConfigurator{}
	mgr := NewLinkMetricsManager(neighbors, configurator)

	mgr.SetEnabled(true)
	mgr.HandleTimer()

	// Set to active
	mgr.HandleMgmtResponse(addr, LinkMetricsStatusSuccess)

	// Receive metrics
	mgr.HandleEnhAckIe(addr, -50, 80)

	data, err := mgr.GetMetricsByExtAddress(addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Rssi != -50 || data.LinkMargin != 80 {
		t.Errorf("unexpected metrics: rssi=%d, margin=%d", data.Rssi, data.LinkMargin)
	}
}

func TestLinkMetricsManagerGetMetricsNotFound(t *testing.T) {
	t.Parallel()

	mgr := NewLinkMetricsManager(&mockNeighborProvider{}, &mockEapConfigurator{})
	mgr.SetEnabled(true)

	_, err := mgr.GetMetricsByExtAddress(makeExtAddr(0xFF))
	if err != errors.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestLinkMetricsManagerGetMetricsInvalidState(t *testing.T) {
	t.Parallel()

	addr := makeExtAddr(0xDD)
	neighbors := &mockNeighborProvider{addrs: []mac_types.ExtAddress{addr}}
	configurator := &mockEapConfigurator{}
	mgr := NewLinkMetricsManager(neighbors, configurator)

	mgr.SetEnabled(true)
	mgr.HandleTimer()

	// Subject is in Configuring state, not Active
	_, err := mgr.GetMetricsByExtAddress(addr)
	if err != errors.ErrInvalidState {
		t.Errorf("expected ErrInvalidState, got %v", err)
	}
}

func TestLinkMetricsManagerEnhAckIeInactiveSubject(t *testing.T) {
	t.Parallel()

	addr := makeExtAddr(0xEE)
	neighbors := &mockNeighborProvider{addrs: []mac_types.ExtAddress{addr}}
	configurator := &mockEapConfigurator{}
	mgr := NewLinkMetricsManager(neighbors, configurator)

	mgr.SetEnabled(true)
	mgr.HandleTimer()

	// Subject is configuring, not active - IE should be ignored
	mgr.HandleEnhAckIe(addr, -30, 90)

	_, err := mgr.GetMetricsByExtAddress(addr)
	if err != errors.ErrInvalidState {
		t.Errorf("expected ErrInvalidState (data not updated), got %v", err)
	}
}

func TestLinkMetricsManagerEnhAckIeUnknownSubject(t *testing.T) {
	t.Parallel()

	mgr := NewLinkMetricsManager(&mockNeighborProvider{}, &mockEapConfigurator{})
	mgr.SetEnabled(true)

	// Should not panic on unknown address
	mgr.HandleEnhAckIe(makeExtAddr(0xFF), -30, 90)
}

func TestLinkMetricsManagerMgmtResponseUnknownSubject(t *testing.T) {
	t.Parallel()

	mgr := NewLinkMetricsManager(&mockNeighborProvider{}, &mockEapConfigurator{})
	mgr.SetEnabled(true)

	// Should not panic on unknown address
	mgr.HandleMgmtResponse(makeExtAddr(0xFF), LinkMetricsStatusSuccess)
}

func TestLinkMetricsManagerConfigureError(t *testing.T) {
	t.Parallel()

	addr := makeExtAddr(0x11)
	neighbors := &mockNeighborProvider{addrs: []mac_types.ExtAddress{addr}}
	configurator := &mockEapConfigurator{configureErr: errors.ErrUnknownNeighbor}
	mgr := NewLinkMetricsManager(neighbors, configurator)

	mgr.SetEnabled(true)
	mgr.HandleTimer()

	// Subject should be removed because the neighbor is unknown
	if mgr.SubjectCount() != 0 {
		t.Errorf("expected 0 subjects (stale removed), got %d", mgr.SubjectCount())
	}
}

func TestLinkMetricsManagerMaxAttempts(t *testing.T) {
	t.Parallel()

	addr := makeExtAddr(0x22)
	neighbors := &mockNeighborProvider{addrs: []mac_types.ExtAddress{addr}}
	configurator := &mockEapConfigurator{}
	mgr := NewLinkMetricsManager(neighbors, configurator)

	mgr.SetEnabled(true)

	// Each HandleTimer increments attempt count. After max attempts,
	// subject should transition to NotSupported and be removed.
	for i := 0; i < int(LinkMetricsMaxConfigAttempts)+2; i++ {
		mgr.HandleTimer()
	}

	// Subject should have been removed after reaching NotSupported state
	if mgr.SubjectCount() != 0 {
		subjects := mgr.GetSubjects()
		t.Errorf("expected 0 subjects (NotSupported removed), got %d, states: %v",
			mgr.SubjectCount(), subjects)
	}
}

func TestLinkMetricsManagerNewNeighborAddedDynamically(t *testing.T) {
	t.Parallel()

	neighbors := &mockNeighborProvider{
		addrs: []mac_types.ExtAddress{makeExtAddr(1)},
	}
	configurator := &mockEapConfigurator{}
	mgr := NewLinkMetricsManager(neighbors, configurator)

	mgr.SetEnabled(true)
	mgr.HandleTimer()

	if mgr.SubjectCount() != 1 {
		t.Fatalf("expected 1 subject, got %d", mgr.SubjectCount())
	}

	// Add a new neighbor dynamically
	neighbors.addrs = append(neighbors.addrs, makeExtAddr(2))
	mgr.HandleTimer()

	if mgr.SubjectCount() != 2 {
		t.Errorf("expected 2 subjects after adding neighbor, got %d", mgr.SubjectCount())
	}
}

func TestLinkMetricsManagerGetSubjectsCopy(t *testing.T) {
	t.Parallel()

	addr := makeExtAddr(0x33)
	neighbors := &mockNeighborProvider{addrs: []mac_types.ExtAddress{addr}}
	configurator := &mockEapConfigurator{}
	mgr := NewLinkMetricsManager(neighbors, configurator)

	mgr.SetEnabled(true)
	mgr.HandleTimer()
	mgr.HandleMgmtResponse(addr, LinkMetricsStatusSuccess)
	mgr.HandleEnhAckIe(addr, -60, 70)

	subjects := mgr.GetSubjects()
	if len(subjects) != 1 {
		t.Fatalf("expected 1 subject, got %d", len(subjects))
	}

	// Modify the copy should not affect the original
	subjects[0].Data.Rssi = 0
	data, err := mgr.GetMetricsByExtAddress(addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Rssi != -60 {
		t.Errorf("modifying copy affected original: rssi=%d", data.Rssi)
	}
}

func TestLinkMetricsManagerStartStop(t *testing.T) {
	t.Parallel()

	addr := makeExtAddr(0x44)
	neighbors := &mockNeighborProvider{addrs: []mac_types.ExtAddress{addr}}
	configurator := &mockEapConfigurator{}
	mgr := NewLinkMetricsManager(neighbors, configurator)

	mgr.SetEnabled(true)
	mgr.Start()
	mgr.HandleTimer()
	if mgr.SubjectCount() != 1 {
		t.Errorf("expected 1 subject after start, got %d", mgr.SubjectCount())
	}

	mgr.Stop()
	if mgr.SubjectCount() != 0 {
		t.Errorf("expected 0 subjects after stop, got %d", mgr.SubjectCount())
	}

	// Timer after stop should be no-op
	mgr.HandleTimer()
	if mgr.SubjectCount() != 0 {
		t.Errorf("expected 0 subjects after stop+timer, got %d", mgr.SubjectCount())
	}
}

func TestLinkMetricsManagerConstants(t *testing.T) {
	t.Parallel()

	if LinkMetricsTimeBeforeStart != 5*time.Second {
		t.Errorf("unexpected TimeBeforeStart: %v", LinkMetricsTimeBeforeStart)
	}
	if LinkMetricsStateUpdateInterval != 150*time.Second {
		t.Errorf("unexpected StateUpdateInterval: %v", LinkMetricsStateUpdateInterval)
	}
	if LinkMetricsMaxConfigAttempts != 3 {
		t.Errorf("unexpected MaxConfigAttempts: %d", LinkMetricsMaxConfigAttempts)
	}
	if LinkMetricsMaxSubjects != 128 {
		t.Errorf("unexpected MaxSubjects: %d", LinkMetricsMaxSubjects)
	}
}

func TestLinkMetricsManagerNilDependencies(t *testing.T) {
	t.Parallel()

	// Should not panic with nil dependencies
	mgr := NewLinkMetricsManager(nil, nil)
	mgr.SetEnabled(true)
	mgr.HandleTimer()
	mgr.HandleMgmtResponse(makeExtAddr(1), LinkMetricsStatusSuccess)
	mgr.HandleEnhAckIe(makeExtAddr(1), -50, 80)
	mgr.Stop()
}
