// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package ip4

import (
	"testing"

	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Address parsing and formatting
// ---------------------------------------------------------------------------

func TestAddressFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Address
		wantErr bool
	}{
		{"zero", "0.0.0.0", Address{0, 0, 0, 0}, false},
		{"loopback", "127.0.0.1", Address{127, 0, 0, 1}, false},
		{"broadcast", "255.255.255.255", Address{255, 255, 255, 255}, false},
		{"private", "192.168.1.1", Address{192, 168, 1, 1}, false},
		{"class_a", "10.0.0.1", Address{10, 0, 0, 1}, false},
		{"class_b", "172.16.0.1", Address{172, 16, 0, 1}, false},
		{"link_local", "169.254.1.1", Address{169, 254, 1, 1}, false},
		{"multicast", "224.0.0.1", Address{224, 0, 0, 1}, false},

		// Error cases.
		{"empty", "", Address{}, true},
		{"too_few_octets", "1.2.3", Address{}, true},
		{"too_many_octets", "1.2.3.4.5", Address{}, true},
		{"octet_too_large", "256.0.0.0", Address{}, true},
		{"negative_octet", "-1.0.0.0", Address{}, true},
		{"leading_zero", "01.02.03.04", Address{}, true},
		{"non_numeric", "a.b.c.d", Address{}, true},
		{"trailing_dot", "1.2.3.", Address{}, true},
		{"leading_dot", ".1.2.3", Address{}, true},
		{"double_dot", "1..2.3", Address{}, true},
		{"spaces", "1 .2.3.4", Address{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AddressFromString(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("AddressFromString(%q) = %v, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("AddressFromString(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("AddressFromString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestAddressString(t *testing.T) {
	tests := []struct {
		addr Address
		want string
	}{
		{Address{0, 0, 0, 0}, "0.0.0.0"},
		{Address{127, 0, 0, 1}, "127.0.0.1"},
		{Address{255, 255, 255, 255}, "255.255.255.255"},
		{Address{192, 168, 1, 100}, "192.168.1.100"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.addr.String()
			if got != tt.want {
				t.Errorf("Address.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAddressRoundTrip(t *testing.T) {
	addrs := []string{
		"0.0.0.0",
		"127.0.0.1",
		"255.255.255.255",
		"10.20.30.40",
		"192.168.0.1",
	}
	for _, s := range addrs {
		addr, err := AddressFromString(s)
		if err != nil {
			t.Fatalf("AddressFromString(%q) error: %v", s, err)
		}
		got := addr.String()
		if got != s {
			t.Errorf("round-trip: %q -> %q", s, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Address classification
// ---------------------------------------------------------------------------

func TestAddressIsUnspecified(t *testing.T) {
	if !(Address{}).IsUnspecified() {
		t.Error("zero address should be unspecified")
	}
	if (Address{1, 0, 0, 0}).IsUnspecified() {
		t.Error("non-zero address should not be unspecified")
	}
}

func TestAddressIsLoopback(t *testing.T) {
	tests := []struct {
		addr Address
		want bool
	}{
		{Address{127, 0, 0, 1}, true},
		{Address{127, 255, 255, 255}, true},
		{Address{127, 0, 0, 0}, true},
		{Address{128, 0, 0, 1}, false},
		{Address{0, 0, 0, 0}, false},
	}
	for _, tt := range tests {
		got := tt.addr.IsLoopback()
		if got != tt.want {
			t.Errorf("%v.IsLoopback() = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestAddressIsMulticast(t *testing.T) {
	tests := []struct {
		addr Address
		want bool
	}{
		{Address{224, 0, 0, 1}, true},
		{Address{239, 255, 255, 255}, true},
		{Address{240, 0, 0, 1}, false},
		{Address{223, 255, 255, 255}, false},
		{Address{0, 0, 0, 0}, false},
	}
	for _, tt := range tests {
		got := tt.addr.IsMulticast()
		if got != tt.want {
			t.Errorf("%v.IsMulticast() = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestAddressIsLinkLocal(t *testing.T) {
	tests := []struct {
		addr Address
		want bool
	}{
		{Address{169, 254, 0, 0}, true},
		{Address{169, 254, 255, 255}, true},
		{Address{169, 253, 0, 0}, false},
		{Address{169, 255, 0, 0}, false},
		{Address{0, 0, 0, 0}, false},
	}
	for _, tt := range tests {
		got := tt.addr.IsLinkLocal()
		if got != tt.want {
			t.Errorf("%v.IsLinkLocal() = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestAddressIsBroadcast(t *testing.T) {
	if !(Address{255, 255, 255, 255}).IsBroadcast() {
		t.Error("255.255.255.255 should be broadcast")
	}
	if (Address{255, 255, 255, 254}).IsBroadcast() {
		t.Error("255.255.255.254 should not be broadcast")
	}
}

// ---------------------------------------------------------------------------
// CIDR
// ---------------------------------------------------------------------------

func TestCIDRFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		wantPfx uint8
	}{
		{"class_c", "192.168.1.0/24", false, 24},
		{"host", "10.0.0.1/32", false, 32},
		{"default", "0.0.0.0/0", false, 0},
		{"slash_16", "172.16.0.0/16", false, 16},
		{"no_slash", "10.0.0.0", true, 0},
		{"bad_prefix", "10.0.0.0/33", true, 0},
		{"empty_prefix", "10.0.0.0/", true, 0},
		{"bad_addr", "999.0.0.0/8", true, 0},
		{"negative_prefix", "10.0.0.0/-1", true, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr, err := CIDRFromString(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("CIDRFromString(%q) = %v, want error", tt.input, cidr)
				}
				return
			}
			if err != nil {
				t.Fatalf("CIDRFromString(%q) unexpected error: %v", tt.input, err)
			}
			if cidr.PrefixLength != tt.wantPfx {
				t.Errorf("CIDRFromString(%q).PrefixLength = %d, want %d", tt.input, cidr.PrefixLength, tt.wantPfx)
			}
		})
	}
}

func TestCIDRString(t *testing.T) {
	cidr := CIDR{Address: Address{192, 168, 1, 0}, PrefixLength: 24}
	got := cidr.String()
	want := "192.168.1.0/24"
	if got != want {
		t.Errorf("CIDR.String() = %q, want %q", got, want)
	}
}

func TestCIDRContains(t *testing.T) {
	cidr := CIDR{Address: Address{192, 168, 1, 0}, PrefixLength: 24}
	tests := []struct {
		addr Address
		want bool
	}{
		{Address{192, 168, 1, 0}, true},
		{Address{192, 168, 1, 255}, true},
		{Address{192, 168, 1, 100}, true},
		{Address{192, 168, 2, 0}, false},
		{Address{10, 0, 0, 1}, false},
	}
	for _, tt := range tests {
		got := cidr.Contains(tt.addr)
		if got != tt.want {
			t.Errorf("CIDR(%s).Contains(%v) = %v, want %v", cidr.String(), tt.addr, got, tt.want)
		}
	}
}

func TestCIDRContainsEdgeCases(t *testing.T) {
	// /0 matches everything.
	cidr0 := CIDR{Address: Address{0, 0, 0, 0}, PrefixLength: 0}
	if !cidr0.Contains(Address{1, 2, 3, 4}) {
		t.Error("/0 should contain any address")
	}

	// /32 matches only the exact address.
	cidr32 := CIDR{Address: Address{10, 0, 0, 1}, PrefixLength: 32}
	if !cidr32.Contains(Address{10, 0, 0, 1}) {
		t.Error("/32 should contain exact address")
	}
	if cidr32.Contains(Address{10, 0, 0, 2}) {
		t.Error("/32 should not contain different address")
	}
}

func TestCIDREqual(t *testing.T) {
	a := CIDR{Address: Address{192, 168, 1, 0}, PrefixLength: 24}
	b := CIDR{Address: Address{192, 168, 1, 0}, PrefixLength: 24}
	c := CIDR{Address: Address{192, 168, 2, 0}, PrefixLength: 24}
	d := CIDR{Address: Address{192, 168, 1, 0}, PrefixLength: 25}

	if !a.Equal(b) {
		t.Error("identical CIDRs should be equal")
	}
	if a.Equal(c) {
		t.Error("different network CIDRs should not be equal")
	}
	if a.Equal(d) {
		t.Error("different prefix length CIDRs should not be equal")
	}
}

func TestSynthesizeFromCIDRAndHost(t *testing.T) {
	cidr := CIDR{Address: Address{192, 168, 1, 0}, PrefixLength: 24}
	got := SynthesizeFromCIDRAndHost(cidr, 42)
	want := Address{192, 168, 1, 42}
	if got != want {
		t.Errorf("SynthesizeFromCIDRAndHost(%s, 42) = %v, want %v", cidr.String(), got, want)
	}
}

// ---------------------------------------------------------------------------
// Header marshal/unmarshal
// ---------------------------------------------------------------------------

func TestHeaderInitAndMarshal(t *testing.T) {
	var h Header
	h.Init()
	h.SetTotalLength(60)
	h.SetTTL(64)
	h.SetProtocol(ProtocolTCP)
	h.SetSource(Address{192, 168, 1, 1})
	h.SetDestination(Address{10, 0, 0, 1})
	h.SetIdentification(0x1234)

	// Verify field reads.
	if !h.IsValid() {
		t.Error("initialized header should be valid")
	}
	if h.GetVersion() != 4 {
		t.Errorf("version = %d, want 4", h.GetVersion())
	}
	if h.GetIHL() != 5 {
		t.Errorf("IHL = %d, want 5", h.GetIHL())
	}
	if h.GetHeaderLength() != 20 {
		t.Errorf("header length = %d, want 20", h.GetHeaderLength())
	}
	if h.GetTotalLength() != 60 {
		t.Errorf("total length = %d, want 60", h.GetTotalLength())
	}
	if h.GetTTL() != 64 {
		t.Errorf("TTL = %d, want 64", h.GetTTL())
	}
	if h.GetProtocol() != ProtocolTCP {
		t.Errorf("protocol = %d, want %d", h.GetProtocol(), ProtocolTCP)
	}
	if h.GetIdentification() != 0x1234 {
		t.Errorf("identification = %x, want 0x1234", h.GetIdentification())
	}
	if h.GetSource() != (Address{192, 168, 1, 1}) {
		t.Errorf("source = %v, want 192.168.1.1", h.GetSource())
	}
	if h.GetDestination() != (Address{10, 0, 0, 1}) {
		t.Errorf("destination = %v, want 10.0.0.1", h.GetDestination())
	}
}

func TestHeaderMarshalUnmarshalRoundTrip(t *testing.T) {
	var h Header
	h.Init()
	h.SetTotalLength(40)
	h.SetTTL(128)
	h.SetProtocol(ProtocolUDP)
	h.SetSource(Address{10, 0, 0, 1})
	h.SetDestination(Address{10, 0, 0, 2})
	h.SetIdentification(0xABCD)
	h.SetDF(true)
	h.ComputeChecksum()

	wire := h.Marshal()

	var h2 Header
	if err := h2.Unmarshal(wire[:]); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if h2.GetTotalLength() != 40 {
		t.Errorf("total length = %d, want 40", h2.GetTotalLength())
	}
	if h2.GetTTL() != 128 {
		t.Errorf("TTL = %d, want 128", h2.GetTTL())
	}
	if h2.GetProtocol() != ProtocolUDP {
		t.Errorf("protocol = %d, want %d", h2.GetProtocol(), ProtocolUDP)
	}
	if h2.GetSource() != (Address{10, 0, 0, 1}) {
		t.Errorf("source mismatch")
	}
	if h2.GetDestination() != (Address{10, 0, 0, 2}) {
		t.Errorf("destination mismatch")
	}
	if !h2.GetDF() {
		t.Error("DF flag should be set")
	}
	if !h2.VerifyChecksum() {
		t.Error("checksum should verify after round-trip")
	}
}

func TestHeaderUnmarshalTooShort(t *testing.T) {
	var h Header
	err := h.Unmarshal([]byte{0x45, 0x00, 0x00})
	if err == nil {
		t.Error("Unmarshal with 3 bytes should fail")
	}
}

func TestHeaderUnmarshalInvalidVersion(t *testing.T) {
	// A buffer with version 6 instead of 4.
	buf := make([]byte, HeaderMinSize)
	buf[0] = 0x65 // version 6, IHL 5
	var h Header
	err := h.Unmarshal(buf)
	if err == nil {
		t.Error("Unmarshal with version 6 should fail")
	}
}

func TestHeaderMarshalToShortBuffer(t *testing.T) {
	var h Header
	h.Init()
	err := h.MarshalTo(make([]byte, 10))
	if err == nil {
		t.Error("MarshalTo with short buffer should fail")
	}
}

func TestHeaderMarshalToSuccess(t *testing.T) {
	var h Header
	h.Init()
	h.SetTTL(42)
	buf := make([]byte, HeaderMinSize+10)
	if err := h.MarshalTo(buf); err != nil {
		t.Fatalf("MarshalTo error: %v", err)
	}
	// Verify TTL byte is in the right position.
	if buf[hdrOffTTL] != 42 {
		t.Errorf("TTL byte = %d, want 42", buf[hdrOffTTL])
	}
}

// ---------------------------------------------------------------------------
// Header DSCP/ECN
// ---------------------------------------------------------------------------

func TestHeaderDscpEcn(t *testing.T) {
	var h Header
	h.Init()

	h.SetDscp(46) // EF = 46
	if h.GetDscp() != 46 {
		t.Errorf("DSCP = %d, want 46", h.GetDscp())
	}

	h.SetEcn(ip6.EcnMarked)
	if h.GetEcn() != ip6.EcnMarked {
		t.Errorf("ECN = %d, want %d", h.GetEcn(), ip6.EcnMarked)
	}

	// Verify DSCP didn't change.
	if h.GetDscp() != 46 {
		t.Errorf("DSCP changed after SetEcn: %d, want 46", h.GetDscp())
	}

	// Verify ECN didn't change.
	h.SetDscp(0)
	if h.GetEcn() != ip6.EcnMarked {
		t.Errorf("ECN changed after SetDscp: %d, want %d", h.GetEcn(), ip6.EcnMarked)
	}
}

// ---------------------------------------------------------------------------
// Header flags and fragment offset
// ---------------------------------------------------------------------------

func TestHeaderFlags(t *testing.T) {
	var h Header
	h.Init()

	// DF flag.
	if h.GetDF() {
		t.Error("DF should be false initially")
	}
	h.SetDF(true)
	if !h.GetDF() {
		t.Error("DF should be true after SetDF(true)")
	}
	h.SetDF(false)
	if h.GetDF() {
		t.Error("DF should be false after SetDF(false)")
	}

	// MF flag.
	if h.GetMF() {
		t.Error("MF should be false initially")
	}
	h.SetMF(true)
	if !h.GetMF() {
		t.Error("MF should be true after SetMF(true)")
	}

	// Fragment offset.
	h.SetFragmentOffset(100)
	if h.GetFragmentOffset() != 100 {
		t.Errorf("fragment offset = %d, want 100", h.GetFragmentOffset())
	}
	// MF should still be set.
	if !h.GetMF() {
		t.Error("MF should still be set after SetFragmentOffset")
	}
}

// ---------------------------------------------------------------------------
// Checksum
// ---------------------------------------------------------------------------

func TestInternetChecksum(t *testing.T) {
	// RFC 1071 example: 16-bit words summed.
	data := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	cksum := InternetChecksum(data)
	// The sum of these words: 0x0001 + 0xf203 + 0xf4f5 + 0xf6f7 = 0x2ddf0
	// Folded: 0xddf0 + 0x0002 = 0xddf2; complement = 0x220d
	if cksum != 0x220d {
		t.Errorf("InternetChecksum = %04x, want 220d", cksum)
	}
}

func TestInternetChecksumOddLength(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	// Words: 0x0102, 0x0300; sum = 0x0402; complement = 0xfbfd
	cksum := InternetChecksum(data)
	if cksum != 0xfbfd {
		t.Errorf("InternetChecksum odd = %04x, want fbfd", cksum)
	}
}

func TestInternetChecksumEmpty(t *testing.T) {
	cksum := InternetChecksum(nil)
	if cksum != 0xffff {
		t.Errorf("InternetChecksum empty = %04x, want ffff", cksum)
	}
}

func TestHeaderChecksumVerification(t *testing.T) {
	var h Header
	h.Init()
	h.SetTotalLength(20)
	h.SetTTL(64)
	h.SetProtocol(ProtocolICMP)
	h.SetSource(Address{192, 168, 1, 1})
	h.SetDestination(Address{192, 168, 1, 2})
	h.ComputeChecksum()

	if !h.VerifyChecksum() {
		t.Error("checksum should verify after ComputeChecksum")
	}

	// Corrupt a byte and verify failure.
	h.data[hdrOffTTL] = 0
	if h.VerifyChecksum() {
		t.Error("checksum should not verify after corruption")
	}
}

// ---------------------------------------------------------------------------
// Pseudo-header checksum
// ---------------------------------------------------------------------------

func TestPseudoHeaderChecksum(t *testing.T) {
	src := Address{192, 168, 1, 1}
	dst := Address{192, 168, 1, 2}
	cksum := PseudoHeaderChecksum(src, dst, ProtocolUDP, 100)
	// Just verify it produces a non-zero result and is deterministic.
	if cksum == 0 {
		t.Error("PseudoHeaderChecksum should not be zero for non-zero inputs")
	}
	cksum2 := PseudoHeaderChecksum(src, dst, ProtocolUDP, 100)
	if cksum != cksum2 {
		t.Error("PseudoHeaderChecksum should be deterministic")
	}
}

// ---------------------------------------------------------------------------
// NAT64 mapping (RFC 6052)
// ---------------------------------------------------------------------------

func TestMappedToV6Prefix96(t *testing.T) {
	// Well-known prefix 64:ff9b::/96.
	var pfxAddr ip6.Address
	pfxAddr[0] = 0x00
	pfxAddr[1] = 0x64
	pfxAddr[2] = 0xff
	pfxAddr[3] = 0x9b
	prefix := ip6.NewPrefix(pfxAddr, 96)

	addr := Address{192, 0, 2, 1}
	v6, err := MappedToV6(addr, prefix)
	if err != nil {
		t.Fatalf("MappedToV6 error: %v", err)
	}

	// Expected: 64:ff9b::192.0.2.1 = 0064:ff9b:0000:0000:0000:0000:c000:0201
	if v6[12] != 192 || v6[13] != 0 || v6[14] != 2 || v6[15] != 1 {
		t.Errorf("MappedToV6 last 4 bytes = %v, want [192 0 2 1]", v6[12:16])
	}
	if v6[0] != 0x00 || v6[1] != 0x64 || v6[2] != 0xff || v6[3] != 0x9b {
		t.Errorf("MappedToV6 prefix bytes wrong: %v", v6[0:4])
	}
}

func TestMappedToV6Prefix32(t *testing.T) {
	var pfxAddr ip6.Address
	pfxAddr[0] = 0x20
	pfxAddr[1] = 0x01
	pfxAddr[2] = 0x0d
	pfxAddr[3] = 0xb8
	prefix := ip6.NewPrefix(pfxAddr, 32)

	addr := Address{192, 0, 2, 33}
	v6, err := MappedToV6(addr, prefix)
	if err != nil {
		t.Fatalf("MappedToV6 error: %v", err)
	}

	// /32 prefix: IPv4 bytes go at index 4,5,6,7 (skipping index 8).
	// Actually for /32: ip6Idx starts at 4, no skip needed since 4,5,6,7 < 8.
	if v6[4] != 192 || v6[5] != 0 || v6[6] != 2 || v6[7] != 33 {
		t.Errorf("MappedToV6 /32 IPv4 bytes = %v, want [192 0 2 33]", v6[4:8])
	}
}

func TestMappedToV6Prefix64(t *testing.T) {
	var pfxAddr ip6.Address
	pfxAddr[0] = 0x20
	pfxAddr[1] = 0x01
	pfxAddr[2] = 0x0d
	pfxAddr[3] = 0xb8
	pfxAddr[4] = 0x00
	pfxAddr[5] = 0x00
	pfxAddr[6] = 0x00
	pfxAddr[7] = 0x01
	prefix := ip6.NewPrefix(pfxAddr, 64)

	addr := Address{10, 20, 30, 40}
	v6, err := MappedToV6(addr, prefix)
	if err != nil {
		t.Fatalf("MappedToV6 error: %v", err)
	}

	// /64: ip6Idx starts at 8 but skips index 8 -> v4 bytes at 9,10,11,12.
	if v6[8] != 0 { // byte 8 should remain 0 (skip index)
		t.Errorf("MappedToV6 /64 byte[8] = %d, want 0", v6[8])
	}
	if v6[9] != 10 || v6[10] != 20 || v6[11] != 30 || v6[12] != 40 {
		t.Errorf("MappedToV6 /64 IPv4 bytes = %v, want [10 20 30 40]", v6[9:13])
	}
}

func TestMappedToV6InvalidPrefix(t *testing.T) {
	prefix := ip6.NewPrefix(ip6.Address{}, 33) // not a valid NAT64 prefix length
	_, err := MappedToV6(Address{1, 2, 3, 4}, prefix)
	if err == nil {
		t.Error("MappedToV6 with invalid prefix should fail")
	}
}

func TestExtractFromV6Prefix96(t *testing.T) {
	var pfxAddr ip6.Address
	pfxAddr[0] = 0x00
	pfxAddr[1] = 0x64
	pfxAddr[2] = 0xff
	pfxAddr[3] = 0x9b
	prefix := ip6.NewPrefix(pfxAddr, 96)

	var v6 ip6.Address
	copy(v6[0:4], []byte{0x00, 0x64, 0xff, 0x9b})
	v6[12] = 192
	v6[13] = 0
	v6[14] = 2
	v6[15] = 1

	addr, err := ExtractFromV6(v6, prefix)
	if err != nil {
		t.Fatalf("ExtractFromV6 error: %v", err)
	}
	if addr != (Address{192, 0, 2, 1}) {
		t.Errorf("ExtractFromV6 = %v, want 192.0.2.1", addr)
	}
}

func TestNAT64RoundTrip(t *testing.T) {
	prefixLengths := []uint8{32, 40, 48, 56, 64, 96}
	v4addr := Address{10, 20, 30, 40}

	for _, plen := range prefixLengths {
		var pfxAddr ip6.Address
		pfxAddr[0] = 0x20
		pfxAddr[1] = 0x01
		pfxAddr[2] = 0x0d
		pfxAddr[3] = 0xb8
		prefix := ip6.NewPrefix(pfxAddr, plen)

		v6, err := MappedToV6(v4addr, prefix)
		if err != nil {
			t.Fatalf("MappedToV6 plen=%d error: %v", plen, err)
		}

		extracted, err := ExtractFromV6(v6, prefix)
		if err != nil {
			t.Fatalf("ExtractFromV6 plen=%d error: %v", plen, err)
		}

		if extracted != v4addr {
			t.Errorf("NAT64 round-trip plen=%d: got %v, want %v", plen, extracted, v4addr)
		}
	}
}

func TestExtractFromV6InvalidPrefix(t *testing.T) {
	prefix := ip6.NewPrefix(ip6.Address{}, 33)
	_, err := ExtractFromV6(ip6.Address{}, prefix)
	if err == nil {
		t.Error("ExtractFromV6 with invalid prefix should fail")
	}
}

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

func TestProtocolConstants(t *testing.T) {
	if ProtocolICMP != 1 {
		t.Errorf("ProtocolICMP = %d, want 1", ProtocolICMP)
	}
	if ProtocolTCP != 6 {
		t.Errorf("ProtocolTCP = %d, want 6", ProtocolTCP)
	}
	if ProtocolUDP != 17 {
		t.Errorf("ProtocolUDP = %d, want 17", ProtocolUDP)
	}
}

// ---------------------------------------------------------------------------
// ECN constants
// ---------------------------------------------------------------------------

func TestEcnConstants(t *testing.T) {
	if EcnNotCapable != 0 {
		t.Errorf("EcnNotCapable = %d, want 0", EcnNotCapable)
	}
	if EcnCapable0 != 1 {
		t.Errorf("EcnCapable0 = %d, want 1", EcnCapable0)
	}
	if EcnCapable1 != 2 {
		t.Errorf("EcnCapable1 = %d, want 2", EcnCapable1)
	}
	if EcnMarked != 3 {
		t.Errorf("EcnMarked = %d, want 3", EcnMarked)
	}
}

// ---------------------------------------------------------------------------
// Header size constant
// ---------------------------------------------------------------------------

func TestHeaderMinSize(t *testing.T) {
	if HeaderMinSize != 20 {
		t.Errorf("HeaderMinSize = %d, want 20", HeaderMinSize)
	}
}

// ---------------------------------------------------------------------------
// CombineChecksums
// ---------------------------------------------------------------------------

func TestCombineChecksums(t *testing.T) {
	// Splitting a known dataset into two parts and combining should
	// yield the same checksum as computing over the whole.
	data := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	whole := InternetChecksum(data)

	part1 := InternetChecksum(data[:4])
	part2 := InternetChecksum(data[4:])
	combined := CombineChecksums(part1, part2)

	if combined != whole {
		t.Errorf("CombineChecksums(%04x, %04x) = %04x, want %04x", part1, part2, combined, whole)
	}
}

// ---------------------------------------------------------------------------
// CIDR round-trip string
// ---------------------------------------------------------------------------

func TestCIDRRoundTrip(t *testing.T) {
	inputs := []string{
		"0.0.0.0/0",
		"10.0.0.0/8",
		"192.168.1.0/24",
		"10.0.0.1/32",
	}
	for _, s := range inputs {
		cidr, err := CIDRFromString(s)
		if err != nil {
			t.Fatalf("CIDRFromString(%q) error: %v", s, err)
		}
		got := cidr.String()
		if got != s {
			t.Errorf("CIDR round-trip: %q -> %q", s, got)
		}
	}
}
