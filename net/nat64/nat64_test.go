// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package nat64

import (
	"testing"
	"time"

	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip4"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// fakeClock returns a controllable clock for deterministic tests.
type fakeClock struct {
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

// nat64Prefix96 returns the well-known 64:ff9b::/96 prefix.
func nat64Prefix96() ip6.Prefix {
	var addr [16]byte
	addr[0] = 0x00
	addr[1] = 0x64
	addr[2] = 0xff
	addr[3] = 0x9b
	return ip6.NewPrefix(addr, 96)
}

// cidr24 returns 192.168.1.0/24.
func cidr24() ip4.CIDR {
	c, _ := ip4.CIDRFromString("192.168.1.0/24")
	return c
}

// cidr30 returns 10.0.0.0/30 — only 2 usable host addresses (1 and 2).
func cidr30() ip4.CIDR {
	c, _ := ip4.CIDRFromString("10.0.0.0/30")
	return c
}

// newTestTranslator creates a translator in the Active state with the
// well-known 64:ff9b::/96 prefix and 192.168.1.0/24 CIDR.
func newTestTranslator(clock *fakeClock) *Translator {
	t := NewTranslator(WithClock(clock.Now), WithMaxMappings(16))
	t.SetEnabled(true)
	t.SetNat64Prefix(nat64Prefix96())
	_ = t.SetIPv4CIDR(cidr24())
	return t
}

// buildIPv6Packet constructs a minimal IPv6 packet with the given fields.
func buildIPv6Packet(src, dst ip6.Address, nextHeader, hopLimit uint8, payload []byte) []byte {
	pkt := make([]byte, ip6.HeaderSize+len(payload))
	pkt[0] = 0x60 // version 6
	encoding.BigEndianWriteUint16(uint16(len(payload)), pkt[4:6])
	pkt[6] = nextHeader
	pkt[7] = hopLimit
	copy(pkt[8:24], src[:])
	copy(pkt[24:40], dst[:])
	copy(pkt[ip6.HeaderSize:], payload)
	return pkt
}

// buildIPv4Packet constructs a minimal IPv4 packet from a header and payload.
func buildIPv4Packet(src, dst ip4.Address, protocol, ttl uint8, payload []byte) []byte {
	var hdr ip4.Header
	hdr.Init()
	hdr.SetProtocol(protocol)
	hdr.SetTTL(ttl)
	hdr.SetSource(src)
	hdr.SetDestination(dst)
	hdr.SetTotalLength(uint16(ip4.HeaderMinSize + len(payload)))

	raw := hdr.Marshal()
	pkt := make([]byte, ip4.HeaderMinSize+len(payload))
	copy(pkt, raw[:])
	copy(pkt[ip4.HeaderMinSize:], payload)

	// Compute header checksum.
	pkt[10] = 0
	pkt[11] = 0
	csum := ip4.InternetChecksum(pkt[:ip4.HeaderMinSize])
	encoding.BigEndianWriteUint16(csum, pkt[10:12])

	return pkt
}

// makeUDPPayload creates a minimal UDP payload (8 bytes header + data).
// Checksum is left as zero (valid for IPv4 UDP; set separately if needed).
func makeUDPPayload(srcPort, dstPort uint16, data []byte) []byte {
	length := uint16(8 + len(data))
	buf := make([]byte, length)
	encoding.BigEndianWriteUint16(srcPort, buf[0:2])
	encoding.BigEndianWriteUint16(dstPort, buf[2:4])
	encoding.BigEndianWriteUint16(length, buf[4:6])
	// checksum at buf[6:8] = 0
	copy(buf[8:], data)
	return buf
}

// makeTCPPayload creates a minimal TCP payload (20 bytes header, no options/data).
func makeTCPPayload(srcPort, dstPort uint16) []byte {
	buf := make([]byte, 20)
	encoding.BigEndianWriteUint16(srcPort, buf[0:2])
	encoding.BigEndianWriteUint16(dstPort, buf[2:4])
	buf[12] = 5 << 4 // data offset = 5 (20 bytes)
	// checksum at buf[16:18] = 0
	return buf
}

// makeICMPv6EchoRequest creates an ICMPv6 echo request payload.
func makeICMPv6EchoRequest(id, seq uint16) []byte {
	buf := make([]byte, 8)
	buf[0] = icmp6EchoRequest // type
	buf[1] = 0                // code
	// checksum at buf[2:4] = 0 (computed by translator)
	encoding.BigEndianWriteUint16(id, buf[4:6])
	encoding.BigEndianWriteUint16(seq, buf[6:8])
	return buf
}

// makeICMPv4EchoReply creates an ICMPv4 echo reply payload.
func makeICMPv4EchoReply(id, seq uint16) []byte {
	buf := make([]byte, 8)
	buf[0] = icmp4EchoReply
	buf[1] = 0
	encoding.BigEndianWriteUint16(id, buf[4:6])
	encoding.BigEndianWriteUint16(seq, buf[6:8])
	return buf
}

// ipv6FromIPv4 synthesizes an IPv6 address from an IPv4 address using /96 prefix.
func ipv6FromIPv4(v4 ip4.Address) ip6.Address {
	v6, _ := ip4.MappedToV6(v4, nat64Prefix96())
	return v6
}

// ---------------------------------------------------------------------------
// State Machine Tests
// ---------------------------------------------------------------------------

func TestNewTranslatorDefaultState(t *testing.T) {
	tr := NewTranslator()
	if tr.GetState() != StateDisabled {
		t.Fatalf("expected Disabled, got %v", tr.GetState())
	}
}

func TestEnableWithoutConfig(t *testing.T) {
	tr := NewTranslator()
	tr.SetEnabled(true)
	if tr.GetState() != StateNotRunning {
		t.Fatalf("expected NotRunning, got %v", tr.GetState())
	}
}

func TestEnableWithPrefixOnly(t *testing.T) {
	tr := NewTranslator()
	tr.SetEnabled(true)
	tr.SetNat64Prefix(nat64Prefix96())
	if tr.GetState() != StateNotRunning {
		t.Fatalf("expected NotRunning, got %v", tr.GetState())
	}
}

func TestEnableWithCIDROnly(t *testing.T) {
	tr := NewTranslator()
	tr.SetEnabled(true)
	_ = tr.SetIPv4CIDR(cidr24())
	if tr.GetState() != StateNotRunning {
		t.Fatalf("expected NotRunning, got %v", tr.GetState())
	}
}

func TestEnableWithBothConfigs(t *testing.T) {
	tr := NewTranslator()
	tr.SetEnabled(true)
	tr.SetNat64Prefix(nat64Prefix96())
	_ = tr.SetIPv4CIDR(cidr24())
	if tr.GetState() != StateActive {
		t.Fatalf("expected Active, got %v", tr.GetState())
	}
}

func TestDisableFromActive(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)
	if tr.GetState() != StateActive {
		t.Fatalf("expected Active, got %v", tr.GetState())
	}
	tr.SetEnabled(false)
	if tr.GetState() != StateDisabled {
		t.Fatalf("expected Disabled, got %v", tr.GetState())
	}
}

func TestClearPrefixGoesToNotRunning(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)
	tr.ClearNat64Prefix()
	if tr.GetState() != StateNotRunning {
		t.Fatalf("expected NotRunning, got %v", tr.GetState())
	}
}

func TestClearCIDRGoesToNotRunning(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)
	tr.ClearIPv4CIDR()
	if tr.GetState() != StateNotRunning {
		t.Fatalf("expected NotRunning, got %v", tr.GetState())
	}
}

func TestSetInvalidCIDR(t *testing.T) {
	tr := NewTranslator()
	err := tr.SetIPv4CIDR(ip4.CIDR{})
	if err != errors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs, got %v", err)
	}
}

func TestStateString(t *testing.T) {
	tests := []struct {
		s    State
		want string
	}{
		{StateDisabled, "Disabled"},
		{StateNotRunning, "NotRunning"},
		{StateIdle, "Idle"},
		{StateActive, "Active"},
		{State(99), "Unknown"},
	}
	for _, tc := range tests {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("State(%d).String() = %q, want %q", tc.s, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Configuration Tests
// ---------------------------------------------------------------------------

func TestGetNat64PrefixNotSet(t *testing.T) {
	tr := NewTranslator()
	_, err := tr.GetNat64Prefix()
	if err != errors.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGetNat64PrefixSet(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)
	p, err := tr.GetNat64Prefix()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.GetLength() != 96 {
		t.Fatalf("prefix length = %d, want 96", p.GetLength())
	}
}

func TestGetIPv4CIDRNotSet(t *testing.T) {
	tr := NewTranslator()
	_, err := tr.GetIPv4CIDR()
	if err != errors.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGetIPv4CIDRSet(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)
	c, err := tr.GetIPv4CIDR()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.PrefixLength != 24 {
		t.Fatalf("prefix length = %d, want 24", c.PrefixLength)
	}
}

func TestSetSameCIDRIsNoop(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	// Create a mapping.
	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	payload := makeUDPPayload(1234, 53, []byte("test"))
	pkt := buildIPv6Packet(src, dst, ip6.ProtoUDP, 64, payload)
	_, _ = tr.TranslateIPv6ToIPv4(pkt)

	if tr.MappingCount() != 1 {
		t.Fatalf("expected 1 mapping, got %d", tr.MappingCount())
	}

	// Setting the same CIDR should not clear mappings.
	_ = tr.SetIPv4CIDR(cidr24())
	if tr.MappingCount() != 1 {
		t.Fatalf("expected 1 mapping after same CIDR, got %d", tr.MappingCount())
	}
}

// ---------------------------------------------------------------------------
// Translation: IPv6 → IPv4 (UDP)
// ---------------------------------------------------------------------------

func TestTranslateIPv6ToIPv4UDP(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	payload := makeUDPPayload(1234, 53, []byte("hello"))
	pkt := buildIPv6Packet(src, dst, ip6.ProtoUDP, 64, payload)

	result, err := tr.TranslateIPv6ToIPv4(pkt)
	if err != nil {
		t.Fatalf("TranslateIPv6ToIPv4 error: %v", err)
	}

	// Verify IPv4 header.
	if result[0]>>4 != 4 {
		t.Fatalf("expected IPv4 version 4, got %d", result[0]>>4)
	}

	var hdr ip4.Header
	if err := hdr.Unmarshal(result); err != nil {
		t.Fatalf("failed to unmarshal IPv4 header: %v", err)
	}

	if hdr.GetProtocol() != ip4.ProtocolUDP {
		t.Fatalf("protocol = %d, want UDP(%d)", hdr.GetProtocol(), ip4.ProtocolUDP)
	}
	if hdr.GetTTL() != 64 {
		t.Fatalf("TTL = %d, want 64", hdr.GetTTL())
	}
	if hdr.GetDestination() != (ip4.Address{8, 8, 8, 8}) {
		t.Fatalf("dst = %v, want 8.8.8.8", hdr.GetDestination())
	}

	// Source should be allocated from 192.168.1.0/24.
	src4 := hdr.GetSource()
	if src4[0] != 192 || src4[1] != 168 || src4[2] != 1 {
		t.Fatalf("source not in expected CIDR: %v", src4)
	}

	// Verify IPv4 header checksum.
	if !hdr.VerifyChecksum() {
		t.Fatal("IPv4 header checksum invalid")
	}

	// Verify a mapping was created.
	if tr.MappingCount() != 1 {
		t.Fatalf("expected 1 mapping, got %d", tr.MappingCount())
	}
}

func TestTranslateIPv6ToIPv4MappingReuse(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	payload := makeUDPPayload(1234, 53, []byte("q1"))
	pkt := buildIPv6Packet(src, dst, ip6.ProtoUDP, 64, payload)

	result1, _ := tr.TranslateIPv6ToIPv4(pkt)
	result2, _ := tr.TranslateIPv6ToIPv4(pkt)

	if tr.MappingCount() != 1 {
		t.Fatalf("expected 1 mapping (reused), got %d", tr.MappingCount())
	}

	// Both should have the same source IPv4 address.
	var hdr1, hdr2 ip4.Header
	_ = hdr1.Unmarshal(result1)
	_ = hdr2.Unmarshal(result2)

	if hdr1.GetSource() != hdr2.GetSource() {
		t.Fatalf("mapping not reused: %v vs %v", hdr1.GetSource(), hdr2.GetSource())
	}
}

// ---------------------------------------------------------------------------
// Translation: IPv6 → IPv4 (TCP)
// ---------------------------------------------------------------------------

func TestTranslateIPv6ToIPv4TCP(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	dst := ipv6FromIPv4(ip4.Address{1, 1, 1, 1})
	payload := makeTCPPayload(5000, 80)
	pkt := buildIPv6Packet(src, dst, ip6.ProtoTCP, 128, payload)

	result, err := tr.TranslateIPv6ToIPv4(pkt)
	if err != nil {
		t.Fatalf("TranslateIPv6ToIPv4 TCP error: %v", err)
	}

	var hdr ip4.Header
	_ = hdr.Unmarshal(result)

	if hdr.GetProtocol() != ip4.ProtocolTCP {
		t.Fatalf("protocol = %d, want TCP(%d)", hdr.GetProtocol(), ip4.ProtocolTCP)
	}
	if hdr.GetTTL() != 128 {
		t.Fatalf("TTL = %d, want 128", hdr.GetTTL())
	}
}

// ---------------------------------------------------------------------------
// Translation: IPv6 → IPv4 (ICMPv6 echo request → ICMPv4 echo request)
// ---------------------------------------------------------------------------

func TestTranslateIPv6ToIPv4ICMPEcho(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}
	dst := ipv6FromIPv4(ip4.Address{8, 8, 4, 4})
	payload := makeICMPv6EchoRequest(0x1234, 1)
	pkt := buildIPv6Packet(src, dst, ip6.ProtoICMPv6, 64, payload)

	result, err := tr.TranslateIPv6ToIPv4(pkt)
	if err != nil {
		t.Fatalf("TranslateIPv6ToIPv4 ICMP error: %v", err)
	}

	var hdr ip4.Header
	_ = hdr.Unmarshal(result)

	if hdr.GetProtocol() != ip4.ProtocolICMP {
		t.Fatalf("protocol = %d, want ICMP(%d)", hdr.GetProtocol(), ip4.ProtocolICMP)
	}

	// ICMPv4 payload starts after IPv4 header.
	icmpPayload := result[ip4.HeaderMinSize:]
	if icmpPayload[0] != icmp4EchoRequest {
		t.Fatalf("ICMP type = %d, want echo request(%d)", icmpPayload[0], icmp4EchoRequest)
	}

	// Verify ICMP checksum.
	csum := ip4.InternetChecksum(icmpPayload)
	if csum != 0 {
		t.Fatalf("ICMP checksum verification failed, residual = 0x%04x", csum)
	}
}

// ---------------------------------------------------------------------------
// Translation: IPv4 → IPv6 (UDP)
// ---------------------------------------------------------------------------

func TestTranslateIPv4ToIPv6UDP(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	// First create a mapping by sending an IPv6→IPv4 packet.
	src6 := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst6 := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	outPayload := makeUDPPayload(1234, 53, []byte("query"))
	outPkt := buildIPv6Packet(src6, dst6, ip6.ProtoUDP, 64, outPayload)

	result4, err := tr.TranslateIPv6ToIPv4(outPkt)
	if err != nil {
		t.Fatalf("outbound translate error: %v", err)
	}

	// Get the allocated IPv4 address.
	var outHdr ip4.Header
	_ = outHdr.Unmarshal(result4)
	mappedIP4 := outHdr.GetSource()

	// Build an IPv4 response.
	respPayload := makeUDPPayload(53, 1234, []byte("response"))
	inPkt := buildIPv4Packet(ip4.Address{8, 8, 8, 8}, mappedIP4, ip4.ProtocolUDP, 64, respPayload)

	result6, err := tr.TranslateIPv4ToIPv6(inPkt)
	if err != nil {
		t.Fatalf("inbound translate error: %v", err)
	}

	// Verify IPv6 header.
	if result6[0]>>4 != 6 {
		t.Fatalf("expected IPv6 version 6, got %d", result6[0]>>4)
	}

	nextHeader := result6[6]
	if nextHeader != ip6.ProtoUDP {
		t.Fatalf("next header = %d, want UDP(%d)", nextHeader, ip6.ProtoUDP)
	}

	// Destination should be the original IPv6 source.
	var resultDst ip6.Address
	copy(resultDst[:], result6[24:40])
	if resultDst != src6 {
		t.Fatalf("dst = %v, want %v", resultDst, src6)
	}
}

// ---------------------------------------------------------------------------
// Translation: IPv4 → IPv6 (ICMP echo reply)
// ---------------------------------------------------------------------------

func TestTranslateIPv4ToIPv6ICMPEchoReply(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	// Create mapping via outbound ICMPv6.
	src6 := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}
	dst6 := ipv6FromIPv4(ip4.Address{8, 8, 4, 4})
	icmp6 := makeICMPv6EchoRequest(0xABCD, 1)
	outPkt := buildIPv6Packet(src6, dst6, ip6.ProtoICMPv6, 64, icmp6)
	out4, err := tr.TranslateIPv6ToIPv4(outPkt)
	if err != nil {
		t.Fatalf("outbound translate error: %v", err)
	}

	var outHdr ip4.Header
	_ = outHdr.Unmarshal(out4)
	mappedIP4 := outHdr.GetSource()

	// Build ICMPv4 echo reply from 8.8.4.4 back to mapped address.
	icmp4 := makeICMPv4EchoReply(0xABCD, 1)
	// Compute ICMP checksum.
	icmp4[2] = 0
	icmp4[3] = 0
	csum := ip4.InternetChecksum(icmp4)
	encoding.BigEndianWriteUint16(csum, icmp4[2:4])

	inPkt := buildIPv4Packet(ip4.Address{8, 8, 4, 4}, mappedIP4, ip4.ProtocolICMP, 64, icmp4)

	result6, err := tr.TranslateIPv4ToIPv6(inPkt)
	if err != nil {
		t.Fatalf("inbound translate error: %v", err)
	}

	// Should be ICMPv6 echo reply.
	icmpPayload := result6[ip6.HeaderSize:]
	if icmpPayload[0] != icmp6EchoReply {
		t.Fatalf("ICMP type = %d, want ICMPv6 echo reply(%d)", icmpPayload[0], icmp6EchoReply)
	}

	nextHdr := result6[6]
	if nextHdr != ip6.ProtoICMPv6 {
		t.Fatalf("next header = %d, want ICMPv6(%d)", nextHdr, ip6.ProtoICMPv6)
	}
}

// ---------------------------------------------------------------------------
// Error Cases
// ---------------------------------------------------------------------------

func TestTranslateNotActiveState(t *testing.T) {
	tr := NewTranslator()
	_, err := tr.TranslateIPv6ToIPv4(make([]byte, 100))
	if err != errors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
	_, err = tr.TranslateIPv4ToIPv6(make([]byte, 100))
	if err != errors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
}

func TestTranslateTruncatedIPv6(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	_, err := tr.TranslateIPv6ToIPv4(make([]byte, 10)) // too short
	if err != errors.ErrDrop {
		t.Fatalf("expected ErrDrop, got %v", err)
	}
}

func TestTranslateTruncatedIPv4(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	_, err := tr.TranslateIPv4ToIPv6(make([]byte, 10)) // too short
	if err != errors.ErrDrop {
		t.Fatalf("expected ErrDrop, got %v", err)
	}
}

func TestTranslateIPv6WrongVersion(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	pkt := make([]byte, 60)
	pkt[0] = 0x40 // version 4, not 6
	_, err := tr.TranslateIPv6ToIPv4(pkt)
	if err != errors.ErrDrop {
		t.Fatalf("expected ErrDrop for wrong version, got %v", err)
	}
}

func TestTranslateIPv6DstNotMatchingPrefix(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := ip6.Address{0x20, 0x01, 0x0d, 0xb8} // not matching prefix
	payload := makeUDPPayload(1234, 53, nil)
	pkt := buildIPv6Packet(src, dst, ip6.ProtoUDP, 64, payload)

	_, err := tr.TranslateIPv6ToIPv4(pkt)
	if err != errors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState for non-matching prefix, got %v", err)
	}
}

func TestTranslateIPv6UnsupportedProtocol(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	payload := make([]byte, 20)                       // some payload
	pkt := buildIPv6Packet(src, dst, 47, 64, payload) // GRE protocol (47) — not supported

	_, err := tr.TranslateIPv6ToIPv4(pkt)
	if err != errors.ErrDrop {
		t.Fatalf("expected ErrDrop for unsupported protocol, got %v", err)
	}
}

func TestTranslateIPv6TruncatedUDPPayload(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	payload := make([]byte, 4) // too short for UDP header (needs 8)
	pkt := buildIPv6Packet(src, dst, ip6.ProtoUDP, 64, payload)

	_, err := tr.TranslateIPv6ToIPv4(pkt)
	if err != errors.ErrDrop {
		t.Fatalf("expected ErrDrop for truncated UDP, got %v", err)
	}
}

func TestTranslateIPv4NoMapping(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	// Try to translate an inbound packet without an existing mapping.
	payload := makeUDPPayload(53, 1234, []byte("response"))
	pkt := buildIPv4Packet(ip4.Address{8, 8, 8, 8}, ip4.Address{192, 168, 1, 1}, ip4.ProtocolUDP, 64, payload)

	_, err := tr.TranslateIPv4ToIPv6(pkt)
	if err != errors.ErrDrop {
		t.Fatalf("expected ErrDrop for no mapping, got %v", err)
	}
}

func TestTranslateUnsupportedICMPv6Type(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	payload := make([]byte, 8)
	payload[0] = 135 // Neighbor Solicitation — not echo
	pkt := buildIPv6Packet(src, dst, ip6.ProtoICMPv6, 64, payload)

	_, err := tr.TranslateIPv6ToIPv4(pkt)
	if err != errors.ErrDrop {
		t.Fatalf("expected ErrDrop for unsupported ICMPv6 type, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Address Mapping Tests
// ---------------------------------------------------------------------------

func TestMappingExpiration(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	payload := makeUDPPayload(1234, 53, nil)
	pkt := buildIPv6Packet(src, dst, ip6.ProtoUDP, 64, payload)

	_, _ = tr.TranslateIPv6ToIPv4(pkt)
	if tr.MappingCount() != 1 {
		t.Fatalf("expected 1 mapping, got %d", tr.MappingCount())
	}

	// Advance past idle timeout.
	clk.Advance(DefaultIdleTimeout + time.Second)
	tr.RemoveExpiredMappings()

	if tr.MappingCount() != 0 {
		t.Fatalf("expected 0 mappings after expiration, got %d", tr.MappingCount())
	}
}

func TestICMPMappingUsesICMPTimeout(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := ipv6FromIPv4(ip4.Address{8, 8, 4, 4})
	payload := makeICMPv6EchoRequest(1, 1)
	pkt := buildIPv6Packet(src, dst, ip6.ProtoICMPv6, 64, payload)

	_, _ = tr.TranslateIPv6ToIPv4(pkt)

	// Advance past ICMP timeout but within idle timeout.
	clk.Advance(DefaultICMPTimeout + time.Second)
	tr.RemoveExpiredMappings()

	if tr.MappingCount() != 0 {
		t.Fatalf("expected 0 mappings after ICMP timeout, got %d", tr.MappingCount())
	}
}

func TestMappingTableFull(t *testing.T) {
	clk := newFakeClock()
	tr := NewTranslator(WithClock(clk.Now), WithMaxMappings(2))
	tr.SetEnabled(true)
	tr.SetNat64Prefix(nat64Prefix96())
	_ = tr.SetIPv4CIDR(cidr24())

	dst := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	payload := makeUDPPayload(1234, 53, nil)

	// Fill the table.
	for i := 0; i < 2; i++ {
		src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i + 1)}
		pkt := buildIPv6Packet(src, dst, ip6.ProtoUDP, 64, payload)
		_, err := tr.TranslateIPv6ToIPv4(pkt)
		if err != nil {
			t.Fatalf("translate %d: %v", i, err)
		}
	}

	if tr.MappingCount() != 2 {
		t.Fatalf("expected 2 mappings, got %d", tr.MappingCount())
	}

	// Third mapping should trigger eviction (advance time past MinEvictTimeout for one).
	clk.Advance(MinEvictTimeout + time.Second)

	// Touch only the second mapping to keep it fresh.
	src2 := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	pkt2 := buildIPv6Packet(src2, dst, ip6.ProtoUDP, 64, payload)
	_, _ = tr.TranslateIPv6ToIPv4(pkt2)

	// Now add a third — should evict the stale first mapping.
	src3 := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}
	pkt3 := buildIPv6Packet(src3, dst, ip6.ProtoUDP, 64, payload)
	_, err := tr.TranslateIPv6ToIPv4(pkt3)
	if err != nil {
		t.Fatalf("translate third mapping: %v", err)
	}

	if tr.MappingCount() != 2 {
		t.Fatalf("expected 2 mappings after eviction, got %d", tr.MappingCount())
	}
}

func TestGetMappingsSnapshot(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	payload := makeUDPPayload(1234, 53, nil)
	pkt := buildIPv6Packet(src, dst, ip6.ProtoUDP, 64, payload)
	_, _ = tr.TranslateIPv6ToIPv4(pkt)

	mappings := tr.GetMappings()
	if len(mappings) != 1 {
		t.Fatalf("expected 1 mapping snapshot, got %d", len(mappings))
	}
	if mappings[0].IPv6Addr != src {
		t.Fatalf("mapping IPv6 = %v, want %v", mappings[0].IPv6Addr, src)
	}
}

// ---------------------------------------------------------------------------
// Counter Tests
// ---------------------------------------------------------------------------

func TestCounters6To4(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})

	// Send one UDP packet.
	payload := makeUDPPayload(1234, 53, []byte("test"))
	pkt := buildIPv6Packet(src, dst, ip6.ProtoUDP, 64, payload)
	_, _ = tr.TranslateIPv6ToIPv4(pkt)

	c := tr.GetCounters()
	if c.UDP.Packets != 1 {
		t.Fatalf("UDP packets = %d, want 1", c.UDP.Packets)
	}
	if c.Total.Packets != 1 {
		t.Fatalf("total packets = %d, want 1", c.Total.Packets)
	}
}

func TestCounters4To6(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	// Create mapping via outbound.
	src6 := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst6 := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	outPayload := makeUDPPayload(1234, 53, nil)
	outPkt := buildIPv6Packet(src6, dst6, ip6.ProtoUDP, 64, outPayload)
	result4, _ := tr.TranslateIPv6ToIPv4(outPkt)

	var outHdr ip4.Header
	_ = outHdr.Unmarshal(result4)
	mappedIP4 := outHdr.GetSource()

	// Send inbound.
	inPayload := makeUDPPayload(53, 1234, []byte("resp"))
	inPkt := buildIPv4Packet(ip4.Address{8, 8, 8, 8}, mappedIP4, ip4.ProtocolUDP, 64, inPayload)
	_, _ = tr.TranslateIPv4ToIPv6(inPkt)

	c := tr.GetCounters()
	if c.UDP.Packets != 2 { // 1 outbound + 1 inbound
		t.Fatalf("UDP packets = %d, want 2", c.UDP.Packets)
	}
	if c.Total.Packets != 2 {
		t.Fatalf("total packets = %d, want 2", c.Total.Packets)
	}
}

func TestErrorCounters(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	// Truncated packet should increment 6→4 error counter.
	_, _ = tr.TranslateIPv6ToIPv4(make([]byte, 10))

	ec := tr.GetErrorCounters()
	if ec.Count6To4[DropReasonIllegalPacket] != 1 {
		t.Fatalf("expected 1 illegal packet drop, got %d", ec.Count6To4[DropReasonIllegalPacket])
	}

	// No mapping for inbound should increment 4→6 counter.
	payload := makeUDPPayload(53, 1234, nil)
	pkt := buildIPv4Packet(ip4.Address{8, 8, 8, 8}, ip4.Address{192, 168, 1, 1}, ip4.ProtocolUDP, 64, payload)
	_, _ = tr.TranslateIPv4ToIPv6(pkt)

	ec = tr.GetErrorCounters()
	if ec.Count4To6[DropReasonNoMapping] != 1 {
		t.Fatalf("expected 1 no-mapping drop, got %d", ec.Count4To6[DropReasonNoMapping])
	}
}

// ---------------------------------------------------------------------------
// Round-trip Tests
// ---------------------------------------------------------------------------

func TestUDPRoundTrip(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	src6 := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst6 := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	queryData := []byte("DNS query payload here!")
	outPayload := makeUDPPayload(1234, 53, queryData)
	outPkt := buildIPv6Packet(src6, dst6, ip6.ProtoUDP, 64, outPayload)

	// Outbound: IPv6 → IPv4
	pkt4, err := tr.TranslateIPv6ToIPv4(outPkt)
	if err != nil {
		t.Fatalf("outbound: %v", err)
	}

	var outHdr ip4.Header
	_ = outHdr.Unmarshal(pkt4)

	// Verify IPv4 UDP payload data is preserved.
	udp4 := pkt4[ip4.HeaderMinSize:]
	udpData := udp4[8:]
	if string(udpData) != string(queryData) {
		t.Fatalf("outbound data = %q, want %q", string(udpData), string(queryData))
	}

	// Build response.
	respData := []byte("DNS response data!!!")
	respPayload := makeUDPPayload(53, 1234, respData)
	respPkt := buildIPv4Packet(ip4.Address{8, 8, 8, 8}, outHdr.GetSource(), ip4.ProtocolUDP, 64, respPayload)

	// Inbound: IPv4 → IPv6
	pkt6, err := tr.TranslateIPv4ToIPv6(respPkt)
	if err != nil {
		t.Fatalf("inbound: %v", err)
	}

	// Verify destination is the original source.
	var resultDst ip6.Address
	copy(resultDst[:], pkt6[24:40])
	if resultDst != src6 {
		t.Fatalf("inbound dst = %v, want %v", resultDst, src6)
	}

	// Verify source is the NAT64-mapped remote.
	var resultSrc ip6.Address
	copy(resultSrc[:], pkt6[8:24])
	expectedSrc := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	if resultSrc != expectedSrc {
		t.Fatalf("inbound src = %v, want %v", resultSrc, expectedSrc)
	}

	// Verify payload data.
	udp6 := pkt6[ip6.HeaderSize:]
	udp6Data := udp6[8:]
	if string(udp6Data) != string(respData) {
		t.Fatalf("inbound data = %q, want %q", string(udp6Data), string(respData))
	}
}

// ---------------------------------------------------------------------------
// CIDR Address Pool Tests
// ---------------------------------------------------------------------------

func TestSmallCIDRExhaustion(t *testing.T) {
	clk := newFakeClock()
	tr := NewTranslator(WithClock(clk.Now), WithMaxMappings(16))
	tr.SetEnabled(true)
	tr.SetNat64Prefix(nat64Prefix96())
	_ = tr.SetIPv4CIDR(cidr30()) // /30 = 2 usable hosts

	dst := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	payload := makeUDPPayload(1234, 53, nil)

	// First two should succeed.
	for i := 0; i < 2; i++ {
		src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i + 1)}
		pkt := buildIPv6Packet(src, dst, ip6.ProtoUDP, 64, payload)
		_, err := tr.TranslateIPv6ToIPv4(pkt)
		if err != nil {
			t.Fatalf("translate %d: %v", i, err)
		}
	}

	// Third should fail — pool exhausted (mappings not expired).
	src3 := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}
	pkt3 := buildIPv6Packet(src3, dst, ip6.ProtoUDP, 64, payload)
	_, err := tr.TranslateIPv6ToIPv4(pkt3)
	if err != errors.ErrDrop {
		t.Fatalf("expected ErrDrop on pool exhaustion, got %v", err)
	}
}

func TestCIDRChangeClearsMappings(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	// Create a mapping.
	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	payload := makeUDPPayload(1234, 53, nil)
	pkt := buildIPv6Packet(src, dst, ip6.ProtoUDP, 64, payload)
	_, _ = tr.TranslateIPv6ToIPv4(pkt)

	if tr.MappingCount() != 1 {
		t.Fatalf("expected 1 mapping, got %d", tr.MappingCount())
	}

	// Change CIDR — should clear mappings.
	newCIDR, _ := ip4.CIDRFromString("10.0.0.0/24")
	_ = tr.SetIPv4CIDR(newCIDR)

	if tr.MappingCount() != 0 {
		t.Fatalf("expected 0 mappings after CIDR change, got %d", tr.MappingCount())
	}
}

// ---------------------------------------------------------------------------
// Functional Option Tests
// ---------------------------------------------------------------------------

func TestWithMaxMappings(t *testing.T) {
	tr := NewTranslator(WithMaxMappings(4))
	if tr.maxMappings != 4 {
		t.Fatalf("maxMappings = %d, want 4", tr.maxMappings)
	}
}

func TestWithIdleTimeout(t *testing.T) {
	tr := NewTranslator(WithIdleTimeout(10 * time.Minute))
	if tr.idleTimeout != 10*time.Minute {
		t.Fatalf("idleTimeout = %v, want 10m", tr.idleTimeout)
	}
}

func TestWithICMPTimeout(t *testing.T) {
	tr := NewTranslator(WithICMPTimeout(1 * time.Minute))
	if tr.icmpTimeout != 1*time.Minute {
		t.Fatalf("icmpTimeout = %v, want 1m", tr.icmpTimeout)
	}
}

func TestWithMaxMappingsZero(t *testing.T) {
	tr := NewTranslator(WithMaxMappings(0))
	if tr.maxMappings != DefaultMaxMappings {
		t.Fatalf("maxMappings = %d, want default %d", tr.maxMappings, DefaultMaxMappings)
	}
}

// ---------------------------------------------------------------------------
// DSCP/ECN Preservation
// ---------------------------------------------------------------------------

func TestDSCPECNPreserved6To4(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	payload := makeUDPPayload(1234, 53, nil)
	pkt := buildIPv6Packet(src, dst, ip6.ProtoUDP, 64, payload)

	// Set traffic class to DSCP=46 (EF), ECN=1.
	// TC = (DSCP << 2) | ECN = (46 << 2) | 1 = 185 = 0xB9
	tc := byte(0xB9)
	pkt[0] = 0x60 | (tc >> 4)            // version + upper 4 bits of TC
	pkt[1] = (tc << 4) | (pkt[1] & 0x0f) // lower 4 bits of TC + upper flow label

	result, err := tr.TranslateIPv6ToIPv4(pkt)
	if err != nil {
		t.Fatalf("translate error: %v", err)
	}

	var hdr ip4.Header
	_ = hdr.Unmarshal(result)
	if hdr.GetDscp() != 46 {
		t.Fatalf("DSCP = %d, want 46", hdr.GetDscp())
	}
	if uint8(hdr.GetEcn()) != 1 {
		t.Fatalf("ECN = %d, want 1", hdr.GetEcn())
	}
}

func TestDSCPECNPreserved4To6(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	// Create mapping.
	src6 := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst6 := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	outPayload := makeUDPPayload(1234, 53, nil)
	outPkt := buildIPv6Packet(src6, dst6, ip6.ProtoUDP, 64, outPayload)
	result4, _ := tr.TranslateIPv6ToIPv4(outPkt)

	var outHdr ip4.Header
	_ = outHdr.Unmarshal(result4)
	mappedIP4 := outHdr.GetSource()

	// Build IPv4 packet with DSCP=46, ECN=2.
	inPayload := makeUDPPayload(53, 1234, nil)
	inPkt := buildIPv4Packet(ip4.Address{8, 8, 8, 8}, mappedIP4, ip4.ProtocolUDP, 64, inPayload)

	// Manually set DSCP/ECN in ToS field (byte 1).
	tos := (46 << 2) | 2 // 0xBA
	inPkt[1] = byte(tos)
	// Recompute IPv4 header checksum.
	inPkt[10] = 0
	inPkt[11] = 0
	csum := ip4.InternetChecksum(inPkt[:ip4.HeaderMinSize])
	encoding.BigEndianWriteUint16(csum, inPkt[10:12])

	result6, err := tr.TranslateIPv4ToIPv6(inPkt)
	if err != nil {
		t.Fatalf("translate error: %v", err)
	}

	// Extract traffic class from IPv6 header.
	tc6 := (result6[0]&0x0f)<<4 | result6[1]>>4
	dscp6 := tc6 >> 2
	ecn6 := tc6 & 0x03

	if dscp6 != 46 {
		t.Fatalf("DSCP = %d, want 46", dscp6)
	}
	if ecn6 != 2 {
		t.Fatalf("ECN = %d, want 2", ecn6)
	}
}

// ---------------------------------------------------------------------------
// Multiple Different Sources Get Different IPv4 Addresses
// ---------------------------------------------------------------------------

func TestMultipleSourcesGetDifferentIPv4(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	dst := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	payload := makeUDPPayload(1234, 53, nil)

	addrs := make(map[ip4.Address]bool)
	for i := 0; i < 5; i++ {
		src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i + 1)}
		pkt := buildIPv6Packet(src, dst, ip6.ProtoUDP, 64, payload)
		result, err := tr.TranslateIPv6ToIPv4(pkt)
		if err != nil {
			t.Fatalf("translate %d: %v", i, err)
		}
		var hdr ip4.Header
		_ = hdr.Unmarshal(result)
		addr := hdr.GetSource()
		if addrs[addr] {
			t.Fatalf("duplicate IPv4 address %v for source %d", addr, i)
		}
		addrs[addr] = true
	}

	if tr.MappingCount() != 5 {
		t.Fatalf("expected 5 mappings, got %d", tr.MappingCount())
	}
}

// ---------------------------------------------------------------------------
// TTL / Hop Limit preservation
// ---------------------------------------------------------------------------

func TestTTLPreservation(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	payload := makeUDPPayload(1234, 53, nil)

	for _, ttl := range []uint8{1, 64, 128, 255} {
		pkt := buildIPv6Packet(src, dst, ip6.ProtoUDP, ttl, payload)
		result, err := tr.TranslateIPv6ToIPv4(pkt)
		if err != nil {
			t.Fatalf("translate TTL=%d: %v", ttl, err)
		}
		var hdr ip4.Header
		_ = hdr.Unmarshal(result)
		if hdr.GetTTL() != ttl {
			t.Fatalf("TTL = %d, want %d", hdr.GetTTL(), ttl)
		}
	}
}

// ---------------------------------------------------------------------------
// Eviction Priority Tests
// ---------------------------------------------------------------------------

func TestEvictionPrefersICMPOverUDP(t *testing.T) {
	clk := newFakeClock()
	tr := NewTranslator(WithClock(clk.Now), WithMaxMappings(2))
	tr.SetEnabled(true)
	tr.SetNat64Prefix(nat64Prefix96())
	_ = tr.SetIPv4CIDR(cidr24())

	dst := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})

	// First mapping: ICMP.
	src1 := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	icmpPkt := buildIPv6Packet(src1, dst, ip6.ProtoICMPv6, 64, makeICMPv6EchoRequest(1, 1))
	_, _ = tr.TranslateIPv6ToIPv4(icmpPkt)

	// Second mapping: UDP.
	src2 := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	udpPkt := buildIPv6Packet(src2, dst, ip6.ProtoUDP, 64, makeUDPPayload(1234, 53, nil))
	_, _ = tr.TranslateIPv6ToIPv4(udpPkt)

	// Advance past MinEvictTimeout.
	clk.Advance(MinEvictTimeout + time.Second)

	// Third mapping should evict the ICMP mapping (lower priority).
	src3 := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}
	pkt3 := buildIPv6Packet(src3, dst, ip6.ProtoUDP, 64, makeUDPPayload(5678, 80, nil))
	_, err := tr.TranslateIPv6ToIPv4(pkt3)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}

	// The ICMP mapping (src1) should be evicted, not the UDP one (src2).
	if tr.MappingCount() != 2 {
		t.Fatalf("expected 2 mappings, got %d", tr.MappingCount())
	}

	// Verify src1 mapping is gone by checking remaining mappings.
	mappings := tr.GetMappings()
	for _, m := range mappings {
		if m.IPv6Addr == src1 {
			t.Fatal("expected ICMP mapping to be evicted, but it still exists")
		}
	}
}

// ---------------------------------------------------------------------------
// IPv4 Header Checksum Verification
// ---------------------------------------------------------------------------

func TestIPv4HeaderChecksumValid(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	payload := makeUDPPayload(1234, 53, []byte("checksum test"))
	pkt := buildIPv6Packet(src, dst, ip6.ProtoUDP, 64, payload)

	result, err := tr.TranslateIPv6ToIPv4(pkt)
	if err != nil {
		t.Fatalf("translate error: %v", err)
	}

	// Internet checksum of the entire header should be 0.
	headerCsum := ip4.InternetChecksum(result[:ip4.HeaderMinSize])
	if headerCsum != 0 {
		t.Fatalf("IPv4 header checksum verification failed: 0x%04x", headerCsum)
	}
}

// ---------------------------------------------------------------------------
// Payload Length Preserved
// ---------------------------------------------------------------------------

func TestPayloadLengthPreserved6To4(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i)
	}
	payload := makeUDPPayload(1234, 53, data)
	pkt := buildIPv6Packet(src, dst, ip6.ProtoUDP, 64, payload)

	result, err := tr.TranslateIPv6ToIPv4(pkt)
	if err != nil {
		t.Fatalf("translate error: %v", err)
	}

	var hdr ip4.Header
	_ = hdr.Unmarshal(result)

	expectedTotal := uint16(ip4.HeaderMinSize + len(payload))
	if hdr.GetTotalLength() != expectedTotal {
		t.Fatalf("total length = %d, want %d", hdr.GetTotalLength(), expectedTotal)
	}

	resultPayloadLen := len(result) - ip4.HeaderMinSize
	if resultPayloadLen != len(payload) {
		t.Fatalf("payload length = %d, want %d", resultPayloadLen, len(payload))
	}
}

// ---------------------------------------------------------------------------
// IPv6 Payload Length Preserved 4→6
// ---------------------------------------------------------------------------

func TestPayloadLengthPreserved4To6(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	// Create mapping.
	src6 := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst6 := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	outPayload := makeUDPPayload(1234, 53, nil)
	outPkt := buildIPv6Packet(src6, dst6, ip6.ProtoUDP, 64, outPayload)
	result4, _ := tr.TranslateIPv6ToIPv4(outPkt)

	var outHdr ip4.Header
	_ = outHdr.Unmarshal(result4)
	mappedIP4 := outHdr.GetSource()

	// Build inbound with known payload length.
	data := make([]byte, 50)
	for i := range data {
		data[i] = byte(i)
	}
	inPayload := makeUDPPayload(53, 1234, data)
	inPkt := buildIPv4Packet(ip4.Address{8, 8, 8, 8}, mappedIP4, ip4.ProtocolUDP, 64, inPayload)

	result6, err := tr.TranslateIPv4ToIPv6(inPkt)
	if err != nil {
		t.Fatalf("translate error: %v", err)
	}

	payloadLen6 := encoding.BigEndianReadUint16(result6[4:6])
	if int(payloadLen6) != len(inPayload) {
		t.Fatalf("IPv6 payload length = %d, want %d", payloadLen6, len(inPayload))
	}
}

// ---------------------------------------------------------------------------
// DisableClears Mappings
// ---------------------------------------------------------------------------

func TestDisableClearsMappings(t *testing.T) {
	clk := newFakeClock()
	tr := newTestTranslator(clk)

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := ipv6FromIPv4(ip4.Address{8, 8, 8, 8})
	payload := makeUDPPayload(1234, 53, nil)
	pkt := buildIPv6Packet(src, dst, ip6.ProtoUDP, 64, payload)
	_, _ = tr.TranslateIPv6ToIPv4(pkt)

	if tr.MappingCount() != 1 {
		t.Fatalf("expected 1 mapping, got %d", tr.MappingCount())
	}

	tr.SetEnabled(false)

	if tr.MappingCount() != 0 {
		t.Fatalf("expected 0 mappings after disable, got %d", tr.MappingCount())
	}
}
