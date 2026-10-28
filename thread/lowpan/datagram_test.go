// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package lowpan

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/hilli/gothread/mac/types"
)

func literalFragmentFixture() (first, last []byte, addresses AddressContext) {
	// RFC 4944 section 5.3 / RFC 6282 sections 2 and 4.3:
	// original IPv6 size=134, tag=0x1234; first compressed headers represent
	// 48 original bytes and carry 80 app bytes. FRAGN starts at 128/8=0x10,
	// NOT at (2+7+80)/8. Checksum 0x6141 is independently calculated for
	// fe80::a617:2bc3:5de6:7980 -> fe80::1a23:4567:89ab:cdef, ports 5540,
	// and application bytes 0..85.
	first = []byte{0xc0, 0x86, 0x12, 0x34, 0x7e, 0x33, 0xf0, 0x15, 0xa4, 0x15, 0xa4, 0x61, 0x41}
	for i := byte(0); i < 80; i++ {
		first = append(first, i)
	}
	last = []byte{0xe0, 0x86, 0x12, 0x34, 0x10, 80, 81, 82, 83, 84, 85}
	return first, last, AddressContext{
		SrcExtAddr: types.ExtAddress{0xa4, 0x17, 0x2b, 0xc3, 0x5d, 0xe6, 0x79, 0x80},
		DstExtAddr: types.ExtAddress{0x18, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
	}
}

func TestRFC6282FirstFragmentOriginalByteCoordinates(t *testing.T) {
	first, last, addresses := literalFragmentFixture()
	firstHeader, consumed, err := ParseFragmentHeader(first)
	if err != nil || firstHeader.DatagramSize != 134 || !firstHeader.IsFirst {
		t.Fatalf("literal FRAG1: %+v %v", firstHeader, err)
	}
	expanded, err := DecompressDatagram(first[consumed:], addresses, firstHeader.DatagramSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(expanded) != 128 || len(first)-consumed == len(expanded) {
		t.Fatalf("FRAG1 represented %d original bytes, want 128", len(expanded))
	}
	if expanded[0] != 0x60 || expanded[6] != 17 || expanded[7] != 64 ||
		binary.BigEndian.Uint16(expanded[4:6]) != 94 ||
		binary.BigEndian.Uint16(expanded[44:46]) != 94 ||
		binary.BigEndian.Uint16(expanded[46:48]) != 0x6141 {
		t.Fatalf("expanded IPv6/UDP header=%x", expanded[:48])
	}
	lastHeader, consumed, err := ParseFragmentHeader(last)
	if err != nil || lastHeader.DatagramOffset != 128 || lastHeader.DatagramSize != 134 {
		t.Fatalf("literal FRAGN: %+v %v", lastHeader, err)
	}
	packet := make([]byte, 134)
	copy(packet, expanded)
	copy(packet[lastHeader.DatagramOffset:], last[consumed:])
	for i, value := range packet[48:] {
		if value != byte(i) {
			t.Fatalf("uncompressed coordinate payload[%d]=%d", i, value)
		}
	}
}

func TestRFC4944LiteralHeaderValidation(t *testing.T) {
	for _, wire := range [][]byte{
		{}, {0xc5}, {0xc5, 0, 1}, {0xc0, 0, 1, 2},
		{0xe5, 0, 1, 2}, {0xe5, 0, 1, 2, 0}, {0xe0, 40, 1, 2, 5},
	} {
		if _, _, err := ParseFragmentHeader(wire); err == nil {
			t.Errorf("accepted invalid literal header %x", wire)
		}
	}
	for _, offset := range []uint16{0, 128, 1272} {
		wire, err := AppendFragmentHeader(nil, 1280, 0xbeef, offset)
		if err != nil {
			t.Fatal(err)
		}
		expected := []byte{0xc5, 0, 0xbe, 0xef}
		if offset != 0 {
			expected[0] = 0xe5
			expected = append(expected, byte(offset/8))
		}
		if !bytes.Equal(wire, expected) {
			t.Errorf("wire=%x, literal expectation=%x", wire, expected)
		}
	}
	for _, invalid := range []struct{ size, offset uint16 }{
		{39, 0}, {2048, 0}, {1280, 1}, {1280, 1280}, {1280, 65528},
	} {
		if _, err := AppendFragmentHeader(nil, invalid.size, 1, invalid.offset); err == nil {
			t.Errorf("encoded invalid size/offset %+v", invalid)
		}
	}
}

func TestFirstFragmentRejectsTruncationAndUnsupportedHeaders(t *testing.T) {
	first, _, addresses := literalFragmentFixture()
	compressed := first[4:13] // Complete compressed IPv6 and UDP headers.
	for i := 0; i < len(compressed); i++ {
		if _, err := DecompressDatagram(compressed[:i], addresses, 134); err == nil {
			t.Errorf("accepted truncated first header %x", compressed[:i])
		}
	}
	for _, edit := range []func([]byte){
		func(b []byte) { b[2] |= NhcUDPChecksum },
		func(b []byte) { b[0] |= 0x01; b[1] |= byte(HcDstAddrContext) },
		func(b []byte) { b[7], b[8] = 0, 0 },
	} {
		bad := append([]byte(nil), compressed...)
		edit(bad)
		if _, err := DecompressDatagram(bad, addresses, 134); err == nil {
			t.Errorf("accepted malformed/unsupported first header %x", bad)
		}
	}
}

func TestNHCUDPPortAndLengthForms(t *testing.T) {
	_, _, addresses := literalFragmentFixture()
	for _, test := range []struct {
		wire     []byte
		src, dst uint16
	}{
		{[]byte{0xf0, 0x15, 0xa4, 0x15, 0xa4, 0x12, 0x34}, 5540, 5540},
		{[]byte{0xf1, 0x15, 0xa4, 0x01, 0x12, 0x34}, 5540, 0xf001},
		{[]byte{0xf2, 0x01, 0x15, 0xa4, 0x12, 0x34}, 0xf001, 5540},
		{[]byte{0xf3, 0x1f, 0x12, 0x34}, 0xf0b1, 0xf0bf},
	} {
		wire := append([]byte{0x7e, 0x33}, test.wire...)
		wire = append(wire, make([]byte, 8)...)
		expanded, err := DecompressDatagram(wire, addresses, 64)
		if err != nil {
			t.Fatal(err)
		}
		if len(expanded) != 56 || binary.BigEndian.Uint16(expanded[40:42]) != test.src ||
			binary.BigEndian.Uint16(expanded[42:44]) != test.dst ||
			binary.BigEndian.Uint16(expanded[44:46]) != 24 {
			t.Errorf("NHC expansion=%x", expanded)
		}
	}

}

func TestOversizeCompressedInputRejectedBeforeAllocation(t *testing.T) {
	input := make([]byte, IPv6MTU+2)
	input[0] = IPv6Dispatch
	allocations := testing.AllocsPerRun(5, func() {
		if result, err := DecompressDatagram(input, AddressContext{}, 0); err == nil || result != nil {
			t.Error("oversized compressed input accepted")
		}
	})
	if allocations != 0 {
		t.Fatalf("oversized input allocated before bounds validation: %v", allocations)
	}
}
