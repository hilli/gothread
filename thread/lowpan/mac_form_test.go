// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package lowpan

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/hilli/gothread/net/ip6"
)

func TestRFC6282ElidedIIDUsesActualShortFormIncludingZero(t *testing.T) {
	_, _, addresses := literalFragmentFixture()
	// Deliberately retain resolved EUIs too: they must NOT override actual
	// short encapsulation. 0x7e33 is SAM=11/DAM=11; checksum is literal bba8.
	addresses.SrcShort, addresses.DstShort = 0, 0x0800
	addresses.SrcShortValid, addresses.DstShortValid = true, true
	wire := []byte{0x7e, 0x33, 0xf0, 0x15, 0xa4, 0x15, 0xa4, 0xbb, 0xa8}
	for i := byte(0); i < 86; i++ {
		wire = append(wire, i)
	}
	packet, err := DecompressDatagram(wire, addresses, 0)
	if err != nil {
		t.Fatal(err)
	}
	wantSource := [16]byte{0xfe, 0x80, 11: 0xff, 12: 0xfe}
	wantDestination := wantSource
	wantDestination[14] = 8
	if !bytes.Equal(packet[8:24], wantSource[:]) || !bytes.Equal(packet[24:40], wantDestination[:]) {
		t.Fatalf("short-zero/short-0800 IPv6 reconstruction=%x", packet[8:40])
	}
	if packet[16]&2 != 0 || packet[32]&2 != 0 {
		t.Fatal("extended-address U/L inversion was applied to a short IID")
	}
}

func TestRFC6282EncoderCannotElideEUIIIDUnderShortMAC(t *testing.T) {
	_, _, addresses := literalFragmentFixture()
	source := ip6.Address{0xfe, 0x80, 8: 0xa6, 9: 0x17, 10: 0x2b, 11: 0xc3, 12: 0x5d, 13: 0xe6, 14: 0x79, 15: 0x80}
	destination := ip6.Address{0xfe, 0x80, 8: 0x1a, 9: 0x23, 10: 0x45, 11: 0x67, 12: 0x89, 13: 0xab, 14: 0xcd, 15: 0xef}
	header := ip6.NewHeader(source, destination, ip6.ProtoUDP, 64, 8)
	addresses.SrcShort, addresses.DstShort = 0, 0x0800
	addresses.SrcShortValid, addresses.DstShortValid = true, true
	wire, err := CompressHeader(header.Bytes(), addresses, nil)
	if err != nil {
		t.Fatal(err)
	}
	dispatch := binary.BigEndian.Uint16(wire[:2])
	if dispatch&HcSrcAddrMask == HcSrcAddrElided || dispatch&HcDstAddrMask == HcDstAddrElided {
		t.Fatal("EUI-derived IPv6 IID was elided against an actual short MAC")
	}
	raw, _, _, err := DecompressHeader(wire, addresses, nil)
	if err != nil || !bytes.Equal(raw[8:24], source[:]) || !bytes.Equal(raw[24:40], destination[:]) {
		t.Fatalf("carried EUI IID did not roundtrip under short encapsulation: %x %v", raw, err)
	}
}
