// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package lowpan

import (
	"testing"

	"github.com/hilli/gothread/mac/types"
)

// Default MAC addresses for test vectors.
var (
	testSrcExtAddr = types.ExtAddress{0x00, 0x00, 0x5e, 0xef, 0x10, 0x22, 0x11, 0x00}
	testDstExtAddr = types.ExtAddress{0x00, 0x00, 0x5e, 0xef, 0x10, 0xaa, 0xbb, 0xcc}
	testSrcShort   = types.ShortAddress(0x0000)
	testDstShort   = types.ShortAddress(0xC003)
)

func testMacAddrs() AddressContext {
	return AddressContext{
		SrcExtAddr: testSrcExtAddr,
		DstExtAddr: testDstExtAddr,
		SrcShort:   testSrcShort,
		DstShort:   testDstShort,
	}
}

// Mesh-local prefix (Context 0): fd00:cafe:face:1234::/64
// Context 1: 2001:2:0:1::/64
// Context 2: 2001:2:0:2::/64
func testContexts() []Context {
	return []Context{
		{
			Prefix:    [16]byte{0xfd, 0x00, 0xca, 0xfe, 0xfa, 0xce, 0x12, 0x34},
			PrefixLen: 64,
		},
		{
			Prefix:    [16]byte{0x20, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01},
			PrefixLen: 64,
		},
		{
			Prefix:    [16]byte{0x20, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02},
			PrefixLen: 64,
		},
	}
}

// srcIIDFromExt is the expected IID derived from testSrcExtAddr with U/L bit toggle.
// ExtAddr = {0x00, 0x00, 0x5e, 0xef, 0x10, 0x22, 0x11, 0x00}
// IID     = {0x02, 0x00, 0x5e, 0xef, 0x10, 0x22, 0x11, 0x00}
var srcIIDFromExt = [8]byte{0x02, 0x00, 0x5e, 0xef, 0x10, 0x22, 0x11, 0x00}

// dstIIDFromExt is the expected IID derived from testDstExtAddr.
var dstIIDFromExt = [8]byte{0x02, 0x00, 0x5e, 0xef, 0x10, 0xaa, 0xbb, 0xcc}

func TestIsLowpanHc(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"valid dispatch", []byte{0x60, 0x00}, true},
		{"valid dispatch 7F", []byte{0x7F, 0xFF}, true},
		{"invalid dispatch 80", []byte{0x80, 0x00}, false},
		{"too short", []byte{0x60}, false},
		{"empty", nil, false},
		{"dispatch 41 (mesh)", []byte{0x41, 0x00}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsLowpanHc(tt.data)
			if got != tt.want {
				t.Errorf("IsLowpanHc(%x) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func TestDecompressHeader(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		macAddrs     AddressContext
		contexts     []Context
		wantHL       uint8
		wantNH       uint8
		wantSrc      [16]byte
		wantDst      [16]byte
		wantTC       uint8
		wantFlow     uint32
		wantConsumed int
		wantErr      bool
	}{
		{
			name: "fully inline TF=00 NH=UDP HL=64 SAM=00 DAM=00",
			data: func() []byte {
				// IPHC = 0x6000: TF=00, NH=inline, HLIM=inline, SAC=0, SAM=00, M=0, DAC=0, DAM=00
				d := []byte{0x60, 0x00}
				d = append(d,
					// TF=00: 4 bytes (ECN=0, DSCP=0, Flow=0)
					0x00, 0x00, 0x00, 0x00,
					// NH = UDP (17)
					0x11,
					// HL = 64
					0x40,
					// Src: fe80::0200:5eef:1022:1100
					0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x5e, 0xef, 0x10, 0x22, 0x11, 0x00,
					// Dst: fe80::0200:5eef:10aa:bbcc
					0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x5e, 0xef, 0x10, 0xaa, 0xbb, 0xcc,
				)
				return d
			}(),
			macAddrs:     testMacAddrs(),
			wantHL:       64,
			wantNH:       17,
			wantSrc:      [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xef, 0x10, 0x22, 0x11, 0x00},
			wantDst:      [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xef, 0x10, 0xaa, 0xbb, 0xcc},
			wantConsumed: 2 + 4 + 1 + 1 + 16 + 16,
		},
		{
			name: "TF=11 HL=1 SAM=11 DAM=11 (elided from MAC ext)",
			// IPHC: 011 11 0 01 0 0 11 0 0 11 = 0111 1001 0011 0011 = 0x7933
			// TF=11, NH=inline, HLIM=01(=1), CID=0, SAC=0, SAM=11, M=0, DAC=0, DAM=11
			data:         []byte{0x79, 0x33, 0x11},
			macAddrs:     testMacAddrs(),
			wantHL:       1,
			wantNH:       17,
			wantSrc:      makeLinkLocalAddr(srcIIDFromExt),
			wantDst:      makeLinkLocalAddr(dstIIDFromExt),
			wantConsumed: 3,
		},
		{
			name: "TF=11 HL=64 SAM=10 DAM=11 (src 16-bit)",
			// IPHC: TF=11, NH=inline, HLIM=10(=64), SAC=0, SAM=10, M=0, DAC=0, DAM=11
			// 011 11_10_0 0_10_0_0_011
			// = 0x7A23
			data: func() []byte {
				d := []byte{0x7A, 0x23}
				d = append(d,
					// NH=UDP
					0x11,
					// 16-bit src short = 0x0000
					0x00, 0x00,
				)
				return d
			}(),
			macAddrs: testMacAddrs(),
			wantHL:   64,
			wantNH:   17,
			wantSrc: func() [16]byte {
				var a [16]byte
				copy(a[:], linkLocalPrefix[:])
				// IID from short 0x0000: 00:00:00:FF:FE:00:00:00
				a[8+3] = 0xFF
				a[8+4] = 0xFE
				return a
			}(),
			wantDst:      makeLinkLocalAddr(dstIIDFromExt),
			wantConsumed: 5,
		},
		{
			name: "TF=11 HL=255 SAM=11 DAM=11 (hop limit 255)",
			// IPHC: TF=11, NH=inline(0), HLIM=11(=255), SAC=0, SAM=11, M=0, DAC=0, DAM=11
			// 0111 1011 0011 0011 = 0x7B33
			data:         []byte{0x7B, 0x33, 0x11},
			macAddrs:     testMacAddrs(),
			wantHL:       255,
			wantNH:       17,
			wantSrc:      makeLinkLocalAddr(srcIIDFromExt),
			wantDst:      makeLinkLocalAddr(dstIIDFromExt),
			wantConsumed: 3,
		},
		{
			name: "TF=11 HL=inline(128) SAM=11 DAM=11",
			// IPHC: TF=11, NH=inline, HLIM=00(inline), SAC=0, SAM=11, M=0, DAC=0, DAM=11
			// 011 11_00_0 0_11_0_0_011 = 0x7833
			data:         []byte{0x78, 0x33, 0x11, 0x80},
			macAddrs:     testMacAddrs(),
			wantHL:       128,
			wantNH:       17,
			wantSrc:      makeLinkLocalAddr(srcIIDFromExt),
			wantDst:      makeLinkLocalAddr(dstIIDFromExt),
			wantConsumed: 4,
		},
		{
			name: "SAM=01 (64-bit IID inline)",
			// IPHC: TF=11, NH=inline, HLIM=01(=1), SAC=0, SAM=01, M=0, DAC=0, DAM=11
			// 011 11_0_01 0_01_0_0_11 = 0x7913
			data: func() []byte {
				d := []byte{0x79, 0x13}
				d = append(d,
					0x11, // NH=UDP
					// 64-bit IID inline for source
					0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44,
				)
				return d
			}(),
			macAddrs: testMacAddrs(),
			wantHL:   1,
			wantNH:   17,
			wantSrc: func() [16]byte {
				var a [16]byte
				copy(a[:], linkLocalPrefix[:])
				copy(a[8:], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44})
				return a
			}(),
			wantDst:      makeLinkLocalAddr(dstIIDFromExt),
			wantConsumed: 11,
		},
		{
			name: "DAM=01 unicast 64-bit IID",
			// IPHC: TF=11, NH=inline, HLIM=01(=1), SAC=0, SAM=11, M=0, DAC=0, DAM=01
			// 011 11_0_01 0_11_0_0_01 = 0x7931
			data: func() []byte {
				d := []byte{0x79, 0x31}
				d = append(d,
					0x11, // NH=UDP
					// 64-bit dst IID inline
					0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
				)
				return d
			}(),
			macAddrs: testMacAddrs(),
			wantHL:   1,
			wantNH:   17,
			wantSrc:  makeLinkLocalAddr(srcIIDFromExt),
			wantDst: func() [16]byte {
				var a [16]byte
				copy(a[:], linkLocalPrefix[:])
				copy(a[8:], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
				return a
			}(),
			wantConsumed: 11,
		},
		{
			name: "DAM=10 unicast 16-bit",
			// IPHC: TF=11, NH=inline, HLIM=01(=1), SAC=0, SAM=11, M=0, DAC=0, DAM=10
			// 011 11_0_01 0_11_0_0_10 = 0x7932
			data: func() []byte {
				d := []byte{0x79, 0x32}
				d = append(d,
					// NH=UDP
					0x11,
					// dst short = 0xC003
					0xC0, 0x03,
				)
				return d
			}(),
			macAddrs: testMacAddrs(),
			wantHL:   1,
			wantNH:   17,
			wantSrc:  makeLinkLocalAddr(srcIIDFromExt),
			wantDst: func() [16]byte {
				var a [16]byte
				copy(a[:], linkLocalPrefix[:])
				// IID from short 0xC003
				a[8+3] = 0xFF
				a[8+4] = 0xFE
				a[8+6] = 0xC0
				a[8+7] = 0x03
				return a
			}(),
			wantConsumed: 5,
		},
		{
			name: "multicast DAM=11 (8-bit ff02::01)",
			// IPHC: TF=11, NH=inline, HLIM=01(=1), SAC=0, SAM=11, M=1, DAC=0, DAM=11
			// 011 11_0_01 0_11_1_0_11 = 0x793B
			data:     []byte{0x79, 0x3B, 0x11, 0x01},
			macAddrs: testMacAddrs(),
			wantHL:   1,
			wantNH:   17,
			wantSrc:  makeLinkLocalAddr(srcIIDFromExt),
			wantDst: func() [16]byte {
				var a [16]byte
				a[0] = 0xFF
				a[1] = 0x02
				a[15] = 0x01
				return a
			}(),
			wantConsumed: 4,
		},
		{
			name: "multicast DAM=10 (32-bit ff05::00db:1234)",
			// M=1, DAC=0, DAM=10: 4 bytes → ffXX::00XX:XXXX
			// IPHC: TF=11, NH=inline, HLIM=01(=1), SAC=0, SAM=11, M=1, DAC=0, DAM=10
			// 011 11_0_01 0_11_1_0_10 = 0x793A
			data: func() []byte {
				d := []byte{0x79, 0x3A}
				d = append(d,
					// NH
					0x11,
					// scope byte → ff05
					0x05,
					// 00DB:1234
					0xDB, 0x12, 0x34,
				)
				return d
			}(),
			macAddrs: testMacAddrs(),
			wantHL:   1,
			wantNH:   17,
			wantSrc:  makeLinkLocalAddr(srcIIDFromExt),
			wantDst: func() [16]byte {
				var a [16]byte
				a[0] = 0xFF
				a[1] = 0x05
				a[13] = 0xDB
				a[14] = 0x12
				a[15] = 0x34
				return a
			}(),
			wantConsumed: 7,
		},
		{
			name: "multicast DAM=01 (48-bit ff15::00db:1234:5678)",
			// M=1, DAC=0, DAM=01: 6 bytes → ffXX::00XX:XXXX:XXXX
			// IPHC: TF=11, NH=inline, HLIM=01(=1), SAC=0, SAM=11, M=1, DAC=0, DAM=01
			// 011 11_0_01 0_11_1_0_01 = 0x7939
			data: func() []byte {
				d := []byte{0x79, 0x39}
				d = append(d,
					// NH
					0x11,
					// scope → ff15
					0x15,
					// byte at [11]
					0xDB,
					0x12, 0x34, 0x56, 0x78,
				)
				return d
			}(),
			macAddrs: testMacAddrs(),
			wantHL:   1,
			wantNH:   17,
			wantSrc:  makeLinkLocalAddr(srcIIDFromExt),
			wantDst: func() [16]byte {
				var a [16]byte
				a[0] = 0xFF
				a[1] = 0x15
				a[11] = 0xDB
				a[12] = 0x12
				a[13] = 0x34
				a[14] = 0x56
				a[15] = 0x78
				return a
			}(),
			wantConsumed: 9,
		},
		{
			name: "multicast DAM=00 (128-bit inline)",
			// M=1, DAC=0, DAM=00: full 128-bit multicast address inline.
			// IPHC: TF=11, NH=inline, HLIM=01(=1), SAC=0, SAM=11, M=1, DAC=0, DAM=00
			// 011 11_0_01 0_11_1_0_00 = 0x7938
			data: func() []byte {
				d := []byte{0x79, 0x38}
				d = append(d,
					0x11, // NH=UDP
					// Full multicast addr ff05::1
					0xFF, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				)
				return d
			}(),
			macAddrs: testMacAddrs(),
			wantHL:   1,
			wantNH:   17,
			wantSrc:  makeLinkLocalAddr(srcIIDFromExt),
			wantDst: func() [16]byte {
				var a [16]byte
				a[0] = 0xFF
				a[1] = 0x05
				a[15] = 0x01
				return a
			}(),
			wantConsumed: 19,
		},
		{
			name: "TF=00 with ECN+DSCP+Flow",
			// IPHC: TF=00, NH=inline, HLIM=01, SAC=0, SAM=11, M=0, DAC=0, DAM=11
			// 011 00_01_0 0_11_0_0_011 = 0x6133
			data: func() []byte {
				d := []byte{0x61, 0x33}
				// TF=00: 4 bytes. ECN=2, DSCP=7 → inline[0] = (2<<6)|7 = 0x87
				// Flow = 0x12345 → inline[1] = 0x01, inline[2] = 0x23, inline[3] = 0x45
				d = append(d,
					0x87, 0x01, 0x23, 0x45,
					// NH=UDP
					0x11,
				)
				return d
			}(),
			macAddrs:     testMacAddrs(),
			wantHL:       1,
			wantNH:       17,
			wantTC:       (7 << 2) | 2, // DSCP=7, ECN=2 → tc=30
			wantFlow:     0x12345,
			wantSrc:      makeLinkLocalAddr(srcIIDFromExt),
			wantDst:      makeLinkLocalAddr(dstIIDFromExt),
			wantConsumed: 7,
		},
		{
			name: "TF=01 (ECN+Flow, DSCP=0)",
			// IPHC: TF=01, NH=inline, HLIM=01, SAC=0, SAM=11, M=0, DAC=0, DAM=11
			// 011 01_01_0 0_11_0_0_011 = 0x6933
			data: func() []byte {
				d := []byte{0x69, 0x33}
				// TF=01: 3 bytes. ECN=1 → inline[0] high 2 bits = 01
				// Flow = 0xABCDE → inline[0] low nibble = 0x0A, inline[1] = 0xBC, inline[2] = 0xDE
				d = append(d,
					0x4A, 0xBC, 0xDE,
					// NH=UDP
					0x11,
				)
				return d
			}(),
			macAddrs:     testMacAddrs(),
			wantHL:       1,
			wantNH:       17,
			wantTC:       1, // DSCP=0, ECN=1
			wantFlow:     0xABCDE,
			wantSrc:      makeLinkLocalAddr(srcIIDFromExt),
			wantDst:      makeLinkLocalAddr(dstIIDFromExt),
			wantConsumed: 6,
		},
		{
			name: "TF=10 (ECN+DSCP only)",
			// IPHC: TF=10, NH=inline, HLIM=01, SAC=0, SAM=11, M=0, DAC=0, DAM=11
			// 011 10_01_0 0_11_0_0_011 = 0x7133
			data: func() []byte {
				d := []byte{0x71, 0x33}
				// TF=10: 1 byte. ECN=3, DSCP=15 → (3<<6)|15 = 0xCF
				d = append(d,
					0xCF,
					// NH=UDP
					0x11,
				)
				return d
			}(),
			macAddrs:     testMacAddrs(),
			wantHL:       1,
			wantNH:       17,
			wantTC:       (15 << 2) | 3, // = 63
			wantFlow:     0,
			wantSrc:      makeLinkLocalAddr(srcIIDFromExt),
			wantDst:      makeLinkLocalAddr(dstIIDFromExt),
			wantConsumed: 4,
		},
		{
			name: "stateful src SAC=1 SAM=11 (IID from MAC, prefix from context 0)",
			// IPHC: TF=11, NH=inline, HLIM=01, CID=1, SAC=1, SAM=11, M=0, DAC=0, DAM=11
			// 011 11_01_1 0_11_0_0_011 = 0x7BB3
			// Wait, let me compute carefully:
			// bit 15-13: 011
			// bit 12-11: 11 (TF=11)
			// bit 10: 0 (NH inline)
			// bit 9-8: 01 (HLIM=1)
			// bit 7: 1 (CID=1)
			// bit 6: 1 (SAC=1)
			// bit 5-4: 11 (SAM=11)
			// bit 3: 0 (M=0)
			// bit 2: 0 (DAC=0)
			// bit 1-0: 11 (DAM=11)
			// = 0111 1001 1111 0011 = 0x79F3
			data: func() []byte {
				d := []byte{0x79, 0xF3}
				d = append(d,
					// CID byte: SCI=0, DCI=0
					0x00,
					// NH=UDP
					0x11,
				)
				return d
			}(),
			macAddrs: testMacAddrs(),
			contexts: testContexts(),
			wantHL:   1,
			wantNH:   17,
			wantSrc: func() [16]byte {
				var a [16]byte
				// Prefix from context 0: fd00:cafe:face:1234
				copy(a[:8], []byte{0xfd, 0x00, 0xca, 0xfe, 0xfa, 0xce, 0x12, 0x34})
				// IID from src MAC ext addr
				copy(a[8:], srcIIDFromExt[:])
				return a
			}(),
			wantDst:      makeLinkLocalAddr(dstIIDFromExt),
			wantConsumed: 4,
		},
		{
			name: "stateful dst DAC=1 DAM=11 (IID from MAC, prefix from context 1)",
			// IPHC: TF=11, NH=inline, HLIM=01, CID=1, SAC=0, SAM=11, M=0, DAC=1, DAM=11
			// bit 15-13: 011
			// bit 12-11: 11
			// bit 10: 0
			// bit 9-8: 01
			// bit 7: 1 (CID)
			// bit 6: 0 (SAC=0)
			// bit 5-4: 11 (SAM=11)
			// bit 3: 0 (M=0)
			// bit 2: 1 (DAC=1)
			// bit 1-0: 11 (DAM=11)
			// = 0111 1001 1011 0111 = 0x79B7
			data: func() []byte {
				d := []byte{0x79, 0xB7}
				d = append(d,
					// CID: SCI=0, DCI=1
					0x01,
					// NH=UDP
					0x11,
				)
				return d
			}(),
			macAddrs: testMacAddrs(),
			contexts: testContexts(),
			wantHL:   1,
			wantNH:   17,
			wantSrc:  makeLinkLocalAddr(srcIIDFromExt),
			wantDst: func() [16]byte {
				var a [16]byte
				// Prefix from context 1: 2001:2:0:1
				copy(a[:8], []byte{0x20, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01})
				// IID from dst MAC ext addr
				copy(a[8:], dstIIDFromExt[:])
				return a
			}(),
			wantConsumed: 4,
		},
		{
			name: "stateful src SAC=1 SAM=01 (64-bit IID inline, prefix from context 0)",
			// IPHC: TF=11, NH=inline, HLIM=01, CID=1, SAC=1, SAM=01, M=0, DAC=0, DAM=11
			// bit 7: 1 (CID), bit 6: 1 (SAC), bit 5-4: 01 (SAM=01)
			// = 0111 1001 1101 0011 = 0x79D3
			data: func() []byte {
				d := []byte{0x79, 0xD3}
				d = append(d,
					// CID: SCI=0, DCI=0
					0x00,
					// NH=UDP
					0x11,
					// 64-bit IID inline
					0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
				)
				return d
			}(),
			macAddrs: testMacAddrs(),
			contexts: testContexts(),
			wantHL:   1,
			wantNH:   17,
			wantSrc: func() [16]byte {
				var a [16]byte
				copy(a[:8], []byte{0xfd, 0x00, 0xca, 0xfe, 0xfa, 0xce, 0x12, 0x34})
				copy(a[8:], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11})
				return a
			}(),
			wantDst:      makeLinkLocalAddr(dstIIDFromExt),
			wantConsumed: 12,
		},
		{
			name: "NH compressed (flag set, no inline NH byte)",
			// IPHC: TF=11, NH=compressed(1), HLIM=01, SAC=0, SAM=11, M=0, DAC=0, DAM=11
			// bit 10: 1 (NH compressed)
			// 011 11_01_1 0_11_0_0_011 = 0x7D33 -> wait
			// 0111 1_1_01 0011 0011
			// byte[0] = 0111 1101 = 0x7D
			// byte[1] = 0011 0011 = 0x33
			data:         []byte{0x7D, 0x33},
			macAddrs:     testMacAddrs(),
			wantHL:       1,
			wantNH:       0, // NH left as 0 because it's NHC-compressed
			wantSrc:      makeLinkLocalAddr(srcIIDFromExt),
			wantDst:      makeLinkLocalAddr(dstIIDFromExt),
			wantConsumed: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, consumed, _, err := DecompressHeader(tt.data, tt.macAddrs, tt.contexts)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if consumed != tt.wantConsumed {
				t.Errorf("consumed = %d, want %d", consumed, tt.wantConsumed)
			}

			// Check version.
			version := header[0] >> 4
			if version != 6 {
				t.Errorf("version = %d, want 6", version)
			}

			// Check traffic class.
			gotTC := (header[0]&0x0F)<<4 | header[1]>>4
			if tt.wantTC != 0 && gotTC != tt.wantTC {
				t.Errorf("traffic class = %d, want %d", gotTC, tt.wantTC)
			}

			// Check flow label.
			gotFlow := uint32(header[1]&0x0F)<<16 | uint32(header[2])<<8 | uint32(header[3])
			if gotFlow != tt.wantFlow {
				t.Errorf("flow label = 0x%05x, want 0x%05x", gotFlow, tt.wantFlow)
			}

			// Check next header.
			if header[6] != tt.wantNH {
				t.Errorf("next header = %d, want %d", header[6], tt.wantNH)
			}

			// Check hop limit.
			if header[7] != tt.wantHL {
				t.Errorf("hop limit = %d, want %d", header[7], tt.wantHL)
			}

			// Check source address.
			var gotSrc [16]byte
			copy(gotSrc[:], header[8:24])
			if gotSrc != tt.wantSrc {
				t.Errorf("src addr = %x, want %x", gotSrc, tt.wantSrc)
			}

			// Check destination address.
			var gotDst [16]byte
			copy(gotDst[:], header[24:40])
			if gotDst != tt.wantDst {
				t.Errorf("dst addr = %x, want %x", gotDst, tt.wantDst)
			}
		})
	}
}

func TestDecompressHeaderErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"nil data", nil},
		{"too short", []byte{0x60}},
		{"invalid dispatch", []byte{0x80, 0x00}},
		{"truncated TF=00", []byte{0x60, 0x00, 0x01}},
		{"truncated NH inline", []byte{0x60, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"truncated HL inline", []byte{0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11}},
		{"truncated src 128-bit", []byte{0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x40, 0xfe}},
		{"truncated CID byte", []byte{0x60, 0x80}}, // CID set but no CID byte
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := DecompressHeader(tt.data, testMacAddrs(), nil)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestDecompressHeader_NhCompressedFlag verifies that DecompressHeader returns
// the correct nhCompressed boolean, distinguishing between NH-compressed frames
// (IPHC NH flag set, header[6]==0) and frames that explicitly carry
// ProtoHopOpts (0) as the inline next header.
func TestDecompressHeader_NhCompressedFlag(t *testing.T) {
	mac := testMacAddrs()

	t.Run("NH flag set returns nhCompressed=true", func(t *testing.T) {
		// IPHC: TF=11, NH=1 (compressed), HLIM=01(=1), SAC=0, SAM=11, M=0, DAC=0, DAM=11
		// 011 11_1_01 0_11_0_0_11 = 0x7D33
		data := []byte{0x7D, 0x33}
		_, _, nhc, err := DecompressHeader(data, mac, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !nhc {
			t.Error("nhCompressed = false, want true (NH flag is set)")
		}
	})

	t.Run("NH flag clear with ProtoHopOpts returns nhCompressed=false", func(t *testing.T) {
		// IPHC: TF=11, NH=0 (inline), HLIM=01(=1), SAC=0, SAM=11, M=0, DAC=0, DAM=11
		// 011 11_0_01 0_11_0_0_11 = 0x7933
		data := []byte{0x79, 0x33, 0x00} // NH=0 (ProtoHopOpts) inline
		_, _, nhc, err := DecompressHeader(data, mac, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if nhc {
			t.Error("nhCompressed = true, want false (NH flag is clear, next header is HopByHop inline)")
		}
	})

	t.Run("NH flag clear with ProtoUDP returns nhCompressed=false", func(t *testing.T) {
		// Same IPHC but NH=17 (UDP) inline.
		data := []byte{0x79, 0x33, 0x11} // NH=17 inline
		_, _, nhc, err := DecompressHeader(data, mac, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if nhc {
			t.Error("nhCompressed = true, want false")
		}
	})
}

// ---------------------------------------------------------------------------
// Fragment detection and parsing tests
// ---------------------------------------------------------------------------

func TestIsFragment(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"nil", nil, false},
		{"empty", []byte{}, false},
		{"IPHC dispatch", []byte{0x60, 0x00}, false},
		{"first fragment 0xC0", []byte{0xC0, 0x50, 0x00, 0x01}, true},
		{"first fragment 0xC7", []byte{0xC7, 0xFF, 0x00, 0x01}, true},
		{"subsequent fragment 0xE0", []byte{0xE0, 0x50, 0x00, 0x01, 0x08}, true},
		{"subsequent fragment 0xE7", []byte{0xE7, 0xFF, 0x00, 0x01, 0x10}, true},
		{"mesh header 0x80", []byte{0x80}, false},
		{"broadcast 0x50", []byte{0x50}, false},
		{"0xD0 not fragment", []byte{0xD0}, false}, // between first and subsequent
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsFragment(tt.data); got != tt.want {
				t.Errorf("IsFragment() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseFragmentHeader(t *testing.T) {
	t.Run("first fragment", func(t *testing.T) {
		// dispatch=0xC0 | size_hi=0x01, size_lo=0x00 → size=256
		// tag=0x00AB
		data := []byte{0xC1, 0x00, 0x00, 0xAB, 0xDE, 0xAD} // payload follows
		hdr, consumed, err := ParseFragmentHeader(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if consumed != FragFirstHeaderLen {
			t.Errorf("consumed = %d, want %d", consumed, FragFirstHeaderLen)
		}
		if !hdr.IsFirst {
			t.Error("IsFirst = false, want true")
		}
		if hdr.DatagramSize != 256 {
			t.Errorf("DatagramSize = %d, want 256", hdr.DatagramSize)
		}
		if hdr.DatagramTag != 0x00AB {
			t.Errorf("DatagramTag = 0x%04X, want 0x00AB", hdr.DatagramTag)
		}
		if hdr.DatagramOffset != 0 {
			t.Errorf("DatagramOffset = %d, want 0", hdr.DatagramOffset)
		}
	})

	t.Run("subsequent fragment", func(t *testing.T) {
		// dispatch=0xE0 | size_hi=0x02, size_lo=0x58 → size=600
		// tag=0x1234, offset_byte=0x0A → offset=80
		data := []byte{0xE2, 0x58, 0x12, 0x34, 0x0A, 0xFF, 0xFF}
		hdr, consumed, err := ParseFragmentHeader(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if consumed != FragSubsequentHeaderLen {
			t.Errorf("consumed = %d, want %d", consumed, FragSubsequentHeaderLen)
		}
		if hdr.IsFirst {
			t.Error("IsFirst = true, want false")
		}
		if hdr.DatagramSize != 600 {
			t.Errorf("DatagramSize = %d, want 600", hdr.DatagramSize)
		}
		if hdr.DatagramTag != 0x1234 {
			t.Errorf("DatagramTag = 0x%04X, want 0x1234", hdr.DatagramTag)
		}
		if hdr.DatagramOffset != 80 {
			t.Errorf("DatagramOffset = %d, want 80", hdr.DatagramOffset)
		}
	})

	t.Run("too short for first", func(t *testing.T) {
		_, _, err := ParseFragmentHeader([]byte{0xC0, 0x50, 0x00})
		if err == nil {
			t.Error("expected error for truncated first fragment header")
		}
	})

	t.Run("too short for subsequent", func(t *testing.T) {
		_, _, err := ParseFragmentHeader([]byte{0xE0, 0x50, 0x00, 0x01})
		if err == nil {
			t.Error("expected error for truncated subsequent fragment header")
		}
	})

	t.Run("invalid dispatch", func(t *testing.T) {
		_, _, err := ParseFragmentHeader([]byte{0x60, 0x00, 0x00, 0x00, 0x00})
		if err == nil {
			t.Error("expected error for non-fragment dispatch")
		}
	})

	t.Run("max datagram size", func(t *testing.T) {
		// Size = 0x7FF (2047), the max 11-bit value.
		data := []byte{0xC7, 0xFF, 0x00, 0x01}
		hdr, _, err := ParseFragmentHeader(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hdr.DatagramSize != 2047 {
			t.Errorf("DatagramSize = %d, want 2047", hdr.DatagramSize)
		}
	})
}

func TestDecompressUDPHeader(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		wantSrcPort  uint16
		wantDstPort  uint16
		wantChecksum uint16
		wantConsumed int
		wantErr      bool
	}{
		{
			name:         "PP=00 both full ports",
			data:         []byte{0xF0, 0x00, 0x50, 0x00, 0x51, 0x00, 0x10},
			wantSrcPort:  80,
			wantDstPort:  81,
			wantChecksum: 0x0010,
			wantConsumed: 7,
		},
		{
			name:         "PP=01 src 16-bit dst 8-bit",
			data:         []byte{0xF1, 0x00, 0x50, 0xAB, 0x12, 0x34},
			wantSrcPort:  80,
			wantDstPort:  0xF0AB,
			wantChecksum: 0x1234,
			wantConsumed: 6,
		},
		{
			name:         "PP=10 src 8-bit dst 16-bit",
			data:         []byte{0xF2, 0xCD, 0x00, 0x51, 0x56, 0x78},
			wantSrcPort:  0xF0CD,
			wantDstPort:  81,
			wantChecksum: 0x5678,
			wantConsumed: 6,
		},
		{
			name:         "PP=11 both 4-bit nibble",
			data:         []byte{0xF3, 0xAB, 0x12, 0x34},
			wantSrcPort:  0xF0BA,
			wantDstPort:  0xF0BB,
			wantChecksum: 0x1234,
			wantConsumed: 4,
		},
		{
			name:         "PP=00 checksum elided",
			data:         []byte{0xF4, 0x00, 0x50, 0x00, 0x51},
			wantSrcPort:  80,
			wantDstPort:  81,
			wantChecksum: 0,
			wantConsumed: 5,
		},
		{
			name:    "invalid dispatch",
			data:    []byte{0xE0},
			wantErr: true,
		},
		{
			name:    "empty data",
			data:    nil,
			wantErr: true,
		},
		{
			name:    "truncated PP=00",
			data:    []byte{0xF0, 0x00},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, consumed, err := DecompressUDPHeader(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if consumed != tt.wantConsumed {
				t.Errorf("consumed = %d, want %d", consumed, tt.wantConsumed)
			}

			srcPort := uint16(header[0])<<8 | uint16(header[1])
			dstPort := uint16(header[2])<<8 | uint16(header[3])
			checksum := uint16(header[6])<<8 | uint16(header[7])

			if srcPort != tt.wantSrcPort {
				t.Errorf("src port = 0x%04X, want 0x%04X", srcPort, tt.wantSrcPort)
			}
			if dstPort != tt.wantDstPort {
				t.Errorf("dst port = 0x%04X, want 0x%04X", dstPort, tt.wantDstPort)
			}
			if checksum != tt.wantChecksum {
				t.Errorf("checksum = 0x%04X, want 0x%04X", checksum, tt.wantChecksum)
			}
		})
	}
}

func TestCompressDecompressRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		header [40]byte
	}{
		{
			name: "link-local src elided, dst elided",
			header: func() [40]byte {
				var h [40]byte
				// Version=6, TC=0, Flow=0
				h[0] = 0x60
				h[6] = 17 // UDP
				h[7] = 64 // HL
				// Src: fe80::0200:5eef:1022:1100
				copy(h[8:], linkLocalPrefix[:])
				copy(h[16:], srcIIDFromExt[:])
				// Dst: fe80::0200:5eef:10aa:bbcc
				copy(h[24:], linkLocalPrefix[:])
				copy(h[32:], dstIIDFromExt[:])
				return h
			}(),
		},
		{
			name: "with TC and flow label",
			header: func() [40]byte {
				var h [40]byte
				tc := uint8((7 << 2) | 2) // DSCP=7, ECN=2
				h[0] = 0x60 | (tc >> 4)
				h[1] = (tc << 4) | 0x01 // flow high nibble = 1
				h[2] = 0x23
				h[3] = 0x45 // Complete the flow label 0x12345.
				h[6] = 17
				h[7] = 255
				copy(h[8:], linkLocalPrefix[:])
				copy(h[16:], srcIIDFromExt[:])
				copy(h[24:], linkLocalPrefix[:])
				copy(h[32:], dstIIDFromExt[:])
				return h
			}(),
		},
		{
			name: "multicast ff02::1 destination",
			header: func() [40]byte {
				var h [40]byte
				h[0] = 0x60
				h[6] = 17
				h[7] = 1
				copy(h[8:], linkLocalPrefix[:])
				copy(h[16:], srcIIDFromExt[:])
				h[24] = 0xFF
				h[25] = 0x02
				h[39] = 0x01
				return h
			}(),
		},
	}

	mac := testMacAddrs()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := CompressHeader(tt.header, mac, nil)
			if err != nil {
				t.Fatalf("compress: %v", err)
			}

			decompressed, consumed, _, err := DecompressHeader(compressed, mac, nil)
			if err != nil {
				t.Fatalf("decompress: %v", err)
			}
			if consumed != len(compressed) {
				t.Errorf("consumed = %d, want %d (len of compressed)", consumed, len(compressed))
			}

			// Compare only version/TC/flow (bytes 0-3), HL (byte 7),
			// src (bytes 8-23), dst (bytes 24-39). Skip payload length (bytes 4-5)
			// which isn't part of IPHC compression.
			// Also skip NH (byte 6) when it's UDP (17) because CompressHeader
			// sets HcNextHeader which means the NH byte is not carried inline;
			// the caller would recover it from the NHC dispatch during full
			// decompression. DecompressHeader alone leaves it as 0.
			for _, rng := range [][2]int{{0, 4}, {7, 8}, {8, 24}, {24, 40}} {
				for i := rng[0]; i < rng[1]; i++ {
					if decompressed[i] != tt.header[i] {
						t.Errorf("byte[%d] = 0x%02X, want 0x%02X", i, decompressed[i], tt.header[i])
					}
				}
			}
		})
	}
}

func TestCompressUDPRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		header [8]byte
	}{
		{
			name:   "both full ports",
			header: [8]byte{0x00, 0x50, 0x00, 0x51, 0x00, 0x00, 0xAB, 0xCD},
		},
		{
			name:   "4-bit nibble ports",
			header: [8]byte{0xF0, 0xBA, 0xF0, 0xBB, 0x00, 0x00, 0x12, 0x34},
		},
		{
			name:   "8-bit dst port",
			header: [8]byte{0x00, 0x50, 0xF0, 0xAB, 0x00, 0x00, 0x56, 0x78},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := CompressUDPHeader(tt.header)
			if err != nil {
				t.Fatalf("compress: %v", err)
			}

			decompressed, consumed, err := DecompressUDPHeader(compressed)
			if err != nil {
				t.Fatalf("decompress: %v", err)
			}
			if consumed != len(compressed) {
				t.Errorf("consumed = %d, want %d", consumed, len(compressed))
			}

			// Compare ports (bytes 0-3) and checksum (bytes 6-7).
			// Length (bytes 4-5) is not part of NHC compression.
			for _, i := range []int{0, 1, 2, 3, 6, 7} {
				if decompressed[i] != tt.header[i] {
					t.Errorf("byte[%d] = 0x%02X, want 0x%02X", i, decompressed[i], tt.header[i])
				}
			}
		})
	}
}

func TestCompressHeader(t *testing.T) {
	t.Run("invalid version", func(t *testing.T) {
		var h [40]byte
		h[0] = 0x40 // version 4, not 6
		_, err := CompressHeader(h, testMacAddrs(), nil)
		if err == nil {
			t.Error("expected error for non-IPv6 header")
		}
	})
}

func FuzzDecompressHeader(f *testing.F) {
	// Seed with known-good test vectors.
	seeds := [][]byte{
		{0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x40,
			0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x5e, 0xef, 0x10, 0x22, 0x11, 0x00,
			0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x5e, 0xef, 0x10, 0xaa, 0xbb, 0xcc},
		{0x79, 0x33, 0x11},
		{0x79, 0x3B, 0x11, 0x01},
		{0x7D, 0x33},
	}
	for _, s := range seeds {
		f.Add(s)
	}

	macAddrs := testMacAddrs()
	f.Fuzz(func(_ *testing.T, data []byte) {
		// Must not panic.
		_, _, _, _ = DecompressHeader(data, macAddrs, nil)
	})
}

func FuzzDecompressUDPHeader(f *testing.F) {
	seeds := [][]byte{
		{0xF0, 0x00, 0x50, 0x00, 0x51, 0x00, 0x10},
		{0xF3, 0xAB, 0x12, 0x34},
		{0xF4, 0x00, 0x50, 0x00, 0x51},
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _, _ = DecompressUDPHeader(data)
	})
}

// ---------------------------------------------------------------------------
// CompressHeader coverage tests
// ---------------------------------------------------------------------------

func TestCompressHeaderStatefulContext(t *testing.T) {
	mac := testMacAddrs()
	contexts := testContexts()

	t.Run("src context with IID from ext addr (SAC=1 SAM=11)", func(t *testing.T) {
		var h [40]byte
		h[0] = 0x60
		h[6] = 17
		h[7] = 64
		// Src: context 0 prefix + IID from src ext addr
		copy(h[8:16], []byte{0xfd, 0x00, 0xca, 0xfe, 0xfa, 0xce, 0x12, 0x34})
		copy(h[16:24], srcIIDFromExt[:])
		// Dst: link-local + IID from dst ext addr
		copy(h[24:32], linkLocalPrefix[:])
		copy(h[32:40], dstIIDFromExt[:])

		compressed, err := CompressHeader(h, mac, contexts)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		decompressed, consumed, _, err := DecompressHeader(compressed, mac, contexts)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		if consumed != len(compressed) {
			t.Errorf("consumed = %d, want %d", consumed, len(compressed))
		}
		for _, rng := range [][2]int{{0, 4}, {7, 8}, {8, 24}, {24, 40}} {
			for i := rng[0]; i < rng[1]; i++ {
				if decompressed[i] != h[i] {
					t.Errorf("byte[%d] = 0x%02X, want 0x%02X", i, decompressed[i], h[i])
				}
			}
		}
	})

	t.Run("src context with short IID (SAC=1 SAM=10)", func(t *testing.T) {
		var h [40]byte
		h[0] = 0x60
		h[6] = 17
		h[7] = 64
		// Src: context 0 prefix + short IID (0000:00FF:FE00:ABCD)
		copy(h[8:16], []byte{0xfd, 0x00, 0xca, 0xfe, 0xfa, 0xce, 0x12, 0x34})
		h[16] = 0x00
		h[17] = 0x00
		h[18] = 0x00
		h[19] = 0xFF
		h[20] = 0xFE
		h[21] = 0x00
		h[22] = 0xAB
		h[23] = 0xCD
		copy(h[24:32], linkLocalPrefix[:])
		copy(h[32:40], dstIIDFromExt[:])

		compressed, err := CompressHeader(h, mac, contexts)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		decompressed, _, _, err := DecompressHeader(compressed, mac, contexts)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		var gotSrc [16]byte
		copy(gotSrc[:], decompressed[8:24])
		var wantSrc [16]byte
		copy(wantSrc[:], h[8:24])
		if gotSrc != wantSrc {
			t.Errorf("src = %x, want %x", gotSrc, wantSrc)
		}
	})

	t.Run("src context with 64-bit IID (SAC=1 SAM=01)", func(t *testing.T) {
		var h [40]byte
		h[0] = 0x60
		h[6] = 17
		h[7] = 64
		copy(h[8:16], []byte{0xfd, 0x00, 0xca, 0xfe, 0xfa, 0xce, 0x12, 0x34})
		copy(h[16:24], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
		copy(h[24:32], linkLocalPrefix[:])
		copy(h[32:40], dstIIDFromExt[:])

		compressed, err := CompressHeader(h, mac, contexts)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		decompressed, _, _, err := DecompressHeader(compressed, mac, contexts)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		var gotSrc [16]byte
		copy(gotSrc[:], decompressed[8:24])
		var wantSrc [16]byte
		copy(wantSrc[:], h[8:24])
		if gotSrc != wantSrc {
			t.Errorf("src = %x, want %x", gotSrc, wantSrc)
		}
	})

	t.Run("dst context with IID from ext addr (DAC=1 DAM=11)", func(t *testing.T) {
		var h [40]byte
		h[0] = 0x60
		h[6] = 17
		h[7] = 64
		copy(h[8:16], linkLocalPrefix[:])
		copy(h[16:24], srcIIDFromExt[:])
		// Dst: context 1 prefix + IID from dst ext addr
		copy(h[24:32], []byte{0x20, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01})
		copy(h[32:40], dstIIDFromExt[:])

		compressed, err := CompressHeader(h, mac, contexts)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		decompressed, _, _, err := DecompressHeader(compressed, mac, contexts)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		for _, rng := range [][2]int{{0, 4}, {7, 8}, {8, 24}, {24, 40}} {
			for i := rng[0]; i < rng[1]; i++ {
				if decompressed[i] != h[i] {
					t.Errorf("byte[%d] = 0x%02X, want 0x%02X", i, decompressed[i], h[i])
				}
			}
		}
	})

	t.Run("dst context with short IID (DAC=1 DAM=10)", func(t *testing.T) {
		var h [40]byte
		h[0] = 0x60
		h[6] = 17
		h[7] = 64
		copy(h[8:16], linkLocalPrefix[:])
		copy(h[16:24], srcIIDFromExt[:])
		copy(h[24:32], []byte{0x20, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01})
		h[32] = 0x00
		h[33] = 0x00
		h[34] = 0x00
		h[35] = 0xFF
		h[36] = 0xFE
		h[37] = 0x00
		h[38] = 0xC0
		h[39] = 0x03

		compressed, err := CompressHeader(h, mac, contexts)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		decompressed, _, _, err := DecompressHeader(compressed, mac, contexts)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		var gotDst [16]byte
		copy(gotDst[:], decompressed[24:40])
		var wantDst [16]byte
		copy(wantDst[:], h[24:40])
		if gotDst != wantDst {
			t.Errorf("dst = %x, want %x", gotDst, wantDst)
		}
	})

	t.Run("dst context with 64-bit IID (DAC=1 DAM=01)", func(t *testing.T) {
		var h [40]byte
		h[0] = 0x60
		h[6] = 17
		h[7] = 64
		copy(h[8:16], linkLocalPrefix[:])
		copy(h[16:24], srcIIDFromExt[:])
		copy(h[24:32], []byte{0x20, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01})
		copy(h[32:40], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})

		compressed, err := CompressHeader(h, mac, contexts)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		decompressed, _, _, err := DecompressHeader(compressed, mac, contexts)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		var gotDst [16]byte
		copy(gotDst[:], decompressed[24:40])
		var wantDst [16]byte
		copy(wantDst[:], h[24:40])
		if gotDst != wantDst {
			t.Errorf("dst = %x, want %x", gotDst, wantDst)
		}
	})

	t.Run("unspecified src (SAC=1 SAM=00)", func(t *testing.T) {
		var h [40]byte
		h[0] = 0x60
		h[6] = 17
		h[7] = 1
		// Src is all zeros (unspecified)
		copy(h[24:32], linkLocalPrefix[:])
		copy(h[32:40], dstIIDFromExt[:])

		compressed, err := CompressHeader(h, mac, nil)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		decompressed, _, _, err := DecompressHeader(compressed, mac, nil)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		var gotSrc [16]byte
		copy(gotSrc[:], decompressed[8:24])
		if gotSrc != [16]byte{} {
			t.Errorf("src should be unspecified, got %x", gotSrc)
		}
	})

	t.Run("full 128-bit src (no context, not link-local)", func(t *testing.T) {
		var h [40]byte
		h[0] = 0x60
		h[6] = 17
		h[7] = 64
		// Src: 2001:db8::1 (not link-local, no matching context)
		copy(h[8:16], []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00})
		h[23] = 0x01
		copy(h[24:32], linkLocalPrefix[:])
		copy(h[32:40], dstIIDFromExt[:])

		compressed, err := CompressHeader(h, mac, nil)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		decompressed, _, _, err := DecompressHeader(compressed, mac, nil)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		var gotSrc [16]byte
		copy(gotSrc[:], decompressed[8:24])
		var wantSrc [16]byte
		copy(wantSrc[:], h[8:24])
		if gotSrc != wantSrc {
			t.Errorf("src = %x, want %x", gotSrc, wantSrc)
		}
	})

	t.Run("full 128-bit dst (no context, not link-local)", func(t *testing.T) {
		var h [40]byte
		h[0] = 0x60
		h[6] = 17
		h[7] = 64
		copy(h[8:16], linkLocalPrefix[:])
		copy(h[16:24], srcIIDFromExt[:])
		copy(h[24:32], []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00})
		h[39] = 0x01

		compressed, err := CompressHeader(h, mac, nil)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		decompressed, _, _, err := DecompressHeader(compressed, mac, nil)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		var gotDst [16]byte
		copy(gotDst[:], decompressed[24:40])
		var wantDst [16]byte
		copy(wantDst[:], h[24:40])
		if gotDst != wantDst {
			t.Errorf("dst = %x, want %x", gotDst, wantDst)
		}
	})
}

func TestCompressHeaderMulticast(t *testing.T) {
	mac := testMacAddrs()
	contexts := testContexts()

	t.Run("multicast 48-bit (ffXX::00XX:XXXX:XXXX)", func(t *testing.T) {
		var h [40]byte
		h[0] = 0x60
		h[6] = 17
		h[7] = 1
		copy(h[8:16], linkLocalPrefix[:])
		copy(h[16:24], srcIIDFromExt[:])
		// ff15::00DB:1234:5678
		h[24] = 0xFF
		h[25] = 0x15
		h[35] = 0xDB
		h[36] = 0x12
		h[37] = 0x34
		h[38] = 0x56
		h[39] = 0x78

		compressed, err := CompressHeader(h, mac, nil)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		decompressed, _, _, err := DecompressHeader(compressed, mac, nil)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		var gotDst [16]byte
		copy(gotDst[:], decompressed[24:40])
		var wantDst [16]byte
		copy(wantDst[:], h[24:40])
		if gotDst != wantDst {
			t.Errorf("dst = %x, want %x", gotDst, wantDst)
		}
	})

	t.Run("multicast 32-bit (ffXX::00XX:XXXX)", func(t *testing.T) {
		var h [40]byte
		h[0] = 0x60
		h[6] = 17
		h[7] = 1
		copy(h[8:16], linkLocalPrefix[:])
		copy(h[16:24], srcIIDFromExt[:])
		// ff05::00DB:1234
		h[24] = 0xFF
		h[25] = 0x05
		h[37] = 0xDB
		h[38] = 0x12
		h[39] = 0x34

		compressed, err := CompressHeader(h, mac, nil)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		decompressed, _, _, err := DecompressHeader(compressed, mac, nil)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		var gotDst [16]byte
		copy(gotDst[:], decompressed[24:40])
		var wantDst [16]byte
		copy(wantDst[:], h[24:40])
		if gotDst != wantDst {
			t.Errorf("dst = %x, want %x", gotDst, wantDst)
		}
	})

	t.Run("multicast full 128-bit inline", func(t *testing.T) {
		var h [40]byte
		h[0] = 0x60
		h[6] = 17
		h[7] = 1
		copy(h[8:16], linkLocalPrefix[:])
		copy(h[16:24], srcIIDFromExt[:])
		// ff05::1:2:3:4:5:6:7 (non-compressible multicast)
		h[24] = 0xFF
		h[25] = 0x05
		h[26] = 0x00
		h[27] = 0x01
		h[28] = 0x00
		h[29] = 0x02
		h[30] = 0x00
		h[31] = 0x03
		h[32] = 0x00
		h[33] = 0x04
		h[34] = 0x00
		h[35] = 0x05
		h[36] = 0x00
		h[37] = 0x06
		h[38] = 0x00
		h[39] = 0x07

		compressed, err := CompressHeader(h, mac, nil)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		decompressed, _, _, err := DecompressHeader(compressed, mac, nil)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		var gotDst [16]byte
		copy(gotDst[:], decompressed[24:40])
		var wantDst [16]byte
		copy(wantDst[:], h[24:40])
		if gotDst != wantDst {
			t.Errorf("dst = %x, want %x", gotDst, wantDst)
		}
	})

	t.Run("multicast with context (M=1 DAC=1 DAM=00)", func(t *testing.T) {
		var h [40]byte
		h[0] = 0x60
		h[6] = 17
		h[7] = 1
		copy(h[8:16], linkLocalPrefix[:])
		copy(h[16:24], srcIIDFromExt[:])
		// Unicast-prefix-based multicast matching context 0
		// ffXX:XXLL:PPPP:PPPP:PPPP:PPPP:XXXX:XXXX
		h[24] = 0xFF
		h[25] = 0x35 // scope
		h[26] = 0x00 // flags
		h[27] = 0x40 // prefix len (64)
		copy(h[28:36], []byte{0xfd, 0x00, 0xca, 0xfe, 0xfa, 0xce, 0x12, 0x34})
		h[36] = 0xAA
		h[37] = 0xBB
		h[38] = 0xCC
		h[39] = 0xDD

		compressed, err := CompressHeader(h, mac, contexts)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		decompressed, _, _, err := DecompressHeader(compressed, mac, contexts)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		var gotDst [16]byte
		copy(gotDst[:], decompressed[24:40])
		var wantDst [16]byte
		copy(wantDst[:], h[24:40])
		if gotDst != wantDst {
			t.Errorf("dst = %x, want %x", gotDst, wantDst)
		}
	})
}

func TestCompressHeaderTFModes(t *testing.T) {
	mac := testMacAddrs()

	mkHeader := func(dscp, ecn uint8, flow uint32, nh, hl uint8) [40]byte {
		var h [40]byte
		tc := (dscp << 2) | ecn
		h[0] = 0x60 | (tc >> 4)
		h[1] = (tc << 4) | uint8((flow>>16)&0x0F)
		h[2] = uint8(flow >> 8)
		h[3] = uint8(flow)
		h[6] = nh
		h[7] = hl
		copy(h[8:16], linkLocalPrefix[:])
		copy(h[16:24], srcIIDFromExt[:])
		copy(h[24:32], linkLocalPrefix[:])
		copy(h[32:40], dstIIDFromExt[:])
		return h
	}

	tests := []struct {
		name string
		h    [40]byte
	}{
		{"TF=11 all elided", mkHeader(0, 0, 0, 17, 64)},
		{"TF=10 ECN+DSCP only", mkHeader(15, 3, 0, 17, 64)},
		{"TF=01 ECN+Flow", mkHeader(0, 1, 0xABCDE, 17, 64)},
		{"TF=00 full inline", mkHeader(7, 2, 0x12345, 17, 64)},
		{"non-UDP NH inline", mkHeader(0, 0, 0, 6, 64)}, // TCP
		{"HL=1", mkHeader(0, 0, 0, 17, 1)},
		{"HL=255", mkHeader(0, 0, 0, 17, 255)},
		{"HL=128 inline", mkHeader(0, 0, 0, 17, 128)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := CompressHeader(tt.h, mac, nil)
			if err != nil {
				t.Fatalf("compress: %v", err)
			}
			decompressed, consumed, _, err := DecompressHeader(compressed, mac, nil)
			if err != nil {
				t.Fatalf("decompress: %v", err)
			}
			if consumed != len(compressed) {
				t.Errorf("consumed = %d, want %d", consumed, len(compressed))
			}
			for _, rng := range [][2]int{{0, 4}, {7, 8}, {8, 24}, {24, 40}} {
				for i := rng[0]; i < rng[1]; i++ {
					if tt.h[6] == 17 && i == 6 {
						continue // NH compressed for UDP
					}
					if decompressed[i] != tt.h[i] {
						t.Errorf("byte[%d] = 0x%02X, want 0x%02X", i, decompressed[i], tt.h[i])
					}
				}
			}
		})
	}
}

func TestCompressHeaderLinkLocalShortIID(t *testing.T) {
	mac := testMacAddrs()

	t.Run("src link-local short IID", func(t *testing.T) {
		var h [40]byte
		h[0] = 0x60
		h[6] = 17
		h[7] = 64
		copy(h[8:16], linkLocalPrefix[:])
		// IID from short: 0000:00FF:FE00:ABCD
		h[19] = 0xFF
		h[20] = 0xFE
		h[22] = 0xAB
		h[23] = 0xCD
		copy(h[24:32], linkLocalPrefix[:])
		copy(h[32:40], dstIIDFromExt[:])

		compressed, err := CompressHeader(h, mac, nil)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		decompressed, _, _, err := DecompressHeader(compressed, mac, nil)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		var gotSrc [16]byte
		copy(gotSrc[:], decompressed[8:24])
		var wantSrc [16]byte
		copy(wantSrc[:], h[8:24])
		if gotSrc != wantSrc {
			t.Errorf("src = %x, want %x", gotSrc, wantSrc)
		}
	})

	t.Run("dst link-local short IID", func(t *testing.T) {
		var h [40]byte
		h[0] = 0x60
		h[6] = 17
		h[7] = 64
		copy(h[8:16], linkLocalPrefix[:])
		copy(h[16:24], srcIIDFromExt[:])
		copy(h[24:32], linkLocalPrefix[:])
		// IID from short: 0000:00FF:FE00:C003
		h[35] = 0xFF
		h[36] = 0xFE
		h[38] = 0xC0
		h[39] = 0x03

		compressed, err := CompressHeader(h, mac, nil)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		decompressed, _, _, err := DecompressHeader(compressed, mac, nil)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		var gotDst [16]byte
		copy(gotDst[:], decompressed[24:40])
		var wantDst [16]byte
		copy(wantDst[:], h[24:40])
		if gotDst != wantDst {
			t.Errorf("dst = %x, want %x", gotDst, wantDst)
		}
	})

	t.Run("dst link-local 64-bit IID (not matching ext or short)", func(t *testing.T) {
		var h [40]byte
		h[0] = 0x60
		h[6] = 17
		h[7] = 64
		copy(h[8:16], linkLocalPrefix[:])
		copy(h[16:24], srcIIDFromExt[:])
		copy(h[24:32], linkLocalPrefix[:])
		copy(h[32:40], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})

		compressed, err := CompressHeader(h, mac, nil)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		decompressed, _, _, err := DecompressHeader(compressed, mac, nil)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		var gotDst [16]byte
		copy(gotDst[:], decompressed[24:40])
		var wantDst [16]byte
		copy(wantDst[:], h[24:40])
		if gotDst != wantDst {
			t.Errorf("dst = %x, want %x", gotDst, wantDst)
		}
	})
}

func TestCompressUDPHeaderModes(t *testing.T) {
	t.Run("src 8-bit only", func(t *testing.T) {
		// Src in 0xF000-0xF0FF range, dst arbitrary
		header := [8]byte{0xF0, 0xCD, 0x00, 0x51, 0x00, 0x00, 0x56, 0x78}
		compressed, err := CompressUDPHeader(header)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		decompressed, consumed, err := DecompressUDPHeader(compressed)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		if consumed != len(compressed) {
			t.Errorf("consumed = %d, want %d", consumed, len(compressed))
		}
		for _, i := range []int{0, 1, 2, 3, 6, 7} {
			if decompressed[i] != header[i] {
				t.Errorf("byte[%d] = 0x%02X, want 0x%02X", i, decompressed[i], header[i])
			}
		}
	})

	t.Run("both in 8-bit range", func(t *testing.T) {
		// Both src and dst in 0xF000-0xF0FF range
		header := [8]byte{0xF0, 0x50, 0xF0, 0xAB, 0x00, 0x00, 0x12, 0x34}
		compressed, err := CompressUDPHeader(header)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		decompressed, consumed, err := DecompressUDPHeader(compressed)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		if consumed != len(compressed) {
			t.Errorf("consumed = %d, want %d", consumed, len(compressed))
		}
		for _, i := range []int{0, 1, 2, 3, 6, 7} {
			if decompressed[i] != header[i] {
				t.Errorf("byte[%d] = 0x%02X, want 0x%02X", i, decompressed[i], header[i])
			}
		}
	})

	t.Run("both full ports", func(t *testing.T) {
		header := [8]byte{0x00, 0x50, 0x00, 0x51, 0x00, 0x00, 0xAB, 0xCD}
		compressed, err := CompressUDPHeader(header)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		if compressed[0]&NhcUDPPortMask != NhcUDPPortBothFull {
			t.Errorf("expected PP=00, got 0x%02X", compressed[0]&NhcUDPPortMask)
		}
	})

	t.Run("dst 8-bit only (src not in range)", func(t *testing.T) {
		header := [8]byte{0x13, 0x88, 0xF0, 0x42, 0x00, 0x00, 0xAB, 0xCD} // src=5000, dst=0xF042
		compressed, err := CompressUDPHeader(header)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		decompressed, _, err := DecompressUDPHeader(compressed)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		for _, i := range []int{0, 1, 2, 3, 6, 7} {
			if decompressed[i] != header[i] {
				t.Errorf("byte[%d] = 0x%02X, want 0x%02X", i, decompressed[i], header[i])
			}
		}
	})
}

func TestDecompressHeaderStatefulEdgeCases(t *testing.T) {
	mac := testMacAddrs()
	contexts := testContexts()

	t.Run("stateful src SAC=1 SAM=10 (16-bit with context)", func(t *testing.T) {
		// IPHC: TF=11, NH=inline, HLIM=01, CID=1, SAC=1, SAM=10, M=0, DAC=0, DAM=11
		// bit 7: 1 (CID), bit 6: 1 (SAC), bit 5-4: 10 (SAM=10)
		// = 0111 1001 1110 0011 = 0x79E3
		data := func() []byte {
			d := []byte{0x79, 0xE3}
			d = append(d,
				// CID: SCI=0, DCI=0
				0x00,
				// NH=UDP
				0x11,
				// 16-bit short
				0xAB, 0xCD,
			)
			return d
		}()

		header, consumed, _, err := DecompressHeader(data, mac, contexts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if consumed != 6 {
			t.Errorf("consumed = %d, want 6", consumed)
		}
		// Check prefix from context 0
		var gotSrc [16]byte
		copy(gotSrc[:], header[8:24])
		var wantSrc [16]byte
		copy(wantSrc[:8], []byte{0xfd, 0x00, 0xca, 0xfe, 0xfa, 0xce, 0x12, 0x34})
		wantSrc[8+3] = 0xFF
		wantSrc[8+4] = 0xFE
		wantSrc[8+6] = 0xAB
		wantSrc[8+7] = 0xCD
		if gotSrc != wantSrc {
			t.Errorf("src = %x, want %x", gotSrc, wantSrc)
		}
	})

	t.Run("stateful dst DAC=1 DAM=01 (64-bit IID with context)", func(t *testing.T) {
		// IPHC: TF=11, NH=inline, HLIM=01, CID=1, SAC=0, SAM=11, M=0, DAC=1, DAM=01
		// = 0111 1001 1011 0101 = 0x79B5
		data := func() []byte {
			d := []byte{0x79, 0xB5}
			d = append(d,
				// CID: SCI=0, DCI=1
				0x01,
				// NH=UDP
				0x11,
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
			)
			return d
		}()

		header, consumed, _, err := DecompressHeader(data, mac, contexts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if consumed != 12 {
			t.Errorf("consumed = %d, want 12", consumed)
		}
		var gotDst [16]byte
		copy(gotDst[:], header[24:40])
		var wantDst [16]byte
		copy(wantDst[:8], []byte{0x20, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01})
		copy(wantDst[8:], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
		if gotDst != wantDst {
			t.Errorf("dst = %x, want %x", gotDst, wantDst)
		}
	})

	t.Run("stateful dst DAC=1 DAM=10 (16-bit with context)", func(t *testing.T) {
		// IPHC: TF=11, NH=inline, HLIM=01, CID=1, SAC=0, SAM=11, M=0, DAC=1, DAM=10
		// = 0111 1001 1011 0110 = 0x79B6
		data := func() []byte {
			d := []byte{0x79, 0xB6}
			d = append(d,
				// CID: SCI=0, DCI=1
				0x01,
				// NH=UDP
				0x11,
				// 16-bit short
				0xC0, 0x03,
			)
			return d
		}()

		header, consumed, _, err := DecompressHeader(data, mac, contexts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if consumed != 6 {
			t.Errorf("consumed = %d, want 6", consumed)
		}
		var gotDst [16]byte
		copy(gotDst[:], header[24:40])
		var wantDst [16]byte
		copy(wantDst[:8], []byte{0x20, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01})
		wantDst[8+3] = 0xFF
		wantDst[8+4] = 0xFE
		wantDst[8+6] = 0xC0
		wantDst[8+7] = 0x03
		if gotDst != wantDst {
			t.Errorf("dst = %x, want %x", gotDst, wantDst)
		}
	})

	t.Run("stateful dst DAC=1 DAM=00 reserved error", func(t *testing.T) {
		// IPHC: TF=11, NH=inline, HLIM=01, CID=1, SAC=0, SAM=11, M=0, DAC=1, DAM=00
		// = 0111 1001 1011 0100 = 0x79B4
		data := func() []byte {
			d := []byte{0x79, 0xB4}
			d = append(d,
				// CID: SCI=0, DCI=1
				0x01,
				// NH=UDP
				0x11,
			)
			return d
		}()

		_, _, _, err := DecompressHeader(data, mac, contexts)
		if err == nil {
			t.Error("expected error for reserved DAC=1 DAM=00")
		}
	})

	t.Run("multicast DAC=1 DAM=00 (unicast-prefix-based)", func(t *testing.T) {
		// IPHC: TF=11, NH=inline, HLIM=01, CID=1, SAC=0, SAM=11, M=1, DAC=1, DAM=00
		// = 0111 1001 1011 1100 = 0x79BC
		data := func() []byte {
			d := []byte{0x79, 0xBC}
			d = append(d,
				// CID: SCI=0, DCI=0
				0x00,
				// NH=UDP
				0x11,
				// 6 bytes: scope, flags, 4 bytes suffix
				0x35, 0x00, 0xAA, 0xBB, 0xCC, 0xDD,
			)
			return d
		}()

		header, consumed, _, err := DecompressHeader(data, mac, contexts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if consumed != 10 {
			t.Errorf("consumed = %d, want 10", consumed)
		}
		// Expected: ff35:0040:fd00:cafe:face:1234:AABB:CCDD
		if header[24] != 0xFF || header[25] != 0x35 {
			t.Errorf("mcast prefix wrong: got %x %x", header[24], header[25])
		}
		if header[27] != 64 { // prefix len from context
			t.Errorf("prefix len = %d, want 64", header[27])
		}
		if header[36] != 0xAA || header[37] != 0xBB || header[38] != 0xCC || header[39] != 0xDD {
			t.Errorf("mcast suffix wrong")
		}
	})

	t.Run("multicast DAC=1 invalid DAM", func(t *testing.T) {
		// M=1, DAC=1, DAM=01 → not defined, should error
		// IPHC: TF=11, NH=inline, HLIM=01, CID=1, SAC=0, SAM=11, M=1, DAC=1, DAM=01
		// = 0111 1001 1011 1101 = 0x79BD
		data := []byte{0x79, 0xBD, 0x00, 0x11}
		_, _, _, err := DecompressHeader(data, mac, contexts)
		if err == nil {
			t.Error("expected error for undefined M=1 DAC=1 DAM=01")
		}
	})
}

func TestDecompressUDPHeaderTruncated(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"truncated PP=01", []byte{0xF1, 0x00}},
		{"truncated PP=10", []byte{0xF2, 0xCD}},
		{"truncated PP=11", []byte{0xF3}},
		{"truncated checksum", []byte{0xF0, 0x00, 0x50, 0x00, 0x51}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := DecompressUDPHeader(tt.data)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// makeLinkLocalAddr constructs a link-local address from an 8-byte IID.
func makeLinkLocalAddr(iid [8]byte) [16]byte {
	var a [16]byte
	copy(a[:8], linkLocalPrefix[:])
	copy(a[8:], iid[:])
	return a
}
