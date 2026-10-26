// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package ip6_test

import (
	"testing"
	"unsafe"

	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// IPv6 Header
// ---------------------------------------------------------------------------

func TestHeaderGetVersion(t *testing.T) {
	tests := []struct {
		name    string
		byte0   byte
		wantVer uint8
	}{
		{"version 6", 0x60, 6},
		{"version 4", 0x40, 4},
		{"version 0", 0x0F, 0},
		{"version 15", 0xFF, 15},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var h ip6.Header
			h.SetTrafficClass(0) // clear TC bits
			// Manually set the version nibble via a known TC to reconstruct byte 0.
			// Since Header is zero-valued, we set byte 0 through the exported API
			// indirectly: first set TC=0 to clear lower nibble, then use a
			// raw-data helper. Instead, construct via the data array directly.
			// We access the internal data by building a full 40-byte slice.
			raw := headerBytes(tt.byte0, 0, 0, 0)
			h = headerFromBytes(raw)
			if got := h.GetVersion(); got != tt.wantVer {
				t.Errorf("GetVersion() = %d, want %d", got, tt.wantVer)
			}
		})
	}
}

func TestHeaderTrafficClass(t *testing.T) {
	tests := []struct {
		name   string
		tc     uint8
		wantTC uint8
	}{
		{"zero", 0x00, 0x00},
		{"max", 0xFF, 0xFF},
		{"0xAB", 0xAB, 0xAB},
		{"0x3C", 0x3C, 0x3C},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a header with Version=6 and a known flow label.
			raw := headerBytes(0x60, 0x00, 0x00, 0x00)
			h := headerFromBytes(raw)
			h.SetTrafficClass(tt.tc)

			if got := h.GetTrafficClass(); got != tt.wantTC {
				t.Errorf("GetTrafficClass() = %#02x, want %#02x", got, tt.wantTC)
			}
			// Version should remain 6.
			if got := h.GetVersion(); got != 6 {
				t.Errorf("Version changed to %d after SetTrafficClass", got)
			}
		})
	}
}

func TestHeaderDscpEcn(t *testing.T) {
	tests := []struct {
		name     string
		dscp     ip6.Dscp
		ecn      ip6.Ecn
		wantTC   uint8
		wantDSCP ip6.Dscp
		wantECN  ip6.Ecn
	}{
		{"cs0/not-capable", ip6.DscpCs0, ip6.EcnNotCapable, 0x00, 0, 0},
		{"cs6/marked", ip6.DscpCs6, ip6.EcnMarked, 0xC3, 48, 3},
		{"tmf-net/capable0", ip6.DscpTmfNetPriority, ip6.EcnCapable0, 0x1D, 7, 1},
		{"cs7/capable1", ip6.DscpCs7, ip6.EcnCapable1, 0xE2, 56, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := headerBytes(0x60, 0x00, 0x00, 0x00)
			h := headerFromBytes(raw)

			h.SetDscp(tt.dscp)
			h.SetEcn(tt.ecn)

			if got := h.GetTrafficClass(); got != tt.wantTC {
				t.Errorf("GetTrafficClass() = %#02x, want %#02x", got, tt.wantTC)
			}
			if got := h.GetDscp(); got != tt.wantDSCP {
				t.Errorf("GetDscp() = %d, want %d", got, tt.wantDSCP)
			}
			if got := h.GetEcn(); got != tt.wantECN {
				t.Errorf("GetEcn() = %d, want %d", got, tt.wantECN)
			}
		})
	}
}

func TestHeaderFlowLabel(t *testing.T) {
	tests := []struct {
		name string
		flow uint32
	}{
		{"zero", 0x00000},
		{"max 20-bit", 0xFFFFF},
		{"0x12345", 0x12345},
		{"0xABCDE", 0xABCDE},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := headerBytes(0x6A, 0xB0, 0x00, 0x00) // Version=6, TC=0xAB
			h := headerFromBytes(raw)
			h.SetFlowLabel(tt.flow)

			if got := h.GetFlowLabel(); got != tt.flow {
				t.Errorf("GetFlowLabel() = %#05x, want %#05x", got, tt.flow)
			}
			// TC should be preserved.
			if got := h.GetTrafficClass(); got != 0xAB {
				t.Errorf("TrafficClass changed to %#02x after SetFlowLabel", got)
			}
		})
	}
}

func TestHeaderKnownBytes(t *testing.T) {
	// Construct a fully known 40-byte IPv6 header and verify all fields.
	//
	// Version=6, TC=0xAB, Flow=0x12345
	// Byte 0: (6<<4) | (0xAB >> 4) = 0x60 | 0x0A = 0x6A
	// Byte 1: (0xAB & 0x0F)<<4 | (0x12345 >> 16) = 0xB0 | 0x01 = 0xB1
	// Byte 2: (0x12345 >> 8) & 0xFF = 0x23
	// Byte 3: 0x12345 & 0xFF = 0x45
	//
	// PayloadLength = 0x0102
	// NextHeader = 17 (UDP)
	// HopLimit = 64
	//
	// Source = fe80::1
	// Destination = ff02::1
	var raw [40]byte
	raw[0] = 0x6A
	raw[1] = 0xB1
	raw[2] = 0x23
	raw[3] = 0x45
	raw[4] = 0x01
	raw[5] = 0x02
	raw[6] = 17
	raw[7] = 64

	// Source: fe80::1
	raw[8] = 0xfe
	raw[9] = 0x80
	raw[23] = 0x01

	// Destination: ff02::1
	raw[24] = 0xff
	raw[25] = 0x02
	raw[39] = 0x01

	h := headerFromBytes(raw[:])

	if got := h.GetVersion(); got != 6 {
		t.Errorf("Version = %d, want 6", got)
	}
	if got := h.GetTrafficClass(); got != 0xAB {
		t.Errorf("TrafficClass = %#02x, want 0xAB", got)
	}
	if got := h.GetDscp(); got != ip6.Dscp(0xAB>>2) {
		t.Errorf("DSCP = %d, want %d", got, 0xAB>>2)
	}
	if got := h.GetEcn(); got != ip6.Ecn(0xAB&0x03) {
		t.Errorf("ECN = %d, want %d", got, 0xAB&0x03)
	}
	if got := h.GetFlowLabel(); got != 0x12345 {
		t.Errorf("FlowLabel = %#05x, want 0x12345", got)
	}
	if got := h.GetPayloadLength(); got != 0x0102 {
		t.Errorf("PayloadLength = %d, want %d", got, 0x0102)
	}
	if got := h.GetNextHeader(); got != 17 {
		t.Errorf("NextHeader = %d, want 17", got)
	}
	if got := h.GetHopLimit(); got != 64 {
		t.Errorf("HopLimit = %d, want 64", got)
	}

	wantSrc := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	if got := h.GetSource(); got != wantSrc {
		t.Errorf("Source = %v, want %v", got, wantSrc)
	}

	wantDst := ip6.Address{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	if got := h.GetDestination(); got != wantDst {
		t.Errorf("Destination = %v, want %v", got, wantDst)
	}
}

func TestHeaderSetters(t *testing.T) {
	var h ip6.Header

	h.SetPayloadLength(1280)
	if got := h.GetPayloadLength(); got != 1280 {
		t.Errorf("PayloadLength = %d, want 1280", got)
	}

	h.SetNextHeader(ip6.ProtoUDP)
	if got := h.GetNextHeader(); got != ip6.ProtoUDP {
		t.Errorf("NextHeader = %d, want %d", got, ip6.ProtoUDP)
	}

	h.SetHopLimit(255)
	if got := h.GetHopLimit(); got != 255 {
		t.Errorf("HopLimit = %d, want 255", got)
	}

	src := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	h.SetSource(src)
	if got := h.GetSource(); got != src {
		t.Errorf("Source = %v, want %v", got, src)
	}

	dst := ip6.Address{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	h.SetDestination(dst)
	if got := h.GetDestination(); got != dst {
		t.Errorf("Destination = %v, want %v", got, dst)
	}
}

func TestHeaderTrafficClassPreservesFlowAndVersion(t *testing.T) {
	// Set up a header with Version=6, TC=0, Flow=0xABCDE, then change TC.
	var h ip6.Header
	raw := headerBytes(0x60, 0x00, 0x00, 0x00)
	h = headerFromBytes(raw)
	h.SetFlowLabel(0xABCDE)
	h.SetTrafficClass(0xFF)

	if got := h.GetVersion(); got != 6 {
		t.Errorf("Version = %d, want 6", got)
	}
	if got := h.GetFlowLabel(); got != 0xABCDE {
		t.Errorf("FlowLabel = %#05x, want 0xABCDE", got)
	}
	if got := h.GetTrafficClass(); got != 0xFF {
		t.Errorf("TrafficClass = %#02x, want 0xFF", got)
	}
}

// ---------------------------------------------------------------------------
// ExtensionHeader
// ---------------------------------------------------------------------------

func TestExtensionHeader(t *testing.T) {
	tests := []struct {
		name       string
		nextHeader uint8
		lenUnits   uint8
		wantLen    uint16
	}{
		{"min length (0 units = 8 bytes)", ip6.ProtoHopOpts, 0, 8},
		{"1 unit = 16 bytes", ip6.ProtoRouting, 1, 16},
		{"2 units = 24 bytes", ip6.ProtoDstOpts, 2, 24},
		{"max units = 255 -> 2048 bytes", ip6.ProtoNone, 255, 2048},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var eh ip6.ExtensionHeader
			eh.SetNextHeader(tt.nextHeader)
			eh.SetLength(tt.lenUnits)

			if got := eh.GetNextHeader(); got != tt.nextHeader {
				t.Errorf("GetNextHeader() = %d, want %d", got, tt.nextHeader)
			}
			if got := eh.GetLength(); got != tt.wantLen {
				t.Errorf("GetLength() = %d, want %d", got, tt.wantLen)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// OptionHeader
// ---------------------------------------------------------------------------

func TestOptionHeaderAction(t *testing.T) {
	tests := []struct {
		name       string
		optType    uint8
		wantAction uint8
	}{
		{"Pad1", ip6.OptionPad1, ip6.OptionActionSkip},
		{"PadN", ip6.OptionPadN, ip6.OptionActionSkip},
		{"skip action 0x3F", 0x3F, ip6.OptionActionSkip},
		{"discard action 0x40", 0x40, ip6.OptionActionDiscard},
		{"force ICMP action 0x80", 0x80, ip6.OptionActionForceICMP},
		{"force ICMP if not mcast 0xC0", 0xC0, ip6.OptionActionForceICMPIfNotMcast},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oh := ip6.OptionHeader{Type: tt.optType, Length: 0}
			if got := oh.GetAction(); got != tt.wantAction {
				t.Errorf("GetAction() = %#02x, want %#02x", got, tt.wantAction)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FragmentHeader
// ---------------------------------------------------------------------------

func TestFragmentHeader(t *testing.T) {
	tests := []struct {
		name     string
		raw      [8]byte
		wantNH   uint8
		wantOff  uint16
		wantMore bool
		wantID   uint32
	}{
		{
			name: "no fragment offset, M=0",
			// NH=17, reserved=0, offset=0|M=0, ID=0x12345678
			raw:      [8]byte{17, 0, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78},
			wantNH:   17,
			wantOff:  0,
			wantMore: false,
			wantID:   0x12345678,
		},
		{
			name: "offset=100, M=1",
			// NH=58, reserved=0, offset=100 -> 100<<3=0x0320, M=1 -> 0x0321
			raw:      [8]byte{58, 0, 0x03, 0x21, 0xDE, 0xAD, 0xBE, 0xEF},
			wantNH:   58,
			wantOff:  100,
			wantMore: true,
			wantID:   0xDEADBEEF,
		},
		{
			name: "max offset=8191, M=1",
			// offset=8191 -> 8191<<3=0xFFF8, M=1 -> 0xFFF9
			raw:      [8]byte{6, 0, 0xFF, 0xF9, 0xFF, 0xFF, 0xFF, 0xFF},
			wantNH:   6,
			wantOff:  8191,
			wantMore: true,
			wantID:   0xFFFFFFFF,
		},
		{
			name: "offset=1, M=0",
			// offset=1 -> 1<<3=0x0008, M=0
			raw:      [8]byte{0, 0, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01},
			wantNH:   0,
			wantOff:  1,
			wantMore: false,
			wantID:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fh := fragmentFromBytes(tt.raw[:])

			if got := fh.GetNextHeader(); got != tt.wantNH {
				t.Errorf("GetNextHeader() = %d, want %d", got, tt.wantNH)
			}
			if got := fh.GetOffset(); got != tt.wantOff {
				t.Errorf("GetOffset() = %d, want %d", got, tt.wantOff)
			}
			if got := fh.IsMoreFlagSet(); got != tt.wantMore {
				t.Errorf("IsMoreFlagSet() = %v, want %v", got, tt.wantMore)
			}
			if got := fh.GetIdentification(); got != tt.wantID {
				t.Errorf("GetIdentification() = %#08x, want %#08x", got, tt.wantID)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// UDP Header
// ---------------------------------------------------------------------------

func TestUDPHeaderKnownBytes(t *testing.T) {
	tests := []struct {
		name     string
		raw      [8]byte
		wantSrc  uint16
		wantDst  uint16
		wantLen  uint16
		wantCsum uint16
	}{
		{
			name:     "standard ports",
			raw:      [8]byte{0x04, 0xD2, 0x16, 0x2E, 0x00, 0x1C, 0xAB, 0xCD},
			wantSrc:  1234,
			wantDst:  5678,
			wantLen:  28,
			wantCsum: 0xABCD,
		},
		{
			name:     "all zeros",
			raw:      [8]byte{0, 0, 0, 0, 0, 0, 0, 0},
			wantSrc:  0,
			wantDst:  0,
			wantLen:  0,
			wantCsum: 0,
		},
		{
			name:     "max values",
			raw:      [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			wantSrc:  0xFFFF,
			wantDst:  0xFFFF,
			wantLen:  0xFFFF,
			wantCsum: 0xFFFF,
		},
		{
			name: "thread MLE port",
			// src=19788 (0x4D4C), dst=19788, len=8+payload, checksum=0
			raw:      [8]byte{0x4D, 0x4C, 0x4D, 0x4C, 0x00, 0x08, 0x00, 0x00},
			wantSrc:  19788,
			wantDst:  19788,
			wantLen:  8,
			wantCsum: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uh := udpFromBytes(tt.raw[:])

			if got := uh.GetSourcePort(); got != tt.wantSrc {
				t.Errorf("GetSourcePort() = %d, want %d", got, tt.wantSrc)
			}
			if got := uh.GetDestinationPort(); got != tt.wantDst {
				t.Errorf("GetDestinationPort() = %d, want %d", got, tt.wantDst)
			}
			if got := uh.GetLength(); got != tt.wantLen {
				t.Errorf("GetLength() = %d, want %d", got, tt.wantLen)
			}
			if got := uh.GetChecksum(); got != tt.wantCsum {
				t.Errorf("GetChecksum() = %#04x, want %#04x", got, tt.wantCsum)
			}
		})
	}
}

func TestUDPHeaderSetters(t *testing.T) {
	var uh ip6.UDPHeader

	uh.SetSourcePort(12345)
	if got := uh.GetSourcePort(); got != 12345 {
		t.Errorf("SourcePort = %d, want 12345", got)
	}

	uh.SetDestinationPort(54321)
	if got := uh.GetDestinationPort(); got != 54321 {
		t.Errorf("DestinationPort = %d, want 54321", got)
	}

	uh.SetLength(100)
	if got := uh.GetLength(); got != 100 {
		t.Errorf("Length = %d, want 100", got)
	}

	uh.SetChecksum(0xBEEF)
	if got := uh.GetChecksum(); got != 0xBEEF {
		t.Errorf("Checksum = %#04x, want 0xBEEF", got)
	}
}

// ---------------------------------------------------------------------------
// TCP Header
// ---------------------------------------------------------------------------

func TestTCPHeaderKnownBytes(t *testing.T) {
	tests := []struct {
		name     string
		raw      [20]byte
		wantSrc  uint16
		wantDst  uint16
		wantSeq  uint32
		wantAck  uint32
		wantFlag uint16
		wantWin  uint16
		wantCsum uint16
		wantUrg  uint16
	}{
		{
			name: "SYN packet",
			raw: [20]byte{
				0x00, 0x50, // src port 80
				0x01, 0xBB, // dst port 443
				0x00, 0x00, 0x00, 0x01, // seq: 1.
				0x00, 0x00, 0x00, 0x00, // Acknowledgment number: 0.
				0x50, 0x02, // data offset=5(20 bytes), SYN flag
				0xFF, 0xFF, // window: 65535.
				0x12, 0x34, // checksum
				0x00, 0x00, // urgent pointer: 0.
			},
			wantSrc:  80,
			wantDst:  443,
			wantSeq:  1,
			wantAck:  0,
			wantFlag: 0x5002,
			wantWin:  65535,
			wantCsum: 0x1234,
			wantUrg:  0,
		},
		{
			name: "all zeros",
			raw:  [20]byte{},
			// everything zero
		},
		{
			name: "ACK packet with sequence numbers",
			raw: [20]byte{
				0xC0, 0x00, // src port 49152
				0x00, 0x16, // dst port 22 (SSH)
				0xAB, 0xCD, 0xEF, 0x01, // Sequence number: 0xABCDEF01.
				0x12, 0x34, 0x56, 0x78, // Acknowledgment number: 0x12345678.
				0x50, 0x10, // data offset=5, ACK flag
				0x10, 0x00, // window: 4096.
				0xFE, 0xDC, // checksum
				0x00, 0x05, // urgent pointer: 5.
			},
			wantSrc:  49152,
			wantDst:  22,
			wantSeq:  0xABCDEF01,
			wantAck:  0x12345678,
			wantFlag: 0x5010,
			wantWin:  4096,
			wantCsum: 0xFEDC,
			wantUrg:  5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			th := tcpFromBytes(tt.raw[:])

			if got := th.GetSourcePort(); got != tt.wantSrc {
				t.Errorf("GetSourcePort() = %d, want %d", got, tt.wantSrc)
			}
			if got := th.GetDestinationPort(); got != tt.wantDst {
				t.Errorf("GetDestinationPort() = %d, want %d", got, tt.wantDst)
			}
			if got := th.GetSequenceNumber(); got != tt.wantSeq {
				t.Errorf("GetSequenceNumber() = %#08x, want %#08x", got, tt.wantSeq)
			}
			if got := th.GetAckNumber(); got != tt.wantAck {
				t.Errorf("GetAckNumber() = %#08x, want %#08x", got, tt.wantAck)
			}
			if got := th.GetFlags(); got != tt.wantFlag {
				t.Errorf("GetFlags() = %#04x, want %#04x", got, tt.wantFlag)
			}
			if got := th.GetWindow(); got != tt.wantWin {
				t.Errorf("GetWindow() = %d, want %d", got, tt.wantWin)
			}
			if got := th.GetChecksum(); got != tt.wantCsum {
				t.Errorf("GetChecksum() = %#04x, want %#04x", got, tt.wantCsum)
			}
			if got := th.GetUrgentPointer(); got != tt.wantUrg {
				t.Errorf("GetUrgentPointer() = %d, want %d", got, tt.wantUrg)
			}
		})
	}
}

func TestTCPHeaderSetters(t *testing.T) {
	var th ip6.TCPHeader

	th.SetSourcePort(8080)
	if got := th.GetSourcePort(); got != 8080 {
		t.Errorf("SourcePort = %d, want 8080", got)
	}

	th.SetDestinationPort(443)
	if got := th.GetDestinationPort(); got != 443 {
		t.Errorf("DestinationPort = %d, want 443", got)
	}

	th.SetSequenceNumber(0xDEADBEEF)
	if got := th.GetSequenceNumber(); got != 0xDEADBEEF {
		t.Errorf("SequenceNumber = %#08x, want 0xDEADBEEF", got)
	}

	th.SetAckNumber(0xCAFEBABE)
	if got := th.GetAckNumber(); got != 0xCAFEBABE {
		t.Errorf("AckNumber = %#08x, want 0xCAFEBABE", got)
	}

	th.SetFlags(0x5012) // data offset=5, SYN+ACK
	if got := th.GetFlags(); got != 0x5012 {
		t.Errorf("Flags = %#04x, want 0x5012", got)
	}

	th.SetWindow(32768)
	if got := th.GetWindow(); got != 32768 {
		t.Errorf("Window = %d, want 32768", got)
	}

	th.SetChecksum(0xAAAA)
	if got := th.GetChecksum(); got != 0xAAAA {
		t.Errorf("Checksum = %#04x, want 0xAAAA", got)
	}

	th.SetUrgentPointer(100)
	if got := th.GetUrgentPointer(); got != 100 {
		t.Errorf("UrgentPointer = %d, want 100", got)
	}
}

// ---------------------------------------------------------------------------
// Protocol number constants
// ---------------------------------------------------------------------------

func TestProtocolConstants(t *testing.T) {
	tests := []struct {
		name  string
		value uint8
		want  uint8
	}{
		{"ProtoHopOpts", ip6.ProtoHopOpts, 0},
		{"ProtoTCP", ip6.ProtoTCP, 6},
		{"ProtoUDP", ip6.ProtoUDP, 17},
		{"ProtoIPv6", ip6.ProtoIPv6, 41},
		{"ProtoRouting", ip6.ProtoRouting, 43},
		{"ProtoFragment", ip6.ProtoFragment, 44},
		{"ProtoICMPv6", ip6.ProtoICMPv6, 58},
		{"ProtoNone", ip6.ProtoNone, 59},
		{"ProtoDstOpts", ip6.ProtoDstOpts, 60},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// DSCP and ECN constants
// ---------------------------------------------------------------------------

func TestDscpConstants(t *testing.T) {
	tests := []struct {
		name string
		dscp ip6.Dscp
		want uint8
	}{
		{"DscpCs0", ip6.DscpCs0, 0},
		{"DscpCs1", ip6.DscpCs1, 8},
		{"DscpCs2", ip6.DscpCs2, 16},
		{"DscpCs3", ip6.DscpCs3, 24},
		{"DscpCs4", ip6.DscpCs4, 32},
		{"DscpCs5", ip6.DscpCs5, 40},
		{"DscpCs6", ip6.DscpCs6, 48},
		{"DscpCs7", ip6.DscpCs7, 56},
		{"DscpTmfNetPriority", ip6.DscpTmfNetPriority, 7},
		{"DscpTmfNormalPriority", ip6.DscpTmfNormalPriority, 15},
		{"DscpTmfLowPriority", ip6.DscpTmfLowPriority, 23},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if uint8(tt.dscp) != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.dscp, tt.want)
			}
		})
	}
}

func TestEcnConstants(t *testing.T) {
	tests := []struct {
		name string
		ecn  ip6.Ecn
		want uint8
	}{
		{"EcnNotCapable", ip6.EcnNotCapable, 0},
		{"EcnCapable0", ip6.EcnCapable0, 1},
		{"EcnCapable1", ip6.EcnCapable1, 2},
		{"EcnMarked", ip6.EcnMarked, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if uint8(tt.ecn) != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.ecn, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Size constants
// ---------------------------------------------------------------------------

func TestSizeConstants(t *testing.T) {
	if ip6.HeaderSize != 40 {
		t.Errorf("HeaderSize = %d, want 40", ip6.HeaderSize)
	}
	if ip6.FragmentHeaderSize != 8 {
		t.Errorf("FragmentHeaderSize = %d, want 8", ip6.FragmentHeaderSize)
	}
	if ip6.UDPHeaderSize != 8 {
		t.Errorf("UDPHeaderSize = %d, want 8", ip6.UDPHeaderSize)
	}
	if ip6.TCPHeaderSize != 20 {
		t.Errorf("TCPHeaderSize = %d, want 20", ip6.TCPHeaderSize)
	}
}

// ---------------------------------------------------------------------------
// HeaderFromBytes and Bytes
// ---------------------------------------------------------------------------

func TestHeaderFromBytes(t *testing.T) {
	// Build a valid IPv6 header: version=6, TC=0, flow=0, payload=0,
	// next header=UDP(17), hop limit=64, src=::1, dst=::2.
	var raw [40]byte
	raw[0] = 0x60 // version=6
	raw[6] = 17   // next header = UDP
	raw[7] = 64   // hop limit
	raw[23] = 1   // src = ::1
	raw[39] = 2   // dst = ::2

	h := ip6.HeaderFromBytes(raw)
	if got := h.GetVersion(); got != 6 {
		t.Errorf("GetVersion() = %d, want 6", got)
	}
	if got := h.GetNextHeader(); got != 17 {
		t.Errorf("GetNextHeader() = %d, want 17", got)
	}
	if got := h.GetHopLimit(); got != 64 {
		t.Errorf("GetHopLimit() = %d, want 64", got)
	}
	src := h.GetSource()
	if src[15] != 1 {
		t.Errorf("GetSource()[15] = %d, want 1", src[15])
	}
	dst := h.GetDestination()
	if dst[15] != 2 {
		t.Errorf("GetDestination()[15] = %d, want 2", dst[15])
	}
}

func TestHeaderBytes(t *testing.T) {
	var h ip6.Header
	h.SetHopLimit(128)
	h.SetNextHeader(58) // ICMPv6
	raw := h.Bytes()
	if raw[7] != 128 {
		t.Errorf("Bytes()[7] = %d, want 128", raw[7])
	}
	if raw[6] != 58 {
		t.Errorf("Bytes()[6] = %d, want 58", raw[6])
	}
}

func TestHeaderFromBytesRoundtrip(t *testing.T) {
	// Build header via setters, extract bytes, reconstruct, verify.
	var h ip6.Header
	h.SetTrafficClass(0xAB)
	h.SetFlowLabel(0x12345)
	h.SetPayloadLength(100)
	h.SetNextHeader(17)
	h.SetHopLimit(64)

	var src, dst ip6.Address
	src[15] = 0x01
	dst[15] = 0x02
	h.SetSource(src)
	h.SetDestination(dst)

	raw := h.Bytes()
	h2 := ip6.HeaderFromBytes(raw)
	if h2.GetTrafficClass() != 0xAB {
		t.Errorf("TC roundtrip: got 0x%02X, want 0xAB", h2.GetTrafficClass())
	}
	if h2.GetFlowLabel() != 0x12345 {
		t.Errorf("FlowLabel roundtrip: got 0x%05X, want 0x12345", h2.GetFlowLabel())
	}
	if h2.GetPayloadLength() != 100 {
		t.Errorf("PayloadLength roundtrip: got %d, want 100", h2.GetPayloadLength())
	}
	if h2.GetSource() != src {
		t.Errorf("Source roundtrip mismatch")
	}
	if h2.GetDestination() != dst {
		t.Errorf("Destination roundtrip mismatch")
	}
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// headerBytes builds a minimal 40-byte slice with the first 4 bytes set.
func headerBytes(b0, b1, b2, b3 byte) []byte {
	raw := make([]byte, 40)
	raw[0] = b0
	raw[1] = b1
	raw[2] = b2
	raw[3] = b3
	return raw
}

// headerFromBytes constructs a Header from a byte slice. Since Header wraps
// an unexported [40]byte array with the same memory layout, we use
// unsafe.Pointer to reinterpret the array as a Header.
func headerFromBytes(b []byte) ip6.Header {
	var arr [40]byte
	copy(arr[:], b)
	return *(*ip6.Header)(unsafe.Pointer(&arr))
}

// fragmentFromBytes constructs a FragmentHeader from a byte slice.
func fragmentFromBytes(b []byte) ip6.FragmentHeader {
	var arr [8]byte
	copy(arr[:], b)
	return *(*ip6.FragmentHeader)(unsafe.Pointer(&arr))
}

// udpFromBytes constructs a UDPHeader from a byte slice.
func udpFromBytes(b []byte) ip6.UDPHeader {
	var arr [8]byte
	copy(arr[:], b)
	return *(*ip6.UDPHeader)(unsafe.Pointer(&arr))
}

// tcpFromBytes constructs a TCPHeader from a byte slice.
func tcpFromBytes(b []byte) ip6.TCPHeader {
	var arr [20]byte
	copy(arr[:], b)
	return *(*ip6.TCPHeader)(unsafe.Pointer(&arr))
}
