// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package frame_test

import (
	"testing"

	"github.com/hilli/gothread/mac/frame"
	"github.com/hilli/gothread/mac/types"
)

// --- Test vectors from OpenThread's test_mac_frame.cpp ---------------------

// Immediate ACK (Version 2006).
// FCF = 0x1002: Type=Ack(2), Version=2006, no security, no pending,
// no ack request, no PAN ID compression, no addrs.
// Sequence = 94 (0x5e). Last 2 bytes = FCS.
var testACK2006 = []byte{0x02, 0x10, 0x5e, 0xd2, 0x9b}

// IEEE 802.15.4-2006 MAC Command frame from OpenThread.
// FCF = 0xDC6B: Type=MacCmd(3), Security=yes, AckRequest=yes,
// PanIDCompression=yes, DstAddr=Extended, SrcAddr=Extended, Version=2006.
// Sequence = 0x85 (133).
var testMacCmd2006 = []byte{
	0x6b, 0xdc, 0x85, 0xce, 0xfa, 0x47, 0x36, 0x07,
	0xd9, 0x74, 0x45, 0x8d, 0xb2, 0x6e, 0x81, 0x25,
	0xc9, 0xdb, 0xac, 0x2b, 0x0a, 0x0d, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x04, 0xaf, 0x14, 0xce, 0xaa,
	0x5a, 0xe5,
}

// IEEE 802.15.4-2015 Data frame from OpenThread.
// FCF = 0xEE29: Type=Data(1), Security=yes, AckRequest=yes,
// PanIDCompression=no, IePresent=yes,
// DstAddr=Extended, SrcAddr=Extended, Version=2015.
// Sequence = 0x53 (83).
var testData2015 = []byte{
	0x29, 0xee, 0x53, 0xce, 0xfa, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x0a, 0x6e, 0x16, 0x05, 0x00, 0x00,
	0x00, 0x00, 0x0a, 0x6e, 0x16, 0x0d, 0x01, 0x00,
	0x00, 0x00, 0x01,
}

// --- FCF parsing tests -----------------------------------------------------

func TestFrameGetFCF(t *testing.T) {
	tests := []struct {
		name string
		psdu []byte
		want uint16
	}{
		{"ack2006", testACK2006, 0x1002},
		{"data2015", testData2015, 0xEE29},
		{"macCmd2006", testMacCmd2006, 0xDC6B},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := frame.NewFrame(tt.psdu)
			got := f.GetFCF()
			if got != tt.want {
				t.Errorf("GetFCF() = 0x%04X, want 0x%04X", got, tt.want)
			}
		})
	}
}

// --- Frame type tests ------------------------------------------------------

func TestFrameGetType(t *testing.T) {
	tests := []struct {
		name string
		psdu []byte
		want frame.Type
	}{
		{"ack2006", testACK2006, frame.TypeAck},
		{"data2015", testData2015, frame.TypeData},
		{"macCmd2006", testMacCmd2006, frame.TypeMacCmd},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := frame.NewFrame(tt.psdu)
			if got := f.GetType(); got != tt.want {
				t.Errorf("GetType() = %d, want %d", got, tt.want)
			}
		})
	}
}

// --- Frame version tests ---------------------------------------------------

func TestFrameGetVersion(t *testing.T) {
	tests := []struct {
		name string
		psdu []byte
		want frame.Version
	}{
		{"ack2006", testACK2006, frame.Version2006},
		{"data2015", testData2015, frame.Version2015},
		{"macCmd2006", testMacCmd2006, frame.Version2006},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := frame.NewFrame(tt.psdu)
			if got := f.GetVersion(); got != tt.want {
				t.Errorf("GetVersion() = 0x%04X, want 0x%04X", got, tt.want)
			}
		})
	}
}

// --- Boolean flag tests ----------------------------------------------------

func TestFrameBooleanFlags(t *testing.T) {
	tests := []struct {
		name      string
		psdu      []byte
		security  bool
		pending   bool
		ackReq    bool
		panComp   bool
		iePresent bool
	}{
		{
			// ACK 2006: FCF=0x1002. All flags false.
			"ack2006", testACK2006,
			false, false, false, false, false,
		},
		{
			// Data 2015: FCF=0xEE29.
			// Security=yes(0x0008), FramePending=no,
			// AckRequest=yes(0x0020), PanIDCompression=no,
			// IePresent=yes(0x0200).
			"data2015", testData2015,
			true, false, true, false, true,
		},
		{
			// MacCmd 2006: FCF=0xDC6B.
			// Security=yes(0x0008), FramePending=no,
			// AckRequest=yes(0x0020), PanIDCompression=yes(0x0040),
			// IePresent=no.
			"macCmd2006", testMacCmd2006,
			true, false, true, true, false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := frame.NewFrame(tt.psdu)
			if got := f.IsSecurityEnabled(); got != tt.security {
				t.Errorf("IsSecurityEnabled() = %v, want %v", got, tt.security)
			}
			if got := f.IsFramePending(); got != tt.pending {
				t.Errorf("IsFramePending() = %v, want %v", got, tt.pending)
			}
			if got := f.IsAckRequest(); got != tt.ackReq {
				t.Errorf("IsAckRequest() = %v, want %v", got, tt.ackReq)
			}
			if got := f.IsPanIDCompression(); got != tt.panComp {
				t.Errorf("IsPanIDCompression() = %v, want %v", got, tt.panComp)
			}
			if got := f.IsIePresent(); got != tt.iePresent {
				t.Errorf("IsIePresent() = %v, want %v", got, tt.iePresent)
			}
		})
	}
}

// --- Sequence number tests -------------------------------------------------

func TestFrameGetSequence(t *testing.T) {
	tests := []struct {
		name string
		psdu []byte
		want uint8
	}{
		{"ack2006", testACK2006, 94},
		{"data2015", testData2015, 83},
		{"macCmd2006", testMacCmd2006, 133},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := frame.NewFrame(tt.psdu)
			if got := f.GetSequence(); got != tt.want {
				t.Errorf("GetSequence() = %d, want %d", got, tt.want)
			}
		})
	}
}

// --- Address mode tests ----------------------------------------------------

func TestFrameGetDstAddrMode(t *testing.T) {
	tests := []struct {
		name string
		psdu []byte
		want types.AddressType
	}{
		{"ack2006_none", testACK2006, types.AddressTypeNone},
		{"data2015_ext", testData2015, types.AddressTypeExtended},
		{"macCmd2006_ext", testMacCmd2006, types.AddressTypeExtended},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := frame.NewFrame(tt.psdu)
			if got := f.GetDstAddrMode(); got != tt.want {
				t.Errorf("GetDstAddrMode() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestFrameGetSrcAddrMode(t *testing.T) {
	tests := []struct {
		name string
		psdu []byte
		want types.AddressType
	}{
		{"ack2006_none", testACK2006, types.AddressTypeNone},
		{"data2015_ext", testData2015, types.AddressTypeExtended},
		{"macCmd2006_ext", testMacCmd2006, types.AddressTypeExtended},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := frame.NewFrame(tt.psdu)
			if got := f.GetSrcAddrMode(); got != tt.want {
				t.Errorf("GetSrcAddrMode() = %d, want %d", got, tt.want)
			}
		})
	}
}

// --- PAN ID presence tests -------------------------------------------------

func TestFrameIsDstPanIDPresent(t *testing.T) {
	tests := []struct {
		name string
		psdu []byte
		want bool
	}{
		// ACK 2006: no addrs → no PAN ID.
		{"ack2006", testACK2006, false},
		// Data 2015: both ext, no compression → dst PAN ID present (row 7).
		{"data2015", testData2015, true},
		// MacCmd 2006: dst ext present → dst PAN ID present.
		{"macCmd2006", testMacCmd2006, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := frame.NewFrame(tt.psdu)
			if got := f.IsDstPanIDPresent(); got != tt.want {
				t.Errorf("IsDstPanIDPresent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFrameIsSrcPanIDPresent(t *testing.T) {
	tests := []struct {
		name string
		psdu []byte
		want bool
	}{
		// ACK 2006: no src addr → no src PAN ID.
		{"ack2006", testACK2006, false},
		// Data 2015: both ext → src PAN ID NOT present (special case).
		{"data2015", testData2015, false},
		// MacCmd 2006: src ext present but compressed → no src PAN ID.
		{"macCmd2006", testMacCmd2006, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := frame.NewFrame(tt.psdu)
			if got := f.IsSrcPanIDPresent(); got != tt.want {
				t.Errorf("IsSrcPanIDPresent() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- PAN ID value tests ----------------------------------------------------

func TestFrameGetDstPanID(t *testing.T) {
	tests := []struct {
		name    string
		psdu    []byte
		wantID  types.PanID
		wantErr bool
	}{
		{
			"ack2006_no_panid", testACK2006, 0, true,
		},
		{
			// Data 2015: DstPanID at bytes 3-4 (LE): 0xCE,0xFA → 0xFACE.
			"data2015", testData2015, 0xFACE, false,
		},
		{
			// MacCmd 2006: DstPanID at bytes 3-4 (LE): 0xCE,0xFA → 0xFACE.
			"macCmd2006", testMacCmd2006, 0xFACE, false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := frame.NewFrame(tt.psdu)
			got, err := f.GetDstPanID()
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetDstPanID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.wantID {
				t.Errorf("GetDstPanID() = 0x%04X, want 0x%04X", got, tt.wantID)
			}
		})
	}
}

// --- Destination address tests ---------------------------------------------

func TestFrameGetDstAddr(t *testing.T) {
	tests := []struct {
		name     string
		psdu     []byte
		wantType types.AddressType
		wantErr  bool
	}{
		{"ack2006_none", testACK2006, types.AddressTypeNone, false},
		{"data2015_ext", testData2015, types.AddressTypeExtended, false},
		{"macCmd2006_ext", testMacCmd2006, types.AddressTypeExtended, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := frame.NewFrame(tt.psdu)
			got, err := f.GetDstAddr()
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetDstAddr() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got.GetType() != tt.wantType {
				t.Errorf("GetDstAddr().GetType() = %d, want %d", got.GetType(), tt.wantType)
			}
		})
	}
}

// --- Source address tests --------------------------------------------------

func TestFrameGetSrcAddr(t *testing.T) {
	tests := []struct {
		name     string
		psdu     []byte
		wantType types.AddressType
		wantErr  bool
	}{
		{"ack2006_none", testACK2006, types.AddressTypeNone, false},
		{"data2015_ext", testData2015, types.AddressTypeExtended, false},
		{"macCmd2006_ext", testMacCmd2006, types.AddressTypeExtended, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := frame.NewFrame(tt.psdu)
			got, err := f.GetSrcAddr()
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetSrcAddr() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got.GetType() != tt.wantType {
				t.Errorf("GetSrcAddr().GetType() = %d, want %d", got.GetType(), tt.wantType)
			}
		})
	}
}

// --- Security accessor tests -----------------------------------------------

func TestFrameSecurityAccessors(t *testing.T) {
	// For the data2015 frame:
	// FCF=0xEE29: both ext, no PanIDCompression, Version2015.
	// 2015 both-ext no-compress: dst PAN ID present, src PAN ID NOT present.
	// Layout: FCF(2) + Seq(1) + DstPanID(2) + DstExt(8) + SrcExt(8) = 21.
	// SecControl at index 21 = 0x0d.
	// 0x0d = 0000 1101. Level = 101b = 5 (EncMic32). Mode = 01b = 1 (KeyIDMode1).
	t.Run("data2015", func(t *testing.T) {
		f := frame.NewFrame(testData2015)
		if got := f.GetSecurityLevel(); got != frame.SecurityEncMic32 {
			t.Errorf("GetSecurityLevel() = %d, want %d (EncMic32)", got, frame.SecurityEncMic32)
		}
		if got := f.GetKeyIDMode(); got != frame.KeyIDMode1 {
			t.Errorf("GetKeyIDMode() = %d, want %d (KeyIDMode1)", got, frame.KeyIDMode1)
		}
		fc, err := f.GetFrameCounter()
		if err != nil {
			t.Fatalf("GetFrameCounter() error = %v", err)
		}
		// FrameCounter at bytes 22-25 (LE): {0x01, 0x00, 0x00, 0x00} → 1.
		if fc != 1 {
			t.Errorf("GetFrameCounter() = %d, want 1", fc)
		}
		kid, err := f.GetKeyID()
		if err != nil {
			t.Fatalf("GetKeyID() error = %v", err)
		}
		// KeyIndex at byte 26 = 0x01.
		if kid != 1 {
			t.Errorf("GetKeyID() = %d, want 1", kid)
		}
	})

	// For macCmd2006:
	// FCF=0xDC6B: both ext, PanIDCompression=yes, Version=2006.
	// Layout: FCF(2)+Seq(1)+DstPanID(2)+DstExt(8)+SrcExt(8) = 21.
	// (No src PAN ID because compressed.)
	// SecControl at index 21 = 0x0d.
	t.Run("macCmd2006", func(t *testing.T) {
		f := frame.NewFrame(testMacCmd2006)
		if got := f.GetSecurityLevel(); got != frame.SecurityEncMic32 {
			t.Errorf("GetSecurityLevel() = %d, want %d (EncMic32)", got, frame.SecurityEncMic32)
		}
		if got := f.GetKeyIDMode(); got != frame.KeyIDMode1 {
			t.Errorf("GetKeyIDMode() = %d, want %d (KeyIDMode1)", got, frame.KeyIDMode1)
		}
		_, err := f.GetFrameCounter()
		if err != nil {
			t.Fatalf("GetFrameCounter() error = %v", err)
		}
		kid, err := f.GetKeyID()
		if err != nil {
			t.Fatalf("GetKeyID() error = %v", err)
		}
		// KeyIndex at byte 26 = 0x01.
		if kid != 1 {
			t.Errorf("GetKeyID() = %d, want 1", kid)
		}
	})

	// ACK: no security header.
	t.Run("ack2006_no_security", func(t *testing.T) {
		f := frame.NewFrame(testACK2006)
		if got := f.GetSecurityLevel(); got != frame.SecurityNone {
			t.Errorf("GetSecurityLevel() = %d, want %d", got, frame.SecurityNone)
		}
		_, err := f.GetFrameCounter()
		if err == nil {
			t.Error("GetFrameCounter() expected error for non-secured frame")
		}
	})
}

// --- Header/footer length tests --------------------------------------------

func TestFrameHeaderFooterLength(t *testing.T) {
	tests := []struct {
		name       string
		psdu       []byte
		wantHeader uint8
		wantFooter uint8
		wantErr    bool
	}{
		{
			// ACK frame (2006): FCF(2) + Seq(1) = 3. No addrs, no security.
			// Footer = FCS(2).
			"ack2006", testACK2006, 3, 2, false,
		},
		{
			// Data 2006, short dst+src, PanID compression, no security.
			// FCF = 0x9841: Type=Data(1), Version=2006(0x1000),
			// DstAddr=Short(0x0800), SrcAddr=Short(0x8000),
			// PanIDCompression(0x0040).
			// Header: FCF(2)+Seq(1)+DstPanID(2)+DstShort(2)+SrcShort(2) = 9.
			// (SrcPanID absent because compressed.)
			"data2006_short_compressed",
			buildMinPSDU(0x9841, 0x00, 9, 2),
			9, 2, false,
		},
		{
			// Data 2006, short dst+src, no compression, no security.
			// FCF = 0x9801: Type=Data(1), Version=2006(0x1000),
			// DstAddr=Short(0x0800), SrcAddr=Short(0x8000).
			// Header: FCF(2)+Seq(1)+DstPanID(2)+DstShort(2)+SrcPanID(2)+SrcShort(2) = 11.
			"data2006_short_both_panid",
			buildMinPSDU(0x9801, 0x00, 11, 2),
			11, 2, false,
		},
		{
			// Data 2015, both ext + no compression, no security.
			// FCF = 0xEC01: Type=Data(1), Version=2015(0x2000),
			// DstAddr=Ext(0x0C00), SrcAddr=Ext(0xC000).
			// 2015 both-ext no-compress: dst PAN ID present, src PAN ID not present.
			// Header: FCF(2)+Seq(1)+DstPanID(2)+DstExt(8)+SrcExt(8) = 21.
			"data2015_ext_no_compress_nosec",
			buildMinPSDU(0xEC01, 0x00, 21, 2),
			21, 2, false,
		},
		{
			// Data 2015, both ext + compressed, no security.
			// FCF = 0xEC41: above | PanIDCompression(0x0040).
			// 2015 both-ext compressed: NO PAN IDs (row 8).
			// Header: FCF(2)+Seq(1)+DstExt(8)+SrcExt(8) = 19.
			"data2015_ext_compressed_nosec",
			buildMinPSDU(0xEC41, 0x00, 19, 2),
			19, 2, false,
		},
		{
			// Data 2015, with security (EncMic32, KeyIDMode1).
			// Uses real testData2015 vector.
			// Header: FCF(2)+Seq(1)+DstPanID(2)+DstExt(8)+SrcExt(8)+
			// SecCtrl(1)+FrameCtr(4)+KeyIndex(1) = 27.
			// Footer: FCS(2)+MIC32(4) = 6.
			"data2015_ext_security",
			testData2015,
			27, 6, false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := frame.NewFrame(tt.psdu)
			gotHeader, err := f.GetHeaderLength()
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetHeaderLength() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && gotHeader != tt.wantHeader {
				t.Errorf("GetHeaderLength() = %d, want %d", gotHeader, tt.wantHeader)
			}
			gotFooter := f.GetFooterLength()
			if gotFooter != tt.wantFooter {
				t.Errorf("GetFooterLength() = %d, want %d", gotFooter, tt.wantFooter)
			}
		})
	}
}

// buildMinPSDU creates a minimal PSDU with the given FCF, filling the
// required header bytes and footer bytes with zeros.
func buildMinPSDU(fcf uint16, seq uint8, headerLen, footerLen int) []byte {
	total := headerLen + footerLen
	psdu := make([]byte, total)
	psdu[0] = byte(fcf)
	psdu[1] = byte(fcf >> 8)
	if headerLen > 2 {
		psdu[2] = seq
	}
	return psdu
}

// --- GetPayload tests ------------------------------------------------------

func TestFrameGetPayload(t *testing.T) {
	// ACK frame: header=3, footer=2. Payload is empty (3+2=5, len=5).
	f := frame.NewFrame(testACK2006)
	payload, err := f.GetPayload()
	if err != nil {
		t.Fatalf("GetPayload() error = %v", err)
	}
	if len(payload) != 0 {
		t.Errorf("ACK payload len = %d, want 0", len(payload))
	}
}

// --- GetPsdu test ----------------------------------------------------------

func TestFrameGetPsdu(t *testing.T) {
	f := frame.NewFrame(testACK2006)
	psdu := f.GetPsdu()
	if len(psdu) != len(testACK2006) {
		t.Errorf("GetPsdu() len = %d, want %d", len(psdu), len(testACK2006))
	}
}

// --- MIC size tests --------------------------------------------------------

func TestSecurityLevelMicSize(t *testing.T) {
	tests := []struct {
		level   frame.SecurityLevel
		wantMIC uint8
	}{
		{frame.SecurityNone, 0},
		{frame.SecurityMic32, 4},
		{frame.SecurityMic64, 8},
		{frame.SecurityMic128, 16},
		{frame.SecurityEnc, 0},
		{frame.SecurityEncMic32, 4},
		{frame.SecurityEncMic64, 8},
		{frame.SecurityEncMic128, 16},
	}
	for _, tt := range tests {
		if got := tt.level.MicSize(); got != tt.wantMIC {
			t.Errorf("SecurityLevel(%d).MicSize() = %d, want %d", tt.level, got, tt.wantMIC)
		}
	}
}

// --- KeyIDMode size tests --------------------------------------------------

func TestKeyIDModeSize(t *testing.T) {
	tests := []struct {
		mode     frame.KeyIDMode
		wantSize uint8
	}{
		{frame.KeyIDMode0, 0},
		{frame.KeyIDMode1, 1},
		{frame.KeyIDMode2, 5},
		{frame.KeyIDMode3, 9},
	}
	for _, tt := range tests {
		if got := tt.mode.KeyIDSize(); got != tt.wantSize {
			t.Errorf("KeyIDMode(%d).KeyIDSize() = %d, want %d", tt.mode, got, tt.wantSize)
		}
	}
}

// --- MacCmd2006 CommandID test ---------------------------------------------

func TestMacCmd2006CommandID(t *testing.T) {
	// Verify that after parsing the header, the first payload byte is the
	// MAC command identifier. For testMacCmd2006, OpenThread confirms
	// command = 0x04 (Data Request).
	f := frame.NewFrame(testMacCmd2006)
	payload, err := f.GetPayload()
	if err != nil {
		t.Fatalf("GetPayload() error = %v", err)
	}
	if len(payload) < 1 {
		t.Fatal("expected at least 1 byte of payload for MAC command")
	}
	const macCmdDataRequest = 0x04
	if payload[0] != macCmdDataRequest {
		t.Errorf("command ID = 0x%02X, want 0x%02X", payload[0], macCmdDataRequest)
	}
}

// --- Fuzz test -------------------------------------------------------------

func FuzzFrame(f *testing.F) {
	// Seed with real test vectors.
	f.Add(testACK2006)
	f.Add(testData2015)
	f.Add(testMacCmd2006)

	// Seed with synthetic minimal frames.
	f.Add(buildMinPSDU(0x9841, 0x00, 9, 2))
	f.Add(buildMinPSDU(0x9801, 0x00, 11, 2))
	f.Add(buildMinPSDU(0xEC41, 0x00, 19, 2))

	// Edge cases.
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xFF, 0xFF})

	f.Fuzz(func(_ *testing.T, data []byte) {
		fr := frame.NewFrame(data)

		// These must not panic regardless of input.
		_ = fr.GetFCF()
		_ = fr.GetType()
		_ = fr.GetVersion()
		_ = fr.IsSecurityEnabled()
		_ = fr.IsFramePending()
		_ = fr.IsAckRequest()
		_ = fr.IsPanIDCompression()
		_ = fr.IsSequenceSuppressed()
		_ = fr.IsIePresent()
		_ = fr.GetSequence()
		_ = fr.GetDstAddrMode()
		_ = fr.GetSrcAddrMode()
		_ = fr.IsDstPanIDPresent()
		_ = fr.IsSrcPanIDPresent()
		_ = fr.GetSecurityLevel()
		_ = fr.GetKeyIDMode()
		_ = fr.GetMicSize()
		_ = fr.GetFooterLength()
		_ = fr.GetPsdu()

		// These may return errors but must not panic.
		_, _ = fr.GetDstPanID()
		_, _ = fr.GetDstAddr()
		_, _ = fr.GetSrcPanID()
		_, _ = fr.GetSrcAddr()
		_, _ = fr.GetFrameCounter()
		_, _ = fr.GetKeyID()
		_, _ = fr.GetHeaderLength()
		_, _ = fr.GetPayload()
	})
}
