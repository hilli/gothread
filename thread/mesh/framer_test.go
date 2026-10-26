// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import (
	"encoding/binary"
	"testing"

	"github.com/hilli/gothread/errors"
)

// TestBuildDataFrame_ShortAddrs_NoSecurity builds a data frame with short
// source and destination addresses and no security, then verifies the wire
// format byte-by-byte.
func TestBuildDataFrame_ShortAddrs_NoSecurity(t *testing.T) {
	f := NewFramer()
	ctx := &FrameContext{
		SrcShortAddr:   0x1234,
		DstShortAddr:   0xABCD,
		UseSrcShort:    true,
		UseDstShort:    true,
		PanId:          0xCAFE,
		SequenceNumber: 42,
	}
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	frame, err := f.BuildDataFrame(ctx, payload)
	if err != nil {
		t.Fatalf("BuildDataFrame() error = %v", err)
	}

	// Expected header: FCF(2) + SeqNum(1) + DstPanId(2) + DstShort(2) + SrcShort(2) = 9 bytes
	// PAN ID compression is on, so no src PAN ID.
	expectedHeaderSize := 9
	if len(frame) != expectedHeaderSize+len(payload) {
		t.Fatalf("frame length = %d, want %d", len(frame), expectedHeaderSize+len(payload))
	}

	// FCF: data frame (0x01), no security, no frame pending, no ack request,
	// PAN ID compression set, dst addr mode short (0x02), frame version 2006 (0x01),
	// src addr mode short (0x02).
	fc := binary.LittleEndian.Uint16(frame[0:2])
	wantFC := buildFrameControl(uint8(FrameTypeData), false, false, false, true, false, AddrModeShort, AddrModeShort, FrameVersion2006)
	if fc != wantFC {
		t.Errorf("FCF = 0x%04X, want 0x%04X", fc, wantFC)
	}

	// Sequence number
	if frame[2] != 42 {
		t.Errorf("SeqNum = %d, want 42", frame[2])
	}

	// Destination PAN ID
	panID := binary.LittleEndian.Uint16(frame[3:5])
	if panID != 0xCAFE {
		t.Errorf("DstPanId = 0x%04X, want 0xCAFE", panID)
	}

	// Destination short address
	dstAddr := binary.LittleEndian.Uint16(frame[5:7])
	if dstAddr != 0xABCD {
		t.Errorf("DstAddr = 0x%04X, want 0xABCD", dstAddr)
	}

	// Source short address
	srcAddr := binary.LittleEndian.Uint16(frame[7:9])
	if srcAddr != 0x1234 {
		t.Errorf("SrcAddr = 0x%04X, want 0x1234", srcAddr)
	}

	// Payload
	for i, b := range payload {
		if frame[expectedHeaderSize+i] != b {
			t.Errorf("payload[%d] = 0x%02X, want 0x%02X", i, frame[expectedHeaderSize+i], b)
		}
	}
}

// TestBuildDataFrame_ExtendedAddrs_NoSecurity builds a data frame with
// extended (8-byte) addresses and no security.
func TestBuildDataFrame_ExtendedAddrs_NoSecurity(t *testing.T) {
	f := NewFramer()
	srcExt := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	dstExt := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	ctx := &FrameContext{
		SrcExtAddr:     srcExt,
		DstExtAddr:     dstExt,
		UseSrcShort:    false,
		UseDstShort:    false,
		PanId:          0x1234,
		SequenceNumber: 7,
	}

	payload := []byte{0xAA}
	frame, err := f.BuildDataFrame(ctx, payload)
	if err != nil {
		t.Fatalf("BuildDataFrame() error = %v", err)
	}

	// Expected: FCF(2) + SeqNum(1) + DstPanId(2) + DstExt(8) + SrcExt(8) = 21 bytes
	expectedHeaderSize := 21
	if len(frame) != expectedHeaderSize+len(payload) {
		t.Fatalf("frame length = %d, want %d", len(frame), expectedHeaderSize+len(payload))
	}

	// Verify extended destination address is reversed on wire.
	for i := 0; i < 8; i++ {
		if frame[5+i] != dstExt[7-i] {
			t.Errorf("DstExtAddr wire[%d] = 0x%02X, want 0x%02X", i, frame[5+i], dstExt[7-i])
		}
	}

	// Verify extended source address is reversed on wire.
	for i := 0; i < 8; i++ {
		if frame[13+i] != srcExt[7-i] {
			t.Errorf("SrcExtAddr wire[%d] = 0x%02X, want 0x%02X", i, frame[13+i], srcExt[7-i])
		}
	}
}

// TestBuildDataFrame_Security_KeyIdMode1 builds a data frame with security
// enabled and key ID mode 1 (1-byte key index), verifying the auxiliary
// security header.
func TestBuildDataFrame_Security_KeyIdMode1(t *testing.T) {
	f := NewFramer()
	ctx := &FrameContext{
		SrcShortAddr:    0x0001,
		DstShortAddr:    0x0002,
		UseSrcShort:     true,
		UseDstShort:     true,
		PanId:           0xBEEF,
		SequenceNumber:  99,
		SecurityEnabled: true,
		Security: SecurityMaterial{
			KeyIdMode:    1,
			KeyId:        0x42,
			FrameCounter: 0x12345678,
			Key:          [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		},
	}

	payload := []byte{0x01, 0x02}
	frame, err := f.BuildDataFrame(ctx, payload)
	if err != nil {
		t.Fatalf("BuildDataFrame() error = %v", err)
	}

	// Header: FCF(2) + SeqNum(1) + DstPanId(2) + DstShort(2) + SrcShort(2)
	//       + SecCtl(1) + FrameCounter(4) + KeyId(1) = 15
	// With encryption: ciphertext(2) + MIC(4) appended.
	expectedHeaderSize := 15
	micSize := 4
	if len(frame) != expectedHeaderSize+len(payload)+micSize {
		t.Fatalf("frame length = %d, want %d", len(frame), expectedHeaderSize+len(payload)+micSize)
	}

	// Verify security enabled bit in FCF.
	fc := binary.LittleEndian.Uint16(frame[0:2])
	if fc&0x0008 == 0 {
		t.Error("security enabled bit not set in FCF")
	}

	// Auxiliary security header starts at offset 9.
	secCtl := frame[9]
	wantSecLevel := uint8(SecurityEncMic32)
	gotSecLevel := secCtl & 0x07
	if gotSecLevel != wantSecLevel {
		t.Errorf("security level = %d, want %d", gotSecLevel, wantSecLevel)
	}

	gotKeyIDMode := (secCtl >> 3) & 0x03
	if gotKeyIDMode != 1 {
		t.Errorf("key ID mode = %d, want 1", gotKeyIDMode)
	}

	// Frame counter (4 bytes LE at offset 10).
	fctr := binary.LittleEndian.Uint32(frame[10:14])
	if fctr != 0x12345678 {
		t.Errorf("frame counter = 0x%08X, want 0x12345678", fctr)
	}

	// Key index at offset 14.
	if frame[14] != 0x42 {
		t.Errorf("key index = 0x%02X, want 0x42", frame[14])
	}
}

// TestBuildDataFrame_Security_KeyIdMode2 builds a data frame with key ID
// mode 2 (4-byte key source + 1-byte key index).
func TestBuildDataFrame_Security_KeyIdMode2(t *testing.T) {
	f := NewFramer()
	ctx := &FrameContext{
		SrcShortAddr:    0x0001,
		DstShortAddr:    0x0002,
		UseSrcShort:     true,
		UseDstShort:     true,
		PanId:           0xBEEF,
		SequenceNumber:  1,
		SecurityEnabled: true,
		Security: SecurityMaterial{
			KeyIdMode:    2,
			KeyId:        0x07,
			FrameCounter: 100,
			Key:          [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		},
	}

	payload := []byte{0xFF}
	frame, err := f.BuildDataFrame(ctx, payload)
	if err != nil {
		t.Fatalf("BuildDataFrame() error = %v", err)
	}

	// Header: FCF(2) + SeqNum(1) + DstPanId(2) + DstShort(2) + SrcShort(2)
	//       + SecCtl(1) + FrameCounter(4) + KeySource(4) + KeyId(1) = 19
	// With encryption: ciphertext(1) + MIC(4) appended.
	expectedHeaderSize := 19
	micSize := 4
	if len(frame) != expectedHeaderSize+len(payload)+micSize {
		t.Fatalf("frame length = %d, want %d", len(frame), expectedHeaderSize+len(payload)+micSize)
	}

	// Key ID mode 2: 4 zero bytes key source + key index.
	secOffset := 9 // after addressing fields
	secCtl := frame[secOffset]
	gotKeyIDMode := (secCtl >> 3) & 0x03
	if gotKeyIDMode != 2 {
		t.Errorf("key ID mode = %d, want 2", gotKeyIDMode)
	}

	// Key source (4 zero bytes) at offset 14.
	for i := 0; i < 4; i++ {
		if frame[14+i] != 0 {
			t.Errorf("key source[%d] = 0x%02X, want 0x00", i, frame[14+i])
		}
	}

	// Key index at offset 18.
	if frame[18] != 0x07 {
		t.Errorf("key index = 0x%02X, want 0x07", frame[18])
	}
}

// TestParseFrameHeader_RoundTrip builds a frame and parses it back,
// verifying all fields survive the round trip.
func TestParseFrameHeader_RoundTrip(t *testing.T) {
	f := NewFramer()

	tests := []struct {
		name string
		ctx  FrameContext
	}{
		{
			name: "short_addrs_no_security",
			ctx: FrameContext{
				SrcShortAddr:   0x1234,
				DstShortAddr:   0x5678,
				UseSrcShort:    true,
				UseDstShort:    true,
				PanId:          0xCAFE,
				SequenceNumber: 10,
			},
		},
		{
			name: "extended_addrs_no_security",
			ctx: FrameContext{
				SrcExtAddr:     [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
				DstExtAddr:     [8]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8},
				UseSrcShort:    false,
				UseDstShort:    false,
				PanId:          0x1234,
				SequenceNumber: 200,
			},
		},
		{
			name: "short_addrs_with_security",
			ctx: FrameContext{
				SrcShortAddr:    0x0001,
				DstShortAddr:    0x0002,
				UseSrcShort:     true,
				UseDstShort:     true,
				PanId:           0xBEEF,
				SequenceNumber:  55,
				SecurityEnabled: true,
				Security: SecurityMaterial{
					KeyIdMode:    1,
					KeyId:        0x03,
					FrameCounter: 999,
					Key:          [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
				},
			},
		},
		{
			name: "with_ack_and_pending",
			ctx: FrameContext{
				SrcShortAddr:   0x0010,
				DstShortAddr:   0x0020,
				UseSrcShort:    true,
				UseDstShort:    true,
				PanId:          0x5555,
				SequenceNumber: 128,
				AckRequest:     true,
				FramePending:   true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := []byte{0xDE, 0xAD}
			frame, err := f.BuildDataFrame(&tt.ctx, payload)
			if err != nil {
				t.Fatalf("BuildDataFrame() error = %v", err)
			}

			parsed, payloadOffset, err := f.ParseFrameHeader(frame)
			if err != nil {
				t.Fatalf("ParseFrameHeader() error = %v", err)
			}

			if parsed.SequenceNumber != tt.ctx.SequenceNumber {
				t.Errorf("SequenceNumber = %d, want %d", parsed.SequenceNumber, tt.ctx.SequenceNumber)
			}
			if parsed.PanId != tt.ctx.PanId {
				t.Errorf("PanId = 0x%04X, want 0x%04X", parsed.PanId, tt.ctx.PanId)
			}
			if parsed.UseDstShort != tt.ctx.UseDstShort {
				t.Errorf("UseDstShort = %v, want %v", parsed.UseDstShort, tt.ctx.UseDstShort)
			}
			if parsed.UseSrcShort != tt.ctx.UseSrcShort {
				t.Errorf("UseSrcShort = %v, want %v", parsed.UseSrcShort, tt.ctx.UseSrcShort)
			}
			if parsed.UseDstShort && parsed.DstShortAddr != tt.ctx.DstShortAddr {
				t.Errorf("DstShortAddr = 0x%04X, want 0x%04X", parsed.DstShortAddr, tt.ctx.DstShortAddr)
			}
			if !parsed.UseDstShort && parsed.DstExtAddr != tt.ctx.DstExtAddr {
				t.Errorf("DstExtAddr = %v, want %v", parsed.DstExtAddr, tt.ctx.DstExtAddr)
			}
			if parsed.UseSrcShort && parsed.SrcShortAddr != tt.ctx.SrcShortAddr {
				t.Errorf("SrcShortAddr = 0x%04X, want 0x%04X", parsed.SrcShortAddr, tt.ctx.SrcShortAddr)
			}
			if !parsed.UseSrcShort && parsed.SrcExtAddr != tt.ctx.SrcExtAddr {
				t.Errorf("SrcExtAddr = %v, want %v", parsed.SrcExtAddr, tt.ctx.SrcExtAddr)
			}
			if parsed.SecurityEnabled != tt.ctx.SecurityEnabled {
				t.Errorf("SecurityEnabled = %v, want %v", parsed.SecurityEnabled, tt.ctx.SecurityEnabled)
			}
			if parsed.SecurityEnabled {
				if parsed.Security.KeyIdMode != tt.ctx.Security.KeyIdMode {
					t.Errorf("KeyIdMode = %d, want %d", parsed.Security.KeyIdMode, tt.ctx.Security.KeyIdMode)
				}
				if parsed.Security.FrameCounter != tt.ctx.Security.FrameCounter {
					t.Errorf("FrameCounter = %d, want %d", parsed.Security.FrameCounter, tt.ctx.Security.FrameCounter)
				}
				if parsed.Security.KeyId != tt.ctx.Security.KeyId {
					t.Errorf("KeyId = 0x%02X, want 0x%02X", parsed.Security.KeyId, tt.ctx.Security.KeyId)
				}
			}
			if parsed.AckRequest != tt.ctx.AckRequest {
				t.Errorf("AckRequest = %v, want %v", parsed.AckRequest, tt.ctx.AckRequest)
			}
			if parsed.FramePending != tt.ctx.FramePending {
				t.Errorf("FramePending = %v, want %v", parsed.FramePending, tt.ctx.FramePending)
			}

			// Verify payload offset points to the payload/ciphertext bytes.
			// When security is enabled, the frame contains ciphertext + MIC
			// instead of plaintext, so raw byte comparison is skipped.
			expectedTrailerSize := len(payload)
			if tt.ctx.SecurityEnabled {
				expectedTrailerSize += 4 // MIC tag
			}
			if payloadOffset+expectedTrailerSize != len(frame) {
				t.Errorf("payloadOffset = %d, but frame length = %d with expected trailer %d", payloadOffset, len(frame), expectedTrailerSize)
			}
			if !tt.ctx.SecurityEnabled {
				for i, b := range payload {
					if frame[payloadOffset+i] != b {
						t.Errorf("payload[%d] = 0x%02X, want 0x%02X", i, frame[payloadOffset+i], b)
					}
				}
			}
		})
	}
}

// TestPanIdCompression verifies that PAN ID compression is applied when
// source and destination use the same PAN ID.
func TestPanIdCompression(t *testing.T) {
	f := NewFramer()
	ctx := &FrameContext{
		SrcShortAddr:   0x0001,
		DstShortAddr:   0x0002,
		UseSrcShort:    true,
		UseDstShort:    true,
		PanId:          0xAAAA,
		SequenceNumber: 1,
	}

	frame, err := f.BuildDataFrame(ctx, nil)
	if err != nil {
		t.Fatalf("BuildDataFrame() error = %v", err)
	}

	fc := binary.LittleEndian.Uint16(frame[0:2])
	if fc&0x0040 == 0 {
		t.Error("PAN ID compression bit not set in FCF")
	}

	// With PAN ID compression, the frame should be:
	// FCF(2) + SeqNum(1) + DstPanId(2) + DstShort(2) + SrcShort(2) = 9
	// Without compression it would be 11 (extra 2 bytes for src PAN ID).
	expectedSize := 9
	if len(frame) != expectedSize {
		t.Errorf("frame size = %d, want %d (PAN ID should be compressed)", len(frame), expectedSize)
	}
}

// TestGetMaxPayloadSize verifies maximum payload calculations for various
// addressing and security configurations.
func TestGetMaxPayloadSize(t *testing.T) {
	f := NewFramer()

	tests := []struct {
		name string
		ctx  FrameContext
		want int
	}{
		{
			name: "short_short_no_sec",
			ctx: FrameContext{
				UseSrcShort: true,
				UseDstShort: true,
			},
			// Header: FCF(2) + Seq(1) + DstPan(2) + DstShort(2) + SrcShort(2) = 9
			// Max payload = 127 - 2(FCS) - 9 = 116
			want: 116,
		},
		{
			name: "ext_ext_no_sec",
			ctx: FrameContext{
				UseSrcShort: false,
				UseDstShort: false,
			},
			// Header: FCF(2) + Seq(1) + DstPan(2) + DstExt(8) + SrcExt(8) = 21
			// Max payload = 127 - 2 - 21 = 104
			want: 104,
		},
		{
			name: "short_short_sec_mode1",
			ctx: FrameContext{
				UseSrcShort:     true,
				UseDstShort:     true,
				SecurityEnabled: true,
				Security: SecurityMaterial{
					KeyIdMode: 1,
				},
			},
			// Header: 9 + SecCtl(1) + FC(4) + KeyId(1) = 15
			// Max payload = 127 - 2 - 15 - 4(MIC) = 106
			want: 106,
		},
		{
			name: "short_short_sec_mode2",
			ctx: FrameContext{
				UseSrcShort:     true,
				UseDstShort:     true,
				SecurityEnabled: true,
				Security: SecurityMaterial{
					KeyIdMode: 2,
				},
			},
			// Header: 9 + SecCtl(1) + FC(4) + KeySrc(4) + KeyId(1) = 19
			// Max payload = 127 - 2 - 19 - 4(MIC) = 102
			want: 102,
		},
		{
			name: "ext_ext_sec_mode1",
			ctx: FrameContext{
				UseSrcShort:     false,
				UseDstShort:     false,
				SecurityEnabled: true,
				Security: SecurityMaterial{
					KeyIdMode: 1,
				},
			},
			// Header: 21 + 6 = 27
			// Max payload = 127 - 2 - 27 - 4(MIC) = 94
			want: 94,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := f.GetMaxPayloadSize(&tt.ctx)
			if got != tt.want {
				t.Errorf("GetMaxPayloadSize() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestGetHeaderSize verifies header size calculations match expected values.
func TestGetHeaderSize(t *testing.T) {
	f := NewFramer()

	tests := []struct {
		name string
		ctx  FrameContext
		want int
	}{
		{
			name: "short_short_no_sec",
			ctx:  FrameContext{UseSrcShort: true, UseDstShort: true},
			want: 9, // FCF(2) + Seq(1) + DstPan(2) + DstShort(2) + SrcShort(2)
		},
		{
			name: "ext_ext_no_sec",
			ctx:  FrameContext{UseSrcShort: false, UseDstShort: false},
			want: 21, // FCF(2) + Seq(1) + DstPan(2) + DstExt(8) + SrcExt(8)
		},
		{
			name: "short_ext_no_sec",
			ctx:  FrameContext{UseSrcShort: true, UseDstShort: false},
			want: 15, // FCF(2) + Seq(1) + DstPan(2) + DstExt(8) + SrcShort(2)
		},
		{
			name: "ext_short_no_sec",
			ctx:  FrameContext{UseSrcShort: false, UseDstShort: true},
			want: 15, // FCF(2) + Seq(1) + DstPan(2) + DstShort(2) + SrcExt(8)
		},
		{
			name: "short_short_sec_mode0",
			ctx: FrameContext{
				UseSrcShort: true, UseDstShort: true,
				SecurityEnabled: true,
				Security:        SecurityMaterial{KeyIdMode: 0},
			},
			want: 14, // 9 + SecCtl(1) + FC(4)
		},
		{
			name: "short_short_sec_mode1",
			ctx: FrameContext{
				UseSrcShort: true, UseDstShort: true,
				SecurityEnabled: true,
				Security:        SecurityMaterial{KeyIdMode: 1},
			},
			want: 15, // 9 + SecCtl(1) + FC(4) + KeyId(1)
		},
		{
			name: "short_short_sec_mode3",
			ctx: FrameContext{
				UseSrcShort: true, UseDstShort: true,
				SecurityEnabled: true,
				Security:        SecurityMaterial{KeyIdMode: 3},
			},
			want: 23, // 9 + SecCtl(1) + FC(4) + KeySrc(8) + KeyId(1)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := f.GetHeaderSize(&tt.ctx)
			if got != tt.want {
				t.Errorf("GetHeaderSize() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestFrameControl_BuildParseRoundTrip verifies that buildFrameControl and
// parseFrameControl are inverse operations.
func TestFrameControl_BuildParseRoundTrip(t *testing.T) {
	tests := []struct {
		name         string
		frameType    uint8
		secEnabled   bool
		framePending bool
		ackRequest   bool
		panIDComp    bool
		iePresent    bool
		dstAddrMode  uint8
		srcAddrMode  uint8
		frameVersion uint8
	}{
		{
			name:      "data_short_short_v2006",
			frameType: uint8(FrameTypeData), dstAddrMode: AddrModeShort,
			srcAddrMode: AddrModeShort, frameVersion: FrameVersion2006,
		},
		{
			name:      "data_ext_ext_v2006_security",
			frameType: uint8(FrameTypeData), secEnabled: true,
			dstAddrMode: AddrModeExtended, srcAddrMode: AddrModeExtended,
			frameVersion: FrameVersion2006,
		},
		{
			name:      "all_flags_set",
			frameType: uint8(FrameTypeData), secEnabled: true, framePending: true,
			ackRequest: true, panIDComp: true, iePresent: true,
			dstAddrMode: AddrModeExtended, srcAddrMode: AddrModeShort,
			frameVersion: FrameVersion2015,
		},
		{
			name:        "no_flags",
			frameType:   uint8(FrameTypeData),
			dstAddrMode: AddrModeNone, srcAddrMode: AddrModeNone,
			frameVersion: FrameVersion2003,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := buildFrameControl(tt.frameType, tt.secEnabled, tt.framePending, tt.ackRequest, tt.panIDComp, tt.iePresent, tt.dstAddrMode, tt.srcAddrMode, tt.frameVersion)

			got := parseFrameControl(fc)

			if got.frameType != tt.frameType {
				t.Errorf("frameType = %d, want %d", got.frameType, tt.frameType)
			}
			if got.dstAddrMode != tt.dstAddrMode {
				t.Errorf("dstAddrMode = %d, want %d", got.dstAddrMode, tt.dstAddrMode)
			}
			if got.srcAddrMode != tt.srcAddrMode {
				t.Errorf("srcAddrMode = %d, want %d", got.srcAddrMode, tt.srcAddrMode)
			}
			if got.frameVersion != tt.frameVersion {
				t.Errorf("frameVersion = %d, want %d", got.frameVersion, tt.frameVersion)
			}
			if got.securityEnabled != tt.secEnabled {
				t.Errorf("secEnabled = %v, want %v", got.securityEnabled, tt.secEnabled)
			}
			if got.framePending != tt.framePending {
				t.Errorf("framePending = %v, want %v", got.framePending, tt.framePending)
			}
			if got.ackRequest != tt.ackRequest {
				t.Errorf("ackRequest = %v, want %v", got.ackRequest, tt.ackRequest)
			}
			if got.panIDCompression != tt.panIDComp {
				t.Errorf("panIDComp = %v, want %v", got.panIDCompression, tt.panIDComp)
			}
			if got.iePresent != tt.iePresent {
				t.Errorf("iePresent = %v, want %v", got.iePresent, tt.iePresent)
			}
		})
	}
}

// TestBuildDataFrame_AckAndPending verifies the AckRequest and FramePending
// flags appear correctly in the built frame.
func TestBuildDataFrame_AckAndPending(t *testing.T) {
	f := NewFramer()

	t.Run("ack_request_set", func(t *testing.T) {
		ctx := &FrameContext{
			UseSrcShort:    true,
			UseDstShort:    true,
			AckRequest:     true,
			SequenceNumber: 1,
		}
		frame, err := f.BuildDataFrame(ctx, nil)
		if err != nil {
			t.Fatalf("BuildDataFrame() error = %v", err)
		}
		fc := binary.LittleEndian.Uint16(frame[0:2])
		if fc&0x0020 == 0 {
			t.Error("AckRequest bit not set in FCF")
		}
	})

	t.Run("frame_pending_set", func(t *testing.T) {
		ctx := &FrameContext{
			UseSrcShort:    true,
			UseDstShort:    true,
			FramePending:   true,
			SequenceNumber: 2,
		}
		frame, err := f.BuildDataFrame(ctx, nil)
		if err != nil {
			t.Fatalf("BuildDataFrame() error = %v", err)
		}
		fc := binary.LittleEndian.Uint16(frame[0:2])
		if fc&0x0010 == 0 {
			t.Error("FramePending bit not set in FCF")
		}
	})

	t.Run("both_set", func(t *testing.T) {
		ctx := &FrameContext{
			UseSrcShort:    true,
			UseDstShort:    true,
			AckRequest:     true,
			FramePending:   true,
			SequenceNumber: 3,
		}
		frame, err := f.BuildDataFrame(ctx, nil)
		if err != nil {
			t.Fatalf("BuildDataFrame() error = %v", err)
		}
		fc := binary.LittleEndian.Uint16(frame[0:2])
		if fc&0x0020 == 0 {
			t.Error("AckRequest bit not set when both flags set")
		}
		if fc&0x0010 == 0 {
			t.Error("FramePending bit not set when both flags set")
		}
	})

	t.Run("neither_set", func(t *testing.T) {
		ctx := &FrameContext{
			UseSrcShort:    true,
			UseDstShort:    true,
			SequenceNumber: 4,
		}
		frame, err := f.BuildDataFrame(ctx, nil)
		if err != nil {
			t.Fatalf("BuildDataFrame() error = %v", err)
		}
		fc := binary.LittleEndian.Uint16(frame[0:2])
		if fc&0x0020 != 0 {
			t.Error("AckRequest bit set but should not be")
		}
		if fc&0x0010 != 0 {
			t.Error("FramePending bit set but should not be")
		}
	})
}

// TestBuildDataFrame_MixedAddressing verifies frames with mixed addressing
// modes (short src, extended dst and vice versa).
func TestBuildDataFrame_MixedAddressing(t *testing.T) {
	f := NewFramer()

	t.Run("short_src_ext_dst", func(t *testing.T) {
		dstExt := [8]byte{0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8}
		ctx := &FrameContext{
			SrcShortAddr:   0x1234,
			DstExtAddr:     dstExt,
			UseSrcShort:    true,
			UseDstShort:    false,
			PanId:          0x5678,
			SequenceNumber: 50,
		}

		frame, err := f.BuildDataFrame(ctx, []byte{0xBB})
		if err != nil {
			t.Fatalf("BuildDataFrame() error = %v", err)
		}

		// The 15-byte header comprises FCF(2), Seq(1), DstPan(2), DstExt(8), and SrcShort(2).
		expectedHeaderSize := 15
		if len(frame) != expectedHeaderSize+1 {
			t.Fatalf("frame length = %d, want %d", len(frame), expectedHeaderSize+1)
		}

		// Parse and verify round-trip.
		parsed, _, err := f.ParseFrameHeader(frame)
		if err != nil {
			t.Fatalf("ParseFrameHeader() error = %v", err)
		}
		if parsed.UseSrcShort != true {
			t.Error("UseSrcShort should be true")
		}
		if parsed.UseDstShort != false {
			t.Error("UseDstShort should be false")
		}
		if parsed.SrcShortAddr != 0x1234 {
			t.Errorf("SrcShortAddr = 0x%04X, want 0x1234", parsed.SrcShortAddr)
		}
		if parsed.DstExtAddr != dstExt {
			t.Errorf("DstExtAddr = %v, want %v", parsed.DstExtAddr, dstExt)
		}
	})

	t.Run("ext_src_short_dst", func(t *testing.T) {
		srcExt := [8]byte{0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8}
		ctx := &FrameContext{
			SrcExtAddr:     srcExt,
			DstShortAddr:   0xABCD,
			UseSrcShort:    false,
			UseDstShort:    true,
			PanId:          0x9876,
			SequenceNumber: 60,
		}

		frame, err := f.BuildDataFrame(ctx, []byte{0xCC})
		if err != nil {
			t.Fatalf("BuildDataFrame() error = %v", err)
		}

		// The 15-byte header comprises FCF(2), Seq(1), DstPan(2), DstShort(2), and SrcExt(8).
		expectedHeaderSize := 15
		if len(frame) != expectedHeaderSize+1 {
			t.Fatalf("frame length = %d, want %d", len(frame), expectedHeaderSize+1)
		}

		parsed, _, err := f.ParseFrameHeader(frame)
		if err != nil {
			t.Fatalf("ParseFrameHeader() error = %v", err)
		}
		if parsed.UseSrcShort != false {
			t.Error("UseSrcShort should be false")
		}
		if parsed.UseDstShort != true {
			t.Error("UseDstShort should be true")
		}
		if parsed.SrcExtAddr != srcExt {
			t.Errorf("SrcExtAddr = %v, want %v", parsed.SrcExtAddr, srcExt)
		}
		if parsed.DstShortAddr != 0xABCD {
			t.Errorf("DstShortAddr = 0x%04X, want 0xABCD", parsed.DstShortAddr)
		}
	})
}

// TestBuildDataFrame_ErrorCases tests error conditions.
func TestBuildDataFrame_ErrorCases(t *testing.T) {
	f := NewFramer()

	t.Run("payload_too_large", func(t *testing.T) {
		ctx := &FrameContext{
			UseSrcShort: true,
			UseDstShort: true,
		}
		maxPayload := f.GetMaxPayloadSize(ctx)

		// Exactly at max should succeed.
		payload := make([]byte, maxPayload)
		_, err := f.BuildDataFrame(ctx, payload)
		if err != nil {
			t.Errorf("BuildDataFrame() with max payload returned error: %v", err)
		}

		// One byte over max should fail.
		overPayload := make([]byte, maxPayload+1)
		_, err = f.BuildDataFrame(ctx, overPayload)
		if err != errors.ErrNoBufs {
			t.Errorf("BuildDataFrame() with oversized payload error = %v, want ErrNoBufs", err)
		}
	})

	t.Run("parse_too_short", func(t *testing.T) {
		// Frame shorter than minimum (3 bytes: FCF + SeqNum).
		_, _, err := f.ParseFrameHeader([]byte{0x01})
		if err != errors.ErrParse {
			t.Errorf("ParseFrameHeader() with 1-byte frame error = %v, want ErrParse", err)
		}

		_, _, err = f.ParseFrameHeader([]byte{0x01, 0x02})
		if err != errors.ErrParse {
			t.Errorf("ParseFrameHeader() with 2-byte frame error = %v, want ErrParse", err)
		}

		_, _, err = f.ParseFrameHeader(nil)
		if err != errors.ErrParse {
			t.Errorf("ParseFrameHeader() with nil frame error = %v, want ErrParse", err)
		}
	})

	t.Run("parse_truncated_dst_addr", func(t *testing.T) {
		// Build a valid FCF indicating short dst addr, but truncate the frame
		// so the dst address bytes are missing.
		fc := buildFrameControl(uint8(FrameTypeData), false, false, false, true, false, AddrModeShort, AddrModeShort, FrameVersion2006)
		var buf [5]byte // FCF(2) + Seq(1) + DstPan(2), but no dst addr
		binary.LittleEndian.PutUint16(buf[0:2], fc)
		buf[2] = 0 // seq
		binary.LittleEndian.PutUint16(buf[3:5], 0x1234)

		_, _, err := f.ParseFrameHeader(buf[:])
		if err != errors.ErrParse {
			t.Errorf("ParseFrameHeader() with truncated dst addr error = %v, want ErrParse", err)
		}
	})

	t.Run("parse_truncated_security_header", func(t *testing.T) {
		// Build a frame with security enabled but truncate before the
		// security header is complete.
		ctx := &FrameContext{
			UseSrcShort:     true,
			UseDstShort:     true,
			SecurityEnabled: true,
			Security:        SecurityMaterial{KeyIdMode: 1, FrameCounter: 1},
		}
		frame, err := f.BuildDataFrame(ctx, nil)
		if err != nil {
			t.Fatalf("BuildDataFrame() error = %v", err)
		}

		// Truncate to just the addressing fields, cutting into the security header.
		truncated := frame[:10] // FCF(2) + Seq(1) + DstPan(2) + DstShort(2) + SrcShort(2) + SecCtl(1) but no frame counter
		_, _, err = f.ParseFrameHeader(truncated)
		if err != errors.ErrParse {
			t.Errorf("ParseFrameHeader() with truncated security header error = %v, want ErrParse", err)
		}
	})
}

// TestBuildMleFrame verifies that BuildMleFrame produces the same output as
// BuildDataFrame (since MLE security is applied before framing).
func TestBuildMleFrame(t *testing.T) {
	f := NewFramer()
	ctx := &FrameContext{
		SrcShortAddr:   0x0001,
		DstShortAddr:   0x0002,
		UseSrcShort:    true,
		UseDstShort:    true,
		PanId:          0x1234,
		SequenceNumber: 77,
	}

	payload := []byte{0x01, 0x02, 0x03}

	dataFrame, err := f.BuildDataFrame(ctx, payload)
	if err != nil {
		t.Fatalf("BuildDataFrame() error = %v", err)
	}

	mleFrame, err := f.BuildMleFrame(ctx, payload)
	if err != nil {
		t.Fatalf("BuildMleFrame() error = %v", err)
	}

	if len(dataFrame) != len(mleFrame) {
		t.Fatalf("frame lengths differ: data=%d, mle=%d", len(dataFrame), len(mleFrame))
	}

	for i := range dataFrame {
		if dataFrame[i] != mleFrame[i] {
			t.Errorf("frame[%d] differs: data=0x%02X, mle=0x%02X", i, dataFrame[i], mleFrame[i])
		}
	}
}
