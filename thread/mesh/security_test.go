// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/hilli/gothread/crypto/aesccm"
)

// TestBuildNonce verifies the 13-byte nonce layout:
// ExtAddr (8) || FrameCounter LE (4) || SecurityLevel (1).
func TestBuildNonce(t *testing.T) {
	extAddr := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	frameCounter := uint32(0xDEADBEEF)
	secLevel := uint8(SecurityEncMic32) // 5

	nonce := BuildNonce(extAddr, frameCounter, secLevel)

	// Bytes 0-7: extended address as-is.
	if nonce[0] != 0x01 || nonce[7] != 0x08 {
		t.Errorf("nonce ext addr = %x, want 0102030405060708", nonce[0:8])
	}
	for i := 0; i < 8; i++ {
		if nonce[i] != extAddr[i] {
			t.Errorf("nonce[%d] = 0x%02X, want 0x%02X", i, nonce[i], extAddr[i])
		}
	}

	// Bytes 8-11: frame counter little-endian.
	gotFC := binary.LittleEndian.Uint32(nonce[8:12])
	if gotFC != frameCounter {
		t.Errorf("nonce frame counter = 0x%08X, want 0x%08X", gotFC, frameCounter)
	}

	// Byte 12: security level.
	if nonce[12] != secLevel {
		t.Errorf("nonce security level = %d, want %d", nonce[12], secLevel)
	}
}

// TestBuildNonce_ZeroValues verifies nonce with all-zero inputs.
func TestBuildNonce_ZeroValues(t *testing.T) {
	nonce := BuildNonce([8]byte{}, 0, 0)
	var expected [13]byte
	if nonce != expected {
		t.Errorf("zero nonce = %x, want all zeros", nonce)
	}
}

// TestEncryptFrame builds a frame with security enabled and verifies
// the payload is encrypted (differs from plaintext) and a 4-byte MIC
// tag is appended. It then decrypts and verifies round-trip integrity.
func TestEncryptFrame(t *testing.T) {
	key := [16]byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
	}
	srcExt := [8]byte{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7}
	payload := []byte("hello, thread!")

	ctx := &FrameContext{
		SrcShortAddr:    0x0001,
		SrcExtAddr:      srcExt,
		DstShortAddr:    0x0002,
		UseSrcShort:     true,
		UseDstShort:     true,
		PanId:           0xBEEF,
		SequenceNumber:  42,
		SecurityEnabled: true,
		Security: SecurityMaterial{
			KeyIdMode:    1,
			KeyId:        0x01,
			Key:          key,
			FrameCounter: 1000,
		},
	}

	f := NewFramer()
	frame, err := f.BuildDataFrame(ctx, payload)
	if err != nil {
		t.Fatalf("BuildDataFrame() error = %v", err)
	}

	// Header size: FCF(2) + Seq(1) + DstPan(2) + DstShort(2) + SrcShort(2)
	//            + SecCtl(1) + FC(4) + KeyId(1) = 15
	headerSize := f.GetHeaderSize(ctx)
	if headerSize != 15 {
		t.Fatalf("header size = %d, want 15", headerSize)
	}

	// Frame should be: header(15) + ciphertext(len(payload)) + MIC(4)
	tagSize := 4
	expectedLen := headerSize + len(payload) + tagSize
	if len(frame) != expectedLen {
		t.Fatalf("frame length = %d, want %d", len(frame), expectedLen)
	}

	// The encrypted payload should NOT match the plaintext.
	encPayload := frame[headerSize : headerSize+len(payload)]
	if bytes.Equal(encPayload, payload) {
		t.Error("encrypted payload matches plaintext; encryption did not occur")
	}

	// Extract MIC tag.
	mic := frame[headerSize+len(payload):]
	if len(mic) != tagSize {
		t.Fatalf("MIC length = %d, want %d", len(mic), tagSize)
	}

	// Verify decryption round-trip using aesccm.Open.
	nonce := BuildNonce(srcExt, ctx.Security.FrameCounter, uint8(SecurityEncMic32))
	additionalData := frame[:headerSize]

	var ccm aesccm.AesCcm
	if err := ccm.SetKey(key[:]); err != nil {
		t.Fatalf("SetKey() error = %v", err)
	}

	decrypted, err := ccm.Open(nonce[:], encPayload, additionalData, mic)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if !bytes.Equal(decrypted, payload) {
		t.Errorf("decrypted = %q, want %q", decrypted, payload)
	}
}

// TestEncryptFrame_EmptyPayload verifies encryption with an empty payload
// still produces a valid frame with only a MIC tag.
func TestEncryptFrame_EmptyPayload(t *testing.T) {
	key := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}

	ctx := &FrameContext{
		SrcShortAddr:    0x0001,
		DstShortAddr:    0x0002,
		UseSrcShort:     true,
		UseDstShort:     true,
		PanId:           0x1234,
		SequenceNumber:  1,
		SecurityEnabled: true,
		Security: SecurityMaterial{
			KeyIdMode:    1,
			KeyId:        0x01,
			Key:          key,
			FrameCounter: 0,
		},
	}

	f := NewFramer()
	frame, err := f.BuildDataFrame(ctx, nil)
	if err != nil {
		t.Fatalf("BuildDataFrame() error = %v", err)
	}

	headerSize := f.GetHeaderSize(ctx)
	tagSize := 4
	// Frame = header + MIC only (no ciphertext for empty payload).
	if len(frame) != headerSize+tagSize {
		t.Fatalf("frame length = %d, want %d", len(frame), headerSize+tagSize)
	}

	// Verify decryption of empty payload.
	nonce := BuildNonce(ctx.SrcExtAddr, ctx.Security.FrameCounter, uint8(SecurityEncMic32))
	mic := frame[headerSize:]

	var ccm aesccm.AesCcm
	if err := ccm.SetKey(key[:]); err != nil {
		t.Fatalf("SetKey() error = %v", err)
	}
	decrypted, err := ccm.Open(nonce[:], nil, frame[:headerSize], mic)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if len(decrypted) != 0 {
		t.Errorf("decrypted length = %d, want 0", len(decrypted))
	}
}

// TestDecryptFramePayload_RoundTrip encrypts a frame with BuildDataFrame
// then decrypts using DecryptFramePayload, verifying full round-trip.
func TestDecryptFramePayload_RoundTrip(t *testing.T) {
	key := [16]byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
	}
	srcExt := [8]byte{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7}
	payload := []byte("decrypt round-trip test")

	ctx := &FrameContext{
		SrcShortAddr:    0x0001,
		SrcExtAddr:      srcExt,
		DstShortAddr:    0x0002,
		UseSrcShort:     true,
		UseDstShort:     true,
		PanId:           0xBEEF,
		SequenceNumber:  42,
		SecurityEnabled: true,
		Security: SecurityMaterial{
			KeyIdMode:    1,
			KeyId:        0x01,
			Key:          key,
			FrameCounter: 1000,
		},
	}

	f := NewFramer()
	frame, err := f.BuildDataFrame(ctx, payload)
	if err != nil {
		t.Fatalf("BuildDataFrame() error = %v", err)
	}

	// Parse the frame header to get the payload offset.
	parsed, offset, err := f.ParseFrameHeader(frame)
	if err != nil {
		t.Fatalf("ParseFrameHeader() error = %v", err)
	}

	// Decrypt using DecryptFramePayload.
	decrypted, err := DecryptFramePayload(frame, offset, parsed, key, srcExt)
	if err != nil {
		t.Fatalf("DecryptFramePayload() error = %v", err)
	}

	if !bytes.Equal(decrypted, payload) {
		t.Errorf("decrypted = %q, want %q", decrypted, payload)
	}
}

// TestDecryptFramePayload_WrongKey verifies that decryption with a wrong
// key returns an authentication error.
func TestDecryptFramePayload_WrongKey(t *testing.T) {
	key := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	wrongKey := [16]byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
		0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0}

	ctx := &FrameContext{
		SrcShortAddr:    0x0001,
		SrcExtAddr:      [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		DstShortAddr:    0x0002,
		UseSrcShort:     true,
		UseDstShort:     true,
		PanId:           0x1234,
		SequenceNumber:  1,
		SecurityEnabled: true,
		Security: SecurityMaterial{
			KeyIdMode:    1,
			KeyId:        0x01,
			Key:          key,
			FrameCounter: 42,
		},
	}

	f := NewFramer()
	frame, err := f.BuildDataFrame(ctx, []byte("secret data"))
	if err != nil {
		t.Fatalf("BuildDataFrame() error = %v", err)
	}

	parsed, offset, err := f.ParseFrameHeader(frame)
	if err != nil {
		t.Fatalf("ParseFrameHeader() error = %v", err)
	}

	_, err = DecryptFramePayload(frame, offset, parsed, wrongKey, ctx.SrcExtAddr)
	if err == nil {
		t.Fatal("expected authentication error with wrong key, got nil")
	}
}
