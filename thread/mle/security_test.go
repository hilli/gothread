// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"testing"

	"github.com/hilli/gothread/crypto/aesccm"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/key"
)

func TestSecuritySuiteConstants(t *testing.T) {
	if SecuritySuiteEncMic32 != 0 {
		t.Errorf("SecuritySuiteEncMic32 = %d, want 0", SecuritySuiteEncMic32)
	}
	if SecuritySuiteNone != 255 {
		t.Errorf("SecuritySuiteNone = %d, want 255", SecuritySuiteNone)
	}
}

func TestSecurityHeaderSize(t *testing.T) {
	if SecurityHeaderSize != 10 {
		t.Errorf("SecurityHeaderSize = %d, want 10", SecurityHeaderSize)
	}
	if SecurityTagSize != 4 {
		t.Errorf("SecurityTagSize = %d, want 4", SecurityTagSize)
	}
}

func TestKeyIndexFromSequence(t *testing.T) {
	tests := []struct {
		seq  uint32
		want uint8
	}{
		{0, 1},
		{1, 2},
		{126, 127},
		{127, 128},
		{128, 1},   // wraps: (128 & 0x7F) + 1 = 1
		{129, 2},   // (129 & 0x7F) + 1 = 2
		{255, 128}, // (255 & 0x7F) + 1 = 128
		{256, 1},   // (256 & 0x7F) + 1 = 1
	}
	for _, tt := range tests {
		got := KeyIndexFromSequence(tt.seq)
		if got != tt.want {
			t.Errorf("KeyIndexFromSequence(%d) = %d, want %d", tt.seq, got, tt.want)
		}
	}
}

func TestNewSecurityHeader(t *testing.T) {
	h := NewSecurityHeader(42, 1000)
	if h.FrameCounter != 1000 {
		t.Errorf("FrameCounter = %d, want 1000", h.FrameCounter)
	}
	if h.KeySource != 42 {
		t.Errorf("KeySource = %d, want 42", h.KeySource)
	}
	want := KeyIndexFromSequence(42)
	if h.KeyIndex != want {
		t.Errorf("KeyIndex = %d, want %d", h.KeyIndex, want)
	}
}

func TestSecurityHeaderMarshalUnmarshal(t *testing.T) {
	original := NewSecurityHeader(42, 12345)
	buf := original.Marshal()

	// Verify size.
	if len(buf) != SecurityHeaderSize {
		t.Fatalf("Marshal length = %d, want %d", len(buf), SecurityHeaderSize)
	}

	// SecurityControl byte.
	if buf[0] != 0x15 {
		t.Errorf("SecurityControl = 0x%02X, want 0x15", buf[0])
	}

	// Frame counter is little-endian.
	fc := uint32(buf[1]) | uint32(buf[2])<<8 | uint32(buf[3])<<16 | uint32(buf[4])<<24
	if fc != 12345 {
		t.Errorf("FrameCounter wire = %d, want 12345", fc)
	}

	// Key source is big-endian.
	ks := uint32(buf[5])<<24 | uint32(buf[6])<<16 | uint32(buf[7])<<8 | uint32(buf[8])
	if ks != 42 {
		t.Errorf("KeySource wire = %d, want 42", ks)
	}

	// Key index.
	if buf[9] != KeyIndexFromSequence(42) {
		t.Errorf("KeyIndex wire = %d, want %d", buf[9], KeyIndexFromSequence(42))
	}

	// Round-trip.
	var parsed SecurityHeader
	if err := parsed.Unmarshal(buf[:]); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if parsed.FrameCounter != original.FrameCounter {
		t.Errorf("FrameCounter = %d, want %d", parsed.FrameCounter, original.FrameCounter)
	}
	if parsed.KeySource != original.KeySource {
		t.Errorf("KeySource = %d, want %d", parsed.KeySource, original.KeySource)
	}
	if parsed.KeyIndex != original.KeyIndex {
		t.Errorf("KeyIndex = %d, want %d", parsed.KeyIndex, original.KeyIndex)
	}
}

func TestSecurityHeaderUnmarshalErrors(t *testing.T) {
	// Too short.
	var h SecurityHeader
	if err := h.Unmarshal(make([]byte, 5)); err == nil {
		t.Error("expected error for short buffer")
	}

	// Wrong security control.
	bad := make([]byte, SecurityHeaderSize)
	bad[0] = 0xFF
	if err := h.Unmarshal(bad); err == nil {
		t.Error("expected error for wrong security control")
	}
}

func TestBuildNonce(t *testing.T) {
	var addr types.ExtAddress
	for i := range addr {
		addr[i] = byte(i + 1) // 01 02 03 04 05 06 07 08
	}
	fc := uint32(0xAABBCCDD)

	nonce := BuildNonce(addr, fc)

	if len(nonce) != aesccm.NonceSize {
		t.Fatalf("nonce length = %d, want %d", len(nonce), aesccm.NonceSize)
	}

	// First 8 bytes = ExtAddress.
	for i := 0; i < 8; i++ {
		if nonce[i] != addr[i] {
			t.Errorf("nonce[%d] = 0x%02X, want 0x%02X", i, nonce[i], addr[i])
		}
	}

	// Bytes 8-11 = frame counter big-endian.
	if nonce[8] != 0xAA || nonce[9] != 0xBB || nonce[10] != 0xCC || nonce[11] != 0xDD {
		t.Errorf("nonce frame counter = %X %X %X %X, want AA BB CC DD",
			nonce[8], nonce[9], nonce[10], nonce[11])
	}

	// Byte 12 = security level.
	if nonce[12] != 5 {
		t.Errorf("nonce security level = %d, want 5", nonce[12])
	}
}

func TestBuildAAD(t *testing.T) {
	var srcIP, dstIP ip6.Address
	for i := range srcIP {
		srcIP[i] = byte(i)
	}
	for i := range dstIP {
		dstIP[i] = byte(i + 0x10)
	}

	secHdr := NewSecurityHeader(1, 2)
	hdrBytes := secHdr.Marshal()

	aad := BuildAAD(srcIP, dstIP, hdrBytes)

	if len(aad) != 42 {
		t.Fatalf("AAD length = %d, want 42", len(aad))
	}

	// Check source IP.
	for i := 0; i < 16; i++ {
		if aad[i] != srcIP[i] {
			t.Errorf("AAD srcIP[%d] = 0x%02X, want 0x%02X", i, aad[i], srcIP[i])
		}
	}

	// Check dest IP.
	for i := 0; i < 16; i++ {
		if aad[16+i] != dstIP[i] {
			t.Errorf("AAD dstIP[%d] = 0x%02X, want 0x%02X", i, aad[16+i], dstIP[i])
		}
	}

	// Check security header.
	for i := 0; i < SecurityHeaderSize; i++ {
		if aad[32+i] != hdrBytes[i] {
			t.Errorf("AAD secHdr[%d] = 0x%02X, want 0x%02X", i, aad[32+i], hdrBytes[i])
		}
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	var mleKey key.MleKey
	for i := range mleKey {
		mleKey[i] = byte(i + 0xA0)
	}

	var addr types.ExtAddress
	for i := range addr {
		addr[i] = byte(i + 1)
	}

	var srcIP, dstIP ip6.Address
	for i := range srcIP {
		srcIP[i] = byte(i)
	}
	for i := range dstIP {
		dstIP[i] = byte(i + 0x20)
	}

	frameCounter := uint32(42)
	nonce := BuildNonce(addr, frameCounter)

	secHdr := NewSecurityHeader(1, frameCounter)
	hdrBytes := secHdr.Marshal()
	aad := BuildAAD(srcIP, dstIP, hdrBytes)

	plaintext := []byte{byte(CommandParentRequest), 0x03, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Encrypt.
	ciphertext, tag, err := Encrypt(mleKey, nonce, aad[:], plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if len(ciphertext) != len(plaintext) {
		t.Errorf("ciphertext length = %d, want %d", len(ciphertext), len(plaintext))
	}

	// Ciphertext should differ from plaintext.
	same := true
	for i := range ciphertext {
		if ciphertext[i] != plaintext[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("ciphertext should differ from plaintext")
	}

	// Decrypt.
	recovered, err := Decrypt(mleKey, nonce, aad[:], ciphertext, tag)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if len(recovered) != len(plaintext) {
		t.Fatalf("recovered length = %d, want %d", len(recovered), len(plaintext))
	}
	for i := range recovered {
		if recovered[i] != plaintext[i] {
			t.Errorf("recovered[%d] = 0x%02X, want 0x%02X", i, recovered[i], plaintext[i])
		}
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	var goodKey, badKey key.MleKey
	for i := range goodKey {
		goodKey[i] = byte(i + 0xA0)
		badKey[i] = byte(i + 0xB0)
	}

	var addr types.ExtAddress
	nonce := BuildNonce(addr, 0)
	var secHdr [SecurityHeaderSize]byte
	secHdr[0] = 0x15
	var srcIP, dstIP ip6.Address
	aad := BuildAAD(srcIP, dstIP, secHdr)

	plaintext := []byte{0x09, 0x01, 0x02}

	ciphertext, tag, err := Encrypt(goodKey, nonce, aad[:], plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = Decrypt(badKey, nonce, aad[:], ciphertext, tag)
	if err == nil {
		t.Error("expected authentication failure with wrong key")
	}
}

func TestDecryptWithTamperedCiphertext(t *testing.T) {
	var mleKey key.MleKey
	for i := range mleKey {
		mleKey[i] = byte(i + 0xA0)
	}

	var addr types.ExtAddress
	nonce := BuildNonce(addr, 0)
	var secHdr [SecurityHeaderSize]byte
	secHdr[0] = 0x15
	var srcIP, dstIP ip6.Address
	aad := BuildAAD(srcIP, dstIP, secHdr)

	plaintext := []byte{0x09, 0x01, 0x02}
	ciphertext, tag, err := Encrypt(mleKey, nonce, aad[:], plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Tamper with ciphertext.
	ciphertext[0] ^= 0xFF

	_, err = Decrypt(mleKey, nonce, aad[:], ciphertext, tag)
	if err == nil {
		t.Error("expected authentication failure with tampered ciphertext")
	}
}
