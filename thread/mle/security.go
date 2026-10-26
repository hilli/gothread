// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"fmt"

	"github.com/hilli/gothread/crypto/aesccm"
	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/key"
)

// Security suite constants.
const (
	// SecuritySuiteEncMic32 indicates the message is secured with AES-CCM
	// using a 4-byte MIC (EncMic32).
	SecuritySuiteEncMic32 uint8 = 0

	// SecuritySuiteNone indicates the message is unsecured
	// (used only for Discovery Request/Response).
	SecuritySuiteNone uint8 = 255
)

// SecurityHeaderSize is the size of the MLE auxiliary security header in bytes.
// Layout: SecurityControl(1) + FrameCounter(4) + KeySource(4) + KeyIndex(1) = 10.
const SecurityHeaderSize = 10

// SecurityTagSize is the size of the AES-CCM authentication tag (MIC) in bytes.
const SecurityTagSize = 4

// securityControl is the fixed value of the security control byte for MLE.
// It encodes KeyIdMode 2 (0x10) + SecurityLevel 5 (0x05) = 0x15.
const securityControl uint8 = 0x15

// securityLevel is the security level used in AES-CCM nonce construction.
const securityLevel uint8 = 5

// aadSize is the size of the additional authenticated data (AAD) for AES-CCM.
// AAD = source IPv6 (16) + destination IPv6 (16) + security header (10) = 42.
const aadSize = 16 + 16 + SecurityHeaderSize

// SecurityHeader represents the MLE auxiliary security header.
type SecurityHeader struct {
	// FrameCounter is the 32-bit frame counter (little-endian on wire).
	FrameCounter uint32

	// KeySource is the key sequence number (big-endian on wire).
	KeySource uint32

	// KeyIndex is derived from the key sequence: (keySequence & 0x7F) + 1.
	KeyIndex uint8
}

// KeyIndexFromSequence derives the key index from a key sequence number.
func KeyIndexFromSequence(keySequence uint32) uint8 {
	return uint8(keySequence&0x7F) + 1
}

// KeySequenceFromKeySource returns the key sequence from the key source field.
// The key source is stored as the key sequence in big-endian format.
func KeySequenceFromKeySource(keySource uint32) uint32 {
	return keySource
}

// NewSecurityHeader creates a SecurityHeader for the given key sequence
// and frame counter.
func NewSecurityHeader(keySequence, frameCounter uint32) SecurityHeader {
	return SecurityHeader{
		FrameCounter: frameCounter,
		KeySource:    keySequence,
		KeyIndex:     KeyIndexFromSequence(keySequence),
	}
}

// Marshal encodes the security header to its 10-byte wire format.
//
// Wire layout:
//
//	[0]     SecurityControl (always 0x15)
//	[1:5]   FrameCounter (little-endian)
//	[5:9]   KeySource (big-endian)
//	[9]     KeyIndex
func (h *SecurityHeader) Marshal() [SecurityHeaderSize]byte {
	var buf [SecurityHeaderSize]byte
	buf[0] = securityControl
	encoding.LittleEndianWriteUint32(h.FrameCounter, buf[1:5])
	encoding.BigEndianWriteUint32(h.KeySource, buf[5:9])
	buf[9] = h.KeyIndex
	return buf
}

// Unmarshal decodes a security header from a 10-byte buffer.
func (h *SecurityHeader) Unmarshal(buf []byte) error {
	if len(buf) < SecurityHeaderSize {
		return fmt.Errorf("mle: security header requires %d bytes, got %d",
			SecurityHeaderSize, len(buf))
	}

	if buf[0] != securityControl {
		return fmt.Errorf("mle: unexpected security control 0x%02X, expected 0x%02X",
			buf[0], securityControl)
	}

	h.FrameCounter = encoding.LittleEndianReadUint32(buf[1:5])
	h.KeySource = encoding.BigEndianReadUint32(buf[5:9])
	h.KeyIndex = buf[9]
	return nil
}

// BuildNonce constructs the 13-byte AES-CCM nonce for MLE encryption.
//
// Layout: ExtAddress(8) + FrameCounter-BE(4) + SecurityLevel(1).
func BuildNonce(addr types.ExtAddress, frameCounter uint32) [aesccm.NonceSize]byte {
	var nonce [aesccm.NonceSize]byte
	copy(nonce[0:8], addr[:])
	encoding.BigEndianWriteUint32(frameCounter, nonce[8:12])
	nonce[12] = securityLevel
	return nonce
}

// BuildAAD constructs the 42-byte additional authenticated data (AAD)
// for MLE AES-CCM encryption.
//
// Layout: SourceIPv6(16) + DestIPv6(16) + SecurityHeader(10).
func BuildAAD(srcIP, dstIP ip6.Address, secHdr [SecurityHeaderSize]byte) [aadSize]byte {
	var aad [aadSize]byte
	copy(aad[0:16], srcIP[:])
	copy(aad[16:32], dstIP[:])
	copy(aad[32:42], secHdr[:])
	return aad
}

// Encrypt encrypts and authenticates an MLE message payload using AES-CCM.
//
// Parameters:
//   - mleKey: the 16-byte MLE key
//   - nonce: the 13-byte nonce (from BuildNonce)
//   - aad: the additional authenticated data (from BuildAAD)
//   - plaintext: the command byte + TLVs to encrypt
//
// Returns the ciphertext (same length as plaintext) and the 4-byte authentication tag.
func Encrypt(mleKey key.MleKey, nonce [aesccm.NonceSize]byte, aad, plaintext []byte) (encrypted []byte, authTag [SecurityTagSize]byte, encryptErr error) {
	var ccm aesccm.AesCcm
	var tag [SecurityTagSize]byte

	if err := ccm.SetKey(mleKey[:]); err != nil {
		return nil, tag, fmt.Errorf("mle: encrypt: %w", err)
	}

	ciphertext, tagSlice, err := ccm.Seal(nonce[:], plaintext, aad, SecurityTagSize)
	if err != nil {
		return nil, tag, fmt.Errorf("mle: encrypt: %w", err)
	}

	copy(tag[:], tagSlice)
	return ciphertext, tag, nil
}

// Decrypt decrypts and verifies an MLE message payload using AES-CCM.
//
// Parameters:
//   - mleKey: the 16-byte MLE key
//   - nonce: the 13-byte nonce (from BuildNonce)
//   - aad: the additional authenticated data (from BuildAAD)
//   - ciphertext: the encrypted command byte + TLVs
//   - tag: the 4-byte authentication tag
//
// Returns the plaintext (command byte + TLVs), or an error if authentication fails.
func Decrypt(mleKey key.MleKey, nonce [aesccm.NonceSize]byte, aad, ciphertext []byte, tag [SecurityTagSize]byte) ([]byte, error) {
	var ccm aesccm.AesCcm

	if err := ccm.SetKey(mleKey[:]); err != nil {
		return nil, fmt.Errorf("mle: decrypt: %w", err)
	}

	plaintext, err := ccm.Open(nonce[:], ciphertext, aad, tag[:])
	if err != nil {
		return nil, fmt.Errorf("mle: decrypt: %w", err)
	}

	return plaintext, nil
}
