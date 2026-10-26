// Package aesccm provides AES-128-CCM authenticated encryption as used
// in IEEE 802.15.4 MAC security.
//
// Reference: openthread/src/core/crypto/aes_ccm.hpp
package aesccm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// MinTagLength is the minimum authentication tag length in bytes.
	MinTagLength = 4

	// MaxTagLength is the maximum authentication tag length in bytes.
	MaxTagLength = 16

	// NonceSize is the IEEE 802.15.4 nonce size in bytes.
	NonceSize = 13

	blockSize = aes.BlockSize  // 16
	lSize     = 15 - NonceSize // L field size = 2
)

// ErrAuth is returned by [AesCcm.Open] when the authentication tag does not
// match.
var ErrAuth = errors.New("aesccm: message authentication failed")

// AesCcm provides AES-CCM authenticated encryption and decryption.
type AesCcm struct {
	block cipher.Block
}

// SetKey sets the AES-128 key. key must be exactly 16 bytes.
func (c *AesCcm) SetKey(key []byte) error {
	if len(key) != blockSize {
		return fmt.Errorf("aesccm: invalid key size %d, must be %d", len(key), blockSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	c.block = block
	return nil
}

// Seal encrypts plaintext and appends an authentication tag.
//
// nonce must be [NonceSize] bytes. additionalData is the authenticated-only
// header. tagLen must be even and in the range [MinTagLength, MaxTagLength].
//
// Returns ciphertext (same length as plaintext) and the authentication tag.
func (c *AesCcm) Seal(nonce, plaintext, additionalData []byte, tagLen int) (ciphertext, tag []byte, err error) {
	if err := c.validateParams(nonce, tagLen); err != nil {
		return nil, nil, err
	}

	// 1. Compute CBC-MAC over the formatted input.
	t := c.cbcMAC(nonce, plaintext, additionalData, tagLen)

	// 2. Generate the key-stream and encrypt the tag (A_0) and plaintext (A_1...).
	ciphertext = make([]byte, len(plaintext))
	tag = make([]byte, tagLen)

	a := c.formatA(nonce) // A_0
	s0 := make([]byte, blockSize)
	c.block.Encrypt(s0, a)

	// Encrypt the tag: tag = T XOR S_0 (first tagLen bytes).
	subtle.XORBytes(tag, t[:tagLen], s0[:tagLen])

	// Encrypt plaintext with A_1, A_2, ...
	c.ctr(a, plaintext, ciphertext)

	return ciphertext, tag, nil
}

// Open decrypts ciphertext and verifies the authentication tag.
//
// Returns the plaintext, or [ErrAuth] if the tag does not match.
func (c *AesCcm) Open(nonce, ciphertext, additionalData, tag []byte) (plaintext []byte, err error) {
	if err := c.validateParams(nonce, len(tag)); err != nil {
		return nil, err
	}

	tagLen := len(tag)

	// 1. Decrypt the ciphertext with CTR to recover plaintext.
	plaintext = make([]byte, len(ciphertext))
	a := c.formatA(nonce)
	s0 := make([]byte, blockSize)
	c.block.Encrypt(s0, a)

	c.ctr(a, ciphertext, plaintext)

	// 2. Recompute CBC-MAC over the recovered plaintext.
	t := c.cbcMAC(nonce, plaintext, additionalData, tagLen)

	// 3. Encrypt the expected tag with S_0 and compare.
	expected := make([]byte, tagLen)
	subtle.XORBytes(expected, t[:tagLen], s0[:tagLen])

	if subtle.ConstantTimeCompare(expected, tag) != 1 {
		// Zero out plaintext on authentication failure.
		clear(plaintext)
		return nil, ErrAuth
	}

	return plaintext, nil
}

// validateParams checks nonce length and tag length constraints.
func (c *AesCcm) validateParams(nonce []byte, tagLen int) error {
	if c.block == nil {
		return errors.New("aesccm: key not set")
	}
	if len(nonce) != NonceSize {
		return fmt.Errorf("aesccm: invalid nonce size %d, must be %d", len(nonce), NonceSize)
	}
	if tagLen < MinTagLength || tagLen > MaxTagLength {
		return fmt.Errorf("aesccm: invalid tag length %d, must be in [%d, %d]", tagLen, MinTagLength, MaxTagLength)
	}
	if tagLen%2 != 0 {
		return fmt.Errorf("aesccm: tag length %d must be even", tagLen)
	}
	return nil
}

// cbcMAC computes the CBC-MAC authentication tag T over the formatted input
// (B_0 || additional data || plaintext).
func (c *AesCcm) cbcMAC(nonce, plaintext, additionalData []byte, tagLen int) []byte {
	x := make([]byte, blockSize) // running CBC-MAC state

	// Process B_0.
	b0 := c.formatB0(nonce, len(plaintext), len(additionalData), tagLen)
	c.cbcMACBlock(x, b0)

	// Process additional data with length prefix.
	if len(additionalData) > 0 {
		c.cbcMACAdditionalData(x, additionalData)
	}

	// Process plaintext.
	c.cbcMACPayload(x, plaintext)

	return x
}

// formatB0 builds the first block B_0 for CBC-MAC.
//
// Layout: flags(1) | nonce(NonceSize) | messageLen(lSize)
//
// flags = (hasAD ? 0x40 : 0) | ((tagLen-2)/2 << 3) | (L-1)
func (c *AesCcm) formatB0(nonce []byte, msgLen, adLen, tagLen int) []byte {
	var b0 [blockSize]byte

	var flags byte
	if adLen > 0 {
		flags |= 0x40
	}
	flags |= byte((tagLen-2)/2) << 3
	flags |= byte(lSize - 1)

	b0[0] = flags
	copy(b0[1:1+NonceSize], nonce)
	binary.BigEndian.PutUint16(b0[1+NonceSize:], uint16(msgLen))

	return b0[:]
}

// formatA builds the initial counter block A_0 for CTR encryption.
//
// Layout: flags(1) | nonce(NonceSize) | counter(lSize)
// flags = L-1
// counter starts at 0
func (c *AesCcm) formatA(nonce []byte) []byte {
	a := make([]byte, blockSize)
	a[0] = byte(lSize - 1)
	copy(a[1:1+NonceSize], nonce)
	// Counter bytes (last lSize bytes) are zero for A_0.
	return a
}

// cbcMACBlock XORs a full block into x and encrypts in place.
func (c *AesCcm) cbcMACBlock(x, block []byte) {
	subtle.XORBytes(x, x, block)
	c.block.Encrypt(x, x)
}

// cbcMACAdditionalData processes the additional data with its length prefix
// into the CBC-MAC state. For adLen < 0xFF00, the length is encoded as 2
// bytes.
func (c *AesCcm) cbcMACAdditionalData(x, ad []byte) {
	// RFC 3610: if 0 < adLen < 0xFF00, encode as 2-byte big-endian.
	var buf [blockSize]byte
	binary.BigEndian.PutUint16(buf[:2], uint16(len(ad)))

	// Fill the rest of the first block with AD bytes.
	firstChunk := blockSize - 2
	if firstChunk > len(ad) {
		firstChunk = len(ad)
	}
	copy(buf[2:], ad[:firstChunk])
	c.cbcMACBlock(x, buf[:])

	// Process remaining AD in full blocks.
	remaining := ad[firstChunk:]
	for len(remaining) > 0 {
		clear(buf[:])
		n := copy(buf[:], remaining)
		c.cbcMACBlock(x, buf[:])
		remaining = remaining[n:]
	}
}

// cbcMACPayload processes the plaintext payload into the CBC-MAC state.
func (c *AesCcm) cbcMACPayload(x, payload []byte) {
	var buf [blockSize]byte
	remaining := payload
	for len(remaining) > 0 {
		clear(buf[:])
		n := copy(buf[:], remaining)
		c.cbcMACBlock(x, buf[:])
		remaining = remaining[n:]
	}
}

// ctr encrypts src into dst using CTR mode starting at counter 1 (A_1).
// a is modified in place (counter incremented).
func (c *AesCcm) ctr(a, src, dst []byte) {
	var keystreamBlock [blockSize]byte
	offset := 0

	for offset < len(src) {
		// Increment counter (last lSize bytes of a, big-endian).
		incCounter(a)

		c.block.Encrypt(keystreamBlock[:], a)

		end := offset + blockSize
		if end > len(src) {
			end = len(src)
		}
		subtle.XORBytes(dst[offset:end], src[offset:end], keystreamBlock[:end-offset])
		offset = end
	}
}

// incCounter increments the big-endian counter in the last lSize bytes of a.
func incCounter(a []byte) {
	for i := len(a) - 1; i >= len(a)-lSize; i-- {
		a[i]++
		if a[i] != 0 {
			break
		}
	}
}
