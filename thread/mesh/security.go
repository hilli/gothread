// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import (
	"encoding/binary"

	"github.com/hilli/gothread/crypto/aesccm"
	"github.com/hilli/gothread/errors"
)

// BuildNonce constructs the 13-byte IEEE 802.15.4 AES-CCM nonce:
//
//	ExtendedAddress (8 bytes) || FrameCounter (4 bytes LE) || SecurityLevel (1 byte)
func BuildNonce(extAddr [8]byte, frameCounter uint32, securityLevel uint8) [13]byte {
	var nonce [13]byte
	copy(nonce[0:8], extAddr[:])
	binary.LittleEndian.PutUint32(nonce[8:12], frameCounter)
	nonce[12] = securityLevel
	return nonce
}

// DecryptFramePayload decrypts the payload portion of an IEEE 802.15.4
// frame that was encrypted with AES-CCM. The frame bytes up to
// payloadOffset are used as AAD (additional authenticated data). The
// encrypted payload starts at payloadOffset and ends with a MIC tag
// of micTagSize(SecurityEncMic32) bytes.
//
// srcExtAddr is the sender's extended address, needed to reconstruct the
// nonce. In a real Thread network, this is looked up from the neighbor
// table when the frame uses short addressing.
//
// Returns the decrypted plaintext payload, or an error if
// authentication or decryption fails.
func DecryptFramePayload(frame []byte, payloadOffset int, ctx *FrameContext, key [16]byte, srcExtAddr [8]byte) ([]byte, error) {
	tagSize := micTagSize(SecurityEncMic32)
	encPayload := frame[payloadOffset:]
	if len(encPayload) < tagSize {
		return nil, errors.ErrParse
	}

	ciphertext := encPayload[:len(encPayload)-tagSize]
	tag := encPayload[len(encPayload)-tagSize:]
	additionalData := frame[:payloadOffset]

	nonce := BuildNonce(srcExtAddr, ctx.Security.FrameCounter, uint8(SecurityEncMic32))

	var ccm aesccm.AesCcm
	if err := ccm.SetKey(key[:]); err != nil {
		return nil, err
	}
	plaintext, err := ccm.Open(nonce[:], ciphertext, additionalData, tag)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
