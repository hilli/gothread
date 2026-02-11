// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"fmt"

	"github.com/hilli/gothread/crypto/pbkdf2"
	"github.com/hilli/gothread/mac/types"
)

// PSKc derivation constants per Thread specification.
const (
	// pskcIterations is the PBKDF2 iteration count for PSKc derivation.
	// Thread uses 16384 iterations with the OpenThread AES-CMAC-PRF-128 implementation.
	pskcIterations = 16384

	// pskcKeyLen is the PSKc output length in bytes.
	pskcKeyLen = 16
)

// GeneratePSKc derives a PSKc from a passphrase, network name, and Extended
// PAN ID using PBKDF2 with AES-CMAC-PRF-128 as the PRF (per Thread spec).
//
// The salt is the concatenation of the network name and the Extended PAN ID.
// The passphrase must be 6-255 UTF-8 characters.
func GeneratePSKc(passphrase string, networkName string, extPanID [8]byte) ([16]byte, error) {
	var pskc [16]byte

	if len(passphrase) < 6 || len(passphrase) > 255 {
		return pskc, fmt.Errorf("meshcop: passphrase length %d out of range [6, 255]", len(passphrase))
	}
	if len(networkName) == 0 || len(networkName) > MaxNetworkNameLength {
		return pskc, fmt.Errorf("meshcop: network name length %d out of range [1, %d]", len(networkName), MaxNetworkNameLength)
	}

	// Salt = networkName || extPanID
	salt := make([]byte, len(networkName)+8)
	copy(salt, networkName)
	copy(salt[len(networkName):], extPanID[:])

	key, err := pbkdf2.GenerateKey([]byte(passphrase), salt, pskcIterations, pskcKeyLen)
	if err != nil {
		return pskc, fmt.Errorf("meshcop: PBKDF2 key derivation failed: %w", err)
	}

	copy(pskc[:], key)
	return pskc, nil
}

// ComputeJoinerId derives a Joiner ID from an IEEE EUI-64. This is a
// convenience wrapper around ComputeJoinerIDFromEUI64.
func ComputeJoinerId(eui64 [8]byte) [8]byte {
	return ComputeJoinerIDFromEUI64(types.ExtAddress(eui64))
}

// SteeringDataCompute creates a 16-byte SteeringData bloom filter and adds
// the given Joiner ID.
func SteeringDataCompute(joinerID [8]byte) SteeringData {
	var sd SteeringData
	_ = sd.Init(SteeringDataMaxLength)
	_ = sd.UpdateBloomFilter(joinerID)
	return sd
}
