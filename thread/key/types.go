// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package key implements Thread security material generation including
// network key derivation, key rotation, and security policy management.
//
// This is a Go port of the key management logic in OpenThread's
// src/core/thread/key_manager.hpp and src/core/thread/key_manager.cpp.
package key

import (
	"crypto/rand"
)

// Key sizes in bytes.
const (
	NetworkKeySize = 16 // Thread Network Key size.
	PskcSize       = 16 // Pre-Shared Key for Commissioner size.
	KekSize        = 16 // Key Encryption Key size.
	MacKeySize     = 16 // MAC encryption key size.
	MleKeySize     = 16 // MLE encryption key size.
)

// NetworkKey is a 16-byte Thread Network Key.
type NetworkKey [NetworkKeySize]byte

// GenerateRandom fills the NetworkKey with cryptographically secure random bytes.
func (k *NetworkKey) GenerateRandom() error {
	_, err := rand.Read(k[:])
	return err
}

// IsZero returns true if the key is all zeros.
func (k NetworkKey) IsZero() bool {
	for _, b := range k {
		if b != 0 {
			return false
		}
	}
	return true
}

// Pskc is a 16-byte Pre-Shared Key for the Commissioner.
type Pskc [PskcSize]byte

// GenerateRandom fills the Pskc with cryptographically secure random bytes.
func (p *Pskc) GenerateRandom() error {
	_, err := rand.Read(p[:])
	return err
}

// IsZero returns true if the Pskc is all zeros.
func (p Pskc) IsZero() bool {
	for _, b := range p {
		if b != 0 {
			return false
		}
	}
	return true
}

// Kek is a 16-byte Key Encryption Key.
type Kek [KekSize]byte

// MacKey is a 16-byte MAC encryption key derived from the Thread Network Key.
type MacKey [MacKeySize]byte

// MleKey is a 16-byte MLE encryption key derived from the Thread Network Key.
type MleKey [MleKeySize]byte

// DerivedKeys holds the MLE and MAC keys derived from a single
// HMAC-SHA-256 computation over (KeySequence || "Thread").
type DerivedKeys struct {
	MleKey MleKey
	MacKey MacKey
}
