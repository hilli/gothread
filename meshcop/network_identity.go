// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"unicode/utf8"
)

// MaxNetworkNameLength is the maximum length of a Thread Network Name in bytes.
const MaxNetworkNameLength = 16

// NetworkName represents a Thread Network Name.
// It wraps a string with validation: must be valid UTF-8 and at most
// MaxNetworkNameLength bytes.
type NetworkName struct {
	name string
}

// NewNetworkName creates a NetworkName from a string.
// Returns an error if the name is invalid.
func NewNetworkName(s string) (NetworkName, error) {
	var nn NetworkName
	if err := nn.Set(s); err != nil {
		return NetworkName{}, err
	}
	return nn, nil
}

// Set sets the network name. Returns an error if the name exceeds
// MaxNetworkNameLength bytes or is not valid UTF-8.
func (nn *NetworkName) Set(s string) error {
	if s == "" || len(s) > MaxNetworkNameLength {
		return fmt.Errorf("meshcop: network name length %d out of range [1, %d]", len(s), MaxNetworkNameLength)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("meshcop: network name is not valid UTF-8")
	}
	nn.name = s
	return nil
}

// String returns the network name as a string.
func (nn NetworkName) String() string {
	return nn.name
}

// GetAsData returns the network name as a byte slice.
func (nn NetworkName) GetAsData() []byte {
	return []byte(nn.name)
}

// IsEmpty reports whether the network name is empty.
func (nn NetworkName) IsEmpty() bool {
	return nn.name == ""
}

// Equal reports whether two network names are equal.
func (nn NetworkName) Equal(other NetworkName) bool {
	return nn.name == other.name
}

// ExtendedPanID represents an 8-byte Extended PAN ID.
type ExtendedPanID [8]byte

// ToString returns the hex string representation of the Extended PAN ID.
func (e ExtendedPanID) ToString() string {
	return hex.EncodeToString(e[:])
}

// String implements the fmt.Stringer interface.
func (e ExtendedPanID) String() string {
	return e.ToString()
}

// GenerateRandom fills the Extended PAN ID with cryptographically random bytes.
func (e *ExtendedPanID) GenerateRandom() error {
	_, err := rand.Read(e[:])
	return err
}

// IsEmpty reports whether the Extended PAN ID is all zeros.
func (e ExtendedPanID) IsEmpty() bool {
	return e == ExtendedPanID{}
}

// Equal reports whether two Extended PAN IDs are equal.
func (e ExtendedPanID) Equal(other ExtendedPanID) bool {
	return e == other
}
