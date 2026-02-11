// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"strings"
	"testing"
)

func TestGeneratePSKc(t *testing.T) {
	tests := []struct {
		name       string
		passphrase string
		network    string
		extPanID   [8]byte
		wantErr    bool
	}{
		{
			name:       "valid inputs",
			passphrase: "123456",
			network:    "MyNetwork",
			extPanID:   [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			wantErr:    false,
		},
		{
			name:       "max length passphrase",
			passphrase: strings.Repeat("A", 255),
			network:    "Net",
			extPanID:   [8]byte{},
			wantErr:    false,
		},
		{
			name:       "min length passphrase",
			passphrase: "abcdef",
			network:    "N",
			extPanID:   [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			wantErr:    false,
		},
		{
			name:       "max length network name",
			passphrase: "123456",
			network:    strings.Repeat("X", MaxNetworkNameLength),
			extPanID:   [8]byte{},
			wantErr:    false,
		},
		{
			name:       "passphrase too short",
			passphrase: "12345",
			network:    "Net",
			extPanID:   [8]byte{},
			wantErr:    true,
		},
		{
			name:       "passphrase too long",
			passphrase: strings.Repeat("A", 256),
			network:    "Net",
			extPanID:   [8]byte{},
			wantErr:    true,
		},
		{
			name:       "empty passphrase",
			passphrase: "",
			network:    "Net",
			extPanID:   [8]byte{},
			wantErr:    true,
		},
		{
			name:       "empty network name",
			passphrase: "123456",
			network:    "",
			extPanID:   [8]byte{},
			wantErr:    true,
		},
		{
			name:       "network name too long",
			passphrase: "123456",
			network:    strings.Repeat("X", MaxNetworkNameLength+1),
			extPanID:   [8]byte{},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pskc, err := GeneratePSKc(tt.passphrase, tt.network, tt.extPanID)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// PSKc must be 16 bytes (it's a [16]byte, so always is).
			// Verify it's not all zeros (extremely unlikely for valid inputs).
			allZero := true
			for _, b := range pskc {
				if b != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				t.Error("PSKc is all zeros, likely invalid")
			}
		})
	}
}

func TestGeneratePSKcDeterministic(t *testing.T) {
	passphrase := "TestPass123"
	network := "TestNet"
	extPanID := [8]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}

	pskc1, err := GeneratePSKc(passphrase, network, extPanID)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	pskc2, err := GeneratePSKc(passphrase, network, extPanID)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	if pskc1 != pskc2 {
		t.Errorf("PSKc not deterministic: %x != %x", pskc1, pskc2)
	}
}

func TestGeneratePSKcDifferentInputs(t *testing.T) {
	extPanID := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	pskc1, err := GeneratePSKc("passphrase1", "NetA", extPanID)
	if err != nil {
		t.Fatalf("first: %v", err)
	}

	pskc2, err := GeneratePSKc("passphrase2", "NetA", extPanID)
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	if pskc1 == pskc2 {
		t.Error("different passphrases produced same PSKc")
	}

	pskc3, err := GeneratePSKc("passphrase1", "NetB", extPanID)
	if err != nil {
		t.Fatalf("third: %v", err)
	}

	if pskc1 == pskc3 {
		t.Error("different network names produced same PSKc")
	}
}

func TestComputeJoinerId(t *testing.T) {
	tests := []struct {
		name  string
		eui64 [8]byte
	}{
		{
			name:  "all zeros",
			eui64: [8]byte{},
		},
		{
			name:  "all ones",
			eui64: [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		},
		{
			name:  "typical address",
			eui64: [8]byte{0x18, 0xB4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x01},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeJoinerId(tt.eui64)
			// Must produce the same result as the underlying function.
			expected := ComputeJoinerIDFromEUI64(tt.eui64)
			if result != expected {
				t.Errorf("ComputeJoinerId(%x) = %x, want %x", tt.eui64, result, expected)
			}

			// Local bit (bit 1 of first byte) must be set.
			if result[0]&0x02 == 0 {
				t.Errorf("local bit not set in joiner ID: %x", result)
			}
		})
	}
}

func TestComputeJoinerIdDeterministic(t *testing.T) {
	eui := [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	id1 := ComputeJoinerId(eui)
	id2 := ComputeJoinerId(eui)
	if id1 != id2 {
		t.Errorf("not deterministic: %x != %x", id1, id2)
	}
}

func TestSteeringDataCompute(t *testing.T) {
	tests := []struct {
		name     string
		joinerID [8]byte
	}{
		{
			name:     "all zeros",
			joinerID: [8]byte{},
		},
		{
			name:     "typical joiner ID",
			joinerID: [8]byte{0x02, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78},
		},
		{
			name:     "all ones",
			joinerID: [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd := SteeringDataCompute(tt.joinerID)

			// Must be valid.
			if !sd.IsValid() {
				t.Fatal("steering data is not valid")
			}

			// Must be max length.
			if sd.Length() != SteeringDataMaxLength {
				t.Errorf("length = %d, want %d", sd.Length(), SteeringDataMaxLength)
			}

			// Must not be empty.
			if sd.IsEmpty() {
				t.Error("steering data is empty after adding joiner")
			}

			// Must contain the joiner ID.
			if !sd.Contains(tt.joinerID) {
				t.Error("steering data does not contain the added joiner ID")
			}
		})
	}
}

func TestSteeringDataComputeNotEmpty(t *testing.T) {
	joinerID := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	sd := SteeringDataCompute(joinerID)

	// At least some bits should be set.
	data := sd.Data()
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("steering data bytes are all zero")
	}
}
