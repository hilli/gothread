// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"testing"
)

func TestSteeringDataInit(t *testing.T) {
	var sd SteeringData

	// Valid lengths.
	for length := uint8(SteeringDataMinLength); length <= SteeringDataMaxLength; length++ {
		if err := sd.Init(length); err != nil {
			t.Fatalf("Init(%d) returned error: %v", length, err)
		}
		if sd.Length() != length {
			t.Errorf("Init(%d): Length() = %d, want %d", length, sd.Length(), length)
		}
		if !sd.IsValid() {
			t.Errorf("Init(%d): IsValid() = false", length)
		}
		// All bytes should be zero after Init.
		for _, b := range sd.Data() {
			if b != 0 {
				t.Errorf("Init(%d): expected all zeros, got non-zero byte", length)
				break
			}
		}
	}

	// Invalid lengths.
	if err := sd.Init(0); err == nil {
		t.Error("Init(0) should return error")
	}
	if err := sd.Init(SteeringDataMaxLength + 1); err == nil {
		t.Error("Init(17) should return error")
	}
}

func TestSteeringDataInitWithData(t *testing.T) {
	var sd SteeringData

	data := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	if err := sd.InitWithData(4, data); err != nil {
		t.Fatalf("InitWithData() returned error: %v", err)
	}
	if sd.Length() != 4 {
		t.Errorf("Length() = %d, want 4", sd.Length())
	}
	got := sd.Data()
	for i, b := range data {
		if got[i] != b {
			t.Errorf("Data()[%d] = %02x, want %02x", i, got[i], b)
		}
	}

	// Invalid length.
	if err := sd.InitWithData(0, nil); err == nil {
		t.Error("InitWithData(0, nil) should return error")
	}
}

func TestSteeringDataClear(t *testing.T) {
	var sd SteeringData

	// Initialize with some data, then clear.
	_ = sd.InitWithData(4, []byte{0xFF, 0xFF, 0xFF, 0xFF})
	sd.Clear()

	if sd.Length() != 1 {
		t.Errorf("After Clear(): Length() = %d, want 1", sd.Length())
	}
	if sd.Data()[0] != 0 {
		t.Errorf("After Clear(): Data()[0] = %02x, want 00", sd.Data()[0])
	}
	if !sd.IsEmpty() {
		t.Error("After Clear(): IsEmpty() should be true")
	}
}

func TestSteeringDataSetToPermitAllJoiners(t *testing.T) {
	var sd SteeringData

	sd.SetToPermitAllJoiners()

	if sd.Length() != 1 {
		t.Errorf("SetToPermitAllJoiners(): Length() = %d, want 1", sd.Length())
	}
	if sd.Data()[0] != 0xFF {
		t.Errorf("SetToPermitAllJoiners(): Data()[0] = %02x, want FF", sd.Data()[0])
	}
	if !sd.PermitsAllJoiners() {
		t.Error("SetToPermitAllJoiners(): PermitsAllJoiners() should be true")
	}
	if sd.IsEmpty() {
		t.Error("SetToPermitAllJoiners(): IsEmpty() should be false")
	}
}

func TestSteeringDataIsEmpty(t *testing.T) {
	var sd SteeringData

	// Empty after Init.
	_ = sd.Init(4)
	if !sd.IsEmpty() {
		t.Error("Should be empty after Init(4)")
	}

	// Not empty after setting a bit.
	sd.data[0] = 0x01
	if sd.IsEmpty() {
		t.Error("Should not be empty after setting a bit")
	}
}

func TestSteeringDataPermitsAllJoiners(t *testing.T) {
	var sd SteeringData

	// Not all set after Init.
	_ = sd.Init(2)
	if sd.PermitsAllJoiners() {
		t.Error("Should not permit all after Init")
	}

	// Set all bits.
	sd.data[0] = 0xFF
	sd.data[1] = 0xFF
	if !sd.PermitsAllJoiners() {
		t.Error("Should permit all when all bits set")
	}

	// One bit unset.
	sd.data[1] = 0xFE
	if sd.PermitsAllJoiners() {
		t.Error("Should not permit all when one bit is unset")
	}
}

func TestSteeringDataIsValid(t *testing.T) {
	var sd SteeringData

	// Zero-value is not valid.
	if sd.IsValid() {
		t.Error("Zero-value SteeringData should not be valid")
	}

	_ = sd.Init(1)
	if !sd.IsValid() {
		t.Error("After Init(1), should be valid")
	}
}

func TestCalculateHashBitIndexes(t *testing.T) {
	// Test with a known Joiner ID.
	joinerID := [8]byte{0x18, 0xb4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x01}
	indexes := CalculateHashBitIndexes(joinerID)

	// The indexes should be non-zero CRC16 values.
	// We verify the two indexes are different (they use different polynomials).
	if indexes.Index[0] == indexes.Index[1] {
		t.Logf("Warning: both hash indexes are equal (%d), unlikely but possible", indexes.Index[0])
	}

	// Verify determinism.
	indexes2 := CalculateHashBitIndexes(joinerID)
	if indexes != indexes2 {
		t.Error("CalculateHashBitIndexes should be deterministic")
	}

	// Different Joiner IDs should produce different indexes.
	differentID := [8]byte{0x18, 0xb4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x02}
	indexes3 := CalculateHashBitIndexes(differentID)
	if indexes == indexes3 {
		t.Error("Different Joiner IDs should produce different indexes")
	}
}

func TestSteeringDataUpdateAndContains(t *testing.T) {
	var sd SteeringData

	_ = sd.Init(16) // 128-bit bloom filter.

	joinerID := [8]byte{0x18, 0xb4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x01}

	// Should not contain before adding.
	if sd.Contains(joinerID) {
		t.Error("Should not contain joinerID before adding")
	}

	// Add the joiner ID.
	if err := sd.UpdateBloomFilter(joinerID); err != nil {
		t.Fatalf("UpdateBloomFilter() returned error: %v", err)
	}

	// Should contain after adding.
	if !sd.Contains(joinerID) {
		t.Error("Should contain joinerID after adding")
	}

	// Should not be empty.
	if sd.IsEmpty() {
		t.Error("Should not be empty after adding a joiner")
	}
}

func TestSteeringDataMultipleJoiners(t *testing.T) {
	var sd SteeringData

	_ = sd.Init(16)

	joiners := [][8]byte{
		{0x18, 0xb4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x01},
		{0x18, 0xb4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x02},
		{0x18, 0xb4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x03},
		{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11},
	}

	for _, j := range joiners {
		if err := sd.UpdateBloomFilter(j); err != nil {
			t.Fatalf("UpdateBloomFilter() returned error: %v", err)
		}
	}

	// All added joiners should be contained.
	for i, j := range joiners {
		if !sd.Contains(j) {
			t.Errorf("Should contain joiner %d", i)
		}
	}
}

func TestSteeringDataContainsIndexes(t *testing.T) {
	var sd SteeringData

	_ = sd.Init(16)

	joinerID := [8]byte{0x18, 0xb4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x01}
	indexes := CalculateHashBitIndexes(joinerID)

	if sd.ContainsIndexes(indexes) {
		t.Error("Should not contain indexes before adding")
	}

	_ = sd.UpdateBloomFilter(joinerID)

	if !sd.ContainsIndexes(indexes) {
		t.Error("Should contain indexes after adding")
	}
}

func TestSteeringDataUpdateBloomFilterInvalid(t *testing.T) {
	var sd SteeringData
	// Don't init — should be invalid.

	joinerID := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if err := sd.UpdateBloomFilter(joinerID); err == nil {
		t.Error("UpdateBloomFilter on invalid SteeringData should return error")
	}
}

func TestSteeringDataContainsOnInvalid(t *testing.T) {
	var sd SteeringData
	// Don't init — should be invalid.

	joinerID := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if sd.Contains(joinerID) {
		t.Error("Contains on invalid SteeringData should return false")
	}
}

func TestSteeringDataMergeWith(t *testing.T) {
	var sd1, sd2 SteeringData

	_ = sd1.Init(4)
	_ = sd2.Init(2)

	joiner1 := [8]byte{0x18, 0xb4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x01}
	joiner2 := [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}

	_ = sd1.UpdateBloomFilter(joiner1)
	_ = sd2.UpdateBloomFilter(joiner2)

	if err := sd1.MergeWith(&sd2); err != nil {
		t.Fatalf("MergeWith() returned error: %v", err)
	}

	// sd1 should contain joiner1 (still).
	if !sd1.Contains(joiner1) {
		t.Error("After merge, should still contain joiner1")
	}
}

func TestSteeringDataMergeWithInvalidLengths(t *testing.T) {
	var sd1, sd2 SteeringData

	// sd1 length not divisible by sd2 length: 5 % 3 != 0.
	_ = sd1.Init(5)
	_ = sd2.Init(3)

	if err := sd1.MergeWith(&sd2); err == nil {
		t.Error("MergeWith should fail when lengths are not divisible")
	}

	// Both invalid.
	var sd3, sd4 SteeringData
	if err := sd3.MergeWith(&sd4); err == nil {
		t.Error("MergeWith should fail when self is invalid")
	}

	// Self valid, other invalid.
	_ = sd3.Init(4)
	if err := sd3.MergeWith(&sd4); err == nil {
		t.Error("MergeWith should fail when other is invalid")
	}
}

func TestSteeringDataMergeWithSameLength(t *testing.T) {
	var sd1, sd2 SteeringData

	_ = sd1.Init(4)
	_ = sd2.Init(4)

	sd1.data[0] = 0x0F
	sd2.data[0] = 0xF0

	if err := sd1.MergeWith(&sd2); err != nil {
		t.Fatalf("MergeWith() returned error: %v", err)
	}

	if sd1.data[0] != 0xFF {
		t.Errorf("After merge: data[0] = %02x, want FF", sd1.data[0])
	}
}

func TestSteeringDataString(t *testing.T) {
	var sd SteeringData

	// Empty (zero length).
	if s := sd.String(); s != "[]" {
		t.Errorf("String() on zero-length = %q, want %q", s, "[]")
	}

	// Initialized with data.
	_ = sd.InitWithData(2, []byte{0xAB, 0xCD})
	expected := "[abcd]"
	if s := sd.String(); s != expected {
		t.Errorf("String() = %q, want %q", s, expected)
	}

	// Permit all.
	sd.SetToPermitAllJoiners()
	if s := sd.String(); s != "[ff]" {
		t.Errorf("String() after SetToPermitAllJoiners() = %q, want %q", s, "[ff]")
	}
}

func TestSteeringDataSmallFilter(t *testing.T) {
	// Test with a 1-byte (8-bit) bloom filter.
	var sd SteeringData

	_ = sd.Init(1)

	joinerID := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if err := sd.UpdateBloomFilter(joinerID); err != nil {
		t.Fatalf("UpdateBloomFilter() returned error: %v", err)
	}

	if !sd.Contains(joinerID) {
		t.Error("Small filter should contain added joiner")
	}

	if sd.IsEmpty() {
		t.Error("Should not be empty after adding a joiner")
	}
}

func TestSteeringDataBitAddressingBigEndian(t *testing.T) {
	// Verify that bit addressing is big-endian:
	// bit 0 should be in data[length-1], bit 8 in data[length-2].
	var sd SteeringData

	_ = sd.Init(2) // 16 bits.

	// Set bit 0 — should affect data[1] (last byte).
	sd.setBit(0)
	if sd.data[1] != 0x01 {
		t.Errorf("Setting bit 0: data[1] = %02x, want 01", sd.data[1])
	}
	if sd.data[0] != 0x00 {
		t.Errorf("Setting bit 0: data[0] = %02x, want 00", sd.data[0])
	}

	_ = sd.Init(2) // Reset.

	// Set bit 8 — should affect data[0] (first byte).
	sd.setBit(8)
	if sd.data[0] != 0x01 {
		t.Errorf("Setting bit 8: data[0] = %02x, want 01", sd.data[0])
	}
	if sd.data[1] != 0x00 {
		t.Errorf("Setting bit 8: data[1] = %02x, want 00", sd.data[1])
	}

	// Verify getBit.
	if !sd.getBit(8) {
		t.Error("getBit(8) should be true after setBit(8)")
	}
	if sd.getBit(0) {
		t.Error("getBit(0) should be false")
	}
}

func TestSteeringDataDiscernerBasic(t *testing.T) {
	var sd SteeringData

	_ = sd.Init(16)

	// A Joiner Discerner value and bit length.
	discValue := uint64(0xABCD)
	discBitLen := uint8(16)

	if sd.ContainsDiscerner(discValue, discBitLen) {
		t.Error("Should not contain discerner before adding")
	}

	if err := sd.UpdateBloomFilterWithDiscerner(discValue, discBitLen); err != nil {
		t.Fatalf("UpdateBloomFilterWithDiscerner() returned error: %v", err)
	}

	if !sd.ContainsDiscerner(discValue, discBitLen) {
		t.Error("Should contain discerner after adding")
	}
}

func TestSteeringDataDiscernerMatchesExpectedAddress(t *testing.T) {
	// Verify that a discerner packed into an 8-byte address matches what
	// we'd get by manually constructing the address and hashing it.
	discValue := uint64(0x1234)
	discBitLen := uint8(16)

	indexes := CalculateHashBitIndexesFromDiscerner(discValue, discBitLen)

	// Manually construct the expected address: zero-padded, value in last bytes.
	expectedAddr := [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34}
	expectedIndexes := CalculateHashBitIndexes(expectedAddr)

	if indexes != expectedIndexes {
		t.Errorf("Discerner indexes %v don't match expected %v", indexes, expectedIndexes)
	}
}

func TestSteeringDataAllZerosJoinerID(t *testing.T) {
	var sd SteeringData

	_ = sd.Init(16)

	zeroID := [8]byte{}
	if err := sd.UpdateBloomFilter(zeroID); err != nil {
		t.Fatalf("UpdateBloomFilter(zeros) returned error: %v", err)
	}

	if !sd.Contains(zeroID) {
		t.Error("Should contain all-zeros joiner ID after adding")
	}
}

func TestSteeringDataAllOnesJoinerID(t *testing.T) {
	var sd SteeringData

	_ = sd.Init(16)

	onesID := [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	if err := sd.UpdateBloomFilter(onesID); err != nil {
		t.Fatalf("UpdateBloomFilter(ones) returned error: %v", err)
	}

	if !sd.Contains(onesID) {
		t.Error("Should contain all-ones joiner ID after adding")
	}
}

func TestSteeringDataMergeWithWrapping(t *testing.T) {
	// Test merging a 2-byte filter into a 4-byte filter.
	// The 2-byte data wraps: sd1.data[i] |= sd2.data[i % 2].
	var sd1, sd2 SteeringData

	_ = sd1.Init(4)
	_ = sd2.Init(2)

	sd2.data[0] = 0xA0
	sd2.data[1] = 0x0B

	if err := sd1.MergeWith(&sd2); err != nil {
		t.Fatalf("MergeWith() returned error: %v", err)
	}

	// sd1.data[0] |= sd2.data[0] = 0xA0
	// sd1.data[1] |= sd2.data[1] = 0x0B
	// sd1.data[2] |= sd2.data[0] = 0xA0
	// sd1.data[3] |= sd2.data[1] = 0x0B
	if sd1.data[0] != 0xA0 || sd1.data[1] != 0x0B || sd1.data[2] != 0xA0 || sd1.data[3] != 0x0B {
		t.Errorf("MergeWith wrapping: got %02x %02x %02x %02x, want A0 0B A0 0B",
			sd1.data[0], sd1.data[1], sd1.data[2], sd1.data[3])
	}
}

func TestSteeringDataPermitAllContainsEverything(t *testing.T) {
	var sd SteeringData

	sd.SetToPermitAllJoiners()

	// Any joiner ID should be "contained" when all bits are set.
	testIDs := [][8]byte{
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		{0x18, 0xb4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x01},
		{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
	}

	for i, id := range testIDs {
		if !sd.Contains(id) {
			t.Errorf("PermitAll should contain joiner %d", i)
		}
	}
}

func TestSteeringDataDataSlice(t *testing.T) {
	var sd SteeringData

	_ = sd.InitWithData(3, []byte{0x11, 0x22, 0x33})

	data := sd.Data()
	if len(data) != 3 {
		t.Fatalf("Data() length = %d, want 3", len(data))
	}
	if data[0] != 0x11 || data[1] != 0x22 || data[2] != 0x33 {
		t.Errorf("Data() = %02x %02x %02x, want 11 22 33", data[0], data[1], data[2])
	}
}
