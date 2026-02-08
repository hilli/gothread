// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"bytes"
	"errors"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
)

// kTLVBytes is the test vector from OpenThread's test_dataset.cpp.
// It contains 10 TLVs for an Active Operational Dataset.
var kTLVBytes = []byte{
	0x0e, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // ActiveTimestamp
	0x00, 0x03, 0x00, 0x00, 0x0f, // Channel (page=0, ch=15, but see below)
	0x35, 0x06, 0x00, 0x04, 0x00, 0x1f, 0xff, 0xe0, // ChannelMask
	0x02, 0x08, 0x1d, 0xe5, 0xbf, 0xec, 0xd5, 0x16, 0x5b, 0x8f, // ExtendedPanID
	0x07, 0x08, 0xfd, 0xe2, 0x1f, 0x0c, 0x8a, 0x13, 0xe8, 0xe7, // MeshLocalPrefix
	0x05, 0x10, 0xea, 0xf9, 0x14, 0x9f, 0xdc, 0x73, 0x78, 0x77, // NetworkKey (16 bytes)
	0x06, 0x98, 0xd5, 0x91, 0x80, 0x22, 0x19, 0x58,
	0x03, 0x0f, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x68, 0x72, 0x65, // NetworkName
	0x61, 0x64, 0x2d, 0x61, 0x61, 0x63, 0x33,
	0x01, 0x02, 0xfa, 0xce, // PanID
	0x04, 0x10, 0x2e, 0xaa, 0xe2, 0x94, 0x84, 0x38, 0x8e, 0x31, // PSKc (16 bytes)
	0x19, 0x58, 0x1a, 0x7b, 0x5a, 0x94, 0x8c, 0x07,
	0x0c, 0x04, 0x02, 0xa0, 0xf7, 0xf8, // SecurityPolicy
}

func TestDatasetSetFromAndLength(t *testing.T) {
	var ds Dataset
	if err := ds.SetFrom(kTLVBytes); err != nil {
		t.Fatalf("SetFrom: %v", err)
	}
	if got := ds.Length(); got != uint8(len(kTLVBytes)) {
		t.Errorf("Length = %d, want %d", got, len(kTLVBytes))
	}
	if !bytes.Equal(ds.Bytes(), kTLVBytes) {
		t.Error("Bytes() does not match input")
	}
}

func TestDatasetSetFromTooLong(t *testing.T) {
	var ds Dataset
	big := make([]byte, DatasetMaxLength+1)
	if err := ds.SetFrom(big); !errors.Is(err, goterrors.ErrInvalidArgs) {
		t.Errorf("SetFrom(too long): got %v, want ErrInvalidArgs", err)
	}
}

func TestDatasetValidateTLVs(t *testing.T) {
	var ds Dataset
	if err := ds.SetFrom(kTLVBytes); err != nil {
		t.Fatalf("SetFrom: %v", err)
	}
	if err := ds.ValidateTLVs(); err != nil {
		t.Errorf("ValidateTLVs: unexpected error: %v", err)
	}
}

func TestDatasetValidateTLVsDuplicates(t *testing.T) {
	// Create a dataset with duplicate PanID TLVs.
	data := []byte{
		0x01, 0x02, 0xfa, 0xce, // PanID
		0x01, 0x02, 0xde, 0xad, // PanID again (duplicate)
	}
	var ds Dataset
	if err := ds.SetFrom(data); err != nil {
		t.Fatalf("SetFrom: %v", err)
	}
	if err := ds.ValidateTLVs(); !errors.Is(err, goterrors.ErrParse) {
		t.Errorf("ValidateTLVs with duplicates: got %v, want ErrParse", err)
	}
}

func TestDatasetValidateTLVsTruncated(t *testing.T) {
	// Truncated TLV: type + length says 5 bytes but only 2 provided.
	data := []byte{0x01, 0x05, 0xaa, 0xbb}
	var ds Dataset
	if err := ds.SetFrom(data); err != nil {
		t.Fatalf("SetFrom: %v", err)
	}
	if err := ds.ValidateTLVs(); !errors.Is(err, goterrors.ErrParse) {
		t.Errorf("ValidateTLVs with truncated data: got %v, want ErrParse", err)
	}
}

func TestDatasetContainsTLV(t *testing.T) {
	var ds Dataset
	if err := ds.SetFrom(kTLVBytes); err != nil {
		t.Fatalf("SetFrom: %v", err)
	}

	expectedTypes := []TLVType{
		TLVActiveTimestamp,
		TLVChannel,
		TLVChannelMask,
		TLVExtendedPanID,
		TLVMeshLocalPrefix,
		TLVNetworkKey,
		TLVNetworkName,
		TLVPanID,
		TLVPSKc,
		TLVSecurityPolicy,
	}
	for _, typ := range expectedTypes {
		if !ds.ContainsTLV(typ) {
			t.Errorf("ContainsTLV(%s) = false, want true", typ)
		}
	}

	// Should NOT contain these.
	absentTypes := []TLVType{
		TLVPendingTimestamp,
		TLVDelayTimer,
		TLVSteeringData,
	}
	for _, typ := range absentTypes {
		if ds.ContainsTLV(typ) {
			t.Errorf("ContainsTLV(%s) = true, want false", typ)
		}
	}
}

func TestDatasetReadUint16TLV(t *testing.T) {
	var ds Dataset
	if err := ds.SetFrom(kTLVBytes); err != nil {
		t.Fatalf("SetFrom: %v", err)
	}

	panID, err := ds.ReadUint16TLV(TLVPanID)
	if err != nil {
		t.Fatalf("ReadUint16TLV(PanID): %v", err)
	}
	if panID != 0xface {
		t.Errorf("PanID = %#x, want 0xface", panID)
	}
}

func TestDatasetReadUint16TLVNotFound(t *testing.T) {
	var ds Dataset
	_, err := ds.ReadUint16TLV(TLVPanID)
	if !errors.Is(err, goterrors.ErrNotFound) {
		t.Errorf("ReadUint16TLV on empty: got %v, want ErrNotFound", err)
	}
}

func TestDatasetWriteAndReadUint32TLV(t *testing.T) {
	var ds Dataset
	if err := ds.WriteUint32TLV(TLVDelayTimer, 300000); err != nil {
		t.Fatalf("WriteUint32TLV: %v", err)
	}
	got, err := ds.ReadUint32TLV(TLVDelayTimer)
	if err != nil {
		t.Fatalf("ReadUint32TLV: %v", err)
	}
	if got != 300000 {
		t.Errorf("DelayTimer = %d, want 300000", got)
	}
}

func TestDatasetWriteTLVUpsert(t *testing.T) {
	var ds Dataset
	if err := ds.SetFrom(kTLVBytes); err != nil {
		t.Fatalf("SetFrom: %v", err)
	}

	// Overwrite PanID with a new value.
	if err := ds.WriteUint16TLV(TLVPanID, 0xBEEF); err != nil {
		t.Fatalf("WriteUint16TLV: %v", err)
	}

	panID, err := ds.ReadUint16TLV(TLVPanID)
	if err != nil {
		t.Fatalf("ReadUint16TLV: %v", err)
	}
	if panID != 0xBEEF {
		t.Errorf("PanID after upsert = %#x, want 0xBEEF", panID)
	}

	// Should still validate (no duplicates).
	if err := ds.ValidateTLVs(); err != nil {
		t.Errorf("ValidateTLVs after upsert: %v", err)
	}
}

func TestDatasetRemoveTLV(t *testing.T) {
	var ds Dataset
	if err := ds.SetFrom(kTLVBytes); err != nil {
		t.Fatalf("SetFrom: %v", err)
	}

	ds.RemoveTLV(TLVPanID)
	if ds.ContainsTLV(TLVPanID) {
		t.Error("ContainsTLV(PanID) = true after RemoveTLV")
	}

	// All other TLVs should still be present.
	if !ds.ContainsTLV(TLVActiveTimestamp) {
		t.Error("ActiveTimestamp missing after removing PanID")
	}
	if !ds.ContainsTLV(TLVNetworkKey) {
		t.Error("NetworkKey missing after removing PanID")
	}

	// Validate still passes.
	if err := ds.ValidateTLVs(); err != nil {
		t.Errorf("ValidateTLVs after remove: %v", err)
	}
}

func TestDatasetRemoveTLVNotFound(t *testing.T) {
	var ds Dataset
	// Should be a no-op on empty dataset.
	ds.RemoveTLV(TLVPanID)
	if ds.Length() != 0 {
		t.Errorf("Length = %d after removing from empty dataset, want 0", ds.Length())
	}
}

func TestDatasetClear(t *testing.T) {
	var ds Dataset
	if err := ds.SetFrom(kTLVBytes); err != nil {
		t.Fatalf("SetFrom: %v", err)
	}
	ds.Clear()
	if ds.Length() != 0 {
		t.Errorf("Length after Clear = %d, want 0", ds.Length())
	}
	if len(ds.Bytes()) != 0 {
		t.Errorf("len(Bytes()) after Clear = %d, want 0", len(ds.Bytes()))
	}
}

func TestDatasetReadWriteTimestamp(t *testing.T) {
	var ds Dataset

	ts := makeTimestamp(1000, 500, true)
	if err := ds.WriteTimestamp(DatasetActive, &ts); err != nil {
		t.Fatalf("WriteTimestamp: %v", err)
	}

	got, err := ds.ReadTimestamp(DatasetActive)
	if err != nil {
		t.Fatalf("ReadTimestamp: %v", err)
	}
	if got.Seconds() != 1000 {
		t.Errorf("Seconds = %d, want 1000", got.Seconds())
	}
	if got.Ticks() != 500 {
		t.Errorf("Ticks = %d, want 500", got.Ticks())
	}
	if !got.Authoritative() {
		t.Error("Authoritative = false, want true")
	}
}

func TestDatasetReadTimestampNotFound(t *testing.T) {
	var ds Dataset
	_, err := ds.ReadTimestamp(DatasetActive)
	if !errors.Is(err, goterrors.ErrNotFound) {
		t.Errorf("ReadTimestamp on empty: got %v, want ErrNotFound", err)
	}
}

func TestDatasetWriteTLVsFrom(t *testing.T) {
	var ds1, ds2 Dataset
	if err := ds1.SetFrom(kTLVBytes); err != nil {
		t.Fatalf("SetFrom: %v", err)
	}

	// Create ds2 with a different PanID.
	if err := ds2.WriteUint16TLV(TLVPanID, 0xDEAD); err != nil {
		t.Fatalf("WriteUint16TLV: %v", err)
	}

	// Merge ds2 into ds1; PanID should be overwritten.
	if err := ds1.WriteTLVsFrom(&ds2); err != nil {
		t.Fatalf("WriteTLVsFrom: %v", err)
	}

	panID, err := ds1.ReadUint16TLV(TLVPanID)
	if err != nil {
		t.Fatalf("ReadUint16TLV: %v", err)
	}
	if panID != 0xDEAD {
		t.Errorf("PanID after merge = %#x, want 0xDEAD", panID)
	}

	if err := ds1.ValidateTLVs(); err != nil {
		t.Errorf("ValidateTLVs after merge: %v", err)
	}
}

func TestDatasetAppendTLVsFrom(t *testing.T) {
	var ds Dataset
	// Append two separate TLVs manually.
	data1 := []byte{0x01, 0x02, 0xfa, 0xce} // PanID
	data2 := []byte{0x05, 0x02, 0xAA, 0xBB} // NetworkKey (short, just for test)

	if err := ds.AppendTLVsFrom(data1); err != nil {
		t.Fatalf("AppendTLVsFrom(1): %v", err)
	}
	if err := ds.AppendTLVsFrom(data2); err != nil {
		t.Fatalf("AppendTLVsFrom(2): %v", err)
	}

	if ds.Length() != 8 {
		t.Errorf("Length = %d, want 8", ds.Length())
	}
	if !ds.ContainsTLV(TLVPanID) {
		t.Error("PanID not found after append")
	}
	if !ds.ContainsTLV(TLVNetworkKey) {
		t.Error("NetworkKey not found after append")
	}
}

func TestDatasetAppendTLVsFromOverflow(t *testing.T) {
	var ds Dataset
	big := make([]byte, DatasetMaxLength)
	if err := ds.SetFrom(big); err != nil {
		t.Fatalf("SetFrom: %v", err)
	}
	if err := ds.AppendTLVsFrom([]byte{0x01}); !errors.Is(err, goterrors.ErrNoBufs) {
		t.Errorf("AppendTLVsFrom on full dataset: got %v, want ErrNoBufs", err)
	}
}

func TestDatasetConvertToInfo(t *testing.T) {
	var ds Dataset
	if err := ds.SetFrom(kTLVBytes); err != nil {
		t.Fatalf("SetFrom: %v", err)
	}

	info := ds.ConvertToInfo()

	// Check components.
	if !info.Components.ActiveTimestamp {
		t.Error("Components.ActiveTimestamp = false")
	}
	if !info.Components.Channel {
		t.Error("Components.Channel = false")
	}
	if !info.Components.ChannelMask {
		t.Error("Components.ChannelMask = false")
	}
	if !info.Components.ExtendedPanID {
		t.Error("Components.ExtendedPanID = false")
	}
	if !info.Components.MeshLocalPrefix {
		t.Error("Components.MeshLocalPrefix = false")
	}
	if !info.Components.NetworkKey {
		t.Error("Components.NetworkKey = false")
	}
	if !info.Components.NetworkName {
		t.Error("Components.NetworkName = false")
	}
	if !info.Components.PanID {
		t.Error("Components.PanID = false")
	}
	if !info.Components.PSKc {
		t.Error("Components.PSKc = false")
	}
	if !info.Components.SecurityPolicy {
		t.Error("Components.SecurityPolicy = false")
	}

	// These should NOT be present.
	if info.Components.PendingTimestamp {
		t.Error("Components.PendingTimestamp = true, want false")
	}
	if info.Components.Delay {
		t.Error("Components.Delay = true, want false")
	}

	// Check specific values.
	if info.PanID != 0xface {
		t.Errorf("PanID = %#x, want 0xface", info.PanID)
	}
	if info.NetworkName != "OpenThread-aac3" {
		t.Errorf("NetworkName = %q, want %q", info.NetworkName, "OpenThread-aac3")
	}

	// ActiveTimestamp: seconds=1, ticks=0, auth=false
	if info.ActiveTimestamp.Seconds() != 1 {
		t.Errorf("ActiveTimestamp.Seconds = %d, want 1", info.ActiveTimestamp.Seconds())
	}
	if info.ActiveTimestamp.Ticks() != 0 {
		t.Errorf("ActiveTimestamp.Ticks = %d, want 0", info.ActiveTimestamp.Ticks())
	}

	// NetworkKey
	wantKey := []byte{0xea, 0xf9, 0x14, 0x9f, 0xdc, 0x73, 0x78, 0x77,
		0x06, 0x98, 0xd5, 0x91, 0x80, 0x22, 0x19, 0x58}
	if !bytes.Equal(info.NetworkKey[:], wantKey) {
		t.Errorf("NetworkKey = %x, want %x", info.NetworkKey, wantKey)
	}

	// ExtendedPanID
	wantExtPanID := []byte{0x1d, 0xe5, 0xbf, 0xec, 0xd5, 0x16, 0x5b, 0x8f}
	if !bytes.Equal(info.ExtendedPanID[:], wantExtPanID) {
		t.Errorf("ExtendedPanID = %x, want %x", info.ExtendedPanID, wantExtPanID)
	}

	// MeshLocalPrefix
	wantMLP := []byte{0xfd, 0xe2, 0x1f, 0x0c, 0x8a, 0x13, 0xe8, 0xe7}
	if !bytes.Equal(info.MeshLocalPrefix[:], wantMLP) {
		t.Errorf("MeshLocalPrefix = %x, want %x", info.MeshLocalPrefix, wantMLP)
	}

	// PSKc
	wantPSKc := []byte{0x2e, 0xaa, 0xe2, 0x94, 0x84, 0x38, 0x8e, 0x31,
		0x19, 0x58, 0x1a, 0x7b, 0x5a, 0x94, 0x8c, 0x07}
	if !bytes.Equal(info.PSKc[:], wantPSKc) {
		t.Errorf("PSKc = %x, want %x", info.PSKc, wantPSKc)
	}
}

func TestDatasetIsSubsetOf(t *testing.T) {
	var ds1, ds2 Dataset
	if err := ds1.SetFrom(kTLVBytes); err != nil {
		t.Fatalf("SetFrom ds1: %v", err)
	}
	if err := ds2.SetFrom(kTLVBytes); err != nil {
		t.Fatalf("SetFrom ds2: %v", err)
	}

	// Same dataset should be a subset of itself.
	if !ds1.IsSubsetOf(&ds2) {
		t.Error("dataset should be subset of itself")
	}

	// Remove a TLV from ds2; ds1 should no longer be a subset.
	ds2.RemoveTLV(TLVNetworkKey)
	if ds1.IsSubsetOf(&ds2) {
		t.Error("ds1 should NOT be subset of ds2 after removing NetworkKey from ds2")
	}
}

func TestDatasetIsSubsetOfIgnoresTimestamps(t *testing.T) {
	var ds1, ds2 Dataset

	// ds1 has PanID + ActiveTimestamp.
	if err := ds1.WriteUint16TLV(TLVPanID, 0xface); err != nil {
		t.Fatalf("WriteUint16TLV: %v", err)
	}
	ts1 := makeTimestamp(100, 0, true)
	if err := ds1.WriteTimestamp(DatasetActive, &ts1); err != nil {
		t.Fatalf("WriteTimestamp: %v", err)
	}

	// ds2 has PanID with same value but different ActiveTimestamp.
	if err := ds2.WriteUint16TLV(TLVPanID, 0xface); err != nil {
		t.Fatalf("WriteUint16TLV: %v", err)
	}
	ts2 := makeTimestamp(999, 0, false)
	if err := ds2.WriteTimestamp(DatasetActive, &ts2); err != nil {
		t.Fatalf("WriteTimestamp: %v", err)
	}

	// ds1 should be a subset of ds2 because timestamps are excluded from comparison.
	if !ds1.IsSubsetOf(&ds2) {
		t.Error("ds1 should be subset of ds2 (timestamps are excluded)")
	}
}

func TestDatasetContainsAllRequiredTLVsFor(t *testing.T) {
	var ds Dataset
	if err := ds.SetFrom(kTLVBytes); err != nil {
		t.Fatalf("SetFrom: %v", err)
	}

	if !ds.ContainsAllRequiredTLVsFor(DatasetActive) {
		t.Error("test vector should contain all required Active TLVs")
	}

	// Missing PendingTimestamp and DelayTimer, so not valid for Pending.
	if ds.ContainsAllRequiredTLVsFor(DatasetPending) {
		t.Error("test vector should NOT contain all required Pending TLVs")
	}
}

func TestDatasetContainsAllRequiredTLVsForPending(t *testing.T) {
	var ds Dataset
	if err := ds.SetFrom(kTLVBytes); err != nil {
		t.Fatalf("SetFrom: %v", err)
	}

	// Add the missing Pending TLVs.
	ts := makeTimestamp(100, 0, true)
	if err := ds.WriteTimestamp(DatasetPending, &ts); err != nil {
		t.Fatalf("WriteTimestamp(Pending): %v", err)
	}
	if err := ds.WriteUint32TLV(TLVDelayTimer, DelayTimerDefault); err != nil {
		t.Fatalf("WriteUint32TLV(DelayTimer): %v", err)
	}

	if !ds.ContainsAllRequiredTLVsFor(DatasetPending) {
		t.Error("dataset should contain all required Pending TLVs")
	}
}

func TestDatasetWriteTLVNoBufs(t *testing.T) {
	var ds Dataset
	// Fill with max data.
	big := make([]byte, DatasetMaxLength)
	if err := ds.SetFrom(big); err != nil {
		t.Fatalf("SetFrom: %v", err)
	}
	// Try to write another TLV.
	err := ds.WriteTLV(TLVPanID, []byte{0x01, 0x02})
	if !errors.Is(err, goterrors.ErrNoBufs) {
		t.Errorf("WriteTLV on full dataset: got %v, want ErrNoBufs", err)
	}
}

func TestDatasetTypeString(t *testing.T) {
	if DatasetActive.String() != "Active" {
		t.Errorf("DatasetActive.String() = %q, want %q", DatasetActive.String(), "Active")
	}
	if DatasetPending.String() != "Pending" {
		t.Errorf("DatasetPending.String() = %q, want %q", DatasetPending.String(), "Pending")
	}
	if DatasetType(99).String() != "DatasetType(99)" {
		t.Errorf("DatasetType(99).String() = %q", DatasetType(99).String())
	}
}

func TestTLVTypeString(t *testing.T) {
	if TLVChannel.String() != "Channel" {
		t.Errorf("TLVChannel.String() = %q, want %q", TLVChannel.String(), "Channel")
	}
	if TLVPanID.String() != "PanID" {
		t.Errorf("TLVPanID.String() = %q, want %q", TLVPanID.String(), "PanID")
	}
	if TLVType(250).String() != "TLVType(250)" {
		t.Errorf("TLVType(250).String() = %q", TLVType(250).String())
	}
}

func TestComponentsIsPresentAndMarkPresent(t *testing.T) {
	var c Components

	comps := []Component{
		ComponentActiveTimestamp,
		ComponentPendingTimestamp,
		ComponentNetworkKey,
		ComponentNetworkName,
		ComponentExtendedPanID,
		ComponentMeshLocalPrefix,
		ComponentDelay,
		ComponentPanID,
		ComponentChannel,
		ComponentWakeupChannel,
		ComponentPSKc,
		ComponentSecurityPolicy,
		ComponentChannelMask,
	}

	// None should be present initially.
	for _, comp := range comps {
		if c.IsPresent(comp) {
			t.Errorf("Component %d should not be present initially", comp)
		}
	}

	// Mark all present.
	for _, comp := range comps {
		c.MarkPresent(comp)
	}

	// All should be present now.
	for _, comp := range comps {
		if !c.IsPresent(comp) {
			t.Errorf("Component %d should be present after MarkPresent", comp)
		}
	}

	// Unknown component should not be present.
	if c.IsPresent(Component(255)) {
		t.Error("unknown component should not be present")
	}
}

func TestDatasetConvertToInfoChannel(t *testing.T) {
	// The channel TLV in kTLVBytes is: 0x00, 0x03, 0x00, 0x00, 0x0f
	// Type=0 (Channel), Length=3, Value={page=0x00, channel=0x000f}
	// So channel should be 15.
	var ds Dataset
	if err := ds.SetFrom(kTLVBytes); err != nil {
		t.Fatalf("SetFrom: %v", err)
	}
	info := ds.ConvertToInfo()
	if info.Channel != 15 {
		t.Errorf("Channel = %d, want 15", info.Channel)
	}
}
