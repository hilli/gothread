// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/thread/key"
)

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

// makeTS creates a valid Timestamp with the given seconds, ticks=0,
// authoritative=true. (Named differently from makeTimestamp in timestamp_test.go
// to avoid redeclaration.)
func makeTS(seconds uint64) Timestamp {
	var ts Timestamp
	ts.SetSeconds(seconds)
	ts.SetTicks(0)
	ts.SetAuthoritative(true)
	return ts
}

// buildMinimalActiveDataset builds a Dataset containing an ActiveTimestamp,
// channel, PAN ID, network key, network name, extended PAN ID, mesh-local
// prefix, PSKc, security policy, and channel mask — the minimum set for an
// Active dataset.
func buildMinimalActiveDataset(activeTS Timestamp) *Dataset {
	info := &Info{}
	info.Components.ActiveTimestamp = true
	info.ActiveTimestamp = activeTS
	info.Components.Channel = true
	info.Channel = 15
	info.Components.PanID = true
	info.PanID = 0xface
	info.Components.NetworkKey = true
	copy(info.NetworkKey[:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	info.Components.NetworkName = true
	info.NetworkName = "TestNet"
	info.Components.ExtendedPanID = true
	copy(info.ExtendedPanID[:], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	info.Components.MeshLocalPrefix = true
	copy(info.MeshLocalPrefix[:], []byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	info.Components.PSKc = true
	copy(info.PSKc[:], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99})
	info.Components.SecurityPolicy = true
	info.SecurityPolicy.SetToDefault()
	info.Components.ChannelMask = true
	info.ChannelMask = 0x07FFF800
	return InfoToDataset(info)
}

// buildMinimalPendingDataset builds a minimal Pending dataset that also has
// a PendingTimestamp and DelayTimer.
func buildMinimalPendingDataset(activeTS, pendingTS Timestamp, delayMs uint32) *Dataset {
	ds := buildMinimalActiveDataset(activeTS)
	tsData, _ := pendingTS.MarshalBinary()
	_ = ds.WriteTLV(TLVPendingTimestamp, tsData)
	_ = ds.WriteUint32TLV(TLVDelayTimer, delayMs)
	return ds
}

// --------------------------------------------------------------------------
// MemoryDatasetStore tests
// --------------------------------------------------------------------------

func TestMemoryDatasetStoreBasic(t *testing.T) {
	store := NewMemoryDatasetStore()

	// Reading non-existent datasets should return ErrNotFound.
	_, err := store.ReadDataset(DatasetActive)
	if !errors.Is(err, goterrors.ErrNotFound) {
		t.Fatalf("ReadDataset(active): got %v, want ErrNotFound", err)
	}
	_, err = store.ReadDataset(DatasetPending)
	if !errors.Is(err, goterrors.ErrNotFound) {
		t.Fatalf("ReadDataset(pending): got %v, want ErrNotFound", err)
	}

	// Save and read back.
	ds := buildMinimalActiveDataset(makeTS(100))
	if err := store.SaveDataset(DatasetActive, ds); err != nil {
		t.Fatalf("SaveDataset: %v", err)
	}
	got, err := store.ReadDataset(DatasetActive)
	if err != nil {
		t.Fatalf("ReadDataset: %v", err)
	}
	if got.Length() != ds.Length() {
		t.Errorf("length: got %d, want %d", got.Length(), ds.Length())
	}

	// Returned dataset should be a copy.
	got.Clear()
	got2, _ := store.ReadDataset(DatasetActive)
	if got2.Length() == 0 {
		t.Error("store returned a reference, not a copy")
	}

	// Delete.
	if err := store.DeleteDataset(DatasetActive); err != nil {
		t.Fatalf("DeleteDataset: %v", err)
	}
	_, err = store.ReadDataset(DatasetActive)
	if !errors.Is(err, goterrors.ErrNotFound) {
		t.Fatalf("after delete: got %v, want ErrNotFound", err)
	}
}

func TestMemoryDatasetStorePending(t *testing.T) {
	store := NewMemoryDatasetStore()
	ds := buildMinimalPendingDataset(makeTS(1), makeTS(1), 60000)
	if err := store.SaveDataset(DatasetPending, ds); err != nil {
		t.Fatalf("SaveDataset: %v", err)
	}
	got, err := store.ReadDataset(DatasetPending)
	if err != nil {
		t.Fatalf("ReadDataset: %v", err)
	}
	if got.Length() != ds.Length() {
		t.Errorf("length: got %d, want %d", got.Length(), ds.Length())
	}
	// Active should still be empty.
	_, err = store.ReadDataset(DatasetActive)
	if !errors.Is(err, goterrors.ErrNotFound) {
		t.Fatalf("active should be ErrNotFound, got %v", err)
	}
}

// --------------------------------------------------------------------------
// DatasetManager basic tests
// --------------------------------------------------------------------------

func TestDatasetManagerNewDefaults(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)

	if dm.Type() != DatasetActive {
		t.Errorf("Type: got %v, want Active", dm.Type())
	}
	if !dm.IsActiveDataset() {
		t.Error("IsActiveDataset should be true")
	}
	if dm.IsPendingDataset() {
		t.Error("IsPendingDataset should be false")
	}
	if dm.LocalSaved() {
		t.Error("LocalSaved should be false")
	}
	if dm.IsMgmtPending() {
		t.Error("IsMgmtPending should be false")
	}
	if ts := dm.GetTimestamp(); ts.IsValid() {
		t.Error("network timestamp should be invalid initially")
	}
	if ts := dm.GetLocalTimestamp(); ts.IsValid() {
		t.Error("local timestamp should be invalid initially")
	}
}

func TestDatasetManagerRestoreEmpty(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)

	err := dm.Restore()
	if !errors.Is(err, goterrors.ErrNotFound) {
		t.Fatalf("Restore empty: got %v, want ErrNotFound", err)
	}
	if ts := dm.GetTimestamp(); ts.IsValid() {
		t.Error("timestamp should remain invalid after empty restore")
	}
}

func TestDatasetManagerSaveAndRestore(t *testing.T) {
	store := NewMemoryDatasetStore()
	var changeCount int
	onChange := func(dt DatasetType) { changeCount++ }
	dm := NewDatasetManager(DatasetActive, store, onChange)

	activeTS := makeTS(100)
	ds := buildMinimalActiveDataset(activeTS)

	// SaveLocal should persist and update timestamps.
	dm.SaveLocal(ds)
	if !dm.LocalSaved() {
		t.Error("LocalSaved should be true after SaveLocal")
	}
	if changeCount != 1 {
		t.Errorf("onChange called %d times, want 1", changeCount)
	}
	localTS := dm.GetLocalTimestamp()
	if !localTS.IsValid() {
		t.Error("local timestamp should be valid")
	}
	if localTS.Seconds() != 100 {
		t.Errorf("local timestamp seconds: got %d, want 100", localTS.Seconds())
	}

	// Restore into a new manager.
	dm2 := NewDatasetManager(DatasetActive, store, nil)
	if err := dm2.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !dm2.LocalSaved() {
		t.Error("LocalSaved should be true after Restore")
	}
	if ts := dm2.GetTimestamp(); ts.Seconds() != 100 {
		t.Errorf("network timestamp after restore: got %d, want 100", ts.Seconds())
	}
}

func TestDatasetManagerSaveLocalFromInfo(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)

	info := &Info{}
	info.Components.ActiveTimestamp = true
	info.ActiveTimestamp = makeTS(42)
	info.Components.Channel = true
	info.Channel = 11
	info.Components.NetworkName = true
	info.NetworkName = "InfoNet"

	dm.SaveLocalFromInfo(info)
	if !dm.LocalSaved() {
		t.Error("should be saved")
	}
	if ts := dm.GetLocalTimestamp(); ts.Seconds() != 42 {
		t.Errorf("seconds: got %d, want 42", ts.Seconds())
	}
}

func TestDatasetManagerClear(t *testing.T) {
	store := NewMemoryDatasetStore()
	var changed bool
	dm := NewDatasetManager(DatasetActive, store, func(dt DatasetType) { changed = true })

	dm.SaveLocal(buildMinimalActiveDataset(makeTS(10)))
	changed = false

	dm.Clear()
	if dm.LocalSaved() {
		t.Error("LocalSaved should be false after Clear")
	}
	if ts := dm.GetTimestamp(); ts.IsValid() {
		t.Error("network timestamp should be invalid after Clear")
	}
	if !changed {
		t.Error("onChange should have been called on Clear")
	}
	_, err := store.ReadDataset(DatasetActive)
	if !errors.Is(err, goterrors.ErrNotFound) {
		t.Fatalf("store should be empty after Clear, got %v", err)
	}
}

func TestDatasetManagerSaveEmpty(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)

	// Save an empty dataset should delete from store.
	dm.SaveLocal(&Dataset{})
	if dm.LocalSaved() {
		t.Error("LocalSaved should be false for empty dataset")
	}
}

func TestDatasetManagerSave(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)

	// Seed with ts=100.
	dm.SaveLocal(buildMinimalActiveDataset(makeTS(100)))

	// Save with newer timestamp should succeed.
	newerDS := buildMinimalActiveDataset(makeTS(200))
	err := dm.Save(newerDS)
	if err != nil {
		t.Fatalf("Save(newer): %v", err)
	}
	if ts := dm.GetTimestamp(); ts.Seconds() != 200 {
		t.Errorf("network timestamp: got %d, want 200", ts.Seconds())
	}

	// Save with older timestamp should return ErrAlready.
	olderDS := buildMinimalActiveDataset(makeTS(50))
	err = dm.Save(olderDS)
	if !errors.Is(err, goterrors.ErrAlready) {
		t.Fatalf("Save(older): got %v, want ErrAlready", err)
	}
}

func TestDatasetManagerSaveWithOptionsAllowOlder(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)

	dm.SaveLocal(buildMinimalActiveDataset(makeTS(100)))

	// Normally older would be rejected.
	olderDS := buildMinimalActiveDataset(makeTS(50))
	err := dm.SaveWithOptions(olderDS, true)
	if err != nil {
		t.Fatalf("SaveWithOptions(allowOlder=true): %v", err)
	}
}

func TestDatasetManagerNeedsSyncWithLeader(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)

	dm.SaveLocal(buildMinimalActiveDataset(makeTS(100)))
	// local=100, network=invalid → local > network → needs sync.
	if !dm.NeedsSyncWithLeader() {
		t.Error("should need sync when local is newer")
	}

	// After Save (which sets network), should not need sync.
	dm.Save(buildMinimalActiveDataset(makeTS(100)))
	if dm.NeedsSyncWithLeader() {
		t.Error("should not need sync when timestamps are equal")
	}
}

func TestDatasetManagerSetMgmtPending(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)

	dm.SetMgmtPending(true)
	if !dm.IsMgmtPending() {
		t.Error("should be pending")
	}
	dm.SetMgmtPending(false)
	if dm.IsMgmtPending() {
		t.Error("should not be pending")
	}
}

// --------------------------------------------------------------------------
// DatasetManager.Read tests
// --------------------------------------------------------------------------

func TestDatasetManagerReadActive(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)

	ds := buildMinimalActiveDataset(makeTS(1))
	// Add pending timestamp and delay timer (should be stripped on Read).
	pendTS := makeTS(2)
	tsData, _ := pendTS.MarshalBinary()
	_ = ds.WriteTLV(TLVPendingTimestamp, tsData)
	_ = ds.WriteUint32TLV(TLVDelayTimer, 60000)
	dm.SaveLocal(ds)

	readDS, err := dm.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if readDS.ContainsTLV(TLVPendingTimestamp) {
		t.Error("Active Read should strip PendingTimestamp")
	}
	if readDS.ContainsTLV(TLVDelayTimer) {
		t.Error("Active Read should strip DelayTimer")
	}
	// Should still have ActiveTimestamp.
	if !readDS.ContainsTLV(TLVActiveTimestamp) {
		t.Error("Active Read should keep ActiveTimestamp")
	}
}

func TestDatasetManagerReadPendingAdjustsDelay(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetPending, store, nil)

	ds := buildMinimalPendingDataset(makeTS(1), makeTS(1), 60000)
	dm.SaveLocal(ds)

	// Wait a short time.
	time.Sleep(50 * time.Millisecond)

	readDS, err := dm.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	delayVal, err := readDS.ReadUint32TLV(TLVDelayTimer)
	if err != nil {
		t.Fatalf("ReadUint32TLV(DelayTimer): %v", err)
	}
	// Delay should be less than original 60000ms.
	if delayVal >= 60000 {
		t.Errorf("delay should be reduced, got %d", delayVal)
	}
	if delayVal == 0 {
		t.Error("delay should not be 0 after only 50ms")
	}
}

func TestDatasetManagerReadInfo(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)

	ts := makeTS(42)
	ds := buildMinimalActiveDataset(ts)
	dm.SaveLocal(ds)

	info, err := dm.ReadInfo()
	if err != nil {
		t.Fatalf("ReadInfo: %v", err)
	}
	if !info.Components.ActiveTimestamp {
		t.Error("ActiveTimestamp should be present")
	}
	if info.ActiveTimestamp.Seconds() != 42 {
		t.Errorf("ActiveTimestamp seconds: got %d, want 42", info.ActiveTimestamp.Seconds())
	}
	if !info.Components.Channel {
		t.Error("Channel should be present")
	}
	if info.Channel != 15 {
		t.Errorf("Channel: got %d, want 15", info.Channel)
	}
}

func TestDatasetManagerReadEmpty(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)

	_, err := dm.Read()
	if !errors.Is(err, goterrors.ErrNotFound) {
		t.Fatalf("Read empty: got %v, want ErrNotFound", err)
	}
}

// --------------------------------------------------------------------------
// ProcessGetRequest tests
// --------------------------------------------------------------------------

func TestProcessGetRequestAll(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)
	dm.SaveLocal(buildMinimalActiveDataset(makeTS(1)))

	result, err := dm.ProcessGetRequest(nil, IgnoreSecurityPolicyFlags)
	if err != nil {
		t.Fatalf("ProcessGetRequest: %v", err)
	}
	if len(result) == 0 {
		t.Error("result should not be empty")
	}

	// Parse the result and check it contains expected TLVs.
	var resultDS Dataset
	if e := resultDS.SetFrom(result); e != nil {
		t.Fatalf("SetFrom result: %v", e)
	}
	if !resultDS.ContainsTLV(TLVActiveTimestamp) {
		t.Error("result should contain ActiveTimestamp")
	}
	if !resultDS.ContainsTLV(TLVChannel) {
		t.Error("result should contain Channel")
	}
	if !resultDS.ContainsTLV(TLVNetworkKey) {
		t.Error("result should contain NetworkKey")
	}
}

func TestProcessGetRequestFiltered(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)
	dm.SaveLocal(buildMinimalActiveDataset(makeTS(1)))

	// Request only Channel and PanID.
	result, err := dm.ProcessGetRequest([]uint8{uint8(TLVChannel), uint8(TLVPanID)}, IgnoreSecurityPolicyFlags)
	if err != nil {
		t.Fatalf("ProcessGetRequest: %v", err)
	}

	var resultDS Dataset
	if e := resultDS.SetFrom(result); e != nil {
		t.Fatalf("SetFrom result: %v", e)
	}
	if !resultDS.ContainsTLV(TLVChannel) {
		t.Error("should contain Channel")
	}
	if !resultDS.ContainsTLV(TLVPanID) {
		t.Error("should contain PanID")
	}
	// Should NOT contain other types.
	if resultDS.ContainsTLV(TLVNetworkKey) {
		t.Error("should not contain NetworkKey when not requested")
	}
}

func TestProcessGetRequestNetworkKeyFiltered(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)
	dm.SaveLocal(buildMinimalActiveDataset(makeTS(1)))

	// With obtainNetKeyOk=false and CheckSecurityPolicyFlags, key should be filtered.
	dm.SetObtainNetworkKeyEnabled(false)
	result, err := dm.ProcessGetRequest(nil, CheckSecurityPolicyFlags)
	if err != nil {
		t.Fatalf("ProcessGetRequest: %v", err)
	}

	var resultDS Dataset
	_ = resultDS.SetFrom(result)
	if resultDS.ContainsTLV(TLVNetworkKey) {
		t.Error("NetworkKey should be filtered when ObtainNetworkKey is disabled")
	}
	if !resultDS.ContainsTLV(TLVChannel) {
		t.Error("Channel should still be present")
	}
}

func TestProcessGetRequestNetworkKeyNotFilteredWhenIgnored(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)
	dm.SaveLocal(buildMinimalActiveDataset(makeTS(1)))
	dm.SetObtainNetworkKeyEnabled(false)

	result, err := dm.ProcessGetRequest(nil, IgnoreSecurityPolicyFlags)
	if err != nil {
		t.Fatalf("ProcessGetRequest: %v", err)
	}

	var resultDS Dataset
	_ = resultDS.SetFrom(result)
	if !resultDS.ContainsTLV(TLVNetworkKey) {
		t.Error("NetworkKey should be present when IgnoreSecurityPolicyFlags")
	}
}

func TestProcessGetRequestEmpty(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)

	// No dataset saved — should return empty result, not error.
	result, err := dm.ProcessGetRequest(nil, IgnoreSecurityPolicyFlags)
	if err != nil {
		t.Fatalf("ProcessGetRequest empty: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d bytes", len(result))
	}
}

func TestProcessGetRequestPendingIncludesDelayTimer(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetPending, store, nil)
	dm.SaveLocal(buildMinimalPendingDataset(makeTS(1), makeTS(1), 60000))

	// Request only Channel — but for pending, DelayTimer should also be included.
	result, err := dm.ProcessGetRequest([]uint8{uint8(TLVChannel)}, IgnoreSecurityPolicyFlags)
	if err != nil {
		t.Fatalf("ProcessGetRequest: %v", err)
	}

	var resultDS Dataset
	_ = resultDS.SetFrom(result)
	if !resultDS.ContainsTLV(TLVChannel) {
		t.Error("should contain Channel")
	}
	if !resultDS.ContainsTLV(TLVDelayTimer) {
		t.Error("Pending GET should always include DelayTimer")
	}
}

// --------------------------------------------------------------------------
// ProcessSetRequest tests
// --------------------------------------------------------------------------

func TestProcessSetRequestValid(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)
	// Seed with ts=100 so incoming ts=200 is newer.
	dm.SaveLocal(buildMinimalActiveDataset(makeTS(100)))

	reqDS := buildMinimalActiveDataset(makeTS(200))
	processed, isComm, affectsConn, affectsKey, err := dm.ProcessSetRequest(
		MgmtSet, reqDS.Bytes(), nil,
		0, false,
		15, 0xface,
		[8]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	)
	if err != nil {
		t.Fatalf("ProcessSetRequest: %v", err)
	}
	if isComm {
		t.Error("should not be from commissioner")
	}
	if affectsConn {
		t.Error("should not affect connectivity (same params)")
	}
	if affectsKey {
		t.Error("should not affect network key")
	}
	if processed == nil {
		t.Fatal("processed dataset should not be nil")
	}
	if !processed.ContainsTLV(TLVActiveTimestamp) {
		t.Error("processed should contain ActiveTimestamp")
	}
}

func TestProcessSetRequestRejectedOlderTimestamp(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)
	dm.SaveLocal(buildMinimalActiveDataset(makeTS(200)))

	// ts=100 is older → should be rejected.
	reqDS := buildMinimalActiveDataset(makeTS(100))
	_, _, _, _, err := dm.ProcessSetRequest(
		MgmtSet, reqDS.Bytes(), nil,
		0, false, 15, 0xface,
		[8]byte{}, [16]byte{},
	)
	if !errors.Is(err, goterrors.ErrRejected) {
		t.Fatalf("expected ErrRejected, got %v", err)
	}
}

func TestProcessSetRequestRejectedEqualTimestamp(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)
	dm.SaveLocal(buildMinimalActiveDataset(makeTS(100)))

	// ts=100 is equal → should be rejected (not strictly newer).
	reqDS := buildMinimalActiveDataset(makeTS(100))
	_, _, _, _, err := dm.ProcessSetRequest(
		MgmtSet, reqDS.Bytes(), nil,
		0, false, 15, 0xface,
		[8]byte{}, [16]byte{},
	)
	if !errors.Is(err, goterrors.ErrRejected) {
		t.Fatalf("expected ErrRejected, got %v", err)
	}
}

func TestProcessSetRequestDetectsChannelChange(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)
	dm.SaveLocal(buildMinimalActiveDataset(makeTS(100)))

	reqDS := buildMinimalActiveDataset(makeTS(200))
	// Current channel is 11, dataset has channel 15 → connectivity change.
	_, _, affectsConn, _, err := dm.ProcessSetRequest(
		MgmtSet, reqDS.Bytes(), nil,
		0, false,
		11, 0xface, // current channel=11
		[8]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	)
	if err != nil {
		t.Fatalf("ProcessSetRequest: %v", err)
	}
	if !affectsConn {
		t.Error("should detect connectivity impact from channel change")
	}
}

func TestProcessSetRequestDetectsPanIDChange(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)
	dm.SaveLocal(buildMinimalActiveDataset(makeTS(100)))

	reqDS := buildMinimalActiveDataset(makeTS(200))
	// Dataset has PanID=0xface, current=0x1234 → connectivity change.
	_, _, affectsConn, _, err := dm.ProcessSetRequest(
		MgmtSet, reqDS.Bytes(), nil,
		0, false,
		15, 0x1234, // different PanID
		[8]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	)
	if err != nil {
		t.Fatalf("ProcessSetRequest: %v", err)
	}
	if !affectsConn {
		t.Error("should detect connectivity impact from PAN ID change")
	}
}

func TestProcessSetRequestDetectsNetworkKeyChange(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)
	dm.SaveLocal(buildMinimalActiveDataset(makeTS(100)))

	reqDS := buildMinimalActiveDataset(makeTS(200))
	_, _, affectsConn, affectsKey, err := dm.ProcessSetRequest(
		MgmtSet, reqDS.Bytes(), nil,
		0, false,
		15, 0xface,
		[8]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		[16]byte{0xFF}, // different key
	)
	if err != nil {
		t.Fatalf("ProcessSetRequest: %v", err)
	}
	if !affectsConn {
		t.Error("network key change should affect connectivity")
	}
	if !affectsKey {
		t.Error("should report network key change")
	}
}

func TestProcessSetRequestCommissionerSessionValid(t *testing.T) {
	store := NewMemoryDatasetStore()
	activeStore := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)
	dm.SaveLocal(buildMinimalActiveDataset(makeTS(100)))

	activeDM := NewDatasetManager(DatasetActive, activeStore, nil)
	activeDM.SaveLocal(buildMinimalActiveDataset(makeTS(100)))

	reqDS := buildMinimalActiveDataset(makeTS(200))
	// Add commissioner session ID TLV.
	_ = reqDS.WriteUint16TLV(TLVCommissionerSessionID, 42)

	_, isComm, _, _, err := dm.ProcessSetRequest(
		MgmtSet, reqDS.Bytes(), activeDM,
		42, true, // session ID matches, commissioner active
		15, 0xface,
		[8]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	)
	if err != nil {
		t.Fatalf("ProcessSetRequest: %v", err)
	}
	if !isComm {
		t.Error("should be from commissioner")
	}
}

func TestProcessSetRequestCommissionerSessionMismatch(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)
	dm.SaveLocal(buildMinimalActiveDataset(makeTS(100)))

	reqDS := buildMinimalActiveDataset(makeTS(200))
	_ = reqDS.WriteUint16TLV(TLVCommissionerSessionID, 42)

	_, _, _, _, err := dm.ProcessSetRequest(
		MgmtSet, reqDS.Bytes(), nil,
		99, true, // wrong session ID
		15, 0xface,
		[8]byte{}, [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	)
	if !errors.Is(err, goterrors.ErrSecurity) {
		t.Fatalf("expected ErrSecurity for session mismatch, got %v", err)
	}
}

func TestProcessSetRequestCommissionerNoCommissioner(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)
	dm.SaveLocal(buildMinimalActiveDataset(makeTS(100)))

	reqDS := buildMinimalActiveDataset(makeTS(200))
	_ = reqDS.WriteUint16TLV(TLVCommissionerSessionID, 42)

	_, _, _, _, err := dm.ProcessSetRequest(
		MgmtSet, reqDS.Bytes(), nil,
		42, false, // commissioner not active
		15, 0xface,
		[8]byte{}, [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	)
	if !errors.Is(err, goterrors.ErrSecurity) {
		t.Fatalf("expected ErrSecurity when no commissioner, got %v", err)
	}
}

func TestProcessSetRequestCommissionerConnectivityRejected(t *testing.T) {
	store := NewMemoryDatasetStore()
	activeStore := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)
	dm.SaveLocal(buildMinimalActiveDataset(makeTS(100)))
	activeDM := NewDatasetManager(DatasetActive, activeStore, nil)
	activeDM.SaveLocal(buildMinimalActiveDataset(makeTS(100)))

	reqDS := buildMinimalActiveDataset(makeTS(200))
	_ = reqDS.WriteUint16TLV(TLVCommissionerSessionID, 42)

	// Commissioner SET on Active with channel change → rejected.
	_, _, _, _, err := dm.ProcessSetRequest(
		MgmtSet, reqDS.Bytes(), activeDM,
		42, true,
		11, 0xface, // current channel 11, dataset has 15 → connectivity change
		[8]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	)
	if !errors.Is(err, goterrors.ErrRejected) {
		t.Fatalf("expected ErrRejected for commissioner connectivity change on active, got %v", err)
	}
}

func TestProcessSetRequestMgmtReplaceNonCommissioner(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)
	dm.SaveLocal(buildMinimalActiveDataset(makeTS(100)))

	reqDS := buildMinimalActiveDataset(makeTS(200))
	_, _, _, _, err := dm.ProcessSetRequest(
		MgmtReplace, reqDS.Bytes(), nil,
		0, false,
		15, 0xface,
		[8]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	)
	if !errors.Is(err, goterrors.ErrRejected) {
		t.Fatalf("MGMT_REPLACE from non-commissioner: expected ErrRejected, got %v", err)
	}
}

func TestProcessSetRequestInvalidTLVs(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)

	// Truncated data.
	_, _, _, _, err := dm.ProcessSetRequest(
		MgmtSet, []byte{0x0e, 0x08, 0x00}, nil,
		0, false, 15, 0xface, [8]byte{}, [16]byte{},
	)
	if !errors.Is(err, goterrors.ErrParse) {
		t.Fatalf("expected ErrParse for truncated data, got %v", err)
	}
}

func TestProcessSetRequestNoActiveTimestamp(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)

	// Dataset with only channel, no ActiveTimestamp.
	var reqDS Dataset
	buf := make([]byte, 3)
	buf[0] = 0
	binary.BigEndian.PutUint16(buf[1:3], 15)
	_ = reqDS.WriteTLV(TLVChannel, buf)

	_, _, _, _, err := dm.ProcessSetRequest(
		MgmtSet, reqDS.Bytes(), nil,
		0, false, 15, 0xface, [8]byte{}, [16]byte{},
	)
	if !errors.Is(err, goterrors.ErrParse) {
		t.Fatalf("expected ErrParse for missing ActiveTimestamp, got %v", err)
	}
}

// --------------------------------------------------------------------------
// ProcessSetRequest on Pending dataset
// --------------------------------------------------------------------------

func TestProcessSetRequestPendingValid(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetPending, store, nil)
	dm.SaveLocal(buildMinimalPendingDataset(makeTS(100), makeTS(100), 60000))

	reqDS := buildMinimalPendingDataset(makeTS(200), makeTS(200), 60000)
	processed, _, _, _, err := dm.ProcessSetRequest(
		MgmtSet, reqDS.Bytes(), nil,
		0, false,
		15, 0xface,
		[8]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	)
	if err != nil {
		t.Fatalf("ProcessSetRequest pending: %v", err)
	}
	if processed == nil {
		t.Fatal("processed should not be nil")
	}
}

func TestProcessSetRequestPendingOlderTimestamp(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetPending, store, nil)
	dm.SaveLocal(buildMinimalPendingDataset(makeTS(200), makeTS(200), 60000))

	// PendingTimestamp=100 <= local=200 → rejected.
	reqDS := buildMinimalPendingDataset(makeTS(200), makeTS(100), 60000)
	_, _, _, _, err := dm.ProcessSetRequest(
		MgmtSet, reqDS.Bytes(), nil,
		0, false, 15, 0xface,
		[8]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	)
	if !errors.Is(err, goterrors.ErrRejected) {
		t.Fatalf("expected ErrRejected for older pending timestamp, got %v", err)
	}
}

func TestProcessSetRequestPendingNoPendingTimestamp(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetPending, store, nil)
	dm.SaveLocal(buildMinimalPendingDataset(makeTS(100), makeTS(100), 60000))

	// Request with ActiveTimestamp only, no PendingTimestamp → ErrParse.
	reqDS := buildMinimalActiveDataset(makeTS(200))
	_, _, _, _, err := dm.ProcessSetRequest(
		MgmtSet, reqDS.Bytes(), nil,
		0, false, 15, 0xface,
		[8]byte{}, [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	)
	if !errors.Is(err, goterrors.ErrParse) {
		t.Fatalf("expected ErrParse for missing PendingTimestamp, got %v", err)
	}
}

func TestProcessSetRequestDelayTimerClamp(t *testing.T) {
	store := NewMemoryDatasetStore()
	dm := NewDatasetManager(DatasetActive, store, nil)
	dm.SaveLocal(buildMinimalActiveDataset(makeTS(100)))

	reqDS := buildMinimalActiveDataset(makeTS(200))
	// Add a delay timer exceeding max.
	_ = reqDS.WriteUint32TLV(TLVDelayTimer, DelayTimerMax+1000)

	processed, _, _, _, err := dm.ProcessSetRequest(
		MgmtSet, reqDS.Bytes(), nil,
		0, false,
		15, 0xface,
		[8]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	)
	if err != nil {
		t.Fatalf("ProcessSetRequest: %v", err)
	}
	delayVal, err := processed.ReadUint32TLV(TLVDelayTimer)
	if err != nil {
		t.Fatalf("ReadUint32TLV: %v", err)
	}
	if delayVal > DelayTimerMax {
		t.Errorf("delay should be clamped to max, got %d", delayVal)
	}
}

// --------------------------------------------------------------------------
// InfoToDataset tests
// --------------------------------------------------------------------------

func TestInfoToDatasetRoundTrip(t *testing.T) {
	info := &Info{}
	info.Components.ActiveTimestamp = true
	info.ActiveTimestamp = makeTS(42)
	info.Components.PendingTimestamp = true
	info.PendingTimestamp = makeTS(43)
	info.Components.NetworkKey = true
	copy(info.NetworkKey[:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	info.Components.NetworkName = true
	info.NetworkName = "GoThread"
	info.Components.ExtendedPanID = true
	copy(info.ExtendedPanID[:], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	info.Components.MeshLocalPrefix = true
	copy(info.MeshLocalPrefix[:], []byte{0xfd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
	info.Components.Delay = true
	info.Delay = 60000
	info.Components.PanID = true
	info.PanID = 0x1234
	info.Components.Channel = true
	info.Channel = 25
	info.Components.WakeupChannel = true
	info.WakeupChannel = 11
	info.Components.PSKc = true
	copy(info.PSKc[:], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99})
	info.Components.SecurityPolicy = true
	info.SecurityPolicy.SetToDefault()
	info.SecurityPolicy.RotationTime = 720
	info.Components.ChannelMask = true
	info.ChannelMask = 0x07FFF800

	ds := InfoToDataset(info)
	if ds.Length() == 0 {
		t.Fatal("dataset should not be empty")
	}

	// Convert back.
	got := ds.ConvertToInfo()

	if !got.Components.ActiveTimestamp {
		t.Error("missing ActiveTimestamp")
	}
	if got.ActiveTimestamp.Seconds() != 42 {
		t.Errorf("ActiveTimestamp seconds: got %d, want 42", got.ActiveTimestamp.Seconds())
	}
	if !got.Components.PendingTimestamp {
		t.Error("missing PendingTimestamp")
	}
	if got.PendingTimestamp.Seconds() != 43 {
		t.Errorf("PendingTimestamp seconds: got %d, want 43", got.PendingTimestamp.Seconds())
	}
	if !got.Components.NetworkKey {
		t.Error("missing NetworkKey")
	}
	if got.NetworkKey != info.NetworkKey {
		t.Error("NetworkKey mismatch")
	}
	if !got.Components.NetworkName || got.NetworkName != "GoThread" {
		t.Errorf("NetworkName: got %q, want GoThread", got.NetworkName)
	}
	if !got.Components.ExtendedPanID || got.ExtendedPanID != info.ExtendedPanID {
		t.Error("ExtendedPanID mismatch")
	}
	if !got.Components.MeshLocalPrefix || got.MeshLocalPrefix != info.MeshLocalPrefix {
		t.Error("MeshLocalPrefix mismatch")
	}
	if !got.Components.Delay || got.Delay != 60000 {
		t.Errorf("Delay: got %d, want 60000", got.Delay)
	}
	if !got.Components.PanID || got.PanID != 0x1234 {
		t.Errorf("PanID: got 0x%04x, want 0x1234", got.PanID)
	}
	if !got.Components.Channel || got.Channel != 25 {
		t.Errorf("Channel: got %d, want 25", got.Channel)
	}
	if !got.Components.WakeupChannel || got.WakeupChannel != 11 {
		t.Errorf("WakeupChannel: got %d, want 11", got.WakeupChannel)
	}
	if !got.Components.PSKc || got.PSKc != info.PSKc {
		t.Error("PSKc mismatch")
	}
	if !got.Components.SecurityPolicy {
		t.Error("missing SecurityPolicy")
	}
	if got.SecurityPolicy.RotationTime != 720 {
		t.Errorf("RotationTime: got %d, want 720", got.SecurityPolicy.RotationTime)
	}
	if !got.Components.ChannelMask || got.ChannelMask != 0x07FFF800 {
		t.Errorf("ChannelMask: got 0x%08x, want 0x07FFF800", got.ChannelMask)
	}
}

func TestInfoToDatasetSecurityPolicyFlags(t *testing.T) {
	info := &Info{}
	info.Components.SecurityPolicy = true
	info.SecurityPolicy.SetToDefault()
	info.SecurityPolicy.ObtainNetworkKeyEnabled = false

	ds := InfoToDataset(info)
	got := ds.ConvertToInfo()
	if got.SecurityPolicy.ObtainNetworkKeyEnabled {
		t.Error("ObtainNetworkKeyEnabled should be false after round-trip")
	}
}

func TestInfoToDatasetPartialComponents(t *testing.T) {
	// Only set Channel.
	info := &Info{}
	info.Components.Channel = true
	info.Channel = 26

	ds := InfoToDataset(info)
	got := ds.ConvertToInfo()

	if !got.Components.Channel || got.Channel != 26 {
		t.Errorf("Channel: got %v/%d, want true/26", got.Components.Channel, got.Channel)
	}
	if got.Components.NetworkKey {
		t.Error("NetworkKey should not be present")
	}
}

// --------------------------------------------------------------------------
// ActiveDatasetManager tests
// --------------------------------------------------------------------------

func TestActiveDatasetManagerIsPartiallyComplete(t *testing.T) {
	store := NewMemoryDatasetStore()
	am := NewActiveDatasetManager(store, nil)

	// Not saved at all → not partially complete.
	if am.IsPartiallyComplete() {
		t.Error("should not be partially complete when nothing saved")
	}

	// SaveLocal but no network timestamp → partially complete.
	am.SaveLocal(buildMinimalActiveDataset(makeTS(1)))
	if !am.IsPartiallyComplete() {
		t.Error("should be partially complete after SaveLocal")
	}

	// After Save (which sets network timestamp) → no longer partially complete.
	am.Save(buildMinimalActiveDataset(makeTS(2)))
	if am.IsPartiallyComplete() {
		t.Error("should not be partially complete after Save sets network timestamp")
	}
}

func TestActiveDatasetManagerIsComplete(t *testing.T) {
	store := NewMemoryDatasetStore()
	am := NewActiveDatasetManager(store, nil)

	if am.IsComplete() {
		t.Error("should not be complete when empty")
	}

	am.SaveLocal(buildMinimalActiveDataset(makeTS(1)))
	if am.IsComplete() {
		t.Error("should not be complete without network timestamp")
	}

	am.Save(buildMinimalActiveDataset(makeTS(2)))
	if !am.IsComplete() {
		t.Error("should be complete after Save")
	}
}

func TestActiveDatasetManagerIsCommissioned(t *testing.T) {
	store := NewMemoryDatasetStore()
	am := NewActiveDatasetManager(store, nil)

	if am.IsCommissioned() {
		t.Error("should not be commissioned when empty")
	}

	am.SaveLocal(buildMinimalActiveDataset(makeTS(1)))
	if !am.IsCommissioned() {
		t.Error("should be commissioned with all required TLVs")
	}

	// Save a dataset missing NetworkKey.
	info := &Info{}
	info.Components.ActiveTimestamp = true
	info.ActiveTimestamp = makeTS(2)
	info.Components.Channel = true
	info.Channel = 15
	info.Components.NetworkName = true
	info.NetworkName = "Partial"
	am.SaveLocal(InfoToDataset(info))
	if am.IsCommissioned() {
		t.Error("should not be commissioned when missing required TLVs")
	}
}

// --------------------------------------------------------------------------
// PendingDatasetManager tests
// --------------------------------------------------------------------------

func TestPendingDatasetManagerDelayTimer(t *testing.T) {
	store := NewMemoryDatasetStore()
	pm := NewPendingDatasetManager(store, nil)

	if pm.IsDelayTimerRunning() {
		t.Error("timer should not be running initially")
	}

	ds := buildMinimalPendingDataset(makeTS(1), makeTS(1), 60000)
	pm.SaveLocal(ds)
	pm.StartDelayTimer(ds)

	if !pm.IsDelayTimerRunning() {
		t.Error("timer should be running after StartDelayTimer")
	}
	if pm.IsDelayTimerExpired() {
		t.Error("timer should not be expired immediately")
	}

	remaining, err := pm.ReadRemainingDelay()
	if err != nil {
		t.Fatalf("ReadRemainingDelay: %v", err)
	}
	if remaining == 0 || remaining > 60000 {
		t.Errorf("remaining: got %d, want 0 < r <= 60000", remaining)
	}
}

func TestPendingDatasetManagerDelayTimerExpiry(t *testing.T) {
	store := NewMemoryDatasetStore()
	pm := NewPendingDatasetManager(store, nil)

	// Use a very short delay.
	ds := buildMinimalPendingDataset(makeTS(100), makeTS(1), 1)
	pm.SaveLocal(ds)
	pm.StartDelayTimer(ds)

	// Wait for expiry.
	time.Sleep(10 * time.Millisecond)

	if !pm.IsDelayTimerExpired() {
		t.Error("timer should be expired")
	}

	remaining, err := pm.ReadRemainingDelay()
	if err != nil {
		t.Fatalf("ReadRemainingDelay: %v", err)
	}
	if remaining != 0 {
		t.Errorf("remaining should be 0, got %d", remaining)
	}
}

func TestPendingDatasetManagerDelayTimerNotRunning(t *testing.T) {
	store := NewMemoryDatasetStore()
	pm := NewPendingDatasetManager(store, nil)

	_, err := pm.ReadRemainingDelay()
	if !errors.Is(err, goterrors.ErrNotFound) {
		t.Fatalf("expected ErrNotFound when timer not running, got %v", err)
	}
}

func TestPendingDatasetManagerDelayTimerClampsMax(t *testing.T) {
	store := NewMemoryDatasetStore()
	pm := NewPendingDatasetManager(store, nil)

	// Build with delay > max.
	ds := buildMinimalPendingDataset(makeTS(1), makeTS(1), DelayTimerMax+1000)
	pm.SaveLocal(ds)
	pm.StartDelayTimer(ds)

	if !pm.IsDelayTimerRunning() {
		t.Error("timer should be running")
	}
	// The remaining delay should not exceed DelayTimerMax.
	remaining, _ := pm.ReadRemainingDelay()
	if remaining > DelayTimerMax {
		t.Errorf("remaining %d exceeds max %d", remaining, DelayTimerMax)
	}
}

func TestPendingDatasetManagerDelayTimerNoTLV(t *testing.T) {
	store := NewMemoryDatasetStore()
	pm := NewPendingDatasetManager(store, nil)

	// Dataset without delay timer TLV.
	ds := buildMinimalActiveDataset(makeTS(1))
	pm.StartDelayTimer(ds)

	if pm.IsDelayTimerRunning() {
		t.Error("timer should not run without DelayTimer TLV")
	}
}

func TestPendingDatasetManagerSetDelayTimerMinimal(t *testing.T) {
	store := NewMemoryDatasetStore()
	pm := NewPendingDatasetManager(store, nil)

	if pm.GetDelayTimerMinimal() != DelayTimerMin {
		t.Errorf("default minimal: got %d, want %d", pm.GetDelayTimerMinimal(), DelayTimerMin)
	}

	// Set a valid minimal value (must be > 0 and < DelayTimerMin).
	err := pm.SetDelayTimerMinimal(1000)
	if err != nil {
		t.Fatalf("SetDelayTimerMinimal(1000): %v", err)
	}
	if pm.GetDelayTimerMinimal() != 1000 {
		t.Errorf("minimal: got %d, want 1000", pm.GetDelayTimerMinimal())
	}

	// Invalid: 0.
	if err := pm.SetDelayTimerMinimal(0); !errors.Is(err, goterrors.ErrInvalidArgs) {
		t.Errorf("SetDelayTimerMinimal(0): got %v, want ErrInvalidArgs", err)
	}

	// Invalid: >= DelayTimerMin.
	if err := pm.SetDelayTimerMinimal(DelayTimerMin); !errors.Is(err, goterrors.ErrInvalidArgs) {
		t.Errorf("SetDelayTimerMinimal(DelayTimerMin): got %v, want ErrInvalidArgs", err)
	}
}

func TestPendingDatasetManagerHandleDelayTimerExpired(t *testing.T) {
	store := NewMemoryDatasetStore()
	pm := NewPendingDatasetManager(store, nil)

	activeTS := makeTS(100)
	pendingActiveTS := makeTS(200) // newer → should replace
	ds := buildMinimalPendingDataset(pendingActiveTS, makeTS(1), 1)
	pm.SaveLocal(ds)
	pm.StartDelayTimer(ds)

	time.Sleep(10 * time.Millisecond)

	currentKey := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	result := pm.HandleDelayTimerExpired(&activeTS, currentKey)
	if result == nil {
		t.Fatal("expected non-nil result (pending active TS is newer)")
	}

	// Result should not contain PendingTimestamp or DelayTimer.
	if result.ContainsTLV(TLVPendingTimestamp) {
		t.Error("result should not contain PendingTimestamp")
	}
	if result.ContainsTLV(TLVDelayTimer) {
		t.Error("result should not contain DelayTimer")
	}
	// But should contain ActiveTimestamp.
	if !result.ContainsTLV(TLVActiveTimestamp) {
		t.Error("result should contain ActiveTimestamp")
	}

	// Timer should no longer be running.
	if pm.IsDelayTimerRunning() {
		t.Error("timer should stop after HandleDelayTimerExpired")
	}
}

func TestPendingDatasetManagerHandleDelayTimerExpiredOlderTimestamp(t *testing.T) {
	store := NewMemoryDatasetStore()
	pm := NewPendingDatasetManager(store, nil)

	activeTS := makeTS(200)
	pendingActiveTS := makeTS(100) // older → should NOT replace
	ds := buildMinimalPendingDataset(pendingActiveTS, makeTS(1), 1)
	pm.SaveLocal(ds)
	pm.StartDelayTimer(ds)

	time.Sleep(10 * time.Millisecond)

	currentKey := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	result := pm.HandleDelayTimerExpired(&activeTS, currentKey)
	if result != nil {
		t.Error("should return nil when pending active TS is older")
	}
}

func TestPendingDatasetManagerHandleDelayTimerExpiredKeyChange(t *testing.T) {
	store := NewMemoryDatasetStore()
	pm := NewPendingDatasetManager(store, nil)

	activeTS := makeTS(200) // same as pending active TS
	pendingActiveTS := makeTS(200)
	ds := buildMinimalPendingDataset(pendingActiveTS, makeTS(1), 1)
	pm.SaveLocal(ds)
	pm.StartDelayTimer(ds)

	time.Sleep(10 * time.Millisecond)

	// Different current key → should replace even with equal timestamp.
	differentKey := [16]byte{0xFF}
	result := pm.HandleDelayTimerExpired(&activeTS, differentKey)
	if result == nil {
		t.Fatal("should replace when network key differs")
	}
}

func TestPendingDatasetManagerReadActiveTimestamp(t *testing.T) {
	store := NewMemoryDatasetStore()
	pm := NewPendingDatasetManager(store, nil)

	ds := buildMinimalPendingDataset(makeTS(42), makeTS(1), 60000)
	pm.SaveLocal(ds)

	ts, err := pm.ReadActiveTimestamp()
	if err != nil {
		t.Fatalf("ReadActiveTimestamp: %v", err)
	}
	if ts.Seconds() != 42 {
		t.Errorf("seconds: got %d, want 42", ts.Seconds())
	}
}

func TestPendingDatasetManagerReadActiveTimestampEmpty(t *testing.T) {
	store := NewMemoryDatasetStore()
	pm := NewPendingDatasetManager(store, nil)

	_, err := pm.ReadActiveTimestamp()
	if !errors.Is(err, goterrors.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// --------------------------------------------------------------------------
// SecurityPolicy GetFlags in InfoToDataset verification
// --------------------------------------------------------------------------

func TestInfoToDatasetSecurityPolicyGetFlags(t *testing.T) {
	// Verify that GetFlags is called correctly (fills buffer).
	var sp key.SecurityPolicy
	sp.SetToDefault()
	sp.ObtainNetworkKeyEnabled = true
	sp.NativeCommissioningEnabled = true
	sp.RoutersEnabled = true
	sp.ExternalCommissioningEnabled = true

	flags := make([]byte, 2)
	sp.GetFlags(flags)

	// flags[0] should have ObtainNetworkKey, NativeCommissioning, Routers,
	// ExternalCommissioning set.
	if flags[0]&(1<<7) == 0 {
		t.Error("ObtainNetworkKey flag not set")
	}
	if flags[0]&(1<<6) == 0 {
		t.Error("NativeCommissioning flag not set")
	}

	// Round-trip through InfoToDataset.
	info := &Info{}
	info.Components.SecurityPolicy = true
	info.SecurityPolicy = sp

	ds := InfoToDataset(info)
	got := ds.ConvertToInfo()
	if !got.SecurityPolicy.ObtainNetworkKeyEnabled {
		t.Error("ObtainNetworkKeyEnabled lost in round-trip")
	}
	if !got.SecurityPolicy.NativeCommissioningEnabled {
		t.Error("NativeCommissioningEnabled lost in round-trip")
	}
}
