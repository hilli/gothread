// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"encoding/binary"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/tlv"
)

// DatasetStore is the interface for persistent storage of operational datasets.
// Implementations provide non-volatile storage for Active and Pending datasets.
type DatasetStore interface {
	// ReadDataset reads the dataset of the given type from storage.
	// Returns ErrNotFound if no dataset is stored.
	ReadDataset(dt DatasetType) (*Dataset, error)

	// SaveDataset saves the dataset of the given type to storage.
	SaveDataset(dt DatasetType, ds *Dataset) error

	// DeleteDataset removes the dataset of the given type from storage.
	DeleteDataset(dt DatasetType) error
}

// DatasetChangeHandler is called when a dataset is modified.
type DatasetChangeHandler func(dt DatasetType)

// MgmtSetCallback is a callback for MGMT_SET response processing.
type MgmtSetCallback func(err error)

// SecurityPolicyCheckMode controls whether network key filtering is applied
// during MGMT_GET response construction.
type SecurityPolicyCheckMode uint8

const (
	// CheckSecurityPolicyFlags checks the security policy to decide whether
	// to include the network key in GET responses.
	CheckSecurityPolicyFlags SecurityPolicyCheckMode = iota
	// IgnoreSecurityPolicyFlags always includes the network key in GET responses.
	IgnoreSecurityPolicyFlags
)

// MgmtCommand identifies the management command type.
type MgmtCommand uint8

const (
	// MgmtSet is a MGMT_SET command.
	MgmtSet MgmtCommand = iota
	// MgmtReplace is a MGMT_REPLACE command (active dataset only, from commissioner).
	MgmtReplace
)

// DatasetManager manages a single operational dataset (Active or Pending).
//
// It tracks local and network timestamps, handles local save/restore,
// processes MGMT_GET requests, and prepares MGMT_SET request payloads.
// The manager does not directly interact with CoAP or the network — those
// responsibilities belong to the caller (e.g., TMF handlers).
type DatasetManager struct {
	datasetType      DatasetType
	localSaved       bool
	mgmtPending      bool
	localTimestamp   Timestamp
	networkTimestamp Timestamp
	localUpdateTime  time.Time
	store            DatasetStore
	onChange         DatasetChangeHandler
	obtainNetKeyOk   bool // reflects security policy for GET filtering
}

// NewDatasetManager creates a new DatasetManager for the given dataset type.
// store provides persistent storage; onChange is called on dataset mutations
// (may be nil).
func NewDatasetManager(dt DatasetType, store DatasetStore, onChange DatasetChangeHandler) *DatasetManager {
	dm := &DatasetManager{
		datasetType:    dt,
		store:          store,
		onChange:       onChange,
		obtainNetKeyOk: true, // default: allow network key in GET responses
	}
	dm.localTimestamp.SetToInvalid()
	dm.networkTimestamp.SetToInvalid()
	return dm
}

// Type returns the dataset type (Active or Pending).
func (dm *DatasetManager) Type() DatasetType {
	return dm.datasetType
}

// IsActiveDataset reports whether this manages the Active dataset.
func (dm *DatasetManager) IsActiveDataset() bool {
	return dm.datasetType == DatasetActive
}

// IsPendingDataset reports whether this manages the Pending dataset.
func (dm *DatasetManager) IsPendingDataset() bool {
	return dm.datasetType == DatasetPending
}

// LocalSaved reports whether a local dataset has been saved.
func (dm *DatasetManager) LocalSaved() bool {
	return dm.localSaved
}

// GetTimestamp returns a copy of the network timestamp.
func (dm *DatasetManager) GetTimestamp() Timestamp {
	return dm.networkTimestamp
}

// GetLocalTimestamp returns a copy of the local timestamp.
func (dm *DatasetManager) GetLocalTimestamp() Timestamp {
	return dm.localTimestamp
}

// SetObtainNetworkKeyEnabled controls whether the network key is included
// in MGMT_GET responses when CheckSecurityPolicyFlags mode is used.
func (dm *DatasetManager) SetObtainNetworkKeyEnabled(enabled bool) {
	dm.obtainNetKeyOk = enabled
}

// IsMgmtPending reports whether a MGMT_SET is currently pending a response.
func (dm *DatasetManager) IsMgmtPending() bool {
	return dm.mgmtPending
}

// SetMgmtPending sets the management pending flag.
func (dm *DatasetManager) SetMgmtPending(pending bool) {
	dm.mgmtPending = pending
}

// Restore reads the dataset from persistent storage and restores timestamps.
// Returns ErrNotFound if no dataset is stored (but timestamps are still cleared).
func (dm *DatasetManager) Restore() error {
	ds, err := dm.store.ReadDataset(dm.datasetType)
	if err != nil {
		dm.networkTimestamp.SetToInvalid()
		dm.localTimestamp.SetToInvalid()
		return err
	}
	dm.RestoreFromDataset(ds)
	return nil
}

// RestoreFromDataset restores the manager state from an in-memory dataset.
func (dm *DatasetManager) RestoreFromDataset(ds *Dataset) {
	dm.networkTimestamp.SetToInvalid()
	dm.localTimestamp.SetToInvalid()

	if ds == nil || ds.Length() == 0 {
		return
	}

	dm.localSaved = true

	ts, err := ds.ReadTimestamp(dm.datasetType)
	if err == nil {
		dm.localTimestamp = *ts
		dm.networkTimestamp = *ts
	}
}

// Read reads the current dataset from persistent storage.
// For Active datasets, Pending Timestamp and Delay Timer TLVs are removed.
// For Pending datasets, the Delay Timer value is adjusted to reflect
// remaining delay since the last local update.
func (dm *DatasetManager) Read() (*Dataset, error) {
	ds, err := dm.store.ReadDataset(dm.datasetType)
	if err != nil {
		return nil, err
	}

	if dm.IsActiveDataset() {
		ds.RemoveTLV(TLVPendingTimestamp)
		ds.RemoveTLV(TLVDelayTimer)
	} else {
		// Adjust delay timer to remaining time.
		delayTLV := ds.FindTLV(TLVDelayTimer)
		if delayTLV != nil && len(delayTLV.Value) >= 4 {
			originalDelay := binary.BigEndian.Uint32(delayTLV.Value[:4])
			remaining := dm.calculateRemainingDelay(originalDelay)
			_ = ds.WriteUint32TLV(TLVDelayTimer, remaining)
		}
	}

	return ds, nil
}

// ReadInfo reads the current dataset and converts it to a structured Info.
func (dm *DatasetManager) ReadInfo() (*Info, error) {
	ds, err := dm.Read()
	if err != nil {
		return nil, err
	}
	info := ds.ConvertToInfo()
	return &info, nil
}

// calculateRemainingDelay computes the remaining delay based on elapsed time
// since the dataset was last updated locally.
func (dm *DatasetManager) calculateRemainingDelay(originalDelay uint32) uint32 {
	if dm.localUpdateTime.IsZero() {
		return originalDelay
	}
	elapsed := time.Since(dm.localUpdateTime)
	elapsedMs := uint32(elapsed.Milliseconds())
	if elapsedMs >= originalDelay {
		return 0
	}
	return originalDelay - elapsedMs
}

// Clear invalidates timestamps, deletes the stored dataset, and signals change.
func (dm *DatasetManager) Clear() {
	dm.networkTimestamp.SetToInvalid()
	dm.localTimestamp.SetToInvalid()
	dm.localSaved = false
	_ = dm.store.DeleteDataset(dm.datasetType)
	dm.signalChange()
}

// Save sets the dataset for the partition. If the new dataset's timestamp
// is newer than the local one, it is saved locally. If older, the caller
// should schedule a sync timer.
//
// Returns:
//   - nil if saved successfully
//   - ErrAlready if the network timestamp is older (caller should sync)
//   - other errors on failure
func (dm *DatasetManager) Save(ds *Dataset) error {
	return dm.SaveWithOptions(ds, false)
}

// SaveWithOptions saves the dataset with optional timestamp override.
// If allowOlderTimestamp is true, the dataset is saved regardless of
// timestamp comparison.
func (dm *DatasetManager) SaveWithOptions(ds *Dataset, allowOlderTimestamp bool) error {
	// Update network timestamp from the dataset.
	ts, err := ds.ReadTimestamp(dm.datasetType)
	if err == nil {
		dm.networkTimestamp = *ts
	}

	cmp := Compare(&dm.networkTimestamp, &dm.localTimestamp)

	if cmp > 0 || allowOlderTimestamp {
		dm.localSave(ds)
		dm.signalChange()
		return nil
	} else if cmp < 0 {
		dm.signalChange()
		return goterrors.ErrAlready
	}

	dm.signalChange()
	return nil
}

// SaveLocal saves the dataset locally (for use by API callers setting
// the dataset from the application layer).
func (dm *DatasetManager) SaveLocal(ds *Dataset) {
	dm.localSave(ds)
	dm.signalChange()
}

// SaveLocalFromInfo saves a dataset constructed from a structured Info.
func (dm *DatasetManager) SaveLocalFromInfo(info *Info) {
	ds := InfoToDataset(info)
	dm.SaveLocal(ds)
}

// localSave persists the dataset and updates local timestamps.
func (dm *DatasetManager) localSave(ds *Dataset) {
	if ds.Length() == 0 {
		_ = dm.store.DeleteDataset(dm.datasetType)
		dm.localSaved = false
	} else {
		_ = dm.store.SaveDataset(dm.datasetType, ds)
		dm.localSaved = true
	}

	ts, err := ds.ReadTimestamp(dm.datasetType)
	if err == nil {
		dm.localTimestamp = *ts
	} else {
		dm.localTimestamp.SetToInvalid()
	}

	dm.localUpdateTime = time.Now()
}

// NeedsSyncWithLeader reports whether the local dataset is newer than the
// network dataset and should be sent to the leader via MGMT_SET.
func (dm *DatasetManager) NeedsSyncWithLeader() bool {
	return Compare(&dm.localTimestamp, &dm.networkTimestamp) > 0
}

// signalChange invokes the change handler if set.
func (dm *DatasetManager) signalChange() {
	if dm.onChange != nil {
		dm.onChange(dm.datasetType)
	}
}

// ProcessGetRequest processes a MGMT_GET request and returns the response
// dataset bytes. The requestTLVTypes parameter lists the TLV types requested;
// if empty, all TLVs are returned. The checkMode parameter controls whether
// the network key is filtered based on security policy.
func (dm *DatasetManager) ProcessGetRequest(requestTLVTypes []uint8, checkMode SecurityPolicyCheckMode) ([]byte, error) {
	ds, _ := dm.Read() // Ignore error; respond with empty dataset if none saved.
	if ds == nil {
		ds = &Dataset{}
	}

	parsed, err := tlv.ParseAll(ds.Bytes())
	if err != nil {
		return nil, goterrors.ErrParse
	}

	// Build a set of requested types for quick lookup.
	typeSet := make(map[uint8]bool)
	for _, t := range requestTLVTypes {
		typeSet[t] = true
	}

	// For pending dataset GET, always include Delay Timer.
	if len(typeSet) > 0 && dm.IsPendingDataset() {
		typeSet[uint8(TLVDelayTimer)] = true
	}

	var result []byte
	for _, t := range parsed {
		shouldAppend := true

		if len(typeSet) > 0 {
			shouldAppend = typeSet[t.Type]
		}

		// Filter network key based on security policy.
		if checkMode == CheckSecurityPolicyFlags &&
			TLVType(t.Type) == TLVNetworkKey &&
			!dm.obtainNetKeyOk {
			shouldAppend = false
		}

		if shouldAppend {
			result = append(result, t.Type, uint8(len(t.Value)))
			result = append(result, t.Value...)
		}
	}

	return result, nil
}

// ProcessSetRequest validates and processes a MGMT_SET request payload.
// Returns the processed dataset ready for saving, and request metadata.
//
// Parameters:
//   - command: MgmtSet or MgmtReplace
//   - requestData: raw TLV bytes from the request message
//   - activeManager: reference to the active dataset manager (for reading
//     the base active dataset when merging partial SET requests from a commissioner)
//
// Returns:
//   - processedDataset: the resulting dataset to be saved
//   - isFromCommissioner: whether the request came from a commissioner
//   - affectsConnectivity: whether the request changes connectivity params
//   - error: non-nil if the request should be rejected
func (dm *DatasetManager) ProcessSetRequest(
	command MgmtCommand,
	requestData []byte,
	activeManager *DatasetManager,
	localCommissionerSessionID uint16,
	hasCommissioner bool,
	currentChannel uint16,
	currentPanID uint16,
	currentMeshLocalPrefix [8]byte,
	currentNetworkKey [16]byte,
) (processedDataset *Dataset, isFromCommissioner, affectsConnectivity, affectsNetworkKey bool, err error) {

	// Parse the incoming request TLVs into a dataset.
	var reqDS Dataset
	if e := reqDS.SetFrom(requestData); e != nil {
		err = goterrors.ErrParse
		return
	}
	if e := reqDS.ValidateTLVs(); e != nil {
		err = goterrors.ErrParse
		return
	}

	// Verify active timestamp is present and newer.
	activeTS, e := reqDS.ReadTimestamp(DatasetActive)
	if e != nil {
		err = goterrors.ErrParse
		return
	}

	if dm.IsPendingDataset() {
		pendingTS, e2 := reqDS.ReadTimestamp(DatasetPending)
		if e2 != nil {
			err = goterrors.ErrParse
			return
		}
		if Compare(pendingTS, &dm.localTimestamp) <= 0 {
			err = goterrors.ErrRejected
			return
		}
	} else if Compare(activeTS, &dm.localTimestamp) <= 0 {
		err = goterrors.ErrRejected
		return
	}

	// Check connectivity impact.
	channelTLV := reqDS.FindTLV(TLVChannel)
	if channelTLV != nil && len(channelTLV.Value) >= 3 {
		ch := binary.BigEndian.Uint16(channelTLV.Value[1:3])
		if ch != currentChannel {
			affectsConnectivity = true
		}
	}

	panIDTLV := reqDS.FindTLV(TLVPanID)
	if panIDTLV != nil && len(panIDTLV.Value) >= 2 {
		pid := binary.BigEndian.Uint16(panIDTLV.Value[:2])
		if pid != currentPanID {
			affectsConnectivity = true
		}
	}

	meshPrefixTLV := reqDS.FindTLV(TLVMeshLocalPrefix)
	if meshPrefixTLV != nil && len(meshPrefixTLV.Value) >= 8 {
		var prefix [8]byte
		copy(prefix[:], meshPrefixTLV.Value[:8])
		if prefix != currentMeshLocalPrefix {
			affectsConnectivity = true
		}
	}

	netKeyTLV := reqDS.FindTLV(TLVNetworkKey)
	if netKeyTLV != nil && len(netKeyTLV.Value) >= 16 {
		var nk [16]byte
		copy(nk[:], netKeyTLV.Value[:16])
		if nk != currentNetworkKey {
			affectsConnectivity = true
			affectsNetworkKey = true
		}
	}

	// Active timestamp rollback check for pending: if no network key change,
	// active timestamp must be ahead of current active timestamp.
	if dm.IsPendingDataset() && !affectsNetworkKey && activeManager != nil {
		activeNetTS := activeManager.GetTimestamp()
		if Compare(activeTS, &activeNetTS) <= 0 {
			err = goterrors.ErrRejected
			return
		}
	}

	// Check commissioner session ID.
	sessionTLV := reqDS.FindTLV(TLVCommissionerSessionID)
	if sessionTLV != nil && len(sessionTLV.Value) >= 2 {
		isFromCommissioner = true
		reqSessionID := binary.BigEndian.Uint16(sessionTLV.Value[:2])
		reqDS.RemoveTLV(TLVCommissionerSessionID)

		if !hasCommissioner || reqSessionID != localCommissionerSessionID {
			err = goterrors.ErrSecurity
			return
		}

		// Commissioner SET on active dataset must not affect connectivity.
		if dm.IsActiveDataset() && affectsConnectivity {
			err = goterrors.ErrRejected
			return
		}

		// Partial update from commissioner: merge onto current active dataset.
		if command == MgmtSet && activeManager != nil {
			baseDS, readErr := activeManager.Read()
			if readErr == nil {
				processedDataset = baseDS
			}
		}
	}

	if command == MgmtReplace {
		// MGMT_REPLACE: must be from commissioner, active only, and complete.
		if !isFromCommissioner {
			err = goterrors.ErrRejected
			return
		}
		if !dm.IsActiveDataset() {
			err = goterrors.ErrRejected
			return
		}
		if !reqDS.ContainsAllRequiredTLVsFor(DatasetActive) {
			err = goterrors.ErrRejected
			return
		}
	}

	// Merge request TLVs into the base dataset.
	if processedDataset == nil {
		processedDataset = &Dataset{}
	}
	if mergeErr := processedDataset.WriteTLVsFrom(&reqDS); mergeErr != nil {
		err = mergeErr
		return
	}

	// Check and update delay timer.
	delayVal, delayErr := processedDataset.ReadUint32TLV(TLVDelayTimer)
	if delayErr == nil {
		if delayVal > DelayTimerMax {
			delayVal = DelayTimerMax
		}
		if affectsNetworkKey && delayVal < DelayTimerDefault {
			delayVal = DelayTimerDefault
		}
		if delayVal < DelayTimerMin {
			delayVal = DelayTimerMin
		}
		_ = processedDataset.WriteUint32TLV(TLVDelayTimer, delayVal)
	}

	return
}

// InfoToDataset converts a structured Info into a Dataset with TLV encoding.
func InfoToDataset(info *Info) *Dataset {
	ds := &Dataset{}

	if info.Components.ActiveTimestamp {
		data, _ := info.ActiveTimestamp.MarshalBinary()
		_ = ds.WriteTLV(TLVActiveTimestamp, data)
	}

	if info.Components.PendingTimestamp {
		data, _ := info.PendingTimestamp.MarshalBinary()
		_ = ds.WriteTLV(TLVPendingTimestamp, data)
	}

	if info.Components.NetworkKey {
		_ = ds.WriteTLV(TLVNetworkKey, info.NetworkKey[:])
	}

	if info.Components.NetworkName {
		_ = ds.WriteTLV(TLVNetworkName, []byte(info.NetworkName))
	}

	if info.Components.ExtendedPanID {
		_ = ds.WriteTLV(TLVExtendedPanID, info.ExtendedPanID[:])
	}

	if info.Components.MeshLocalPrefix {
		_ = ds.WriteTLV(TLVMeshLocalPrefix, info.MeshLocalPrefix[:])
	}

	if info.Components.Delay {
		_ = ds.WriteUint32TLV(TLVDelayTimer, info.Delay)
	}

	if info.Components.PanID {
		_ = ds.WriteUint16TLV(TLVPanID, info.PanID)
	}

	if info.Components.Channel {
		// Channel TLV: 1 byte page (0) + 2 bytes channel.
		buf := make([]byte, 3)
		buf[0] = 0 // page 0
		binary.BigEndian.PutUint16(buf[1:3], info.Channel)
		_ = ds.WriteTLV(TLVChannel, buf)
	}

	if info.Components.WakeupChannel {
		buf := make([]byte, 3)
		buf[0] = 0
		binary.BigEndian.PutUint16(buf[1:3], info.WakeupChannel)
		_ = ds.WriteTLV(TLVWakeupChannel, buf)
	}

	if info.Components.PSKc {
		_ = ds.WriteTLV(TLVPSKc, info.PSKc[:])
	}

	if info.Components.SecurityPolicy {
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, info.SecurityPolicy.RotationTime)
		flags := make([]byte, 2)
		info.SecurityPolicy.GetFlags(flags)
		buf = append(buf, flags...)
		_ = ds.WriteTLV(TLVSecurityPolicy, buf)
	}

	if info.Components.ChannelMask {
		// Channel Mask TLV: page(1) + maskLen(1) + mask(4).
		buf := make([]byte, 6)
		buf[0] = 0 // page 0
		buf[1] = 4 // mask length
		binary.BigEndian.PutUint32(buf[2:6], info.ChannelMask)
		_ = ds.WriteTLV(TLVChannelMask, buf)
	}

	return ds
}

// ActiveDatasetManager extends DatasetManager with Active dataset specifics.
type ActiveDatasetManager struct {
	*DatasetManager
}

// NewActiveDatasetManager creates a new Active dataset manager.
func NewActiveDatasetManager(store DatasetStore, onChange DatasetChangeHandler) *ActiveDatasetManager {
	return &ActiveDatasetManager{
		DatasetManager: NewDatasetManager(DatasetActive, store, onChange),
	}
}

// IsPartiallyComplete reports whether the Active dataset is locally saved
// but does not have a valid network timestamp (i.e., not yet committed to
// the partition).
func (am *ActiveDatasetManager) IsPartiallyComplete() bool {
	return am.localSaved && !am.networkTimestamp.IsValid()
}

// IsComplete reports whether the Active dataset is locally saved and has
// a valid network timestamp.
func (am *ActiveDatasetManager) IsComplete() bool {
	return am.localSaved && am.networkTimestamp.IsValid()
}

// IsCommissioned reports whether the Active dataset contains all the TLVs
// required for a commissioned Thread device.
func (am *ActiveDatasetManager) IsCommissioned() bool {
	ds, err := am.Read()
	if err != nil {
		return false
	}
	requiredTypes := []TLVType{
		TLVNetworkKey, TLVNetworkName, TLVExtendedPanID, TLVPanID, TLVChannel,
	}
	for _, t := range requiredTypes {
		if !ds.ContainsTLV(t) {
			return false
		}
	}
	return true
}

// PendingDatasetManager extends DatasetManager with Pending dataset specifics.
type PendingDatasetManager struct {
	*DatasetManager
	delayTimerMinimal uint32
	delayExpiry       time.Time // When the delay timer expires.
	delayTimerRunning bool
}

// NewPendingDatasetManager creates a new Pending dataset manager.
func NewPendingDatasetManager(store DatasetStore, onChange DatasetChangeHandler) *PendingDatasetManager {
	return &PendingDatasetManager{
		DatasetManager:    NewDatasetManager(DatasetPending, store, onChange),
		delayTimerMinimal: DelayTimerMin,
	}
}

// GetDelayTimerMinimal returns the minimum delay timer value.
func (pm *PendingDatasetManager) GetDelayTimerMinimal() uint32 {
	return pm.delayTimerMinimal
}

// SetDelayTimerMinimal sets the minimum delay timer value.
// Returns ErrInvalidArgs if the value is 0 or >= DelayTimerMin.
func (pm *PendingDatasetManager) SetDelayTimerMinimal(delay uint32) error {
	if delay == 0 || delay >= DelayTimerMin {
		return goterrors.ErrInvalidArgs
	}
	pm.delayTimerMinimal = delay
	return nil
}

// StartDelayTimer starts the delay timer based on the dataset's Delay Timer TLV.
func (pm *PendingDatasetManager) StartDelayTimer(ds *Dataset) {
	pm.delayTimerRunning = false

	delayTLV := ds.FindTLV(TLVDelayTimer)
	if delayTLV == nil || len(delayTLV.Value) < 4 {
		return
	}

	delay := binary.BigEndian.Uint32(delayTLV.Value[:4])
	if delay > DelayTimerMax {
		delay = DelayTimerMax
	}

	pm.delayExpiry = time.Now().Add(time.Duration(delay) * time.Millisecond)
	pm.delayTimerRunning = true
}

// IsDelayTimerRunning reports whether the delay timer is currently running.
func (pm *PendingDatasetManager) IsDelayTimerRunning() bool {
	return pm.delayTimerRunning
}

// ReadRemainingDelay returns the remaining delay in milliseconds.
// Returns ErrNotFound if the delay timer is not running.
func (pm *PendingDatasetManager) ReadRemainingDelay() (uint32, error) {
	if !pm.delayTimerRunning {
		return 0, goterrors.ErrNotFound
	}
	remaining := time.Until(pm.delayExpiry)
	if remaining <= 0 {
		return 0, nil
	}
	return uint32(remaining.Milliseconds()), nil
}

// IsDelayTimerExpired reports whether the delay timer has expired.
func (pm *PendingDatasetManager) IsDelayTimerExpired() bool {
	return pm.delayTimerRunning && time.Now().After(pm.delayExpiry)
}

// HandleDelayTimerExpired processes the delay timer expiry, converting the
// Pending dataset to Active. Returns the dataset to be applied as the new
// Active dataset, or nil if conversion should not occur.
//
// Parameters:
//   - activeTimestamp: the current Active dataset's network timestamp
//   - currentNetworkKey: the current network key for comparison
//
// After calling this, the caller should Clear() the Pending dataset manager.
func (pm *PendingDatasetManager) HandleDelayTimerExpired(
	activeTimestamp *Timestamp,
	currentNetworkKey [16]byte,
) *Dataset {
	pm.delayTimerRunning = false

	ds, err := pm.Read()
	if err != nil {
		return nil
	}

	// Read the Active Timestamp from the pending dataset.
	pendingActiveTS, err := ds.ReadTimestamp(DatasetActive)
	if err != nil {
		return nil
	}

	shouldReplace := false

	// Replace if pending's active timestamp is newer.
	if Compare(pendingActiveTS, activeTimestamp) > 0 {
		shouldReplace = true
	} else {
		// Or if the network key is different.
		netKeyTLV := ds.FindTLV(TLVNetworkKey)
		if netKeyTLV != nil && len(netKeyTLV.Value) >= 16 {
			var newKey [16]byte
			copy(newKey[:], netKeyTLV.Value[:16])
			if newKey != currentNetworkKey {
				shouldReplace = true
			}
		}
	}

	if !shouldReplace {
		return nil
	}

	// Convert to active: remove pending timestamp and delay timer.
	ds.RemoveTLV(TLVPendingTimestamp)
	ds.RemoveTLV(TLVDelayTimer)

	return ds
}

// ReadActiveTimestamp reads the Active Timestamp from the Pending dataset.
func (pm *PendingDatasetManager) ReadActiveTimestamp() (*Timestamp, error) {
	ds, err := pm.Read()
	if err != nil {
		return nil, err
	}
	return ds.ReadTimestamp(DatasetActive)
}

// MemoryDatasetStore is an in-memory implementation of DatasetStore,
// useful for testing and for devices without persistent storage.
type MemoryDatasetStore struct {
	active  *Dataset
	pending *Dataset
}

// NewMemoryDatasetStore creates a new in-memory dataset store.
func NewMemoryDatasetStore() *MemoryDatasetStore {
	return &MemoryDatasetStore{}
}

// ReadDataset reads the dataset from memory.
func (s *MemoryDatasetStore) ReadDataset(dt DatasetType) (*Dataset, error) {
	var ds *Dataset
	if dt == DatasetActive {
		ds = s.active
	} else {
		ds = s.pending
	}
	if ds == nil {
		return nil, goterrors.ErrNotFound
	}
	// Return a copy.
	cp := *ds
	return &cp, nil
}

// SaveDataset saves a copy of the dataset to memory.
func (s *MemoryDatasetStore) SaveDataset(dt DatasetType, ds *Dataset) error {
	cp := *ds
	if dt == DatasetActive {
		s.active = &cp
	} else {
		s.pending = &cp
	}
	return nil
}

// DeleteDataset removes the dataset from memory.
func (s *MemoryDatasetStore) DeleteDataset(dt DatasetType) error {
	if dt == DatasetActive {
		s.active = nil
	} else {
		s.pending = nil
	}
	return nil
}
