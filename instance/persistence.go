// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"errors"
	"fmt"

	"github.com/hilli/gothread/common/settings"
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/radio"
)

type settingsDatasetStore struct {
	settings *settings.Settings
}

func datasetSettingKey(dt meshcop.DatasetType) uint16 {
	if dt == meshcop.DatasetActive {
		return settings.KeyActiveDataset
	}
	return settings.KeyPendingDataset
}

func (s *settingsDatasetStore) ReadDataset(dt meshcop.DatasetType) (*meshcop.Dataset, error) {
	data, err := s.settings.Read(datasetSettingKey(dt))
	if errors.Is(err, settings.ErrNotFound) {
		return nil, goterrors.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return parseStoredDataset(data)
}

func parseStoredDataset(data []byte) (*meshcop.Dataset, error) {
	ds := &meshcop.Dataset{}
	if err := ds.SetFrom(data); err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, goterrors.ErrParse
	}
	if err := ds.ValidateTLVs(); err != nil {
		return nil, err
	}
	// Validate lengths of known TLVs as well as their container format.
	for _, field := range []struct {
		typ    meshcop.TLVType
		length int
	}{
		{meshcop.TLVNetworkKey, 16}, {meshcop.TLVPSKc, 16},
		{meshcop.TLVActiveTimestamp, 8}, {meshcop.TLVPendingTimestamp, 8},
		{meshcop.TLVExtendedPanID, 8}, {meshcop.TLVMeshLocalPrefix, 8},
		{meshcop.TLVPanID, 2}, {meshcop.TLVChannel, 3}, {meshcop.TLVDelayTimer, 4},
	} {
		if t := ds.FindTLV(field.typ); t != nil && len(t.Value) != field.length {
			return nil, goterrors.ErrParse
		}
	}
	return ds, nil
}

func (s *settingsDatasetStore) SaveDataset(dt meshcop.DatasetType, ds *meshcop.Dataset) error {
	if _, err := parseStoredDataset(ds.Bytes()); err != nil {
		return err
	}
	return s.settings.Write(datasetSettingKey(dt), ds.Bytes())
}

func (s *settingsDatasetStore) DeleteDataset(dt meshcop.DatasetType) error {
	err := s.settings.Delete(datasetSettingKey(dt))
	if errors.Is(err, settings.ErrNotFound) || errors.Is(err, platform.ErrSettingsNotFound) {
		return nil
	}
	return err
}

func (inst *Instance) restorePersistence() {
	for _, dm := range []*meshcop.DatasetManager{
		inst.activeDataset.DatasetManager, inst.pendingDataset.DatasetManager,
	} {
		if err := dm.Restore(); err != nil && !errors.Is(err, goterrors.ErrNotFound) {
			inst.restoreErr = errors.Join(inst.restoreErr, fmt.Errorf("restore %s dataset: %w", dm.Type(), err))
		}
	}
	if inst.stackSettings == nil || inst.restoreErr != nil {
		return
	}
	allowCreate := !inst.activeDataset.LocalSaved() && !inst.pendingDataset.LocalSaved()
	if err := inst.keyManager.EnablePersistence(inst.stackSettings, allowCreate); err != nil {
		return // The key manager latches this error for PersistenceError.
	}
	// Offload can allocate counters autonomously (e.g. secured enhanced ACKs).
	// The generic radio interface cannot constrain those to a reserved range.
	if inst.platRadio != nil && inst.platRadio.GetCaps().Has(radio.CapTransmitSec) {
		inst.restoreErr = errors.Join(inst.restoreErr, errors.New("instance: persistent counters require software MAC security"))
	}
}

// PersistenceError reports restoration failures and latched counter write
// failures. Start and interface/Thread startup return this error too.
// Dataset mutations return their own storage errors without changing state.
func (inst *Instance) PersistenceError() error {
	return errors.Join(inst.restoreErr, inst.keyManager.PersistenceError())
}

func (inst *Instance) allocateMacFrameCounter() (uint32, error) {
	if err := inst.PersistenceError(); err != nil {
		return 0, err
	}
	counter, err := inst.keyManager.AllocateMacFrameCounter()
	if err == nil {
		inst.subMac.SetFrameCounter(inst.keyManager.GetMacFrameCounter(), false)
	}
	return counter, err
}
