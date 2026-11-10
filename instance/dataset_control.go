// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"errors"
	"fmt"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/meshcop"
)

// DatasetRecord owns a dataset or explicitly represents its absence.
// A present record must contain a complete supported operational dataset.
type DatasetRecord struct {
	Present bool
	TLVs    []byte
}

// OperationalDatasetSnapshot owns dataset-only checkpoint material. Pending
// TLVs contain remaining delay at CapturedAt; the caller's durable failsafe
// protocol must account for elapsed time before staging a restored record.
// This is not a Settings/key/counter snapshot or an atomic transaction.
type OperationalDatasetSnapshot struct {
	Active, Pending DatasetRecord
	CapturedAt      time.Time
}

// ValidateOperationalDataset checks the full candidate against the actual
// selected radio's supported channels. LOOP-ONLY; external callers use Do.
func (inst *Instance) ValidateOperationalDataset(data []byte, kind meshcop.DatasetType) error {
	if inst.platRadio == nil {
		return goterrors.ErrNotCapable
	}
	return meshcop.ValidateOperationalDataset(data, kind, inst.platRadio.GetSupportedChannelMask())
}

// ReadOperationalDatasets returns owned dataset-only material, preserving
// absent-versus-I/O errors. LOOP-ONLY, not an atomic backend checkpoint.
func (inst *Instance) ReadOperationalDatasets() (OperationalDatasetSnapshot, error) {
	snapshot := OperationalDatasetSnapshot{CapturedAt: time.Now()}
	for _, target := range []struct {
		manager *meshcop.DatasetManager
		record  *DatasetRecord
	}{
		{inst.activeDataset.DatasetManager, &snapshot.Active},
		{inst.pendingDataset.DatasetManager, &snapshot.Pending},
	} {
		dataset, err := target.manager.Read()
		if errors.Is(err, goterrors.ErrNotFound) {
			continue
		}
		if err != nil {
			return OperationalDatasetSnapshot{}, err
		}
		target.record.Present = true
		target.record.TLVs = append([]byte(nil), dataset.Bytes()...)
	}
	return snapshot, nil
}

// StageOperationalDatasets validates BOTH records before stopping traffic and
// making independent dataset writes. It does not implement a multi-key/Matter
// transaction. The caller must durably establish its dataset-only recovery
// protocol before calling. Any write error latches closed until a fresh
// Instance reopens/reconciles storage, including ambiguous committed writes.
// Never restore Settings/key/counter state to perform a failsafe rollback.
func (inst *Instance) StageOperationalDatasets(active, pending DatasetRecord) error {
	if err := inst.SecurityError(); err != nil {
		return err
	}
	if len(active.TLVs) > meshcop.DatasetMaxLength || len(pending.TLVs) > meshcop.DatasetMaxLength {
		return goterrors.ErrInvalidArgs
	}
	active.TLVs = append([]byte(nil), active.TLVs...)
	pending.TLVs = append([]byte(nil), pending.TLVs...)
	if inst.platSettings == nil {
		return goterrors.ErrInvalidState
	}
	if err := inst.PersistenceError(); err != nil {
		return err
	}
	records := []struct {
		record  DatasetRecord
		kind    meshcop.DatasetType
		manager *meshcop.DatasetManager
	}{
		{active, meshcop.DatasetActive, inst.activeDataset.DatasetManager},
		{pending, meshcop.DatasetPending, inst.pendingDataset.DatasetManager},
	}
	for _, item := range records {
		if !item.record.Present {
			if len(item.record.TLVs) != 0 {
				return goterrors.ErrInvalidArgs
			}
		} else if err := inst.ValidateOperationalDataset(item.record.TLVs, item.kind); err != nil {
			return err
		}
	}
	if inst.threadEnabled {
		if err := inst.ThreadStop(); err != nil {
			return err
		}
	}
	inst.abortFragmentedTraffic()
	if inst.subMac.IsTransmittingOrScanning() {
		return goterrors.ErrBusy // No dataset write until the radio is quiescent.
	}
	if inst.ifConfigUp {
		if err := inst.IfConfigDown(); err != nil {
			return err
		}
	}
	for _, item := range records {
		var err error
		if item.record.Present {
			dataset := &meshcop.Dataset{}
			if err = dataset.SetFrom(item.record.TLVs); err == nil {
				err = item.manager.SaveLocal(dataset)
			}
		} else {
			err = item.manager.Clear()
		}
		if err != nil {
			inst.datasetWriteErr = fmt.Errorf("instance: stage operational dataset (fresh recovery required): %w", err)
			return inst.datasetWriteErr
		}
	}
	return nil
}
