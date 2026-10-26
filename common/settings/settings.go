// Copyright (c) 2026, Jan Hillegeer. All rights reserved.
// Copyright (c) 2016, The OpenThread Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from this
//    software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

// Package settings implements persistent settings storage for OpenThread.
//
// This is a Go port of openthread/src/core/common/settings.hpp,
// settings.cpp, and settings_driver.hpp. It provides a Driver interface for
// platform-specific non-volatile storage, an in-memory driver for testing,
// and a high-level Settings struct with typed accessors for each setting key.
package settings

import (
	"errors"
	"sync"
)

// Setting key constants matching OpenThread's SettingsBase::Key.
const (
	KeyActiveDataset     uint16 = 0x0001
	KeyPendingDataset    uint16 = 0x0002
	KeyNetworkInfo       uint16 = 0x0003
	KeyParentInfo        uint16 = 0x0004
	KeyChildInfo         uint16 = 0x0005
	KeySlaacIidSecretKey uint16 = 0x0007
	KeyDadInfo           uint16 = 0x0008
	KeySrpEcdsaKey       uint16 = 0x000b
	KeySrpClientInfo     uint16 = 0x000c
	KeyBrUlaPrefix       uint16 = 0x000f
	KeyBrOnLinkPrefixes  uint16 = 0x0010
	KeyBorderAgentId     uint16 = 0x0011 //nolint:revive // Retain the established public API spelling for source compatibility.
)

// Sentinel errors.
var (
	ErrNotFound = errors.New("settings: not found")
	ErrNoBufs   = errors.New("settings: no buffers")
)

// Driver is the platform abstraction for non-volatile settings storage.
// Each key can hold either a single value (Set/Get) or a list of values
// (Add/Get-by-index/Delete-by-index).
type Driver interface {
	// Init initialises the settings subsystem.
	Init() error
	// Deinit tears down the settings subsystem.
	Deinit()
	// Add appends value to the list stored under key.
	Add(key uint16, value []byte) error
	// Delete removes the entry at index from the list under key.
	// An index of -1 deletes all entries for that key.
	Delete(key uint16, index int) error
	// Get retrieves entry at index from the list under key.
	// For single-value keys, use index 0.
	Get(key uint16, index int) ([]byte, error)
	// Set stores a single value under key (replacing any existing entries).
	Set(key uint16, value []byte) error
	// Wipe removes all settings.
	Wipe() error
}

// InMemoryDriver is a Driver backed by Go maps, suitable for testing.
type InMemoryDriver struct {
	mu   sync.RWMutex
	data map[uint16][][]byte
	init bool
}

// NewInMemoryDriver creates an un-initialised InMemoryDriver.
func NewInMemoryDriver() *InMemoryDriver {
	return &InMemoryDriver{}
}

// Init initialises the driver.
func (d *InMemoryDriver) Init() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.data = make(map[uint16][][]byte)
	d.init = true
	return nil
}

// Deinit tears down the driver.
func (d *InMemoryDriver) Deinit() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.data = nil
	d.init = false
}

// Add appends value to the list for key.
func (d *InMemoryDriver) Add(key uint16, value []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	d.data[key] = append(d.data[key], cp)
	return nil
}

// Delete removes the entry at index, or all entries if index == -1.
func (d *InMemoryDriver) Delete(key uint16, index int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	entries, ok := d.data[key]
	if !ok || len(entries) == 0 {
		return ErrNotFound
	}
	if index == -1 {
		delete(d.data, key)
		return nil
	}
	if index < 0 || index >= len(entries) {
		return ErrNotFound
	}
	d.data[key] = append(entries[:index], entries[index+1:]...)
	if len(d.data[key]) == 0 {
		delete(d.data, key)
	}
	return nil
}

// Get retrieves the entry at index for key.
func (d *InMemoryDriver) Get(key uint16, index int) ([]byte, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	entries, ok := d.data[key]
	if !ok || len(entries) == 0 {
		return nil, ErrNotFound
	}
	if index < 0 || index >= len(entries) {
		return nil, ErrNotFound
	}
	cp := make([]byte, len(entries[index]))
	copy(cp, entries[index])
	return cp, nil
}

// Set replaces all entries for key with a single value.
func (d *InMemoryDriver) Set(key uint16, value []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	d.data[key] = [][]byte{cp}
	return nil
}

// Wipe removes all stored settings.
func (d *InMemoryDriver) Wipe() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.data = make(map[uint16][][]byte)
	return nil
}

// Settings wraps a Driver and provides typed Read/Write/Delete methods.
type Settings struct {
	driver Driver
}

// New creates a Settings that delegates to the given Driver.
func New(driver Driver) *Settings {
	return &Settings{driver: driver}
}

// Init initialises the underlying driver.
func (s *Settings) Init() error { return s.driver.Init() }

// Deinit de-initialises the underlying driver.
func (s *Settings) Deinit() { s.driver.Deinit() }

// Wipe removes all stored settings.
func (s *Settings) Wipe() error { return s.driver.Wipe() }

// Read retrieves a single-value setting.
func (s *Settings) Read(key uint16) ([]byte, error) {
	return s.driver.Get(key, 0)
}

// Write stores a single-value setting.
func (s *Settings) Write(key uint16, value []byte) error {
	return s.driver.Set(key, value)
}

// Delete removes all entries for key.
func (s *Settings) Delete(key uint16) error {
	return s.driver.Delete(key, -1)
}

// Add appends an entry to a list-type setting.
func (s *Settings) Add(key uint16, value []byte) error {
	return s.driver.Add(key, value)
}

// ReadAt retrieves the entry at index for a list-type setting.
func (s *Settings) ReadAt(key uint16, index int) ([]byte, error) {
	return s.driver.Get(key, index)
}

// DeleteAt removes a specific entry from a list-type setting.
func (s *Settings) DeleteAt(key uint16, index int) error {
	return s.driver.Delete(key, index)
}

// ReadActiveDataset reads the active operational dataset.
func (s *Settings) ReadActiveDataset() ([]byte, error) { return s.Read(KeyActiveDataset) }

// WriteActiveDataset writes the active operational dataset.
func (s *Settings) WriteActiveDataset(data []byte) error { return s.Write(KeyActiveDataset, data) }

// DeleteActiveDataset deletes the active operational dataset.
func (s *Settings) DeleteActiveDataset() error { return s.Delete(KeyActiveDataset) }

// ReadPendingDataset reads the pending operational dataset.
func (s *Settings) ReadPendingDataset() ([]byte, error) { return s.Read(KeyPendingDataset) }

// WritePendingDataset writes the pending operational dataset.
func (s *Settings) WritePendingDataset(data []byte) error { return s.Write(KeyPendingDataset, data) }

// DeletePendingDataset deletes the pending operational dataset.
func (s *Settings) DeletePendingDataset() error { return s.Delete(KeyPendingDataset) }

// ReadNetworkInfo reads the network info setting.
func (s *Settings) ReadNetworkInfo() ([]byte, error) { return s.Read(KeyNetworkInfo) }

// WriteNetworkInfo writes the network info setting.
func (s *Settings) WriteNetworkInfo(data []byte) error { return s.Write(KeyNetworkInfo, data) }

// DeleteNetworkInfo deletes the network info setting.
func (s *Settings) DeleteNetworkInfo() error { return s.Delete(KeyNetworkInfo) }

// ReadParentInfo reads the parent info setting.
func (s *Settings) ReadParentInfo() ([]byte, error) { return s.Read(KeyParentInfo) }

// WriteParentInfo writes the parent info setting.
func (s *Settings) WriteParentInfo(data []byte) error { return s.Write(KeyParentInfo, data) }

// DeleteParentInfo deletes the parent info setting.
func (s *Settings) DeleteParentInfo() error { return s.Delete(KeyParentInfo) }

// AddChildInfo adds a child info entry (list-type setting).
func (s *Settings) AddChildInfo(data []byte) error { return s.Add(KeyChildInfo, data) }

// ReadChildInfo reads the child info entry at index.
func (s *Settings) ReadChildInfo(index int) ([]byte, error) { return s.ReadAt(KeyChildInfo, index) }

// DeleteChildInfo deletes the child info entry at index.
func (s *Settings) DeleteChildInfo(index int) error { return s.DeleteAt(KeyChildInfo, index) }

// DeleteAllChildInfo deletes all child info entries.
func (s *Settings) DeleteAllChildInfo() error { return s.Delete(KeyChildInfo) }

// ReadSlaacIidSecretKey reads the SLAAC IID secret key.
func (s *Settings) ReadSlaacIidSecretKey() ([]byte, error) { return s.Read(KeySlaacIidSecretKey) }

// WriteSlaacIidSecretKey writes the SLAAC IID secret key.
func (s *Settings) WriteSlaacIidSecretKey(data []byte) error {
	return s.Write(KeySlaacIidSecretKey, data)
}

// ReadDadInfo reads the DAD info setting.
func (s *Settings) ReadDadInfo() ([]byte, error) { return s.Read(KeyDadInfo) }

// WriteDadInfo writes the DAD info setting.
func (s *Settings) WriteDadInfo(data []byte) error { return s.Write(KeyDadInfo, data) }

// ReadSrpEcdsaKey reads the SRP ECDSA key pair.
func (s *Settings) ReadSrpEcdsaKey() ([]byte, error) { return s.Read(KeySrpEcdsaKey) }

// WriteSrpEcdsaKey writes the SRP ECDSA key pair.
func (s *Settings) WriteSrpEcdsaKey(data []byte) error { return s.Write(KeySrpEcdsaKey, data) }

// ReadSrpClientInfo reads the SRP client info.
func (s *Settings) ReadSrpClientInfo() ([]byte, error) { return s.Read(KeySrpClientInfo) }

// WriteSrpClientInfo writes the SRP client info.
func (s *Settings) WriteSrpClientInfo(data []byte) error { return s.Write(KeySrpClientInfo, data) }

// ReadBrUlaPrefix reads the Border Router ULA prefix.
func (s *Settings) ReadBrUlaPrefix() ([]byte, error) { return s.Read(KeyBrUlaPrefix) }

// WriteBrUlaPrefix writes the Border Router ULA prefix.
func (s *Settings) WriteBrUlaPrefix(data []byte) error { return s.Write(KeyBrUlaPrefix, data) }

// AddBrOnLinkPrefix adds a BR on-link prefix entry.
func (s *Settings) AddBrOnLinkPrefix(data []byte) error { return s.Add(KeyBrOnLinkPrefixes, data) }

// ReadBrOnLinkPrefix reads the BR on-link prefix at index.
func (s *Settings) ReadBrOnLinkPrefix(index int) ([]byte, error) {
	return s.ReadAt(KeyBrOnLinkPrefixes, index)
}

// DeleteBrOnLinkPrefix deletes the BR on-link prefix at index.
func (s *Settings) DeleteBrOnLinkPrefix(index int) error {
	return s.DeleteAt(KeyBrOnLinkPrefixes, index)
}

// DeleteAllBrOnLinkPrefixes deletes all BR on-link prefix entries.
func (s *Settings) DeleteAllBrOnLinkPrefixes() error { return s.Delete(KeyBrOnLinkPrefixes) }

// ReadBorderAgentId reads the Border Agent ID.
func (s *Settings) ReadBorderAgentId() ([]byte, error) { return s.Read(KeyBorderAgentId) } //nolint:revive // Retain the established public API spelling for source compatibility.

// WriteBorderAgentId writes the Border Agent ID.
func (s *Settings) WriteBorderAgentId(data []byte) error { return s.Write(KeyBorderAgentId, data) } //nolint:revive // Retain the established public API spelling for source compatibility.
