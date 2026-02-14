// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package simulation

import (
	"sync"

	"github.com/hilli/gothread/platform"
)

// Compile-time interface check.
var _ platform.Settings = (*SimSettings)(nil)

// SimSettings implements platform.Settings with in-memory map-based storage.
type SimSettings struct {
	mu   sync.Mutex
	data map[platform.SettingsKey][][]byte
}

// NewSimSettings creates a new SimSettings with an empty store.
func NewSimSettings() *SimSettings {
	return &SimSettings{data: make(map[platform.SettingsKey][][]byte)}
}

// Get reads the entry at index for the setting identified by key.
func (s *SimSettings) Get(key platform.SettingsKey, index int) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vals, ok := s.data[key]
	if !ok || index < 0 || index >= len(vals) {
		return nil, platform.ErrSettingsNotFound
	}
	dst := make([]byte, len(vals[index]))
	copy(dst, vals[index])
	return dst, nil
}

// Set writes (or overwrites) a single-value setting identified by key.
func (s *SimSettings) Set(key platform.SettingsKey, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dst := make([]byte, len(value))
	copy(dst, value)
	s.data[key] = [][]byte{dst}
	return nil
}

// Add appends a value to a list-type setting identified by key.
func (s *SimSettings) Add(key platform.SettingsKey, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dst := make([]byte, len(value))
	copy(dst, value)
	s.data[key] = append(s.data[key], dst)
	return nil
}

// Delete removes the entry at index for the setting identified by key.
// An index of -1 deletes all entries for that key.
func (s *SimSettings) Delete(key platform.SettingsKey, index int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index == -1 {
		delete(s.data, key)
		return nil
	}
	vals, ok := s.data[key]
	if !ok || index < 0 || index >= len(vals) {
		return platform.ErrSettingsNotFound
	}
	s.data[key] = append(vals[:index], vals[index+1:]...)
	if len(s.data[key]) == 0 {
		delete(s.data, key)
	}
	return nil
}

// Wipe removes all settings (factory reset).
func (s *SimSettings) Wipe() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = make(map[platform.SettingsKey][][]byte)
	return nil
}
