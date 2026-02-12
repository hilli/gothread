// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package platform

import (
	"testing"
)

// --------------------------------------------------------------------------
// Mock types that satisfy the interfaces — compile-time verification
// --------------------------------------------------------------------------

type mockAlarm struct{ now uint32 }

func (m *mockAlarm) Start(_, _ uint32) {}
func (m *mockAlarm) Stop()             {}
func (m *mockAlarm) GetNow() uint32    { return m.now }

type mockAlarmMicro struct{}

func (m *mockAlarmMicro) StartMicro(_, _ uint32) {}
func (m *mockAlarmMicro) StopMicro()             {}
func (m *mockAlarmMicro) GetNowMicro() uint32    { return 0 }

type mockTime struct{}

func (m *mockTime) Now() uint64 { return 0 }

type mockEntropy struct{}

func (m *mockEntropy) Fill(_ []byte) error { return nil }

type mockSettings struct{ store map[SettingsKey][][]byte }

func (m *mockSettings) Get(key SettingsKey, index int) ([]byte, error) {
	entries, ok := m.store[key]
	if !ok || len(entries) == 0 {
		return nil, ErrSettingsNotFound
	}
	if index < 0 || index >= len(entries) {
		return nil, ErrSettingsNotFound
	}
	return entries[index], nil
}

func (m *mockSettings) Set(key SettingsKey, value []byte) error {
	m.store[key] = [][]byte{value}
	return nil
}

func (m *mockSettings) Add(key SettingsKey, value []byte) error {
	cp := make([]byte, len(value))
	copy(cp, value)
	m.store[key] = append(m.store[key], cp)
	return nil
}

func (m *mockSettings) Delete(key SettingsKey, index int) error {
	entries, ok := m.store[key]
	if !ok || len(entries) == 0 {
		return ErrSettingsNotFound
	}
	if index == -1 {
		delete(m.store, key)
		return nil
	}
	if index < 0 || index >= len(entries) {
		return ErrSettingsNotFound
	}
	m.store[key] = append(entries[:index], entries[index+1:]...)
	if len(m.store[key]) == 0 {
		delete(m.store, key)
	}
	return nil
}

func (m *mockSettings) Wipe() error {
	m.store = make(map[SettingsKey][][]byte)
	return nil
}

type mockLogger struct{ last string }

func (m *mockLogger) Log(_ LogLevel, _ LogRegion, msg string) {
	m.last = msg
}

type mockResetter struct{ reason ResetReason }

func (m *mockResetter) Reset(reason ResetReason)    { m.reason = reason }
func (m *mockResetter) GetResetReason() ResetReason { return m.reason }

// Compile-time interface checks.
var (
	_ Alarm      = (*mockAlarm)(nil)
	_ AlarmMicro = (*mockAlarmMicro)(nil)
	_ Time       = (*mockTime)(nil)
	_ Entropy    = (*mockEntropy)(nil)
	_ Settings   = (*mockSettings)(nil)
	_ Logger     = (*mockLogger)(nil)
	_ Resetter   = (*mockResetter)(nil)
)

// --------------------------------------------------------------------------
// Functional tests
// --------------------------------------------------------------------------

func TestAlarmGetNow(t *testing.T) {
	a := &mockAlarm{now: 12345}
	if got := a.GetNow(); got != 12345 {
		t.Errorf("GetNow() = %d, want 12345", got)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	s := &mockSettings{store: make(map[SettingsKey][][]byte)}

	data := []byte{0x01, 0x02, 0x03}
	if err := s.Set(SettingsKeyActiveDataset, data); err != nil {
		t.Fatalf("Set() error: %v", err)
	}

	got, err := s.Get(SettingsKeyActiveDataset, 0)
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if len(got) != len(data) {
		t.Fatalf("Get() len = %d, want %d", len(got), len(data))
	}
	for i := range data {
		if got[i] != data[i] {
			t.Errorf("byte %d: got %#02x, want %#02x", i, got[i], data[i])
		}
	}
}

func TestSettingsNotFound(t *testing.T) {
	s := &mockSettings{store: make(map[SettingsKey][][]byte)}
	_, err := s.Get(SettingsKeyNetworkInfo, 0)
	if err == nil {
		t.Fatal("Get() on missing key should return error")
	}
}

func TestSettingsDelete(t *testing.T) {
	s := &mockSettings{store: make(map[SettingsKey][][]byte)}
	_ = s.Set(SettingsKeyChildInfo, []byte{0xff})
	_ = s.Delete(SettingsKeyChildInfo, -1)
	_, err := s.Get(SettingsKeyChildInfo, 0)
	if err == nil {
		t.Fatal("Get() after Delete() should return error")
	}
}

func TestSettingsWipe(t *testing.T) {
	s := &mockSettings{store: make(map[SettingsKey][][]byte)}
	_ = s.Set(SettingsKeyActiveDataset, []byte{1})
	_ = s.Set(SettingsKeyPendingDataset, []byte{2})
	_ = s.Wipe()
	_, err1 := s.Get(SettingsKeyActiveDataset, 0)
	_, err2 := s.Get(SettingsKeyPendingDataset, 0)
	if err1 == nil || err2 == nil {
		t.Fatal("Get() after Wipe() should return error for all keys")
	}
}

func TestLoggerLog(t *testing.T) {
	l := &mockLogger{}
	l.Log(LogLevelInfo, LogRegionMAC, "test message")
	if l.last != "test message" {
		t.Errorf("Log() did not store message, got %q", l.last)
	}
}

func TestResetterRoundTrip(t *testing.T) {
	r := &mockResetter{}
	r.Reset(ResetSoftware)
	if got := r.GetResetReason(); got != ResetSoftware {
		t.Errorf("GetResetReason() = %d, want %d", got, ResetSoftware)
	}
}

func TestLogLevelString(t *testing.T) {
	tests := []struct {
		level LogLevel
		want  string
	}{
		{LogLevelNone, "NONE"},
		{LogLevelCrit, "CRIT"},
		{LogLevelWarn, "WARN"},
		{LogLevelNote, "NOTE"},
		{LogLevelInfo, "INFO"},
		{LogLevelDebg, "DEBG"},
		{LogLevel(99), "UNKN"},
	}
	for _, tt := range tests {
		if got := tt.level.String(); got != tt.want {
			t.Errorf("LogLevel(%d).String() = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestResetReasonString(t *testing.T) {
	tests := []struct {
		reason ResetReason
		want   string
	}{
		{ResetPowerOn, "PowerOn"},
		{ResetExternal, "External"},
		{ResetSoftware, "Software"},
		{ResetFault, "Fault"},
		{ResetCrash, "Crash"},
		{ResetAssert, "Assert"},
		{ResetWatchdog, "Watchdog"},
		{ResetOther, "Other"},
		{ResetReason(99), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.reason.String(); got != tt.want {
			t.Errorf("ResetReason(%d).String() = %q, want %q", tt.reason, got, tt.want)
		}
	}
}

func TestSettingsKeyValues(t *testing.T) {
	// Verify key constants match OpenThread's values.
	tests := []struct {
		key  SettingsKey
		want uint16
	}{
		{SettingsKeyActiveDataset, 0x0001},
		{SettingsKeyPendingDataset, 0x0002},
		{SettingsKeyNetworkInfo, 0x0003},
		{SettingsKeyParentInfo, 0x0004},
		{SettingsKeyChildInfo, 0x0005},
		{SettingsKeySRPClientInfo, 0x0007},
		{SettingsKeySRPServerInfo, 0x0008},
		{SettingsKeySLAACIIDSecretKey, 0x0009},
		{SettingsKeyDADInfo, 0x000a},
		{SettingsKeyBorderAgentID, 0x000b},
	}
	for _, tt := range tests {
		if uint16(tt.key) != tt.want {
			t.Errorf("SettingsKey %#04x != expected %#04x", uint16(tt.key), tt.want)
		}
	}
}

func TestLogRegionValues(t *testing.T) {
	// Verify iota-based ordering.
	if LogRegionAPI != 0 {
		t.Error("LogRegionAPI should be 0")
	}
	if LogRegionPlatform != 15 {
		t.Errorf("LogRegionPlatform = %d, want 15", LogRegionPlatform)
	}
}

func TestEntropyFill(t *testing.T) {
	e := &mockEntropy{}
	buf := make([]byte, 32)
	if err := e.Fill(buf); err != nil {
		t.Errorf("Fill() error: %v", err)
	}
}
