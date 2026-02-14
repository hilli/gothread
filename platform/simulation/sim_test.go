// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package simulation

import (
	"testing"

	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/radio"
)

func TestNewPlatform(t *testing.T) {
	p := NewPlatform()
	if p.Alarm == nil || p.Entropy == nil || p.Settings == nil || p.Logger == nil || p.Radio == nil {
		t.Fatal("NewPlatform returned nil component")
	}
}

func TestInterfaceCompliance(t *testing.T) {
	// These are compile-time checks; if they compile, the interfaces are satisfied.
	var _ platform.Alarm = (*SimAlarm)(nil)
	var _ platform.Entropy = (*SimEntropy)(nil)
	var _ platform.Settings = (*SimSettings)(nil)
	var _ platform.Logger = (*SimLogger)(nil)
	var _ radio.Radio = (*SimRadio)(nil)
}

func TestAlarmGetNow(t *testing.T) {
	a := NewSimAlarm()
	now := a.GetNow()
	if now > 1000 {
		t.Errorf("GetNow() = %d, expected close to 0", now)
	}
}

func TestAlarmStartStop(t *testing.T) {
	a := NewSimAlarm()
	a.Start(0, 100)
	if !a.running {
		t.Error("alarm should be running after Start")
	}
	a.Stop()
	if a.running {
		t.Error("alarm should not be running after Stop")
	}
}

func TestEntropyFill(t *testing.T) {
	e := &SimEntropy{}
	buf := make([]byte, 32)
	if err := e.Fill(buf); err != nil {
		t.Fatalf("Fill() error: %v", err)
	}
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Fill() produced all zeros")
	}
}

func TestSettingsSetGet(t *testing.T) {
	s := NewSimSettings()
	key := platform.SettingsKeyActiveDataset
	val := []byte{1, 2, 3}
	if err := s.Set(key, val); err != nil {
		t.Fatalf("Set() error: %v", err)
	}
	got, err := s.Get(key, 0)
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Errorf("Get() = %v, want [1 2 3]", got)
	}
}

func TestSettingsAddDelete(t *testing.T) {
	s := NewSimSettings()
	key := platform.SettingsKeyChildInfo
	_ = s.Add(key, []byte{10})
	_ = s.Add(key, []byte{20})
	_ = s.Add(key, []byte{30})

	got, err := s.Get(key, 1)
	if err != nil || got[0] != 20 {
		t.Errorf("Get(index=1) = %v, %v; want [20], nil", got, err)
	}

	_ = s.Delete(key, 1)
	got, err = s.Get(key, 1)
	if err != nil || got[0] != 30 {
		t.Errorf("after delete, Get(index=1) = %v, %v; want [30], nil", got, err)
	}
}

func TestSettingsWipe(t *testing.T) {
	s := NewSimSettings()
	_ = s.Set(platform.SettingsKeyNetworkInfo, []byte{1})
	_ = s.Wipe()
	_, err := s.Get(platform.SettingsKeyNetworkInfo, 0)
	if err != platform.ErrSettingsNotFound {
		t.Errorf("after Wipe, Get() error = %v, want ErrSettingsNotFound", err)
	}
}

func TestSettingsNotFound(t *testing.T) {
	s := NewSimSettings()
	_, err := s.Get(platform.SettingsKeyActiveDataset, 0)
	if err != platform.ErrSettingsNotFound {
		t.Errorf("Get() error = %v, want ErrSettingsNotFound", err)
	}
}

func TestRadioEnableDisable(t *testing.T) {
	r := NewSimRadio()
	if r.IsEnabled() {
		t.Error("radio should be disabled initially")
	}
	_ = r.Enable()
	if !r.IsEnabled() {
		t.Error("radio should be enabled after Enable()")
	}
	if r.GetState() != radio.StateSleep {
		t.Errorf("state = %v, want Sleep", r.GetState())
	}
	_ = r.Disable()
	if r.IsEnabled() {
		t.Error("radio should be disabled after Disable()")
	}
	if r.GetState() != radio.StateDisabled {
		t.Errorf("state = %v, want Disabled", r.GetState())
	}
}

func TestRadioReceiveTransmit(t *testing.T) {
	r := NewSimRadio()
	_ = r.Enable()
	_ = r.Receive(15)
	if r.GetState() != radio.StateReceive {
		t.Errorf("state = %v, want Receive", r.GetState())
	}
	frame := r.GetTransmitBuffer()
	if frame == nil {
		t.Fatal("GetTransmitBuffer() returned nil")
	}
	_ = r.Transmit(frame)
	if r.GetState() != radio.StateTransmit {
		t.Errorf("state = %v, want Transmit", r.GetState())
	}
}

func TestRadioTransmitPower(t *testing.T) {
	r := NewSimRadio()
	_ = r.SetTransmitPower(5)
	p, err := r.GetTransmitPower()
	if err != nil || p != 5 {
		t.Errorf("GetTransmitPower() = %d, %v; want 5, nil", p, err)
	}
}

func TestLoggerDoesNotPanic(t *testing.T) {
	l := NewSimLogger(platform.LogLevelDebg)
	l.Log(platform.LogLevelInfo, platform.LogRegionCore, "test message")
}
