// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tcat

import (
	"encoding/binary"
	"testing"
)

func TestNewAgent(t *testing.T) {
	a := NewAgent()
	if a.IsEnabled() {
		t.Error("new agent should not be enabled")
	}
	if a.IsConnected() {
		t.Error("new agent should not be connected")
	}
}

func TestEnableDisable(t *testing.T) {
	a := NewAgent()

	if err := a.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if !a.IsEnabled() {
		t.Error("agent should be enabled after Enable")
	}

	// Double-enable returns ErrAlready.
	if err := a.Enable(); err == nil {
		t.Error("double Enable should return error")
	}

	a.Disable()
	if a.IsEnabled() {
		t.Error("agent should be disabled after Disable")
	}
}

func TestConnectDisconnect(t *testing.T) {
	a := NewAgent()

	// Cannot connect when not enabled.
	auth := Authorization{}
	if err := a.HandleConnect(auth); err == nil {
		t.Error("HandleConnect should fail when disabled")
	}

	_ = a.Enable()

	if err := a.HandleConnect(auth); err != nil {
		t.Fatalf("HandleConnect: %v", err)
	}
	if !a.IsConnected() {
		t.Error("should be connected")
	}

	// Double-connect returns ErrBusy.
	if err := a.HandleConnect(auth); err == nil {
		t.Error("double HandleConnect should return error")
	}

	a.HandleDisconnect()
	if a.IsConnected() {
		t.Error("should not be connected after disconnect")
	}
}

func TestDisableDropsConnection(t *testing.T) {
	a := NewAgent()
	_ = a.Enable()
	_ = a.HandleConnect(Authorization{})

	a.Disable()
	if a.IsConnected() {
		t.Error("Disable should drop connection")
	}
}

func TestDeviceID(t *testing.T) {
	a := NewAgent()
	id := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	a.SetDeviceID(id)

	got := a.GetDeviceID()
	if got != id {
		t.Errorf("GetDeviceID = %x, want %x", got, id)
	}
}

func TestVendorInfo(t *testing.T) {
	a := NewAgent()
	info := VendorInfo{
		Name:      "TestVendor",
		Model:     "TestModel",
		SwVersion: "1.0.0",
	}
	a.SetVendorInfo(info)

	got := a.GetVendorInfo()
	if got.Name != info.Name || got.Model != info.Model || got.SwVersion != info.SwVersion {
		t.Errorf("GetVendorInfo mismatch: got %+v, want %+v", got, info)
	}
}

func TestHandleSingleTlvNotConnected(t *testing.T) {
	a := NewAgent()
	_ = a.Enable()

	_, err := a.HandleSingleTlv([]byte{byte(TlvDeviceID), 0})
	if err == nil {
		t.Error("should fail when not connected")
	}
}

func TestHandleSingleTlvParseError(t *testing.T) {
	a := NewAgent()
	_ = a.Enable()
	auth := Authorization{}
	auth.AllowAll()
	_ = a.HandleConnect(auth)

	// Too short.
	resp, err := a.HandleSingleTlv([]byte{0x01})
	if err == nil {
		t.Error("should fail with too short data")
	}
	if resp == nil {
		t.Fatal("should return status response even on parse error")
	}
	assertStatus(t, resp, StatusParseError)
}

func TestHandleSingleTlvTruncated(t *testing.T) {
	a := NewAgent()
	_ = a.Enable()
	auth := Authorization{}
	auth.AllowAll()
	_ = a.HandleConnect(auth)

	// Length says 5 bytes but only 2 available.
	resp, err := a.HandleSingleTlv([]byte{byte(TlvActiveDataset), 5, 0x01, 0x02})
	if err == nil {
		t.Error("should fail with truncated data")
	}
	assertStatus(t, resp, StatusParseError)
}

func TestHandleUnsupportedTlv(t *testing.T) {
	a := NewAgent()
	_ = a.Enable()
	auth := Authorization{}
	auth.AllowAll()
	_ = a.HandleConnect(auth)

	resp, err := a.HandleSingleTlv([]byte{0xFF, 0})
	if err != nil {
		t.Fatalf("unsupported TLV should not return error: %v", err)
	}
	assertStatus(t, resp, StatusUnsupported)
}

func TestHandleActiveDataset(t *testing.T) {
	a := NewAgent()
	_ = a.Enable()

	var received []byte
	a.SetDatasetHandler(func(data []byte) error {
		received = make([]byte, len(data))
		copy(received, data)
		return nil
	})

	auth := Authorization{}
	auth.Allow(ClassCommissioning)
	_ = a.HandleConnect(auth)

	dataset := []byte{0x01, 0x02, 0x03, 0x04}
	tlv := encodeTlv(TlvActiveDataset, dataset)
	resp, err := a.HandleSingleTlv(tlv)
	if err != nil {
		t.Fatalf("HandleSingleTlv: %v", err)
	}
	assertStatus(t, resp, StatusSuccess)

	if len(received) != len(dataset) {
		t.Fatalf("handler received %d bytes, want %d", len(received), len(dataset))
	}
	for i, b := range received {
		if b != dataset[i] {
			t.Errorf("byte %d: got %02x, want %02x", i, b, dataset[i])
		}
	}
}

func TestHandleActiveDatasetUnauthorized(t *testing.T) {
	a := NewAgent()
	_ = a.Enable()

	// Only general class authorized — not commissioning.
	auth := Authorization{}
	auth.Allow(ClassGeneral)
	_ = a.HandleConnect(auth)

	dataset := []byte{0x01, 0x02}
	tlv := encodeTlv(TlvActiveDataset, dataset)
	resp, err := a.HandleSingleTlv(tlv)
	if err != nil {
		t.Fatalf("HandleSingleTlv: %v", err)
	}
	assertStatus(t, resp, StatusUnauthorized)
}

func TestHandleDeviceIDGet(t *testing.T) {
	a := NewAgent()
	_ = a.Enable()

	id := [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	a.SetDeviceID(id)

	auth := Authorization{}
	auth.Allow(ClassGeneral)
	_ = a.HandleConnect(auth)

	resp, err := a.HandleCommand(TlvDeviceID, nil)
	if err != nil {
		t.Fatalf("HandleCommand: %v", err)
	}

	// Response should be a DeviceID TLV.
	if len(resp) < 2 {
		t.Fatal("response too short")
	}
	if TlvType(resp[0]) != TlvDeviceID {
		t.Errorf("response type = %d, want %d", resp[0], TlvDeviceID)
	}
	if int(resp[1]) != 8 {
		t.Errorf("response length = %d, want 8", resp[1])
	}
	var gotID [8]byte
	copy(gotID[:], resp[2:])
	if gotID != id {
		t.Errorf("device ID = %x, want %x", gotID, id)
	}
}

func TestHandleDecommission(t *testing.T) {
	a := NewAgent()
	_ = a.Enable()

	auth := Authorization{}
	auth.Allow(ClassDecommissioning)
	_ = a.HandleConnect(auth)

	resp, err := a.HandleCommand(TlvDecommission, nil)
	if err != nil {
		t.Fatalf("HandleCommand: %v", err)
	}
	assertStatus(t, resp, StatusSuccess)
}

func TestHandleDecommissionUnauthorized(t *testing.T) {
	a := NewAgent()
	_ = a.Enable()

	auth := Authorization{}
	auth.Allow(ClassGeneral) // No decommissioning.
	_ = a.HandleConnect(auth)

	resp, err := a.HandleCommand(TlvDecommission, nil)
	if err != nil {
		t.Fatalf("HandleCommand: %v", err)
	}
	assertStatus(t, resp, StatusUnauthorized)
}

func TestAuthorization(t *testing.T) {
	var auth Authorization

	// Initially none allowed.
	for _, c := range []CommandClass{ClassGeneral, ClassCommissioning, ClassExtraction, ClassDecommissioning, ClassApplication} {
		if auth.IsAllowed(c) {
			t.Errorf("%s should not be allowed initially", c)
		}
	}

	// Allow one.
	auth.Allow(ClassCommissioning)
	if !auth.IsAllowed(ClassCommissioning) {
		t.Error("ClassCommissioning should be allowed")
	}
	if auth.IsAllowed(ClassGeneral) {
		t.Error("ClassGeneral should not be allowed")
	}

	// AllowAll.
	auth.AllowAll()
	for _, c := range []CommandClass{ClassGeneral, ClassCommissioning, ClassExtraction, ClassDecommissioning, ClassApplication} {
		if !auth.IsAllowed(c) {
			t.Errorf("%s should be allowed after AllowAll", c)
		}
	}

	// Clear.
	auth.Clear()
	for _, c := range []CommandClass{ClassGeneral, ClassCommissioning, ClassExtraction, ClassDecommissioning, ClassApplication} {
		if auth.IsAllowed(c) {
			t.Errorf("%s should not be allowed after Clear", c)
		}
	}

	// Out of range.
	if auth.IsAllowed(CommandClass(99)) {
		t.Error("out-of-range class should not be allowed")
	}
}

func TestCommandClassString(t *testing.T) {
	tests := []struct {
		c    CommandClass
		want string
	}{
		{ClassGeneral, "General"},
		{ClassCommissioning, "Commissioning"},
		{ClassExtraction, "Extraction"},
		{ClassDecommissioning, "Decommissioning"},
		{ClassApplication, "Application"},
		{CommandClass(99), "CommandClass(99)"},
	}
	for _, tt := range tests {
		if got := tt.c.String(); got != tt.want {
			t.Errorf("CommandClass(%d).String() = %q, want %q", tt.c, got, tt.want)
		}
	}
}

func TestTlvTypeString(t *testing.T) {
	tests := []struct {
		typ  TlvType
		want string
	}{
		{TlvResponseWithStatus, "ResponseWithStatus"},
		{TlvActiveDataset, "ActiveDataset"},
		{TlvDecommission, "Decommission"},
		{TlvType(99), "TlvType(99)"},
	}
	for _, tt := range tests {
		if got := tt.typ.String(); got != tt.want {
			t.Errorf("TlvType(%d).String() = %q, want %q", tt.typ, got, tt.want)
		}
	}
}

func TestStatusCodeString(t *testing.T) {
	tests := []struct {
		s    StatusCode
		want string
	}{
		{StatusSuccess, "Success"},
		{StatusUnsupported, "Unsupported"},
		{StatusParseError, "ParseError"},
		{StatusBusy, "Busy"},
		{StatusGeneral, "General"},
		{StatusAuth, "Auth"},
		{StatusUnauthorized, "Unauthorized"},
		{StatusCode(99), "StatusCode(99)"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("StatusCode(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

// assertStatus checks that a response TLV is a ResponseWithStatus with the expected code.
func assertStatus(t *testing.T, resp []byte, expected StatusCode) {
	t.Helper()
	if len(resp) < 4 {
		t.Fatalf("response too short (%d bytes) to contain status", len(resp))
	}
	if TlvType(resp[0]) != TlvResponseWithStatus {
		t.Errorf("response type = %d, want %d (ResponseWithStatus)", resp[0], TlvResponseWithStatus)
	}
	if resp[1] != 2 {
		t.Errorf("response length = %d, want 2", resp[1])
	}
	got := StatusCode(binary.BigEndian.Uint16(resp[2:4]))
	if got != expected {
		t.Errorf("status = %s (%d), want %s (%d)", got, got, expected, expected)
	}
}
