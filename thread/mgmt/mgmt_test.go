// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mgmt

import (
	"sync"
	"testing"

	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Mock scanners
// ---------------------------------------------------------------------------

// mockEnergyScanner records calls and returns pre-configured RSSI values.
type mockEnergyScanner struct {
	mu       sync.Mutex
	calls    []energyScanCall
	results  map[uint16]int8 // channel → RSSI
	failChan map[uint16]bool // channels that return an error
}

type energyScanCall struct {
	Channel  uint16
	Duration uint16
}

func newMockEnergyScanner() *mockEnergyScanner {
	return &mockEnergyScanner{
		results:  make(map[uint16]int8),
		failChan: make(map[uint16]bool),
	}
}

func (m *mockEnergyScanner) EnergyScan(channel, duration uint16) (int8, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, energyScanCall{channel, duration})
	if m.failChan[channel] {
		return 0, errors.ErrFailed
	}
	rssi, ok := m.results[channel]
	if !ok {
		rssi = -100 // default
	}
	return rssi, nil
}

func (m *mockEnergyScanner) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

// mockPanIDScanner records calls and returns pre-configured presence results.
type mockPanIDScanner struct {
	mu          sync.Mutex
	calls       []panIDScanCall
	foundOnChan map[uint16]bool // channels where PAN ID is found
}

type panIDScanCall struct {
	Channel uint16
	PanID   uint16
}

func newMockPanIDScanner() *mockPanIDScanner {
	return &mockPanIDScanner{
		foundOnChan: make(map[uint16]bool),
	}
}

func (m *mockPanIDScanner) ScanForPanId(channel, panID uint16) (bool, error) { //nolint:revive // Implement the existing PanIdScanner interface without breaking callers.
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, panIDScanCall{channel, panID})
	return m.foundOnChan[channel], nil
}

func (m *mockPanIDScanner) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

// ---------------------------------------------------------------------------
// Helper: channel mask from channel list
// ---------------------------------------------------------------------------

func maskFromChannels(channels ...uint16) uint32 {
	var mask uint32
	for _, ch := range channels {
		mask |= 1 << ch
	}
	return mask
}

// ---------------------------------------------------------------------------
// lowestChannel tests
// ---------------------------------------------------------------------------

func TestLowestChannel(t *testing.T) {
	tests := []struct {
		name string
		mask uint32
		want uint16
	}{
		{"zero mask", 0, 0},
		{"channel 11", maskFromChannels(11), 11},
		{"channel 26", maskFromChannels(26), 26},
		{"channels 11,15,26", maskFromChannels(11, 15, 26), 11},
		{"channels 15,26", maskFromChannels(15, 26), 15},
		{"single bit 0", 1, 0}, // bit 0 → channel 0
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := lowestChannel(tt.mask)
			if got != tt.want {
				t.Errorf("lowestChannel(0x%08x) = %d, want %d", tt.mask, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EnergyScanServer tests
// ---------------------------------------------------------------------------

func TestEnergyScanServer_NewDefault(t *testing.T) {
	scanner := newMockEnergyScanner()
	srv := NewEnergyScanServer(scanner)

	if srv.IsScanning() {
		t.Error("new server should not be scanning")
	}
	if srv.scanner != scanner {
		t.Error("scanner not set")
	}
}

func TestEnergyScanServer_WithOptions(t *testing.T) {
	scanner := newMockEnergyScanner()
	srv := NewEnergyScanServer(scanner, WithDefaultScanDuration(500), WithDefaultCount(2))

	if srv.scanDuration != 500 {
		t.Errorf("scanDuration = %d, want 500", srv.scanDuration)
	}
	if srv.count != 2 {
		t.Errorf("count = %d, want 2", srv.count)
	}
}

func TestEnergyScanServer_WithDefaultCountClamp(t *testing.T) {
	scanner := newMockEnergyScanner()

	srv := NewEnergyScanServer(scanner, WithDefaultCount(0))
	if srv.count != energyMinCount {
		t.Errorf("count = %d, want %d (clamped to min)", srv.count, energyMinCount)
	}

	srv = NewEnergyScanServer(scanner, WithDefaultCount(10))
	if srv.count != energyMaxCount {
		t.Errorf("count = %d, want %d (clamped to max)", srv.count, energyMaxCount)
	}
}

func TestEnergyScanServer_HandleRequest_InvalidMask(t *testing.T) {
	scanner := newMockEnergyScanner()
	srv := NewEnergyScanServer(scanner)

	err := srv.HandleRequest(0, 1, 100, 200)
	if err != errors.ErrInvalidArgs {
		t.Errorf("err = %v, want ErrInvalidArgs", err)
	}
}

func TestEnergyScanServer_HandleRequest_Busy(t *testing.T) {
	scanner := newMockEnergyScanner()
	srv := NewEnergyScanServer(scanner)

	mask := maskFromChannels(11)
	if err := srv.HandleRequest(mask, 1, 100, 200); err != nil {
		t.Fatalf("first request failed: %v", err)
	}

	err := srv.HandleRequest(mask, 1, 100, 200)
	if err != errors.ErrBusy {
		t.Errorf("err = %v, want ErrBusy", err)
	}
}

func TestEnergyScanServer_HandleRequest_ClampsCount(t *testing.T) {
	scanner := newMockEnergyScanner()
	srv := NewEnergyScanServer(scanner)

	mask := maskFromChannels(11)
	_ = srv.HandleRequest(mask, 0, 100, 200) // count 0 → clamped to 1
	if srv.count != energyMinCount {
		t.Errorf("count = %d, want %d", srv.count, energyMinCount)
	}

	srv.Stop()
	_ = srv.HandleRequest(mask, 10, 100, 200) // count 10 → clamped to 3
	if srv.count != energyMaxCount {
		t.Errorf("count = %d, want %d", srv.count, energyMaxCount)
	}
}

func TestEnergyScanServer_SingleChannelSinglePass(t *testing.T) {
	scanner := newMockEnergyScanner()
	scanner.results[11] = -50

	srv := NewEnergyScanServer(scanner)

	var reportMask uint32
	var reportResults []EnergyScanResult
	srv.SetReportCallback(func(mask uint32, results []EnergyScanResult) {
		reportMask = mask
		reportResults = results
	})

	mask := maskFromChannels(11)
	if err := srv.HandleRequest(mask, 1, 100, 200); err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}

	if !srv.IsScanning() {
		t.Error("should be scanning")
	}

	// Drive the state machine: one HandleTimer for the scan, one to finalize.
	srv.HandleTimer()

	if srv.IsScanning() {
		t.Error("should not be scanning after single-channel single-pass")
	}

	if reportMask != mask {
		t.Errorf("reportMask = 0x%08x, want 0x%08x", reportMask, mask)
	}
	if len(reportResults) != 1 {
		t.Fatalf("len(reportResults) = %d, want 1", len(reportResults))
	}
	if reportResults[0].Channel != 11 {
		t.Errorf("Channel = %d, want 11", reportResults[0].Channel)
	}
	if reportResults[0].MaxRssi != -50 {
		t.Errorf("MaxRssi = %d, want -50", reportResults[0].MaxRssi)
	}
}

func TestEnergyScanServer_MultipleChannelsSinglePass(t *testing.T) {
	scanner := newMockEnergyScanner()
	scanner.results[11] = -40
	scanner.results[15] = -60
	scanner.results[26] = -80

	srv := NewEnergyScanServer(scanner)

	var reportResults []EnergyScanResult
	srv.SetReportCallback(func(_ uint32, results []EnergyScanResult) {
		reportResults = results
	})

	mask := maskFromChannels(11, 15, 26)
	if err := srv.HandleRequest(mask, 1, 100, 200); err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}

	// Drive through all channels.
	for srv.IsScanning() {
		srv.HandleTimer()
	}

	if len(reportResults) != 3 {
		t.Fatalf("len(reportResults) = %d, want 3", len(reportResults))
	}

	// Results should be in channel order (lowest first).
	expectedChannels := []uint16{11, 15, 26}
	expectedRssi := []int8{-40, -60, -80}
	for i, r := range reportResults {
		if r.Channel != expectedChannels[i] {
			t.Errorf("result[%d].Channel = %d, want %d", i, r.Channel, expectedChannels[i])
		}
		if r.MaxRssi != expectedRssi[i] {
			t.Errorf("result[%d].MaxRssi = %d, want %d", i, r.MaxRssi, expectedRssi[i])
		}
	}
}

func TestEnergyScanServer_MultiplePassses(t *testing.T) {
	scanner := newMockEnergyScanner()
	scanner.results[11] = -50
	scanner.results[15] = -70

	srv := NewEnergyScanServer(scanner)

	var reportResults []EnergyScanResult
	srv.SetReportCallback(func(_ uint32, results []EnergyScanResult) {
		reportResults = results
	})

	mask := maskFromChannels(11, 15)
	// 2 passes
	if err := srv.HandleRequest(mask, 2, 100, 200); err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}

	for srv.IsScanning() {
		srv.HandleTimer()
	}

	// 2 channels × 2 passes = 4 results
	if len(reportResults) != 4 {
		t.Fatalf("len(reportResults) = %d, want 4", len(reportResults))
	}

	// Pass 1: ch11, ch15; Pass 2: ch11, ch15
	expected := []EnergyScanResult{
		{Channel: 11, MaxRssi: -50},
		{Channel: 15, MaxRssi: -70},
		{Channel: 11, MaxRssi: -50},
		{Channel: 15, MaxRssi: -70},
	}
	for i, r := range reportResults {
		if r != expected[i] {
			t.Errorf("result[%d] = %+v, want %+v", i, r, expected[i])
		}
	}
}

func TestEnergyScanServer_ScannerError(t *testing.T) {
	scanner := newMockEnergyScanner()
	scanner.failChan[11] = true

	srv := NewEnergyScanServer(scanner)

	var reportResults []EnergyScanResult
	srv.SetReportCallback(func(_ uint32, results []EnergyScanResult) {
		reportResults = results
	})

	mask := maskFromChannels(11)
	if err := srv.HandleRequest(mask, 1, 100, 200); err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}

	srv.HandleTimer()

	if len(reportResults) != 1 {
		t.Fatalf("len(reportResults) = %d, want 1", len(reportResults))
	}
	// On error, RSSI should be -128 (minimum sentinel).
	if reportResults[0].MaxRssi != -128 {
		t.Errorf("MaxRssi = %d, want -128", reportResults[0].MaxRssi)
	}
}

func TestEnergyScanServer_Stop(t *testing.T) {
	scanner := newMockEnergyScanner()
	srv := NewEnergyScanServer(scanner)

	mask := maskFromChannels(11, 15, 26)
	if err := srv.HandleRequest(mask, 3, 100, 200); err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}

	if !srv.IsScanning() {
		t.Error("should be scanning")
	}

	srv.Stop()

	if srv.IsScanning() {
		t.Error("should not be scanning after Stop")
	}
}

func TestEnergyScanServer_NoCallbackDoesNotPanic(t *testing.T) {
	scanner := newMockEnergyScanner()
	scanner.results[11] = -50

	srv := NewEnergyScanServer(scanner)
	// No callback set.

	mask := maskFromChannels(11)
	if err := srv.HandleRequest(mask, 1, 100, 200); err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}

	// Should not panic.
	srv.HandleTimer()

	if srv.IsScanning() {
		t.Error("should not be scanning")
	}
}

func TestEnergyScanServer_HandleTimerWhenNotScanning(t *testing.T) {
	scanner := newMockEnergyScanner()
	srv := NewEnergyScanServer(scanner)

	// Should be a no-op and not panic.
	srv.HandleTimer()
	if scanner.callCount() != 0 {
		t.Error("scanner should not have been called")
	}
}

func TestEnergyScanServer_Results(t *testing.T) {
	scanner := newMockEnergyScanner()
	scanner.results[11] = -45
	srv := NewEnergyScanServer(scanner)

	mask := maskFromChannels(11)
	_ = srv.HandleRequest(mask, 1, 100, 200)
	srv.HandleTimer()

	results := srv.Results()
	if len(results) != 1 {
		t.Fatalf("len(Results()) = %d, want 1", len(results))
	}
	if results[0].Channel != 11 || results[0].MaxRssi != -45 {
		t.Errorf("Results()[0] = %+v, want {11 -45}", results[0])
	}
}

func TestEnergyScanServer_ScanDuration(t *testing.T) {
	scanner := newMockEnergyScanner()
	srv := NewEnergyScanServer(scanner)

	mask := maskFromChannels(11)
	_ = srv.HandleRequest(mask, 1, 100, 300)

	srv.HandleTimer()

	scanner.mu.Lock()
	defer scanner.mu.Unlock()
	if len(scanner.calls) != 1 {
		t.Fatalf("call count = %d, want 1", len(scanner.calls))
	}
	if scanner.calls[0].Duration != 300 {
		t.Errorf("duration = %d, want 300", scanner.calls[0].Duration)
	}
}

// ---------------------------------------------------------------------------
// PanIdQueryServer tests
// ---------------------------------------------------------------------------

func TestPanIdQueryServer_New(t *testing.T) {
	scanner := newMockPanIDScanner()
	srv := NewPanIdQueryServer(scanner)

	if srv.IsScanning() {
		t.Error("new server should not be scanning")
	}
	if srv.panID != 0xffff {
		t.Errorf("panID = 0x%04x, want 0xffff", srv.panID)
	}
}

func TestPanIdQueryServer_HandleRequest_InvalidMask(t *testing.T) {
	scanner := newMockPanIDScanner()
	srv := NewPanIdQueryServer(scanner)

	err := srv.HandleRequest(0x1234, 0)
	if err != errors.ErrInvalidArgs {
		t.Errorf("err = %v, want ErrInvalidArgs", err)
	}
}

func TestPanIdQueryServer_HandleRequest_Busy(t *testing.T) {
	scanner := newMockPanIDScanner()
	srv := NewPanIdQueryServer(scanner)

	mask := maskFromChannels(11)
	if err := srv.HandleRequest(0x1234, mask); err != nil {
		t.Fatalf("first request failed: %v", err)
	}

	err := srv.HandleRequest(0x1234, mask)
	if err != errors.ErrBusy {
		t.Errorf("err = %v, want ErrBusy", err)
	}
}

func TestPanIdQueryServer_NoConflict(t *testing.T) {
	scanner := newMockPanIDScanner()
	// No channels have the PAN ID.

	srv := NewPanIdQueryServer(scanner)

	callbackCalled := false
	srv.SetReportCallback(func(panID uint16, mask uint32) {
		callbackCalled = true
	})

	mask := maskFromChannels(11, 15)
	if err := srv.HandleRequest(0x1234, mask); err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}

	for srv.IsScanning() {
		srv.HandleTimer()
	}

	if callbackCalled {
		t.Error("callback should not be called when no conflicts found")
	}
	if srv.Conflicts() != 0 {
		t.Errorf("Conflicts() = 0x%08x, want 0", srv.Conflicts())
	}
}

func TestPanIdQueryServer_ConflictOnSingleChannel(t *testing.T) {
	scanner := newMockPanIDScanner()
	scanner.foundOnChan[15] = true

	srv := NewPanIdQueryServer(scanner)

	var reportPanID uint16
	var reportMask uint32
	srv.SetReportCallback(func(panID uint16, mask uint32) {
		reportPanID = panID
		reportMask = mask
	})

	mask := maskFromChannels(11, 15, 26)
	if err := srv.HandleRequest(0xABCD, mask); err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}

	for srv.IsScanning() {
		srv.HandleTimer()
	}

	if reportPanID != 0xABCD {
		t.Errorf("reportPanID = 0x%04x, want 0xABCD", reportPanID)
	}
	expectedConflict := maskFromChannels(15)
	if reportMask != expectedConflict {
		t.Errorf("reportMask = 0x%08x, want 0x%08x", reportMask, expectedConflict)
	}
}

func TestPanIdQueryServer_ConflictOnMultipleChannels(t *testing.T) {
	scanner := newMockPanIDScanner()
	scanner.foundOnChan[11] = true
	scanner.foundOnChan[26] = true

	srv := NewPanIdQueryServer(scanner)

	var reportMask uint32
	srv.SetReportCallback(func(_ uint16, mask uint32) {
		reportMask = mask
	})

	mask := maskFromChannels(11, 15, 26)
	if err := srv.HandleRequest(0x5678, mask); err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}

	for srv.IsScanning() {
		srv.HandleTimer()
	}

	expectedConflict := maskFromChannels(11, 26)
	if reportMask != expectedConflict {
		t.Errorf("reportMask = 0x%08x, want 0x%08x", reportMask, expectedConflict)
	}
}

func TestPanIdQueryServer_Stop(t *testing.T) {
	scanner := newMockPanIDScanner()
	srv := NewPanIdQueryServer(scanner)

	mask := maskFromChannels(11, 15, 26)
	if err := srv.HandleRequest(0x1234, mask); err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}

	srv.Stop()

	if srv.IsScanning() {
		t.Error("should not be scanning after Stop")
	}
}

func TestPanIdQueryServer_HandleTimerWhenNotScanning(t *testing.T) {
	scanner := newMockPanIDScanner()
	srv := NewPanIdQueryServer(scanner)

	// Should be a no-op and not panic.
	srv.HandleTimer()
	if scanner.callCount() != 0 {
		t.Error("scanner should not have been called")
	}
}

func TestPanIdQueryServer_NoCallbackDoesNotPanic(t *testing.T) {
	scanner := newMockPanIDScanner()
	scanner.foundOnChan[11] = true

	srv := NewPanIdQueryServer(scanner)
	// No callback set.

	mask := maskFromChannels(11)
	if err := srv.HandleRequest(0x1234, mask); err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}

	// Should not panic even with a conflict and no callback.
	for srv.IsScanning() {
		srv.HandleTimer()
	}
}

func TestPanIdQueryServer_ScansAllChannels(t *testing.T) {
	scanner := newMockPanIDScanner()
	srv := NewPanIdQueryServer(scanner)

	mask := maskFromChannels(11, 15, 26)
	if err := srv.HandleRequest(0x1234, mask); err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}

	for srv.IsScanning() {
		srv.HandleTimer()
	}

	scanner.mu.Lock()
	defer scanner.mu.Unlock()
	if len(scanner.calls) != 3 {
		t.Fatalf("call count = %d, want 3", len(scanner.calls))
	}

	// Channels scanned in ascending order.
	expectedChannels := []uint16{11, 15, 26}
	for i, c := range scanner.calls {
		if c.Channel != expectedChannels[i] {
			t.Errorf("call[%d].Channel = %d, want %d", i, c.Channel, expectedChannels[i])
		}
		if c.PanID != 0x1234 {
			t.Errorf("call[%d].PanID = 0x%04x, want 0x1234", i, c.PanID)
		}
	}
}

// ---------------------------------------------------------------------------
// AnycastLocator tests
// ---------------------------------------------------------------------------

func TestAnycastLocator_New(t *testing.T) {
	loc := NewAnycastLocator()
	if loc.IsInProgress() {
		t.Error("new locator should not be in progress")
	}
}

func TestAnycastLocator_Locate_NilCallback(t *testing.T) {
	loc := NewAnycastLocator()
	err := loc.Locate([16]byte{}, nil)
	if err != errors.ErrInvalidArgs {
		t.Errorf("err = %v, want ErrInvalidArgs", err)
	}
}

func TestAnycastLocator_Locate_SetsInProgress(t *testing.T) {
	loc := NewAnycastLocator()
	err := loc.Locate([16]byte{0xfc, 0x00}, func(error, uint16, [16]byte) {})
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	if !loc.IsInProgress() {
		t.Error("should be in progress after Locate")
	}
}

func TestAnycastLocator_HandleResponse(t *testing.T) {
	loc := NewAnycastLocator()

	var gotErr error
	var gotRloc uint16
	var gotEid [16]byte

	addr := [16]byte{0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_ = loc.Locate(addr, func(err error, rloc16 uint16, eid [16]byte) {
		gotErr = err
		gotRloc = rloc16
		gotEid = eid
	})

	expectedEid := [16]byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	loc.HandleResponse(0x4000, expectedEid)

	if gotErr != nil {
		t.Errorf("gotErr = %v, want nil", gotErr)
	}
	if gotRloc != 0x4000 {
		t.Errorf("gotRloc = 0x%04x, want 0x4000", gotRloc)
	}
	if gotEid != expectedEid {
		t.Errorf("gotEid = %v, want %v", gotEid, expectedEid)
	}
	if loc.IsInProgress() {
		t.Error("should not be in progress after HandleResponse")
	}
}

func TestAnycastLocator_HandleError(t *testing.T) {
	loc := NewAnycastLocator()

	var gotErr error
	var gotRloc uint16
	var gotEid [16]byte

	_ = loc.Locate([16]byte{}, func(err error, rloc16 uint16, eid [16]byte) {
		gotErr = err
		gotRloc = rloc16
		gotEid = eid
	})

	loc.HandleError(errors.ErrResponseTimeout)

	if gotErr != errors.ErrResponseTimeout {
		t.Errorf("gotErr = %v, want ErrResponseTimeout", gotErr)
	}
	if gotRloc != 0 {
		t.Errorf("gotRloc = 0x%04x, want 0", gotRloc)
	}
	if gotEid != ([16]byte{}) {
		t.Errorf("gotEid = %v, want zero", gotEid)
	}
	if loc.IsInProgress() {
		t.Error("should not be in progress after HandleError")
	}
}

func TestAnycastLocator_HandleResponseWhenNotPending(t *testing.T) {
	loc := NewAnycastLocator()

	callbackCalled := false
	// No Locate call — not pending.
	loc.HandleResponse(0x1234, [16]byte{})
	if callbackCalled {
		t.Error("callback should not be invoked when not pending")
	}
}

func TestAnycastLocator_HandleErrorWhenNotPending(t *testing.T) {
	loc := NewAnycastLocator()

	// No Locate call — not pending.
	// Should not panic.
	loc.HandleError(errors.ErrFailed)
}

func TestAnycastLocator_ReplacesPreviousRequest(t *testing.T) {
	loc := NewAnycastLocator()

	firstCalled := false
	_ = loc.Locate([16]byte{}, func(error, uint16, [16]byte) {
		firstCalled = true
	})

	var secondErr error
	_ = loc.Locate([16]byte{}, func(err error, _ uint16, _ [16]byte) {
		secondErr = err
	})

	// The second Locate replaces the first. Only the second callback
	// should be invoked.
	loc.HandleResponse(0x2000, [16]byte{0xAA})

	if firstCalled {
		t.Error("first callback should not be called after replacement")
	}
	if secondErr != nil {
		t.Errorf("secondErr = %v, want nil", secondErr)
	}
}

func TestAnycastLocator_DoubleHandleResponse(t *testing.T) {
	loc := NewAnycastLocator()

	callCount := 0
	_ = loc.Locate([16]byte{}, func(error, uint16, [16]byte) {
		callCount++
	})

	loc.HandleResponse(0x1000, [16]byte{})
	loc.HandleResponse(0x2000, [16]byte{}) // Should be a no-op.

	if callCount != 1 {
		t.Errorf("callCount = %d, want 1", callCount)
	}
}
