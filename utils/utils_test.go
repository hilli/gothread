// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"testing"

	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

// mockEnergyScanner returns configurable RSSI values per channel.
type mockEnergyScanner struct {
	rssi      map[uint16]int8 // channel -> RSSI
	scanErr   error
	scanCount int
}

func newMockEnergyScanner() *mockEnergyScanner {
	return &mockEnergyScanner{rssi: make(map[uint16]int8)}
}

func (s *mockEnergyScanner) EnergyScan(channel uint16, _ uint16) (int8, error) {
	s.scanCount++
	if s.scanErr != nil {
		return 0, s.scanErr
	}
	if v, ok := s.rssi[channel]; ok {
		return v, nil
	}
	return -100, nil // very quiet by default
}

// mockNetworkDataUpdater records channel change requests.
type mockNetworkDataUpdater struct {
	lastChannel uint16
	callCount   int
	err         error
}

func (u *mockNetworkDataUpdater) RequestChannelChange(channel uint16) error {
	u.callCount++
	u.lastChannel = channel
	return u.err
}

// mockRssiReader returns a configurable RSSI value.
type mockRssiReader struct {
	rssi int8
	err  error
}

func (r *mockRssiReader) GetRssi() (int8, error) {
	return r.rssi, r.err
}

// ---------------------------------------------------------------------------
// ChannelMonitor tests
// ---------------------------------------------------------------------------

func TestNewChannelMonitor_Defaults(t *testing.T) {
	scanner := newMockEnergyScanner()
	m := NewChannelMonitor(scanner)

	if m.sampleInterval != DefaultSampleInterval {
		t.Fatalf("expected sample interval %d, got %d", DefaultSampleInterval, m.sampleInterval)
	}
	if m.rssiThreshold != DefaultRssiThreshold {
		t.Fatalf("expected RSSI threshold %d, got %d", DefaultRssiThreshold, m.rssiThreshold)
	}
	if m.sampleWindow != DefaultSampleWindow {
		t.Fatalf("expected sample window %d, got %d", DefaultSampleWindow, m.sampleWindow)
	}
	if m.IsEnabled() {
		t.Fatal("expected monitor to be disabled initially")
	}
}

func TestNewChannelMonitor_Options(t *testing.T) {
	scanner := newMockEnergyScanner()
	m := NewChannelMonitor(scanner,
		WithSampleInterval(5000),
		WithRssiThreshold(-60),
		WithSampleWindow(100),
	)

	if m.sampleInterval != 5000 {
		t.Fatalf("expected sample interval 5000, got %d", m.sampleInterval)
	}
	if m.rssiThreshold != -60 {
		t.Fatalf("expected RSSI threshold -60, got %d", m.rssiThreshold)
	}
	if m.sampleWindow != 100 {
		t.Fatalf("expected sample window 100, got %d", m.sampleWindow)
	}
}

func TestNewChannelMonitor_InvalidOptions(t *testing.T) {
	scanner := newMockEnergyScanner()
	m := NewChannelMonitor(scanner,
		WithSampleInterval(0),
		WithSampleWindow(0),
	)
	if m.sampleInterval != DefaultSampleInterval {
		t.Fatal("zero sample interval should keep default")
	}
	if m.sampleWindow != DefaultSampleWindow {
		t.Fatal("zero sample window should keep default")
	}
}

func TestChannelMonitor_StartStop(t *testing.T) {
	scanner := newMockEnergyScanner()
	m := NewChannelMonitor(scanner)

	if err := m.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if !m.IsEnabled() {
		t.Fatal("expected enabled after Start")
	}

	// Starting again should return ErrAlready.
	if err := m.Start(); err != errors.ErrAlready {
		t.Fatalf("expected ErrAlready, got %v", err)
	}

	m.Stop()
	if m.IsEnabled() {
		t.Fatal("expected disabled after Stop")
	}
}

func TestChannelMonitor_HandleTimer_SampleCount(t *testing.T) {
	scanner := newMockEnergyScanner()
	m := NewChannelMonitor(scanner)
	_ = m.Start()

	if m.GetSampleCount() != 0 {
		t.Fatal("expected 0 samples before any timer tick")
	}

	m.HandleTimer()
	if m.GetSampleCount() != 1 {
		t.Fatalf("expected 1 sample after one timer tick, got %d", m.GetSampleCount())
	}

	m.HandleTimer()
	if m.GetSampleCount() != 2 {
		t.Fatalf("expected 2 samples, got %d", m.GetSampleCount())
	}
}

func TestChannelMonitor_Occupancy_QuietChannels(t *testing.T) {
	scanner := newMockEnergyScanner()
	// All channels return -100 (well below default threshold of -75).
	m := NewChannelMonitor(scanner)
	_ = m.Start()

	for i := 0; i < 10; i++ {
		m.HandleTimer()
	}

	for ch := uint16(ChannelMin); ch <= ChannelMax; ch++ {
		occ, err := m.GetChannelOccupancy(ch)
		if err != nil {
			t.Fatalf("GetChannelOccupancy(%d) error: %v", ch, err)
		}
		if occ != 0 {
			t.Fatalf("expected 0 occupancy for quiet channel %d, got %d", ch, occ)
		}
	}
}

func TestChannelMonitor_Occupancy_BusyChannel(t *testing.T) {
	scanner := newMockEnergyScanner()
	scanner.rssi[15] = -50 // channel 15 is noisy (above -75 threshold)
	m := NewChannelMonitor(scanner)
	_ = m.Start()

	for i := 0; i < 100; i++ {
		m.HandleTimer()
	}

	occ, err := m.GetChannelOccupancy(15)
	if err != nil {
		t.Fatalf("GetChannelOccupancy(15) error: %v", err)
	}
	if occ == 0 {
		t.Fatal("expected non-zero occupancy for busy channel 15")
	}

	// Quiet channel should still be 0.
	occ11, _ := m.GetChannelOccupancy(11)
	if occ11 != 0 {
		t.Fatalf("expected 0 occupancy for quiet channel 11, got %d", occ11)
	}
}

func TestChannelMonitor_Occupancy_AllBusy(t *testing.T) {
	scanner := newMockEnergyScanner()
	for ch := uint16(ChannelMin); ch <= ChannelMax; ch++ {
		scanner.rssi[ch] = -40 // all channels busy
	}
	m := NewChannelMonitor(scanner, WithSampleWindow(10))
	_ = m.Start()

	for i := 0; i < 50; i++ {
		m.HandleTimer()
	}

	for ch := uint16(ChannelMin); ch <= ChannelMax; ch++ {
		occ, _ := m.GetChannelOccupancy(ch)
		if occ != MaxOccupancy {
			t.Fatalf("expected max occupancy for channel %d, got %d", ch, occ)
		}
	}
}

func TestChannelMonitor_GetChannelOccupancy_InvalidChannel(t *testing.T) {
	scanner := newMockEnergyScanner()
	m := NewChannelMonitor(scanner)

	_, err := m.GetChannelOccupancy(10) // below ChannelMin
	if err != errors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs for channel 10, got %v", err)
	}

	_, err = m.GetChannelOccupancy(27) // above ChannelMax
	if err != errors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs for channel 27, got %v", err)
	}
}

func TestChannelMonitor_GetBestChannels(t *testing.T) {
	scanner := newMockEnergyScanner()
	scanner.rssi[20] = -50 // channel 20 is noisy
	scanner.rssi[21] = -40 // channel 21 is noisier
	m := NewChannelMonitor(scanner, WithSampleWindow(10))
	_ = m.Start()

	for i := 0; i < 20; i++ {
		m.HandleTimer()
	}

	best := m.GetBestChannels(3)
	if len(best) != 3 {
		t.Fatalf("expected 3 best channels, got %d", len(best))
	}

	// None of the best channels should be 20 or 21 (the noisy ones).
	for _, ch := range best {
		if ch == 20 || ch == 21 {
			t.Fatalf("noisy channel %d should not be in best channels", ch)
		}
	}
}

func TestChannelMonitor_GetBestChannels_EdgeCases(t *testing.T) {
	scanner := newMockEnergyScanner()
	m := NewChannelMonitor(scanner)

	// Zero count.
	if got := m.GetBestChannels(0); got != nil {
		t.Fatalf("expected nil for count 0, got %v", got)
	}

	// Negative count.
	if got := m.GetBestChannels(-1); got != nil {
		t.Fatalf("expected nil for count -1, got %v", got)
	}

	// More than NumChannels.
	got := m.GetBestChannels(100)
	if len(got) != NumChannels {
		t.Fatalf("expected %d channels, got %d", NumChannels, len(got))
	}
}

func TestChannelMonitor_HandleTimer_WhenDisabled(t *testing.T) {
	scanner := newMockEnergyScanner()
	m := NewChannelMonitor(scanner)
	// Don't start the monitor.
	m.HandleTimer()
	if m.GetSampleCount() != 0 {
		t.Fatal("HandleTimer should not sample when disabled")
	}
}

func TestChannelMonitor_ScanError(t *testing.T) {
	scanner := newMockEnergyScanner()
	scanner.scanErr = errors.ErrFailed
	m := NewChannelMonitor(scanner)
	_ = m.Start()

	m.HandleTimer()
	// Sample count should still increment even with scan errors.
	if m.GetSampleCount() != 1 {
		t.Fatalf("expected sample count 1 after timer tick with errors, got %d", m.GetSampleCount())
	}

	// All channels should be 0 since scans failed.
	for ch := uint16(ChannelMin); ch <= ChannelMax; ch++ {
		occ, _ := m.GetChannelOccupancy(ch)
		if occ != 0 {
			t.Fatalf("expected 0 occupancy for channel %d with scan errors, got %d", ch, occ)
		}
	}
}

func TestChannelMonitor_FindBestChannel(t *testing.T) {
	scanner := newMockEnergyScanner()
	scanner.rssi[15] = -50 // noisy
	m := NewChannelMonitor(scanner, WithSampleWindow(10))
	_ = m.Start()

	for i := 0; i < 20; i++ {
		m.HandleTimer()
	}

	// All channels supported.
	ch, occ := m.FindBestChannel(DefaultSupportedChannelMask)
	if ch == 15 {
		t.Fatal("best channel should not be the noisy channel 15")
	}
	if occ != 0 {
		t.Fatalf("expected 0 occupancy for best channel, got %d", occ)
	}
	_ = ch
}

func TestChannelMonitor_FindBestChannel_EmptyMask(t *testing.T) {
	scanner := newMockEnergyScanner()
	m := NewChannelMonitor(scanner)

	ch, occ := m.FindBestChannel(0)
	if ch != 0 {
		t.Fatalf("expected channel 0 for empty mask, got %d", ch)
	}
	if occ != MaxOccupancy {
		t.Fatalf("expected max occupancy for empty mask, got %d", occ)
	}
}

func TestChannelMonitor_EWMA_Convergence(t *testing.T) {
	scanner := newMockEnergyScanner()
	scanner.rssi[11] = -50 // busy for first phase
	m := NewChannelMonitor(scanner, WithSampleWindow(10))
	_ = m.Start()

	// Phase 1: channel 11 busy.
	for i := 0; i < 20; i++ {
		m.HandleTimer()
	}

	occBusy, _ := m.GetChannelOccupancy(11)
	if occBusy == 0 {
		t.Fatal("expected non-zero occupancy after busy phase")
	}

	// Phase 2: channel 11 becomes quiet.
	scanner.rssi[11] = -100
	for i := 0; i < 100; i++ {
		m.HandleTimer()
	}

	occQuiet, _ := m.GetChannelOccupancy(11)
	if occQuiet >= occBusy {
		t.Fatalf("occupancy should decrease after quiet phase: busy=%d quiet=%d", occBusy, occQuiet)
	}
}

// ---------------------------------------------------------------------------
// ChannelManager tests
// ---------------------------------------------------------------------------

func TestNewChannelManager_Defaults(t *testing.T) {
	scanner := newMockEnergyScanner()
	monitor := NewChannelMonitor(scanner)
	updater := &mockNetworkDataUpdater{}
	mgr := NewChannelManager(monitor, updater)

	if mgr.GetDelay() != DefaultDelay {
		t.Fatalf("expected delay %d, got %d", DefaultDelay, mgr.GetDelay())
	}
	if mgr.GetAutoSelectInterval() != DefaultAutoSelectInterval {
		t.Fatalf("expected auto-select interval %d, got %d", DefaultAutoSelectInterval, mgr.GetAutoSelectInterval())
	}
	if mgr.IsAutoSelectEnabled() {
		t.Fatal("expected auto-select disabled initially")
	}
	if mgr.GetSupportedChannels() != DefaultSupportedChannelMask {
		t.Fatalf("expected supported channels %x, got %x", DefaultSupportedChannelMask, mgr.GetSupportedChannels())
	}
}

func TestNewChannelManager_Options(t *testing.T) {
	scanner := newMockEnergyScanner()
	monitor := NewChannelMonitor(scanner)
	updater := &mockNetworkDataUpdater{}
	mgr := NewChannelManager(monitor, updater,
		WithDelay(300),
		WithAutoSelectInterval(7200),
		WithFavoredChannels(0x0F800),
		WithSupportedChannels(0x07FFF800),
	)

	if mgr.GetDelay() != 300 {
		t.Fatalf("expected delay 300, got %d", mgr.GetDelay())
	}
	if mgr.GetAutoSelectInterval() != 7200 {
		t.Fatalf("expected auto-select interval 7200, got %d", mgr.GetAutoSelectInterval())
	}
	if mgr.GetFavoredChannels() != 0x0F800 {
		t.Fatalf("expected favored channels 0x0F800, got %x", mgr.GetFavoredChannels())
	}
}

func TestChannelManager_DelayBelowMinimum(t *testing.T) {
	scanner := newMockEnergyScanner()
	monitor := NewChannelMonitor(scanner)
	updater := &mockNetworkDataUpdater{}
	mgr := NewChannelManager(monitor, updater, WithDelay(10))

	// Should keep default since 10 < MinimumDelay.
	if mgr.GetDelay() != DefaultDelay {
		t.Fatalf("expected default delay, got %d", mgr.GetDelay())
	}
}

func TestChannelManager_RequestChannelChange(t *testing.T) {
	scanner := newMockEnergyScanner()
	monitor := NewChannelMonitor(scanner)
	updater := &mockNetworkDataUpdater{}
	mgr := NewChannelManager(monitor, updater)
	mgr.SetCurrentChannel(15)

	if err := mgr.RequestChannelChange(20); err != nil {
		t.Fatalf("RequestChannelChange failed: %v", err)
	}
	if mgr.selectedChannel != 20 {
		t.Fatalf("expected selected channel 20, got %d", mgr.selectedChannel)
	}
	if mgr.state != stateChangeRequested {
		t.Fatal("expected state change requested")
	}
}

func TestChannelManager_RequestChannelChange_InvalidChannel(t *testing.T) {
	scanner := newMockEnergyScanner()
	monitor := NewChannelMonitor(scanner)
	updater := &mockNetworkDataUpdater{}
	mgr := NewChannelManager(monitor, updater)

	if err := mgr.RequestChannelChange(5); err != errors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs for channel 5, got %v", err)
	}
	if err := mgr.RequestChannelChange(30); err != errors.ErrInvalidArgs {
		t.Fatalf("expected ErrInvalidArgs for channel 30, got %v", err)
	}
}

func TestChannelManager_RequestChannelChange_SameChannel(t *testing.T) {
	scanner := newMockEnergyScanner()
	monitor := NewChannelMonitor(scanner)
	updater := &mockNetworkDataUpdater{}
	mgr := NewChannelManager(monitor, updater)
	mgr.SetCurrentChannel(15)

	if err := mgr.RequestChannelChange(15); err != errors.ErrAlready {
		t.Fatalf("expected ErrAlready for same channel, got %v", err)
	}
}

func TestChannelManager_HandleTimer_AppliesChange(t *testing.T) {
	scanner := newMockEnergyScanner()
	monitor := NewChannelMonitor(scanner)
	updater := &mockNetworkDataUpdater{}
	mgr := NewChannelManager(monitor, updater)
	mgr.SetCurrentChannel(15)

	_ = mgr.RequestChannelChange(20)
	mgr.HandleTimer()

	if updater.lastChannel != 20 {
		t.Fatalf("expected updater called with channel 20, got %d", updater.lastChannel)
	}
	if mgr.GetCurrentChannel() != 20 {
		t.Fatalf("expected current channel 20, got %d", mgr.GetCurrentChannel())
	}
	if mgr.state != stateIdle {
		t.Fatal("expected idle state after successful change")
	}
}

func TestChannelManager_HandleTimer_UpdaterError(t *testing.T) {
	scanner := newMockEnergyScanner()
	monitor := NewChannelMonitor(scanner)
	updater := &mockNetworkDataUpdater{err: errors.ErrBusy}
	mgr := NewChannelManager(monitor, updater)
	mgr.SetCurrentChannel(15)

	_ = mgr.RequestChannelChange(20)
	mgr.HandleTimer()

	// Should remain in change-requested state for retry.
	if mgr.state != stateChangeRequested {
		t.Fatal("expected state to remain change-requested on updater error")
	}
	if mgr.GetCurrentChannel() != 15 {
		t.Fatal("current channel should not change on updater error")
	}
}

func TestChannelManager_HandleTimer_NilUpdater(t *testing.T) {
	scanner := newMockEnergyScanner()
	monitor := NewChannelMonitor(scanner)
	mgr := NewChannelManager(monitor, nil)
	mgr.SetCurrentChannel(15)

	_ = mgr.RequestChannelChange(20)
	mgr.HandleTimer()

	// With nil updater, should still update current channel.
	if mgr.GetCurrentChannel() != 20 {
		t.Fatalf("expected current channel 20, got %d", mgr.GetCurrentChannel())
	}
}

func TestChannelManager_SetGetFavoredChannels(t *testing.T) {
	scanner := newMockEnergyScanner()
	monitor := NewChannelMonitor(scanner)
	mgr := NewChannelManager(monitor, nil)

	mgr.SetFavoredChannels(0x1234)
	if mgr.GetFavoredChannels() != 0x1234 {
		t.Fatalf("expected favored 0x1234, got %x", mgr.GetFavoredChannels())
	}
}

func TestChannelManager_SetGetSupportedChannels(t *testing.T) {
	scanner := newMockEnergyScanner()
	monitor := NewChannelMonitor(scanner)
	mgr := NewChannelManager(monitor, nil)

	mgr.SetSupportedChannels(0x5678)
	if mgr.GetSupportedChannels() != 0x5678 {
		t.Fatalf("expected supported 0x5678, got %x", mgr.GetSupportedChannels())
	}
}

func TestChannelManager_SetGetDelay(t *testing.T) {
	scanner := newMockEnergyScanner()
	monitor := NewChannelMonitor(scanner)
	mgr := NewChannelManager(monitor, nil)

	mgr.SetDelay(300)
	if mgr.GetDelay() != 300 {
		t.Fatalf("expected delay 300, got %d", mgr.GetDelay())
	}

	// Below minimum should not change.
	mgr.SetDelay(10)
	if mgr.GetDelay() != 300 {
		t.Fatalf("expected delay to stay 300, got %d", mgr.GetDelay())
	}
}

func TestChannelManager_AutoSelect(t *testing.T) {
	scanner := newMockEnergyScanner()
	monitor := NewChannelMonitor(scanner)
	mgr := NewChannelManager(monitor, nil)

	mgr.SetAutoSelectEnabled(true)
	if !mgr.IsAutoSelectEnabled() {
		t.Fatal("expected auto-select enabled")
	}

	mgr.SetAutoSelectEnabled(false)
	if mgr.IsAutoSelectEnabled() {
		t.Fatal("expected auto-select disabled")
	}
}

func TestChannelManager_RequestChannelSelect_NoSamples(t *testing.T) {
	scanner := newMockEnergyScanner()
	monitor := NewChannelMonitor(scanner)
	mgr := NewChannelManager(monitor, nil)

	// No samples collected yet.
	err := mgr.RequestChannelSelect(false)
	if err != errors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
}

func TestChannelManager_RequestChannelSelect_SkipQualityCheck(t *testing.T) {
	scanner := newMockEnergyScanner()
	scanner.rssi[20] = -50 // channel 20 is noisy
	monitor := NewChannelMonitor(scanner, WithSampleWindow(10))
	_ = monitor.Start()
	for i := 0; i < 20; i++ {
		monitor.HandleTimer()
	}

	updater := &mockNetworkDataUpdater{}
	mgr := NewChannelManager(monitor, updater)
	mgr.SetCurrentChannel(20) // We're on the noisy channel.

	err := mgr.RequestChannelSelect(true)
	if err != nil {
		t.Fatalf("RequestChannelSelect failed: %v", err)
	}

	// Should have selected a different channel.
	if mgr.selectedChannel == 20 {
		t.Fatal("should have selected a different channel than noisy 20")
	}
}

func TestChannelManager_RequestChannelSelect_NilMonitor(t *testing.T) {
	mgr := NewChannelManager(nil, nil)
	err := mgr.RequestChannelSelect(false)
	if err != errors.ErrInvalidState {
		t.Fatalf("expected ErrInvalidState with nil monitor, got %v", err)
	}
}

func TestChannelManager_HandleTimer_IdleNoAutoSelect(t *testing.T) {
	scanner := newMockEnergyScanner()
	monitor := NewChannelMonitor(scanner)
	mgr := NewChannelManager(monitor, nil)

	// With auto-select disabled, HandleTimer in idle state should be a no-op.
	mgr.HandleTimer()
	if mgr.state != stateIdle {
		t.Fatal("expected idle state")
	}
}

// ---------------------------------------------------------------------------
// JamDetector tests
// ---------------------------------------------------------------------------

func TestNewJamDetector_Defaults(t *testing.T) {
	reader := &mockRssiReader{rssi: -80}
	d := NewJamDetector(reader)

	if d.rssiThreshold != DefaultJamRssiThreshold {
		t.Fatalf("expected RSSI threshold %d, got %d", DefaultJamRssiThreshold, d.rssiThreshold)
	}
	if d.window != DefaultJamWindow {
		t.Fatalf("expected window %d, got %d", DefaultJamWindow, d.window)
	}
	if d.busyPeriod != DefaultJamBusyPeriod {
		t.Fatalf("expected busy period %d, got %d", DefaultJamBusyPeriod, d.busyPeriod)
	}
	if d.IsEnabled() {
		t.Fatal("expected disabled initially")
	}
}

func TestNewJamDetector_Options(t *testing.T) {
	reader := &mockRssiReader{rssi: -80}
	d := NewJamDetector(reader,
		WithJamRssiThreshold(-30),
		WithWindow(30),
		WithBusyPeriod(20),
		WithJamSampleInterval(100),
	)

	if d.rssiThreshold != -30 {
		t.Fatalf("expected RSSI threshold -30, got %d", d.rssiThreshold)
	}
	if d.window != 30 {
		t.Fatalf("expected window 30, got %d", d.window)
	}
	if d.busyPeriod != 20 {
		t.Fatalf("expected busy period 20, got %d", d.busyPeriod)
	}
	if d.sampleInterval != 100 {
		t.Fatalf("expected sample interval 100, got %d", d.sampleInterval)
	}
}

func TestNewJamDetector_BusyPeriodClampedToWindow(t *testing.T) {
	reader := &mockRssiReader{rssi: -80}
	d := NewJamDetector(reader,
		WithWindow(10),
		WithBusyPeriod(50), // exceeds window
	)

	if d.busyPeriod != 10 {
		t.Fatalf("expected busy period clamped to window 10, got %d", d.busyPeriod)
	}
}

func TestNewJamDetector_InvalidOptions(t *testing.T) {
	reader := &mockRssiReader{rssi: -80}
	d := NewJamDetector(reader,
		WithWindow(0),            // invalid
		WithBusyPeriod(0),        // invalid
		WithJamSampleInterval(0), // invalid
	)

	if d.window != DefaultJamWindow {
		t.Fatal("zero window should keep default")
	}
	if d.busyPeriod != DefaultJamBusyPeriod {
		t.Fatal("zero busy period should keep default")
	}
	if d.sampleInterval != DefaultJamSampleInterval {
		t.Fatal("zero sample interval should keep default")
	}
}

func TestNewJamDetector_WindowTooLarge(t *testing.T) {
	reader := &mockRssiReader{rssi: -80}
	d := NewJamDetector(reader, WithWindow(100)) // exceeds max

	if d.window != DefaultJamWindow {
		t.Fatalf("expected default window for oversized input, got %d", d.window)
	}
}

func TestJamDetector_StartStop(t *testing.T) {
	reader := &mockRssiReader{rssi: -80}
	d := NewJamDetector(reader)

	if err := d.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if !d.IsEnabled() {
		t.Fatal("expected enabled after Start")
	}

	// Starting again should return ErrAlready.
	if err := d.Start(); err != errors.ErrAlready {
		t.Fatalf("expected ErrAlready, got %v", err)
	}

	d.Stop()
	if d.IsEnabled() {
		t.Fatal("expected disabled after Stop")
	}
	if d.IsJamDetected() {
		t.Fatal("expected no jam after Stop")
	}
}

func TestJamDetector_NoJam_QuietChannel(t *testing.T) {
	reader := &mockRssiReader{rssi: -80} // below threshold
	d := NewJamDetector(reader,
		WithWindow(10),
		WithBusyPeriod(5),
		WithJamSampleInterval(100), // 10 samples per second
	)
	_ = d.Start()

	// Simulate 20 seconds.
	for i := 0; i < 200; i++ {
		d.HandleTimer()
	}

	if d.IsJamDetected() {
		t.Fatal("expected no jam on quiet channel")
	}
}

func TestJamDetector_JamDetected_BusyChannel(t *testing.T) {
	reader := &mockRssiReader{rssi: -20} // well above threshold
	d := NewJamDetector(reader,
		WithJamRssiThreshold(-45),
		WithWindow(10),
		WithBusyPeriod(5),
		WithJamSampleInterval(100), // 10 samples per second
	)
	_ = d.Start()

	// Simulate enough seconds to trigger jam detection.
	// Need at least 5 busy seconds in a 10-second window.
	for i := 0; i < 100; i++ {
		d.HandleTimer()
	}

	if !d.IsJamDetected() {
		t.Fatal("expected jam detected on busy channel")
	}
}

func TestJamDetector_JamClears(t *testing.T) {
	reader := &mockRssiReader{rssi: -20} // busy
	d := NewJamDetector(reader,
		WithJamRssiThreshold(-45),
		WithWindow(10),
		WithBusyPeriod(5),
		WithJamSampleInterval(100),
	)
	_ = d.Start()

	// Phase 1: jam detected.
	for i := 0; i < 150; i++ {
		d.HandleTimer()
	}
	if !d.IsJamDetected() {
		t.Fatal("expected jam detected in phase 1")
	}

	// Phase 2: channel becomes quiet.
	reader.rssi = -80
	for i := 0; i < 150; i++ {
		d.HandleTimer()
	}
	if d.IsJamDetected() {
		t.Fatal("expected jam cleared after quiet phase")
	}
}

func TestJamDetector_Callback(t *testing.T) {
	reader := &mockRssiReader{rssi: -20} // busy
	d := NewJamDetector(reader,
		WithJamRssiThreshold(-45),
		WithWindow(5),
		WithBusyPeriod(3),
		WithJamSampleInterval(100),
	)

	var callbackCalls int
	var lastJamState bool
	d.SetCallback(func(jamDetected bool) {
		callbackCalls++
		lastJamState = jamDetected
	})

	_ = d.Start()

	// Simulate enough time for jam detection.
	for i := 0; i < 100; i++ {
		d.HandleTimer()
	}

	if callbackCalls == 0 {
		t.Fatal("expected callback to be called")
	}
	if !lastJamState {
		t.Fatal("expected last callback to report jam detected")
	}
}

func TestJamDetector_Callback_StateChange(t *testing.T) {
	reader := &mockRssiReader{rssi: -20} // busy
	d := NewJamDetector(reader,
		WithJamRssiThreshold(-45),
		WithWindow(5),
		WithBusyPeriod(3),
		WithJamSampleInterval(100),
	)

	var states []bool
	d.SetCallback(func(jamDetected bool) {
		states = append(states, jamDetected)
	})

	_ = d.Start()

	// Phase 1: jam.
	for i := 0; i < 80; i++ {
		d.HandleTimer()
	}

	// Phase 2: quiet.
	reader.rssi = -80
	for i := 0; i < 80; i++ {
		d.HandleTimer()
	}

	if len(states) < 2 {
		t.Fatalf("expected at least 2 state changes, got %d", len(states))
	}

	// First should be true (jam detected), last should be false (cleared).
	if !states[0] {
		t.Fatal("first state change should be jam detected")
	}
	if states[len(states)-1] {
		t.Fatal("last state change should be jam cleared")
	}
}

func TestJamDetector_HistoryBitmap(t *testing.T) {
	reader := &mockRssiReader{rssi: -20} // busy
	d := NewJamDetector(reader,
		WithJamRssiThreshold(-45),
		WithWindow(10),
		WithBusyPeriod(5),
		WithJamSampleInterval(1000), // 1 sample per second
	)
	_ = d.Start()

	// Simulate 5 busy seconds.
	for i := 0; i < 5; i++ {
		d.HandleTimer()
	}

	bitmap := d.GetHistoryBitmap()
	if bitmap == 0 {
		t.Fatal("expected non-zero history bitmap after busy samples")
	}

	// All 5 LSBs should be set.
	expectedMask := uint64(0x1F) // 5 bits set
	if bitmap&expectedMask != expectedMask {
		t.Fatalf("expected lower 5 bits set in bitmap, got %064b", bitmap)
	}
}

func TestJamDetector_HistoryBitmap_Mixed(t *testing.T) {
	reader := &mockRssiReader{rssi: -20} // busy
	d := NewJamDetector(reader,
		WithJamRssiThreshold(-45),
		WithWindow(10),
		WithBusyPeriod(8),
		WithJamSampleInterval(1000), // 1 sample per second
	)
	_ = d.Start()

	// 3 busy seconds.
	for i := 0; i < 3; i++ {
		d.HandleTimer()
	}

	// 2 quiet seconds.
	reader.rssi = -80
	for i := 0; i < 2; i++ {
		d.HandleTimer()
	}

	// 3 more busy seconds.
	reader.rssi = -20
	for i := 0; i < 3; i++ {
		d.HandleTimer()
	}

	bitmap := d.GetHistoryBitmap()
	// Pattern should be: 111_00_111 from LSB = 0b11100111 = 0xE7
	expected := uint64(0xE7)
	if bitmap&0xFF != expected {
		t.Fatalf("expected bitmap pattern 0x%02X, got 0x%02X (full: %064b)",
			expected, bitmap&0xFF, bitmap)
	}
}

func TestJamDetector_HandleTimer_WhenDisabled(t *testing.T) {
	reader := &mockRssiReader{rssi: -20}
	d := NewJamDetector(reader)
	// Don't start.
	d.HandleTimer()
	if d.GetHistoryBitmap() != 0 {
		t.Fatal("HandleTimer should not update when disabled")
	}
}

func TestJamDetector_ReaderError(t *testing.T) {
	reader := &mockRssiReader{rssi: 0, err: errors.ErrFailed}
	d := NewJamDetector(reader,
		WithWindow(5),
		WithBusyPeriod(3),
		WithJamSampleInterval(100),
	)
	_ = d.Start()

	for i := 0; i < 100; i++ {
		d.HandleTimer()
	}

	// With read errors, no samples should be collected, no jam detected.
	if d.IsJamDetected() {
		t.Fatal("expected no jam with reader errors")
	}
	if d.GetHistoryBitmap() != 0 {
		t.Fatal("expected empty history with reader errors")
	}
}

func TestJamDetector_GetWindow(t *testing.T) {
	reader := &mockRssiReader{rssi: -80}
	d := NewJamDetector(reader, WithWindow(20))
	if d.GetWindow() != 20 {
		t.Fatalf("expected window 20, got %d", d.GetWindow())
	}
}

func TestJamDetector_GetBusyPeriod(t *testing.T) {
	reader := &mockRssiReader{rssi: -80}
	d := NewJamDetector(reader, WithWindow(20), WithBusyPeriod(10))
	if d.GetBusyPeriod() != 10 {
		t.Fatalf("expected busy period 10, got %d", d.GetBusyPeriod())
	}
}

func TestJamDetector_GetRssiThreshold(t *testing.T) {
	reader := &mockRssiReader{rssi: -80}
	d := NewJamDetector(reader, WithJamRssiThreshold(-30))
	if d.GetRssiThreshold() != -30 {
		t.Fatalf("expected RSSI threshold -30, got %d", d.GetRssiThreshold())
	}
}

// ---------------------------------------------------------------------------
// Integration-style tests
// ---------------------------------------------------------------------------

func TestIntegration_MonitorAndManager(t *testing.T) {
	scanner := newMockEnergyScanner()
	// Make channel 20 very noisy.
	scanner.rssi[20] = -30
	monitor := NewChannelMonitor(scanner, WithSampleWindow(10))
	_ = monitor.Start()

	// Collect samples.
	for i := 0; i < 20; i++ {
		monitor.HandleTimer()
	}

	updater := &mockNetworkDataUpdater{}
	mgr := NewChannelManager(monitor, updater)
	mgr.SetCurrentChannel(20) // We're on the noisy channel.

	// Skip quality check to force selection.
	err := mgr.RequestChannelSelect(true)
	if err != nil {
		t.Fatalf("RequestChannelSelect failed: %v", err)
	}

	// Apply the change.
	mgr.HandleTimer()

	if mgr.GetCurrentChannel() == 20 {
		t.Fatal("expected manager to switch away from noisy channel 20")
	}
}

func TestIntegration_MonitorBestChannelsMatchManager(t *testing.T) {
	scanner := newMockEnergyScanner()
	scanner.rssi[11] = -50 // somewhat noisy
	scanner.rssi[12] = -40 // noisier
	monitor := NewChannelMonitor(scanner, WithSampleWindow(10))
	_ = monitor.Start()

	for i := 0; i < 30; i++ {
		monitor.HandleTimer()
	}

	best := monitor.GetBestChannels(1)
	if len(best) != 1 {
		t.Fatal("expected exactly 1 best channel")
	}

	// The best channel should not be 11 or 12.
	if best[0] == 11 || best[0] == 12 {
		t.Fatalf("best channel %d should not be one of the noisy channels", best[0])
	}
}
