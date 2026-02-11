// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package seeker

import (
	"sync"
	"testing"
)

// mockScanner is a test Scanner implementation.
type mockScanner struct {
	mu       sync.Mutex
	scanning bool
	cb       func(result *DiscoverResult)
}

func (m *mockScanner) StartScan(cb func(result *DiscoverResult)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scanning = true
	m.cb = cb
	return nil
}

func (m *mockScanner) StopScan() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scanning = false
	m.cb = nil
}

func (m *mockScanner) pushResult(r *DiscoverResult) {
	m.mu.Lock()
	cb := m.cb
	m.mu.Unlock()
	if cb != nil {
		cb(r)
	}
}

func TestNewSeeker(t *testing.T) {
	s := NewSeeker(&mockScanner{})
	if s.GetState() != StateStopped {
		t.Errorf("initial state = %s, want Stopped", s.GetState())
	}
}

func TestStartStop(t *testing.T) {
	scanner := &mockScanner{}
	s := NewSeeker(scanner)

	err := s.Start(nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if s.GetState() != StateDiscover {
		t.Errorf("state = %s, want Discover", s.GetState())
	}

	// Double start fails.
	if err := s.Start(nil); err == nil {
		t.Error("double Start should return error")
	}

	// Stop.
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if s.GetState() != StateStopped {
		t.Errorf("state = %s, want Stopped", s.GetState())
	}

	// Double stop fails.
	if err := s.Stop(); err == nil {
		t.Error("double Stop should return error")
	}
}

func TestDiscoverResults(t *testing.T) {
	scanner := &mockScanner{}
	s := NewSeeker(scanner)

	var gotResults []DiscoverResult
	err := s.Start(func(results []DiscoverResult) {
		gotResults = results
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Push some results.
	scanner.pushResult(&DiscoverResult{
		NetworkName: "Net1",
		PanID:       0x1234,
		Channel:     11,
		RSSI:        -50,
	})
	scanner.pushResult(&DiscoverResult{
		NetworkName: "Net2",
		ExtPanID:    [8]byte{0xDE, 0xAD},
		PanID:       0x5678,
		Channel:     15,
		RSSI:        -40,
	})

	// Check intermediate results.
	results := s.GetResults()
	if len(results) != 2 {
		t.Fatalf("GetResults returned %d, want 2", len(results))
	}

	// Signal scan complete.
	scanner.pushResult(nil)

	// Callback should have fired.
	if len(gotResults) != 2 {
		t.Fatalf("callback received %d results, want 2", len(gotResults))
	}
	if gotResults[0].NetworkName != "Net1" {
		t.Errorf("result[0].NetworkName = %q, want %q", gotResults[0].NetworkName, "Net1")
	}
	if gotResults[1].NetworkName != "Net2" {
		t.Errorf("result[1].NetworkName = %q, want %q", gotResults[1].NetworkName, "Net2")
	}

	// State should be Stopped after scan complete.
	if s.GetState() != StateStopped {
		t.Errorf("state = %s, want Stopped", s.GetState())
	}
}

func TestDiscoverNoCallback(t *testing.T) {
	scanner := &mockScanner{}
	s := NewSeeker(scanner)

	// Start with nil callback — should not panic.
	if err := s.Start(nil); err != nil {
		t.Fatalf("Start: %v", err)
	}

	scanner.pushResult(&DiscoverResult{NetworkName: "Net"})
	scanner.pushResult(nil) // scan complete

	if s.GetState() != StateStopped {
		t.Errorf("state = %s, want Stopped", s.GetState())
	}
}

func TestResultIgnoredWhenNotDiscovering(t *testing.T) {
	scanner := &mockScanner{}
	s := NewSeeker(scanner)

	// Inject result when stopped — should be ignored.
	s.HandleDiscoverResult(&DiscoverResult{NetworkName: "Ignored"})

	results := s.GetResults()
	if len(results) != 0 {
		t.Errorf("expected 0 results when stopped, got %d", len(results))
	}
}

func TestStopDuringScan(t *testing.T) {
	scanner := &mockScanner{}
	s := NewSeeker(scanner)

	_ = s.Start(nil)
	scanner.pushResult(&DiscoverResult{NetworkName: "Net"})

	_ = s.Stop()

	// Results should be cleared.
	results := s.GetResults()
	if len(results) != 0 {
		t.Errorf("expected 0 results after Stop, got %d", len(results))
	}
}

func TestStateString(t *testing.T) {
	tests := []struct {
		s    State
		want string
	}{
		{StateStopped, "Stopped"},
		{StateDiscover, "Discover"},
		{StateConnect, "Connect"},
		{State(99), "State(99)"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}
