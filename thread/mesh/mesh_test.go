// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import "testing"

func TestCounters_Reset(t *testing.T) {
	c := Counters{
		TxSuccess: 10,
		RxSuccess: 20,
		TxFailure: 5,
		RxFailure: 3,
	}
	c.Reset()

	if c.TxSuccess != 0 || c.RxSuccess != 0 || c.TxFailure != 0 || c.RxFailure != 0 {
		t.Errorf("Reset() did not clear all fields: %+v", c)
	}
}

func TestCounters_Increments(t *testing.T) {
	var c Counters

	c.TxSuccess++
	c.TxSuccess++
	c.RxSuccess++
	c.TxFailure++
	c.RxFailure++
	c.RxFailure++
	c.RxFailure++

	if c.TxSuccess != 2 {
		t.Errorf("TxSuccess = %d, want 2", c.TxSuccess)
	}
	if c.RxSuccess != 1 {
		t.Errorf("RxSuccess = %d, want 1", c.RxSuccess)
	}
	if c.TxFailure != 1 {
		t.Errorf("TxFailure = %d, want 1", c.TxFailure)
	}
	if c.RxFailure != 3 {
		t.Errorf("RxFailure = %d, want 3", c.RxFailure)
	}
}

func TestEvictReason_String(t *testing.T) {
	tests := []struct {
		reason EvictReason
		want   string
	}{
		{EvictNoMessageBuffer, "NoMessageBuffer"},
		{EvictDirectTxQueueAtLimit, "DirectTxQueueAtLimit"},
		{EvictReason(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.reason.String(); got != tt.want {
				t.Errorf("EvictReason(%d).String() = %q, want %q", tt.reason, got, tt.want)
			}
		})
	}
}

func TestMessageAction_String(t *testing.T) {
	tests := []struct {
		action MessageAction
		want   string
	}{
		{MessageReceive, "Receive"},
		{MessageTransmit, "Transmit"},
		{MessagePrepareIndirect, "PrepareIndirect"},
		{MessageDrop, "Drop"},
		{MessageReassemblyDrop, "ReassemblyDrop"},
		{MessageEvict, "Evict"},
		{MessageFullQueueEvict, "FullQueueEvict"},
		{MessageFullQueueDrop, "FullQueueDrop"},
		{MessageMarkECN, "MarkECN"},
		{MessageQueueMgmtDrop, "QueueMgmtDrop"},
		{MessageAction(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.action.String(); got != tt.want {
				t.Errorf("MessageAction(%d).String() = %q, want %q", tt.action, got, tt.want)
			}
		})
	}
}

func TestFwdFrameInfo_Init(t *testing.T) {
	var f FwdFrameInfo
	f.Init(0x0400, 0x1234, PriorityHigh)

	if f.SrcRLOC16 != 0x0400 {
		t.Errorf("SrcRLOC16 = 0x%04X, want 0x0400", f.SrcRLOC16)
	}
	if f.DatagramTag != 0x1234 {
		t.Errorf("DatagramTag = 0x%04X, want 0x1234", f.DatagramTag)
	}
	if f.Priority != PriorityHigh {
		t.Errorf("Priority = %d, want %d", f.Priority, PriorityHigh)
	}
	if f.Lifetime == 0 {
		t.Error("Lifetime should be non-zero after Init")
	}
	if f.ShouldDrop {
		t.Error("ShouldDrop should be false after Init")
	}
}

func TestFwdFrameInfo_Matches(t *testing.T) {
	var f FwdFrameInfo
	f.Init(0x0400, 0x1234, PriorityNormal)

	t.Run("matching", func(t *testing.T) {
		if !f.Matches(0x0400, 0x1234) {
			t.Error("Matches() = false, want true")
		}
	})

	t.Run("wrong_src", func(t *testing.T) {
		if f.Matches(0x0800, 0x1234) {
			t.Error("Matches() = true, want false (wrong src)")
		}
	})

	t.Run("wrong_tag", func(t *testing.T) {
		if f.Matches(0x0400, 0x5678) {
			t.Error("Matches() = true, want false (wrong tag)")
		}
	})

	t.Run("both_wrong", func(t *testing.T) {
		if f.Matches(0x0800, 0x5678) {
			t.Error("Matches() = true, want false (both wrong)")
		}
	})
}

func TestFwdFrameInfo_Lifetime(t *testing.T) {
	var f FwdFrameInfo
	f.Init(0x0400, 0x1234, PriorityNormal)

	t.Run("not_expired_initially", func(t *testing.T) {
		if f.IsExpired() {
			t.Error("IsExpired() = true, want false after Init")
		}
	})

	t.Run("expires_after_decrements", func(t *testing.T) {
		var f2 FwdFrameInfo
		f2.Init(0x0400, 0x1234, PriorityNormal)
		initialLifetime := f2.Lifetime

		for i := uint8(0); i < initialLifetime; i++ {
			if f2.IsExpired() {
				t.Fatalf("IsExpired() = true after %d decrements, expected %d", i, initialLifetime)
			}
			f2.DecrementLifetime()
		}
		if !f2.IsExpired() {
			t.Error("IsExpired() = false after all decrements, want true")
		}
	})

	t.Run("decrement_at_zero_stays_zero", func(t *testing.T) {
		var f2 FwdFrameInfo
		f2.Lifetime = 0
		f2.DecrementLifetime()
		if f2.Lifetime != 0 {
			t.Errorf("Lifetime = %d after decrement at zero, want 0", f2.Lifetime)
		}
	})

	t.Run("reset_lifetime", func(t *testing.T) {
		var f2 FwdFrameInfo
		f2.Init(0x0400, 0x1234, PriorityNormal)
		initialLifetime := f2.Lifetime

		f2.DecrementLifetime()
		f2.DecrementLifetime()
		f2.ResetLifetime()

		if f2.Lifetime != initialLifetime {
			t.Errorf("Lifetime = %d after ResetLifetime, want %d", f2.Lifetime, initialLifetime)
		}
	})
}

func TestFwdFrameInfo_ShouldDrop(t *testing.T) {
	var f FwdFrameInfo
	f.Init(0x0400, 0x1234, PriorityNormal)

	if f.ShouldDrop {
		t.Error("ShouldDrop = true after Init, want false")
	}

	f.ShouldDrop = true
	if !f.ShouldDrop {
		t.Error("ShouldDrop = false after setting true, want true")
	}
}

func TestFwdFrameInfoTable_AddAndFind(t *testing.T) {
	table := NewFwdFrameInfoTable(NumFragmentPriorityEntries)

	entry := table.Add(0x0400, 0x1234, PriorityHigh)
	if entry == nil {
		t.Fatal("Add() returned nil")
	}
	if entry.SrcRLOC16 != 0x0400 {
		t.Errorf("entry.SrcRLOC16 = 0x%04X, want 0x0400", entry.SrcRLOC16)
	}
	if entry.Priority != PriorityHigh {
		t.Errorf("entry.Priority = %d, want %d", entry.Priority, PriorityHigh)
	}

	found := table.Find(0x0400, 0x1234)
	if found == nil {
		t.Fatal("Find() returned nil for existing entry")
	}
	if found.SrcRLOC16 != 0x0400 || found.DatagramTag != 0x1234 {
		t.Errorf("Find() returned wrong entry: %+v", found)
	}
}

func TestFwdFrameInfoTable_FindNonExistent(t *testing.T) {
	table := NewFwdFrameInfoTable(NumFragmentPriorityEntries)

	if table.Find(0x0400, 0x1234) != nil {
		t.Error("Find() returned non-nil for empty table")
	}

	table.Add(0x0400, 0x1234, PriorityNormal)

	if table.Find(0x0800, 0x1234) != nil {
		t.Error("Find() returned non-nil for non-existent src")
	}
	if table.Find(0x0400, 0x5678) != nil {
		t.Error("Find() returned non-nil for non-existent tag")
	}
}

func TestFwdFrameInfoTable_AddUpdatesExisting(t *testing.T) {
	table := NewFwdFrameInfoTable(NumFragmentPriorityEntries)

	table.Add(0x0400, 0x1234, PriorityLow)
	if table.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", table.Len())
	}

	// Add same key again with different priority.
	entry := table.Add(0x0400, 0x1234, PriorityNet)
	if table.Len() != 1 {
		t.Fatalf("Len() = %d after update, want 1", table.Len())
	}
	if entry.Priority != PriorityNet {
		t.Errorf("Priority = %d after update, want %d", entry.Priority, PriorityNet)
	}
}

func TestFwdFrameInfoTable_RemoveExpired(t *testing.T) {
	table := NewFwdFrameInfoTable(NumFragmentPriorityEntries)

	table.Add(0x0400, 0x0001, PriorityNormal)
	table.Add(0x0400, 0x0002, PriorityNormal)
	table.Add(0x0400, 0x0003, PriorityNormal)

	// Expire the second entry.
	entry := table.Find(0x0400, 0x0002)
	if entry == nil {
		t.Fatal("Find() returned nil for existing entry")
	}
	entry.Lifetime = 0

	table.RemoveExpired()

	if table.Len() != 2 {
		t.Errorf("Len() = %d after RemoveExpired, want 2", table.Len())
	}
	if table.Find(0x0400, 0x0002) != nil {
		t.Error("expired entry still found after RemoveExpired")
	}
	if table.Find(0x0400, 0x0001) == nil {
		t.Error("non-expired entry 0x0001 not found after RemoveExpired")
	}
	if table.Find(0x0400, 0x0003) == nil {
		t.Error("non-expired entry 0x0003 not found after RemoveExpired")
	}
}

func TestFwdFrameInfoTable_Capacity(t *testing.T) {
	const tableCap = 3
	table := NewFwdFrameInfoTable(tableCap)

	table.Add(0x0400, 0x0001, PriorityLow)
	table.Add(0x0400, 0x0002, PriorityNormal)
	table.Add(0x0400, 0x0003, PriorityHigh)

	if table.Len() != tableCap {
		t.Fatalf("Len() = %d, want %d", table.Len(), tableCap)
	}

	// Adding a fourth entry should evict the oldest (0x0001).
	table.Add(0x0400, 0x0004, PriorityNet)
	if table.Len() != tableCap {
		t.Errorf("Len() = %d after overflow, want %d", table.Len(), tableCap)
	}
	if table.Find(0x0400, 0x0001) != nil {
		t.Error("oldest entry still found after capacity eviction")
	}
	if table.Find(0x0400, 0x0004) == nil {
		t.Error("newest entry not found after capacity eviction")
	}
}

func TestFwdFrameInfoTable_Len(t *testing.T) {
	table := NewFwdFrameInfoTable(NumFragmentPriorityEntries)

	if table.Len() != 0 {
		t.Errorf("Len() = %d for new table, want 0", table.Len())
	}

	table.Add(0x0400, 0x0001, PriorityNormal)
	if table.Len() != 1 {
		t.Errorf("Len() = %d after one add, want 1", table.Len())
	}

	table.Add(0x0400, 0x0002, PriorityNormal)
	if table.Len() != 2 {
		t.Errorf("Len() = %d after two adds, want 2", table.Len())
	}
}

func TestTxQueueStats_Reset(t *testing.T) {
	s := TxQueueStats{MaxInterval: 100}
	s.Histogram[0] = 5
	s.Histogram[1] = 10

	s.Reset()

	if s.MaxInterval != 0 {
		t.Errorf("MaxInterval = %d after Reset, want 0", s.MaxInterval)
	}
	for i, v := range s.Histogram {
		if v != 0 {
			t.Errorf("Histogram[%d] = %d after Reset, want 0", i, v)
		}
	}
}

func TestTxQueueStats_Record(t *testing.T) {
	t.Run("bin_assignment", func(t *testing.T) {
		var s TxQueueStats

		// 0ms should go in bin 0 (0-9ms).
		s.Record(0)
		if s.Histogram[0] != 1 {
			t.Errorf("Histogram[0] = %d, want 1", s.Histogram[0])
		}

		// 5ms should also go in bin 0.
		s.Record(5)
		if s.Histogram[0] != 2 {
			t.Errorf("Histogram[0] = %d, want 2", s.Histogram[0])
		}

		// 10ms should go in bin 1 (10-19ms).
		s.Record(10)
		if s.Histogram[1] != 1 {
			t.Errorf("Histogram[1] = %d, want 1", s.Histogram[1])
		}

		// 25ms should go in bin 2 (20-29ms).
		s.Record(25)
		if s.Histogram[2] != 1 {
			t.Errorf("Histogram[2] = %d, want 1", s.Histogram[2])
		}
	})

	t.Run("overflow_goes_to_last_bin", func(t *testing.T) {
		var s TxQueueStats
		lastBin := HistogramNumBins - 1

		// Value at exactly HistogramMaxInterval.
		s.Record(HistogramMaxInterval)
		if s.Histogram[lastBin] != 1 {
			t.Errorf("Histogram[%d] = %d for HistogramMaxInterval, want 1", lastBin, s.Histogram[lastBin])
		}

		// Value well above HistogramMaxInterval.
		s.Record(10000)
		if s.Histogram[lastBin] != 2 {
			t.Errorf("Histogram[%d] = %d for 10000ms, want 2", lastBin, s.Histogram[lastBin])
		}
	})

	t.Run("max_interval_tracking", func(t *testing.T) {
		var s TxQueueStats

		s.Record(50)
		if s.MaxInterval != 50 {
			t.Errorf("MaxInterval = %d, want 50", s.MaxInterval)
		}

		s.Record(200)
		if s.MaxInterval != 200 {
			t.Errorf("MaxInterval = %d, want 200", s.MaxInterval)
		}

		// A smaller value should not reduce MaxInterval.
		s.Record(100)
		if s.MaxInterval != 200 {
			t.Errorf("MaxInterval = %d after smaller record, want 200", s.MaxInterval)
		}
	})
}

func TestTxQueueStats_GetHistogram(t *testing.T) {
	var s TxQueueStats
	s.Record(15)
	s.Record(25)

	bins, numBins, binInterval := s.GetHistogram()

	if numBins != int(HistogramNumBins) {
		t.Errorf("numBins = %d, want %d", numBins, HistogramNumBins)
	}
	if binInterval != HistogramBinInterval {
		t.Errorf("binInterval = %d, want %d", binInterval, HistogramBinInterval)
	}
	if len(bins) != int(HistogramNumBins) {
		t.Errorf("len(bins) = %d, want %d", len(bins), HistogramNumBins)
	}
	// 15ms -> bin 1, 25ms -> bin 2.
	if bins[1] != 1 {
		t.Errorf("bins[1] = %d, want 1", bins[1])
	}
	if bins[2] != 1 {
		t.Errorf("bins[2] = %d, want 1", bins[2])
	}
}

func TestConstants(t *testing.T) {
	// Verify key constants have expected values from OpenThread.
	tests := []struct {
		name string
		got  int
		want int
	}{
		{"FailedRouterTransmissions", FailedRouterTransmissions, 4},
		{"FailedCSLDataPollTransmissions", FailedCSLDataPollTransmissions, 15},
		{"ReassemblyTimeout", ReassemblyTimeout, 2},
		{"MeshHeaderFrameMTU", MeshHeaderFrameMTU, 127},
		{"MeshHeaderFrameFCSSize", MeshHeaderFrameFCSSize, 2},
		{"MeshHeaderHopsLeft", MeshHeaderHopsLeft, 19},
		{"TxDelayInterval", TxDelayInterval, 8},
		{"MaxFramesInDirectTxQueue", MaxFramesInDirectTxQueue, 100},
		{"NumFragmentPriorityEntries", NumFragmentPriorityEntries, 8},
		{"DelayAwareMarkECNInterval", DelayAwareMarkECNInterval, 500},
		{"DelayAwareDropMsgInterval", DelayAwareDropMsgInterval, 1000},
		{"DelayAwareFragTagRetainTime", DelayAwareFragTagRetainTime, 240},
		{"HistogramNumBins", int(HistogramNumBins), 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
			}
		})
	}
}
