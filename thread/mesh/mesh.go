// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package mesh implements Thread mesh forwarding.
//
// This package ports the mesh forwarding types from OpenThread.
// Reference: https://github.com/openthread/openthread
package mesh

// Counters tracks IPv6 message transmission and reception statistics.
type Counters struct {
	// TxSuccess counts successfully transmitted IPv6 packets.
	TxSuccess uint32
	// RxSuccess counts successfully received IPv6 packets.
	RxSuccess uint32
	// TxFailure counts failed IPv6 packet transmissions.
	TxFailure uint32
	// RxFailure counts failed IPv6 packet receptions.
	RxFailure uint32
}

// Reset clears all counters to zero.
func (c *Counters) Reset() { *c = Counters{} }

// Constants for mesh forwarding configuration.
const (
	// FailedRouterTransmissions is the number of consecutive failed
	// transmissions to a router before considering the link broken.
	FailedRouterTransmissions = 4

	// FailedCSLDataPollTransmissions is the number of consecutive failed
	// CSL data poll transmissions before considering the link broken.
	FailedCSLDataPollTransmissions = 15

	// ReassemblyTimeout is the 6LoWPAN reassembly timeout in seconds.
	ReassemblyTimeout = 2

	// MeshHeaderFrameMTU is the maximum frame size for mesh header frames.
	MeshHeaderFrameMTU = 127

	// MeshHeaderFrameFCSSize is the FCS size for mesh header frames.
	MeshHeaderFrameFCSSize = 2

	// MeshHeaderHopsLeft is the initial hops-left value for mesh header frames.
	// This is MaxRouteCost(16) + 3.
	MeshHeaderHopsLeft = 19

	// TxDelayInterval is the collision avoidance delay in milliseconds.
	TxDelayInterval = 8

	// MaxFramesInDirectTxQueue is the maximum frames in the direct TX queue.
	MaxFramesInDirectTxQueue = 100

	// NumFragmentPriorityEntries is the number of fragment priority tracking entries.
	NumFragmentPriorityEntries = 8

	// DelayAwareMarkECNInterval is the time-in-queue (ms) to mark ECN.
	DelayAwareMarkECNInterval = 500

	// DelayAwareDropMsgInterval is the time-in-queue (ms) to drop a message.
	DelayAwareDropMsgInterval = 1000

	// DelayAwareFragTagRetainTime is the max retain time (s) for frag tag entries.
	DelayAwareFragTagRetainTime = 240
)

// EvictReason indicates why a message was evicted from the queue.
type EvictReason uint8

const (
	// EvictNoMessageBuffer indicates eviction due to buffer exhaustion.
	EvictNoMessageBuffer EvictReason = 0
	// EvictDirectTxQueueAtLimit indicates eviction due to direct TX queue limit.
	EvictDirectTxQueueAtLimit EvictReason = 1
)

// String returns a human-readable name for the evict reason.
func (r EvictReason) String() string {
	switch r {
	case EvictNoMessageBuffer:
		return "NoMessageBuffer"
	case EvictDirectTxQueueAtLimit:
		return "DirectTxQueueAtLimit"
	default:
		return "Unknown"
	}
}

// MessageAction represents an action taken on a message.
type MessageAction uint8

const (
	// MessageReceive indicates a message was received.
	MessageReceive MessageAction = 0
	// MessageTransmit indicates a message was transmitted.
	MessageTransmit MessageAction = 1
	// MessagePrepareIndirect indicates a message was prepared for indirect TX.
	MessagePrepareIndirect MessageAction = 2
	// MessageDrop indicates an outbound message was dropped.
	MessageDrop MessageAction = 3
	// MessageReassemblyDrop indicates a message was dropped from reassembly.
	MessageReassemblyDrop MessageAction = 4
	// MessageEvict indicates a message was evicted due to buffer exhaustion.
	MessageEvict MessageAction = 5
	// MessageFullQueueEvict indicates lower priority eviction at queue limit.
	MessageFullQueueEvict MessageAction = 6
	// MessageFullQueueDrop indicates a drop at queue limit.
	MessageFullQueueDrop MessageAction = 7
	// MessageMarkECN indicates ECN was marked on a message.
	MessageMarkECN MessageAction = 8
	// MessageQueueMgmtDrop indicates a drop by delay-aware queue management.
	MessageQueueMgmtDrop MessageAction = 9
)

// String returns a human-readable name for the message action.
func (a MessageAction) String() string {
	switch a {
	case MessageReceive:
		return "Receive"
	case MessageTransmit:
		return "Transmit"
	case MessagePrepareIndirect:
		return "PrepareIndirect"
	case MessageDrop:
		return "Drop"
	case MessageReassemblyDrop:
		return "ReassemblyDrop"
	case MessageEvict:
		return "Evict"
	case MessageFullQueueEvict:
		return "FullQueueEvict"
	case MessageFullQueueDrop:
		return "FullQueueDrop"
	case MessageMarkECN:
		return "MarkECN"
	case MessageQueueMgmtDrop:
		return "QueueMgmtDrop"
	default:
		return "Unknown"
	}
}

// Priority represents a message priority level.
type Priority uint8

const (
	// PriorityLow is the lowest message priority.
	PriorityLow Priority = 0
	// PriorityNormal is the default message priority.
	PriorityNormal Priority = 1
	// PriorityHigh is for important messages.
	PriorityHigh Priority = 2
	// PriorityNet is the highest priority for network control messages.
	PriorityNet Priority = 3
)

// fwdFrameInfoDefaultLifetime is the default lifetime for forwarded frame
// info entries. In OpenThread this is FragTagRetainTime / kStateUpdatePeriod.
// We use a reasonable default of 4.
const fwdFrameInfoDefaultLifetime uint8 = 4

// FwdFrameInfo tracks forwarded mesh-header fragmented frames for
// consistent priority assignment across fragments.
type FwdFrameInfo struct {
	// SrcRLOC16 is the source RLOC16 of the datagram.
	SrcRLOC16 uint16
	// DatagramTag is the 6LoWPAN datagram tag.
	DatagramTag uint16
	// Lifetime is the remaining lifetime counter.
	Lifetime uint8
	// Priority is the assigned priority for this datagram (2-bit in C++, full uint8 here).
	Priority Priority
	// ShouldDrop indicates whether this datagram should be dropped.
	ShouldDrop bool
}

// Init initializes the forwarded frame info.
func (f *FwdFrameInfo) Init(srcRLOC16, datagramTag uint16, priority Priority) {
	f.SrcRLOC16 = srcRLOC16
	f.DatagramTag = datagramTag
	f.Priority = priority
	f.Lifetime = fwdFrameInfoDefaultLifetime
	f.ShouldDrop = false
}

// IsExpired returns true if the lifetime has reached zero.
func (f *FwdFrameInfo) IsExpired() bool {
	return f.Lifetime == 0
}

// DecrementLifetime decrements the lifetime counter.
func (f *FwdFrameInfo) DecrementLifetime() {
	if f.Lifetime > 0 {
		f.Lifetime--
	}
}

// ResetLifetime resets the lifetime to the default value.
func (f *FwdFrameInfo) ResetLifetime() {
	f.Lifetime = fwdFrameInfoDefaultLifetime
}

// Matches returns true if the source RLOC16 and datagram tag match.
func (f *FwdFrameInfo) Matches(srcRLOC16, datagramTag uint16) bool {
	return f.SrcRLOC16 == srcRLOC16 && f.DatagramTag == datagramTag
}

// FwdFrameInfoTable manages a collection of FwdFrameInfo entries.
type FwdFrameInfoTable struct {
	entries  []FwdFrameInfo
	capacity int
}

// NewFwdFrameInfoTable creates a new table with the given capacity.
func NewFwdFrameInfoTable(capacity int) *FwdFrameInfoTable {
	return &FwdFrameInfoTable{
		entries:  make([]FwdFrameInfo, 0, capacity),
		capacity: capacity,
	}
}

// Find looks up a forwarded frame info by source and tag.
func (t *FwdFrameInfoTable) Find(srcRLOC16, datagramTag uint16) *FwdFrameInfo {
	for i := range t.entries {
		if t.entries[i].Matches(srcRLOC16, datagramTag) {
			return &t.entries[i]
		}
	}
	return nil
}

// Add adds or updates a forwarded frame info entry.
// If an entry with the same source and tag already exists, it is updated.
// If the table is at capacity, the oldest (first) entry is evicted.
func (t *FwdFrameInfoTable) Add(srcRLOC16, datagramTag uint16, priority Priority) *FwdFrameInfo {
	if entry := t.Find(srcRLOC16, datagramTag); entry != nil {
		entry.Priority = priority
		entry.ResetLifetime()
		return entry
	}

	if len(t.entries) >= t.capacity {
		// Evict the first entry (oldest).
		copy(t.entries, t.entries[1:])
		t.entries = t.entries[:len(t.entries)-1]
	}

	t.entries = append(t.entries, FwdFrameInfo{})
	entry := &t.entries[len(t.entries)-1]
	entry.Init(srcRLOC16, datagramTag, priority)
	return entry
}

// RemoveExpired removes all expired entries.
func (t *FwdFrameInfoTable) RemoveExpired() {
	n := 0
	for i := range t.entries {
		if !t.entries[i].IsExpired() {
			t.entries[n] = t.entries[i]
			n++
		}
	}
	t.entries = t.entries[:n]
}

// Len returns the number of active entries.
func (t *FwdFrameInfoTable) Len() int {
	return len(t.entries)
}

// Histogram constants for TxQueueStats.
const (
	// HistogramMaxInterval is the maximum tracked interval in milliseconds.
	HistogramMaxInterval uint32 = 500

	// HistogramBinInterval is the bin width in milliseconds.
	HistogramBinInterval uint32 = 10

	// HistogramNumBins is the number of histogram bins.
	HistogramNumBins = (HistogramMaxInterval + HistogramBinInterval - 1) / HistogramBinInterval // = 50
)

// TxQueueStats maintains statistics about message time-in-queue.
type TxQueueStats struct {
	// MaxInterval is the maximum time-in-queue observed (ms).
	MaxInterval uint32
	// Histogram tracks the distribution of time-in-queue values.
	Histogram [HistogramNumBins]uint32
}

// Reset clears all statistics.
func (s *TxQueueStats) Reset() { *s = TxQueueStats{} }

// Record records a message's time-in-queue.
func (s *TxQueueStats) Record(timeInQueueMs uint32) {
	if timeInQueueMs > s.MaxInterval {
		s.MaxInterval = timeInQueueMs
	}

	bin := timeInQueueMs / HistogramBinInterval
	if bin >= HistogramNumBins {
		bin = HistogramNumBins - 1
	}
	s.Histogram[bin]++
}

// GetHistogram returns the histogram data, bin count, and bin interval.
func (s *TxQueueStats) GetHistogram() (bins []uint32, numBins int, binInterval uint32) {
	return s.Histogram[:], int(HistogramNumBins), HistogramBinInterval
}
