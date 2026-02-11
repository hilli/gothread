// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package linkmetrics

import (
	"testing"

	mac_types "github.com/hilli/gothread/mac/types"
)

// testAddr returns a deterministic ExtAddress for testing.
func testAddr(id byte) mac_types.ExtAddress {
	return mac_types.ExtAddress{id, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
}

// ============================================================================
// Types tests
// ============================================================================

func TestMetricConstants(t *testing.T) {
	// Verify bitmask values are powers of 2 and don't overlap.
	if MetricPduCount != 1 {
		t.Errorf("MetricPduCount = %d, want 1", MetricPduCount)
	}
	if MetricLqi != 2 {
		t.Errorf("MetricLqi = %d, want 2", MetricLqi)
	}
	if MetricLinkMargin != 4 {
		t.Errorf("MetricLinkMargin = %d, want 4", MetricLinkMargin)
	}
	if MetricRssi != 8 {
		t.Errorf("MetricRssi = %d, want 8", MetricRssi)
	}
}

func TestSeriesFlagConstants(t *testing.T) {
	if SeriesFlagLinkProbe != 1 {
		t.Errorf("SeriesFlagLinkProbe = %d, want 1", SeriesFlagLinkProbe)
	}
	if SeriesFlagMacData != 2 {
		t.Errorf("SeriesFlagMacData = %d, want 2", SeriesFlagMacData)
	}
	if SeriesFlagMacDataReq != 4 {
		t.Errorf("SeriesFlagMacDataReq = %d, want 4", SeriesFlagMacDataReq)
	}
	if SeriesFlagAck != 8 {
		t.Errorf("SeriesFlagAck = %d, want 8", SeriesFlagAck)
	}
}

func TestTypeIDConstants(t *testing.T) {
	// TypeIDPdu should have the length flag set (bit 6).
	if TypeIDPdu&typeIDLengthFlag == 0 {
		t.Error("TypeIDPdu should have length flag set")
	}
	if TypeIDValueLength(TypeIDPdu) != 4 {
		t.Errorf("TypeIDValueLength(TypeIDPdu) = %d, want 4", TypeIDValueLength(TypeIDPdu))
	}

	// Other Type IDs should not have the length flag.
	for _, tc := range []struct {
		name   string
		typeID uint8
	}{
		{"LQI", TypeIDLqi},
		{"LinkMargin", TypeIDLinkMargin},
		{"RSSI", TypeIDRssi},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if TypeIDValueLength(tc.typeID) != 1 {
				t.Errorf("TypeIDValueLength(%s) = %d, want 1", tc.name, TypeIDValueLength(tc.typeID))
			}
			if TypeIDIsExtended(tc.typeID) {
				t.Errorf("%s should not be extended", tc.name)
			}
		})
	}
}

// ============================================================================
// Scaling tests
// ============================================================================

func TestScaleLinkMargin(t *testing.T) {
	tests := []struct {
		name       string
		linkMargin uint8
	}{
		{"zero", 0},
		{"mid", 65},
		{"max", 130},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := ScaleLinkMarginToRaw(tc.linkMargin)
			back := ScaleRawToLinkMargin(raw)
			// Allow +-1 due to rounding.
			diff := int(tc.linkMargin) - int(back)
			if diff < -1 || diff > 1 {
				t.Errorf("ScaleLinkMargin round-trip: %d -> raw %d -> %d (diff %d)",
					tc.linkMargin, raw, back, diff)
			}
		})
	}

	// Edge: above 130 should clamp.
	raw := ScaleLinkMarginToRaw(200)
	if raw != 255 {
		t.Errorf("ScaleLinkMarginToRaw(200) = %d, want 255 (clamped)", raw)
	}

	// 0 -> 0
	if ScaleLinkMarginToRaw(0) != 0 {
		t.Errorf("ScaleLinkMarginToRaw(0) = %d, want 0", ScaleLinkMarginToRaw(0))
	}

	// 130 -> 255
	if ScaleLinkMarginToRaw(130) != 255 {
		t.Errorf("ScaleLinkMarginToRaw(130) = %d, want 255", ScaleLinkMarginToRaw(130))
	}
}

func TestScaleRssi(t *testing.T) {
	tests := []struct {
		name string
		rssi int8
	}{
		{"zero", 0},
		{"negative", -65},
		{"min_clamped", -128}, // int8 min, should clamp to -128 range
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := ScaleRssiToRaw(tc.rssi)
			back := ScaleRawToRssi(raw)
			diff := int(tc.rssi) - int(back)
			if diff < -1 || diff > 1 {
				t.Errorf("ScaleRssi round-trip: %d -> raw %d -> %d (diff %d)",
					tc.rssi, raw, back, diff)
			}
		})
	}

	// 0 -> 255
	if ScaleRssiToRaw(0) != 255 {
		t.Errorf("ScaleRssiToRaw(0) = %d, want 255", ScaleRssiToRaw(0))
	}

	// Raw 0 -> -130, but clamped to -128 for int8.
	if ScaleRawToRssi(0) != -128 {
		t.Errorf("ScaleRawToRssi(0) = %d, want -128", ScaleRawToRssi(0))
	}

	// Raw 255 -> 0
	if ScaleRawToRssi(255) != 0 {
		t.Errorf("ScaleRawToRssi(255) = %d, want 0", ScaleRawToRssi(255))
	}
}

// ============================================================================
// SeriesInfo tests
// ============================================================================

func TestSeriesInfo_Aggregate(t *testing.T) {
	info := &SeriesInfo{
		SeriesID:    1,
		SeriesFlags: SeriesFlagMacData,
		Metrics:     MetricLqi | MetricLinkMargin | MetricRssi,
	}

	info.Aggregate(100, 50, -60)
	info.Aggregate(120, 70, -40)

	if info.PduCount != 2 {
		t.Errorf("PduCount = %d, want 2", info.PduCount)
	}
	if info.GetAverageLqi() != 110 {
		t.Errorf("GetAverageLqi() = %d, want 110", info.GetAverageLqi())
	}
	if info.GetAverageLinkMargin() != 60 {
		t.Errorf("GetAverageLinkMargin() = %d, want 60", info.GetAverageLinkMargin())
	}
	if info.GetAverageRssi() != -50 {
		t.Errorf("GetAverageRssi() = %d, want -50", info.GetAverageRssi())
	}
}

func TestSeriesInfo_AggregatePartialMetrics(t *testing.T) {
	// Only track LQI.
	info := &SeriesInfo{
		SeriesID:    2,
		SeriesFlags: SeriesFlagMacData,
		Metrics:     MetricLqi,
	}

	info.Aggregate(80, 50, -60)
	info.Aggregate(120, 70, -40)

	if info.PduCount != 2 {
		t.Errorf("PduCount = %d, want 2", info.PduCount)
	}
	if info.GetAverageLqi() != 100 {
		t.Errorf("GetAverageLqi() = %d, want 100", info.GetAverageLqi())
	}
	// LinkMargin and RSSI should not be aggregated.
	if info.LinkMarginCount != 0 {
		t.Errorf("LinkMarginCount = %d, want 0", info.LinkMarginCount)
	}
	if info.RssiCount != 0 {
		t.Errorf("RssiCount = %d, want 0", info.RssiCount)
	}
}

func TestSeriesInfo_NoSamples(t *testing.T) {
	info := &SeriesInfo{Metrics: MetricLqi | MetricLinkMargin | MetricRssi}
	if info.GetAverageLqi() != 0 {
		t.Errorf("GetAverageLqi() with no samples = %d, want 0", info.GetAverageLqi())
	}
	if info.GetAverageLinkMargin() != 0 {
		t.Errorf("GetAverageLinkMargin() with no samples = %d, want 0", info.GetAverageLinkMargin())
	}
	if info.GetAverageRssi() != 0 {
		t.Errorf("GetAverageRssi() with no samples = %d, want 0", info.GetAverageRssi())
	}
}

func TestSeriesInfo_ToMetricsValues(t *testing.T) {
	info := &SeriesInfo{
		SeriesID:    1,
		SeriesFlags: SeriesFlagMacData,
		Metrics:     MetricLqi | MetricRssi,
	}
	info.Aggregate(100, 50, -60)

	vals := info.ToMetricsValues()
	if vals.PduCount != 1 {
		t.Errorf("PduCount = %d, want 1", vals.PduCount)
	}
	if vals.Metrics&MetricPduCount == 0 {
		t.Error("MetricPduCount should always be set in ToMetricsValues")
	}
	if vals.Metrics&MetricLqi == 0 {
		t.Error("MetricLqi should be set")
	}
	if vals.Metrics&MetricRssi == 0 {
		t.Error("MetricRssi should be set")
	}
	if vals.Lqi != 100 {
		t.Errorf("Lqi = %d, want 100", vals.Lqi)
	}
	if vals.Rssi != -60 {
		t.Errorf("Rssi = %d, want -60", vals.Rssi)
	}
}

// ============================================================================
// Subject tests
// ============================================================================

func TestSubject_HandleManagementRequest_RegisterAndQuery(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	// Register a series.
	status := s.HandleManagementRequest(addr, 1, SeriesFlagMacData, MetricLqi|MetricRssi)
	if status != StatusSuccess {
		t.Fatalf("HandleManagementRequest register: status = %d, want %d", status, StatusSuccess)
	}

	// Aggregate some data.
	s.AggregateLinkMetrics(addr, 1, 100, 50, -60)
	s.AggregateLinkMetrics(addr, 1, 120, 70, -40)

	// Query the series.
	vals, qStatus := s.HandleSeriesQuery(addr, 1)
	if qStatus != StatusSuccess {
		t.Fatalf("HandleSeriesQuery: status = %d, want %d", qStatus, StatusSuccess)
	}
	if vals == nil {
		t.Fatal("HandleSeriesQuery returned nil values")
	}
	if vals.PduCount != 2 {
		t.Errorf("PduCount = %d, want 2", vals.PduCount)
	}
	if vals.Lqi != 110 {
		t.Errorf("Lqi = %d, want 110", vals.Lqi)
	}
	if vals.Rssi != -50 {
		t.Errorf("Rssi = %d, want -50", vals.Rssi)
	}
}

func TestSubject_HandleManagementRequest_ClearSeries(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	// Register and then clear.
	s.HandleManagementRequest(addr, 1, SeriesFlagMacData, MetricLqi)
	status := s.HandleManagementRequest(addr, 1, 0, 0) // clear
	if status != StatusSuccess {
		t.Fatalf("Clear series: status = %d, want %d", status, StatusSuccess)
	}

	// Query should fail.
	_, qStatus := s.HandleSeriesQuery(addr, 1)
	if qStatus != StatusSeriesIDNotRecognized {
		t.Errorf("Query after clear: status = %d, want %d", qStatus, StatusSeriesIDNotRecognized)
	}
}

func TestSubject_HandleManagementRequest_ClearAllSeries(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	s.HandleManagementRequest(addr, 1, SeriesFlagMacData, MetricLqi)
	s.HandleManagementRequest(addr, 2, SeriesFlagMacData, MetricRssi)

	// Clear all (seriesID=255, seriesFlags=0).
	status := s.HandleManagementRequest(addr, seriesIDAllSeries, 0, 0)
	if status != StatusSuccess {
		t.Fatalf("Clear all: status = %d, want %d", status, StatusSuccess)
	}

	_, q1 := s.HandleSeriesQuery(addr, 1)
	_, q2 := s.HandleSeriesQuery(addr, 2)
	if q1 != StatusSeriesIDNotRecognized || q2 != StatusSeriesIDNotRecognized {
		t.Errorf("Queries after clear all: s1=%d, s2=%d, want both %d",
			q1, q2, StatusSeriesIDNotRecognized)
	}
}

func TestSubject_HandleManagementRequest_DuplicateSeriesID(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	s.HandleManagementRequest(addr, 1, SeriesFlagMacData, MetricLqi)
	status := s.HandleManagementRequest(addr, 1, SeriesFlagMacData, MetricLqi)
	if status != StatusSeriesIDAlreadyRegistered {
		t.Errorf("Duplicate series: status = %d, want %d", status, StatusSeriesIDAlreadyRegistered)
	}
}

func TestSubject_HandleManagementRequest_MaxSeries(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	// Register MaxSeriesPerNeighbor series.
	for i := uint8(1); i <= MaxSeriesPerNeighbor; i++ {
		status := s.HandleManagementRequest(addr, i, SeriesFlagMacData, MetricLqi)
		if status != StatusSuccess {
			t.Fatalf("Register series %d: status = %d, want %d", i, status, StatusSuccess)
		}
	}

	// Next should fail.
	status := s.HandleManagementRequest(addr, MaxSeriesPerNeighbor+1, SeriesFlagMacData, MetricLqi)
	if status != StatusCannotSupportNewSeries {
		t.Errorf("Exceed max series: status = %d, want %d", status, StatusCannotSupportNewSeries)
	}
}

func TestSubject_HandleManagementRequest_SeriesIDZero(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	status := s.HandleManagementRequest(addr, 0, SeriesFlagMacData, MetricLqi)
	if status != StatusOtherError {
		t.Errorf("SeriesID=0: status = %d, want %d", status, StatusOtherError)
	}
}

func TestSubject_HandleManagementRequest_ClearNotRecognized(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	status := s.HandleManagementRequest(addr, 42, 0, 0)
	if status != StatusSeriesIDNotRecognized {
		t.Errorf("Clear unknown: status = %d, want %d", status, StatusSeriesIDNotRecognized)
	}
}

func TestSubject_HandleManagementRequest_NoFrames(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	s.HandleManagementRequest(addr, 1, SeriesFlagMacData, MetricLqi)

	// Query without any aggregated data.
	_, qStatus := s.HandleSeriesQuery(addr, 1)
	if qStatus != StatusNoMatchingFramesReceived {
		t.Errorf("Query no frames: status = %d, want %d", qStatus, StatusNoMatchingFramesReceived)
	}
}

func TestSubject_HandleManagementRequest_IsolationBetweenNeighbors(t *testing.T) {
	s := NewSubject()
	addr1 := testAddr(1)
	addr2 := testAddr(2)

	s.HandleManagementRequest(addr1, 1, SeriesFlagMacData, MetricLqi)
	s.HandleManagementRequest(addr2, 1, SeriesFlagMacData, MetricLqi)

	s.AggregateLinkMetrics(addr1, 1, 100, 0, 0)

	// addr1 should have data, addr2 should not.
	vals, st := s.HandleSeriesQuery(addr1, 1)
	if st != StatusSuccess || vals == nil || vals.PduCount != 1 {
		t.Errorf("addr1 query: status=%d, vals=%v", st, vals)
	}

	_, st2 := s.HandleSeriesQuery(addr2, 1)
	if st2 != StatusNoMatchingFramesReceived {
		t.Errorf("addr2 query: status=%d, want %d", st2, StatusNoMatchingFramesReceived)
	}
}

func TestSubject_HandleLinkProbe(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	// Register series with link probe flag.
	s.HandleManagementRequest(addr, 5, SeriesFlagLinkProbe, MetricPduCount)

	s.HandleLinkProbe(addr, 5)
	s.HandleLinkProbe(addr, 5)

	vals, st := s.HandleSeriesQuery(addr, 5)
	if st != StatusSuccess {
		t.Fatalf("HandleSeriesQuery after probe: status = %d", st)
	}
	if vals.PduCount != 2 {
		t.Errorf("PduCount = %d, want 2", vals.PduCount)
	}
}

func TestSubject_HandleLinkProbe_NoMatchingFlag(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	// Register series without link probe flag.
	s.HandleManagementRequest(addr, 5, SeriesFlagMacData, MetricPduCount)

	s.HandleLinkProbe(addr, 5)

	_, st := s.HandleSeriesQuery(addr, 5)
	if st != StatusNoMatchingFramesReceived {
		t.Errorf("Query after probe w/o flag: status = %d, want %d", st, StatusNoMatchingFramesReceived)
	}
}

func TestSubject_HandleLinkProbe_UnknownSeries(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	// Should not panic for unknown series.
	s.HandleLinkProbe(addr, 99)
}

func TestSubject_EnhAckProbing_Register(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	status := s.HandleEnhAckProbingRequest(addr, EnhAckRegister, MetricLqi|MetricRssi)
	if status != StatusSuccess {
		t.Fatalf("Register Enh-ACK: status = %d, want %d", status, StatusSuccess)
	}

	vals, ok := s.GetEnhAckMetrics(addr)
	if !ok {
		t.Fatal("GetEnhAckMetrics returned false after register")
	}
	if vals.Metrics&MetricLqi == 0 || vals.Metrics&MetricRssi == 0 {
		t.Errorf("Metrics = 0x%02X, want LQI+RSSI", vals.Metrics)
	}
}

func TestSubject_EnhAckProbing_Clear(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	s.HandleEnhAckProbingRequest(addr, EnhAckRegister, MetricLqi)
	status := s.HandleEnhAckProbingRequest(addr, EnhAckClear, 0)
	if status != StatusSuccess {
		t.Fatalf("Clear Enh-ACK: status = %d, want %d", status, StatusSuccess)
	}

	_, ok := s.GetEnhAckMetrics(addr)
	if ok {
		t.Error("GetEnhAckMetrics returned true after clear")
	}
}

func TestSubject_EnhAckProbing_InvalidPduCount(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	// PDU count not allowed.
	status := s.HandleEnhAckProbingRequest(addr, EnhAckRegister, MetricPduCount|MetricLqi)
	if status != StatusOtherError {
		t.Errorf("Enh-ACK with PDU: status = %d, want %d", status, StatusOtherError)
	}
}

func TestSubject_EnhAckProbing_NoMetrics(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	// Must have at least one metric.
	status := s.HandleEnhAckProbingRequest(addr, EnhAckRegister, 0)
	if status != StatusOtherError {
		t.Errorf("Enh-ACK no metrics: status = %d, want %d", status, StatusOtherError)
	}
}

func TestSubject_EnhAckProbing_AllThreeMetrics(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	// All three not allowed.
	status := s.HandleEnhAckProbingRequest(addr, EnhAckRegister, MetricLqi|MetricLinkMargin|MetricRssi)
	if status != StatusOtherError {
		t.Errorf("Enh-ACK all three: status = %d, want %d", status, StatusOtherError)
	}
}

func TestSubject_EnhAckProbing_ClearWithMetrics(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	status := s.HandleEnhAckProbingRequest(addr, EnhAckClear, MetricLqi)
	if status != StatusOtherError {
		t.Errorf("Clear with metrics: status = %d, want %d", status, StatusOtherError)
	}
}

func TestSubject_EnhAckProbing_InvalidFlags(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	status := s.HandleEnhAckProbingRequest(addr, 5, MetricLqi)
	if status != StatusOtherError {
		t.Errorf("Invalid flags: status = %d, want %d", status, StatusOtherError)
	}
}

func TestSubject_RemoveAllSeriesInfo(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	s.HandleManagementRequest(addr, 1, SeriesFlagMacData, MetricLqi)
	s.HandleManagementRequest(addr, 2, SeriesFlagMacData, MetricRssi)
	s.HandleEnhAckProbingRequest(addr, EnhAckRegister, MetricLqi)

	s.RemoveAllSeriesInfo(addr)

	_, q1 := s.HandleSeriesQuery(addr, 1)
	_, q2 := s.HandleSeriesQuery(addr, 2)
	if q1 != StatusSeriesIDNotRecognized || q2 != StatusSeriesIDNotRecognized {
		t.Errorf("After RemoveAll: q1=%d, q2=%d, want %d", q1, q2, StatusSeriesIDNotRecognized)
	}

	_, ok := s.GetEnhAckMetrics(addr)
	if ok {
		t.Error("GetEnhAckMetrics returned true after RemoveAllSeriesInfo")
	}
}

func TestSubject_AggregateLinkMetrics_UnknownSeries(t *testing.T) {
	s := NewSubject()
	addr := testAddr(1)

	// Should not panic.
	s.AggregateLinkMetrics(addr, 99, 100, 50, -60)
}

// ============================================================================
// Initiator tests
// ============================================================================

func TestInitiator_SendLinkMetricsQuery_SingleProbe(t *testing.T) {
	ini := NewInitiator()

	err := ini.SendLinkMetricsQuery(testAddr(1), 0, MetricLqi|MetricRssi)
	if err != nil {
		t.Fatalf("SendLinkMetricsQuery: %v", err)
	}

	queries := ini.GetPendingQueries()
	if len(queries) != 1 {
		t.Fatalf("pending queries: got %d, want 1", len(queries))
	}
	if queries[0].SeriesID != 0 {
		t.Errorf("SeriesID = %d, want 0", queries[0].SeriesID)
	}
	if queries[0].Metrics != MetricLqi|MetricRssi {
		t.Errorf("Metrics = 0x%02X, want 0x%02X", queries[0].Metrics, MetricLqi|MetricRssi)
	}
}

func TestInitiator_SendLinkMetricsQuery_ForwardSeries(t *testing.T) {
	ini := NewInitiator()

	err := ini.SendLinkMetricsQuery(testAddr(1), 5, 0)
	if err != nil {
		t.Fatalf("SendLinkMetricsQuery: %v", err)
	}

	queries := ini.GetPendingQueries()
	if len(queries) != 1 {
		t.Fatalf("pending queries: got %d, want 1", len(queries))
	}
	if queries[0].SeriesID != 5 {
		t.Errorf("SeriesID = %d, want 5", queries[0].SeriesID)
	}
}

func TestInitiator_SendLinkMetricsQuery_InvalidArgs(t *testing.T) {
	ini := NewInitiator()

	// Forward series with metrics specified is invalid.
	err := ini.SendLinkMetricsQuery(testAddr(1), 5, MetricLqi)
	if err == nil {
		t.Error("expected error for forward series with metrics")
	}

	// Single probe with no metrics is invalid.
	err = ini.SendLinkMetricsQuery(testAddr(1), 0, 0)
	if err == nil {
		t.Error("expected error for single probe with no metrics")
	}
}

func TestInitiator_SendMgmtRequest(t *testing.T) {
	ini := NewInitiator()

	err := ini.SendMgmtRequest(testAddr(1), 1, SeriesFlagMacData, MetricLqi)
	if err != nil {
		t.Fatalf("SendMgmtRequest: %v", err)
	}

	reqs := ini.GetPendingMgmtRequests()
	if len(reqs) != 1 {
		t.Fatalf("pending mgmt: got %d, want 1", len(reqs))
	}
	if reqs[0].SeriesID != 1 || reqs[0].SeriesFlags != SeriesFlagMacData {
		t.Errorf("unexpected request: %+v", reqs[0])
	}
}

func TestInitiator_SendMgmtRequest_InvalidSeriesID(t *testing.T) {
	ini := NewInitiator()

	err := ini.SendMgmtRequest(testAddr(1), 0, SeriesFlagMacData, MetricLqi)
	if err == nil {
		t.Error("expected error for seriesID=0")
	}
}

func TestInitiator_SendEnhAckProbingRequest(t *testing.T) {
	ini := NewInitiator()

	err := ini.SendEnhAckProbingRequest(testAddr(1), EnhAckRegister, MetricLqi)
	if err != nil {
		t.Fatalf("SendEnhAckProbingRequest: %v", err)
	}

	reqs := ini.GetPendingEnhAckRequests()
	if len(reqs) != 1 {
		t.Fatalf("pending enh-ack: got %d, want 1", len(reqs))
	}
}

func TestInitiator_SendEnhAckProbingRequest_ClearWithMetrics(t *testing.T) {
	ini := NewInitiator()

	err := ini.SendEnhAckProbingRequest(testAddr(1), EnhAckClear, MetricLqi)
	if err == nil {
		t.Error("expected error for clear with metrics")
	}
}

func TestInitiator_SendEnhAckProbingRequest_InvalidFlags(t *testing.T) {
	ini := NewInitiator()

	err := ini.SendEnhAckProbingRequest(testAddr(1), 99, MetricLqi)
	if err == nil {
		t.Error("expected error for invalid flags")
	}
}

func TestInitiator_SendLinkProbe(t *testing.T) {
	ini := NewInitiator()

	err := ini.SendLinkProbe(testAddr(1), 5)
	if err != nil {
		t.Fatalf("SendLinkProbe: %v", err)
	}

	probes := ini.GetPendingLinkProbes()
	if len(probes) != 1 {
		t.Fatalf("pending probes: got %d, want 1", len(probes))
	}
	if probes[0].SeriesID != 5 {
		t.Errorf("SeriesID = %d, want 5", probes[0].SeriesID)
	}
}

func TestInitiator_SendLinkProbe_InvalidSeriesID(t *testing.T) {
	ini := NewInitiator()

	// seriesID 0 is invalid for link probe.
	if err := ini.SendLinkProbe(testAddr(1), 0); err == nil {
		t.Error("expected error for seriesID=0")
	}

	// seriesID 255 is invalid for link probe.
	if err := ini.SendLinkProbe(testAddr(1), 255); err == nil {
		t.Error("expected error for seriesID=255")
	}
}

func TestInitiator_HandleReport_WithValues(t *testing.T) {
	ini := NewInitiator()

	var reportAddr mac_types.ExtAddress
	var reportVals *MetricsValues
	var reportStatus uint8

	ini.SetReportCallback(func(source mac_types.ExtAddress, values *MetricsValues, status uint8) {
		reportAddr = source
		reportVals = values
		reportStatus = status
	})

	// Encode a report: LQI=200, RSSI raw=128
	data := []byte{
		TypeIDLqi, 200,
		TypeIDRssi, 128,
	}

	addr := testAddr(1)
	err := ini.HandleReport(addr, data)
	if err != nil {
		t.Fatalf("HandleReport: %v", err)
	}

	if reportAddr != addr {
		t.Errorf("callback addr = %v, want %v", reportAddr, addr)
	}
	if reportStatus != StatusSuccess {
		t.Errorf("callback status = %d, want %d", reportStatus, StatusSuccess)
	}
	if reportVals == nil {
		t.Fatal("callback values is nil")
	}
	if reportVals.Lqi != 200 {
		t.Errorf("Lqi = %d, want 200", reportVals.Lqi)
	}
	if reportVals.Metrics&MetricLqi == 0 {
		t.Error("MetricLqi not set")
	}
	if reportVals.Metrics&MetricRssi == 0 {
		t.Error("MetricRssi not set")
	}
}

func TestInitiator_HandleReport_StatusOnly(t *testing.T) {
	ini := NewInitiator()

	var reportStatus uint8
	var reportVals *MetricsValues

	ini.SetReportCallback(func(source mac_types.ExtAddress, values *MetricsValues, status uint8) {
		reportStatus = status
		reportVals = values
	})

	err := ini.HandleReport(testAddr(1), []byte{StatusSeriesIDNotRecognized})
	if err != nil {
		t.Fatalf("HandleReport: %v", err)
	}
	if reportStatus != StatusSeriesIDNotRecognized {
		t.Errorf("status = %d, want %d", reportStatus, StatusSeriesIDNotRecognized)
	}
	if reportVals != nil {
		t.Error("values should be nil for status-only report")
	}
}

func TestInitiator_HandleReport_WithPduCount(t *testing.T) {
	ini := NewInitiator()

	var reportVals *MetricsValues

	ini.SetReportCallback(func(source mac_types.ExtAddress, values *MetricsValues, status uint8) {
		reportVals = values
	})

	// PDU type ID + 4 bytes big-endian value (1000 = 0x000003E8)
	data := []byte{
		TypeIDPdu, 0x00, 0x00, 0x03, 0xE8,
		TypeIDLqi, 150,
	}

	err := ini.HandleReport(testAddr(1), data)
	if err != nil {
		t.Fatalf("HandleReport: %v", err)
	}
	if reportVals == nil {
		t.Fatal("callback values is nil")
	}
	if reportVals.PduCount != 1000 {
		t.Errorf("PduCount = %d, want 1000", reportVals.PduCount)
	}
	if reportVals.Lqi != 150 {
		t.Errorf("Lqi = %d, want 150", reportVals.Lqi)
	}
}

func TestInitiator_HandleReport_EmptyData(t *testing.T) {
	ini := NewInitiator()

	err := ini.HandleReport(testAddr(1), []byte{})
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestInitiator_HandleReport_TruncatedPdu(t *testing.T) {
	ini := NewInitiator()

	// PDU type ID but only 2 bytes of value (need 4).
	data := []byte{TypeIDPdu, 0x00, 0x01}

	err := ini.HandleReport(testAddr(1), data)
	if err == nil {
		t.Error("expected error for truncated PDU value")
	}
}

func TestInitiator_HandleReport_NoCallback(t *testing.T) {
	ini := NewInitiator()

	// Should not panic when no callback is set.
	err := ini.HandleReport(testAddr(1), []byte{TypeIDLqi, 100})
	if err != nil {
		t.Fatalf("HandleReport without callback: %v", err)
	}
}

func TestInitiator_HandleManagementResponse(t *testing.T) {
	ini := NewInitiator()

	var cbAddr mac_types.ExtAddress
	var cbStatus uint8
	called := false

	ini.SetMgmtResponseCallback(func(source mac_types.ExtAddress, status uint8) {
		cbAddr = source
		cbStatus = status
		called = true
	})

	addr := testAddr(1)
	err := ini.HandleManagementResponse(addr, StatusSuccess)
	if err != nil {
		t.Fatalf("HandleManagementResponse: %v", err)
	}
	if !called {
		t.Fatal("callback not called")
	}
	if cbAddr != addr {
		t.Errorf("callback addr = %v, want %v", cbAddr, addr)
	}
	if cbStatus != StatusSuccess {
		t.Errorf("callback status = %d, want %d", cbStatus, StatusSuccess)
	}
}

func TestInitiator_HandleManagementResponse_NoCallback(t *testing.T) {
	ini := NewInitiator()

	// Should not panic.
	err := ini.HandleManagementResponse(testAddr(1), StatusSuccess)
	if err != nil {
		t.Fatalf("HandleManagementResponse without callback: %v", err)
	}
}

func TestInitiator_ClearPending(t *testing.T) {
	ini := NewInitiator()

	ini.SendLinkMetricsQuery(testAddr(1), 0, MetricLqi)
	ini.SendMgmtRequest(testAddr(1), 1, SeriesFlagMacData, MetricLqi)
	ini.SendEnhAckProbingRequest(testAddr(1), EnhAckRegister, MetricLqi)
	ini.SendLinkProbe(testAddr(1), 5)

	ini.ClearPendingQueries()
	ini.ClearPendingMgmtRequests()
	ini.ClearPendingEnhAckRequests()
	ini.ClearPendingLinkProbes()

	if len(ini.GetPendingQueries()) != 0 {
		t.Error("expected 0 pending queries")
	}
	if len(ini.GetPendingMgmtRequests()) != 0 {
		t.Error("expected 0 pending mgmt requests")
	}
	if len(ini.GetPendingEnhAckRequests()) != 0 {
		t.Error("expected 0 pending enh-ack requests")
	}
	if len(ini.GetPendingLinkProbes()) != 0 {
		t.Error("expected 0 pending link probes")
	}
}

// ============================================================================
// Encoding helpers tests
// ============================================================================

func TestEncodeReport_RoundTrip(t *testing.T) {
	original := &MetricsValues{
		PduCount:   42,
		Lqi:        200,
		LinkMargin: 65,
		Rssi:       -50,
		Metrics:    MetricPduCount | MetricLqi | MetricLinkMargin | MetricRssi,
	}

	encoded := EncodeReport(original)
	if len(encoded) == 0 {
		t.Fatal("EncodeReport produced empty output")
	}

	// Parse it back through HandleReport.
	ini := NewInitiator()
	var decoded *MetricsValues
	ini.SetReportCallback(func(source mac_types.ExtAddress, values *MetricsValues, status uint8) {
		decoded = values
	})

	err := ini.HandleReport(testAddr(1), encoded)
	if err != nil {
		t.Fatalf("HandleReport: %v", err)
	}
	if decoded == nil {
		t.Fatal("decoded is nil")
	}

	if decoded.PduCount != original.PduCount {
		t.Errorf("PduCount = %d, want %d", decoded.PduCount, original.PduCount)
	}
	if decoded.Lqi != original.Lqi {
		t.Errorf("Lqi = %d, want %d", decoded.Lqi, original.Lqi)
	}
	// LinkMargin and RSSI go through scaling, so allow +-1.
	lmDiff := int(decoded.LinkMargin) - int(original.LinkMargin)
	if lmDiff < -1 || lmDiff > 1 {
		t.Errorf("LinkMargin = %d, want %d (+-1)", decoded.LinkMargin, original.LinkMargin)
	}
	rssiDiff := int(decoded.Rssi) - int(original.Rssi)
	if rssiDiff < -1 || rssiDiff > 1 {
		t.Errorf("Rssi = %d, want %d (+-1)", decoded.Rssi, original.Rssi)
	}
}

func TestMetricsToTypeIDs(t *testing.T) {
	ids := MetricsToTypeIDs(MetricPduCount | MetricLqi | MetricRssi)
	if len(ids) != 3 {
		t.Fatalf("MetricsToTypeIDs: got %d IDs, want 3", len(ids))
	}
	// Verify expected IDs are present.
	found := make(map[uint8]bool)
	for _, id := range ids {
		found[id] = true
	}
	if !found[TypeIDPdu] {
		t.Error("missing TypeIDPdu")
	}
	if !found[TypeIDLqi] {
		t.Error("missing TypeIDLqi")
	}
	if !found[TypeIDRssi] {
		t.Error("missing TypeIDRssi")
	}
}

func TestTypeIDsToMetrics(t *testing.T) {
	metrics := TypeIDsToMetrics([]uint8{TypeIDPdu, TypeIDLinkMargin})
	if metrics != MetricPduCount|MetricLinkMargin {
		t.Errorf("TypeIDsToMetrics = 0x%02X, want 0x%02X", metrics, MetricPduCount|MetricLinkMargin)
	}
}

func TestMetricsTypeIDs_RoundTrip(t *testing.T) {
	original := MetricPduCount | MetricLqi | MetricLinkMargin | MetricRssi
	ids := MetricsToTypeIDs(original)
	back := TypeIDsToMetrics(ids)
	if back != original {
		t.Errorf("round-trip: 0x%02X -> %v -> 0x%02X", original, ids, back)
	}
}

// ============================================================================
// Integration: Initiator + Subject
// ============================================================================

func TestIntegration_ForwardTrackingSeries(t *testing.T) {
	subj := NewSubject()
	ini := NewInitiator()
	addr := testAddr(1)

	// Step 1: Initiator sends management request to register series.
	err := ini.SendMgmtRequest(addr, 1, SeriesFlagMacData|SeriesFlagLinkProbe, MetricLqi|MetricRssi)
	if err != nil {
		t.Fatalf("SendMgmtRequest: %v", err)
	}

	// Step 2: Subject processes the management request.
	reqs := ini.GetPendingMgmtRequests()
	status := subj.HandleManagementRequest(addr, reqs[0].SeriesID, reqs[0].SeriesFlags, reqs[0].Metrics)
	if status != StatusSuccess {
		t.Fatalf("HandleManagementRequest: status = %d", status)
	}

	// Step 3: Initiator receives management response.
	ini.HandleManagementResponse(addr, status)

	// Step 4: Subject aggregates some data.
	subj.AggregateLinkMetrics(addr, 1, 100, 50, -60)
	subj.AggregateLinkMetrics(addr, 1, 120, 70, -40)

	// Step 5: Initiator queries the series.
	err = ini.SendLinkMetricsQuery(addr, 1, 0) // forward tracking query
	if err != nil {
		t.Fatalf("SendLinkMetricsQuery: %v", err)
	}

	// Step 6: Subject responds with report.
	vals, qStatus := subj.HandleSeriesQuery(addr, 1)
	if qStatus != StatusSuccess {
		t.Fatalf("HandleSeriesQuery: status = %d", qStatus)
	}

	// Step 7: Encode and decode the report.
	encoded := EncodeReport(vals)

	var decoded *MetricsValues
	ini.SetReportCallback(func(source mac_types.ExtAddress, values *MetricsValues, st uint8) {
		decoded = values
	})
	err = ini.HandleReport(addr, encoded)
	if err != nil {
		t.Fatalf("HandleReport: %v", err)
	}
	if decoded == nil {
		t.Fatal("decoded is nil")
	}
	if decoded.PduCount != 2 {
		t.Errorf("PduCount = %d, want 2", decoded.PduCount)
	}
}

func TestIntegration_EnhAckProbing(t *testing.T) {
	subj := NewSubject()
	ini := NewInitiator()
	addr := testAddr(1)

	// Register.
	err := ini.SendEnhAckProbingRequest(addr, EnhAckRegister, MetricLqi|MetricLinkMargin)
	if err != nil {
		t.Fatalf("SendEnhAckProbingRequest: %v", err)
	}

	reqs := ini.GetPendingEnhAckRequests()
	status := subj.HandleEnhAckProbingRequest(addr, reqs[0].Flags, reqs[0].Metrics)
	if status != StatusSuccess {
		t.Fatalf("HandleEnhAckProbingRequest: status = %d", status)
	}

	vals, ok := subj.GetEnhAckMetrics(addr)
	if !ok {
		t.Fatal("GetEnhAckMetrics returned false")
	}
	if vals.Metrics != MetricLqi|MetricLinkMargin {
		t.Errorf("Metrics = 0x%02X, want 0x%02X", vals.Metrics, MetricLqi|MetricLinkMargin)
	}

	// Clear.
	err = ini.SendEnhAckProbingRequest(addr, EnhAckClear, 0)
	if err != nil {
		t.Fatalf("SendEnhAckProbingRequest clear: %v", err)
	}

	reqs = ini.GetPendingEnhAckRequests()
	// Last request (index 1) is the clear.
	status = subj.HandleEnhAckProbingRequest(addr, reqs[len(reqs)-1].Flags, reqs[len(reqs)-1].Metrics)
	if status != StatusSuccess {
		t.Fatalf("HandleEnhAckProbingRequest clear: status = %d", status)
	}

	_, ok = subj.GetEnhAckMetrics(addr)
	if ok {
		t.Error("GetEnhAckMetrics returned true after clear")
	}
}
