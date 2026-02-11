// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package linkmetrics implements Thread Link Metrics query and management.
//
// This is a Go port of OpenThread's Link Metrics functionality defined in
// src/core/thread/link_metrics.hpp, link_metrics.cpp, and
// link_metrics_types.hpp.
package linkmetrics

import (
	mac_types "github.com/hilli/gothread/mac/types"
)

// ---------------- Metric flags ------------------------------------------------

// Metric flag bitmask values indicating which metrics to track or report.
const (
	MetricPduCount   uint8 = 1 << 0 // Track PDU count.
	MetricLqi        uint8 = 1 << 1 // Track LQI.
	MetricLinkMargin uint8 = 1 << 2 // Track Link Margin.
	MetricRssi       uint8 = 1 << 3 // Track RSSI.
)

// MaxTypeIDs is the maximum number of metric Type IDs.
const MaxTypeIDs = 4

// ---------------- Status codes ------------------------------------------------

// Status codes returned by Link Metrics operations.
const (
	StatusSuccess                   uint8 = 0
	StatusCannotSupportNewSeries    uint8 = 1
	StatusSeriesIDAlreadyRegistered uint8 = 2
	StatusSeriesIDNotRecognized     uint8 = 3
	StatusNoMatchingFramesReceived  uint8 = 4
	StatusOtherError                uint8 = 254
)

// ---------------- EnhAck flags ------------------------------------------------

// Enhanced ACK probing flags.
const (
	EnhAckClear    uint8 = 0 // Clear enhanced ACK probing.
	EnhAckRegister uint8 = 1 // Register enhanced ACK probing.
)

// ---------------- Series flags ------------------------------------------------

// Series flag bitmask values specifying which frame types to count.
const (
	SeriesFlagLinkProbe  uint8 = 1 << 0 // Count MLE Link Probe messages.
	SeriesFlagMacData    uint8 = 1 << 1 // Count MAC Data frames.
	SeriesFlagMacDataReq uint8 = 1 << 2 // Count MAC Data Request frames.
	SeriesFlagAck        uint8 = 1 << 3 // Count MAC ACK frames.
)

// ---------------- Special series/query IDs ------------------------------------

const (
	queryIDSingleProbe uint8 = 0   // Series ID 0 means single probe.
	seriesIDAllSeries  uint8 = 255 // Series ID 255 means all series.
)

// ---------------- Type IDs (wire format) --------------------------------------

// Type ID flags layout:
//
//	7   6   5   4   3   2   1   0
//
// +---+---+---+---+---+---+---+---+
// | E | L |   Type    |   Metric  |
// +---+---+---+---+---+---+---+---+
const (
	typeIDExtendedFlag uint8 = 1 << 7
	typeIDLengthFlag   uint8 = 1 << 6

	typeIDTypeCount uint8 = 0 << 3 // Count/summation
	typeIDTypeAve   uint8 = 1 << 3 // Exponential moving average

	typeIDMetricPdu        uint8 = 0
	typeIDMetricLqi        uint8 = 1
	typeIDMetricLinkMargin uint8 = 2
	typeIDMetricRssi       uint8 = 3
)

// Wire Type IDs used in Link Metrics Report TLVs.
const (
	TypeIDPdu        = typeIDMetricPdu | typeIDTypeCount | typeIDLengthFlag // 0x40
	TypeIDLqi        = typeIDMetricLqi | typeIDTypeAve                      // 0x09
	TypeIDLinkMargin = typeIDMetricLinkMargin | typeIDTypeAve               // 0x0A
	TypeIDRssi       = typeIDMetricRssi | typeIDTypeAve                     // 0x0B
)

// TypeIDIsExtended reports whether a Type ID has the Extended flag set.
func TypeIDIsExtended(typeID uint8) bool {
	return typeID&typeIDExtendedFlag != 0
}

// TypeIDValueLength returns the value length in bytes for a given Type ID.
// Type IDs with the Length flag set carry a 4-byte (uint32) value; otherwise 1 byte.
func TypeIDValueLength(typeID uint8) int {
	if typeID&typeIDLengthFlag != 0 {
		return 4
	}
	return 1
}

// ---------------- Scaling functions -------------------------------------------

// Constants for scaling Link Margin and RSSI to/from raw 0-255 values.
const (
	maxLinkMargin = 130
	minRssi       = -130
	maxRssi       = 0
)

// ScaleLinkMarginToRaw linearly scales a Link Margin from [0, 130] to [0, 255].
func ScaleLinkMarginToRaw(linkMargin uint8) uint8 {
	v := uint16(linkMargin)
	if v > maxLinkMargin {
		v = maxLinkMargin
	}
	v = v * 255
	// Divide and round to closest.
	v = (v + maxLinkMargin/2) / maxLinkMargin
	return uint8(v)
}

// ScaleRawToLinkMargin scales a raw value from [0, 255] back to Link Margin [0, 130].
func ScaleRawToLinkMargin(raw uint8) uint8 {
	v := uint16(raw)
	v = v * maxLinkMargin
	v = (v + 255/2) / 255
	return uint8(v)
}

// ScaleRssiToRaw linearly scales RSSI from [-130, 0] to [0, 255].
func ScaleRssiToRaw(rssi int8) uint8 {
	v := int32(rssi)
	if v < minRssi {
		v = minRssi
	}
	if v > maxRssi {
		v = maxRssi
	}
	v = v - minRssi // shift to [0, 130]
	v = v * 255
	// Divide and round to closest: (minRssi - maxRssi) is 130 but we want
	// (maxRssi - minRssi) = 130.
	v = (v + (maxRssi-minRssi)/2) / (maxRssi - minRssi)
	return uint8(v)
}

// ScaleRawToRssi scales a raw value from [0, 255] back to RSSI [-130, 0].
func ScaleRawToRssi(raw uint8) int8 {
	v := int32(raw)
	v = v * (maxRssi - minRssi)
	v = (v + 255/2) / 255
	v += minRssi
	// Clamp to int8 range.
	if v < -128 {
		v = -128
	}
	if v > 127 {
		v = 127
	}
	return int8(v)
}

// ---------------- MetricsValues -----------------------------------------------

// MetricsValues holds the reported values for a set of link metrics.
type MetricsValues struct {
	PduCount   uint32 // Number of PDUs received.
	Lqi        uint8  // Link Quality Indicator.
	LinkMargin uint8  // Link Margin in dB.
	Rssi       int8   // RSSI in dBm.
	Metrics    uint8  // Bitmask of which metrics are present (MetricPduCount, etc.).
}

// ---------------- SeriesInfo --------------------------------------------------

// SeriesInfo tracks one Forward Tracking Series for a single neighbor.
type SeriesInfo struct {
	SeriesID        uint8
	SeriesFlags     uint8  // Frame type filter (SeriesFlagLinkProbe, etc.).
	Metrics         uint8  // Which metrics to aggregate (MetricPduCount, etc.).
	PduCount        uint32 // Number of matching PDUs counted.
	LqiSum          uint32 // Sum of LQI values for averaging.
	LqiCount        uint32 // Number of LQI samples.
	LinkMarginSum   uint32 // Sum of Link Margin values for averaging.
	LinkMarginCount uint32 // Number of Link Margin samples.
	RssiSum         int32  // Sum of RSSI values for averaging.
	RssiCount       uint32 // Number of RSSI samples.
}

// GetAverageLqi returns the average LQI, or 0 if no samples.
func (s *SeriesInfo) GetAverageLqi() uint8 {
	if s.LqiCount == 0 {
		return 0
	}
	return uint8(s.LqiSum / s.LqiCount)
}

// GetAverageLinkMargin returns the average Link Margin, or 0 if no samples.
func (s *SeriesInfo) GetAverageLinkMargin() uint8 {
	if s.LinkMarginCount == 0 {
		return 0
	}
	return uint8(s.LinkMarginSum / s.LinkMarginCount)
}

// GetAverageRssi returns the average RSSI, or 0 if no samples.
func (s *SeriesInfo) GetAverageRssi() int8 {
	if s.RssiCount == 0 {
		return 0
	}
	return int8(s.RssiSum / int32(s.RssiCount))
}

// Aggregate adds a sample to the series if the frame type matches.
func (s *SeriesInfo) Aggregate(lqi uint8, linkMargin uint8, rssi int8) {
	s.PduCount++
	if s.Metrics&MetricLqi != 0 {
		s.LqiSum += uint32(lqi)
		s.LqiCount++
	}
	if s.Metrics&MetricLinkMargin != 0 {
		s.LinkMarginSum += uint32(linkMargin)
		s.LinkMarginCount++
	}
	if s.Metrics&MetricRssi != 0 {
		s.RssiSum += int32(rssi)
		s.RssiCount++
	}
}

// ToMetricsValues converts the series aggregation into a MetricsValues report.
func (s *SeriesInfo) ToMetricsValues() MetricsValues {
	return MetricsValues{
		PduCount:   s.PduCount,
		Lqi:        s.GetAverageLqi(),
		LinkMargin: s.GetAverageLinkMargin(),
		Rssi:       s.GetAverageRssi(),
		Metrics:    s.Metrics | MetricPduCount, // PDU count is always included for series queries.
	}
}

// ---------------- EnhAckConfig ------------------------------------------------

// EnhAckConfig tracks enhanced ACK probing configuration for a neighbor.
type EnhAckConfig struct {
	Metrics uint8 // Bitmask of metrics to include in enhanced ACK IE.
}

// ---------------- seriesKey ---------------------------------------------------

// seriesKey is the composite map key for looking up SeriesInfo per neighbor.
type seriesKey struct {
	Addr     mac_types.ExtAddress
	SeriesID uint8
}

// ---------------- MaxSeriesPerNeighbor ----------------------------------------

// MaxSeriesPerNeighbor is the maximum number of forward tracking series
// that can be registered per neighbor.
const MaxSeriesPerNeighbor = 4
