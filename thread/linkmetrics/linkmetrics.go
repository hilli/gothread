// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package linkmetrics

import (
	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/errors"
	mac_types "github.com/hilli/gothread/mac/types"
)

// ============================================================================
// Subject (responder side)
// ============================================================================

// Subject handles incoming Link Metrics requests from Initiators.
//
// It manages Forward Tracking Series and Enhanced ACK Probing configuration
// on a per-neighbor basis.
type Subject struct {
	seriesMap map[seriesKey]*SeriesInfo
	enhAckMap map[mac_types.ExtAddress]*EnhAckConfig
}

// NewSubject creates a new Subject instance.
func NewSubject() *Subject {
	return &Subject{
		seriesMap: make(map[seriesKey]*SeriesInfo),
		enhAckMap: make(map[mac_types.ExtAddress]*EnhAckConfig),
	}
}

// countSeriesForNeighbor returns the number of series registered for the
// given neighbor.
func (s *Subject) countSeriesForNeighbor(source mac_types.ExtAddress) int {
	count := 0
	for k := range s.seriesMap {
		if k.Addr == source {
			count++
		}
	}
	return count
}

// HandleManagementRequest processes a Forward Tracking Series management
// request. It registers or clears series based on the seriesFlags.
//
// Returns a Link Metrics status code.
func (s *Subject) HandleManagementRequest(source mac_types.ExtAddress, seriesID uint8, seriesFlags uint8, metrics uint8) uint8 {
	// Series ID must be > 0 (0 is reserved for single probe).
	if seriesID == queryIDSingleProbe {
		return StatusOtherError
	}

	if seriesFlags == 0 {
		// Clear series.
		if seriesID == seriesIDAllSeries {
			// Remove all series for this neighbor.
			for k := range s.seriesMap {
				if k.Addr == source {
					delete(s.seriesMap, k)
				}
			}
		} else {
			key := seriesKey{Addr: source, SeriesID: seriesID}
			if _, ok := s.seriesMap[key]; !ok {
				return StatusSeriesIDNotRecognized
			}
			delete(s.seriesMap, key)
		}
	} else {
		// Register a new series.
		key := seriesKey{Addr: source, SeriesID: seriesID}
		if _, ok := s.seriesMap[key]; ok {
			return StatusSeriesIDAlreadyRegistered
		}

		if s.countSeriesForNeighbor(source) >= MaxSeriesPerNeighbor {
			return StatusCannotSupportNewSeries
		}

		s.seriesMap[key] = &SeriesInfo{
			SeriesID:    seriesID,
			SeriesFlags: seriesFlags,
			Metrics:     metrics,
		}
	}

	return StatusSuccess
}

// HandleEnhAckProbingRequest processes an Enhanced ACK probing request.
//
// When flags is EnhAckRegister, metrics must not include MetricPduCount,
// must include at least one of LQI/LinkMargin/RSSI, and must not include
// all three simultaneously.
//
// Returns a Link Metrics status code.
func (s *Subject) HandleEnhAckProbingRequest(source mac_types.ExtAddress, flags uint8, metrics uint8) uint8 {
	switch flags {
	case EnhAckRegister:
		// PDU count is not allowed in Enh-ACK probing.
		if metrics&MetricPduCount != 0 {
			return StatusOtherError
		}
		// Must have at least one metric.
		if metrics&(MetricLqi|MetricLinkMargin|MetricRssi) == 0 {
			return StatusOtherError
		}
		// Cannot request all three simultaneously (max 2 in Enh-ACK IE).
		if metrics&MetricLqi != 0 && metrics&MetricLinkMargin != 0 && metrics&MetricRssi != 0 {
			return StatusOtherError
		}
		s.enhAckMap[source] = &EnhAckConfig{Metrics: metrics}

	case EnhAckClear:
		// When clearing, no metrics should be specified.
		if metrics&(MetricLqi|MetricLinkMargin|MetricRssi) != 0 {
			return StatusOtherError
		}
		delete(s.enhAckMap, source)

	default:
		return StatusOtherError
	}

	return StatusSuccess
}

// HandleLinkProbe processes an incoming Link Probe message by aggregating
// metrics for matching series (those with SeriesFlagLinkProbe set).
func (s *Subject) HandleLinkProbe(source mac_types.ExtAddress, seriesID uint8) {
	key := seriesKey{Addr: source, SeriesID: seriesID}
	info, ok := s.seriesMap[key]
	if !ok {
		return
	}
	if info.SeriesFlags&SeriesFlagLinkProbe == 0 {
		return
	}
	// Link Probe doesn't carry actual LQI/RSSI, so aggregate with zeros.
	info.Aggregate(0, 0, 0)
}

// HandleSeriesQuery returns the aggregated metrics for a given series.
// For seriesID 0 (single probe), the caller should provide metrics directly.
//
// Returns the MetricsValues and a status code.
func (s *Subject) HandleSeriesQuery(source mac_types.ExtAddress, seriesID uint8) (*MetricsValues, uint8) {
	key := seriesKey{Addr: source, SeriesID: seriesID}
	info, ok := s.seriesMap[key]
	if !ok {
		return nil, StatusSeriesIDNotRecognized
	}
	if info.PduCount == 0 {
		return nil, StatusNoMatchingFramesReceived
	}
	vals := info.ToMetricsValues()
	return &vals, StatusSuccess
}

// AggregateLinkMetrics records a received frame's metrics for the specified
// series.
func (s *Subject) AggregateLinkMetrics(source mac_types.ExtAddress, seriesID uint8, lqi uint8, linkMargin uint8, rssi int8) {
	key := seriesKey{Addr: source, SeriesID: seriesID}
	info, ok := s.seriesMap[key]
	if !ok {
		return
	}
	info.Aggregate(lqi, linkMargin, rssi)
}

// GetEnhAckMetrics returns the Enhanced ACK probing configuration for a
// neighbor. The second return value indicates whether a configuration exists.
func (s *Subject) GetEnhAckMetrics(source mac_types.ExtAddress) (MetricsValues, bool) {
	config, ok := s.enhAckMap[source]
	if !ok {
		return MetricsValues{}, false
	}
	return MetricsValues{Metrics: config.Metrics}, true
}

// RemoveAllSeriesInfo removes all forward tracking series and enhanced ACK
// probing configuration for the given neighbor. This is typically called when
// a neighbor is removed.
func (s *Subject) RemoveAllSeriesInfo(source mac_types.ExtAddress) {
	for k := range s.seriesMap {
		if k.Addr == source {
			delete(s.seriesMap, k)
		}
	}
	delete(s.enhAckMap, source)
}

// ============================================================================
// Initiator (requester side)
// ============================================================================

// ReportCallback is called when a Link Metrics Report is received.
type ReportCallback func(source mac_types.ExtAddress, values *MetricsValues, status uint8)

// MgmtResponseCallback is called when a Link Metrics Management Response is received.
type MgmtResponseCallback func(source mac_types.ExtAddress, status uint8)

// QueryRequest represents an outstanding link metrics query.
type QueryRequest struct {
	Destination mac_types.ExtAddress
	SeriesID    uint8
	Metrics     uint8
}

// MgmtRequest represents an outstanding management request.
type MgmtRequest struct {
	Destination mac_types.ExtAddress
	SeriesID    uint8
	SeriesFlags uint8
	Metrics     uint8
}

// EnhAckRequest represents an outstanding enhanced ACK probing request.
type EnhAckRequest struct {
	Destination mac_types.ExtAddress
	Flags       uint8
	Metrics     uint8
}

// LinkProbeRequest represents an outstanding Link Probe request.
type LinkProbeRequest struct {
	Destination mac_types.ExtAddress
	SeriesID    uint8
}

// Initiator initiates Link Metrics queries and management requests.
//
// It tracks outstanding requests and provides methods to build request
// messages and handle responses.
type Initiator struct {
	reportCallback    ReportCallback
	mgmtResponseCb    MgmtResponseCallback
	pendingQueries    []QueryRequest
	pendingMgmt       []MgmtRequest
	pendingEnhAck     []EnhAckRequest
	pendingLinkProbes []LinkProbeRequest
}

// NewInitiator creates a new Initiator instance.
func NewInitiator() *Initiator {
	return &Initiator{}
}

// SetReportCallback registers a callback for Link Metrics reports.
func (i *Initiator) SetReportCallback(cb ReportCallback) {
	i.reportCallback = cb
}

// SetMgmtResponseCallback registers a callback for management responses.
func (i *Initiator) SetMgmtResponseCallback(cb MgmtResponseCallback) {
	i.mgmtResponseCb = cb
}

// SendLinkMetricsQuery prepares a Link Metrics query for the given destination.
// For single probe (seriesID=0), metrics must be non-zero. For forward
// tracking series (seriesID>0), metrics must be zero (query existing series).
func (i *Initiator) SendLinkMetricsQuery(destination mac_types.ExtAddress, seriesID uint8, metrics uint8) error {
	if seriesID != queryIDSingleProbe && metrics != 0 {
		return errors.ErrInvalidArgs
	}
	if seriesID == queryIDSingleProbe && metrics == 0 {
		return errors.ErrInvalidArgs
	}

	i.pendingQueries = append(i.pendingQueries, QueryRequest{
		Destination: destination,
		SeriesID:    seriesID,
		Metrics:     metrics,
	})
	return nil
}

// SendMgmtRequest prepares a Forward Tracking Series management request.
// seriesID must be > 0 (0 is reserved for single probe).
func (i *Initiator) SendMgmtRequest(destination mac_types.ExtAddress, seriesID uint8, seriesFlags uint8, metrics uint8) error {
	if seriesID == queryIDSingleProbe {
		return errors.ErrInvalidArgs
	}

	i.pendingMgmt = append(i.pendingMgmt, MgmtRequest{
		Destination: destination,
		SeriesID:    seriesID,
		SeriesFlags: seriesFlags,
		Metrics:     metrics,
	})
	return nil
}

// SendEnhAckProbingRequest prepares an Enhanced ACK probing request.
// When flags is EnhAckClear, metrics must be 0.
func (i *Initiator) SendEnhAckProbingRequest(destination mac_types.ExtAddress, flags uint8, metrics uint8) error {
	if flags == EnhAckClear && metrics != 0 {
		return errors.ErrInvalidArgs
	}
	if flags != EnhAckClear && flags != EnhAckRegister {
		return errors.ErrInvalidArgs
	}

	i.pendingEnhAck = append(i.pendingEnhAck, EnhAckRequest{
		Destination: destination,
		Flags:       flags,
		Metrics:     metrics,
	})
	return nil
}

// SendLinkProbe prepares a Link Probe message for the given series.
// seriesID must not be 0 (single probe) or 255 (all series).
func (i *Initiator) SendLinkProbe(destination mac_types.ExtAddress, seriesID uint8) error {
	if seriesID == queryIDSingleProbe || seriesID == seriesIDAllSeries {
		return errors.ErrInvalidArgs
	}

	i.pendingLinkProbes = append(i.pendingLinkProbes, LinkProbeRequest{
		Destination: destination,
		SeriesID:    seriesID,
	})
	return nil
}

// HandleReport processes a received Link Metrics report.
//
// The data is encoded as a sequence of Type ID + value pairs:
//   - Type ID 0x40 (PDU): 4 bytes big-endian uint32
//   - Type ID 0x09 (LQI): 1 byte
//   - Type ID 0x0A (Link Margin): 1 byte (raw, scaled to link margin)
//   - Type ID 0x0B (RSSI): 1 byte (raw, scaled to RSSI)
//
// A report with a single status byte (length == 1) is also accepted.
func (i *Initiator) HandleReport(source mac_types.ExtAddress, data []byte) error {
	if len(data) == 0 {
		return errors.ErrParse
	}

	// Check for status-only report.
	if len(data) == 1 {
		if i.reportCallback != nil {
			i.reportCallback(source, nil, data[0])
		}
		return nil
	}

	var values MetricsValues
	idx := 0

	for idx < len(data) {
		if idx >= len(data) {
			break
		}
		typeID := data[idx]
		idx++

		if TypeIDIsExtended(typeID) {
			// Skip extended type IDs (reserved).
			if idx < len(data) {
				idx++ // skip second byte
			}
			continue
		}

		valLen := TypeIDValueLength(typeID)
		if idx+valLen > len(data) {
			return errors.ErrParse
		}

		switch typeID {
		case TypeIDPdu:
			values.Metrics |= MetricPduCount
			values.PduCount = encoding.BigEndianReadUint32(data[idx : idx+4])
		case TypeIDLqi:
			values.Metrics |= MetricLqi
			values.Lqi = data[idx]
		case TypeIDLinkMargin:
			values.Metrics |= MetricLinkMargin
			values.LinkMargin = ScaleRawToLinkMargin(data[idx])
		case TypeIDRssi:
			values.Metrics |= MetricRssi
			values.Rssi = ScaleRawToRssi(data[idx])
		}
		idx += valLen
	}

	if i.reportCallback != nil {
		i.reportCallback(source, &values, StatusSuccess)
	}
	return nil
}

// HandleManagementResponse processes a received management response.
func (i *Initiator) HandleManagementResponse(source mac_types.ExtAddress, status uint8) error {
	if i.mgmtResponseCb != nil {
		i.mgmtResponseCb(source, status)
	}
	return nil
}

// GetPendingQueries returns a copy of the pending query requests.
func (i *Initiator) GetPendingQueries() []QueryRequest {
	result := make([]QueryRequest, len(i.pendingQueries))
	copy(result, i.pendingQueries)
	return result
}

// GetPendingMgmtRequests returns a copy of the pending management requests.
func (i *Initiator) GetPendingMgmtRequests() []MgmtRequest {
	result := make([]MgmtRequest, len(i.pendingMgmt))
	copy(result, i.pendingMgmt)
	return result
}

// GetPendingEnhAckRequests returns a copy of the pending enhanced ACK requests.
func (i *Initiator) GetPendingEnhAckRequests() []EnhAckRequest {
	result := make([]EnhAckRequest, len(i.pendingEnhAck))
	copy(result, i.pendingEnhAck)
	return result
}

// GetPendingLinkProbes returns a copy of the pending link probe requests.
func (i *Initiator) GetPendingLinkProbes() []LinkProbeRequest {
	result := make([]LinkProbeRequest, len(i.pendingLinkProbes))
	copy(result, i.pendingLinkProbes)
	return result
}

// ClearPendingQueries removes all pending query requests.
func (i *Initiator) ClearPendingQueries() {
	i.pendingQueries = nil
}

// ClearPendingMgmtRequests removes all pending management requests.
func (i *Initiator) ClearPendingMgmtRequests() {
	i.pendingMgmt = nil
}

// ClearPendingEnhAckRequests removes all pending enhanced ACK requests.
func (i *Initiator) ClearPendingEnhAckRequests() {
	i.pendingEnhAck = nil
}

// ClearPendingLinkProbes removes all pending link probe requests.
func (i *Initiator) ClearPendingLinkProbes() {
	i.pendingLinkProbes = nil
}

// ============================================================================
// Report encoding helpers
// ============================================================================

// EncodeReport encodes a MetricsValues into the wire format used in
// Link Metrics Report TLVs. Each present metric is encoded as a Type ID
// followed by its value.
func EncodeReport(values *MetricsValues) []byte {
	var buf []byte

	if values.Metrics&MetricPduCount != 0 {
		buf = append(buf, TypeIDPdu)
		b := make([]byte, 4)
		encoding.BigEndianWriteUint32(values.PduCount, b)
		buf = append(buf, b...)
	}
	if values.Metrics&MetricLqi != 0 {
		buf = append(buf, TypeIDLqi)
		buf = append(buf, values.Lqi)
	}
	if values.Metrics&MetricLinkMargin != 0 {
		buf = append(buf, TypeIDLinkMargin)
		buf = append(buf, ScaleLinkMarginToRaw(values.LinkMargin))
	}
	if values.Metrics&MetricRssi != 0 {
		buf = append(buf, TypeIDRssi)
		buf = append(buf, ScaleRssiToRaw(values.Rssi))
	}

	return buf
}

// MetricsToTypeIDs converts a metrics bitmask to a slice of Type ID values.
func MetricsToTypeIDs(metrics uint8) []uint8 {
	var ids []uint8
	if metrics&MetricPduCount != 0 {
		ids = append(ids, TypeIDPdu)
	}
	if metrics&MetricLqi != 0 {
		ids = append(ids, TypeIDLqi)
	}
	if metrics&MetricLinkMargin != 0 {
		ids = append(ids, TypeIDLinkMargin)
	}
	if metrics&MetricRssi != 0 {
		ids = append(ids, TypeIDRssi)
	}
	return ids
}

// TypeIDsToMetrics converts a slice of Type ID values back to a metrics
// bitmask.
func TypeIDsToMetrics(typeIDs []uint8) uint8 {
	var metrics uint8
	for _, id := range typeIDs {
		switch id {
		case TypeIDPdu:
			metrics |= MetricPduCount
		case TypeIDLqi:
			metrics |= MetricLqi
		case TypeIDLinkMargin:
			metrics |= MetricLinkMargin
		case TypeIDRssi:
			metrics |= MetricRssi
		}
	}
	return metrics
}
