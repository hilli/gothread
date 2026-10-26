// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package link provides link quality tracking for Thread mesh networking.
//
// This is a pure Go port of OpenThread's link quality implementation.
// Reference: openthread/src/core/thread/link_quality.hpp
//
//	openthread/src/core/thread/link_quality.cpp
package link

import (
	goterrors "github.com/hilli/gothread/errors"
)

// InvalidRSSI is the sentinel value indicating an invalid or unknown RSS.
// Matches Radio::kInvalidRssi in OpenThread.
const InvalidRSSI int8 = 127

// MaxRateValue is the maximum value for success/failure rate (representing 100%).
const MaxRateValue uint16 = 0xffff

// Link quality values (0 through 3).
const (
	Quality0 uint8 = 0
	Quality1 uint8 = 1
	Quality2 uint8 = 2
	Quality3 uint8 = 3
)

// Route cost values corresponding to each link quality level.
const (
	CostForQuality0 uint8 = 16 // MaxRouteCost
	CostForQuality1 uint8 = 4
	CostForQuality2 uint8 = 2
	CostForQuality3 uint8 = 1
)

// Link margin thresholds for quality level transitions.
const (
	threshold3          uint8 = 20
	threshold2          uint8 = 10
	threshold1          uint8 = 2
	hysteresisThreshold uint8 = 2
)

// Typical link margins for each quality level.
const (
	quality3LinkMargin uint8 = 50
	quality2LinkMargin uint8 = 15
	quality1LinkMargin uint8 = 5
	quality0LinkMargin uint8 = 0
)

// noLinkQuality indicates no previous quality is available (used for hysteresis bypass).
const noLinkQuality uint8 = 0xff

// Default weights for IIR filters.
const (
	defaultWeight           uint16 = 64
	defaultFrameTxErrWeight uint16 = 128
	defaultMsgTxErrWeight   uint16 = 128
)

// SuccessRateTracker tracks a success/failure rate using an IIR filter.
type SuccessRateTracker struct {
	failureRate uint16
}

// AddSample adds a sample to the tracker. The weight parameter controls the IIR
// filter response (larger weight = slower response). The filter formula is:
//
//	failureRate = ((old * (weight - 1)) + newValue + (weight / 2)) / weight
//
// where newValue is 0 for success and MaxRateValue for failure.
func (s *SuccessRateTracker) AddSample(success bool, weight uint16) {
	var newValue uint32
	if !success {
		newValue = uint32(MaxRateValue)
	}
	s.failureRate = uint16((uint32(s.failureRate)*(uint32(weight)-1) + newValue + uint32(weight)/2) / uint32(weight))
}

// GetFailureRate returns the current failure rate.
func (s *SuccessRateTracker) GetFailureRate() uint16 {
	return s.failureRate
}

// GetSuccessRate returns the current success rate (MaxRateValue - failureRate).
func (s *SuccessRateTracker) GetSuccessRate() uint16 {
	return MaxRateValue - s.failureRate
}

// Clear resets the tracker to zero failure rate.
func (s *SuccessRateTracker) Clear() {
	s.failureRate = 0
}

// RSSAverager computes an exponential moving average of RSS (Received Signal Strength) values.
//
// Internally the average is stored as a fixed-point value with 3 bits of fractional
// precision. The count is capped at 8, meaning after 8 samples the coefficients are fixed.
type RSSAverager struct {
	average uint16 // stored as (-rss) << precisionBitShift
	count   uint16 // number of samples, capped at coeffMax (8)
}

// RSSAverager constants.
const (
	precisionBitShift uint8  = 3
	precision         uint16 = 1 << precisionBitShift // 8
	precisionBitMask  uint16 = precision - 1          // 7
	coeffBitShift     uint8  = 3
)

// Add adds an RSS sample to the averager. Returns an error if rss equals InvalidRSSI.
func (r *RSSAverager) Add(rss int8) error {
	if rss == InvalidRSSI {
		return goterrors.ErrInvalidArgs
	}

	// Clamp rss to max 0.
	if rss > 0 {
		rss = 0
	}

	newValue := uint16(-int16(rss)) << precisionBitShift

	if r.count >= precision {
		// count stays at precision (8), use exponential moving average.
		r.average = uint16((uint32(r.average)*(uint32(precision)-1) + uint32(newValue)) / uint32(precision))
	} else {
		r.count++
		// Arithmetic average of the first 'count' samples.
		r.average = uint16((uint32(r.average)*(uint32(r.count)-1) + uint32(newValue)) / uint32(r.count))
	}

	return nil
}

// GetAverage returns the averaged RSS value. Returns InvalidRSSI if no samples have been added.
func (r *RSSAverager) GetAverage() int8 {
	if r.count == 0 {
		return InvalidRSSI
	}

	avg := -int8(r.average >> precisionBitShift)

	// Round toward more negative if fractional part >= 0.5.
	if r.average&precisionBitMask >= (precision / 2) {
		avg--
	}

	return avg
}

// GetRaw returns the raw internal average value.
func (r *RSSAverager) GetRaw() uint16 {
	return r.average
}

// HasAverage reports whether the averager has at least one sample.
func (r *RSSAverager) HasAverage() bool {
	return r.count != 0
}

// Clear resets the averager to its initial state.
func (r *RSSAverager) Clear() {
	r.average = 0
	r.count = 0
}

// LQIAverager computes a simple moving average of LQI (Link Quality Indicator) values.
type LQIAverager struct {
	average uint8
	count   uint8
}

// Add adds an LQI sample to the averager.
func (l *LQIAverager) Add(lqi uint8) {
	if l.count < 255 {
		l.count++
	}

	effCount := l.count
	if effCount > 8 {
		effCount = 8
	}

	l.average = uint8((uint16(l.average)*(uint16(effCount)-1) + uint16(lqi)) / uint16(effCount))
}

// GetAverage returns the current LQI average.
func (l *LQIAverager) GetAverage() uint8 {
	return l.average
}

// GetCount returns the number of samples added.
func (l *LQIAverager) GetCount() uint8 {
	return l.count
}

// Clear resets the averager.
func (l *LQIAverager) Clear() {
	l.average = 0
	l.count = 0
}

// CostForQuality returns the route cost for a given link quality level.
func CostForQuality(q uint8) uint8 {
	switch q {
	case Quality0:
		return CostForQuality0
	case Quality1:
		return CostForQuality1
	case Quality2:
		return CostForQuality2
	case Quality3:
		return CostForQuality3
	default:
		return CostForQuality0
	}
}

// ComputeLinkMargin computes the link margin from a noise floor and RSS.
// Returns 0 if rss equals InvalidRSSI or if rss is below noiseFloor.
func ComputeLinkMargin(noiseFloor, rss int8) uint8 {
	if rss == InvalidRSSI {
		return 0
	}

	margin := int16(rss) - int16(noiseFloor)
	if margin < 0 {
		return 0
	}

	return uint8(margin)
}

// QualityForLinkMargin returns the link quality level for a given link margin,
// without hysteresis (no previous quality state).
func QualityForLinkMargin(linkMargin uint8) uint8 {
	return calculateQuality(linkMargin, noLinkQuality)
}

// GetTypicalRSSForQuality returns a typical RSS value for the given quality level
// relative to the provided noise floor.
func GetTypicalRSSForQuality(noiseFloor int8, quality uint8) int8 {
	var margin uint8

	switch quality {
	case Quality3:
		margin = quality3LinkMargin
	case Quality2:
		margin = quality2LinkMargin
	case Quality1:
		margin = quality1LinkMargin
	default:
		margin = quality0LinkMargin
	}

	return noiseFloor + int8(margin)
}

// calculateQuality determines the link quality level from the link margin,
// applying hysteresis based on the last known quality. If lastQuality is
// noLinkQuality, no hysteresis is applied.
func calculateQuality(linkMargin, lastQuality uint8) uint8 {
	t1 := threshold1
	t2 := threshold2
	t3 := threshold3

	if lastQuality != noLinkQuality {
		switch lastQuality {
		case 0:
			t1 += hysteresisThreshold
			t2 += hysteresisThreshold
			t3 += hysteresisThreshold
		case 1:
			t2 += hysteresisThreshold
			t3 += hysteresisThreshold
		case 2:
			t3 += hysteresisThreshold
		}
	}

	if linkMargin > t3 {
		return Quality3
	}
	if linkMargin > t2 {
		return Quality2
	}
	if linkMargin > t1 {
		return Quality1
	}
	return Quality0
}

// QualityInfo tracks comprehensive link quality information for a neighbor.
type QualityInfo struct {
	RSSAverager      RSSAverager
	qualityIn        uint8
	qualityOut       uint8
	LastRSS          int8
	FrameErrorRate   SuccessRateTracker
	MessageErrorRate SuccessRateTracker
	noiseFloor       int8
}

// NewQualityInfo creates a new QualityInfo with the given noise floor.
func NewQualityInfo(noiseFloor int8) *QualityInfo {
	q := &QualityInfo{
		noiseFloor: noiseFloor,
	}
	q.Clear()
	return q
}

// Clear resets all quality info to defaults.
func (q *QualityInfo) Clear() {
	q.RSSAverager.Clear()
	q.qualityIn = Quality0
	q.qualityOut = Quality0
	q.LastRSS = InvalidRSSI
	q.FrameErrorRate.Clear()
	q.MessageErrorRate.Clear()
}

// AddRSS adds an RSS sample and updates the link quality.
func (q *QualityInfo) AddRSS(rss int8) {
	if rss == InvalidRSSI {
		return
	}

	q.LastRSS = rss

	// Determine the previous quality for hysteresis.
	lastQuality := noLinkQuality
	if q.RSSAverager.HasAverage() {
		lastQuality = q.qualityIn
	}

	_ = q.RSSAverager.Add(rss)

	linkMargin := ComputeLinkMargin(q.noiseFloor, q.RSSAverager.GetAverage())
	q.qualityIn = calculateQuality(linkMargin, lastQuality)
}

// GetAverageRSS returns the average RSS value.
func (q *QualityInfo) GetAverageRSS() int8 {
	return q.RSSAverager.GetAverage()
}

// GetAverageRSSRaw returns the raw internal average RSS value.
func (q *QualityInfo) GetAverageRSSRaw() uint16 {
	return q.RSSAverager.GetRaw()
}

// GetLinkMargin computes and returns the current link margin.
func (q *QualityInfo) GetLinkMargin() uint8 {
	return ComputeLinkMargin(q.noiseFloor, q.GetAverageRSS())
}

// GetQualityIn returns the incoming link quality.
func (q *QualityInfo) GetQualityIn() uint8 {
	return q.qualityIn
}

// GetQualityOut returns the outgoing link quality.
func (q *QualityInfo) GetQualityOut() uint8 {
	return q.qualityOut
}

// SetQualityOut sets the outgoing link quality.
func (q *QualityInfo) SetQualityOut(quality uint8) {
	q.qualityOut = quality
}

// AddFrameTxStatus adds a frame transmission result using the default frame error weight.
func (q *QualityInfo) AddFrameTxStatus(success bool) {
	q.FrameErrorRate.AddSample(success, defaultFrameTxErrWeight)
}

// AddMessageTxStatus adds a message transmission result using the default message error weight.
func (q *QualityInfo) AddMessageTxStatus(success bool) {
	q.MessageErrorRate.AddSample(success, defaultMsgTxErrWeight)
}

// GetFrameErrorRate returns the current frame error (failure) rate.
func (q *QualityInfo) GetFrameErrorRate() uint16 {
	return q.FrameErrorRate.GetFailureRate()
}

// GetMessageErrorRate returns the current message error (failure) rate.
func (q *QualityInfo) GetMessageErrorRate() uint16 {
	return q.MessageErrorRate.GetFailureRate()
}

// SetQualityIn directly overrides the incoming link quality level (0-3).
// This is useful for testing or for explicitly setting a quality value
// without going through the RSS-based calculation path.
func (q *QualityInfo) SetQualityIn(quality uint8) {
	if quality > Quality3 {
		quality = Quality3
	}
	q.qualityIn = quality
}
