// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package links provides multi-radio link management for MAC operations.
// It defines RadioType, RadioTypes bitmask, TxFrames for multi-radio
// frame management, and Links for coordinating operations across
// multiple radio links (IEEE 802.15.4 and TREL).
//
// This is a Go port of the multi-radio link classes in OpenThread's
// src/core/mac/mac_links.hpp, src/core/mac/mac_links.cpp, and the
// RadioType/RadioTypes types from src/core/mac/mac_types.hpp.
package links

import (
	"errors"
	"fmt"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/radio"
)

// --------------------------------------------------------------------------
// RadioType — identifies a radio link type
// --------------------------------------------------------------------------

// RadioType identifies a specific radio link type.
type RadioType uint8

const (
	// RadioTypeIeee802154 is the IEEE 802.15.4 (2.4 GHz) radio link type.
	RadioTypeIeee802154 RadioType = 0
	// RadioTypeTrel is the Thread Radio Encapsulation Link type.
	RadioTypeTrel RadioType = 1
)

// NumRadioTypes is the number of supported radio link types.
const NumRadioTypes = 2

// AllRadioTypes contains all supported radio link types.
var AllRadioTypes = [NumRadioTypes]RadioType{RadioTypeIeee802154, RadioTypeTrel}

// String returns a human-readable name for the radio type.
func (t RadioType) String() string {
	switch t {
	case RadioTypeIeee802154:
		return "15.4"
	case RadioTypeTrel:
		return "TREL"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

// --------------------------------------------------------------------------
// RadioTypes — bitmask of radio link types
// --------------------------------------------------------------------------

// RadioTypes is a bitmask representing a set of radio link types.
type RadioTypes uint8

// Contains reports whether the set contains the given radio type.
func (rt RadioTypes) Contains(t RadioType) bool {
	return (rt & RadioTypes(1<<uint(t))) != 0
}

// Add returns a new set with the given radio type added.
func (rt RadioTypes) Add(t RadioType) RadioTypes {
	return rt | RadioTypes(1<<uint(t))
}

// AddTypes returns a new set that is the union of rt and other.
func (rt RadioTypes) AddTypes(other RadioTypes) RadioTypes {
	return rt | other
}

// AddAll returns a new set containing all supported radio types.
func (rt RadioTypes) AddAll() RadioTypes {
	var result RadioTypes
	for _, t := range AllRadioTypes {
		result = result.Add(t)
	}
	return result
}

// Remove returns a new set with the given radio type removed.
func (rt RadioTypes) Remove(t RadioType) RadioTypes {
	return rt &^ RadioTypes(1<<uint(t))
}

// Clear returns an empty set.
func (rt RadioTypes) Clear() RadioTypes {
	return 0
}

// IsEmpty reports whether the set is empty.
func (rt RadioTypes) IsEmpty() bool {
	return rt == 0
}

// ContainsSingleRadio reports whether the set contains exactly one radio type.
func (rt RadioTypes) ContainsSingleRadio() bool {
	return !rt.IsEmpty() && (rt&(rt-1)) == 0
}

// GetAsBitMask returns the underlying bitmask value.
func (rt RadioTypes) GetAsBitMask() uint8 {
	return uint8(rt)
}

// Subtract returns a new set that is the set difference (rt minus other).
func (rt RadioTypes) Subtract(other RadioTypes) RadioTypes {
	return rt &^ other
}

// String returns a human-readable string for the set of radio types.
func (rt RadioTypes) String() string {
	if rt.IsEmpty() {
		return "{}"
	}
	s := "{"
	first := true
	for _, t := range AllRadioTypes {
		if rt.Contains(t) {
			if !first {
				s += ", "
			}
			s += t.String()
			first = false
		}
	}
	s += "}"
	return s
}

// --------------------------------------------------------------------------
// Error sentinels
// --------------------------------------------------------------------------

var (
	// ErrNotEnabled indicates the Links has not been enabled.
	ErrNotEnabled = errors.New("links: not enabled")
	// ErrNotImplemented indicates the operation is not supported.
	ErrNotImplemented = errors.New("links: not implemented")
)

// --------------------------------------------------------------------------
// TxFrames — manages transmit frames across multiple radio types
// --------------------------------------------------------------------------

// TxFrames manages transmit frames for different radio link types.
// It tracks which radio types have been selected for transmission and
// provides access to the appropriate transmit frame.
type TxFrames struct {
	frames        [NumRadioTypes]*radio.Frame
	selectedTypes RadioTypes
	requiredTypes RadioTypes
}

// NewTxFrames creates a new TxFrames with pre-allocated frames for each
// radio type.
func NewTxFrames() *TxFrames {
	tf := &TxFrames{}
	for i := range tf.frames {
		tf.frames[i] = &radio.Frame{
			PSDU:    make([]byte, 0, radio.FrameMaxSize),
			TxInfo:  &radio.TxInfo{CsmaCaEnabled: true},
			Channel: radio.Channel24GHzMin,
		}
	}
	return tf
}

// GetTxFrame returns the transmit frame for a given radio type and adds
// the type to the selected set.
func (tf *TxFrames) GetTxFrame(t RadioType) *radio.Frame {
	tf.selectedTypes = tf.selectedTypes.Add(t)
	return tf.frames[t]
}

// GetTxFrameForTypes returns the transmit frame with the smallest MTU
// among the given set of radio types. It adds all types from the set
// to the selected set.
func (tf *TxFrames) GetTxFrameForTypes(types RadioTypes) *radio.Frame {
	var best *radio.Frame
	for _, t := range AllRadioTypes {
		if types.Contains(t) {
			f := tf.frames[t]
			if best == nil || cap(f.PSDU) < cap(best.PSDU) {
				best = f
			}
		}
	}
	tf.selectedTypes = tf.selectedTypes.AddTypes(types)
	return best
}

// GetBroadcastTxFrame returns the transmit frame for broadcast (selects
// all radio types and returns the frame with the smallest MTU).
func (tf *TxFrames) GetBroadcastTxFrame() *radio.Frame {
	var all RadioTypes
	all = all.AddAll()
	return tf.GetTxFrameForTypes(all)
}

// GetSelectedRadioTypes returns the set of radio types that have been
// selected for transmission via calls to GetTxFrame/GetTxFrameForTypes/
// GetBroadcastTxFrame.
func (tf *TxFrames) GetSelectedRadioTypes() RadioTypes {
	return tf.selectedTypes
}

// GetRequiredRadioTypes returns the set of radio types for which
// transmission must succeed for the overall operation to be considered
// successful.
func (tf *TxFrames) GetRequiredRadioTypes() RadioTypes {
	return tf.requiredTypes
}

// SetRequiredRadioTypes sets the required radio types.
func (tf *TxFrames) SetRequiredRadioTypes(types RadioTypes) {
	tf.requiredTypes = types
}

// Clear resets all frames and clears selected/required radio types.
func (tf *TxFrames) Clear() {
	for _, f := range tf.frames {
		f.PSDU = f.PSDU[:0]
		if f.TxInfo != nil {
			f.TxInfo.IsARetx = false
			f.TxInfo.IsSecurityProcessed = false
			f.TxInfo.CsmaCaEnabled = true
			f.TxInfo.IsHeaderUpdated = false
			f.TxInfo.TxPower = radio.PowerInvalid
		}
	}
	tf.selectedTypes = tf.selectedTypes.Clear()
	tf.requiredTypes = tf.requiredTypes.Clear()
}

// SetChannel sets the channel on all transmit frames.
func (tf *TxFrames) SetChannel(channel uint8) {
	for _, f := range tf.frames {
		f.Channel = channel
	}
}

// --------------------------------------------------------------------------
// Links — multi-radio link coordinator
// --------------------------------------------------------------------------

// Links coordinates MAC operations across multiple radio link types.
// In the Go port we support both IEEE 802.15.4 and TREL radios.
type Links struct {
	radios    [NumRadioTypes]radio.Radio
	txFrames  *TxFrames
	enabled   bool
	channel   uint8
	shortAddr types.ShortAddress
	extAddr   types.ExtAddress
	panID     types.PanID
}

// New creates a new Links. At least one radio must be non-nil.
// The ieee radio corresponds to RadioTypeIeee802154, and the trel
// radio corresponds to RadioTypeTrel. Either may be nil if not used.
func New(ieee, trel radio.Radio) *Links {
	l := &Links{
		txFrames:  NewTxFrames(),
		channel:   radio.Channel24GHzMin,
		shortAddr: types.ShortAddressInvalid,
		panID:     types.BroadcastPanID,
	}
	l.radios[RadioTypeIeee802154] = ieee
	l.radios[RadioTypeTrel] = trel
	return l
}

// GetRadio returns the radio for the given type, or nil if not configured.
func (l *Links) GetRadio(t RadioType) radio.Radio {
	return l.radios[t]
}

// HasRadio reports whether a radio of the given type is configured.
func (l *Links) HasRadio(t RadioType) bool {
	return l.radios[t] != nil
}

// SetPanID sets the PAN ID on all configured radios.
func (l *Links) SetPanID(panID types.PanID) {
	l.panID = panID
	for _, r := range l.radios {
		if r != nil {
			r.SetPanID(uint16(panID))
		}
	}
}

// GetShortAddress returns the current short address.
func (l *Links) GetShortAddress() types.ShortAddress {
	return l.shortAddr
}

// SetShortAddress sets the short address on all configured radios.
func (l *Links) SetShortAddress(addr types.ShortAddress) {
	l.shortAddr = addr
	for _, r := range l.radios {
		if r != nil {
			r.SetShortAddress(addr)
		}
	}
}

// GetExtAddress returns the current extended address.
func (l *Links) GetExtAddress() types.ExtAddress {
	return l.extAddr
}

// SetExtAddress sets the extended address on all configured radios.
func (l *Links) SetExtAddress(addr types.ExtAddress) {
	l.extAddr = addr
	for _, r := range l.radios {
		if r != nil {
			r.SetExtendedAddress(addr)
		}
	}
}

// Enable enables all configured radio links.
func (l *Links) Enable() error {
	for _, r := range l.radios {
		if r != nil {
			if err := r.Enable(); err != nil {
				return err
			}
		}
	}
	l.enabled = true
	return nil
}

// Disable disables all configured radio links.
func (l *Links) Disable() error {
	for _, r := range l.radios {
		if r != nil {
			if err := r.Disable(); err != nil {
				return err
			}
		}
	}
	l.enabled = false
	return nil
}

// IsEnabled reports whether the links are enabled.
func (l *Links) IsEnabled() bool {
	return l.enabled
}

// Sleep puts all configured radios into sleep mode.
func (l *Links) Sleep() error {
	for _, r := range l.radios {
		if r != nil {
			if err := r.Sleep(); err != nil {
				return err
			}
		}
	}
	return nil
}

// Receive puts all configured radios into receive mode on the given
// channel.
func (l *Links) Receive(channel uint8) error {
	l.channel = channel
	for _, r := range l.radios {
		if r != nil {
			if err := r.Receive(channel); err != nil {
				return err
			}
		}
	}
	return nil
}

// GetTxFrames returns the TxFrames for preparing frames for transmission.
func (l *Links) GetTxFrames() *TxFrames {
	return l.txFrames
}

// Send sends the frame from the given radio type's transmit buffer.
// In multi-radio mode, it sends over the specified set of radio types.
func (l *Links) Send(t RadioType) error {
	r := l.radios[t]
	if r == nil {
		return ErrNotImplemented
	}
	frame := l.txFrames.frames[t]
	return r.Transmit(frame)
}

// SendMulti sends frames over the specified set of radio types.
// The source frame is copied to each radio type's transmit buffer
// before sending.
func (l *Links) SendMulti(source *radio.Frame, radioTypes RadioTypes) error {
	for _, t := range AllRadioTypes {
		if !radioTypes.Contains(t) {
			continue
		}
		r := l.radios[t]
		if r == nil {
			continue
		}
		// Copy source PSDU to the radio type's frame if it's not
		// already the same frame.
		dst := l.txFrames.frames[t]
		if dst != source {
			dst.PSDU = append(dst.PSDU[:0], source.PSDU...)
			dst.Channel = source.Channel
			if source.TxInfo != nil && dst.TxInfo != nil {
				*dst.TxInfo = *source.TxInfo
			}
		}
		if err := r.Transmit(dst); err != nil {
			return err
		}
	}
	return nil
}

// EnergyScan starts an energy scan on the IEEE 802.15.4 radio.
// Returns ErrNotImplemented if no IEEE 802.15.4 radio is configured.
func (l *Links) EnergyScan(channel uint8, durationMs uint16) error {
	r := l.radios[RadioTypeIeee802154]
	if r == nil {
		return ErrNotImplemented
	}
	return r.EnergyScan(channel, durationMs)
}

// GetRssi returns the current RSSI from the IEEE 802.15.4 radio.
// Returns radio.RSSIInvalid if no IEEE 802.15.4 radio is configured.
func (l *Links) GetRssi() int8 {
	r := l.radios[RadioTypeIeee802154]
	if r == nil {
		return radio.RSSIInvalid
	}
	return r.GetRSSI()
}

// GetNoiseFloor returns the noise floor from the IEEE 802.15.4 radio
// (currently using receive sensitivity). Returns -100 dBm as default
// if no IEEE 802.15.4 radio is configured.
func (l *Links) GetNoiseFloor() int8 {
	r := l.radios[RadioTypeIeee802154]
	if r == nil {
		return -100
	}
	return r.GetReceiveSensitivity()
}

// GetTransmitRetries returns 0. In the full implementation this would
// query the sub-MAC for the number of retries on the last frame.
// Currently returns 0 as a placeholder.
func (l *Links) GetTransmitRetries() uint8 {
	return 0
}
