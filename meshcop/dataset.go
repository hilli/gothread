// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"bytes"
	"encoding/binary"
	"fmt"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/tlv"
)

// DatasetMaxLength is the maximum length in bytes for a MeshCoP dataset's
// TLV buffer. Corresponds to OT Dataset::kMaxLength.
const DatasetMaxLength = 254

// DatasetType identifies the type of operational dataset.
type DatasetType uint8

const (
	// DatasetActive represents the Active Operational Dataset.
	DatasetActive DatasetType = 0
	// DatasetPending represents the Pending Operational Dataset.
	DatasetPending DatasetType = 1
)

// String returns a human-readable name for the DatasetType.
func (dt DatasetType) String() string {
	switch dt {
	case DatasetActive:
		return "Active"
	case DatasetPending:
		return "Pending"
	default:
		return fmt.Sprintf("DatasetType(%d)", dt)
	}
}

// Component identifies a single component of an operational dataset.
type Component uint8

const (
	// ComponentActiveTimestamp identifies the Active Timestamp component.
	ComponentActiveTimestamp Component = iota
	// ComponentPendingTimestamp identifies the Pending Timestamp component.
	ComponentPendingTimestamp
	// ComponentNetworkKey identifies the Network Key component.
	ComponentNetworkKey
	// ComponentNetworkName identifies the Network Name component.
	ComponentNetworkName
	// ComponentExtendedPanID identifies the Extended PAN ID component.
	ComponentExtendedPanID
	// ComponentMeshLocalPrefix identifies the Mesh Local Prefix component.
	ComponentMeshLocalPrefix
	// ComponentDelay identifies the Delay Timer component.
	ComponentDelay
	// ComponentPanID identifies the PAN ID component.
	ComponentPanID
	// ComponentChannel identifies the Channel component.
	ComponentChannel
	// ComponentWakeupChannel identifies the Wakeup Channel component.
	ComponentWakeupChannel
	// ComponentPSKc identifies the PSKc component.
	ComponentPSKc
	// ComponentSecurityPolicy identifies the Security Policy component.
	ComponentSecurityPolicy
	// ComponentChannelMask identifies the Channel Mask component.
	ComponentChannelMask
)

// Components tracks which dataset components are present.
type Components struct {
	// ActiveTimestamp indicates the Active Timestamp is present.
	ActiveTimestamp bool
	// PendingTimestamp indicates the Pending Timestamp is present.
	PendingTimestamp bool
	// NetworkKey indicates the Network Key is present.
	NetworkKey bool
	// NetworkName indicates the Network Name is present.
	NetworkName bool
	// ExtendedPanID indicates the Extended PAN ID is present.
	ExtendedPanID bool
	// MeshLocalPrefix indicates the Mesh Local Prefix is present.
	MeshLocalPrefix bool
	// Delay indicates the Delay Timer is present.
	Delay bool
	// PanID indicates the PAN ID is present.
	PanID bool
	// Channel indicates the Channel is present.
	Channel bool
	// WakeupChannel indicates the Wakeup Channel is present.
	WakeupChannel bool
	// PSKc indicates the PSKc is present.
	PSKc bool
	// SecurityPolicy indicates the Security Policy is present.
	SecurityPolicy bool
	// ChannelMask indicates the Channel Mask is present.
	ChannelMask bool
}

// IsPresent reports whether the specified component is marked as present.
func (c *Components) IsPresent(comp Component) bool {
	switch comp {
	case ComponentActiveTimestamp:
		return c.ActiveTimestamp
	case ComponentPendingTimestamp:
		return c.PendingTimestamp
	case ComponentNetworkKey:
		return c.NetworkKey
	case ComponentNetworkName:
		return c.NetworkName
	case ComponentExtendedPanID:
		return c.ExtendedPanID
	case ComponentMeshLocalPrefix:
		return c.MeshLocalPrefix
	case ComponentDelay:
		return c.Delay
	case ComponentPanID:
		return c.PanID
	case ComponentChannel:
		return c.Channel
	case ComponentWakeupChannel:
		return c.WakeupChannel
	case ComponentPSKc:
		return c.PSKc
	case ComponentSecurityPolicy:
		return c.SecurityPolicy
	case ComponentChannelMask:
		return c.ChannelMask
	default:
		return false
	}
}

// MarkPresent sets the specified component as present.
func (c *Components) MarkPresent(comp Component) {
	switch comp {
	case ComponentActiveTimestamp:
		c.ActiveTimestamp = true
	case ComponentPendingTimestamp:
		c.PendingTimestamp = true
	case ComponentNetworkKey:
		c.NetworkKey = true
	case ComponentNetworkName:
		c.NetworkName = true
	case ComponentExtendedPanID:
		c.ExtendedPanID = true
	case ComponentMeshLocalPrefix:
		c.MeshLocalPrefix = true
	case ComponentDelay:
		c.Delay = true
	case ComponentPanID:
		c.PanID = true
	case ComponentChannel:
		c.Channel = true
	case ComponentWakeupChannel:
		c.WakeupChannel = true
	case ComponentPSKc:
		c.PSKc = true
	case ComponentSecurityPolicy:
		c.SecurityPolicy = true
	case ComponentChannelMask:
		c.ChannelMask = true
	}
}

// Info is the structured representation of an operational dataset.
type Info struct {
	// ActiveTimestamp is the Active Timestamp value.
	ActiveTimestamp Timestamp
	// PendingTimestamp is the Pending Timestamp value.
	PendingTimestamp Timestamp
	// NetworkKey is the 16-byte Thread Network Key.
	NetworkKey [16]byte
	// NetworkName is the Thread Network Name (up to 16 UTF-8 characters).
	NetworkName string
	// ExtendedPanID is the 8-byte Extended PAN ID.
	ExtendedPanID [8]byte
	// MeshLocalPrefix is the 8-byte Mesh-Local Prefix.
	MeshLocalPrefix [8]byte
	// Delay is the Delay Timer in milliseconds.
	Delay uint32
	// PanID is the IEEE 802.15.4 PAN ID.
	PanID uint16
	// Channel is the IEEE 802.15.4 channel number.
	Channel uint16
	// WakeupChannel is the Wakeup Channel number.
	WakeupChannel uint16
	// PSKc is the 16-byte Pre-Shared Key for the Commissioner.
	PSKc [16]byte
	// SecurityPolicy contains the Thread Security Policy.
	SecurityPolicy key.SecurityPolicy
	// ChannelMask is the channel mask (page 0).
	ChannelMask uint32
	// Components tracks which fields are populated.
	Components Components
}

// Dataset is a flat TLV buffer that holds a Thread Operational Dataset.
type Dataset struct {
	tlvs   [DatasetMaxLength]byte
	length uint8
}

// Clear resets the dataset to empty.
func (d *Dataset) Clear() {
	d.length = 0
}

// Length returns the current dataset length in bytes.
func (d *Dataset) Length() uint8 {
	return d.length
}

// Bytes returns a slice of the dataset's TLV bytes.
func (d *Dataset) Bytes() []byte {
	return d.tlvs[:d.length]
}

// SetFrom sets the dataset from raw TLV bytes.
// Returns ErrInvalidArgs if data is longer than DatasetMaxLength.
func (d *Dataset) SetFrom(data []byte) error {
	if len(data) > DatasetMaxLength {
		return goterrors.ErrInvalidArgs
	}
	copy(d.tlvs[:], data)
	d.length = uint8(len(data))
	return nil
}

// FindTLV searches for a TLV by type. Returns nil if not found.
func (d *Dataset) FindTLV(typ TLVType) *tlv.TLV {
	parsed, err := tlv.ParseAll(d.Bytes())
	if err != nil {
		return nil
	}
	return tlv.FindByType(parsed, uint8(typ))
}

// ContainsTLV reports whether a TLV of the given type exists.
func (d *Dataset) ContainsTLV(typ TLVType) bool {
	return d.FindTLV(typ) != nil
}

// WriteTLV writes (upserts) a TLV. If the type already exists, it is replaced;
// otherwise it is appended. Returns ErrNoBufs if there is not enough space.
func (d *Dataset) WriteTLV(typ TLVType, value []byte) error {
	newSize := tlv.HeaderSize + len(value)

	// Check if the type already exists and remove it first.
	existing := d.findTLVOffset(typ)
	if existing >= 0 {
		d.removeTLVAtOffset(existing)
	}

	// Check if there is room for the new TLV.
	if int(d.length)+newSize > DatasetMaxLength {
		return goterrors.ErrNoBufs
	}

	// Append the new TLV.
	d.tlvs[d.length] = uint8(typ)
	d.tlvs[d.length+1] = uint8(len(value))
	copy(d.tlvs[d.length+2:], value)
	d.length += uint8(newSize)
	return nil
}

// WriteTLVRaw writes a pre-encoded TLV (type+length+value bytes) to the dataset.
// If a TLV of the same type exists, it is replaced; otherwise it is appended.
// Returns ErrNoBufs if there is not enough space.
func (d *Dataset) WriteTLVRaw(t tlv.TLV) error {
	return d.WriteTLV(TLVType(t.Type), t.Value)
}

// RemoveTLV removes a TLV by type. No-op if not found.
func (d *Dataset) RemoveTLV(typ TLVType) {
	offset := d.findTLVOffset(typ)
	if offset < 0 {
		return
	}
	d.removeTLVAtOffset(offset)
}

// findTLVOffset returns the byte offset of the TLV with the given type,
// or -1 if not found.
func (d *Dataset) findTLVOffset(typ TLVType) int {
	data := d.Bytes()
	offset := 0
	for offset < len(data) {
		t, n, err := tlv.Parse(data[offset:])
		if err != nil {
			return -1
		}
		if t.Type == uint8(typ) {
			return offset
		}
		offset += n
	}
	return -1
}

// removeTLVAtOffset removes the TLV at the given byte offset.
func (d *Dataset) removeTLVAtOffset(offset int) {
	data := d.Bytes()
	_, n, err := tlv.Parse(data[offset:])
	if err != nil {
		return
	}
	end := offset + n
	copy(d.tlvs[offset:], d.tlvs[end:d.length])
	d.length -= uint8(n)
}

// ValidateTLVs validates all TLVs in the dataset.
// Checks that the format is valid, there are no duplicate types, and no
// extended-format TLVs are present. Returns ErrParse on failure.
func (d *Dataset) ValidateTLVs() error {
	data := d.Bytes()
	seen := make(map[uint8]bool)
	offset := 0

	for offset < len(data) {
		// Reject extended-format TLVs.
		if tlv.IsExtended(data[offset:]) {
			return goterrors.ErrParse
		}

		t, n, err := tlv.Parse(data[offset:])
		if err != nil {
			return goterrors.ErrParse
		}

		// Check for duplicates.
		if seen[t.Type] {
			return goterrors.ErrParse
		}
		seen[t.Type] = true

		offset += n
	}

	return nil
}

// ReadUint16TLV reads a uint16 value from a TLV. Returns ErrNotFound if the
// TLV is missing or has an insufficient value length.
func (d *Dataset) ReadUint16TLV(typ TLVType) (uint16, error) {
	t := d.FindTLV(typ)
	if t == nil || len(t.Value) < 2 {
		return 0, goterrors.ErrNotFound
	}
	return binary.BigEndian.Uint16(t.Value[:2]), nil
}

// ReadUint32TLV reads a uint32 value from a TLV. Returns ErrNotFound if the
// TLV is missing or has an insufficient value length.
func (d *Dataset) ReadUint32TLV(typ TLVType) (uint32, error) {
	t := d.FindTLV(typ)
	if t == nil || len(t.Value) < 4 {
		return 0, goterrors.ErrNotFound
	}
	return binary.BigEndian.Uint32(t.Value[:4]), nil
}

// WriteUint16TLV writes a uint16 TLV (big-endian encoded).
func (d *Dataset) WriteUint16TLV(typ TLVType, val uint16) error {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, val)
	return d.WriteTLV(typ, buf)
}

// WriteUint32TLV writes a uint32 TLV (big-endian encoded).
func (d *Dataset) WriteUint32TLV(typ TLVType, val uint32) error {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, val)
	return d.WriteTLV(typ, buf)
}

// timestampTLVTypeFor returns the TLV type for the given DatasetType's
// timestamp.
func timestampTLVTypeFor(dt DatasetType) TLVType {
	if dt == DatasetActive {
		return TLVActiveTimestamp
	}
	return TLVPendingTimestamp
}

// ReadTimestamp reads an Active or Pending Timestamp from the dataset.
// Returns ErrNotFound if the timestamp TLV is not present.
func (d *Dataset) ReadTimestamp(dt DatasetType) (*Timestamp, error) {
	t := d.FindTLV(timestampTLVTypeFor(dt))
	if t == nil {
		return nil, goterrors.ErrNotFound
	}
	var ts Timestamp
	if err := ts.UnmarshalBinary(t.Value); err != nil {
		return nil, err
	}
	return &ts, nil
}

// WriteTimestamp writes an Active or Pending Timestamp to the dataset.
func (d *Dataset) WriteTimestamp(dt DatasetType, ts *Timestamp) error {
	data, err := ts.MarshalBinary()
	if err != nil {
		return err
	}
	return d.WriteTLV(timestampTLVTypeFor(dt), data)
}

// WriteTLVsFrom merges all TLVs from another dataset into this one using
// upsert semantics. Returns ErrParse if the source dataset is invalid,
// or ErrNoBufs if there is insufficient space.
func (d *Dataset) WriteTLVsFrom(other *Dataset) error {
	if err := other.ValidateTLVs(); err != nil {
		return goterrors.ErrParse
	}

	parsed, err := tlv.ParseAll(other.Bytes())
	if err != nil {
		return goterrors.ErrParse
	}

	for _, t := range parsed {
		if writeErr := d.WriteTLV(TLVType(t.Type), t.Value); writeErr != nil {
			return writeErr
		}
	}
	return nil
}

// AppendTLVsFrom appends raw TLV bytes without validation or dedup.
// Returns ErrNoBufs if there is insufficient space.
func (d *Dataset) AppendTLVsFrom(data []byte) error {
	if int(d.length)+len(data) > DatasetMaxLength {
		return goterrors.ErrNoBufs
	}
	copy(d.tlvs[d.length:], data)
	d.length += uint8(len(data))
	return nil
}

// ConvertToInfo converts the TLV buffer to a structured Info representation.
func (d *Dataset) ConvertToInfo() Info {
	var info Info

	parsed, err := tlv.ParseAll(d.Bytes())
	if err != nil {
		return info
	}

	for _, t := range parsed {
		switch TLVType(t.Type) {
		case TLVActiveTimestamp:
			if info.ActiveTimestamp.UnmarshalBinary(t.Value) == nil {
				info.Components.MarkPresent(ComponentActiveTimestamp)
			}

		case TLVPendingTimestamp:
			if info.PendingTimestamp.UnmarshalBinary(t.Value) == nil {
				info.Components.MarkPresent(ComponentPendingTimestamp)
			}

		case TLVNetworkKey:
			if len(t.Value) >= 16 {
				copy(info.NetworkKey[:], t.Value[:16])
				info.Components.MarkPresent(ComponentNetworkKey)
			}

		case TLVNetworkName:
			info.NetworkName = string(t.Value)
			info.Components.MarkPresent(ComponentNetworkName)

		case TLVExtendedPanID:
			if len(t.Value) >= 8 {
				copy(info.ExtendedPanID[:], t.Value[:8])
				info.Components.MarkPresent(ComponentExtendedPanID)
			}

		case TLVMeshLocalPrefix:
			if len(t.Value) >= 8 {
				copy(info.MeshLocalPrefix[:], t.Value[:8])
				info.Components.MarkPresent(ComponentMeshLocalPrefix)
			}

		case TLVDelayTimer:
			if len(t.Value) >= 4 {
				info.Delay = binary.BigEndian.Uint32(t.Value[:4])
				info.Components.MarkPresent(ComponentDelay)
			}

		case TLVPanID:
			if len(t.Value) >= 2 {
				info.PanID = binary.BigEndian.Uint16(t.Value[:2])
				info.Components.MarkPresent(ComponentPanID)
			}

		case TLVChannel:
			// Channel TLV value: 1 byte page + 2 bytes channel (big-endian).
			if len(t.Value) >= 3 {
				info.Channel = binary.BigEndian.Uint16(t.Value[1:3])
				info.Components.MarkPresent(ComponentChannel)
			}

		case TLVWakeupChannel:
			// Same format as Channel TLV.
			if len(t.Value) >= 3 {
				info.WakeupChannel = binary.BigEndian.Uint16(t.Value[1:3])
				info.Components.MarkPresent(ComponentWakeupChannel)
			}

		case TLVPSKc:
			if len(t.Value) >= 16 {
				copy(info.PSKc[:], t.Value[:16])
				info.Components.MarkPresent(ComponentPSKc)
			}

		case TLVSecurityPolicy:
			// Security Policy TLV: 2 bytes rotation time (big-endian) + flags.
			if len(t.Value) >= 2 {
				info.SecurityPolicy.RotationTime = binary.BigEndian.Uint16(t.Value[:2])
				if len(t.Value) > 2 {
					info.SecurityPolicy.SetFlags(t.Value[2:])
				}
				info.Components.MarkPresent(ComponentSecurityPolicy)
			}

		case TLVChannelMask:
			// Channel Mask TLV value: entries of
			// (1 byte page + 1 byte maskLen + maskLen bytes mask).
			offset := 0
			v := t.Value
			for offset < len(v) {
				if offset+2 > len(v) {
					break
				}
				page := v[offset]
				maskLen := v[offset+1]
				offset += 2
				if offset+int(maskLen) > len(v) {
					break
				}
				if page == 0 && maskLen >= 4 {
					info.ChannelMask = binary.BigEndian.Uint32(v[offset : offset+4])
					info.Components.MarkPresent(ComponentChannelMask)
				}
				offset += int(maskLen)
			}
		}
	}

	return info
}

// IsSubsetOf reports whether this dataset is a subset of another.
// A dataset is a subset if all TLVs (excluding Active Timestamp, Pending
// Timestamp, and Delay Timer) are present and equal in the other dataset.
func (d *Dataset) IsSubsetOf(other *Dataset) bool {
	parsed, err := tlv.ParseAll(d.Bytes())
	if err != nil {
		return false
	}

	otherParsed, err := tlv.ParseAll(other.Bytes())
	if err != nil {
		return false
	}

	for _, t := range parsed {
		typ := TLVType(t.Type)
		// Skip timestamps and delay timer.
		if typ == TLVActiveTimestamp || typ == TLVPendingTimestamp || typ == TLVDelayTimer {
			continue
		}

		match := tlv.FindByType(otherParsed, t.Type)
		if match == nil {
			return false
		}
		if !bytes.Equal(t.Value, match.Value) {
			return false
		}
	}
	return true
}

// requiredActiveTLVs lists the TLV types required for an Active Dataset.
var requiredActiveTLVs = []TLVType{
	TLVActiveTimestamp,
	TLVChannel,
	TLVChannelMask,
	TLVExtendedPanID,
	TLVMeshLocalPrefix,
	TLVNetworkKey,
	TLVNetworkName,
	TLVPanID,
	TLVPSKc,
	TLVSecurityPolicy,
}

// requiredPendingTLVs lists the additional TLV types required for a Pending
// Dataset beyond the Active Dataset requirements.
var requiredPendingTLVs = []TLVType{
	TLVPendingTimestamp,
	TLVDelayTimer,
}

// ContainsAllRequiredTLVsFor reports whether the dataset has all required TLVs
// for the given DatasetType.
//
// Active requires: ActiveTimestamp, Channel, ChannelMask, ExtendedPanID,
// MeshLocalPrefix, NetworkKey, NetworkName, PanID, PSKc, SecurityPolicy
// (10 TLVs).
//
// Pending requires: all Active TLVs plus PendingTimestamp and DelayTimer
// (12 TLVs).
func (d *Dataset) ContainsAllRequiredTLVsFor(dt DatasetType) bool {
	for _, typ := range requiredActiveTLVs {
		if !d.ContainsTLV(typ) {
			return false
		}
	}

	if dt == DatasetPending {
		for _, typ := range requiredPendingTLVs {
			if !d.ContainsTLV(typ) {
				return false
			}
		}
	}

	return true
}
