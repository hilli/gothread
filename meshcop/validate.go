// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
	"unicode/utf8"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/tlv"
)

// Page0ThreadChannelMask is the supported 2.4GHz Thread channel range 11..26.
const Page0ThreadChannelMask uint32 = 0x07fff800

// ValidateOperationalDataset validates a complete, supported page-zero
// operational dataset without mutation. supportedChannels must be explicitly
// supplied by the selected radio, not inferred from a preferred-channel mask.
// This validates configuration, not credentials, attachment or RF reachability.
func ValidateOperationalDataset(data []byte, kind DatasetType, supportedChannels uint32) error {
	if kind != DatasetActive && kind != DatasetPending {
		return goterrors.ErrInvalidArgs
	}
	if supportedChannels&Page0ThreadChannelMask == 0 {
		return goterrors.ErrNotCapable
	}
	dataset := &Dataset{}
	if err := dataset.SetFrom(data); err != nil {
		return err
	}
	if len(data) == 0 {
		return goterrors.ErrInvalidArgs
	}
	if err := dataset.ValidateTLVs(); err != nil {
		return err
	}
	if !dataset.ContainsAllRequiredTLVsFor(kind) {
		return fmt.Errorf("meshcop: incomplete operational dataset: %w", goterrors.ErrInvalidArgs)
	}
	records, err := tlv.ParseAll(data)
	if err != nil {
		return goterrors.ErrParse
	}
	var channel uint16
	var mask uint32
	for _, record := range records {
		value := record.Value
		length := len(value)
		switch TLVType(record.Type) {
		case TLVActiveTimestamp, TLVPendingTimestamp:
			if length != TimestampSize {
				return goterrors.ErrParse
			}
			var timestamp Timestamp
			if err := timestamp.UnmarshalBinary(value); err != nil || !timestamp.IsValid() {
				return goterrors.ErrInvalidArgs
			}
			if TLVType(record.Type) == TLVPendingTimestamp && kind != DatasetPending {
				return goterrors.ErrInvalidArgs
			}
		case TLVChannel:
			if length != 3 {
				return goterrors.ErrParse
			}
			if value[0] != 0 {
				return goterrors.ErrNotCapable
			}
			channel = binary.BigEndian.Uint16(value[1:])
			if channel < 11 || channel > 26 {
				return goterrors.ErrInvalidArgs
			}
		case TLVChannelMask:
			// This subset supports exactly one page-zero, 32-bit mask entry.
			if length != 6 || value[1] != 4 {
				return goterrors.ErrParse
			}
			if value[0] != 0 {
				return goterrors.ErrNotCapable
			}
			mask = bits.Reverse32(binary.BigEndian.Uint32(value[2:]))
			if mask == 0 || mask & ^Page0ThreadChannelMask != 0 {
				return goterrors.ErrInvalidArgs
			}
		case TLVNetworkKey, TLVPSKc:
			if length != 16 {
				return goterrors.ErrParse
			}
		case TLVExtendedPanID:
			if length != 8 {
				return goterrors.ErrParse
			}
		case TLVMeshLocalPrefix:
			if length != 8 {
				return goterrors.ErrParse
			}
			if value[0] != 0xfd {
				return goterrors.ErrInvalidArgs
			}
		case TLVNetworkName:
			if length == 0 || length > 16 || !utf8.Valid(value) || bytes.IndexByte(value, 0) >= 0 {
				return goterrors.ErrInvalidArgs
			}
		case TLVPanID:
			if length != 2 {
				return goterrors.ErrParse
			}
			if binary.BigEndian.Uint16(value) == 0xffff {
				return goterrors.ErrInvalidArgs
			}
		case TLVSecurityPolicy:
			if length != 3 && length != 4 {
				return goterrors.ErrParse
			}
			if binary.BigEndian.Uint16(value) < key.MinKeyRotationTime {
				return goterrors.ErrInvalidArgs
			}
		case TLVDelayTimer:
			if kind != DatasetPending || length != 4 {
				return goterrors.ErrInvalidArgs
			}
		default:
			return fmt.Errorf("meshcop: unsupported operational dataset TLV %d: %w", record.Type, goterrors.ErrNotCapable)
		}
	}
	if mask&(uint32(1)<<channel) == 0 || supportedChannels&(uint32(1)<<channel) == 0 {
		return goterrors.ErrNotCapable
	}
	return nil
}
