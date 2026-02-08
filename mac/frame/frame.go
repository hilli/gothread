// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package frame implements IEEE 802.15.4 MAC frame parsing and building.
//
// This is a Go port of the frame handling in OpenThread's
// src/core/mac/mac_frame.hpp and src/core/mac/mac_frame.cpp.
package frame

import (
	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
)

// ---------------- Frame Control Field (FCF) constants ----------------------

// FCF bitmask and value constants for the 16-bit Frame Control Field,
// encoded in little-endian on the wire.
const (
	FcfFrameTypeMask       uint16 = 0x0007
	FcfFrameBeacon         uint16 = 0x0000
	FcfFrameData           uint16 = 0x0001
	FcfFrameAck            uint16 = 0x0002
	FcfFrameMacCmd         uint16 = 0x0003
	FcfFrameMultipurpose   uint16 = 0x0005
	FcfSecurityEnabled     uint16 = 0x0008
	FcfFramePending        uint16 = 0x0010
	FcfAckRequest          uint16 = 0x0020
	FcfPanIDCompression    uint16 = 0x0040
	FcfSequenceSuppression uint16 = 0x0100
	FcfIePresent           uint16 = 0x0200
	FcfDstAddrMask         uint16 = 0x0C00
	FcfDstAddrNone         uint16 = 0x0000
	FcfDstAddrShort        uint16 = 0x0800
	FcfDstAddrExt          uint16 = 0x0C00
	FcfFrameVersionMask    uint16 = 0x3000
	FcfFrameVersion2003    uint16 = 0x0000
	FcfFrameVersion2006    uint16 = 0x1000
	FcfFrameVersion2015    uint16 = 0x2000
	FcfSrcAddrMask         uint16 = 0xC000
	FcfSrcAddrNone         uint16 = 0x0000
	FcfSrcAddrShort        uint16 = 0x8000
	FcfSrcAddrExt          uint16 = 0xC000
)

// Size constants for frame fields.
const (
	FcfSize = 2 // Frame Control Field: 2 bytes
	FcsSize = 2 // Frame Check Sequence: 2 bytes (16-bit FCS)
	SeqSize = 1 // Sequence Number: 1 byte
)

// ---------------- Frame Type -----------------------------------------------

// Type represents an IEEE 802.15.4 frame type.
type Type uint8

const (
	// TypeBeacon is the IEEE 802.15.4 beacon frame type.
	TypeBeacon Type = 0
	// TypeData is the IEEE 802.15.4 data frame type.
	TypeData Type = 1
	// TypeAck is the IEEE 802.15.4 acknowledgement frame type.
	TypeAck Type = 2
	// TypeMacCmd is the IEEE 802.15.4 MAC command frame type.
	TypeMacCmd Type = 3
	// TypeMultipurpose is the IEEE 802.15.4 multipurpose frame type.
	TypeMultipurpose Type = 5
)

// ---------------- Frame Version --------------------------------------------

// Version represents an IEEE 802.15.4 frame version.
type Version uint16

const (
	// Version2003 is the IEEE 802.15.4-2003 frame version.
	Version2003 Version = Version(FcfFrameVersion2003)
	// Version2006 is the IEEE 802.15.4-2006 frame version.
	Version2006 Version = Version(FcfFrameVersion2006)
	// Version2015 is the IEEE 802.15.4-2015 frame version.
	Version2015 Version = Version(FcfFrameVersion2015)
)

// ---------------- Security constants ---------------------------------------

// SecurityLevel represents the IEEE 802.15.4 security level.
type SecurityLevel uint8

const (
	// SecurityNone indicates no security (security level 0).
	SecurityNone SecurityLevel = 0
	// SecurityMic32 indicates MIC-32 authentication only (security level 1).
	SecurityMic32 SecurityLevel = 1
	// SecurityMic64 indicates MIC-64 authentication only (security level 2).
	SecurityMic64 SecurityLevel = 2
	// SecurityMic128 indicates MIC-128 authentication only (security level 3).
	SecurityMic128 SecurityLevel = 3
	// SecurityEnc indicates encryption only (security level 4).
	SecurityEnc SecurityLevel = 4
	// SecurityEncMic32 indicates encryption with MIC-32 (security level 5).
	SecurityEncMic32 SecurityLevel = 5
	// SecurityEncMic64 indicates encryption with MIC-64 (security level 6).
	SecurityEncMic64 SecurityLevel = 6
	// SecurityEncMic128 indicates encryption with MIC-128 (security level 7).
	SecurityEncMic128 SecurityLevel = 7
)

// micSizes maps each SecurityLevel to its MIC size in bytes.
var micSizes = [8]uint8{0, 4, 8, 16, 0, 4, 8, 16}

// MicSize returns the MIC (Message Integrity Code) size in bytes for the
// given security level.
func (sl SecurityLevel) MicSize() uint8 {
	if sl > SecurityEncMic128 {
		return 0
	}
	return micSizes[sl]
}

// KeyIDMode represents the IEEE 802.15.4 key identifier mode.
type KeyIDMode uint8

const (
	// KeyIDMode0 selects implicit key identification (no key identifier field).
	KeyIDMode0 KeyIDMode = 0
	// KeyIDMode1 selects key identification with a 1-byte key index.
	KeyIDMode1 KeyIDMode = 1
	// KeyIDMode2 selects key identification with a 4-byte key source and 1-byte key index.
	KeyIDMode2 KeyIDMode = 2
	// KeyIDMode3 selects key identification with an 8-byte key source and 1-byte key index.
	KeyIDMode3 KeyIDMode = 3
)

// keyIDSizes maps each KeyIDMode to the key identifier field size in bytes.
var keyIDSizes = [4]uint8{0, 1, 5, 9}

// KeyIDSize returns the key identifier field size in bytes for the mode.
func (m KeyIDMode) KeyIDSize() uint8 {
	if m > KeyIDMode3 {
		return 0
	}
	return keyIDSizes[m]
}

// Aux security header field sizes.
const (
	SecurityControlSize = 1 // SecurityControl: 1 byte
	FrameCounterSize    = 4 // FrameCounter: 4 bytes
	SecurityLevelMask   = 0x07
	SecurityLevelOffset = 0
	KeyIDModeMask       = 0x18
	KeyIDModeOffset     = 3
)

// ---------------- Frame struct ---------------------------------------------

// Frame wraps a raw IEEE 802.15.4 PSDU (PHY Service Data Unit) and provides
// methods to parse its fields lazily.
type Frame struct {
	psdu []byte
}

// NewFrame creates a Frame from a raw PSDU byte slice.
func NewFrame(psdu []byte) Frame {
	return Frame{psdu: psdu}
}

// GetPsdu returns the raw PSDU bytes.
func (f *Frame) GetPsdu() []byte {
	return f.psdu
}

// GetFCF returns the 16-bit Frame Control Field (little-endian).
func (f *Frame) GetFCF() uint16 {
	if len(f.psdu) < FcfSize {
		return 0
	}
	return encoding.LittleEndianReadUint16(f.psdu[:FcfSize])
}

// GetType returns the frame type extracted from the FCF.
func (f *Frame) GetType() Type {
	return Type(f.GetFCF() & FcfFrameTypeMask)
}

// GetVersion returns the frame version extracted from the FCF.
func (f *Frame) GetVersion() Version {
	return Version(f.GetFCF() & FcfFrameVersionMask)
}

// IsSecurityEnabled reports whether the Security Enabled bit is set.
func (f *Frame) IsSecurityEnabled() bool {
	return f.GetFCF()&FcfSecurityEnabled != 0
}

// IsFramePending reports whether the Frame Pending bit is set.
func (f *Frame) IsFramePending() bool {
	return f.GetFCF()&FcfFramePending != 0
}

// IsAckRequest reports whether the Ack Request bit is set.
func (f *Frame) IsAckRequest() bool {
	return f.GetFCF()&FcfAckRequest != 0
}

// IsPanIDCompression reports whether the PAN ID Compression bit is set.
func (f *Frame) IsPanIDCompression() bool {
	return f.GetFCF()&FcfPanIDCompression != 0
}

// IsSequenceSuppressed reports whether the sequence number is suppressed.
// This is only meaningful for Version 2015 frames.
func (f *Frame) IsSequenceSuppressed() bool {
	return f.GetVersion() == Version2015 && (f.GetFCF()&FcfSequenceSuppression != 0)
}

// IsIePresent reports whether the IE Present bit is set.
func (f *Frame) IsIePresent() bool {
	return f.GetFCF()&FcfIePresent != 0
}

// GetSequence returns the Sequence Number (byte 2 of the PSDU).
// Only valid when the sequence number is not suppressed.
func (f *Frame) GetSequence() uint8 {
	if len(f.psdu) < FcfSize+SeqSize {
		return 0
	}
	return f.psdu[FcfSize]
}

// GetDstAddrMode returns the destination address type from the FCF.
func (f *Frame) GetDstAddrMode() types.AddressType {
	return fcfAddrModeToType((f.GetFCF() & FcfDstAddrMask) >> 10)
}

// GetSrcAddrMode returns the source address type from the FCF.
func (f *Frame) GetSrcAddrMode() types.AddressType {
	return fcfAddrModeToType((f.GetFCF() & FcfSrcAddrMask) >> 14)
}

// fcfAddrModeToType converts a 2-bit FCF address mode field to AddressType.
// Values: 0=None, 2=Short, 3=Extended. Value 1 is reserved.
func fcfAddrModeToType(mode uint16) types.AddressType {
	switch mode {
	case 0:
		return types.AddressTypeNone
	case 2:
		return types.AddressTypeShort
	case 3:
		return types.AddressTypeExtended
	default:
		// Mode 1 is reserved in 802.15.4; treat as None.
		return types.AddressTypeNone
	}
}

// addrSize returns the on-wire size in bytes for the given address type.
func addrSize(at types.AddressType) uint8 {
	switch at {
	case types.AddressTypeShort:
		return 2
	case types.AddressTypeExtended:
		return types.ExtAddressSize
	default:
		return 0
	}
}

// ---------------- PAN ID presence rules ------------------------------------

// IsDstPanIDPresent reports whether a Destination PAN ID is present in the
// frame header, following the 802.15.4-2006 and 802.15.4-2015 rules.
// The 2015 truth table is from OpenThread's mac_frame.cpp.
func (f *Frame) IsDstPanIDPresent() bool {
	fcf := f.GetFCF()

	if f.GetVersion() == Version2015 {
		// IEEE 802.15.4-2015 truth table (from OpenThread):
		//  1: DstNone + SrcNone + NoComp  → Not Present
		//  2: DstNone + SrcNone + Comp    → Present
		//  3: DstPresent + SrcNone + NoComp → Present
		//  4: DstPresent + SrcNone + Comp  → Not Present
		//  5: DstNone + SrcPresent + NoComp → Not Present
		//  6: DstNone + SrcPresent + Comp  → Not Present
		//  7: DstExt + SrcExt + NoComp    → Present
		//  8: DstExt + SrcExt + Comp      → Not Present
		//  9-14: other both-present combos → Present
		mask := fcf & (FcfDstAddrMask | FcfSrcAddrMask | FcfPanIDCompression)
		switch mask {
		case FcfDstAddrNone | FcfSrcAddrNone: // 1
			return false
		case FcfDstAddrShort | FcfSrcAddrNone | FcfPanIDCompression: // 4 (short dst)
			return false
		case FcfDstAddrExt | FcfSrcAddrNone | FcfPanIDCompression: // 4 (ext dst)
			return false
		case FcfDstAddrNone | FcfSrcAddrShort: // 5 (short src)
			return false
		case FcfDstAddrNone | FcfSrcAddrExt: // 5 (ext src)
			return false
		case FcfDstAddrNone | FcfSrcAddrShort | FcfPanIDCompression: // 6 (short src)
			return false
		case FcfDstAddrNone | FcfSrcAddrExt | FcfPanIDCompression: // 6 (ext src)
			return false
		case FcfDstAddrExt | FcfSrcAddrExt | FcfPanIDCompression: // 8
			return false
		default:
			return true
		}
	}

	// 802.15.4-2003 / 2006: Dst PAN ID present if dst addr is present.
	return fcf&FcfDstAddrMask != FcfDstAddrNone
}

// IsSrcPanIDPresent reports whether a Source PAN ID is present in the
// frame header.
func (f *Frame) IsSrcPanIDPresent() bool {
	fcf := f.GetFCF()

	if f.GetVersion() == Version2015 &&
		(fcf&(FcfDstAddrMask|FcfSrcAddrMask)) == (FcfDstAddrExt|FcfSrcAddrExt) {
		// Special case: when both addresses are extended in a 2015 frame,
		// the source PAN ID is never present regardless of PAN ID compression.
		return false
	}

	// For all other cases (including 2006): src PAN ID present if
	// src addr present AND PAN ID compression is NOT set.
	return fcf&FcfSrcAddrMask != FcfSrcAddrNone && fcf&FcfPanIDCompression == 0
}

// ---------------- Header offset helpers ------------------------------------

// headerOffsets holds the computed byte offsets for variable-length header
// fields. Computed once by findHeaderOffsets.
type headerOffsets struct {
	dstPanID   int // -1 if not present
	dstAddr    int // -1 if not present
	srcPanID   int // -1 if not present
	srcAddr    int // -1 if not present
	secControl int // -1 if no security
	headerEnd  int // first byte after the header (start of payload)
}

// findHeaderOffsets walks the PSDU to compute byte offsets for each header field.
func (f *Frame) findHeaderOffsets() (headerOffsets, error) {
	var h headerOffsets
	h.dstPanID = -1
	h.dstAddr = -1
	h.srcPanID = -1
	h.srcAddr = -1
	h.secControl = -1

	offset := FcfSize // past FCF

	if len(f.psdu) < FcfSize {
		return h, errors.ErrParse
	}

	// Sequence number.
	if !f.IsSequenceSuppressed() {
		offset += SeqSize
	}

	// Destination PAN ID.
	if f.IsDstPanIDPresent() {
		if offset+2 > len(f.psdu) {
			return h, errors.ErrParse
		}
		h.dstPanID = offset
		offset += 2
	}

	// Destination address.
	dstSize := int(addrSize(f.GetDstAddrMode()))
	if dstSize > 0 {
		if offset+dstSize > len(f.psdu) {
			return h, errors.ErrParse
		}
		h.dstAddr = offset
		offset += dstSize
	}

	// Source PAN ID.
	if f.IsSrcPanIDPresent() {
		if offset+2 > len(f.psdu) {
			return h, errors.ErrParse
		}
		h.srcPanID = offset
		offset += 2
	}

	// Source address.
	srcSize := int(addrSize(f.GetSrcAddrMode()))
	if srcSize > 0 {
		if offset+srcSize > len(f.psdu) {
			return h, errors.ErrParse
		}
		h.srcAddr = offset
		offset += srcSize
	}

	// Auxiliary security header.
	if f.IsSecurityEnabled() {
		if offset+SecurityControlSize > len(f.psdu) {
			return h, errors.ErrParse
		}
		h.secControl = offset
		sc := f.psdu[offset]
		offset += SecurityControlSize

		// Frame counter.
		if offset+FrameCounterSize > len(f.psdu) {
			return h, errors.ErrParse
		}
		offset += FrameCounterSize

		// Key identifier.
		kidMode := KeyIDMode((sc & KeyIDModeMask) >> KeyIDModeOffset)
		kidSize := int(kidMode.KeyIDSize())
		if offset+kidSize > len(f.psdu) {
			return h, errors.ErrParse
		}
		offset += kidSize
	}

	h.headerEnd = offset
	return h, nil
}

// ---------------- Address / PAN ID accessors --------------------------------

// GetDstPanID returns the Destination PAN ID.
func (f *Frame) GetDstPanID() (types.PanID, error) {
	h, err := f.findHeaderOffsets()
	if err != nil {
		return 0, err
	}
	if h.dstPanID < 0 {
		return 0, errors.ErrParse
	}
	return types.PanID(encoding.LittleEndianReadUint16(f.psdu[h.dstPanID:])), nil
}

// GetDstAddr returns the Destination Address.
func (f *Frame) GetDstAddr() (types.Address, error) {
	h, err := f.findHeaderOffsets()
	if err != nil {
		return types.Address{}, err
	}
	return f.readAddr(h.dstAddr, f.GetDstAddrMode())
}

// GetSrcPanID returns the Source PAN ID.
func (f *Frame) GetSrcPanID() (types.PanID, error) {
	h, err := f.findHeaderOffsets()
	if err != nil {
		return 0, err
	}
	if h.srcPanID < 0 {
		return 0, errors.ErrParse
	}
	return types.PanID(encoding.LittleEndianReadUint16(f.psdu[h.srcPanID:])), nil
}

// GetSrcAddr returns the Source Address.
func (f *Frame) GetSrcAddr() (types.Address, error) {
	h, err := f.findHeaderOffsets()
	if err != nil {
		return types.Address{}, err
	}
	return f.readAddr(h.srcAddr, f.GetSrcAddrMode())
}

// readAddr reads an address at the given PSDU offset with the given mode.
func (f *Frame) readAddr(offset int, mode types.AddressType) (types.Address, error) {
	var addr types.Address
	if mode == types.AddressTypeNone {
		addr.SetNone()
		return addr, nil
	}
	if offset < 0 {
		return addr, errors.ErrParse
	}
	switch mode {
	case types.AddressTypeShort:
		if offset+2 > len(f.psdu) {
			return addr, errors.ErrParse
		}
		addr.SetShort(types.ShortAddress(encoding.LittleEndianReadUint16(f.psdu[offset:])))
	case types.AddressTypeExtended:
		if offset+types.ExtAddressSize > len(f.psdu) {
			return addr, errors.ErrParse
		}
		var ext types.ExtAddress
		ext.Set(f.psdu[offset:offset+types.ExtAddressSize], types.ReverseByteOrder)
		addr.SetExtended(ext)
	}
	return addr, nil
}

// ---------------- Security accessors ----------------------------------------

// GetSecurityLevel returns the security level from the Aux Security Header.
// Returns SecurityNone if security is not enabled.
func (f *Frame) GetSecurityLevel() SecurityLevel {
	h, err := f.findHeaderOffsets()
	if err != nil || h.secControl < 0 {
		return SecurityNone
	}
	sc := f.psdu[h.secControl]
	return SecurityLevel((sc >> SecurityLevelOffset) & SecurityLevelMask)
}

// GetKeyIDMode returns the key identifier mode from the Aux Security Header.
// Returns KeyIDMode0 if security is not enabled.
func (f *Frame) GetKeyIDMode() KeyIDMode {
	h, err := f.findHeaderOffsets()
	if err != nil || h.secControl < 0 {
		return KeyIDMode0
	}
	sc := f.psdu[h.secControl]
	return KeyIDMode((sc & KeyIDModeMask) >> KeyIDModeOffset)
}

// GetFrameCounter returns the frame counter from the Aux Security Header.
func (f *Frame) GetFrameCounter() (uint32, error) {
	h, err := f.findHeaderOffsets()
	if err != nil {
		return 0, err
	}
	if h.secControl < 0 {
		return 0, errors.ErrParse
	}
	fcOffset := h.secControl + SecurityControlSize
	if fcOffset+FrameCounterSize > len(f.psdu) {
		return 0, errors.ErrParse
	}
	return encoding.LittleEndianReadUint32(f.psdu[fcOffset:]), nil
}

// GetKeyID returns the KeyIndex byte from the Aux Security Header.
// This is the last byte of the key identifier field (valid for all
// KeyIDModes except Mode0, which has no key identifier).
func (f *Frame) GetKeyID() (uint8, error) {
	h, err := f.findHeaderOffsets()
	if err != nil {
		return 0, err
	}
	if h.secControl < 0 {
		return 0, errors.ErrParse
	}
	kidMode := f.GetKeyIDMode()
	kidSize := int(kidMode.KeyIDSize())
	if kidSize == 0 {
		return 0, errors.ErrParse
	}
	// The KeyIndex is the last byte of the key identifier field.
	kidStart := h.secControl + SecurityControlSize + FrameCounterSize
	keyIndexOffset := kidStart + kidSize - 1
	if keyIndexOffset >= len(f.psdu) {
		return 0, errors.ErrParse
	}
	return f.psdu[keyIndexOffset], nil
}

// ---------------- Length accessors ------------------------------------------

// GetHeaderLength returns the MAC header length in bytes.
func (f *Frame) GetHeaderLength() (uint8, error) {
	h, err := f.findHeaderOffsets()
	if err != nil {
		return 0, err
	}
	return uint8(h.headerEnd), nil
}

// GetMicSize returns the MIC size in bytes based on the security level.
func (f *Frame) GetMicSize() uint8 {
	return f.GetSecurityLevel().MicSize()
}

// GetFooterLength returns the total footer length: FCS + MIC.
func (f *Frame) GetFooterLength() uint8 {
	return FcsSize + f.GetMicSize()
}

// GetPayload returns the frame payload (between header and footer).
func (f *Frame) GetPayload() ([]byte, error) {
	h, err := f.findHeaderOffsets()
	if err != nil {
		return nil, err
	}
	footerLen := int(f.GetFooterLength())
	payloadEnd := len(f.psdu) - footerLen
	if payloadEnd < h.headerEnd {
		return nil, errors.ErrParse
	}
	return f.psdu[h.headerEnd:payloadEnd], nil
}
