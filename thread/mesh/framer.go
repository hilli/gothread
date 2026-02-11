// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import (
	"encoding/binary"

	"github.com/hilli/gothread/errors"
)

// SecurityLevel represents the IEEE 802.15.4 security level used in
// the auxiliary security header. Values match the Security Level field
// in the Security Control byte.
type SecurityLevel uint8

const (
	// SecurityNone indicates no security (level 0).
	SecurityNone SecurityLevel = 0
	// SecurityMic32 indicates MIC-32 authentication only (level 1).
	SecurityMic32 SecurityLevel = 1
	// SecurityMic64 indicates MIC-64 authentication only (level 2).
	SecurityMic64 SecurityLevel = 2
	// SecurityMic128 indicates MIC-128 authentication only (level 3).
	SecurityMic128 SecurityLevel = 3
	// SecurityEnc indicates encryption only (level 4).
	SecurityEnc SecurityLevel = 4
	// SecurityEncMic32 indicates encryption with MIC-32 (level 5).
	SecurityEncMic32 SecurityLevel = 5
	// SecurityEncMic64 indicates encryption with MIC-64 (level 6).
	SecurityEncMic64 SecurityLevel = 6
	// SecurityEncMic128 indicates encryption with MIC-128 (level 7).
	SecurityEncMic128 SecurityLevel = 7
)

// FrameType identifies the type of message being framed.
type FrameType uint8

const (
	// FrameTypeData is a MAC data frame.
	FrameTypeData FrameType = 0x01
	// FrameTypeMleCommand is an MLE command frame.
	FrameTypeMleCommand FrameType = 0x02
	// FrameTypeMeshHeader is a mesh-header frame.
	FrameTypeMeshHeader FrameType = 0x03
)

// Address mode constants for IEEE 802.15.4 FCF address mode fields.
const (
	AddrModeNone     uint8 = 0x00
	AddrModeShort    uint8 = 0x02
	AddrModeExtended uint8 = 0x03
)

// Frame version constants for IEEE 802.15.4 FCF frame version field.
const (
	FrameVersion2003 uint8 = 0x00
	FrameVersion2006 uint8 = 0x01
	FrameVersion2015 uint8 = 0x02
)

// MaxPsduSize is the maximum 802.15.4 PHY-layer frame size (127 bytes).
const MaxPsduSize = 127

// FCSSize is the Frame Check Sequence size added by radio hardware.
const FCSSize = 2

// SecurityMaterial holds the keying material and frame counter needed
// to construct the auxiliary security header.
type SecurityMaterial struct {
	// KeyIdMode is the key identifier mode (0, 1, or 2).
	KeyIdMode uint8
	// KeyId is the key identifier (key index byte).
	KeyId uint8
	// Key is the 128-bit AES key.
	Key [16]byte
	// FrameCounter is the outgoing frame counter.
	FrameCounter uint32
}

// FrameContext holds all addressing, security, and control information
// needed to build or parse an IEEE 802.15.4 MAC frame header.
type FrameContext struct {
	SrcShortAddr    uint16
	SrcExtAddr      [8]byte
	DstShortAddr    uint16
	DstExtAddr      [8]byte
	UseSrcShort     bool // true: use short source address; false: use extended
	UseDstShort     bool // true: use short dest address; false: use extended
	PanId           uint16
	SecurityEnabled bool
	Security        SecurityMaterial
	AckRequest      bool
	SequenceNumber  uint8
	FramePending    bool
	IEPresent       bool
}

// Framer constructs and parses IEEE 802.15.4 MAC data frames.
type Framer struct{}

// NewFramer creates a new Framer.
func NewFramer() *Framer {
	return &Framer{}
}

// buildFrameControl constructs the 16-bit Frame Control Field from
// individual flag and mode values. The result is stored in the frame
// in little-endian byte order.
func buildFrameControl(frameType uint8, securityEnabled, framePending, ackRequest, panIdCompression, iePresent bool, dstAddrMode, srcAddrMode, frameVersion uint8) uint16 {
	var fc uint16

	fc |= uint16(frameType & 0x07)

	if securityEnabled {
		fc |= 0x0008
	}
	if framePending {
		fc |= 0x0010
	}
	if ackRequest {
		fc |= 0x0020
	}
	if panIdCompression {
		fc |= 0x0040
	}
	if iePresent {
		fc |= 0x0200
	}

	fc |= uint16(dstAddrMode&0x03) << 10
	fc |= uint16(frameVersion&0x03) << 12
	fc |= uint16(srcAddrMode&0x03) << 14

	return fc
}

// parseFrameControl decomposes a 16-bit FCF into its constituent fields.
func parseFrameControl(fc uint16) (frameType, dstAddrMode, srcAddrMode, frameVersion uint8, securityEnabled, framePending, ackRequest, panIdCompression, iePresent bool) {
	frameType = uint8(fc & 0x0007)
	securityEnabled = (fc & 0x0008) != 0
	framePending = (fc & 0x0010) != 0
	ackRequest = (fc & 0x0020) != 0
	panIdCompression = (fc & 0x0040) != 0
	iePresent = (fc & 0x0200) != 0
	dstAddrMode = uint8((fc >> 10) & 0x03)
	frameVersion = uint8((fc >> 12) & 0x03)
	srcAddrMode = uint8((fc >> 14) & 0x03)
	return
}

// addrModeSize returns the on-wire byte size for the given address mode.
func addrModeSize(mode uint8) int {
	switch mode {
	case AddrModeShort:
		return 2
	case AddrModeExtended:
		return 8
	default:
		return 0
	}
}

// keyIdFieldSize returns the size of the key identifier field for the
// given key ID mode.
func keyIdFieldSize(mode uint8) int {
	switch mode {
	case 0:
		return 0 // implicit
	case 1:
		return 1 // 1-byte key index
	case 2:
		return 5 // 4-byte key source + 1-byte key index
	case 3:
		return 9 // 8-byte key source + 1-byte key index
	default:
		return 0
	}
}

// securityHeaderSize returns the total auxiliary security header size
// for the given key ID mode: security control (1) + frame counter (4) +
// key identifier (variable).
func securityHeaderSize(keyIdMode uint8) int {
	return 1 + 4 + keyIdFieldSize(keyIdMode)
}

// ctxDstAddrMode returns the FCF address mode for the destination in ctx.
func ctxDstAddrMode(ctx *FrameContext) uint8 {
	if ctx.UseDstShort {
		return AddrModeShort
	}
	return AddrModeExtended
}

// ctxSrcAddrMode returns the FCF address mode for the source in ctx.
func ctxSrcAddrMode(ctx *FrameContext) uint8 {
	if ctx.UseSrcShort {
		return AddrModeShort
	}
	return AddrModeExtended
}

// shouldCompressPanId returns true if PAN ID compression should be used.
// For 802.15.4-2006 frames with both source and destination present and
// same PAN ID, the source PAN ID is omitted.
func shouldCompressPanId(ctx *FrameContext) bool {
	// Both addresses are present and they share the same PAN.
	return true // src PAN == dst PAN (same PanId field), always compress when both present
}

// GetHeaderSize calculates the total MAC header size for the given
// frame context (not including payload or FCS).
func (f *Framer) GetHeaderSize(ctx *FrameContext) int {
	size := 2 // FCF
	size++    // sequence number

	dstMode := ctxDstAddrMode(ctx)
	srcMode := ctxSrcAddrMode(ctx)

	// Destination PAN ID (always present when dst addr present)
	size += 2
	// Destination address
	size += addrModeSize(dstMode)

	// Source PAN ID: present only if not compressed
	panIdCompressed := shouldCompressPanId(ctx)
	if !panIdCompressed {
		size += 2
	}

	// Source address
	size += addrModeSize(srcMode)

	// Auxiliary security header
	if ctx.SecurityEnabled {
		size += securityHeaderSize(ctx.Security.KeyIdMode)
	}

	return size
}

// GetMaxPayloadSize returns the maximum payload that can fit in a
// single MAC frame for the given context. This accounts for the header
// size and FCS (which is added by radio hardware and not included in
// the frame buffer, but counts against the 127-byte PSDU limit).
func (f *Framer) GetMaxPayloadSize(ctx *FrameContext) int {
	maxPayload := MaxPsduSize - FCSSize - f.GetHeaderSize(ctx)
	if maxPayload < 0 {
		return 0
	}
	return maxPayload
}

// BuildDataFrame constructs a complete IEEE 802.15.4 MAC data frame
// from the given context and payload. The frame is returned without FCS
// (that is appended by radio hardware).
func (f *Framer) BuildDataFrame(ctx *FrameContext, payload []byte) ([]byte, error) {
	headerSize := f.GetHeaderSize(ctx)
	maxPayload := MaxPsduSize - FCSSize - headerSize
	if len(payload) > maxPayload {
		return nil, errors.ErrNoBufs
	}

	buf := make([]byte, 0, headerSize+len(payload))

	dstMode := ctxDstAddrMode(ctx)
	srcMode := ctxSrcAddrMode(ctx)
	panIdCompressed := shouldCompressPanId(ctx)

	// Frame version: use 2006 by default (supports security + PAN ID compression).
	frameVersion := uint8(FrameVersion2006)

	fc := buildFrameControl(
		uint8(FrameTypeData), // MAC data frame type = 0x01
		ctx.SecurityEnabled,
		ctx.FramePending,
		ctx.AckRequest,
		panIdCompressed,
		ctx.IEPresent,
		dstMode,
		srcMode,
		frameVersion,
	)

	// Frame Control (2 bytes, little-endian)
	var fcBytes [2]byte
	binary.LittleEndian.PutUint16(fcBytes[:], fc)
	buf = append(buf, fcBytes[:]...)

	// Sequence Number (1 byte)
	buf = append(buf, ctx.SequenceNumber)

	// Destination PAN ID (2 bytes, little-endian)
	var panBytes [2]byte
	binary.LittleEndian.PutUint16(panBytes[:], ctx.PanId)
	buf = append(buf, panBytes[:]...)

	// Destination Address (little-endian)
	if dstMode == AddrModeShort {
		var addrBytes [2]byte
		binary.LittleEndian.PutUint16(addrBytes[:], ctx.DstShortAddr)
		buf = append(buf, addrBytes[:]...)
	} else {
		// Extended address: written in reverse byte order on the wire
		// (least significant byte first per 802.15.4).
		var rev [8]byte
		for i := 0; i < 8; i++ {
			rev[i] = ctx.DstExtAddr[7-i]
		}
		buf = append(buf, rev[:]...)
	}

	// Source PAN ID (2 bytes, little-endian) — only if not compressed
	if !panIdCompressed {
		buf = append(buf, panBytes[:]...) // same PAN ID
	}

	// Source Address (little-endian)
	if srcMode == AddrModeShort {
		var addrBytes [2]byte
		binary.LittleEndian.PutUint16(addrBytes[:], ctx.SrcShortAddr)
		buf = append(buf, addrBytes[:]...)
	} else {
		var rev [8]byte
		for i := 0; i < 8; i++ {
			rev[i] = ctx.SrcExtAddr[7-i]
		}
		buf = append(buf, rev[:]...)
	}

	// Auxiliary Security Header
	if ctx.SecurityEnabled {
		// Security Control byte: security level (bits 0-2) | key ID mode (bits 3-4)
		secCtl := uint8(SecurityEncMic32) | (ctx.Security.KeyIdMode << 3)
		buf = append(buf, secCtl)

		// Frame Counter (4 bytes, little-endian)
		var fctrBytes [4]byte
		binary.LittleEndian.PutUint32(fctrBytes[:], ctx.Security.FrameCounter)
		buf = append(buf, fctrBytes[:]...)

		// Key Identifier field
		switch ctx.Security.KeyIdMode {
		case 0:
			// No key identifier
		case 1:
			buf = append(buf, ctx.Security.KeyId)
		case 2:
			// 4-byte key source (zeros) + 1-byte key index
			buf = append(buf, 0, 0, 0, 0, ctx.Security.KeyId)
		case 3:
			// 8-byte key source (zeros) + 1-byte key index
			buf = append(buf, 0, 0, 0, 0, 0, 0, 0, 0, ctx.Security.KeyId)
		}
	}

	// Payload
	buf = append(buf, payload...)

	return buf, nil
}

// BuildMleFrame constructs a MAC data frame carrying an MLE payload.
// The frame structure is the same as a data frame; the MLE security
// wrapping is expected to have been applied to mlePayload before calling.
func (f *Framer) BuildMleFrame(ctx *FrameContext, mlePayload []byte) ([]byte, error) {
	return f.BuildDataFrame(ctx, mlePayload)
}

// ParseFrameHeader parses the MAC header from a raw frame and returns
// the reconstructed FrameContext and the byte offset where the payload
// begins. The frame is expected without FCS.
func (f *Framer) ParseFrameHeader(frame []byte) (*FrameContext, int, error) {
	if len(frame) < 3 {
		return nil, 0, errors.ErrParse
	}

	fc := binary.LittleEndian.Uint16(frame[0:2])
	frameType, dstAddrMode, srcAddrMode, _, secEnabled, framePending, ackReq, panIdComp, iePresent := parseFrameControl(fc)
	_ = frameType

	offset := 2

	// Sequence number
	if offset >= len(frame) {
		return nil, 0, errors.ErrParse
	}
	seqNum := frame[offset]
	offset++

	ctx := &FrameContext{
		SequenceNumber:  seqNum,
		SecurityEnabled: secEnabled,
		FramePending:    framePending,
		AckRequest:      ackReq,
		IEPresent:       iePresent,
	}

	// Destination PAN ID
	if dstAddrMode != AddrModeNone {
		if offset+2 > len(frame) {
			return nil, 0, errors.ErrParse
		}
		ctx.PanId = binary.LittleEndian.Uint16(frame[offset : offset+2])
		offset += 2
	}

	// Destination Address
	switch dstAddrMode {
	case AddrModeShort:
		if offset+2 > len(frame) {
			return nil, 0, errors.ErrParse
		}
		ctx.DstShortAddr = binary.LittleEndian.Uint16(frame[offset : offset+2])
		ctx.UseDstShort = true
		offset += 2
	case AddrModeExtended:
		if offset+8 > len(frame) {
			return nil, 0, errors.ErrParse
		}
		// Reverse byte order (wire is LSB first)
		for i := 0; i < 8; i++ {
			ctx.DstExtAddr[7-i] = frame[offset+i]
		}
		ctx.UseDstShort = false
		offset += 8
	}

	// Source PAN ID
	if !panIdComp && srcAddrMode != AddrModeNone {
		if offset+2 > len(frame) {
			return nil, 0, errors.ErrParse
		}
		// Source PAN ID present but we store only one PanId field;
		// in a real implementation you might track both.
		_ = binary.LittleEndian.Uint16(frame[offset : offset+2])
		offset += 2
	}

	// Source Address
	switch srcAddrMode {
	case AddrModeShort:
		if offset+2 > len(frame) {
			return nil, 0, errors.ErrParse
		}
		ctx.SrcShortAddr = binary.LittleEndian.Uint16(frame[offset : offset+2])
		ctx.UseSrcShort = true
		offset += 2
	case AddrModeExtended:
		if offset+8 > len(frame) {
			return nil, 0, errors.ErrParse
		}
		for i := 0; i < 8; i++ {
			ctx.SrcExtAddr[7-i] = frame[offset+i]
		}
		ctx.UseSrcShort = false
		offset += 8
	}

	// Auxiliary Security Header
	if secEnabled {
		if offset >= len(frame) {
			return nil, 0, errors.ErrParse
		}
		secCtl := frame[offset]
		offset++

		keyIdMode := (secCtl >> 3) & 0x03
		ctx.Security.KeyIdMode = keyIdMode

		// Frame counter
		if offset+4 > len(frame) {
			return nil, 0, errors.ErrParse
		}
		ctx.Security.FrameCounter = binary.LittleEndian.Uint32(frame[offset : offset+4])
		offset += 4

		// Key identifier
		kidSize := keyIdFieldSize(keyIdMode)
		if offset+kidSize > len(frame) {
			return nil, 0, errors.ErrParse
		}
		if kidSize > 0 {
			// Key index is the last byte of the key identifier field
			ctx.Security.KeyId = frame[offset+kidSize-1]
		}
		offset += kidSize
	}

	return ctx, offset, nil
}
