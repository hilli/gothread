// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tmf

import (
	"encoding/binary"
	"fmt"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/tlv"
)

// ---------------------------------------------------------------------------
// Thread Network Layer TLV types
// ---------------------------------------------------------------------------

// ThreadTLVType identifies a Thread Network Layer TLV as defined in
// OpenThread's src/core/thread/thread_tlvs.hpp.
type ThreadTLVType = uint8

const (
	// ThreadTLVTargetEID is the TLV type for a target EID (16-byte IPv6 address).
	ThreadTLVTargetEID ThreadTLVType = 0

	// ThreadTLVExtMACAddress is the TLV type for an extended MAC address (8 bytes).
	ThreadTLVExtMACAddress ThreadTLVType = 1

	// ThreadTLVRLOC16 is the TLV type for an RLOC16 (2 bytes, big-endian).
	ThreadTLVRLOC16 ThreadTLVType = 2

	// ThreadTLVMeshLocalEID is the TLV type for a Mesh-Local EID (8-byte IID).
	ThreadTLVMeshLocalEID ThreadTLVType = 3

	// ThreadTLVStatus is the TLV type for a status code (1 byte).
	ThreadTLVStatus ThreadTLVType = 4

	// ThreadTLVTimeSinceLastTransaction is the TLV type for the time since
	// last transaction (4 bytes, big-endian, seconds).
	ThreadTLVTimeSinceLastTransaction ThreadTLVType = 6

	// ThreadTLVRouterMask is the TLV type for the router mask, containing
	// the Router ID sequence (1 byte) followed by the Router ID set (8 bytes).
	ThreadTLVRouterMask ThreadTLVType = 7

	// ThreadTLVNDOption is the TLV type for an ND Option.
	ThreadTLVNDOption ThreadTLVType = 8

	// ThreadTLVNDData is the TLV type for ND Data.
	ThreadTLVNDData ThreadTLVType = 9

	// ThreadTLVNetworkData is the TLV type for Thread Network Data.
	ThreadTLVNetworkData ThreadTLVType = 10

	// ThreadTLVTimeout is the TLV type for a timeout value (4 bytes, big-endian).
	ThreadTLVTimeout ThreadTLVType = 11

	// ThreadTLVNetworkName is the TLV type for a network name (up to 16 bytes).
	ThreadTLVNetworkName ThreadTLVType = 12

	// ThreadTLVIPv6Addresses is the TLV type for IPv6 addresses.
	ThreadTLVIPv6Addresses ThreadTLVType = 14

	// ThreadTLVCommissionerSessionID is the TLV type for the Commissioner
	// Session ID (2 bytes, big-endian).
	ThreadTLVCommissionerSessionID ThreadTLVType = 15
)

// ---------------------------------------------------------------------------
// Address Solicit status codes
// ---------------------------------------------------------------------------

// AddrSolicitStatus represents the status code in an Address Solicit response.
type AddrSolicitStatus uint8

const (
	// AddrSolicitSuccess indicates a Router ID was successfully assigned.
	AddrSolicitSuccess AddrSolicitStatus = 0

	// AddrSolicitNoAddressAvailable indicates no Router ID is available.
	AddrSolicitNoAddressAvailable AddrSolicitStatus = 1

	// AddrSolicitUnrecognizedReason indicates the upgrade reason in the
	// request was not recognized by the Leader.
	AddrSolicitUnrecognizedReason AddrSolicitStatus = 6
)

// String returns a human-readable representation of the Address Solicit status.
func (s AddrSolicitStatus) String() string {
	switch s {
	case AddrSolicitSuccess:
		return "Success"
	case AddrSolicitNoAddressAvailable:
		return "NoAddressAvailable"
	case AddrSolicitUnrecognizedReason:
		return "UnrecognizedReason"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// Address Solicit request / response payload helpers
// ---------------------------------------------------------------------------

// RouterMaskTLVSize is the value length of a Router Mask TLV:
// 1 byte ID sequence + 8 bytes RouterIDSet.
const RouterMaskTLVSize = 1 + 8

// AddrSolicitRequest represents the parsed payload of an Address Solicit
// (a/as) CoAP POST request.
type AddrSolicitRequest struct {
	// ExtAddress is the sender's extended MAC address (always present).
	ExtAddress types.ExtAddress
	// HasRLOC16 indicates whether RLOC16 was present in the request.
	HasRLOC16 bool
	// RLOC16 is the sender's previous RLOC16 (only valid when HasRLOC16 is true).
	RLOC16 uint16
	// Status is the upgrade reason code from the requester.
	Status mle.RouterUpgradeReason
}

// MarshalAddrSolicitRequest serializes an Address Solicit request payload
// into TLV wire format.
func MarshalAddrSolicitRequest(req *AddrSolicitRequest) []byte {
	var buf []byte

	// Extended MAC Address TLV (type 1, 8 bytes).
	buf = append(buf, tlv.TLV{
		Type:  ThreadTLVExtMACAddress,
		Value: req.ExtAddress[:],
	}.Marshal()...)

	// Status TLV (type 4, 1 byte).
	buf = append(buf, tlv.TLV{
		Type:  ThreadTLVStatus,
		Value: []byte{uint8(req.Status)},
	}.Marshal()...)

	// Optional RLOC16 TLV (type 2, 2 bytes).
	if req.HasRLOC16 {
		rloc := [2]byte{}
		binary.BigEndian.PutUint16(rloc[:], req.RLOC16)
		buf = append(buf, tlv.TLV{
			Type:  ThreadTLVRLOC16,
			Value: rloc[:],
		}.Marshal()...)
	}

	return buf
}

// ParseAddrSolicitRequest parses an Address Solicit request payload from
// raw TLV bytes. It requires the Extended MAC Address and Status TLVs.
func ParseAddrSolicitRequest(data []byte) (*AddrSolicitRequest, error) {
	tlvs, err := tlv.ParseAll(data)
	if err != nil {
		return nil, fmt.Errorf("address solicit request: %w", goterrors.ErrParse)
	}

	extAddrTLV := tlv.FindByType(tlvs, ThreadTLVExtMACAddress)
	if extAddrTLV == nil || len(extAddrTLV.Value) != types.ExtAddressSize {
		return nil, fmt.Errorf("missing or invalid ExtMACAddress TLV: %w", goterrors.ErrParse)
	}

	statusTLV := tlv.FindByType(tlvs, ThreadTLVStatus)
	if statusTLV == nil || len(statusTLV.Value) != 1 {
		return nil, fmt.Errorf("missing or invalid Status TLV: %w", goterrors.ErrParse)
	}

	req := &AddrSolicitRequest{
		Status: mle.RouterUpgradeReason(statusTLV.Value[0]),
	}
	copy(req.ExtAddress[:], extAddrTLV.Value)

	rloc16TLV := tlv.FindByType(tlvs, ThreadTLVRLOC16)
	if rloc16TLV != nil && len(rloc16TLV.Value) == 2 {
		req.HasRLOC16 = true
		req.RLOC16 = binary.BigEndian.Uint16(rloc16TLV.Value)
	}

	return req, nil
}

// AddrSolicitResponse represents the parsed payload of an Address Solicit
// (a/as) CoAP response.
type AddrSolicitResponse struct {
	// Status is the result of the Address Solicit operation.
	Status AddrSolicitStatus
	// HasRLOC16 indicates whether RLOC16 was present (only on success).
	HasRLOC16 bool
	// RLOC16 is the assigned RLOC16 (valid only when HasRLOC16 is true).
	RLOC16 uint16
	// HasRouterMask indicates whether Router Mask was present (only on success).
	HasRouterMask bool
	// RouterIDSequence is the current router ID sequence from the Leader.
	RouterIDSequence uint8
	// RouterIDSet is the current set of allocated router IDs.
	RouterIDSet mle.RouterIDSet
}

// MarshalAddrSolicitResponse serializes an Address Solicit response payload
// into TLV wire format.
func MarshalAddrSolicitResponse(resp *AddrSolicitResponse) []byte {
	var buf []byte

	// Status TLV (type 4, 1 byte) — always present.
	buf = append(buf, tlv.TLV{
		Type:  ThreadTLVStatus,
		Value: []byte{uint8(resp.Status)},
	}.Marshal()...)

	// On success, include RLOC16 and Router Mask.
	if resp.Status == AddrSolicitSuccess {
		// RLOC16 TLV (type 2, 2 bytes).
		rloc := [2]byte{}
		binary.BigEndian.PutUint16(rloc[:], resp.RLOC16)
		buf = append(buf, tlv.TLV{
			Type:  ThreadTLVRLOC16,
			Value: rloc[:],
		}.Marshal()...)

		// Router Mask TLV (type 7, 9 bytes = 1 ID seq + 8 router ID set).
		maskValue := make([]byte, RouterMaskTLVSize)
		maskValue[0] = resp.RouterIDSequence
		copy(maskValue[1:], resp.RouterIDSet[:])
		buf = append(buf, tlv.TLV{
			Type:  ThreadTLVRouterMask,
			Value: maskValue,
		}.Marshal()...)
	}

	return buf
}

// ParseAddrSolicitResponse parses an Address Solicit response payload from
// raw TLV bytes. It requires the Status TLV. The RLOC16 and Router Mask
// TLVs are optional (present only on success).
func ParseAddrSolicitResponse(data []byte) (*AddrSolicitResponse, error) {
	tlvs, err := tlv.ParseAll(data)
	if err != nil {
		return nil, fmt.Errorf("address solicit response: %w", goterrors.ErrParse)
	}

	statusTLV := tlv.FindByType(tlvs, ThreadTLVStatus)
	if statusTLV == nil || len(statusTLV.Value) != 1 {
		return nil, fmt.Errorf("missing or invalid Status TLV: %w", goterrors.ErrParse)
	}

	resp := &AddrSolicitResponse{
		Status: AddrSolicitStatus(statusTLV.Value[0]),
	}

	rloc16TLV := tlv.FindByType(tlvs, ThreadTLVRLOC16)
	if rloc16TLV != nil && len(rloc16TLV.Value) == 2 {
		resp.HasRLOC16 = true
		resp.RLOC16 = binary.BigEndian.Uint16(rloc16TLV.Value)
	}

	routerMaskTLV := tlv.FindByType(tlvs, ThreadTLVRouterMask)
	if routerMaskTLV != nil && len(routerMaskTLV.Value) == RouterMaskTLVSize {
		resp.HasRouterMask = true
		resp.RouterIDSequence = routerMaskTLV.Value[0]
		copy(resp.RouterIDSet[:], routerMaskTLV.Value[1:])
	}

	return resp, nil
}

// ---------------------------------------------------------------------------
// Address Release request payload helpers
// ---------------------------------------------------------------------------

// AddrReleaseRequest represents the parsed payload of an Address Release
// (a/ar) CoAP POST request.
type AddrReleaseRequest struct {
	// RLOC16 is the RLOC16 being released.
	RLOC16 uint16
	// ExtAddress is the sender's extended MAC address.
	ExtAddress types.ExtAddress
}

// MarshalAddrReleaseRequest serializes an Address Release request payload
// into TLV wire format.
func MarshalAddrReleaseRequest(req *AddrReleaseRequest) []byte {
	var buf []byte

	// RLOC16 TLV (type 2, 2 bytes).
	rloc := [2]byte{}
	binary.BigEndian.PutUint16(rloc[:], req.RLOC16)
	buf = append(buf, tlv.TLV{
		Type:  ThreadTLVRLOC16,
		Value: rloc[:],
	}.Marshal()...)

	// Extended MAC Address TLV (type 1, 8 bytes).
	buf = append(buf, tlv.TLV{
		Type:  ThreadTLVExtMACAddress,
		Value: req.ExtAddress[:],
	}.Marshal()...)

	return buf
}

// ParseAddrReleaseRequest parses an Address Release request payload from
// raw TLV bytes.
func ParseAddrReleaseRequest(data []byte) (*AddrReleaseRequest, error) {
	tlvs, err := tlv.ParseAll(data)
	if err != nil {
		return nil, fmt.Errorf("address release request: %w", goterrors.ErrParse)
	}

	rloc16TLV := tlv.FindByType(tlvs, ThreadTLVRLOC16)
	if rloc16TLV == nil || len(rloc16TLV.Value) != 2 {
		return nil, fmt.Errorf("missing or invalid RLOC16 TLV: %w", goterrors.ErrParse)
	}

	extAddrTLV := tlv.FindByType(tlvs, ThreadTLVExtMACAddress)
	if extAddrTLV == nil || len(extAddrTLV.Value) != types.ExtAddressSize {
		return nil, fmt.Errorf("missing or invalid ExtMACAddress TLV: %w", goterrors.ErrParse)
	}

	req := &AddrReleaseRequest{
		RLOC16: binary.BigEndian.Uint16(rloc16TLV.Value),
	}
	copy(req.ExtAddress[:], extAddrTLV.Value)

	return req, nil
}

// ---------------------------------------------------------------------------
// Server Data request payload helpers
// ---------------------------------------------------------------------------

// ServerDataRequest represents the parsed payload of a Server Data
// Registration (a/sd) CoAP POST request.
type ServerDataRequest struct {
	// RLOC16 is the registering device's RLOC16.
	RLOC16 uint16
	// NetworkData is the raw Thread Network Data being registered.
	// An empty slice means the device is removing all its entries.
	NetworkData []byte
}

// MarshalServerDataRequest serializes a Server Data Registration request
// payload into TLV wire format.
func MarshalServerDataRequest(req *ServerDataRequest) []byte {
	var buf []byte

	// RLOC16 TLV (type 2, 2 bytes).
	rloc := [2]byte{}
	binary.BigEndian.PutUint16(rloc[:], req.RLOC16)
	buf = append(buf, tlv.TLV{
		Type:  ThreadTLVRLOC16,
		Value: rloc[:],
	}.Marshal()...)

	// Network Data TLV (type 10, variable length).
	// Always present, even when empty (to distinguish from a malformed request).
	buf = append(buf, tlv.TLV{
		Type:  ThreadTLVNetworkData,
		Value: req.NetworkData,
	}.Marshal()...)

	return buf
}

// ParseServerDataRequest parses a Server Data Registration request payload
// from raw TLV bytes. The RLOC16 TLV is required; the Network Data TLV is
// optional (absence means empty network data, i.e. remove all entries).
func ParseServerDataRequest(data []byte) (*ServerDataRequest, error) {
	tlvs, err := tlv.ParseAll(data)
	if err != nil {
		return nil, fmt.Errorf("server data request: %w", goterrors.ErrParse)
	}

	rloc16TLV := tlv.FindByType(tlvs, ThreadTLVRLOC16)
	if rloc16TLV == nil || len(rloc16TLV.Value) != 2 {
		return nil, fmt.Errorf("missing or invalid RLOC16 TLV: %w", goterrors.ErrParse)
	}

	req := &ServerDataRequest{
		RLOC16: binary.BigEndian.Uint16(rloc16TLV.Value),
	}

	ndTLV := tlv.FindByType(tlvs, ThreadTLVNetworkData)
	if ndTLV != nil {
		req.NetworkData = ndTLV.Value
	}

	return req, nil
}
