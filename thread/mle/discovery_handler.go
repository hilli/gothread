// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file implements the MLE Discovery Request/Response handlers.
//
// Thread Discovery uses unsecured MLE messages (SecuritySuiteNone) to allow
// devices to find networks before joining. A scanning device sends a
// Discovery Request on each channel; routers and leader devices respond
// with Discovery Response messages containing the network name, extended
// PAN ID, and other information.
//
// Discovery messages carry an MLE Discovery TLV (type 26) that wraps
// MeshCoP sub-TLVs: DiscoveryRequest (128) or DiscoveryResponse (129),
// ExtendedPanID (2), NetworkName (3), and optionally SteeringData (8).
//
// This is a Go port of OpenThread's HandleDiscoveryRequest (mle.cpp)
// and related Discovery logic.

package mle

import (
	"fmt"

	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/net/ip6"
)

// DiscoveryRequestData holds the parsed fields from a MeshCoP
// DiscoveryRequest sub-TLV (type 128).
type DiscoveryRequestData struct {
	// Version is the Thread protocol version from the requester.
	Version uint16

	// IsJoiner indicates whether the requester is a Joiner device.
	IsJoiner bool
}

// DiscoveryResponseData holds the parsed fields from a MeshCoP
// DiscoveryResponse sub-TLV (type 129).
type DiscoveryResponseData struct {
	// Version is the Thread protocol version of the responder.
	Version uint16

	// IsNativeCommissioner indicates whether native commissioning is enabled.
	IsNativeCommissioner bool
}

// discoveryRequestDataSize is the encoded size of a DiscoveryRequest sub-TLV value.
const discoveryRequestDataSize = 2

// discoveryResponseDataSize is the encoded size of a DiscoveryResponse sub-TLV value.
const discoveryResponseDataSize = 2

// Bit layout for Discovery Request/Response sub-TLV values:
//
//	byte 0: version (bits 7:4) + isJoiner/isNativeCommissioner (bit 3) + reserved (bits 2:0)
//	byte 1: reserved
const (
	discoveryVersionShift = 4
	discoveryVersionMask  = 0xF0
	discoveryFlagBit      = 0x08
)

// encodeDiscoveryRequest encodes a DiscoveryRequestData into a 2-byte value.
func encodeDiscoveryRequest(d DiscoveryRequestData) [discoveryRequestDataSize]byte {
	var val [discoveryRequestDataSize]byte
	val[0] = byte(d.Version&0x0F) << discoveryVersionShift
	if d.IsJoiner {
		val[0] |= discoveryFlagBit
	}
	return val
}

// decodeDiscoveryRequest parses a DiscoveryRequestData from raw bytes.
func decodeDiscoveryRequest(data []byte) (DiscoveryRequestData, error) {
	if len(data) < discoveryRequestDataSize {
		return DiscoveryRequestData{}, fmt.Errorf("mle: DiscoveryRequest sub-TLV too short: %d", len(data))
	}
	return DiscoveryRequestData{
		Version:  uint16((data[0] & discoveryVersionMask) >> discoveryVersionShift),
		IsJoiner: data[0]&discoveryFlagBit != 0,
	}, nil
}

// encodeDiscoveryResponse encodes a DiscoveryResponseData into a 2-byte value.
func encodeDiscoveryResponse(d DiscoveryResponseData) [discoveryResponseDataSize]byte {
	var val [discoveryResponseDataSize]byte
	val[0] = byte(d.Version&0x0F) << discoveryVersionShift
	if d.IsNativeCommissioner {
		val[0] |= discoveryFlagBit
	}
	return val
}

// decodeDiscoveryResponse parses a DiscoveryResponseData from raw bytes.
func decodeDiscoveryResponse(data []byte) (DiscoveryResponseData, error) {
	if len(data) < discoveryResponseDataSize {
		return DiscoveryResponseData{}, fmt.Errorf("mle: DiscoveryResponse sub-TLV too short: %d", len(data))
	}
	return DiscoveryResponseData{
		Version:              uint16((data[0] & discoveryVersionMask) >> discoveryVersionShift),
		IsNativeCommissioner: data[0]&discoveryFlagBit != 0,
	}, nil
}

// NetworkInfoProvider supplies the network identity information needed
// to build a Discovery Response.
type NetworkInfoProvider interface {
	// GetNetworkName returns the Thread network name.
	GetNetworkName() string

	// GetExtendedPanID returns the 8-byte Extended PAN ID.
	GetExtendedPanID() [8]byte

	// GetSteeringData returns the steering data for Joiner filtering.
	// Returns nil if no steering data is available.
	GetSteeringData() []byte

	// IsNativeCommissioner reports whether native commissioning is enabled.
	IsNativeCommissioner() bool
}

// DiscoveryHandler handles incoming MLE Discovery Request messages and
// sends Discovery Response messages.
type DiscoveryHandler struct {
	mle         *Mle
	dispatcher  *Dispatcher
	networkInfo NetworkInfoProvider
}

// NewDiscoveryHandler creates a new DiscoveryHandler and registers the
// CommandDiscoveryRequest handler with the dispatcher.
func NewDiscoveryHandler(
	mle *Mle,
	dispatcher *Dispatcher,
	networkInfo NetworkInfoProvider,
) *DiscoveryHandler {
	h := &DiscoveryHandler{
		mle:         mle,
		dispatcher:  dispatcher,
		networkInfo: networkInfo,
	}

	dispatcher.RegisterHandler(CommandDiscoveryRequest, h.HandleDiscoveryRequest)

	return h
}

// HandleDiscoveryRequest processes a received MLE Discovery Request.
//
// The handler validates that:
//   - The device is attached (Router or Leader).
//   - The message contains a Discovery TLV with a valid DiscoveryRequest sub-TLV.
//   - The requester's Thread version is compatible.
//
// If all checks pass, a Discovery Response is sent back to the requester.
//
// This is a Go port of OpenThread's Mle::HandleDiscoveryRequest.
func (h *DiscoveryHandler) HandleDiscoveryRequest(rxInfo *RxInfo) error {
	// 1. Only Routers and Leaders respond to Discovery Requests.
	if !h.mle.IsRouterOrLeader() {
		return nil
	}

	// 2. Parse the MLE Discovery TLV.
	discoveryVal, ok := FindTLV(rxInfo.TLVs, TLVDiscovery)
	if !ok {
		return fmt.Errorf("mle: discovery request missing Discovery TLV")
	}

	subTLVs, err := ReadDiscoveryTLV(discoveryVal)
	if err != nil {
		return fmt.Errorf("mle: discovery request: %w", err)
	}

	// 3. Parse the MeshCoP sub-TLVs inside the Discovery TLV.
	parsedSubTLVs, err := parseMeshCoPSubTLVs(subTLVs)
	if err != nil {
		return fmt.Errorf("mle: discovery request: parse sub-TLVs: %w", err)
	}

	// 4. Find and decode the DiscoveryRequest sub-TLV (MeshCoP type 128).
	reqValue, ok := findMeshCoPSubTLV(parsedSubTLVs, meshcop.TLVDiscoveryRequest)
	if !ok {
		return fmt.Errorf("mle: discovery request missing DiscoveryRequest sub-TLV")
	}

	reqData, err := decodeDiscoveryRequest(reqValue)
	if err != nil {
		return fmt.Errorf("mle: discovery request: %w", err)
	}

	// 5. Version check: only respond if the requester's version is compatible
	// with our Thread version. We require at least version 4 (Thread 1.3+).
	if reqData.Version < ThreadVersion {
		return nil // silently ignore incompatible versions
	}

	// 6. If the requester is a Joiner, check steering data.
	// A real implementation would check whether the Joiner's EUI-64 passes
	// the Bloom filter in the steering data. For now we always respond.

	// 7. Send Discovery Response.
	return h.SendDiscoveryResponse(rxInfo.SrcIP)
}

// SendDiscoveryResponse builds and sends an MLE Discovery Response to the
// given destination address.
//
// The response is an unsecured MLE message containing a Discovery TLV that
// wraps the following MeshCoP sub-TLVs:
//   - DiscoveryResponse (129): version + native commissioner flag
//   - ExtendedPanID (2): 8-byte Extended PAN ID
//   - NetworkName (3): network name string
//   - SteeringData (8): optional, included if available
func (h *DiscoveryHandler) SendDiscoveryResponse(dst ip6.Address) error {
	msg := NewUnsecuredMessage(CommandDiscoveryResponse)

	// Build the MeshCoP sub-TLVs.
	var subTLVs []byte

	// DiscoveryResponse sub-TLV (type 129).
	respData := encodeDiscoveryResponse(DiscoveryResponseData{
		Version:              ThreadVersion,
		IsNativeCommissioner: h.networkInfo.IsNativeCommissioner(),
	})
	subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVDiscoveryResponse, respData[:])

	// ExtendedPanID sub-TLV (type 2).
	extPanID := h.networkInfo.GetExtendedPanID()
	subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVExtendedPanID, extPanID[:])

	// NetworkName sub-TLV (type 3).
	networkName := h.networkInfo.GetNetworkName()
	subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVNetworkName, []byte(networkName))

	// SteeringData sub-TLV (type 8), optional.
	if steeringData := h.networkInfo.GetSteeringData(); len(steeringData) > 0 {
		subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVSteeringData, steeringData)
	}

	// Wrap the sub-TLVs in the MLE Discovery TLV.
	msg.AppendDiscoveryTLV(subTLVs)

	return h.dispatcher.SendMessage(msg, dst)
}

// SendDiscoveryRequest builds and sends an MLE Discovery Request to the
// link-local all-nodes multicast address (ff02::1).
//
// The request is an unsecured MLE message containing a Discovery TLV that
// wraps a DiscoveryRequest MeshCoP sub-TLV with the version and joiner flag.
func (h *DiscoveryHandler) SendDiscoveryRequest(isJoiner bool) error {
	msg := NewUnsecuredMessage(CommandDiscoveryRequest)

	// Build the MeshCoP sub-TLVs.
	reqData := encodeDiscoveryRequest(DiscoveryRequestData{
		Version:  ThreadVersion,
		IsJoiner: isJoiner,
	})
	var subTLVs []byte
	subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVDiscoveryRequest, reqData[:])

	msg.AppendDiscoveryTLV(subTLVs)

	return h.dispatcher.SendMessage(msg, LinkLocalAllNodesMulticast)
}

// --- MeshCoP sub-TLV helpers ---

// meshCoPSubTLV represents a parsed MeshCoP sub-TLV within a Discovery TLV.
type meshCoPSubTLV struct {
	// Type is the MeshCoP TLV type.
	Type meshcop.TLVType

	// Value is the sub-TLV value bytes.
	Value []byte
}

// parseMeshCoPSubTLVs parses a sequence of MeshCoP sub-TLVs from raw bytes.
func parseMeshCoPSubTLVs(data []byte) ([]meshCoPSubTLV, error) {
	var result []meshCoPSubTLV
	offset := 0
	for offset < len(data) {
		if offset+2 > len(data) {
			return nil, fmt.Errorf("truncated MeshCoP sub-TLV at offset %d", offset)
		}
		t := data[offset]
		l := int(data[offset+1])
		offset += 2
		if offset+l > len(data) {
			return nil, fmt.Errorf("MeshCoP sub-TLV type %d length %d exceeds buffer at offset %d",
				t, l, offset-2)
		}
		result = append(result, meshCoPSubTLV{
			Type:  meshcop.TLVType(t),
			Value: data[offset : offset+l],
		})
		offset += l
	}
	return result, nil
}

// findMeshCoPSubTLV searches for a MeshCoP sub-TLV by type.
func findMeshCoPSubTLV(tlvs []meshCoPSubTLV, typ meshcop.TLVType) ([]byte, bool) {
	for _, t := range tlvs {
		if t.Type == typ {
			return t.Value, true
		}
	}
	return nil, false
}

// appendMeshCoPSubTLV appends a type-length-value triple to a byte slice
// using the MeshCoP TLV format.
func appendMeshCoPSubTLV(buf []byte, typ meshcop.TLVType, value []byte) []byte {
	buf = append(buf, byte(typ), byte(len(value)))
	buf = append(buf, value...)
	return buf
}

// --- Discovery Response parsing (for scanning side) ---

// ParsedDiscoveryResponse holds the information extracted from a received
// MLE Discovery Response message.
type ParsedDiscoveryResponse struct {
	// Version is the Thread protocol version of the responder.
	Version uint16

	// IsNativeCommissioner indicates whether native commissioning is enabled.
	IsNativeCommissioner bool

	// ExtendedPanID is the 8-byte Extended PAN ID of the network.
	ExtendedPanID [8]byte

	// NetworkName is the Thread network name.
	NetworkName string

	// SteeringData is the optional steering data for Joiner filtering.
	SteeringData []byte
}

// ParseDiscoveryResponse extracts network information from the TLVs of a
// received Discovery Response message.
func ParseDiscoveryResponse(tlvs []TLV) (*ParsedDiscoveryResponse, error) {
	// Find the MLE Discovery TLV.
	discoveryVal, ok := FindTLV(tlvs, TLVDiscovery)
	if !ok {
		return nil, fmt.Errorf("mle: discovery response missing Discovery TLV")
	}

	subTLVData, err := ReadDiscoveryTLV(discoveryVal)
	if err != nil {
		return nil, fmt.Errorf("mle: discovery response: %w", err)
	}

	subTLVs, err := parseMeshCoPSubTLVs(subTLVData)
	if err != nil {
		return nil, fmt.Errorf("mle: discovery response: parse sub-TLVs: %w", err)
	}

	result := &ParsedDiscoveryResponse{}

	// DiscoveryResponse sub-TLV (type 129) — required.
	respValue, ok := findMeshCoPSubTLV(subTLVs, meshcop.TLVDiscoveryResponse)
	if !ok {
		return nil, fmt.Errorf("mle: discovery response missing DiscoveryResponse sub-TLV")
	}
	respData, err := decodeDiscoveryResponse(respValue)
	if err != nil {
		return nil, fmt.Errorf("mle: discovery response: %w", err)
	}
	result.Version = respData.Version
	result.IsNativeCommissioner = respData.IsNativeCommissioner

	// ExtendedPanID sub-TLV (type 2) — required.
	extPanIDValue, ok := findMeshCoPSubTLV(subTLVs, meshcop.TLVExtendedPanID)
	if !ok {
		return nil, fmt.Errorf("mle: discovery response missing ExtendedPanID sub-TLV")
	}
	if len(extPanIDValue) < 8 {
		return nil, fmt.Errorf("mle: ExtendedPanID sub-TLV too short: %d", len(extPanIDValue))
	}
	copy(result.ExtendedPanID[:], extPanIDValue[:8])

	// NetworkName sub-TLV (type 3) — required.
	networkNameValue, ok := findMeshCoPSubTLV(subTLVs, meshcop.TLVNetworkName)
	if !ok {
		return nil, fmt.Errorf("mle: discovery response missing NetworkName sub-TLV")
	}
	result.NetworkName = string(networkNameValue)

	// SteeringData sub-TLV (type 8) — optional.
	if steeringValue, ok := findMeshCoPSubTLV(subTLVs, meshcop.TLVSteeringData); ok {
		result.SteeringData = steeringValue
	}

	return result, nil
}
