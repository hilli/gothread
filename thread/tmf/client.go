// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tmf

import (
	"crypto/rand"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/mle"

	goterrors "github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Address Solicit result callback
// ---------------------------------------------------------------------------

// AddressSolicitResult is passed to the callback when an Address Solicit
// response is received (or the request times out / fails).
type AddressSolicitResult struct {
	// Status is the solicit outcome. AddrSolicitSuccess means the leader
	// allocated a router ID.
	Status AddrSolicitStatus
	// HasRLOC16 is true when the response included a valid RLOC16.
	HasRLOC16 bool
	// RLOC16 is the allocated RLOC16 (valid when HasRLOC16 is true).
	RLOC16 uint16
	// RouterID is the allocated router ID extracted from RLOC16.
	RouterID uint8
	// HasRouterMask is true when the response contained a router mask.
	HasRouterMask bool
	// RouterIDSequence is the leader's current Router ID Sequence number.
	RouterIDSequence uint8
	// RouterIDSet is the leader's current set of allocated Router IDs.
	RouterIDSet mle.RouterIDSet
	// Err is non-nil on timeout, abort, or parse failure.
	Err error
}

// AddressSolicitCallback is invoked when the Address Solicit transaction
// completes (successfully or not).
type AddressSolicitCallback func(result AddressSolicitResult)

// ---------------------------------------------------------------------------
// Address Solicit client
// ---------------------------------------------------------------------------

// tokenLength is the CoAP token size used for TMF requests.
const tokenLength = 4

// SendAddressSolicit sends a CON POST to the leader's Address Solicit URI
// (a/as). The result is delivered asynchronously via the callback.
//
// Parameters:
//   - agent: the TMF agent whose CoAP engine will send the message.
//   - meshLocalPrefix: the mesh-local prefix for constructing RLOC addresses.
//   - senderRLOC16: this device's current RLOC16 (used as source address).
//   - leaderRLOC16: the leader's RLOC16.
//   - extAddr: this device's extended MAC address.
//   - reason: the upgrade reason code.
//   - requestedRLOC16: if non-zero, requests a specific RLOC16 from the leader.
//   - cb: callback invoked when the response arrives or the request fails.
func SendAddressSolicit(
	agent *Agent,
	meshLocalPrefix ip6.NetworkPrefix,
	senderRLOC16 uint16,
	leaderRLOC16 uint16,
	extAddr types.ExtAddress,
	reason mle.RouterUpgradeReason,
	requestedRLOC16 uint16,
	cb AddressSolicitCallback,
) error {
	req := &AddrSolicitRequest{
		ExtAddress: extAddr,
		Status:     reason,
	}
	if requestedRLOC16 != 0 {
		req.HasRLOC16 = true
		req.RLOC16 = requestedRLOC16
	}

	msg, err := buildCONPost(URIAddressSolicit, MarshalAddrSolicitRequest(req))
	if err != nil {
		return err
	}

	coapInfo := tmfCoapInfo(meshLocalPrefix, senderRLOC16, leaderRLOC16)

	return agent.GetEngine().SendMessage(msg, coapInfo, nil, func(respMsg *coap.Message, _ coap.MessageInfo, respErr error) {
		if respErr != nil {
			if cb != nil {
				cb(AddressSolicitResult{Err: respErr})
			}
			return
		}
		result := parseAddrSolicitResult(respMsg)
		if cb != nil {
			cb(result)
		}
	})
}

// parseAddrSolicitResult extracts an AddressSolicitResult from a CoAP
// response message.
func parseAddrSolicitResult(respMsg *coap.Message) AddressSolicitResult {
	payload := respMsg.GetPayload()
	resp, err := ParseAddrSolicitResponse(payload)
	if err != nil {
		return AddressSolicitResult{Err: err}
	}

	result := AddressSolicitResult{
		Status:    resp.Status,
		HasRLOC16: resp.HasRLOC16,
		RLOC16:    resp.RLOC16,
	}
	if resp.HasRLOC16 {
		result.RouterID = mle.RouterIDFromRLOC16(resp.RLOC16)
	}
	if resp.HasRouterMask {
		result.HasRouterMask = true
		result.RouterIDSequence = resp.RouterIDSequence
		result.RouterIDSet = resp.RouterIDSet
	}
	return result
}

// ---------------------------------------------------------------------------
// Address Release client
// ---------------------------------------------------------------------------

// SendAddressRelease sends a CON POST to the leader's Address Release URI
// (a/ar). The response is an empty ACK; this function does not provide a
// result callback because Address Release is fire-and-forget from the
// sender's perspective (the device has already downgraded to Child).
//
// Parameters:
//   - agent: the TMF agent whose CoAP engine will send the message.
//   - meshLocalPrefix: the mesh-local prefix for constructing RLOC addresses.
//   - senderRLOC16: this device's current RLOC16 (used as source address).
//   - leaderRLOC16: the leader's RLOC16.
//   - rloc16: the RLOC16 being released (this device's former router RLOC16).
//   - extAddr: this device's extended MAC address.
func SendAddressRelease(
	agent *Agent,
	meshLocalPrefix ip6.NetworkPrefix,
	senderRLOC16 uint16,
	leaderRLOC16 uint16,
	rloc16 uint16,
	extAddr types.ExtAddress,
) error {
	req := &AddrReleaseRequest{
		RLOC16:     rloc16,
		ExtAddress: extAddr,
	}

	msg, err := buildCONPost(URIAddressRelease, MarshalAddrReleaseRequest(req))
	if err != nil {
		return err
	}

	coapInfo := tmfCoapInfo(meshLocalPrefix, senderRLOC16, leaderRLOC16)

	// No response handler — Address Release is best-effort.
	return agent.GetEngine().SendMessage(msg, coapInfo, nil, nil)
}

// ---------------------------------------------------------------------------
// Server Data Registration result callback
// ---------------------------------------------------------------------------

// ServerDataResult is passed to the callback when a Server Data Registration
// response is received (or the request times out / fails).
type ServerDataResult struct {
	// Accepted is true when the leader responded with 2.04 Changed,
	// indicating the network data was successfully registered.
	Accepted bool
	// Err is non-nil on timeout, abort, or transport failure.
	Err error
}

// ServerDataCallback is invoked when the Server Data Registration transaction
// completes (successfully or not).
type ServerDataCallback func(result ServerDataResult)

// ---------------------------------------------------------------------------
// Server Data Registration client
// ---------------------------------------------------------------------------

// SendServerData sends a CON POST to the leader's Server Data URI (a/sd),
// registering the caller's network data entries. The result is delivered
// asynchronously via the callback.
//
// Parameters:
//   - agent: the TMF agent whose CoAP engine will send the message.
//   - meshLocalPrefix: the mesh-local prefix for constructing RLOC addresses.
//   - senderRLOC16: this device's current RLOC16 (used as source address and
//     included in the request payload).
//   - leaderRLOC16: the leader's RLOC16.
//   - networkData: the raw network data TLVs to register. An empty slice
//     removes all entries for this device.
//   - cb: callback invoked when the response arrives or the request fails.
func SendServerData(
	agent *Agent,
	meshLocalPrefix ip6.NetworkPrefix,
	senderRLOC16 uint16,
	leaderRLOC16 uint16,
	networkData []byte,
	cb ServerDataCallback,
) error {
	req := &ServerDataRequest{
		RLOC16:      senderRLOC16,
		NetworkData: networkData,
	}

	msg, err := buildCONPost(URIServerData, MarshalServerDataRequest(req))
	if err != nil {
		return err
	}

	coapInfo := tmfCoapInfo(meshLocalPrefix, senderRLOC16, leaderRLOC16)

	return agent.GetEngine().SendMessage(msg, coapInfo, nil, func(respMsg *coap.Message, _ coap.MessageInfo, respErr error) {
		if respErr != nil {
			if cb != nil {
				cb(ServerDataResult{Err: respErr})
			}
			return
		}
		result := ServerDataResult{
			Accepted: respMsg.GetCode() == coap.CodeChanged,
		}
		if cb != nil {
			cb(result)
		}
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildCONPost builds a confirmable POST CoAP message for the given TMF URI
// with the provided payload. A random 4-byte token is generated.
func buildCONPost(uri URI, payload []byte) (*coap.Message, error) {
	// Message ID 0 is a placeholder; the engine will assign a real one.
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 0)

	token := make([]byte, tokenLength)
	if _, err := rand.Read(token); err != nil {
		return nil, goterrors.ErrFailed
	}
	if err := msg.SetToken(token); err != nil {
		return nil, err
	}
	if err := msg.AppendURIPathOptions(PathForURI(uri)); err != nil {
		return nil, err
	}
	if len(payload) > 0 {
		if err := msg.AppendPayloadMarker(); err != nil {
			return nil, err
		}
		if err := msg.AppendPayload(payload); err != nil {
			return nil, err
		}
	}
	return msg, nil
}

// tmfCoapInfo builds a coap.MessageInfo addressed to the given leader RLOC16
// using mesh-local addressing. senderRLOC16 is the sender's own RLOC16, used
// to populate LocalAddr so that the TMF interceptor can validate the message.
func tmfCoapInfo(meshLocalPrefix ip6.NetworkPrefix, senderRLOC16, leaderRLOC16 uint16) coap.MessageInfo {
	mi := NewAgentMessageInfo()
	mi.SetSockAddrToRLOC(meshLocalPrefix, senderRLOC16)
	mi.SetPeerAddrToRLOC(meshLocalPrefix, leaderRLOC16)

	return coap.MessageInfo{
		PeerPort:  mi.PeerPort,
		PeerAddr:  [16]byte(mi.PeerAddr),
		LocalAddr: [16]byte(mi.SockAddr),
	}
}
