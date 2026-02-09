// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tmf

import (
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/mle"
)

// ---------------------------------------------------------------------------
// Leader service interfaces
// ---------------------------------------------------------------------------

// LeaderRouterTable is the interface required by LeaderService for managing
// Router ID allocation and release. It extends the basic RouterTableOps
// with lookup and release capabilities needed by the Address Solicit and
// Address Release handlers.
//
// The routing.RouterTable type satisfies this interface via the
// RouterTableAdapter wrapper.
type LeaderRouterTable interface {
	mle.RouterTableOps

	// AllocateWithIDForRouter allocates a router with a specific ID and
	// returns its RLOC16. Unlike RouterTableOps.AllocateWithID this also
	// sets the ExtAddress on the allocated entry.
	AllocateWithIDForRouter(routerID uint8, extAddr types.ExtAddress) (uint16, error)

	// AllocateForRouter allocates a new random router ID and returns the
	// chosen ID and RLOC16. Sets the ExtAddress on the allocated entry.
	AllocateForRouter(extAddr types.ExtAddress) (routerID uint8, rloc16 uint16, err error)

	// FindRLOC16ByExtAddress returns the RLOC16 of the router with the
	// given ExtAddress. Returns 0 and false if not found.
	FindRLOC16ByExtAddress(addr types.ExtAddress) (rloc16 uint16, found bool)

	// Release releases a router ID back to the pool.
	Release(routerID uint8) error

	// ValidateOwnership checks that the given RLOC16 is allocated and owned
	// by the given ExtAddress.
	ValidateOwnership(rloc16 uint16, extAddr types.ExtAddress) bool
}

// ---------------------------------------------------------------------------
// Leader service
// ---------------------------------------------------------------------------

// LeaderService implements the Leader-side TMF handlers for Address Solicit
// (a/as) and Address Release (a/ar). It is registered with a TMF Agent and
// delegates router table operations to a LeaderRouterTable implementation.
//
// This is a Go port of the Address Solicit/Release handling logic in
// OpenThread's src/core/thread/mle_router.cpp.
type LeaderService struct {
	agent                  *Agent
	routerTable            LeaderRouterTable
	routerUpgradeThreshold uint8
}

// NewLeaderService creates a new LeaderService and registers the Address
// Solicit and Address Release handlers on the given TMF agent.
func NewLeaderService(agent *Agent, routerTable LeaderRouterTable, upgradeThreshold uint8) *LeaderService {
	ls := &LeaderService{
		agent:                  agent,
		routerTable:            routerTable,
		routerUpgradeThreshold: upgradeThreshold,
	}

	agent.RegisterHandler(URIAddressSolicit, ls.handleAddressSolicit)
	agent.RegisterHandler(URIAddressRelease, ls.handleAddressRelease)

	return ls
}

// Stop unregisters the TMF handlers.
func (ls *LeaderService) Stop() {
	ls.agent.UnregisterHandler(URIAddressSolicit)
	ls.agent.UnregisterHandler(URIAddressRelease)
}

// SetRouterUpgradeThreshold updates the threshold used to gate
// TooFewRouters upgrade requests.
func (ls *LeaderService) SetRouterUpgradeThreshold(threshold uint8) {
	ls.routerUpgradeThreshold = threshold
}

// ---------------------------------------------------------------------------
// Address Solicit handler
// ---------------------------------------------------------------------------

func (ls *LeaderService) handleAddressSolicit(_ URI, msg *coap.Message, info ip6.MessageInfo) {
	// Only handle Confirmable POST.
	if msg.GetType() != coap.TypeConfirmable || msg.GetCode() != coap.CodePost {
		return
	}

	payload := msg.GetPayload()
	req, err := ParseAddrSolicitRequest(payload)
	if err != nil {
		return
	}

	resp := ls.processAddressSolicit(req)
	ls.sendAddrSolicitResponse(msg, info, resp)
}

// processAddressSolicit implements the Leader's decision logic for Address
// Solicit. It mirrors OpenThread's Mle::ProcessAddressSolicit().
func (ls *LeaderService) processAddressSolicit(req *AddrSolicitRequest) *AddrSolicitResponse {
	resp := &AddrSolicitResponse{
		Status: AddrSolicitNoAddressAvailable,
	}

	// CHECK 1: Is this device already a router (re-registration)?
	if rloc16, found := ls.routerTable.FindRLOC16ByExtAddress(req.ExtAddress); found {
		resp.Status = AddrSolicitSuccess
		resp.HasRLOC16 = true
		resp.RLOC16 = rloc16
		ls.fillRouterMask(resp)
		return resp
	}

	// CHECK 2: Validate the upgrade reason.
	switch req.Status {
	case mle.UpgradeReasonTooFewRouters:
		// Only allow if active count is below the threshold.
		if ls.routerTable.GetActiveRouterCount() >= int(ls.routerUpgradeThreshold) {
			return resp
		}

	case mle.UpgradeReasonHaveChildIDRequest,
		mle.UpgradeReasonParentPartitionChange:
		// Always allow these reasons.

	case mle.UpgradeReasonBorderRouterRequest:
		// For now, always allow border router requests.
		// A full implementation would check NetworkData for existing BRs.

	default:
		resp.Status = AddrSolicitUnrecognizedReason
		return resp
	}

	// ALLOCATION: Try requested ID first, then random.
	allocated := false

	if req.HasRLOC16 {
		routerID := mle.RouterIDFromRLOC16(req.RLOC16)
		rloc16, allocErr := ls.routerTable.AllocateWithIDForRouter(routerID, req.ExtAddress)
		if allocErr == nil {
			resp.RLOC16 = rloc16
			allocated = true
		}
	}

	if !allocated {
		_, rloc16, allocErr := ls.routerTable.AllocateForRouter(req.ExtAddress)
		if allocErr != nil {
			return resp // NoAddressAvailable
		}
		resp.RLOC16 = rloc16
	}

	resp.Status = AddrSolicitSuccess
	resp.HasRLOC16 = true
	ls.fillRouterMask(resp)
	return resp
}

func (ls *LeaderService) fillRouterMask(resp *AddrSolicitResponse) {
	resp.HasRouterMask = true
	resp.RouterIDSequence = ls.routerTable.GetRouterIDSequence()
	resp.RouterIDSet = ls.routerTable.GetRouterIDSet()
}

func (ls *LeaderService) sendAddrSolicitResponse(
	reqMsg *coap.Message,
	info ip6.MessageInfo,
	resp *AddrSolicitResponse,
) {
	payload := MarshalAddrSolicitResponse(resp)

	coapInfo := coap.MessageInfo{
		PeerPort: info.PeerPort,
	}
	copy(coapInfo.PeerAddr[:], info.PeerAddr[:])
	copy(coapInfo.LocalAddr[:], info.SockAddr[:])

	_ = ls.agent.GetEngine().SendPiggybackedResponse(coap.CodeChanged, reqMsg, coapInfo, payload)
}

// ---------------------------------------------------------------------------
// Address Release handler
// ---------------------------------------------------------------------------

func (ls *LeaderService) handleAddressRelease(_ URI, msg *coap.Message, info ip6.MessageInfo) {
	// Only handle Confirmable POST.
	if msg.GetType() != coap.TypeConfirmable || msg.GetCode() != coap.CodePost {
		return
	}

	payload := msg.GetPayload()
	req, err := ParseAddrReleaseRequest(payload)
	if err != nil {
		return
	}

	// Validate ownership: the RLOC16 must be allocated and the ExtAddress
	// must match the registered owner.
	if !ls.routerTable.ValidateOwnership(req.RLOC16, req.ExtAddress) {
		return
	}

	routerID := mle.RouterIDFromRLOC16(req.RLOC16)
	_ = ls.routerTable.Release(routerID)

	// Send empty ACK.
	_ = ls.agent.GetEngine().SendAck(msg.GetMessageID(), coap.MessageInfo{
		PeerPort: info.PeerPort,
		PeerAddr: info.PeerAddr,
	})
}
