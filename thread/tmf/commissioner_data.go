// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tmf

import (
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Commissioning Data Leader interface
// ---------------------------------------------------------------------------

// CommissioningDataLeader is the interface required by
// CommissionerDataService for storing commissioning data in the Leader's
// network data. In production this is backed by netdata.Leader; in tests a
// stub can be used.
type CommissioningDataLeader interface {
	// SetCommissioningData stores the raw MeshCoP TLV bytes as the
	// CommissioningData TLV in network data. An empty slice removes the
	// existing entry.
	SetCommissioningData(data []byte) error
}

// ---------------------------------------------------------------------------
// Commissioner Data service
// ---------------------------------------------------------------------------

// CommissionerDataService implements the TMF handler for Commissioner Data
// Registration (a/cd). The Commissioner uses this URI to push its dataset
// (steering data, session ID, border agent locator) to the Leader.
//
// This is a Go port of the Commissioner Data handling logic in OpenThread's
// src/core/thread/network_data_leader_ftd.cpp (Leader::HandleCommissioningSet).
type CommissionerDataService struct {
	agent  *Agent
	leader CommissioningDataLeader
}

// NewCommissionerDataService creates a new CommissionerDataService and
// registers the handler on the given TMF agent.
func NewCommissionerDataService(agent *Agent, leader CommissioningDataLeader) *CommissionerDataService {
	s := &CommissionerDataService{
		agent:  agent,
		leader: leader,
	}
	agent.RegisterHandler(URICommissionerData, s.handleCommissionerData)
	return s
}

// Stop unregisters the TMF handler.
func (s *CommissionerDataService) Stop() {
	s.agent.UnregisterHandler(URICommissionerData)
}

// handleCommissionerData processes incoming Commissioner Data Registration
// requests. The payload is raw MeshCoP TLVs that are stored as-is inside a
// CommissioningData network data TLV.
func (s *CommissionerDataService) handleCommissionerData(_ URI, msg *coap.Message, info ip6.MessageInfo) {
	// Only handle Confirmable POST.
	if msg.GetType() != coap.TypeConfirmable || msg.GetCode() != coap.CodePost {
		return
	}

	payload := msg.GetPayload()

	coapInfo := coap.MessageInfo{
		PeerPort: info.PeerPort,
	}
	copy(coapInfo.PeerAddr[:], info.PeerAddr[:])
	copy(coapInfo.LocalAddr[:], info.SockAddr[:])

	if err := s.leader.SetCommissioningData(payload); err != nil {
		_ = s.agent.GetEngine().SendHeaderResponse(coap.CodeInternalError, msg, coapInfo)
		return
	}

	_ = s.agent.GetEngine().SendHeaderResponse(coap.CodeChanged, msg, coapInfo)
}
