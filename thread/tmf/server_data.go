// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tmf

import (
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Network Data Leader interface
// ---------------------------------------------------------------------------

// NetworkDataLeader is the interface required by ServerDataService for
// registering incoming network data with the Leader. In production this
// is backed by netdata.Leader; in tests a stub can be used.
type NetworkDataLeader interface {
	// RegisterNetworkData validates and merges the incoming network data
	// for the given RLOC16 into the Leader's authoritative copy. An empty
	// incoming slice removes all entries for that RLOC16.
	RegisterNetworkData(rloc16 uint16, incoming []byte) error
}

// ---------------------------------------------------------------------------
// Server Data service
// ---------------------------------------------------------------------------

// ServerDataService implements the TMF handler for Server Data Registration
// (a/sd). Routers and children use this URI to register their network data
// entries with the Leader.
//
// This is a Go port of the Server Data handling logic in OpenThread's
// src/core/thread/network_data_leader_ftd.cpp (Leader::HandleServerData).
type ServerDataService struct {
	agent  *Agent
	leader NetworkDataLeader
}

// NewServerDataService creates a new ServerDataService and registers the
// Server Data handler on the given TMF agent.
func NewServerDataService(agent *Agent, leader NetworkDataLeader) *ServerDataService {
	s := &ServerDataService{
		agent:  agent,
		leader: leader,
	}
	agent.RegisterHandler(URIServerData, s.handleServerData)
	return s
}

// Stop unregisters the TMF handler.
func (s *ServerDataService) Stop() {
	s.agent.UnregisterHandler(URIServerData)
}

// handleServerData processes incoming Server Data Registration requests.
func (s *ServerDataService) handleServerData(_ URI, msg *coap.Message, info ip6.MessageInfo) {
	// Only handle Confirmable POST.
	if msg.GetType() != coap.TypeConfirmable || msg.GetCode() != coap.CodePost {
		return
	}

	payload := msg.GetPayload()
	req, err := ParseServerDataRequest(payload)
	if err != nil {
		return
	}

	if regErr := s.leader.RegisterNetworkData(req.RLOC16, req.NetworkData); regErr != nil {
		// Registration failed — send a 5.00 Internal Server Error so the
		// client's response handler is finalized (a bare ACK only stops
		// retransmission without delivering a response code).
		errInfo := coap.MessageInfo{
			PeerPort: info.PeerPort,
		}
		copy(errInfo.PeerAddr[:], info.PeerAddr[:])
		copy(errInfo.LocalAddr[:], info.SockAddr[:])
		_ = s.agent.GetEngine().SendHeaderResponse(coap.CodeInternalError, msg, errInfo)
		return
	}

	// Success — send a piggybacked 2.04 Changed response (no payload).
	coapInfo := coap.MessageInfo{
		PeerPort: info.PeerPort,
	}
	copy(coapInfo.PeerAddr[:], info.PeerAddr[:])
	copy(coapInfo.LocalAddr[:], info.SockAddr[:])

	_ = s.agent.GetEngine().SendHeaderResponse(coap.CodeChanged, msg, coapInfo)
}
