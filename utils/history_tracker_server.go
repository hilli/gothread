// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"sync"
)

// ---------------------------------------------------------------------------
// History Provider interface
// ---------------------------------------------------------------------------

// HistoryNetworkInfoEntry holds a single network info entry from the local
// history tracker, along with its age in milliseconds.
type HistoryNetworkInfoEntry struct {
	Info     NetworkInfoTlv
	EntryAge uint32
}

// HistoryProvider abstracts access to the local history tracker's entries.
// It allows the server to iterate over stored history entries without a
// direct dependency on the Tracker struct.
type HistoryProvider interface {
	// IterateNetworkInfo returns all network info entries in
	// newest-first order. Each entry includes the info and its age
	// in milliseconds relative to "now".
	IterateNetworkInfo() []HistoryNetworkInfoEntry
}

// ---------------------------------------------------------------------------
// Server transport interface
// ---------------------------------------------------------------------------

// HTServerTransport abstracts the TMF transport operations needed by the
// history tracker server.
type HTServerTransport interface {
	// RegisterQueryHandler registers a handler that will be called
	// when a POST is received on the history query URI ("h/qy").
	// The handler receives the raw payload and the sender's RLOC16.
	// For CON requests, the transport sends an empty ACK before
	// calling the handler.
	RegisterQueryHandler(handler func(payload []byte, senderRloc16 uint16))

	// UnregisterQueryHandler removes the previously registered query
	// handler.
	UnregisterQueryHandler()

	// SendConPost sends a CON POST message to the given RLOC16 with the
	// specified URI path and payload. The responseHandler is called when
	// the peer responds (or on timeout). The response error is nil on
	// success (ACK with CodeChanged). The responseHandler receives the
	// peer's RLOC16 in case it is needed.
	SendConPost(peerRloc16 uint16, uriPath string, payload []byte,
		responseHandler func(err error, peerRloc16 uint16)) error
}

// ---------------------------------------------------------------------------
// HTServer — History Tracker Server
// ---------------------------------------------------------------------------

// answerMessageLengthThreshold is the maximum payload size before splitting
// into a new answer message. Matches the C++ kAnswerMessageLengthThreshold.
const answerMessageLengthThreshold = 800

// HTServer responds to incoming history tracker queries by iterating the
// local history and sending one or more answer messages.
//
// This is a Go port of OpenThread's HistoryTracker::Server
// (src/core/utils/history_tracker_server.hpp/.cpp).
type HTServer struct {
	transport HTServerTransport
	provider  HistoryProvider
	mu        sync.Mutex
}

// NewHTServer creates a new history tracker server.
func NewHTServer(transport HTServerTransport, provider HistoryProvider) *HTServer {
	s := &HTServer{
		transport: transport,
		provider:  provider,
	}
	transport.RegisterQueryHandler(s.handleQuery)
	return s
}

// Close shuts down the server.
func (s *HTServer) Close() {
	s.transport.UnregisterQueryHandler()
}

// ---------------------------------------------------------------------------
// Internal: answer building
// ---------------------------------------------------------------------------

// answerMsg holds a prepared answer payload and metadata.
type answerMsg struct {
	payload []byte
}

// answerInfo tracks state while building answers.
type answerInfo struct {
	queryID    uint16
	hasQueryID bool
	answers    []*answerMsg
}

// handleQuery is called by the transport when a POST arrives on "h/qy".
func (s *HTServer) handleQuery(payload []byte, senderRloc16 uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()

	info := &answerInfo{}

	// Parse QueryID TLV if present.
	offset := 0
	var requests []*RequestTlv

	for offset < len(payload) {
		tlvType, value, consumed, err := ParseHTTlv(payload[offset:])
		if err != nil {
			return // Malformed query — silently ignore.
		}
		offset += consumed

		switch tlvType {
		case HTTlvQueryID:
			qid, err := ParseQueryIDTlv(value)
			if err != nil {
				return
			}
			info.hasQueryID = true
			info.queryID = qid

		case HTTlvRequest:
			req, err := ParseRequestTlv(value)
			if err != nil {
				return
			}
			requests = append(requests, req)
		}
	}

	// Start building the first answer.
	currentAnswer := s.allocateAnswer(info)

	// Process each request TLV.
	for _, req := range requests {
		switch req.TlvType {
		case HTTlvNetworkInfo:
			currentAnswer = s.appendNetworkInfo(currentAnswer, info, req)
			if currentAnswer == nil {
				return // allocation failure
			}
		}

		// Check answer length and split if needed.
		currentAnswer = s.checkAnswerLength(currentAnswer, info)
		if currentAnswer == nil {
			return // allocation failure
		}
	}

	// Append final AnswerTlv (isLast=true) to the current answer.
	answerTlvBytes := MarshalAnswerTlv(&AnswerTlv{
		Index:  uint16(len(info.answers)),
		IsLast: true,
	})
	currentAnswer.payload = append(currentAnswer.payload, answerTlvBytes...)
	info.answers = append(info.answers, currentAnswer)

	// Send all answers.
	if len(info.answers) > 0 {
		s.sendAnswerChain(info.answers, 0, senderRloc16)
	}
}

// allocateAnswer creates a new answer payload buffer with the QueryID TLV
// prepended if needed.
func (s *HTServer) allocateAnswer(info *answerInfo) *answerMsg {
	a := &answerMsg{}
	if info.hasQueryID {
		a.payload = append(a.payload, MarshalQueryIDTlv(info.queryID)...)
	}
	return a
}

// checkAnswerLength checks whether the current answer exceeds the length
// threshold. If so, it finalizes it with an AnswerTlv (isLast=false),
// appends it to info.answers, and allocates a new answer.
func (s *HTServer) checkAnswerLength(current *answerMsg, info *answerInfo) *answerMsg {
	if len(current.payload) < answerMessageLengthThreshold {
		return current
	}

	// Finalize with AnswerTlv (not last).
	answerTlvBytes := MarshalAnswerTlv(&AnswerTlv{
		Index:  uint16(len(info.answers)),
		IsLast: false,
	})
	current.payload = append(current.payload, answerTlvBytes...)
	info.answers = append(info.answers, current)

	// Allocate new answer.
	return s.allocateAnswer(info)
}

// appendNetworkInfo appends NetworkInfoTlv entries from the history provider
// to the current answer, splitting as needed.
func (s *HTServer) appendNetworkInfo(current *answerMsg, info *answerInfo, req *RequestTlv) *answerMsg {
	entries := s.provider.IterateNetworkInfo()

	maxCount := int(req.NumEntries)
	maxAge := req.MaxEntryAge
	count := 0

	for _, entry := range entries {
		if maxCount > 0 && count >= maxCount {
			break
		}
		if maxAge > 0 && entry.EntryAge > maxAge {
			break
		}

		tlvBytes := MarshalNetworkInfoTlv(&entry.Info)
		current.payload = append(current.payload, tlvBytes...)
		count++

		// Check length and split if needed.
		current = s.checkAnswerLength(current, info)
	}

	// Append empty NetworkInfoTlv as terminator.
	current.payload = append(current.payload, MarshalEmptyNetworkInfoTlv()...)

	return current
}

// sendAnswerChain sends answers one at a time, chaining each to the next
// via the response callback.
func (s *HTServer) sendAnswerChain(answers []*answerMsg, idx int, peerRloc16 uint16) {
	if idx >= len(answers) {
		return
	}

	answer := answers[idx]

	// The URI path for history answer is "h/an".
	err := s.transport.SendConPost(peerRloc16, "h/an", answer.payload,
		func(respErr error, respPeerRloc16 uint16) {
			if respErr != nil {
				// On error, abandon remaining answers.
				return
			}
			// Send next answer in the chain.
			if idx+1 < len(answers) {
				s.sendAnswerChain(answers, idx+1, respPeerRloc16)
			}
		})

	if err != nil {
		// Transport failed — abandon.
		_ = err
	}
}

// ---------------------------------------------------------------------------
// Convenience: build a combined client+server system
// ---------------------------------------------------------------------------

// HTClientServerPair holds a matched client and server for convenience.
type HTClientServerPair struct {
	Client *HTClient
	Server *HTServer
}

// NewHTClientServer creates a client/server pair. This is a convenience
// for tests and applications that need both endpoints.
func NewHTClientServer(
	clientTransport HTClientTransport,
	serverTransport HTServerTransport,
	provider HistoryProvider,
) *HTClientServerPair {
	return &HTClientServerPair{
		Client: NewHTClient(clientTransport),
		Server: NewHTServer(serverTransport, provider),
	}
}

// Close shuts down both client and server.
func (p *HTClientServerPair) Close() {
	p.Client.Close()
	p.Server.Close()
}
