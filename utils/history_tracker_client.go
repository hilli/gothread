// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"sync"
	"time"

	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Callback types
// ---------------------------------------------------------------------------

// NetInfoCallback is invoked when network info entries are received from a
// remote history tracker query.
//
// The callback is called once per received entry with err == ErrPending and
// a non-nil info. When the last entry has been delivered, the callback is
// invoked with err == nil and info == nil. On error (timeout, parse error,
// etc.) the callback is invoked with the relevant error and info == nil.
type NetInfoCallback func(err error, info *NetworkInfoTlv, entryAge uint32)

// ---------------------------------------------------------------------------
// Transport interfaces
// ---------------------------------------------------------------------------

// HTClientTransport abstracts the TMF transport operations needed by the
// history tracker client. It decouples the client from the concrete TMF
// agent and CoAP engine, allowing easy testing.
type HTClientTransport interface {
	// SendNonPost sends a NON-confirmable POST to the given RLOC16
	// with the specified URI path and payload. It returns an error if
	// the message cannot be sent.
	SendNonPost(peerRloc16 uint16, uriPath string, payload []byte) error

	// RegisterAnswerHandler registers a handler that will be called
	// when a CON POST is received on the history answer URI ("h/an").
	// The handler receives the raw payload and the sender's RLOC16.
	// The implementation must send an empty ACK before calling the
	// handler.
	RegisterAnswerHandler(handler func(payload []byte, senderRloc16 uint16))

	// UnregisterAnswerHandler removes the previously registered answer
	// handler.
	UnregisterAnswerHandler()
}

// ---------------------------------------------------------------------------
// HTClient — History Tracker Client
// ---------------------------------------------------------------------------

// htClientResponseTimeout is the maximum time to wait for an answer.
const htClientResponseTimeout = 5 * time.Second

// HTClient queries a remote device for its history tracker entries via TMF.
//
// This is a Go port of OpenThread's HistoryTracker::Client
// (src/core/utils/history_tracker_client.hpp/.cpp).
type HTClient struct {
	transport HTClientTransport

	mu          sync.Mutex
	active      bool
	tlvType     uint8
	queryRloc16 uint16
	queryID     uint16
	answerIndex uint16
	callback    NetInfoCallback
	timer       *time.Timer
	nextQueryID uint16 // monotonically increasing query ID
}

// NewHTClient creates a new history tracker client using the given transport.
func NewHTClient(transport HTClientTransport) *HTClient {
	c := &HTClient{
		transport: transport,
	}
	transport.RegisterAnswerHandler(c.handleAnswer)
	return c
}

// QueryNetInfo initiates a query for NetworkInfo entries from the device at
// the given RLOC16.
//
// Parameters:
//   - rloc16: the RLOC16 of the device to query.
//   - maxEntries: maximum entries to request (0 = all).
//   - maxEntryAge: maximum age in ms (0 = no limit).
//   - callback: invoked for each received entry and on completion/error.
//
// Errors:
//   - ErrBusy: a query is already in progress.
//   - Any error from the transport layer.
func (c *HTClient) QueryNetInfo(rloc16 uint16, maxEntries uint16, maxEntryAge uint32, callback NetInfoCallback) error {
	c.mu.Lock()
	if c.active {
		c.mu.Unlock()
		return errors.ErrBusy
	}
	c.callback = callback
	c.mu.Unlock()

	return c.sendQuery(HTTlvNetworkInfo, maxEntries, maxEntryAge, rloc16)
}

// CancelQuery cancels any ongoing query.
func (c *HTClient) CancelQuery() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cancelLocked()
}

// IsActive reports whether a query is currently in progress.
func (c *HTClient) IsActive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}

// Close shuts down the client, cancelling any query and unregistering the
// answer handler.
func (c *HTClient) Close() {
	c.CancelQuery()
	c.transport.UnregisterAnswerHandler()
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

func (c *HTClient) sendQuery(tlvType uint8, maxEntries uint16, maxEntryAge uint32, rloc16 uint16) error {
	c.mu.Lock()

	c.nextQueryID++
	queryID := c.nextQueryID

	// Build payload: QueryIDTlv + RequestTlv
	qidBytes := MarshalQueryIDTlv(queryID)
	reqBytes := MarshalRequestTlv(&RequestTlv{
		TlvType:     tlvType,
		NumEntries:  maxEntries,
		MaxEntryAge: maxEntryAge,
	})
	payload := make([]byte, 0, len(qidBytes)+len(reqBytes))
	payload = append(payload, qidBytes...)
	payload = append(payload, reqBytes...)

	c.mu.Unlock()

	// The URI path for history query is "h/qy".
	err := c.transport.SendNonPost(rloc16, "h/qy", payload)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.active = true
	c.tlvType = tlvType
	c.queryRloc16 = rloc16
	c.queryID = queryID
	c.answerIndex = 0

	// Start response timeout timer.
	if c.timer != nil {
		c.timer.Stop()
	}
	c.timer = time.AfterFunc(htClientResponseTimeout, c.handleTimer)
	c.mu.Unlock()

	return nil
}

// handleAnswer is called by the transport when a CON POST is received on
// the history answer URI. The transport has already sent an empty ACK.
func (c *HTClient) handleAnswer(payload []byte, senderRloc16 uint16) {
	c.mu.Lock()

	if !c.active {
		c.mu.Unlock()
		return
	}

	// Validate sender matches query target.
	if senderRloc16 != c.queryRloc16 {
		c.mu.Unlock()
		return
	}

	// First pass: scan the entire payload to extract QueryID and AnswerTlv,
	// and collect the byte ranges of all data TLVs (e.g. NetworkInfoTlv).
	// The AnswerTlv may appear at the end of the payload (after all data
	// TLVs), so we must scan everything before processing data.
	var (
		foundQueryID bool
		queryIDVal   uint16
		foundAnswer  bool
		answerTlv    *AnswerTlv
	)

	// dataTLVRanges records [start, end) byte offsets of data TLVs.
	type tlvRange struct{ start, end int }
	var dataTLVRanges []tlvRange

	offset := 0
	for offset < len(payload) {
		tlvStart := offset
		tlvType, value, consumed, err := ParseHTTlv(payload[offset:])
		if err != nil {
			c.finalizeLocked(errors.ErrParse)
			return
		}
		offset += consumed

		switch tlvType {
		case HTTlvQueryID:
			qid, err := ParseQueryIDTlv(value)
			if err != nil {
				c.finalizeLocked(errors.ErrParse)
				return
			}
			foundQueryID = true
			queryIDVal = qid

		case HTTlvAnswer:
			a, err := ParseAnswerTlv(value)
			if err != nil {
				c.finalizeLocked(errors.ErrParse)
				return
			}
			foundAnswer = true
			answerTlv = a

		default:
			// Data TLV — record its byte range for later processing.
			dataTLVRanges = append(dataTLVRanges, tlvRange{tlvStart, offset})
		}
	}

	// Reassemble data TLV bytes in order for processing.
	var dataBytes []byte
	for _, r := range dataTLVRanges {
		dataBytes = append(dataBytes, payload[r.start:r.end]...)
	}

	// Validate QueryID matches.
	if foundQueryID && queryIDVal != c.queryID {
		c.mu.Unlock()
		return
	}

	// Validate answer index sequence.
	if foundAnswer && answerTlv.Index != c.answerIndex {
		c.finalizeLocked(errors.ErrResponseTimeout)
		return
	}

	c.answerIndex++

	// Reset timer for next answer.
	if c.timer != nil {
		c.timer.Stop()
	}
	c.timer = time.AfterFunc(htClientResponseTimeout, c.handleTimer)

	tlvType := c.tlvType
	cb := c.callback
	c.mu.Unlock()

	// Process data TLVs based on the query type.
	switch tlvType {
	case HTTlvNetworkInfo:
		c.processNetInfoAnswer(dataBytes, cb)
	}
}

// processNetInfoAnswer iterates over the remaining TLVs in the answer
// payload. For each NetworkInfoTlv it invokes the callback with
// ErrPending. An empty NetworkInfoTlv (length=0) terminates the query
// successfully.
func (c *HTClient) processNetInfoAnswer(data []byte, cb NetInfoCallback) {
	offset := 0
	for offset < len(data) {
		tlvType, value, consumed, err := ParseHTTlv(data[offset:])
		if err != nil {
			c.finalize(errors.ErrParse)
			return
		}
		offset += consumed

		if tlvType != HTTlvNetworkInfo {
			// Skip non-NetworkInfo TLVs (e.g. trailing AnswerTlv).
			continue
		}

		// Empty NetworkInfoTlv is the terminator.
		if len(value) == 0 {
			c.finalize(nil)
			return
		}

		info, err := ParseNetworkInfoTlv(value)
		if err != nil {
			c.finalize(errors.ErrParse)
			return
		}

		// Deliver entry to caller.
		if cb != nil {
			cb(errors.ErrPending, info, info.EntryAge)
		}

		// Check if query was cancelled during callback.
		c.mu.Lock()
		if !c.active {
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
	}
}

// finalize completes the query, cancels the timer, and invokes the callback
// with the final error.
func (c *HTClient) finalize(err error) {
	c.mu.Lock()
	c.finalizeLocked(err)
}

// finalizeLocked completes the query under the lock. It unlocks before
// invoking the callback to avoid deadlock.
func (c *HTClient) finalizeLocked(err error) {
	if !c.active {
		c.mu.Unlock()
		return
	}

	c.cancelLocked()
	cb := c.callback
	tlvType := c.tlvType
	c.mu.Unlock()

	if cb != nil {
		switch tlvType {
		case HTTlvNetworkInfo:
			cb(err, nil, 0)
		}
	}
}

// cancelLocked stops the timer and marks the client as inactive.
// Must be called with c.mu held.
func (c *HTClient) cancelLocked() {
	c.active = false
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
}

func (c *HTClient) handleTimer() {
	c.finalize(errors.ErrResponseTimeout)
}
