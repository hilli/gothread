// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package coap

import (
	"crypto/rand"
	"math/big"
	"strings"
	"sync"
	"time"

	goterrors "github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Transmission Parameters (RFC 7252 Section 4.8)
// ---------------------------------------------------------------------------

// Default transmission parameter values per RFC 7252 and OpenThread.
const (
	// DefaultAckTimeout is the default initial ACK timeout in milliseconds.
	DefaultAckTimeout uint32 = 2000

	// DefaultAckRandomFactorNumerator is the numerator of the default ACK random factor (1.5 = 3/2).
	DefaultAckRandomFactorNumerator uint8 = 3

	// DefaultAckRandomFactorDenominator is the denominator of the default ACK random factor.
	DefaultAckRandomFactorDenominator uint8 = 2

	// DefaultMaxRetransmit is the default maximum number of retransmissions.
	DefaultMaxRetransmit uint8 = 4

	// DefaultMaxLatency is the default maximum expected round-trip latency in milliseconds.
	DefaultMaxLatency uint32 = 100_000

	// MaxRetransmitLimit is the maximum allowed MaxRetransmit value.
	MaxRetransmitLimit uint8 = 30

	// MinAckTimeout is the minimum allowed ACK timeout in milliseconds.
	MinAckTimeout uint32 = 1000
)

// TxParameters holds CoAP transmission parameters for retransmission logic.
type TxParameters struct {
	// AckTimeout is the initial ACK timeout in milliseconds.
	AckTimeout uint32
	// AckRandomFactorNumerator is the numerator of the random factor.
	AckRandomFactorNumerator uint8
	// AckRandomFactorDenominator is the denominator of the random factor.
	AckRandomFactorDenominator uint8
	// MaxRetransmit is the maximum number of retransmissions for a CON message.
	MaxRetransmit uint8
}

// DefaultTxParameters returns the default RFC 7252 transmission parameters.
func DefaultTxParameters() TxParameters {
	return TxParameters{
		AckTimeout:                 DefaultAckTimeout,
		AckRandomFactorNumerator:   DefaultAckRandomFactorNumerator,
		AckRandomFactorDenominator: DefaultAckRandomFactorDenominator,
		MaxRetransmit:              DefaultMaxRetransmit,
	}
}

// Validate checks that the transmission parameters are well-formed.
// If isConfirmable is false (NON), retransmission parameters are not checked.
func (p TxParameters) Validate(isConfirmable bool) error {
	if p.AckRandomFactorDenominator == 0 {
		return goterrors.ErrInvalidArgs
	}
	if p.AckRandomFactorNumerator < p.AckRandomFactorDenominator {
		return goterrors.ErrInvalidArgs
	}
	if isConfirmable {
		if p.AckTimeout < MinAckTimeout {
			return goterrors.ErrInvalidArgs
		}
		if p.MaxRetransmit > MaxRetransmitLimit {
			return goterrors.ErrInvalidArgs
		}
	}
	return nil
}

// CalculateInitialRetxTimeout returns a random initial retransmission timeout
// in [AckTimeout, AckTimeout * numerator/denominator].
func (p TxParameters) CalculateInitialRetxTimeout() time.Duration {
	base := time.Duration(p.AckTimeout) * time.Millisecond
	upper := time.Duration(uint64(p.AckTimeout)*uint64(p.AckRandomFactorNumerator)/uint64(p.AckRandomFactorDenominator)+1) * time.Millisecond

	spread := int64(upper - base)
	if spread <= 0 {
		return base
	}

	n, err := rand.Int(rand.Reader, big.NewInt(spread))
	if err != nil {
		// Fallback to base on crypto/rand failure (should not happen).
		return base
	}
	return base + time.Duration(n.Int64())
}

// calculateSpan returns ACK_TIMEOUT * ((2^maxRetx) - 1) * ACK_RANDOM_FACTOR.
func (p TxParameters) calculateSpan(maxRetx uint8) time.Duration {
	// 2^maxRetx - 1
	factor := (uint64(1) << maxRetx) - 1
	// Scale AckTimeout by factor and the random-factor ratio (numerator / denominator).
	spanMs := uint64(p.AckTimeout) * factor * uint64(p.AckRandomFactorNumerator) / uint64(p.AckRandomFactorDenominator)
	return time.Duration(spanMs) * time.Millisecond
}

// CalculateExchangeLifetime returns the time from first CON transmission to
// the time when the sender gives up on receiving an ACK:
// MAX_TRANSMIT_SPAN + 2*MAX_LATENCY + PROCESSING_DELAY
// where PROCESSING_DELAY = ACK_TIMEOUT.
func (p TxParameters) CalculateExchangeLifetime() time.Duration {
	span := p.calculateSpan(p.MaxRetransmit)
	maxLatency := time.Duration(DefaultMaxLatency) * time.Millisecond
	processingDelay := time.Duration(p.AckTimeout) * time.Millisecond
	return span + 2*maxLatency + processingDelay
}

// CalculateMaxTransmitWait returns the maximum time from first CON transmission
// to its last retransmission: MAX_TRANSMIT_SPAN + ACK_TIMEOUT * ACK_RANDOM_FACTOR.
func (p TxParameters) CalculateMaxTransmitWait() time.Duration {
	span := p.calculateSpan(p.MaxRetransmit)
	lastRetx := time.Duration(uint64(p.AckTimeout)*uint64(p.AckRandomFactorNumerator)/uint64(p.AckRandomFactorDenominator)+1) * time.Millisecond
	return span + lastRetx
}

// ---------------------------------------------------------------------------
// MessageInfo — peer addressing context
// ---------------------------------------------------------------------------

// MessageInfo holds addressing information for a CoAP message exchange.
type MessageInfo struct {
	// PeerAddr is the IPv6 address of the remote peer.
	PeerAddr [16]byte
	// PeerPort is the UDP port of the remote peer.
	PeerPort uint16
	// LocalAddr is the local IPv6 address.
	LocalAddr [16]byte
	// MulticastLoop indicates whether multicast messages should be looped back.
	MulticastLoop bool
}

// HasSamePeerAddrAndPort reports whether m and other have identical peer
// address and port.
func (m MessageInfo) HasSamePeerAddrAndPort(other MessageInfo) bool {
	return m.PeerAddr == other.PeerAddr && m.PeerPort == other.PeerPort
}

// ---------------------------------------------------------------------------
// Handler types and Resource
// ---------------------------------------------------------------------------

// ResponseHandler is called when a response to a sent request is received,
// or when the request times out or is aborted. On timeout, msg is nil and
// err is ErrResponseTimeout. On reset, msg is nil and err is ErrAbort.
type ResponseHandler func(msg *Message, info MessageInfo, err error)

// RequestHandler is called when an incoming request is received for a
// registered resource or as the default handler.
type RequestHandler func(msg *Message, info MessageInfo)

// Resource represents a CoAP server resource identified by a URI path.
type Resource struct {
	// URIPath is the resource path (e.g. "ot/cli").
	URIPath string
	// Handler is called when a matching request is received.
	Handler RequestHandler
}

// ---------------------------------------------------------------------------
// Sender — transport abstraction
// ---------------------------------------------------------------------------

// Sender is a function that transmits a CoAP message to the given peer.
// It is provided by the transport layer (typically UDP).
type Sender func(data []byte, info MessageInfo) error

// ---------------------------------------------------------------------------
// Internal: pending request metadata
// ---------------------------------------------------------------------------

type pendingRequest struct {
	message      *Message
	info         MessageInfo
	handler      ResponseHandler
	timerFire    time.Time
	retxTimeout  time.Duration
	retxRemain   uint8
	acknowledged bool
	confirmable  bool
	messageID    uint16
	token        []byte
}

func (pr *pendingRequest) shouldRetransmit() bool {
	return pr.confirmable && !pr.acknowledged && pr.retxRemain > 0
}

func (pr *pendingRequest) advanceRetx(now time.Time) {
	pr.retxRemain--
	pr.retxTimeout *= 2
	pr.timerFire = now.Add(pr.retxTimeout)
}

// ---------------------------------------------------------------------------
// Internal: response cache entry
// ---------------------------------------------------------------------------

type cachedResponse struct {
	data       []byte
	info       MessageInfo
	messageID  uint16
	expireTime time.Time
}

// ---------------------------------------------------------------------------
// Engine — CoAP client/server
// ---------------------------------------------------------------------------

// Engine is a CoAP client/server engine that manages retransmissions,
// request/response matching, resource dispatch, and response deduplication.
//
// It is a Go port of OpenThread's CoapBase (src/core/coap/coap.hpp).
type Engine struct {
	sender         Sender
	messageID      uint16
	pending        []*pendingRequest
	resources      []*Resource
	defaultHandler RequestHandler
	cache          []*cachedResponse
	maxCacheSize   int
	retxTimer      *time.Timer
	mu             sync.Mutex
	interceptor    func(*Message, MessageInfo) error

	// nowFunc is used for getting the current time; overridable in tests.
	nowFunc func() time.Time
}

// NewEngine creates a new CoAP engine with the given sender function.
// The engine starts with a random message ID.
func NewEngine(sender Sender) *Engine {
	e := &Engine{
		sender:       sender,
		maxCacheSize: 8,
		nowFunc:      time.Now,
	}
	// Initialize message ID randomly.
	n, err := rand.Int(rand.Reader, big.NewInt(0xFFFF))
	if err != nil {
		e.messageID = 1
	} else {
		e.messageID = uint16(n.Int64())
	}
	return e
}

// nextMessageID returns the next message ID and increments the counter.
func (e *Engine) nextMessageID() uint16 {
	id := e.messageID
	e.messageID++
	return id
}

// ---------------------------------------------------------------------------
// Resource management
// ---------------------------------------------------------------------------

// AddResource registers a resource with the engine. If a resource with the
// same URI path already exists, it is replaced.
func (e *Engine) AddResource(r *Resource) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, existing := range e.resources {
		if existing.URIPath == r.URIPath {
			e.resources[i] = r
			return
		}
	}
	e.resources = append(e.resources, r)
}

// RemoveResource unregisters the resource with the given URI path.
func (e *Engine) RemoveResource(uriPath string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, r := range e.resources {
		if r.URIPath == uriPath {
			e.resources = append(e.resources[:i], e.resources[i+1:]...)
			return
		}
	}
}

// SetDefaultHandler sets the handler invoked for requests that do not match
// any registered resource.
func (e *Engine) SetDefaultHandler(h RequestHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.defaultHandler = h
}

// SetInterceptor sets an optional interceptor called before normal receive
// processing. If the interceptor returns a non-nil error, the message is
// consumed and not processed further.
func (e *Engine) SetInterceptor(fn func(*Message, MessageInfo) error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.interceptor = fn
}

// findResource returns the resource matching the URI path, or nil.
// Must be called with e.mu held.
func (e *Engine) findResource(uriPath string) *Resource {
	for _, r := range e.resources {
		if r.URIPath == uriPath {
			return r
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Send API
// ---------------------------------------------------------------------------

// SendMessage sends a CoAP message. For CON messages, the engine queues the
// message for retransmission and calls handler when a response arrives or
// the request times out. For NON messages with a handler, the engine tracks
// the request but does not retransmit. txParams may be nil for defaults.
func (e *Engine) SendMessage(msg *Message, info MessageInfo, txParams *TxParameters, handler ResponseHandler) error {
	if txParams == nil {
		def := DefaultTxParameters()
		txParams = &def
	}

	typ := msg.GetType()
	isConfirmable := typ == TypeConfirmable

	if err := txParams.Validate(isConfirmable); err != nil {
		return err
	}

	// Assign message ID.
	e.mu.Lock()
	mid := e.nextMessageID()
	e.mu.Unlock()

	// Write the message ID into the message bytes.
	msgBytes := msg.GetBytes()
	if len(msgBytes) < HeaderSize {
		return goterrors.ErrInvalidArgs
	}
	msgBytes[2] = byte(mid >> 8)
	msgBytes[3] = byte(mid)

	if isConfirmable || handler != nil {
		pr := &pendingRequest{
			message:     msg,
			info:        info,
			handler:     handler,
			confirmable: isConfirmable,
			messageID:   mid,
			token:       copyToken(msg.GetToken()),
		}

		if isConfirmable {
			pr.retxRemain = txParams.MaxRetransmit
			pr.retxTimeout = txParams.CalculateInitialRetxTimeout()
			pr.timerFire = e.nowFunc().Add(pr.retxTimeout)
		} else {
			// NON with handler — set expiry based on exchange lifetime.
			pr.timerFire = e.nowFunc().Add(txParams.CalculateExchangeLifetime())
		}

		e.mu.Lock()
		e.pending = append(e.pending, pr)
		e.scheduleRetxTimerLocked()
		e.mu.Unlock()
	}

	return e.sender(msgBytes, info)
}

// SendReset sends a RST message with the given message ID.
func (e *Engine) SendReset(msgID uint16, info MessageInfo) error {
	msg := NewMessage(TypeReset, CodeEmpty, msgID)
	return e.sender(msg.GetBytes(), info)
}

// SendAck sends an empty ACK for the given message ID.
func (e *Engine) SendAck(msgID uint16, info MessageInfo) error {
	msg := NewMessage(TypeAck, CodeEmpty, msgID)
	return e.sender(msg.GetBytes(), info)
}

// SendHeaderResponse sends a response with only a code (no payload/token) as
// an ACK to the given request.
func (e *Engine) SendHeaderResponse(code Code, reqMsg *Message, info MessageInfo) error {
	resp := NewMessage(TypeAck, code, reqMsg.GetMessageID())
	token := reqMsg.GetToken()
	if len(token) > 0 {
		if err := resp.SetToken(token); err != nil {
			return err
		}
	}

	// Cache the response for deduplication.
	e.mu.Lock()
	lifetime := DefaultTxParameters().CalculateExchangeLifetime()
	e.addToCacheLocked(resp.GetBytes(), info, reqMsg.GetMessageID(), lifetime)
	e.mu.Unlock()

	return e.sender(resp.GetBytes(), info)
}

// SendPiggybackedResponse sends a piggybacked ACK response carrying the given
// response code, the request's token, and an optional payload. The message ID
// is taken from reqMsg so it matches the confirmable request being
// acknowledged. Unlike SendMessage, the message ID is NOT reassigned.
//
// This is the standard way to send a response with payload to a CON request.
func (e *Engine) SendPiggybackedResponse(code Code, reqMsg *Message, info MessageInfo, payload []byte) error {
	resp := NewMessage(TypeAck, code, reqMsg.GetMessageID())
	token := reqMsg.GetToken()
	if len(token) > 0 {
		if err := resp.SetToken(token); err != nil {
			return err
		}
	}
	if len(payload) > 0 {
		if err := resp.AppendPayloadMarker(); err != nil {
			return err
		}
		if err := resp.AppendPayload(payload); err != nil {
			return err
		}
	}

	// Cache the response for deduplication.
	e.mu.Lock()
	lifetime := DefaultTxParameters().CalculateExchangeLifetime()
	e.addToCacheLocked(resp.GetBytes(), info, reqMsg.GetMessageID(), lifetime)
	e.mu.Unlock()

	return e.sender(resp.GetBytes(), info)
}

// ---------------------------------------------------------------------------
// Receive path
// ---------------------------------------------------------------------------

// Receive processes an incoming CoAP message. It is called by the transport
// layer when data arrives.
func (e *Engine) Receive(data []byte, info MessageInfo) {
	msg, err := ParseMessage(data)
	if err != nil {
		return
	}

	e.mu.Lock()
	interceptor := e.interceptor
	e.mu.Unlock()

	if interceptor != nil {
		if interceptor(msg, info) != nil {
			return
		}
	}

	code := msg.GetCode()
	if code.IsRequest() {
		e.processReceivedRequest(msg, info)
	} else {
		e.processReceivedResponse(msg, info)
	}
}

// processReceivedRequest dispatches an incoming request to the matching
// resource handler, or sends 4.04 Not Found.
func (e *Engine) processReceivedRequest(msg *Message, info MessageInfo) {
	typ := msg.GetType()
	msgID := msg.GetMessageID()

	// Check response cache for duplicate CON.
	if typ == TypeConfirmable {
		e.mu.Lock()
		cached := e.findCachedResponseLocked(msgID, info)
		e.mu.Unlock()
		if cached != nil {
			// Re-send cached response.
			_ = e.sender(cached.data, info)
			return
		}
	}

	// Extract URI path from options.
	uriPath := getURIPath(msg)

	e.mu.Lock()
	resource := e.findResource(uriPath)
	defaultH := e.defaultHandler
	e.mu.Unlock()

	switch {
	case resource != nil:
		resource.Handler(msg, info)
	case defaultH != nil:
		defaultH(msg, info)
	case typ == TypeConfirmable:
		// No handler found — send 4.04 Not Found.
		_ = e.SendHeaderResponse(CodeNotFound, msg, info)
	}
	// For NON requests with no handler, silently ignore.
}

// processReceivedResponse matches an incoming response to a pending request.
func (e *Engine) processReceivedResponse(msg *Message, info MessageInfo) {
	typ := msg.GetType()
	code := msg.GetCode()
	msgID := msg.GetMessageID()

	e.mu.Lock()
	pr := e.findRelatedRequestLocked(msg, info)
	e.mu.Unlock()

	if pr == nil {
		// No matching request. If it's a CON response, send RST.
		if typ == TypeConfirmable {
			_ = e.SendReset(msgID, info)
		}
		return
	}

	switch typ {
	case TypeReset:
		// Peer rejected our request.
		e.finalizeCoapTransaction(pr, nil, info, goterrors.ErrAbort)

	case TypeAck:
		if code.IsEmpty() {
			// Separate ACK — stop retransmissions, wait for response.
			e.mu.Lock()
			pr.acknowledged = true
			e.mu.Unlock()
		} else {
			// Piggybacked response.
			e.finalizeCoapTransaction(pr, msg, info, nil)
		}

	case TypeConfirmable:
		// CON response — send ACK and deliver.
		_ = e.SendAck(msgID, info)
		e.finalizeCoapTransaction(pr, msg, info, nil)

	case TypeNonConfirmable:
		// NON response.
		e.finalizeCoapTransaction(pr, msg, info, nil)
	}
}

// findRelatedRequestLocked finds a pending request that matches the response.
// For ACK/RST: match by message ID.
// For CON/NON: match by token.
// Must be called with e.mu held.
func (e *Engine) findRelatedRequestLocked(msg *Message, info MessageInfo) *pendingRequest {
	typ := msg.GetType()
	msgID := msg.GetMessageID()
	token := msg.GetToken()

	switch typ {
	case TypeAck, TypeReset:
		for _, pr := range e.pending {
			if pr.messageID == msgID {
				return pr
			}
		}
	case TypeConfirmable, TypeNonConfirmable:
		for _, pr := range e.pending {
			if tokensEqual(pr.token, token) && pr.info.HasSamePeerAddrAndPort(info) {
				return pr
			}
		}
	}
	return nil
}

// finalizeCoapTransaction completes a pending request, calls the handler,
// and removes it from the pending list.
func (e *Engine) finalizeCoapTransaction(pr *pendingRequest, response *Message, info MessageInfo, err error) {
	e.mu.Lock()
	e.removePendingLocked(pr)
	e.scheduleRetxTimerLocked()
	e.mu.Unlock()

	if pr.handler != nil {
		pr.handler(response, info, err)
	}
}

// removePendingLocked removes pr from the pending list.
// Must be called with e.mu held.
func (e *Engine) removePendingLocked(pr *pendingRequest) {
	for i, p := range e.pending {
		if p == pr {
			e.pending = append(e.pending[:i], e.pending[i+1:]...)
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Retransmission timer
// ---------------------------------------------------------------------------

// scheduleRetxTimerLocked schedules or reschedules the retransmission timer
// based on the earliest pending request fire time. Must be called with e.mu held.
func (e *Engine) scheduleRetxTimerLocked() {
	if e.retxTimer != nil {
		e.retxTimer.Stop()
		e.retxTimer = nil
	}

	if len(e.pending) == 0 {
		return
	}

	now := e.nowFunc()
	var earliest time.Time
	found := false
	for _, pr := range e.pending {
		if !found || pr.timerFire.Before(earliest) {
			earliest = pr.timerFire
			found = true
		}
	}

	if !found {
		return
	}

	delay := earliest.Sub(now)
	if delay < 0 {
		delay = 0
	}

	e.retxTimer = time.AfterFunc(delay, func() {
		e.handleRetransmissionTimer()
	})
}

// handleRetransmissionTimer processes all pending requests whose timer has fired.
func (e *Engine) handleRetransmissionTimer() {
	now := e.nowFunc()

	e.mu.Lock()
	var expired []*pendingRequest
	var retransmit []*pendingRequest

	for _, pr := range e.pending {
		if !now.Before(pr.timerFire) {
			switch {
			case pr.shouldRetransmit():
				retransmit = append(retransmit, pr)
			case pr.confirmable && !pr.acknowledged:
				// All retransmissions exhausted.
				expired = append(expired, pr)
			case !pr.confirmable:
				// NON request timed out waiting for response.
				expired = append(expired, pr)
			}
			// If acknowledged but still pending, it's waiting for a
			// separate response — extend the timer.
		}
	}
	e.mu.Unlock()

	// Retransmit.
	for _, pr := range retransmit {
		e.mu.Lock()
		pr.advanceRetx(now)
		e.mu.Unlock()
		_ = e.sender(pr.message.GetBytes(), pr.info)
	}

	// Expire.
	for _, pr := range expired {
		e.finalizeCoapTransaction(pr, nil, pr.info, goterrors.ErrResponseTimeout)
	}

	e.mu.Lock()
	e.scheduleRetxTimerLocked()
	e.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Response cache
// ---------------------------------------------------------------------------

// addToCacheLocked adds a response to the deduplication cache.
// Must be called with e.mu held.
func (e *Engine) addToCacheLocked(data []byte, info MessageInfo, msgID uint16, lifetime time.Duration) {
	// Evict expired entries.
	e.cleanCacheLocked()

	// Evict oldest if at capacity.
	for len(e.cache) >= e.maxCacheSize {
		e.cache = e.cache[1:]
	}

	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	e.cache = append(e.cache, &cachedResponse{
		data:       dataCopy,
		info:       info,
		messageID:  msgID,
		expireTime: e.nowFunc().Add(lifetime),
	})
}

// findCachedResponseLocked returns a cached response matching the message ID
// and peer info, or nil. Must be called with e.mu held.
func (e *Engine) findCachedResponseLocked(msgID uint16, info MessageInfo) *cachedResponse {
	now := e.nowFunc()
	for _, cr := range e.cache {
		if cr.messageID == msgID && cr.info.HasSamePeerAddrAndPort(info) && now.Before(cr.expireTime) {
			return cr
		}
	}
	return nil
}

// cleanCacheLocked removes expired cache entries. Must be called with e.mu held.
func (e *Engine) cleanCacheLocked() {
	now := e.nowFunc()
	n := 0
	for _, cr := range e.cache {
		if now.Before(cr.expireTime) {
			e.cache[n] = cr
			n++
		}
	}
	e.cache = e.cache[:n]
}

// ---------------------------------------------------------------------------
// Transaction management
// ---------------------------------------------------------------------------

// AbortTransaction aborts all pending requests whose handler matches the
// given handler (by pointer identity). Each is finalized with ErrAbort.
func (e *Engine) AbortTransaction(handler ResponseHandler) error {
	e.mu.Lock()
	var toAbort []*pendingRequest
	for _, pr := range e.pending {
		if &pr.handler == &handler {
			toAbort = append(toAbort, pr)
		}
	}
	e.mu.Unlock()

	for _, pr := range toAbort {
		e.finalizeCoapTransaction(pr, nil, pr.info, goterrors.ErrAbort)
	}
	return nil
}

// ClearAllRequestsAndResponses removes all pending requests (calling their
// handlers with ErrAbort) and clears the response cache.
func (e *Engine) ClearAllRequestsAndResponses() {
	e.mu.Lock()
	pending := e.pending
	e.pending = nil
	e.cache = nil
	if e.retxTimer != nil {
		e.retxTimer.Stop()
		e.retxTimer = nil
	}
	e.mu.Unlock()

	for _, pr := range pending {
		if pr.handler != nil {
			pr.handler(nil, pr.info, goterrors.ErrAbort)
		}
	}
}

// Stop stops the engine, aborting all pending transactions.
func (e *Engine) Stop() {
	e.ClearAllRequestsAndResponses()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// getURIPath extracts the URI path from message options by concatenating all
// Uri-Path option values with '/'.
func getURIPath(msg *Message) string {
	var parts []string
	it := msg.GetOptionIterator()
	for {
		num, val, ok := it.Next()
		if !ok {
			break
		}
		if num == OptionURIPath {
			parts = append(parts, string(val))
		}
	}
	return strings.Join(parts, "/")
}

// copyToken returns a copy of the token slice, or nil for empty tokens.
func copyToken(token []byte) []byte {
	if len(token) == 0 {
		return nil
	}
	cp := make([]byte, len(token))
	copy(cp, token)
	return cp
}

// tokensEqual reports whether two token byte slices are equal.
func tokensEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
