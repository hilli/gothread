// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// DSO TLV Type (RFC 8490 Section 5.4)
// ---------------------------------------------------------------------------

// DSOTlvType identifies a DSO TLV.
type DSOTlvType uint16

const (
	// DSOTlvReserved is reserved (must not appear on wire).
	DSOTlvReserved DSOTlvType = 0
	// DSOTlvKeepAlive is the KeepAlive TLV type (RFC 8490 Section 7.1).
	DSOTlvKeepAlive DSOTlvType = 1
	// DSOTlvRetryDelay is the Retry Delay TLV type (RFC 8490 Section 7.2).
	DSOTlvRetryDelay DSOTlvType = 2
	// DSOTlvEncryptionPadding is the Encryption Padding TLV type (RFC 8490 Section 7.3).
	DSOTlvEncryptionPadding DSOTlvType = 3
)

// DSOTlvHeaderSize is the size of a DSO TLV header: 2-byte type + 2-byte length.
const DSOTlvHeaderSize = 4

// ---------------------------------------------------------------------------
// DSO TLV wire format
// ---------------------------------------------------------------------------

// DSOTlv represents a DSO TLV header.
type DSOTlv struct {
	Type   DSOTlvType
	Length uint16
}

// MarshalBinary encodes the TLV header to 4 bytes (big-endian).
func (t *DSOTlv) MarshalBinary() [DSOTlvHeaderSize]byte {
	var buf [DSOTlvHeaderSize]byte
	binary.BigEndian.PutUint16(buf[0:2], uint16(t.Type))
	binary.BigEndian.PutUint16(buf[2:4], t.Length)
	return buf
}

// UnmarshalBinary decodes a TLV header from at least 4 bytes.
func (t *DSOTlv) UnmarshalBinary(data []byte) error {
	if len(data) < DSOTlvHeaderSize {
		return errors.ErrParse
	}
	t.Type = DSOTlvType(binary.BigEndian.Uint16(data[0:2]))
	t.Length = binary.BigEndian.Uint16(data[2:4])
	return nil
}

// ---------------------------------------------------------------------------
// KeepAlive TLV data (8 bytes value)
// ---------------------------------------------------------------------------

// KeepAliveTlvDataSize is the wire size of the KeepAlive TLV value.
const KeepAliveTlvDataSize = 8

// KeepAliveTlvData holds the KeepAlive TLV value fields.
type KeepAliveTlvData struct {
	InactivityTimeout uint32 // milliseconds
	KeepAliveInterval uint32 // milliseconds
}

// MarshalBinary encodes the KeepAlive data (8 bytes, big-endian).
func (k *KeepAliveTlvData) MarshalBinary() [KeepAliveTlvDataSize]byte {
	var buf [KeepAliveTlvDataSize]byte
	binary.BigEndian.PutUint32(buf[0:4], k.InactivityTimeout)
	binary.BigEndian.PutUint32(buf[4:8], k.KeepAliveInterval)
	return buf
}

// UnmarshalBinary decodes the KeepAlive data from at least 8 bytes.
func (k *KeepAliveTlvData) UnmarshalBinary(data []byte) error {
	if len(data) < KeepAliveTlvDataSize {
		return errors.ErrParse
	}
	k.InactivityTimeout = binary.BigEndian.Uint32(data[0:4])
	k.KeepAliveInterval = binary.BigEndian.Uint32(data[4:8])
	return nil
}

// ---------------------------------------------------------------------------
// RetryDelay TLV data (4 bytes value)
// ---------------------------------------------------------------------------

// RetryDelayTlvDataSize is the wire size of the RetryDelay TLV value.
const RetryDelayTlvDataSize = 4

// RetryDelayTlvData holds the Retry Delay TLV value fields.
type RetryDelayTlvData struct {
	RetryDelay uint32 // milliseconds
}

// MarshalBinary encodes the RetryDelay data (4 bytes, big-endian).
func (r *RetryDelayTlvData) MarshalBinary() [RetryDelayTlvDataSize]byte {
	var buf [RetryDelayTlvDataSize]byte
	binary.BigEndian.PutUint32(buf[0:4], r.RetryDelay)
	return buf
}

// UnmarshalBinary decodes the RetryDelay data from at least 4 bytes.
func (r *RetryDelayTlvData) UnmarshalBinary(data []byte) error {
	if len(data) < RetryDelayTlvDataSize {
		return errors.ErrParse
	}
	r.RetryDelay = binary.BigEndian.Uint32(data[0:4])
	return nil
}

// ---------------------------------------------------------------------------
// Connection State
// ---------------------------------------------------------------------------

// DSOConnectionState represents the state of a DSO connection.
type DSOConnectionState uint8

const (
	// DSOStateDisconnected is the initial/terminal state.
	DSOStateDisconnected DSOConnectionState = iota
	// DSOStateConnecting means a client-initiated connection is in progress.
	DSOStateConnecting
	// DSOStateConnectedButSessionless means TCP connected, no DSO session yet.
	DSOStateConnectedButSessionless
	// DSOStateEstablishingSession means first DSO request sent (client) or received (server).
	DSOStateEstablishingSession
	// DSOStateSessionEstablished means a DSO session is fully established.
	DSOStateSessionEstablished
)

// ---------------------------------------------------------------------------
// DisconnectMode / DisconnectReason
// ---------------------------------------------------------------------------

// DisconnectMode indicates how a connection is terminated.
type DisconnectMode uint8

const (
	// DisconnectGracefullyClose performs a clean TCP close.
	DisconnectGracefullyClose DisconnectMode = iota
	// DisconnectForciblyAbort resets the connection immediately.
	DisconnectForciblyAbort
)

// DisconnectReason indicates why a connection was terminated.
type DisconnectReason uint8

const (
	DisconnectReasonFailedToConnect         DisconnectReason = iota // TCP connection failed.
	DisconnectReasonResponseTimeout                                 // No response to a request.
	DisconnectReasonPeerDoesNotSupportDso                           // Peer rejected DSO.
	DisconnectReasonPeerClosed                                      // Peer performed graceful close.
	DisconnectReasonPeerAborted                                     // Peer reset connection.
	DisconnectReasonInactivityTimeout                               // Session inactivity timer fired.
	DisconnectReasonKeepAliveTimeout                                // KeepAlive timer fired on server.
	DisconnectReasonServerRetryDelayRequest                         // Server sent RetryDelay.
	DisconnectReasonPeerMisbehavior                                 // Protocol violation.
	DisconnectReasonUnknown                                         // Unknown/unspecified.
)

// ---------------------------------------------------------------------------
// DSO Constants
// ---------------------------------------------------------------------------

const (
	// dsoInfiniteTimeout indicates no timeout (RFC 8490).
	dsoInfiniteTimeout = 0xFFFFFFFF

	// dsoDefaultTimeout is the default inactivity/keepalive timeout in ms.
	dsoDefaultTimeout uint32 = 15000

	// dsoMinKeepAliveInterval is the minimum keep-alive interval in ms.
	dsoMinKeepAliveInterval uint32 = 10000

	// dsoResponseTimeout is the maximum wait for a DSO response in ms.
	dsoResponseTimeout uint32 = 30000

	// dsoConnectingTimeout is the maximum time to wait for TCP connect in ms.
	dsoConnectingTimeout uint32 = 30000

	// dsoMinServerInactivityWaitTime is the minimum server-side inactivity
	// wait time in ms before aborting a session.
	dsoMinServerInactivityWaitTime uint32 = 5000

	// dsoMaxPendingRequests is the max number of outstanding requests tracked.
	dsoMaxPendingRequests = 4

	// paddingBlockSizes are the random block sizes for encryption padding
	// (matching the C++ reference).
	paddingBlockSize0 = 8
	paddingBlockSize1 = 11
	paddingBlockSize2 = 17
	paddingBlockSize3 = 21
)

// ---------------------------------------------------------------------------
// DSOTransport — platform abstraction for the TCP connection
// ---------------------------------------------------------------------------

// DSOTransport abstracts the underlying TCP transport used by a DSO connection.
type DSOTransport interface {
	// Connect initiates a TCP connection to the specified peer.
	Connect(peerAddr ip6.Address, peerPort uint16) error
	// Send transmits raw bytes over the established connection.
	Send(data []byte) error
	// Disconnect tears down the connection.
	Disconnect(mode DisconnectMode) error
}

// ---------------------------------------------------------------------------
// DSOCallbacks — application-level event handlers
// ---------------------------------------------------------------------------

// DSOCallbacks holds the callback functions invoked by a DSOConnection.
type DSOCallbacks struct {
	// OnConnected is called when the TCP connection is established.
	OnConnected func(conn *DSOConnection)
	// OnSessionEstablished is called when the DSO session is fully established.
	OnSessionEstablished func(conn *DSOConnection)
	// OnDisconnected is called when the connection is terminated.
	OnDisconnected func(conn *DSOConnection)
	// OnRequestMessage processes an incoming DSO request. It should return
	// nil if the request was handled, or an error to send an error response.
	OnRequestMessage func(conn *DSOConnection, messageID uint16, data []byte, primaryTlvType DSOTlvType) error
	// OnUnidirectionalMessage processes an incoming unidirectional DSO message.
	OnUnidirectionalMessage func(conn *DSOConnection, data []byte, primaryTlvType DSOTlvType) error
	// OnResponseMessage processes an incoming DSO response.
	OnResponseMessage func(conn *DSOConnection, header Header, data []byte, responseTlvType DSOTlvType, requestTlvType DSOTlvType) error
}

// ---------------------------------------------------------------------------
// pendingRequest — tracks an outstanding request awaiting response
// ---------------------------------------------------------------------------

type pendingRequest struct {
	messageID      uint16
	primaryTlvType DSOTlvType
	expiration     time.Time
}

// ---------------------------------------------------------------------------
// dsoTimeout — tracks inactivity/keepalive timer state
// ---------------------------------------------------------------------------

type dsoTimeout struct {
	interval   uint32 // configured interval in ms (or dsoInfiniteTimeout)
	desired    uint32 // interval requested but not yet confirmed
	expiration time.Time
	isInfinite bool
}

// reset sets the timeout interval and recomputes expiration from now.
func (t *dsoTimeout) reset(intervalMs uint32, now time.Time) {
	t.interval = intervalMs
	t.desired = intervalMs
	t.isInfinite = (intervalMs == dsoInfiniteTimeout)
	if t.isInfinite {
		t.expiration = time.Time{} // zero = never
	} else {
		t.expiration = now.Add(time.Duration(intervalMs) * time.Millisecond)
	}
}

// isExpired returns true if the timeout has elapsed.
func (t *dsoTimeout) isExpired(now time.Time) bool {
	if t.isInfinite || t.expiration.IsZero() {
		return false
	}
	return !now.Before(t.expiration)
}

// ---------------------------------------------------------------------------
// DSOConnection
// ---------------------------------------------------------------------------

// DSOConnection represents a single DSO connection (client or server side).
type DSOConnection struct {
	mu sync.Mutex

	transport DSOTransport
	callbacks DSOCallbacks
	afterFunc AfterFunc

	peerAddr ip6.Address
	peerPort uint16
	isServer bool

	state            DSOConnectionState
	disconnectReason DisconnectReason
	retryDelay       uint32 // ms; from server's RetryDelay TLV

	nextMessageID uint16
	pendingReqs   []pendingRequest

	longLivedOperation bool

	inactivityTimeout dsoTimeout
	keepAliveTimeout  dsoTimeout

	connectExpiration time.Time // deadline for Connecting state

	timer Timer            // periodic timer for HandleTimer
	now   func() time.Time // injectable clock for testing
}

// DSOConnectionConfig holds configuration for creating a DSOConnection.
type DSOConnectionConfig struct {
	Transport DSOTransport
	Callbacks DSOCallbacks
	AfterFunc AfterFunc
	PeerAddr  ip6.Address
	PeerPort  uint16
	IsServer  bool
	Now       func() time.Time // optional; defaults to time.Now
}

// NewDSOConnection creates a new DSO connection in the Disconnected state.
func NewDSOConnection(cfg DSOConnectionConfig) *DSOConnection {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	af := cfg.AfterFunc
	if af == nil {
		af = func(d time.Duration, f func()) Timer {
			return &stdTimer{t: time.AfterFunc(d, f)}
		}
	}
	c := &DSOConnection{
		transport:     cfg.Transport,
		callbacks:     cfg.Callbacks,
		afterFunc:     af,
		peerAddr:      cfg.PeerAddr,
		peerPort:      cfg.PeerPort,
		isServer:      cfg.IsServer,
		state:         DSOStateDisconnected,
		nextMessageID: 1,
		now:           now,
	}
	return c
}

// stdTimer wraps time.Timer to implement Timer.
type stdTimer struct{ t *time.Timer }

func (s *stdTimer) Stop() bool { return s.t.Stop() }

// --- Public getters ---------------------------------------------------------

// GetState returns the current connection state.
func (c *DSOConnection) GetState() DSOConnectionState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// GetDisconnectReason returns why the connection was disconnected.
func (c *DSOConnection) GetDisconnectReason() DisconnectReason {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.disconnectReason
}

// GetRetryDelay returns the retry delay received from the server (ms).
func (c *DSOConnection) GetRetryDelay() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.retryDelay
}

// GetKeepAliveInterval returns the current keep-alive interval (ms).
func (c *DSOConnection) GetKeepAliveInterval() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.keepAliveTimeout.interval
}

// GetInactivityTimeout returns the current inactivity timeout (ms).
func (c *DSOConnection) GetInactivityTimeout() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inactivityTimeout.interval
}

// IsServer returns true if this is a server-side connection.
func (c *DSOConnection) IsServer() bool {
	return c.isServer
}

// GetPeerAddr returns the peer's IPv6 address.
func (c *DSOConnection) GetPeerAddr() ip6.Address {
	return c.peerAddr
}

// GetPeerPort returns the peer's port.
func (c *DSOConnection) GetPeerPort() uint16 {
	return c.peerPort
}

// --- Connection lifecycle ---------------------------------------------------

// Connect initiates a client-side TCP connection. The connection must be
// in the Disconnected state.
func (c *DSOConnection) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != DSOStateDisconnected {
		return errors.ErrInvalidState
	}
	if c.isServer {
		return errors.ErrInvalidState
	}

	c.state = DSOStateConnecting
	now := c.now()
	c.connectExpiration = now.Add(time.Duration(dsoConnectingTimeout) * time.Millisecond)

	// Initialize default timeouts.
	c.inactivityTimeout.reset(dsoDefaultTimeout, now)
	c.keepAliveTimeout.reset(dsoDefaultTimeout, now)

	err := c.transport.Connect(c.peerAddr, c.peerPort)
	if err != nil {
		c.state = DSOStateDisconnected
		c.disconnectReason = DisconnectReasonFailedToConnect
		return err
	}

	c.scheduleTimerLocked()
	return nil
}

// Disconnect terminates the connection with the given mode and reason.
func (c *DSOConnection) Disconnect(mode DisconnectMode, reason DisconnectReason) {
	c.mu.Lock()
	c.disconnectLocked(mode, reason)
	c.mu.Unlock()
}

func (c *DSOConnection) disconnectLocked(mode DisconnectMode, reason DisconnectReason) {
	if c.state == DSOStateDisconnected {
		return
	}

	c.state = DSOStateDisconnected
	c.disconnectReason = reason
	c.pendingReqs = nil

	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}

	// Best-effort transport disconnect.
	_ = c.transport.Disconnect(mode)

	if c.callbacks.OnDisconnected != nil {
		c.callbacks.OnDisconnected(c)
	}
}

// MarkSessionEstablished transitions the connection to SessionEstablished state
// without requiring the normal request-response exchange. Used when the session
// is established implicitly.
func (c *DSOConnection) MarkSessionEstablished() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != DSOStateConnectedButSessionless && c.state != DSOStateEstablishingSession {
		return errors.ErrInvalidState
	}

	c.state = DSOStateSessionEstablished

	if c.callbacks.OnSessionEstablished != nil {
		c.callbacks.OnSessionEstablished(c)
	}
	return nil
}

// SetLongLivedOperation sets or clears the long-lived operation flag.
// When set, the inactivity timeout is suppressed.
func (c *DSOConnection) SetLongLivedOperation(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.longLivedOperation = enabled
}

// --- Transport callbacks (called by platform layer) -------------------------

// HandleConnected is called by the transport when TCP connect succeeds.
func (c *DSOConnection) HandleConnected() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != DSOStateConnecting {
		return
	}

	c.state = DSOStateConnectedButSessionless

	// Reset timeouts with current time.
	now := c.now()
	c.inactivityTimeout.reset(c.inactivityTimeout.interval, now)
	c.keepAliveTimeout.reset(c.keepAliveTimeout.interval, now)

	c.scheduleTimerLocked()

	if c.callbacks.OnConnected != nil {
		c.callbacks.OnConnected(c)
	}
}

// AcceptConnection is called on a server-side connection that was accepted.
// It initializes the connection to the ConnectedButSessionless state.
func (c *DSOConnection) AcceptConnection() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != DSOStateDisconnected {
		return errors.ErrInvalidState
	}
	if !c.isServer {
		return errors.ErrInvalidState
	}

	c.state = DSOStateConnectedButSessionless

	now := c.now()
	c.inactivityTimeout.reset(dsoDefaultTimeout, now)
	c.keepAliveTimeout.reset(dsoDefaultTimeout, now)

	c.scheduleTimerLocked()
	return nil
}

// HandleDisconnected is called by the transport when the peer disconnects.
func (c *DSOConnection) HandleDisconnected(mode DisconnectMode) {
	c.mu.Lock()
	defer c.mu.Unlock()

	reason := DisconnectReasonPeerClosed
	if mode == DisconnectForciblyAbort {
		reason = DisconnectReasonPeerAborted
	}

	c.disconnectLocked(mode, reason)
}

// HandleReceive is called by the transport when a DNS message is received.
func (c *DSOConnection) HandleReceive(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == DSOStateDisconnected || c.state == DSOStateConnecting {
		return
	}

	if len(data) < HeaderSize {
		c.disconnectLocked(DisconnectForciblyAbort, DisconnectReasonPeerMisbehavior)
		return
	}

	var hdr Header
	if err := hdr.UnmarshalBinary(data); err != nil {
		c.disconnectLocked(DisconnectForciblyAbort, DisconnectReasonPeerMisbehavior)
		return
	}

	// Validate: QD/AN/NS/AR must all be zero for DSO messages.
	if hdr.QDCount != 0 || hdr.ANCount != 0 || hdr.NSCount != 0 || hdr.ARCount != 0 {
		// If the peer sends a non-DSO query, send an error response.
		if hdr.GetType() == TypeQuery {
			c.sendErrorResponseLocked(hdr.MessageID, RcodeNotImplemented)
		} else {
			// Response with non-zero counts is misbehavior.
			c.disconnectLocked(DisconnectForciblyAbort, DisconnectReasonPeerMisbehavior)
		}
		return
	}

	// Check opcode — must be DSO.
	if hdr.GetOpCode() != OpcodeDso {
		if hdr.GetType() == TypeQuery {
			c.sendErrorResponseLocked(hdr.MessageID, RcodeNotImplemented)
		} else {
			c.disconnectLocked(DisconnectForciblyAbort, DisconnectReasonPeerMisbehavior)
		}
		return
	}

	tlvData := data[HeaderSize:]

	if hdr.GetType() == TypeResponse {
		c.processResponseLocked(hdr, tlvData)
	} else {
		// Query: request (messageID != 0) or unidirectional (messageID == 0).
		if hdr.MessageID != 0 {
			c.processRequestLocked(hdr, tlvData)
		} else {
			c.processUnidirectionalLocked(hdr, tlvData)
		}
	}
}

// --- Sending messages -------------------------------------------------------

// SendRequestMessage sends a DSO request message. The message should contain
// only the DSO TLV payload (no DNS header). The function prepends the header,
// appends padding, assigns a message ID, and tracks the pending request.
// The assigned message ID is returned.
func (c *DSOConnection) SendRequestMessage(payload []byte, responseTimeoutMs uint32) (uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == DSOStateDisconnected || c.state == DSOStateConnecting {
		return 0, errors.ErrInvalidState
	}

	if len(c.pendingReqs) >= dsoMaxPendingRequests {
		return 0, errors.ErrNoBufs
	}

	msgID := c.nextMessageIDLocked()

	msg := c.buildMessageLocked(TypeQuery, msgID, payload)

	// Read primary TLV type for tracking.
	primaryType := DSOTlvReserved
	if len(payload) >= DSOTlvHeaderSize {
		primaryType = DSOTlvType(binary.BigEndian.Uint16(payload[0:2]))
	}

	now := c.now()
	timeout := responseTimeoutMs
	if timeout == 0 {
		timeout = dsoResponseTimeout
	}

	c.pendingReqs = append(c.pendingReqs, pendingRequest{
		messageID:      msgID,
		primaryTlvType: primaryType,
		expiration:     now.Add(time.Duration(timeout) * time.Millisecond),
	})

	if err := c.transport.Send(msg); err != nil {
		// Remove the pending request we just added.
		c.pendingReqs = c.pendingReqs[:len(c.pendingReqs)-1]
		return 0, err
	}

	// If this is the first request on a client, transition to EstablishingSession.
	if !c.isServer && c.state == DSOStateConnectedButSessionless {
		c.state = DSOStateEstablishingSession
	}

	// Reset inactivity timer (we sent data).
	c.resetInactivityLocked()
	c.scheduleTimerLocked()

	return msgID, nil
}

// SendUnidirectionalMessage sends a unidirectional DSO message (messageID=0).
func (c *DSOConnection) SendUnidirectionalMessage(payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != DSOStateSessionEstablished {
		return errors.ErrInvalidState
	}

	msg := c.buildMessageLocked(TypeQuery, 0, payload)

	if err := c.transport.Send(msg); err != nil {
		return err
	}

	c.resetInactivityLocked()
	return nil
}

// SendResponseMessage sends a DSO response to a request with the given messageID.
func (c *DSOConnection) SendResponseMessage(payload []byte, responseID uint16, rcode ResponseCode) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == DSOStateDisconnected || c.state == DSOStateConnecting {
		return errors.ErrInvalidState
	}

	msg := c.buildResponseMessageLocked(responseID, rcode, payload)

	if err := c.transport.Send(msg); err != nil {
		return err
	}

	c.resetInactivityLocked()
	return nil
}

// SendKeepAliveMessage sends a KeepAlive DSO message. On a client this is a
// request (expecting a response); on a server this is unidirectional.
func (c *DSOConnection) SendKeepAliveMessage() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != DSOStateSessionEstablished {
		return errors.ErrInvalidState
	}

	payload := c.buildKeepAliveTlvPayload()

	if c.isServer {
		// Server sends keepalive as unidirectional.
		msg := c.buildMessageLocked(TypeQuery, 0, payload)
		return c.transport.Send(msg)
	}

	// Client sends keepalive as request.
	if len(c.pendingReqs) >= dsoMaxPendingRequests {
		return errors.ErrNoBufs
	}

	msgID := c.nextMessageIDLocked()
	msg := c.buildMessageLocked(TypeQuery, msgID, payload)

	now := c.now()
	c.pendingReqs = append(c.pendingReqs, pendingRequest{
		messageID:      msgID,
		primaryTlvType: DSOTlvKeepAlive,
		expiration:     now.Add(time.Duration(dsoResponseTimeout) * time.Millisecond),
	})

	if err := c.transport.Send(msg); err != nil {
		c.pendingReqs = c.pendingReqs[:len(c.pendingReqs)-1]
		return err
	}

	// Reset keep-alive timer.
	c.keepAliveTimeout.reset(c.keepAliveTimeout.interval, now)
	c.scheduleTimerLocked()

	return nil
}

// SetTimeouts updates the inactivity timeout and keep-alive interval.
// The keep-alive interval is clamped to a minimum of dsoMinKeepAliveInterval.
func (c *DSOConnection) SetTimeouts(inactivityTimeoutMs, keepAliveIntervalMs uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if keepAliveIntervalMs != dsoInfiniteTimeout && keepAliveIntervalMs < dsoMinKeepAliveInterval {
		keepAliveIntervalMs = dsoMinKeepAliveInterval
	}

	now := c.now()

	// Adjust inactivity: if reducing timeout, account for time already elapsed.
	if c.state == DSOStateSessionEstablished && inactivityTimeoutMs < c.inactivityTimeout.interval {
		c.adjustInactivityTimeoutLocked(inactivityTimeoutMs, now)
	} else {
		c.inactivityTimeout.reset(inactivityTimeoutMs, now)
	}

	c.keepAliveTimeout.reset(keepAliveIntervalMs, now)
	c.scheduleTimerLocked()
}

// SendRetryDelayMessage sends a RetryDelay DSO message (server only) as a
// unidirectional message, then gracefully disconnects.
func (c *DSOConnection) SendRetryDelayMessage(delayMs uint32, rcode ResponseCode) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isServer {
		return errors.ErrInvalidState
	}
	if c.state == DSOStateDisconnected || c.state == DSOStateConnecting {
		return errors.ErrInvalidState
	}

	// Build RetryDelay TLV.
	var tlvHdr DSOTlv
	tlvHdr.Type = DSOTlvRetryDelay
	tlvHdr.Length = RetryDelayTlvDataSize

	hdrBytes := tlvHdr.MarshalBinary()
	var rd RetryDelayTlvData
	rd.RetryDelay = delayMs
	rdBytes := rd.MarshalBinary()

	payload := make([]byte, 0, DSOTlvHeaderSize+RetryDelayTlvDataSize)
	payload = append(payload, hdrBytes[:]...)
	payload = append(payload, rdBytes[:]...)

	// Send as unidirectional message with the given RCODE.
	msg := c.buildResponseMessageLocked(0, rcode, payload)
	_ = c.transport.Send(msg)

	c.disconnectLocked(DisconnectGracefullyClose, DisconnectReasonServerRetryDelayRequest)
	return nil
}

// --- HandleTimer (called periodically) --------------------------------------

// HandleTimer checks all timeouts and takes appropriate action.
// Returns the time at which it should next be called (zero means no timer needed).
func (c *DSOConnection) HandleTimer() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.handleTimerLocked()
}

func (c *DSOConnection) handleTimerLocked() time.Time {
	if c.state == DSOStateDisconnected {
		return time.Time{}
	}

	now := c.now()

	// Check connecting timeout.
	if c.state == DSOStateConnecting {
		if !c.connectExpiration.IsZero() && !now.Before(c.connectExpiration) {
			c.disconnectLocked(DisconnectForciblyAbort, DisconnectReasonFailedToConnect)
			return time.Time{}
		}
		return c.connectExpiration
	}

	// Check pending request response timeouts.
	for i := 0; i < len(c.pendingReqs); i++ {
		if !now.Before(c.pendingReqs[i].expiration) {
			c.disconnectLocked(DisconnectForciblyAbort, DisconnectReasonResponseTimeout)
			return time.Time{}
		}
	}

	if c.state != DSOStateSessionEstablished {
		return c.nextFireTimeLocked()
	}

	// Check inactivity timeout.
	if !c.longLivedOperation && c.inactivityTimeout.isExpired(now) {
		if c.isServer {
			c.disconnectLocked(DisconnectForciblyAbort, DisconnectReasonInactivityTimeout)
		} else {
			c.disconnectLocked(DisconnectGracefullyClose, DisconnectReasonInactivityTimeout)
		}
		return time.Time{}
	}

	// Check keep-alive timeout.
	if c.keepAliveTimeout.isExpired(now) {
		if c.isServer {
			// Server aborts if keep-alive not received.
			c.disconnectLocked(DisconnectForciblyAbort, DisconnectReasonKeepAliveTimeout)
			return time.Time{}
		}
		// Client sends a keep-alive request.
		c.mu.Unlock()
		_ = c.SendKeepAliveMessage()
		c.mu.Lock()
	}

	return c.nextFireTimeLocked()
}

// --- Internal helpers -------------------------------------------------------

// nextMessageIDLocked allocates the next message ID, skipping 0.
func (c *DSOConnection) nextMessageIDLocked() uint16 {
	id := c.nextMessageID
	c.nextMessageID++
	if c.nextMessageID == 0 {
		c.nextMessageID = 1
	}
	return id
}

// buildMessageLocked builds a complete DSO message with DNS header + payload + padding.
func (c *DSOConnection) buildMessageLocked(qr HeaderType, messageID uint16, payload []byte) []byte {
	var hdr Header
	hdr.SetType(qr)
	hdr.SetOpCode(OpcodeDso)
	hdr.MessageID = messageID

	hdrBytes := hdr.MarshalBinary()

	// Append encryption padding.
	padding := c.generatePadding(len(hdrBytes) + len(payload))

	msg := make([]byte, 0, HeaderSize+len(payload)+len(padding))
	msg = append(msg, hdrBytes[:]...)
	msg = append(msg, payload...)
	msg = append(msg, padding...)

	return msg
}

// buildResponseMessageLocked builds a DSO response message with the given RCODE.
func (c *DSOConnection) buildResponseMessageLocked(responseID uint16, rcode ResponseCode, payload []byte) []byte {
	var hdr Header
	hdr.SetType(TypeResponse)
	hdr.SetOpCode(OpcodeDso)
	hdr.MessageID = responseID
	hdr.SetResponseCode(rcode)

	hdrBytes := hdr.MarshalBinary()

	padding := c.generatePadding(HeaderSize + len(payload))

	msg := make([]byte, 0, HeaderSize+len(payload)+len(padding))
	msg = append(msg, hdrBytes[:]...)
	msg = append(msg, payload...)
	msg = append(msg, padding...)

	return msg
}

// buildKeepAliveTlvPayload creates the TLV payload for a KeepAlive message.
func (c *DSOConnection) buildKeepAliveTlvPayload() []byte {
	var tlvHdr DSOTlv
	tlvHdr.Type = DSOTlvKeepAlive
	tlvHdr.Length = KeepAliveTlvDataSize

	hdrBytes := tlvHdr.MarshalBinary()

	var ka KeepAliveTlvData
	ka.InactivityTimeout = c.inactivityTimeout.interval
	ka.KeepAliveInterval = c.keepAliveTimeout.interval
	kaBytes := ka.MarshalBinary()

	payload := make([]byte, 0, DSOTlvHeaderSize+KeepAliveTlvDataSize)
	payload = append(payload, hdrBytes[:]...)
	payload = append(payload, kaBytes[:]...)
	return payload
}

// generatePadding creates an EncryptionPadding TLV of a random block size.
func (c *DSOConnection) generatePadding(currentLen int) []byte {
	blockSizes := [4]int{paddingBlockSize0, paddingBlockSize1, paddingBlockSize2, paddingBlockSize3}

	// Pick a random block size index.
	var randByte [1]byte
	_, _ = rand.Read(randByte[:])
	blockSize := blockSizes[int(randByte[0])%len(blockSizes)]

	// Calculate padding needed to reach next block boundary.
	totalWithTlvHdr := currentLen + DSOTlvHeaderSize
	remainder := totalWithTlvHdr % blockSize
	padLen := 0
	if remainder != 0 {
		padLen = blockSize - remainder
	}

	// Build the EncryptionPadding TLV.
	var tlvHdr DSOTlv
	tlvHdr.Type = DSOTlvEncryptionPadding
	tlvHdr.Length = uint16(padLen)
	hdrBytes := tlvHdr.MarshalBinary()

	result := make([]byte, DSOTlvHeaderSize+padLen)
	copy(result, hdrBytes[:])
	// Padding value is all zeros (already zeroed by make).
	return result
}

// resetInactivityLocked resets the inactivity timeout from the current time.
func (c *DSOConnection) resetInactivityLocked() {
	c.inactivityTimeout.reset(c.inactivityTimeout.interval, c.now())
}

// adjustInactivityTimeoutLocked handles a reduction in inactivity timeout,
// accounting for elapsed time since the last reset.
func (c *DSOConnection) adjustInactivityTimeoutLocked(newIntervalMs uint32, now time.Time) {
	if c.inactivityTimeout.isInfinite {
		c.inactivityTimeout.reset(newIntervalMs, now)
		return
	}

	// How much time was remaining on the old timeout?
	oldRemaining := time.Duration(0)
	if !c.inactivityTimeout.expiration.IsZero() && c.inactivityTimeout.expiration.After(now) {
		oldRemaining = c.inactivityTimeout.expiration.Sub(now)
	}

	// How much time has elapsed since the timeout was last set?
	oldInterval := time.Duration(c.inactivityTimeout.interval) * time.Millisecond
	elapsed := oldInterval - oldRemaining

	newInterval := time.Duration(newIntervalMs) * time.Millisecond

	c.inactivityTimeout.interval = newIntervalMs
	c.inactivityTimeout.desired = newIntervalMs
	c.inactivityTimeout.isInfinite = false

	if elapsed >= newInterval {
		// Already exceeded the new timeout — expire immediately.
		c.inactivityTimeout.expiration = now
	} else {
		c.inactivityTimeout.expiration = now.Add(newInterval - elapsed)
	}
}

// calculateServerInactivityWaitTime returns the server-side inactivity wait
// time, which is max(2 * inactivityTimeout, dsoMinServerInactivityWaitTime).
func (c *DSOConnection) calculateServerInactivityWaitTime() uint32 {
	if c.inactivityTimeout.isInfinite {
		return dsoInfiniteTimeout
	}
	doubled := c.inactivityTimeout.interval * 2
	if doubled < dsoMinServerInactivityWaitTime {
		doubled = dsoMinServerInactivityWaitTime
	}
	return doubled
}

// sendErrorResponseLocked sends a DNS error response for a non-DSO query.
func (c *DSOConnection) sendErrorResponseLocked(messageID uint16, rcode ResponseCode) {
	msg := c.buildResponseMessageLocked(messageID, rcode, nil)
	_ = c.transport.Send(msg)
}

// processRequestLocked handles an incoming DSO request (messageID != 0).
func (c *DSOConnection) processRequestLocked(hdr Header, tlvData []byte) {
	primaryType, err := c.readPrimaryTlvType(tlvData)
	if err != nil {
		c.disconnectLocked(DisconnectForciblyAbort, DisconnectReasonPeerMisbehavior)
		return
	}

	// Server: transition to EstablishingSession on first request.
	if c.isServer && c.state == DSOStateConnectedButSessionless {
		c.state = DSOStateEstablishingSession
	}

	// Handle KeepAlive request internally.
	if primaryType == DSOTlvKeepAlive {
		c.processKeepAliveRequestLocked(hdr, tlvData)
		return
	}

	// Delegate to callback.
	if c.callbacks.OnRequestMessage != nil {
		c.mu.Unlock()
		err = c.callbacks.OnRequestMessage(c, hdr.MessageID, tlvData, primaryType)
		c.mu.Lock()
		if err != nil {
			// Send error response.
			c.sendErrorResponseLocked(hdr.MessageID, RcodeDsoNotImpl)
		}
	} else {
		c.sendErrorResponseLocked(hdr.MessageID, RcodeDsoNotImpl)
	}

	c.resetInactivityLocked()
	c.scheduleTimerLocked()
}

// processUnidirectionalLocked handles an incoming unidirectional DSO message (messageID == 0).
func (c *DSOConnection) processUnidirectionalLocked(hdr Header, tlvData []byte) {
	primaryType, err := c.readPrimaryTlvType(tlvData)
	if err != nil {
		c.disconnectLocked(DisconnectForciblyAbort, DisconnectReasonPeerMisbehavior)
		return
	}

	// Must be in session-established state.
	if c.state != DSOStateSessionEstablished {
		c.disconnectLocked(DisconnectForciblyAbort, DisconnectReasonPeerMisbehavior)
		return
	}

	// Handle KeepAlive unidirectional from server (client receives).
	if primaryType == DSOTlvKeepAlive {
		c.processKeepAliveUnidirectionalLocked(tlvData)
		return
	}

	// Handle RetryDelay from server (client receives).
	if primaryType == DSOTlvRetryDelay {
		c.processRetryDelayLocked(tlvData)
		return
	}

	// Delegate to callback.
	if c.callbacks.OnUnidirectionalMessage != nil {
		c.mu.Unlock()
		err = c.callbacks.OnUnidirectionalMessage(c, tlvData, primaryType)
		c.mu.Lock()
		if err != nil {
			// For unidirectional, cannot send error response — abort.
			c.disconnectLocked(DisconnectForciblyAbort, DisconnectReasonPeerMisbehavior)
		}
	}

	c.resetInactivityLocked()
	c.scheduleTimerLocked()
}

// processResponseLocked handles an incoming DSO response.
func (c *DSOConnection) processResponseLocked(hdr Header, tlvData []byte) {
	// Find matching pending request.
	reqIdx := -1
	for i, pr := range c.pendingReqs {
		if pr.messageID == hdr.MessageID {
			reqIdx = i
			break
		}
	}

	if reqIdx == -1 {
		// Unexpected response — misbehavior.
		c.disconnectLocked(DisconnectForciblyAbort, DisconnectReasonPeerMisbehavior)
		return
	}

	requestTlvType := c.pendingReqs[reqIdx].primaryTlvType

	// Remove from pending.
	c.pendingReqs = append(c.pendingReqs[:reqIdx], c.pendingReqs[reqIdx+1:]...)

	// Check RCODE.
	rcode := hdr.GetResponseCode()

	// Read response primary TLV type (may be empty for error responses).
	responseTlvType := DSOTlvReserved
	if len(tlvData) >= DSOTlvHeaderSize {
		responseTlvType = DSOTlvType(binary.BigEndian.Uint16(tlvData[0:2]))
	}

	// If this was the first request and we're establishing session:
	if c.state == DSOStateEstablishingSession {
		if rcode == RcodeSuccess {
			c.state = DSOStateSessionEstablished
			if c.callbacks.OnSessionEstablished != nil {
				c.callbacks.OnSessionEstablished(c)
			}
		} else if rcode == RcodeDsoNotImpl || rcode == RcodeNotImplemented {
			c.disconnectLocked(DisconnectGracefullyClose, DisconnectReasonPeerDoesNotSupportDso)
			return
		} else {
			c.disconnectLocked(DisconnectGracefullyClose, DisconnectReasonPeerMisbehavior)
			return
		}
	}

	// Handle KeepAlive response internally.
	if requestTlvType == DSOTlvKeepAlive {
		c.processKeepAliveResponseLocked(hdr, tlvData, rcode)
		return
	}

	// Delegate to callback.
	if c.callbacks.OnResponseMessage != nil {
		c.mu.Unlock()
		_ = c.callbacks.OnResponseMessage(c, hdr, tlvData, responseTlvType, requestTlvType)
		c.mu.Lock()
	}

	c.resetInactivityLocked()
	c.scheduleTimerLocked()
}

// processKeepAliveRequestLocked handles an incoming KeepAlive request.
// On the server: update timeouts and send a KeepAlive response.
func (c *DSOConnection) processKeepAliveRequestLocked(hdr Header, tlvData []byte) {
	if len(tlvData) < DSOTlvHeaderSize+KeepAliveTlvDataSize {
		c.disconnectLocked(DisconnectForciblyAbort, DisconnectReasonPeerMisbehavior)
		return
	}

	var ka KeepAliveTlvData
	if err := ka.UnmarshalBinary(tlvData[DSOTlvHeaderSize:]); err != nil {
		c.disconnectLocked(DisconnectForciblyAbort, DisconnectReasonPeerMisbehavior)
		return
	}

	// Validate keep-alive interval.
	if ka.KeepAliveInterval != dsoInfiniteTimeout && ka.KeepAliveInterval < dsoMinKeepAliveInterval {
		c.sendErrorResponseLocked(hdr.MessageID, RcodeRefused)
		return
	}

	// Update our timeouts with the values from the peer.
	now := c.now()
	c.inactivityTimeout.reset(ka.InactivityTimeout, now)
	c.keepAliveTimeout.reset(ka.KeepAliveInterval, now)

	// Server uses a longer inactivity wait.
	if c.isServer {
		serverWait := c.calculateServerInactivityWaitTime()
		c.inactivityTimeout.reset(serverWait, now)
	}

	// Send KeepAlive response with the same values.
	respPayload := c.buildKeepAliveTlvPayload()
	c.sendResponseWithPayloadLocked(hdr.MessageID, RcodeSuccess, respPayload)

	// If server was in EstablishingSession, mark session established.
	if c.isServer && c.state == DSOStateEstablishingSession {
		c.state = DSOStateSessionEstablished
		if c.callbacks.OnSessionEstablished != nil {
			c.callbacks.OnSessionEstablished(c)
		}
	}

	c.scheduleTimerLocked()
}

// processKeepAliveResponseLocked handles a KeepAlive response (client).
func (c *DSOConnection) processKeepAliveResponseLocked(hdr Header, tlvData []byte, rcode ResponseCode) {
	if rcode != RcodeSuccess {
		return // Ignore non-success keepalive responses.
	}

	if len(tlvData) < DSOTlvHeaderSize+KeepAliveTlvDataSize {
		return
	}

	var ka KeepAliveTlvData
	if err := ka.UnmarshalBinary(tlvData[DSOTlvHeaderSize:]); err != nil {
		return
	}

	// Update timeouts from the server's response.
	now := c.now()
	c.inactivityTimeout.reset(ka.InactivityTimeout, now)

	keepAlive := ka.KeepAliveInterval
	if keepAlive != dsoInfiniteTimeout && keepAlive < dsoMinKeepAliveInterval {
		keepAlive = dsoMinKeepAliveInterval
	}
	c.keepAliveTimeout.reset(keepAlive, now)

	c.scheduleTimerLocked()
}

// processKeepAliveUnidirectionalLocked handles a unidirectional KeepAlive
// from the server (received on the client side).
func (c *DSOConnection) processKeepAliveUnidirectionalLocked(tlvData []byte) {
	if len(tlvData) < DSOTlvHeaderSize+KeepAliveTlvDataSize {
		c.disconnectLocked(DisconnectForciblyAbort, DisconnectReasonPeerMisbehavior)
		return
	}

	var ka KeepAliveTlvData
	if err := ka.UnmarshalBinary(tlvData[DSOTlvHeaderSize:]); err != nil {
		c.disconnectLocked(DisconnectForciblyAbort, DisconnectReasonPeerMisbehavior)
		return
	}

	now := c.now()
	c.adjustInactivityTimeoutLocked(ka.InactivityTimeout, now)

	keepAlive := ka.KeepAliveInterval
	if keepAlive != dsoInfiniteTimeout && keepAlive < dsoMinKeepAliveInterval {
		keepAlive = dsoMinKeepAliveInterval
	}
	c.keepAliveTimeout.reset(keepAlive, now)

	c.resetInactivityLocked()
	c.scheduleTimerLocked()
}

// processRetryDelayLocked handles a RetryDelay message from the server.
func (c *DSOConnection) processRetryDelayLocked(tlvData []byte) {
	if len(tlvData) < DSOTlvHeaderSize+RetryDelayTlvDataSize {
		c.disconnectLocked(DisconnectForciblyAbort, DisconnectReasonPeerMisbehavior)
		return
	}

	var rd RetryDelayTlvData
	if err := rd.UnmarshalBinary(tlvData[DSOTlvHeaderSize:]); err != nil {
		c.disconnectLocked(DisconnectForciblyAbort, DisconnectReasonPeerMisbehavior)
		return
	}

	c.retryDelay = rd.RetryDelay
	c.disconnectLocked(DisconnectGracefullyClose, DisconnectReasonServerRetryDelayRequest)
}

// readPrimaryTlvType reads the primary TLV type from DSO TLV data.
func (c *DSOConnection) readPrimaryTlvType(tlvData []byte) (DSOTlvType, error) {
	if len(tlvData) < DSOTlvHeaderSize {
		return DSOTlvReserved, errors.ErrParse
	}
	return DSOTlvType(binary.BigEndian.Uint16(tlvData[0:2])), nil
}

// sendResponseWithPayloadLocked is a convenience to send a response.
func (c *DSOConnection) sendResponseWithPayloadLocked(messageID uint16, rcode ResponseCode, payload []byte) {
	msg := c.buildResponseMessageLocked(messageID, rcode, payload)
	_ = c.transport.Send(msg)
}

// nextFireTimeLocked returns the earliest expiration among all active timeouts.
func (c *DSOConnection) nextFireTimeLocked() time.Time {
	var earliest time.Time

	updateEarliest := func(t time.Time) {
		if t.IsZero() {
			return
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}

	if c.state == DSOStateConnecting {
		updateEarliest(c.connectExpiration)
	}

	for _, pr := range c.pendingReqs {
		updateEarliest(pr.expiration)
	}

	if !c.longLivedOperation && !c.inactivityTimeout.isInfinite {
		updateEarliest(c.inactivityTimeout.expiration)
	}

	if !c.keepAliveTimeout.isInfinite {
		updateEarliest(c.keepAliveTimeout.expiration)
	}

	return earliest
}

// scheduleTimerLocked (re-)schedules the periodic timer based on the next
// fire time.
func (c *DSOConnection) scheduleTimerLocked() {
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}

	next := c.nextFireTimeLocked()
	if next.IsZero() {
		return
	}

	delay := time.Until(next)
	if delay < 0 {
		delay = 0
	}

	c.timer = c.afterFunc(delay, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.handleTimerLocked()
		c.scheduleTimerLocked()
	})
}

// ---------------------------------------------------------------------------
// DSO (top-level manager)
// ---------------------------------------------------------------------------

// DSOAcceptHandler is called when a new server-side connection is accepted.
// It should return a configured DSOConnection to handle the session, or nil
// to reject the connection.
type DSOAcceptHandler func(peerAddr ip6.Address, peerPort uint16) *DSOConnection

// DSO manages client and server DSO connections.
type DSO struct {
	mu sync.Mutex

	acceptHandler     DSOAcceptHandler
	listening         bool
	clientConnections []*DSOConnection
	serverConnections []*DSOConnection
}

// NewDSO creates a new DSO manager.
func NewDSO() *DSO {
	return &DSO{}
}

// StartListening begins accepting incoming DSO connections.
func (d *DSO) StartListening(handler DSOAcceptHandler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.acceptHandler = handler
	d.listening = true
}

// StopListening stops accepting new connections and disconnects all
// server-side connections.
func (d *DSO) StopListening() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.listening = false
	d.acceptHandler = nil

	// Disconnect all server connections.
	for _, conn := range d.serverConnections {
		conn.Disconnect(DisconnectGracefullyClose, DisconnectReasonUnknown)
	}
	d.serverConnections = nil
}

// AcceptConnection processes an incoming connection request from the platform
// transport. It calls the accept handler to create a DSOConnection.
func (d *DSO) AcceptConnection(peerAddr ip6.Address, peerPort uint16) *DSOConnection {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.listening || d.acceptHandler == nil {
		return nil
	}

	conn := d.acceptHandler(peerAddr, peerPort)
	if conn == nil {
		return nil
	}

	d.serverConnections = append(d.serverConnections, conn)
	return conn
}

// AddClientConnection registers a client connection with the manager.
func (d *DSO) AddClientConnection(conn *DSOConnection) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.clientConnections = append(d.clientConnections, conn)
}

// RemoveClientConnection unregisters a client connection.
func (d *DSO) RemoveClientConnection(conn *DSOConnection) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, c := range d.clientConnections {
		if c == conn {
			d.clientConnections = append(d.clientConnections[:i], d.clientConnections[i+1:]...)
			return
		}
	}
}

// RemoveServerConnection unregisters a server connection.
func (d *DSO) RemoveServerConnection(conn *DSOConnection) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, c := range d.serverConnections {
		if c == conn {
			d.serverConnections = append(d.serverConnections[:i], d.serverConnections[i+1:]...)
			return
		}
	}
}

// FindClientConnection finds a client connection by peer address and port.
func (d *DSO) FindClientConnection(peerAddr ip6.Address, peerPort uint16) *DSOConnection {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, conn := range d.clientConnections {
		if conn.peerAddr == peerAddr && conn.peerPort == peerPort {
			return conn
		}
	}
	return nil
}

// FindServerConnection finds a server connection by peer address and port.
func (d *DSO) FindServerConnection(peerAddr ip6.Address, peerPort uint16) *DSOConnection {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, conn := range d.serverConnections {
		if conn.peerAddr == peerAddr && conn.peerPort == peerPort {
			return conn
		}
	}
	return nil
}

// GetClientConnections returns a snapshot of client connections.
func (d *DSO) GetClientConnections() []*DSOConnection {
	d.mu.Lock()
	defer d.mu.Unlock()
	result := make([]*DSOConnection, len(d.clientConnections))
	copy(result, d.clientConnections)
	return result
}

// GetServerConnections returns a snapshot of server connections.
func (d *DSO) GetServerConnections() []*DSOConnection {
	d.mu.Lock()
	defer d.mu.Unlock()
	result := make([]*DSOConnection, len(d.serverConnections))
	copy(result, d.serverConnections)
	return result
}
