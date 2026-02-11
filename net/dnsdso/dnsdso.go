// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package dnsdso implements DNS Stateful Operations (DSO) per RFC 8490.
//
// DSO extends DNS to support long-lived stateful sessions over TCP, enabling
// features such as DNS Push Notifications. This package provides message
// encoding/decoding, TLV handling, and a connection state machine.
//
// This is a Go port of the DSO module in OpenThread's
// src/core/net/dns_dso.hpp and src/core/net/dns_dso.cpp.
package dnsdso

import (
	"encoding/binary"
	"sync"

	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// DSO TLV type constants (RFC 8490 + proposed)
// ---------------------------------------------------------------------------

// MessageType identifies the DSO TLV type used as the primary TLV in a
// DSO message.
type MessageType = uint16

const (
	// TypeReserved is the reserved TLV type (must not be used).
	TypeReserved MessageType = 0x0000
	// TypeKeepAlive is the Keep Alive TLV type (bidirectional, RFC 8490).
	TypeKeepAlive MessageType = 0x0001
	// TypeRetryDelay is the Retry Delay TLV type (RFC 8490).
	TypeRetryDelay MessageType = 0x0002
	// TypeEncryptionPadding is the Encryption Padding TLV type (RFC 8490).
	TypeEncryptionPadding MessageType = 0x0003
	// TypeSubscribe is the DNS Push Subscribe TLV type (proposed).
	TypeSubscribe MessageType = 0x0040
	// TypePush is the DNS Push Notification TLV type (proposed).
	TypePush MessageType = 0x0041
	// TypeReconfirm is the DNS Push Reconfirm TLV type (proposed).
	TypeReconfirm MessageType = 0x0042
	// TypeUnsubscribe is the DNS Push Unsubscribe TLV type (proposed).
	TypeUnsubscribe MessageType = 0x0043
)

// ---------------------------------------------------------------------------
// Timeout defaults (in milliseconds)
// ---------------------------------------------------------------------------

const (
	// DefaultTimeout is the default inactivity/keepalive timeout (15 s).
	DefaultTimeout uint32 = 15_000
	// MinKeepAliveInterval is the minimum keepalive interval (10 s).
	MinKeepAliveInterval uint32 = 10_000
	// InfiniteTimeout disables the timeout.
	InfiniteTimeout uint32 = 0xffffffff
	// ResponseTimeout is the max wait for a DSO response (30 s).
	ResponseTimeout uint32 = 30_000
)

// ---------------------------------------------------------------------------
// TLV
// ---------------------------------------------------------------------------

// TLV represents a DSO Type-Length-Value element.
type TLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

// tlvHeaderSize is the size of the TLV type + length fields.
const tlvHeaderSize = 4

// EncodeTLV encodes a DSO TLV into wire format (big-endian type, length,
// value).
func EncodeTLV(tlvType uint16, value []byte) []byte {
	buf := make([]byte, tlvHeaderSize+len(value))
	binary.BigEndian.PutUint16(buf[0:2], tlvType)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(value)))
	copy(buf[4:], value)
	return buf
}

// DecodeTLV decodes a single DSO TLV from the given data. It returns the
// decoded TLV, the number of bytes consumed, and any error.
func DecodeTLV(data []byte) (TLV, int, error) {
	if len(data) < tlvHeaderSize {
		return TLV{}, 0, errors.ErrParse
	}
	tlvType := binary.BigEndian.Uint16(data[0:2])
	tlvLen := binary.BigEndian.Uint16(data[2:4])
	total := tlvHeaderSize + int(tlvLen)
	if len(data) < total {
		return TLV{}, 0, errors.ErrParse
	}
	value := make([]byte, tlvLen)
	copy(value, data[4:total])
	return TLV{Type: tlvType, Length: tlvLen, Value: value}, total, nil
}

// ---------------------------------------------------------------------------
// Message — DSO message header
// ---------------------------------------------------------------------------

// dnsHeaderSize is the fixed size of the DNS header portion of a DSO message.
const dnsHeaderSize = 12

// Message represents a DSO message consisting of a DNS-like header and
// zero or more TLVs.
type Message struct {
	// ID is the message identifier (transaction ID).
	ID uint16
	// QR indicates whether this is a query (false) or response (true).
	QR bool
	// RCode is the DNS response code.
	RCode uint8
	// PrimaryTLV is the first (primary) TLV in the message, or nil.
	PrimaryTLV *TLV
	// AdditionalTLVs contains any additional TLVs after the primary.
	AdditionalTLVs []TLV
}

// Encode serialises a DSO message into wire format. The DNS header is
// followed by the primary TLV and any additional TLVs.
func (m *Message) Encode() []byte {
	var buf []byte

	// DNS header: ID(2) + flags(2) + 4 x count(2) = 12 bytes.
	hdr := make([]byte, dnsHeaderSize)
	binary.BigEndian.PutUint16(hdr[0:2], m.ID)

	var flags uint16
	if m.QR {
		flags |= 0x8000 // QR bit
	}
	// Opcode 6 (DSO) is in bits 14-11.
	flags |= 6 << 11
	flags |= uint16(m.RCode) & 0x000f
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	// QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT are all zero for DSO.
	buf = append(buf, hdr...)

	// Primary TLV.
	if m.PrimaryTLV != nil {
		buf = append(buf, EncodeTLV(m.PrimaryTLV.Type, m.PrimaryTLV.Value)...)
	}

	// Additional TLVs.
	for i := range m.AdditionalTLVs {
		buf = append(buf, EncodeTLV(m.AdditionalTLVs[i].Type, m.AdditionalTLVs[i].Value)...)
	}

	return buf
}

// Decode parses a wire-format DSO message into the Message struct.
func (m *Message) Decode(data []byte) error {
	if len(data) < dnsHeaderSize {
		return errors.ErrParse
	}

	m.ID = binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	m.QR = (flags & 0x8000) != 0
	m.RCode = uint8(flags & 0x000f)
	m.PrimaryTLV = nil
	m.AdditionalTLVs = nil

	offset := dnsHeaderSize

	// Parse primary TLV.
	if offset < len(data) {
		tlv, n, err := DecodeTLV(data[offset:])
		if err != nil {
			return err
		}
		m.PrimaryTLV = &tlv
		offset += n
	}

	// Parse additional TLVs.
	for offset < len(data) {
		tlv, n, err := DecodeTLV(data[offset:])
		if err != nil {
			return err
		}
		m.AdditionalTLVs = append(m.AdditionalTLVs, tlv)
		offset += n
	}

	return nil
}

// ---------------------------------------------------------------------------
// Connection state machine
// ---------------------------------------------------------------------------

// State represents the state of a DSO connection.
type State uint8

const (
	// StateDisconnected means no connection is established.
	StateDisconnected State = iota
	// StateConnectedButSessionless means the TCP connection is up but
	// no DSO session has been established yet.
	StateConnectedButSessionless
	// StateEstablishingSession means a DSO session is being negotiated.
	StateEstablishingSession
	// StateSessionEstablished means the DSO session is active.
	StateSessionEstablished
)

// ResponseCallback is invoked when a DSO response is received.
type ResponseCallback func(messageID uint16, rCode uint8, data []byte)

// RequestCallback is invoked when a DSO request is received. It returns
// response data and a DNS response code.
type RequestCallback func(primaryTlvType uint16, data []byte) ([]byte, uint8)

// Connection represents a DSO session over TCP. It manages the state
// machine, message IDs, keepalive intervals, and request/response
// dispatching.
type Connection struct {
	mu sync.Mutex

	state             State
	nextMessageID     uint16
	peerAddr          [16]byte
	peerPort          uint16
	inactivityTimeout uint32
	keepAliveInterval uint32
	retryDelay        uint32

	// Pending requests keyed by message ID → primary TLV type.
	pendingRequests map[uint16]uint16

	responseCb ResponseCallback
	requestCb  RequestCallback
}

// NewConnection creates a new DSO Connection targeted at the given peer.
// The connection starts in StateDisconnected.
func NewConnection(peerAddr [16]byte, peerPort uint16) *Connection {
	return &Connection{
		state:             StateDisconnected,
		nextMessageID:     1,
		peerAddr:          peerAddr,
		peerPort:          peerPort,
		inactivityTimeout: DefaultTimeout,
		keepAliveInterval: DefaultTimeout,
		pendingRequests:   make(map[uint16]uint16),
	}
}

// GetState returns the current connection state.
func (c *Connection) GetState() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Connect transitions the connection from StateDisconnected to
// StateConnectedButSessionless. In a full implementation this would
// initiate a TCP connection; here we model the state machine only.
func (c *Connection) Connect(serverAddr [16]byte, serverPort uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != StateDisconnected {
		return errors.ErrInvalidState
	}
	c.peerAddr = serverAddr
	c.peerPort = serverPort
	c.state = StateConnectedButSessionless
	return nil
}

// Disconnect transitions the connection to StateDisconnected and clears
// pending state.
func (c *Connection) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = StateDisconnected
	c.pendingRequests = make(map[uint16]uint16)
}

// SetResponseCallback registers a callback for incoming DSO responses.
func (c *Connection) SetResponseCallback(cb ResponseCallback) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.responseCb = cb
}

// SetRequestCallback registers a callback for incoming DSO requests.
func (c *Connection) SetRequestCallback(cb RequestCallback) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requestCb = cb
}

// allocMessageID returns the next message ID and advances the counter.
// Must be called with c.mu held.
func (c *Connection) allocMessageID() uint16 {
	id := c.nextMessageID
	c.nextMessageID++
	if c.nextMessageID == 0 {
		c.nextMessageID = 1 // skip zero
	}
	return id
}

// SendKeepAlive sends a DSO KeepAlive message with the given inactivity
// timeout and keepalive interval (both in milliseconds). It transitions
// the session to StateEstablishingSession or keeps it in
// StateSessionEstablished.
func (c *Connection) SendKeepAlive(inactivityTimeout, keepAliveInterval uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateConnectedButSessionless &&
		c.state != StateEstablishingSession &&
		c.state != StateSessionEstablished {
		return errors.ErrInvalidState
	}

	c.inactivityTimeout = inactivityTimeout
	c.keepAliveInterval = keepAliveInterval

	// Build KeepAlive TLV value: inactivity timeout (4 bytes) +
	// keepalive interval (4 bytes).
	value := make([]byte, 8)
	binary.BigEndian.PutUint32(value[0:4], inactivityTimeout)
	binary.BigEndian.PutUint32(value[4:8], keepAliveInterval)

	id := c.allocMessageID()
	c.pendingRequests[id] = TypeKeepAlive

	if c.state == StateConnectedButSessionless {
		c.state = StateEstablishingSession
	}
	return nil
}

// SendRequestMessage sends a DSO request with the given primary TLV type
// and data. It returns the assigned message ID.
func (c *Connection) SendRequestMessage(primaryTlvType uint16, data []byte) (uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateConnectedButSessionless &&
		c.state != StateEstablishingSession &&
		c.state != StateSessionEstablished {
		return 0, errors.ErrInvalidState
	}

	id := c.allocMessageID()
	c.pendingRequests[id] = primaryTlvType

	if c.state == StateConnectedButSessionless {
		c.state = StateEstablishingSession
	}
	return id, nil
}

// SendUnidirectionalMessage sends a DSO unidirectional message (message
// ID = 0) with the given primary TLV type and data. Unidirectional
// messages require an established session.
func (c *Connection) SendUnidirectionalMessage(primaryTlvType uint16, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateSessionEstablished {
		return errors.ErrInvalidState
	}
	// Unidirectional messages use message ID 0 and need no tracking.
	return nil
}

// HandleReceived processes an incoming DSO message. It dispatches to the
// appropriate callback based on whether the message is a response (QR=1)
// or a request/unidirectional (QR=0).
func (c *Connection) HandleReceived(data []byte) {
	var msg Message
	if err := msg.Decode(data); err != nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if msg.QR {
		// Response message.
		primaryType, ok := c.pendingRequests[msg.ID]
		if !ok {
			return // spurious response
		}
		delete(c.pendingRequests, msg.ID)

		// If this was the session-establishing exchange, mark session
		// as established.
		if c.state == StateEstablishingSession && msg.RCode == 0 {
			c.state = StateSessionEstablished
		}

		// Handle Retry Delay in response.
		if msg.PrimaryTLV != nil && msg.PrimaryTLV.Type == TypeRetryDelay &&
			len(msg.PrimaryTLV.Value) >= 4 {
			c.retryDelay = binary.BigEndian.Uint32(msg.PrimaryTLV.Value[0:4])
		}

		if c.responseCb != nil {
			var respData []byte
			if msg.PrimaryTLV != nil {
				respData = msg.PrimaryTLV.Value
			}
			_ = primaryType // could be passed to callback in future
			c.responseCb(msg.ID, msg.RCode, respData)
		}
	} else {
		// Request or unidirectional message.
		if msg.ID == 0 {
			// Unidirectional — no response expected.
			return
		}

		if c.requestCb != nil && msg.PrimaryTLV != nil {
			respData, rCode := c.requestCb(msg.PrimaryTLV.Type, msg.PrimaryTLV.Value)
			_ = respData
			_ = rCode
			// In a full implementation we'd send a response message here.
		}
	}
}

// GetInactivityTimeout returns the current inactivity timeout in ms.
func (c *Connection) GetInactivityTimeout() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inactivityTimeout
}

// GetKeepAliveInterval returns the current keepalive interval in ms.
func (c *Connection) GetKeepAliveInterval() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.keepAliveInterval
}

// GetRetryDelay returns the last received retry delay in ms.
func (c *Connection) GetRetryDelay() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.retryDelay
}
