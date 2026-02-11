// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package sntp implements an SNTP (Simple Network Time Protocol) client
// for Thread networks.
//
// This is a Go port of the SNTP client in OpenThread's
// src/core/net/sntp_client.hpp and src/core/net/sntp_client.cpp.
package sntp

import (
	"time"

	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	// HeaderSize is the size of an NTP message header in bytes.
	HeaderSize = 48

	// NtpPort is the well-known SNTP/NTP port number.
	NtpPort uint16 = 123

	// ServerPort is the default NTP server port.
	ServerPort uint16 = 123

	// ntpVersion is the NTP protocol version used by this client.
	ntpVersion uint8 = 4

	// KissCodeLength is the length of a Kiss-o'-death code in bytes.
	KissCodeLength = 4

	// ntpEpochOffset is the number of seconds between the NTP epoch
	// (January 1, 1900) and the Unix epoch (January 1, 1970).
	ntpEpochOffset uint32 = 2208988800

	// defaultMaxRetries is the default maximum number of retransmission
	// attempts before a query times out.
	defaultMaxRetries uint8 = 4

	// defaultTimeout is the default timeout between retransmissions.
	defaultTimeout = 5 * time.Second
)

// Mode represents the NTP association mode.
type Mode uint8

const (
	// ModeClient is the NTP client mode (3).
	ModeClient Mode = 3
	// ModeServer is the NTP server mode (4).
	ModeServer Mode = 4
)

// ---------------------------------------------------------------------------
// Bit-field layout for the flags byte
// ---------------------------------------------------------------------------

const (
	modeOffset    = 0
	modeMask      = 0x07 << modeOffset
	versionOffset = 3
	versionMask   = 0x07 << versionOffset
	leapOffset    = 6
	leapMask      = 0x03 << leapOffset //nolint:unused // defined for completeness
)

// ---------------------------------------------------------------------------
// Header — 48-byte NTP message
// ---------------------------------------------------------------------------

// Header represents a 48-byte SNTP/NTP message, stored as a raw byte array
// with big-endian field accessors.
//
// Layout:
//
//	Byte  0:    LI (2 bits) | VN (3 bits) | Mode (3 bits)
//	Byte  1:    Stratum
//	Byte  2:    Poll interval
//	Byte  3:    Precision
//	Bytes 4-7:  Root delay (uint32, big-endian)
//	Bytes 8-11: Root dispersion (uint32, big-endian)
//	Bytes 12-15: Reference ID (uint32, big-endian)
//	Bytes 16-23: Reference timestamp (uint64, big-endian)
//	Bytes 24-31: Originate timestamp (uint64, big-endian)
//	Bytes 32-39: Receive timestamp (uint64, big-endian)
//	Bytes 40-47: Transmit timestamp (uint64, big-endian)
type Header [HeaderSize]byte

// Init initialises the header to a zero state, then sets the version to 4
// and the mode to client (3).
func (h *Header) Init() {
	*h = Header{}
	h[0] = ntpVersion<<versionOffset | uint8(ModeClient)<<modeOffset
}

// --- Flags byte ---

// GetFlags returns the raw flags byte (LI | VN | Mode).
func (h *Header) GetFlags() uint8 { return h[0] }

// SetFlags sets the raw flags byte.
func (h *Header) SetFlags(flags uint8) { h[0] = flags }

// GetMode returns the NTP mode from the flags byte.
func (h *Header) GetMode() Mode { return Mode(h[0] & modeMask >> modeOffset) }

// GetVersion returns the NTP version from the flags byte.
func (h *Header) GetVersion() uint8 { return (h[0] & versionMask) >> versionOffset }

// GetLeapIndicator returns the leap indicator from the flags byte.
func (h *Header) GetLeapIndicator() uint8 { return h[0] >> leapOffset }

// --- Scalar fields ---

// GetStratum returns the stratum value.
func (h *Header) GetStratum() uint8 { return h[1] }

// SetStratum sets the stratum value.
func (h *Header) SetStratum(v uint8) { h[1] = v }

// GetPoll returns the poll interval (log2 seconds).
func (h *Header) GetPoll() uint8 { return h[2] }

// SetPoll sets the poll interval (log2 seconds).
func (h *Header) SetPoll(v uint8) { h[2] = v }

// GetPrecision returns the clock precision (log2 seconds).
func (h *Header) GetPrecision() uint8 { return h[3] }

// SetPrecision sets the clock precision (log2 seconds).
func (h *Header) SetPrecision(v uint8) { h[3] = v }

// --- 32-bit fields ---

// GetRootDelay returns the root delay in NTP short format.
func (h *Header) GetRootDelay() uint32 { return encoding.BigEndianReadUint32(h[4:8]) }

// SetRootDelay sets the root delay in NTP short format.
func (h *Header) SetRootDelay(v uint32) { encoding.BigEndianWriteUint32(v, h[4:8]) }

// GetRootDispersion returns the root dispersion in NTP short format.
func (h *Header) GetRootDispersion() uint32 { return encoding.BigEndianReadUint32(h[8:12]) }

// SetRootDispersion sets the root dispersion in NTP short format.
func (h *Header) SetRootDispersion(v uint32) { encoding.BigEndianWriteUint32(v, h[8:12]) }

// GetReferenceID returns the reference identifier.
func (h *Header) GetReferenceID() uint32 { return encoding.BigEndianReadUint32(h[12:16]) }

// SetReferenceID sets the reference identifier.
func (h *Header) SetReferenceID(v uint32) { encoding.BigEndianWriteUint32(v, h[12:16]) }

// GetKissCode returns the Kiss-o'-death code as a 4-byte string.
// This is valid only when the stratum is 0.
func (h *Header) GetKissCode() string { return string(h[12:16]) }

// --- Timestamp fields (seconds + fraction, each uint32 big-endian) ---

// GetReferenceTimestampSeconds returns the seconds portion of the reference timestamp.
func (h *Header) GetReferenceTimestampSeconds() uint32 {
	return encoding.BigEndianReadUint32(h[16:20])
}

// SetReferenceTimestampSeconds sets the seconds portion of the reference timestamp.
func (h *Header) SetReferenceTimestampSeconds(v uint32) {
	encoding.BigEndianWriteUint32(v, h[16:20])
}

// GetReferenceTimestampFraction returns the fraction portion of the reference timestamp.
func (h *Header) GetReferenceTimestampFraction() uint32 {
	return encoding.BigEndianReadUint32(h[20:24])
}

// SetReferenceTimestampFraction sets the fraction portion of the reference timestamp.
func (h *Header) SetReferenceTimestampFraction(v uint32) {
	encoding.BigEndianWriteUint32(v, h[20:24])
}

// GetOriginateTimestampSeconds returns the seconds portion of the originate timestamp.
func (h *Header) GetOriginateTimestampSeconds() uint32 {
	return encoding.BigEndianReadUint32(h[24:28])
}

// SetOriginateTimestampSeconds sets the seconds portion of the originate timestamp.
func (h *Header) SetOriginateTimestampSeconds(v uint32) {
	encoding.BigEndianWriteUint32(v, h[24:28])
}

// GetOriginateTimestampFraction returns the fraction portion of the originate timestamp.
func (h *Header) GetOriginateTimestampFraction() uint32 {
	return encoding.BigEndianReadUint32(h[28:32])
}

// SetOriginateTimestampFraction sets the fraction portion of the originate timestamp.
func (h *Header) SetOriginateTimestampFraction(v uint32) {
	encoding.BigEndianWriteUint32(v, h[28:32])
}

// GetReceiveTimestampSeconds returns the seconds portion of the receive timestamp.
func (h *Header) GetReceiveTimestampSeconds() uint32 {
	return encoding.BigEndianReadUint32(h[32:36])
}

// SetReceiveTimestampSeconds sets the seconds portion of the receive timestamp.
func (h *Header) SetReceiveTimestampSeconds(v uint32) {
	encoding.BigEndianWriteUint32(v, h[32:36])
}

// GetReceiveTimestampFraction returns the fraction portion of the receive timestamp.
func (h *Header) GetReceiveTimestampFraction() uint32 {
	return encoding.BigEndianReadUint32(h[36:40])
}

// SetReceiveTimestampFraction sets the fraction portion of the receive timestamp.
func (h *Header) SetReceiveTimestampFraction(v uint32) {
	encoding.BigEndianWriteUint32(v, h[36:40])
}

// GetTransmitTimestampSeconds returns the seconds portion of the transmit timestamp.
func (h *Header) GetTransmitTimestampSeconds() uint32 {
	return encoding.BigEndianReadUint32(h[40:44])
}

// SetTransmitTimestampSeconds sets the seconds portion of the transmit timestamp.
func (h *Header) SetTransmitTimestampSeconds(v uint32) {
	encoding.BigEndianWriteUint32(v, h[40:44])
}

// GetTransmitTimestampFraction returns the fraction portion of the transmit timestamp.
func (h *Header) GetTransmitTimestampFraction() uint32 {
	return encoding.BigEndianReadUint32(h[44:48])
}

// SetTransmitTimestampFraction sets the fraction portion of the transmit timestamp.
func (h *Header) SetTransmitTimestampFraction(v uint32) {
	encoding.BigEndianWriteUint32(v, h[44:48])
}

// Marshal serialises the header to a 48-byte slice.
func (h *Header) Marshal() []byte {
	b := make([]byte, HeaderSize)
	copy(b, h[:])
	return b
}

// Unmarshal deserialises a 48-byte slice into the header.
// It returns ErrParse if the buffer is too short.
func (h *Header) Unmarshal(b []byte) error {
	if len(b) < HeaderSize {
		return errors.ErrParse
	}
	copy(h[:], b[:HeaderSize])
	return nil
}

// ---------------------------------------------------------------------------
// ResponseHandler
// ---------------------------------------------------------------------------

// ResponseHandler is the callback function type invoked when an SNTP
// response is received or a query times out.
//
// On success, err is nil and unixTime contains the number of seconds
// since the Unix epoch (January 1, 1970). On failure, err is non-nil
// and unixTime is 0.
type ResponseHandler func(unixTime uint64, err error)

// ---------------------------------------------------------------------------
// SendFunc
// ---------------------------------------------------------------------------

// SendFunc is a function the client calls to send an NTP message.
// The payload is a 48-byte NTP header and messageInfo provides the
// destination address.
type SendFunc func(payload []byte, messageInfo *ip6.MessageInfo) error

// ---------------------------------------------------------------------------
// Query — a pending query tracked by the client
// ---------------------------------------------------------------------------

// Query represents a pending SNTP query waiting for a response.
type Query struct {
	transmitTimestamp   uint32
	handler             ResponseHandler
	destAddress         ip6.Address
	srcAddress          ip6.Address
	destPort            uint16
	retransmissionCount uint8
	maxRetries          uint8
	timeout             time.Duration
	deadline            time.Time
	message             []byte // the original NTP request message
}

// ---------------------------------------------------------------------------
// Option — functional options for Client.Query
// ---------------------------------------------------------------------------

// Option configures optional query parameters.
type Option func(*queryConfig)

type queryConfig struct {
	maxRetries uint8
	timeout    time.Duration
}

// WithMaxRetries sets the maximum number of retransmission attempts.
func WithMaxRetries(n uint8) Option {
	return func(c *queryConfig) { c.maxRetries = n }
}

// WithTimeout sets the timeout duration between retransmissions.
func WithTimeout(d time.Duration) Option {
	return func(c *queryConfig) { c.timeout = d }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client is an SNTP client that sends time queries and tracks pending
// responses.
type Client struct {
	queries    []*Query
	sendFunc   SendFunc
	unixEra    uint32
	maxRetries uint8
	timeout    time.Duration
	nowFunc    func() time.Time // injectable clock for testing
}

// NewClient creates a new SNTP client.
//
// sendFunc is called whenever the client needs to transmit an NTP
// message over the network. If sendFunc is nil, the client will return
// ErrInvalidArgs from SendQuery.
func NewClient(sendFunc SendFunc) *Client {
	return &Client{
		sendFunc:   sendFunc,
		maxRetries: defaultMaxRetries,
		timeout:    defaultTimeout,
		nowFunc:    time.Now,
	}
}

// GetUnixEra returns the current Unix era number.
// Era 0 covers dates from 1900 to ~2036. Era 1 covers ~2036 to ~2172.
func (c *Client) GetUnixEra() uint32 { return c.unixEra }

// SetUnixEra sets the Unix era number for timestamp conversion.
func (c *Client) SetUnixEra(era uint32) { c.unixEra = era }

// GetPendingQueryCount returns the number of queries awaiting responses.
func (c *Client) GetPendingQueryCount() int { return len(c.queries) }

// now returns the current time using the injectable clock.
func (c *Client) now() time.Time { return c.nowFunc() }

// SendQuery sends an SNTP query to the specified server address.
//
// The handler will be called asynchronously when a response is received
// (via HandleResponse) or when the query times out (via HandleTimer).
//
// Options can be used to override the default retry count and timeout
// for this specific query.
func (c *Client) SendQuery(dest ip6.SockAddr, handler ResponseHandler, opts ...Option) error {
	if c.sendFunc == nil {
		return errors.ErrInvalidArgs
	}
	if handler == nil {
		return errors.ErrInvalidArgs
	}

	cfg := queryConfig{
		maxRetries: c.maxRetries,
		timeout:    c.timeout,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	// Build the NTP request header.
	var header Header
	header.Init()

	// Use the current time as the transmit timestamp. This also serves
	// as a unique token to match responses.
	nowSec := uint32(c.now().Unix()) + ntpEpochOffset
	header.SetTransmitTimestampSeconds(nowSec)

	payload := header.Marshal()

	messageInfo := &ip6.MessageInfo{
		PeerAddr: dest.Address,
		PeerPort: dest.Port,
	}

	q := &Query{
		transmitTimestamp:   nowSec,
		handler:             handler,
		destAddress:         dest.Address,
		destPort:            dest.Port,
		retransmissionCount: 0,
		maxRetries:          cfg.maxRetries,
		timeout:             cfg.timeout,
		deadline:            c.now().Add(cfg.timeout),
		message:             payload,
	}

	// Send the message.
	if err := c.sendFunc(payload, messageInfo); err != nil {
		return err
	}

	c.queries = append(c.queries, q)
	return nil
}

// HandleResponse processes an incoming SNTP response message.
//
// It validates the response, matches it to a pending query by comparing
// the originate timestamp with the query's transmit timestamp, computes
// the Unix time, and invokes the query's response handler.
//
// This method should be called by the UDP receive handler when a
// message is received on the NTP port.
func (c *Client) HandleResponse(payload []byte, messageInfo *ip6.MessageInfo) error {
	var response Header
	if err := response.Unmarshal(payload); err != nil {
		return errors.ErrParse
	}

	// Find the matching pending query by originate timestamp.
	q, idx := c.findQuery(response.GetOriginateTimestampSeconds())
	if q == nil {
		return errors.ErrNotFound
	}

	// Validate the response mode.
	if response.GetMode() != ModeServer {
		c.finalise(idx, 0, errors.ErrFailed)
		return errors.ErrFailed
	}

	// Check for Kiss-o'-death (stratum == 0).
	if response.GetStratum() == 0 {
		c.finalise(idx, 0, errors.ErrBusy)
		return errors.ErrBusy
	}

	// Check that the transmit timestamp is non-zero.
	if response.GetTransmitTimestampSeconds() == 0 && response.GetTransmitTimestampFraction() == 0 {
		c.finalise(idx, 0, errors.ErrFailed)
		return errors.ErrFailed
	}

	// Convert NTP timestamp to Unix time.
	unixTime := c.ntpToUnix(response.GetTransmitTimestampSeconds())

	c.finalise(idx, unixTime, nil)
	return nil
}

// HandleTimer should be called periodically to check for timed-out
// queries and trigger retransmissions.
//
// It returns the time until the next deadline, or 0 if there are no
// pending queries. The caller can use this to schedule the next timer
// invocation.
func (c *Client) HandleTimer() time.Duration {
	now := c.now()
	var nextDeadline time.Time

	i := 0
	for i < len(c.queries) {
		q := c.queries[i]

		if now.Before(q.deadline) {
			if nextDeadline.IsZero() || q.deadline.Before(nextDeadline) {
				nextDeadline = q.deadline
			}
			i++
			continue
		}

		// Deadline has passed.
		if q.retransmissionCount >= q.maxRetries {
			// Max retries exceeded — timeout.
			c.finalise(i, 0, errors.ErrResponseTimeout)
			// finalise removes the element; don't increment i.
			continue
		}

		// Retransmit.
		q.retransmissionCount++
		q.deadline = now.Add(q.timeout)

		messageInfo := &ip6.MessageInfo{
			PeerAddr: q.destAddress,
			PeerPort: q.destPort,
			SockAddr: q.srcAddress,
		}
		// Best-effort retransmission; ignore send errors.
		_ = c.sendFunc(q.message, messageInfo)

		if nextDeadline.IsZero() || q.deadline.Before(nextDeadline) {
			nextDeadline = q.deadline
		}
		i++
	}

	if nextDeadline.IsZero() {
		return 0
	}
	d := nextDeadline.Sub(now)
	if d < 0 {
		return 0
	}
	return d
}

// Stop aborts all pending queries, invoking each handler with ErrAbort.
func (c *Client) Stop() {
	for len(c.queries) > 0 {
		c.finalise(0, 0, errors.ErrAbort)
	}
}

// findQuery searches pending queries for one whose transmit timestamp
// matches the given originate timestamp from a response.
func (c *Client) findQuery(originateTimestamp uint32) (*Query, int) {
	for i, q := range c.queries {
		if q.transmitTimestamp == originateTimestamp {
			return q, i
		}
	}
	return nil, -1
}

// finalise completes a query by removing it from the pending list and
// invoking its response handler.
func (c *Client) finalise(idx int, unixTime uint64, err error) {
	q := c.queries[idx]
	c.queries = append(c.queries[:idx], c.queries[idx+1:]...)
	if q.handler != nil {
		q.handler(unixTime, err)
	}
}

// ntpToUnix converts an NTP timestamp (seconds since 1900) to a Unix
// timestamp (seconds since 1970), accounting for the configured Unix era.
func (c *Client) ntpToUnix(ntpSeconds uint32) uint64 {
	unixTime := uint64(c.unixEra) * (1 << 32)

	if ntpSeconds > ntpEpochOffset {
		unixTime += uint64(ntpSeconds) - uint64(ntpEpochOffset)
	} else {
		unixTime += uint64(ntpSeconds) + (1 << 32) - uint64(ntpEpochOffset)
	}

	return unixTime
}
