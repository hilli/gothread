// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"encoding/binary"
	"log/slog"
	"sync"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Commissioner state machine
// ---------------------------------------------------------------------------

// CommissionerState represents the state of the Commissioner.
type CommissionerState uint8

const (
	// CommissionerDisabled means the commissioner role is off.
	CommissionerDisabled CommissionerState = 0
	// CommissionerPetition means the commissioner is petitioning the leader.
	CommissionerPetition CommissionerState = 1
	// CommissionerActive means the commissioner is active.
	CommissionerActive CommissionerState = 2
)

// String returns the name of the commissioner state.
func (s CommissionerState) String() string {
	switch s {
	case CommissionerDisabled:
		return "Disabled"
	case CommissionerPetition:
		return "Petition"
	case CommissionerActive:
		return "Active"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// Joiner types
// ---------------------------------------------------------------------------

// JoinerType indicates the kind of joiner entry.
type JoinerType uint8

const (
	// JoinerTypeUnused means the entry is available.
	JoinerTypeUnused JoinerType = 0
	// JoinerTypeAny means the entry matches any joiner.
	JoinerTypeAny JoinerType = 1
	// JoinerTypeEUI64 means the entry matches by EUI-64.
	JoinerTypeEUI64 JoinerType = 2
	// JoinerTypeDiscerner means the entry matches by discerner.
	JoinerTypeDiscerner JoinerType = 3
)

// JoinerEvent is an event in the joiner lifecycle.
type JoinerEvent uint8

const (
	// JoinerEventStart indicates a new DTLS session started.
	JoinerEventStart JoinerEvent = iota
	// JoinerEventConnected indicates the DTLS handshake completed.
	JoinerEventConnected
	// JoinerEventFinalize indicates JOIN_FIN.rsp was sent.
	JoinerEventFinalize
	// JoinerEventEnd indicates the DTLS session disconnected.
	JoinerEventEnd
	// JoinerEventRemoved indicates the joiner entry was removed.
	JoinerEventRemoved
)

// String returns the name of the joiner event.
func (e JoinerEvent) String() string {
	switch e {
	case JoinerEventStart:
		return "Start"
	case JoinerEventConnected:
		return "Connected"
	case JoinerEventFinalize:
		return "Finalize"
	case JoinerEventEnd:
		return "End"
	case JoinerEventRemoved:
		return "Removed"
	default:
		return "Unknown"
	}
}

// JoinerDiscerner holds a bit-length-limited discerner value.
type JoinerDiscerner struct {
	Value     uint64
	BitLength uint8
}

// Joiner represents an entry in the commissioner's joiner table.
type Joiner struct {
	Type      JoinerType
	EUI64     types.ExtAddress
	Discerner JoinerDiscerner
	PSKd      string
	ExpiresAt time.Time
}

// JoinerInfo contains information about a joiner entry, suitable for
// external iteration.
type JoinerInfo struct {
	Type      JoinerType
	EUI64     types.ExtAddress
	Discerner JoinerDiscerner
	PSKd      string
	ExpiresAt time.Time
}

// ---------------------------------------------------------------------------
// Commissioner constants
// ---------------------------------------------------------------------------

const (
	// DefaultCommissionerID is the default commissioner identity string.
	DefaultCommissionerID = "GoThread Commissioner"

	// MaxJoinerEntries is the maximum number of joiner entries.
	MaxJoinerEntries = 8

	// MaxJoinerPSKdLength is the maximum length of a joiner PSKd.
	MaxJoinerPSKdLength = 32

	// petitionRetryCount is the max number of petition retries.
	petitionRetryCount = 2

	// petitionRetryDelay is the delay before retrying a petition.
	petitionRetryDelay = 1 * time.Second

	// keepAliveTimeout is the leader's petition timeout (50 seconds).
	keepAliveTimeout = 50 * time.Second

	// keepAlivePeriod is the interval between keep-alive messages (half of timeout).
	keepAlivePeriod = keepAliveTimeout / 2

	// removeJoinerDelay is the delay before removing a successfully joined joiner.
	removeJoinerDelay = 20 * time.Second

	// joinerSessionTimeout is the maximum duration of a joiner DTLS session.
	joinerSessionTimeout = 120 * time.Second
)

// ---------------------------------------------------------------------------
// Commissioner transport interface
// ---------------------------------------------------------------------------

// CommissionerTransport provides the commissioner's interface to send and
// receive CoAP messages. In production this is backed by the TMF agent; in
// tests a stub can be used.
type CommissionerTransport interface {
	// SendRequest sends a CoAP message and invokes the callback with the response.
	// The callback may be nil for non-confirmable messages.
	SendRequest(msg *coap.Message, info coap.MessageInfo, cb func(*coap.Message, coap.MessageInfo, error)) error

	// SendResponse sends a CoAP response message.
	SendResponse(code coap.Code, req *coap.Message, info coap.MessageInfo) error

	// RegisterHandler registers a handler for the given URI path.
	RegisterHandler(uriPath string, handler func(*coap.Message, coap.MessageInfo))

	// UnregisterHandler removes the handler for the given URI path.
	UnregisterHandler(uriPath string)
}

// CommissionerAddressing provides address information needed for
// constructing CoAP messages.
type CommissionerAddressing interface {
	// MeshLocalPrefix returns the current mesh-local /64 prefix.
	MeshLocalPrefix() ip6.NetworkPrefix

	// RLOC16 returns this device's current RLOC16.
	RLOC16() uint16

	// LeaderRLOC16 returns the leader's RLOC16.
	LeaderRLOC16() uint16

	// IsAttached reports whether the device is currently attached to a Thread network.
	IsAttached() bool
}

// ---------------------------------------------------------------------------
// Commissioner
// ---------------------------------------------------------------------------

// Commissioner implements the Thread MeshCoP Commissioner role. It manages
// the state machine (Disabled → Petition → Active), joiner table, steering
// data, and petition/keep-alive flows.
//
// This is a Go port of OpenThread's src/core/meshcop/commissioner.hpp/cpp.
type Commissioner struct {
	mu sync.Mutex

	state           CommissionerState
	sessionID       uint16
	commissionerID  string
	provisioningURL string

	joiners      [MaxJoinerEntries]Joiner
	activeJoiner *Joiner
	joinerIID    ip6.InterfaceIdentifier
	joinerPort   uint16
	joinerRLOC   uint16

	transmitAttempts uint8

	// Timers
	commissionerTimer  *time.Timer
	joinerExpTimer     *time.Timer
	joinerSessionTimer *time.Timer

	// Timer stop channels — used to cancel pending timer goroutines.
	timerStopCh chan struct{}

	// Callbacks
	stateCallback  func(CommissionerState)
	joinerCallback func(JoinerEvent, *JoinerInfo)

	// Dependencies
	transport  CommissionerTransport
	addressing CommissionerAddressing

	// nowFunc allows tests to inject a clock.
	nowFunc func() time.Time

	// afterFunc allows tests to inject timer scheduling.
	afterFunc func(d time.Duration, f func()) *time.Timer
}

// NewCommissioner creates a new Commissioner. The transport and addressing
// parameters must not be nil. Callbacks may be nil.
func NewCommissioner(
	transport CommissionerTransport,
	addressing CommissionerAddressing,
	stateCallback func(CommissionerState),
	joinerCallback func(JoinerEvent, *JoinerInfo),
) *Commissioner {
	c := &Commissioner{
		state:          CommissionerDisabled,
		commissionerID: DefaultCommissionerID,
		transport:      transport,
		addressing:     addressing,
		stateCallback:  stateCallback,
		joinerCallback: joinerCallback,
		timerStopCh:    make(chan struct{}),
		nowFunc:        time.Now,
		afterFunc:      time.AfterFunc,
	}
	return c
}

// ---------------------------------------------------------------------------
// Public accessors
// ---------------------------------------------------------------------------

// GetState returns the current commissioner state.
func (c *Commissioner) GetState() CommissionerState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// IsActive reports whether the commissioner is in the Active state.
func (c *Commissioner) IsActive() bool {
	return c.GetState() == CommissionerActive
}

// IsDisabled reports whether the commissioner is in the Disabled state.
func (c *Commissioner) IsDisabled() bool {
	return c.GetState() == CommissionerDisabled
}

// GetSessionID returns the current commissioner session ID.
func (c *Commissioner) GetSessionID() uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionID
}

// GetID returns the commissioner identity string.
func (c *Commissioner) GetID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.commissionerID
}

// SetID sets the commissioner identity string. Must be called while disabled.
func (c *Commissioner) SetID(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != CommissionerDisabled {
		return goterrors.ErrInvalidState
	}
	if id == "" || len(id) > MaxCommissionerIDLength {
		return goterrors.ErrInvalidArgs
	}
	c.commissionerID = id
	return nil
}

// encodeExtendedTLV encodes a MeshCoP extended TLV: [type(1), 0xFF, length(2 big-endian), value...].
// This format is used when the value exceeds 254 bytes (e.g., JoinerDTLSEncapsulation).
func encodeExtendedTLV(typ TLVType, value []byte) []byte {
	buf := make([]byte, 4+len(value))
	buf[0] = uint8(typ)
	buf[1] = 0xFF
	buf[2] = byte(len(value) >> 8)
	buf[3] = byte(len(value))
	copy(buf[4:], value)
	return buf
}

// findTLVInBytesExtended searches raw TLV bytes for a TLV of the given type,
// supporting both short-form (length < 255) and extended-form (0xFF + 2-byte length).
func findTLVInBytesExtended(data []byte, typ TLVType) []byte {
	offset := 0
	for offset+2 <= len(data) {
		t := TLVType(data[offset])
		lenByte := data[offset+1]
		var l int
		var hdrSize int
		if lenByte == 0xFF {
			// Extended TLV.
			if offset+4 > len(data) {
				return nil
			}
			l = int(data[offset+2])<<8 | int(data[offset+3])
			hdrSize = 4
		} else {
			l = int(lenByte)
			hdrSize = 2
		}
		if offset+hdrSize+l > len(data) {
			return nil // Truncated.
		}
		if t == typ {
			return data[offset+hdrSize : offset+hdrSize+l]
		}
		offset += hdrSize + l
	}
	return nil
}

// buildNONPost builds a Non-Confirmable POST message for the given URI path.
func buildNONPost(uriPath string, payload []byte) *coap.Message {
	msg := coap.NewMessage(coap.TypeNonConfirmable, coap.CodePost, 0)

	// Set a 4-byte token.
	token := []byte{0x05, 0x06, 0x07, 0x08}
	_ = msg.SetToken(token)
	_ = msg.AppendURIPathOptions(uriPath)

	if len(payload) > 0 {
		_ = msg.AppendPayloadMarker()
		_ = msg.AppendPayload(payload)
	}
	return msg
}

// linkLocalFromIID constructs a link-local IPv6 address from an Interface Identifier.
func linkLocalFromIID(iid [8]byte) [16]byte {
	var addr [16]byte
	addr[0] = 0xfe
	addr[1] = 0x80
	copy(addr[8:], iid[:])
	return addr
}

// SetProvisioningURL sets the provisioning URL. Must be called while disabled.
func (c *Commissioner) SetProvisioningURL(url string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != CommissionerDisabled {
		return goterrors.ErrInvalidState
	}
	if len(url) > MaxProvisioningURLLength {
		return goterrors.ErrInvalidArgs
	}
	c.provisioningURL = url
	return nil
}

// GetProvisioningURL returns the configured provisioning URL.
func (c *Commissioner) GetProvisioningURL() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.provisioningURL
}

// ---------------------------------------------------------------------------
// Start / Stop
// ---------------------------------------------------------------------------

// Start begins the commissioner petition process. The device must be attached
// to a Thread network.
func (c *Commissioner) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != CommissionerDisabled {
		return goterrors.ErrAlready
	}
	if !c.addressing.IsAttached() {
		return goterrors.ErrInvalidState
	}

	c.setState(CommissionerPetition)
	c.transmitAttempts = 0
	c.sendPetition()
	return nil
}

// Stop stops the commissioner. If currently active, it sends a keep-alive
// with Reject state to resign the session on the leader.
func (c *Commissioner) Stop() error {
	return c.stop(true)
}

// stop is the internal stop that optionally sends a resign keep-alive.
func (c *Commissioner) stop(sendKeepAlive bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == CommissionerDisabled {
		return goterrors.ErrAlready
	}

	wasActive := c.state == CommissionerActive
	c.stopTimers()
	c.clearJoinersLocked()
	c.setState(CommissionerDisabled)

	if wasActive && sendKeepAlive {
		c.sendKeepAliveLocked(c.sessionID, StateReject)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Joiner management
// ---------------------------------------------------------------------------

// AddJoinerAny adds a joiner entry that matches any joiner ID.
func (c *Commissioner) AddJoinerAny(pskd string, timeout time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.addJoiner(JoinerTypeAny, types.ExtAddress{}, JoinerDiscerner{}, pskd, timeout)
}

// AddJoinerEUI64 adds a joiner entry matching a specific EUI-64.
func (c *Commissioner) AddJoinerEUI64(eui64 types.ExtAddress, pskd string, timeout time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.addJoiner(JoinerTypeEUI64, eui64, JoinerDiscerner{}, pskd, timeout)
}

// AddJoinerDiscerner adds a joiner entry matching a specific discerner.
func (c *Commissioner) AddJoinerDiscerner(discerner JoinerDiscerner, pskd string, timeout time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.addJoiner(JoinerTypeDiscerner, types.ExtAddress{}, discerner, pskd, timeout)
}

// addJoiner is the internal joiner add implementation.
func (c *Commissioner) addJoiner(jtype JoinerType, eui64 types.ExtAddress, disc JoinerDiscerner, pskd string, timeout time.Duration) error {
	if c.state != CommissionerActive {
		return goterrors.ErrInvalidState
	}
	if pskd == "" || len(pskd) > MaxJoinerPSKdLength {
		return goterrors.ErrInvalidArgs
	}

	// Check for an existing entry of the same identity.
	idx := c.findJoinerIndex(jtype, eui64, disc)
	if idx >= 0 {
		// Update existing entry.
		c.joiners[idx].PSKd = pskd
		c.joiners[idx].ExpiresAt = c.nowFunc().Add(timeout)
		c.updateJoinerExpTimer()
		c.sendCommissionerSet()
		return nil
	}

	// Find an unused slot.
	idx = c.findUnusedJoinerIndex()
	if idx < 0 {
		return goterrors.ErrNoBufs
	}

	j := &c.joiners[idx]
	j.Type = jtype
	j.EUI64 = eui64
	j.Discerner = disc
	j.PSKd = pskd
	j.ExpiresAt = c.nowFunc().Add(timeout)

	c.updateJoinerExpTimer()
	c.sendCommissionerSet()
	return nil
}

// RemoveJoinerAny removes the "any" joiner entry.
func (c *Commissioner) RemoveJoinerAny(delay time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.removeJoiner(JoinerTypeAny, types.ExtAddress{}, JoinerDiscerner{}, delay)
}

// RemoveJoinerEUI64 removes a joiner entry by EUI-64.
func (c *Commissioner) RemoveJoinerEUI64(eui64 types.ExtAddress, delay time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.removeJoiner(JoinerTypeEUI64, eui64, JoinerDiscerner{}, delay)
}

// RemoveJoinerDiscerner removes a joiner entry by discerner.
func (c *Commissioner) RemoveJoinerDiscerner(discerner JoinerDiscerner, delay time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.removeJoiner(JoinerTypeDiscerner, types.ExtAddress{}, discerner, delay)
}

// removeJoiner is the internal joiner removal implementation.
func (c *Commissioner) removeJoiner(jtype JoinerType, eui64 types.ExtAddress, disc JoinerDiscerner, delay time.Duration) error {
	if c.state != CommissionerActive {
		return goterrors.ErrInvalidState
	}

	idx := c.findJoinerIndex(jtype, eui64, disc)
	if idx < 0 {
		return goterrors.ErrNotFound
	}

	if delay > 0 {
		c.joiners[idx].ExpiresAt = c.nowFunc().Add(delay)
		c.updateJoinerExpTimer()
		return nil
	}

	c.removeJoinerAtIndex(idx)
	return nil
}

// ClearJoiners removes all joiner entries.
func (c *Commissioner) ClearJoiners() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearJoinersLocked()
	if c.state == CommissionerActive {
		c.sendCommissionerSet()
	}
}

// clearJoinersLocked clears all joiner entries without locking.
func (c *Commissioner) clearJoinersLocked() {
	for i := range c.joiners {
		if c.joiners[i].Type != JoinerTypeUnused {
			c.signalJoinerEvent(JoinerEventRemoved, &c.joiners[i])
			c.joiners[i].Type = JoinerTypeUnused
		}
	}
	c.activeJoiner = nil
	if c.joinerExpTimer != nil {
		c.joinerExpTimer.Stop()
		c.joinerExpTimer = nil
	}
}

// removeJoinerAtIndex removes a joiner entry by index and updates steering data.
func (c *Commissioner) removeJoinerAtIndex(idx int) {
	c.signalJoinerEvent(JoinerEventRemoved, &c.joiners[idx])
	c.joiners[idx].Type = JoinerTypeUnused
	c.updateJoinerExpTimer()
	c.sendCommissionerSet()
}

// GetJoiners returns a slice of all active joiner entries.
func (c *Commissioner) GetJoiners() []JoinerInfo {
	c.mu.Lock()
	defer c.mu.Unlock()

	var result []JoinerInfo
	for i := range c.joiners {
		if c.joiners[i].Type == JoinerTypeUnused {
			continue
		}
		result = append(result, JoinerInfo{
			Type:      c.joiners[i].Type,
			EUI64:     c.joiners[i].EUI64,
			Discerner: c.joiners[i].Discerner,
			PSKd:      c.joiners[i].PSKd,
			ExpiresAt: c.joiners[i].ExpiresAt,
		})
	}
	return result
}

// JoinerCount returns the number of active joiner entries.
func (c *Commissioner) JoinerCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	count := 0
	for i := range c.joiners {
		if c.joiners[i].Type != JoinerTypeUnused {
			count++
		}
	}
	return count
}

// ---------------------------------------------------------------------------
// Joiner lookup helpers
// ---------------------------------------------------------------------------

// findJoinerIndex finds a joiner entry matching the given identity.
// Returns -1 if not found.
func (c *Commissioner) findJoinerIndex(jtype JoinerType, eui64 types.ExtAddress, disc JoinerDiscerner) int {
	for i := range c.joiners {
		if c.joiners[i].Type != jtype {
			continue
		}
		switch jtype {
		case JoinerTypeAny:
			return i
		case JoinerTypeEUI64:
			if c.joiners[i].EUI64 == eui64 {
				return i
			}
		case JoinerTypeDiscerner:
			if c.joiners[i].Discerner == disc {
				return i
			}
		}
	}
	return -1
}

// findUnusedJoinerIndex returns the index of the first unused joiner slot,
// or -1 if the table is full.
func (c *Commissioner) findUnusedJoinerIndex() int {
	for i := range c.joiners {
		if c.joiners[i].Type == JoinerTypeUnused {
			return i
		}
	}
	return -1
}

// FindBestMatchingJoiner finds the best matching joiner for a given joiner ID.
// Preference: exact EUI-64 > longest discerner match > any.
func (c *Commissioner) FindBestMatchingJoiner(joinerID [8]byte) *Joiner {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.findBestMatchingJoinerLocked(joinerID)
}

// findBestMatchingJoinerLocked finds the best matching joiner (no lock).
func (c *Commissioner) findBestMatchingJoinerLocked(joinerID [8]byte) *Joiner {
	var best *Joiner
	var bestBitLen uint8

	for i := range c.joiners {
		j := &c.joiners[i]
		switch j.Type {
		case JoinerTypeUnused:
			continue
		case JoinerTypeAny:
			if best == nil {
				best = j
			}
		case JoinerTypeEUI64:
			if j.EUI64 == types.ExtAddress(joinerID) {
				return j // Exact match — best possible.
			}
		case JoinerTypeDiscerner:
			if j.Discerner.BitLength > bestBitLen {
				// Check if discerner matches the joiner ID.
				if discernerMatchesEUI64(j.Discerner, joinerID) {
					best = j
					bestBitLen = j.Discerner.BitLength
				}
			}
		}
	}
	return best
}

// discernerMatchesEUI64 checks whether a discerner matches a Joiner ID.
// The discerner's value bits (from LSB) must match the corresponding bits
// of the joiner ID's 8-byte address (packed big-endian).
func discernerMatchesEUI64(d JoinerDiscerner, joinerID [8]byte) bool {
	// Convert joiner ID to uint64 (big-endian).
	val := binary.BigEndian.Uint64(joinerID[:])
	mask := uint64(0)
	if d.BitLength >= 64 {
		mask = ^uint64(0)
	} else {
		mask = (uint64(1) << d.BitLength) - 1
	}
	return (val & mask) == (d.Value & mask)
}

// ---------------------------------------------------------------------------
// Bloom filter computation
// ---------------------------------------------------------------------------

// ComputeBloomFilter computes the steering data bloom filter from the
// current joiner table.
func (c *Commissioner) ComputeBloomFilter() SteeringData {
	var sd SteeringData
	_ = sd.Init(SteeringDataMaxLength)

	hasEntries := false
	for i := range c.joiners {
		j := &c.joiners[i]
		switch j.Type {
		case JoinerTypeUnused:
			continue
		case JoinerTypeAny:
			sd.SetToPermitAllJoiners()
			return sd
		case JoinerTypeEUI64:
			hasEntries = true
			joinerID := computeJoinerID(j.EUI64)
			_ = sd.UpdateBloomFilter(joinerID)
		case JoinerTypeDiscerner:
			hasEntries = true
			_ = sd.UpdateBloomFilterWithDiscerner(j.Discerner.Value, j.Discerner.BitLength)
		}
	}

	if !hasEntries {
		// No joiners — return an empty 1-byte filter.
		sd.Clear()
	}

	return sd
}

// computeJoinerID derives a Joiner ID from an EUI-64 by toggling the
// Universal/Local bit (bit 1 of the first byte).
func computeJoinerID(eui64 types.ExtAddress) [8]byte {
	var id [8]byte
	copy(id[:], eui64[:])
	id[0] ^= 0x02 // Toggle U/L bit.
	return id
}

// ---------------------------------------------------------------------------
// Petition flow
// ---------------------------------------------------------------------------

// sendPetition sends a Commissioner Petition (COMM_PET.req) to the leader.
// Must be called with c.mu held.
func (c *Commissioner) sendPetition() {
	c.transmitAttempts++

	payload := c.buildPetitionPayload()
	msg := buildCONPost("c/lp", payload)
	info := c.leaderCoapInfo()

	if err := c.transport.SendRequest(msg, info, func(resp *coap.Message, respInfo coap.MessageInfo, err error) {
		c.handlePetitionResponse(resp, err)
	}); err != nil {
		c.retryPetitionOrStop()
	}
}

// handlePetitionResponse processes the leader's petition response.
func (c *Commissioner) handlePetitionResponse(resp *coap.Message, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == CommissionerActive {
		return // Ignore late responses.
	}

	if c.state != CommissionerPetition {
		return // We were stopped while waiting.
	}

	if err != nil || resp == nil {
		c.retryPetitionOrStop()
		return
	}

	// Check response code — expect 2.04 Changed.
	if resp.GetCode() != coap.CodeChanged {
		c.retryPetitionOrStop()
		return
	}

	// Parse the response payload for State and SessionID TLVs.
	payload := resp.GetPayload()
	state, sessionID, ok := parsePetitionResponse(payload)
	if !ok || state != StateAccept {
		c.stopTimers()
		c.setState(CommissionerDisabled)
		return
	}

	// Success — transition to Active.
	c.sessionID = sessionID
	c.transmitAttempts = 0
	c.setState(CommissionerActive)

	// Start keep-alive timer.
	c.startKeepAliveTimer()
}

// retryPetitionOrStop retries the petition or gives up.
func (c *Commissioner) retryPetitionOrStop() {
	if c.transmitAttempts >= petitionRetryCount {
		c.stopTimers()
		c.setState(CommissionerDisabled)
		return
	}

	// Schedule a retry.
	c.commissionerTimer = c.afterFunc(petitionRetryDelay, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.state == CommissionerPetition {
			c.sendPetition()
		}
	})
}

// buildPetitionPayload builds the COMM_PET.req payload containing
// the Commissioner ID TLV.
func (c *Commissioner) buildPetitionPayload() []byte {
	return encodeTLV(TLVCommissionerID, []byte(c.commissionerID))
}

// parsePetitionResponse extracts the State TLV value and Commissioner
// Session ID from the petition response payload.
func parsePetitionResponse(payload []byte) (state uint8, sessionID uint16, ok bool) {
	stateTLV := findTLVInBytes(payload, TLVState)
	if len(stateTLV) != 1 {
		return 0, 0, false
	}
	state = stateTLV[0]

	sessionTLV := findTLVInBytes(payload, TLVCommissionerSessionID)
	if len(sessionTLV) != 2 {
		return state, 0, false
	}
	sessionID = binary.BigEndian.Uint16(sessionTLV)

	return state, sessionID, true
}

// ---------------------------------------------------------------------------
// Keep-Alive flow
// ---------------------------------------------------------------------------

// startKeepAliveTimer starts the periodic keep-alive timer.
func (c *Commissioner) startKeepAliveTimer() {
	c.commissionerTimer = c.afterFunc(keepAlivePeriod, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.state == CommissionerActive {
			c.sendKeepAliveLocked(c.sessionID, StateAccept)
		}
	})
}

// sendKeepAliveLocked sends a COMM_KA.req. Must be called with c.mu held.
func (c *Commissioner) sendKeepAliveLocked(sessionID uint16, stateVal uint8) {
	payload := c.buildKeepAlivePayload(sessionID, stateVal)
	msg := buildCONPost("c/la", payload)
	info := c.leaderCoapInfo()

	if err := c.transport.SendRequest(msg, info, func(resp *coap.Message, respInfo coap.MessageInfo, err error) {
		c.handleKeepAliveResponse(resp, err)
	}); err != nil {
		c.stopTimers()
		c.clearJoinersLocked()
		c.setState(CommissionerDisabled)
	}
}

// handleKeepAliveResponse processes the leader's keep-alive response.
func (c *Commissioner) handleKeepAliveResponse(resp *coap.Message, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != CommissionerActive {
		return
	}

	if err != nil || resp == nil {
		c.stopTimers()
		c.clearJoinersLocked()
		c.setState(CommissionerDisabled)
		return
	}

	if resp.GetCode() != coap.CodeChanged {
		c.stopTimers()
		c.clearJoinersLocked()
		c.setState(CommissionerDisabled)
		return
	}

	// Parse State TLV from response.
	payload := resp.GetPayload()
	stateTLV := findTLVInBytes(payload, TLVState)
	if len(stateTLV) != 1 || stateTLV[0] != StateAccept {
		c.stopTimers()
		c.clearJoinersLocked()
		c.setState(CommissionerDisabled)
		return
	}

	// Restart keep-alive timer.
	c.startKeepAliveTimer()
}

// buildKeepAlivePayload builds the COMM_KA.req payload.
func (c *Commissioner) buildKeepAlivePayload(sessionID uint16, stateVal uint8) []byte {
	var buf []byte
	buf = append(buf, encodeTLV(TLVState, []byte{stateVal})...)
	sidBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sidBytes, sessionID)
	buf = append(buf, encodeTLV(TLVCommissionerSessionID, sidBytes)...)
	return buf
}

// ---------------------------------------------------------------------------
// Commissioner Set (steering data push)
// ---------------------------------------------------------------------------

// sendCommissionerSet sends MGMT_COMMISSIONER_SET.req to the leader with
// the current steering data and session ID. Must be called with c.mu held.
func (c *Commissioner) sendCommissionerSet() {
	if c.state != CommissionerActive {
		return
	}

	sd := c.ComputeBloomFilter()
	payload := c.buildCommissionerSetPayload(sd)
	msg := buildCONPost("c/cs", payload)
	info := c.leaderCoapInfo()

	// Fire-and-forget for steering data updates — the response is informational.
	if err := c.transport.SendRequest(msg, info, func(resp *coap.Message, _ coap.MessageInfo, err error) {
		if err != nil {
			slog.Warn("Commissioner steering data update failed", "error", err)
		}
	}); err != nil {
		slog.Warn("Failed to send commissioner steering data update", "error", err)
	}
}

// buildCommissionerSetPayload builds the MGMT_COMMISSIONER_SET.req payload
// containing the session ID and steering data TLVs.
func (c *Commissioner) buildCommissionerSetPayload(sd SteeringData) []byte {
	var buf []byte
	sidBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sidBytes, c.sessionID)
	buf = append(buf, encodeTLV(TLVCommissionerSessionID, sidBytes)...)
	buf = append(buf, encodeTLV(TLVSteeringData, sd.Data())...)
	return buf
}

// ---------------------------------------------------------------------------
// Commissioner Get
// ---------------------------------------------------------------------------

// SendMgmtCommissionerGetRequest sends a MGMT_COMMISSIONER_GET.req.
func (c *Commissioner) SendMgmtCommissionerGetRequest(tlvTypes []byte, cb func([]byte, error)) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != CommissionerActive {
		return goterrors.ErrInvalidState
	}

	var payload []byte
	if len(tlvTypes) > 0 {
		payload = encodeTLV(TLVGet, tlvTypes)
	}

	msg := buildCONPost("c/cg", payload)
	info := c.leaderCoapInfo()

	return c.transport.SendRequest(msg, info, func(resp *coap.Message, _ coap.MessageInfo, err error) {
		if cb != nil {
			if err != nil {
				cb(nil, err)
				return
			}
			cb(resp.GetPayload(), nil)
		}
	})
}

// ---------------------------------------------------------------------------
// TMF handlers
// ---------------------------------------------------------------------------

// RegisterHandlers registers the commissioner's TMF handlers on the transport.
func (c *Commissioner) RegisterHandlers() {
	c.transport.RegisterHandler("c/rx", c.handleRelayRx)
	c.transport.RegisterHandler("c/dc", c.handleDatasetChanged)
}

// UnregisterHandlers removes the commissioner's TMF handlers.
func (c *Commissioner) UnregisterHandlers() {
	c.transport.UnregisterHandler("c/rx")
	c.transport.UnregisterHandler("c/dc")
}

// handleRelayRx processes incoming RelayRx messages from a Joiner Router.
// This contains DTLS-encapsulated data from a Joiner, which would be fed
// into the secure agent. The full relay flow is deferred to Phase 18f.
func (c *Commissioner) handleRelayRx(msg *coap.Message, info coap.MessageInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != CommissionerActive {
		return
	}

	// Parse Joiner IID, Joiner UDP Port, Joiner Router Locator, and
	// DTLS encapsulation TLVs from the payload.
	payload := msg.GetPayload()

	joinerUDPPort := findTLVInBytes(payload, TLVJoinerUDPPort)
	joinerIID := findTLVInBytes(payload, TLVJoinerIID)
	joinerRouterLocator := findTLVInBytes(payload, TLVJoinerRouterLocator)
	dtlsData := findTLVInBytes(payload, TLVJoinerDTLSEncapsulation)

	if joinerUDPPort == nil || joinerIID == nil || joinerRouterLocator == nil || dtlsData == nil {
		return
	}

	if len(joinerUDPPort) != 2 || len(joinerIID) != 8 || len(joinerRouterLocator) != 2 {
		return
	}

	c.joinerPort = binary.BigEndian.Uint16(joinerUDPPort)
	copy(c.joinerIID[:], joinerIID)
	c.joinerRLOC = binary.BigEndian.Uint16(joinerRouterLocator)

	// Derive joiner ID from IID for matching.
	var joinerID [8]byte
	copy(joinerID[:], c.joinerIID[:])

	if c.activeJoiner == nil {
		// No active DTLS session — find a matching joiner entry.
		best := c.findBestMatchingJoinerLocked(joinerID)
		if best == nil {
			return // No matching joiner.
		}
		c.activeJoiner = best
		c.signalJoinerEvent(JoinerEventStart, best)

		// Start joiner session timer.
		c.joinerSessionTimer = c.afterFunc(joinerSessionTimeout, func() {
			c.handleJoinerSessionTimeout()
		})
	}

	// In a full implementation, the DTLS data would be fed to SecureAgent here.
	// This is deferred to Phase 18f (Joiner package).
}

// handleDatasetChanged processes incoming Dataset Changed notifications.
func (c *Commissioner) handleDatasetChanged(msg *coap.Message, info coap.MessageInfo) {
	c.mu.Lock()
	state := c.state
	c.mu.Unlock()

	if state != CommissionerActive {
		return
	}

	// ACK the notification.
	if msg.GetType() == coap.TypeConfirmable {
		_ = c.transport.SendResponse(coap.CodeChanged, msg, info)
	}
}

// HandleJoinerFinalize processes a Joiner Finalize request received over
// the secure CoAP (DTLS) session. This is called by the secure agent when
// a c/jf message arrives.
func (c *Commissioner) HandleJoinerFinalize(payload []byte) (state uint8) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != CommissionerActive {
		return StateReject
	}

	// Check provisioning URL.
	provURL := findTLVInBytes(payload, TLVProvisioningURL)
	if provURL != nil && string(provURL) != c.provisioningURL {
		return StateReject
	}

	c.signalJoinerEvent(JoinerEventFinalize, c.activeJoiner)

	// Schedule removal of non-"any" joiner entries after a delay.
	if c.activeJoiner != nil && c.activeJoiner.Type != JoinerTypeAny {
		joinerPtr := c.activeJoiner
		c.afterFunc(removeJoinerDelay, func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			// Find and remove the entry if it still exists.
			for i := range c.joiners {
				if &c.joiners[i] == joinerPtr && c.joiners[i].Type != JoinerTypeUnused {
					c.removeJoinerAtIndex(i)
					break
				}
			}
		})
	}

	return StateAccept
}

// ---------------------------------------------------------------------------
// Timer management
// ---------------------------------------------------------------------------

// handleJoinerSessionTimeout handles joiner DTLS session timeout.
func (c *Commissioner) handleJoinerSessionTimeout() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.activeJoiner != nil {
		c.signalJoinerEvent(JoinerEventEnd, c.activeJoiner)
		c.activeJoiner = nil
	}
}

// handleJoinerExpiration handles joiner entry expiration.
func (c *Commissioner) handleJoinerExpiration() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.nowFunc()
	removed := false

	for i := range c.joiners {
		if c.joiners[i].Type == JoinerTypeUnused {
			continue
		}
		if !c.joiners[i].ExpiresAt.After(now) {
			c.signalJoinerEvent(JoinerEventRemoved, &c.joiners[i])
			c.joiners[i].Type = JoinerTypeUnused
			removed = true
		}
	}

	if removed && c.state == CommissionerActive {
		c.sendCommissionerSet()
	}

	// Re-arm the timer for the next expiration.
	c.updateJoinerExpTimerLocked()
}

// updateJoinerExpTimer reschedules the joiner expiration timer.
func (c *Commissioner) updateJoinerExpTimer() {
	c.updateJoinerExpTimerLocked()
}

// updateJoinerExpTimerLocked reschedules the joiner expiration timer (no extra lock).
func (c *Commissioner) updateJoinerExpTimerLocked() {
	if c.joinerExpTimer != nil {
		c.joinerExpTimer.Stop()
		c.joinerExpTimer = nil
	}

	var earliest time.Time
	found := false
	for i := range c.joiners {
		if c.joiners[i].Type == JoinerTypeUnused {
			continue
		}
		if !found || c.joiners[i].ExpiresAt.Before(earliest) {
			earliest = c.joiners[i].ExpiresAt
			found = true
		}
	}

	if !found {
		return
	}

	delay := earliest.Sub(c.nowFunc())
	if delay < 0 {
		delay = 0
	}

	c.joinerExpTimer = c.afterFunc(delay, func() {
		c.handleJoinerExpiration()
	})
}

// stopTimers stops all commissioner timers.
func (c *Commissioner) stopTimers() {
	if c.commissionerTimer != nil {
		c.commissionerTimer.Stop()
		c.commissionerTimer = nil
	}
	if c.joinerExpTimer != nil {
		c.joinerExpTimer.Stop()
		c.joinerExpTimer = nil
	}
	if c.joinerSessionTimer != nil {
		c.joinerSessionTimer.Stop()
		c.joinerSessionTimer = nil
	}
}

// ---------------------------------------------------------------------------
// State transitions
// ---------------------------------------------------------------------------

// setState transitions to the given state and fires the callback.
func (c *Commissioner) setState(newState CommissionerState) {
	if c.state == newState {
		return
	}
	c.state = newState
	if c.stateCallback != nil {
		c.stateCallback(newState)
	}
}

// ---------------------------------------------------------------------------
// Event signaling
// ---------------------------------------------------------------------------

// signalJoinerEvent fires the joiner callback if set.
func (c *Commissioner) signalJoinerEvent(event JoinerEvent, joiner *Joiner) {
	if c.joinerCallback == nil {
		return
	}
	var info *JoinerInfo
	if joiner != nil {
		info = &JoinerInfo{
			Type:      joiner.Type,
			EUI64:     joiner.EUI64,
			Discerner: joiner.Discerner,
			PSKd:      joiner.PSKd,
			ExpiresAt: joiner.ExpiresAt,
		}
	}
	c.joinerCallback(event, info)
}

// ---------------------------------------------------------------------------
// CoAP message helpers
// ---------------------------------------------------------------------------

// leaderCoapInfo builds a coap.MessageInfo addressed to the leader.
func (c *Commissioner) leaderCoapInfo() coap.MessageInfo {
	mlp := c.addressing.MeshLocalPrefix()
	senderRLOC := c.addressing.RLOC16()
	leaderRLOC := c.addressing.LeaderRLOC16()

	var localAddr, peerAddr [16]byte
	localAddr = [16]byte(rlocAddr(mlp, senderRLOC))
	peerAddr = [16]byte(rlocAddr(mlp, leaderRLOC))

	return coap.MessageInfo{
		PeerPort:  61631, // TMF port
		PeerAddr:  peerAddr,
		LocalAddr: localAddr,
	}
}

// rlocAddr constructs an IPv6 RLOC address from prefix and RLOC16.
func rlocAddr(prefix ip6.NetworkPrefix, rloc16 uint16) ip6.Address {
	var addr ip6.Address
	addr.SetPrefix(prefix)
	iid := ip6.InterfaceIdentifier{0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x00}
	iid.SetLocator(rloc16)
	addr.SetIid(iid)
	return addr
}

// buildCONPost builds a Confirmable POST message for the given URI path.
func buildCONPost(uriPath string, payload []byte) *coap.Message {
	msg := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 0)

	// Set a 4-byte token.
	token := []byte{0x01, 0x02, 0x03, 0x04}
	_ = msg.SetToken(token)
	_ = msg.AppendURIPathOptions(uriPath)

	if len(payload) > 0 {
		_ = msg.AppendPayloadMarker()
		_ = msg.AppendPayload(payload)
	}
	return msg
}

// ---------------------------------------------------------------------------
// TLV encoding/decoding helpers
// ---------------------------------------------------------------------------

// encodeTLV encodes a single TLV as [type(1), length(1), value...].
func encodeTLV(typ TLVType, value []byte) []byte {
	buf := make([]byte, 2+len(value))
	buf[0] = uint8(typ)
	buf[1] = uint8(len(value))
	copy(buf[2:], value)
	return buf
}

// findTLVInBytes searches raw TLV bytes for a TLV of the given type.
// Returns the value portion, or nil if not found.
func findTLVInBytes(data []byte, typ TLVType) []byte {
	offset := 0
	for offset+2 <= len(data) {
		t := TLVType(data[offset])
		l := int(data[offset+1])
		if offset+2+l > len(data) {
			return nil // Truncated.
		}
		if t == typ {
			return data[offset+2 : offset+2+l]
		}
		offset += 2 + l
	}
	return nil
}
