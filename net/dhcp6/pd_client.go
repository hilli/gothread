// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package dhcp6

import (
	"encoding/binary"
	"time"
)

// ---------------------------------------------------------------------------
// PD Client States
// ---------------------------------------------------------------------------

// PdClientState represents the PD client state machine state.
type PdClientState uint8

// Prefix delegation client states.
const (
	PdStateStopped    PdClientState = 0
	PdStateToSolicit  PdClientState = 1
	PdStateSoliciting PdClientState = 2
	PdStateRequesting PdClientState = 3
	PdStateToRenew    PdClientState = 4
	PdStateRenewing   PdClientState = 5
	PdStateRebinding  PdClientState = 6
	PdStateReleasing  PdClientState = 7
)

// ---------------------------------------------------------------------------
// RFC 8415 Retransmission Constants (all in milliseconds)
// ---------------------------------------------------------------------------

const (
	pdMaxDelayFirstSolicit     = 1000     // ms - SOL_MAX_DELAY
	pdInitialSolicitTimeout    = 1000     // ms - SOL_TIMEOUT
	pdDefaultMaxSolicitTimeout = 3600_000 // ms (1 hour) - SOL_MAX_RT
	pdInitialRequestTimeout    = 1000     // ms - REQ_TIMEOUT
	pdMaxRequestTimeout        = 30_000   // ms - REQ_MAX_RT
	pdMaxRequestRetxCount      = 10       // REQ_MAX_RC
	pdInitialRenewTimeout      = 10_000   // ms - REN_TIMEOUT
	pdMaxRenewTimeout          = 600_000  // ms - REN_MAX_RT
	pdInitialRebindTimeout     = 10_000   // ms - REB_TIMEOUT
	pdMaxRebindTimeout         = 600_000  // ms - REB_MAX_RT
	pdInitialReleaseTimeout    = 1000     // ms - REL_TIMEOUT
	pdMaxReleaseRetxCount      = 4        // REL_MAX_RC
	pdRetxDelayOnFailedTx      = 330      // ms

	// Lifetime adjustment constants (in seconds).
	pdMinPreferredLifetime                 = 30 * 60     // 30 minutes
	pdMaxPreferredLifetime                 = 4 * 60 * 60 // 4 hours
	pdMaxValidMarginAfterPreferredLifetime = 2 * 60      // 2 minutes
	pdMinT1                                = 5 * 60      // 5 minutes
	pdMinT1MarginBeforePreferredLifetime   = 15 * 60     // 15 minutes
	pdMinT2MarginBeforePreferredLifetime   = 6 * 60      // 6 minutes
	pdDefaultT1FactorNumerator             = 5
	pdDefaultT1FactorDenominator           = 10
	pdDefaultT2FactorNumerator             = 8
	pdDefaultT2FactorDenominator           = 10
)

// ---------------------------------------------------------------------------
// DelegatedPrefix
// ---------------------------------------------------------------------------

// DelegatedPrefix represents a delegated prefix from a DHCPv6 server.
type DelegatedPrefix struct {
	Prefix            [16]byte
	PrefixLength      uint8
	AdjustedPrefix    [16]byte // prefix adjusted to /64
	AdjustedLength    uint8    // always 64 when valid
	T1                uint32   // renewal time in seconds
	T2                uint32   // rebind time in seconds
	PreferredLifetime uint32   // seconds
	ValidLifetime     uint32   // seconds
	UpdateTimeMs      int64    // when this prefix was last updated (ms)
}

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

// PdClientTransport provides the network transport for sending DHCPv6 messages.
type PdClientTransport interface {
	SendDhcp6(payload []byte, dst [16]byte) error
	SetDhcp6ListeningEnabled(enabled bool)
}

// PdClientCallback is called when the delegated prefix changes.
type PdClientCallback func(prefix *DelegatedPrefix)

// PdClientClock provides time functions for testability.
type PdClientClock interface {
	NowMs() int64
	NewTimer(fn func()) PdTimer
	RandomInt63n(n int64) int64
}

// PdTimer abstracts a timer for the PD client.
type PdTimer interface {
	Reset(d time.Duration)
	Stop() bool
}

// ---------------------------------------------------------------------------
// PdClientOption for functional option pattern
// ---------------------------------------------------------------------------

// PdClientOption configures a PdClient.
type PdClientOption func(*PdClient)

// WithPdClock sets a custom clock for the PD client (used in tests).
func WithPdClock(c PdClientClock) PdClientOption {
	return func(pc *PdClient) {
		pc.clock = c
	}
}

// ---------------------------------------------------------------------------
// retxTracker
// ---------------------------------------------------------------------------

type retxTracker struct {
	startTimeMs   int64
	endTimeMs     int64
	timeoutMs     uint32
	maxTimeoutMs  uint32
	count         uint16
	maxCount      uint16
	transactionID TransactionID
	hasEndTime    bool
	clock         PdClientClock
}

func (r *retxTracker) start(initialTimeoutMs, maxTimeoutMs uint32, maxCount uint16, endTimeMs *int64) {
	// Generate a new transaction ID different from current.
	old := r.transactionID
	for {
		r.generateTransactionID()
		if r.transactionID != old {
			break
		}
	}

	r.startTimeMs = r.clock.NowMs()
	r.maxTimeoutMs = maxTimeoutMs
	r.count = 0
	r.maxCount = maxCount

	if endTimeMs != nil {
		r.hasEndTime = true
		r.endTimeMs = *endTimeMs
	} else {
		r.hasEndTime = false
	}

	// Apply positive jitter for first timeout: [value, value * 1.1]
	r.timeoutMs = r.addPositiveJitter(initialTimeoutMs)
}

func (r *retxTracker) generateTransactionID() {
	// Use the clock's random to fill the transaction ID deterministically in tests.
	v := r.clock.RandomInt63n(1 << 24)
	r.transactionID[0] = byte(v >> 16)
	r.transactionID[1] = byte(v >> 8)
	r.transactionID[2] = byte(v)
}

func (r *retxTracker) addPositiveJitter(value uint32) uint32 {
	jitter := value / 10
	if jitter == 0 {
		return value
	}
	return value + uint32(r.clock.RandomInt63n(int64(jitter)))
}

func (r *retxTracker) addFullJitter(value uint32) uint32 {
	jitter := value / 10
	if jitter == 0 {
		return value
	}
	// Range: [value * 0.9, value * 1.1]
	return value - jitter + uint32(r.clock.RandomInt63n(int64(2*jitter)))
}

// nextTimeout returns the current timeout as a Duration and then updates
// the timeout for the next retransmission using exponential backoff with jitter.
func (r *retxTracker) nextTimeout() time.Duration {
	current := r.timeoutMs

	// RFC 8415 Section 15: RT = 2*RTprev + RAND*RTprev
	// Interpreted as RT = RTprev + (RTprev + RAND*RTprev)
	r.timeoutMs += r.addFullJitter(r.timeoutMs)

	if r.maxTimeoutMs != 0 && r.timeoutMs > r.maxTimeoutMs {
		r.timeoutMs = r.addFullJitter(r.maxTimeoutMs)
	}

	if r.count < 0xFFFF {
		r.count++
	}

	d := time.Duration(current) * time.Millisecond

	// If we have an end time, clamp the duration.
	if r.hasEndTime {
		now := r.clock.NowMs()
		remaining := time.Duration(r.endTimeMs-now) * time.Millisecond
		if remaining < 0 {
			remaining = 0
		}
		if d > remaining {
			d = remaining
		}
	}

	return d
}

func (r *retxTracker) isExhausted() bool {
	if r.maxCount != 0 && r.count >= r.maxCount {
		return true
	}
	if r.hasEndTime && r.clock.NowMs() >= r.endTimeMs {
		return true
	}
	return false
}

func (r *retxTracker) elapsedTimeHundredths() uint16 {
	if r.count == 0 {
		return 0
	}
	ms := r.clock.NowMs() - r.startTimeMs
	hundredths := ms / 10
	if hundredths > 0xFFFF {
		return 0xFFFF
	}
	return uint16(hundredths)
}

func (r *retxTracker) isFirstAttempt() bool {
	return r.count <= 1
}

// ---------------------------------------------------------------------------
// pdPrefix (internal representation with extra methods)
// ---------------------------------------------------------------------------

type pdPrefix struct {
	DelegatedPrefix
}

func (p *pdPrefix) isValid() bool {
	return p.PrefixLength != 0
}

func (p *pdPrefix) clear() {
	*p = pdPrefix{}
}

func (p *pdPrefix) matches(other *pdPrefix) bool {
	return p.Prefix == other.Prefix && p.PrefixLength == other.PrefixLength
}

func (p *pdPrefix) determineT1TimeMs() int64 {
	return p.UpdateTimeMs + int64(p.T1)*1000
}

func (p *pdPrefix) determineT2TimeMs() int64 {
	return p.UpdateTimeMs + int64(p.T2)*1000
}

func (p *pdPrefix) determinePreferredTimeMs() int64 {
	return p.UpdateTimeMs + int64(p.PreferredLifetime)*1000
}

func (p *pdPrefix) adjustLifetimesT1AndT2() {
	// Limit preferred lifetime to pdMaxPreferredLifetime.
	if p.PreferredLifetime > pdMaxPreferredLifetime {
		p.PreferredLifetime = pdMaxPreferredLifetime
	}

	// Valid lifetime at most preferred + margin.
	maxValid := p.PreferredLifetime + pdMaxValidMarginAfterPreferredLifetime
	if p.ValidLifetime > maxValid {
		p.ValidLifetime = maxValid
	}

	// Default T1 and T2 if zero.
	if p.T1 == 0 {
		p.T1 = p.PreferredLifetime * pdDefaultT1FactorNumerator / pdDefaultT1FactorDenominator
	}
	if p.T2 == 0 {
		p.T2 = p.PreferredLifetime * pdDefaultT2FactorNumerator / pdDefaultT2FactorDenominator
	}

	switch {
	case p.PreferredLifetime >= pdMinPreferredLifetime:
		p.T1 = clampUint32(p.T1, pdMinT1, p.PreferredLifetime-pdMinT1MarginBeforePreferredLifetime)
		p.T2 = clampUint32(p.T2, p.T1, p.PreferredLifetime-pdMinT2MarginBeforePreferredLifetime)
	case p.PreferredLifetime >= pdMinT1:
		p.T1 = clampUint32(p.T1, pdMinT1, p.PreferredLifetime)
		p.T2 = clampUint32(p.T2, p.T1, p.PreferredLifetime)
	default:
		p.T1 = p.PreferredLifetime
		p.T2 = p.PreferredLifetime
	}
}

// ---------------------------------------------------------------------------
// PdClient
// ---------------------------------------------------------------------------

// PdClient implements a DHCPv6 Prefix Delegation client per RFC 8415.
type PdClient struct {
	state             PdClientState
	transport         PdClientTransport
	callback          PdClientCallback
	clock             PdClientClock
	timer             PdTimer
	extAddr           [8]byte // client EUI-64 for DUID-LL
	retx              retxTracker
	maxSolicitTimeout uint32 // updated by SOL_MAX_RT option (ms)
	prefix            *pdPrefix
	serverDuid        []byte   // selected server's DUID (up to 130 bytes)
	serverAddr        [16]byte // server unicast address
	hasServerAddr     bool
	pdPrefixCommitted bool
}

// NewPdClient creates a new DHCPv6 PD client.
func NewPdClient(transport PdClientTransport, callback PdClientCallback, extAddr [8]byte, opts ...PdClientOption) *PdClient {
	pc := &PdClient{
		state:             PdStateStopped,
		transport:         transport,
		callback:          callback,
		extAddr:           extAddr,
		maxSolicitTimeout: pdDefaultMaxSolicitTimeout,
	}

	for _, opt := range opts {
		opt(pc)
	}

	if pc.clock == nil {
		pc.clock = &defaultPdClock{}
	}

	pc.retx.clock = pc.clock
	pc.timer = pc.clock.NewTimer(pc.handleTimer)

	return pc
}

// Start begins the PD client. It enters ToSolicit state with a random delay.
func (pc *PdClient) Start() {
	switch pc.state {
	case PdStateStopped:
		pc.transport.SetDhcp6ListeningEnabled(true)
		pc.enterState(PdStateToSolicit)
	case PdStateReleasing:
		pc.enterState(PdStateToSolicit)
	default:
		// Already running, do nothing.
	}
}

// Stop stops the PD client. If it has a committed prefix, it enters Releasing.
func (pc *PdClient) Stop() {
	switch pc.state {
	case PdStateStopped, PdStateReleasing:
		// Already stopped or releasing.
	case PdStateToSolicit, PdStateSoliciting, PdStateRequesting:
		pc.enterState(PdStateStopped)
	case PdStateToRenew, PdStateRenewing, PdStateRebinding:
		pc.enterState(PdStateReleasing)
	}
}

// GetState returns the current state of the PD client.
func (pc *PdClient) GetState() PdClientState {
	return pc.state
}

// GetDelegatedPrefix returns the currently delegated prefix, or nil if none.
func (pc *PdClient) GetDelegatedPrefix() *DelegatedPrefix {
	if pc.pdPrefixCommitted && pc.prefix != nil {
		dp := pc.prefix.DelegatedPrefix
		return &dp
	}
	return nil
}

// HandleReceive processes an incoming DHCPv6 message.
func (pc *PdClient) HandleReceive(payload []byte, src [16]byte) {
	// Only process in states that expect incoming messages.
	switch pc.state {
	case PdStateSoliciting, PdStateRequesting, PdStateRenewing, PdStateRebinding, PdStateReleasing:
		// OK
	default:
		return
	}

	if len(payload) < HeaderSize {
		return
	}

	var hdr Header
	if err := hdr.UnmarshalBinary(payload); err != nil {
		return
	}

	// Verify message type is appropriate for current state.
	switch hdr.Type {
	case MsgTypeAdvertise:
		if pc.state != PdStateSoliciting {
			return
		}
	case MsgTypeReply:
		if pc.state == PdStateSoliciting {
			return
		}
	default:
		return
	}

	// Verify transaction ID.
	if hdr.TransactionID != pc.retx.transactionID {
		return
	}

	optionData := payload[HeaderSize:]

	// Validate Client ID matches ours.
	clientIDOpt := FindOptionInBytes(optionData, OptionCodeClientID)
	if clientIDOpt == nil {
		return
	}
	var clientDUID Eui64DUID
	if err := clientDUID.UnmarshalBinary(clientIDOpt.Data); err != nil {
		return
	}
	var expectedDUID Eui64DUID
	expectedDUID.Init(pc.extAddr)
	if clientDUID != expectedDUID {
		return
	}

	// Must have Server ID.
	serverIDOpt := FindOptionInBytes(optionData, OptionCodeServerID)
	if serverIDOpt == nil {
		return
	}

	// If we have selected a server, ensure DUID matches (except during soliciting).
	if len(pc.serverDuid) > 0 && pc.state != PdStateSoliciting {
		if len(serverIDOpt.Data) != len(pc.serverDuid) {
			return
		}
		for i := range pc.serverDuid {
			if serverIDOpt.Data[i] != pc.serverDuid[i] {
				return
			}
		}
	}

	// Process SOL_MAX_RT option (always, even on failure).
	pc.processSolMaxRtOption(optionData)

	switch hdr.Type {
	case MsgTypeAdvertise:
		pc.handleAdvertise(optionData, src)
	case MsgTypeReply:
		pc.handleReply(optionData, src)
	}
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

func (pc *PdClient) enterState(state PdClientState) {
	pc.state = state

	switch state {
	case PdStateStopped:
		pc.clearServerDuid()
		pc.clearPdPrefix()
		pc.transport.SetDhcp6ListeningEnabled(false)
		pc.timer.Stop()

	case PdStateToSolicit:
		pc.clearServerDuid()
		pc.clearPdPrefix()
		delay := pc.clock.RandomInt63n(pdMaxDelayFirstSolicit)
		pc.timer.Reset(time.Duration(delay) * time.Millisecond)

	case PdStateSoliciting:
		pc.clearServerDuid()
		pc.clearPdPrefix()
		pc.retx.start(pdInitialSolicitTimeout, pc.maxSolicitTimeout, 0, nil)
		pc.sendMessage()

	case PdStateRequesting:
		pc.retx.start(pdInitialRequestTimeout, pdMaxRequestTimeout, pdMaxRequestRetxCount, nil)
		pc.sendMessage()

	case PdStateToRenew:
		if pc.prefix != nil {
			t1Ms := pc.prefix.determineT1TimeMs()
			now := pc.clock.NowMs()
			delay := t1Ms - now
			if delay < 0 {
				delay = 0
			}
			pc.timer.Reset(time.Duration(delay) * time.Millisecond)
		}

	case PdStateRenewing:
		t2Ms := pc.prefix.determineT2TimeMs()
		pc.retx.start(pdInitialRenewTimeout, pdMaxRenewTimeout, 0, &t2Ms)
		pc.sendMessage()

	case PdStateRebinding:
		pc.clearServerDuid()
		prefMs := pc.prefix.determinePreferredTimeMs()
		pc.retx.start(pdInitialRebindTimeout, pdMaxRebindTimeout, 0, &prefMs)
		pc.sendMessage()

	case PdStateReleasing:
		// Notify callback that the prefix is being removed before sending Release.
		if pc.pdPrefixCommitted && pc.prefix != nil && pc.callback != nil {
			dp := pc.prefix.DelegatedPrefix
			dp.PreferredLifetime = 0
			dp.ValidLifetime = 0
			dp.T1 = 0
			dp.T2 = 0
			pc.callback(&dp)
		}
		pc.pdPrefixCommitted = false
		pc.retx.start(pdInitialReleaseTimeout, 0, pdMaxReleaseRetxCount, nil)
		pc.sendMessage()
	}
}

func (pc *PdClient) handleTimer() {
	switch pc.state {
	case PdStateStopped:
		return

	case PdStateToSolicit:
		pc.enterState(PdStateSoliciting)

	case PdStateSoliciting:
		// If we got a favored prefix from Advertise, enter Requesting.
		if pc.prefix != nil && pc.prefix.isValid() {
			pc.enterState(PdStateRequesting)
			return
		}
		pc.sendMessage()

	case PdStateRequesting:
		pc.sendMessage()

	case PdStateToRenew:
		pc.enterState(PdStateRenewing)

	case PdStateRenewing:
		pc.sendMessage()

	case PdStateRebinding:
		pc.sendMessage()

	case PdStateReleasing:
		pc.sendMessage()
	}
}

func (pc *PdClient) sendMessage() {
	var msgType MsgType

	switch pc.state {
	case PdStateSoliciting:
		msgType = MsgTypeSolicit
	case PdStateRequesting:
		msgType = MsgTypeRequest
	case PdStateRenewing:
		msgType = MsgTypeRenew
	case PdStateRebinding:
		msgType = MsgTypeRebind
	case PdStateReleasing:
		msgType = MsgTypeRelease
	default:
		return
	}

	// Check if retransmissions are exhausted.
	if pc.retx.isExhausted() {
		pc.updateStateAfterRetxExhausted()
		return
	}

	// Build and send the message.
	payload := pc.buildMessage(msgType)
	if payload == nil {
		// Failed to build; schedule a short retry.
		pc.timer.Reset(time.Duration(pdRetxDelayOnFailedTx) * time.Millisecond)
		return
	}

	// Determine destination.
	var dst [16]byte
	if pc.hasServerAddr {
		dst = pc.serverAddr
	} else {
		copy(dst[:], AllDHCPRelayAgentsAndServers[:])
	}

	if err := pc.transport.SendDhcp6(payload, dst); err != nil {
		pc.timer.Reset(time.Duration(pdRetxDelayOnFailedTx) * time.Millisecond)
		return
	}

	// Schedule next retransmission.
	d := pc.retx.nextTimeout()
	pc.timer.Reset(d)
}

func (pc *PdClient) updateStateAfterRetxExhausted() {
	switch pc.state {
	case PdStateRequesting:
		pc.enterState(PdStateSoliciting)
	case PdStateRenewing:
		pc.enterState(PdStateRebinding)
	case PdStateRebinding:
		pc.enterState(PdStateSoliciting)
	case PdStateReleasing:
		pc.enterState(PdStateStopped)
	default:
		// Nothing to do.
	}
}

// ---------------------------------------------------------------------------
// Message building
// ---------------------------------------------------------------------------

func (pc *PdClient) buildMessage(msgType MsgType) []byte {
	hdr := Header{
		Type:          msgType,
		TransactionID: pc.retx.transactionID,
	}
	hdrBytes, err := hdr.MarshalBinary()
	if err != nil {
		return nil
	}

	buf := make([]byte, 0, 256)
	buf = append(buf, hdrBytes...)

	// Client ID.
	var clientDUID Eui64DUID
	clientDUID.Init(pc.extAddr)
	buf = AppendClientIDOption(buf, &clientDUID)

	// Server ID (for Request, Renew, Release).
	if len(pc.serverDuid) > 0 {
		buf = AppendServerIDOptionRaw(buf, pc.serverDuid)
	}

	// Elapsed Time.
	buf = AppendElapsedTimeOption(buf, pc.retx.elapsedTimeHundredths())

	// Option Request (SOL_MAX_RT).
	oro := make([]byte, 2)
	binary.BigEndian.PutUint16(oro, uint16(OptionCodeSolMaxRt))
	buf = AppendOption(buf, OptionCodeOptionReq, oro)

	// IA_PD.
	buf = pc.appendIaPdOption(buf)

	return buf
}

func (pc *PdClient) appendIaPdOption(buf []byte) []byte {
	// Build IA_PD with IAID=0, T1=0, T2=0.
	iapd := IaPd{
		IAID: 0,
		T1:   0,
		T2:   0,
	}

	// Build sub-options: an IA_Prefix hint.
	var subOpts []byte
	if pc.prefix != nil && pc.prefix.isValid() {
		// Include the current prefix as a hint.
		iap := IaPrefix{
			PreferredLifetime: 0,
			ValidLifetime:     0,
			PrefixLength:      pc.prefix.PrefixLength,
			Prefix:            pc.prefix.Prefix,
		}
		subOpts = AppendIaPrefixOption(subOpts, &iap)
	} else {
		// Request a /64 prefix.
		iap := IaPrefix{
			PreferredLifetime: 0,
			ValidLifetime:     0,
			PrefixLength:      64,
		}
		subOpts = AppendIaPrefixOption(subOpts, &iap)
	}

	iapd.SubOptions = subOpts
	return AppendIaPdOption(buf, &iapd)
}

// ---------------------------------------------------------------------------
// Receive handling
// ---------------------------------------------------------------------------

func (pc *PdClient) handleAdvertise(optionData []byte, src [16]byte) {
	// Check top-level status.
	status, err := ReadStatusFrom(optionData)
	if err != nil || status != StatusSuccess {
		return
	}

	// Parse IA_PD options to find prefixes.
	prefixes := pc.processIaPd(optionData)
	if len(prefixes) == 0 {
		return
	}

	favored := pc.selectFavoredPrefix(prefixes)
	if favored == nil {
		return
	}

	// Read preference.
	preference := pc.readPreference(optionData)

	// If this is the first attempt and we already have a tracked favored
	// prefix, only update if the new one is more preferred (numerically smaller).
	if pc.retx.isFirstAttempt() && len(pc.serverDuid) > 0 {
		if !prefixLessThan(favored.AdjustedPrefix, pc.prefix.AdjustedPrefix) {
			return
		}
	}

	// Save the favored prefix.
	if pc.prefix == nil {
		pc.prefix = &pdPrefix{}
	}
	pc.prefix.DelegatedPrefix = favored.DelegatedPrefix

	// Save server DUID and address.
	pc.saveServerDuidAndAddress(optionData, src)

	// If not first attempt or preference is max, immediately request.
	if !pc.retx.isFirstAttempt() || preference == 255 {
		pc.enterState(PdStateRequesting)
	}
}

func (pc *PdClient) handleReply(optionData []byte, src [16]byte) {
	status, _ := ReadStatusFrom(optionData)

	if status == StatusUnspecFail {
		return
	}

	if status == StatusUseMulticast {
		if pc.hasServerAddr {
			pc.hasServerAddr = false
			pc.serverAddr = [16]byte{}
			pc.sendMessage()
		}
		return
	}

	if pc.state == PdStateReleasing {
		// Per RFC 8415 Section 18.2.10.2: any Reply to Release completes it.
		pc.state = PdStateStopped
		pc.timer.Stop()
		pc.clearServerDuid()
		pc.clearPdPrefix()
		pc.transport.SetDhcp6ListeningEnabled(false)
		return
	}

	prefixes := pc.processIaPd(optionData)
	iapdStatus := pc.readIaPdStatus(optionData)

	if pc.state == PdStateRequesting {
		favored := pc.selectFavoredPrefix(prefixes)
		if iapdStatus == StatusNoPrefixAvail || favored == nil {
			pc.enterState(PdStateToSolicit)
			return
		}

		pc.saveServerDuidAndAddress(optionData, src)
		pc.commitPdPrefix(favored)
		return
	}

	if pc.state == PdStateRenewing || pc.state == PdStateRebinding {
		if iapdStatus == StatusNoPrefixAvail {
			return
		}

		// Try to find matching prefix.
		matched := pc.findMatchingPrefix(prefixes)
		if matched != nil {
			pc.saveServerDuidAndAddress(optionData, src)
			pc.commitPdPrefix(matched)
			if pc.prefix.PreferredLifetime >= pdMinPreferredLifetime {
				return
			}
		}

		// Try any favored prefix.
		favored := pc.selectFavoredPrefix(prefixes)
		if favored != nil {
			pc.saveServerDuidAndAddress(optionData, src)
			pc.commitPdPrefix(favored)
			return
		}

		if iapdStatus == StatusNoBinding && pc.state == PdStateRenewing {
			pc.enterState(PdStateRebinding)
		}
	}
}

// ---------------------------------------------------------------------------
// IA_PD processing
// ---------------------------------------------------------------------------

func (pc *PdClient) processIaPd(optionData []byte) []*pdPrefix {
	var result []*pdPrefix

	opts, err := ParseOptions(optionData)
	if err != nil {
		return nil
	}

	for i := range opts {
		if opts[i].Header.Code != OptionCodeIaPd {
			continue
		}

		var iapd IaPd
		if err := iapd.Unmarshal(opts[i].Data); err != nil {
			continue
		}

		// Skip if IAID doesn't match.
		if iapd.IAID != 0 {
			continue
		}

		// Skip if T1 > T2 and both non-zero.
		if iapd.T1 != 0 && iapd.T2 != 0 && iapd.T1 > iapd.T2 {
			continue
		}

		// Parse IA Prefix sub-options within the IA_PD.
		subOpts, err := ParseOptions(iapd.SubOptions)
		if err != nil {
			continue
		}

		for j := range subOpts {
			if subOpts[j].Header.Code != OptionCodeIaPrefix {
				continue
			}

			var iap IaPrefix
			if err := iap.Unmarshal(subOpts[j].Data); err != nil {
				continue
			}

			// Validate prefix option.
			if iap.PrefixLength > 128 {
				continue
			}
			if iap.PreferredLifetime > iap.ValidLifetime {
				continue
			}

			p := &pdPrefix{}
			p.Prefix = iap.Prefix
			p.PrefixLength = iap.PrefixLength
			p.T1 = iapd.T1
			p.T2 = iapd.T2
			p.PreferredLifetime = iap.PreferredLifetime
			p.ValidLifetime = iap.ValidLifetime
			p.UpdateTimeMs = pc.clock.NowMs()

			// Adjust to /64.
			if iap.PrefixLength <= 64 {
				p.AdjustedPrefix = iap.Prefix
				// Zero bits beyond prefix length up to 64 bits.
				tidyPrefix(&p.AdjustedPrefix, iap.PrefixLength, 64)
				p.AdjustedLength = 64
			} else {
				p.AdjustedPrefix = [16]byte{}
				p.AdjustedLength = 0
			}

			result = append(result, p)
		}

		// Only process the first matching IA_PD.
		break
	}

	return result
}

func (pc *PdClient) selectFavoredPrefix(prefixes []*pdPrefix) *pdPrefix {
	var favored *pdPrefix

	for _, p := range prefixes {
		if p.PrefixLength > 64 {
			continue
		}
		if p.PreferredLifetime < pdMinPreferredLifetime {
			continue
		}
		if favored == nil || prefixLessThan(p.AdjustedPrefix, favored.AdjustedPrefix) {
			favored = p
		}
	}

	return favored
}

func (pc *PdClient) findMatchingPrefix(prefixes []*pdPrefix) *pdPrefix {
	if pc.prefix == nil {
		return nil
	}
	for _, p := range prefixes {
		if p.Prefix == pc.prefix.Prefix && p.PrefixLength == pc.prefix.PrefixLength {
			return p
		}
	}
	return nil
}

func (pc *PdClient) readPreference(optionData []byte) uint8 {
	opt := FindOptionInBytes(optionData, OptionCodePreference)
	if opt == nil {
		return 0
	}
	var p Preference
	if err := p.UnmarshalBinary(opt.Data); err != nil {
		return 0
	}
	return p.Value
}

func (pc *PdClient) readIaPdStatus(optionData []byte) StatusCodeValue {
	opts, err := ParseOptions(optionData)
	if err != nil {
		return StatusSuccess
	}

	for i := range opts {
		if opts[i].Header.Code != OptionCodeIaPd {
			continue
		}
		var iapd IaPd
		if err := iapd.Unmarshal(opts[i].Data); err != nil {
			continue
		}
		if iapd.IAID != 0 {
			continue
		}
		status, err := ReadStatusFrom(iapd.SubOptions)
		if err != nil {
			return StatusSuccess
		}
		return status
	}

	return StatusSuccess
}

// ---------------------------------------------------------------------------
// SOL_MAX_RT processing
// ---------------------------------------------------------------------------

func (pc *PdClient) processSolMaxRtOption(optionData []byte) {
	opt := FindOptionInBytes(optionData, OptionCodeSolMaxRt)
	if opt == nil {
		return
	}

	var smr SolMaxRt
	if err := smr.Unmarshal(opt.Data); err != nil {
		return
	}

	if !smr.IsValid() {
		return
	}

	solMaxRtMs := smr.Value * 1000

	if pc.maxSolicitTimeout == pdDefaultMaxSolicitTimeout {
		pc.maxSolicitTimeout = solMaxRtMs
	} else if solMaxRtMs != pc.maxSolicitTimeout {
		pc.maxSolicitTimeout = pdDefaultMaxSolicitTimeout
	}

	if pc.state == PdStateSoliciting {
		pc.retx.maxTimeoutMs = pc.maxSolicitTimeout
	}
}

// ---------------------------------------------------------------------------
// Server DUID / address management
// ---------------------------------------------------------------------------

func (pc *PdClient) saveServerDuidAndAddress(optionData []byte, src [16]byte) {
	serverIDOpt := FindOptionInBytes(optionData, OptionCodeServerID)
	if serverIDOpt == nil {
		return
	}
	pc.serverDuid = make([]byte, len(serverIDOpt.Data))
	copy(pc.serverDuid, serverIDOpt.Data)

	// Check for Server Unicast option.
	unicastOpt := FindOptionInBytes(optionData, OptionCodeServerUnicast)
	if unicastOpt != nil && len(unicastOpt.Data) >= 16 {
		copy(pc.serverAddr[:], unicastOpt.Data[:16])
		pc.hasServerAddr = true
	}
}

func (pc *PdClient) clearServerDuid() {
	pc.serverDuid = nil
	pc.serverAddr = [16]byte{}
	pc.hasServerAddr = false
}

func (pc *PdClient) clearPdPrefix() {
	if pc.pdPrefixCommitted && pc.prefix != nil && pc.callback != nil {
		// Report removal with zero lifetimes.
		dp := pc.prefix.DelegatedPrefix
		dp.PreferredLifetime = 0
		dp.ValidLifetime = 0
		dp.T1 = 0
		dp.T2 = 0
		pc.callback(&dp)
	}

	pc.prefix = nil
	pc.pdPrefixCommitted = false
}

func (pc *PdClient) commitPdPrefix(p *pdPrefix) {
	if pc.prefix != nil && !pc.prefix.matches(p) {
		pc.clearPdPrefix()
	}

	if pc.prefix == nil {
		pc.prefix = &pdPrefix{}
	}
	pc.prefix.DelegatedPrefix = p.DelegatedPrefix
	pc.prefix.adjustLifetimesT1AndT2()
	pc.pdPrefixCommitted = true

	pc.enterState(PdStateToRenew)

	if pc.callback != nil {
		dp := pc.prefix.DelegatedPrefix
		pc.callback(&dp)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func prefixLessThan(a, b [16]byte) bool {
	for i := 0; i < 16; i++ {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return false
}

func clampUint32(v, minimum, maximum uint32) uint32 {
	if v < minimum {
		return minimum
	}
	if v > maximum {
		return maximum
	}
	return v
}

// tidyPrefix zeros bits in prefix from fromLen to toLen.
func tidyPrefix(prefix *[16]byte, fromLen, toLen uint8) {
	// Zero out bits from fromLen to toLen (which should be >= fromLen).
	// This masks out any bits that shouldn't be part of the prefix.
	for bit := fromLen; bit < toLen && bit < 128; bit++ {
		byteIdx := bit / 8
		bitIdx := 7 - (bit % 8)
		prefix[byteIdx] &^= 1 << bitIdx
	}
}

// ---------------------------------------------------------------------------
// Default clock implementation using real time
// ---------------------------------------------------------------------------

type defaultPdClock struct{}

func (c *defaultPdClock) NowMs() int64 {
	return time.Now().UnixMilli()
}

func (c *defaultPdClock) NewTimer(fn func()) PdTimer {
	return &defaultPdTimer{fn: fn}
}

func (c *defaultPdClock) RandomInt63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(time.Now().UnixNano()))
	return int64(binary.BigEndian.Uint64(buf[:]) % uint64(n))
}

type defaultPdTimer struct {
	fn    func()
	timer *time.Timer
}

func (t *defaultPdTimer) Reset(d time.Duration) {
	if t.timer != nil {
		t.timer.Stop()
	}
	t.timer = time.AfterFunc(d, t.fn)
}

func (t *defaultPdTimer) Stop() bool {
	if t.timer != nil {
		return t.timer.Stop()
	}
	return false
}
