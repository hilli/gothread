// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"fmt"
	"time"
)

// parentRequestType controls which devices should respond to a Parent Request.
type parentRequestType uint8

const (
	// parentRequestRouters sends Parent Requests to routers only.
	parentRequestRouters parentRequestType = 0
	// parentRequestRoutersAndREEDs sends Parent Requests to both routers and REEDs.
	parentRequestRoutersAndREEDs parentRequestType = 1
)

// Attach cycle constants. These mirror OpenThread's kFirstAttachCycle* and
// kNextAttachCycle* constants.
const (
	// firstCycleTotalRequests is the total Parent Requests in the first cycle.
	firstCycleTotalRequests = 3
	// firstCycleRouterOnlyRequests is how many of those go to routers only.
	firstCycleRouterOnlyRequests = 1
	// nextCycleTotalRequests is the total Parent Requests in subsequent cycles.
	nextCycleTotalRequests = 1
	// nextCycleRouterOnlyRequests is how many go to routers only.
	nextCycleRouterOnlyRequests = 1
)

// Attacher implements the MLE attach state machine.
//
// It drives the flow: Start -> ParentRequest (routers) -> ParentRequest
// (routers + REEDs) -> ChildIDRequest -> attached as Child.
//
// This is a Go port of OpenThread's Mle::Attacher class.
type Attacher struct {
	mle        *Mle
	dispatcher *Dispatcher

	// challenge is the random challenge sent in Parent Requests.
	challenge Challenge

	// candidate is the best parent candidate received so far.
	candidate ParentCandidate
	// hasCandidate indicates whether a valid candidate exists.
	hasCandidate bool

	// parentRequestCounter counts how many Parent Requests have been
	// sent in the current attach cycle.
	parentRequestCounter uint8

	// attachCounter counts attach cycles.
	attachCounter uint8

	// lastTimerFire is when HandleTimer was last called (for testing).
	lastTimerFire time.Time

	// NextTimerDelay is the requested delay until the next HandleTimer
	// call. Zero means no timer is pending. Callers are responsible for
	// scheduling the actual timer based on this value.
	NextTimerDelay time.Duration
}

// NewAttacher creates a new Attacher bound to the given Mle state machine
// and Dispatcher.
func NewAttacher(mle *Mle, dispatcher *Dispatcher) *Attacher {
	return &Attacher{
		mle:        mle,
		dispatcher: dispatcher,
	}
}

// Start begins the attach process with the given mode.
// It resets state, generates a challenge, and arms the timer.
func (a *Attacher) Start(mode AttachMode) error {
	if err := a.mle.StartAttach(mode); err != nil {
		return err
	}

	a.hasCandidate = false
	a.parentRequestCounter = 0
	a.attachCounter++
	a.challenge.GenerateChallenge()

	// Start with a small delay before sending the first Parent Request.
	a.NextTimerDelay = AttachStartJitter
	return nil
}

// GetCandidate returns the current parent candidate and whether one exists.
func (a *Attacher) GetCandidate() (*ParentCandidate, bool) {
	return &a.candidate, a.hasCandidate
}

// HandleTimer advances the attach state machine. It should be called when
// the timer armed by NextTimerDelay fires.
//
// Returns an error if a protocol error occurs during state advancement.
func (a *Attacher) HandleTimer() error {
	a.lastTimerFire = time.Now()
	a.NextTimerDelay = 0

	state := a.mle.GetAttachState()

	// If we have an acceptable candidate, proceed to Child ID Request.
	if a.hasAcceptableCandidate() {
		return a.sendChildIDRequest()
	}

	switch state {
	case AttachStateIdle:
		// Timer fired after successful attach; nothing to do.
		return nil

	case AttachStateStart:
		// Transition to sending Parent Requests.
		a.hasCandidate = false
		a.parentRequestCounter = 0
		a.mle.SetAttachState(AttachStateParentRequest)
		return a.handleParentRequestState()

	case AttachStateParentRequest:
		return a.handleParentRequestState()

	case AttachStateChildIDRequest:
		// Timed out waiting for Child ID Response. Attach failed.
		a.mle.SetAttachState(AttachStateIdle)
		a.hasCandidate = false
		return fmt.Errorf("mle: attach timeout waiting for Child ID Response")

	case AttachStateAnnounce:
		// Announce processing complete — reset state and start a fresh attach.
		a.mle.SetAttachState(AttachStateIdle)
		a.hasCandidate = false
		return a.Start(AttachAnyPartition)

	default:
		return fmt.Errorf("mle: unexpected attach state: %s", state)
	}
}

// handleParentRequestState sends the next Parent Request or transitions
// when all requests for this cycle are exhausted.
func (a *Attacher) handleParentRequestState() error {
	a.parentRequestCounter++

	reqType, ok := a.determineParentRequestType()
	if !ok {
		// All Parent Requests sent, no acceptable candidate found.
		a.mle.SetAttachState(AttachStateIdle)
		a.hasCandidate = false
		return fmt.Errorf("mle: attach failed: no parent response received")
	}

	return a.sendParentRequest(reqType)
}

// determineParentRequestType decides what type of Parent Request to send
// based on the current attach cycle and request counter.
//
// Returns the request type and true if a request should be sent, or
// false if all requests for this cycle have been exhausted.
func (a *Attacher) determineParentRequestType() (parentRequestType, bool) {
	mode := a.mle.GetAttachMode()

	// SelectedParent mode sends a single request to routers.
	if mode == AttachSelectedParent {
		if a.parentRequestCounter > 1 {
			return 0, false
		}
		return parentRequestRouters, true
	}

	var totalRequests, routerOnlyRequests uint8

	if a.attachCounter <= 1 && mode != AttachBetterParent {
		totalRequests = firstCycleTotalRequests
		routerOnlyRequests = firstCycleRouterOnlyRequests
	} else {
		totalRequests = nextCycleTotalRequests
		routerOnlyRequests = nextCycleRouterOnlyRequests
	}

	if a.parentRequestCounter > totalRequests {
		return 0, false
	}

	// SamePartition always includes REEDs.
	if mode == AttachSamePartition {
		return parentRequestRoutersAndREEDs, true
	}

	if a.parentRequestCounter <= routerOnlyRequests {
		return parentRequestRouters, true
	}

	return parentRequestRoutersAndREEDs, true
}

// hasAcceptableCandidate reports whether the current candidate is good
// enough to proceed to Child ID Request.
func (a *Attacher) hasAcceptableCandidate() bool {
	if !a.hasCandidate {
		return false
	}

	// During the router-only phase, require link quality 3 to accept early.
	reqType, ok := a.determineParentRequestType()
	if ok && reqType == parentRequestRouters {
		lq := LinkQualityForLinkMargin(a.candidate.LinkMargin)
		return lq >= 3
	}

	return true
}

// sendParentRequest constructs and sends an MLE Parent Request message.
//
// TLVs: Mode, Challenge, ScanMask, Version.
// Destination: link-local all-routers multicast.
func (a *Attacher) sendParentRequest(reqType parentRequestType) error {
	msg := NewMessage(CommandParentRequest)

	msg.AppendModeTLV(a.mle.GetDeviceMode())
	msg.AppendChallengeTLV(a.challenge)

	var scanMask uint8
	switch reqType {
	case parentRequestRouters:
		scanMask = ScanMaskRouterFlag
	case parentRequestRoutersAndREEDs:
		scanMask = ScanMaskRouterFlag | ScanMaskEndDeviceFlag
	}
	msg.AppendScanMaskTLV(scanMask)

	msg.AppendVersionTLV(ThreadVersion)

	dstIP := a.dispatcher.transport.GetLinkLocalAllRoutersMulticast()

	if err := a.dispatcher.SendMessage(msg, dstIP); err != nil {
		return fmt.Errorf("mle: send parent request: %w", err)
	}

	// Arm the timer based on request type.
	switch reqType {
	case parentRequestRouters:
		a.NextTimerDelay = ParentRequestRouterTimeout
	case parentRequestRoutersAndREEDs:
		a.NextTimerDelay = ParentRequestReedTimeout
	}

	return nil
}

// HandleParentResponse processes a received MLE Parent Response.
//
// Required TLVs: SourceAddress, Version, Response, LeaderData,
// LinkMargin, Connectivity, LinkFrameCounter, Challenge.
// Optional TLV: MleFrameCounter.
func (a *Attacher) HandleParentResponse(rxInfo *RxInfo) error {
	state := a.mle.GetAttachState()
	if state == AttachStateChildIDRequest {
		// Already sent Child ID Request; ignore late Parent Responses.
		return nil
	}

	if state != AttachStateParentRequest {
		return fmt.Errorf("mle: parent response in unexpected state: %s", state)
	}

	// Parse required TLVs.
	srcAddrVal, ok := FindTLV(rxInfo.TLVs, TLVSourceAddress)
	if !ok {
		return fmt.Errorf("mle: parent response missing SourceAddress TLV")
	}
	sourceAddress, err := ReadSourceAddressTLV(srcAddrVal)
	if err != nil {
		return err
	}

	versionVal, ok := FindTLV(rxInfo.TLVs, TLVVersion)
	if !ok {
		return fmt.Errorf("mle: parent response missing Version TLV")
	}
	version, err := ReadVersionTLV(versionVal)
	if err != nil {
		return err
	}

	responseVal, ok := FindTLV(rxInfo.TLVs, TLVResponse)
	if !ok {
		return fmt.Errorf("mle: parent response missing Response TLV")
	}
	if !a.verifyResponse(responseVal) {
		return fmt.Errorf("mle: parent response challenge mismatch")
	}

	leaderDataVal, ok := FindTLV(rxInfo.TLVs, TLVLeaderData)
	if !ok {
		return fmt.Errorf("mle: parent response missing LeaderData TLV")
	}
	leaderData, err := ReadLeaderDataTLV(leaderDataVal)
	if err != nil {
		return err
	}

	linkMarginVal, ok := FindTLV(rxInfo.TLVs, TLVLinkMargin)
	if !ok {
		return fmt.Errorf("mle: parent response missing LinkMargin TLV")
	}
	linkMarginOut, err := ReadLinkMarginTLV(linkMarginVal)
	if err != nil {
		return err
	}

	connVal, ok := FindTLV(rxInfo.TLVs, TLVConnectivity)
	if !ok {
		return fmt.Errorf("mle: parent response missing Connectivity TLV")
	}
	connectivity, err := ReadConnectivityTLV(connVal)
	if err != nil {
		return err
	}

	linkFCVal, ok := FindTLV(rxInfo.TLVs, TLVLinkFrameCounter)
	if !ok {
		return fmt.Errorf("mle: parent response missing LinkFrameCounter TLV")
	}
	linkFrameCounter, err := ReadLinkFrameCounterTLV(linkFCVal)
	if err != nil {
		return err
	}

	// MLE frame counter defaults to link frame counter if not present.
	mleFrameCounter := linkFrameCounter
	if mleFCVal, ok := FindTLV(rxInfo.TLVs, TLVMleFrameCounter); ok {
		mleFrameCounter, err = ReadMleFrameCounterTLV(mleFCVal)
		if err != nil {
			return err
		}
	}

	challengeVal, ok := FindTLV(rxInfo.TLVs, TLVChallenge)
	if !ok {
		return fmt.Errorf("mle: parent response missing Challenge TLV")
	}
	rxChallenge, err := ReadChallengeTLV(challengeVal)
	if err != nil {
		return err
	}

	// Compute two-way link margin = min(local link margin, reported margin).
	twoWayLinkMargin := rxInfo.LinkMarginRaw
	if linkMarginOut < twoWayLinkMargin {
		twoWayLinkMargin = linkMarginOut
	}

	// Compare with current candidate.
	if a.hasCandidate {
		currentLQ := LinkQualityForLinkMargin(a.candidate.LinkMargin)
		if !IsBetterParent(
			twoWayLinkMargin,
			sourceAddress,
			connectivity,
			version,
			currentLQ,
			a.candidate.RLOC16,
			a.candidate.Connectivity,
			a.candidate.ThreadVersion,
			a.candidate.LinkMargin,
		) {
			// Current candidate is at least as good; keep it.
			return nil
		}
	}

	// Accept this candidate.
	a.candidate = ParentCandidate{
		Connectivity:  connectivity,
		LinkMargin:    twoWayLinkMargin,
		ThreadVersion: version,
		RxChallenge:   rxChallenge,
	}
	a.candidate.MacAddr = rxInfo.SrcAddr
	a.candidate.RLOC16 = sourceAddress
	a.candidate.State = StateParentResponse
	a.candidate.Version = version
	a.candidate.Counters.LinkFrameCounter = linkFrameCounter
	a.candidate.Counters.MleFrameCounter = mleFrameCounter
	a.candidate.KeySequence = rxInfo.KeySequence
	a.candidate.LeaderCost = connectivity.LeaderCost

	// Store leader data from this candidate.
	a.mle.SetLeaderData(leaderData)

	a.hasCandidate = true

	return nil
}

// sendChildIDRequest constructs and sends an MLE Child ID Request to
// the best parent candidate.
//
// TLVs: Response, LinkFrameCounter, MleFrameCounter, Mode, Timeout,
// Version, TLVRequest[Address16, NetworkData, Route].
func (a *Attacher) sendChildIDRequest() error {
	if !a.hasCandidate {
		return fmt.Errorf("mle: no parent candidate for Child ID Request")
	}

	a.mle.SetAttachState(AttachStateChildIDRequest)

	msg := NewMessage(CommandChildIDRequest)

	// Echo the parent's challenge.
	msg.AppendResponseTLV(a.candidate.RxChallenge[:])

	// Frame counters.
	msg.AppendLinkFrameCounterTLV(a.dispatcher.keyMgr.GetMacFrameCounter())
	msg.AppendMleFrameCounterTLV(a.dispatcher.keyMgr.GetMleFrameCounter())

	// Device mode.
	msg.AppendModeTLV(a.mle.GetDeviceMode())

	// Child timeout.
	msg.AppendTimeoutTLV(a.mle.GetChildTimeout())

	// Version.
	msg.AppendVersionTLV(ThreadVersion)

	// TLV Request: ask for Address16, NetworkData, and Route64 (FTD).
	requestedTLVs := []uint8{TLVAddress16, TLVNetworkData, TLVRoute64}
	if !a.mle.GetDeviceMode().IsFullThreadDevice() {
		// MTDs don't request the Route TLV.
		requestedTLVs = requestedTLVs[:2]
	}
	msg.AppendTLVRequestTLV(requestedTLVs)

	// Mark the candidate as valid (we're sending the request).
	a.candidate.State = StateValid

	// Copy candidate into the Mle's parent candidate slot.
	pc := a.mle.GetParentCandidate()
	pc.Router = a.candidate.Router
	pc.LeaderCost = a.candidate.LeaderCost

	// Send unicast to the candidate parent's link-local address.
	if err := a.dispatcher.SendMessage(msg, a.parentIP()); err != nil {
		return fmt.Errorf("mle: send child ID request: %w", err)
	}

	a.NextTimerDelay = ChildIDResponseTimeout
	return nil
}

// parentIP computes the link-local IPv6 address from the candidate's
// extended MAC address using the EUI-64 to modified EUI-64 conversion.
func (a *Attacher) parentIP() [16]byte {
	var addr [16]byte
	// Link-local prefix: fe80::/10
	addr[0] = 0xfe
	addr[1] = 0x80
	// Bytes [2..7] are zero.
	// Interface identifier from modified EUI-64.
	addr[8] = a.candidate.MacAddr[0] ^ 0x02 // Toggle U/L bit
	addr[9] = a.candidate.MacAddr[1]
	addr[10] = a.candidate.MacAddr[2]
	addr[11] = a.candidate.MacAddr[3]
	addr[12] = a.candidate.MacAddr[4]
	addr[13] = a.candidate.MacAddr[5]
	addr[14] = a.candidate.MacAddr[6]
	addr[15] = a.candidate.MacAddr[7]
	return addr
}

// HandleChildIDResponse processes a received MLE Child ID Response.
//
// Required TLVs: SourceAddress, Address16, LeaderData, NetworkData.
// Optional TLVs: ActiveTimestamp, PendingTimestamp, Route64.
func (a *Attacher) HandleChildIDResponse(rxInfo *RxInfo) error {
	state := a.mle.GetAttachState()
	if state != AttachStateChildIDRequest {
		return fmt.Errorf("mle: child ID response in unexpected state: %s", state)
	}

	// Parse required TLVs.
	srcAddrVal, ok := FindTLV(rxInfo.TLVs, TLVSourceAddress)
	if !ok {
		return fmt.Errorf("mle: child ID response missing SourceAddress TLV")
	}
	sourceAddress, err := ReadSourceAddressTLV(srcAddrVal)
	if err != nil {
		return err
	}

	addr16Val, ok := FindTLV(rxInfo.TLVs, TLVAddress16)
	if !ok {
		return fmt.Errorf("mle: child ID response missing Address16 TLV")
	}
	assignedRLOC16, err := ReadAddress16TLV(addr16Val)
	if err != nil {
		return err
	}

	// The assigned address must belong to the same router as the source.
	if !RouterIDMatch(assignedRLOC16, sourceAddress) {
		return fmt.Errorf("mle: child ID response router ID mismatch: assigned %04X, source %04X",
			assignedRLOC16, sourceAddress)
	}

	leaderDataVal, ok := FindTLV(rxInfo.TLVs, TLVLeaderData)
	if !ok {
		return fmt.Errorf("mle: child ID response missing LeaderData TLV")
	}
	leaderData, err := ReadLeaderDataTLV(leaderDataVal)
	if err != nil {
		return err
	}

	// Network Data TLV must be present (even if empty).
	if _, ok := FindTLV(rxInfo.TLVs, TLVNetworkData); !ok {
		return fmt.Errorf("mle: child ID response missing NetworkData TLV")
	}

	// Finalize attachment:

	// Set leader data.
	a.mle.SetLeaderData(leaderData)

	// Copy candidate to parent.
	parent := a.mle.GetParent()
	parent.Router = a.candidate.Router
	parent.LeaderCost = a.candidate.LeaderCost
	parent.RLOC16 = sourceAddress
	parent.State = StateValid

	// Clear candidate.
	a.hasCandidate = false

	// Transition to Child role.
	if err := a.mle.SetStateChild(assignedRLOC16); err != nil {
		return fmt.Errorf("mle: set state child: %w", err)
	}

	a.NextTimerDelay = 0
	return nil
}

// verifyResponse checks that the received response matches the challenge
// we sent in the Parent Request.
func (a *Attacher) verifyResponse(response []byte) bool {
	if len(response) < ChallengeSize {
		return false
	}
	for i := 0; i < ChallengeSize; i++ {
		if response[i] != a.challenge[i] {
			return false
		}
	}
	return true
}
