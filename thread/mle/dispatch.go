// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"fmt"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/key"
)

// CommandHandler is a function that handles a specific MLE command.
// It receives the parsed RxInfo which contains the command, TLVs,
// source address, and neighbor state.
type CommandHandler func(rxInfo *RxInfo) error

// Dispatcher handles receiving, decrypting, and dispatching MLE messages
// to the appropriate command handlers.
//
// It performs security validation including key sequence checking,
// frame counter validation, and AES-CCM decryption before routing
// to registered handlers.
type Dispatcher struct {
	mle       *Mle
	keyMgr    KeyProvider
	transport Transport

	// handlers maps command codes to their handler functions.
	handlers map[Command]CommandHandler

	// lookupNeighbor resolves a source extended address to a known neighbor.
	// Returns nil if the neighbor is unknown.
	lookupNeighbor func(addr types.ExtAddress) *Neighbor
}

// NewDispatcher creates a new MLE message Dispatcher.
func NewDispatcher(mle *Mle, keyMgr KeyProvider, transport Transport) *Dispatcher {
	return &Dispatcher{
		mle:       mle,
		keyMgr:    keyMgr,
		transport: transport,
		handlers:  make(map[Command]CommandHandler),
	}
}

// RegisterHandler registers a handler for the given MLE command.
func (d *Dispatcher) RegisterHandler(cmd Command, handler CommandHandler) {
	d.handlers[cmd] = handler
}

// SetNeighborLookup sets the function used to resolve source addresses
// to neighbor entries. This is typically provided by the router/child table.
func (d *Dispatcher) SetNeighborLookup(fn func(addr types.ExtAddress) *Neighbor) {
	d.lookupNeighbor = fn
}

// HandleReceive processes a received MLE message from the UDP layer.
//
// It parses the message, performs security validation, decrypts if needed,
// resolves the sender to a neighbor, and dispatches to the registered handler.
//
// This is analogous to OpenThread's Mle::HandleUdpReceive.
func (d *Dispatcher) HandleReceive(data []byte, srcAddr types.ExtAddress, srcIP, dstIP ip6.Address, linkMargin uint8) error {
	// 1. Parse the wire message.
	pm, err := ParseMessage(data)
	if err != nil {
		return fmt.Errorf("mle dispatch: parse: %w", err)
	}

	rxInfo := &RxInfo{
		SrcAddr:       srcAddr,
		SrcIP:         srcIP,
		DstIP:         dstIP,
		LinkMarginRaw: linkMargin,
	}

	// 2. Handle secured vs unsecured messages.
	var payload []byte

	switch pm.SecuritySuite {
	case SecuritySuiteEncMic32:
		rxInfo.IsSecured = true
		rxInfo.KeySequence = pm.SecHeader.KeySource
		rxInfo.FrameCounter = pm.SecHeader.FrameCounter

		// Determine which MLE key to use based on key sequence.
		mleKey, err := d.resolveKey(pm.SecHeader.KeySource)
		if err != nil {
			return fmt.Errorf("mle dispatch: resolve key: %w", err)
		}

		// Decrypt the payload.
		secHdrBytes := pm.SecHeader.Marshal()
		payload, err = pm.DecryptPayload(mleKey, srcAddr, srcIP, dstIP, secHdrBytes)
		if err != nil {
			return fmt.Errorf("mle dispatch: decrypt: %w", err)
		}

	case SecuritySuiteNone:
		rxInfo.IsSecured = false
		payload = pm.Payload

	default:
		return fmt.Errorf("mle dispatch: unknown security suite 0x%02X", pm.SecuritySuite)
	}

	// 3. Parse command and TLVs from the decrypted payload.
	if len(payload) < 1 {
		return fmt.Errorf("mle dispatch: empty payload")
	}

	rxInfo.Command = Command(payload[0])

	if len(payload) > 1 {
		rxInfo.TLVs, err = ParseTLVs(payload[1:])
		if err != nil {
			return fmt.Errorf("mle dispatch: parse TLVs: %w", err)
		}
	}

	// 4. Look up the neighbor.
	if d.lookupNeighbor != nil {
		rxInfo.Neighbor = d.lookupNeighbor(srcAddr)
	}

	// 5. For secured messages, validate frame counter against known neighbor.
	if rxInfo.IsSecured && rxInfo.Neighbor != nil && rxInfo.Neighbor.IsStateValid() {
		if err := d.validateFrameCounter(rxInfo); err != nil {
			return err
		}
	}

	// 6. Dispatch to the registered handler.
	handler, ok := d.handlers[rxInfo.Command]
	if !ok {
		return fmt.Errorf("mle dispatch: no handler for command %d", rxInfo.Command)
	}

	if err := handler(rxInfo); err != nil {
		return fmt.Errorf("mle dispatch: handler for command %d: %w", rxInfo.Command, err)
	}

	// 7. For secured messages, update the neighbor's frame counter and key state.
	if rxInfo.IsSecured {
		d.processKeySequence(rxInfo)
	}

	return nil
}

// resolveKey returns the MLE key for the given key sequence.
// If it matches the current key sequence, the current key is used.
// Otherwise, a temporary key is computed for the given sequence.
func (d *Dispatcher) resolveKey(keySequence uint32) ([16]byte, error) {
	currentSeq := d.keyMgr.GetCurrentKeySequence()

	if keySequence == currentSeq {
		return d.keyMgr.GetCurrentMleKey(), nil
	}

	// Allow messages from the next key sequence (key rotation).
	if keySequence == currentSeq+1 {
		return d.keyMgr.GetTemporaryMleKey(keySequence), nil
	}

	// Also allow the previous key sequence for delayed messages.
	if keySequence+1 == currentSeq {
		return d.keyMgr.GetTemporaryMleKey(keySequence), nil
	}

	return [16]byte{}, fmt.Errorf("mle: key sequence %d too far from current %d", keySequence, currentSeq)
}

// validateFrameCounter checks that the received frame counter is valid
// (not a replay) for a known neighbor.
func (d *Dispatcher) validateFrameCounter(rxInfo *RxInfo) error {
	n := rxInfo.Neighbor

	// The frame counter must be greater than what we've previously seen.
	if rxInfo.KeySequence == d.keyMgr.GetCurrentKeySequence() {
		if rxInfo.FrameCounter <= n.Counters.MleFrameCounter {
			return fmt.Errorf("mle: frame counter replay: got %d, last seen %d",
				rxInfo.FrameCounter, n.Counters.MleFrameCounter)
		}
	}
	// If the key sequence is newer, any frame counter is acceptable
	// (frame counters reset on key rotation).

	return nil
}

// processKeySequence updates the neighbor's frame counter and potentially
// advances the global key sequence based on the received message.
//
// This implements OpenThread's ProcessKeySequence logic which classifies
// messages as authoritative (Advertisement, DataResponse, etc.) or peer
// messages and decides whether to adopt the sender's key sequence.
func (d *Dispatcher) processKeySequence(rxInfo *RxInfo) {
	if rxInfo.Neighbor == nil {
		return
	}

	// Update the neighbor's MLE frame counter.
	rxInfo.Neighbor.Counters.MleFrameCounter = rxInfo.FrameCounter

	// Classify the message to decide whether to advance key sequence.
	msgClass := classifyMessage(rxInfo.Command)

	currentSeq := d.keyMgr.GetCurrentKeySequence()

	if rxInfo.KeySequence <= currentSeq {
		return
	}

	// The sender's key sequence is newer than ours.
	switch msgClass {
	case messageClassAuthoritative:
		// Authoritative messages (from attached parents/routers) force
		// immediate key sequence adoption.
		d.keyMgr.SetCurrentKeySequence(rxInfo.KeySequence, key.ForceUpdate|key.ResetGuardTimer)

	case messageClassPeer:
		// Peer messages apply the switch guard check.
		d.keyMgr.SetCurrentKeySequence(rxInfo.KeySequence, key.ApplySwitchGuard|key.ResetGuardTimer)
	}
}

// messageClass categorizes MLE messages for key sequence adoption decisions.
type messageClass uint8

const (
	// messageClassUnknown is an unclassified message that does not trigger
	// key sequence changes.
	messageClassUnknown messageClass = 0
	// messageClassAuthoritative is a message from an authoritative source
	// (parent, leader) that forces key sequence adoption.
	messageClassAuthoritative messageClass = 1
	// messageClassPeer is a message from a peer that triggers guarded
	// key sequence adoption.
	messageClassPeer messageClass = 2
)

// classifyMessage returns the message class for key sequence handling.
// This mirrors OpenThread's ProcessKeySequence classification.
func classifyMessage(cmd Command) messageClass {
	switch cmd {
	case CommandAdvertisement, CommandDataResponse,
		CommandParentResponse, CommandChildIDResponse,
		CommandChildUpdateResponse:
		return messageClassAuthoritative

	case CommandLinkAccept, CommandLinkAcceptAndRequest:
		return messageClassPeer

	default:
		return messageClassUnknown
	}
}

// SendMessage constructs, encrypts, and sends a secured MLE message.
//
// It fills in the security header with the current key sequence and
// frame counter, encrypts the payload, and sends via the transport.
func (d *Dispatcher) SendMessage(msg *Message, dstIP ip6.Address) error {
	if !msg.IsSecured() {
		// Unsecured messages are sent as-is.
		return d.transport.SendMLE(msg.Bytes(), dstIP)
	}

	// Build the security header from current key material.
	frameCounter := d.keyMgr.GetMleFrameCounter()
	if allocator, ok := d.keyMgr.(interface {
		AllocateMleFrameCounter() (uint32, error)
	}); ok {
		var err error
		frameCounter, err = allocator.AllocateMleFrameCounter()
		if err != nil {
			return fmt.Errorf("mle send: allocate frame counter: %w", err)
		}
	} else {
		if frameCounter == ^uint32(0) {
			return key.ErrFrameCounterExhausted
		}
		d.keyMgr.IncrementMleFrameCounter()
	}
	keySequence := d.keyMgr.GetCurrentKeySequence()
	secHdr := NewSecurityHeader(keySequence, frameCounter)

	srcAddr := d.transport.GetExtAddress()
	srcIP := d.transport.GetLinkLocalAddress()
	mleKey := d.keyMgr.GetCurrentMleKey()

	if err := msg.Finalize(secHdr, mleKey, srcAddr, srcIP, dstIP); err != nil {
		return fmt.Errorf("mle send: finalize: %w", err)
	}

	return d.transport.SendMLE(msg.Bytes(), dstIP)
}
