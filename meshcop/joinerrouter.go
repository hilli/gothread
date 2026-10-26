// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"

	goterrors "github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	// joinerEntrustTxDelay is the delay before sending Joiner Entrust after
	// receiving the KEK (50 ms per Thread spec).
	joinerEntrustTxDelay = 50 * time.Millisecond

	// tmfPort is the TMF (Thread Management Framework) port.
	tmfPort uint16 = 61631
)

// ---------------------------------------------------------------------------
// Dependency interfaces
// ---------------------------------------------------------------------------

// JoinerRouterTransport abstracts CoAP message sending for the JoinerRouter.
// In production, this is backed by the TMF agent.
type JoinerRouterTransport interface {
	// SendMessage sends a CoAP message to the given destination.
	SendMessage(msg *coap.Message, info coap.MessageInfo) error

	// SendRequest sends a confirmable CoAP request and invokes the callback
	// with the response.
	SendRequest(msg *coap.Message, info coap.MessageInfo, cb func(*coap.Message, coap.MessageInfo, error)) error

	// RegisterHandler registers a handler for incoming CoAP requests on a URI path.
	RegisterHandler(uriPath string, handler func(*coap.Message, coap.MessageInfo))

	// UnregisterHandler unregisters a handler for a URI path.
	UnregisterHandler(uriPath string)
}

// JoinerRouterUDPSocket abstracts the raw UDP socket used to relay DTLS
// packets to/from Joiners on the mesh link.
type JoinerRouterUDPSocket interface {
	// Open opens the socket on the given port.
	Open(port uint16) error

	// Close closes the socket.
	Close() error

	// IsBound reports whether the socket is currently bound.
	IsBound() bool

	// Send sends raw UDP data to the given destination.
	Send(data []byte, peerAddr [16]byte, peerPort uint16) error

	// SetReceiveHandler sets the callback invoked when data arrives.
	SetReceiveHandler(handler func(data []byte, peerAddr [16]byte, peerPort uint16))
}

// JoinerRouterAddressing provides network addressing information.
type JoinerRouterAddressing interface {
	// MeshLocalPrefix returns the current mesh-local prefix.
	MeshLocalPrefix() ip6.NetworkPrefix

	// RLOC16 returns this device's RLOC16.
	RLOC16() uint16

	// IsFullThreadDevice reports whether this device is a Full Thread Device.
	IsFullThreadDevice() bool
}

// JoinerRouterNetworkData provides access to network data for joining state.
type JoinerRouterNetworkData interface {
	// IsJoiningAllowed reports whether commissioning is active
	// (Border Agent Locator exists and Steering Data is non-empty).
	IsJoiningAllowed() bool

	// FindBorderAgentRLOC returns the Border Agent's RLOC16, or 0 if not found.
	FindBorderAgentRLOC() (uint16, bool)

	// FindJoinerUDPPort returns the Joiner UDP port from commissioning data,
	// or 0 if not found.
	FindJoinerUDPPort() (uint16, bool)
}

// JoinerRouterKeyManager abstracts key management for KEK handling.
type JoinerRouterKeyManager interface {
	// SetKEK sets the Key Encryption Key for MAC-layer encryption
	// of the Joiner Entrust message.
	SetKEK(kek [16]byte)

	// GetCurrentKeySequence returns the current network key sequence number.
	GetCurrentKeySequence() uint32
}

// JoinerRouterDatasetReader provides access to the active operational dataset.
type JoinerRouterDatasetReader interface {
	// ReadActiveDataset reads the current active dataset.
	ReadActiveDataset() (Dataset, error)
}

// ---------------------------------------------------------------------------
// Pending Joiner Entrust
// ---------------------------------------------------------------------------

// pendingEntrust holds information needed to send a delayed Joiner Entrust.
type pendingEntrust struct {
	joinerAddr [16]byte  // Joiner's link-local address
	kek        [16]byte  // KEK from Commissioner
	sendTime   time.Time // When to send
}

// ---------------------------------------------------------------------------
// JoinerRouter
// ---------------------------------------------------------------------------

// JoinerRouter relays DTLS traffic between Joiners and the Commissioner,
// and sends Joiner Entrust messages with network credentials after the
// DTLS handshake completes.
//
// The JoinerRouter is a mostly stateless relay. It does not maintain per-Joiner
// session state — it simply forwards DTLS packets wrapped in RelayRx/RelayTx
// CoAP messages. The only state it holds is a queue of pending Joiner Entrust
// messages that are delayed by 50ms after receiving the KEK.
type JoinerRouter struct {
	mu sync.Mutex

	// Dependencies.
	transport     JoinerRouterTransport
	socket        JoinerRouterUDPSocket
	addressing    JoinerRouterAddressing
	networkData   JoinerRouterNetworkData
	keyManager    JoinerRouterKeyManager
	datasetReader JoinerRouterDatasetReader

	// Configuration.
	joinerUDPPort          uint16
	isJoinerPortConfigured bool

	// Pending Joiner Entrust queue.
	pendingEntrusts []pendingEntrust

	// Timer injection for testing.
	afterFunc func(d time.Duration, f func()) Timer
	nowFunc   func() time.Time

	// State.
	started bool
}

// NewJoinerRouter creates a new JoinerRouter with the given dependencies.
func NewJoinerRouter(
	transport JoinerRouterTransport,
	socket JoinerRouterUDPSocket,
	addressing JoinerRouterAddressing,
	networkData JoinerRouterNetworkData,
	keyManager JoinerRouterKeyManager,
	datasetReader JoinerRouterDatasetReader,
) *JoinerRouter {
	jr := &JoinerRouter{
		transport:     transport,
		socket:        socket,
		addressing:    addressing,
		networkData:   networkData,
		keyManager:    keyManager,
		datasetReader: datasetReader,
		afterFunc: func(d time.Duration, f func()) Timer {
			return time.AfterFunc(d, f)
		},
		nowFunc: time.Now,
	}
	return jr
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// GetJoinerUDPPort returns the effective Joiner UDP port. Priority:
// 1. Explicitly configured port (via SetJoinerUDPPort)
// 2. Port from network data (commissioning data)
// 3. DefaultJoinerUDPPort (1000)
func (jr *JoinerRouter) GetJoinerUDPPort() uint16 {
	jr.mu.Lock()
	defer jr.mu.Unlock()

	if jr.isJoinerPortConfigured {
		return jr.joinerUDPPort
	}
	if port, ok := jr.networkData.FindJoinerUDPPort(); ok {
		return port
	}
	return DefaultJoinerUDPPort
}

// SetJoinerUDPPort explicitly sets the Joiner UDP port.
// This triggers a restart of the UDP socket if the router is active.
func (jr *JoinerRouter) SetJoinerUDPPort(port uint16) {
	jr.mu.Lock()
	defer jr.mu.Unlock()

	jr.joinerUDPPort = port
	jr.isJoinerPortConfigured = true
	jr.startLocked()
}

// HandleNetworkDataChanged should be called when Thread network data changes.
// The JoinerRouter checks whether joining is allowed and starts/stops accordingly.
func (jr *JoinerRouter) HandleNetworkDataChanged() {
	jr.mu.Lock()
	defer jr.mu.Unlock()
	jr.startLocked()
}

// IsStarted reports whether the JoinerRouter is actively listening.
func (jr *JoinerRouter) IsStarted() bool {
	jr.mu.Lock()
	defer jr.mu.Unlock()
	return jr.started
}

// GetPendingEntrustCount returns the number of pending Joiner Entrust messages
// (primarily for testing).
func (jr *JoinerRouter) GetPendingEntrustCount() int {
	jr.mu.Lock()
	defer jr.mu.Unlock()
	return len(jr.pendingEntrusts)
}

// ---------------------------------------------------------------------------
// Start / Stop logic
// ---------------------------------------------------------------------------

func (jr *JoinerRouter) startLocked() {
	if !jr.addressing.IsFullThreadDevice() {
		jr.stopLocked()
		return
	}

	if jr.networkData.IsJoiningAllowed() {
		if !jr.started {
			port := jr.getEffectivePortLocked()
			if err := jr.socket.Open(port); err != nil {
				return
			}
			jr.socket.SetReceiveHandler(jr.handleUDPReceive)

			// Register handler for RelayTx ("c/tx") from Commissioner.
			jr.transport.RegisterHandler("c/tx", jr.handleRelayTx)

			jr.started = true
		}
	} else {
		jr.stopLocked()
	}
}

func (jr *JoinerRouter) stopLocked() {
	if !jr.started {
		return
	}
	jr.transport.UnregisterHandler("c/tx")
	_ = jr.socket.Close()
	jr.pendingEntrusts = nil
	jr.started = false
}

func (jr *JoinerRouter) getEffectivePortLocked() uint16 {
	if jr.isJoinerPortConfigured {
		return jr.joinerUDPPort
	}
	if port, ok := jr.networkData.FindJoinerUDPPort(); ok {
		return port
	}
	return DefaultJoinerUDPPort
}

// ---------------------------------------------------------------------------
// UDP receive → RelayRx
// ---------------------------------------------------------------------------

// handleUDPReceive is called when a raw UDP packet arrives from a Joiner
// on the mesh link. It wraps the DTLS data in a RelayRx CoAP message and
// sends it to the Border Agent (Commissioner).
func (jr *JoinerRouter) handleUDPReceive(data []byte, peerAddr [16]byte, peerPort uint16) {
	jr.mu.Lock()
	defer jr.mu.Unlock()

	if !jr.started {
		return
	}

	// Find the Border Agent RLOC.
	borderAgentRLOC, ok := jr.networkData.FindBorderAgentRLOC()
	if !ok {
		return
	}

	// Build RelayRx payload with TLVs.
	var payload []byte

	// JoinerUdpPort TLV (type 18, 2 bytes)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, peerPort)
	payload = append(payload, encodeTLV(TLVJoinerUDPPort, portBytes)...)

	// JoinerIID TLV (type 19, 8 bytes) — IID is bytes 8-15 of the IPv6 address.
	iid := peerAddr[8:16]
	payload = append(payload, encodeTLV(TLVJoinerIID, iid)...)

	// JoinerRouterLocator TLV (type 20, 2 bytes)
	rlocBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(rlocBytes, jr.addressing.RLOC16())
	payload = append(payload, encodeTLV(TLVJoinerRouterLocator, rlocBytes)...)

	// JoinerDTLSEncapsulation TLV (type 17, variable — use extended form for large data).
	if len(data) > 254 {
		payload = append(payload, encodeExtendedTLV(TLVJoinerDTLSEncapsulation, data)...)
	} else {
		payload = append(payload, encodeTLV(TLVJoinerDTLSEncapsulation, data)...)
	}

	// Build NON POST to "c/rx".
	msg := buildNONPost("c/rx", payload)

	// Send to Border Agent RLOC.
	prefix := jr.addressing.MeshLocalPrefix()
	destAddr := rlocAddr(prefix, borderAgentRLOC)
	info := coap.MessageInfo{
		PeerAddr: [16]byte(destAddr),
		PeerPort: tmfPort,
	}

	_ = jr.transport.SendMessage(msg, info)
}

// ---------------------------------------------------------------------------
// RelayTx handler (Commissioner → JoinerRouter → Joiner)
// ---------------------------------------------------------------------------

// handleRelayTx handles incoming RelayTx ("c/tx") messages from the
// Commissioner (or Border Agent). It extracts the DTLS data and forwards
// it to the Joiner via raw UDP. If the message contains a KEK TLV, it
// schedules a Joiner Entrust.
func (jr *JoinerRouter) handleRelayTx(msg *coap.Message, info coap.MessageInfo) {
	jr.mu.Lock()
	defer jr.mu.Unlock()

	if !jr.started {
		return
	}

	// Must be Non-Confirmable POST.
	if msg.GetType() != coap.TypeNonConfirmable || msg.GetCode() != coap.CodePost {
		return
	}

	payload := msg.GetPayload()
	if payload == nil {
		return
	}

	// Parse required TLVs.
	joinerPortBytes := findTLVInBytesExtended(payload, TLVJoinerUDPPort)
	joinerIIDBytes := findTLVInBytesExtended(payload, TLVJoinerIID)
	dtlsData := findTLVInBytesExtended(payload, TLVJoinerDTLSEncapsulation)

	if len(joinerPortBytes) != 2 {
		return
	}
	if len(joinerIIDBytes) != 8 {
		return
	}
	if dtlsData == nil {
		return
	}

	joinerPort := binary.BigEndian.Uint16(joinerPortBytes)

	// Construct the Joiner's link-local address from the IID.
	var iid [8]byte
	copy(iid[:], joinerIIDBytes)
	joinerAddr := linkLocalFromIID(iid)

	// Forward DTLS data to Joiner via raw UDP (no link security).
	_ = jr.socket.Send(dtlsData, joinerAddr, joinerPort)

	// Check for KEK TLV — indicates DTLS handshake completed.
	kekBytes := findTLVInBytesExtended(payload, TLVJoinerRouterKEK)
	if len(kekBytes) == 16 {
		var kek [16]byte
		copy(kek[:], kekBytes)
		jr.delaySendingJoinerEntrust(joinerAddr, kek)
	}
}

// ---------------------------------------------------------------------------
// Joiner Entrust
// ---------------------------------------------------------------------------

// delaySendingJoinerEntrust queues a Joiner Entrust to be sent after the
// configured delay (50ms). The delay allows the Joiner to process the
// DTLS Finalize Response before receiving the entrust.
func (jr *JoinerRouter) delaySendingJoinerEntrust(joinerAddr, kek [16]byte) {
	pe := pendingEntrust{
		joinerAddr: joinerAddr,
		kek:        kek,
		sendTime:   jr.nowFunc().Add(joinerEntrustTxDelay),
	}
	jr.pendingEntrusts = append(jr.pendingEntrusts, pe)

	// Schedule timer for the send.
	jr.afterFunc(joinerEntrustTxDelay, func() {
		jr.sendDelayedJoinerEntrust()
	})
}

// sendDelayedJoinerEntrust processes the head of the pending entrust queue.
func (jr *JoinerRouter) sendDelayedJoinerEntrust() {
	jr.mu.Lock()
	defer jr.mu.Unlock()

	if len(jr.pendingEntrusts) == 0 {
		return
	}

	pe := jr.pendingEntrusts[0]
	jr.pendingEntrusts = jr.pendingEntrusts[1:]

	// Set KEK on the key manager for MAC-layer encryption.
	jr.keyManager.SetKEK(pe.kek)

	// Build and send the Joiner Entrust message.
	err := jr.sendJoinerEntrustLocked(pe.joinerAddr)
	if err != nil {
		// On failure, re-queue immediately for retry.
		pe.sendTime = jr.nowFunc()
		jr.pendingEntrusts = append([]pendingEntrust{pe}, jr.pendingEntrusts...)
		jr.afterFunc(0, func() {
			jr.sendDelayedJoinerEntrust()
		})
	}
}

// sendJoinerEntrustLocked builds and sends the Joiner Entrust CoAP message.
func (jr *JoinerRouter) sendJoinerEntrustLocked(joinerAddr [16]byte) error {
	msg, err := jr.prepareJoinerEntrustMessage()
	if err != nil {
		return err
	}

	info := coap.MessageInfo{
		PeerAddr: joinerAddr,
		PeerPort: tmfPort,
	}

	return jr.transport.SendRequest(msg, info, func(resp *coap.Message, rInfo coap.MessageInfo, err error) {
		// Response handler — just processes next queued entrust.
		jr.mu.Lock()
		defer jr.mu.Unlock()
		if len(jr.pendingEntrusts) > 0 {
			jr.afterFunc(joinerEntrustTxDelay, func() {
				jr.sendDelayedJoinerEntrust()
			})
		}
	})
}

// prepareJoinerEntrustMessage builds the Joiner Entrust CoAP payload
// containing network credentials from the active dataset.
func (jr *JoinerRouter) prepareJoinerEntrustMessage() (*coap.Message, error) {
	ds, err := jr.datasetReader.ReadActiveDataset()
	if err != nil {
		return nil, err
	}

	var payload []byte

	// Append dataset TLVs in the standard order.
	// These are copied directly from the dataset's raw TLV storage.
	tlvTypes := []TLVType{
		TLVNetworkKey,
		TLVMeshLocalPrefix,
		TLVExtendedPanID,
		TLVNetworkName,
		TLVActiveTimestamp,
		TLVChannelMask,
		TLVPSKc,
		TLVSecurityPolicy,
	}

	for _, typ := range tlvTypes {
		t := ds.FindTLV(typ)
		if t != nil {
			payload = append(payload, encodeTLV(typ, t.Value)...)
		}
	}

	// Append NetworkKeySequence from KeyManager.
	seqBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(seqBytes, jr.keyManager.GetCurrentKeySequence())
	payload = append(payload, encodeTLV(TLVNetworkKeySequence, seqBytes)...)

	// Build CON POST to "c/je".
	msg := buildCONPost("c/je", payload)

	return msg, nil
}

// ---------------------------------------------------------------------------
// Exported helpers
// ---------------------------------------------------------------------------

// EncodeRelayTxPayload builds a RelayTx ("c/tx") payload containing the
// Joiner's IID, UDP port, DTLS data, and optionally a KEK. This is useful
// for testing and for the Commissioner to build relay messages.
func EncodeRelayTxPayload(joinerIID [8]byte, joinerPort uint16, dtlsData []byte, kek *[16]byte) []byte {
	var payload []byte

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, joinerPort)
	payload = append(payload, encodeTLV(TLVJoinerUDPPort, portBytes)...)
	payload = append(payload, encodeTLV(TLVJoinerIID, joinerIID[:])...)

	if len(dtlsData) > 254 {
		payload = append(payload, encodeExtendedTLV(TLVJoinerDTLSEncapsulation, dtlsData)...)
	} else {
		payload = append(payload, encodeTLV(TLVJoinerDTLSEncapsulation, dtlsData)...)
	}

	if kek != nil {
		payload = append(payload, encodeTLV(TLVJoinerRouterKEK, kek[:])...)
	}

	return payload
}

// EncodeRelayRxPayload builds a RelayRx ("c/rx") payload. This is the
// inverse of what the JoinerRouter produces internally when relaying
// a Joiner's DTLS packet.
func EncodeRelayRxPayload(joinerIID [8]byte, joinerPort, joinerRouterRLOC uint16, dtlsData []byte) []byte {
	var payload []byte

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, joinerPort)
	payload = append(payload, encodeTLV(TLVJoinerUDPPort, portBytes)...)
	payload = append(payload, encodeTLV(TLVJoinerIID, joinerIID[:])...)

	rlocBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(rlocBytes, joinerRouterRLOC)
	payload = append(payload, encodeTLV(TLVJoinerRouterLocator, rlocBytes)...)

	if len(dtlsData) > 254 {
		payload = append(payload, encodeExtendedTLV(TLVJoinerDTLSEncapsulation, dtlsData)...)
	} else {
		payload = append(payload, encodeTLV(TLVJoinerDTLSEncapsulation, dtlsData)...)
	}

	return payload
}

// ParseRelayPayload parses TLVs from a relay (Rx or Tx) CoAP payload.
// Returns the Joiner IID, UDP port, router locator (from Rx only), DTLS data,
// and optional KEK (from Tx only).
//
//nolint:gocritic // Preserve the exported return signature for API compatibility.
func ParseRelayPayload(payload []byte) (
	joinerIID [8]byte,
	joinerPort uint16,
	joinerRouterLocator uint16,
	dtlsData []byte,
	kek *[16]byte,
	err error,
) {
	portBytes := findTLVInBytesExtended(payload, TLVJoinerUDPPort)
	iidBytes := findTLVInBytesExtended(payload, TLVJoinerIID)
	dtlsData = findTLVInBytesExtended(payload, TLVJoinerDTLSEncapsulation)

	if len(portBytes) != 2 {
		return joinerIID, 0, 0, nil, nil, goterrors.ErrParse
	}
	if len(iidBytes) != 8 {
		return joinerIID, 0, 0, nil, nil, goterrors.ErrParse
	}
	if dtlsData == nil {
		return joinerIID, 0, 0, nil, nil, goterrors.ErrParse
	}

	copy(joinerIID[:], iidBytes)
	joinerPort = binary.BigEndian.Uint16(portBytes)

	// Optional: JoinerRouterLocator (in RelayRx)
	rlocBytes := findTLVInBytesExtended(payload, TLVJoinerRouterLocator)
	if len(rlocBytes) == 2 {
		joinerRouterLocator = binary.BigEndian.Uint16(rlocBytes)
	}

	// Optional: KEK (in RelayTx)
	kekBytes := findTLVInBytesExtended(payload, TLVJoinerRouterKEK)
	if len(kekBytes) == 16 {
		k := [16]byte{}
		copy(k[:], kekBytes)
		kek = &k
	}

	return joinerIID, joinerPort, joinerRouterLocator, dtlsData, kek, nil
}
