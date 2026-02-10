// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package border implements the Thread Border Agent, which bridges an
// external Commissioner (connected over DTLS on the infrastructure link)
// to the Thread mesh using TMF/CoAP.
//
// This is a Go port of OpenThread's src/core/meshcop/border_agent.hpp/cpp.
package border

import (
	"encoding/binary"
	"strings"
	"sync"
	"time"

	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	// DefaultUDPPort is the default Border Agent DTLS port.
	DefaultUDPPort uint16 = 49191

	// keepAliveTimeout is the maximum time between Commissioner keep-alive
	// messages before the session is considered stale (50 seconds per Thread spec).
	keepAliveTimeout = 50 * time.Second

	// tmfPort is the TMF (Thread Management Framework) port.
	tmfPort uint16 = 61631

	// commissionerALOCBase is the base RLOC16 for Commissioner ALOC addresses.
	// Commissioner ALOC16 = 0xfc30 + (sessionID % 8).
	commissionerALOCBase uint16 = 0xfc30
)

// ---------------------------------------------------------------------------
// Dependency interfaces
// ---------------------------------------------------------------------------

// Transport abstracts CoAP message sending on the mesh (TMF) side.
type Transport interface {
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

// SecureSession abstracts the DTLS-secured CoAP session with an external
// Commissioner. In production, this wraps a coaps.Session.
type SecureSession interface {
	// IsConnected reports whether the DTLS session is established.
	IsConnected() bool

	// SendMessage sends a CoAP message over the DTLS session.
	SendMessage(msg *coap.Message) error

	// SetDefaultHandler sets the handler invoked for all incoming CoAP
	// requests from the Commissioner.
	SetDefaultHandler(h func(msg *coap.Message, info coap.MessageInfo))

	// SetConnectHandler sets the handler invoked when the DTLS connection
	// state changes.
	SetConnectHandler(h func(connected bool))

	// Disconnect terminates the DTLS session.
	Disconnect()

	// SetPSKc sets the PSKc credential for DTLS authentication.
	SetPSKc(pskc [16]byte)
}

// Addressing provides network addressing information needed by the Border Agent.
type Addressing interface {
	// MeshLocalPrefix returns the current mesh-local /64 prefix.
	MeshLocalPrefix() ip6.NetworkPrefix

	// RLOC16 returns this device's current RLOC16.
	RLOC16() uint16

	// LeaderALOC16 returns the leader's ALOC16 (typically 0xfc00).
	LeaderALOC16() uint16

	// IsAttached reports whether the device is currently attached to a Thread network.
	IsAttached() bool
}

// KeyManager provides access to PSKc for DTLS authentication.
type KeyManager interface {
	// GetPSKc returns the Pre-Shared Key for the Commissioner.
	GetPSKc() [16]byte
}

// DatasetReader provides read access to the operational datasets.
type DatasetReader interface {
	// ReadActiveDataset reads the current active dataset.
	ReadActiveDataset() (meshcop.Dataset, error)

	// ReadPendingDataset reads the current pending dataset.
	ReadPendingDataset() (meshcop.Dataset, error)
}

// NetworkInfo provides unicast address management for the Thread network interface.
type NetworkInfo interface {
	// AddUnicastAddress adds a unicast address to the Thread network interface.
	AddUnicastAddress(addr [16]byte)

	// RemoveUnicastAddress removes a unicast address from the Thread network interface.
	RemoveUnicastAddress(addr [16]byte)
}

// Timer abstracts a cancellable timer (compatible with meshcop.Timer).
type Timer interface {
	Stop() bool
}

// ---------------------------------------------------------------------------
// Forward context
// ---------------------------------------------------------------------------

// forwardContext stores the mapping between an original Commissioner request
// and the corresponding forwarded request to the Leader, so responses can
// be relayed back with the correct token.
type forwardContext struct {
	origURI   string // original Commissioner URI path (e.g. "c/cp")
	origToken []byte // original Commissioner request token
	origMsgID uint16 // original Commissioner message ID
}

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

// Agent implements the Thread Border Agent. It bridges an external
// Commissioner (connected via DTLS on the infrastructure link) to the
// Thread mesh, relaying petition/keep-alive/relay messages and providing
// local dataset access.
type Agent struct {
	mu sync.Mutex

	// Dependencies.
	transport     Transport
	secureSession SecureSession
	addressing    Addressing
	keyManager    KeyManager
	datasetReader DatasetReader
	networkInfo   NetworkInfo

	// State.
	enabled bool
	started bool

	// Commissioner session state.
	commissionerConnected bool
	commissionerSessionID uint16

	// Forward contexts for pending Leader requests.
	forwardContexts []*forwardContext

	// Keep-alive timer.
	keepAliveTimer Timer

	// Configuration.
	udpPort uint16

	// Timer injection for testing.
	afterFunc func(d time.Duration, f func()) Timer
}

// NewAgent creates a new Border Agent with the given dependencies.
func NewAgent(
	transport Transport,
	secureSession SecureSession,
	addressing Addressing,
	keyManager KeyManager,
	datasetReader DatasetReader,
	networkInfo NetworkInfo,
) *Agent {
	return &Agent{
		transport:     transport,
		secureSession: secureSession,
		addressing:    addressing,
		keyManager:    keyManager,
		datasetReader: datasetReader,
		networkInfo:   networkInfo,
		enabled:       true,
		udpPort:       DefaultUDPPort,
		afterFunc: func(d time.Duration, f func()) Timer {
			return time.AfterFunc(d, f)
		},
	}
}

// ---------------------------------------------------------------------------
// Public accessors
// ---------------------------------------------------------------------------

// IsEnabled reports whether the Border Agent is enabled.
func (a *Agent) IsEnabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.enabled
}

// SetEnabled enables or disables the Border Agent and triggers a state update.
func (a *Agent) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
	a.updateStateLocked()
}

// IsStarted reports whether the Border Agent's DTLS transport is active.
func (a *Agent) IsStarted() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.started
}

// IsCommissionerConnected reports whether an external Commissioner is
// currently connected and petitioned.
func (a *Agent) IsCommissionerConnected() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.commissionerConnected
}

// GetUDPPort returns the configured DTLS port.
func (a *Agent) GetUDPPort() uint16 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.udpPort
}

// SetUDPPort sets the DTLS port. The agent must be stopped before
// changing the port.
func (a *Agent) SetUDPPort(port uint16) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.udpPort = port
}

// ---------------------------------------------------------------------------
// State change handlers
// ---------------------------------------------------------------------------

// HandleAttachStateChanged should be called when the device's Thread
// attach state changes. It triggers a start/stop evaluation.
func (a *Agent) HandleAttachStateChanged() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.updateStateLocked()
}

// HandlePSKcChanged should be called when the PSKc changes. It updates
// the DTLS credential.
func (a *Agent) HandlePSKcChanged() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.started {
		pskc := a.keyManager.GetPSKc()
		a.secureSession.SetPSKc(pskc)
	}
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

// updateStateLocked evaluates whether the agent should be running and
// starts or stops accordingly. Must be called with a.mu held.
func (a *Agent) updateStateLocked() {
	if a.enabled && a.addressing.IsAttached() {
		a.startLocked()
	} else {
		a.stopLocked()
	}
}

// startLocked activates the Border Agent: registers mesh-side handlers,
// sets up the secure session, and begins accepting Commissioner connections.
// Must be called with a.mu held.
func (a *Agent) startLocked() {
	if a.started {
		return
	}

	// Register mesh-side handler for RelayRx ("c/rx") from Joiner Routers.
	a.transport.RegisterHandler("c/rx", a.handleRelayRx)

	// Configure the secure session.
	pskc := a.keyManager.GetPSKc()
	a.secureSession.SetPSKc(pskc)
	a.secureSession.SetDefaultHandler(a.handleSecureRequest)
	a.secureSession.SetConnectHandler(a.handleSessionConnected)

	a.started = true
}

// stopLocked deactivates the Border Agent: revokes any active Commissioner,
// unregisters handlers, and disconnects the secure session.
// Must be called with a.mu held.
func (a *Agent) stopLocked() {
	if !a.started {
		return
	}

	a.revokeCommissionerLocked()
	a.transport.UnregisterHandler("c/rx")
	a.secureSession.Disconnect()
	a.forwardContexts = nil

	if a.keepAliveTimer != nil {
		a.keepAliveTimer.Stop()
		a.keepAliveTimer = nil
	}

	a.started = false
}

// ---------------------------------------------------------------------------
// Secure session connect/disconnect
// ---------------------------------------------------------------------------

// handleSessionConnected is called when the DTLS session state changes.
func (a *Agent) handleSessionConnected(connected bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if connected {
		a.resetKeepAliveTimerLocked()
	} else {
		a.revokeCommissionerLocked()
		a.forwardContexts = nil
		if a.keepAliveTimer != nil {
			a.keepAliveTimer.Stop()
			a.keepAliveTimer = nil
		}
	}
}

// resetKeepAliveTimerLocked restarts the 50-second keep-alive timer.
// Must be called with a.mu held.
func (a *Agent) resetKeepAliveTimerLocked() {
	if a.keepAliveTimer != nil {
		a.keepAliveTimer.Stop()
	}
	a.keepAliveTimer = a.afterFunc(keepAliveTimeout, func() {
		a.handleKeepAliveTimeout()
	})
}

// handleKeepAliveTimeout is called when the Commissioner's keep-alive timer
// expires, indicating a stale session.
func (a *Agent) handleKeepAliveTimeout() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.revokeCommissionerLocked()
	a.secureSession.Disconnect()
	a.forwardContexts = nil
}

// ---------------------------------------------------------------------------
// Commissioner session management
// ---------------------------------------------------------------------------

// revokeCommissionerLocked clears the commissioner session state and
// removes the Commissioner ALOC. Must be called with a.mu held.
func (a *Agent) revokeCommissionerLocked() {
	if !a.commissionerConnected {
		return
	}

	// Remove Commissioner ALOC from the network interface.
	alocAddr := a.commissionerALOCAddr()
	a.networkInfo.RemoveUnicastAddress(alocAddr)

	a.commissionerConnected = false
	a.commissionerSessionID = 0
}

// commissionerALOCAddr returns the Commissioner ALOC IPv6 address
// derived from the current session ID and mesh-local prefix.
func (a *Agent) commissionerALOCAddr() [16]byte {
	aloc16 := commissionerALOCBase + (a.commissionerSessionID % 8)
	return rlocAddr(a.addressing.MeshLocalPrefix(), aloc16)
}

// ---------------------------------------------------------------------------
// Incoming CoAP from Commissioner (DTLS side)
// ---------------------------------------------------------------------------

// handleSecureRequest dispatches incoming CoAP requests from the
// Commissioner by URI path.
func (a *Agent) handleSecureRequest(msg *coap.Message, info coap.MessageInfo) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.started {
		return
	}

	uriPath := extractURIPath(msg)

	switch uriPath {
	case "c/cp": // Commissioner Petition
		a.forwardToLeaderLocked("c/lp", msg, info)
	case "c/ca": // Commissioner Keep-Alive
		a.handleKeepAliveLocked(msg, info)
	case "c/tx": // RelayTx (Commissioner → Joiner Router)
		a.handleRelayTxLocked(msg, info)
	case "c/cg": // Commissioner Dataset Get
		a.handleDatasetGetLocked(msg, info, meshcop.DatasetActive)
	case "c/ag": // Active Dataset Get
		a.handleDatasetGetLocked(msg, info, meshcop.DatasetActive)
	case "c/pg": // Pending Dataset Get
		a.handleDatasetGetLocked(msg, info, meshcop.DatasetPending)
	case "c/ut": // ProxyTx (UDP encapsulation)
		a.handleProxyTxLocked(msg, info)
	default:
		// Unknown URI — ignore.
	}
}

// ---------------------------------------------------------------------------
// Commissioner Petition forwarding
// ---------------------------------------------------------------------------

// forwardToLeaderLocked forwards a Commissioner Petition or Keep-Alive to
// the Leader, saving a forward context so the response can be relayed back.
// Must be called with a.mu held.
func (a *Agent) forwardToLeaderLocked(leaderURI string, msg *coap.Message, info coap.MessageInfo) {
	// Save forward context for matching the Leader's response.
	ctx := &forwardContext{
		origURI:   extractURIPath(msg),
		origToken: copySlice(msg.GetToken()),
		origMsgID: msg.GetMessageID(),
	}
	a.forwardContexts = append(a.forwardContexts, ctx)

	// Build a CON POST to the Leader.
	payload := msg.GetPayload()
	leaderMsg := buildCONPost(leaderURI, payload)

	leaderInfo := a.leaderCoapInfo()

	// Send to Leader with a response handler that relays back.
	capturedCtx := ctx
	a.transport.SendRequest(leaderMsg, leaderInfo, func(resp *coap.Message, respInfo coap.MessageInfo, err error) {
		a.handleLeaderResponse(resp, respInfo, err, capturedCtx)
	})
}

// handleLeaderResponse relays the Leader's response back to the Commissioner
// over the DTLS session.
func (a *Agent) handleLeaderResponse(resp *coap.Message, respInfo coap.MessageInfo, err error, ctx *forwardContext) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Remove the forward context.
	a.removeForwardContext(ctx)

	if err != nil || resp == nil {
		return
	}

	if !a.secureSession.IsConnected() {
		return
	}

	// Check if the petition was accepted.
	if ctx.origURI == "c/cp" {
		a.handlePetitionResponseLocked(resp)
	} else if ctx.origURI == "c/ca" {
		a.handleKeepAliveResponseLocked(resp)
	}

	// Build response to Commissioner with original token.
	fwdMsg := coap.NewMessage(coap.TypeNonConfirmable, resp.GetCode(), 0)
	if len(ctx.origToken) > 0 {
		_ = fwdMsg.SetToken(ctx.origToken)
	}

	payload := resp.GetPayload()
	if len(payload) > 0 {
		_ = fwdMsg.AppendPayloadMarker()
		_ = fwdMsg.AppendPayload(payload)
	}

	_ = a.secureSession.SendMessage(fwdMsg)
}

// handlePetitionResponseLocked processes the state from a petition response
// to determine if the Commissioner was accepted. Must be called with a.mu held.
func (a *Agent) handlePetitionResponseLocked(resp *coap.Message) {
	payload := resp.GetPayload()
	stateTLV := findTLVInBytes(payload, meshcop.TLVState)
	if stateTLV == nil || len(stateTLV) != 1 {
		return
	}

	if stateTLV[0] != meshcop.StateAccept {
		return
	}

	// Extract session ID.
	sessionTLV := findTLVInBytes(payload, meshcop.TLVCommissionerSessionID)
	if sessionTLV == nil || len(sessionTLV) != 2 {
		return
	}

	sessionID := binary.BigEndian.Uint16(sessionTLV)

	// Mark commissioner as connected.
	a.commissionerConnected = true
	a.commissionerSessionID = sessionID

	// Add Commissioner ALOC to the network interface.
	alocAddr := a.commissionerALOCAddr()
	a.networkInfo.AddUnicastAddress(alocAddr)
}

// handleKeepAliveResponseLocked processes the state from a keep-alive response.
// If the Leader rejected the session, revoke the commissioner.
// Must be called with a.mu held.
func (a *Agent) handleKeepAliveResponseLocked(resp *coap.Message) {
	payload := resp.GetPayload()
	stateTLV := findTLVInBytes(payload, meshcop.TLVState)
	if stateTLV == nil || len(stateTLV) != 1 {
		return
	}

	if stateTLV[0] != meshcop.StateAccept {
		// Session was rejected — revoke commissioner.
		a.revokeCommissionerLocked()
	}
}

// ---------------------------------------------------------------------------
// Commissioner Keep-Alive
// ---------------------------------------------------------------------------

// handleKeepAliveLocked processes a Commissioner Keep-Alive request.
// It forwards the request to the Leader and resets the keep-alive timer.
// Must be called with a.mu held.
func (a *Agent) handleKeepAliveLocked(msg *coap.Message, info coap.MessageInfo) {
	// Check for resign (State = Reject).
	payload := msg.GetPayload()
	stateTLV := findTLVInBytes(payload, meshcop.TLVState)
	if stateTLV != nil && len(stateTLV) == 1 && stateTLV[0] == meshcop.StateReject {
		// Commissioner is resigning — forward to Leader and revoke.
		a.forwardToLeaderLocked("c/la", msg, info)
		a.revokeCommissionerLocked()
		return
	}

	// Normal keep-alive — reset timer and forward.
	a.resetKeepAliveTimerLocked()
	a.forwardToLeaderLocked("c/la", msg, info)
}

// ---------------------------------------------------------------------------
// RelayTx (Commissioner → Joiner Router via mesh)
// ---------------------------------------------------------------------------

// handleRelayTxLocked forwards a RelayTx message from the Commissioner to
// the appropriate Joiner Router on the mesh, addressed by the Joiner Router
// Locator TLV. Must be called with a.mu held.
func (a *Agent) handleRelayTxLocked(msg *coap.Message, _ coap.MessageInfo) {
	if !a.commissionerConnected {
		return
	}

	payload := msg.GetPayload()
	if payload == nil {
		return
	}

	// Parse Joiner Router Locator from the RelayTx payload.
	rlocBytes := findTLVInBytes(payload, meshcop.TLVJoinerRouterLocator)
	if rlocBytes == nil || len(rlocBytes) != 2 {
		return
	}
	joinerRouterRLOC := binary.BigEndian.Uint16(rlocBytes)

	// Build NON POST "c/tx" to the Joiner Router.
	fwdMsg := buildNONPost("c/tx", payload)

	prefix := a.addressing.MeshLocalPrefix()
	destAddr := rlocAddr(prefix, joinerRouterRLOC)
	fwdInfo := coap.MessageInfo{
		PeerAddr: [16]byte(destAddr),
		PeerPort: tmfPort,
	}

	_ = a.transport.SendMessage(fwdMsg, fwdInfo)
}

// ---------------------------------------------------------------------------
// RelayRx (Joiner Router → Commissioner via DTLS)
// ---------------------------------------------------------------------------

// handleRelayRx receives RelayRx messages from Joiner Routers on the mesh
// and forwards them to the Commissioner over the DTLS session.
func (a *Agent) handleRelayRx(msg *coap.Message, info coap.MessageInfo) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.started || !a.secureSession.IsConnected() {
		return
	}

	payload := msg.GetPayload()
	if payload == nil {
		return
	}

	// Forward the RelayRx payload to the Commissioner as a NON POST "c/rx".
	fwdMsg := buildNONPost("c/rx", payload)
	_ = a.secureSession.SendMessage(fwdMsg)
}

// ---------------------------------------------------------------------------
// Dataset Get
// ---------------------------------------------------------------------------

// handleDatasetGetLocked processes a dataset GET request from the Commissioner.
// It reads the requested dataset and returns matching TLVs.
// Must be called with a.mu held.
func (a *Agent) handleDatasetGetLocked(msg *coap.Message, info coap.MessageInfo, dsType meshcop.DatasetType) {
	var ds meshcop.Dataset
	var err error

	if dsType == meshcop.DatasetPending {
		ds, err = a.datasetReader.ReadPendingDataset()
	} else {
		ds, err = a.datasetReader.ReadActiveDataset()
	}

	if err != nil {
		// Respond with the error payload (empty).
		resp := coap.NewMessage(coap.TypeNonConfirmable, coap.CodeChanged, 0)
		if token := msg.GetToken(); len(token) > 0 {
			_ = resp.SetToken(token)
		}
		_ = a.secureSession.SendMessage(resp)
		return
	}

	// Check if the request contains a Get TLV specifying which types to return.
	reqPayload := msg.GetPayload()
	getTLV := findTLVInBytes(reqPayload, meshcop.TLVGet)

	var respPayload []byte

	if getTLV != nil && len(getTLV) > 0 {
		// Return only the requested TLV types.
		for _, typ := range getTLV {
			t := ds.FindTLV(meshcop.TLVType(typ))
			if t != nil {
				respPayload = append(respPayload, encodeTLV(meshcop.TLVType(typ), t.Value)...)
			}
		}
	} else {
		// Return all dataset TLVs.
		respPayload = ds.Bytes()
	}

	resp := coap.NewMessage(coap.TypeNonConfirmable, coap.CodeChanged, 0)
	if token := msg.GetToken(); len(token) > 0 {
		_ = resp.SetToken(token)
	}
	if len(respPayload) > 0 {
		_ = resp.AppendPayloadMarker()
		_ = resp.AppendPayload(respPayload)
	}
	_ = a.secureSession.SendMessage(resp)
}

// ---------------------------------------------------------------------------
// ProxyTx (UDP encapsulation)
// ---------------------------------------------------------------------------

// handleProxyTxLocked processes a ProxyTx request from the Commissioner.
// It extracts the UDP encapsulation TLV and sends the raw UDP payload to
// the specified Thread device.
// Must be called with a.mu held.
func (a *Agent) handleProxyTxLocked(msg *coap.Message, _ coap.MessageInfo) {
	payload := msg.GetPayload()
	if payload == nil {
		return
	}

	// Parse UDP Encapsulation TLV (type 48): src_port(2) + dst_port(2) + payload.
	udpEnc := findTLVInBytesExtended(payload, meshcop.TLVUDPEncapsulation)
	if udpEnc == nil || len(udpEnc) < 4 {
		return
	}

	// Parse IPv6 Address TLV (type 49): 16-byte destination address.
	addrTLV := findTLVInBytes(payload, meshcop.TLVIP6Address)
	if addrTLV == nil || len(addrTLV) != 16 {
		return
	}

	// dstPort is bytes 2-3 of the UDP encapsulation.
	dstPort := binary.BigEndian.Uint16(udpEnc[2:4])
	udpPayload := udpEnc[4:]

	var dstAddr [16]byte
	copy(dstAddr[:], addrTLV)

	fwdInfo := coap.MessageInfo{
		PeerAddr: dstAddr,
		PeerPort: dstPort,
	}

	// For ProxyTx we send the raw UDP payload to the destination.
	// The actual implementation uses a raw UDP socket, but here we send
	// via the mesh transport as a simplified implementation.
	fwdMsg := buildNONPost("c/ur", udpPayload)
	_ = a.transport.SendMessage(fwdMsg, fwdInfo)
}

// ---------------------------------------------------------------------------
// Forward context management
// ---------------------------------------------------------------------------

// removeForwardContext removes the specified context from the pending list.
func (a *Agent) removeForwardContext(ctx *forwardContext) {
	for i, c := range a.forwardContexts {
		if c == ctx {
			a.forwardContexts = append(a.forwardContexts[:i], a.forwardContexts[i+1:]...)
			return
		}
	}
}

// ---------------------------------------------------------------------------
// CoAP message helpers
// ---------------------------------------------------------------------------

// leaderCoapInfo builds a coap.MessageInfo addressed to the Leader.
func (a *Agent) leaderCoapInfo() coap.MessageInfo {
	prefix := a.addressing.MeshLocalPrefix()
	localRLOC := a.addressing.RLOC16()
	leaderALOC := a.addressing.LeaderALOC16()

	localAddr := rlocAddr(prefix, localRLOC)
	peerAddr := rlocAddr(prefix, leaderALOC)

	return coap.MessageInfo{
		PeerAddr:  [16]byte(peerAddr),
		PeerPort:  tmfPort,
		LocalAddr: [16]byte(localAddr),
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
	token := []byte{0x01, 0x02, 0x03, 0x04}
	_ = msg.SetToken(token)
	_ = msg.AppendURIPathOptions(uriPath)
	if len(payload) > 0 {
		_ = msg.AppendPayloadMarker()
		_ = msg.AppendPayload(payload)
	}
	return msg
}

// buildNONPost builds a Non-Confirmable POST message for the given URI path.
func buildNONPost(uriPath string, payload []byte) *coap.Message {
	msg := coap.NewMessage(coap.TypeNonConfirmable, coap.CodePost, 0)
	token := []byte{0x05, 0x06, 0x07, 0x08}
	_ = msg.SetToken(token)
	_ = msg.AppendURIPathOptions(uriPath)
	if len(payload) > 0 {
		_ = msg.AppendPayloadMarker()
		_ = msg.AppendPayload(payload)
	}
	return msg
}

// ---------------------------------------------------------------------------
// CoAP option helpers
// ---------------------------------------------------------------------------

// extractURIPath extracts the URI path from CoAP message options by
// concatenating all Uri-Path option values with '/'.
func extractURIPath(msg *coap.Message) string {
	var parts []string
	it := msg.GetOptionIterator()
	for {
		num, val, ok := it.Next()
		if !ok {
			break
		}
		if num == coap.OptionURIPath {
			parts = append(parts, string(val))
		}
	}
	return strings.Join(parts, "/")
}

// ---------------------------------------------------------------------------
// TLV helpers
// ---------------------------------------------------------------------------

// encodeTLV encodes a single TLV as [type(1), length(1), value...].
func encodeTLV(typ meshcop.TLVType, value []byte) []byte {
	buf := make([]byte, 2+len(value))
	buf[0] = uint8(typ)
	buf[1] = uint8(len(value))
	copy(buf[2:], value)
	return buf
}

// findTLVInBytes searches raw TLV bytes for a TLV of the given type.
// Returns the value portion, or nil if not found.
func findTLVInBytes(data []byte, typ meshcop.TLVType) []byte {
	offset := 0
	for offset+2 <= len(data) {
		t := meshcop.TLVType(data[offset])
		l := int(data[offset+1])
		if offset+2+l > len(data) {
			return nil
		}
		if t == typ {
			return data[offset+2 : offset+2+l]
		}
		offset += 2 + l
	}
	return nil
}

// findTLVInBytesExtended searches raw TLV bytes for a TLV of the given type,
// supporting both short-form and extended-form TLVs.
func findTLVInBytesExtended(data []byte, typ meshcop.TLVType) []byte {
	offset := 0
	for offset+2 <= len(data) {
		t := meshcop.TLVType(data[offset])
		lenByte := data[offset+1]
		var l int
		var hdrSize int
		if lenByte == 0xFF {
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
			return nil
		}
		if t == typ {
			return data[offset+hdrSize : offset+hdrSize+l]
		}
		offset += hdrSize + l
	}
	return nil
}

// copySlice returns a copy of the given byte slice.
func copySlice(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
