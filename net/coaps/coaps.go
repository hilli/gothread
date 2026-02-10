// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package coaps provides CoAP-over-DTLS (CoAPS) support, bridging the CoAP
// engine (net/coap) with DTLS sessions (meshcop/dtls) for encrypted
// application-layer messaging used by Thread's Mesh Commissioning Protocol.
//
// This is a Go port of OpenThread's Coap::SecureSession and
// ApplicationCoapSecure (src/core/coap/coap_secure.hpp/cpp).
//
// The Session type composes a coap.Engine with a dtls.Session, routing
// outbound CoAP messages through DTLS encryption and inbound decrypted
// data through CoAP parsing/dispatch.
//
// The SecureServer type combines a dtls.Transport with a single Session,
// providing a complete CoAPS endpoint suitable for Commissioner, Joiner,
// and Border Agent roles.
package coaps

import (
	"sync"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/meshcop/dtls"
	"github.com/hilli/gothread/net/coap"
)

// ConnectHandler is called when the DTLS session state changes.
type ConnectHandler func(event dtls.ConnectEvent)

// ---------------------------------------------------------------------------
// Session — CoAP-over-DTLS session
// ---------------------------------------------------------------------------

// Session bridges a coap.Engine with a dtls.Session, providing encrypted
// CoAP messaging. Outbound CoAP messages are serialized and sent through
// the DTLS session; inbound decrypted data is parsed and dispatched by
// the CoAP engine.
//
// Go port of OpenThread's Coap::SecureSession (coap/coap_secure.hpp).
type Session struct {
	mu sync.Mutex

	engine      *coap.Engine
	dtlsSession *dtls.Session

	connectHandler ConnectHandler

	// transmitQueue buffers CoAP messages while the DTLS session
	// completes handshake or when send is called from a callback context.
	transmitQueue [][]byte
}

// NewSession creates a CoAP-over-DTLS session wrapping the given DTLS
// session. A new coap.Engine is created with the Session's send method
// as the transport.
func NewSession(dtlsSession *dtls.Session) *Session {
	s := &Session{
		dtlsSession: dtlsSession,
	}

	// Create the CoAP engine with our sender that routes through DTLS.
	s.engine = coap.NewEngine(s.send)

	// Wire DTLS callbacks.
	dtlsSession.SetConnectHandler(s.handleDtlsConnect)
	dtlsSession.SetReceiveHandler(s.handleDtlsReceive)

	return s
}

// Engine returns the underlying CoAP engine for direct resource management
// or advanced use (e.g., by tmf.Agent).
func (s *Session) Engine() *coap.Engine {
	return s.engine
}

// DtlsSession returns the underlying DTLS session.
func (s *Session) DtlsSession() *dtls.Session {
	return s.dtlsSession
}

// Peer returns the remote peer info from the DTLS session.
func (s *Session) Peer() dtls.PeerInfo {
	return s.dtlsSession.Peer()
}

// IsConnected reports whether the underlying DTLS session is connected.
func (s *Session) IsConnected() bool {
	return s.dtlsSession.IsConnected()
}

// ---------------------------------------------------------------------------
// Connect / Disconnect
// ---------------------------------------------------------------------------

// Connect initiates a client-side DTLS connection to the given peer.
func (s *Session) Connect(peer dtls.PeerInfo, conn dtls.Conn) error {
	return s.dtlsSession.Connect(peer, conn)
}

// Disconnect initiates a local close of the DTLS session.
func (s *Session) Disconnect() {
	s.dtlsSession.Disconnect()
}

// ---------------------------------------------------------------------------
// Send API
// ---------------------------------------------------------------------------

// SendMessage sends a CoAP message over the DTLS session. If handler is
// non-nil, the engine tracks the request for retransmission and response
// matching.
func (s *Session) SendMessage(msg *coap.Message, txParams *coap.TxParameters, handler coap.ResponseHandler) error {
	if !s.dtlsSession.IsConnected() {
		return errors.ErrInvalidState
	}

	peer := s.dtlsSession.Peer()
	info := peerInfoToMessageInfo(peer)

	return s.engine.SendMessage(msg, info, txParams, handler)
}

// SendMessageNoTrack sends a CoAP message without response tracking.
func (s *Session) SendMessageNoTrack(msg *coap.Message) error {
	return s.SendMessage(msg, nil, nil)
}

// ---------------------------------------------------------------------------
// Resource management (delegates to engine)
// ---------------------------------------------------------------------------

// AddResource registers a CoAP resource with the engine.
func (s *Session) AddResource(r *coap.Resource) {
	s.engine.AddResource(r)
}

// RemoveResource unregisters the resource with the given URI path.
func (s *Session) RemoveResource(uriPath string) {
	s.engine.RemoveResource(uriPath)
}

// SetDefaultHandler sets the fallback handler for unmatched requests.
func (s *Session) SetDefaultHandler(h coap.RequestHandler) {
	s.engine.SetDefaultHandler(h)
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

// SetConnectHandler sets the callback invoked on DTLS connection state
// changes. This is the application-level callback; the Session's internal
// handler always runs first.
func (s *Session) SetConnectHandler(h ConnectHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connectHandler = h
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

// Cleanup clears all pending CoAP transactions and drains the transmit
// queue. Call this when the session is disconnecting or being reset.
func (s *Session) Cleanup() {
	s.engine.ClearAllRequestsAndResponses()

	s.mu.Lock()
	s.transmitQueue = nil
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Internal: DTLS callbacks
// ---------------------------------------------------------------------------

// send is the coap.Sender implementation. It enqueues outbound serialized
// CoAP messages and processes them through the DTLS session.
func (s *Session) send(data []byte, _ coap.MessageInfo) error {
	if !s.dtlsSession.IsConnected() {
		return errors.ErrInvalidState
	}

	// Copy data to avoid retention of the engine's internal buffer.
	buf := make([]byte, len(data))
	copy(buf, data)

	return s.dtlsSession.Send(buf)
}

// handleDtlsConnect is called when the DTLS session state changes.
func (s *Session) handleDtlsConnect(event dtls.ConnectEvent) {
	if event != dtls.EventConnected {
		// On any disconnect, clear all pending CoAP transactions and
		// drain the transmit queue.
		s.Cleanup()
	}

	s.mu.Lock()
	handler := s.connectHandler
	s.mu.Unlock()

	if handler != nil {
		handler(event)
	}
}

// handleDtlsReceive is called when decrypted data arrives from the DTLS
// session. It forwards the data to the CoAP engine for parsing and dispatch.
func (s *Session) handleDtlsReceive(data []byte, peer dtls.PeerInfo) {
	info := peerInfoToMessageInfo(peer)
	s.engine.Receive(data, info)
}

// ---------------------------------------------------------------------------
// SecureServer — all-in-one CoAPS endpoint
// ---------------------------------------------------------------------------

// SecureServer combines a dtls.Transport with a single CoAP secure session,
// providing a complete CoAPS client/server endpoint. It supports one active
// session at a time, suitable for Commissioner, Joiner, and similar roles.
//
// Go port of OpenThread's ApplicationCoapSecure (coap/coap_secure.hpp).
type SecureServer struct {
	mu sync.Mutex

	transport *dtls.Transport
	session   *Session
	started   bool

	connectHandler ConnectHandler

	// resources and defaultHandler are stored so they can be applied
	// to new sessions.
	resources      []*coap.Resource
	defaultHandler coap.RequestHandler
}

// NewSecureServer creates a new CoAPS server with the given DTLS connection
// factory and credential. The credential may be nil and set later with
// SetCredential.
func NewSecureServer(factory dtls.ConnFactory, cred *dtls.Credential) (*SecureServer, error) {
	transport, err := dtls.NewTransport(factory, cred)
	if err != nil {
		return nil, err
	}

	transport.MaxSessions = 1

	ss := &SecureServer{
		transport: transport,
	}

	// Wire the transport's accept handler.
	transport.AcceptHandler = ss.handleAccept

	return ss, nil
}

// Start opens the CoAPS server on the given port.
func (ss *SecureServer) Start(port uint16) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if ss.started {
		return errors.ErrAlready
	}

	ss.transport.SetPort(port)
	ss.started = true
	return nil
}

// Stop closes all sessions and shuts down the server.
func (ss *SecureServer) Stop() {
	ss.mu.Lock()
	if ss.session != nil {
		ss.session.Cleanup()
		ss.session = nil
	}
	ss.started = false
	ss.mu.Unlock()

	ss.transport.Close()
}

// IsStarted reports whether the server has been started.
func (ss *SecureServer) IsStarted() bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.started
}

// Connect initiates a client-side DTLS connection to the given peer.
func (ss *SecureServer) Connect(peer dtls.PeerInfo) error {
	ss.mu.Lock()
	if !ss.started {
		ss.mu.Unlock()
		return errors.ErrInvalidState
	}

	// Disconnect any existing session.
	if ss.session != nil && ss.session.IsConnected() {
		ss.session.Disconnect()
		ss.session = nil
	}
	ss.mu.Unlock()

	dtlsSession, err := ss.transport.Connect(peer)
	if err != nil {
		return err
	}

	session := NewSession(dtlsSession)
	session.SetConnectHandler(ss.handleSessionConnect)

	// Apply stored resources and handler.
	ss.mu.Lock()
	for _, r := range ss.resources {
		session.AddResource(r)
	}
	if ss.defaultHandler != nil {
		session.SetDefaultHandler(ss.defaultHandler)
	}
	ss.session = session
	ss.mu.Unlock()

	return nil
}

// Disconnect closes the active session.
func (ss *SecureServer) Disconnect() {
	ss.mu.Lock()
	session := ss.session
	ss.mu.Unlock()

	if session != nil {
		session.Disconnect()
	}
}

// IsConnected reports whether the active session is connected.
func (ss *SecureServer) IsConnected() bool {
	ss.mu.Lock()
	session := ss.session
	ss.mu.Unlock()

	if session == nil {
		return false
	}
	return session.IsConnected()
}

// SendMessage sends a CoAP message through the active session.
func (ss *SecureServer) SendMessage(msg *coap.Message, txParams *coap.TxParameters, handler coap.ResponseHandler) error {
	ss.mu.Lock()
	session := ss.session
	ss.mu.Unlock()

	if session == nil {
		return errors.ErrInvalidState
	}
	return session.SendMessage(msg, txParams, handler)
}

// AddResource registers a CoAP resource. Resources are stored and applied
// to both current and future sessions.
func (ss *SecureServer) AddResource(r *coap.Resource) {
	ss.mu.Lock()
	ss.resources = append(ss.resources, r)
	session := ss.session
	ss.mu.Unlock()

	if session != nil {
		session.AddResource(r)
	}
}

// RemoveResource unregisters a resource.
func (ss *SecureServer) RemoveResource(uriPath string) {
	ss.mu.Lock()
	for i, r := range ss.resources {
		if r.URIPath == uriPath {
			ss.resources = append(ss.resources[:i], ss.resources[i+1:]...)
			break
		}
	}
	session := ss.session
	ss.mu.Unlock()

	if session != nil {
		session.RemoveResource(uriPath)
	}
}

// SetDefaultHandler sets the fallback request handler for current and
// future sessions.
func (ss *SecureServer) SetDefaultHandler(h coap.RequestHandler) {
	ss.mu.Lock()
	ss.defaultHandler = h
	session := ss.session
	ss.mu.Unlock()

	if session != nil {
		session.SetDefaultHandler(h)
	}
}

// SetConnectHandler sets the callback for connection state changes.
func (ss *SecureServer) SetConnectHandler(h ConnectHandler) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.connectHandler = h
}

// SetCredential updates the transport's credential.
func (ss *SecureServer) SetCredential(cred *dtls.Credential) error {
	return ss.transport.SetCredential(cred)
}

// GetSession returns the active session, or nil if none.
func (ss *SecureServer) GetSession() *Session {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.session
}

// HandleReceive processes an incoming UDP packet, potentially creating
// a new incoming session.
func (ss *SecureServer) HandleReceive(data []byte, peer dtls.PeerInfo) {
	ss.transport.HandleReceive(data, peer)
}

// ---------------------------------------------------------------------------
// Internal: accept and connect handlers
// ---------------------------------------------------------------------------

// handleAccept is called by the DTLS transport when a new incoming
// connection arrives. It returns true to accept (if no session is active).
func (ss *SecureServer) handleAccept(peer dtls.PeerInfo) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if !ss.started {
		return false
	}

	// Only accept if we don't have an active session.
	if ss.session != nil && ss.session.IsConnected() {
		return false
	}
	return true
}

// handleSessionConnect is called when the active session's DTLS state changes.
func (ss *SecureServer) handleSessionConnect(event dtls.ConnectEvent) {
	if event != dtls.EventConnected {
		ss.mu.Lock()
		ss.session = nil
		ss.mu.Unlock()
	}

	ss.mu.Lock()
	handler := ss.connectHandler
	ss.mu.Unlock()

	if handler != nil {
		handler(event)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// peerInfoToMessageInfo converts a dtls.PeerInfo to a coap.MessageInfo.
func peerInfoToMessageInfo(p dtls.PeerInfo) coap.MessageInfo {
	return coap.MessageInfo{
		PeerAddr: p.Address,
		PeerPort: p.Port,
	}
}
