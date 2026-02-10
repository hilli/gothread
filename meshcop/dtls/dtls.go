// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package dtls provides a DTLS 1.2 transport abstraction for Thread's
// Mesh Commissioning Protocol (MeshCoP). It manages DTLS sessions with
// support for EC-JPAKE (Thread Commissioning), PSK, and certificate-based
// authentication.
//
// This is a Go port of OpenThread's SecureTransport and SecureSession
// (src/core/meshcop/secure_transport.hpp/cpp), adapted to use Go's
// crypto primitives and a pluggable transport backend.
//
// The design separates the session state machine and transport management
// from the underlying DTLS implementation, which is provided through the
// Connector and Listener interfaces. This allows testing with mock
// implementations and swapping DTLS backends (e.g. pion/dtls, crypto/tls).
package dtls

import (
	"crypto/ecdsa"
	"crypto/x509"
	"sync"
	"time"

	goterrors "github.com/hilli/gothread/errors"
)

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

// DefaultPort is the default CoAPS port (RFC 7252).
const DefaultPort uint16 = 5684

// GuardTimeNewConnection is the delay between a session disconnecting and
// being fully cleaned up, allowing the peer to process close_notify.
const GuardTimeNewConnection = 2 * time.Second

// HandshakeTimeoutIntermediate is the intermediate handshake timeout used
// for DTLS retransmissions.
const HandshakeTimeoutIntermediate = 8 * time.Second

// HandshakeTimeoutFinal is the maximum handshake timeout.
const HandshakeTimeoutFinal = 60 * time.Second

// MaxPSKLength is the maximum length of a pre-shared key in bytes.
const MaxPSKLength = 32

// ApplicationDataMaxLength is the maximum application data payload size.
const ApplicationDataMaxLength = 1152

// --------------------------------------------------------------------------
// Session States
// --------------------------------------------------------------------------

// SessionState represents the state of a DTLS session.
type SessionState uint8

const (
	// StateDisconnected indicates the session is idle with no connection.
	StateDisconnected SessionState = iota
	// StateInitializing indicates the DTLS context is being set up.
	StateInitializing
	// StateConnecting indicates the DTLS handshake is in progress.
	StateConnecting
	// StateConnected indicates the handshake is complete and application
	// data can flow.
	StateConnected
	// StateDisconnecting indicates close_notify has been sent and the
	// guard timer is running before cleanup.
	StateDisconnecting
)

// String returns the human-readable name of a SessionState.
func (s SessionState) String() string {
	switch s {
	case StateDisconnected:
		return "Disconnected"
	case StateInitializing:
		return "Initializing"
	case StateConnecting:
		return "Connecting"
	case StateConnected:
		return "Connected"
	case StateDisconnecting:
		return "Disconnecting"
	default:
		return "Unknown"
	}
}

// --------------------------------------------------------------------------
// Connect Events
// --------------------------------------------------------------------------

// ConnectEvent describes why a session's connectivity state changed.
type ConnectEvent uint8

const (
	// EventConnected indicates the DTLS handshake completed successfully.
	EventConnected ConnectEvent = iota
	// EventDisconnectedPeerClosed indicates the peer sent close_notify.
	EventDisconnectedPeerClosed
	// EventDisconnectedLocalClosed indicates a local Disconnect() call.
	EventDisconnectedLocalClosed
	// EventDisconnectedMaxAttempts indicates max connection attempts reached.
	EventDisconnectedMaxAttempts
	// EventDisconnectedError indicates a fatal alert or handshake failure.
	EventDisconnectedError
	// EventDisconnectedTimeout indicates a local session timeout.
	EventDisconnectedTimeout
)

// String returns the human-readable name of a ConnectEvent.
func (e ConnectEvent) String() string {
	switch e {
	case EventConnected:
		return "Connected"
	case EventDisconnectedPeerClosed:
		return "PeerClosed"
	case EventDisconnectedLocalClosed:
		return "LocalClosed"
	case EventDisconnectedMaxAttempts:
		return "MaxAttempts"
	case EventDisconnectedError:
		return "Error"
	case EventDisconnectedTimeout:
		return "Timeout"
	default:
		return "Unknown"
	}
}

// --------------------------------------------------------------------------
// Cipher Suites
// --------------------------------------------------------------------------

// CipherSuite identifies the DTLS cipher suite to use.
type CipherSuite uint8

const (
	// CipherSuiteEcjpake uses TLS_ECJPAKE_WITH_AES_128_CCM_8, the
	// cipher suite used for Thread Commissioning (Joiner/Commissioner).
	CipherSuiteEcjpake CipherSuite = iota
	// CipherSuitePsk uses TLS_PSK_WITH_AES_128_CCM_8, for application
	// CoAP Secure with a pre-shared key.
	CipherSuitePsk
	// CipherSuiteEcdheEcdsa uses TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
	// for certificate-based DTLS authentication.
	CipherSuiteEcdheEcdsa
)

// String returns the cipher suite name.
func (cs CipherSuite) String() string {
	switch cs {
	case CipherSuiteEcjpake:
		return "ECJPAKE_WITH_AES_128_CCM_8"
	case CipherSuitePsk:
		return "PSK_WITH_AES_128_CCM_8"
	case CipherSuiteEcdheEcdsa:
		return "ECDHE_ECDSA_WITH_AES_128_CCM_8"
	default:
		return "Unknown"
	}
}

// --------------------------------------------------------------------------
// Peer Info
// --------------------------------------------------------------------------

// PeerInfo identifies a remote DTLS endpoint.
type PeerInfo struct {
	// Address is the peer's IPv6 address (16 bytes).
	Address [16]byte
	// Port is the peer's UDP port.
	Port uint16
}

// Key returns a string key suitable for use as a map key.
func (p PeerInfo) Key() peerKey {
	return peerKey{addr: p.Address, port: p.Port}
}

// peerKey is an internal comparable type for map lookups.
type peerKey struct {
	addr [16]byte
	port uint16
}

// --------------------------------------------------------------------------
// Session Callbacks
// --------------------------------------------------------------------------

// ConnectHandler is invoked when a session's connectivity state changes.
type ConnectHandler func(event ConnectEvent)

// ReceiveHandler is invoked when decrypted application data is received.
type ReceiveHandler func(data []byte, peer PeerInfo)

// --------------------------------------------------------------------------
// Credential — authentication material
// --------------------------------------------------------------------------

// Credential holds the authentication material for a DTLS session.
// Exactly one of the credential fields should be set.
type Credential struct {
	// CipherSuite selects which cipher suite to use.
	CipherSuite CipherSuite

	// PSK is the pre-shared key (for CipherSuitePsk or CipherSuiteEcjpake).
	PSK []byte

	// PSKIdentity is the PSK identity hint (for CipherSuitePsk).
	PSKIdentity []byte

	// Certificate is the local X.509 certificate (for CipherSuiteEcdheEcdsa).
	Certificate *x509.Certificate

	// PrivateKey is the local ECDSA private key (for CipherSuiteEcdheEcdsa).
	PrivateKey *ecdsa.PrivateKey

	// CACertificates are the trusted CA certificates for peer verification
	// (for CipherSuiteEcdheEcdsa).
	CACertificates []*x509.Certificate

	// VerifyPeer controls whether the peer's certificate is verified
	// (for CipherSuiteEcdheEcdsa).
	VerifyPeer bool
}

// Validate checks that the credential is internally consistent.
func (c *Credential) Validate() error {
	switch c.CipherSuite {
	case CipherSuiteEcjpake:
		if len(c.PSK) == 0 {
			return goterrors.ErrInvalidArgs
		}
		if len(c.PSK) > MaxPSKLength {
			return goterrors.ErrInvalidArgs
		}
	case CipherSuitePsk:
		if len(c.PSK) == 0 || len(c.PSKIdentity) == 0 {
			return goterrors.ErrInvalidArgs
		}
		if len(c.PSK) > MaxPSKLength {
			return goterrors.ErrInvalidArgs
		}
	case CipherSuiteEcdheEcdsa:
		if c.Certificate == nil || c.PrivateKey == nil {
			return goterrors.ErrInvalidArgs
		}
	default:
		return goterrors.ErrInvalidArgs
	}
	return nil
}

// --------------------------------------------------------------------------
// Session — DTLS session abstraction
// --------------------------------------------------------------------------

// Session represents a single DTLS session with a remote peer. It manages
// the session state machine and provides send/receive for application data.
//
// The session state machine:
//
//	Disconnected → Initializing → Connecting → Connected → Disconnecting → Disconnected
type Session struct {
	mu sync.Mutex

	state          SessionState
	peer           PeerInfo
	isServer       bool
	connectHandler ConnectHandler
	receiveHandler ReceiveHandler
	conn           Conn

	// KEK (Key Encryption Key) derived during EC-JPAKE handshake.
	kek    [32]byte
	hasKEK bool

	// Connection attempt tracking.
	maxAttempts     uint16
	currentAttempts uint16

	// Guard timer for disconnect cleanup.
	guardTimer *time.Timer
}

// NewSession creates a new DTLS session in the Disconnected state.
func NewSession() *Session {
	return &Session{
		state: StateDisconnected,
	}
}

// State returns the current session state.
func (s *Session) State() SessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Peer returns the peer info for this session.
func (s *Session) Peer() PeerInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peer
}

// IsServer reports whether this session is the server (acceptor) side.
func (s *Session) IsServer() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isServer
}

// IsConnected reports whether the session is in the Connected state.
func (s *Session) IsConnected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state == StateConnected
}

// IsConnectionActive reports whether the session is in any active state
// (not Disconnected).
func (s *Session) IsConnectionActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state != StateDisconnected
}

// SetConnectHandler sets the callback for connection state changes.
func (s *Session) SetConnectHandler(h ConnectHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connectHandler = h
}

// SetReceiveHandler sets the callback for received application data.
func (s *Session) SetReceiveHandler(h ReceiveHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receiveHandler = h
}

// SetMaxAttempts configures the maximum number of connection attempts.
// A value of 0 means unlimited attempts.
func (s *Session) SetMaxAttempts(max uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxAttempts = max
}

// Connect initiates a client-side DTLS connection to the given peer using
// the provided DTLS connection backend.
func (s *Session) Connect(peer PeerInfo, conn Conn) error {
	s.mu.Lock()

	if s.state != StateDisconnected {
		s.mu.Unlock()
		return goterrors.ErrInvalidState
	}

	if s.maxAttempts > 0 && s.currentAttempts >= s.maxAttempts {
		s.mu.Unlock()
		s.invokeConnectHandler(EventDisconnectedMaxAttempts)
		return goterrors.ErrInvalidState
	}

	s.peer = peer
	s.conn = conn
	s.isServer = false
	s.currentAttempts++
	s.state = StateConnecting
	s.mu.Unlock()

	// Start the handshake in a goroutine to avoid blocking the caller.
	go s.doHandshake()

	return nil
}

// Accept sets up a server-side session for an incoming connection.
func (s *Session) Accept(peer PeerInfo, conn Conn) error {
	s.mu.Lock()

	if s.state != StateDisconnected {
		s.mu.Unlock()
		return goterrors.ErrInvalidState
	}

	s.peer = peer
	s.conn = conn
	s.isServer = true
	s.currentAttempts = 0
	s.state = StateConnecting
	s.mu.Unlock()

	// Start the handshake in a goroutine.
	go s.doHandshake()

	return nil
}

// doHandshake performs the DTLS handshake and transitions to Connected
// or handles failure. This runs in a separate goroutine.
func (s *Session) doHandshake() {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()

	if conn == nil {
		s.handleHandshakeFailure(EventDisconnectedError)
		return
	}

	// The Conn.Handshake method blocks until the handshake completes.
	err := conn.Handshake()
	if err != nil {
		s.handleHandshakeFailure(EventDisconnectedError)
		return
	}

	s.mu.Lock()
	if s.state != StateConnecting {
		// Session was disconnected during handshake.
		s.mu.Unlock()
		return
	}
	s.state = StateConnected
	s.mu.Unlock()

	s.invokeConnectHandler(EventConnected)

	// Start reading application data.
	s.readLoop()
}

// handleHandshakeFailure transitions the session to Disconnected on
// handshake failure.
func (s *Session) handleHandshakeFailure(event ConnectEvent) {
	s.mu.Lock()
	s.state = StateDisconnected
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	s.mu.Unlock()

	s.invokeConnectHandler(event)
}

// readLoop continuously reads decrypted data from the DTLS connection
// and passes it to the receive handler.
func (s *Session) readLoop() {
	buf := make([]byte, ApplicationDataMaxLength)

	for {
		s.mu.Lock()
		if s.state != StateConnected {
			s.mu.Unlock()
			return
		}
		conn := s.conn
		s.mu.Unlock()

		if conn == nil {
			return
		}

		n, err := conn.Read(buf)
		if err != nil {
			s.disconnectWithEvent(EventDisconnectedPeerClosed)
			return
		}

		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])

			s.mu.Lock()
			peer := s.peer
			handler := s.receiveHandler
			s.mu.Unlock()

			if handler != nil {
				handler(data, peer)
			}
		}
	}
}

// Send writes application data through the DTLS connection.
func (s *Session) Send(data []byte) error {
	s.mu.Lock()
	if s.state != StateConnected {
		s.mu.Unlock()
		return goterrors.ErrInvalidState
	}
	conn := s.conn
	s.mu.Unlock()

	if conn == nil {
		return goterrors.ErrInvalidState
	}

	_, err := conn.Write(data)
	return err
}

// Disconnect initiates a local close of the session.
func (s *Session) Disconnect() {
	s.disconnectWithEvent(EventDisconnectedLocalClosed)
}

// DisconnectTimeout initiates a close due to timeout.
func (s *Session) DisconnectTimeout() {
	s.disconnectWithEvent(EventDisconnectedTimeout)
}

// disconnectWithEvent transitions the session through the disconnect flow.
func (s *Session) disconnectWithEvent(event ConnectEvent) {
	s.mu.Lock()
	if s.state == StateDisconnected || s.state == StateDisconnecting {
		s.mu.Unlock()
		return
	}

	s.state = StateDisconnecting

	// Close the underlying connection (sends close_notify).
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}

	// Start guard timer before transitioning to Disconnected.
	s.guardTimer = time.AfterFunc(GuardTimeNewConnection, func() {
		s.mu.Lock()
		s.state = StateDisconnected
		s.hasKEK = false
		s.guardTimer = nil
		s.mu.Unlock()
	})

	s.mu.Unlock()

	s.invokeConnectHandler(event)
}

// invokeConnectHandler calls the connect handler if set.
func (s *Session) invokeConnectHandler(event ConnectEvent) {
	s.mu.Lock()
	handler := s.connectHandler
	s.mu.Unlock()

	if handler != nil {
		handler(event)
	}
}

// SetKEK sets the Key Encryption Key derived from the DTLS handshake.
func (s *Session) SetKEK(kek [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kek = kek
	s.hasKEK = true
}

// KEK returns the Key Encryption Key if available.
func (s *Session) KEK() ([32]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kek, s.hasKEK
}

// Reset forces the session to the Disconnected state, cleaning up resources.
func (s *Session) Reset() {
	s.mu.Lock()
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	if s.guardTimer != nil {
		s.guardTimer.Stop()
		s.guardTimer = nil
	}
	s.state = StateDisconnected
	s.hasKEK = false
	s.currentAttempts = 0
	s.mu.Unlock()
}

// --------------------------------------------------------------------------
// Conn — pluggable DTLS connection interface
// --------------------------------------------------------------------------

// Conn abstracts a single DTLS connection. Implementations wrap the actual
// DTLS library (e.g. pion/dtls, crypto/tls for testing).
type Conn interface {
	// Handshake performs the DTLS handshake. It blocks until the handshake
	// completes or fails.
	Handshake() error

	// Read reads decrypted application data. It blocks until data is
	// available or the connection is closed.
	Read(buf []byte) (int, error)

	// Write sends application data through the DTLS connection.
	Write(data []byte) (int, error)

	// Close sends close_notify and releases resources.
	Close() error
}

// --------------------------------------------------------------------------
// ConnFactory — creates Conn instances
// --------------------------------------------------------------------------

// ConnFactory creates DTLS connections for the given credential and peer.
// Client connections use Dial, server connections use Accept.
type ConnFactory interface {
	// Dial creates a client-side DTLS connection to the given peer.
	Dial(peer PeerInfo, cred *Credential) (Conn, error)

	// Accept creates a server-side DTLS connection from an incoming message.
	// The raw parameter contains the initial DTLS ClientHello bytes.
	Accept(peer PeerInfo, cred *Credential, raw []byte) (Conn, error)
}

// --------------------------------------------------------------------------
// Transport — manages DTLS sessions
// --------------------------------------------------------------------------

// Transport manages one or more DTLS sessions over a shared UDP socket.
// It provides session creation, lookup, and lifecycle management.
//
// This is a Go port of OpenThread's SecureTransport
// (src/core/meshcop/secure_transport.hpp).
type Transport struct {
	mu sync.Mutex

	sessions map[peerKey]*Session
	cred     *Credential
	factory  ConnFactory

	// AcceptHandler is invoked when a new incoming connection is received.
	// It returns true to accept the connection, false to reject.
	AcceptHandler func(peer PeerInfo) bool

	// RemoveHandler is invoked when a session is removed from the transport.
	RemoveHandler func(peer PeerInfo)

	// MaxSessions limits the number of concurrent sessions. 0 = unlimited.
	MaxSessions int

	port   uint16
	closed bool
}

// NewTransport creates a new Transport with the given connection factory
// and credential.
func NewTransport(factory ConnFactory, cred *Credential) (*Transport, error) {
	if cred != nil {
		if err := cred.Validate(); err != nil {
			return nil, err
		}
	}

	return &Transport{
		sessions: make(map[peerKey]*Session),
		cred:     cred,
		factory:  factory,
		port:     DefaultPort,
	}, nil
}

// SetPort sets the local port for the transport.
func (t *Transport) SetPort(port uint16) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.port = port
}

// Port returns the local port.
func (t *Transport) Port() uint16 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.port
}

// SetCredential updates the transport's credential for new sessions.
func (t *Transport) SetCredential(cred *Credential) error {
	if err := cred.Validate(); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cred = cred
	return nil
}

// Connect creates a new client-side session to the given peer.
func (t *Transport) Connect(peer PeerInfo) (*Session, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, goterrors.ErrInvalidState
	}
	if t.cred == nil {
		t.mu.Unlock()
		return nil, goterrors.ErrInvalidArgs
	}

	key := peer.Key()

	// Check for existing session.
	if existing, ok := t.sessions[key]; ok {
		t.mu.Unlock()
		if existing.IsConnectionActive() {
			return existing, goterrors.ErrAlready
		}
		// Reuse the session slot.
		existing.Reset()
	}

	// Check session limit.
	if t.MaxSessions > 0 && len(t.sessions) >= t.MaxSessions {
		t.mu.Unlock()
		return nil, goterrors.ErrNoBufs
	}

	cred := t.cred
	factory := t.factory
	t.mu.Unlock()

	// Create the underlying DTLS connection.
	conn, err := factory.Dial(peer, cred)
	if err != nil {
		return nil, err
	}

	session := NewSession()
	session.SetConnectHandler(func(event ConnectEvent) {
		if event != EventConnected {
			t.removeSession(peer)
		}
	})

	t.mu.Lock()
	t.sessions[key] = session
	t.mu.Unlock()

	if err := session.Connect(peer, conn); err != nil {
		t.removeSession(peer)
		return nil, err
	}

	return session, nil
}

// HandleReceive processes an incoming UDP packet that may be a DTLS
// ClientHello (new session) or data for an existing session.
func (t *Transport) HandleReceive(data []byte, peer PeerInfo) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}

	key := peer.Key()

	// Check for existing session.
	if session, ok := t.sessions[key]; ok {
		t.mu.Unlock()
		// Data is handled by the session's read loop via the Conn.
		_ = session
		return
	}

	// New connection — check accept handler.
	if t.AcceptHandler != nil && !t.AcceptHandler(peer) {
		t.mu.Unlock()
		return
	}

	// Check session limit.
	if t.MaxSessions > 0 && len(t.sessions) >= t.MaxSessions {
		t.mu.Unlock()
		return
	}

	cred := t.cred
	factory := t.factory
	t.mu.Unlock()

	if cred == nil || factory == nil {
		return
	}

	// Create a server-side session.
	conn, err := factory.Accept(peer, cred, data)
	if err != nil {
		return
	}

	session := NewSession()
	session.SetConnectHandler(func(event ConnectEvent) {
		if event != EventConnected {
			t.removeSession(peer)
		}
	})

	t.mu.Lock()
	t.sessions[key] = session
	t.mu.Unlock()

	if err := session.Accept(peer, conn); err != nil {
		t.removeSession(peer)
	}
}

// FindSession returns the session for the given peer, or nil if none exists.
func (t *Transport) FindSession(peer PeerInfo) *Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sessions[peer.Key()]
}

// Sessions returns all active sessions.
func (t *Transport) Sessions() []*Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make([]*Session, 0, len(t.sessions))
	for _, s := range t.sessions {
		result = append(result, s)
	}
	return result
}

// removeSession removes a session from the transport and invokes the
// remove handler.
func (t *Transport) removeSession(peer PeerInfo) {
	t.mu.Lock()
	key := peer.Key()
	session, ok := t.sessions[key]
	if ok {
		delete(t.sessions, key)
	}
	handler := t.RemoveHandler
	t.mu.Unlock()

	if ok && session != nil {
		session.Reset()
	}
	if handler != nil {
		handler(peer)
	}
}

// RemoveSession explicitly removes a session for the given peer.
func (t *Transport) RemoveSession(peer PeerInfo) {
	t.removeSession(peer)
}

// Close closes all sessions and marks the transport as closed.
func (t *Transport) Close() {
	t.mu.Lock()
	t.closed = true
	sessions := make(map[peerKey]*Session)
	for k, v := range t.sessions {
		sessions[k] = v
	}
	t.sessions = make(map[peerKey]*Session)
	t.mu.Unlock()

	for _, s := range sessions {
		s.Reset()
	}
}

// SessionCount returns the number of active sessions.
func (t *Transport) SessionCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sessions)
}

// IsClosed reports whether the transport has been closed.
func (t *Transport) IsClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}
