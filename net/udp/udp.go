// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package udp implements UDP/IPv6 socket management for Thread networks.
//
// This is a Go port of the UDP handling in OpenThread's
// src/core/net/udp6.hpp and src/core/net/udp6.cpp.
package udp

import (
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	// DynamicPortMin is the start of the IANA dynamic/ephemeral port range.
	DynamicPortMin uint16 = 49152
	// DynamicPortMax is the end of the IANA dynamic/ephemeral port range.
	DynamicPortMax uint16 = 65535
	// TmfPort is the Thread Management Framework port.
	TmfPort uint16 = 61631
	// SrpServerPortMin is the start of the SRP server reserved port range.
	SrpServerPortMin uint16 = 53535
	// SrpServerPortMax is the end of the SRP server reserved port range.
	SrpServerPortMax uint16 = 53554
)

// ---------------------------------------------------------------------------
// NetifIdentifier
// ---------------------------------------------------------------------------

// NetifIdentifier identifies the network interface a socket is bound to.
type NetifIdentifier uint8

const (
	// NetifUnspecified indicates no specific interface binding.
	NetifUnspecified NetifIdentifier = 0
	// NetifThreadHost indicates the Thread host interface.
	NetifThreadHost NetifIdentifier = 1
	// NetifThreadInternal indicates the Thread-internal interface.
	NetifThreadInternal NetifIdentifier = 2
	// NetifBackbone indicates the backbone interface.
	NetifBackbone NetifIdentifier = 3
)

// ---------------------------------------------------------------------------
// ReceiveHandler
// ---------------------------------------------------------------------------

// ReceiveHandler is called when a UDP message is received on a socket.
type ReceiveHandler func(payload []byte, messageInfo *ip6.MessageInfo)

// ---------------------------------------------------------------------------
// Socket
// ---------------------------------------------------------------------------

// Socket represents a UDP socket with local and peer addresses, a network
// interface binding, and a receive callback.
//
// This combines OpenThread's SocketHandle and Socket types.
type Socket struct {
	sockName ip6.SockAddr
	peerName ip6.SockAddr
	netifID  NetifIdentifier
	handler  ReceiveHandler
}

// IsBound reports whether the socket has been bound to a local port.
func (s *Socket) IsBound() bool {
	return s.sockName.Port != 0
}

// GetSockName returns the local socket address.
func (s *Socket) GetSockName() ip6.SockAddr {
	return s.sockName
}

// GetPeerName returns the peer socket address.
func (s *Socket) GetPeerName() ip6.SockAddr {
	return s.peerName
}

// GetNetifID returns the network interface identifier for this socket.
func (s *Socket) GetNetifID() NetifIdentifier {
	return s.netifID
}

// SetNetifID sets the network interface identifier for this socket.
func (s *Socket) SetNetifID(id NetifIdentifier) {
	s.netifID = id
}

// ShouldUsePlatformUDP reports whether this socket should use the platform
// UDP stack rather than Thread-internal transport.
func (s *Socket) ShouldUsePlatformUDP() bool {
	return s.netifID != NetifThreadInternal
}

// Matches reports whether this socket should receive a message described
// by the given MessageInfo.
//
// A socket matches if:
//   - The socket's local port matches the message's peer port (destination).
//   - The socket's local address is unspecified or matches the message's
//     local (sock) address.
//   - The socket's peer address is unspecified or matches the message's
//     peer address.
//   - The socket's peer port is zero or matches the message's peer port.
func (s *Socket) Matches(messageInfo *ip6.MessageInfo) bool {
	// The socket must be bound to a port that matches the destination port.
	if s.sockName.Port != messageInfo.SockPort {
		return false
	}

	// If the socket is bound to a specific address, it must match.
	if !s.sockName.Address.IsUnspecified() && s.sockName.Address != messageInfo.SockAddr {
		return false
	}

	// If a peer address is set, it must match the source.
	if !s.peerName.Address.IsUnspecified() && s.peerName.Address != messageInfo.PeerAddr {
		return false
	}

	// If a peer port is set, it must match the source port.
	if s.peerName.Port != 0 && s.peerName.Port != messageInfo.PeerPort {
		return false
	}

	return true
}

// ---------------------------------------------------------------------------
// Receiver
// ---------------------------------------------------------------------------

// Receiver is a handler that can intercept incoming UDP messages before
// they are dispatched to sockets.
type Receiver struct {
	handler func(payload []byte, messageInfo *ip6.MessageInfo) bool
}

// NewReceiver creates a new Receiver with the given handler function.
// The handler returns true if the message was consumed and should not be
// dispatched to sockets.
func NewReceiver(handler func(payload []byte, messageInfo *ip6.MessageInfo) bool) *Receiver {
	return &Receiver{handler: handler}
}

// ---------------------------------------------------------------------------
// UDP — the main socket manager
// ---------------------------------------------------------------------------

// UDP manages UDP sockets and receivers for Thread networks.
type UDP struct {
	ephemeralPort uint16
	sockets       []*Socket
	receivers     []*Receiver
}

// New creates a new UDP manager with the ephemeral port counter
// initialised to DynamicPortMin.
func New() *UDP {
	return &UDP{
		ephemeralPort: DynamicPortMin,
	}
}

// AddReceiver registers a Receiver to intercept incoming UDP messages.
// It returns ErrAlready if the receiver is already registered.
func (u *UDP) AddReceiver(r *Receiver) error {
	for _, existing := range u.receivers {
		if existing == r {
			return errors.ErrAlready
		}
	}
	u.receivers = append(u.receivers, r)
	return nil
}

// RemoveReceiver removes a previously registered Receiver.
// It returns ErrNotFound if the receiver is not registered.
func (u *UDP) RemoveReceiver(r *Receiver) error {
	for i, existing := range u.receivers {
		if existing == r {
			u.receivers = append(u.receivers[:i], u.receivers[i+1:]...)
			return nil
		}
	}
	return errors.ErrNotFound
}

// Open opens a socket, binding it to the given network interface and setting
// its receive handler. The socket must not already be open (tracked by this
// UDP manager).
func (u *UDP) Open(s *Socket, netifID NetifIdentifier, handler ReceiveHandler) error {
	if u.IsOpen(s) {
		return errors.ErrAlready
	}
	s.netifID = netifID
	s.handler = handler
	u.sockets = append(u.sockets, s)
	return nil
}

// IsOpen reports whether the socket is currently tracked by this UDP manager.
func (u *UDP) IsOpen(s *Socket) bool {
	for _, existing := range u.sockets {
		if existing == s {
			return true
		}
	}
	return false
}

// Bind binds a socket to the given local address. The socket must already
// be open. If the address port is zero, an ephemeral port is assigned.
func (u *UDP) Bind(s *Socket, addr ip6.SockAddr) error {
	if !u.IsOpen(s) {
		return errors.ErrInvalidState
	}
	if addr.Port == 0 {
		addr.Port = u.GetEphemeralPort()
	}
	s.sockName = addr
	return nil
}

// Connect sets the peer address on a socket. If the socket is not yet
// bound, it is automatically bound with an ephemeral port.
func (u *UDP) Connect(s *Socket, addr ip6.SockAddr) error {
	if !u.IsOpen(s) {
		return errors.ErrInvalidState
	}
	if !s.IsBound() {
		if err := u.Bind(s, ip6.SockAddr{}); err != nil {
			return err
		}
	}
	s.peerName = addr
	return nil
}

// Close removes a socket from the manager and resets its state.
// Closing a socket that is not open is a no-op (returns nil).
func (u *UDP) Close(s *Socket) error {
	for i, existing := range u.sockets {
		if existing != s {
			continue
		}
		u.sockets = append(u.sockets[:i], u.sockets[i+1:]...)
		s.sockName = ip6.SockAddr{}
		s.peerName = ip6.SockAddr{}
		s.netifID = NetifUnspecified
		s.handler = nil
		return nil
	}
	// Not open — no-op.
	return nil
}

// GetEphemeralPort returns the next available ephemeral port, advancing
// the internal counter. Reserved ports (TMF and SRP server ranges) are
// skipped. The counter wraps around from DynamicPortMax to DynamicPortMin.
func (u *UDP) GetEphemeralPort() uint16 {
	// We need to find a port that is not reserved. In the worst case we
	// scan the entire ephemeral range once.
	rangeSize := int(DynamicPortMax-DynamicPortMin) + 1
	for i := 0; i < rangeSize; i++ {
		port := u.ephemeralPort
		u.advanceEphemeralPort()
		if !u.IsPortReserved(port) {
			return port
		}
	}
	// Fallback: all ports reserved (should never happen in practice).
	port := u.ephemeralPort
	u.advanceEphemeralPort()
	return port
}

// advanceEphemeralPort moves the ephemeral counter forward, wrapping at
// DynamicPortMax.
func (u *UDP) advanceEphemeralPort() {
	if u.ephemeralPort >= DynamicPortMax {
		u.ephemeralPort = DynamicPortMin
	} else {
		u.ephemeralPort++
	}
}

// IsPortInUse reports whether any open socket is bound to the given port.
func (u *UDP) IsPortInUse(port uint16) bool {
	for _, s := range u.sockets {
		if s.sockName.Port == port {
			return true
		}
	}
	return false
}

// IsPortReserved reports whether the given port falls within a reserved
// range (TMF port or SRP server port range).
func (u *UDP) IsPortReserved(port uint16) bool {
	if port == TmfPort {
		return true
	}
	if port >= SrpServerPortMin && port <= SrpServerPortMax {
		return true
	}
	return false
}

// HandleMessage dispatches an incoming UDP message to registered receivers
// and sockets.
//
// Receivers are checked first in registration order. If a receiver's handler
// returns true, the message is considered consumed and no further dispatch
// occurs. If no receiver consumes the message, it is delivered to all
// matching sockets.
//
// This method mirrors OpenThread's Udp::HandleMessage().
func (u *UDP) HandleMessage(payload []byte, messageInfo *ip6.MessageInfo) {
	// First pass: check receivers (interceptors).
	for _, r := range u.receivers {
		if r.handler != nil && r.handler(payload, messageInfo) {
			return // consumed
		}
	}

	// Second pass: deliver to matching sockets.
	for _, s := range u.sockets {
		if s.Matches(messageInfo) && s.handler != nil {
			s.handler(payload, messageInfo)
		}
	}
}
