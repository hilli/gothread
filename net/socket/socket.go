// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package socket provides socket address types and a port-based muxer
// for IPv6 network sockets.
//
// This is a Go port of socket-related types in OpenThread's
// src/core/net/socket.hpp.
package socket

import (
	"fmt"

	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Address — an IPv6 socket address (address + port)
// ---------------------------------------------------------------------------

// Address represents an IPv6 socket address containing a 128-bit address and
// a port number.
type Address struct {
	// Addr is the 128-bit IPv6 address.
	Addr [16]byte
	// Port is the transport-layer port number.
	Port uint16
}

// IsUnspecified reports whether both the address and port are zero.
func (a Address) IsUnspecified() bool {
	return a.Addr == [16]byte{} && a.Port == 0
}

// IsAddrUnspecified reports whether the address part is all zeros,
// regardless of the port value.
func (a Address) IsAddrUnspecified() bool {
	return a.Addr == [16]byte{}
}

// Equal reports whether two Address values are identical.
func (a Address) Equal(other Address) bool {
	return a.Addr == other.Addr && a.Port == other.Port
}

// String returns the address formatted as "[ipv6]:port".
func (a Address) String() string {
	return fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
		uint16(a.Addr[0])<<8|uint16(a.Addr[1]),
		uint16(a.Addr[2])<<8|uint16(a.Addr[3]),
		uint16(a.Addr[4])<<8|uint16(a.Addr[5]),
		uint16(a.Addr[6])<<8|uint16(a.Addr[7]),
		uint16(a.Addr[8])<<8|uint16(a.Addr[9]),
		uint16(a.Addr[10])<<8|uint16(a.Addr[11]),
		uint16(a.Addr[12])<<8|uint16(a.Addr[13]),
		uint16(a.Addr[14])<<8|uint16(a.Addr[15]),
		a.Port,
	)
}

// ---------------------------------------------------------------------------
// Handle — represents an open socket
// ---------------------------------------------------------------------------

// Handle represents a socket with local and peer address bindings.
type Handle struct {
	sockName  Address
	peerName  Address
	bound     bool
	connected bool
}

// NewHandle creates a new unbound, unconnected socket handle.
func NewHandle() *Handle {
	return &Handle{}
}

// GetSockName returns the local socket address.
func (h *Handle) GetSockName() Address {
	return h.sockName
}

// GetPeerName returns the peer socket address.
func (h *Handle) GetPeerName() Address {
	return h.peerName
}

// Bind binds the socket to the given local address. Returns
// ErrInvalidState if the socket is already bound.
func (h *Handle) Bind(local Address) error {
	if h.bound {
		return errors.ErrInvalidState
	}
	h.sockName = local
	h.bound = true
	return nil
}

// Connect sets the peer address. The socket must be bound first.
// Returns ErrInvalidState if the socket is already connected or not yet
// bound.
func (h *Handle) Connect(peer Address) error {
	if h.connected {
		return errors.ErrInvalidState
	}
	if !h.bound {
		return errors.ErrInvalidState
	}
	h.peerName = peer
	h.connected = true
	return nil
}

// Close resets the socket to an unbound, unconnected state.
func (h *Handle) Close() {
	h.sockName = Address{}
	h.peerName = Address{}
	h.bound = false
	h.connected = false
}

// IsBound reports whether the socket has been bound to a local address.
func (h *Handle) IsBound() bool {
	return h.bound
}

// IsConnected reports whether the socket has been connected to a peer.
func (h *Handle) IsConnected() bool {
	return h.connected
}

// ---------------------------------------------------------------------------
// Muxer — routes incoming packets to handlers by port
// ---------------------------------------------------------------------------

// muxEntry associates a socket handle with a port for the Muxer.
type muxEntry struct {
	handle *Handle
	port   uint16
}

// Muxer routes incoming packets to registered socket handles based on
// destination port.
type Muxer struct {
	entries []muxEntry
}

// NewMuxer creates a new empty Muxer.
func NewMuxer() *Muxer {
	return &Muxer{}
}

// Register associates the given handle with a port. Returns
// ErrAlready if the port is already registered, or ErrInvalidArgs if
// the handle is nil.
func (m *Muxer) Register(handle *Handle, port uint16) error {
	if handle == nil {
		return errors.ErrInvalidArgs
	}
	for _, e := range m.entries {
		if e.port == port {
			return errors.ErrAlready
		}
	}
	m.entries = append(m.entries, muxEntry{handle: handle, port: port})
	return nil
}

// Unregister removes the given handle from the muxer. If the handle is
// not registered, no action is taken.
func (m *Muxer) Unregister(handle *Handle) {
	for i, e := range m.entries {
		if e.handle == handle {
			m.entries = append(m.entries[:i], m.entries[i+1:]...)
			return
		}
	}
}

// FindHandler returns the handle registered for the given port, or nil
// if no handle is registered on that port.
func (m *Muxer) FindHandler(port uint16) *Handle {
	for _, e := range m.entries {
		if e.port == port {
			return e.handle
		}
	}
	return nil
}

// GetRegisteredCount returns the number of registered handles.
func (m *Muxer) GetRegisteredCount() int {
	return len(m.entries)
}
