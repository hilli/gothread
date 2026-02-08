// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package tcp provides a placeholder for TCP/IPv6 socket management
// in Thread networks.
//
// OpenThread's TCP implementation wraps TCPlp, a lightweight TCP stack.
// This placeholder defines the basic types and constants needed by other
// packages. Full TCP functionality will be implemented in a later phase.
//
// This is a Go port of the TCP types in OpenThread's
// src/core/net/tcp6.hpp.
package tcp

const (
	// DynamicPortMin is the start of the IANA dynamic/ephemeral port range.
	DynamicPortMin uint16 = 49152
	// DynamicPortMax is the end of the IANA dynamic/ephemeral port range.
	DynamicPortMax uint16 = 65535
)

// TCP manages TCP endpoints and listeners.
//
// This is a placeholder; full TCP functionality will be added in a
// later phase.
type TCP struct {
	ephemeralPort uint16
}

// New creates a new TCP manager.
func New() *TCP {
	return &TCP{
		ephemeralPort: DynamicPortMin,
	}
}

// Endpoint represents a TCP connection endpoint.
//
// This is a placeholder type; full implementation will be added
// in a later phase.
type Endpoint struct {
	// Placeholder fields will be added when TCPlp is ported.
}

// IsClosed reports whether this endpoint is in the closed state.
func (e *Endpoint) IsClosed() bool {
	return true // placeholder: always closed
}

// Listener represents a TCP listener that accepts incoming connections.
//
// This is a placeholder type; full implementation will be added
// in a later phase.
type Listener struct {
	// Placeholder fields will be added when TCPlp is ported.
}

// IsClosed reports whether this listener is in the closed state.
func (l *Listener) IsClosed() bool {
	return true // placeholder: always closed
}
