// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package peer provides a P2P peer table for Thread Direct Communication.
//
// This is a Go port of OpenThread's src/core/thread/peer.hpp and
// src/core/thread/peer_table.hpp.
package peer

import (
	"time"

	"github.com/hilli/gothread/errors"
)

// DefaultMaxPeers is the default maximum number of peers in the table,
// matching OPENTHREAD_CONFIG_P2P_MAX_PEERS in OpenThread.
const DefaultMaxPeers = 16

// PeerState represents the connection state of a peer.
type PeerState uint8 //nolint:revive // Preserve the exported type name for existing callers.

const (
	// StateDiscovered indicates the peer has been discovered but no
	// connection has been attempted.
	StateDiscovered PeerState = iota
	// StateConnecting indicates a connection to the peer is in progress.
	StateConnecting
	// StateConnected indicates an active connection to the peer.
	StateConnected
	// StateDisconnected indicates the peer was previously connected but
	// the connection has been lost.
	StateDisconnected
)

// String returns the human-readable name of a PeerState.
func (s PeerState) String() string {
	switch s {
	case StateDiscovered:
		return "Discovered"
	case StateConnecting:
		return "Connecting"
	case StateConnected:
		return "Connected"
	case StateDisconnected:
		return "Disconnected"
	default:
		return "Unknown"
	}
}

// Peer represents a P2P peer in the Thread network.
type Peer struct {
	// ExtAddress is the IEEE 802.15.4 Extended Address of the peer.
	ExtAddress [8]byte
	// MeshLocalEid is the peer's Mesh-Local EID (16-byte IPv6 address).
	MeshLocalEid [16]byte
	// Rloc16 is the peer's 16-bit RLOC address.
	Rloc16 uint16
	// LastHeard is the time the peer was last heard from.
	LastHeard time.Time
	// State is the current connection state of the peer.
	State PeerState
}

// PeerTable manages a collection of peers with a fixed maximum capacity.
type PeerTable struct { //nolint:revive // Preserve the exported type name for existing callers.
	peers    []Peer
	maxPeers int
}

// NewPeerTable creates a new PeerTable with the given maximum capacity.
// If maxPeers is zero, DefaultMaxPeers is used.
func NewPeerTable(maxPeers int) *PeerTable {
	if maxPeers <= 0 {
		maxPeers = DefaultMaxPeers
	}
	return &PeerTable{
		peers:    make([]Peer, 0, maxPeers),
		maxPeers: maxPeers,
	}
}

// Add inserts a peer into the table. Returns ErrNoBufs if the table is full,
// or ErrAlready if a peer with the same ExtAddress already exists.
func (t *PeerTable) Add(p Peer) error {
	if _, ok := t.Find(p.ExtAddress); ok {
		return errors.ErrAlready
	}
	if len(t.peers) >= t.maxPeers {
		return errors.ErrNoBufs
	}
	t.peers = append(t.peers, p)
	return nil
}

// Remove removes the peer with the given extended address from the table.
// If no such peer exists the call is a no-op.
func (t *PeerTable) Remove(extAddr [8]byte) {
	for i := range t.peers {
		if t.peers[i].ExtAddress == extAddr {
			t.peers = append(t.peers[:i], t.peers[i+1:]...)
			return
		}
	}
}

// Find looks up a peer by its extended address. Returns the peer and true
// if found, or nil and false otherwise.
func (t *PeerTable) Find(extAddr [8]byte) (*Peer, bool) {
	for i := range t.peers {
		if t.peers[i].ExtAddress == extAddr {
			return &t.peers[i], true
		}
	}
	return nil, false
}

// FindByRloc16 looks up a peer by its RLOC16 address. Returns the peer and
// true if found, or nil and false otherwise.
func (t *PeerTable) FindByRloc16(rloc16 uint16) (*Peer, bool) {
	for i := range t.peers {
		if t.peers[i].Rloc16 == rloc16 {
			return &t.peers[i], true
		}
	}
	return nil, false
}

// GetCount returns the number of peers in the table.
func (t *PeerTable) GetCount() int {
	return len(t.peers)
}

// ForEach calls the given function for each peer in the table.
func (t *PeerTable) ForEach(fn func(*Peer)) {
	for i := range t.peers {
		fn(&t.peers[i])
	}
}

// Clear removes all peers from the table.
func (t *PeerTable) Clear() {
	t.peers = t.peers[:0]
}
