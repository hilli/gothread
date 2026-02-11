// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package trel

import (
	"time"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
)

// --------------------------------------------------------------------------
// Peer — a discovered TREL peer
// --------------------------------------------------------------------------

// PeerState represents the DNS-SD discovery state of a peer.
type PeerState uint8

const (
	// PeerStateResolved indicates the peer is fully resolved via DNS-SD.
	PeerStateResolved PeerState = iota
	// PeerStateRemoved indicates the peer service was removed or timed out.
	PeerStateRemoved
	// PeerStateResolving indicates an ongoing resolution for the peer.
	PeerStateResolving
)

// String returns a human-readable name for the peer state.
func (s PeerState) String() string {
	switch s {
	case PeerStateResolved:
		return "resolved"
	case PeerStateRemoved:
		return "removed"
	case PeerStateResolving:
		return "resolving"
	default:
		return "unknown"
	}
}

// Peer represents a discovered TREL peer node.
type Peer struct {
	// ExtAddress is the peer's extended MAC address.
	ExtAddress types.ExtAddress
	// SockAddr is the peer's IPv6 socket address (address + port).
	SockAddr ip6.SockAddr
	// State is the current DNS-SD discovery state.
	State PeerState
	// LastActivity is the timestamp of the last interaction with this peer.
	LastActivity time.Time
}

// HasValidSockAddr reports whether the peer has a non-zero socket address.
func (p *Peer) HasValidSockAddr() bool {
	return !p.SockAddr.Address.IsUnspecified()
}

// UpdateLastActivity sets the last activity timestamp to the current time.
func (p *Peer) UpdateLastActivity() {
	p.LastActivity = time.Now()
}

// SecondsSinceLastActivity returns the number of seconds since the last
// interaction with this peer.
func (p *Peer) SecondsSinceLastActivity() uint32 {
	if p.LastActivity.IsZero() {
		return 0
	}
	elapsed := time.Since(p.LastActivity)
	secs := uint32(elapsed.Seconds())
	return secs
}

// --------------------------------------------------------------------------
// PeerTable — collection of discovered TREL peers
// --------------------------------------------------------------------------

// PeerTable maintains a table of discovered TREL peers.
type PeerTable struct {
	peers []Peer
}

// NewPeerTable creates a new, empty PeerTable.
func NewPeerTable() *PeerTable {
	return &PeerTable{}
}

// Add adds a peer with the given extended address and socket address.
// If a peer with the same extended address already exists, it is updated.
// Returns a pointer to the added or updated peer.
func (pt *PeerTable) Add(extAddr types.ExtAddress, sockAddr ip6.SockAddr) *Peer {
	for i := range pt.peers {
		if pt.peers[i].ExtAddress == extAddr {
			pt.peers[i].SockAddr = sockAddr
			pt.peers[i].State = PeerStateResolved
			pt.peers[i].UpdateLastActivity()
			return &pt.peers[i]
		}
	}
	pt.peers = append(pt.peers, Peer{
		ExtAddress:   extAddr,
		SockAddr:     sockAddr,
		State:        PeerStateResolved,
		LastActivity: time.Now(),
	})
	return &pt.peers[len(pt.peers)-1]
}

// Remove removes the peer with the given extended address. Returns true if
// a peer was removed.
func (pt *PeerTable) Remove(extAddr types.ExtAddress) bool {
	for i := range pt.peers {
		if pt.peers[i].ExtAddress == extAddr {
			// Remove by swapping with last element.
			pt.peers[i] = pt.peers[len(pt.peers)-1]
			pt.peers = pt.peers[:len(pt.peers)-1]
			return true
		}
	}
	return false
}

// FindByExtAddress looks up a peer by its extended MAC address.
// Returns nil if not found.
func (pt *PeerTable) FindByExtAddress(extAddr types.ExtAddress) *Peer {
	for i := range pt.peers {
		if pt.peers[i].ExtAddress == extAddr {
			return &pt.peers[i]
		}
	}
	return nil
}

// FindBySockAddr looks up a peer by its IPv6 socket address.
// Returns nil if not found.
func (pt *PeerTable) FindBySockAddr(sockAddr ip6.SockAddr) *Peer {
	for i := range pt.peers {
		if pt.peers[i].SockAddr.Equal(sockAddr) {
			return &pt.peers[i]
		}
	}
	return nil
}

// GetSize returns the number of peers in the table.
func (pt *PeerTable) GetSize() int {
	return len(pt.peers)
}

// PeerIterator is used to iterate over peers in the table.
type PeerIterator struct {
	table *PeerTable
	index int
}

// GetIterator returns an iterator for traversing all peers in the table.
func (pt *PeerTable) GetIterator() *PeerIterator {
	return &PeerIterator{table: pt, index: 0}
}

// Next returns the next peer in the iteration, or nil if there are no more.
func (it *PeerIterator) Next() *Peer {
	if it.index >= len(it.table.peers) {
		return nil
	}
	p := &it.table.peers[it.index]
	it.index++
	return p
}

// GetPeers returns a copy of all peers in the table.
func (pt *PeerTable) GetPeers() []Peer {
	result := make([]Peer, len(pt.peers))
	copy(result, pt.peers)
	return result
}
