// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package ip6

import "fmt"

// --------------------------------------------------------------------------
// SockAddr — an IPv6 socket address (address + port)
// --------------------------------------------------------------------------

// SockAddr represents an IPv6 socket address containing an IP address and
// a port number.
//
// This is a Go port of ot::Ip6::SockAddr from OpenThread's
// src/core/net/socket.hpp.
type SockAddr struct {
	// Address is the IPv6 address.
	Address Address
	// Port is the transport-layer port number.
	Port uint16
}

// IsEmpty reports whether the SockAddr has a zero address and zero port.
func (sa SockAddr) IsEmpty() bool {
	return sa.Port == 0 && sa.Address == Address{}
}

// Equal reports whether two SockAddr values are identical.
func (sa SockAddr) Equal(other SockAddr) bool {
	return sa.Address == other.Address && sa.Port == other.Port
}

// ToString returns a string representation formatted as "[address]:port".
func (sa SockAddr) ToString() string {
	return fmt.Sprintf("[%s]:%d", sa.Address.ToString(), sa.Port)
}

// --------------------------------------------------------------------------
// MessageInfo — metadata accompanying an IPv6 datagram
// --------------------------------------------------------------------------

// MessageInfo holds addressing information associated with an IPv6 message.
//
// This is a Go port of ot::Ip6::MessageInfo from OpenThread's
// src/core/net/socket.hpp.
type MessageInfo struct {
	// SockAddr is the local (source) address.
	SockAddr Address
	// SockPort is the local (source) port.
	SockPort uint16
	// PeerAddr is the remote (destination/source) address.
	PeerAddr Address
	// PeerPort is the remote (destination/source) port.
	PeerPort uint16
	// HopLimit is the IPv6 Hop Limit. Zero means use the default hop limit.
	HopLimit uint8
	// Ecn is the Explicit Congestion Notification value (2 bits).
	Ecn Ecn
	// MulticastLoop indicates whether multicast may be looped back.
	MulticastLoop bool
	// IsHostInterface indicates whether the peer is via the host interface.
	IsHostInterface bool
	// AllowZeroHopLimit when true applies hop limit 0 literally rather than
	// substituting the default.
	AllowZeroHopLimit bool
}

// HasSamePeerAddrAndPort reports whether the peer address and port match
// those of another MessageInfo.
func (mi *MessageInfo) HasSamePeerAddrAndPort(other *MessageInfo) bool {
	return mi.PeerAddr == other.PeerAddr && mi.PeerPort == other.PeerPort
}

// GetSockSockAddr returns the local end as a SockAddr.
func (mi *MessageInfo) GetSockSockAddr() SockAddr {
	return SockAddr{Address: mi.SockAddr, Port: mi.SockPort}
}

// GetPeerSockAddr returns the remote end as a SockAddr.
func (mi *MessageInfo) GetPeerSockAddr() SockAddr {
	return SockAddr{Address: mi.PeerAddr, Port: mi.PeerPort}
}
