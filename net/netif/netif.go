// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package netif provides a network interface abstraction for managing
// unicast and multicast IPv6 addresses.
//
// This is a Go port of the Netif types in OpenThread's
// src/core/net/netif.hpp and src/core/net/netif.cpp. It supplements the
// lower-level ip6.Netif with a standalone, reusable API.
package netif

import (
	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Address origin
// ---------------------------------------------------------------------------

// AddressOrigin represents the origin of an address assignment.
type AddressOrigin uint8

const (
	// OriginThread indicates a Thread-assigned address.
	OriginThread AddressOrigin = 0
	// OriginSlaac indicates a SLAAC-assigned address.
	OriginSlaac AddressOrigin = 1
	// OriginDhcpv6 indicates a DHCPv6-assigned address.
	OriginDhcpv6 AddressOrigin = 2
	// OriginManual indicates a manually-assigned address.
	OriginManual AddressOrigin = 3
)

// ---------------------------------------------------------------------------
// Well-known multicast addresses
// ---------------------------------------------------------------------------

var (
	// AllNodesLinkLocal is ff02::1.
	AllNodesLinkLocal = [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	// AllRoutersLinkLocal is ff02::2.
	AllRoutersLinkLocal = [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	// AllNodesRealmLocal is ff03::1.
	AllNodesRealmLocal = [16]byte{0xff, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	// AllRoutersRealmLocal is ff03::2.
	AllRoutersRealmLocal = [16]byte{0xff, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	// AllMLENodesLinkLocal is ff02::fc.
	AllMLENodesLinkLocal = [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfc}
	// AllMLENodesRealmLocal is ff03::fc.
	AllMLENodesRealmLocal = [16]byte{0xff, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfc}
	// AllMLDv2Routers is ff02::16.
	AllMLDv2Routers = [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16}
)

// ---------------------------------------------------------------------------
// UnicastAddress
// ---------------------------------------------------------------------------

// UnicastAddress represents an IPv6 unicast address assigned to a network
// interface.
type UnicastAddress struct {
	// Address is the 128-bit IPv6 address.
	Address [16]byte
	// PrefixLength is the prefix length in bits (typically 64 for Thread).
	PrefixLength uint8
	// Origin indicates the origin of the address assignment.
	Origin AddressOrigin
	// Preferred indicates whether this address is preferred for source
	// address selection.
	Preferred bool
	// Valid indicates whether this address is valid.
	Valid bool
	// ScopeOverride overrides the scope if non-zero.
	ScopeOverride uint8
	// Rloc indicates whether this is a Thread Routing Locator address.
	Rloc bool
	// MeshLocal indicates whether this is a mesh-local address.
	MeshLocal bool
}

// ---------------------------------------------------------------------------
// MulticastAddress
// ---------------------------------------------------------------------------

// MulticastAddress represents an IPv6 multicast group subscription.
type MulticastAddress struct {
	// Address is the 128-bit IPv6 multicast address.
	Address [16]byte
	// Origin indicates the origin of the subscription.
	Origin AddressOrigin
}

// ---------------------------------------------------------------------------
// NetIf
// ---------------------------------------------------------------------------

// NetIf represents an IPv6 network interface with unicast and multicast
// address management.
type NetIf struct {
	unicastAddresses   []UnicastAddress
	multicastAddresses []MulticastAddress

	subscribedAllNodes   bool
	subscribedAllRouters bool

	stateChangedCb func()
}

// NewNetIf creates a new empty network interface.
func NewNetIf() *NetIf {
	return &NetIf{}
}

// SetStateChangedCallback registers a callback invoked when addresses change.
func (n *NetIf) SetStateChangedCallback(cb func()) {
	n.stateChangedCb = cb
}

func (n *NetIf) notifyChanged() {
	if n.stateChangedCb != nil {
		n.stateChangedCb()
	}
}

// ---------------------------------------------------------------------------
// Unicast address management
// ---------------------------------------------------------------------------

// AddUnicastAddress adds a unicast address to the interface. Returns
// ErrAlready if the address is already present.
func (n *NetIf) AddUnicastAddress(addr UnicastAddress) error {
	if n.HasUnicastAddress(addr.Address) {
		return errors.ErrAlready
	}
	n.unicastAddresses = append(n.unicastAddresses, addr)
	n.notifyChanged()
	return nil
}

// RemoveUnicastAddress removes a unicast address from the interface.
// Returns ErrNotFound if the address is not present.
func (n *NetIf) RemoveUnicastAddress(address [16]byte) error {
	for i := range n.unicastAddresses {
		if n.unicastAddresses[i].Address == address {
			n.unicastAddresses = append(n.unicastAddresses[:i], n.unicastAddresses[i+1:]...)
			n.notifyChanged()
			return nil
		}
	}
	return errors.ErrNotFound
}

// HasUnicastAddress reports whether the given address is assigned.
func (n *NetIf) HasUnicastAddress(address [16]byte) bool {
	return n.FindUnicastAddress(address) != nil
}

// FindUnicastAddress returns a pointer to the unicast address entry
// matching the given address, or nil if not found.
func (n *NetIf) FindUnicastAddress(address [16]byte) *UnicastAddress {
	for i := range n.unicastAddresses {
		if n.unicastAddresses[i].Address == address {
			return &n.unicastAddresses[i]
		}
	}
	return nil
}

// GetAddressCount returns the total number of unicast and multicast
// addresses on the interface.
func (n *NetIf) GetAddressCount() int {
	return len(n.unicastAddresses) + len(n.multicastAddresses)
}

// GetUnicastAddresses returns a copy of all unicast addresses.
func (n *NetIf) GetUnicastAddresses() []UnicastAddress {
	out := make([]UnicastAddress, len(n.unicastAddresses))
	copy(out, n.unicastAddresses)
	return out
}

// ---------------------------------------------------------------------------
// Multicast address management
// ---------------------------------------------------------------------------

// AddMulticastAddress subscribes to a multicast address. Returns
// ErrAlready if already subscribed, ErrInvalidArgs if not a multicast
// address.
func (n *NetIf) AddMulticastAddress(addr MulticastAddress) error {
	if addr.Address[0] != 0xff {
		return errors.ErrInvalidArgs
	}
	if n.HasMulticastAddress(addr.Address) {
		return errors.ErrAlready
	}
	n.multicastAddresses = append(n.multicastAddresses, addr)
	n.notifyChanged()
	return nil
}

// RemoveMulticastAddress unsubscribes from a multicast address. Returns
// ErrNotFound if not subscribed.
func (n *NetIf) RemoveMulticastAddress(address [16]byte) error {
	for i := range n.multicastAddresses {
		if n.multicastAddresses[i].Address == address {
			n.multicastAddresses = append(n.multicastAddresses[:i], n.multicastAddresses[i+1:]...)
			n.notifyChanged()
			return nil
		}
	}
	return errors.ErrNotFound
}

// HasMulticastAddress reports whether the interface is subscribed to the
// given multicast address.
func (n *NetIf) HasMulticastAddress(address [16]byte) bool {
	for i := range n.multicastAddresses {
		if n.multicastAddresses[i].Address == address {
			return true
		}
	}
	return false
}

// IsMulticastSubscribed is an alias for HasMulticastAddress.
func (n *NetIf) IsMulticastSubscribed(address [16]byte) bool {
	return n.HasMulticastAddress(address)
}

// GetMulticastAddresses returns a copy of all multicast subscriptions.
func (n *NetIf) GetMulticastAddresses() []MulticastAddress {
	out := make([]MulticastAddress, len(n.multicastAddresses))
	copy(out, n.multicastAddresses)
	return out
}

// ---------------------------------------------------------------------------
// Well-known multicast group subscriptions
// ---------------------------------------------------------------------------

// SubscribeAllNodesMulticast subscribes to the all-nodes multicast
// groups (link-local and realm-local).
func (n *NetIf) SubscribeAllNodesMulticast() {
	if n.subscribedAllNodes {
		return
	}
	for _, addr := range [][16]byte{AllNodesLinkLocal, AllNodesRealmLocal} {
		if !n.HasMulticastAddress(addr) {
			n.multicastAddresses = append(n.multicastAddresses,
				MulticastAddress{Address: addr, Origin: OriginThread})
		}
	}
	n.subscribedAllNodes = true
	n.notifyChanged()
}

// SubscribeAllRoutersMulticast subscribes to the all-routers multicast
// groups (link-local and realm-local).
func (n *NetIf) SubscribeAllRoutersMulticast() {
	if n.subscribedAllRouters {
		return
	}
	for _, addr := range [][16]byte{AllRoutersLinkLocal, AllRoutersRealmLocal} {
		if !n.HasMulticastAddress(addr) {
			n.multicastAddresses = append(n.multicastAddresses,
				MulticastAddress{Address: addr, Origin: OriginThread})
		}
	}
	n.subscribedAllRouters = true
	n.notifyChanged()
}

// UnsubscribeAllRoutersMulticast unsubscribes from the all-routers
// multicast groups.
func (n *NetIf) UnsubscribeAllRoutersMulticast() {
	if !n.subscribedAllRouters {
		return
	}
	for _, addr := range [][16]byte{AllRoutersLinkLocal, AllRoutersRealmLocal} {
		for i := range n.multicastAddresses {
			if n.multicastAddresses[i].Address == addr {
				n.multicastAddresses = append(n.multicastAddresses[:i], n.multicastAddresses[i+1:]...)
				break
			}
		}
	}
	n.subscribedAllRouters = false
	n.notifyChanged()
}

// GetLinkLocalAddress returns the first link-local unicast address
// (fe80::/10) on the interface, or the zero address if none is found.
func (n *NetIf) GetLinkLocalAddress() [16]byte {
	for i := range n.unicastAddresses {
		addr := n.unicastAddresses[i].Address
		if addr[0] == 0xfe && (addr[1]&0xc0) == 0x80 {
			return addr
		}
	}
	return [16]byte{}
}
