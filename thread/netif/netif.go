// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package netif implements the Thread network interface, managing unicast
// and multicast IPv6 addresses and the mesh-local prefix.
//
// This is a Go port of the network interface defined in OpenThread's
// src/core/thread/thread_netif.hpp and src/core/net/netif.hpp.
package netif

// MaxUnicastAddresses is the maximum number of unicast IPv6 addresses.
const MaxUnicastAddresses = 8

// MaxMulticastAddresses is the maximum number of multicast IPv6 addresses.
const MaxMulticastAddresses = 8

// NetIf represents the Thread network interface.
type NetIf struct {
	meshLocalPrefix [8]byte
	rloc16          uint16
	isUp            bool

	unicastAddresses     [MaxUnicastAddresses][16]byte
	unicastCount         int
	multicastAddresses   [MaxMulticastAddresses][16]byte
	multicastCount       int
	subscribedAllRouters bool
}

// Init initializes the network interface to its default state.
func (n *NetIf) Init() {
	n.isUp = false
	n.rloc16 = 0
	n.unicastCount = 0
	n.multicastCount = 0
	n.subscribedAllRouters = false
	n.meshLocalPrefix = [8]byte{}
}

// Up brings the network interface up.
func (n *NetIf) Up() {
	n.isUp = true
}

// Down brings the network interface down.
func (n *NetIf) Down() {
	n.isUp = false
}

// IsUp reports whether the network interface is up.
func (n *NetIf) IsUp() bool {
	return n.isUp
}

// GetMeshLocalPrefix returns the mesh-local prefix (first 8 bytes).
func (n *NetIf) GetMeshLocalPrefix() [8]byte {
	return n.meshLocalPrefix
}

// SetMeshLocalPrefix sets the mesh-local prefix (first 8 bytes of the
// mesh-local address).
func (n *NetIf) SetMeshLocalPrefix(prefix [8]byte) {
	n.meshLocalPrefix = prefix
}

// GetRloc16 returns the RLOC16 short address.
func (n *NetIf) GetRloc16() uint16 {
	return n.rloc16
}

// SetRloc16 sets the RLOC16 short address.
func (n *NetIf) SetRloc16(rloc16 uint16) {
	n.rloc16 = rloc16
}

// GetRloc computes and returns the full 16-byte RLOC address from the
// mesh-local prefix and the RLOC16.
func (n *NetIf) GetRloc() [16]byte {
	var addr [16]byte
	copy(addr[:8], n.meshLocalPrefix[:])
	addr[8] = 0x00
	addr[9] = 0x00
	addr[10] = 0x00
	addr[11] = 0xFF
	addr[12] = 0xFE
	addr[13] = 0x00
	addr[14] = byte(n.rloc16 >> 8)
	addr[15] = byte(n.rloc16)
	return addr
}

// GetLinkLocalAddress returns the link-local IPv6 address (fe80::).
// This is a placeholder that returns a well-known prefix.
func (n *NetIf) GetLinkLocalAddress() [16]byte {
	var addr [16]byte
	addr[0] = 0xFE
	addr[1] = 0x80
	return addr
}

// AddUnicastAddress adds a unicast IPv6 address to the interface.
// Returns true on success, false if the table is full or the address
// is already present.
func (n *NetIf) AddUnicastAddress(addr [16]byte) bool {
	// Check for duplicate.
	for i := 0; i < n.unicastCount; i++ {
		if n.unicastAddresses[i] == addr {
			return false
		}
	}
	if n.unicastCount >= MaxUnicastAddresses {
		return false
	}
	n.unicastAddresses[n.unicastCount] = addr
	n.unicastCount++
	return true
}

// RemoveUnicastAddress removes a unicast IPv6 address from the interface.
// Returns true if the address was found and removed.
func (n *NetIf) RemoveUnicastAddress(addr [16]byte) bool {
	for i := 0; i < n.unicastCount; i++ {
		if n.unicastAddresses[i] == addr {
			// Shift remaining entries.
			for j := i; j < n.unicastCount-1; j++ {
				n.unicastAddresses[j] = n.unicastAddresses[j+1]
			}
			n.unicastCount--
			n.unicastAddresses[n.unicastCount] = [16]byte{}
			return true
		}
	}
	return false
}

// HasUnicastAddress reports whether the given unicast address is registered.
func (n *NetIf) HasUnicastAddress(addr [16]byte) bool {
	for i := 0; i < n.unicastCount; i++ {
		if n.unicastAddresses[i] == addr {
			return true
		}
	}
	return false
}

// AddMulticastAddress adds a multicast IPv6 address to the interface.
// Returns true on success, false if the table is full or already present.
func (n *NetIf) AddMulticastAddress(addr [16]byte) bool {
	for i := 0; i < n.multicastCount; i++ {
		if n.multicastAddresses[i] == addr {
			return false
		}
	}
	if n.multicastCount >= MaxMulticastAddresses {
		return false
	}
	n.multicastAddresses[n.multicastCount] = addr
	n.multicastCount++
	return true
}

// RemoveMulticastAddress removes a multicast IPv6 address from the interface.
// Returns true if the address was found and removed.
func (n *NetIf) RemoveMulticastAddress(addr [16]byte) bool {
	for i := 0; i < n.multicastCount; i++ {
		if n.multicastAddresses[i] == addr {
			for j := i; j < n.multicastCount-1; j++ {
				n.multicastAddresses[j] = n.multicastAddresses[j+1]
			}
			n.multicastCount--
			n.multicastAddresses[n.multicastCount] = [16]byte{}
			return true
		}
	}
	return false
}

// SubscribeAllRoutersMulticast subscribes to the all-routers multicast group.
func (n *NetIf) SubscribeAllRoutersMulticast() {
	n.subscribedAllRouters = true
}

// UnsubscribeAllRoutersMulticast unsubscribes from the all-routers multicast group.
func (n *NetIf) UnsubscribeAllRoutersMulticast() {
	n.subscribedAllRouters = false
}

// IsSubscribedAllRoutersMulticast reports whether the interface is subscribed
// to the all-routers multicast group.
func (n *NetIf) IsSubscribedAllRoutersMulticast() bool {
	return n.subscribedAllRouters
}

// GetUnicastAddressCount returns the number of registered unicast addresses.
func (n *NetIf) GetUnicastAddressCount() int {
	return n.unicastCount
}

// GetMulticastAddressCount returns the number of registered multicast addresses.
func (n *NetIf) GetMulticastAddressCount() int {
	return n.multicastCount
}
