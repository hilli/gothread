// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package routing

import (
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// Child address capacity limits.
const (
	// MaxRequestTLVs is the maximum number of TLVs in a child request.
	MaxRequestTLVs = 6
	// MaxChildIP6Addrs is the maximum number of IPv6 addresses per child
	// (OPENTHREAD_CONFIG_MLE_IP_ADDRS_PER_CHILD default).
	MaxChildIP6Addrs = 4
)

// Child represents a Thread child neighbor.
type Child struct {
	Neighbor
	Timeout                 uint32
	MeshLocalIID            ip6.InterfaceIdentifier
	IP6Addresses            []ip6.Address // up to MaxChildIP6Addrs - 1 (mesh local stored separately)
	NetworkDataVersion      uint8
	RequestTLVs             [MaxRequestTLVs]uint8
	SupervisionInterval     uint16
	SecondsSinceSupervision uint16
}

// GetMeshLocalIP6Address constructs the mesh-local IPv6 address from the
// given network prefix and the child's MeshLocalIID.
func (c *Child) GetMeshLocalIP6Address(prefix ip6.NetworkPrefix) (ip6.Address, error) {
	if c.MeshLocalIID == (ip6.InterfaceIdentifier{}) {
		return ip6.Address{}, goterrors.ErrNotFound
	}
	var addr ip6.Address
	addr.SetPrefix(prefix)
	addr.SetIid(c.MeshLocalIID)
	return addr, nil
}

// HasIP6Address returns true if the child has the given IPv6 address in its
// address list.
func (c *Child) HasIP6Address(addr ip6.Address) bool {
	for i := range c.IP6Addresses {
		if c.IP6Addresses[i] == addr {
			return true
		}
	}
	return false
}

// AddIP6Address adds an IPv6 address to the child's address list.
// Returns ErrAlready if the address is already present, or ErrNoBufs if
// the list is full.
func (c *Child) AddIP6Address(addr ip6.Address) error {
	if c.HasIP6Address(addr) {
		return goterrors.ErrAlready
	}
	if len(c.IP6Addresses) >= MaxChildIP6Addrs-1 {
		return goterrors.ErrNoBufs
	}
	c.IP6Addresses = append(c.IP6Addresses, addr)
	return nil
}

// RemoveIP6Address removes an IPv6 address from the child's address list.
// Returns ErrNotFound if the address is not present.
func (c *Child) RemoveIP6Address(addr ip6.Address) error {
	for i := range c.IP6Addresses {
		if c.IP6Addresses[i] == addr {
			c.IP6Addresses = append(c.IP6Addresses[:i], c.IP6Addresses[i+1:]...)
			return nil
		}
	}
	return goterrors.ErrNotFound
}

// ClearIP6Addresses removes all IPv6 addresses from the child's address list.
func (c *Child) ClearIP6Addresses() {
	c.IP6Addresses = c.IP6Addresses[:0]
}

// GetIP6AddressCount returns the number of IPv6 addresses the child has.
func (c *Child) GetIP6AddressCount() int {
	return len(c.IP6Addresses)
}
