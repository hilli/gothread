// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package ip6

// IPv6 network interface for Thread networks.
//
// This is a Go port of the Netif class in OpenThread's
// src/core/net/netif.hpp and src/core/net/netif.cpp.

import (
	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Address event and origin types
// ---------------------------------------------------------------------------

// AddressEvent indicates whether an address was added or removed.
type AddressEvent bool

const (
	// AddressRemoved indicates that an address was removed.
	AddressRemoved AddressEvent = false
	// AddressAdded indicates that an address was added.
	AddressAdded AddressEvent = true
)

// AddressOrigin represents the origin of a unicast address.
type AddressOrigin uint8

const (
	// OriginThread indicates a Thread-assigned address (ALOC, RLOC, MLEID, etc).
	OriginThread AddressOrigin = 0
	// OriginSLAAC indicates a SLAAC-assigned address.
	OriginSLAAC AddressOrigin = 1
	// OriginDHCPv6 indicates a DHCPv6-assigned address.
	OriginDHCPv6 AddressOrigin = 2
	// OriginManual indicates a manually assigned address.
	OriginManual AddressOrigin = 3
)

// ---------------------------------------------------------------------------
// UnicastAddress
// ---------------------------------------------------------------------------

// UnicastAddress represents an IPv6 unicast address assigned to a network
// interface.
type UnicastAddress struct {
	// Address is the IPv6 address.
	Address Address
	// PrefixLength is the prefix length in bits (typically 64 for Thread).
	PrefixLength uint8
	// Origin is the origin of the address assignment.
	Origin AddressOrigin
	// Preferred indicates whether this address is preferred for source
	// address selection.
	Preferred bool
	// Valid indicates whether this address is valid.
	Valid bool
	// RLOC indicates whether this is a Thread Routing Locator address.
	RLOC bool
	// MeshLocal indicates whether this is a mesh-local address.
	MeshLocal bool
	// ScopeOverride overrides the scope derived from the address if
	// ScopeOverrideValid is true.
	ScopeOverride uint8
	// ScopeOverrideValid indicates whether ScopeOverride should be used
	// instead of the address-derived scope.
	ScopeOverrideValid bool
}

// GetScope returns the IPv6 scope of the unicast address. If a scope override
// is set, that value is returned; otherwise the scope is derived from the
// address itself.
func (u *UnicastAddress) GetScope() uint8 {
	if u.ScopeOverrideValid {
		return u.ScopeOverride
	}
	return u.Address.GetScope()
}

// HasPrefix reports whether the unicast address has the given prefix
// (matching both prefix length and address bits).
func (u *UnicastAddress) HasPrefix(p Prefix) bool {
	return u.PrefixLength == p.GetLength() && u.Address.MatchesPrefix(p)
}

// InitAsThreadOrigin clears the address and initialises it as a preferred,
// valid, Thread-origin address with a 64-bit prefix length.
func (u *UnicastAddress) InitAsThreadOrigin() {
	*u = UnicastAddress{}
	u.PrefixLength = NetworkPrefixLength
	u.Origin = OriginThread
	u.Preferred = true
	u.Valid = true
}

// InitAsThreadOriginMeshLocal clears the address and initialises it as a
// valid (but not preferred), Thread-origin, mesh-local address with a
// realm-local scope override.
func (u *UnicastAddress) InitAsThreadOriginMeshLocal() {
	u.InitAsThreadOrigin()
	u.ScopeOverride = ScopeRealmLocal
	u.ScopeOverrideValid = true
	u.MeshLocal = true
}

// InitAsThreadOriginGlobalScope clears the address and initialises it as a
// valid (but not preferred), Thread-origin, global-scope address.
func (u *UnicastAddress) InitAsThreadOriginGlobalScope() {
	*u = UnicastAddress{}
	u.Origin = OriginThread
	u.Valid = true
	u.ScopeOverride = ScopeGlobal
	u.ScopeOverrideValid = true
}

// InitAsSLAACOrigin clears the address and initialises it as a valid,
// SLAAC-origin address with the given prefix length and preferred flag.
func (u *UnicastAddress) InitAsSLAACOrigin(prefixLength uint8, preferred bool) {
	*u = UnicastAddress{}
	u.PrefixLength = prefixLength
	u.Origin = OriginSLAAC
	u.Preferred = preferred
	u.Valid = true
}

// NetworkPrefixLength is the standard 64-bit prefix length used by Thread
// mesh-local addresses.
const NetworkPrefixLength = 64

// ---------------------------------------------------------------------------
// MulticastAddress
// ---------------------------------------------------------------------------

// MulticastAddress represents an IPv6 multicast address subscribed to by a
// network interface.
type MulticastAddress struct {
	// Address is the IPv6 multicast address.
	Address Address
}

// ---------------------------------------------------------------------------
// AddressCallback
// ---------------------------------------------------------------------------

// AddressInfo contains information about an address change event.
type AddressInfo struct {
	// Address is the IPv6 address involved.
	Address Address
	// PrefixLength is the prefix length in bits.
	PrefixLength uint8
	// Scope is the IPv6 scope value.
	Scope uint8
	// Preferred indicates whether the address is preferred.
	Preferred bool
	// MeshLocal indicates whether the address is mesh-local.
	MeshLocal bool
}

// AddressCallback is the callback function type invoked when an address is
// added or removed.
type AddressCallback func(info AddressInfo, event AddressEvent)

// ---------------------------------------------------------------------------
// Well-known multicast addresses
// ---------------------------------------------------------------------------

// Well-known multicast addresses used by Thread.
var (
	// MulticastRealmLocalAllMPLForwarders is ff03::fc.
	MulticastRealmLocalAllMPLForwarders = Address{0xff, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfc}
	// MulticastLinkLocalAllNodes is ff02::1.
	MulticastLinkLocalAllNodes = Address{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	// MulticastRealmLocalAllNodes is ff03::1.
	MulticastRealmLocalAllNodes = Address{0xff, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	// MulticastLinkLocalAllRouters is ff02::2.
	MulticastLinkLocalAllRouters = Address{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	// MulticastRealmLocalAllRouters is ff03::2.
	MulticastRealmLocalAllRouters = Address{0xff, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
)

// fixedAllNodesChain is the ordered list of fixed multicast addresses
// appended when subscribing to all-nodes multicast:
// LinkLocalAllNodes -> RealmLocalAllNodes -> RealmLocalAllMPLForwarders.
var fixedAllNodesChain = []Address{
	MulticastLinkLocalAllNodes,
	MulticastRealmLocalAllNodes,
	MulticastRealmLocalAllMPLForwarders,
}

// fixedAllRoutersChain is the ordered list of fixed multicast addresses
// prepended when subscribing to all-routers multicast:
// LinkLocalAllRouters -> RealmLocalAllRouters.
var fixedAllRoutersChain = []Address{
	MulticastLinkLocalAllRouters,
	MulticastRealmLocalAllRouters,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// Default pool sizes for external addresses.
const (
	// MaxExternalUnicastAddresses is the maximum number of external unicast
	// addresses that can be added.
	MaxExternalUnicastAddresses = 8
	// MaxExternalMulticastAddresses is the maximum number of external
	// multicast addresses that can be subscribed.
	MaxExternalMulticastAddresses = 8
)

// ---------------------------------------------------------------------------
// Netif
// ---------------------------------------------------------------------------

// Netif represents an IPv6 network interface with unicast and multicast
// address management.
type Netif struct {
	unicastAddresses   []UnicastAddress
	multicastAddresses []MulticastAddress

	// External address pools (index-based; nil entries are free).
	extUnicast   [MaxExternalUnicastAddresses]*UnicastAddress
	extMulticast [MaxExternalMulticastAddresses]*MulticastAddress

	// subscribedAllNodes tracks whether the fixed all-nodes multicast chain
	// has been appended.
	subscribedAllNodes bool
	// subscribedAllRouters tracks whether the fixed all-routers multicast
	// chain has been appended.
	subscribedAllRouters bool

	addressCallback AddressCallback
}

// NewNetif creates a new empty network interface.
func NewNetif() *Netif {
	return &Netif{}
}

// SetAddressCallback registers a callback to be invoked on address changes.
func (n *Netif) SetAddressCallback(cb AddressCallback) {
	n.addressCallback = cb
}

// ---------------------------------------------------------------------------
// Unicast address management
// ---------------------------------------------------------------------------

// GetUnicastAddresses returns the list of unicast addresses on this interface.
func (n *Netif) GetUnicastAddresses() []UnicastAddress {
	return n.unicastAddresses
}

// AddUnicastAddress adds an internal (Thread-managed) unicast address to the
// interface. If the address is already present, no action is taken.
func (n *Netif) AddUnicastAddress(addr *UnicastAddress) {
	if n.hasUnicastEntry(addr) {
		return
	}
	n.unicastAddresses = append(n.unicastAddresses, *addr)
	n.signalUnicastAddressChange(AddressAdded, addr)
}

// RemoveUnicastAddress removes an internal unicast address from the interface.
// If the address is not present, no action is taken.
func (n *Netif) RemoveUnicastAddress(addr *UnicastAddress) {
	idx := n.findUnicastByAddress(addr.Address)
	if idx < 0 {
		return
	}
	removed := n.unicastAddresses[idx]
	n.unicastAddresses = append(n.unicastAddresses[:idx], n.unicastAddresses[idx+1:]...)
	n.signalUnicastAddressChange(AddressRemoved, &removed)
}

// HasUnicastAddress reports whether the given IPv6 address is assigned to the
// interface.
func (n *Netif) HasUnicastAddress(addr Address) bool {
	return n.findUnicastByAddress(addr) >= 0
}

// UpdatePreferredFlagOn updates the preferred flag of a unicast address. If
// the address is not present or the flag is already the desired value, no
// action is taken.
func (n *Netif) UpdatePreferredFlagOn(addr Address, preferred bool) {
	idx := n.findUnicastByAddress(addr)
	if idx < 0 {
		return
	}
	if n.unicastAddresses[idx].Preferred == preferred {
		return
	}
	n.signalUnicastAddressChange(AddressRemoved, &n.unicastAddresses[idx])
	n.unicastAddresses[idx].Preferred = preferred
	n.signalUnicastAddressChange(AddressAdded, &n.unicastAddresses[idx])
}

// AddExternalUnicastAddress adds an external unicast address, allocating from
// the internal pool. If the address is already present as an external address
// it is updated. Returns an error if the pool is exhausted or the address is
// invalid.
func (n *Netif) AddExternalUnicastAddress(addr *UnicastAddress) error {
	if addr.Address.IsMulticast() {
		return errors.ErrInvalidArgs
	}

	// Check if the address already exists.
	idx := n.findUnicastByAddress(addr.Address)
	if idx >= 0 {
		existing := &n.unicastAddresses[idx]
		if !n.isUnicastExternal(existing) {
			return errors.ErrInvalidArgs
		}
		// Update mutable fields.
		existing.PrefixLength = addr.PrefixLength
		existing.Origin = addr.Origin
		existing.Preferred = addr.Preferred
		existing.Valid = addr.Valid
		return nil
	}

	if addr.Address.IsLinkLocalUnicast() {
		return errors.ErrInvalidArgs
	}

	// Allocate from external pool.
	poolIdx := n.allocExtUnicast()
	if poolIdx < 0 {
		return errors.ErrNoBufs
	}

	entry := *addr
	entry.RLOC = false
	entry.MeshLocal = false
	n.unicastAddresses = append(n.unicastAddresses, entry)
	n.extUnicast[poolIdx] = &n.unicastAddresses[len(n.unicastAddresses)-1]
	n.signalUnicastAddressChange(AddressAdded, &n.unicastAddresses[len(n.unicastAddresses)-1])
	return nil
}

// RemoveExternalUnicastAddress removes an external unicast address. Returns
// an error if the address is not found or is an internal address.
func (n *Netif) RemoveExternalUnicastAddress(addr Address) error {
	idx := n.findUnicastByAddress(addr)
	if idx < 0 {
		return errors.ErrNotFound
	}

	entry := &n.unicastAddresses[idx]
	if !n.isUnicastExternal(entry) {
		return errors.ErrRejected
	}

	removed := *entry
	n.freeExtUnicast(entry)
	n.unicastAddresses = append(n.unicastAddresses[:idx], n.unicastAddresses[idx+1:]...)
	n.fixExtUnicastPointers()
	n.signalUnicastAddressChange(AddressRemoved, &removed)
	return nil
}

// RemoveAllExternalUnicastAddresses removes all external unicast addresses.
func (n *Netif) RemoveAllExternalUnicastAddresses() {
	// Iterate backwards to avoid index invalidation.
	for i := len(n.unicastAddresses) - 1; i >= 0; i-- {
		if n.isUnicastExternal(&n.unicastAddresses[i]) {
			_ = n.RemoveExternalUnicastAddress(n.unicastAddresses[i].Address)
		}
	}
}

// IsUnicastAddressExternal reports whether the given unicast address is
// external (was added via AddExternalUnicastAddress).
func (n *Netif) IsUnicastAddressExternal(addr Address) bool {
	idx := n.findUnicastByAddress(addr)
	if idx < 0 {
		return false
	}
	return n.isUnicastExternal(&n.unicastAddresses[idx])
}

// ---------------------------------------------------------------------------
// Multicast address management
// ---------------------------------------------------------------------------

// GetMulticastAddresses returns the list of multicast addresses subscribed to
// by this interface.
func (n *Netif) GetMulticastAddresses() []MulticastAddress {
	return n.multicastAddresses
}

// IsMulticastSubscribed reports whether the interface is subscribed to the
// given multicast address.
func (n *Netif) IsMulticastSubscribed(addr Address) bool {
	return n.findMulticastByAddress(addr) >= 0
}

// SubscribeMulticast subscribes to an internal multicast address. If already
// subscribed, no action is taken.
func (n *Netif) SubscribeMulticast(addr Address) {
	if n.IsMulticastSubscribed(addr) {
		return
	}
	n.multicastAddresses = append(n.multicastAddresses, MulticastAddress{Address: addr})
	n.signalMulticastAddressChange(AddressAdded, addr, OriginThread)
}

// UnsubscribeMulticast unsubscribes from an internal multicast address. If
// not subscribed, no action is taken.
func (n *Netif) UnsubscribeMulticast(addr Address) {
	idx := n.findMulticastByAddress(addr)
	if idx < 0 {
		return
	}
	n.multicastAddresses = append(n.multicastAddresses[:idx], n.multicastAddresses[idx+1:]...)
	n.fixExtMulticastPointers()
	n.signalMulticastAddressChange(AddressRemoved, addr, OriginThread)
}

// SubscribeAllNodesMulticast subscribes to the all-nodes multicast group
// (link-local and realm-local all nodes, plus realm-local all MPL
// forwarders).
func (n *Netif) SubscribeAllNodesMulticast() {
	if n.subscribedAllNodes {
		return
	}
	for _, addr := range fixedAllNodesChain {
		if !n.IsMulticastSubscribed(addr) {
			n.multicastAddresses = append(n.multicastAddresses, MulticastAddress{Address: addr})
			n.signalMulticastAddressChange(AddressAdded, addr, OriginThread)
		}
	}
	n.subscribedAllNodes = true
}

// UnsubscribeAllNodesMulticast unsubscribes from the all-nodes multicast
// group. Must be called after UnsubscribeAllRoutersMulticast.
func (n *Netif) UnsubscribeAllNodesMulticast() {
	if !n.subscribedAllNodes {
		return
	}
	for _, addr := range fixedAllNodesChain {
		idx := n.findMulticastByAddress(addr)
		if idx >= 0 {
			n.multicastAddresses = append(n.multicastAddresses[:idx], n.multicastAddresses[idx+1:]...)
			n.fixExtMulticastPointers()
			n.signalMulticastAddressChange(AddressRemoved, addr, OriginThread)
		}
	}
	n.subscribedAllNodes = false
}

// SubscribeAllRoutersMulticast subscribes to the all-routers multicast group
// (link-local and realm-local all routers). Must be called after
// SubscribeAllNodesMulticast.
func (n *Netif) SubscribeAllRoutersMulticast() {
	if n.subscribedAllRouters {
		return
	}
	for _, addr := range fixedAllRoutersChain {
		if !n.IsMulticastSubscribed(addr) {
			n.multicastAddresses = append(n.multicastAddresses, MulticastAddress{Address: addr})
			n.signalMulticastAddressChange(AddressAdded, addr, OriginThread)
		}
	}
	n.subscribedAllRouters = true
}

// UnsubscribeAllRoutersMulticast unsubscribes from the all-routers multicast
// group.
func (n *Netif) UnsubscribeAllRoutersMulticast() {
	if !n.subscribedAllRouters {
		return
	}
	for _, addr := range fixedAllRoutersChain {
		idx := n.findMulticastByAddress(addr)
		if idx >= 0 {
			n.multicastAddresses = append(n.multicastAddresses[:idx], n.multicastAddresses[idx+1:]...)
			n.fixExtMulticastPointers()
			n.signalMulticastAddressChange(AddressRemoved, addr, OriginThread)
		}
	}
	n.subscribedAllRouters = false
}

// SubscribeExternalMulticast subscribes to an external multicast address,
// allocating from the internal pool. Returns an error if the address is
// invalid, already subscribed, is a fixed internal address, or the pool is
// exhausted.
func (n *Netif) SubscribeExternalMulticast(addr Address) error {
	if !addr.IsMulticast() {
		return errors.ErrInvalidArgs
	}
	if n.IsMulticastSubscribed(addr) {
		return errors.ErrAlready
	}
	if isFixedMulticast(addr) {
		return errors.ErrRejected
	}

	poolIdx := n.allocExtMulticast()
	if poolIdx < 0 {
		return errors.ErrNoBufs
	}

	n.multicastAddresses = append(n.multicastAddresses, MulticastAddress{Address: addr})
	n.extMulticast[poolIdx] = &n.multicastAddresses[len(n.multicastAddresses)-1]
	n.signalMulticastAddressChange(AddressAdded, addr, OriginManual)
	return nil
}

// UnsubscribeExternalMulticast unsubscribes from an external multicast
// address. Returns an error if not found or if the address is an internal
// address.
func (n *Netif) UnsubscribeExternalMulticast(addr Address) error {
	idx := n.findMulticastByAddress(addr)
	if idx < 0 {
		return errors.ErrNotFound
	}

	entry := &n.multicastAddresses[idx]
	if !n.isMulticastExternal(entry) {
		return errors.ErrRejected
	}

	n.freeExtMulticast(entry)
	n.multicastAddresses = append(n.multicastAddresses[:idx], n.multicastAddresses[idx+1:]...)
	n.fixExtMulticastPointers()
	n.signalMulticastAddressChange(AddressRemoved, addr, OriginManual)
	return nil
}

// UnsubscribeAllExternalMulticastAddresses removes all external multicast
// addresses.
func (n *Netif) UnsubscribeAllExternalMulticastAddresses() {
	for i := len(n.multicastAddresses) - 1; i >= 0; i-- {
		if n.isMulticastExternal(&n.multicastAddresses[i]) {
			_ = n.UnsubscribeExternalMulticast(n.multicastAddresses[i].Address)
		}
	}
}

// IsMulticastAddressExternal reports whether the given multicast address was
// added as an external subscription.
func (n *Netif) IsMulticastAddressExternal(addr Address) bool {
	idx := n.findMulticastByAddress(addr)
	if idx < 0 {
		return false
	}
	return n.isMulticastExternal(&n.multicastAddresses[idx])
}

// ---------------------------------------------------------------------------
// Internal helpers — unicast
// ---------------------------------------------------------------------------

func (n *Netif) findUnicastByAddress(addr Address) int {
	for i := range n.unicastAddresses {
		if n.unicastAddresses[i].Address == addr {
			return i
		}
	}
	return -1
}

func (n *Netif) hasUnicastEntry(addr *UnicastAddress) bool {
	for i := range n.unicastAddresses {
		if n.unicastAddresses[i].Address == addr.Address {
			return true
		}
	}
	return false
}

func (n *Netif) isUnicastExternal(addr *UnicastAddress) bool {
	for _, p := range n.extUnicast {
		if p != nil && p.Address == addr.Address {
			return true
		}
	}
	return false
}

func (n *Netif) allocExtUnicast() int {
	for i, p := range n.extUnicast {
		if p == nil {
			return i
		}
	}
	return -1
}

func (n *Netif) freeExtUnicast(addr *UnicastAddress) {
	for i, p := range n.extUnicast {
		if p != nil && p.Address == addr.Address {
			n.extUnicast[i] = nil
			return
		}
	}
}

// fixExtUnicastPointers rebuilds the external unicast pool pointers after
// the slice has been modified (elements may have moved).
func (n *Netif) fixExtUnicastPointers() {
	for i, p := range n.extUnicast {
		if p == nil {
			continue
		}
		found := false
		for j := range n.unicastAddresses {
			if n.unicastAddresses[j].Address == p.Address {
				n.extUnicast[i] = &n.unicastAddresses[j]
				found = true
				break
			}
		}
		if !found {
			n.extUnicast[i] = nil
		}
	}
}

// ---------------------------------------------------------------------------
// Internal helpers — multicast
// ---------------------------------------------------------------------------

func (n *Netif) findMulticastByAddress(addr Address) int {
	for i := range n.multicastAddresses {
		if n.multicastAddresses[i].Address == addr {
			return i
		}
	}
	return -1
}

func (n *Netif) isMulticastExternal(addr *MulticastAddress) bool {
	for _, p := range n.extMulticast {
		if p != nil && p.Address == addr.Address {
			return true
		}
	}
	return false
}

func (n *Netif) allocExtMulticast() int {
	for i, p := range n.extMulticast {
		if p == nil {
			return i
		}
	}
	return -1
}

func (n *Netif) freeExtMulticast(addr *MulticastAddress) {
	for i, p := range n.extMulticast {
		if p != nil && p.Address == addr.Address {
			n.extMulticast[i] = nil
			return
		}
	}
}

// fixExtMulticastPointers rebuilds the external multicast pool pointers after
// the slice has been modified.
func (n *Netif) fixExtMulticastPointers() {
	for i, p := range n.extMulticast {
		if p == nil {
			continue
		}
		found := false
		for j := range n.multicastAddresses {
			if n.multicastAddresses[j].Address == p.Address {
				n.extMulticast[i] = &n.multicastAddresses[j]
				found = true
				break
			}
		}
		if !found {
			n.extMulticast[i] = nil
		}
	}
}

// isFixedMulticast returns true if the address is one of the well-known
// fixed multicast addresses managed by SubscribeAllNodesMulticast and
// SubscribeAllRoutersMulticast.
func isFixedMulticast(addr Address) bool {
	fixed := []Address{
		MulticastRealmLocalAllMPLForwarders,
		MulticastLinkLocalAllNodes,
		MulticastRealmLocalAllNodes,
		MulticastLinkLocalAllRouters,
		MulticastRealmLocalAllRouters,
	}
	for _, f := range fixed {
		if addr == f {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Signalling
// ---------------------------------------------------------------------------

func (n *Netif) signalUnicastAddressChange(event AddressEvent, addr *UnicastAddress) {
	if n.addressCallback == nil {
		return
	}
	info := AddressInfo{
		Address:      addr.Address,
		PrefixLength: addr.PrefixLength,
		Scope:        addr.GetScope(),
		Preferred:    addr.Preferred,
		MeshLocal:    addr.MeshLocal,
	}
	n.addressCallback(info, event)
}

func (n *Netif) signalMulticastAddressChange(event AddressEvent, addr Address, _ AddressOrigin) {
	if n.addressCallback == nil {
		return
	}
	info := AddressInfo{
		Address:      addr,
		PrefixLength: 128,
		Scope:        addr.GetScope(),
		Preferred:    false,
		MeshLocal:    false,
	}
	n.addressCallback(info, event)
}
