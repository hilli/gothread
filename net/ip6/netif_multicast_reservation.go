// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package ip6

import "github.com/hilli/gothread/errors"

// ExternalMulticastReservation is an explicit protocol owner's bounded pool.
// The ordinary external API still has exactly8 slots before, during and after
// a reservation. Reserved subscriptions stay external, not internal aliases.
type ExternalMulticastReservation struct {
	netif  *Netif
	pool   []*MulticastAddress
	active bool
}

// ReserveExternalMulticast creates one bounded protocol-owned external pool.
func (n *Netif) ReserveExternalMulticast(capacity int) (*ExternalMulticastReservation, error) {
	if capacity <= 0 || capacity > MaxReservedExternalMulticastAddresses {
		return nil, errors.ErrInvalidArgs
	}
	if n.reservedMulticast != nil {
		return nil, errors.ErrBusy
	}
	reservation := &ExternalMulticastReservation{netif: n, pool: make([]*MulticastAddress, capacity), active: true}
	n.reservedMulticast = reservation
	return reservation, nil
}

func (reservation *ExternalMulticastReservation) owns(entry *MulticastAddress) bool {
	for _, owned := range reservation.pool {
		if owned == entry {
			return true
		}
	}
	return false
}

func (reservation *ExternalMulticastReservation) fixPointers() {
	for i, old := range reservation.pool {
		if old == nil {
			continue
		}
		reservation.pool[i] = nil
		for j := range reservation.netif.multicastAddresses {
			current := &reservation.netif.multicastAddresses[j]
			if current.Address == old.Address {
				reservation.pool[i] = current
				break
			}
		}
	}
}

// Subscribe acquires one genuine external subscription in this owner's pool.
func (reservation *ExternalMulticastReservation) Subscribe(address Address) error {
	if !reservation.active {
		return errors.ErrInvalidState
	}
	if !address.IsMulticast() {
		return errors.ErrInvalidArgs
	}
	if reservation.netif.IsMulticastSubscribed(address) {
		return errors.ErrAlready
	}
	if isFixedMulticast(address) {
		return errors.ErrRejected
	}
	slot := -1
	for i, entry := range reservation.pool {
		if entry == nil {
			slot = i
			break
		}
	}
	if slot < 0 {
		return errors.ErrNoBufs
	}
	n := reservation.netif
	n.multicastAddresses = append(n.multicastAddresses, MulticastAddress{Address: address})
	n.fixExtMulticastPointers()
	reservation.pool[slot] = &n.multicastAddresses[len(n.multicastAddresses)-1]
	n.signalMulticastAddressChange(AddressAdded, address, OriginManual)
	return nil
}

// Unsubscribe removes only a subscription owned by this reservation.
func (reservation *ExternalMulticastReservation) Unsubscribe(address Address) error {
	if !reservation.active {
		return errors.ErrInvalidState
	}
	n := reservation.netif
	index := n.findMulticastByAddress(address)
	if index < 0 {
		return errors.ErrNotFound
	}
	entry := &n.multicastAddresses[index]
	if !reservation.owns(entry) {
		return errors.ErrRejected
	}
	for i, owned := range reservation.pool {
		if owned == entry {
			reservation.pool[i] = nil
			break
		}
	}
	n.removeMulticast(index)
	n.signalMulticastAddressChange(AddressRemoved, address, OriginManual)
	return nil
}

// Release removes this owner's subscriptions without changing the default pool.
func (reservation *ExternalMulticastReservation) Release() error {
	if !reservation.active {
		return nil
	}
	for _, entry := range reservation.pool {
		if entry != nil {
			if err := reservation.Unsubscribe(entry.Address); err != nil {
				return err
			}
		}
	}
	reservation.netif.reservedMulticast = nil
	reservation.active = false
	reservation.pool = nil
	return nil
}
