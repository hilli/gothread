// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"errors"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// MulticastMembershipState distinguishes local intent from a current remote lease.
type MulticastMembershipState uint8

// Membership states never imply a remote prune acknowledgement.
const (
	MulticastPending MulticastMembershipState = iota
	MulticastReady
	MulticastLocalLeft
)

// MulticastMembershipStatus reports a local reference and its conservative
// remote lease. Ordinary Leave is not a remote prune ACK.
type MulticastMembershipStatus struct {
	State              MulticastMembershipState
	RemoteLeaseUnknown bool
	ExpiryPending      bool
	Err                error
}

type siteGroupEntry struct {
	address             ip6.Address
	refs                uint8
	leaseUntil, renewAt time.Time
	accepted            bool
}

// MulticastMembership is one loop-owned retained reference to a site group.
type MulticastMembership struct {
	owner  *ownedSiteGroups
	entry  *siteGroupEntry
	slot   int
	active bool
	last   MulticastMembershipStatus
}

type ownedSiteGroups struct {
	inst           *Instance
	client         *ownedMlrClient
	entries        [maxOwnedSiteGroups]*siteGroupEntry
	handles        [maxOwnedSiteGroups]*MulticastMembership
	cancelTick     func()
	stopped        bool
	mpl            *ip6.Mpl
	startScheduled bool
	pendingRx      int
	reservation    *ip6.ExternalMulticastReservation
}

func supportedSiteGroup(address ip6.Address) bool {
	return address[0] == 0xff && address[1] == 0x35 && address[2] == 0 && address[3] == 64 && address[4] == 0xfd
}

// JoinMulticast retains up to80 local references and80 distinct selected
// site5 addresses. A returned handle is pending, not an MLR ACK or RX permit.
func (inst *Instance) JoinMulticast(address ip6.Address) (*MulticastMembership, error) {
	if !supportedSiteGroup(address) {
		return nil, goterrors.ErrInvalidArgs
	}
	if _, err := inst.currentOwnedPrimaryBBR(); err != nil {
		return nil, err
	}
	owner := inst.siteGroups
	created := false
	if owner == nil {
		reservation, err := inst.netif.ReserveExternalMulticast(maxOwnedSiteGroups)
		if err != nil {
			return nil, err
		}
		client, err := newOwnedMlrClient(inst)
		if err != nil {
			if releaseErr := reservation.Release(); releaseErr != nil {
				inst.logOwnedControlError(releaseErr)
			}
			return nil, err
		}
		owner = &ownedSiteGroups{inst: inst, client: client, mpl: client.mpl, reservation: reservation}
		client.accepted = owner.accepted
		client.invalidated = owner.invalidate
		created = true
	}
	slot := -1
	for i, handle := range &owner.handles {
		if handle == nil {
			slot = i
			break
		}
	}
	if slot < 0 {
		return nil, goterrors.ErrNoBufs
	}
	var entry *siteGroupEntry
	free := -1
	for i, current := range &owner.entries {
		if current == nil {
			if free < 0 {
				free = i
			}
			continue
		}
		if current.address == address {
			entry = current
			break
		}
	}
	if entry == nil {
		if free < 0 {
			return nil, goterrors.ErrNoBufs
		}
		if err := owner.reservation.Subscribe(address); err != nil {
			if created {
				owner.client.stopMlr(err)
				if releaseErr := owner.reservation.Release(); releaseErr != nil {
					inst.logOwnedControlError(releaseErr)
				}
			}
			return nil, err
		}
		if err := owner.client.manager.AddAddress([16]byte(address)); err != nil {
			if rollback := owner.reservation.Unsubscribe(address); rollback != nil {
				inst.logOwnedControlError(rollback)
			}
			if created {
				owner.client.stopMlr(err)
				if releaseErr := owner.reservation.Release(); releaseErr != nil {
					inst.logOwnedControlError(releaseErr)
				}
			}
			return nil, err
		}
		entry = &siteGroupEntry{address: address}
		owner.entries[free] = entry
	}
	entry.refs++
	handle := &MulticastMembership{owner: owner, entry: entry, slot: slot, active: true}
	owner.handles[slot] = handle
	if created {
		inst.siteGroups = owner
		owner.scheduleTick()
	}
	// Defer sending so additional join intents can form actual15-address batches.
	if !owner.startScheduled {
		owner.startScheduled = true
		inst.deferRadioMaintenance(func() {
			owner.startScheduled = false
			if !owner.stopped && owner.client.pending == nil && owner.client.cancelRetry == nil {
				if err := owner.client.start(); err != nil {
					inst.logOwnedControlError(err)
				}
			}
		})
	}
	return handle, nil
}

// Status observes current attachment health and lease without sending traffic.
func (membership *MulticastMembership) Status() MulticastMembershipStatus {
	if !membership.active {
		return membership.last
	}
	owner, entry := membership.owner, membership.entry
	status := MulticastMembershipStatus{State: MulticastPending, RemoteLeaseUnknown: true, Err: owner.client.lastErr}
	if owner.stopped {
		if membership.last.Err != nil {
			status.Err = membership.last.Err
		}
		if status.Err == nil {
			status.Err = goterrors.ErrAbort
		}
		return status
	}
	proof, err := owner.inst.currentOwnedPrimaryBBR()
	if err != nil {
		status.Err = err
		return status
	}
	if proof != owner.client.primary {
		return status
	}
	if entry.accepted && owner.inst.timers.nowTime().Before(entry.leaseUntil) {
		status.State = MulticastReady
		status.RemoteLeaseUnknown = false
		status.Err = nil
	}
	return status
}

// Leave removes this local reference and stops its last-address renewal.
// A cleanup failure retains the reference so the caller can retry.
func (membership *MulticastMembership) Leave() error {
	if !membership.active {
		return nil
	}
	owner, entry := membership.owner, membership.entry
	if entry.refs == 1 {
		// If teardown fails the actual reference/token remains available to retry.
		if err := owner.reservation.Unsubscribe(entry.address); err != nil {
			if !errors.Is(err, goterrors.ErrNotFound) || owner.inst.netif.IsMulticastSubscribed(entry.address) {
				return err
			}
		}
		owner.client.manager.RemoveAddress([16]byte(entry.address))
		for i, current := range &owner.entries {
			if current == entry {
				owner.entries[i] = nil
				break
			}
		}
	}
	entry.refs--
	membership.active = false
	membership.last = MulticastMembershipStatus{State: MulticastLocalLeft, RemoteLeaseUnknown: true,
		ExpiryPending: entry.accepted && owner.inst.timers.nowTime().Before(entry.leaseUntil)}
	owner.handles[membership.slot] = nil
	if len(owner.client.manager.GetEntries()) == 0 {
		if !owner.stopped {
			owner.stop(goterrors.ErrAbort)
		}
		if owner.reservation != nil {
			if err := owner.reservation.Release(); err != nil {
				return err
			}
			owner.reservation = nil
		}
		if owner.inst.siteGroups == owner {
			owner.inst.siteGroups = nil
		}
	}
	return nil
}

func (owner *ownedSiteGroups) accepted(addresses [][16]byte, until time.Time) {
	now := owner.inst.timers.nowTime()
	for _, address := range addresses {
		for _, entry := range &owner.entries {
			if entry != nil && entry.refs > 0 && [16]byte(entry.address) == address {
				entry.accepted, entry.leaseUntil = true, until
				entry.renewAt = now.Add(until.Sub(now) * 3 / 4)
			}
		}
	}
}

func (owner *ownedSiteGroups) invalidate() {
	for _, entry := range &owner.entries {
		if entry != nil {
			entry.accepted = false
		}
	}
}

func (owner *ownedSiteGroups) scheduleTick() {
	owner.cancelTick = owner.inst.timers.scheduleWithCancel(time.Second, func() {
		if owner.stopped {
			return
		}
		now := owner.inst.timers.nowTime()
		for _, entry := range &owner.entries {
			if entry == nil || entry.refs == 0 {
				continue
			}
			expired := entry.accepted && !now.Before(entry.leaseUntil)
			if expired {
				entry.accepted = false
			}
			if expired || entry.accepted && !now.Before(entry.renewAt) {
				registering := false
				if batch := owner.client.pending; batch != nil {
					for _, address := range batch.addresses {
						if address == [16]byte(entry.address) {
							registering = true
							break
						}
					}
				}
				if registering {
					continue // The captured request still owns this registration attempt.
				}
				owner.client.manager.RemoveAddress([16]byte(entry.address))
				if err := owner.client.manager.AddAddress([16]byte(entry.address)); err != nil {
					owner.client.lastErr = err
					owner.inst.logOwnedControlError(err)
				}
				entry.renewAt = entry.leaseUntil
			}
		}
		if owner.client.pending == nil && owner.client.cancelRetry == nil {
			if err := owner.client.start(); err != nil {
				owner.client.lastErr = err
				owner.inst.logOwnedControlError(err)
			}
		}
		owner.scheduleTick()
	})
}

func (owner *ownedSiteGroups) stop(cause error) {
	owner.stopped = true
	if owner.cancelTick != nil {
		owner.cancelTick()
	}
	owner.client.stopMlr(cause)
	for _, handle := range &owner.handles {
		if handle == nil || !handle.active {
			continue
		}
		err := handle.Leave()
		if err != nil {
			owner.inst.logOwnedControlError(err)
			handle.last.Err = err
		}
	}
	if len(owner.client.manager.GetEntries()) == 0 && owner.reservation != nil {
		if err := owner.reservation.Release(); err != nil {
			owner.inst.logOwnedControlError(err)
		} else {
			owner.reservation = nil
		}
	}
}
