// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mac

import (
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/submac"
)

// DiscoveryRadioLease excludes ordinary MAC operations without changing the
// configured PAN/channel/RX-on-idle identity. It owns no queue or frame pool.
type DiscoveryRadioLease struct {
	mac     *Mac
	channel uint8
	state   submac.State
}

// AcquireDiscoveryRadio is loop-only. Busy is retryable; it never interrupts
// an in-flight packet, energy/beacon scan or pending ordinary operation.
func (m *Mac) AcquireDiscoveryRadio() (*DiscoveryRadioLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled || m.subMac == nil {
		return nil, goterrors.ErrInvalidState
	}
	if m.discoveryLease != nil || m.currentOp != OperationIdle || m.pendingOps != 0 ||
		m.scanning || m.energyScanning || m.subMac.IsTransmittingOrScanning() {
		return nil, goterrors.ErrBusy
	}
	state := m.subMac.GetState()
	if state != submac.StateReceive && state != submac.StateSleep {
		return nil, goterrors.ErrInvalidState
	}
	lease := &DiscoveryRadioLease{mac: m, channel: m.radioChannel, state: state}
	m.discoveryLease = lease
	return lease, nil
}

// Restore releases ownership only after the actual fallible RX/sleep restore.
// The caller restores the driver's PAN filter before this call; configured
// MAC/SubMac PAN state was never changed by the temporary receive filter.
func (lease *DiscoveryRadioLease) Restore() error {
	return lease.restore(true)
}

// RestoreStopped requires the caller's stopped-stack serialization. It restores
// the same physical state but cannot schedule pending ordinary MAC operations.
func (lease *DiscoveryRadioLease) RestoreStopped() error {
	return lease.restore(false)
}

func (lease *DiscoveryRadioLease) restore(resume bool) error {
	if lease == nil || lease.mac == nil {
		return goterrors.ErrInvalidState
	}
	m := lease.mac
	m.mu.Lock()
	if m.discoveryLease != lease {
		m.mu.Unlock()
		return goterrors.ErrInvalidState
	}
	if m.subMac.IsTransmittingOrScanning() {
		m.mu.Unlock()
		return goterrors.ErrBusy
	}
	m.mu.Unlock()
	var err error
	if lease.state == submac.StateReceive {
		err = m.subMac.Receive(lease.channel)
	} else {
		err = m.subMac.Sleep()
	}
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.discoveryLease != lease {
		return goterrors.ErrInvalidState
	}
	m.discoveryLease = nil
	if resume {
		m.scheduleNextOperation()
	}
	return nil
}
