// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package ip6

import "github.com/hilli/gothread/errors"

// MaxUnsecurePorts is the maximum number of unsecure ports that a Filter can
// hold. Ports in this list are allowed to receive traffic even when link
// security is not enabled.
const MaxUnsecurePorts = 2

// Filter manages a list of "unsecure ports" — ports that are allowed to
// receive traffic without link-layer security.
//
// This is a Go port of ot::Ip6::Filter from OpenThread's
// src/core/net/ip6_filter.hpp / ip6_filter.cpp.
type Filter struct {
	unsecurePorts    [MaxUnsecurePorts]uint16
	numUnsecurePorts uint8
}

// AddUnsecurePort adds a port to the unsecure port list. Port 0 is reserved
// and returns ErrInvalidArgs. If the port is already present the call is a
// no-op. If the list is full ErrNoBufs is returned.
func (f *Filter) AddUnsecurePort(port uint16) error {
	if port == 0 {
		return errors.ErrInvalidArgs
	}

	if f.IsUnsecurePort(port) {
		return nil
	}

	if f.numUnsecurePorts >= MaxUnsecurePorts {
		return errors.ErrNoBufs
	}

	f.unsecurePorts[f.numUnsecurePorts] = port
	f.numUnsecurePorts++

	return nil
}

// RemoveUnsecurePort removes a port from the unsecure port list. Port 0 is
// reserved and returns ErrInvalidArgs. If the port is not in the list
// ErrNotFound is returned. On removal the array is compacted so that there
// are no gaps.
func (f *Filter) RemoveUnsecurePort(port uint16) error {
	if port == 0 {
		return errors.ErrInvalidArgs
	}

	for i := uint8(0); i < f.numUnsecurePorts; i++ {
		if f.unsecurePorts[i] == port {
			// Shift remaining entries left to compact.
			f.numUnsecurePorts--
			for j := i; j < f.numUnsecurePorts; j++ {
				f.unsecurePorts[j] = f.unsecurePorts[j+1]
			}
			f.unsecurePorts[f.numUnsecurePorts] = 0

			return nil
		}
	}

	return errors.ErrNotFound
}

// IsUnsecurePort reports whether the given port is in the unsecure port list.
func (f *Filter) IsUnsecurePort(port uint16) bool {
	for i := uint8(0); i < f.numUnsecurePorts; i++ {
		if f.unsecurePorts[i] == port {
			return true
		}
	}

	return false
}

// RemoveAllUnsecurePorts clears the unsecure port list.
func (f *Filter) RemoveAllUnsecurePorts() {
	f.unsecurePorts = [MaxUnsecurePorts]uint16{}
	f.numUnsecurePorts = 0
}

// GetUnsecurePorts returns a slice of the currently registered unsecure ports.
func (f *Filter) GetUnsecurePorts() []uint16 {
	return f.unsecurePorts[:f.numUnsecurePorts]
}
