// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package srpclient provides a fixed-size pool of SRP client service entry
// buffers. Each entry contains pre-allocated name and TXT buffers, avoiding
// dynamic allocation at runtime.
//
// This is a Go port of OpenThread's src/core/utils/srp_client_buffers.cpp.
package srpclient

import (
	"github.com/hilli/gothread/errors"
)

// Buffer size constants.
const (
	// MaxServices is the maximum number of concurrent service entries.
	MaxServices = 5
	// MaxHostAddresses is the maximum number of host addresses.
	MaxHostAddresses = 4
	// ServiceNameLen is the maximum length of a service name.
	ServiceNameLen = 64
	// InstanceNameLen is the maximum length of an instance name.
	InstanceNameLen = 64
	// MaxSubTypeLabels is the maximum number of sub-type labels per service.
	MaxSubTypeLabels = 4
	// SubTypeLabelLen is the maximum length of a sub-type label.
	SubTypeLabelLen = 64
	// TxtBufferLen is the maximum length of the TXT record buffer.
	TxtBufferLen = 256
)

// ServiceEntry represents a single SRP client service registration with
// pre-allocated buffers for names and TXT data.
type ServiceEntry struct {
	ServiceName   [ServiceNameLen]byte
	InstanceName  [InstanceNameLen]byte
	SubTypeLabels [MaxSubTypeLabels][SubTypeLabelLen]byte
	TxtBuffer     [TxtBufferLen]byte
	TxtLen        int
	Port          uint16
	Priority      uint16
	Weight        uint16
	inUse         bool
}

// IsInUse reports whether this entry is currently allocated.
func (e *ServiceEntry) IsInUse() bool {
	return e.inUse
}

// Reset clears all fields of the service entry.
func (e *ServiceEntry) Reset() {
	e.ServiceName = [ServiceNameLen]byte{}
	e.InstanceName = [InstanceNameLen]byte{}
	e.SubTypeLabels = [MaxSubTypeLabels][SubTypeLabelLen]byte{}
	e.TxtBuffer = [TxtBufferLen]byte{}
	e.TxtLen = 0
	e.Port = 0
	e.Priority = 0
	e.Weight = 0
}

// GetServiceName returns the service name as a string (up to the first NUL).
func (e *ServiceEntry) GetServiceName() string {
	return cString(e.ServiceName[:])
}

// GetInstanceName returns the instance name as a string (up to the first NUL).
func (e *ServiceEntry) GetInstanceName() string {
	return cString(e.InstanceName[:])
}

// Pool manages a fixed pool of ServiceEntry buffers.
type Pool struct {
	entries [MaxServices]ServiceEntry
}

// Allocate returns a pointer to a free ServiceEntry, or ErrNoBufs if the
// pool is exhausted.
func (p *Pool) Allocate() (*ServiceEntry, error) {
	for i := range p.entries {
		if !p.entries[i].inUse {
			p.entries[i].inUse = true
			p.entries[i].Reset()
			return &p.entries[i], nil
		}
	}
	return nil, errors.ErrNoBufs
}

// Free returns a ServiceEntry to the pool. The entry is reset and marked as
// available. It is safe to call Free with a nil pointer.
func (p *Pool) Free(entry *ServiceEntry) {
	if entry == nil {
		return
	}
	entry.Reset()
	entry.inUse = false
}

// GetFreeCount returns the number of available entries in the pool.
func (p *Pool) GetFreeCount() int {
	count := 0
	for i := range p.entries {
		if !p.entries[i].inUse {
			count++
		}
	}
	return count
}

// GetInUseCount returns the number of allocated entries in the pool.
func (p *Pool) GetInUseCount() int {
	return MaxServices - p.GetFreeCount()
}

// cString returns the Go string corresponding to a NUL-terminated byte slice.
func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
