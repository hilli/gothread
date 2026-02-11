// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package srpclient

import (
	"testing"

	"github.com/hilli/gothread/errors"
)

func TestPoolInitialState(t *testing.T) {
	var p Pool
	if got := p.GetFreeCount(); got != MaxServices {
		t.Errorf("GetFreeCount() = %d, want %d", got, MaxServices)
	}
	if got := p.GetInUseCount(); got != 0 {
		t.Errorf("GetInUseCount() = %d, want 0", got)
	}
}

func TestAllocateAndFree(t *testing.T) {
	var p Pool
	entry, err := p.Allocate()
	if err != nil {
		t.Fatalf("Allocate() = %v", err)
	}
	if entry == nil {
		t.Fatal("Allocate() returned nil entry")
	}
	if !entry.IsInUse() {
		t.Error("allocated entry should be in use")
	}
	if p.GetInUseCount() != 1 {
		t.Errorf("GetInUseCount() = %d, want 1", p.GetInUseCount())
	}
	if p.GetFreeCount() != MaxServices-1 {
		t.Errorf("GetFreeCount() = %d, want %d", p.GetFreeCount(), MaxServices-1)
	}

	p.Free(entry)
	if entry.IsInUse() {
		t.Error("freed entry should not be in use")
	}
	if p.GetFreeCount() != MaxServices {
		t.Errorf("after Free: GetFreeCount() = %d, want %d", p.GetFreeCount(), MaxServices)
	}
}

func TestAllocateAll(t *testing.T) {
	var p Pool
	entries := make([]*ServiceEntry, MaxServices)
	for i := 0; i < MaxServices; i++ {
		e, err := p.Allocate()
		if err != nil {
			t.Fatalf("Allocate() #%d = %v", i, err)
		}
		entries[i] = e
	}
	if p.GetFreeCount() != 0 {
		t.Errorf("GetFreeCount() = %d, want 0", p.GetFreeCount())
	}
	// Next allocation should fail.
	_, err := p.Allocate()
	if err != errors.ErrNoBufs {
		t.Errorf("Allocate() when full = %v, want ErrNoBufs", err)
	}
	// Free one and allocate again.
	p.Free(entries[2])
	e, err := p.Allocate()
	if err != nil {
		t.Fatalf("Allocate() after Free = %v", err)
	}
	if e == nil {
		t.Fatal("Allocate() after Free returned nil")
	}
}

func TestFreeNil(t *testing.T) {
	var p Pool
	// Should not panic.
	p.Free(nil)
}

func TestServiceEntryNames(t *testing.T) {
	var p Pool
	entry, _ := p.Allocate()
	copy(entry.ServiceName[:], "_http._tcp")
	copy(entry.InstanceName[:], "My Web Server")

	if got := entry.GetServiceName(); got != "_http._tcp" {
		t.Errorf("GetServiceName() = %q, want %q", got, "_http._tcp")
	}
	if got := entry.GetInstanceName(); got != "My Web Server" {
		t.Errorf("GetInstanceName() = %q, want %q", got, "My Web Server")
	}
}

func TestServiceEntryReset(t *testing.T) {
	var p Pool
	entry, _ := p.Allocate()
	entry.Port = 8080
	entry.Priority = 10
	entry.Weight = 20
	copy(entry.ServiceName[:], "test")

	entry.Reset()
	if entry.Port != 0 || entry.Priority != 0 || entry.Weight != 0 {
		t.Error("Reset did not clear numeric fields")
	}
	if entry.GetServiceName() != "" {
		t.Errorf("Reset did not clear ServiceName, got %q", entry.GetServiceName())
	}
}

func TestServiceEntryTxtBuffer(t *testing.T) {
	var p Pool
	entry, _ := p.Allocate()
	txt := []byte{3, 'k', '=', 'v'}
	copy(entry.TxtBuffer[:], txt)
	entry.TxtLen = len(txt)

	if entry.TxtLen != 4 {
		t.Errorf("TxtLen = %d, want 4", entry.TxtLen)
	}
	for i, b := range txt {
		if entry.TxtBuffer[i] != b {
			t.Errorf("TxtBuffer[%d] = %d, want %d", i, entry.TxtBuffer[i], b)
		}
	}
}

func TestSubTypeLabels(t *testing.T) {
	var p Pool
	entry, _ := p.Allocate()
	copy(entry.SubTypeLabels[0][:], "_printer")
	copy(entry.SubTypeLabels[1][:], "_scanner")

	if got := cString(entry.SubTypeLabels[0][:]); got != "_printer" {
		t.Errorf("SubTypeLabels[0] = %q, want %q", got, "_printer")
	}
	if got := cString(entry.SubTypeLabels[1][:]); got != "_scanner" {
		t.Errorf("SubTypeLabels[1] = %q, want %q", got, "_scanner")
	}
}
