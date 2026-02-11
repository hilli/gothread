// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package peer

import (
	"testing"
	"time"

	"github.com/hilli/gothread/errors"
)

func TestPeerStateString(t *testing.T) {
	tests := []struct {
		state PeerState
		want  string
	}{
		{StateDiscovered, "Discovered"},
		{StateConnecting, "Connecting"},
		{StateConnected, "Connected"},
		{StateDisconnected, "Disconnected"},
		{PeerState(99), "Unknown"},
	}
	for _, tc := range tests {
		if got := tc.state.String(); got != tc.want {
			t.Errorf("PeerState(%d).String() = %q, want %q", tc.state, got, tc.want)
		}
	}
}

func TestNewPeerTable(t *testing.T) {
	pt := NewPeerTable(0)
	if pt.maxPeers != DefaultMaxPeers {
		t.Errorf("maxPeers = %d, want %d", pt.maxPeers, DefaultMaxPeers)
	}
	pt2 := NewPeerTable(8)
	if pt2.maxPeers != 8 {
		t.Errorf("maxPeers = %d, want 8", pt2.maxPeers)
	}
}

func makePeer(id byte) Peer {
	var addr [8]byte
	addr[0] = id
	return Peer{
		ExtAddress: addr,
		Rloc16:     uint16(id) * 100,
		LastHeard:  time.Now(),
		State:      StateDiscovered,
	}
}

func TestAddAndFind(t *testing.T) {
	pt := NewPeerTable(4)
	p := makePeer(1)
	if err := pt.Add(p); err != nil {
		t.Fatalf("Add() = %v", err)
	}
	if pt.GetCount() != 1 {
		t.Errorf("GetCount() = %d, want 1", pt.GetCount())
	}
	found, ok := pt.Find(p.ExtAddress)
	if !ok {
		t.Fatal("Find() returned false")
	}
	if found.ExtAddress != p.ExtAddress {
		t.Error("Find() returned wrong peer")
	}
}

func TestAddDuplicate(t *testing.T) {
	pt := NewPeerTable(4)
	p := makePeer(1)
	pt.Add(p)
	if err := pt.Add(p); err != errors.ErrAlready {
		t.Errorf("duplicate Add() = %v, want ErrAlready", err)
	}
}

func TestAddFull(t *testing.T) {
	pt := NewPeerTable(2)
	pt.Add(makePeer(1))
	pt.Add(makePeer(2))
	if err := pt.Add(makePeer(3)); err != errors.ErrNoBufs {
		t.Errorf("Add() when full = %v, want ErrNoBufs", err)
	}
}

func TestRemove(t *testing.T) {
	pt := NewPeerTable(4)
	p1 := makePeer(1)
	p2 := makePeer(2)
	pt.Add(p1)
	pt.Add(p2)

	pt.Remove(p1.ExtAddress)
	if pt.GetCount() != 1 {
		t.Errorf("GetCount() = %d, want 1", pt.GetCount())
	}
	_, ok := pt.Find(p1.ExtAddress)
	if ok {
		t.Error("removed peer should not be found")
	}
	_, ok = pt.Find(p2.ExtAddress)
	if !ok {
		t.Error("remaining peer should be found")
	}
}

func TestRemoveNonExistent(t *testing.T) {
	pt := NewPeerTable(4)
	pt.Add(makePeer(1))
	pt.Remove(makePeer(99).ExtAddress) // no-op
	if pt.GetCount() != 1 {
		t.Errorf("GetCount() = %d, want 1", pt.GetCount())
	}
}

func TestFindByRloc16(t *testing.T) {
	pt := NewPeerTable(4)
	p := makePeer(5)
	pt.Add(p)
	found, ok := pt.FindByRloc16(p.Rloc16)
	if !ok {
		t.Fatal("FindByRloc16() returned false")
	}
	if found.Rloc16 != p.Rloc16 {
		t.Error("FindByRloc16() returned wrong peer")
	}
	_, ok = pt.FindByRloc16(9999)
	if ok {
		t.Error("FindByRloc16() should return false for unknown RLOC")
	}
}

func TestForEach(t *testing.T) {
	pt := NewPeerTable(4)
	pt.Add(makePeer(1))
	pt.Add(makePeer(2))
	pt.Add(makePeer(3))

	count := 0
	pt.ForEach(func(p *Peer) {
		count++
	})
	if count != 3 {
		t.Errorf("ForEach visited %d peers, want 3", count)
	}
}

func TestClear(t *testing.T) {
	pt := NewPeerTable(4)
	pt.Add(makePeer(1))
	pt.Add(makePeer(2))
	pt.Clear()
	if pt.GetCount() != 0 {
		t.Errorf("GetCount() after Clear = %d, want 0", pt.GetCount())
	}
}

func TestForEachMutation(t *testing.T) {
	pt := NewPeerTable(4)
	pt.Add(makePeer(1))
	pt.Add(makePeer(2))

	// ForEach should allow mutating peer state.
	pt.ForEach(func(p *Peer) {
		p.State = StateConnected
	})
	pt.ForEach(func(p *Peer) {
		if p.State != StateConnected {
			t.Errorf("peer state = %v, want Connected", p.State)
		}
	})
}

func TestFindNotFound(t *testing.T) {
	pt := NewPeerTable(4)
	_, ok := pt.Find([8]byte{0xFF})
	if ok {
		t.Error("Find() on empty table should return false")
	}
}
