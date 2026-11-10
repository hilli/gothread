// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import (
	"bytes"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
)

func reassemblyFixture() (*Forwarder, FragmentKey, []byte) {
	f := NewForwarder()
	f.SetEnabled(true)
	key := FragmentKey{Tag: 0x1234, Size: 160, Scope: FragmentScope{
		Source:      [8]byte{0xaa, 1, 2, 3, 4, 5, 0x66, 0x77},
		Destination: [8]byte{0xbb, 1, 2, 3, 4, 5, 6, 7},
		PanID:       0xface, Channel: 20, Secured: true,
	}}
	packet := make([]byte, key.Size)
	for i := range packet {
		packet[i] = byte(i)
	}
	return f, key, packet
}

func TestScopedReassemblyFirstLateDuplicateAndOwnership(t *testing.T) {
	f, key, packet := reassemblyFixture()
	for _, part := range []struct{ start, end int }{{128, 160}, {64, 128}, {64, 128}} {
		data := append([]byte(nil), packet[part.start:part.end]...)
		if got, err := f.HandleScopedFragment(key, uint16(part.start), data); err != nil || got != nil {
			t.Fatalf("out-of-order/duplicate part: %x %v", got, err)
		}
		clear(data)
	}
	got, err := f.HandleScopedFragment(key, 0, packet[:64])
	if err != nil || !bytes.Equal(got, packet) {
		t.Fatalf("first-late completion: %x %v", got, err)
	}
	if usage := f.GetBufferUsage(); usage.RxDatagrams != 0 || usage.RxBytes != 0 {
		t.Fatalf("completed buffers retained: %+v", usage)
	}
	for _, part := range []struct{ start, end int }{{0, 64}, {64, 128}, {128, 160}} {
		if duplicate, err := f.HandleScopedFragment(key, uint16(part.start), packet[part.start:part.end]); err != nil || duplicate != nil {
			t.Fatalf("completed datagram delivered twice: %x %v", duplicate, err)
		}
	}
}

func TestScopedReassemblyRejectsOverlapAndSizeConflicts(t *testing.T) {
	for _, kind := range []string{"partial-identical", "partial-conflicting", "exact-conflicting", "size-conflict"} {
		t.Run(kind, func(t *testing.T) {
			f, key, packet := reassemblyFixture()
			if _, err := f.HandleScopedFragment(key, 0, packet[:64]); err != nil {
				t.Fatal(err)
			}
			offset, data := uint16(56), append([]byte(nil), packet[56:72]...)
			switch kind {
			case "partial-conflicting":
				data[0] ^= 0xff
			case "exact-conflicting":
				offset, data = 0, append([]byte(nil), packet[:64]...)
				data[1] ^= 0xff
			case "size-conflict":
				key.Size += 8
				offset, data = 64, packet[64:128]
			}
			if got, err := f.HandleScopedFragment(key, offset, data); err != goterrors.ErrParse || got != nil {
				t.Fatalf("conflict accepted: %x %v", got, err)
			}
			if usage := f.GetBufferUsage(); usage.RxBytes != 0 || usage.RxDatagrams != 0 {
				t.Fatalf("conflicting datagram retained resources: %+v", usage)
			}
			if got, _ := f.HandleScopedFragment(key, 64, packet[64:128]); got != nil || f.GetReassemblyList() != 0 {
				t.Fatal("late fragment revived rejected datagram")
			}
		})
	}
}

func TestScopedReassemblyFullPeerAndLinkIdentity(t *testing.T) {
	for _, edit := range []func(*FragmentScope){
		func(s *FragmentScope) { s.Source[0] ^= 1 }, // Same final 16 source bits.
		func(s *FragmentScope) { s.Destination[0] ^= 1 },
		func(s *FragmentScope) { s.PanID++ },
		func(s *FragmentScope) { s.Channel++ },
		func(s *FragmentScope) { s.Secured = false },
	} {
		f, a, packet := reassemblyFixture()
		b := a
		edit(&b.Scope)
		other := append([]byte(nil), packet...)
		other[100] ^= 1
		if _, err := f.HandleScopedFragment(a, 0, packet[:64]); err != nil {
			t.Fatal(err)
		}
		if result, err := f.HandleScopedFragment(b, 64, other[64:]); err != nil || result != nil {
			t.Fatalf("merged peer contexts: %x %v", result, err)
		}
		if result, err := f.HandleScopedFragment(a, 64, packet[64:]); err != nil || !bytes.Equal(result, packet) {
			t.Fatal("first peer assembly corrupted")
		}
		if result, err := f.HandleScopedFragment(b, 0, other[:64]); err != nil || !bytes.Equal(result, other) {
			t.Fatal("second peer assembly corrupted")
		}
	}
}

func TestScopedReassemblyValidationBeforeAllocation(t *testing.T) {
	for _, test := range []struct {
		size, offset int
		data         int
	}{
		{0, 0, 64}, {39, 0, 40}, {1281, 0, 64}, {2047, 0, 64},
		{160, 1, 64}, {160, 65528, 8}, {160, 152, 16}, {160, 64, 7},
		{160, 0, 32}, {160, 0, 0}, {160, 64, 0},
	} {
		f, key, _ := reassemblyFixture()
		key.Size = uint16(test.size)
		if result, err := f.HandleScopedFragment(key, uint16(test.offset), make([]byte, test.data)); err != goterrors.ErrParse || result != nil {
			t.Fatalf("invalid range accepted: %+v %v", test, err)
		}
		if usage := f.GetBufferUsage(); usage.RxBytes != 0 {
			t.Fatalf("invalid range allocated bytes: %+v", usage)
		}
	}
}

func TestScopedReassemblyCountBytesExpiryAndTeardown(t *testing.T) {
	f, key, _ := reassemblyFixture()
	clock := time.Now()
	f.now = func() time.Time { return clock }
	key.Size = IPv6MTU
	for i := 0; i < MaxReassemblyBytes/IPv6MTU; i++ {
		key.Tag = uint16(i)
		if _, err := f.HandleScopedFragment(key, 64, make([]byte, 64)); err != nil {
			t.Fatal(err)
		}
	}
	before := f.GetBufferUsage()
	key.Tag, key.Size = 99, 40
	if _, err := f.HandleScopedFragment(key, 0, make([]byte, 40)); err != goterrors.ErrNoBufs {
		t.Fatalf("RX byte budget not enforced: %v", err)
	}
	if f.GetBufferUsage() != before {
		t.Fatal("failed RX admission changed resource usage")
	}
	clock = clock.Add(FragReassemblyTimeoutSec * time.Second)
	if removed := f.CleanupExpiredReassemblies(); removed != before.RxDatagrams {
		t.Fatalf("expiry removed=%d, want %d", removed, before.RxDatagrams)
	}
	key.Size = 80
	for i := 0; i < MaxReassemblyDatagrams; i++ {
		key.Tag = uint16(i)
		if _, err := f.HandleScopedFragment(key, 0, make([]byte, 40)); err != nil {
			t.Fatal(err)
		}
	}
	key.Tag = 100
	if _, err := f.HandleScopedFragment(key, 0, make([]byte, 40)); err != goterrors.ErrNoBufs {
		t.Fatalf("RX context count not enforced: %v", err)
	}
	f.AbortFragments()
	if usage := f.GetBufferUsage(); usage.RxBytes != 0 || usage.RxDatagrams != 0 {
		t.Fatalf("disassociation retained RX resources: %+v", usage)
	}
	for i := 0; i < 2*MaxRecentFragmentTags; i++ {
		key.Tag, key.Size = uint16(i), 40
		if _, err := f.HandleScopedFragment(key, 0, make([]byte, 40)); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.recentFragments) != MaxRecentFragmentTags {
		t.Fatal("completed-tag suppression cache exceeded its bound")
	}
	clock = clock.Add(FragReassemblyTimeoutSec * time.Second)
	f.CleanupExpiredReassemblies()
	if len(f.recentFragments) != 0 {
		t.Fatal("completed-tag entries did not expire")
	}
	f.SetEnabled(false)
	if _, err := f.HandleScopedFragment(key, 0, make([]byte, 40)); err != ErrForwarderDisabled {
		t.Fatalf("disabled reassembly accepted traffic: %v", err)
	}
}
