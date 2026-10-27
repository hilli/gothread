// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import (
	"bytes"
	"time"

	goterrors "github.com/hilli/gothread/errors"
)

const (
	// MaxReassemblyDatagrams bounds simultaneously incomplete packets.
	MaxReassemblyDatagrams = 4
	// MaxReassemblyBytes is the shared raw-packet byte budget.
	MaxReassemblyBytes = 2 * IPv6MTU
	// MaxRecentFragmentTags bounds completion/conflict duplicate suppression.
	// Suppression lasts at most 60 seconds or until this cache evicts the tag.
	MaxRecentFragmentTags = 16
)

// FragmentScope is authenticated link identity, not merely a short address.
type FragmentScope struct {
	Source, Destination [8]byte
	PanID               uint16
	Channel             uint8
	Secured             bool
}

// FragmentKey identifies a complete RFC 4944 datagram and its link scope.
type FragmentKey struct {
	Scope     FragmentScope
	Tag, Size uint16
}

type fragmentIdentity struct {
	Scope FragmentScope
	Tag   uint16
}

type recentFragment struct {
	size  uint16
	until time.Time
}

type fragmentRange struct{ start, end uint16 }

// HandleScopedFragment places an ORIGINAL IPv6 byte range. The caller expands
// FRAG1 headers before calling; subsequent wire offsets then need no adjustment.
// Exact duplicates are ignored. Any other overlap poisons and retires the
// datagram, even if some overlapping bytes match.
func (f *Forwarder) HandleScopedFragment(key FragmentKey, offset uint16, data []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.enabled {
		return nil, ErrForwarderDisabled
	}
	now := f.now()
	f.expireFragmentsLocked(now)
	f.counters.RxFragment++
	identity := fragmentIdentity{Scope: key.Scope, Tag: key.Tag}
	fail := func() ([]byte, error) {
		f.rejectFragmentLocked(key, now)
		return nil, goterrors.ErrParse
	}
	end := int(offset) + len(data)
	if key.Size < 40 || key.Size > IPv6MTU || len(data) == 0 || offset%8 != 0 ||
		end > int(key.Size) || (end < int(key.Size) && end%8 != 0) ||
		(offset == 0 && len(data) < 40) {
		return fail()
	}
	if recent, exists := f.recentFragments[identity]; exists {
		if recent.size != key.Size {
			return fail()
		}
		return nil, nil
	}
	for candidate := range f.reassemblyMap {
		if candidate.Scope == key.Scope && candidate.Tag == key.Tag && candidate.Size != key.Size {
			return fail()
		}
	}
	entry := f.reassemblyMap[key]
	if entry == nil {
		total := int(key.Size)
		for _, existing := range f.reassemblyMap {
			total += int(existing.Size)
		}
		if len(f.reassemblyMap) >= MaxReassemblyDatagrams || total > MaxReassemblyBytes {
			f.counters.RxDropped++
			return nil, goterrors.ErrNoBufs
		}
		entry = &FragmentInfo{
			Tag: key.Tag, Size: key.Size, Source: key.Scope.Source,
			Timer: now, buffer: make([]byte, key.Size),
		}
		f.reassemblyMap[key] = entry
	}
	for _, occupied := range entry.ranges[:entry.rangeCount] {
		if int(offset) < int(occupied.end) && end > int(occupied.start) {
			if offset == occupied.start && end == int(occupied.end) &&
				bytes.Equal(entry.buffer[offset:end], data) {
				return nil, nil
			}
			return fail()
		}
	}
	if entry.rangeCount >= len(entry.ranges) {
		return fail()
	}
	copy(entry.buffer[offset:end], data)
	entry.ranges[entry.rangeCount] = fragmentRange{start: offset, end: uint16(end)}
	entry.rangeCount++
	entry.ReceivedLen += uint16(len(data))
	if !entry.IsComplete() {
		return nil, nil
	}
	delete(f.reassemblyMap, key)
	f.rememberFragmentLocked(identity, key.Size, now)
	return entry.buffer, nil // Ownership transfers to the synchronous RX path.
}

// RejectFragment releases and suppresses a known datagram whose first-header
// decoding failed before a byte range could be admitted.
func (f *Forwarder) RejectFragment(key FragmentKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejectFragmentLocked(key, f.now())
}

func (f *Forwarder) rejectFragmentLocked(key FragmentKey, now time.Time) {
	for candidate := range f.reassemblyMap {
		if candidate.Scope == key.Scope && candidate.Tag == key.Tag {
			delete(f.reassemblyMap, candidate)
		}
	}
	f.rememberFragmentLocked(fragmentIdentity{Scope: key.Scope, Tag: key.Tag}, key.Size, now)
	f.counters.FragmentError++
	f.counters.RxDropped++
}

func (f *Forwarder) rememberFragmentLocked(identity fragmentIdentity, size uint16, now time.Time) {
	if _, exists := f.recentFragments[identity]; !exists && len(f.recentFragments) >= MaxRecentFragmentTags {
		var oldest fragmentIdentity
		var deadline time.Time
		for key, entry := range f.recentFragments {
			if deadline.IsZero() || entry.until.Before(deadline) {
				oldest, deadline = key, entry.until
			}
		}
		delete(f.recentFragments, oldest)
	}
	f.recentFragments[identity] = recentFragment{size: size, until: now.Add(FragReassemblyTimeoutSec * time.Second)}
}

func (f *Forwarder) expireFragmentsLocked(now time.Time) int {
	removed := 0
	for key, entry := range f.reassemblyMap {
		if !now.Before(entry.Timer.Add(FragReassemblyTimeoutSec * time.Second)) {
			delete(f.reassemblyMap, key)
			f.counters.ReassemblyTimeout++
			removed++
		}
	}
	for key, entry := range f.recentFragments {
		if !now.Before(entry.until) {
			delete(f.recentFragments, key)
		}
	}
	return removed
}

// RecordReceiveError makes rejected headers/checksums observable without
// dispatching an application callback or retaining malformed bytes.
func (f *Forwarder) RecordReceiveError(fragment bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counters.RxDropped++
	if fragment {
		f.counters.FragmentError++
	}
}
