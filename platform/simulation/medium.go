// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package simulation

import (
	"sync"

	"github.com/hilli/gothread/radio"
)

// Medium simulates a shared RF medium connecting multiple SimRadio instances.
// When a radio transmits a frame, the medium delivers a copy to all other
// radios tuned to the same channel.
type Medium struct {
	mu     sync.Mutex
	radios []*SimRadio
}

// NewMedium creates an empty shared medium.
func NewMedium() *Medium {
	return &Medium{}
}

// Register adds a radio to the medium.
func (m *Medium) Register(r *SimRadio) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.radios = append(m.radios, r)
	r.SetMedium(m)
}

// Unregister removes a radio from the medium.
func (m *Medium) Unregister(r *SimRadio) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, rr := range m.radios {
		if rr == r {
			m.radios = append(m.radios[:i], m.radios[i+1:]...)
			break
		}
	}
	r.SetMedium(nil)
}

// Broadcast delivers a copy of the frame to all radios on the given channel,
// except the sender. Returns the number of receivers that got the frame.
func (m *Medium) Broadcast(sender *SimRadio, frame *radio.Frame) int {
	m.mu.Lock()
	targets := make([]*SimRadio, len(m.radios))
	copy(targets, m.radios)
	m.mu.Unlock()

	count := 0
	for _, r := range targets {
		if r == sender {
			continue
		}
		r.mu.Lock()
		ch := r.channel
		state := r.state
		r.mu.Unlock()
		if ch == frame.Channel && state == radio.StateReceive {
			dup := copyFrame(frame)
			r.DeliverFrame(dup)
			count++
		}
	}
	return count
}

// copyFrame creates a deep copy of a radio frame.
func copyFrame(f *radio.Frame) *radio.Frame {
	dup := &radio.Frame{
		Channel:   f.Channel,
		RadioType: f.RadioType,
	}
	if len(f.PSDU) > 0 {
		dup.PSDU = make([]byte, len(f.PSDU))
		copy(dup.PSDU, f.PSDU)
	}
	if f.RxInfo != nil {
		ri := *f.RxInfo
		dup.RxInfo = &ri
	}
	if f.TxInfo != nil {
		ti := *f.TxInfo
		dup.TxInfo = &ti
	}
	return dup
}
