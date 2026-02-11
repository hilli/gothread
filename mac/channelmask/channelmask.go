// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package channelmask provides an immutable-style IEEE 802.15.4 channel mask
// type. Methods return new Mask values rather than mutating the receiver.
//
// This is a Go port of the channel mask handling in OpenThread's
// src/core/mac/channel_mask.hpp and src/core/mac/channel_mask.cpp.
package channelmask

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"math/bits"
)

// Thread 2.4 GHz channel constants.
const (
	Channel11 uint8 = 11
	Channel12 uint8 = 12
	Channel13 uint8 = 13
	Channel14 uint8 = 14
	Channel15 uint8 = 15
	Channel16 uint8 = 16
	Channel17 uint8 = 17
	Channel18 uint8 = 18
	Channel19 uint8 = 19
	Channel20 uint8 = 20
	Channel21 uint8 = 21
	Channel22 uint8 = 22
	Channel23 uint8 = 23
	Channel24 uint8 = 24
	Channel25 uint8 = 25
	Channel26 uint8 = 26
)

// Pre-defined channel masks.
var (
	// AllChannels802154 is a Mask with all 2.4 GHz channels (11-26) set.
	AllChannels802154 = New(
		Channel11, Channel12, Channel13, Channel14,
		Channel15, Channel16, Channel17, Channel18,
		Channel19, Channel20, Channel21, Channel22,
		Channel23, Channel24, Channel25, Channel26,
	)

	// NoChannels is an empty channel mask.
	NoChannels Mask = 0
)

// Mask is a uint32 bit-vector where bit N represents channel N.
// Methods return new Mask values rather than mutating the receiver.
type Mask uint32

// New creates a Mask from the given channel numbers.
func New(channels ...uint8) Mask {
	var m Mask
	for _, ch := range channels {
		if ch < 32 {
			m |= 1 << ch
		}
	}
	return m
}

// Contains reports whether the mask includes the given channel.
func (m Mask) Contains(channel uint8) bool {
	if channel >= 32 {
		return false
	}
	return (m & (1 << channel)) != 0
}

// Add returns a new Mask with the given channel added.
func (m Mask) Add(channel uint8) Mask {
	if channel >= 32 {
		return m
	}
	return m | (1 << channel)
}

// Remove returns a new Mask with the given channel removed.
func (m Mask) Remove(channel uint8) Mask {
	if channel >= 32 {
		return m
	}
	return m &^ (1 << channel)
}

// Union returns the union of two channel masks.
func (m Mask) Union(other Mask) Mask {
	return m | other
}

// Intersect returns the intersection of two channel masks.
func (m Mask) Intersect(other Mask) Mask {
	return m & other
}

// IsEmpty reports whether the mask contains no channels.
func (m Mask) IsEmpty() bool { return m == 0 }

// Count returns the number of channels set in the mask.
func (m Mask) Count() int {
	return bits.OnesCount32(uint32(m))
}

// GetFirstChannel returns the lowest channel in the mask.
// The bool is false if the mask is empty.
func (m Mask) GetFirstChannel() (uint8, bool) {
	if m == 0 {
		return 0, false
	}
	return uint8(bits.TrailingZeros32(uint32(m))), true
}

// GetNextChannel returns the next channel after the given one.
// The bool is false if there is no higher channel set.
func (m Mask) GetNextChannel(after uint8) (uint8, bool) {
	if after >= 31 {
		return 0, false
	}
	// Clear bits 0..after.
	cleared := m & ^Mask((1<<(after+1))-1)
	if cleared == 0 {
		return 0, false
	}
	return uint8(bits.TrailingZeros32(uint32(cleared))), true
}

// Iterate returns a sorted slice of all channels present in the mask.
func (m Mask) Iterate() []uint8 {
	if m == 0 {
		return nil
	}
	channels := make([]uint8, 0, m.Count())
	for ch := uint8(0); ch < 32; ch++ {
		if m.Contains(ch) {
			channels = append(channels, ch)
		}
	}
	return channels
}

// ChooseRandomChannel picks a uniformly random channel from the mask
// using crypto/rand. Returns false if the mask is empty.
func (m Mask) ChooseRandomChannel() (uint8, bool) {
	count := m.Count()
	if count == 0 {
		return 0, false
	}
	if count == 1 {
		ch, _ := m.GetFirstChannel()
		return ch, true
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(count)))
	if err != nil {
		// Fallback to first channel on error (should not happen).
		ch, _ := m.GetFirstChannel()
		return ch, true
	}
	idx := int(n.Int64())
	i := 0
	for ch := uint8(0); ch < 32; ch++ {
		if m.Contains(ch) {
			if i == idx {
				return ch, true
			}
			i++
		}
	}
	// Should not reach here.
	ch, _ := m.GetFirstChannel()
	return ch, true
}

// String returns a human-readable range string matching OpenThread's
// format, e.g. "{ 11, 14-17, 20-22, 24, 25 }".
func (m Mask) String() string {
	channels := m.Iterate()
	if len(channels) == 0 {
		return "{ }"
	}

	result := "{"
	first := true

	i := 0
	for i < len(channels) {
		rangeStart := channels[i]
		rangeEnd := channels[i]

		// Extend the range as far as consecutive channels go.
		for i+1 < len(channels) && channels[i+1] == rangeEnd+1 {
			i++
			rangeEnd = channels[i]
		}

		if !first {
			result += ","
		}
		first = false

		result += fmt.Sprintf(" %d", rangeStart)
		if rangeStart < rangeEnd {
			if rangeEnd == rangeStart+1 {
				// Two consecutive channels: "14, 15" not "14-15".
				result += fmt.Sprintf(", %d", rangeEnd)
			} else {
				result += fmt.Sprintf("-%d", rangeEnd)
			}
		}

		i++
	}

	result += " }"
	return result
}
