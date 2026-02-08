// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"fmt"
	"math/bits"
)

// Thread 2.4 GHz channel constants.
const (
	ChannelMin uint8 = 11
	ChannelMax uint8 = 26
)

// ChannelMask is a uint32 bit-vector where bit N represents channel N.
// Thread 2.4 GHz channels are 11-26.
type ChannelMask uint32

// Contains reports whether the mask includes the given channel.
func (m ChannelMask) Contains(channel uint8) bool {
	if channel >= 32 {
		return false
	}
	return (m & (1 << channel)) != 0
}

// Add adds a channel to the mask.
func (m *ChannelMask) Add(channel uint8) {
	if channel < 32 {
		*m |= 1 << channel
	}
}

// Remove removes a channel from the mask.
func (m *ChannelMask) Remove(channel uint8) {
	if channel < 32 {
		*m &^= 1 << channel
	}
}

// Intersect returns the intersection of two channel masks.
func (m ChannelMask) Intersect(other ChannelMask) ChannelMask {
	return m & other
}

// IsEmpty reports whether the mask contains no channels.
func (m ChannelMask) IsEmpty() bool { return m == 0 }

// Count returns the number of channels set in the mask.
func (m ChannelMask) Count() int {
	return bits.OnesCount32(uint32(m))
}

// Iterate returns a sorted slice of all channels present in the mask.
func (m ChannelMask) Iterate() []uint8 {
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

// GetLowest returns the lowest channel in the mask. The bool is false if the
// mask is empty.
func (m ChannelMask) GetLowest() (uint8, bool) {
	if m == 0 {
		return 0, false
	}
	return uint8(bits.TrailingZeros32(uint32(m))), true
}

// ToString produces a human-readable range string matching OpenThread's
// format, e.g. "{ 11, 14-17, 20-22, 24, 25 }".
func (m ChannelMask) ToString() string {
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
