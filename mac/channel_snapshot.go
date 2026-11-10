// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mac

// GetPanChannelSnapshot observes the configured channel without re-entering the
// MAC mutex. It is safe from frame-admission/radio retry validators; temporary
// scan channels do not change the configured PAN channel.
func (m *Mac) GetPanChannelSnapshot() uint8 {
	return uint8(m.panChannelSnapshot.Load())
}
