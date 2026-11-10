// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import (
	"testing"
	"unsafe"
)

func TestFragmentResourceStructuralFootprint(t *testing.T) {
	// This accounts for owned protocol storage, not total Go heap/GC overhead,
	// application receive queues, the existing Instance, or radio-driver RAM.
	descriptor := unsafe.Sizeof(TxMessage{}) + unsafe.Sizeof(TxMetadata{}) +
		unsafe.Sizeof(transmitState{}) + 48 // Compression header capacity.
	tx := uintptr(MaxPendingDatagramBytes) + uintptr(MaxFramesInDirectTxQueue)*descriptor
	rx := uintptr(MaxReassemblyBytes) + uintptr(MaxReassemblyDatagrams)*unsafe.Sizeof(FragmentInfo{})
	recent := uintptr(MaxRecentFragmentTags) *
		(unsafe.Sizeof(fragmentIdentity{}) + unsafe.Sizeof(recentFragment{}))
	queues := uintptr(2*MaxFramesInDirectTxQueue) * unsafe.Sizeof((*TxMessage)(nil))
	entries := uintptr(MaxFramesInDirectTxQueue) *
		(unsafe.Sizeof((*TxMessage)(nil)) + unsafe.Sizeof(int(0)))
	entries += uintptr(MaxReassemblyDatagrams) *
		(unsafe.Sizeof(FragmentKey{}) + unsafe.Sizeof((*FragmentInfo)(nil)))
	t.Logf("pointer=%d TX-descriptor/header=%d TX-owned=%d RX-owned=%d recent=%d queues=%d entry-values=%d subtotal=%d",
		unsafe.Sizeof((*TxMessage)(nil)), descriptor, tx, rx, recent, queues, entries,
		tx+rx+recent+queues+entries)
	if tx+rx+recent+queues+entries > 64*1024 {
		t.Fatal("fragment structural storage exceeded its documented 64-bit envelope")
	}
}
