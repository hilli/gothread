// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package backbone

import (
	"testing"

	"github.com/hilli/gothread/errors"
)

func iid(v byte) [8]byte {
	var b [8]byte
	b[7] = v
	return b
}

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

func TestNDP_RegisterNew(t *testing.T) {
	tbl := NewNdProxyTable()
	err := tbl.Register(iid(1), iid(0xA0), 0x0400, nil, 1000)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if tbl.Count() != 1 {
		t.Fatalf("Count = %d, want 1", tbl.Count())
	}
}

func TestNDP_RegisterRenewSameIids(t *testing.T) {
	var events []NdProxyEvent
	tbl := NewNdProxyTable(WithNdProxyCallback(func(e NdProxyEvent, _ [8]byte) {
		events = append(events, e)
	}))
	_ = tbl.Register(iid(1), iid(0xA0), 0x0400, nil, 1000)

	// Complete DAD so the renew callback fires.
	tbl.HandleTimer(1000) // dadAttempts 0->1
	tbl.HandleTimer(1000) // dadAttempts 1->2
	tbl.HandleTimer(1000) // dadAttempts 2->3
	tbl.HandleTimer(1000) // 3 >= DuaDadRepeats -> NdProxyAdded

	events = nil // reset
	_ = tbl.Register(iid(1), iid(0xA0), 0x0800, nil, 2000)
	if tbl.Count() != 1 {
		t.Fatalf("Count = %d, want 1 after renew", tbl.Count())
	}
	// Renew should invoke NdProxyRenewed callback.
	if len(events) != 1 || events[0] != NdProxyRenewed {
		t.Fatalf("events = %v, want [NdProxyRenewed]", events)
	}
}

func TestNDP_RegisterDuplicateAddressIidDifferentMeshLocal(t *testing.T) {
	tbl := NewNdProxyTable()
	_ = tbl.Register(iid(1), iid(0xA0), 0x0400, nil, 1000)
	err := tbl.Register(iid(1), iid(0xB0), 0x0800, nil, 2000)
	if err != errors.ErrDuplicated {
		t.Fatalf("expected ErrDuplicated, got %v", err)
	}
}

func TestNDP_RegisterSameMeshLocalNewDua(t *testing.T) {
	var removed int
	tbl := NewNdProxyTable(WithNdProxyCallback(func(e NdProxyEvent, _ [8]byte) {
		if e == NdProxyRemoved {
			removed++
		}
	}))
	_ = tbl.Register(iid(1), iid(0xA0), 0x0400, nil, 1000)
	// Same mesh-local IID, different address IID -> replace old.
	_ = tbl.Register(iid(2), iid(0xA0), 0x0800, nil, 2000)
	if tbl.Count() != 1 {
		t.Fatalf("Count = %d, want 1 after replacement", tbl.Count())
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
}

func TestNDP_RegisterTableFull(t *testing.T) {
	tbl := NewNdProxyTable(WithMaxNdProxies(2))
	_ = tbl.Register(iid(1), iid(0xA0), 0x0400, nil, 1000)
	_ = tbl.Register(iid(2), iid(0xB0), 0x0800, nil, 2000)
	err := tbl.Register(iid(3), iid(0xC0), 0x0C00, nil, 3000)
	if err != errors.ErrNoBufs {
		t.Fatalf("expected ErrNoBufs, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// ResolveDua
// ---------------------------------------------------------------------------

func TestNDP_ResolveDuaFound(t *testing.T) {
	tbl := NewNdProxyTable()
	_ = tbl.Register(iid(1), iid(0xA0), 0x0400, nil, 1000)
	// Complete DAD.
	tbl.HandleTimer(1000)
	tbl.HandleTimer(1000)
	tbl.HandleTimer(1000)
	tbl.HandleTimer(1000)

	info := tbl.ResolveDua(iid(1))
	if info == nil {
		t.Fatal("ResolveDua returned nil for valid proxy")
	}
	if info.MeshLocalIid != iid(0xA0) {
		t.Fatalf("MeshLocalIid = %v, want %v", info.MeshLocalIid, iid(0xA0))
	}
}

func TestNDP_ResolveDuaDadInProgress(t *testing.T) {
	tbl := NewNdProxyTable()
	_ = tbl.Register(iid(1), iid(0xA0), 0x0400, nil, 1000)
	// DAD not completed yet.
	info := tbl.ResolveDua(iid(1))
	if info != nil {
		t.Fatal("ResolveDua should return nil while DAD in progress")
	}
}

func TestNDP_ResolveDuaNotFound(t *testing.T) {
	tbl := NewNdProxyTable()
	info := tbl.ResolveDua(iid(99))
	if info != nil {
		t.Fatal("ResolveDua should return nil for non-existent proxy")
	}
}

// ---------------------------------------------------------------------------
// HandleTimer / DAD
// ---------------------------------------------------------------------------

func TestNDP_HandleTimerProgressesDad(t *testing.T) {
	var dadSends int
	tbl := NewNdProxyTable(WithDadSendCallback(func(_ [8]byte) {
		dadSends++
	}))
	_ = tbl.Register(iid(1), iid(0xA0), 0x0400, nil, 1000)

	tbl.HandleTimer(1000)
	if dadSends != 1 {
		t.Fatalf("dadSends = %d, want 1 after first HandleTimer", dadSends)
	}
	if !tbl.IsAnyDadInProcess() {
		t.Fatal("expected DAD still in process")
	}
}

func TestNDP_HandleTimerCompletesDadAfterRepeats(t *testing.T) {
	var events []NdProxyEvent
	var dadSends int
	tbl := NewNdProxyTable(
		WithNdProxyCallback(func(e NdProxyEvent, _ [8]byte) {
			events = append(events, e)
		}),
		WithDadSendCallback(func(_ [8]byte) {
			dadSends++
		}),
	)
	_ = tbl.Register(iid(1), iid(0xA0), 0x0400, nil, 1000)

	// DAD requires DuaDadRepeats (3) sends, then completes on 4th call.
	for i := 0; i < int(DuaDadRepeats); i++ {
		tbl.HandleTimer(1000)
	}
	if dadSends != int(DuaDadRepeats) {
		t.Fatalf("dadSends = %d, want %d", dadSends, DuaDadRepeats)
	}

	// One more call to complete.
	tbl.HandleTimer(1000)

	found := false
	for _, e := range events {
		if e == NdProxyAdded {
			found = true
		}
	}
	if !found {
		t.Fatal("expected NdProxyAdded after DAD completes")
	}
	if tbl.IsAnyDadInProcess() {
		t.Fatal("expected no more DAD in process")
	}
}

// ---------------------------------------------------------------------------
// NotifyDadComplete
// ---------------------------------------------------------------------------

func TestNDP_NotifyDadCompleteDuplicated(t *testing.T) {
	var removed int
	tbl := NewNdProxyTable(WithNdProxyCallback(func(e NdProxyEvent, _ [8]byte) {
		if e == NdProxyRemoved {
			removed++
		}
	}))
	_ = tbl.Register(iid(1), iid(0xA0), 0x0400, nil, 1000)
	tbl.NotifyDadComplete(iid(1), true)
	if tbl.Count() != 0 {
		t.Fatalf("Count = %d, want 0 after duplicate detection", tbl.Count())
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
}

func TestNDP_NotifyDadCompleteNoDuplicate(t *testing.T) {
	var events []NdProxyEvent
	tbl := NewNdProxyTable(WithNdProxyCallback(func(e NdProxyEvent, _ [8]byte) {
		events = append(events, e)
	}))
	_ = tbl.Register(iid(1), iid(0xA0), 0x0400, nil, 1000)
	tbl.NotifyDadComplete(iid(1), false)
	// Now HandleTimer should complete immediately.
	tbl.HandleTimer(1000)

	found := false
	for _, e := range events {
		if e == NdProxyAdded {
			found = true
		}
	}
	if !found {
		t.Fatal("expected NdProxyAdded after fast-complete")
	}
}

// ---------------------------------------------------------------------------
// Clear
// ---------------------------------------------------------------------------

func TestNDP_Clear(t *testing.T) {
	var cleared int
	tbl := NewNdProxyTable(WithNdProxyCallback(func(e NdProxyEvent, _ [8]byte) {
		if e == NdProxyCleared {
			cleared++
		}
	}))
	_ = tbl.Register(iid(1), iid(0xA0), 0x0400, nil, 1000)
	_ = tbl.Register(iid(2), iid(0xB0), 0x0800, nil, 2000)
	tbl.Clear()
	if tbl.Count() != 0 {
		t.Fatalf("Count = %d, want 0 after Clear", tbl.Count())
	}
	if cleared != 1 {
		t.Fatalf("cleared callbacks = %d, want 1", cleared)
	}
}

// ---------------------------------------------------------------------------
// Erase
// ---------------------------------------------------------------------------

func TestNDP_Erase(t *testing.T) {
	var removed int
	tbl := NewNdProxyTable(WithNdProxyCallback(func(e NdProxyEvent, _ [8]byte) {
		if e == NdProxyRemoved {
			removed++
		}
	}))
	_ = tbl.Register(iid(1), iid(0xA0), 0x0400, nil, 1000)
	tbl.Erase(iid(1))
	if tbl.Count() != 0 {
		t.Fatalf("Count = %d, want 0 after Erase", tbl.Count())
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
}

func TestNDP_EraseNonExistent(t *testing.T) {
	tbl := NewNdProxyTable()
	tbl.Erase(iid(99)) // should not panic
}

// ---------------------------------------------------------------------------
// GetInfo / GetInfoAt
// ---------------------------------------------------------------------------

func TestNDP_GetInfo(t *testing.T) {
	tbl := NewNdProxyTable()
	_ = tbl.Register(iid(1), iid(0xA0), 0x0400, nil, 1000)
	info := tbl.GetInfo(iid(1))
	if info == nil {
		t.Fatal("GetInfo returned nil")
	}
	if info.MeshLocalIid != iid(0xA0) {
		t.Fatalf("MeshLocalIid = %v, want %v", info.MeshLocalIid, iid(0xA0))
	}
	if info.Rloc16 != 0x0400 {
		t.Fatalf("Rloc16 = 0x%04x, want 0x0400", info.Rloc16)
	}
}

func TestNDP_GetInfoNotFound(t *testing.T) {
	tbl := NewNdProxyTable()
	info := tbl.GetInfo(iid(99))
	if info != nil {
		t.Fatal("GetInfo should return nil for non-existent proxy")
	}
}

func TestNDP_GetInfoAt_TimeSinceLastTx(t *testing.T) {
	tbl := NewNdProxyTable()
	tsltt := uint32(60)
	_ = tbl.Register(iid(1), iid(0xA0), 0x0400, &tsltt, 10000)
	// At nowMs=10000, lastRegTimeMs = 10000 - 60*1000 = -50000.
	// At nowMs=15000, delta = 65000ms = 65s.
	info := tbl.GetInfoAt(iid(1), 15000)
	if info == nil {
		t.Fatal("GetInfoAt returned nil")
	}
	if info.TimeSinceLastTxSec != 65 {
		t.Fatalf("TimeSinceLastTxSec = %d, want 65", info.TimeSinceLastTxSec)
	}
}

func TestNDP_GetInfoAt_MaxTimeClamped(t *testing.T) {
	tbl := NewNdProxyTable()
	big := MaxTimeSinceLastTransaction + 1000
	_ = tbl.Register(iid(1), iid(0xA0), 0x0400, &big, 10000)
	// tsltt is clamped to MaxTimeSinceLastTransaction (864000s).
	// lastRegTimeMs = 10000 - 864000*1000 = -863990000
	// At nowMs = 10000 + 864000*1000 = 864010000, delta = 864010000 - (-863990000) = very large
	info := tbl.GetInfoAt(iid(1), 864010000)
	if info == nil {
		t.Fatal("GetInfoAt returned nil")
	}
	if info.TimeSinceLastTxSec > MaxTimeSinceLastTransaction {
		t.Fatalf("TimeSinceLastTxSec = %d, want <= %d", info.TimeSinceLastTxSec, MaxTimeSinceLastTransaction)
	}
}

// ---------------------------------------------------------------------------
// Count
// ---------------------------------------------------------------------------

func TestNDP_Count(t *testing.T) {
	tbl := NewNdProxyTable()
	if tbl.Count() != 0 {
		t.Fatalf("Count = %d on empty table, want 0", tbl.Count())
	}
	_ = tbl.Register(iid(1), iid(0xA0), 0x0400, nil, 1000)
	_ = tbl.Register(iid(2), iid(0xB0), 0x0800, nil, 2000)
	if tbl.Count() != 2 {
		t.Fatalf("Count = %d, want 2", tbl.Count())
	}
	tbl.Erase(iid(1))
	if tbl.Count() != 1 {
		t.Fatalf("Count = %d, want 1 after Erase", tbl.Count())
	}
}

// ---------------------------------------------------------------------------
// IsAnyDadInProcess
// ---------------------------------------------------------------------------

func TestNDP_IsAnyDadInProcess(t *testing.T) {
	tbl := NewNdProxyTable()
	if tbl.IsAnyDadInProcess() {
		t.Fatal("expected no DAD on empty table")
	}
	_ = tbl.Register(iid(1), iid(0xA0), 0x0400, nil, 1000)
	if !tbl.IsAnyDadInProcess() {
		t.Fatal("expected DAD after Register")
	}
}

// ---------------------------------------------------------------------------
// Register with timeSinceLastTransaction
// ---------------------------------------------------------------------------

func TestNDP_RegisterWithTimeSinceLastTx(t *testing.T) {
	tbl := NewNdProxyTable()
	tsltt := uint32(120)
	err := tbl.Register(iid(1), iid(0xA0), 0x0400, &tsltt, 200000)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	info := tbl.GetInfoAt(iid(1), 200000)
	if info == nil {
		t.Fatal("GetInfoAt returned nil")
	}
	// At registration time, tsltt was 120s, so at the same nowMs the
	// elapsed time should be 120s.
	if info.TimeSinceLastTxSec != 120 {
		t.Fatalf("TimeSinceLastTxSec = %d, want 120", info.TimeSinceLastTxSec)
	}
}

func TestNDP_RegisterNilTimeSinceLastTx(t *testing.T) {
	tbl := NewNdProxyTable()
	err := tbl.Register(iid(1), iid(0xA0), 0x0400, nil, 5000)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	info := tbl.GetInfoAt(iid(1), 5000)
	if info == nil {
		t.Fatal("GetInfoAt returned nil")
	}
	// nil tsltt → 0, so at same nowMs the delta is 0.
	if info.TimeSinceLastTxSec != 0 {
		t.Fatalf("TimeSinceLastTxSec = %d, want 0", info.TimeSinceLastTxSec)
	}
}

// ---------------------------------------------------------------------------
// Slot reuse after Erase
// ---------------------------------------------------------------------------

func TestNDP_SlotReuse(t *testing.T) {
	tbl := NewNdProxyTable(WithMaxNdProxies(2))
	_ = tbl.Register(iid(1), iid(0xA0), 0x0400, nil, 1000)
	_ = tbl.Register(iid(2), iid(0xB0), 0x0800, nil, 2000)
	tbl.Erase(iid(1))
	// Should reuse the freed slot.
	err := tbl.Register(iid(3), iid(0xC0), 0x0C00, nil, 3000)
	if err != nil {
		t.Fatalf("expected slot reuse, got %v", err)
	}
	if tbl.Count() != 2 {
		t.Fatalf("Count = %d, want 2", tbl.Count())
	}
}
