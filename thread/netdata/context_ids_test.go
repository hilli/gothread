// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package netdata

import (
	"testing"

	goterrors "github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Constructor and initial state
// ---------------------------------------------------------------------------

func TestNewContextIDManagerDefaults(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()

	if m.ReuseDelay() != DefaultContextIDReuseDelay {
		t.Fatalf("ReuseDelay() = %d, want %d", m.ReuseDelay(), DefaultContextIDReuseDelay)
	}
	// All IDs 1-15 should be unallocated.
	for id := uint8(1); id <= 15; id++ {
		if s := m.State(id); s != ContextIDUnallocated {
			t.Fatalf("State(%d) = %d, want ContextIDUnallocated", id, s)
		}
	}
}

// ---------------------------------------------------------------------------
// State transitions
// ---------------------------------------------------------------------------

func TestContextIDManagerStateTransitions(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()

	// Mark ID 5 as in-use.
	m.MarkAsInUse(5)
	if s := m.State(5); s != ContextIDInUse {
		t.Fatalf("State(5) after MarkAsInUse = %d, want ContextIDInUse", s)
	}

	// Schedule to remove.
	removeTime := m.ScheduleToRemove(5, 1000)
	if removeTime == 0 {
		t.Fatal("ScheduleToRemove returned 0 for InUse ID")
	}
	if s := m.State(5); s != ContextIDScheduledToRemove {
		t.Fatalf("State(5) after ScheduleToRemove = %d, want ContextIDScheduledToRemove", s)
	}

	// Mark as unallocated directly.
	m.MarkAsUnallocated(5)
	if s := m.State(5); s != ContextIDUnallocated {
		t.Fatalf("State(5) after MarkAsUnallocated = %d, want ContextIDUnallocated", s)
	}
}

func TestContextIDManagerMarkAsInUseThenUnallocated(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()

	m.MarkAsInUse(1)
	if s := m.State(1); s != ContextIDInUse {
		t.Fatalf("State(1) = %d, want ContextIDInUse", s)
	}
	m.MarkAsUnallocated(1)
	if s := m.State(1); s != ContextIDUnallocated {
		t.Fatalf("State(1) = %d, want ContextIDUnallocated", s)
	}
}

// ---------------------------------------------------------------------------
// GetUnallocatedID
// ---------------------------------------------------------------------------

func TestContextIDManagerGetUnallocatedIDSequential(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()

	// Should return IDs 1 through 15 in order.
	for want := uint8(1); want <= 15; want++ {
		id, err := m.GetUnallocatedID()
		if err != nil {
			t.Fatalf("GetUnallocatedID() error for expected ID %d: %v", want, err)
		}
		if id != want {
			t.Fatalf("GetUnallocatedID() = %d, want %d", id, want)
		}
		m.MarkAsInUse(id)
	}

	// Now all IDs are in use; should return ErrNotFound.
	id, err := m.GetUnallocatedID()
	if err != goterrors.ErrNotFound {
		t.Fatalf("GetUnallocatedID() error = %v, want ErrNotFound (id=%d)", err, id)
	}
	if id != InvalidContextID {
		t.Fatalf("GetUnallocatedID() id = %d, want InvalidContextID (%d)", id, InvalidContextID)
	}
}

func TestContextIDManagerGetUnallocatedIDSkipsNonFree(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()

	// Mark IDs 1 and 2 as in-use.
	m.MarkAsInUse(1)
	m.MarkAsInUse(2)

	id, err := m.GetUnallocatedID()
	if err != nil {
		t.Fatalf("GetUnallocatedID() error: %v", err)
	}
	if id != 3 {
		t.Fatalf("GetUnallocatedID() = %d, want 3", id)
	}
}

// ---------------------------------------------------------------------------
// ScheduleToRemove
// ---------------------------------------------------------------------------

func TestContextIDManagerScheduleToRemoveOnlyFromInUse(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()

	// Scheduling from Unallocated is a no-op.
	if rt := m.ScheduleToRemove(3, 1000); rt != 0 {
		t.Fatalf("ScheduleToRemove from Unallocated = %d, want 0", rt)
	}

	// Mark as InUse, then schedule.
	m.MarkAsInUse(3)
	rt := m.ScheduleToRemove(3, 1000)
	if rt == 0 {
		t.Fatal("ScheduleToRemove from InUse returned 0")
	}

	// Scheduling again from ScheduledToRemove is a no-op.
	if rt2 := m.ScheduleToRemove(3, 2000); rt2 != 0 {
		t.Fatalf("ScheduleToRemove from ScheduledToRemove = %d, want 0", rt2)
	}
}

func TestContextIDManagerScheduleToRemoveReturnTime(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()
	m.SetReuseDelay(500)
	m.MarkAsInUse(7)

	rt := m.ScheduleToRemove(7, 1000)
	// Expected removal at nowMs + reuseDelay = 1500.
	if rt != 1500 {
		t.Fatalf("ScheduleToRemove returned %d, want 1500", rt)
	}
}

func TestContextIDManagerScheduleToRemoveSentinelCollision(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()

	// If nowMs + reuseDelay == 0 (wrapping), the sentinel collision avoidance
	// should bump the stored value to 2.
	m.SetReuseDelay(0)

	// nowMs=0, delay=0 => removeTime=0, which collides with unallocated sentinel.
	m.MarkAsInUse(1)
	rt := m.ScheduleToRemove(1, 0)
	if rt < 2 {
		t.Fatalf("ScheduleToRemove(0) returned %d, want >= 2 (sentinel collision avoidance)", rt)
	}
	if m.State(1) != ContextIDScheduledToRemove {
		t.Fatal("ID 1 should be in ScheduledToRemove state")
	}

	// nowMs=1, delay=0 => removeTime=1, which collides with in-use sentinel.
	m.MarkAsInUse(2)
	rt2 := m.ScheduleToRemove(2, 1)
	if rt2 < 2 {
		t.Fatalf("ScheduleToRemove(1) returned %d, want >= 2 (sentinel collision avoidance)", rt2)
	}
}

// ---------------------------------------------------------------------------
// HandleTimer
// ---------------------------------------------------------------------------

func TestContextIDManagerHandleTimerExpires(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()
	m.SetReuseDelay(100)

	m.MarkAsInUse(4)
	m.MarkAsInUse(8)

	// Schedule both for removal at nowMs=1000.
	_ = m.ScheduleToRemove(4, 1000) // expires at 1100
	_ = m.ScheduleToRemove(8, 1000) // expires at 1100

	// Timer at 1050 — nothing should expire yet.
	var expired []uint8
	cb := func(id uint8) { expired = append(expired, id) }

	next := m.HandleTimer(1050, cb)
	if len(expired) != 0 {
		t.Fatalf("expected 0 expired at t=1050, got %v", expired)
	}
	if next != 1100 {
		t.Fatalf("next fire time = %d, want 1100", next)
	}

	// Timer at 1100 — both should expire.
	expired = nil
	next = m.HandleTimer(1100, cb)
	if len(expired) != 2 {
		t.Fatalf("expected 2 expired at t=1100, got %v", expired)
	}
	if next != 0 {
		t.Fatalf("next fire time = %d, want 0 (no pending)", next)
	}
	// Both should be unallocated now.
	if m.State(4) != ContextIDUnallocated {
		t.Fatal("ID 4 should be unallocated after expiry")
	}
	if m.State(8) != ContextIDUnallocated {
		t.Fatal("ID 8 should be unallocated after expiry")
	}
}

func TestContextIDManagerHandleTimerStaggered(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()
	m.SetReuseDelay(100)

	m.MarkAsInUse(2)
	m.MarkAsInUse(5)

	_ = m.ScheduleToRemove(2, 1000) // expires at 1100
	_ = m.ScheduleToRemove(5, 1200) // expires at 1300

	var expired []uint8
	cb := func(id uint8) { expired = append(expired, id) }

	// At t=1100, only ID 2 should expire.
	next := m.HandleTimer(1100, cb)
	if len(expired) != 1 || expired[0] != 2 {
		t.Fatalf("expected [2] expired at t=1100, got %v", expired)
	}
	if next != 1300 {
		t.Fatalf("next fire time = %d, want 1300", next)
	}

	// At t=1300, ID 5 should expire.
	expired = nil
	next = m.HandleTimer(1300, cb)
	if len(expired) != 1 || expired[0] != 5 {
		t.Fatalf("expected [5] expired at t=1300, got %v", expired)
	}
	if next != 0 {
		t.Fatalf("next fire time = %d, want 0", next)
	}
}

func TestContextIDManagerHandleTimerNilCallback(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()
	m.SetReuseDelay(0)

	m.MarkAsInUse(10)
	_ = m.ScheduleToRemove(10, 100)

	// Should not panic with nil callback.
	next := m.HandleTimer(200, nil)
	if next != 0 {
		t.Fatalf("next = %d, want 0", next)
	}
	if m.State(10) != ContextIDUnallocated {
		t.Fatal("ID 10 should be unallocated after nil-callback expiry")
	}
}

func TestContextIDManagerHandleTimerNoPending(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()

	next := m.HandleTimer(5000, func(_ uint8) {
		t.Fatal("callback should not be invoked when no timers pending")
	})
	if next != 0 {
		t.Fatalf("next = %d, want 0", next)
	}
}

// ---------------------------------------------------------------------------
// PendingTimerIDs
// ---------------------------------------------------------------------------

func TestContextIDManagerPendingTimerIDs(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()
	m.SetReuseDelay(100)

	if ids := m.PendingTimerIDs(); len(ids) != 0 {
		t.Fatalf("PendingTimerIDs() = %v, want empty", ids)
	}

	m.MarkAsInUse(3)
	m.MarkAsInUse(9)
	_ = m.ScheduleToRemove(3, 1000)
	_ = m.ScheduleToRemove(9, 1000)

	ids := m.PendingTimerIDs()
	if len(ids) != 2 {
		t.Fatalf("PendingTimerIDs() len = %d, want 2", len(ids))
	}
	if ids[0] != 3 || ids[1] != 9 {
		t.Fatalf("PendingTimerIDs() = %v, want [3, 9]", ids)
	}
}

// ---------------------------------------------------------------------------
// Clear
// ---------------------------------------------------------------------------

func TestContextIDManagerClear(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()

	// Put IDs into various states.
	m.MarkAsInUse(1)
	m.MarkAsInUse(2)
	_ = m.ScheduleToRemove(2, 1000)
	m.MarkAsInUse(15)

	m.Clear()

	for id := uint8(1); id <= 15; id++ {
		if s := m.State(id); s != ContextIDUnallocated {
			t.Fatalf("State(%d) after Clear = %d, want ContextIDUnallocated", id, s)
		}
	}

	// GetUnallocatedID should return 1 again.
	id, err := m.GetUnallocatedID()
	if err != nil {
		t.Fatalf("GetUnallocatedID after Clear: %v", err)
	}
	if id != 1 {
		t.Fatalf("GetUnallocatedID after Clear = %d, want 1", id)
	}
}

// ---------------------------------------------------------------------------
// Out-of-range IDs
// ---------------------------------------------------------------------------

func TestContextIDManagerOutOfRange(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()

	// ID 0 is out of range.
	if s := m.State(0); s != ContextIDUnallocated {
		t.Fatalf("State(0) = %d, want ContextIDUnallocated", s)
	}
	// ID 16 is out of range.
	if s := m.State(16); s != ContextIDUnallocated {
		t.Fatalf("State(16) = %d, want ContextIDUnallocated", s)
	}
	// ID 255 is out of range.
	if s := m.State(255); s != ContextIDUnallocated {
		t.Fatalf("State(255) = %d, want ContextIDUnallocated", s)
	}

	// MarkAsInUse / MarkAsUnallocated / ScheduleToRemove should be no-ops.
	m.MarkAsInUse(0)
	m.MarkAsInUse(16)
	m.MarkAsUnallocated(0)
	if rt := m.ScheduleToRemove(0, 100); rt != 0 {
		t.Fatalf("ScheduleToRemove(0) = %d, want 0", rt)
	}
	if rt := m.ScheduleToRemove(16, 100); rt != 0 {
		t.Fatalf("ScheduleToRemove(16) = %d, want 0", rt)
	}
}

// ---------------------------------------------------------------------------
// SetReuseDelay
// ---------------------------------------------------------------------------

func TestContextIDManagerSetReuseDelay(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()

	m.SetReuseDelay(42000)
	if d := m.ReuseDelay(); d != 42000 {
		t.Fatalf("ReuseDelay() = %d, want 42000", d)
	}

	// Verify the new delay is used for scheduling.
	m.MarkAsInUse(1)
	rt := m.ScheduleToRemove(1, 1000)
	if rt != 43000 {
		t.Fatalf("ScheduleToRemove with custom delay returned %d, want 43000", rt)
	}
}

// ---------------------------------------------------------------------------
// Wrapping uint32 time arithmetic
// ---------------------------------------------------------------------------

func TestTimeMsWrapping(t *testing.T) {
	t.Parallel()

	// timeMsGe: basic cases.
	if !timeMsGe(100, 50) {
		t.Fatal("timeMsGe(100, 50) should be true")
	}
	if !timeMsGe(50, 50) {
		t.Fatal("timeMsGe(50, 50) should be true (equal)")
	}
	if timeMsGe(50, 100) {
		t.Fatal("timeMsGe(50, 100) should be false")
	}

	// Wrapping: a = 10, b = 0xFFFFFFF0 => a - b = 20 (positive in int32).
	if !timeMsGe(10, 0xFFFFFFF0) {
		t.Fatal("timeMsGe(10, 0xFFFFFFF0) should be true (wrap)")
	}

	// timeMsBefore: basic cases.
	if !timeMsBefore(50, 100) {
		t.Fatal("timeMsBefore(50, 100) should be true")
	}
	if timeMsBefore(100, 50) {
		t.Fatal("timeMsBefore(100, 50) should be false")
	}
	if timeMsBefore(50, 50) {
		t.Fatal("timeMsBefore(50, 50) should be false (equal)")
	}

	// Wrapping: a = 0xFFFFFFF0, b = 10 => a - b wraps to large negative.
	if !timeMsBefore(0xFFFFFFF0, 10) {
		t.Fatal("timeMsBefore(0xFFFFFFF0, 10) should be true (wrap)")
	}
}

func TestContextIDManagerHandleTimerWrappingTime(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()
	m.SetReuseDelay(100)

	// Schedule near uint32 max boundary.
	m.MarkAsInUse(6)
	rt := m.ScheduleToRemove(6, 0xFFFFFF00)
	wantRT := uint32(0xFFFFFF00 + 100) // 0xFFFFFF64
	if rt != wantRT {
		t.Fatalf("ScheduleToRemove returned 0x%08X, want 0x%08X", rt, wantRT)
	}

	// Not expired yet at 0xFFFFFF50.
	var expired []uint8
	cb := func(id uint8) { expired = append(expired, id) }

	next := m.HandleTimer(0xFFFFFF50, cb)
	if len(expired) != 0 {
		t.Fatalf("expected 0 expired, got %v", expired)
	}
	if next != wantRT {
		t.Fatalf("next = 0x%08X, want 0x%08X", next, wantRT)
	}

	// Expired at exact time.
	expired = nil
	next = m.HandleTimer(wantRT, cb)
	if len(expired) != 1 || expired[0] != 6 {
		t.Fatalf("expected [6] expired, got %v", expired)
	}
	if next != 0 {
		t.Fatalf("next = %d, want 0", next)
	}
}

func TestContextIDManagerHandleTimerWrappingAcrossZero(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()
	m.SetReuseDelay(0x20) // 32 ms

	// Schedule near max so removal wraps past 0.
	m.MarkAsInUse(11)
	rt := m.ScheduleToRemove(11, 0xFFFFFFF0)
	// Expected: (0xFFFFFFF0 + 0x20) mod 2^32 = 0x00000010.
	// 0x10 = 16 which doesn't collide with sentinels 0 or 1.
	var wantRT uint32 = 0x00000010
	if rt != wantRT {
		t.Fatalf("ScheduleToRemove returned 0x%08X, want 0x%08X", rt, wantRT)
	}

	// HandleTimer before wrap: at 0xFFFFFFFF, not yet expired.
	var expired []uint8
	cb := func(id uint8) { expired = append(expired, id) }

	next := m.HandleTimer(0xFFFFFFFF, cb)
	if len(expired) != 0 {
		t.Fatal("should not have expired before wrap")
	}
	if next != wantRT {
		t.Fatalf("next = 0x%08X, want 0x%08X", next, wantRT)
	}

	// HandleTimer after wrap: at 0x00000010, should expire.
	expired = nil
	next = m.HandleTimer(0x00000010, cb)
	if len(expired) != 1 || expired[0] != 11 {
		t.Fatalf("expected [11] expired, got %v", expired)
	}
	if next != 0 {
		t.Fatalf("next = %d, want 0", next)
	}
}

// ---------------------------------------------------------------------------
// Boundary: ID 1 and ID 15
// ---------------------------------------------------------------------------

func TestContextIDManagerBoundaryIDs(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()

	for _, id := range []uint8{1, 15} {
		m.MarkAsInUse(id)
		if s := m.State(id); s != ContextIDInUse {
			t.Fatalf("State(%d) = %d, want ContextIDInUse", id, s)
		}
		m.MarkAsUnallocated(id)
		if s := m.State(id); s != ContextIDUnallocated {
			t.Fatalf("State(%d) = %d, want ContextIDUnallocated", id, s)
		}
	}
}

// ---------------------------------------------------------------------------
// HandleTimer returns earliest next fire time
// ---------------------------------------------------------------------------

func TestContextIDManagerHandleTimerReturnsEarliestNext(t *testing.T) {
	t.Parallel()
	m := NewContextIDManager()
	m.SetReuseDelay(100)

	m.MarkAsInUse(1)
	m.MarkAsInUse(2)
	m.MarkAsInUse(3)

	_ = m.ScheduleToRemove(1, 1000) // expires at 1100
	_ = m.ScheduleToRemove(2, 1500) // expires at 1600
	_ = m.ScheduleToRemove(3, 1200) // expires at 1300

	var expired []uint8
	cb := func(id uint8) { expired = append(expired, id) }

	// At t=1100, ID 1 expires. Remaining: ID 3 at 1300, ID 2 at 1600.
	next := m.HandleTimer(1100, cb)
	if len(expired) != 1 || expired[0] != 1 {
		t.Fatalf("expected [1] expired, got %v", expired)
	}
	// Should return 1300 (ID 3), not 1600 (ID 2).
	if next != 1300 {
		t.Fatalf("next = %d, want 1300 (earliest remaining)", next)
	}
}
