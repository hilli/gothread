// Copyright (c) 2026, Jan Hillegeer. All rights reserved.
// Copyright (c) 2016, The OpenThread Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from this
//    software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package message

import (
	"bytes"
	"errors"
	"testing"
)

// ---------------------------------------------------------------------------
// Message tests
// ---------------------------------------------------------------------------

func TestNewMessage(t *testing.T) {
	m := NewMessage(TypeIp6, PriorityHigh)
	if m.GetType() != TypeIp6 {
		t.Errorf("type = %v, want %v", m.GetType(), TypeIp6)
	}
	if m.GetPriority() != PriorityHigh {
		t.Errorf("priority = %v, want %v", m.GetPriority(), PriorityHigh)
	}
	if m.GetLength() != 0 {
		t.Errorf("length = %d, want 0", m.GetLength())
	}
}

func TestAppendAndRead(t *testing.T) {
	m := NewMessage(TypeData, PriorityNormal)
	data := []byte{0x01, 0x02, 0x03, 0x04}
	if err := m.Append(data); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if m.GetLength() != 4 {
		t.Fatalf("length = %d, want 4", m.GetLength())
	}
	buf := make([]byte, 4)
	n := m.Read(0, buf)
	if n != 4 || !bytes.Equal(buf, data) {
		t.Errorf("Read = %x (%d bytes), want %x", buf, n, data)
	}
}

func TestWriteOverwrite(t *testing.T) {
	m := NewMessage(TypeData, PriorityNormal)
	_ = m.Append([]byte{0x00, 0x00, 0x00, 0x00})
	m.Write(1, []byte{0xAA, 0xBB})
	buf := make([]byte, 4)
	m.Read(0, buf)
	want := []byte{0x00, 0xAA, 0xBB, 0x00}
	if !bytes.Equal(buf, want) {
		t.Errorf("after Write = %x, want %x", buf, want)
	}
}

func TestPrepend(t *testing.T) {
	m := NewMessage(TypeIp6, PriorityNormal)
	_ = m.Append([]byte{0x03, 0x04})
	m.SetOffset(1)
	_ = m.Prepend([]byte{0x01, 0x02})

	if m.GetLength() != 4 {
		t.Fatalf("length = %d, want 4", m.GetLength())
	}
	if m.GetOffset() != 3 { // original offset 1 + prepend 2
		t.Errorf("offset = %d, want 3", m.GetOffset())
	}
	buf := make([]byte, 4)
	m.Read(0, buf)
	want := []byte{0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(buf, want) {
		t.Errorf("data = %x, want %x", buf, want)
	}
}

func TestRemoveHeader(t *testing.T) {
	tests := []struct {
		name       string
		initial    []byte
		offset     int
		remove     int
		wantData   []byte
		wantOffset int
	}{
		{"partial", []byte{1, 2, 3, 4}, 2, 1, []byte{2, 3, 4}, 1},
		{"all", []byte{1, 2, 3}, 1, 5, []byte{}, 0},
		{"zero", []byte{1, 2}, 1, 0, []byte{1, 2}, 1},
		{"offset clamp", []byte{1, 2, 3, 4}, 1, 3, []byte{4}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMessage(TypeData, PriorityNormal)
			_ = m.Append(tt.initial)
			m.SetOffset(tt.offset)
			m.RemoveHeader(tt.remove)
			if m.GetLength() != len(tt.wantData) {
				t.Errorf("length = %d, want %d", m.GetLength(), len(tt.wantData))
			}
			if m.GetOffset() != tt.wantOffset {
				t.Errorf("offset = %d, want %d", m.GetOffset(), tt.wantOffset)
			}
			buf := make([]byte, m.GetLength())
			m.Read(0, buf)
			if !bytes.Equal(buf, tt.wantData) {
				t.Errorf("data = %x, want %x", buf, tt.wantData)
			}
		})
	}
}

func TestSetLength(t *testing.T) {
	m := NewMessage(TypeData, PriorityNormal)
	_ = m.Append([]byte{1, 2, 3, 4, 5})

	// Shrink.
	_ = m.SetLength(3)
	if m.GetLength() != 3 {
		t.Errorf("after shrink: length = %d, want 3", m.GetLength())
	}

	// Grow with zero-fill.
	_ = m.SetLength(6)
	if m.GetLength() != 6 {
		t.Errorf("after grow: length = %d, want 6", m.GetLength())
	}
	buf := make([]byte, 6)
	m.Read(0, buf)
	want := []byte{1, 2, 3, 0, 0, 0}
	if !bytes.Equal(buf, want) {
		t.Errorf("after grow: data = %x, want %x", buf, want)
	}

	// Invalid.
	if err := m.SetLength(-1); err == nil {
		t.Error("SetLength(-1) should return error")
	}
}

func TestSetOffset(t *testing.T) {
	m := NewMessage(TypeData, PriorityNormal)
	_ = m.Append([]byte{1, 2, 3})

	m.SetOffset(2)
	if m.GetOffset() != 2 {
		t.Errorf("offset = %d, want 2", m.GetOffset())
	}

	// Clamp to length.
	m.SetOffset(100)
	if m.GetOffset() != 3 {
		t.Errorf("offset = %d, want 3 (clamped)", m.GetOffset())
	}

	// Clamp to 0.
	m.SetOffset(-5)
	if m.GetOffset() != 0 {
		t.Errorf("offset = %d, want 0 (clamped)", m.GetOffset())
	}
}

func TestReadOutOfBounds(t *testing.T) {
	m := NewMessage(TypeData, PriorityNormal)
	_ = m.Append([]byte{1, 2, 3})
	buf := make([]byte, 2)

	// Offset beyond length.
	if n := m.Read(10, buf); n != 0 {
		t.Errorf("Read(10) = %d bytes, want 0", n)
	}
	// Negative offset.
	if n := m.Read(-1, buf); n != 0 {
		t.Errorf("Read(-1) = %d bytes, want 0", n)
	}
}

func TestWriteOutOfBounds(t *testing.T) {
	m := NewMessage(TypeData, PriorityNormal)
	_ = m.Append([]byte{1, 2, 3})

	// Should not panic.
	m.Write(10, []byte{0xFF})
	m.Write(-1, []byte{0xFF})

	// Verify data unchanged.
	buf := make([]byte, 3)
	m.Read(0, buf)
	if !bytes.Equal(buf, []byte{1, 2, 3}) {
		t.Errorf("data = %x, want 010203", buf)
	}
}

func TestClone(t *testing.T) {
	m := NewMessage(TypeIp6, PriorityNet)
	_ = m.Append([]byte{0xCA, 0xFE})
	m.SetOffset(1)
	m.SetDirect(true)
	m.SetLinkSecurity(true)
	m.SetOrigin(42)

	c := m.Clone()
	if c.GetType() != TypeIp6 || c.GetPriority() != PriorityNet {
		t.Error("type or priority mismatch")
	}
	if c.GetOffset() != 1 {
		t.Errorf("clone offset = %d, want 1", c.GetOffset())
	}
	if !c.GetDirect() || !c.GetLinkSecurity() || c.GetOrigin() != 42 {
		t.Error("metadata mismatch in clone")
	}

	// Verify deep copy.
	buf := make([]byte, 2)
	c.Read(0, buf)
	if !bytes.Equal(buf, []byte{0xCA, 0xFE}) {
		t.Errorf("clone data = %x, want cafe", buf)
	}

	// Mutating clone should not affect original.
	c.Write(0, []byte{0xFF})
	origBuf := make([]byte, 2)
	m.Read(0, origBuf)
	if origBuf[0] == 0xFF {
		t.Error("clone mutation affected original")
	}
}

func TestReadWriteUint8(t *testing.T) {
	m := NewMessage(TypeData, PriorityNormal)
	_ = m.Append([]byte{0, 0, 0})

	m.WriteUint8(1, 0xAB)
	if got := m.ReadUint8(1); got != 0xAB {
		t.Errorf("ReadUint8 = 0x%02x, want 0xAB", got)
	}

	// Out of bounds.
	if got := m.ReadUint8(10); got != 0 {
		t.Errorf("ReadUint8 OOB = 0x%02x, want 0", got)
	}
}

func TestReadWriteUint16(t *testing.T) {
	m := NewMessage(TypeData, PriorityNormal)
	_ = m.Append([]byte{0, 0, 0, 0})

	m.WriteUint16(1, 0xBEEF)
	if got := m.ReadUint16(1); got != 0xBEEF {
		t.Errorf("ReadUint16 = 0x%04x, want 0xBEEF", got)
	}

	// Verify big-endian byte order.
	if m.ReadUint8(1) != 0xBE || m.ReadUint8(2) != 0xEF {
		t.Error("uint16 not stored in big-endian")
	}

	// Out of bounds.
	if got := m.ReadUint16(3); got != 0 {
		t.Errorf("ReadUint16 OOB = 0x%04x, want 0", got)
	}
}

func TestMessageFlags(t *testing.T) {
	m := NewMessage(TypeIp6, PriorityNormal)
	m.SetDirect(true)
	m.SetLinkSecurity(true)
	m.SetOrigin(7)
	m.SetPriority(PriorityHigh)

	if !m.GetDirect() {
		t.Error("GetDirect() = false, want true")
	}
	if !m.GetLinkSecurity() {
		t.Error("GetLinkSecurity() = false, want true")
	}
	if m.GetOrigin() != 7 {
		t.Errorf("GetOrigin() = %d, want 7", m.GetOrigin())
	}
	if m.GetPriority() != PriorityHigh {
		t.Errorf("GetPriority() = %v, want %v", m.GetPriority(), PriorityHigh)
	}
}

// ---------------------------------------------------------------------------
// Pool tests
// ---------------------------------------------------------------------------

func TestPoolAllocateAndFree(t *testing.T) {
	p := NewPool(3)

	msgs := make([]*Message, 3)
	for i := 0; i < 3; i++ {
		m, err := p.Allocate(TypeIp6, PriorityNormal)
		if err != nil {
			t.Fatalf("Allocate[%d]: %v", i, err)
		}
		msgs[i] = m
	}

	if p.GetFreeCount() != 0 {
		t.Errorf("free count = %d, want 0", p.GetFreeCount())
	}

	// Pool exhaustion.
	_, err := p.Allocate(TypeIp6, PriorityNormal)
	if !errors.Is(err, ErrNoBufs) {
		t.Errorf("expected ErrNoBufs, got %v", err)
	}

	// Free one and re-allocate.
	p.Free(msgs[0])
	if p.GetFreeCount() != 1 {
		t.Errorf("free count = %d, want 1", p.GetFreeCount())
	}
	_, err = p.Allocate(TypeIp6, PriorityNormal)
	if err != nil {
		t.Fatalf("Allocate after Free: %v", err)
	}
}

func TestPoolUnlimited(t *testing.T) {
	p := NewPool(0)
	if p.GetFreeCount() != -1 {
		t.Errorf("unlimited pool free count = %d, want -1", p.GetFreeCount())
	}
	for i := 0; i < 100; i++ {
		_, err := p.Allocate(TypeData, PriorityLow)
		if err != nil {
			t.Fatalf("Allocate[%d]: %v", i, err)
		}
	}
}

func TestPoolFreeNil(t *testing.T) {
	p := NewPool(5)
	p.Free(nil) // should not panic
}

func TestPoolFreeRemovesFromQueue(t *testing.T) {
	p := NewPool(5)
	q := NewQueue()

	m, _ := p.Allocate(TypeIp6, PriorityNormal)
	q.Enqueue(m)
	if q.GetLength() != 1 {
		t.Fatal("queue should have 1 message")
	}

	p.Free(m)
	if q.GetLength() != 0 {
		t.Error("Free should remove message from queue")
	}
}

// ---------------------------------------------------------------------------
// Queue tests
// ---------------------------------------------------------------------------

func TestQueueEnqueueDequeue(t *testing.T) {
	q := NewQueue()

	m1 := NewMessage(TypeIp6, PriorityNormal)
	_ = m1.Append([]byte{1})
	m2 := NewMessage(TypeIp6, PriorityNormal)
	_ = m2.Append([]byte{2})
	m3 := NewMessage(TypeIp6, PriorityNormal)
	_ = m3.Append([]byte{3})

	q.Enqueue(m1)
	q.Enqueue(m2)
	q.Enqueue(m3)

	if q.GetLength() != 3 {
		t.Fatalf("length = %d, want 3", q.GetLength())
	}

	// FIFO order.
	for i, want := range []*Message{m1, m2, m3} {
		got := q.Dequeue()
		if got != want {
			t.Errorf("Dequeue[%d]: got %p, want %p", i, got, want)
		}
	}

	if q.GetLength() != 0 {
		t.Errorf("length after drain = %d, want 0", q.GetLength())
	}
	if q.Dequeue() != nil {
		t.Error("Dequeue on empty queue should return nil")
	}
}

func TestQueueGetHead(t *testing.T) {
	q := NewQueue()
	if q.GetHead() != nil {
		t.Error("GetHead on empty queue should return nil")
	}

	m := NewMessage(TypeData, PriorityNormal)
	q.Enqueue(m)
	if q.GetHead() != m {
		t.Error("GetHead should return first enqueued message")
	}
}

func TestQueueEnqueueNil(t *testing.T) {
	q := NewQueue()
	q.Enqueue(nil) // should not panic
	if q.GetLength() != 0 {
		t.Error("length should be 0 after enqueueing nil")
	}
}

func TestQueueReEnqueue(t *testing.T) {
	q1 := NewQueue()
	q2 := NewQueue()

	m := NewMessage(TypeIp6, PriorityNormal)
	q1.Enqueue(m)
	if q1.GetLength() != 1 {
		t.Fatal("q1 length should be 1")
	}

	// Enqueue into q2 should remove from q1.
	q2.Enqueue(m)
	if q1.GetLength() != 0 {
		t.Error("q1 length should be 0 after re-enqueue")
	}
	if q2.GetLength() != 1 {
		t.Error("q2 length should be 1 after re-enqueue")
	}
}

func TestQueueMiddleRemoval(t *testing.T) {
	q := NewQueue()
	m1 := NewMessage(TypeIp6, PriorityNormal)
	m2 := NewMessage(TypeIp6, PriorityNormal)
	m3 := NewMessage(TypeIp6, PriorityNormal)

	q.Enqueue(m1)
	q.Enqueue(m2)
	q.Enqueue(m3)

	// Remove middle via re-enqueue to another queue.
	q2 := NewQueue()
	q2.Enqueue(m2)

	if q.GetLength() != 2 {
		t.Errorf("q length = %d, want 2", q.GetLength())
	}

	// Remaining should be m1, m3.
	if q.Dequeue() != m1 {
		t.Error("expected m1")
	}
	if q.Dequeue() != m3 {
		t.Error("expected m3")
	}
}
