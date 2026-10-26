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

// Package message implements the OpenThread message buffer pool and queue.
//
// This is a Go port of openthread/src/core/common/message.hpp and
// message.cpp. It provides variable-length message buffers with priority
// levels, a pool for allocation, and a queue (doubly-linked list) for
// ordered processing.
package message

import (
	"encoding/binary"
	"errors"
	"sync"
)

// Priority represents the message transmission priority.
type Priority uint8

// Message priorities in increasing order of urgency.
const (
	PriorityLow    Priority = 0
	PriorityNormal Priority = 1
	PriorityHigh   Priority = 2
	PriorityNet    Priority = 3
)

// Type represents the message type.
type Type uint8

const (
	TypeIp6   Type = 0 //nolint:revive // Retain the established public API spelling for source compatibility.
	TypeIp4   Type = 1 //nolint:revive // Retain the established public API spelling for source compatibility.
	TypeData  Type = 2
	TypeOther Type = 3
)

// Sentinel errors.
var (
	ErrNoBufs      = errors.New("message: no buffers available")
	ErrInvalidArgs = errors.New("message: invalid arguments")
)

// Message represents a variable-length message buffer used for packet
// processing throughout the OpenThread stack.
type Message struct {
	data         []byte
	offset       int
	msgType      Type
	priority     Priority
	direct       bool
	linkSecurity bool
	origin       uint8

	// Queue linkage (managed by Queue).
	prev *Message
	next *Message
	q    *Queue
}

// NewMessage creates a new empty message with the specified type and priority.
func NewMessage(msgType Type, priority Priority) *Message {
	return &Message{
		msgType:  msgType,
		priority: priority,
	}
}

// GetLength returns the total number of bytes in the message.
func (m *Message) GetLength() int { return len(m.data) }

// SetLength resizes the message data buffer. If the new length is shorter,
// data is truncated. If longer, zero bytes are appended.
func (m *Message) SetLength(length int) error {
	if length < 0 {
		return ErrInvalidArgs
	}
	if length <= len(m.data) {
		m.data = m.data[:length]
	} else {
		m.data = append(m.data, make([]byte, length-len(m.data))...)
	}
	// Clamp offset.
	if m.offset > len(m.data) {
		m.offset = len(m.data)
	}
	return nil
}

// GetOffset returns the current read/write offset.
func (m *Message) GetOffset() int { return m.offset }

// SetOffset sets the read/write offset. It is clamped to [0, length].
func (m *Message) SetOffset(offset int) {
	if offset < 0 {
		offset = 0
	}
	if offset > len(m.data) {
		offset = len(m.data)
	}
	m.offset = offset
}

// Read copies data from the message starting at offset into buf.
// It returns the number of bytes actually copied.
func (m *Message) Read(offset int, buf []byte) int {
	if offset < 0 || offset >= len(m.data) {
		return 0
	}
	return copy(buf, m.data[offset:])
}

// Write copies data into the message at offset, overwriting existing bytes.
// Bytes beyond the message length are silently discarded.
func (m *Message) Write(offset int, data []byte) {
	if offset < 0 || offset >= len(m.data) {
		return
	}
	copy(m.data[offset:], data)
}

// Append adds data to the end of the message.
func (m *Message) Append(data []byte) error {
	m.data = append(m.data, data...)
	return nil
}

// Prepend inserts data at the beginning of the message. The offset is
// adjusted to remain at the same logical position.
func (m *Message) Prepend(data []byte) error {
	m.data = append(data, m.data...)
	m.offset += len(data)
	return nil
}

// RemoveHeader removes length bytes from the front of the message and adjusts
// the offset accordingly.
func (m *Message) RemoveHeader(length int) {
	if length <= 0 {
		return
	}
	if length >= len(m.data) {
		m.data = m.data[:0]
		m.offset = 0
		return
	}
	m.data = m.data[length:]
	m.offset -= length
	if m.offset < 0 {
		m.offset = 0
	}
}

// GetType returns the message type.
func (m *Message) GetType() Type { return m.msgType }

// GetPriority returns the message priority.
func (m *Message) GetPriority() Priority { return m.priority }

// SetPriority sets the message priority.
func (m *Message) SetPriority(p Priority) { m.priority = p }

// GetDirect returns whether the message requires direct transmission.
func (m *Message) GetDirect() bool { return m.direct }

// SetDirect sets the direct transmission flag.
func (m *Message) SetDirect(d bool) { m.direct = d }

// GetLinkSecurity returns whether link-layer security is enabled.
func (m *Message) GetLinkSecurity() bool { return m.linkSecurity }

// SetLinkSecurity sets the link-layer security flag.
func (m *Message) SetLinkSecurity(s bool) { m.linkSecurity = s }

// GetOrigin returns the origin identifier.
func (m *Message) GetOrigin() uint8 { return m.origin }

// SetOrigin sets the origin identifier.
func (m *Message) SetOrigin(o uint8) { m.origin = o }

// Clone creates a deep copy of the message. Queue linkage is not copied.
func (m *Message) Clone() *Message {
	cp := &Message{
		offset:       m.offset,
		msgType:      m.msgType,
		priority:     m.priority,
		direct:       m.direct,
		linkSecurity: m.linkSecurity,
		origin:       m.origin,
	}
	if len(m.data) > 0 {
		cp.data = make([]byte, len(m.data))
		copy(cp.data, m.data)
	}
	return cp
}

// ReadUint8 reads a single byte at offset. Returns 0 if out of bounds.
func (m *Message) ReadUint8(offset int) uint8 {
	if offset < 0 || offset >= len(m.data) {
		return 0
	}
	return m.data[offset]
}

// ReadUint16 reads a big-endian uint16 at offset. Returns 0 if out of bounds.
func (m *Message) ReadUint16(offset int) uint16 {
	if offset < 0 || offset+2 > len(m.data) {
		return 0
	}
	return binary.BigEndian.Uint16(m.data[offset:])
}

// WriteUint8 writes a single byte at offset.
func (m *Message) WriteUint8(offset int, v uint8) {
	if offset < 0 || offset >= len(m.data) {
		return
	}
	m.data[offset] = v
}

// WriteUint16 writes a big-endian uint16 at offset.
func (m *Message) WriteUint16(offset int, v uint16) {
	if offset < 0 || offset+2 > len(m.data) {
		return
	}
	binary.BigEndian.PutUint16(m.data[offset:], v)
}

// ---------------------------------------------------------------------------
// Pool
// ---------------------------------------------------------------------------

// Pool manages a set of message buffers. When maxMessages is > 0, allocation
// is limited; when 0, allocation is unlimited (dynamic).
type Pool struct {
	mu          sync.Mutex
	maxMessages int
	allocated   int
}

// NewPool creates a Pool. Pass maxMessages=0 for unlimited allocation.
func NewPool(maxMessages int) *Pool {
	return &Pool{maxMessages: maxMessages}
}

// Allocate returns a new Message from the pool.
func (p *Pool) Allocate(msgType Type, priority Priority) (*Message, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.maxMessages > 0 && p.allocated >= p.maxMessages {
		return nil, ErrNoBufs
	}
	p.allocated++
	return NewMessage(msgType, priority), nil
}

// Free returns a message to the pool.
func (p *Pool) Free(msg *Message) {
	if msg == nil {
		return
	}
	// Remove from queue if enqueued.
	if msg.q != nil {
		msg.q.remove(msg)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.allocated > 0 {
		p.allocated--
	}
}

// GetFreeCount returns the number of messages that can still be allocated.
// Returns -1 for unlimited pools.
func (p *Pool) GetFreeCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.maxMessages <= 0 {
		return -1
	}
	return p.maxMessages - p.allocated
}

// GetAllocatedCount returns the number of currently allocated messages.
func (p *Pool) GetAllocatedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.allocated
}

// ---------------------------------------------------------------------------
// Queue
// ---------------------------------------------------------------------------

// Queue is a doubly-linked list of Messages.
type Queue struct {
	head   *Message
	tail   *Message
	length int
}

// NewQueue creates an empty message queue.
func NewQueue() *Queue {
	return &Queue{}
}

// Enqueue appends msg to the tail of the queue. If msg is already in a queue
// it is first removed.
func (q *Queue) Enqueue(msg *Message) {
	if msg == nil {
		return
	}
	if msg.q != nil {
		msg.q.remove(msg)
	}
	msg.prev = q.tail
	msg.next = nil
	if q.tail != nil {
		q.tail.next = msg
	} else {
		q.head = msg
	}
	q.tail = msg
	msg.q = q
	q.length++
}

// Dequeue removes and returns the head of the queue, or nil if empty.
func (q *Queue) Dequeue() *Message {
	msg := q.head
	if msg == nil {
		return nil
	}
	q.remove(msg)
	return msg
}

// GetHead returns the head message without removing it, or nil if empty.
func (q *Queue) GetHead() *Message { return q.head }

// GetLength returns the number of messages in the queue.
func (q *Queue) GetLength() int { return q.length }

// remove unlinks msg from the queue.
func (q *Queue) remove(msg *Message) {
	if msg.q != q {
		return
	}
	if msg.prev != nil {
		msg.prev.next = msg.next
	} else {
		q.head = msg.next
	}
	if msg.next != nil {
		msg.next.prev = msg.prev
	} else {
		q.tail = msg.prev
	}
	msg.prev = nil
	msg.next = nil
	msg.q = nil
	q.length--
}
