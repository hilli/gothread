// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"

	goterrors "github.com/hilli/gothread/errors"
)

// Mesh header constants for IEEE 802.15.4 mesh addressing.
const (
	// MeshDispatch is the dispatch byte pattern for mesh headers (0b10xxxxxx).
	MeshDispatch = 0x80

	// MeshDispatchMask masks the top two bits to identify mesh dispatch.
	MeshDispatchMask = 0xC0

	// MeshHopsLeftMask masks the lower 4 bits for the hops-left field.
	MeshHopsLeftMask = 0x0F

	// MeshDeepHopsFlag indicates that hops-left > 15 and an extra byte follows.
	MeshDeepHopsFlag = 0x10

	// MeshSourceShortFlag indicates the source address is a short (16-bit) address.
	MeshSourceShortFlag = 0x20

	// MeshDestShortFlag indicates the destination address is a short (16-bit) address.
	// In the standard encoding, bit 4 of the V/F field is 0 for short dest.
	MeshDestShortFlag = 0x00

	// MaxHopsLeft is the maximum hops-left value for mesh headers.
	MaxHopsLeft = 20

	// meshHeaderMinLen is the minimum mesh header length:
	// 1 byte dispatch + 2 bytes originator + 2 bytes final dest.
	meshHeaderMinLen = 5

	// meshHeaderDeepHopsLen is the mesh header length with deep hops:
	// 1 byte dispatch + 1 byte deep hops + 2 bytes originator + 2 bytes final dest.
	meshHeaderDeepHopsLen = 6
)

// 6LoWPAN fragmentation header constants.
const (
	// FragDispatch is the dispatch byte for first fragments (0b11000xxx).
	FragDispatch = 0xC0

	// FragDispatchMask masks the top 5 bits for fragment identification.
	FragDispatchMask = 0xF8

	// FragFirstDispatch is the dispatch value for first fragments.
	FragFirstDispatch = 0xC0

	// FragSubsequentDispatch is the dispatch value for subsequent fragments.
	FragSubsequentDispatch = 0xE0

	// FragFirstHeaderLen is the header length for a first fragment (4 bytes).
	FragFirstHeaderLen = 4

	// FragSubsequentHeaderLen is the header length for subsequent fragments (5 bytes).
	FragSubsequentHeaderLen = 5

	// FragMaxSize is the maximum datagram size (11 bits).
	FragMaxSize = 0x07FF

	// DefaultFragmentTag is the starting fragment tag value.
	DefaultFragmentTag = 1

	// FragReassemblyTimeoutSec is the reassembly timeout in seconds.
	FragReassemblyTimeoutSec = 60
)

// Errors used by the mesh forwarder.
var (
	ErrForwarderDisabled = errors.New("mesh forwarder is disabled")
	ErrQueueFull         = errors.New("transmit queue is full")
	ErrInvalidMeshHeader = errors.New("invalid mesh header")
	ErrFragmentTooLarge  = errors.New("fragment exceeds maximum size")
	ErrReassemblyTimeout = errors.New("reassembly timeout")
	ErrNoRoute           = errors.New("no route available")
)

// Shared TX budgets include direct, indirect, and in-flight owned datagrams.
// Four maximum-MTU packets fit the byte budget; small packets may use the
// existing descriptor bound without allocating 100 maximum-MTU buffers.
const (
	MaxPendingDatagramBytes = 4 * IPv6MTU
	MaxPendingFragments     = MaxFramesInDirectTxQueue
)

// ForwarderCounters tracks mesh forwarder-specific transmission and reception statistics.
type ForwarderCounters struct {
	TxUnicast         uint32
	TxBroadcast       uint32
	TxDirect          uint32
	TxIndirect        uint32
	TxMesh            uint32
	TxFragment        uint32
	RxUnicast         uint32
	RxBroadcast       uint32
	RxDirect          uint32
	RxMesh            uint32
	RxFragment        uint32
	TxDropped         uint32
	RxDropped         uint32
	ReassemblyTimeout uint32
	FragmentError     uint32
}

// Reset clears all forwarder counters to zero.
func (c *ForwarderCounters) Reset() { *c = ForwarderCounters{} }

// TxMetadata holds IPv6 and transport-layer metadata required to build
// a proper 6LoWPAN-compressed frame on the TX path. When populated,
// HandleFrameRequest can construct the full stack of headers:
// 802.15.4 MAC → 6LoWPAN IPHC → (optional NHC UDP) → payload.
type TxMetadata struct {
	// SrcAddr is the IPv6 source address.
	SrcAddr [16]byte
	// DstAddr is the IPv6 destination address.
	DstAddr [16]byte

	// SrcPort is the UDP source port (0 if not UDP).
	SrcPort uint16
	// DstPort is the UDP destination port (0 if not UDP).
	DstPort uint16

	// NextHeader is the IPv6 next header protocol number
	// (e.g. ip6.ProtoUDP=17, ip6.ProtoICMPv6=58).
	NextHeader uint8
	// HopLimit is the IPv6 hop limit.
	HopLimit uint8

	// SrcExtAddr is the source extended MAC address (for MAC header and
	// IPHC stateless address compression).
	SrcExtAddr [8]byte
	// DstExtAddr is the destination extended MAC address.
	DstExtAddr [8]byte

	// UseSrcShort indicates the MAC source should use the short address
	// (MeshSource) rather than SrcExtAddr.
	UseSrcShort bool
	// UseDstShort indicates the MAC destination should use the short
	// address (MeshDest) rather than DstExtAddr.
	UseDstShort bool

	// PanId is the IEEE 802.15.4 PAN ID.
	PanId uint16 //nolint:revive // Preserve the exported API spelling for existing callers.

	// SecurityEnabled indicates whether MAC-layer security is used.
	SecurityEnabled bool
	// Security holds the MAC-layer security material when SecurityEnabled.
	Security SecurityMaterial
}

// TxMessage represents a message queued for transmission through the mesh.
type TxMessage struct {
	// Data is the application-layer payload to transmit (e.g. MLE or
	// CoAP message body). When Metadata is non-nil, this is just the
	// payload — IPv6, UDP, and MAC headers are constructed from
	// Metadata during frame building.
	Data []byte
	// MeshDest is the destination short address for mesh routing.
	MeshDest uint16
	// MeshSource is the source short address for mesh routing.
	MeshSource uint16
	// Priority is the message priority level.
	Priority uint8
	// Direct indicates whether the message is sent directly (not via mesh).
	Direct bool
	// AckRequired indicates whether an acknowledgment is requested.
	AckRequired bool
	// MaxHops is the maximum number of hops for mesh forwarding.
	MaxHops uint8
	// Metadata holds IPv6/transport/MAC metadata for frame construction.
	// When nil, Data is treated as a pre-built frame (legacy behavior).
	Metadata *TxMetadata
	// ValidateFrame rechecks changing admission prerequisites before each
	// distinct frame is built or takes a security counter. It runs on the
	// owner's serialized loop and must not re-enter the upper MAC mutex.
	// A failure retires the entire datagram through normal TX-drop handling.
	ValidateFrame func() error
	transmit      *transmitState
	retired       bool
}

// NewTxMessage creates a new TxMessage with default settings.
func NewTxMessage(data []byte, dest, source uint16) *TxMessage {
	return &TxMessage{
		Data:        data,
		MeshDest:    dest,
		MeshSource:  source,
		Priority:    uint8(PriorityNormal),
		Direct:      true,
		AckRequired: true,
		MaxHops:     MaxHopsLeft,
	}
}

// NewTxMessageWithMetadata creates a TxMessage with full IPv6/transport
// metadata for proper frame construction. The data parameter is the
// application-layer payload (not including IPv6 or UDP headers).
func NewTxMessageWithMetadata(data []byte, dest, source uint16, meta *TxMetadata) *TxMessage {
	return &TxMessage{
		Data:        data,
		MeshDest:    dest,
		MeshSource:  source,
		Priority:    uint8(PriorityNormal),
		Direct:      true,
		AckRequired: true,
		MaxHops:     MaxHopsLeft,
		Metadata:    meta,
	}
}

// HasMetadata reports whether this TxMessage has IPv6/transport metadata
// for full frame construction.
func (m *TxMessage) HasMetadata() bool {
	return m.Metadata != nil
}

// FragmentInfo tracks a partially reassembled datagram.
type FragmentInfo struct {
	// Tag is the 6LoWPAN datagram tag.
	Tag uint16
	// Size is the total datagram size.
	Size uint16
	// Source is the originator's extended address.
	Source [8]byte
	// Fragments holds the received fragment data indexed by offset.
	Fragments []FragmentData
	// ReceivedLen is the total bytes received so far.
	ReceivedLen uint16
	// Timer is the time the first fragment was received.
	Timer      time.Time
	buffer     []byte
	ranges     [IPv6MTU / 8]fragmentRange
	rangeCount int
}

// FragmentData holds a single fragment's offset and payload.
type FragmentData struct {
	Offset uint16
	Data   []byte
}

// IsComplete returns true if all bytes of the datagram have been received.
func (f *FragmentInfo) IsComplete() bool {
	return f.Size > 0 && f.ReceivedLen >= f.Size
}

// IsExpired returns true if the reassembly has timed out.
func (f *FragmentInfo) IsExpired(now time.Time) bool {
	return now.Sub(f.Timer) > FragReassemblyTimeoutSec*time.Second
}

// Reassemble returns the fully reassembled datagram or nil if incomplete.
func (f *FragmentInfo) Reassemble() []byte {
	if !f.IsComplete() {
		return nil
	}
	if f.buffer != nil {
		return append([]byte(nil), f.buffer...)
	}
	buf := make([]byte, f.Size)
	for _, frag := range f.Fragments {
		copy(buf[frag.Offset:], frag.Data)
	}
	return buf
}

// FrameMeta holds metadata for a frame to be transmitted.
type FrameMeta struct {
	DstAddr         uint16
	SrcAddr         uint16
	PanID           uint16
	Channel         uint8
	AckRequest      bool
	SecurityEnabled bool
	KeyIDMode       uint8
}

// ReceivedFrameInfo holds metadata about a received frame.
type ReceivedFrameInfo struct {
	Rssi         int8
	Lqi          uint8
	Channel      uint8
	LinkSecurity bool
	Timestamp    uint64
}

// Forwarder implements the Thread mesh forwarder.
//
// It manages TX/RX queues, mesh header construction/parsing,
// 6LoWPAN fragmentation and reassembly, and forwarding counters.
type Forwarder struct {
	mu sync.Mutex

	enabled      bool
	rxOnWhenIdle bool

	directQueue      []*TxMessage
	indirectQueue    []*TxMessage
	reassemblyMap    map[FragmentKey]*FragmentInfo
	recentFragments  map[fragmentIdentity]recentFragment
	now              func() time.Time
	owned            map[*TxMessage]int
	pendingBytes     int
	pendingFragments int

	counters    ForwarderCounters
	nextFragTag uint16
}

// NewForwarder creates a new Forwarder ready for use.
func NewForwarder() *Forwarder {
	return NewForwarderWithTag(DefaultFragmentTag)
}

// NewForwarderWithTag selects the initial (otherwise unspecified by RFC 4944)
// fragment tag. Instance seeds this from its restored MAC counter to avoid
// immediately repeating recent tags after an ordinary persistent reboot.
func NewForwarderWithTag(tag uint16) *Forwarder {
	return &Forwarder{
		directQueue:     make([]*TxMessage, 0, MaxFramesInDirectTxQueue),
		indirectQueue:   make([]*TxMessage, 0, MaxFramesInDirectTxQueue),
		reassemblyMap:   make(map[FragmentKey]*FragmentInfo),
		recentFragments: make(map[fragmentIdentity]recentFragment),
		now:             time.Now,
		owned:           make(map[*TxMessage]int),
		nextFragTag:     tag,
	}
}

// SetEnabled enables or disables the mesh forwarder.
func (f *Forwarder) SetEnabled(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled = enabled
	if !enabled {
		for msg := range f.owned {
			msg.transmit, msg.Data, msg.Metadata, msg.ValidateFrame, msg.retired = nil, nil, nil, nil, true
			f.counters.TxDropped++
		}
		clear(f.owned)
		f.pendingBytes, f.pendingFragments = 0, 0
		f.directQueue = f.directQueue[:0]
		f.indirectQueue = f.indirectQueue[:0]
		clear(f.reassemblyMap)
		clear(f.recentFragments)
	}
}

// IsEnabled returns whether the mesh forwarder is enabled.
func (f *Forwarder) IsEnabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enabled
}

// SetRxOnWhenIdle sets whether the receiver is on when idle.
func (f *Forwarder) SetRxOnWhenIdle(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rxOnWhenIdle = on
}

// GetRxOnWhenIdle returns whether the receiver is on when idle.
func (f *Forwarder) GetRxOnWhenIdle() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rxOnWhenIdle
}

// SendMessage queues a message for transmission.
func (f *Forwarder) SendMessage(msg *TxMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.enabled {
		return ErrForwarderDisabled
	}
	if msg == nil {
		return goterrors.ErrInvalidArgs
	}
	if _, exists := f.owned[msg]; exists {
		return goterrors.ErrInvalidState
	}
	if len(f.owned) >= MaxFramesInDirectTxQueue {
		f.counters.TxDropped++
		return ErrQueueFull
	}
	owned := *msg
	owned.retired = false
	var state *transmitState
	if msg.Metadata != nil {
		metadata := *msg.Metadata
		owned.Metadata = &metadata
		var err error
		state, err = prepareTransmit(&owned)
		if err != nil {
			return err
		}
		owned.Data = state.packet[state.headerSize:]
	} else {
		if len(msg.Data) > MaxPsduSize-FCSSize {
			return goterrors.ErrNoBufs
		}
		owned.Data = append([]byte(nil), msg.Data...)
		state = &transmitState{packet: owned.Data, fragments: 1, remaining: 1}
	}
	if f.pendingBytes+len(state.packet) > MaxPendingDatagramBytes ||
		f.pendingFragments+state.fragments > MaxPendingFragments {
		f.counters.TxDropped++
		return ErrQueueFull
	}
	if state.fragments > 1 {
		state.tag = f.allocateTagLocked()
	}
	owned.transmit = state
	*msg = owned
	f.owned[msg] = len(state.packet)
	f.pendingBytes += len(state.packet)
	f.pendingFragments += state.fragments
	if msg.Direct {
		f.directQueue = append(f.directQueue, msg)
	} else {
		f.indirectQueue = append(f.indirectQueue, msg)
	}

	return nil
}

// HandleFrameRequest dequeues the next direct message for transmission.
// Returns nil if the queue is empty.
func (f *Forwarder) HandleFrameRequest() *TxMessage {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.directQueue) == 0 {
		return nil
	}

	msg := f.directQueue[0]
	copy(f.directQueue, f.directQueue[1:])
	f.directQueue[len(f.directQueue)-1] = nil
	f.directQueue = f.directQueue[:len(f.directQueue)-1]
	return msg
}

// HandleSentFrame updates counters after a frame was successfully sent.
func (f *Forwarder) HandleSentFrame(msg *TxMessage, success bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if msg.retired {
		return
	}

	if state := msg.transmit; state != nil {
		if _, exists := f.owned[msg]; exists && success {
			state.offset = state.frameEnd
			state.remaining--
			f.pendingFragments--
			if state.remaining > 0 {
				f.directQueue = append(f.directQueue, nil)
				copy(f.directQueue[1:], f.directQueue[:len(f.directQueue)-1])
				f.directQueue[0] = msg
				return
			}
		}
	}
	f.releaseTxLocked(msg)
	if !success {
		f.counters.TxDropped++
		return
	}
	if msg.Direct {
		f.counters.TxDirect++
	} else {
		f.counters.TxIndirect++
	}
	if msg.MeshDest == 0xFFFF {
		f.counters.TxBroadcast++
	} else {
		f.counters.TxUnicast++
	}
}

func (f *Forwarder) releaseTxLocked(msg *TxMessage) {
	if count, exists := f.owned[msg]; exists {
		f.pendingBytes -= count
		if msg.transmit != nil {
			f.pendingFragments -= msg.transmit.remaining
		}
		delete(f.owned, msg)
		msg.transmit, msg.Data, msg.Metadata, msg.ValidateFrame, msg.retired = nil, nil, nil, nil, true
	}
}

func (f *Forwarder) allocateTagLocked() uint16 {
	for {
		tag := f.nextFragTag
		f.nextFragTag++ // RFC 4944 wraps 65535 to zero.
		used := false
		for msg := range f.owned {
			if msg.transmit != nil && msg.transmit.fragments > 1 && msg.transmit.tag == tag {
				used = true
				break
			}
		}
		if !used {
			return tag
		}
	}
}

// FramePrepared records a distinct secured fragment, not a MAC retry.
func (f *Forwarder) FramePrepared(msg *TxMessage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if msg.transmit != nil && msg.transmit.fragments > 1 {
		f.counters.TxFragment++
	}
}

// HasPendingDirect reports whether the MAC should request another frame.
func (f *Forwarder) HasPendingDirect() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.directQueue) != 0
}

// AbortFragments discards queued/partial fragmented datagrams on a Thread
// disassociation or event-loop stop. An already prepared radio frame cannot
// be retracted, but its eventual completion cannot revive the datagram.
// Unfragmented pending traffic retains the pre-existing lifecycle behavior.
func (f *Forwarder) AbortFragments() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for msg := range f.owned {
		if msg.transmit != nil && msg.transmit.fragments > 1 {
			f.releaseTxLocked(msg)
			f.counters.TxDropped++
		}
	}
	keep := func(queue []*TxMessage) []*TxMessage {
		n := 0
		for _, msg := range queue {
			if !msg.retired {
				queue[n] = msg
				n++
			}
		}
		clear(queue[n:])
		return queue[:n]
	}
	f.directQueue = keep(f.directQueue)
	f.indirectQueue = keep(f.indirectQueue)
	clear(f.reassemblyMap)
	clear(f.recentFragments)
}

// BufferUsage reports owned payload resources, including in-flight TX.
type BufferUsage struct {
	TxDatagrams int
	TxBytes     int
	TxFragments int
	RxDatagrams int
	RxBytes     int
}

// GetBufferUsage returns the current bounded buffer usage.
func (f *Forwarder) GetBufferUsage() BufferUsage {
	f.mu.Lock()
	defer f.mu.Unlock()
	usage := BufferUsage{TxDatagrams: len(f.owned), TxBytes: f.pendingBytes, TxFragments: f.pendingFragments}
	for _, entry := range f.reassemblyMap {
		usage.RxDatagrams++
		usage.RxBytes += int(entry.Size)
	}
	return usage
}

// PrepareDirectFrame builds a direct (non-mesh) frame from a TxMessage.
// Returns the frame data and metadata.
func (f *Forwarder) PrepareDirectFrame(msg *TxMessage) ([]byte, *FrameMeta) {
	meta := &FrameMeta{
		DstAddr:    msg.MeshDest,
		SrcAddr:    msg.MeshSource,
		AckRequest: msg.AckRequired,
	}

	frame := make([]byte, len(msg.Data))
	copy(frame, msg.Data)
	return frame, meta
}

// PrepareMeshFrame builds a mesh-forwarded frame by prepending a mesh header.
func (f *Forwarder) PrepareMeshFrame(msg *TxMessage) ([]byte, *FrameMeta, error) {
	hdr := BuildMeshHeader(msg.MeshSource, msg.MeshDest, msg.MaxHops)

	frame := make([]byte, 0, len(hdr)+len(msg.Data))
	frame = append(frame, hdr...)
	frame = append(frame, msg.Data...)

	meta := &FrameMeta{
		DstAddr:    msg.MeshDest,
		SrcAddr:    msg.MeshSource,
		AckRequest: msg.AckRequired,
	}

	f.mu.Lock()
	f.counters.TxMesh++
	f.mu.Unlock()

	return frame, meta, nil
}

// HandleReceivedFrame processes a received frame, dispatching to the
// appropriate handler based on the frame type (mesh or direct).
// Returns the payload data and whether it was a mesh frame.
func (f *Forwarder) HandleReceivedFrame(data []byte, info *ReceivedFrameInfo) (payload []byte, isMesh bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.enabled {
		return nil, false, ErrForwarderDisabled
	}

	if len(data) == 0 {
		f.counters.RxDropped++
		return nil, false, ErrInvalidMeshHeader
	}

	// Check if this is a mesh header frame.
	if data[0]&MeshDispatchMask == MeshDispatch {
		f.counters.RxMesh++
		payload, err := f.handleMeshFrameLocked(data)
		return payload, true, err
	}

	// Direct frame.
	f.counters.RxDirect++
	f.counters.RxUnicast++
	return data, false, nil
}

// handleMeshFrameLocked processes a mesh-header frame. Must be called with mu held.
func (f *Forwarder) handleMeshFrameLocked(data []byte) ([]byte, error) {
	source, dest, hopsLeft, headerLen, err := ParseMeshHeader(data)
	if err != nil {
		f.counters.RxDropped++
		return nil, err
	}

	_ = source
	_ = dest

	if hopsLeft == 0 {
		f.counters.RxDropped++
		return nil, ErrNoRoute
	}

	payload := data[headerLen:]
	return payload, nil
}

// HandleFragment is the compatibility entry point for uncompressed byte ranges
// with no additional link scope. Real MAC receivers use HandleScopedFragment.
func (f *Forwarder) HandleFragment(srcAddr [8]byte, tag, size, offset uint16, data []byte) ([]byte, error) {
	return f.HandleScopedFragment(FragmentKey{
		Scope: FragmentScope{Source: srcAddr}, Tag: tag, Size: size,
	}, offset, data)
}

// GetReassemblyList returns the number of datagrams currently being reassembled.
func (f *Forwarder) GetReassemblyList() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reassemblyMap)
}

// CleanupExpiredReassemblies removes timed-out reassembly entries.
func (f *Forwarder) CleanupExpiredReassemblies() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.expireFragmentsLocked(f.now())
}

// GetDirectQueue returns a snapshot of the current direct TX queue.
func (f *Forwarder) GetDirectQueue() []*TxMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*TxMessage, len(f.directQueue))
	copy(out, f.directQueue)
	return out
}

// GetIndirectQueue returns a snapshot of the current indirect TX queue.
func (f *Forwarder) GetIndirectQueue() []*TxMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*TxMessage, len(f.indirectQueue))
	copy(out, f.indirectQueue)
	return out
}

// GetQueueLength returns the number of messages in the direct and indirect queues.
func (f *Forwarder) GetQueueLength() (direct, indirect int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.directQueue), len(f.indirectQueue)
}

// EvictMessage attempts to evict the lowest priority message from the direct
// queue that is below the given priority threshold. Returns true if a message
// was evicted.
func (f *Forwarder) EvictMessage(priority uint8) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	lowestIdx := -1
	lowestPri := priority

	for i, msg := range f.directQueue {
		if msg.Priority < lowestPri {
			lowestPri = msg.Priority
			lowestIdx = i
		}
	}

	if lowestIdx < 0 {
		return false
	}

	// Remove the evicted message.
	f.releaseTxLocked(f.directQueue[lowestIdx])
	copy(f.directQueue[lowestIdx:], f.directQueue[lowestIdx+1:])
	f.directQueue = f.directQueue[:len(f.directQueue)-1]
	f.counters.TxDropped++
	return true
}

// FragmentMessage splits a datagram into 6LoWPAN fragments.
// Each fragment will be at most fragmentSize bytes of payload.
func (f *Forwarder) FragmentMessage(data []byte, fragmentSize int) (frames [][]byte, datagramTag uint16, err error) {
	// This utility accepts ORIGINAL IPv6 bytes, not an already compressed
	// buffer. Its first fragment uses the standard uncompressed dispatch.
	if len(data) < 40 || len(data) > IPv6MTU || data[0]>>4 != 6 ||
		int(binary.BigEndian.Uint16(data[4:6]))+40 != len(data) ||
		fragmentSize < FragFirstHeaderLen+41 || fragmentSize > MaxPsduSize-FCSSize {
		return nil, 0, ErrFragmentTooLarge
	}
	header := append([]byte{0x41}, data[:40]...)
	if len(data)+1 <= fragmentSize {
		return [][]byte{append([]byte{0x41}, data...)}, 0, nil
	}
	state := &transmitState{packet: data, header: header, headerSize: 40, maxPayload: fragmentSize}
	for offset := 0; offset < len(data); {
		end, endErr := state.nextEnd(offset)
		if endErr != nil {
			return nil, 0, endErr
		}
		state.fragments++
		offset = end
	}
	f.mu.Lock()
	state.tag = f.allocateTagLocked()
	f.mu.Unlock()
	for state.offset < len(data) {
		part, partErr := state.payload()
		if partErr != nil {
			return nil, 0, partErr
		}
		frames = append(frames, part)
		state.offset = state.frameEnd
	}
	f.mu.Lock()
	f.counters.TxFragment += uint32(len(frames))
	f.mu.Unlock()
	return frames, state.tag, nil
}

// GetCounters returns a copy of the forwarder counters.
func (f *Forwarder) GetCounters() ForwarderCounters {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counters
}

// ResetCounters resets all forwarder counters to zero.
func (f *Forwarder) ResetCounters() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counters.Reset()
}

// BuildMeshHeader constructs a mesh header with the given source, destination,
// and hops-left values.
//
// For hopsLeft <= 15, the header is 5 bytes:
//
//	[dispatch|hopsLeft] [originator_hi] [originator_lo] [dest_hi] [dest_lo]
//
// For hopsLeft > 15, the header is 6 bytes (deep hops):
//
//	[dispatch|deepFlag|0xF] [hopsLeft] [originator_hi] [originator_lo] [dest_hi] [dest_lo]
func BuildMeshHeader(source, dest uint16, hopsLeft uint8) []byte {
	if hopsLeft > MaxHopsLeft {
		hopsLeft = MaxHopsLeft
	}

	if hopsLeft <= 15 {
		hdr := make([]byte, meshHeaderMinLen)
		hdr[0] = MeshDispatch | MeshSourceShortFlag | hopsLeft
		binary.BigEndian.PutUint16(hdr[1:3], source)
		binary.BigEndian.PutUint16(hdr[3:5], dest)
		return hdr
	}

	// Deep hops: hopsLeft > 15.
	hdr := make([]byte, meshHeaderDeepHopsLen)
	hdr[0] = MeshDispatch | MeshSourceShortFlag | MeshDeepHopsFlag | MeshHopsLeftMask
	hdr[1] = hopsLeft
	binary.BigEndian.PutUint16(hdr[2:4], source)
	binary.BigEndian.PutUint16(hdr[4:6], dest)
	return hdr
}

// ParseMeshHeader parses a mesh header from raw data.
// Returns source address, destination address, hops left, header length, and any error.
func ParseMeshHeader(data []byte) (source, dest uint16, hopsLeft uint8, headerLen int, err error) {
	if len(data) < meshHeaderMinLen {
		return 0, 0, 0, 0, ErrInvalidMeshHeader
	}

	dispatch := data[0]
	if dispatch&MeshDispatchMask != MeshDispatch {
		return 0, 0, 0, 0, ErrInvalidMeshHeader
	}

	deepHops := dispatch&MeshDeepHopsFlag != 0

	if deepHops {
		if len(data) < meshHeaderDeepHopsLen {
			return 0, 0, 0, 0, ErrInvalidMeshHeader
		}
		hopsLeft = data[1]
		source = binary.BigEndian.Uint16(data[2:4])
		dest = binary.BigEndian.Uint16(data[4:6])
		headerLen = meshHeaderDeepHopsLen
	} else {
		hopsLeft = dispatch & MeshHopsLeftMask
		source = binary.BigEndian.Uint16(data[1:3])
		dest = binary.BigEndian.Uint16(data[3:5])
		headerLen = meshHeaderMinLen
	}

	return source, dest, hopsLeft, headerLen, nil
}
