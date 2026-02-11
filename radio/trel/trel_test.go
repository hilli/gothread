// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package trel

import (
	"testing"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/radio"
)

// --------------------------------------------------------------------------
// Mock platform
// --------------------------------------------------------------------------

type mockPlatform struct {
	enabled       bool
	port          uint16
	sendCalls     []sendCall
	registerCalls []registerCall
	enableErr     error
	disableErr    error
	sendErr       error
}

type sendCall struct {
	data []byte
	dest ip6.SockAddr
}

type registerCall struct {
	port    uint16
	txtData []byte
}

func newMockPlatform(port uint16) *mockPlatform {
	return &mockPlatform{port: port}
}

func (m *mockPlatform) Enable() (uint16, error) {
	if m.enableErr != nil {
		return 0, m.enableErr
	}
	m.enabled = true
	return m.port, nil
}

func (m *mockPlatform) Disable() error {
	m.enabled = false
	return m.disableErr
}

func (m *mockPlatform) Send(packet []byte, dest ip6.SockAddr) error {
	cp := make([]byte, len(packet))
	copy(cp, packet)
	m.sendCalls = append(m.sendCalls, sendCall{data: cp, dest: dest})
	return m.sendErr
}

func (m *mockPlatform) RegisterService(port uint16, txtData []byte) error {
	m.registerCalls = append(m.registerCalls, registerCall{port: port, txtData: txtData})
	return nil
}

// --------------------------------------------------------------------------
// Mock callbacks
// --------------------------------------------------------------------------

type mockCallbacks struct {
	receiveDoneCalls  []receiveDoneCall
	transmitDoneCalls []transmitDoneCall
}

type receiveDoneCall struct {
	frame *radio.Frame
	err   error
}

type transmitDoneCall struct {
	frame    *radio.Frame
	ackFrame *radio.Frame
	err      error
}

func (m *mockCallbacks) HandleReceiveDone(frame *radio.Frame, err error) {
	m.receiveDoneCalls = append(m.receiveDoneCalls, receiveDoneCall{frame: frame, err: err})
}

func (m *mockCallbacks) HandleTransmitStarted(frame *radio.Frame) {}

func (m *mockCallbacks) HandleTransmitDone(frame *radio.Frame, ackFrame *radio.Frame, err error) {
	m.transmitDoneCalls = append(m.transmitDoneCalls, transmitDoneCall{frame: frame, ackFrame: ackFrame, err: err})
}

func (m *mockCallbacks) HandleEnergyScanDone(maxRSSI int8) {}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func makeExtAddr(b byte) types.ExtAddress {
	return types.ExtAddress{b, b, b, b, b, b, b, b}
}

func makeSockAddr(lastByte byte, port uint16) ip6.SockAddr {
	var addr ip6.Address
	addr[15] = lastByte
	return ip6.SockAddr{Address: addr, Port: port}
}

// ============================================================================
// Packet tests
// ============================================================================

func TestHeaderInitAndFields(t *testing.T) {
	buf := make([]byte, MaxHeaderSize)
	h := NewHeader(buf)

	h.Init(TypeBroadcast)
	if h.GetType() != TypeBroadcast {
		t.Errorf("expected TypeBroadcast, got %v", h.GetType())
	}
	if !h.IsVersionValid() {
		t.Error("version should be valid after Init")
	}
	if h.GetLength() != HeaderSizeBroadcast {
		t.Errorf("expected broadcast header size %d, got %d", HeaderSizeBroadcast, h.GetLength())
	}

	h.SetChannel(15)
	if h.GetChannel() != 15 {
		t.Errorf("expected channel 15, got %d", h.GetChannel())
	}

	h.SetPanID(0xABCD)
	if h.GetPanID() != 0xABCD {
		t.Errorf("expected panid 0xABCD, got 0x%04x", h.GetPanID())
	}

	h.SetPacketNumber(42)
	if h.GetPacketNumber() != 42 {
		t.Errorf("expected packet number 42, got %d", h.GetPacketNumber())
	}

	src := makeExtAddr(0x11)
	h.SetSource(src)
	if h.GetSource() != src {
		t.Errorf("source mismatch")
	}

	h.SetAckMode(AckModeRequested)
	if h.GetAckMode() != AckModeRequested {
		t.Error("expected AckModeRequested")
	}
	h.SetAckMode(AckModeNoAck)
	if h.GetAckMode() != AckModeNoAck {
		t.Error("expected AckModeNoAck")
	}
}

func TestHeaderUnicastDestination(t *testing.T) {
	buf := make([]byte, MaxHeaderSize)
	h := NewHeader(buf)
	h.Init(TypeUnicast)

	if h.GetLength() != HeaderSizeUnicast {
		t.Errorf("expected unicast header size %d, got %d", HeaderSizeUnicast, h.GetLength())
	}

	dst := makeExtAddr(0x22)
	h.SetDestination(dst)
	if h.GetDestination() != dst {
		t.Error("destination mismatch")
	}
}

func TestHeaderAckType(t *testing.T) {
	buf := make([]byte, MaxHeaderSize)
	h := NewHeader(buf)
	h.Init(TypeAck)

	if h.GetType() != TypeAck {
		t.Errorf("expected TypeAck, got %v", h.GetType())
	}
	if h.GetLength() != HeaderSizeAck {
		t.Errorf("expected ack header size %d, got %d", HeaderSizeAck, h.GetLength())
	}
}

func TestHeaderSizeFunction(t *testing.T) {
	if HeaderSize(TypeBroadcast) != 16 {
		t.Error("broadcast header size should be 16")
	}
	if HeaderSize(TypeUnicast) != 24 {
		t.Error("unicast header size should be 24")
	}
	if HeaderSize(TypeAck) != 24 {
		t.Error("ack header size should be 24")
	}
}

func TestTypeString(t *testing.T) {
	tests := []struct {
		t    Type
		want string
	}{
		{TypeBroadcast, "broadcast"},
		{TypeUnicast, "unicast"},
		{TypeAck, "ack"},
		{Type(99), "unknown"},
	}
	for _, tc := range tests {
		if got := tc.t.String(); got != tc.want {
			t.Errorf("Type(%d).String() = %q, want %q", tc.t, got, tc.want)
		}
	}
}

func TestPacketValid(t *testing.T) {
	// Valid broadcast packet with 4-byte payload.
	buf := make([]byte, HeaderSizeBroadcast+4)
	h := NewHeader(buf)
	h.Init(TypeBroadcast)
	buf[HeaderSizeBroadcast] = 0xDE
	buf[HeaderSizeBroadcast+1] = 0xAD
	buf[HeaderSizeBroadcast+2] = 0xBE
	buf[HeaderSizeBroadcast+3] = 0xEF

	pkt := NewPacket(buf)
	if !pkt.IsHeaderValid() {
		t.Error("packet should be valid")
	}
	if pkt.GetLength() != HeaderSizeBroadcast+4 {
		t.Errorf("expected length %d, got %d", HeaderSizeBroadcast+4, pkt.GetLength())
	}
	if pkt.GetPayloadLength() != 4 {
		t.Errorf("expected payload length 4, got %d", pkt.GetPayloadLength())
	}
	payload := pkt.GetPayload()
	if payload[0] != 0xDE || payload[3] != 0xEF {
		t.Error("payload content mismatch")
	}
}

func TestPacketInvalid(t *testing.T) {
	// Empty buffer.
	pkt := NewPacket(nil)
	if pkt.IsHeaderValid() {
		t.Error("nil buffer should be invalid")
	}

	pkt = NewPacket([]byte{})
	if pkt.IsHeaderValid() {
		t.Error("empty buffer should be invalid")
	}

	// Buffer too short for broadcast header.
	buf := make([]byte, 4)
	buf[0] = 0 // TypeBroadcast, version 0
	pkt = NewPacket(buf)
	if pkt.IsHeaderValid() {
		t.Error("truncated buffer should be invalid")
	}

	// Bad version.
	buf = make([]byte, HeaderSizeBroadcast)
	buf[0] = 0xE0 // version = 7, type = 0
	pkt = NewPacket(buf)
	if pkt.IsHeaderValid() {
		t.Error("bad version should be invalid")
	}
}

func TestPacketHeaderOnly(t *testing.T) {
	buf := make([]byte, HeaderSizeBroadcast)
	NewHeader(buf).Init(TypeBroadcast)
	pkt := NewPacket(buf)
	if !pkt.IsHeaderValid() {
		t.Error("header-only packet should be valid")
	}
	if pkt.GetPayloadLength() != 0 {
		t.Errorf("expected 0 payload, got %d", pkt.GetPayloadLength())
	}
	if pkt.GetPayload() != nil {
		t.Error("expected nil payload")
	}
}

func TestMarshalHeader(t *testing.T) {
	src := makeExtAddr(0xAA)
	dst := makeExtAddr(0xBB)

	// Broadcast — no destination.
	buf := make([]byte, MaxHeaderSize)
	n, err := MarshalHeader(buf, TypeBroadcast, AckModeNoAck, 11, 0x1234, 100, src, nil)
	if err != nil {
		t.Fatalf("MarshalHeader broadcast: %v", err)
	}
	if n != int(HeaderSizeBroadcast) {
		t.Errorf("expected %d bytes, got %d", HeaderSizeBroadcast, n)
	}
	h := NewHeader(buf)
	if h.GetType() != TypeBroadcast {
		t.Error("type mismatch")
	}
	if h.GetChannel() != 11 {
		t.Error("channel mismatch")
	}
	if h.GetPanID() != 0x1234 {
		t.Error("panid mismatch")
	}
	if h.GetPacketNumber() != 100 {
		t.Error("packet number mismatch")
	}
	if h.GetSource() != src {
		t.Error("source mismatch")
	}

	// Unicast with destination.
	buf2 := make([]byte, MaxHeaderSize)
	n2, err2 := MarshalHeader(buf2, TypeUnicast, AckModeRequested, 15, 0x5678, 200, src, &dst)
	if err2 != nil {
		t.Fatalf("MarshalHeader unicast: %v", err2)
	}
	if n2 != int(HeaderSizeUnicast) {
		t.Errorf("expected %d bytes, got %d", HeaderSizeUnicast, n2)
	}
	h2 := NewHeader(buf2)
	if h2.GetDestination() != dst {
		t.Error("destination mismatch")
	}
	if h2.GetAckMode() != AckModeRequested {
		t.Error("ack mode mismatch")
	}
}

func TestMarshalHeaderBufferTooSmall(t *testing.T) {
	buf := make([]byte, 4)
	_, err := MarshalHeader(buf, TypeBroadcast, AckModeNoAck, 11, 0, 0, types.ExtAddress{}, nil)
	if err == nil {
		t.Error("expected error for small buffer")
	}
}

func TestHeaderToString(t *testing.T) {
	buf := make([]byte, MaxHeaderSize)
	h := NewHeader(buf)
	h.Init(TypeBroadcast)
	h.SetChannel(11)
	h.SetAckMode(AckModeNoAck)
	s := h.ToString()
	if s == "" {
		t.Error("ToString should not be empty")
	}
	// Verify it contains expected substrings.
	if !contains(s, "broadcast") {
		t.Errorf("ToString %q should contain 'broadcast'", s)
	}
	if !contains(s, "no-ack") {
		t.Errorf("ToString %q should contain 'no-ack'", s)
	}
}

func TestInitFromPayload(t *testing.T) {
	// Simulate a buffer with header space reserved before payload.
	payload := []byte{0x01, 0x02, 0x03}
	hdrSize := int(HeaderSizeBroadcast)
	fullBuf := make([]byte, hdrSize+len(payload))
	copy(fullBuf[hdrSize:], payload)

	pkt := InitFromPayload(TypeBroadcast, fullBuf, hdrSize, uint16(len(payload)))
	if !pkt.IsHeaderValid() {
		t.Error("packet should be valid")
	}
	if pkt.GetPayloadLength() != 3 {
		t.Errorf("expected payload length 3, got %d", pkt.GetPayloadLength())
	}
	got := pkt.GetPayload()
	if got[0] != 0x01 || got[1] != 0x02 || got[2] != 0x03 {
		t.Error("payload content mismatch")
	}
}

// ============================================================================
// Peer tests
// ============================================================================

func TestPeerHasValidSockAddr(t *testing.T) {
	p := &Peer{ExtAddress: makeExtAddr(0x01)}
	if p.HasValidSockAddr() {
		t.Error("zero sockaddr should not be valid")
	}
	p.SockAddr = makeSockAddr(1, 12345)
	if !p.HasValidSockAddr() {
		t.Error("non-zero sockaddr should be valid")
	}
}

func TestPeerLastActivity(t *testing.T) {
	p := &Peer{}
	if p.SecondsSinceLastActivity() != 0 {
		t.Error("zero time should return 0 seconds")
	}
	p.UpdateLastActivity()
	secs := p.SecondsSinceLastActivity()
	if secs > 1 {
		t.Errorf("just updated, expected <=1 sec, got %d", secs)
	}
}

func TestPeerStateString(t *testing.T) {
	tests := []struct {
		s    PeerState
		want string
	}{
		{PeerStateResolved, "resolved"},
		{PeerStateRemoved, "removed"},
		{PeerStateResolving, "resolving"},
		{PeerState(99), "unknown"},
	}
	for _, tc := range tests {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("PeerState(%d).String() = %q, want %q", tc.s, got, tc.want)
		}
	}
}

// ============================================================================
// PeerTable tests
// ============================================================================

func TestPeerTableAddAndFind(t *testing.T) {
	pt := NewPeerTable()
	if pt.GetSize() != 0 {
		t.Error("new table should be empty")
	}

	addr1 := makeExtAddr(0x01)
	sock1 := makeSockAddr(1, 1000)
	p := pt.Add(addr1, sock1)
	if p == nil {
		t.Fatal("Add returned nil")
	}
	if pt.GetSize() != 1 {
		t.Errorf("expected size 1, got %d", pt.GetSize())
	}
	if p.ExtAddress != addr1 {
		t.Error("ext address mismatch")
	}
	if !p.SockAddr.Equal(sock1) {
		t.Error("sock addr mismatch")
	}
	if p.State != PeerStateResolved {
		t.Error("state should be Resolved")
	}

	// Find by ext address.
	found := pt.FindByExtAddress(addr1)
	if found == nil {
		t.Fatal("FindByExtAddress returned nil")
	}
	if found.ExtAddress != addr1 {
		t.Error("found wrong peer by ext address")
	}

	// Find by sock addr.
	found2 := pt.FindBySockAddr(sock1)
	if found2 == nil {
		t.Fatal("FindBySockAddr returned nil")
	}

	// Not found.
	if pt.FindByExtAddress(makeExtAddr(0xFF)) != nil {
		t.Error("should not find non-existent peer")
	}
}

func TestPeerTableUpsert(t *testing.T) {
	pt := NewPeerTable()
	addr := makeExtAddr(0x01)
	sock1 := makeSockAddr(1, 1000)
	sock2 := makeSockAddr(2, 2000)

	pt.Add(addr, sock1)
	pt.Add(addr, sock2) // upsert
	if pt.GetSize() != 1 {
		t.Errorf("upsert should not increase size, got %d", pt.GetSize())
	}
	p := pt.FindByExtAddress(addr)
	if !p.SockAddr.Equal(sock2) {
		t.Error("upsert should update sock addr")
	}
}

func TestPeerTableRemove(t *testing.T) {
	pt := NewPeerTable()
	addr1 := makeExtAddr(0x01)
	addr2 := makeExtAddr(0x02)
	addr3 := makeExtAddr(0x03)
	sock := makeSockAddr(1, 1000)

	pt.Add(addr1, sock)
	pt.Add(addr2, sock)
	pt.Add(addr3, sock)

	if !pt.Remove(addr2) {
		t.Error("Remove should return true")
	}
	if pt.GetSize() != 2 {
		t.Errorf("expected size 2, got %d", pt.GetSize())
	}
	if pt.FindByExtAddress(addr2) != nil {
		t.Error("removed peer should not be found")
	}
	// addr1 and addr3 should still exist.
	if pt.FindByExtAddress(addr1) == nil {
		t.Error("addr1 should still exist")
	}
	if pt.FindByExtAddress(addr3) == nil {
		t.Error("addr3 should still exist")
	}

	// Remove non-existent.
	if pt.Remove(makeExtAddr(0xFF)) {
		t.Error("removing non-existent should return false")
	}
}

func TestPeerTableIterator(t *testing.T) {
	pt := NewPeerTable()
	for i := byte(1); i <= 5; i++ {
		pt.Add(makeExtAddr(i), makeSockAddr(i, 1000+uint16(i)))
	}

	it := pt.GetIterator()
	count := 0
	for {
		p := it.Next()
		if p == nil {
			break
		}
		count++
	}
	if count != 5 {
		t.Errorf("expected 5 iterations, got %d", count)
	}
}

func TestPeerTableGetPeers(t *testing.T) {
	pt := NewPeerTable()
	pt.Add(makeExtAddr(0x01), makeSockAddr(1, 1000))
	pt.Add(makeExtAddr(0x02), makeSockAddr(2, 2000))

	peers := pt.GetPeers()
	if len(peers) != 2 {
		t.Errorf("expected 2 peers, got %d", len(peers))
	}
	// Modifying the copy should not affect the table.
	peers[0].ExtAddress = makeExtAddr(0xFF)
	if pt.FindByExtAddress(makeExtAddr(0x01)) == nil {
		t.Error("modifying copy should not affect table")
	}
}

// ============================================================================
// Interface tests
// ============================================================================

func TestInterfaceInitAndEnable(t *testing.T) {
	mp := newMockPlatform(9000)
	iface := NewInterface(mp)

	if iface.IsEnabled() {
		t.Error("should not be enabled before Init")
	}

	iface.Init()

	// User is enabled by default; stack is not. So still disabled.
	if iface.IsEnabled() {
		t.Error("should not be enabled with only user enabled")
	}

	iface.SetEnabled(true, RequesterStack)
	if !iface.IsEnabled() {
		t.Error("should be enabled with both user and stack enabled")
	}
	if !mp.enabled {
		t.Error("platform should be enabled")
	}
	if iface.GetUDPPort() != 9000 {
		t.Errorf("expected port 9000, got %d", iface.GetUDPPort())
	}
}

func TestInterfaceDualEnable(t *testing.T) {
	mp := newMockPlatform(9000)
	iface := NewInterface(mp)
	iface.Init()

	// Enable stack.
	iface.SetEnabled(true, RequesterStack)
	if !iface.IsEnabled() {
		t.Error("should be enabled")
	}

	// Disable user — should disable.
	iface.SetEnabled(false, RequesterUser)
	if iface.IsEnabled() {
		t.Error("should be disabled when user disables")
	}

	// Re-enable user — should enable again.
	iface.SetEnabled(true, RequesterUser)
	if !iface.IsEnabled() {
		t.Error("should be re-enabled")
	}

	// Disable stack — should disable.
	iface.SetEnabled(false, RequesterStack)
	if iface.IsEnabled() {
		t.Error("should be disabled when stack disables")
	}
}

func TestInterfaceFilter(t *testing.T) {
	mp := newMockPlatform(9000)
	iface := NewInterface(mp)
	iface.Init()
	iface.SetEnabled(true, RequesterStack)

	iface.SetFilterEnabled(true)
	if !iface.IsFilterEnabled() {
		t.Error("filter should be enabled")
	}

	// Send should succeed silently (drop).
	buf := make([]byte, HeaderSizeBroadcast)
	NewHeader(buf).Init(TypeBroadcast)
	pkt := NewPacket(buf)
	err := iface.Send(pkt, NewPeerTable())
	if err != nil {
		t.Errorf("filtered send should return nil, got %v", err)
	}
	if len(mp.sendCalls) != 0 {
		t.Error("filtered send should not call platform.Send")
	}

	iface.SetFilterEnabled(false)
	if iface.IsFilterEnabled() {
		t.Error("filter should be disabled")
	}
}

func TestInterfaceSendBroadcast(t *testing.T) {
	mp := newMockPlatform(9000)
	iface := NewInterface(mp)
	iface.Init()
	iface.SetEnabled(true, RequesterStack)

	pt := NewPeerTable()
	pt.Add(makeExtAddr(0x01), makeSockAddr(1, 1000))
	pt.Add(makeExtAddr(0x02), makeSockAddr(2, 2000))

	buf := make([]byte, HeaderSizeBroadcast+2)
	h := NewHeader(buf)
	h.Init(TypeBroadcast)
	buf[HeaderSizeBroadcast] = 0xAA
	buf[HeaderSizeBroadcast+1] = 0xBB
	pkt := NewPacket(buf)

	err := iface.Send(pkt, pt)
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if len(mp.sendCalls) != 2 {
		t.Errorf("expected 2 send calls for 2 peers, got %d", len(mp.sendCalls))
	}
}

func TestInterfaceSendUnicast(t *testing.T) {
	mp := newMockPlatform(9000)
	iface := NewInterface(mp)
	iface.Init()
	iface.SetEnabled(true, RequesterStack)

	destAddr := makeExtAddr(0x02)
	pt := NewPeerTable()
	pt.Add(destAddr, makeSockAddr(2, 2000))

	buf := make([]byte, HeaderSizeUnicast+2)
	h := NewHeader(buf)
	h.Init(TypeUnicast)
	h.SetDestination(destAddr)
	buf[HeaderSizeUnicast] = 0xCC
	pkt := NewPacket(buf)

	err := iface.Send(pkt, pt)
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if len(mp.sendCalls) != 1 {
		t.Errorf("expected 1 send call, got %d", len(mp.sendCalls))
	}
}

func TestInterfaceSendUnicastPeerNotFound(t *testing.T) {
	mp := newMockPlatform(9000)
	iface := NewInterface(mp)
	iface.Init()
	iface.SetEnabled(true, RequesterStack)

	buf := make([]byte, HeaderSizeUnicast)
	h := NewHeader(buf)
	h.Init(TypeUnicast)
	h.SetDestination(makeExtAddr(0xFF))
	pkt := NewPacket(buf)

	err := iface.Send(pkt, NewPeerTable())
	if err == nil {
		t.Error("expected error when peer not found")
	}
}

func TestInterfaceSendDisabled(t *testing.T) {
	mp := newMockPlatform(9000)
	iface := NewInterface(mp)
	iface.Init()
	// Don't enable stack — interface stays disabled.

	buf := make([]byte, HeaderSizeBroadcast)
	NewHeader(buf).Init(TypeBroadcast)
	pkt := NewPacket(buf)

	err := iface.Send(pkt, NewPeerTable())
	if err == nil {
		t.Error("expected error when interface disabled")
	}
}

func TestInterfaceHandleReceived(t *testing.T) {
	mp := newMockPlatform(9000)
	iface := NewInterface(mp)
	iface.Init()
	iface.SetEnabled(true, RequesterStack)

	var received []Packet
	iface.SetRxCallback(func(pkt Packet, addr ip6.SockAddr) {
		received = append(received, pkt)
	})

	buf := make([]byte, HeaderSizeBroadcast+4)
	NewHeader(buf).Init(TypeBroadcast)
	iface.HandleReceived(buf, makeSockAddr(1, 1000))

	if len(received) != 1 {
		t.Errorf("expected 1 received packet, got %d", len(received))
	}
}

func TestInterfaceHandleReceivedFiltered(t *testing.T) {
	mp := newMockPlatform(9000)
	iface := NewInterface(mp)
	iface.Init()
	iface.SetEnabled(true, RequesterStack)
	iface.SetFilterEnabled(true)

	var received []Packet
	iface.SetRxCallback(func(pkt Packet, addr ip6.SockAddr) {
		received = append(received, pkt)
	})

	buf := make([]byte, HeaderSizeBroadcast)
	NewHeader(buf).Init(TypeBroadcast)
	iface.HandleReceived(buf, makeSockAddr(1, 1000))

	if len(received) != 0 {
		t.Error("filtered rx should not deliver packets")
	}
}

// ============================================================================
// Link tests
// ============================================================================

func newTestLink() (*Link, *mockPlatform, *mockCallbacks) {
	mp := newMockPlatform(9000)
	cb := &mockCallbacks{}
	l := NewLink(mp, cb)
	return l, mp, cb
}

func TestLinkInitialState(t *testing.T) {
	l, _, _ := newTestLink()
	if l.GetState() != radio.StateDisabled {
		t.Errorf("expected StateDisabled, got %v", l.GetState())
	}
}

func TestLinkEnable(t *testing.T) {
	l, mp, _ := newTestLink()

	err := l.Enable()
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if l.GetState() != radio.StateSleep {
		t.Errorf("expected StateSleep after Enable, got %v", l.GetState())
	}
	if !mp.enabled {
		t.Error("platform should be enabled")
	}

	// Double enable should fail.
	err = l.Enable()
	if err == nil {
		t.Error("expected error on double Enable")
	}
}

func TestLinkDisable(t *testing.T) {
	l, mp, _ := newTestLink()
	l.Enable()

	err := l.Disable()
	if err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if l.GetState() != radio.StateDisabled {
		t.Errorf("expected StateDisabled, got %v", l.GetState())
	}
	if mp.enabled {
		t.Error("platform should be disabled")
	}

	// Disable when already disabled is a no-op.
	err = l.Disable()
	if err != nil {
		t.Fatalf("Disable no-op: %v", err)
	}
}

func TestLinkSleep(t *testing.T) {
	l, _, _ := newTestLink()

	// Sleep while disabled should fail.
	err := l.Sleep()
	if err == nil {
		t.Error("expected error when sleeping in disabled state")
	}

	l.Enable()
	l.Receive(11)
	if l.GetState() != radio.StateReceive {
		t.Error("should be in Receive state")
	}

	err = l.Sleep()
	if err != nil {
		t.Fatalf("Sleep: %v", err)
	}
	if l.GetState() != radio.StateSleep {
		t.Errorf("expected StateSleep, got %v", l.GetState())
	}

	// Sleep while already sleeping is ok.
	err = l.Sleep()
	if err != nil {
		t.Fatalf("Sleep no-op: %v", err)
	}
}

func TestLinkReceive(t *testing.T) {
	l, _, _ := newTestLink()

	// Receive while disabled should fail.
	err := l.Receive(11)
	if err == nil {
		t.Error("expected error when receiving in disabled state")
	}

	l.Enable()
	err = l.Receive(15)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if l.GetState() != radio.StateReceive {
		t.Errorf("expected StateReceive, got %v", l.GetState())
	}
}

func TestLinkSendBroadcast(t *testing.T) {
	l, mp, cb := newTestLink()
	l.Enable()
	l.Receive(11)
	l.SetExtAddress(makeExtAddr(0xAA))
	l.SetPanID(0x1234)

	// Add peers.
	l.GetPeerTable().Add(makeExtAddr(0x01), makeSockAddr(1, 1000))
	l.GetPeerTable().Add(makeExtAddr(0x02), makeSockAddr(2, 2000))

	payload := []byte{0xDE, 0xAD}
	err := l.Send(payload, nil)
	if err != nil {
		t.Fatalf("Send broadcast: %v", err)
	}

	// Should have sent to 2 peers.
	if len(mp.sendCalls) != 2 {
		t.Errorf("expected 2 platform sends, got %d", len(mp.sendCalls))
	}

	// Callback should have been called.
	if len(cb.transmitDoneCalls) != 1 {
		t.Errorf("expected 1 transmitDone callback, got %d", len(cb.transmitDoneCalls))
	}
	if cb.transmitDoneCalls[0].err != nil {
		t.Error("transmitDone should report success")
	}

	// Check counters.
	c := l.GetCounters()
	if c.TxPackets != 1 {
		t.Errorf("expected TxPackets=1, got %d", c.TxPackets)
	}
	if c.TxBytes == 0 {
		t.Error("TxBytes should be > 0")
	}
	if c.TxFailures != 0 {
		t.Errorf("expected 0 failures, got %d", c.TxFailures)
	}

	// State should return to Receive.
	if l.GetState() != radio.StateReceive {
		t.Errorf("expected StateReceive after send, got %v", l.GetState())
	}
}

func TestLinkSendUnicast(t *testing.T) {
	l, mp, cb := newTestLink()
	l.Enable()
	l.Receive(11)
	l.SetExtAddress(makeExtAddr(0xAA))
	l.SetPanID(0x1234)

	dest := makeExtAddr(0x01)
	l.GetPeerTable().Add(dest, makeSockAddr(1, 1000))

	payload := []byte{0xBE, 0xEF}
	err := l.Send(payload, &dest)
	if err != nil {
		t.Fatalf("Send unicast: %v", err)
	}

	if len(mp.sendCalls) != 1 {
		t.Errorf("expected 1 platform send, got %d", len(mp.sendCalls))
	}

	// Verify the sent packet has correct header fields.
	sentData := mp.sendCalls[0].data
	pkt := NewPacket(sentData)
	if !pkt.IsHeaderValid() {
		t.Fatal("sent packet should have valid header")
	}
	h := pkt.GetHeader()
	if h.GetType() != TypeUnicast {
		t.Errorf("expected TypeUnicast, got %v", h.GetType())
	}
	if h.GetAckMode() != AckModeRequested {
		t.Error("unicast should have AckModeRequested")
	}
	if h.GetChannel() != 11 {
		t.Errorf("expected channel 11, got %d", h.GetChannel())
	}
	if h.GetPanID() != 0x1234 {
		t.Errorf("expected panid 0x1234, got 0x%04x", h.GetPanID())
	}
	if h.GetSource() != makeExtAddr(0xAA) {
		t.Error("source mismatch")
	}
	if h.GetDestination() != dest {
		t.Error("destination mismatch")
	}

	if len(cb.transmitDoneCalls) != 1 || cb.transmitDoneCalls[0].err != nil {
		t.Error("callback should indicate success")
	}
}

func TestLinkSendDisabled(t *testing.T) {
	l, _, _ := newTestLink()
	err := l.Send([]byte{0x01}, nil)
	if err == nil {
		t.Error("expected error when sending in disabled state")
	}
}

func TestLinkSendUnicastPeerNotFound(t *testing.T) {
	l, _, cb := newTestLink()
	l.Enable()
	l.Receive(11)
	l.SetExtAddress(makeExtAddr(0xAA))
	l.SetPanID(0x1234)

	dest := makeExtAddr(0xFF) // not in peer table
	err := l.Send([]byte{0x01}, &dest)
	if err == nil {
		t.Error("expected error when peer not found")
	}

	c := l.GetCounters()
	if c.TxFailures != 1 {
		t.Errorf("expected 1 tx failure, got %d", c.TxFailures)
	}

	if len(cb.transmitDoneCalls) != 1 || cb.transmitDoneCalls[0].err == nil {
		t.Error("callback should indicate failure")
	}
}

func TestLinkReceivePacket(t *testing.T) {
	l, _, cb := newTestLink()
	l.Enable()
	l.Receive(11)
	l.SetExtAddress(makeExtAddr(0xAA))
	l.SetPanID(0x1234)
	l.SetChannel(11)

	// Build a broadcast packet from a "remote" source.
	src := makeExtAddr(0x01)
	payload := []byte{0xCA, 0xFE}
	hdrSize := int(HeaderSizeBroadcast)
	buf := make([]byte, hdrSize+len(payload))
	MarshalHeader(buf, TypeBroadcast, AckModeNoAck, 11, 0x1234, 1, src, nil)
	copy(buf[hdrSize:], payload)

	senderSock := makeSockAddr(1, 1000)
	l.ProcessReceivedPacket(buf, senderSock)

	// Should have delivered to callbacks.
	if len(cb.receiveDoneCalls) != 1 {
		t.Fatalf("expected 1 receiveDone call, got %d", len(cb.receiveDoneCalls))
	}
	frame := cb.receiveDoneCalls[0].frame
	if frame == nil {
		t.Fatal("received frame should not be nil")
	}
	if len(frame.PSDU) != 2 || frame.PSDU[0] != 0xCA || frame.PSDU[1] != 0xFE {
		t.Error("received payload mismatch")
	}

	// Sender should be added to peer table.
	peer := l.GetPeerTable().FindByExtAddress(src)
	if peer == nil {
		t.Error("sender should be in peer table")
	}

	// Check counters.
	c := l.GetCounters()
	if c.RxPackets != 1 {
		t.Errorf("expected RxPackets=1, got %d", c.RxPackets)
	}
	if c.RxBytes == 0 {
		t.Error("RxBytes should be > 0")
	}
}

func TestLinkReceiveUnicastWithAck(t *testing.T) {
	l, mp, cb := newTestLink()
	l.Enable()
	l.Receive(11)
	localAddr := makeExtAddr(0xAA)
	l.SetExtAddress(localAddr)
	l.SetPanID(0x1234)
	l.SetChannel(11)

	// Add the sender as a peer so ack can be sent.
	src := makeExtAddr(0x01)
	senderSock := makeSockAddr(1, 1000)
	l.GetPeerTable().Add(src, senderSock)

	// Build a unicast packet addressed to us with ack requested.
	payload := []byte{0x42}
	hdrSize := int(HeaderSizeUnicast)
	buf := make([]byte, hdrSize+len(payload))
	MarshalHeader(buf, TypeUnicast, AckModeRequested, 11, 0x1234, 77, src, &localAddr)
	copy(buf[hdrSize:], payload)

	l.ProcessReceivedPacket(buf, senderSock)

	// Should have delivered data.
	if len(cb.receiveDoneCalls) != 1 {
		t.Fatalf("expected 1 receiveDone call, got %d", len(cb.receiveDoneCalls))
	}

	// Should have sent an ack back.
	if len(mp.sendCalls) != 1 {
		t.Fatalf("expected 1 ack send, got %d", len(mp.sendCalls))
	}
	ackData := mp.sendCalls[0].data
	ackPkt := NewPacket(ackData)
	if !ackPkt.IsHeaderValid() {
		t.Fatal("ack packet should be valid")
	}
	ackH := ackPkt.GetHeader()
	if ackH.GetType() != TypeAck {
		t.Errorf("expected TypeAck, got %v", ackH.GetType())
	}
	if ackH.GetDestination() != src {
		t.Error("ack destination should be the original source")
	}
	if ackH.GetSource() != localAddr {
		t.Error("ack source should be our address")
	}
	if ackH.GetPacketNumber() != 77 {
		t.Errorf("ack packet number should match original (77), got %d", ackH.GetPacketNumber())
	}
}

func TestLinkReceiveFilteredByChannel(t *testing.T) {
	l, _, cb := newTestLink()
	l.Enable()
	l.Receive(11)
	l.SetExtAddress(makeExtAddr(0xAA))
	l.SetPanID(0x1234)
	l.SetChannel(11)

	// Packet on wrong channel.
	buf := make([]byte, HeaderSizeBroadcast+2)
	MarshalHeader(buf, TypeBroadcast, AckModeNoAck, 15, 0x1234, 1, makeExtAddr(0x01), nil) // channel 15
	l.ProcessReceivedPacket(buf, makeSockAddr(1, 1000))

	if len(cb.receiveDoneCalls) != 0 {
		t.Error("packet on wrong channel should be filtered")
	}
}

func TestLinkReceiveFilteredByPanID(t *testing.T) {
	l, _, cb := newTestLink()
	l.Enable()
	l.Receive(11)
	l.SetExtAddress(makeExtAddr(0xAA))
	l.SetPanID(0x1234)
	l.SetChannel(11)

	// Packet with wrong PAN ID.
	buf := make([]byte, HeaderSizeBroadcast+2)
	MarshalHeader(buf, TypeBroadcast, AckModeNoAck, 11, 0xFFFF, 1, makeExtAddr(0x01), nil) // wrong panid
	l.ProcessReceivedPacket(buf, makeSockAddr(1, 1000))

	if len(cb.receiveDoneCalls) != 0 {
		t.Error("packet with wrong PAN ID should be filtered")
	}
}

func TestLinkReceiveFilteredOwnPacket(t *testing.T) {
	l, _, cb := newTestLink()
	l.Enable()
	l.Receive(11)
	local := makeExtAddr(0xAA)
	l.SetExtAddress(local)
	l.SetPanID(0x1234)
	l.SetChannel(11)

	// Packet from ourselves.
	buf := make([]byte, HeaderSizeBroadcast+2)
	MarshalHeader(buf, TypeBroadcast, AckModeNoAck, 11, 0x1234, 1, local, nil) // our own address
	l.ProcessReceivedPacket(buf, makeSockAddr(1, 1000))

	if len(cb.receiveDoneCalls) != 0 {
		t.Error("own packet should be filtered")
	}
}

func TestLinkReceiveUnicastNotForUs(t *testing.T) {
	l, _, cb := newTestLink()
	l.Enable()
	l.Receive(11)
	l.SetExtAddress(makeExtAddr(0xAA))
	l.SetPanID(0x1234)
	l.SetChannel(11)

	// Unicast addressed to someone else.
	otherDest := makeExtAddr(0xBB)
	buf := make([]byte, HeaderSizeUnicast+2)
	MarshalHeader(buf, TypeUnicast, AckModeNoAck, 11, 0x1234, 1, makeExtAddr(0x01), &otherDest)
	l.ProcessReceivedPacket(buf, makeSockAddr(1, 1000))

	if len(cb.receiveDoneCalls) != 0 {
		t.Error("unicast to other destination should be filtered")
	}
}

func TestLinkCountersReset(t *testing.T) {
	l, _, _ := newTestLink()
	l.Enable()
	l.Receive(11)
	l.SetExtAddress(makeExtAddr(0xAA))
	l.SetPanID(0x1234)

	l.GetPeerTable().Add(makeExtAddr(0x01), makeSockAddr(1, 1000))
	l.Send([]byte{0x01}, nil)

	c := l.GetCounters()
	if c.TxPackets == 0 {
		t.Error("should have tx packets")
	}

	l.ResetCounters()
	c = l.GetCounters()
	if c.TxPackets != 0 || c.RxPackets != 0 || c.TxBytes != 0 || c.RxBytes != 0 || c.TxFailures != 0 {
		t.Error("counters should be zeroed after reset")
	}
}

func TestLinkGetTransmitBuffer(t *testing.T) {
	l, _, _ := newTestLink()
	buf := l.GetTransmitBuffer()
	if buf == nil {
		t.Fatal("transmit buffer should not be nil")
	}
	if len(buf.PSDU) != radio.FrameMaxSize {
		t.Errorf("expected PSDU size %d, got %d", radio.FrameMaxSize, len(buf.PSDU))
	}
}

func TestLinkPacketNumberIncrement(t *testing.T) {
	l, mp, _ := newTestLink()
	l.Enable()
	l.Receive(11)
	l.SetExtAddress(makeExtAddr(0xAA))
	l.SetPanID(0x1234)

	l.GetPeerTable().Add(makeExtAddr(0x01), makeSockAddr(1, 1000))

	// Send two broadcast packets and verify packet numbers increment.
	l.Send([]byte{0x01}, nil)
	l.Send([]byte{0x02}, nil)

	if len(mp.sendCalls) < 2 {
		t.Fatal("expected at least 2 send calls")
	}

	pkt1 := NewPacket(mp.sendCalls[0].data)
	pkt2 := NewPacket(mp.sendCalls[1].data)

	num1 := pkt1.GetHeader().GetPacketNumber()
	num2 := pkt2.GetHeader().GetPacketNumber()
	if num2 != num1+1 {
		t.Errorf("packet numbers should increment: got %d and %d", num1, num2)
	}
}

func TestLinkNilCallbacks(t *testing.T) {
	mp := newMockPlatform(9000)
	l := NewLink(mp, nil) // nil callbacks
	l.Enable()
	l.Receive(11)
	l.SetExtAddress(makeExtAddr(0xAA))
	l.SetPanID(0x1234)

	l.GetPeerTable().Add(makeExtAddr(0x01), makeSockAddr(1, 1000))

	// Should not panic with nil callbacks.
	err := l.Send([]byte{0x01}, nil)
	if err != nil {
		t.Fatalf("Send with nil callbacks: %v", err)
	}

	// Receive should also not panic.
	buf := make([]byte, HeaderSizeBroadcast+2)
	MarshalHeader(buf, TypeBroadcast, AckModeNoAck, 11, 0x1234, 1, makeExtAddr(0x01), nil)
	l.ProcessReceivedPacket(buf, makeSockAddr(1, 1000))
}

// ============================================================================
// Helpers
// ============================================================================

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
