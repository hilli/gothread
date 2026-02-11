// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the
//    names of its contributors may be used to endorse or promote products
//    derived from this software without specific prior written permission.
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

package mdns

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Mock Platform
// ---------------------------------------------------------------------------

type sentPacket struct {
	data    []byte
	dst     net.IP
	dstPort uint16
	unicast bool
}

type mockPlatform struct {
	mu       sync.Mutex
	packets  []sentPacket
	callback func(data []byte, src net.IP, srcPort uint16)
}

func newMockPlatform() *mockPlatform {
	return &mockPlatform{}
}

func (m *mockPlatform) SendMulticast(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	m.packets = append(m.packets, sentPacket{data: cp})
	return nil
}

func (m *mockPlatform) SendUnicast(data []byte, dst net.IP, port uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	m.packets = append(m.packets, sentPacket{data: cp, dst: dst, dstPort: port, unicast: true})
	return nil
}

func (m *mockPlatform) SetReceiveCallback(cb func(data []byte, src net.IP, srcPort uint16)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callback = cb
}

func (m *mockPlatform) getPackets() []sentPacket {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]sentPacket, len(m.packets))
	copy(out, m.packets)
	return out
}

func (m *mockPlatform) clearPackets() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.packets = m.packets[:0]
}

func (m *mockPlatform) inject(data []byte, src net.IP, srcPort uint16) {
	m.mu.Lock()
	cb := m.callback
	m.mu.Unlock()
	if cb != nil {
		cb(data, src, srcPort)
	}
}

// helper to create a new Core with a mock platform.
func newTestCore() (*Core, *mockPlatform) {
	mp := newMockPlatform()
	c := NewCore(mp, Config{HostName: "testhost"})
	return c, mp
}

// ---------------------------------------------------------------------------
// DNS wire-format tests
// ---------------------------------------------------------------------------

func TestEncodeName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr bool
	}{
		{"root", ".", []byte{0}, false},
		{"empty", "", []byte{0}, false},
		{"simple", "local", []byte{5, 'l', 'o', 'c', 'a', 'l', 0}, false},
		{"dotted", "myhost.local", []byte{6, 'm', 'y', 'h', 'o', 's', 't', 5, 'l', 'o', 'c', 'a', 'l', 0}, false},
		{"trailing dot", "myhost.local.", []byte{6, 'm', 'y', 'h', 'o', 's', 't', 5, 'l', 'o', 'c', 'a', 'l', 0}, false},
		{"empty label", "my..host", nil, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := encodeName(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("encodeName(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestDecodeName(t *testing.T) {
	// Simple name.
	wire := []byte{6, 'm', 'y', 'h', 'o', 's', 't', 5, 'l', 'o', 'c', 'a', 'l', 0}
	name, consumed, err := decodeName(wire, 0)
	if err != nil {
		t.Fatalf("decodeName error: %v", err)
	}
	if name != "myhost.local" {
		t.Fatalf("got %q, want %q", name, "myhost.local")
	}
	if consumed != len(wire) {
		t.Fatalf("consumed %d, want %d", consumed, len(wire))
	}
}

func TestDecodeNamePointer(t *testing.T) {
	// Build a message with a name at offset 0, then a pointer to it.
	var buf []byte
	// Offset 0: "local" => 5 'l' 'o' 'c' 'a' 'l' 0  (7 bytes)
	buf = append(buf, 5, 'l', 'o', 'c', 'a', 'l', 0)
	// Offset 7: "myhost" label + pointer to offset 0.
	buf = append(buf, 6, 'm', 'y', 'h', 'o', 's', 't', 0xC0, 0x00)

	name, consumed, err := decodeName(buf, 7)
	if err != nil {
		t.Fatalf("decodeName error: %v", err)
	}
	if name != "myhost.local" {
		t.Fatalf("got %q, want %q", name, "myhost.local")
	}
	// consumed should be 8 (label "myhost" = 7 bytes + 2-byte pointer = 9,
	// but consumed at original position, which is label(7) + pointer(2) = 9 - 7 offset... no:
	// pos starts at 7, label consumes 7 bytes (length byte + "myhost"), pointer consumes 2 bytes.
	// consumed = pos_before_break - offset = (7+7+2) - 7 ... Wait, let's trace:
	// pos=7 -> length=6 (not pointer, not zero) -> pos=8, read 6 bytes "myhost", pos=14
	// pos=14 -> data[14]=0xC0 -> pointer, jumped=false so consumed = 14 - 7 + 2 = 9
	if consumed != 9 {
		t.Fatalf("consumed %d, want 9", consumed)
	}
}

func TestDecodeNamePointerLoop(t *testing.T) {
	// Two pointers that loop to each other: ptr@0->2, ptr@2->0.
	buf := []byte{0xC0, 0x02, 0xC0, 0x00}
	_, _, err := decodeName(buf, 0)
	if err == nil {
		t.Fatal("expected error for pointer loop, got nil")
	}
}

func TestDecodeNameTruncated(t *testing.T) {
	// Label says 10 bytes but data is shorter.
	buf := []byte{10, 'a', 'b'}
	_, _, err := decodeName(buf, 0)
	if err == nil {
		t.Fatal("expected truncated error")
	}
}

func TestCompressorNameCompression(t *testing.T) {
	c := newCompressor()
	var buf []byte
	var err error

	// First name: "myhost.local"
	buf, err = c.appendName(buf, "myhost.local")
	if err != nil {
		t.Fatalf("appendName error: %v", err)
	}

	// Second name: "other.local" — "local" should be compressed via pointer.
	startLen := len(buf)
	buf, err = c.appendName(buf, "other.local")
	if err != nil {
		t.Fatalf("appendName error: %v", err)
	}

	secondLen := len(buf) - startLen
	// Without compression: 1+5+"local"+0 = 13 bytes.
	// With compression: 1+5+"other" + 2-byte pointer = 8 bytes.
	if secondLen >= 13 {
		t.Fatalf("expected compression, second name took %d bytes (no compression would be 13)", secondLen)
	}

	// Verify both names decode correctly.
	name1, consumed1, err := decodeName(buf, 0)
	if err != nil {
		t.Fatalf("decodeName 1 error: %v", err)
	}
	if name1 != "myhost.local" {
		t.Fatalf("got %q, want %q", name1, "myhost.local")
	}

	name2, _, err := decodeName(buf, consumed1)
	if err != nil {
		t.Fatalf("decodeName 2 error: %v", err)
	}
	if name2 != "other.local" {
		t.Fatalf("got %q, want %q", name2, "other.local")
	}
}

func TestMsgHeaderMarshalUnmarshal(t *testing.T) {
	h := msgHeader{
		ID:      0x1234,
		QDCount: 1,
		ANCount: 2,
		NSCount: 3,
		ARCount: 4,
	}
	h.setResponse()
	h.setAA()

	data := h.marshal()
	if len(data) != headerSize {
		t.Fatalf("marshal length %d, want %d", len(data), headerSize)
	}

	h2, ok := unmarshalHeader(data)
	if !ok {
		t.Fatal("unmarshalHeader failed")
	}
	if h2.ID != 0x1234 {
		t.Fatalf("ID = %x, want 0x1234", h2.ID)
	}
	if !h2.isResponse() {
		t.Fatal("expected response flag")
	}
	if h2.QDCount != 1 || h2.ANCount != 2 || h2.NSCount != 3 || h2.ARCount != 4 {
		t.Fatalf("counts mismatch: QD=%d AN=%d NS=%d AR=%d", h2.QDCount, h2.ANCount, h2.NSCount, h2.ARCount)
	}
}

func TestUnmarshalHeaderTooShort(t *testing.T) {
	_, ok := unmarshalHeader([]byte{0, 1, 2})
	if ok {
		t.Fatal("expected failure for short data")
	}
}

func TestBuildAndParseSRVRData(t *testing.T) {
	rdata, err := buildSRVRData(10, 20, 8080, "myhost.local")
	if err != nil {
		t.Fatalf("buildSRVRData error: %v", err)
	}

	priority, weight, port, target, err := parseSRVRData(rdata)
	if err != nil {
		t.Fatalf("parseSRVRData error: %v", err)
	}
	if priority != 10 || weight != 20 || port != 8080 {
		t.Fatalf("SRV fields: priority=%d weight=%d port=%d", priority, weight, port)
	}
	if target != "myhost.local" {
		t.Fatalf("target = %q, want %q", target, "myhost.local")
	}
}

func TestBuildAndParsePTRRData(t *testing.T) {
	rdata, err := buildPTRRData("My Service._http._tcp.local")
	if err != nil {
		t.Fatalf("buildPTRRData error: %v", err)
	}
	name, err := parsePTRRData(rdata)
	if err != nil {
		t.Fatalf("parsePTRRData error: %v", err)
	}
	if name != "My Service._http._tcp.local" {
		t.Fatalf("got %q, want %q", name, "My Service._http._tcp.local")
	}
}

func TestBuildAAAARData(t *testing.T) {
	ip := net.ParseIP("fe80::1")
	rdata := buildAAAARData(ip)
	if len(rdata) != 16 {
		t.Fatalf("AAAA RDATA length = %d, want 16", len(rdata))
	}
	if rdata == nil {
		t.Fatal("expected non-nil RDATA")
	}
}

func TestBuildAAAARDataTooShort(t *testing.T) {
	rdata := buildAAAARData([]byte{1, 2, 3})
	if rdata != nil {
		t.Fatal("expected nil for short IP")
	}
}

func TestBuildARData(t *testing.T) {
	ip := net.IPv4(192, 168, 1, 1).To4()
	rdata := buildARData(ip)
	if len(rdata) != 4 {
		t.Fatalf("A RDATA length = %d, want 4", len(rdata))
	}
}

func TestBuildTXTRData(t *testing.T) {
	// Non-empty.
	data := []byte{4, 'k', '=', 'v', 'a'}
	rdata := buildTXTRData(data)
	if !bytes.Equal(rdata, data) {
		t.Fatalf("TXT RDATA mismatch")
	}

	// Empty — should produce single zero-length string.
	rdata = buildTXTRData(nil)
	if !bytes.Equal(rdata, []byte{0}) {
		t.Fatalf("empty TXT RDATA = %v, want [0]", rdata)
	}
}

func TestBuildKeyRData(t *testing.T) {
	key := []byte{1, 2, 3, 4, 5}
	rdata := buildKeyRData(key)
	if !bytes.Equal(rdata, key) {
		t.Fatal("key RDATA mismatch")
	}
	// Verify it's a copy.
	key[0] = 0xFF
	if rdata[0] == 0xFF {
		t.Fatal("key RDATA should be a copy")
	}
}

func TestBuildNSECRData(t *testing.T) {
	rdata, err := buildNSECRData("myhost.local", []uint16{TypeAAAA, TypeKey})
	if err != nil {
		t.Fatalf("buildNSECRData error: %v", err)
	}
	if len(rdata) == 0 {
		t.Fatal("expected non-empty NSEC RDATA")
	}
	// Verify it starts with the encoded owner name.
	name, _, err := decodeName(rdata, 0)
	if err != nil {
		t.Fatalf("decodeName in NSEC error: %v", err)
	}
	if name != "myhost.local" {
		t.Fatalf("NSEC owner = %q, want %q", name, "myhost.local")
	}
}

func TestParseSRVRDataTruncated(t *testing.T) {
	_, _, _, _, err := parseSRVRData([]byte{0, 0, 0, 0})
	if err == nil {
		t.Fatal("expected error for truncated SRV RDATA")
	}
}

// ---------------------------------------------------------------------------
// Message builder / parser round-trip tests
// ---------------------------------------------------------------------------

func TestMessageBuilderRoundTrip(t *testing.T) {
	mb := newMessageBuilder(0)
	mb.setResponse()

	if err := mb.addQuestion("myhost.local", TypeAAAA, ClassInternet); err != nil {
		t.Fatalf("addQuestion error: %v", err)
	}

	rdata := buildAAAARData(net.ParseIP("fe80::1"))
	if err := mb.addAnswer("myhost.local", TypeAAAA, ClassInternet|CacheFlushFlag, 120, rdata); err != nil {
		t.Fatalf("addAnswer error: %v", err)
	}

	srvData, _ := buildSRVRData(0, 0, 80, "myhost.local")
	if err := mb.addAuthority("web._http._tcp.local", TypeSRV, ClassInternet, 4500, srvData); err != nil {
		t.Fatalf("addAuthority error: %v", err)
	}

	if err := mb.addAdditional("_http._tcp.local", TypeTXT, ClassInternet, 4500, buildTXTRData(nil)); err != nil {
		t.Fatalf("addAdditional error: %v", err)
	}

	data := mb.build()
	msg, err := parseMessage(data)
	if err != nil {
		t.Fatalf("parseMessage error: %v", err)
	}

	if !msg.Header.isResponse() {
		t.Fatal("expected response")
	}
	if len(msg.Questions) != 1 {
		t.Fatalf("questions = %d, want 1", len(msg.Questions))
	}
	if msg.Questions[0].Name != "myhost.local" {
		t.Fatalf("question name = %q", msg.Questions[0].Name)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(msg.Answers))
	}
	if msg.Answers[0].Type != TypeAAAA {
		t.Fatalf("answer type = %d, want %d", msg.Answers[0].Type, TypeAAAA)
	}
	if len(msg.Authorities) != 1 {
		t.Fatalf("authorities = %d, want 1", len(msg.Authorities))
	}
	if len(msg.Additionals) != 1 {
		t.Fatalf("additionals = %d, want 1", len(msg.Additionals))
	}
}

func TestMessageBuilderEmpty(t *testing.T) {
	mb := newMessageBuilder(0)
	if !mb.isEmpty() {
		t.Fatal("new builder should be empty")
	}
	if mb.totalRecords() != 0 {
		t.Fatalf("totalRecords = %d, want 0", mb.totalRecords())
	}
}

func TestMessageBuilderMaxSize(t *testing.T) {
	// Very small max size: only room for header + one question.
	mb := newMessageBuilder(headerSize + 20)
	if err := mb.addQuestion("a.local", TypeA, ClassInternet); err != nil {
		t.Fatalf("first addQuestion error: %v", err)
	}
	// Second question should fail.
	err := mb.addAnswer("b.local", TypeA, ClassInternet, 120, []byte{1, 2, 3, 4})
	if err != errNoSpace {
		t.Fatalf("expected errNoSpace, got %v", err)
	}
}

func TestParseMessageTruncated(t *testing.T) {
	_, err := parseMessage([]byte{0, 1, 2})
	if err == nil {
		t.Fatal("expected error for truncated message")
	}
}

func TestParseMessageBadQuestionCount(t *testing.T) {
	var h msgHeader
	h.QDCount = 1
	data := h.marshal() // No question data follows.
	_, err := parseMessage(data)
	if err == nil {
		t.Fatal("expected error for missing question data")
	}
}

// ---------------------------------------------------------------------------
// Cache tests
// ---------------------------------------------------------------------------

func TestCacheAddLookup(t *testing.T) {
	c := NewCache()
	now := time.Now()

	c.Add(CacheEntry{
		Name:        "myhost.local",
		Type:        TypeAAAA,
		Class:       ClassInternet,
		TTL:         120,
		RData:       net.ParseIP("fe80::1").To16(),
		ReceiveTime: now,
	})

	if c.Len() != 1 {
		t.Fatalf("Len = %d, want 1", c.Len())
	}

	results := c.Lookup("myhost.local", TypeAAAA, now)
	if len(results) != 1 {
		t.Fatalf("Lookup returned %d, want 1", len(results))
	}
	if results[0].TTL != 120 {
		t.Fatalf("TTL = %d, want 120", results[0].TTL)
	}
}

func TestCacheLookupCaseInsensitive(t *testing.T) {
	c := NewCache()
	now := time.Now()
	c.Add(CacheEntry{
		Name:        "MyHost.Local",
		Type:        TypeAAAA,
		Class:       ClassInternet,
		TTL:         120,
		RData:       net.ParseIP("fe80::1").To16(),
		ReceiveTime: now,
	})

	results := c.Lookup("myhost.local", TypeAAAA, now)
	if len(results) != 1 {
		t.Fatalf("case-insensitive lookup returned %d, want 1", len(results))
	}
}

func TestCacheLookupTypeANY(t *testing.T) {
	c := NewCache()
	now := time.Now()
	c.Add(CacheEntry{Name: "x.local", Type: TypeAAAA, Class: ClassInternet, TTL: 60, RData: make([]byte, 16), ReceiveTime: now})
	c.Add(CacheEntry{Name: "x.local", Type: TypeTXT, Class: ClassInternet, TTL: 60, RData: []byte{0}, ReceiveTime: now})

	results := c.Lookup("x.local", TypeANY, now)
	if len(results) != 2 {
		t.Fatalf("TypeANY lookup returned %d, want 2", len(results))
	}
}

func TestCacheLookupAll(t *testing.T) {
	c := NewCache()
	now := time.Now()
	c.Add(CacheEntry{Name: "x.local", Type: TypeAAAA, Class: ClassInternet, TTL: 60, RData: make([]byte, 16), ReceiveTime: now})
	c.Add(CacheEntry{Name: "x.local", Type: TypeTXT, Class: ClassInternet, TTL: 60, RData: []byte{0}, ReceiveTime: now})

	results := c.LookupAll("x.local", now)
	if len(results) != 2 {
		t.Fatalf("LookupAll returned %d, want 2", len(results))
	}
}

func TestCacheExpiry(t *testing.T) {
	c := NewCache()
	past := time.Now().Add(-200 * time.Second)

	c.Add(CacheEntry{
		Name:        "old.local",
		Type:        TypeAAAA,
		Class:       ClassInternet,
		TTL:         60,
		RData:       make([]byte, 16),
		ReceiveTime: past,
	})

	now := time.Now()
	results := c.Lookup("old.local", TypeAAAA, now)
	if len(results) != 0 {
		t.Fatalf("expired entry should not be returned, got %d", len(results))
	}

	removed := c.Expire(now)
	if removed != 1 {
		t.Fatalf("Expire removed %d, want 1", removed)
	}
	if c.Len() != 0 {
		t.Fatalf("Len after expire = %d, want 0", c.Len())
	}
}

func TestCacheGoodbye(t *testing.T) {
	c := NewCache()
	now := time.Now()
	rdata := net.ParseIP("fe80::1").To16()

	c.Add(CacheEntry{Name: "host.local", Type: TypeAAAA, Class: ClassInternet, TTL: 120, RData: rdata, ReceiveTime: now})
	if c.Len() != 1 {
		t.Fatalf("Len = %d after add, want 1", c.Len())
	}

	// Goodbye: TTL=0 with same rdata removes it.
	c.Add(CacheEntry{Name: "host.local", Type: TypeAAAA, Class: ClassInternet, TTL: 0, RData: rdata, ReceiveTime: now})
	if c.Len() != 0 {
		t.Fatalf("Len = %d after goodbye, want 0", c.Len())
	}
}

func TestCacheGoodbyeNonExistent(t *testing.T) {
	c := NewCache()
	now := time.Now()
	// Goodbye for a record that doesn't exist should be a no-op.
	c.Add(CacheEntry{Name: "nope.local", Type: TypeAAAA, Class: ClassInternet, TTL: 0, RData: make([]byte, 16), ReceiveTime: now})
	if c.Len() != 0 {
		t.Fatalf("Len = %d, want 0", c.Len())
	}
}

func TestCacheHasEntry(t *testing.T) {
	c := NewCache()
	now := time.Now()
	rdata := net.ParseIP("fe80::2").To16()

	c.Add(CacheEntry{Name: "h.local", Type: TypeAAAA, Class: ClassInternet, TTL: 120, RData: rdata, ReceiveTime: now})

	if !c.HasEntry("h.local", TypeAAAA, rdata, now) {
		t.Fatal("HasEntry should return true")
	}
	if c.HasEntry("h.local", TypeAAAA, []byte{0}, now) {
		t.Fatal("HasEntry should return false for different rdata")
	}
	if c.HasEntry("h.local", TypeA, rdata, now) {
		t.Fatal("HasEntry should return false for different type")
	}
}

func TestCacheUpdate(t *testing.T) {
	c := NewCache()
	now := time.Now()
	rdata := net.ParseIP("fe80::1").To16()

	c.Add(CacheEntry{Name: "h.local", Type: TypeAAAA, Class: ClassInternet, TTL: 60, RData: rdata, ReceiveTime: now})
	// Update with same name+type+rdata but new TTL.
	c.Add(CacheEntry{Name: "h.local", Type: TypeAAAA, Class: ClassInternet, TTL: 240, RData: rdata, ReceiveTime: now})

	if c.Len() != 1 {
		t.Fatalf("Len = %d after update, want 1", c.Len())
	}

	results := c.Lookup("h.local", TypeAAAA, now)
	if len(results) != 1 || results[0].TTL != 240 {
		t.Fatalf("updated TTL = %d, want 240", results[0].TTL)
	}
}

func TestCacheClear(t *testing.T) {
	c := NewCache()
	now := time.Now()
	c.Add(CacheEntry{Name: "a.local", Type: TypeA, Class: ClassInternet, TTL: 60, RData: []byte{1, 2, 3, 4}, ReceiveTime: now})
	c.Add(CacheEntry{Name: "b.local", Type: TypeA, Class: ClassInternet, TTL: 60, RData: []byte{5, 6, 7, 8}, ReceiveTime: now})
	c.Clear()
	if c.Len() != 0 {
		t.Fatalf("Len after Clear = %d, want 0", c.Len())
	}
}

func TestCacheEntryRemainingTTL(t *testing.T) {
	now := time.Now()
	e := CacheEntry{TTL: 120, ReceiveTime: now.Add(-30 * time.Second)}
	remaining := e.RemainingTTL(now)
	if remaining != 90 {
		t.Fatalf("RemainingTTL = %d, want 90", remaining)
	}

	e2 := CacheEntry{TTL: 10, ReceiveTime: now.Add(-20 * time.Second)}
	if e2.RemainingTTL(now) != 0 {
		t.Fatal("expired entry should have RemainingTTL 0")
	}
}

func TestCacheEntryIsExpired(t *testing.T) {
	now := time.Now()

	// TTL=0 is always expired.
	e := CacheEntry{TTL: 0, ReceiveTime: now}
	if !e.IsExpired(now) {
		t.Fatal("TTL=0 should be expired")
	}

	// Not expired.
	e2 := CacheEntry{TTL: 120, ReceiveTime: now}
	if e2.IsExpired(now) {
		t.Fatal("should not be expired yet")
	}

	// Expired.
	e3 := CacheEntry{TTL: 10, ReceiveTime: now.Add(-11 * time.Second)}
	if !e3.IsExpired(now) {
		t.Fatal("should be expired")
	}
}

// ---------------------------------------------------------------------------
// Core creation and state tests
// ---------------------------------------------------------------------------

func TestNewCoreEnabled(t *testing.T) {
	core, _ := newTestCore()
	if !core.IsEnabled() {
		t.Fatal("new core should be enabled")
	}
}

func TestSetEnabled(t *testing.T) {
	core, _ := newTestCore()
	core.SetEnabled(false)
	if core.IsEnabled() {
		t.Fatal("should be disabled")
	}
	core.SetEnabled(true)
	if !core.IsEnabled() {
		t.Fatal("should be enabled")
	}
}

func TestRegisterHostDisabled(t *testing.T) {
	core, _ := newTestCore()
	core.SetEnabled(false)
	err := core.RegisterHost(HostInfo{Name: "h"})
	if err != errNotEnabled {
		t.Fatalf("expected errNotEnabled, got %v", err)
	}
}

func TestRegisterHostEmptyName(t *testing.T) {
	core, _ := newTestCore()
	err := core.RegisterHost(HostInfo{Name: ""})
	if err != errInvalidArgs {
		t.Fatalf("expected errInvalidArgs, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Host registration: probing -> registered state machine
// ---------------------------------------------------------------------------

func TestHostProbing(t *testing.T) {
	core, mp := newTestCore()

	ip := net.ParseIP("fe80::1")
	err := core.RegisterHost(HostInfo{Name: "myhost", Addresses: []net.IP{ip}})
	if err != nil {
		t.Fatalf("RegisterHost error: %v", err)
	}

	state, ok := core.GetHostState("myhost")
	if !ok || state != StateProbing {
		t.Fatalf("state = %v (%v), want probing", state, ok)
	}

	now := time.Now()

	// Process: should send first probe.
	core.Process(now)
	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected at least one probe packet")
	}

	// Verify probe is a query with authority.
	msg, err := parseMessage(packets[0].data)
	if err != nil {
		t.Fatalf("parseMessage error: %v", err)
	}
	if !msg.Header.isQuery() {
		t.Fatal("probe should be a query")
	}
	if len(msg.Questions) < 1 {
		t.Fatal("probe should have at least one question")
	}
	if len(msg.Authorities) < 1 {
		t.Fatal("probe should have authority records")
	}
}

func TestHostProbingToRegistered(t *testing.T) {
	core, mp := newTestCore()

	ip := net.ParseIP("fe80::1")
	err := core.RegisterHost(HostInfo{Name: "myhost", Addresses: []net.IP{ip}})
	if err != nil {
		t.Fatalf("RegisterHost error: %v", err)
	}

	now := time.Now()

	// Drive through 3 probes.
	for i := 0; i < probeCount; i++ {
		core.Process(now)
		now = now.Add(probeInterval + time.Millisecond)
	}

	// One more Process should transition to registered and send first announcement.
	mp.clearPackets()
	core.Process(now)

	state, ok := core.GetHostState("myhost")
	if !ok || state != StateRegistered {
		t.Fatalf("state = %v (%v), want registered", state, ok)
	}

	// Verify announcement is a response with AAAA records.
	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected announcement packet")
	}
	msg, err := parseMessage(packets[0].data)
	if err != nil {
		t.Fatalf("parseMessage error: %v", err)
	}
	if !msg.Header.isResponse() {
		t.Fatal("announcement should be a response")
	}
	if len(msg.Answers) < 1 {
		t.Fatal("announcement should have answers")
	}
	if msg.Answers[0].Type != TypeAAAA {
		t.Fatalf("answer type = %d, want AAAA (%d)", msg.Answers[0].Type, TypeAAAA)
	}
}

func TestHostAnnouncementCount(t *testing.T) {
	core, mp := newTestCore()
	ip := net.ParseIP("fe80::1")
	_ = core.RegisterHost(HostInfo{Name: "myhost", Addresses: []net.IP{ip}})

	now := time.Now()
	// Drive through probing.
	for i := 0; i < probeCount; i++ {
		core.Process(now)
		now = now.Add(probeInterval + time.Millisecond)
	}

	// Count announcement packets.
	mp.clearPackets()
	for i := 0; i < announceCount+2; i++ {
		core.Process(now)
		now = now.Add(announceInterval + time.Millisecond)
	}

	packets := mp.getPackets()
	// Should get exactly announceCount announcements (no more).
	announcements := 0
	for _, p := range packets {
		msg, err := parseMessage(p.data)
		if err != nil {
			continue
		}
		if msg.Header.isResponse() {
			announcements++
		}
	}
	if announcements != announceCount {
		t.Fatalf("got %d announcements, want %d", announcements, announceCount)
	}
}

// ---------------------------------------------------------------------------
// Host unregister and goodbye
// ---------------------------------------------------------------------------

func TestHostUnregisterGoodbye(t *testing.T) {
	core, mp := newTestCore()
	ip := net.ParseIP("fe80::1")
	_ = core.RegisterHost(HostInfo{Name: "myhost", Addresses: []net.IP{ip}})

	// Fast-forward to registered.
	now := time.Now()
	for i := 0; i < probeCount; i++ {
		core.Process(now)
		now = now.Add(probeInterval + time.Millisecond)
	}
	core.Process(now)
	now = now.Add(announceInterval + time.Millisecond)
	core.Process(now)
	now = now.Add(announceInterval + time.Millisecond)
	core.Process(now)

	mp.clearPackets()

	err := core.UnregisterHost("myhost")
	if err != nil {
		t.Fatalf("UnregisterHost error: %v", err)
	}

	// Should have sent goodbye (TTL=0).
	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected goodbye packet")
	}
	msg, err := parseMessage(packets[0].data)
	if err != nil {
		t.Fatalf("parseMessage error: %v", err)
	}
	for _, ans := range msg.Answers {
		if ans.TTL != 0 {
			t.Fatalf("goodbye TTL = %d, want 0", ans.TTL)
		}
	}

	// Host should be gone.
	_, ok := core.GetHostState("myhost")
	if ok {
		t.Fatal("host should not exist after unregister")
	}
}

func TestUnregisterHostNotRegistered(t *testing.T) {
	core, _ := newTestCore()
	err := core.UnregisterHost("nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Service registration
// ---------------------------------------------------------------------------

func TestRegisterServiceProbing(t *testing.T) {
	core, mp := newTestCore()

	err := core.RegisterService(ServiceInfo{
		ServiceType:  "_http._tcp",
		InstanceName: "Web Server",
		HostName:     "myhost",
		Port:         80,
	})
	if err != nil {
		t.Fatalf("RegisterService error: %v", err)
	}

	state, ok := core.GetServiceState("_http._tcp", "Web Server")
	if !ok || state != StateProbing {
		t.Fatalf("state = %v (%v), want probing", state, ok)
	}

	now := time.Now()
	core.Process(now)

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected probe packet")
	}

	msg, err := parseMessage(packets[0].data)
	if err != nil {
		t.Fatalf("parseMessage error: %v", err)
	}
	if !msg.Header.isQuery() {
		t.Fatal("service probe should be a query")
	}
}

func TestRegisterServiceToRegistered(t *testing.T) {
	core, mp := newTestCore()

	_ = core.RegisterService(ServiceInfo{
		ServiceType:  "_http._tcp",
		InstanceName: "Web",
		HostName:     "myhost",
		Port:         80,
		SubTypes:     []string{"_printer"},
		TxtData:      []byte{5, 'h', 'e', 'l', 'l', 'o'},
	})

	now := time.Now()
	for i := 0; i < probeCount; i++ {
		core.Process(now)
		now = now.Add(probeInterval + time.Millisecond)
	}

	mp.clearPackets()
	core.Process(now)

	state, ok := core.GetServiceState("_http._tcp", "Web")
	if !ok || state != StateRegistered {
		t.Fatalf("state = %v (%v), want registered", state, ok)
	}

	// Verify announcement contains PTR, SRV, TXT, sub-type PTR, and _services PTR.
	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected announcement")
	}
	msg, err := parseMessage(packets[0].data)
	if err != nil {
		t.Fatalf("parseMessage error: %v", err)
	}

	foundPTR, foundSRV, foundTXT := false, false, false
	for _, ans := range msg.Answers {
		switch ans.Type {
		case TypePTR:
			foundPTR = true
		case TypeSRV:
			foundSRV = true
		case TypeTXT:
			foundTXT = true
		}
	}
	if !foundPTR {
		t.Fatal("announcement missing PTR")
	}
	if !foundSRV {
		t.Fatal("announcement missing SRV")
	}
	if !foundTXT {
		t.Fatal("announcement missing TXT")
	}
}

func TestRegisterServiceInvalidArgs(t *testing.T) {
	core, _ := newTestCore()
	err := core.RegisterService(ServiceInfo{ServiceType: "", InstanceName: "x"})
	if err != errInvalidArgs {
		t.Fatalf("expected errInvalidArgs, got %v", err)
	}
	err = core.RegisterService(ServiceInfo{ServiceType: "_tcp", InstanceName: ""})
	if err != errInvalidArgs {
		t.Fatalf("expected errInvalidArgs, got %v", err)
	}
}

func TestUnregisterServiceGoodbye(t *testing.T) {
	core, mp := newTestCore()

	_ = core.RegisterService(ServiceInfo{
		ServiceType:  "_http._tcp",
		InstanceName: "Web",
		HostName:     "myhost",
		Port:         80,
	})

	// Fast-forward to registered.
	now := time.Now()
	for i := 0; i < probeCount; i++ {
		core.Process(now)
		now = now.Add(probeInterval + time.Millisecond)
	}
	for i := 0; i < announceCount+1; i++ {
		core.Process(now)
		now = now.Add(announceInterval + time.Millisecond)
	}

	mp.clearPackets()
	err := core.UnregisterService("_http._tcp", "Web")
	if err != nil {
		t.Fatalf("UnregisterService error: %v", err)
	}

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected goodbye packet")
	}
	msg, err := parseMessage(packets[0].data)
	if err != nil {
		t.Fatalf("parseMessage error: %v", err)
	}
	for _, ans := range msg.Answers {
		if ans.TTL != 0 {
			t.Fatalf("goodbye TTL = %d, want 0", ans.TTL)
		}
	}
}

// ---------------------------------------------------------------------------
// Key registration
// ---------------------------------------------------------------------------

func TestRegisterKeyProbing(t *testing.T) {
	core, mp := newTestCore()

	err := core.RegisterKey(KeyRecord{Name: "myhost", KeyData: []byte{1, 2, 3, 4}})
	if err != nil {
		t.Fatalf("RegisterKey error: %v", err)
	}

	now := time.Now()
	core.Process(now)

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected probe packet for key")
	}
	msg, err := parseMessage(packets[0].data)
	if err != nil {
		t.Fatalf("parseMessage error: %v", err)
	}
	if !msg.Header.isQuery() {
		t.Fatal("key probe should be a query")
	}
	if len(msg.Authorities) < 1 {
		t.Fatal("key probe should have authority")
	}
	if msg.Authorities[0].Type != TypeKey {
		t.Fatalf("authority type = %d, want KEY (%d)", msg.Authorities[0].Type, TypeKey)
	}
}

func TestRegisterKeyToRegistered(t *testing.T) {
	core, mp := newTestCore()
	_ = core.RegisterKey(KeyRecord{Name: "myhost", KeyData: []byte{1, 2, 3, 4}})

	now := time.Now()
	for i := 0; i < probeCount; i++ {
		core.Process(now)
		now = now.Add(probeInterval + time.Millisecond)
	}
	mp.clearPackets()
	core.Process(now)

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected key announcement")
	}
	msg, err := parseMessage(packets[0].data)
	if err != nil {
		t.Fatalf("parseMessage error: %v", err)
	}
	if !msg.Header.isResponse() {
		t.Fatal("key announcement should be response")
	}
	foundKey := false
	for _, ans := range msg.Answers {
		if ans.Type == TypeKey {
			foundKey = true
		}
	}
	if !foundKey {
		t.Fatal("announcement missing KEY record")
	}
}

func TestRegisterKeyInvalidArgs(t *testing.T) {
	core, _ := newTestCore()
	err := core.RegisterKey(KeyRecord{Name: "", KeyData: []byte{1}})
	if err != errInvalidArgs {
		t.Fatalf("expected errInvalidArgs for empty name, got %v", err)
	}
	err = core.RegisterKey(KeyRecord{Name: "x", KeyData: nil})
	if err != errInvalidArgs {
		t.Fatalf("expected errInvalidArgs for empty key, got %v", err)
	}
}

func TestRegisterServiceKey(t *testing.T) {
	core, _ := newTestCore()
	err := core.RegisterKey(KeyRecord{
		Name:        "Web",
		ServiceType: "_http._tcp",
		KeyData:     []byte{1, 2, 3},
	})
	if err != nil {
		t.Fatalf("RegisterKey (service) error: %v", err)
	}
}

func TestUnregisterKey(t *testing.T) {
	core, mp := newTestCore()
	_ = core.RegisterKey(KeyRecord{Name: "myhost", KeyData: []byte{1, 2, 3}})

	// Fast-forward to registered.
	now := time.Now()
	for i := 0; i < probeCount; i++ {
		core.Process(now)
		now = now.Add(probeInterval + time.Millisecond)
	}
	for i := 0; i < announceCount+1; i++ {
		core.Process(now)
		now = now.Add(announceInterval + time.Millisecond)
	}

	mp.clearPackets()
	err := core.UnregisterKey("myhost")
	if err != nil {
		t.Fatalf("UnregisterKey error: %v", err)
	}

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected goodbye for key")
	}
	msg, err := parseMessage(packets[0].data)
	if err != nil {
		t.Fatalf("parseMessage error: %v", err)
	}
	for _, ans := range msg.Answers {
		if ans.TTL != 0 {
			t.Fatalf("goodbye TTL = %d, want 0", ans.TTL)
		}
	}
}

// ---------------------------------------------------------------------------
// Query response generation
// ---------------------------------------------------------------------------

func registerAndAdvance(t *testing.T, core *Core, mp *mockPlatform) time.Time {
	t.Helper()
	now := time.Now()
	for i := 0; i < probeCount; i++ {
		core.Process(now)
		now = now.Add(probeInterval + time.Millisecond)
	}
	for i := 0; i < announceCount+1; i++ {
		core.Process(now)
		now = now.Add(announceInterval + time.Millisecond)
	}
	mp.clearPackets()
	return now
}

func buildQuery(name string, qtype uint16) []byte {
	mb := newMessageBuilder(0)
	_ = mb.addQuestion(name, qtype, ClassInternet)
	return mb.build()
}

func TestQueryResponseHost(t *testing.T) {
	core, mp := newTestCore()
	ip := net.ParseIP("fe80::1")
	_ = core.RegisterHost(HostInfo{Name: "myhost", Addresses: []net.IP{ip}})
	registerAndAdvance(t, core, mp)

	// Inject a query for myhost.local AAAA.
	query := buildQuery("myhost.local", TypeAAAA)
	mp.inject(query, net.ParseIP("fe80::99"), 5353)

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected response to query")
	}
	msg, err := parseMessage(packets[0].data)
	if err != nil {
		t.Fatalf("parseMessage error: %v", err)
	}
	if !msg.Header.isResponse() {
		t.Fatal("expected response")
	}
	foundAAAA := false
	for _, ans := range msg.Answers {
		if ans.Type == TypeAAAA && strings.EqualFold(ans.Name, "myhost.local") {
			foundAAAA = true
		}
	}
	if !foundAAAA {
		t.Fatal("response missing AAAA for myhost.local")
	}
}

func TestQueryResponseService(t *testing.T) {
	core, mp := newTestCore()
	_ = core.RegisterService(ServiceInfo{
		ServiceType:  "_http._tcp",
		InstanceName: "Web",
		HostName:     "myhost",
		Port:         80,
		TxtData:      []byte{5, 'h', 'e', 'l', 'l', 'o'},
	})
	registerAndAdvance(t, core, mp)

	// Query for PTR.
	query := buildQuery("_http._tcp.local", TypePTR)
	mp.inject(query, net.ParseIP("fe80::99"), 5353)

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected response to PTR query")
	}
	msg, err := parseMessage(packets[0].data)
	if err != nil {
		t.Fatalf("parseMessage error: %v", err)
	}
	foundPTR := false
	for _, ans := range msg.Answers {
		if ans.Type == TypePTR {
			foundPTR = true
		}
	}
	if !foundPTR {
		t.Fatal("response missing PTR")
	}
}

func TestQueryResponseSRV(t *testing.T) {
	core, mp := newTestCore()
	_ = core.RegisterService(ServiceInfo{
		ServiceType:  "_http._tcp",
		InstanceName: "Web",
		HostName:     "myhost",
		Port:         80,
	})
	registerAndAdvance(t, core, mp)

	query := buildQuery("Web._http._tcp.local", TypeSRV)
	mp.inject(query, net.ParseIP("fe80::99"), 5353)

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected SRV response")
	}
	msg, _ := parseMessage(packets[0].data)
	foundSRV := false
	for _, ans := range msg.Answers {
		if ans.Type == TypeSRV {
			foundSRV = true
		}
	}
	if !foundSRV {
		t.Fatal("response missing SRV")
	}
}

func TestQueryResponseTXT(t *testing.T) {
	core, mp := newTestCore()
	_ = core.RegisterService(ServiceInfo{
		ServiceType:  "_http._tcp",
		InstanceName: "Web",
		HostName:     "myhost",
		Port:         80,
		TxtData:      []byte{2, 'h', 'i'},
	})
	registerAndAdvance(t, core, mp)

	query := buildQuery("Web._http._tcp.local", TypeTXT)
	mp.inject(query, net.ParseIP("fe80::99"), 5353)

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected TXT response")
	}
	msg, _ := parseMessage(packets[0].data)
	foundTXT := false
	for _, ans := range msg.Answers {
		if ans.Type == TypeTXT {
			foundTXT = true
		}
	}
	if !foundTXT {
		t.Fatal("response missing TXT")
	}
}

func TestQueryResponseDNSSD(t *testing.T) {
	core, mp := newTestCore()
	_ = core.RegisterService(ServiceInfo{
		ServiceType:  "_http._tcp",
		InstanceName: "Web",
		HostName:     "myhost",
		Port:         80,
	})
	registerAndAdvance(t, core, mp)

	// Query _services._dns-sd._udp.local
	query := buildQuery("_services._dns-sd._udp.local", TypePTR)
	mp.inject(query, net.ParseIP("fe80::99"), 5353)

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected DNS-SD response")
	}
	msg, _ := parseMessage(packets[0].data)
	foundPTR := false
	for _, ans := range msg.Answers {
		if ans.Type == TypePTR {
			foundPTR = true
		}
	}
	if !foundPTR {
		t.Fatal("DNS-SD response missing PTR")
	}
}

func TestQueryUnicastResponse(t *testing.T) {
	core, mp := newTestCore()
	ip := net.ParseIP("fe80::1")
	_ = core.RegisterHost(HostInfo{Name: "myhost", Addresses: []net.IP{ip}})
	registerAndAdvance(t, core, mp)

	// Query from a non-standard port triggers unicast reply.
	query := buildQuery("myhost.local", TypeAAAA)
	mp.inject(query, net.ParseIP("fe80::99"), 12345)

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected unicast response")
	}
	if !packets[0].unicast {
		t.Fatal("expected unicast flag set")
	}
	if packets[0].dstPort != 12345 {
		t.Fatalf("dst port = %d, want 12345", packets[0].dstPort)
	}
}

func TestQueryNoResponseForUnregistered(t *testing.T) {
	_, mp := newTestCore()
	// No hosts or services registered.
	query := buildQuery("unknown.local", TypeAAAA)
	mp.inject(query, net.ParseIP("fe80::99"), 5353)

	packets := mp.getPackets()
	if len(packets) != 0 {
		t.Fatal("should not respond to unknown name")
	}
}

// ---------------------------------------------------------------------------
// Known-answer suppression
// ---------------------------------------------------------------------------

func TestKnownAnswerSuppression(t *testing.T) {
	core, mp := newTestCore()
	ip := net.ParseIP("fe80::1")
	_ = core.RegisterHost(HostInfo{Name: "myhost", Addresses: []net.IP{ip}})
	registerAndAdvance(t, core, mp)

	// Build a query that includes the answer in the known-answer section.
	mb := newMessageBuilder(0)
	_ = mb.addQuestion("myhost.local", TypeAAAA, ClassInternet)
	rdata := buildAAAARData(ip.To16())
	_ = mb.addAnswer("myhost.local", TypeAAAA, ClassInternet, 120, rdata)
	query := mb.build()

	mp.inject(query, net.ParseIP("fe80::99"), 5353)

	packets := mp.getPackets()
	// The answer should be suppressed, so no response (or response without AAAA).
	for _, p := range packets {
		msg, err := parseMessage(p.data)
		if err != nil {
			continue
		}
		for _, ans := range msg.Answers {
			if ans.Type == TypeAAAA && strings.EqualFold(ans.Name, "myhost.local") {
				t.Fatal("known answer should suppress AAAA response")
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Conflict detection
// ---------------------------------------------------------------------------

func TestHostConflictDuringProbing(t *testing.T) {
	core, mp := newTestCore()
	ip := net.ParseIP("fe80::1")
	_ = core.RegisterHost(HostInfo{Name: "myhost", Addresses: []net.IP{ip}})

	conflictName := ""
	core.SetConflictCallback(func(name, serviceType string) {
		conflictName = name
	})

	now := time.Now()
	core.Process(now)

	// Simulate another host probing for the same name (query with authority).
	probeMb := newMessageBuilder(0)
	_ = probeMb.addQuestion("myhost.local", TypeANY, ClassInternet)
	otherIP := net.ParseIP("fe80::FF")
	otherRData := buildAAAARData(otherIP.To16())
	_ = probeMb.addAuthority("myhost.local", TypeAAAA, ClassInternet, 120, otherRData)
	probeData := probeMb.build()

	mp.inject(probeData, net.ParseIP("fe80::FF"), 5353)

	state, _ := core.GetHostState("myhost")
	if state != StateConflict {
		t.Fatalf("state = %v, want conflict", state)
	}
	if conflictName != "myhost" {
		t.Fatalf("conflictName = %q, want %q", conflictName, "myhost")
	}
}

func TestServiceConflictDuringProbing(t *testing.T) {
	core, mp := newTestCore()
	_ = core.RegisterService(ServiceInfo{
		ServiceType:  "_http._tcp",
		InstanceName: "Web",
		HostName:     "myhost",
		Port:         80,
	})

	conflictName := ""
	conflictSvc := ""
	core.SetConflictCallback(func(name, serviceType string) {
		conflictName = name
		conflictSvc = serviceType
	})

	now := time.Now()
	core.Process(now)

	// Simulate another service probing for the same instance name.
	probeMb := newMessageBuilder(0)
	_ = probeMb.addQuestion("Web._http._tcp.local", TypeANY, ClassInternet)
	srvRData, _ := buildSRVRData(0, 0, 80, "otherhost.local")
	_ = probeMb.addAuthority("Web._http._tcp.local", TypeSRV, ClassInternet, 4500, srvRData)
	mp.inject(probeMb.build(), net.ParseIP("fe80::FF"), 5353)

	state, _ := core.GetServiceState("_http._tcp", "Web")
	if state != StateConflict {
		t.Fatalf("state = %v, want conflict", state)
	}
	if conflictName != "Web" {
		t.Fatalf("conflictName = %q, want %q", conflictName, "Web")
	}
	if conflictSvc != "_http._tcp" {
		t.Fatalf("conflictSvc = %q, want %q", conflictSvc, "_http._tcp")
	}
}

func TestHostConflictFromResponse(t *testing.T) {
	core, mp := newTestCore()
	ip := net.ParseIP("fe80::1")
	_ = core.RegisterHost(HostInfo{Name: "myhost", Addresses: []net.IP{ip}})

	conflictDetected := false
	core.SetConflictCallback(func(name, serviceType string) {
		conflictDetected = true
	})

	now := time.Now()
	core.Process(now) // Start probing.

	// Simulate a response with cache-flush for our hostname.
	respMb := newMessageBuilder(0)
	respMb.setResponse()
	otherIP := net.ParseIP("fe80::FF")
	otherRData := buildAAAARData(otherIP.To16())
	_ = respMb.addAnswer("myhost.local", TypeAAAA, ClassInternet|CacheFlushFlag, 120, otherRData)
	mp.inject(respMb.build(), net.ParseIP("fe80::FF"), 5353)

	state, _ := core.GetHostState("myhost")
	if state != StateConflict {
		t.Fatalf("state = %v, want conflict", state)
	}
	if !conflictDetected {
		t.Fatal("conflict callback not invoked")
	}
}

// ---------------------------------------------------------------------------
// Browser
// ---------------------------------------------------------------------------

func TestBrowserReceivesPTR(t *testing.T) {
	core, mp := newTestCore()

	var results []BrowseResult
	browser, err := core.StartBrowser("_http._tcp", func(r BrowseResult) {
		results = append(results, r)
	})
	if err != nil {
		t.Fatalf("StartBrowser error: %v", err)
	}
	if browser == nil {
		t.Fatal("browser is nil")
	}
	if browser.ServiceType() != "_http._tcp" {
		t.Fatalf("ServiceType() = %q", browser.ServiceType())
	}

	// Process to send query.
	now := time.Now()
	core.Process(now)

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected browser query packet")
	}

	// Simulate response with PTR record.
	ptrRData, _ := buildPTRRData("Web Server._http._tcp.local")
	respMb := newMessageBuilder(0)
	respMb.setResponse()
	_ = respMb.addAnswer("_http._tcp.local", TypePTR, ClassInternet, 4500, ptrRData)
	mp.inject(respMb.build(), net.ParseIP("fe80::99"), 5353)

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].InstanceName != "Web Server" {
		t.Fatalf("InstanceName = %q, want %q", results[0].InstanceName, "Web Server")
	}
	if results[0].TTL != 4500 {
		t.Fatalf("TTL = %d, want 4500", results[0].TTL)
	}
}

func TestBrowserDuplicate(t *testing.T) {
	core, _ := newTestCore()
	_, err := core.StartBrowser("_http._tcp", func(BrowseResult) {})
	if err != nil {
		t.Fatalf("StartBrowser error: %v", err)
	}
	_, err = core.StartBrowser("_http._tcp", func(BrowseResult) {})
	if err != errAlready {
		t.Fatalf("expected errAlready, got %v", err)
	}
}

func TestBrowserInvalidArgs(t *testing.T) {
	core, _ := newTestCore()
	_, err := core.StartBrowser("", func(BrowseResult) {})
	if err != errInvalidArgs {
		t.Fatalf("expected errInvalidArgs, got %v", err)
	}
	_, err = core.StartBrowser("_http._tcp", nil)
	if err != errInvalidArgs {
		t.Fatalf("expected errInvalidArgs, got %v", err)
	}
}

func TestStopBrowser(t *testing.T) {
	core, mp := newTestCore()

	var results []BrowseResult
	browser, _ := core.StartBrowser("_http._tcp", func(r BrowseResult) {
		results = append(results, r)
	})

	core.StopBrowser(browser)

	// Inject PTR record after stopping.
	ptrRData, _ := buildPTRRData("Web._http._tcp.local")
	respMb := newMessageBuilder(0)
	respMb.setResponse()
	_ = respMb.addAnswer("_http._tcp.local", TypePTR, ClassInternet, 4500, ptrRData)
	mp.inject(respMb.build(), net.ParseIP("fe80::99"), 5353)

	if len(results) != 0 {
		t.Fatalf("got %d results after stop, want 0", len(results))
	}
}

func TestBrowserGoodbye(t *testing.T) {
	core, mp := newTestCore()

	var results []BrowseResult
	_, _ = core.StartBrowser("_http._tcp", func(r BrowseResult) {
		results = append(results, r)
	})

	// Inject PTR with TTL=0 (goodbye).
	ptrRData, _ := buildPTRRData("Web._http._tcp.local")
	respMb := newMessageBuilder(0)
	respMb.setResponse()
	_ = respMb.addAnswer("_http._tcp.local", TypePTR, ClassInternet, 0, ptrRData)
	mp.inject(respMb.build(), net.ParseIP("fe80::99"), 5353)

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].TTL != 0 {
		t.Fatalf("goodbye TTL = %d, want 0", results[0].TTL)
	}
}

// ---------------------------------------------------------------------------
// SRV Resolver
// ---------------------------------------------------------------------------

func TestSrvResolver(t *testing.T) {
	core, mp := newTestCore()

	var results []SrvResult
	resolver, err := core.StartSrvResolver("Web", "_http._tcp", func(r SrvResult) {
		results = append(results, r)
	})
	if err != nil {
		t.Fatalf("StartSrvResolver error: %v", err)
	}

	now := time.Now()
	core.Process(now)

	// Verify query sent.
	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected SRV query")
	}

	// Inject SRV response.
	srvRData, _ := buildSRVRData(0, 0, 80, "myhost.local")
	respMb := newMessageBuilder(0)
	respMb.setResponse()
	_ = respMb.addAnswer("Web._http._tcp.local", TypeSRV, ClassInternet|CacheFlushFlag, 4500, srvRData)
	mp.inject(respMb.build(), net.ParseIP("fe80::99"), 5353)

	if len(results) != 1 {
		t.Fatalf("got %d SRV results, want 1", len(results))
	}
	if results[0].Port != 80 {
		t.Fatalf("port = %d, want 80", results[0].Port)
	}
	if results[0].HostName != "myhost" {
		t.Fatalf("hostname = %q, want %q", results[0].HostName, "myhost")
	}

	core.StopSrvResolver(resolver)
}

func TestSrvResolverInvalidArgs(t *testing.T) {
	core, _ := newTestCore()
	_, err := core.StartSrvResolver("", "_http._tcp", func(SrvResult) {})
	if err != errInvalidArgs {
		t.Fatalf("expected errInvalidArgs, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TXT Resolver
// ---------------------------------------------------------------------------

func TestTxtResolver(t *testing.T) {
	core, mp := newTestCore()

	var results []TxtResult
	resolver, err := core.StartTxtResolver("Web", "_http._tcp", func(r TxtResult) {
		results = append(results, r)
	})
	if err != nil {
		t.Fatalf("StartTxtResolver error: %v", err)
	}

	now := time.Now()
	core.Process(now)

	// Inject TXT response.
	txtData := []byte{5, 'h', 'e', 'l', 'l', 'o'}
	respMb := newMessageBuilder(0)
	respMb.setResponse()
	_ = respMb.addAnswer("Web._http._tcp.local", TypeTXT, ClassInternet|CacheFlushFlag, 4500, txtData)
	mp.inject(respMb.build(), net.ParseIP("fe80::99"), 5353)

	if len(results) != 1 {
		t.Fatalf("got %d TXT results, want 1", len(results))
	}
	if !bytes.Equal(results[0].TxtData, txtData) {
		t.Fatalf("TXT data mismatch")
	}

	core.StopTxtResolver(resolver)
}

func TestTxtResolverInvalidArgs(t *testing.T) {
	core, _ := newTestCore()
	_, err := core.StartTxtResolver("", "_http._tcp", func(TxtResult) {})
	if err != errInvalidArgs {
		t.Fatalf("expected errInvalidArgs, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Address Resolver
// ---------------------------------------------------------------------------

func TestAddressResolver(t *testing.T) {
	core, mp := newTestCore()

	var results []AddressResult
	resolver, err := core.StartAddressResolver("myhost", func(r AddressResult) {
		results = append(results, r)
	})
	if err != nil {
		t.Fatalf("StartAddressResolver error: %v", err)
	}

	now := time.Now()
	core.Process(now)

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected AAAA query")
	}

	// Inject AAAA response.
	ip := net.ParseIP("fe80::42").To16()
	rdata := buildAAAARData(ip)
	respMb := newMessageBuilder(0)
	respMb.setResponse()
	_ = respMb.addAnswer("myhost.local", TypeAAAA, ClassInternet|CacheFlushFlag, 120, rdata)
	mp.inject(respMb.build(), net.ParseIP("fe80::99"), 5353)

	if len(results) != 1 {
		t.Fatalf("got %d addr results, want 1", len(results))
	}
	if !results[0].Address.Equal(ip) {
		t.Fatalf("address = %v, want %v", results[0].Address, ip)
	}
	if results[0].HostName != "myhost" {
		t.Fatalf("hostname = %q, want %q", results[0].HostName, "myhost")
	}

	core.StopAddressResolver(resolver)
}

func TestAddressResolverInvalidArgs(t *testing.T) {
	core, _ := newTestCore()
	_, err := core.StartAddressResolver("", func(AddressResult) {})
	if err != errInvalidArgs {
		t.Fatalf("expected errInvalidArgs, got %v", err)
	}
}

func TestAddressResolverIgnoresShortRData(t *testing.T) {
	core, mp := newTestCore()

	var results []AddressResult
	_, _ = core.StartAddressResolver("myhost", func(r AddressResult) {
		results = append(results, r)
	})

	// Inject AAAA response with wrong-length RDATA (not 16 bytes).
	respMb := newMessageBuilder(0)
	respMb.setResponse()
	_ = respMb.addAnswer("myhost.local", TypeAAAA, ClassInternet, 120, []byte{1, 2, 3, 4})
	mp.inject(respMb.build(), net.ParseIP("fe80::99"), 5353)

	if len(results) != 0 {
		t.Fatalf("got %d results for short RDATA, want 0", len(results))
	}
}

// ---------------------------------------------------------------------------
// Multi-question handling
// ---------------------------------------------------------------------------

func TestMultiQuestionQuery(t *testing.T) {
	core, mp := newTestCore()
	ip := net.ParseIP("fe80::1")
	_ = core.RegisterHost(HostInfo{Name: "myhost", Addresses: []net.IP{ip}})
	_ = core.RegisterService(ServiceInfo{
		ServiceType:  "_http._tcp",
		InstanceName: "Web",
		HostName:     "myhost",
		Port:         80,
	})
	registerAndAdvance(t, core, mp)

	// Query for both AAAA and PTR in one message.
	mb := newMessageBuilder(0)
	_ = mb.addQuestion("myhost.local", TypeAAAA, ClassInternet)
	_ = mb.addQuestion("_http._tcp.local", TypePTR, ClassInternet)
	query := mb.build()

	mp.inject(query, net.ParseIP("fe80::99"), 5353)

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected response to multi-question query")
	}
	msg, _ := parseMessage(packets[0].data)
	foundAAAA, foundPTR := false, false
	for _, ans := range msg.Answers {
		if ans.Type == TypeAAAA {
			foundAAAA = true
		}
		if ans.Type == TypePTR {
			foundPTR = true
		}
	}
	if !foundAAAA {
		t.Fatal("response missing AAAA")
	}
	if !foundPTR {
		t.Fatal("response missing PTR")
	}
}

// ---------------------------------------------------------------------------
// Response with additional records updates cache
// ---------------------------------------------------------------------------

func TestResponseAdditionalRecordsUpdateCache(t *testing.T) {
	core, mp := newTestCore()

	// Inject a response with records in the additionals section.
	ip := net.ParseIP("fe80::99").To16()
	rdata := buildAAAARData(ip)
	respMb := newMessageBuilder(0)
	respMb.setResponse()
	_ = respMb.addAdditional("otherhost.local", TypeAAAA, ClassInternet, 120, rdata)
	mp.inject(respMb.build(), net.ParseIP("fe80::99"), 5353)

	// Cache should contain the additional record.
	now := time.Now()
	cached := core.Cache().Lookup("otherhost.local", TypeAAAA, now)
	if len(cached) != 1 {
		t.Fatalf("cache has %d entries, want 1", len(cached))
	}
}

// ---------------------------------------------------------------------------
// State string representation
// ---------------------------------------------------------------------------

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateProbing, "probing"},
		{StateRegistered, "registered"},
		{StateConflict, "conflict"},
		{State(99), "unknown"},
	}
	for _, tc := range tests {
		got := tc.state.String()
		if got != tc.want {
			t.Fatalf("State(%d).String() = %q, want %q", tc.state, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Config defaults
// ---------------------------------------------------------------------------

func TestConfigDefaults(t *testing.T) {
	cfg := Config{}
	cfg.applyDefaults()
	if cfg.Port != 5353 {
		t.Fatalf("Port = %d, want 5353", cfg.Port)
	}
	if cfg.MulticastAddress != "ff02::fb" {
		t.Fatalf("MulticastAddress = %q, want %q", cfg.MulticastAddress, "ff02::fb")
	}
	if cfg.MaxMessageSize != 1200 {
		t.Fatalf("MaxMessageSize = %d, want 1200", cfg.MaxMessageSize)
	}
}

// ---------------------------------------------------------------------------
// Info helpers
// ---------------------------------------------------------------------------

func TestHostInfoFQDN(t *testing.T) {
	h := HostInfo{Name: "myhost"}
	if h.fqdn() != "myhost.local" {
		t.Fatalf("fqdn = %q", h.fqdn())
	}
}

func TestHostInfoEffectiveTTL(t *testing.T) {
	h := HostInfo{Name: "h", TTL: 0}
	if h.effectiveTTL() != defaultAddrTTL {
		t.Fatalf("default TTL = %d, want %d", h.effectiveTTL(), defaultAddrTTL)
	}
	h.TTL = 300
	if h.effectiveTTL() != 300 {
		t.Fatalf("custom TTL = %d, want 300", h.effectiveTTL())
	}
}

func TestServiceInfoFQDNs(t *testing.T) {
	s := ServiceInfo{
		ServiceType:  "_http._tcp",
		InstanceName: "Web",
		HostName:     "myhost",
	}
	if s.serviceFQDN() != "_http._tcp.local" {
		t.Fatalf("serviceFQDN = %q", s.serviceFQDN())
	}
	if s.instanceFQDN() != "Web._http._tcp.local" {
		t.Fatalf("instanceFQDN = %q", s.instanceFQDN())
	}
	if s.hostFQDN() != "myhost.local" {
		t.Fatalf("hostFQDN = %q", s.hostFQDN())
	}
}

func TestServiceInfoEffectiveTTL(t *testing.T) {
	s := ServiceInfo{ServiceType: "_tcp", InstanceName: "x"}
	if s.effectiveTTL() != defaultServiceTTL {
		t.Fatalf("default TTL = %d", s.effectiveTTL())
	}
	s.TTL = 999
	if s.effectiveTTL() != 999 {
		t.Fatalf("custom TTL = %d", s.effectiveTTL())
	}
}

func TestKeyRecordFQDN(t *testing.T) {
	kr := KeyRecord{Name: "myhost"}
	if kr.fqdn() != "myhost.local" {
		t.Fatalf("host key fqdn = %q", kr.fqdn())
	}
	kr.ServiceType = "_http._tcp"
	if kr.fqdn() != "myhost._http._tcp.local" {
		t.Fatalf("service key fqdn = %q", kr.fqdn())
	}
	if !kr.isServiceKey() {
		t.Fatal("should be service key")
	}
}

// ---------------------------------------------------------------------------
// Process when disabled
// ---------------------------------------------------------------------------

func TestProcessDisabled(t *testing.T) {
	core, _ := newTestCore()
	core.SetEnabled(false)
	d := core.Process(time.Now())
	if d != time.Hour {
		t.Fatalf("Process disabled duration = %v, want 1h", d)
	}
}

// ---------------------------------------------------------------------------
// HandleMessage when disabled
// ---------------------------------------------------------------------------

func TestHandleMessageDisabled(t *testing.T) {
	core, mp := newTestCore()
	core.SetEnabled(false)

	query := buildQuery("myhost.local", TypeAAAA)
	mp.inject(query, net.ParseIP("fe80::99"), 5353)

	packets := mp.getPackets()
	if len(packets) != 0 {
		t.Fatal("should not respond when disabled")
	}
}

// ---------------------------------------------------------------------------
// HandleMessage ignores malformed data
// ---------------------------------------------------------------------------

func TestHandleMessageMalformed(t *testing.T) {
	_, mp := newTestCore()
	// Inject garbage.
	mp.inject([]byte{0, 1, 2}, net.ParseIP("fe80::99"), 5353)
	// Should not panic.
}

// ---------------------------------------------------------------------------
// Compressor appendServiceInstanceName
// ---------------------------------------------------------------------------

func TestCompressorAppendServiceInstanceName(t *testing.T) {
	c := newCompressor()
	var buf []byte
	var err error

	// First, add the service type so it gets recorded.
	buf, err = c.appendName(buf, "_http._tcp.local")
	if err != nil {
		t.Fatalf("appendName error: %v", err)
	}

	// Now add instance name with compression.
	startLen := len(buf)
	buf, err = c.appendServiceInstanceName(buf, "Web Server", "_http._tcp", "local")
	if err != nil {
		t.Fatalf("appendServiceInstanceName error: %v", err)
	}

	// Should be compressed (instance label + pointer).
	instPartLen := len(buf) - startLen
	// Full: 1+10 + 1+5 + 1+4 + 1+5 + 0 = 28; compressed: 1+10 + 2 = 13
	if instPartLen >= 20 {
		t.Fatalf("expected compression, instance part took %d bytes", instPartLen)
	}

	// Decode the instance name.
	name, _, err := decodeName(buf, startLen)
	if err != nil {
		t.Fatalf("decodeName error: %v", err)
	}
	// The name should be "Web Server._http._tcp.local"
	if name != "Web Server._http._tcp.local" {
		t.Fatalf("got %q, want %q", name, "Web Server._http._tcp.local")
	}
}

func TestCompressorAppendServiceInstanceNameNoCompression(t *testing.T) {
	c := newCompressor()
	var buf []byte
	var err error

	// Without previously added names, compression falls through to appendName.
	buf, err = c.appendServiceInstanceName(buf, "Web", "_http._tcp", "local")
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	name, _, err := decodeName(buf, 0)
	if err != nil {
		t.Fatalf("decodeName error: %v", err)
	}
	if name != "Web._http._tcp.local" {
		t.Fatalf("got %q, want %q", name, "Web._http._tcp.local")
	}
}

// ---------------------------------------------------------------------------
// encodeNameLabel
// ---------------------------------------------------------------------------

func TestEncodeNameLabel(t *testing.T) {
	b, err := encodeNameLabel("hello")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !bytes.Equal(b, []byte{5, 'h', 'e', 'l', 'l', 'o'}) {
		t.Fatalf("got %v", b)
	}

	// Empty label should fail.
	_, err = encodeNameLabel("")
	if err == nil {
		t.Fatal("expected error for empty label")
	}
}

// ---------------------------------------------------------------------------
// msgHeader flag tests
// ---------------------------------------------------------------------------

func TestMsgHeaderFlags(t *testing.T) {
	var h msgHeader

	if h.isResponse() {
		t.Fatal("new header should be query")
	}
	if !h.isQuery() {
		t.Fatal("new header should be query")
	}

	h.setResponse()
	if !h.isResponse() {
		t.Fatal("should be response after setResponse")
	}

	h.setTruncated()
	if !h.isTruncated() {
		t.Fatal("should be truncated")
	}
}

// ---------------------------------------------------------------------------
// isKnownAnswer helper
// ---------------------------------------------------------------------------

func TestIsKnownAnswer(t *testing.T) {
	answers := []resourceRecord{
		{Name: "myhost.local", Type: TypeAAAA, TTL: 120, RData: []byte{1, 2, 3}},
	}

	if !isKnownAnswer(answers, "myhost.local", TypeAAAA, []byte{1, 2, 3}) {
		t.Fatal("should be known answer")
	}
	if !isKnownAnswer(answers, "MYHOST.LOCAL", TypeAAAA, []byte{1, 2, 3}) {
		t.Fatal("should be case-insensitive")
	}
	if isKnownAnswer(answers, "myhost.local", TypeAAAA, []byte{4, 5, 6}) {
		t.Fatal("different rdata should not match")
	}
	if isKnownAnswer(answers, "myhost.local", TypeA, []byte{1, 2, 3}) {
		t.Fatal("different type should not match")
	}

	// TTL=0 answer should not suppress.
	answersGoodbye := []resourceRecord{
		{Name: "myhost.local", Type: TypeAAAA, TTL: 0, RData: []byte{1, 2, 3}},
	}
	if isKnownAnswer(answersGoodbye, "myhost.local", TypeAAAA, []byte{1, 2, 3}) {
		t.Fatal("TTL=0 should not suppress")
	}
}

// ---------------------------------------------------------------------------
// rdataEqual
// ---------------------------------------------------------------------------

func TestRDataEqual(t *testing.T) {
	if !rdataEqual([]byte{1, 2, 3}, []byte{1, 2, 3}) {
		t.Fatal("equal slices should be equal")
	}
	if rdataEqual([]byte{1, 2, 3}, []byte{1, 2, 4}) {
		t.Fatal("different slices should not be equal")
	}
	if rdataEqual([]byte{1, 2}, []byte{1, 2, 3}) {
		t.Fatal("different lengths should not be equal")
	}
	if !rdataEqual(nil, nil) {
		t.Fatal("nil slices should be equal")
	}
	if !rdataEqual([]byte{}, []byte{}) {
		t.Fatal("empty slices should be equal")
	}
}

// ---------------------------------------------------------------------------
// queryInterval exponential backoff
// ---------------------------------------------------------------------------

func TestQueryInterval(t *testing.T) {
	if queryInterval(1) != time.Second {
		t.Fatalf("first interval = %v, want 1s", queryInterval(1))
	}
	if queryInterval(2) != 2*time.Second {
		t.Fatalf("second interval = %v, want 2s", queryInterval(2))
	}
	if queryInterval(3) != 4*time.Second {
		t.Fatalf("third interval = %v, want 4s", queryInterval(3))
	}
	// Should cap at 1 hour.
	if queryInterval(100) != time.Hour {
		t.Fatalf("large count interval = %v, want 1h", queryInterval(100))
	}
}

// ---------------------------------------------------------------------------
// Browser query includes known answers
// ---------------------------------------------------------------------------

func TestBrowserQueryIncludesKnownAnswers(t *testing.T) {
	core, mp := newTestCore()

	_, _ = core.StartBrowser("_http._tcp", func(BrowseResult) {})

	// Pre-populate cache with a PTR record.
	ptrRData, _ := buildPTRRData("Web._http._tcp.local")
	core.Cache().Add(CacheEntry{
		Name:        "_http._tcp.local",
		Type:        TypePTR,
		Class:       ClassInternet,
		TTL:         4500,
		RData:       ptrRData,
		ReceiveTime: time.Now(),
	})

	mp.clearPackets()
	now := time.Now()
	core.Process(now)

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected browser query")
	}
	msg, _ := parseMessage(packets[0].data)
	if len(msg.Answers) == 0 {
		t.Fatal("browser query should include known answers")
	}
}

// ---------------------------------------------------------------------------
// SetEnabled clears state
// ---------------------------------------------------------------------------

func TestSetEnabledClearsState(t *testing.T) {
	core, _ := newTestCore()
	_ = core.RegisterHost(HostInfo{Name: "h", Addresses: []net.IP{net.ParseIP("fe80::1")}})
	_ = core.RegisterService(ServiceInfo{ServiceType: "_tcp", InstanceName: "x", HostName: "h", Port: 1})
	_, _ = core.StartBrowser("_tcp", func(BrowseResult) {})

	core.SetEnabled(false)

	_, ok := core.GetHostState("h")
	if ok {
		t.Fatal("host should be cleared after disable")
	}
	_, ok = core.GetServiceState("_tcp", "x")
	if ok {
		t.Fatal("service should be cleared after disable")
	}
}

// ---------------------------------------------------------------------------
// SubType PTR query response
// ---------------------------------------------------------------------------

func TestSubTypePTRQueryResponse(t *testing.T) {
	core, mp := newTestCore()
	_ = core.RegisterService(ServiceInfo{
		ServiceType:  "_http._tcp",
		InstanceName: "Web",
		HostName:     "myhost",
		Port:         80,
		SubTypes:     []string{"_printer"},
	})
	registerAndAdvance(t, core, mp)

	// Query for the sub-type PTR.
	query := buildQuery("_printer._sub._http._tcp.local", TypePTR)
	mp.inject(query, net.ParseIP("fe80::99"), 5353)

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected response to sub-type PTR query")
	}
	msg, _ := parseMessage(packets[0].data)
	foundPTR := false
	for _, ans := range msg.Answers {
		if ans.Type == TypePTR {
			foundPTR = true
		}
	}
	if !foundPTR {
		t.Fatal("response missing sub-type PTR")
	}
}

// ---------------------------------------------------------------------------
// Query for registered key record
// ---------------------------------------------------------------------------

func TestQueryResponseKey(t *testing.T) {
	core, mp := newTestCore()
	_ = core.RegisterKey(KeyRecord{Name: "myhost", KeyData: []byte{0xAA, 0xBB}})

	// Fast-forward key to registered.
	now := time.Now()
	for i := 0; i < probeCount; i++ {
		core.Process(now)
		now = now.Add(probeInterval + time.Millisecond)
	}
	for i := 0; i < announceCount+1; i++ {
		core.Process(now)
		now = now.Add(announceInterval + time.Millisecond)
	}
	mp.clearPackets()

	query := buildQuery("myhost.local", TypeKey)
	mp.inject(query, net.ParseIP("fe80::99"), 5353)

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected KEY response")
	}
	msg, _ := parseMessage(packets[0].data)
	foundKey := false
	for _, ans := range msg.Answers {
		if ans.Type == TypeKey {
			foundKey = true
		}
	}
	if !foundKey {
		t.Fatal("response missing KEY record")
	}
}

// ---------------------------------------------------------------------------
// Non-IN class questions are ignored
// ---------------------------------------------------------------------------

func TestQueryNonINClassIgnored(t *testing.T) {
	core, mp := newTestCore()
	ip := net.ParseIP("fe80::1")
	_ = core.RegisterHost(HostInfo{Name: "myhost", Addresses: []net.IP{ip}})
	registerAndAdvance(t, core, mp)

	// Build a query with non-IN class (e.g., Chaos class = 3).
	mb := newMessageBuilder(0)
	_ = mb.addQuestion("myhost.local", TypeAAAA, 3) // class 3 = CH
	mp.inject(mb.build(), net.ParseIP("fe80::99"), 5353)

	packets := mp.getPackets()
	if len(packets) != 0 {
		t.Fatal("should not respond to non-IN class query")
	}
}

// ---------------------------------------------------------------------------
// Non-IN class responses are ignored for cache
// ---------------------------------------------------------------------------

func TestResponseNonINClassIgnored(t *testing.T) {
	core, mp := newTestCore()

	// Build response with non-IN class.
	respMb := newMessageBuilder(0)
	respMb.setResponse()
	rdata := buildAAAARData(net.ParseIP("fe80::1").To16())
	// Use a non-IN class (3 = CH).
	_ = respMb.addAnswer("myhost.local", TypeAAAA, 3, 120, rdata)
	mp.inject(respMb.build(), net.ParseIP("fe80::99"), 5353)

	cached := core.Cache().Lookup("myhost.local", TypeAAAA, time.Now())
	if len(cached) != 0 {
		t.Fatal("non-IN class records should not be cached")
	}
}

// ---------------------------------------------------------------------------
// Cached results delivered to browsers/resolvers on start
// ---------------------------------------------------------------------------

func TestBrowserDeliversCachedResults(t *testing.T) {
	core, _ := newTestCore()

	// Pre-populate cache.
	ptrRData, _ := buildPTRRData("Cached._http._tcp.local")
	core.Cache().Add(CacheEntry{
		Name:        "_http._tcp.local",
		Type:        TypePTR,
		Class:       ClassInternet,
		TTL:         4500,
		RData:       ptrRData,
		ReceiveTime: time.Now(),
	})

	var results []BrowseResult
	_, _ = core.StartBrowser("_http._tcp", func(r BrowseResult) {
		results = append(results, r)
	})

	if len(results) != 1 {
		t.Fatalf("cached results: got %d, want 1", len(results))
	}
	if results[0].InstanceName != "Cached" {
		t.Fatalf("instance = %q, want %q", results[0].InstanceName, "Cached")
	}
}

func TestSrvResolverDeliversCachedResults(t *testing.T) {
	core, _ := newTestCore()

	srvRData, _ := buildSRVRData(0, 0, 443, "cached.local")
	core.Cache().Add(CacheEntry{
		Name:        "Web._http._tcp.local",
		Type:        TypeSRV,
		Class:       ClassInternet,
		TTL:         4500,
		RData:       srvRData,
		ReceiveTime: time.Now(),
	})

	var results []SrvResult
	_, _ = core.StartSrvResolver("Web", "_http._tcp", func(r SrvResult) {
		results = append(results, r)
	})

	if len(results) != 1 {
		t.Fatalf("cached SRV results: got %d, want 1", len(results))
	}
	if results[0].Port != 443 {
		t.Fatalf("port = %d, want 443", results[0].Port)
	}
}

func TestTxtResolverDeliversCachedResults(t *testing.T) {
	core, _ := newTestCore()

	txtData := []byte{3, 'k', '=', 'v'}
	core.Cache().Add(CacheEntry{
		Name:        "Web._http._tcp.local",
		Type:        TypeTXT,
		Class:       ClassInternet,
		TTL:         4500,
		RData:       txtData,
		ReceiveTime: time.Now(),
	})

	var results []TxtResult
	_, _ = core.StartTxtResolver("Web", "_http._tcp", func(r TxtResult) {
		results = append(results, r)
	})

	if len(results) != 1 {
		t.Fatalf("cached TXT results: got %d, want 1", len(results))
	}
}

func TestAddressResolverDeliversCachedResults(t *testing.T) {
	core, _ := newTestCore()

	ip := net.ParseIP("fe80::42").To16()
	core.Cache().Add(CacheEntry{
		Name:        "myhost.local",
		Type:        TypeAAAA,
		Class:       ClassInternet,
		TTL:         120,
		RData:       ip,
		ReceiveTime: time.Now(),
	})

	var results []AddressResult
	_, _ = core.StartAddressResolver("myhost", func(r AddressResult) {
		results = append(results, r)
	})

	if len(results) != 1 {
		t.Fatalf("cached addr results: got %d, want 1", len(results))
	}
	if !results[0].Address.Equal(ip) {
		t.Fatalf("address = %v, want %v", results[0].Address, ip)
	}
}

// ---------------------------------------------------------------------------
// serviceKey helper
// ---------------------------------------------------------------------------

func TestServiceKey(t *testing.T) {
	k := serviceKey("Web", "_http._tcp")
	if k != "web._http._tcp" {
		t.Fatalf("serviceKey = %q", k)
	}
}

// ---------------------------------------------------------------------------
// Message building: compressor appendQuestion and appendRecord
// ---------------------------------------------------------------------------

func TestCompressorAppendQuestionAndRecord(t *testing.T) {
	c := newCompressor()
	var buf []byte
	var err error

	buf, err = c.appendQuestion(buf, "test.local", TypeAAAA, ClassInternet)
	if err != nil {
		t.Fatalf("appendQuestion error: %v", err)
	}

	buf, err = c.appendRecord(buf, "test.local", TypeAAAA, ClassInternet, 120, make([]byte, 16))
	if err != nil {
		t.Fatalf("appendRecord error: %v", err)
	}

	// The second "test.local" should be compressed.
	// Parse from the start to verify.
	name, consumed, err := decodeName(buf, 0)
	if err != nil {
		t.Fatalf("decodeName error: %v", err)
	}
	if name != "test.local" {
		t.Fatalf("name = %q", name)
	}

	// Skip question type+class.
	offset := consumed + 4
	name2, _, err := decodeName(buf, offset)
	if err != nil {
		t.Fatalf("decodeName record error: %v", err)
	}
	if name2 != "test.local" {
		t.Fatalf("record name = %q", name2)
	}
}

// ---------------------------------------------------------------------------
// Service re-registration (update)
// ---------------------------------------------------------------------------

func TestServiceReRegistration(t *testing.T) {
	core, mp := newTestCore()
	_ = core.RegisterService(ServiceInfo{
		ServiceType:  "_http._tcp",
		InstanceName: "Web",
		HostName:     "myhost",
		Port:         80,
	})
	registerAndAdvance(t, core, mp)

	// Re-register with different port.
	mp.clearPackets()
	err := core.RegisterService(ServiceInfo{
		ServiceType:  "_http._tcp",
		InstanceName: "Web",
		HostName:     "myhost",
		Port:         8080,
	})
	if err != nil {
		t.Fatalf("re-register error: %v", err)
	}

	// Should have sent goodbye for old record.
	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected goodbye for old service")
	}

	// New state should be probing again.
	state, _ := core.GetServiceState("_http._tcp", "Web")
	if state != StateProbing {
		t.Fatalf("state = %v, want probing", state)
	}
}

// ---------------------------------------------------------------------------
// Full wire-format round trip: build message -> parse -> verify
// ---------------------------------------------------------------------------

func TestFullWireFormatRoundTrip(t *testing.T) {
	mb := newMessageBuilder(0)
	_ = mb.addQuestion("_http._tcp.local", TypePTR, ClassInternet)

	ptrRData, _ := buildPTRRData("My Web Server._http._tcp.local")
	_ = mb.addAnswer("_http._tcp.local", TypePTR, ClassInternet, 4500, ptrRData)

	srvRData, _ := buildSRVRData(0, 0, 80, "myhost.local")
	_ = mb.addAdditional("My Web Server._http._tcp.local", TypeSRV, ClassInternet|CacheFlushFlag, 4500, srvRData)

	data := mb.build()

	msg, err := parseMessage(data)
	if err != nil {
		t.Fatalf("parseMessage error: %v", err)
	}

	// Verify header.
	if msg.Header.isResponse() {
		t.Fatal("should be query")
	}
	if msg.Header.QDCount != 1 {
		t.Fatalf("QDCount = %d", msg.Header.QDCount)
	}

	// Verify question.
	if len(msg.Questions) != 1 {
		t.Fatalf("questions = %d", len(msg.Questions))
	}
	q := msg.Questions[0]
	if q.Name != "_http._tcp.local" {
		t.Fatalf("question name = %q", q.Name)
	}
	if q.Type != TypePTR {
		t.Fatalf("question type = %d", q.Type)
	}

	// Verify answer.
	if len(msg.Answers) != 1 {
		t.Fatalf("answers = %d", len(msg.Answers))
	}
	ans := msg.Answers[0]
	ptrName, err := parsePTRRData(ans.RData)
	if err != nil {
		t.Fatalf("parsePTRRData error: %v", err)
	}
	if ptrName != "My Web Server._http._tcp.local" {
		t.Fatalf("PTR name = %q", ptrName)
	}

	// Verify additional.
	if len(msg.Additionals) != 1 {
		t.Fatalf("additionals = %d", len(msg.Additionals))
	}
	add := msg.Additionals[0]
	if add.Type != TypeSRV {
		t.Fatalf("additional type = %d", add.Type)
	}
	_, _, port, target, err := parseSRVRData(add.RData)
	if err != nil {
		t.Fatalf("parseSRVRData error: %v", err)
	}
	if port != 80 {
		t.Fatalf("SRV port = %d", port)
	}
	if target != "myhost.local" {
		t.Fatalf("SRV target = %q", target)
	}
}

// ---------------------------------------------------------------------------
// Process expiry of cache entries
// ---------------------------------------------------------------------------

func TestProcessExpiresCacheEntries(t *testing.T) {
	core, _ := newTestCore()

	past := time.Now().Add(-200 * time.Second)
	core.Cache().Add(CacheEntry{
		Name:        "old.local",
		Type:        TypeAAAA,
		Class:       ClassInternet,
		TTL:         60,
		RData:       make([]byte, 16),
		ReceiveTime: past,
	})

	if core.Cache().Len() != 1 {
		t.Fatal("cache should have 1 entry before Process")
	}

	core.Process(time.Now())

	if core.Cache().Len() != 0 {
		t.Fatal("Process should have expired the stale entry")
	}
}

// ---------------------------------------------------------------------------
// Host re-registration (update)
// ---------------------------------------------------------------------------

func TestHostReRegistration(t *testing.T) {
	core, mp := newTestCore()
	ip1 := net.ParseIP("fe80::1")
	_ = core.RegisterHost(HostInfo{Name: "myhost", Addresses: []net.IP{ip1}})
	registerAndAdvance(t, core, mp)

	mp.clearPackets()
	ip2 := net.ParseIP("fe80::2")
	_ = core.RegisterHost(HostInfo{Name: "myhost", Addresses: []net.IP{ip2}})

	// Should have sent goodbye for old.
	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected goodbye for old host")
	}

	state, _ := core.GetHostState("myhost")
	if state != StateProbing {
		t.Fatalf("state = %v, want probing", state)
	}
}

// ---------------------------------------------------------------------------
// Key re-registration
// ---------------------------------------------------------------------------

func TestKeyReRegistration(t *testing.T) {
	core, mp := newTestCore()
	_ = core.RegisterKey(KeyRecord{Name: "myhost", KeyData: []byte{1, 2}})

	now := time.Now()
	for i := 0; i < probeCount; i++ {
		core.Process(now)
		now = now.Add(probeInterval + time.Millisecond)
	}
	for i := 0; i < announceCount+1; i++ {
		core.Process(now)
		now = now.Add(announceInterval + time.Millisecond)
	}
	mp.clearPackets()

	_ = core.RegisterKey(KeyRecord{Name: "myhost", KeyData: []byte{3, 4}})

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected goodbye for old key")
	}
}

// ---------------------------------------------------------------------------
// TypeANY query for host
// ---------------------------------------------------------------------------

func TestQueryTypeANYForHost(t *testing.T) {
	core, mp := newTestCore()
	ip := net.ParseIP("fe80::1")
	_ = core.RegisterHost(HostInfo{Name: "myhost", Addresses: []net.IP{ip}})
	registerAndAdvance(t, core, mp)

	query := buildQuery("myhost.local", TypeANY)
	mp.inject(query, net.ParseIP("fe80::99"), 5353)

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected response to ANY query")
	}
	msg, _ := parseMessage(packets[0].data)
	if len(msg.Answers) == 0 {
		t.Fatal("ANY query should return answers")
	}
}

// ---------------------------------------------------------------------------
// Probe does not trigger response for probing hosts
// ---------------------------------------------------------------------------

func TestProbingHostDoesNotRespondToQueries(t *testing.T) {
	core, mp := newTestCore()
	ip := net.ParseIP("fe80::1")
	_ = core.RegisterHost(HostInfo{Name: "myhost", Addresses: []net.IP{ip}})

	// Don't advance to registered — still probing.
	core.Process(time.Now())
	mp.clearPackets()

	// Query should not get a response since host is still probing.
	query := buildQuery("myhost.local", TypeAAAA)
	mp.inject(query, net.ParseIP("fe80::99"), 5353)

	packets := mp.getPackets()
	// Filter out any response packets.
	for _, p := range packets {
		msg, err := parseMessage(p.data)
		if err != nil {
			continue
		}
		if msg.Header.isResponse() {
			for _, ans := range msg.Answers {
				if ans.Type == TypeAAAA && strings.EqualFold(ans.Name, "myhost.local") {
					t.Fatal("probing host should not respond to queries")
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Multiple addresses in host
// ---------------------------------------------------------------------------

func TestHostMultipleAddresses(t *testing.T) {
	core, mp := newTestCore()
	ips := []net.IP{
		net.ParseIP("fe80::1"),
		net.ParseIP("fe80::2"),
		net.ParseIP("fe80::3"),
	}
	_ = core.RegisterHost(HostInfo{Name: "multihost", Addresses: ips})
	registerAndAdvance(t, core, mp)

	query := buildQuery("multihost.local", TypeAAAA)
	mp.inject(query, net.ParseIP("fe80::99"), 5353)

	packets := mp.getPackets()
	if len(packets) == 0 {
		t.Fatal("expected response")
	}
	msg, _ := parseMessage(packets[0].data)
	aaaaCount := 0
	for _, ans := range msg.Answers {
		if ans.Type == TypeAAAA {
			aaaaCount++
		}
	}
	if aaaaCount != 3 {
		t.Fatalf("got %d AAAA answers, want 3", aaaaCount)
	}
}

// ---------------------------------------------------------------------------
// Key conflict during probing via response
// ---------------------------------------------------------------------------

func TestKeyConflictFromResponse(t *testing.T) {
	core, mp := newTestCore()
	_ = core.RegisterKey(KeyRecord{Name: "myhost", KeyData: []byte{1, 2}})

	conflictDetected := false
	core.SetConflictCallback(func(name, serviceType string) {
		conflictDetected = true
	})

	now := time.Now()
	core.Process(now)

	// Inject response with cache-flush KEY for our name.
	respMb := newMessageBuilder(0)
	respMb.setResponse()
	_ = respMb.addAnswer("myhost.local", TypeKey, ClassInternet|CacheFlushFlag, 4500, []byte{9, 9})
	mp.inject(respMb.build(), net.ParseIP("fe80::FF"), 5353)

	if !conflictDetected {
		t.Fatal("key conflict should be detected")
	}
}

// ---------------------------------------------------------------------------
// buildAAAARData / buildARData edge cases
// ---------------------------------------------------------------------------

func TestBuildARDataTooShort(t *testing.T) {
	rdata := buildARData([]byte{1, 2})
	if rdata != nil {
		t.Fatal("expected nil for short IP")
	}
}

// ---------------------------------------------------------------------------
// Large label name encoding edge case
// ---------------------------------------------------------------------------

func TestEncodeNameLabelMaxLength(t *testing.T) {
	// 63-byte label (max).
	label := strings.Repeat("a", 63)
	b, err := encodeNameLabel(label)
	if err != nil {
		t.Fatalf("error for 63-byte label: %v", err)
	}
	if b[0] != 63 {
		t.Fatalf("length byte = %d, want 63", b[0])
	}

	// 64-byte label (too long).
	_, err = encodeNameLabel(strings.Repeat("a", 64))
	if err == nil {
		t.Fatal("expected error for 64-byte label")
	}
}

func TestEncodeNameLabelMaxInName(t *testing.T) {
	label := strings.Repeat("a", 64)
	_, err := encodeName(label + ".local")
	if err == nil {
		t.Fatal("expected error for label > 63 bytes in name")
	}
}

// ---------------------------------------------------------------------------
// parseMessage with answer counts
// ---------------------------------------------------------------------------

func TestParseMessageAnswerMismatch(t *testing.T) {
	// Create a header claiming 1 answer but provide no answer data.
	var h msgHeader
	h.ANCount = 1
	data := h.marshal()
	_, err := parseMessage(data)
	if err == nil {
		t.Fatal("expected error for missing answer data")
	}
}

// ---------------------------------------------------------------------------
// Verify SRV query backoff
// ---------------------------------------------------------------------------

func TestResolverQueryBackoff(t *testing.T) {
	core, mp := newTestCore()

	_, _ = core.StartSrvResolver("Web", "_http._tcp", func(SrvResult) {})

	now := time.Now()

	// First query.
	mp.clearPackets()
	core.Process(now)
	if len(mp.getPackets()) == 0 {
		t.Fatal("expected first query")
	}

	// Advance by less than 1s — should not query again.
	mp.clearPackets()
	core.Process(now.Add(500 * time.Millisecond))
	if len(mp.getPackets()) != 0 {
		t.Fatal("should not query before interval elapsed")
	}

	// Advance past 1s — should query.
	mp.clearPackets()
	core.Process(now.Add(1100 * time.Millisecond))
	if len(mp.getPackets()) == 0 {
		t.Fatal("should query after interval")
	}
}

// ---------------------------------------------------------------------------
// Verify message builder uses big-endian for type/class fields
// ---------------------------------------------------------------------------

func TestWireFormatBigEndian(t *testing.T) {
	mb := newMessageBuilder(0)
	_ = mb.addQuestion("x.local", TypeSRV, ClassInternet)
	data := mb.build()

	// Find the question type/class after the name in wire format.
	// Name: 1+'x'+5+'local'+0 = 9 bytes, starting at offset 12 (after header).
	offset := headerSize + 9 // after name
	if offset+4 > len(data) {
		t.Fatal("data too short")
	}
	qtype := binary.BigEndian.Uint16(data[offset : offset+2])
	qclass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
	if qtype != TypeSRV {
		t.Fatalf("qtype = %d, want %d", qtype, TypeSRV)
	}
	if qclass != ClassInternet {
		t.Fatalf("qclass = %d, want %d", qclass, ClassInternet)
	}
}
