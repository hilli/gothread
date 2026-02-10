// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// mockTimer implements Timer for testing.
type mockTimer struct {
	stopped bool
}

func (t *mockTimer) Stop() bool {
	was := !t.stopped
	t.stopped = true
	return was
}

// mockTimerControl captures AfterFunc calls for manual triggering.
type mockTimerControl struct {
	mu       sync.Mutex
	timers   []mockTimerEntry
	autoFire bool
}

type mockTimerEntry struct {
	delay time.Duration
	fn    func()
	timer *mockTimer
}

func newMockTimerControl() *mockTimerControl {
	return &mockTimerControl{}
}

func (m *mockTimerControl) afterFunc(d time.Duration, f func()) Timer {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := &mockTimer{}
	m.timers = append(m.timers, mockTimerEntry{delay: d, fn: f, timer: t})
	return t
}

// fire triggers the most recent timer callback (if not stopped).
func (m *mockTimerControl) fire() {
	m.mu.Lock()
	if len(m.timers) == 0 {
		m.mu.Unlock()
		return
	}
	entry := m.timers[len(m.timers)-1]
	m.mu.Unlock()
	if !entry.timer.stopped {
		entry.fn()
	}
}

// count returns the number of timers scheduled.
func (m *mockTimerControl) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.timers)
}

// appendEncodedName encodes a DNS name and appends it to buf.
func appendEncodedName(buf []byte, name string) []byte {
	b, err := AppendName(buf, name)
	if err != nil {
		panic("appendEncodedName: " + err.Error())
	}
	return b
}

// appendRRHeader appends a resource record header (10 bytes) to buf.
func appendRRHeader(buf []byte, rrType RRType, class RRClass, ttl uint32, rdLength uint16) []byte {
	var rr [ResourceRecordSize]byte
	binary.BigEndian.PutUint16(rr[0:], uint16(rrType))
	binary.BigEndian.PutUint16(rr[2:], uint16(class))
	binary.BigEndian.PutUint32(rr[4:], ttl)
	binary.BigEndian.PutUint16(rr[8:], rdLength)
	return append(buf, rr[:]...)
}

// appendAaaaRecord appends an encoded AAAA resource record (name + RR header + 16-byte addr).
func appendAaaaRecord(buf []byte, name string, addr ip6.Address, ttl uint32) []byte {
	buf = appendEncodedName(buf, name)
	buf = appendRRHeader(buf, RRTypeAaaa, ClassInternet, ttl, AaaaRecordRDataSize)
	buf = append(buf, addr[:]...)
	return buf
}

// appendPtrRecord appends an encoded PTR resource record.
func appendPtrRecord(buf []byte, name string, targetName string, ttl uint32) []byte {
	buf = appendEncodedName(buf, name)
	// Encode the target name to determine RDATA length.
	rdata, err := AppendName(nil, targetName)
	if err != nil {
		panic("appendPtrRecord: " + err.Error())
	}
	buf = appendRRHeader(buf, RRTypePtr, ClassInternet, ttl, uint16(len(rdata)))
	buf = append(buf, rdata...)
	return buf
}

// appendSrvRecord appends an encoded SRV resource record.
func appendSrvRecord(buf []byte, name string, targetHost string, port, priority, weight uint16, ttl uint32) []byte {
	buf = appendEncodedName(buf, name)
	// RDATA: 6 bytes fixed + encoded target name.
	targetNameBytes, err := AppendName(nil, targetHost)
	if err != nil {
		panic("appendSrvRecord: " + err.Error())
	}
	rdLen := SrvRecordFixedSize + len(targetNameBytes)
	buf = appendRRHeader(buf, RRTypeSrv, ClassInternet, ttl, uint16(rdLen))
	var fixed [SrvRecordFixedSize]byte
	binary.BigEndian.PutUint16(fixed[0:], priority)
	binary.BigEndian.PutUint16(fixed[2:], weight)
	binary.BigEndian.PutUint16(fixed[4:], port)
	buf = append(buf, fixed[:]...)
	buf = append(buf, targetNameBytes...)
	return buf
}

// appendTxtRecord appends an encoded TXT resource record.
func appendTxtRecord(buf []byte, name string, txtData []byte, ttl uint32) []byte {
	buf = appendEncodedName(buf, name)
	buf = appendRRHeader(buf, RRTypeTxt, ClassInternet, ttl, uint16(len(txtData)))
	buf = append(buf, txtData...)
	return buf
}

// appendCnameRecord appends an encoded CNAME resource record.
func appendCnameRecord(buf []byte, name string, canonical string, ttl uint32) []byte {
	buf = appendEncodedName(buf, name)
	rdata, err := AppendName(nil, canonical)
	if err != nil {
		panic("appendCnameRecord: " + err.Error())
	}
	buf = appendRRHeader(buf, RRTypeCname, ClassInternet, ttl, uint16(len(rdata)))
	buf = append(buf, rdata...)
	return buf
}

// buildDNSResponse constructs a raw DNS response message.
// questions, answers, and additional are already encoded record bytes.
func buildDNSResponse(messageID uint16, rcode ResponseCode, qdCount, anCount, nsCount, arCount uint16,
	questions, answers, authority, additional []byte) []byte {

	var h Header
	h.MessageID = messageID
	h.SetType(TypeResponse)
	h.SetOpCode(OpcodeQuery)
	h.SetResponseCode(rcode)
	h.QDCount = qdCount
	h.ANCount = anCount
	h.NSCount = nsCount
	h.ARCount = arCount

	hdr := h.MarshalBinary()
	buf := make([]byte, 0, HeaderSize+len(questions)+len(answers)+len(authority)+len(additional))
	buf = append(buf, hdr[:]...)
	buf = append(buf, questions...)
	buf = append(buf, answers...)
	buf = append(buf, authority...)
	buf = append(buf, additional...)
	return buf
}

// buildQuestion builds raw question bytes (encoded name + Question struct).
func buildQuestion(name string, rrType RRType) []byte {
	buf := appendEncodedName(nil, name)
	q := Question{Type: rrType, Class: ClassInternet}
	qBytes := q.MarshalBinary()
	buf = append(buf, qBytes[:]...)
	return buf
}

// testAddr returns a test IPv6 address with the last byte set to n.
func testAddr(n byte) ip6.Address {
	var addr ip6.Address
	addr[0] = 0x20
	addr[1] = 0x01
	addr[2] = 0x0d
	addr[3] = 0xb8
	addr[15] = n
	return addr
}

// testServerAddr returns the test DNS server address.
func testServerAddr() ip6.Address {
	return testAddr(53)
}

// newTestClient creates a Client with a mock timer and a capturing sender.
func newTestClient(sent *[][]byte) (*Client, *mockTimerControl) {
	tc := newMockTimerControl()
	sender := func(data []byte, peerAddr ip6.Address, peerPort uint16) error {
		cp := make([]byte, len(data))
		copy(cp, data)
		*sent = append(*sent, cp)
		return nil
	}
	cfg := DefaultQueryConfig()
	cfg.ServerAddr = testServerAddr()
	c := NewClient(sender, WithAfterFunc(tc.afterFunc), WithDefaultConfig(cfg))
	return c, tc
}

// extractMessageID parses the message ID from a raw DNS query.
func extractMessageID(data []byte) uint16 {
	if len(data) < HeaderSize {
		return 0
	}
	return binary.BigEndian.Uint16(data[0:2])
}

// ---------------------------------------------------------------------------
// QueryConfig Tests
// ---------------------------------------------------------------------------

func TestDefaultQueryConfig(t *testing.T) {
	cfg := DefaultQueryConfig()

	if cfg.ServerPort != DefaultServerPort {
		t.Errorf("ServerPort = %d, want %d", cfg.ServerPort, DefaultServerPort)
	}
	if cfg.ResponseTimeout != DefaultResponseTimeout {
		t.Errorf("ResponseTimeout = %d, want %d", cfg.ResponseTimeout, DefaultResponseTimeout)
	}
	if cfg.MaxTxAttempts != DefaultMaxTxAttempts {
		t.Errorf("MaxTxAttempts = %d, want %d", cfg.MaxTxAttempts, DefaultMaxTxAttempts)
	}
	if cfg.RecursionFlag != RecursionDesired {
		t.Errorf("RecursionFlag = %d, want %d", cfg.RecursionFlag, RecursionDesired)
	}
	if cfg.ServiceMode != ServiceModeSrvTxtOptimize {
		t.Errorf("ServiceMode = %d, want %d", cfg.ServiceMode, ServiceModeSrvTxtOptimize)
	}
	if cfg.ServerAddr != (ip6.Address{}) {
		t.Errorf("ServerAddr should be zero, got %v", cfg.ServerAddr)
	}
}

func TestQueryConfigSetFromNilOverride(t *testing.T) {
	defaults := QueryConfig{
		ServerPort:      8053,
		ResponseTimeout: 1000,
		MaxTxAttempts:   5,
		RecursionFlag:   NoRecursion,
		ServiceMode:     ServiceModeSrv,
	}

	var cfg QueryConfig
	cfg.SetFrom(nil, defaults)

	if cfg != defaults {
		t.Errorf("SetFrom(nil) should copy defaults, got %+v", cfg)
	}
}

func TestQueryConfigSetFromPartialOverride(t *testing.T) {
	defaults := QueryConfig{
		ServerPort:      53,
		ResponseTimeout: 6000,
		MaxTxAttempts:   3,
		RecursionFlag:   RecursionDesired,
		ServiceMode:     ServiceModeSrvTxtOptimize,
	}

	override := QueryConfig{
		ServerPort: 8053,
		// All other fields are zero => should come from defaults.
	}

	var cfg QueryConfig
	cfg.SetFrom(&override, defaults)

	if cfg.ServerPort != 8053 {
		t.Errorf("ServerPort = %d, want 8053", cfg.ServerPort)
	}
	if cfg.ResponseTimeout != defaults.ResponseTimeout {
		t.Errorf("ResponseTimeout = %d, want %d", cfg.ResponseTimeout, defaults.ResponseTimeout)
	}
	if cfg.MaxTxAttempts != defaults.MaxTxAttempts {
		t.Errorf("MaxTxAttempts = %d, want %d", cfg.MaxTxAttempts, defaults.MaxTxAttempts)
	}
	if cfg.RecursionFlag != defaults.RecursionFlag {
		t.Errorf("RecursionFlag = %d, want %d", cfg.RecursionFlag, defaults.RecursionFlag)
	}
	if cfg.ServiceMode != defaults.ServiceMode {
		t.Errorf("ServiceMode = %d, want %d", cfg.ServiceMode, defaults.ServiceMode)
	}
}

func TestQueryConfigSetFromFullOverride(t *testing.T) {
	defaults := DefaultQueryConfig()
	serverAddr := testServerAddr()
	override := QueryConfig{
		ServerAddr:      serverAddr,
		ServerPort:      8053,
		ResponseTimeout: 2000,
		MaxTxAttempts:   1,
		RecursionFlag:   NoRecursion,
		ServiceMode:     ServiceModeTxt,
	}

	var cfg QueryConfig
	cfg.SetFrom(&override, defaults)

	if cfg != override {
		t.Errorf("Full override should be used as-is, got %+v", cfg)
	}
}

// ---------------------------------------------------------------------------
// Response parsing tests
// ---------------------------------------------------------------------------

func TestResponsePopulateFromMinimal(t *testing.T) {
	// Build a response with 1 question, 1 AAAA answer, no additional.
	hostname := "host.example.com."
	addr := testAddr(1)
	question := buildQuestion(hostname, RRTypeAaaa)
	answer := appendAaaaRecord(nil, hostname, addr, 300)

	data := buildDNSResponse(0x1234, RcodeSuccess, 1, 1, 0, 0, question, answer, nil, nil)

	var resp Response
	resp.data = data
	resp.queryName = hostname

	if err := resp.populateFrom(data); err != nil {
		t.Fatalf("populateFrom: %v", err)
	}

	if resp.header.MessageID != 0x1234 {
		t.Errorf("MessageID = 0x%x, want 0x1234", resp.header.MessageID)
	}
	if resp.answerRecordCount != 1 {
		t.Errorf("answerRecordCount = %d, want 1", resp.answerRecordCount)
	}
	if resp.additionalRecordCount != 0 {
		t.Errorf("additionalRecordCount = %d, want 0", resp.additionalRecordCount)
	}
}

func TestResponsePopulateFromInvalidTooShort(t *testing.T) {
	var resp Response
	err := resp.populateFrom(make([]byte, 5))
	if err != errors.ErrParse {
		t.Errorf("err = %v, want ErrParse", err)
	}
}

func TestAddressResponseGetAddress(t *testing.T) {
	hostname := "host.example.com."
	addr0 := testAddr(1)
	addr1 := testAddr(2)

	question := buildQuestion(hostname, RRTypeAaaa)
	var answer []byte
	answer = appendAaaaRecord(answer, hostname, addr0, 300)
	answer = appendAaaaRecord(answer, hostname, addr1, 600)

	data := buildDNSResponse(0x0001, RcodeSuccess, 1, 2, 0, 0, question, answer, nil, nil)

	ar := &AddressResponse{}
	ar.data = data
	ar.queryName = hostname
	if err := ar.populateFrom(data); err != nil {
		t.Fatalf("populateFrom: %v", err)
	}

	if ar.GetHostName() != hostname {
		t.Errorf("GetHostName = %q, want %q", ar.GetHostName(), hostname)
	}

	got0, ttl0, err := ar.GetAddress(0)
	if err != nil {
		t.Fatalf("GetAddress(0): %v", err)
	}
	if got0 != addr0 {
		t.Errorf("addr[0] = %v, want %v", got0, addr0)
	}
	if ttl0 != 300 {
		t.Errorf("ttl[0] = %d, want 300", ttl0)
	}

	got1, ttl1, err := ar.GetAddress(1)
	if err != nil {
		t.Fatalf("GetAddress(1): %v", err)
	}
	if got1 != addr1 {
		t.Errorf("addr[1] = %v, want %v", got1, addr1)
	}
	if ttl1 != 600 {
		t.Errorf("ttl[1] = %d, want 600", ttl1)
	}

	// Index beyond range.
	_, _, err = ar.GetAddress(2)
	if err != errors.ErrNotFound {
		t.Errorf("GetAddress(2): err = %v, want ErrNotFound", err)
	}
}

func TestAddressResponseCnameAlias(t *testing.T) {
	hostname := "alias.example.com."
	canonical := "real.example.com."
	addr := testAddr(42)

	question := buildQuestion(hostname, RRTypeAaaa)
	var answer []byte
	answer = appendCnameRecord(answer, hostname, canonical, 100)
	answer = appendAaaaRecord(answer, canonical, addr, 300)

	data := buildDNSResponse(0x0002, RcodeSuccess, 1, 2, 0, 0, question, answer, nil, nil)

	ar := &AddressResponse{}
	ar.data = data
	ar.queryName = hostname
	if err := ar.populateFrom(data); err != nil {
		t.Fatalf("populateFrom: %v", err)
	}

	got, ttl, err := ar.GetAddress(0)
	if err != nil {
		t.Fatalf("GetAddress(0) with CNAME: %v", err)
	}
	if got != addr {
		t.Errorf("addr = %v, want %v", got, addr)
	}
	if ttl != 300 {
		t.Errorf("ttl = %d, want 300", ttl)
	}
}

func TestBrowseResponseGetServiceInstance(t *testing.T) {
	serviceName := "_http._tcp.local."
	inst1 := "My Web Server._http._tcp.local."
	inst2 := "Other Server._http._tcp.local."

	question := buildQuestion(serviceName, RRTypePtr)
	var answer []byte
	answer = appendPtrRecord(answer, serviceName, inst1, 4500)
	answer = appendPtrRecord(answer, serviceName, inst2, 4500)

	data := buildDNSResponse(0x0003, RcodeSuccess, 1, 2, 0, 0, question, answer, nil, nil)

	br := &BrowseResponse{}
	br.data = data
	br.queryName = serviceName
	if err := br.populateFrom(data); err != nil {
		t.Fatalf("populateFrom: %v", err)
	}

	if br.GetServiceName() != serviceName {
		t.Errorf("GetServiceName = %q, want %q", br.GetServiceName(), serviceName)
	}

	label0, err := br.GetServiceInstance(0)
	if err != nil {
		t.Fatalf("GetServiceInstance(0): %v", err)
	}
	if label0 != "My Web Server" {
		t.Errorf("instance[0] = %q, want %q", label0, "My Web Server")
	}

	label1, err := br.GetServiceInstance(1)
	if err != nil {
		t.Fatalf("GetServiceInstance(1): %v", err)
	}
	if label1 != "Other Server" {
		t.Errorf("instance[1] = %q, want %q", label1, "Other Server")
	}

	_, err = br.GetServiceInstance(2)
	if err != errors.ErrNotFound {
		t.Errorf("GetServiceInstance(2): err = %v, want ErrNotFound", err)
	}
}

func TestBrowseResponseGetServiceInfo(t *testing.T) {
	serviceName := "_http._tcp.local."
	instanceName := "My Server._http._tcp.local."
	instanceLabel := "My Server"
	hostName := "myhost.local."
	hostAddr := testAddr(10)
	txtData := []byte{3, 'k', '=', 'v'}

	question := buildQuestion(serviceName, RRTypePtr)
	answer := appendPtrRecord(nil, serviceName, instanceName, 4500)

	// Additional: SRV + TXT + AAAA
	var additional []byte
	additional = appendSrvRecord(additional, instanceName, hostName, 80, 0, 0, 120)
	additional = appendTxtRecord(additional, instanceName, txtData, 120)
	additional = appendAaaaRecord(additional, hostName, hostAddr, 120)

	data := buildDNSResponse(0x0004, RcodeSuccess, 1, 1, 0, 3, question, answer, nil, additional)

	br := &BrowseResponse{}
	br.data = data
	br.queryName = serviceName
	if err := br.populateFrom(data); err != nil {
		t.Fatalf("populateFrom: %v", err)
	}

	info, err := br.GetServiceInfo(instanceLabel)
	if err != nil {
		t.Fatalf("GetServiceInfo: %v", err)
	}

	if info.HostName != hostName {
		t.Errorf("HostName = %q, want %q", info.HostName, hostName)
	}
	if info.Port != 80 {
		t.Errorf("Port = %d, want 80", info.Port)
	}
	if info.TTL != 120 {
		t.Errorf("TTL = %d, want 120", info.TTL)
	}
	if info.HostAddress != hostAddr {
		t.Errorf("HostAddress = %v, want %v", info.HostAddress, hostAddr)
	}
	if info.HostAddrTTL != 120 {
		t.Errorf("HostAddrTTL = %d, want 120", info.HostAddrTTL)
	}
	if string(info.TxtData) != string(txtData) {
		t.Errorf("TxtData = %v, want %v", info.TxtData, txtData)
	}
	if info.TxtDataTTL != 120 {
		t.Errorf("TxtDataTTL = %d, want 120", info.TxtDataTTL)
	}
}

func TestServiceResponseGetServiceInfo(t *testing.T) {
	instanceName := "My Server._http._tcp.local."
	hostName := "myhost.local."
	hostAddr := testAddr(20)
	txtData := []byte{5, 'h', 'e', 'l', 'l', 'o'}

	question := buildQuestion(instanceName, RRTypeSrv)

	// Answer: SRV + TXT
	var answer []byte
	answer = appendSrvRecord(answer, instanceName, hostName, 8080, 10, 5, 300)
	answer = appendTxtRecord(answer, instanceName, txtData, 300)

	// Additional: AAAA for the host.
	additional := appendAaaaRecord(nil, hostName, hostAddr, 300)

	data := buildDNSResponse(0x0005, RcodeSuccess, 1, 2, 0, 1, question, answer, nil, additional)

	sr := &ServiceResponse{}
	sr.data = data
	sr.queryName = instanceName
	if err := sr.populateFrom(data); err != nil {
		t.Fatalf("populateFrom: %v", err)
	}

	info, err := sr.GetServiceInfo()
	if err != nil {
		t.Fatalf("GetServiceInfo: %v", err)
	}

	if info.HostName != hostName {
		t.Errorf("HostName = %q, want %q", info.HostName, hostName)
	}
	if info.Port != 8080 {
		t.Errorf("Port = %d, want 8080", info.Port)
	}
	if info.Priority != 10 {
		t.Errorf("Priority = %d, want 10", info.Priority)
	}
	if info.Weight != 5 {
		t.Errorf("Weight = %d, want 5", info.Weight)
	}
	if info.TTL != 300 {
		t.Errorf("TTL = %d, want 300", info.TTL)
	}
	if info.HostAddress != hostAddr {
		t.Errorf("HostAddress = %v, want %v", info.HostAddress, hostAddr)
	}
	if string(info.TxtData) != string(txtData) {
		t.Errorf("TxtData = %v, want %v", info.TxtData, txtData)
	}
}

func TestServiceResponseGetHostAddress(t *testing.T) {
	instanceName := "svc._tcp.local."
	hostName := "h.local."
	hostAddr := testAddr(30)

	question := buildQuestion(instanceName, RRTypeSrv)
	answer := appendSrvRecord(nil, instanceName, hostName, 80, 0, 0, 60)
	additional := appendAaaaRecord(nil, hostName, hostAddr, 60)

	data := buildDNSResponse(0x0006, RcodeSuccess, 1, 1, 0, 1, question, answer, nil, additional)

	sr := &ServiceResponse{}
	sr.data = data
	sr.queryName = instanceName
	if err := sr.populateFrom(data); err != nil {
		t.Fatalf("populateFrom: %v", err)
	}

	addr, ttl, err := sr.GetHostAddress(hostName, 0)
	if err != nil {
		t.Fatalf("GetHostAddress: %v", err)
	}
	if addr != hostAddr {
		t.Errorf("addr = %v, want %v", addr, hostAddr)
	}
	if ttl != 60 {
		t.Errorf("ttl = %d, want 60", ttl)
	}
}

// ---------------------------------------------------------------------------
// Client lifecycle tests
// ---------------------------------------------------------------------------

func TestClientNotStarted(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)

	err := c.ResolveAddress("host.example.com.", func(err error, resp *AddressResponse) {}, nil)
	if err != errors.ErrInvalidState {
		t.Errorf("err = %v, want ErrInvalidState", err)
	}

	err = c.Browse("_http._tcp.local.", func(err error, resp *BrowseResponse) {}, nil)
	if err != errors.ErrInvalidState {
		t.Errorf("Browse err = %v, want ErrInvalidState", err)
	}

	err = c.ResolveService("inst", "_http._tcp.local.", func(err error, resp *ServiceResponse) {}, nil)
	if err != errors.ErrInvalidState {
		t.Errorf("ResolveService err = %v, want ErrInvalidState", err)
	}
}

func TestClientStartStop(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)

	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	callbackCalled := false
	err := c.ResolveAddress("host.example.com.", func(err error, resp *AddressResponse) {
		callbackCalled = true
		if err != errors.ErrAbort {
			t.Errorf("callback err = %v, want ErrAbort", err)
		}
		if resp != nil {
			t.Errorf("resp should be nil on abort")
		}
	}, nil)
	if err != nil {
		t.Fatalf("ResolveAddress: %v", err)
	}

	// Stop should cancel pending queries.
	c.Stop()

	if !callbackCalled {
		t.Error("callback was not called on Stop")
	}
}

func TestClientGetSetDefaultConfig(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)

	cfg := c.GetDefaultConfig()
	if cfg.ServerPort != DefaultServerPort {
		t.Errorf("default ServerPort = %d, want %d", cfg.ServerPort, DefaultServerPort)
	}

	c.SetDefaultConfig(QueryConfig{ServerPort: 5353})
	cfg = c.GetDefaultConfig()
	if cfg.ServerPort != 5353 {
		t.Errorf("updated ServerPort = %d, want 5353", cfg.ServerPort)
	}
	// Other fields should still have defaults.
	if cfg.ResponseTimeout != DefaultResponseTimeout {
		t.Errorf("ResponseTimeout = %d, want %d", cfg.ResponseTimeout, DefaultResponseTimeout)
	}
}

// ---------------------------------------------------------------------------
// Query message building tests
// ---------------------------------------------------------------------------

func TestBuildAddressQuery(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)
	c.Start()
	defer c.Stop()

	err := c.ResolveAddress("host.example.com.", func(err error, resp *AddressResponse) {}, nil)
	if err != nil {
		t.Fatalf("ResolveAddress: %v", err)
	}

	if len(sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(sent))
	}

	msg := sent[0]
	if len(msg) < HeaderSize {
		t.Fatalf("message too short: %d bytes", len(msg))
	}

	var h Header
	if err := h.UnmarshalBinary(msg); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}

	if h.GetType() != TypeQuery {
		t.Errorf("type = %d, want TypeQuery", h.GetType())
	}
	if h.GetOpCode() != OpcodeQuery {
		t.Errorf("opcode = %d, want OpcodeQuery", h.GetOpCode())
	}
	if !h.IsRecursionDesired() {
		t.Error("RD should be set")
	}
	if h.QDCount != 1 {
		t.Errorf("QDCount = %d, want 1", h.QDCount)
	}
	if h.MessageID == 0 {
		t.Error("MessageID should be non-zero")
	}

	// Parse the question.
	offset := HeaderSize
	name, newOffset, err := ReadName(msg, offset)
	if err != nil {
		t.Fatalf("ReadName: %v", err)
	}
	if name != "host.example.com." {
		t.Errorf("question name = %q, want %q", name, "host.example.com.")
	}

	var q Question
	if err := q.UnmarshalBinary(msg[newOffset:]); err != nil {
		t.Fatalf("Question.UnmarshalBinary: %v", err)
	}
	if q.Type != RRTypeAaaa {
		t.Errorf("question type = %d, want RRTypeAaaa(%d)", q.Type, RRTypeAaaa)
	}
	if q.Class != ClassInternet {
		t.Errorf("question class = %d, want ClassInternet", q.Class)
	}
}

func TestBuildBrowseQuery(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)
	c.Start()
	defer c.Stop()

	err := c.Browse("_http._tcp.local.", func(err error, resp *BrowseResponse) {}, nil)
	if err != nil {
		t.Fatalf("Browse: %v", err)
	}

	if len(sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(sent))
	}

	msg := sent[0]
	offset := HeaderSize
	_, newOffset, _ := ReadName(msg, offset)
	var q Question
	q.UnmarshalBinary(msg[newOffset:])
	if q.Type != RRTypePtr {
		t.Errorf("question type = %d, want RRTypePtr(%d)", q.Type, RRTypePtr)
	}
}

func TestBuildServiceQuery(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)
	c.Start()
	defer c.Stop()

	err := c.ResolveService("My Server", "_http._tcp.local.", func(err error, resp *ServiceResponse) {}, nil)
	if err != nil {
		t.Fatalf("ResolveService: %v", err)
	}

	if len(sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(sent))
	}

	msg := sent[0]
	offset := HeaderSize
	name, newOffset, _ := ReadName(msg, offset)
	if name != "My Server._http._tcp.local." {
		t.Errorf("question name = %q, want %q", name, "My Server._http._tcp.local.")
	}
	var q Question
	q.UnmarshalBinary(msg[newOffset:])
	if q.Type != RRTypeSrv {
		t.Errorf("question type = %d, want RRTypeSrv(%d)", q.Type, RRTypeSrv)
	}
}

func TestBuildQueryNoRecursion(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)
	c.Start()
	defer c.Stop()

	cfg := QueryConfig{
		ServerAddr:    testServerAddr(),
		RecursionFlag: NoRecursion,
	}
	err := c.ResolveAddress("host.example.com.", func(err error, resp *AddressResponse) {}, &cfg)
	if err != nil {
		t.Fatalf("ResolveAddress: %v", err)
	}

	var h Header
	h.UnmarshalBinary(sent[0])
	if h.IsRecursionDesired() {
		t.Error("RD should not be set when NoRecursion is specified")
	}
}

// ---------------------------------------------------------------------------
// Full round-trip tests
// ---------------------------------------------------------------------------

func TestResolveAddressRoundTrip(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)
	c.Start()
	defer c.Stop()

	hostname := "host.example.com."
	expectedAddr := testAddr(1)

	var gotErr error
	var gotResp *AddressResponse
	done := make(chan struct{})

	err := c.ResolveAddress(hostname, func(err error, resp *AddressResponse) {
		gotErr = err
		gotResp = resp
		close(done)
	}, nil)
	if err != nil {
		t.Fatalf("ResolveAddress: %v", err)
	}

	// Extract message ID from sent query.
	mid := extractMessageID(sent[0])

	// Build and inject a response.
	question := buildQuestion(hostname, RRTypeAaaa)
	answer := appendAaaaRecord(nil, hostname, expectedAddr, 300)
	resp := buildDNSResponse(mid, RcodeSuccess, 1, 1, 0, 0, question, answer, nil, nil)

	c.HandleUDPReceive(resp, testServerAddr(), DefaultServerPort)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("callback not called within timeout")
	}

	if gotErr != nil {
		t.Errorf("callback err = %v, want nil", gotErr)
	}
	if gotResp == nil {
		t.Fatal("callback resp is nil")
	}

	addr, ttl, err := gotResp.GetAddress(0)
	if err != nil {
		t.Fatalf("GetAddress(0): %v", err)
	}
	if addr != expectedAddr {
		t.Errorf("addr = %v, want %v", addr, expectedAddr)
	}
	if ttl != 300 {
		t.Errorf("ttl = %d, want 300", ttl)
	}
}

func TestBrowseRoundTrip(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)
	c.Start()
	defer c.Stop()

	serviceName := "_http._tcp.local."
	inst1 := "Server A._http._tcp.local."
	inst2 := "Server B._http._tcp.local."

	var gotErr error
	var gotResp *BrowseResponse
	done := make(chan struct{})

	err := c.Browse(serviceName, func(err error, resp *BrowseResponse) {
		gotErr = err
		gotResp = resp
		close(done)
	}, nil)
	if err != nil {
		t.Fatalf("Browse: %v", err)
	}

	mid := extractMessageID(sent[0])

	question := buildQuestion(serviceName, RRTypePtr)
	var answer []byte
	answer = appendPtrRecord(answer, serviceName, inst1, 4500)
	answer = appendPtrRecord(answer, serviceName, inst2, 4500)
	resp := buildDNSResponse(mid, RcodeSuccess, 1, 2, 0, 0, question, answer, nil, nil)

	c.HandleUDPReceive(resp, testServerAddr(), DefaultServerPort)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("callback not called within timeout")
	}

	if gotErr != nil {
		t.Errorf("callback err = %v, want nil", gotErr)
	}
	if gotResp == nil {
		t.Fatal("callback resp is nil")
	}

	label0, err := gotResp.GetServiceInstance(0)
	if err != nil {
		t.Fatalf("GetServiceInstance(0): %v", err)
	}
	if label0 != "Server A" {
		t.Errorf("instance[0] = %q, want %q", label0, "Server A")
	}

	label1, err := gotResp.GetServiceInstance(1)
	if err != nil {
		t.Fatalf("GetServiceInstance(1): %v", err)
	}
	if label1 != "Server B" {
		t.Errorf("instance[1] = %q, want %q", label1, "Server B")
	}
}

func TestResolveServiceRoundTrip(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)
	c.Start()
	defer c.Stop()

	serviceName := "_http._tcp.local."
	instanceLabel := "My Server"
	instanceName := instanceLabel + "." + serviceName
	hostName := "myhost.local."
	hostAddr := testAddr(99)
	txtData := []byte{3, 'a', '=', 'b'}

	var gotErr error
	var gotResp *ServiceResponse
	done := make(chan struct{})

	err := c.ResolveService(instanceLabel, serviceName, func(err error, resp *ServiceResponse) {
		gotErr = err
		gotResp = resp
		close(done)
	}, nil)
	if err != nil {
		t.Fatalf("ResolveService: %v", err)
	}

	mid := extractMessageID(sent[0])

	question := buildQuestion(instanceName, RRTypeSrv)
	var answer []byte
	answer = appendSrvRecord(answer, instanceName, hostName, 443, 10, 5, 300)
	answer = appendTxtRecord(answer, instanceName, txtData, 300)
	additional := appendAaaaRecord(nil, hostName, hostAddr, 300)
	resp := buildDNSResponse(mid, RcodeSuccess, 1, 2, 0, 1, question, answer, nil, additional)

	c.HandleUDPReceive(resp, testServerAddr(), DefaultServerPort)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("callback not called within timeout")
	}

	if gotErr != nil {
		t.Errorf("callback err = %v, want nil", gotErr)
	}
	if gotResp == nil {
		t.Fatal("callback resp is nil")
	}

	info, err := gotResp.GetServiceInfo()
	if err != nil {
		t.Fatalf("GetServiceInfo: %v", err)
	}

	if info.HostName != hostName {
		t.Errorf("HostName = %q, want %q", info.HostName, hostName)
	}
	if info.Port != 443 {
		t.Errorf("Port = %d, want 443", info.Port)
	}
	if info.Priority != 10 {
		t.Errorf("Priority = %d, want 10", info.Priority)
	}
	if info.Weight != 5 {
		t.Errorf("Weight = %d, want 5", info.Weight)
	}
	if info.HostAddress != hostAddr {
		t.Errorf("HostAddress = %v, want %v", info.HostAddress, hostAddr)
	}
	if string(info.TxtData) != string(txtData) {
		t.Errorf("TxtData = %v, want %v", info.TxtData, txtData)
	}
}

// ---------------------------------------------------------------------------
// Error handling tests
// ---------------------------------------------------------------------------

func TestResponseNXDomain(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)
	c.Start()
	defer c.Stop()

	hostname := "nonexistent.example.com."

	var gotErr error
	done := make(chan struct{})

	c.ResolveAddress(hostname, func(err error, resp *AddressResponse) {
		gotErr = err
		close(done)
	}, nil)

	mid := extractMessageID(sent[0])
	question := buildQuestion(hostname, RRTypeAaaa)
	resp := buildDNSResponse(mid, RcodeNameError, 1, 0, 0, 0, question, nil, nil, nil)

	c.HandleUDPReceive(resp, testServerAddr(), DefaultServerPort)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("callback not called")
	}

	if gotErr != errors.ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", gotErr)
	}
}

func TestResponseServerFailure(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)
	c.Start()
	defer c.Stop()

	hostname := "host.example.com."

	var gotErr error
	done := make(chan struct{})

	c.ResolveAddress(hostname, func(err error, resp *AddressResponse) {
		gotErr = err
		close(done)
	}, nil)

	mid := extractMessageID(sent[0])
	question := buildQuestion(hostname, RRTypeAaaa)
	resp := buildDNSResponse(mid, RcodeServerFailure, 1, 0, 0, 0, question, nil, nil, nil)

	c.HandleUDPReceive(resp, testServerAddr(), DefaultServerPort)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("callback not called")
	}

	if gotErr != errors.ErrFailed {
		t.Errorf("err = %v, want ErrFailed", gotErr)
	}
}

func TestResponseTruncatedDropped(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)
	c.Start()

	callbackCount := 0
	var callbackErr error
	c.ResolveAddress("host.example.com.", func(err error, resp *AddressResponse) {
		callbackCount++
		callbackErr = err
	}, nil)

	mid := extractMessageID(sent[0])

	// Build a truncated response.
	var h Header
	h.MessageID = mid
	h.SetType(TypeResponse)
	h.SetOpCode(OpcodeQuery)
	h.SetTruncated(true)
	h.SetResponseCode(RcodeSuccess)
	h.QDCount = 0
	hdr := h.MarshalBinary()

	c.HandleUDPReceive(hdr[:], testServerAddr(), DefaultServerPort)

	// Query should still be pending — truncated responses are dropped.
	c.Stop()

	if callbackCount != 1 {
		t.Errorf("callback count = %d, want 1 (only from Stop)", callbackCount)
	}
	if callbackErr != errors.ErrAbort {
		t.Errorf("callback err = %v, want ErrAbort (from Stop)", callbackErr)
	}
}

func TestResponseWrongMessageID(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)
	c.Start()

	callbackCount := 0
	var callbackErr error
	c.ResolveAddress("host.example.com.", func(err error, resp *AddressResponse) {
		callbackCount++
		callbackErr = err
	}, nil)

	hostname := "host.example.com."
	// Use a different message ID.
	question := buildQuestion(hostname, RRTypeAaaa)
	answer := appendAaaaRecord(nil, hostname, testAddr(1), 300)
	resp := buildDNSResponse(0xFFFF, RcodeSuccess, 1, 1, 0, 0, question, answer, nil, nil)

	c.HandleUDPReceive(resp, testServerAddr(), DefaultServerPort)

	// Query should still be pending — wrong message ID was ignored.
	c.Stop()

	if callbackCount != 1 {
		t.Errorf("callback count = %d, want 1 (only from Stop)", callbackCount)
	}
	if callbackErr != errors.ErrAbort {
		t.Errorf("callback err = %v, want ErrAbort (from Stop)", callbackErr)
	}
}

func TestResponseTooShortDropped(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)
	c.Start()

	callbackCalled := false
	c.ResolveAddress("host.example.com.", func(err error, resp *AddressResponse) {
		callbackCalled = true
	}, nil)

	c.HandleUDPReceive([]byte{0x00, 0x01}, testServerAddr(), DefaultServerPort)

	// The query is still pending (short message was ignored).
	// Stop will call callback with ErrAbort, but that's expected.
	c.Stop()

	// callbackCalled should be true (from Stop's abort), not from the short message.
	// We verify by checking that Stop produced the call, not HandleUDPReceive.
	if !callbackCalled {
		t.Error("callback should have been called by Stop")
	}
}

// ---------------------------------------------------------------------------
// Retry / Timeout tests
// ---------------------------------------------------------------------------

func TestQueryRetransmission(t *testing.T) {
	var sent [][]byte
	c, tc := newTestClient(&sent)

	// Use 1ms timeout so retransmit time is quickly in the past.
	cfg := DefaultQueryConfig()
	cfg.ServerAddr = testServerAddr()
	cfg.ResponseTimeout = 1
	cfg.MaxTxAttempts = 3
	c.SetDefaultConfig(cfg)
	c.Start()
	defer c.Stop()

	c.ResolveAddress("host.example.com.", func(err error, resp *AddressResponse) {}, nil)

	if len(sent) != 1 {
		t.Fatalf("initial: sent %d, want 1", len(sent))
	}

	// Wait for retransmit time to pass, then fire the mock timer.
	time.Sleep(5 * time.Millisecond)
	tc.fire()

	if len(sent) != 2 {
		t.Fatalf("after first timer: sent %d, want 2", len(sent))
	}

	// Both messages should have the same message ID.
	mid1 := extractMessageID(sent[0])
	mid2 := extractMessageID(sent[1])
	if mid1 != mid2 {
		t.Errorf("retransmit message ID mismatch: %d vs %d", mid1, mid2)
	}
}

func TestQueryTimeout(t *testing.T) {
	var sent [][]byte
	c, tc := newTestClient(&sent)

	cfg := DefaultQueryConfig()
	cfg.ServerAddr = testServerAddr()
	cfg.ResponseTimeout = 1
	cfg.MaxTxAttempts = 2
	c.SetDefaultConfig(cfg)
	c.Start()
	defer c.Stop()

	var gotErr error
	done := make(chan struct{})

	c.ResolveAddress("host.example.com.", func(err error, resp *AddressResponse) {
		gotErr = err
		close(done)
	}, nil)

	// Wait for retransmit time to pass, then fire: causes retransmit.
	time.Sleep(5 * time.Millisecond)
	tc.fire()

	// Wait again and fire: all attempts exhausted -> timeout.
	time.Sleep(5 * time.Millisecond)
	tc.fire()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("callback not called after timeout")
	}

	if gotErr != errors.ErrResponseTimeout {
		t.Errorf("err = %v, want ErrResponseTimeout", gotErr)
	}

	if len(sent) != 2 {
		t.Errorf("sent %d messages, want 2 (initial + 1 retransmit)", len(sent))
	}
}

// ---------------------------------------------------------------------------
// Multiple concurrent queries
// ---------------------------------------------------------------------------

func TestMultipleConcurrentQueries(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)
	c.Start()
	defer c.Stop()

	host1 := "host1.example.com."
	host2 := "host2.example.com."
	addr1 := testAddr(1)
	addr2 := testAddr(2)

	var gotErr1, gotErr2 error
	var gotResp1 *AddressResponse
	var gotResp2 *AddressResponse
	done1 := make(chan struct{})
	done2 := make(chan struct{})

	c.ResolveAddress(host1, func(err error, resp *AddressResponse) {
		gotErr1 = err
		gotResp1 = resp
		close(done1)
	}, nil)

	c.ResolveAddress(host2, func(err error, resp *AddressResponse) {
		gotErr2 = err
		gotResp2 = resp
		close(done2)
	}, nil)

	if len(sent) != 2 {
		t.Fatalf("sent %d messages, want 2", len(sent))
	}

	mid1 := extractMessageID(sent[0])
	mid2 := extractMessageID(sent[1])

	if mid1 == mid2 {
		t.Error("concurrent queries should have different message IDs")
	}

	// Respond to query 2 first.
	q2 := buildQuestion(host2, RRTypeAaaa)
	a2 := appendAaaaRecord(nil, host2, addr2, 120)
	resp2 := buildDNSResponse(mid2, RcodeSuccess, 1, 1, 0, 0, q2, a2, nil, nil)
	c.HandleUDPReceive(resp2, testServerAddr(), DefaultServerPort)

	select {
	case <-done2:
	case <-time.After(time.Second):
		t.Fatal("callback2 not called")
	}

	// Query 1 should still be pending.
	select {
	case <-done1:
		t.Fatal("callback1 should not be called yet")
	default:
	}

	// Now respond to query 1.
	q1 := buildQuestion(host1, RRTypeAaaa)
	a1 := appendAaaaRecord(nil, host1, addr1, 60)
	resp1 := buildDNSResponse(mid1, RcodeSuccess, 1, 1, 0, 0, q1, a1, nil, nil)
	c.HandleUDPReceive(resp1, testServerAddr(), DefaultServerPort)

	select {
	case <-done1:
	case <-time.After(time.Second):
		t.Fatal("callback1 not called")
	}

	if gotErr1 != nil || gotErr2 != nil {
		t.Errorf("errors: %v, %v", gotErr1, gotErr2)
	}

	a, _, _ := gotResp1.GetAddress(0)
	if a != addr1 {
		t.Errorf("resp1 addr = %v, want %v", a, addr1)
	}
	a, _, _ = gotResp2.GetAddress(0)
	if a != addr2 {
		t.Errorf("resp2 addr = %v, want %v", a, addr2)
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestStopCancelsMultipleQueries(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)
	c.Start()

	count := 0
	cb := func(err error, resp *AddressResponse) {
		count++
		if err != errors.ErrAbort {
			t.Errorf("callback err = %v, want ErrAbort", err)
		}
	}

	c.ResolveAddress("a.example.com.", cb, nil)
	c.ResolveAddress("b.example.com.", cb, nil)
	c.ResolveAddress("c.example.com.", cb, nil)

	c.Stop()

	if count != 3 {
		t.Errorf("callback count = %d, want 3", count)
	}
}

func TestNoRecursionFlagInQuery(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)
	// Set default to NoRecursion.
	c.SetDefaultConfig(QueryConfig{
		ServerAddr:    testServerAddr(),
		RecursionFlag: NoRecursion,
	})
	c.Start()
	defer c.Stop()

	c.ResolveAddress("host.example.com.", func(err error, resp *AddressResponse) {}, nil)

	var h Header
	h.UnmarshalBinary(sent[0])
	if h.IsRecursionDesired() {
		t.Error("RD should not be set")
	}
}

func TestSenderErrorReturned(t *testing.T) {
	tc := newMockTimerControl()
	sender := func(data []byte, peerAddr ip6.Address, peerPort uint16) error {
		return errors.ErrFailed
	}
	cfg := DefaultQueryConfig()
	cfg.ServerAddr = testServerAddr()
	c := NewClient(sender, WithAfterFunc(tc.afterFunc), WithDefaultConfig(cfg))
	c.Start()
	defer c.Stop()

	err := c.ResolveAddress("host.example.com.", func(err error, resp *AddressResponse) {
		t.Error("callback should not be called on sender error")
	}, nil)

	if err != errors.ErrFailed {
		t.Errorf("err = %v, want ErrFailed", err)
	}
}

func TestResponseQueryNotAResponse(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)
	c.Start()

	callbackCount := 0
	var callbackErr error
	c.ResolveAddress("host.example.com.", func(err error, resp *AddressResponse) {
		callbackCount++
		callbackErr = err
	}, nil)

	mid := extractMessageID(sent[0])

	// Send a message that is a query (not a response) with matching ID.
	var h Header
	h.MessageID = mid
	h.SetType(TypeQuery) // Not a response!
	h.SetOpCode(OpcodeQuery)
	hdr := h.MarshalBinary()
	c.HandleUDPReceive(hdr[:], testServerAddr(), DefaultServerPort)

	// Query should still be pending (not finalized by HandleUDPReceive).
	// Stop will finalize it with ErrAbort.
	c.Stop()

	if callbackCount != 1 {
		t.Errorf("callback count = %d, want 1 (only from Stop)", callbackCount)
	}
	if callbackErr != errors.ErrAbort {
		t.Errorf("callback err = %v, want ErrAbort (from Stop, not from HandleUDPReceive)", callbackErr)
	}
}

func TestBrowseTimeoutWithRetransmit(t *testing.T) {
	var sent [][]byte
	c, tc := newTestClient(&sent)

	cfg := DefaultQueryConfig()
	cfg.ServerAddr = testServerAddr()
	cfg.ResponseTimeout = 1
	cfg.MaxTxAttempts = 2
	c.SetDefaultConfig(cfg)
	c.Start()
	defer c.Stop()

	var gotErr error
	done := make(chan struct{})

	c.Browse("_http._tcp.local.", func(err error, resp *BrowseResponse) {
		gotErr = err
		close(done)
	}, nil)

	// Fire timer twice with small delays: retransmit, then timeout.
	time.Sleep(5 * time.Millisecond)
	tc.fire()
	time.Sleep(5 * time.Millisecond)
	tc.fire()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("callback not called")
	}

	if gotErr != errors.ErrResponseTimeout {
		t.Errorf("err = %v, want ErrResponseTimeout", gotErr)
	}
	if len(sent) != 2 {
		t.Errorf("sent %d, want 2", len(sent))
	}
}

func TestServiceResponseNoTxt(t *testing.T) {
	// Service response with SRV but no TXT record should still work.
	instanceName := "svc._tcp.local."
	hostName := "h.local."
	hostAddr := testAddr(50)

	question := buildQuestion(instanceName, RRTypeSrv)
	answer := appendSrvRecord(nil, instanceName, hostName, 80, 0, 0, 120)
	additional := appendAaaaRecord(nil, hostName, hostAddr, 120)

	data := buildDNSResponse(0x0010, RcodeSuccess, 1, 1, 0, 1, question, answer, nil, additional)

	sr := &ServiceResponse{}
	sr.data = data
	sr.queryName = instanceName
	sr.populateFrom(data)

	info, err := sr.GetServiceInfo()
	if err != nil {
		t.Fatalf("GetServiceInfo: %v", err)
	}

	if info.HostName != hostName {
		t.Errorf("HostName = %q, want %q", info.HostName, hostName)
	}
	if info.Port != 80 {
		t.Errorf("Port = %d, want 80", info.Port)
	}
	if info.TxtData != nil {
		t.Errorf("TxtData should be nil when no TXT record, got %v", info.TxtData)
	}
	if info.TxtDataTTL != 0 {
		t.Errorf("TxtDataTTL = %d, want 0", info.TxtDataTTL)
	}
}

func TestServiceResponseNoHostAddress(t *testing.T) {
	// Service response with SRV but no AAAA in additional.
	instanceName := "svc._tcp.local."
	hostName := "h.local."

	question := buildQuestion(instanceName, RRTypeSrv)
	answer := appendSrvRecord(nil, instanceName, hostName, 80, 0, 0, 120)

	data := buildDNSResponse(0x0011, RcodeSuccess, 1, 1, 0, 0, question, answer, nil, nil)

	sr := &ServiceResponse{}
	sr.data = data
	sr.queryName = instanceName
	sr.populateFrom(data)

	info, err := sr.GetServiceInfo()
	if err != nil {
		t.Fatalf("GetServiceInfo: %v", err)
	}

	if info.HostName != hostName {
		t.Errorf("HostName = %q, want %q", info.HostName, hostName)
	}
	if info.HostAddress != (ip6.Address{}) {
		t.Errorf("HostAddress should be zero, got %v", info.HostAddress)
	}
}

func TestMultipleAddressesInResponse(t *testing.T) {
	hostname := "multi.example.com."
	addr0 := testAddr(10)
	addr1 := testAddr(20)
	addr2 := testAddr(30)

	question := buildQuestion(hostname, RRTypeAaaa)
	var answer []byte
	answer = appendAaaaRecord(answer, hostname, addr0, 100)
	answer = appendAaaaRecord(answer, hostname, addr1, 200)
	answer = appendAaaaRecord(answer, hostname, addr2, 300)

	data := buildDNSResponse(0x0020, RcodeSuccess, 1, 3, 0, 0, question, answer, nil, nil)

	ar := &AddressResponse{}
	ar.data = data
	ar.queryName = hostname
	ar.populateFrom(data)

	addrs := make([]ip6.Address, 0)
	for i := 0; ; i++ {
		a, _, err := ar.GetAddress(i)
		if err == errors.ErrNotFound {
			break
		}
		if err != nil {
			t.Fatalf("GetAddress(%d): %v", i, err)
		}
		addrs = append(addrs, a)
	}

	if len(addrs) != 3 {
		t.Fatalf("got %d addresses, want 3", len(addrs))
	}
	if addrs[0] != addr0 || addrs[1] != addr1 || addrs[2] != addr2 {
		t.Errorf("addresses = %v, want %v", addrs, []ip6.Address{addr0, addr1, addr2})
	}
}

func TestResponseRefusedError(t *testing.T) {
	var sent [][]byte
	c, _ := newTestClient(&sent)
	c.Start()
	defer c.Stop()

	hostname := "host.example.com."
	var gotErr error
	done := make(chan struct{})

	c.ResolveAddress(hostname, func(err error, resp *AddressResponse) {
		gotErr = err
		close(done)
	}, nil)

	mid := extractMessageID(sent[0])
	question := buildQuestion(hostname, RRTypeAaaa)
	resp := buildDNSResponse(mid, RcodeRefused, 1, 0, 0, 0, question, nil, nil, nil)

	c.HandleUDPReceive(resp, testServerAddr(), DefaultServerPort)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("callback not called")
	}

	if gotErr != errors.ErrSecurity {
		t.Errorf("err = %v, want ErrSecurity", gotErr)
	}
}
