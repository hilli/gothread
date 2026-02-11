// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package dnssdserver

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Mock resolver
// ---------------------------------------------------------------------------

type mockResolver struct {
	services     map[string][]string             // serviceType → instance names
	instances    map[string]*ServiceInstanceInfo // "instance.serviceType" → info
	hosts        map[string]*HostInfo            // hostname → info
	serviceTypes []string
	browseErr    error
	resolveErr   error
	hostErr      error
	typesErr     error
}

func newMockResolver() *mockResolver {
	return &mockResolver{
		services:  make(map[string][]string),
		instances: make(map[string]*ServiceInstanceInfo),
		hosts:     make(map[string]*HostInfo),
	}
}

func (m *mockResolver) BrowseServices(serviceType string) ([]string, error) {
	if m.browseErr != nil {
		return nil, m.browseErr
	}
	instances, ok := m.services[serviceType]
	if !ok {
		return nil, fmt.Errorf("service type not found: %s", serviceType)
	}
	return instances, nil
}

func (m *mockResolver) ResolveService(instanceName, serviceType string) (*ServiceInstanceInfo, error) {
	if m.resolveErr != nil {
		return nil, m.resolveErr
	}
	key := instanceName + "." + serviceType
	info, ok := m.instances[key]
	if !ok {
		return nil, fmt.Errorf("service not found: %s", key)
	}
	return info, nil
}

func (m *mockResolver) ResolveHost(hostname string) (*HostInfo, error) {
	if m.hostErr != nil {
		return nil, m.hostErr
	}
	info, ok := m.hosts[hostname]
	if !ok {
		return nil, fmt.Errorf("host not found: %s", hostname)
	}
	return info, nil
}

func (m *mockResolver) GetAllServiceTypes() ([]string, error) {
	if m.typesErr != nil {
		return nil, m.typesErr
	}
	return m.serviceTypes, nil
}

func (m *mockResolver) addService(instanceName, serviceType string, info *ServiceInstanceInfo) {
	m.services[serviceType] = append(m.services[serviceType], instanceName)
	m.instances[instanceName+"."+serviceType] = info
	// Track service types.
	found := false
	for _, t := range m.serviceTypes {
		if t == serviceType {
			found = true
			break
		}
	}
	if !found {
		m.serviceTypes = append(m.serviceTypes, serviceType)
	}
}

func (m *mockResolver) addHost(hostname string, info *HostInfo) {
	m.hosts[hostname] = info
}

// ---------------------------------------------------------------------------
// Helper: build a DNS query message
// ---------------------------------------------------------------------------

func buildQuery(id uint16, questions []DnsQuestion) []byte {
	buf := make([]byte, 0, 256)

	var header [headerSize]byte
	binary.BigEndian.PutUint16(header[0:2], id)
	flags := uint16(0) | flagRD // Standard query with RD set.
	binary.BigEndian.PutUint16(header[2:4], flags)
	binary.BigEndian.PutUint16(header[4:6], uint16(len(questions)))
	buf = append(buf, header[:]...)

	for _, q := range questions {
		buf = append(buf, EncodeDnsName(q.Name)...)
		var qfield [4]byte
		binary.BigEndian.PutUint16(qfield[0:2], q.Type)
		binary.BigEndian.PutUint16(qfield[2:4], q.Class)
		buf = append(buf, qfield[:]...)
	}

	return buf
}

// parseResponseHeader extracts key fields from a DNS response.
func parseResponseHeader(data []byte) (id uint16, rcode uint8, qdCount, anCount, nsCount, arCount uint16, err error) {
	if len(data) < headerSize {
		return 0, 0, 0, 0, 0, 0, fmt.Errorf("response too short")
	}
	id = binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	rcode = uint8(flags & flagRCode)
	qdCount = binary.BigEndian.Uint16(data[4:6])
	anCount = binary.BigEndian.Uint16(data[6:8])
	nsCount = binary.BigEndian.Uint16(data[8:10])
	arCount = binary.BigEndian.Uint16(data[10:12])
	return
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestParseDnsQuerySingleQuestion(t *testing.T) {
	questions := []DnsQuestion{
		{Name: "_http._tcp.default.service.arpa.", Type: TypePTR, Class: ClassIN},
	}
	data := buildQuery(0x1234, questions)

	q, err := ParseDnsQuery(data)
	if err != nil {
		t.Fatalf("ParseDnsQuery failed: %v", err)
	}
	if q.ID != 0x1234 {
		t.Errorf("ID = %d, want 0x1234", q.ID)
	}
	if !q.IsRecursionDesired {
		t.Error("IsRecursionDesired = false, want true")
	}
	if len(q.Questions) != 1 {
		t.Fatalf("len(Questions) = %d, want 1", len(q.Questions))
	}
	if q.Questions[0].Name != "_http._tcp.default.service.arpa." {
		t.Errorf("Question.Name = %q, want %q", q.Questions[0].Name, "_http._tcp.default.service.arpa.")
	}
	if q.Questions[0].Type != TypePTR {
		t.Errorf("Question.Type = %d, want %d", q.Questions[0].Type, TypePTR)
	}
}

func TestParseDnsQueryMultipleQuestions(t *testing.T) {
	questions := []DnsQuestion{
		{Name: "My Service._http._tcp.default.service.arpa.", Type: TypeSRV, Class: ClassIN},
		{Name: "My Service._http._tcp.default.service.arpa.", Type: TypeTXT, Class: ClassIN},
	}
	data := buildQuery(0x5678, questions)

	q, err := ParseDnsQuery(data)
	if err != nil {
		t.Fatalf("ParseDnsQuery failed: %v", err)
	}
	if len(q.Questions) != 2 {
		t.Fatalf("len(Questions) = %d, want 2", len(q.Questions))
	}
	if q.Questions[0].Type != TypeSRV {
		t.Errorf("Questions[0].Type = %d, want %d (SRV)", q.Questions[0].Type, TypeSRV)
	}
	if q.Questions[1].Type != TypeTXT {
		t.Errorf("Questions[1].Type = %d, want %d (TXT)", q.Questions[1].Type, TypeTXT)
	}
}

func TestBuildDnsResponsePTR(t *testing.T) {
	q := &DnsQuery{
		ID:                 0xABCD,
		IsRecursionDesired: true,
		Questions: []DnsQuestion{
			{Name: "_http._tcp.default.service.arpa.", Type: TypePTR, Class: ClassIN},
		},
	}

	answers := []DnsRecord{
		{
			Name:  "_http._tcp.default.service.arpa.",
			Type:  TypePTR,
			Class: ClassIN,
			TTL:   4500,
			RData: EncodePtrRData("My Service._http._tcp.default.service.arpa."),
		},
	}

	resp, err := BuildDnsResponse(q, answers, nil, nil, RCodeSuccess)
	if err != nil {
		t.Fatalf("BuildDnsResponse failed: %v", err)
	}

	id, rcode, qdCount, anCount, _, _, err := parseResponseHeader(resp)
	if err != nil {
		t.Fatalf("parseResponseHeader: %v", err)
	}
	if id != 0xABCD {
		t.Errorf("id = 0x%04X, want 0xABCD", id)
	}
	if rcode != RCodeSuccess {
		t.Errorf("rcode = %d, want %d", rcode, RCodeSuccess)
	}
	if qdCount != 1 {
		t.Errorf("qdCount = %d, want 1", qdCount)
	}
	if anCount != 1 {
		t.Errorf("anCount = %d, want 1", anCount)
	}

	// Verify QR bit is set (response).
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&flagQR == 0 {
		t.Error("QR bit not set in response")
	}
}

func TestBuildDnsResponseSRV_TXT_AAAA(t *testing.T) {
	q := &DnsQuery{
		ID: 0x1111,
		Questions: []DnsQuestion{
			{Name: "My Service._http._tcp.default.service.arpa.", Type: TypeSRV, Class: ClassIN},
		},
	}

	addr := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	answers := []DnsRecord{
		{
			Name:  "My Service._http._tcp.default.service.arpa.",
			Type:  TypeSRV,
			Class: ClassIN,
			TTL:   120,
			RData: EncodeSrvRData(0, 0, 8080, "my-host.default.service.arpa."),
		},
		{
			Name:  "My Service._http._tcp.default.service.arpa.",
			Type:  TypeTXT,
			Class: ClassIN,
			TTL:   120,
			RData: EncodeTxtRData([]byte{3, 'k', '=', 'v'}),
		},
	}
	additional := []DnsRecord{
		{
			Name:  "my-host.default.service.arpa.",
			Type:  TypeAAAA,
			Class: ClassIN,
			TTL:   120,
			RData: EncodeAAAARData(addr),
		},
	}

	resp, err := BuildDnsResponse(q, answers, nil, additional, RCodeSuccess)
	if err != nil {
		t.Fatalf("BuildDnsResponse failed: %v", err)
	}

	_, rcode, _, anCount, _, arCount, err := parseResponseHeader(resp)
	if err != nil {
		t.Fatalf("parseResponseHeader: %v", err)
	}
	if rcode != RCodeSuccess {
		t.Errorf("rcode = %d, want %d", rcode, RCodeSuccess)
	}
	if anCount != 2 {
		t.Errorf("anCount = %d, want 2", anCount)
	}
	if arCount != 1 {
		t.Errorf("arCount = %d, want 1", arCount)
	}
}

func TestServiceTypeEnumeration(t *testing.T) {
	resolver := newMockResolver()
	resolver.serviceTypes = []string{"_http._tcp", "_mqtt._tcp"}
	resolver.services["_http._tcp"] = []string{"Web Server"}
	resolver.services["_mqtt._tcp"] = []string{"Broker"}

	srv := NewServer(resolver)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}

	q := buildQuery(0x2222, []DnsQuestion{
		{Name: ServicesDnssdUdpFull, Type: TypePTR, Class: ClassIN},
	})

	resp, err := srv.HandleQuery(q)
	if err != nil {
		t.Fatal(err)
	}

	_, rcode, _, anCount, _, _, err := parseResponseHeader(resp)
	if err != nil {
		t.Fatal(err)
	}
	if rcode != RCodeSuccess {
		t.Errorf("rcode = %d, want %d", rcode, RCodeSuccess)
	}
	if anCount != 2 {
		t.Errorf("anCount = %d, want 2 (one PTR per service type)", anCount)
	}
}

func TestHostResolution(t *testing.T) {
	resolver := newMockResolver()
	addr := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	resolver.addHost("my-host.default.service.arpa", &HostInfo{
		FullName:  "my-host.default.service.arpa.",
		Addresses: [][16]byte{addr},
		TTL:       300,
	})

	srv := NewServer(resolver)
	_ = srv.Start()

	q := buildQuery(0x3333, []DnsQuestion{
		{Name: "my-host.default.service.arpa.", Type: TypeAAAA, Class: ClassIN},
	})

	resp, err := srv.HandleQuery(q)
	if err != nil {
		t.Fatal(err)
	}

	_, rcode, _, anCount, _, _, err := parseResponseHeader(resp)
	if err != nil {
		t.Fatal(err)
	}
	if rcode != RCodeSuccess {
		t.Errorf("rcode = %d, want %d", rcode, RCodeSuccess)
	}
	if anCount != 1 {
		t.Errorf("anCount = %d, want 1", anCount)
	}
}

func TestNameErrorForUnknownService(t *testing.T) {
	resolver := newMockResolver()
	srv := NewServer(resolver)
	_ = srv.Start()

	q := buildQuery(0x4444, []DnsQuestion{
		{Name: "_unknown._tcp.default.service.arpa.", Type: TypePTR, Class: ClassIN},
	})

	resp, err := srv.HandleQuery(q)
	if err != nil {
		t.Fatal(err)
	}

	_, rcode, _, _, _, _, err := parseResponseHeader(resp)
	if err != nil {
		t.Fatal(err)
	}
	if rcode != RCodeNameError {
		t.Errorf("rcode = %d, want %d (NXDOMAIN)", rcode, RCodeNameError)
	}
}

func TestDnsNameEncodingDecodingRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string // What the decoded name should be (always with trailing dot).
	}{
		{"simple", "example.com.", "example.com."},
		{"with trailing dot", "foo.bar.baz.", "foo.bar.baz."},
		{"without trailing dot", "foo.bar.baz", "foo.bar.baz."},
		{"single label", "localhost.", "localhost."},
		{"long label", strings.Repeat("a", 63) + ".com.", strings.Repeat("a", 63) + ".com."},
		{"service name", "_http._tcp.default.service.arpa.", "_http._tcp.default.service.arpa."},
		{"instance name", "My Service._http._tcp.default.service.arpa.", "My Service._http._tcp.default.service.arpa."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeDnsName(tt.input)
			decoded, endOffset, err := DecodeDnsName(encoded, 0)
			if err != nil {
				t.Fatalf("DecodeDnsName failed: %v", err)
			}
			if endOffset != len(encoded) {
				t.Errorf("endOffset = %d, want %d", endOffset, len(encoded))
			}
			if decoded != tt.expected {
				t.Errorf("decoded = %q, want %q", decoded, tt.expected)
			}
		})
	}
}

func TestDnsNamePointerCompression(t *testing.T) {
	// Build data with a name, then a pointer back to it.
	name := EncodeDnsName("example.com.")
	data := make([]byte, len(name)+2)
	copy(data, name)

	// Append a pointer to offset 0.
	data[len(name)] = 0xC0
	data[len(name)+1] = 0x00

	decoded, endOffset, err := DecodeDnsName(data, len(name))
	if err != nil {
		t.Fatalf("DecodeDnsName with pointer failed: %v", err)
	}
	if endOffset != len(name)+2 {
		t.Errorf("endOffset = %d, want %d", endOffset, len(name)+2)
	}
	if decoded != "example.com." {
		t.Errorf("decoded = %q, want %q", decoded, "example.com.")
	}
}

func TestServerLifecycle(t *testing.T) {
	resolver := newMockResolver()
	srv := NewServer(resolver)

	if srv.IsRunning() {
		t.Error("server should not be running before Start")
	}
	if srv.IsEnabled() {
		t.Error("server should not be enabled before Start")
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if !srv.IsRunning() {
		t.Error("server should be running after Start")
	}
	if !srv.IsEnabled() {
		t.Error("server should be enabled after Start")
	}

	srv.Stop()
	if srv.IsRunning() {
		t.Error("server should not be running after Stop")
	}

	// Start again.
	_ = srv.Start()
	if !srv.IsRunning() {
		t.Error("server should be running after second Start")
	}

	srv.SetEnabled(false)
	if srv.IsEnabled() {
		t.Error("server should not be enabled after SetEnabled(false)")
	}
	if srv.IsRunning() {
		t.Error("server should not be running after SetEnabled(false)")
	}
}

func TestCounterTracking(t *testing.T) {
	resolver := newMockResolver()
	resolver.services["_http._tcp"] = []string{"Web"}
	resolver.instances["Web._http._tcp"] = &ServiceInstanceInfo{
		FullName:  "Web._http._tcp.default.service.arpa.",
		HostName:  "host.default.service.arpa.",
		Port:      80,
		TTL:       120,
		Addresses: [][16]byte{{0x20, 0x01}},
	}
	resolver.serviceTypes = []string{"_http._tcp"}

	srv := NewServer(resolver)
	_ = srv.Start()

	// Successful browse.
	q := buildQuery(1, []DnsQuestion{
		{Name: "_http._tcp.default.service.arpa.", Type: TypePTR, Class: ClassIN},
	})
	_, _ = srv.HandleQuery(q)

	// NXDOMAIN.
	q2 := buildQuery(2, []DnsQuestion{
		{Name: "_nope._tcp.default.service.arpa.", Type: TypePTR, Class: ClassIN},
	})
	_, _ = srv.HandleQuery(q2)

	c := srv.GetCounters()
	if c.TotalQueries != 2 {
		t.Errorf("TotalQueries = %d, want 2", c.TotalQueries)
	}
	if c.SuccessResponses != 1 {
		t.Errorf("SuccessResponses = %d, want 1", c.SuccessResponses)
	}
	if c.NameErrors != 1 {
		t.Errorf("NameErrors = %d, want 1", c.NameErrors)
	}
	if c.BrowseQueries != 2 {
		t.Errorf("BrowseQueries = %d, want 2", c.BrowseQueries)
	}

	srv.ResetCounters()
	c = srv.GetCounters()
	if c.TotalQueries != 0 {
		t.Errorf("TotalQueries after reset = %d, want 0", c.TotalQueries)
	}
}

func TestMockResolverIntegration(t *testing.T) {
	resolver := newMockResolver()

	addr1 := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	addr2 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	txtData := []byte{5, 'h', 'i', '=', 'y', 'o'}

	resolver.addService("My Printer", "_ipp._tcp", &ServiceInstanceInfo{
		FullName:  "My Printer._ipp._tcp.default.service.arpa.",
		HostName:  "printer.default.service.arpa.",
		Port:      631,
		Priority:  0,
		Weight:    0,
		TxtData:   txtData,
		Addresses: [][16]byte{addr1, addr2},
		TTL:       120,
	})
	resolver.addHost("printer.default.service.arpa", &HostInfo{
		FullName:  "printer.default.service.arpa.",
		Addresses: [][16]byte{addr1, addr2},
		TTL:       300,
	})

	srv := NewServer(resolver)
	_ = srv.Start()

	// Browse.
	q := buildQuery(10, []DnsQuestion{
		{Name: "_ipp._tcp.default.service.arpa.", Type: TypePTR, Class: ClassIN},
	})
	resp, err := srv.HandleQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	_, rcode, _, anCount, _, arCount, _ := parseResponseHeader(resp)
	if rcode != RCodeSuccess {
		t.Errorf("browse rcode = %d, want %d", rcode, RCodeSuccess)
	}
	if anCount < 1 {
		t.Errorf("browse anCount = %d, want >= 1", anCount)
	}
	// Additional section should have SRV + TXT + AAAA for the single instance.
	if arCount < 1 {
		t.Errorf("browse arCount = %d, want >= 1 (additional records)", arCount)
	}

	// Resolve (SRV).
	q2 := buildQuery(11, []DnsQuestion{
		{Name: "My Printer._ipp._tcp.default.service.arpa.", Type: TypeSRV, Class: ClassIN},
	})
	resp2, err := srv.HandleQuery(q2)
	if err != nil {
		t.Fatal(err)
	}
	_, rcode, _, anCount, _, arCount, _ = parseResponseHeader(resp2)
	if rcode != RCodeSuccess {
		t.Errorf("resolve rcode = %d, want %d", rcode, RCodeSuccess)
	}
	if anCount != 1 {
		t.Errorf("resolve anCount = %d, want 1 (SRV)", anCount)
	}
	if arCount != 2 {
		t.Errorf("resolve arCount = %d, want 2 (AAAA records)", arCount)
	}

	// Resolve (TXT).
	q3 := buildQuery(12, []DnsQuestion{
		{Name: "My Printer._ipp._tcp.default.service.arpa.", Type: TypeTXT, Class: ClassIN},
	})
	resp3, err := srv.HandleQuery(q3)
	if err != nil {
		t.Fatal(err)
	}
	_, rcode, _, anCount, _, _, _ = parseResponseHeader(resp3)
	if rcode != RCodeSuccess {
		t.Errorf("txt rcode = %d, want %d", rcode, RCodeSuccess)
	}
	if anCount != 1 {
		t.Errorf("txt anCount = %d, want 1", anCount)
	}

	// Host resolve.
	q4 := buildQuery(13, []DnsQuestion{
		{Name: "printer.default.service.arpa.", Type: TypeAAAA, Class: ClassIN},
	})
	resp4, err := srv.HandleQuery(q4)
	if err != nil {
		t.Fatal(err)
	}
	_, rcode, _, anCount, _, _, _ = parseResponseHeader(resp4)
	if rcode != RCodeSuccess {
		t.Errorf("host rcode = %d, want %d", rcode, RCodeSuccess)
	}
	if anCount != 2 {
		t.Errorf("host anCount = %d, want 2", anCount)
	}
}

func TestANYQueryServiceInstance(t *testing.T) {
	resolver := newMockResolver()
	addr := [16]byte{0x20, 0x01, 0x0d, 0xb8}
	resolver.addService("Svc", "_http._tcp", &ServiceInstanceInfo{
		FullName:  "Svc._http._tcp.default.service.arpa.",
		HostName:  "h.default.service.arpa.",
		Port:      80,
		TTL:       60,
		TxtData:   []byte{0},
		Addresses: [][16]byte{addr},
	})

	srv := NewServer(resolver)
	_ = srv.Start()

	q := buildQuery(20, []DnsQuestion{
		{Name: "Svc._http._tcp.default.service.arpa.", Type: TypeANY, Class: ClassIN},
	})

	resp, err := srv.HandleQuery(q)
	if err != nil {
		t.Fatal(err)
	}

	_, rcode, _, anCount, _, arCount, _ := parseResponseHeader(resp)
	if rcode != RCodeSuccess {
		t.Errorf("rcode = %d, want %d", rcode, RCodeSuccess)
	}
	// ANY for a service instance should return SRV + TXT in answer.
	if anCount < 2 {
		t.Errorf("anCount = %d, want >= 2 (SRV + TXT)", anCount)
	}
	// AAAA in additional.
	if arCount < 1 {
		t.Errorf("arCount = %d, want >= 1", arCount)
	}
}

func TestFormatErrorMalformedQuery(t *testing.T) {
	srv := NewServer(newMockResolver())
	_ = srv.Start()

	// Too short to be a valid DNS message.
	resp, err := srv.HandleQuery([]byte{0x00, 0x01, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	_, rcode, _, _, _, _, err := parseResponseHeader(resp)
	if err != nil {
		t.Fatal(err)
	}
	if rcode != RCodeFormatError {
		t.Errorf("rcode = %d, want %d (FormatError)", rcode, RCodeFormatError)
	}
}

func TestEmptyQueryNoQuestions(t *testing.T) {
	srv := NewServer(newMockResolver())
	_ = srv.Start()

	// Valid header with 0 questions.
	q := buildQuery(0x9999, nil)

	resp, err := srv.HandleQuery(q)
	if err != nil {
		t.Fatal(err)
	}

	_, rcode, _, _, _, _, err := parseResponseHeader(resp)
	if err != nil {
		t.Fatal(err)
	}
	if rcode != RCodeFormatError {
		t.Errorf("rcode = %d, want %d (FormatError for empty query)", rcode, RCodeFormatError)
	}
}

func TestHandleDnsQueryOverCoap(t *testing.T) {
	resolver := newMockResolver()
	resolver.services["_coap._udp"] = []string{"CoAP Svc"}
	resolver.instances["CoAP Svc._coap._udp"] = &ServiceInstanceInfo{
		FullName: "CoAP Svc._coap._udp.default.service.arpa.",
		HostName: "node.default.service.arpa.",
		Port:     5683,
		TTL:      120,
	}
	resolver.serviceTypes = []string{"_coap._udp"}

	srv := NewServer(resolver)
	_ = srv.Start()

	q := buildQuery(30, []DnsQuestion{
		{Name: "_coap._udp.default.service.arpa.", Type: TypePTR, Class: ClassIN},
	})

	resp, err := srv.HandleDnsQueryOverCoap(q)
	if err != nil {
		t.Fatal(err)
	}

	_, rcode, _, anCount, _, _, _ := parseResponseHeader(resp)
	if rcode != RCodeSuccess {
		t.Errorf("rcode = %d, want %d", rcode, RCodeSuccess)
	}
	if anCount < 1 {
		t.Errorf("anCount = %d, want >= 1", anCount)
	}
}

func TestExtractInstanceAndServiceType(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantInst    string
		wantSvcType string
		wantOk      bool
	}{
		{
			name:        "standard instance",
			input:       "My Printer._ipp._tcp.default.service.arpa.",
			wantInst:    "My Printer",
			wantSvcType: "_ipp._tcp",
			wantOk:      true,
		},
		{
			name:        "instance with dots",
			input:       "My.Service._http._tcp.default.service.arpa.",
			wantInst:    "My.Service",
			wantSvcType: "_http._tcp",
			wantOk:      true, // dots in instance name are valid; service type starts at underscore labels
		},
		{
			name:   "service type only (no instance)",
			input:  "_http._tcp.default.service.arpa.",
			wantOk: false,
		},
		{
			name:   "wrong domain",
			input:  "foo._bar._tcp.other.domain.",
			wantOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst, svcType, ok := extractInstanceAndServiceType(tt.input)
			if ok != tt.wantOk {
				t.Errorf("ok = %v, want %v (inst=%q, svcType=%q)", ok, tt.wantOk, inst, svcType)
				return
			}
			if ok {
				if inst != tt.wantInst {
					t.Errorf("instance = %q, want %q", inst, tt.wantInst)
				}
				if svcType != tt.wantSvcType {
					t.Errorf("serviceType = %q, want %q", svcType, tt.wantSvcType)
				}
			}
		})
	}
}

func TestQueryTypeConstants(t *testing.T) {
	if QueryTypeNone != 0 {
		t.Errorf("QueryTypeNone = %d, want 0", QueryTypeNone)
	}
	if QueryTypeBrowse != 1 {
		t.Errorf("QueryTypeBrowse = %d, want 1", QueryTypeBrowse)
	}
	if QueryTypeResolve != 2 {
		t.Errorf("QueryTypeResolve = %d, want 2", QueryTypeResolve)
	}
	if QueryTypeResolveHost != 3 {
		t.Errorf("QueryTypeResolveHost = %d, want 3", QueryTypeResolveHost)
	}
}

func TestResponseCodeConstants(t *testing.T) {
	tests := []struct {
		name string
		code uint8
		want uint8
	}{
		{"Success", RCodeSuccess, 0},
		{"FormatError", RCodeFormatError, 1},
		{"ServerFailure", RCodeServerFailure, 2},
		{"NameError", RCodeNameError, 3},
		{"NotImplemented", RCodeNotImplemented, 4},
		{"Refused", RCodeRefused, 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.code != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.code, tt.want)
			}
		})
	}
}

func TestEncodeAAAARData(t *testing.T) {
	addr := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	data := EncodeAAAARData(addr)
	if len(data) != 16 {
		t.Fatalf("AAAA RDATA len = %d, want 16", len(data))
	}
	for i, b := range addr {
		if data[i] != b {
			t.Errorf("data[%d] = 0x%02x, want 0x%02x", i, data[i], b)
		}
	}
}

func TestEncodeSrvRData(t *testing.T) {
	data := EncodeSrvRData(10, 20, 8080, "host.example.com.")
	if len(data) < 6 {
		t.Fatal("SRV RDATA too short")
	}
	priority := binary.BigEndian.Uint16(data[0:2])
	weight := binary.BigEndian.Uint16(data[2:4])
	port := binary.BigEndian.Uint16(data[4:6])

	if priority != 10 {
		t.Errorf("priority = %d, want 10", priority)
	}
	if weight != 20 {
		t.Errorf("weight = %d, want 20", weight)
	}
	if port != 8080 {
		t.Errorf("port = %d, want 8080", port)
	}

	// Decode the target host name.
	name, _, err := DecodeDnsName(data, 6)
	if err != nil {
		t.Fatalf("failed to decode target: %v", err)
	}
	if name != "host.example.com." {
		t.Errorf("target = %q, want %q", name, "host.example.com.")
	}
}

func TestEncodeTxtRData(t *testing.T) {
	// Non-empty.
	txt := []byte{5, 'h', 'e', 'l', 'l', 'o'}
	data := EncodeTxtRData(txt)
	if len(data) != len(txt) {
		t.Errorf("TXT RDATA len = %d, want %d", len(data), len(txt))
	}

	// Empty.
	empty := EncodeTxtRData(nil)
	if len(empty) != 1 || empty[0] != 0 {
		t.Errorf("empty TXT RDATA = %v, want [0]", empty)
	}
}

func TestDefaultDomainConstant(t *testing.T) {
	if DefaultDomain != "default.service.arpa." {
		t.Errorf("DefaultDomain = %q, want %q", DefaultDomain, "default.service.arpa.")
	}
}

func TestServicesDnssdUdpConstant(t *testing.T) {
	if ServicesDnssdUdp != "_services._dns-sd._udp" {
		t.Errorf("ServicesDnssdUdp = %q, want %q", ServicesDnssdUdp, "_services._dns-sd._udp")
	}
}

func TestBrowseQueryWithAdditionalRecords(t *testing.T) {
	resolver := newMockResolver()
	addr := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	resolver.addService("OnlyOne", "_mqtt._tcp", &ServiceInstanceInfo{
		FullName:  "OnlyOne._mqtt._tcp.default.service.arpa.",
		HostName:  "broker.default.service.arpa.",
		Port:      1883,
		TTL:       60,
		TxtData:   []byte{0},
		Addresses: [][16]byte{addr},
	})

	srv := NewServer(resolver)
	_ = srv.Start()

	q := buildQuery(40, []DnsQuestion{
		{Name: "_mqtt._tcp.default.service.arpa.", Type: TypePTR, Class: ClassIN},
	})

	resp, err := srv.HandleQuery(q)
	if err != nil {
		t.Fatal(err)
	}

	_, rcode, _, anCount, _, arCount, _ := parseResponseHeader(resp)
	if rcode != RCodeSuccess {
		t.Errorf("rcode = %d, want %d", rcode, RCodeSuccess)
	}
	if anCount != 1 {
		t.Errorf("anCount = %d, want 1", anCount)
	}
	// Single instance → additional records (SRV + TXT + AAAA).
	if arCount != 3 {
		t.Errorf("arCount = %d, want 3 (SRV+TXT+AAAA)", arCount)
	}
}

func TestDnsNameEncodingEmptyName(t *testing.T) {
	encoded := EncodeDnsName("")
	if len(encoded) != 1 || encoded[0] != 0 {
		t.Errorf("EncodeDnsName(\"\") = %v, want [0]", encoded)
	}

	decoded, end, err := DecodeDnsName(encoded, 0)
	if err != nil {
		t.Fatalf("DecodeDnsName failed: %v", err)
	}
	if decoded != "." {
		t.Errorf("decoded empty = %q, want %q", decoded, ".")
	}
	if end != 1 {
		t.Errorf("end = %d, want 1", end)
	}
}

func TestDnsNameDecodeTruncated(t *testing.T) {
	data := []byte{3, 'f', 'o'} // Label says 3 bytes but only 2 available.
	_, _, err := DecodeDnsName(data, 0)
	if err == nil {
		t.Error("expected error for truncated name")
	}
}

func TestDnsNameDecodePointerLoop(t *testing.T) {
	// Self-referencing pointer at offset 0.
	data := []byte{0xC0, 0x00}
	_, _, err := DecodeDnsName(data, 0)
	if err == nil {
		t.Error("expected error for pointer loop")
	}
}

func TestANYQueryHost(t *testing.T) {
	resolver := newMockResolver()
	addr := [16]byte{0x20, 0x01}
	resolver.addHost("myhost.default.service.arpa", &HostInfo{
		FullName:  "myhost.default.service.arpa.",
		Addresses: [][16]byte{addr},
		TTL:       60,
	})

	srv := NewServer(resolver)
	_ = srv.Start()

	q := buildQuery(50, []DnsQuestion{
		{Name: "myhost.default.service.arpa.", Type: TypeANY, Class: ClassIN},
	})

	resp, err := srv.HandleQuery(q)
	if err != nil {
		t.Fatal(err)
	}

	_, rcode, _, anCount, _, _, _ := parseResponseHeader(resp)
	if rcode != RCodeSuccess {
		t.Errorf("rcode = %d, want %d", rcode, RCodeSuccess)
	}
	if anCount < 1 {
		t.Errorf("anCount = %d, want >= 1", anCount)
	}
}
