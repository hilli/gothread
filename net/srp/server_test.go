// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the conditions in the
// LICENSE file are met.

package srp

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/hilli/gothread/crypto/ecdsa"
	"github.com/hilli/gothread/crypto/sha256"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/dns"
	"github.com/hilli/gothread/net/ip6"
)

// -------------------------------------------------------
// Server test helpers
// -------------------------------------------------------

// serverTestEnv provides a controlled test environment for the SRP server.
type serverTestEnv struct {
	t         *testing.T
	server    *Server
	now       time.Time
	timer     *fakeTimer
	keyPair   *ecdsa.KeyPair
	responses []serverResponse
}

type serverResponse struct {
	data []byte
	peer ip6.SockAddr
}

func newServerTestEnv(t *testing.T) *serverTestEnv {
	t.Helper()

	kp, err := ecdsa.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	env := &serverTestEnv{
		t:       t,
		now:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		keyPair: kp,
	}

	env.server = NewServer(
		WithServerNow(func() time.Time { return env.now }),
		WithServerAfterFunc(func(d time.Duration, f func()) Timer {
			env.timer = &fakeTimer{delay: d, fn: f}
			return env.timer
		}),
		WithServerResponder(func(data []byte, peer ip6.SockAddr) {
			cp := make([]byte, len(data))
			copy(cp, data)
			env.responses = append(env.responses, serverResponse{data: cp, peer: peer})
		}),
	)

	return env
}

// startServer enables and starts the server.
func (env *serverTestEnv) startServer() {
	env.t.Helper()
	env.server.Enable(true)
	if err := env.server.Start(53535); err != nil {
		env.t.Fatalf("Start: %v", err)
	}
}

// defaultPeer returns a default test peer address.
func defaultPeer() ip6.SockAddr {
	var addr ip6.Address
	addr[15] = 1
	return ip6.SockAddr{Address: addr, Port: 12345}
}

// buildSrpUpdate constructs a valid DNS Update message for SRP with SIG(0).
// Returns the raw bytes ready to be passed to ProcessMessage.
func (env *serverTestEnv) buildSrpUpdate(opts *updateOpts) []byte {
	env.t.Helper()
	return buildSrpUpdateMessage(env.t, env.keyPair, opts)
}

// updateOpts controls what goes into the SRP update message.
type updateOpts struct {
	msgID      uint16
	domain     string
	hostName   string // e.g., "myhost" (label only, domain appended automatically)
	addresses  []ip6.Address
	services   []testService
	lease      uint32
	keyLease   uint32
	ttl        uint32
	shortLease bool
	deleteHost bool // If true, send lease=0 (host removal).
}

type testService struct {
	instanceLabel string // e.g., "My Printer"
	serviceType   string // e.g., "_ipp._tcp"
	port          uint16
	priority      uint16
	weight        uint16
	txtData       []byte
	subTypes      []string // e.g., ["_print"]
	isDeleted     bool
}

func defaultUpdateOpts() updateOpts {
	var addr ip6.Address
	addr[0] = 0xfd
	addr[15] = 1
	return updateOpts{
		msgID:     0x1234,
		domain:    ServerDefaultDomain,
		hostName:  "myhost",
		addresses: []ip6.Address{addr},
		lease:     7200,
		keyLease:  604800,
		ttl:       3600,
	}
}

// buildSrpUpdateMessage builds a complete DNS Update message with SIG(0).
func buildSrpUpdateMessage(t *testing.T, kp *ecdsa.KeyPair, opts *updateOpts) []byte {
	t.Helper()

	if opts.domain == "" {
		opts.domain = ServerDefaultDomain
	}

	hostFullName := opts.hostName + "." + opts.domain

	data := make([]byte, 0, 512)

	// ---- Header ----
	var header dns.UpdateHeader
	header.MessageID = opts.msgID
	header.SetOpCode(dns.OpcodeUpdate)
	header.SetZoneCount(1)
	// Counts filled in later.

	headerBuf := header.MarshalBinary()
	data = append(data, headerBuf[:]...)

	// ---- Zone section ----
	data, _ = dns.AppendName(data, opts.domain)
	zone := dns.NewZone()
	zoneBuf := zone.MarshalBinary()
	data = append(data, zoneBuf[:]...)

	// ---- Update section ----
	updateCount := uint16(0)

	// Pass 0: PTR records for service discovery.
	for _, svc := range opts.services {
		instanceName := svc.instanceLabel + "." + svc.serviceType + "." + opts.domain
		serviceName := svc.serviceType + "." + opts.domain

		// PTR from service name -> instance name.
		data, _ = dns.AppendName(data, serviceName)
		ptrRdata, _ := dns.AppendName(nil, instanceName)
		var ptrRR dns.ResourceRecord
		if svc.isDeleted {
			ptrRR.Init(dns.RRTypePtr, dns.ClassNone)
		} else {
			ptrRR.Init(dns.RRTypePtr, dns.ClassInternet)
		}
		ptrRR.TTL = opts.ttl
		ptrRR.RDLength = uint16(len(ptrRdata))
		rrBuf := ptrRR.MarshalBinary()
		data = append(data, rrBuf[:]...)
		data = append(data, ptrRdata...)
		updateCount++

		// Sub-type PTRs.
		for _, sub := range svc.subTypes {
			subName := sub + "._sub." + svc.serviceType + "." + opts.domain
			data, _ = dns.AppendName(data, subName)
			subRdata, _ := dns.AppendName(nil, instanceName)
			var subRR dns.ResourceRecord
			subRR.Init(dns.RRTypePtr, dns.ClassInternet)
			subRR.TTL = opts.ttl
			subRR.RDLength = uint16(len(subRdata))
			subBuf := subRR.MarshalBinary()
			data = append(data, subBuf[:]...)
			data = append(data, subRdata...)
			updateCount++
		}
	}

	// Pass 1: Host description.

	// Delete all RRsets for host.
	data, _ = dns.AppendName(data, hostFullName)
	var deleteAllRR dns.ResourceRecord
	deleteAllRR.Init(dns.RRTypeAny, dns.ClassAny)
	deleteAllRR.RDLength = 0
	daBuf := deleteAllRR.MarshalBinary()
	data = append(data, daBuf[:]...)
	updateCount++

	// AAAA records for host addresses.
	for _, addr := range opts.addresses {
		data, _ = dns.AppendName(data, hostFullName)
		var aaaaRR dns.ResourceRecord
		aaaaRR.Init(dns.RRTypeAaaa, dns.ClassInternet)
		aaaaRR.TTL = opts.ttl
		aaaaRR.RDLength = 16
		aaaaBuf := aaaaRR.MarshalBinary()
		data = append(data, aaaaBuf[:]...)
		data = append(data, addr[:]...)
		updateCount++
	}

	// KEY record.
	pubKey := kp.GetPublicKey()
	data, _ = dns.AppendName(data, hostFullName)
	var keyRR dns.ResourceRecord
	keyRR.Init(dns.RRTypeKey, dns.ClassInternet)
	keyRR.TTL = opts.ttl
	keyRR.RDLength = uint16(dns.KeyRecordFixedSize + ecdsa.PublicKeySize)
	keyBuf := keyRR.MarshalBinary()
	data = append(data, keyBuf[:]...)
	// Key RDATA: flags(2) + protocol(1) + algorithm(1) + public key(64).
	data = append(data, 0x00, 0x00, 3, dns.KeyAlgorithmEcdsaP256Sha256) // Flags, DNSSEC protocol, ECDSA algorithm.
	data = append(data, pubKey[:]...)
	updateCount++

	// Pass 2: Service descriptions.
	for _, svc := range opts.services {
		instanceName := svc.instanceLabel + "." + svc.serviceType + "." + opts.domain

		// Delete all RRsets for service instance.
		data, _ = dns.AppendName(data, instanceName)
		var svcDeleteRR dns.ResourceRecord
		svcDeleteRR.Init(dns.RRTypeAny, dns.ClassAny)
		svcDeleteRR.RDLength = 0
		sdBuf := svcDeleteRR.MarshalBinary()
		data = append(data, sdBuf[:]...)
		updateCount++

		if !svc.isDeleted {
			// SRV record.
			hostNameEncoded, _ := dns.AppendName(nil, hostFullName)
			data, _ = dns.AppendName(data, instanceName)
			var srvRR dns.ResourceRecord
			srvRR.Init(dns.RRTypeSrv, dns.ClassInternet)
			srvRR.TTL = opts.ttl
			srvRR.RDLength = uint16(dns.SrvRecordFixedSize + len(hostNameEncoded))
			srvBuf := srvRR.MarshalBinary()
			data = append(data, srvBuf[:]...)
			// SRV RDATA: priority(2) + weight(2) + port(2) + target(variable).
			var srvData [6]byte
			binary.BigEndian.PutUint16(srvData[0:2], svc.priority)
			binary.BigEndian.PutUint16(srvData[2:4], svc.weight)
			binary.BigEndian.PutUint16(srvData[4:6], svc.port)
			data = append(data, srvData[:]...)
			data = append(data, hostNameEncoded...)
			updateCount++

			// TXT record.
			txtData := svc.txtData
			if txtData == nil {
				txtData = []byte{0} // empty TXT entry
			}
			data, _ = dns.AppendName(data, instanceName)
			var txtRR dns.ResourceRecord
			txtRR.Init(dns.RRTypeTxt, dns.ClassInternet)
			txtRR.TTL = opts.ttl
			txtRR.RDLength = uint16(len(txtData))
			txtBuf := txtRR.MarshalBinary()
			data = append(data, txtBuf[:]...)
			data = append(data, txtData...)
			updateCount++
		}
	}

	// ---- Additional section (OPT + SIG(0)) ----
	additionalCount := uint16(2)

	// OPT record with lease option.
	data = append(data, 0x00) // root name
	var optRR dns.OptRecord
	optRR.Init()
	optRR.SetUDPPayloadSize(UDPPayloadSize)

	lease := opts.lease
	keyLease := opts.keyLease
	if opts.deleteHost {
		lease = 0
	}

	var leaseOpt dns.LeaseOption
	if opts.shortLease {
		leaseOpt.InitShort(lease)
	} else {
		leaseOpt.InitLong(lease, keyLease)
	}
	leaseOptBuf := leaseOpt.MarshalBinary()
	optRR.RDLength = uint16(len(leaseOptBuf))
	optBuf := optRR.MarshalBinary()
	data = append(data, optBuf[:]...)
	data = append(data, leaseOptBuf...)

	// SIG(0) record.
	sigRecordOffset := len(data)
	data = append(data, 0x00) // root name

	// We need to build the SIG RDATA, then sign.
	// SIG RDATA = fixed(18) + signer name + signature(64).
	signerNameEncoded, _ := dns.AppendName(nil, hostFullName)

	var sigFixedRData [dns.SigRecordFixedSize]byte
	// TypeCovered = 0 (SIG(0)).
	binary.BigEndian.PutUint16(sigFixedRData[0:2], 0)
	sigFixedRData[2] = dns.KeyAlgorithmEcdsaP256Sha256
	sigFixedRData[3] = 0                                // Labels
	binary.BigEndian.PutUint32(sigFixedRData[4:8], 0)   // OriginalTTL
	binary.BigEndian.PutUint32(sigFixedRData[8:12], 0)  // Expiration
	binary.BigEndian.PutUint32(sigFixedRData[12:16], 0) // Inception
	binary.BigEndian.PutUint16(sigFixedRData[16:18], 0) // KeyTag

	sigRDataWithoutSig := make([]byte, 0, dns.SigRecordFixedSize+len(signerNameEncoded))
	sigRDataWithoutSig = append(sigRDataWithoutSig, sigFixedRData[:]...)
	sigRDataWithoutSig = append(sigRDataWithoutSig, signerNameEncoded...)

	// Compute hash for SIG(0): hash(sigRDataWithoutSig + modifiedHeader + bodyAfterHeader).
	var hash sha256.Hash
	var hasher sha256.Sha256
	hasher.Start()

	// 1. SIG RDATA (without signature).
	hasher.Update(sigRDataWithoutSig)

	// 2. Modified DNS header (ARCount decremented by 1).
	// But first, we need to finalize the header counts.
	binary.BigEndian.PutUint16(data[4:6], 1)                 // One zone.
	binary.BigEndian.PutUint16(data[6:8], 0)                 // PrerequisiteCount: 0.
	binary.BigEndian.PutUint16(data[8:10], updateCount)      // UpdateCount
	binary.BigEndian.PutUint16(data[10:12], additionalCount) // ARCount

	modifiedHeader := make([]byte, dns.HeaderSize)
	copy(modifiedHeader, data[:dns.HeaderSize])
	arCount := binary.BigEndian.Uint16(modifiedHeader[10:12])
	binary.BigEndian.PutUint16(modifiedHeader[10:12], arCount-1)
	hasher.Update(modifiedHeader)

	// 3. All bytes from after header up to SIG record.
	hasher.Update(data[dns.HeaderSize:sigRecordOffset])

	hasher.Finish(&hash)

	// Sign.
	sig, err := kp.Sign(hash)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Build complete SIG record.
	sigRDLength := uint16(len(sigRDataWithoutSig) + ecdsa.SignatureSize)
	var sigRR dns.ResourceRecord
	sigRR.Init(dns.RRTypeSig, dns.ClassAny)
	sigRR.RDLength = sigRDLength
	sigRRBuf := sigRR.MarshalBinary()
	data = append(data, sigRRBuf[:]...)
	data = append(data, sigRDataWithoutSig...)
	data = append(data, sig[:]...)

	return data
}

// lastResponse returns the most recent response.
func (env *serverTestEnv) lastResponse() *serverResponse {
	if len(env.responses) == 0 {
		return nil
	}
	return &env.responses[len(env.responses)-1]
}

// parseResponseCode parses the DNS response code from a response.
func parseResponseCode(t *testing.T, data []byte) dns.ResponseCode {
	t.Helper()
	if len(data) < dns.HeaderSize {
		t.Fatalf("response too short: %d bytes", len(data))
	}
	var hdr dns.Header
	if err := hdr.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	return hdr.GetResponseCode()
}

// parseResponseLease parses the lease option from a response (if present).
func parseResponseLease(t *testing.T, data []byte) *dns.LeaseOption {
	t.Helper()
	if len(data) < dns.HeaderSize {
		return nil
	}
	var hdr dns.Header
	if err := hdr.UnmarshalBinary(data); err != nil {
		return nil
	}
	if hdr.ARCount == 0 {
		return nil
	}
	// Skip header, read root name + OPT record.
	offset := dns.HeaderSize
	if offset >= len(data) || data[offset] != 0x00 {
		return nil
	}
	offset++ // skip root name
	if offset+dns.ResourceRecordSize > len(data) {
		return nil
	}
	var optRR dns.OptRecord
	if err := optRR.UnmarshalBinary(data[offset:]); err != nil {
		return nil
	}
	rdataStart := offset + dns.ResourceRecordSize
	rdataEnd := rdataStart + int(optRR.RDLength)
	if rdataEnd > len(data) {
		return nil
	}
	lo, err := dns.FindLeaseOption(data[rdataStart:rdataEnd])
	if err != nil {
		return nil
	}
	return lo
}

// -------------------------------------------------------
// Server lifecycle tests
// -------------------------------------------------------

func TestServerNewServerDefaults(t *testing.T) {
	s := NewServer()
	if s.GetState() != ServerStateDisabled {
		t.Errorf("state = %v, want Disabled", s.GetState())
	}
	if s.GetDomain() != ServerDefaultDomain {
		t.Errorf("domain = %q, want %q", s.GetDomain(), ServerDefaultDomain)
	}
	if s.GetPort() != 0 {
		t.Errorf("port = %d, want 0", s.GetPort())
	}
	tc := s.GetTTLConfig()
	if tc.MinTTL != DefaultMinTTL || tc.MaxTTL != DefaultMaxTTL {
		t.Errorf("ttl config = %+v, unexpected", tc)
	}
	lc := s.GetLeaseConfig()
	if lc.MinLease != DefaultMinLease || lc.MaxLease != DefaultMaxLease {
		t.Errorf("lease config = %+v, unexpected", lc)
	}
}

func TestServerEnableDisable(t *testing.T) {
	s := NewServer()
	s.Enable(true)
	if s.GetState() != ServerStateStopped {
		t.Errorf("state after enable = %v, want Stopped", s.GetState())
	}
	s.Enable(false)
	if s.GetState() != ServerStateDisabled {
		t.Errorf("state after disable = %v, want Disabled", s.GetState())
	}
}

func TestServerStartStop(t *testing.T) {
	env := newServerTestEnv(t)
	env.server.Enable(true)
	if err := env.server.Start(53535); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if env.server.GetState() != ServerStateRunning {
		t.Errorf("state = %v, want Running", env.server.GetState())
	}
	if env.server.GetPort() != 53535 {
		t.Errorf("port = %d, want 53535", env.server.GetPort())
	}
	env.server.Stop()
	if env.server.GetState() != ServerStateStopped {
		t.Errorf("state after stop = %v, want Stopped", env.server.GetState())
	}
	if env.server.GetPort() != 0 {
		t.Errorf("port after stop = %d, want 0", env.server.GetPort())
	}
}

func TestServerStartRequiresStopped(t *testing.T) {
	s := NewServer()
	// Cannot start when disabled.
	if err := s.Start(53535); err != errors.ErrInvalidState {
		t.Errorf("Start when disabled err = %v, want ErrInvalidState", err)
	}
}

func TestServerSetDomainRequiresDisabled(t *testing.T) {
	s := NewServer()
	if err := s.SetDomain("test.arpa."); err != nil {
		t.Fatalf("SetDomain: %v", err)
	}
	if s.GetDomain() != "test.arpa." {
		t.Errorf("domain = %q, want %q", s.GetDomain(), "test.arpa.")
	}
	// Enable -> can't set domain.
	s.Enable(true)
	if err := s.SetDomain("other.arpa."); err != errors.ErrInvalidState {
		t.Errorf("SetDomain when stopped err = %v, want ErrInvalidState", err)
	}
}

func TestServerSetDomainAddsTrailingDot(t *testing.T) {
	s := NewServer()
	if err := s.SetDomain("custom.arpa"); err != nil {
		t.Fatalf("SetDomain: %v", err)
	}
	if s.GetDomain() != "custom.arpa." {
		t.Errorf("domain = %q, want %q", s.GetDomain(), "custom.arpa.")
	}
}

func TestServerSetDomainRejectsEmpty(t *testing.T) {
	s := NewServer()
	if err := s.SetDomain(""); err != errors.ErrInvalidArgs {
		t.Errorf("SetDomain empty err = %v, want ErrInvalidArgs", err)
	}
}

// -------------------------------------------------------
// TTL and Lease config tests
// -------------------------------------------------------

func TestTTLConfigIsValid(t *testing.T) {
	valid := TTLConfig{MinTTL: 10, MaxTTL: 100}
	if !valid.IsValid() {
		t.Error("expected valid")
	}
	invalid := TTLConfig{MinTTL: 100, MaxTTL: 10}
	if invalid.IsValid() {
		t.Error("expected invalid")
	}
}

func TestTTLConfigGrantTTL(t *testing.T) {
	c := TTLConfig{MinTTL: 30, MaxTTL: 3600}

	tests := []struct {
		lease, ttl, want uint32
	}{
		{3600, 1800, 1800}, // Within range, below lease.
		{3600, 7200, 3600}, // TTL capped to lease.
		{3600, 10, 30},     // TTL below min -> clamped to min.
		{3600, 9999, 3600}, // TTL > lease, capped to lease, then within max.
		{20, 3600, 30},     // lease < min TTL, result is min TTL.
	}
	for _, tt := range tests {
		got := c.GrantTTL(tt.lease, tt.ttl)
		if got != tt.want {
			t.Errorf("GrantTTL(lease=%d, ttl=%d) = %d, want %d", tt.lease, tt.ttl, got, tt.want)
		}
	}
}

func TestLeaseConfigIsValid(t *testing.T) {
	valid := DefaultLeaseConfig()
	if !valid.IsValid() {
		t.Error("default lease config should be valid")
	}
	invalid := LeaseConfig{MinLease: 100, MaxLease: 50, MinKeyLease: 100, MaxKeyLease: 200}
	if invalid.IsValid() {
		t.Error("expected invalid when min > max")
	}
	invalid2 := LeaseConfig{MinLease: 30, MaxLease: 100, MinKeyLease: 10, MaxKeyLease: 200}
	if invalid2.IsValid() {
		t.Error("expected invalid when minLease > minKeyLease")
	}
}

func TestLeaseConfigGrantLease(t *testing.T) {
	c := LeaseConfig{MinLease: 30, MaxLease: 3600, MinKeyLease: 30, MaxKeyLease: 86400}

	// Zero -> zero (deletion).
	if got := c.GrantLease(0); got != 0 {
		t.Errorf("GrantLease(0) = %d, want 0", got)
	}
	// Below min -> clamped.
	if got := c.GrantLease(10); got != 30 {
		t.Errorf("GrantLease(10) = %d, want 30", got)
	}
	// Above max -> clamped.
	if got := c.GrantLease(9999); got != 3600 {
		t.Errorf("GrantLease(9999) = %d, want 3600", got)
	}
	// Within range -> passthrough.
	if got := c.GrantLease(100); got != 100 {
		t.Errorf("GrantLease(100) = %d, want 100", got)
	}
	// Key lease zero.
	if got := c.GrantKeyLease(0); got != 0 {
		t.Errorf("GrantKeyLease(0) = %d, want 0", got)
	}
}

func TestServerSetTTLConfig(t *testing.T) {
	s := NewServer()
	valid := TTLConfig{MinTTL: 60, MaxTTL: 7200}
	if err := s.SetTTLConfig(valid); err != nil {
		t.Fatalf("SetTTLConfig: %v", err)
	}
	if got := s.GetTTLConfig(); got != valid {
		t.Errorf("got %+v, want %+v", got, valid)
	}
	// Invalid config rejected.
	invalid := TTLConfig{MinTTL: 100, MaxTTL: 10}
	if err := s.SetTTLConfig(invalid); err != errors.ErrInvalidArgs {
		t.Errorf("SetTTLConfig invalid err = %v, want ErrInvalidArgs", err)
	}
}

func TestServerSetLeaseConfig(t *testing.T) {
	s := NewServer()
	valid := LeaseConfig{MinLease: 60, MaxLease: 7200, MinKeyLease: 60, MaxKeyLease: 86400}
	if err := s.SetLeaseConfig(valid); err != nil {
		t.Fatalf("SetLeaseConfig: %v", err)
	}
	if got := s.GetLeaseConfig(); got != valid {
		t.Errorf("got %+v, want %+v", got, valid)
	}
}

// -------------------------------------------------------
// DNS Update processing tests
// -------------------------------------------------------

func TestServerProcessSimpleRegistration(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	opts := defaultUpdateOpts()
	opts.services = []testService{
		{
			instanceLabel: "My Printer",
			serviceType:   "_ipp._tcp",
			port:          631,
			priority:      0,
			weight:        0,
			txtData:       []byte{0}, // empty TXT
		},
	}

	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	// Should have a success response.
	resp := env.lastResponse()
	if resp == nil {
		t.Fatal("no response received")
	}
	rcode := parseResponseCode(t, resp.data)
	if rcode != dns.RcodeSuccess {
		t.Errorf("response code = %d, want Success(0)", rcode)
	}

	// Should have registered the host.
	hosts := env.server.GetHosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts count = %d, want 1", len(hosts))
	}
	host := hosts[0]
	if !host.Matches("myhost." + ServerDefaultDomain) {
		t.Errorf("host name = %q, unexpected", host.FullName)
	}
	if len(host.Addresses) != 1 {
		t.Errorf("addresses count = %d, want 1", len(host.Addresses))
	}
	if len(host.Services) != 1 {
		t.Fatalf("services count = %d, want 1", len(host.Services))
	}
	svc := host.Services[0]
	if svc.Port != 631 {
		t.Errorf("service port = %d, want 631", svc.Port)
	}
	if svc.IsDeleted {
		t.Error("service should not be deleted")
	}
}

func TestServerProcessRegistrationGrantsLease(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	// Set tight lease config.
	env.server.SetLeaseConfig(LeaseConfig{
		MinLease:    60,
		MaxLease:    3600,
		MinKeyLease: 60,
		MaxKeyLease: 86400,
	})

	opts := defaultUpdateOpts()
	opts.lease = 7200 // Requested: 7200, max=3600 -> will be clamped.
	opts.keyLease = 604800

	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	resp := env.lastResponse()
	if resp == nil {
		t.Fatal("no response received")
	}

	// Since the granted lease differs from requested, response should include lease option.
	lo := parseResponseLease(t, resp.data)
	if lo == nil {
		t.Fatal("expected lease option in response")
	}
	if lo.LeaseInterval != 3600 {
		t.Errorf("granted lease = %d, want 3600", lo.LeaseInterval)
	}

	// Verify host has clamped lease.
	hosts := env.server.GetHosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts count = %d, want 1", len(hosts))
	}
	if hosts[0].Lease != 3600 {
		t.Errorf("host lease = %d, want 3600", hosts[0].Lease)
	}
}

func TestServerProcessHostRemoval(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	// First register a host.
	opts := defaultUpdateOpts()
	opts.services = []testService{
		{instanceLabel: "My Printer", serviceType: "_ipp._tcp", port: 631, txtData: []byte{0}},
	}
	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	hosts := env.server.GetHosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts count after register = %d, want 1", len(hosts))
	}

	// Now remove the host.
	opts.msgID = 0x5678
	opts.deleteHost = true
	opts.keyLease = 604800 // Keep name for key-lease duration.
	data = env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	hosts = env.server.GetHosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts count after removal = %d, want 1 (name retained)", len(hosts))
	}
	if !hosts[0].IsDeleted() {
		t.Error("host should be deleted (lease=0)")
	}
}

func TestServerProcessHostFullRemoval(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	// Register a host.
	opts := defaultUpdateOpts()
	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	// Remove with keyLease=0 (full removal).
	opts.msgID = 0x5678
	opts.deleteHost = true
	opts.keyLease = 0
	data = env.buildSrpUpdate(&opts)

	// For keyLease=0 with short lease, both lease=0 and keyLease=0.
	env.server.ProcessMessage(data, defaultPeer())

	hosts := env.server.GetHosts()
	if len(hosts) != 0 {
		t.Errorf("hosts count after full removal = %d, want 0", len(hosts))
	}
}

func TestServerRejectsWrongDomain(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	opts := defaultUpdateOpts()
	opts.domain = "wrong.arpa."
	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	resp := env.lastResponse()
	if resp == nil {
		t.Fatal("no response received")
	}
	rcode := parseResponseCode(t, resp.data)
	if rcode != dns.RcodeRefused {
		t.Errorf("response code = %d, want Refused(%d)", rcode, dns.RcodeRefused)
	}
}

func TestServerNameConflictDifferentKey(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	// Register with first key.
	opts := defaultUpdateOpts()
	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	hosts := env.server.GetHosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts count = %d, want 1", len(hosts))
	}

	// Try to register same hostname with different key.
	kp2, err := ecdsa.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	env.keyPair = kp2
	opts.msgID = 0xABCD
	data = env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	resp := env.lastResponse()
	if resp == nil {
		t.Fatal("no response received")
	}
	rcode := parseResponseCode(t, resp.data)
	if rcode != dns.RcodeNameExists {
		t.Errorf("response code = %d, want NameExists(%d)", rcode, dns.RcodeNameExists)
	}

	// Original registration should still be there.
	hosts = env.server.GetHosts()
	if len(hosts) != 1 {
		t.Errorf("hosts count = %d, want 1 (original)", len(hosts))
	}
}

func TestServerAllowsRefreshWithSameKey(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	// Register.
	opts := defaultUpdateOpts()
	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	hosts := env.server.GetHosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts count = %d, want 1", len(hosts))
	}

	// Refresh with same key.
	env.now = env.now.Add(100 * time.Second)
	opts.msgID = 0x9999
	data = env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	resp := env.lastResponse()
	if resp == nil {
		t.Fatal("no response received")
	}
	rcode := parseResponseCode(t, resp.data)
	if rcode != dns.RcodeSuccess {
		t.Errorf("response code = %d, want Success", rcode)
	}

	// Should still have exactly 1 host (updated, not duplicated).
	hosts = env.server.GetHosts()
	if len(hosts) != 1 {
		t.Errorf("hosts count after refresh = %d, want 1", len(hosts))
	}
}

func TestServerMultipleServices(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	opts := defaultUpdateOpts()
	opts.services = []testService{
		{instanceLabel: "Printer", serviceType: "_ipp._tcp", port: 631, txtData: []byte{0}},
		{instanceLabel: "Web", serviceType: "_http._tcp", port: 80, txtData: []byte{0}},
	}

	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	hosts := env.server.GetHosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts count = %d, want 1", len(hosts))
	}
	if len(hosts[0].Services) != 2 {
		t.Errorf("services count = %d, want 2", len(hosts[0].Services))
	}
}

func TestServerMultipleAddresses(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	var addr1, addr2 ip6.Address
	addr1[0] = 0xfd
	addr1[15] = 1
	addr2[0] = 0xfd
	addr2[15] = 2

	opts := defaultUpdateOpts()
	opts.addresses = []ip6.Address{addr1, addr2}

	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	hosts := env.server.GetHosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts count = %d, want 1", len(hosts))
	}
	if len(hosts[0].Addresses) != 2 {
		t.Errorf("addresses count = %d, want 2", len(hosts[0].Addresses))
	}
}

func TestServerShortLeaseOption(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	// Set lease config with small max.
	env.server.SetLeaseConfig(LeaseConfig{
		MinLease:    30,
		MaxLease:    3600,
		MinKeyLease: 30,
		MaxKeyLease: 86400,
	})

	opts := defaultUpdateOpts()
	opts.shortLease = true
	opts.lease = 7200

	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	hosts := env.server.GetHosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts count = %d, want 1", len(hosts))
	}
	// With short lease, keyLease = grantedLease.
	if hosts[0].Lease != 3600 {
		t.Errorf("lease = %d, want 3600", hosts[0].Lease)
	}
	if hosts[0].KeyLease != 3600 {
		t.Errorf("keyLease = %d, want 3600 (should match lease for short variant)", hosts[0].KeyLease)
	}
}

// -------------------------------------------------------
// Lease timer tests
// -------------------------------------------------------

func TestServerLeaseExpiration(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	opts := defaultUpdateOpts()
	opts.lease = 100
	opts.keyLease = 200

	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	hosts := env.server.GetHosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts count = %d, want 1", len(hosts))
	}

	// Advance past lease but before key-lease.
	env.now = env.now.Add(101 * time.Second)
	if env.timer != nil {
		env.timer.Fire()
	}

	hosts = env.server.GetHosts()
	if len(hosts) != 1 {
		t.Fatalf("hosts count = %d, want 1 (name retained)", len(hosts))
	}
	if !hosts[0].IsDeleted() {
		t.Error("host should be deleted (lease expired)")
	}

	// Advance past key-lease.
	env.now = env.now.Add(200 * time.Second)
	if env.timer != nil {
		env.timer.Fire()
	}

	hosts = env.server.GetHosts()
	if len(hosts) != 0 {
		t.Errorf("hosts count = %d, want 0 (key-lease expired)", len(hosts))
	}
}

func TestServerServiceLeaseExpiration(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	opts := defaultUpdateOpts()
	opts.lease = 100
	opts.keyLease = 200
	opts.services = []testService{
		{instanceLabel: "Svc1", serviceType: "_test._tcp", port: 8080, txtData: []byte{0}},
	}

	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	hosts := env.server.GetHosts()
	if len(hosts) != 1 || len(hosts[0].Services) != 1 {
		t.Fatalf("expected 1 host with 1 service")
	}

	// Expire lease.
	env.now = env.now.Add(101 * time.Second)
	if env.timer != nil {
		env.timer.Fire()
	}

	hosts = env.server.GetHosts()
	if len(hosts) != 1 {
		t.Fatal("expected host still present")
	}
	if !hosts[0].Services[0].IsDeleted {
		t.Error("service should be deleted after lease expiry")
	}
}

// -------------------------------------------------------
// Service update handler tests
// -------------------------------------------------------

func TestServerWithServiceUpdateHandler(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	var handlerCalled bool
	var handlerID uint32
	var handlerHost *RegHost

	env.server.SetServiceUpdateHandler(func(id uint32, host *RegHost, timeout time.Duration) {
		handlerCalled = true
		handlerID = id
		handlerHost = host
	})

	opts := defaultUpdateOpts()
	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	if !handlerCalled {
		t.Fatal("handler was not called")
	}
	if handlerHost == nil {
		t.Fatal("handler received nil host")
	}
	if handlerHost.FullName == "" {
		t.Error("handler host has empty name")
	}

	// No response yet (waiting for handler result).
	if len(env.responses) != 0 {
		t.Errorf("responses count = %d, want 0 (waiting for handler)", len(env.responses))
	}

	// Host should not be committed yet.
	hosts := env.server.GetHosts()
	if len(hosts) != 0 {
		t.Errorf("hosts count = %d, want 0 (not yet committed)", len(hosts))
	}

	// Complete the handler.
	env.server.HandleServiceUpdateResult(handlerID, nil)

	// Now response should be sent and host committed.
	if len(env.responses) == 0 {
		t.Fatal("no response after handler completion")
	}
	rcode := parseResponseCode(t, env.responses[0].data)
	if rcode != dns.RcodeSuccess {
		t.Errorf("response code = %d, want Success", rcode)
	}

	hosts = env.server.GetHosts()
	if len(hosts) != 1 {
		t.Errorf("hosts count = %d, want 1", len(hosts))
	}
}

func TestServerHandlerReturnsError(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	var handlerID uint32

	env.server.SetServiceUpdateHandler(func(id uint32, host *RegHost, timeout time.Duration) {
		handlerID = id
	})

	opts := defaultUpdateOpts()
	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	// Handler returns error.
	env.server.HandleServiceUpdateResult(handlerID, errors.ErrFailed)

	if len(env.responses) == 0 {
		t.Fatal("no response after handler error")
	}
	rcode := parseResponseCode(t, env.responses[0].data)
	if rcode != dns.RcodeRefused {
		t.Errorf("response code = %d, want Refused(%d)", rcode, dns.RcodeRefused)
	}

	// Host should not be committed.
	hosts := env.server.GetHosts()
	if len(hosts) != 0 {
		t.Errorf("hosts count = %d, want 0", len(hosts))
	}
}

func TestServerHandlerTimeout(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	env.server.SetServiceUpdateHandler(func(id uint32, host *RegHost, timeout time.Duration) {
		// Don't call HandleServiceUpdateResult - simulate timeout.
	})

	opts := defaultUpdateOpts()
	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	// No response yet.
	if len(env.responses) != 0 {
		t.Errorf("responses = %d before timeout, want 0", len(env.responses))
	}

	// Fire the timeout timer.
	env.now = env.now.Add(DefaultHandlerTimeout + time.Millisecond)
	if env.timer != nil {
		env.timer.Fire()
	}

	// Should get a response with timeout error.
	if len(env.responses) == 0 {
		t.Fatal("no response after timeout")
	}
	rcode := parseResponseCode(t, env.responses[0].data)
	if rcode != dns.RcodeRefused {
		t.Errorf("response code = %d, want Refused (timeout -> ErrResponseTimeout -> Refused)", rcode)
	}
}

func TestServerIgnoresLateHandlerResult(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	var handlerID uint32

	env.server.SetServiceUpdateHandler(func(id uint32, host *RegHost, timeout time.Duration) {
		handlerID = id
	})

	opts := defaultUpdateOpts()
	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	// Complete first, then try to complete again (late/stale).
	env.server.HandleServiceUpdateResult(handlerID, nil)
	initialResponseCount := len(env.responses)

	// Late callback should be silently ignored.
	env.server.HandleServiceUpdateResult(handlerID, nil)
	if len(env.responses) != initialResponseCount {
		t.Errorf("responses count changed after late callback: %d -> %d",
			initialResponseCount, len(env.responses))
	}
}

// -------------------------------------------------------
// Error response code mapping tests
// -------------------------------------------------------

func TestErrorToDnsResponseCode(t *testing.T) {
	tests := []struct {
		err  error
		want dns.ResponseCode
	}{
		{nil, dns.RcodeSuccess},
		{errors.ErrNoBufs, dns.RcodeServerFailure},
		{errors.ErrParse, dns.RcodeFormatError},
		{errors.ErrDuplicated, dns.RcodeNameExists},
		{errors.ErrFailed, dns.RcodeRefused},
		{errors.ErrSecurity, dns.RcodeRefused},
		{errors.ErrInvalidArgs, dns.RcodeRefused},
	}
	for _, tt := range tests {
		got := errorToDNSResponseCode(tt.err)
		if got != tt.want {
			t.Errorf("errorToDNSResponseCode(%v) = %d, want %d", tt.err, got, tt.want)
		}
	}
}

// -------------------------------------------------------
// Response counter tests
// -------------------------------------------------------

func TestServerResponseCounters(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	// Successful registration.
	opts := defaultUpdateOpts()
	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	counters := env.server.GetResponseCounters()
	if counters.Success != 1 {
		t.Errorf("success count = %d, want 1", counters.Success)
	}

	// Wrong domain -> refused.
	opts.msgID = 0x2222
	opts.domain = "wrong.arpa."
	data = env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	counters = env.server.GetResponseCounters()
	if counters.Refused != 1 {
		t.Errorf("refused count = %d, want 1", counters.Refused)
	}
}

// -------------------------------------------------------
// Helper function tests
// -------------------------------------------------------

func TestExtractInstanceLabel(t *testing.T) {
	tests := []struct {
		name    string
		want    string
		wantErr bool
	}{
		{"My Printer._ipp._tcp.default.service.arpa.", "My Printer", false},
		{"web._http._tcp.default.service.arpa.", "web", false},
		{"nodots", "", true},
		{"", "", true},
	}
	for _, tt := range tests {
		got, err := extractInstanceLabel(tt.name)
		if (err != nil) != tt.wantErr {
			t.Errorf("extractInstanceLabel(%q) err = %v, wantErr %v", tt.name, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("extractInstanceLabel(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestDeriveServiceName(t *testing.T) {
	tests := []struct {
		instanceName string
		want         string
	}{
		{"My Printer._ipp._tcp.default.service.arpa.", "_ipp._tcp.default.service.arpa."},
		{"web._http._tcp.default.service.arpa.", "_http._tcp.default.service.arpa."},
	}
	for _, tt := range tests {
		got := deriveServiceName(tt.instanceName)
		if got != tt.want {
			t.Errorf("deriveServiceName(%q) = %q, want %q", tt.instanceName, got, tt.want)
		}
	}
}

func TestIsNameUnderDomain(t *testing.T) {
	tests := []struct {
		name, domain string
		want         bool
	}{
		{"myhost.default.service.arpa.", "default.service.arpa.", true},
		{"default.service.arpa.", "default.service.arpa.", true},
		{"myhost.other.arpa.", "default.service.arpa.", false},
		{"MYHOST.DEFAULT.SERVICE.ARPA.", "default.service.arpa.", true},
	}
	for _, tt := range tests {
		got := isNameUnderDomain(tt.name, tt.domain)
		if got != tt.want {
			t.Errorf("isNameUnderDomain(%q, %q) = %v, want %v", tt.name, tt.domain, got, tt.want)
		}
	}
}

func TestIsServiceInstanceName(t *testing.T) {
	tests := []struct {
		name, domain string
		want         bool
	}{
		{"My Printer._ipp._tcp.default.service.arpa.", "default.service.arpa.", true},
		{"myhost.default.service.arpa.", "default.service.arpa.", false},
		{"default.service.arpa.", "default.service.arpa.", false},
	}
	for _, tt := range tests {
		got := isServiceInstanceName(tt.name, tt.domain)
		if got != tt.want {
			t.Errorf("isServiceInstanceName(%q, %q) = %v, want %v", tt.name, tt.domain, got, tt.want)
		}
	}
}

func TestParseSubType(t *testing.T) {
	tests := []struct {
		name      string
		wantIsSub bool
		wantLabel string
	}{
		{"_print._sub._ipp._tcp.default.service.arpa.", true, "_print"},
		{"_ipp._tcp.default.service.arpa.", false, ""},
		{"myhost.default.service.arpa.", false, ""},
	}
	for _, tt := range tests {
		gotIsSub, gotLabel := parseSubType(tt.name)
		if gotIsSub != tt.wantIsSub || gotLabel != tt.wantLabel {
			t.Errorf("parseSubType(%q) = (%v, %q), want (%v, %q)",
				tt.name, gotIsSub, gotLabel, tt.wantIsSub, tt.wantLabel)
		}
	}
}

func TestClampU32(t *testing.T) {
	tests := []struct {
		v, min, max, want uint32
	}{
		{50, 10, 100, 50},
		{5, 10, 100, 10},
		{150, 10, 100, 100},
		{10, 10, 10, 10},
	}
	for _, tt := range tests {
		got := clampU32(tt.v, tt.min, tt.max)
		if got != tt.want {
			t.Errorf("clampU32(%d, %d, %d) = %d, want %d", tt.v, tt.min, tt.max, got, tt.want)
		}
	}
}

// -------------------------------------------------------
// RegHost / RegService tests
// -------------------------------------------------------

func TestRegHostIsDeleted(t *testing.T) {
	h := &RegHost{Lease: 100}
	if h.IsDeleted() {
		t.Error("should not be deleted with lease > 0")
	}
	h.Lease = 0
	if !h.IsDeleted() {
		t.Error("should be deleted with lease = 0")
	}
}

func TestRegHostGetExpireTime(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	h := &RegHost{Lease: 100, UpdateTime: now}
	expected := now.Add(100 * time.Second)
	if h.GetExpireTime() != expected {
		t.Errorf("GetExpireTime() = %v, want %v", h.GetExpireTime(), expected)
	}
}

func TestRegHostGetLeaseInfo(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	h := &RegHost{Lease: 100, KeyLease: 200, UpdateTime: now}
	info := h.GetLeaseInfo(now.Add(50 * time.Second))
	if info.Lease != 100*time.Second {
		t.Errorf("Lease = %v, want 100s", info.Lease)
	}
	if info.RemainingLease != 50*time.Second {
		t.Errorf("RemainingLease = %v, want 50s", info.RemainingLease)
	}
}

func TestRegHostFindService(t *testing.T) {
	h := &RegHost{
		Services: []*RegService{
			{InstanceName: "Printer._ipp._tcp.default.service.arpa."},
			{InstanceName: "Web._http._tcp.default.service.arpa."},
		},
	}
	svc := h.FindService("printer._ipp._tcp.default.service.arpa.") // case-insensitive
	if svc == nil {
		t.Fatal("FindService returned nil")
	}
	if svc.InstanceName != "Printer._ipp._tcp.default.service.arpa." {
		t.Errorf("found wrong service: %q", svc.InstanceName)
	}
	if h.FindService("nonexistent._tcp.default.service.arpa.") != nil {
		t.Error("expected nil for nonexistent service")
	}
}

func TestRegServiceMatchesInstanceName(t *testing.T) {
	svc := &RegService{InstanceName: "My Printer._ipp._tcp.default.service.arpa."}
	if !svc.MatchesInstanceName("my printer._ipp._tcp.default.service.arpa.") {
		t.Error("case-insensitive match should work")
	}
	if svc.MatchesInstanceName("other._ipp._tcp.default.service.arpa.") {
		t.Error("should not match different name")
	}
}

// -------------------------------------------------------
// Edge case tests
// -------------------------------------------------------

func TestServerIgnoresNonUpdateMessage(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	// Build a standard query (not an update).
	var hdr dns.Header
	hdr.MessageID = 0x1234
	hdr.SetOpCode(dns.OpcodeQuery)
	buf := hdr.MarshalBinary()
	env.server.ProcessMessage(buf[:], defaultPeer())

	if len(env.responses) != 0 {
		t.Errorf("responses = %d, want 0 for non-update message", len(env.responses))
	}
}

func TestServerIgnoresResponseMessage(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	var hdr dns.Header
	hdr.MessageID = 0x1234
	hdr.SetType(dns.TypeResponse)
	hdr.SetOpCode(dns.OpcodeUpdate)
	buf := hdr.MarshalBinary()
	env.server.ProcessMessage(buf[:], defaultPeer())

	if len(env.responses) != 0 {
		t.Errorf("responses = %d, want 0 for response message", len(env.responses))
	}
}

func TestServerIgnoresWhenNotRunning(t *testing.T) {
	env := newServerTestEnv(t)
	// Don't start server.
	env.server.Enable(true)

	opts := defaultUpdateOpts()
	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	if len(env.responses) != 0 {
		t.Errorf("responses = %d, want 0 when not running", len(env.responses))
	}
}

func TestServerIgnoresTooShortMessage(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	env.server.ProcessMessage([]byte{0x00, 0x01}, defaultPeer())

	if len(env.responses) != 0 {
		t.Errorf("responses = %d, want 0 for too-short message", len(env.responses))
	}
}

func TestServerStopClearsHosts(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	opts := defaultUpdateOpts()
	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	if len(env.server.GetHosts()) == 0 {
		t.Fatal("expected at least 1 host")
	}

	env.server.Stop()

	if len(env.server.GetHosts()) != 0 {
		t.Error("hosts should be cleared after stop")
	}
}

func TestServerResponseCounterIncrement(t *testing.T) {
	env := newServerTestEnv(t)

	env.server.mu.Lock()
	env.server.incrementResponseCounter(dns.RcodeSuccess)
	env.server.incrementResponseCounter(dns.RcodeServerFailure)
	env.server.incrementResponseCounter(dns.RcodeFormatError)
	env.server.incrementResponseCounter(dns.RcodeNameExists)
	env.server.incrementResponseCounter(dns.RcodeRefused)
	env.server.incrementResponseCounter(dns.RcodeNameError) // -> Other
	env.server.mu.Unlock()

	c := env.server.GetResponseCounters()
	if c.Success != 1 {
		t.Errorf("Success = %d", c.Success)
	}
	if c.ServerFailure != 1 {
		t.Errorf("ServerFailure = %d", c.ServerFailure)
	}
	if c.FormatError != 1 {
		t.Errorf("FormatError = %d", c.FormatError)
	}
	if c.NameExists != 1 {
		t.Errorf("NameExists = %d", c.NameExists)
	}
	if c.Refused != 1 {
		t.Errorf("Refused = %d", c.Refused)
	}
	if c.Other != 1 {
		t.Errorf("Other = %d", c.Other)
	}
}

func TestServerStateString(t *testing.T) {
	tests := []struct {
		state ServerState
		want  string
	}{
		{ServerStateDisabled, "Disabled"},
		{ServerStateStopped, "Stopped"},
		{ServerStateRunning, "Running"},
		{ServerState(99), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("ServerState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestServerDisableWhileRunning(t *testing.T) {
	env := newServerTestEnv(t)
	env.startServer()

	opts := defaultUpdateOpts()
	data := env.buildSrpUpdate(&opts)
	env.server.ProcessMessage(data, defaultPeer())

	env.server.Enable(false)
	if env.server.GetState() != ServerStateDisabled {
		t.Errorf("state = %v, want Disabled", env.server.GetState())
	}
	if len(env.server.GetHosts()) != 0 {
		t.Error("hosts should be cleared on disable")
	}
}
