// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"testing"

	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/net/ip6"
)

func TestNewMessage(t *testing.T) {
	msg := NewMessage(CommandParentRequest)
	if !msg.IsSecured() {
		t.Error("expected secured message")
	}
	if msg.Command() != CommandParentRequest {
		t.Errorf("Command() = %d, want %d", msg.Command(), CommandParentRequest)
	}
	// SecuritySuite(1) + SecurityHeader(10) + Command(1) = 12
	if len(msg.Bytes()) != 12 {
		t.Errorf("initial length = %d, want 12", len(msg.Bytes()))
	}
}

func TestNewUnsecuredMessage(t *testing.T) {
	msg := NewUnsecuredMessage(CommandDiscoveryRequest)
	if msg.IsSecured() {
		t.Error("expected unsecured message")
	}
	if msg.Command() != CommandDiscoveryRequest {
		t.Errorf("Command() = %d, want %d", msg.Command(), CommandDiscoveryRequest)
	}
	// SecuritySuite(1) + Command(1) = 2
	if len(msg.Bytes()) != 2 {
		t.Errorf("initial length = %d, want 2", len(msg.Bytes()))
	}
}

func TestAppendSourceAddressTLV(t *testing.T) {
	msg := NewMessage(CommandAdvertisement)
	msg.AppendSourceAddressTLV(0x0C01)

	payload := msg.Payload()
	// payload[0] = command, payload[1] = TLV type, payload[2] = TLV length, payload[3:5] = value
	if payload[1] != TLVSourceAddress {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVSourceAddress)
	}
	if payload[2] != 2 {
		t.Errorf("TLV length = %d, want 2", payload[2])
	}
	// Big-endian RLOC16.
	if payload[3] != 0x0C || payload[4] != 0x01 {
		t.Errorf("RLOC16 = %02X%02X, want 0C01", payload[3], payload[4])
	}
}

func TestAppendModeTLV(t *testing.T) {
	msg := NewMessage(CommandChildIDRequest)
	mode := NewDeviceMode(ModeRxOnWhenIdle | ModeFullThreadDevice | ModeFullNetworkData)
	msg.AppendModeTLV(mode)

	payload := msg.Payload()
	if payload[1] != TLVMode {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVMode)
	}
	if payload[2] != 1 {
		t.Errorf("TLV length = %d, want 1", payload[2])
	}
	if payload[3] != mode.Get() {
		t.Errorf("mode = 0x%02X, want 0x%02X", payload[3], mode.Get())
	}
}

func TestAppendTimeoutTLV(t *testing.T) {
	msg := NewMessage(CommandChildIDRequest)
	msg.AppendTimeoutTLV(240)

	payload := msg.Payload()
	if payload[1] != TLVTimeout {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVTimeout)
	}
	if payload[2] != 4 {
		t.Errorf("TLV length = %d, want 4", payload[2])
	}
	// 240 big-endian = 0x000000F0
	if payload[3] != 0 || payload[4] != 0 || payload[5] != 0 || payload[6] != 0xF0 {
		t.Errorf("timeout bytes = %X, want 000000F0", payload[3:7])
	}
}

func TestAppendChallengeTLV(t *testing.T) {
	msg := NewMessage(CommandParentRequest)
	challenge := Challenge{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	msg.AppendChallengeTLV(challenge)

	payload := msg.Payload()
	if payload[1] != TLVChallenge {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVChallenge)
	}
	if payload[2] != 8 {
		t.Errorf("TLV length = %d, want 8", payload[2])
	}
	for i := 0; i < 8; i++ {
		if payload[3+i] != challenge[i] {
			t.Errorf("challenge[%d] = 0x%02X, want 0x%02X", i, payload[3+i], challenge[i])
		}
	}
}

func TestAppendResponseTLV(t *testing.T) {
	msg := NewMessage(CommandParentResponse)
	resp := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	msg.AppendResponseTLV(resp)

	payload := msg.Payload()
	if payload[1] != TLVResponse {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVResponse)
	}
	if payload[2] != 8 {
		t.Errorf("TLV length = %d, want 8", payload[2])
	}
}

func TestAppendFrameCounterTLVs(t *testing.T) {
	msg := NewMessage(CommandLinkAccept)
	msg.AppendLinkFrameCounterTLV(1000)
	msg.AppendMleFrameCounterTLV(2000)

	payload := msg.Payload()

	// Link Frame Counter TLV at offset 1.
	if payload[1] != TLVLinkFrameCounter {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVLinkFrameCounter)
	}
	if payload[2] != 4 {
		t.Errorf("TLV length = %d, want 4", payload[2])
	}

	// MLE Frame Counter TLV after the first TLV (1+2+4=7, so offset 7+1=8 from payload start).
	offset := 1 + 2 + 4
	if payload[offset] != TLVMleFrameCounter {
		t.Errorf("TLV type = %d, want %d", payload[offset], TLVMleFrameCounter)
	}
}

func TestAppendLeaderDataTLV(t *testing.T) {
	msg := NewMessage(CommandAdvertisement)
	ld := LeaderData{
		PartitionID:       0x12345678,
		Weighting:         64,
		DataVersion:       10,
		StableDataVersion: 5,
		LeaderRouterID:    1,
	}
	msg.AppendLeaderDataTLV(ld)

	payload := msg.Payload()
	if payload[1] != TLVLeaderData {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVLeaderData)
	}
	if payload[2] != LeaderDataTLVSize {
		t.Errorf("TLV length = %d, want %d", payload[2], LeaderDataTLVSize)
	}

	// PartitionID big-endian.
	if payload[3] != 0x12 || payload[4] != 0x34 || payload[5] != 0x56 || payload[6] != 0x78 {
		t.Error("PartitionID encoding incorrect")
	}
	if payload[7] != 64 {
		t.Errorf("Weighting = %d, want 64", payload[7])
	}
	if payload[8] != 10 {
		t.Errorf("DataVersion = %d, want 10", payload[8])
	}
	if payload[9] != 5 {
		t.Errorf("StableDataVersion = %d, want 5", payload[9])
	}
	if payload[10] != 1 {
		t.Errorf("LeaderRouterID = %d, want 1", payload[10])
	}
}

func TestAppendVersionTLV(t *testing.T) {
	msg := NewMessage(CommandParentResponse)
	msg.AppendVersionTLV(4)

	payload := msg.Payload()
	if payload[1] != TLVVersion {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVVersion)
	}
	if payload[2] != 2 {
		t.Errorf("TLV length = %d, want 2", payload[2])
	}
	// Version 4 big-endian = 0x0004.
	if payload[3] != 0x00 || payload[4] != 0x04 {
		t.Errorf("version bytes = %02X%02X, want 0004", payload[3], payload[4])
	}
}

func TestAppendChannelTLV(t *testing.T) {
	msg := NewMessage(CommandAnnounce)
	msg.AppendChannelTLV(0, 15)

	payload := msg.Payload()
	if payload[1] != TLVChannel {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVChannel)
	}
	if payload[2] != 3 {
		t.Errorf("TLV length = %d, want 3", payload[2])
	}
	if payload[3] != 0 {
		t.Errorf("channel page = %d, want 0", payload[3])
	}
	// Channel 15 big-endian = 0x000F.
	if payload[4] != 0x00 || payload[5] != 0x0F {
		t.Errorf("channel bytes = %02X%02X, want 000F", payload[4], payload[5])
	}
}

func TestAppendPanIDTLV(t *testing.T) {
	msg := NewMessage(CommandAnnounce)
	msg.AppendPanIDTLV(0xABCD)

	payload := msg.Payload()
	if payload[1] != TLVPanID {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVPanID)
	}
	if payload[3] != 0xAB || payload[4] != 0xCD {
		t.Errorf("PAN ID bytes = %02X%02X, want ABCD", payload[3], payload[4])
	}
}

func TestAppendScanMaskTLV(t *testing.T) {
	msg := NewMessage(CommandParentRequest)
	msg.AppendScanMaskTLV(ScanMaskRouterFlag | ScanMaskEndDeviceFlag)

	payload := msg.Payload()
	if payload[1] != TLVScanMask {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVScanMask)
	}
	if payload[3] != 0xC0 {
		t.Errorf("scan mask = 0x%02X, want 0xC0", payload[3])
	}
}

func TestAppendStatusTLV(t *testing.T) {
	msg := NewMessage(CommandLinkReject)
	msg.AppendStatusTLV(StatusError)

	payload := msg.Payload()
	if payload[1] != TLVStatus {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVStatus)
	}
	if payload[3] != StatusError {
		t.Errorf("status = %d, want %d", payload[3], StatusError)
	}
}

func TestAppendLinkMarginTLV(t *testing.T) {
	msg := NewMessage(CommandParentResponse)
	msg.AppendLinkMarginTLV(42)

	payload := msg.Payload()
	if payload[1] != TLVLinkMargin {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVLinkMargin)
	}
	if payload[3] != 42 {
		t.Errorf("link margin = %d, want 42", payload[3])
	}
}

func TestAppendTLVRequestTLV(t *testing.T) {
	msg := NewMessage(CommandParentRequest)
	requested := []uint8{TLVSourceAddress, TLVLeaderData, TLVVersion}
	msg.AppendTLVRequestTLV(requested)

	payload := msg.Payload()
	if payload[1] != TLVTLVRequest {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVTLVRequest)
	}
	if payload[2] != 3 {
		t.Errorf("TLV length = %d, want 3", payload[2])
	}
	for i, v := range requested {
		if payload[3+i] != v {
			t.Errorf("requested[%d] = %d, want %d", i, payload[3+i], v)
		}
	}
}

func TestAppendNetworkDataTLV(t *testing.T) {
	msg := NewMessage(CommandDataResponse)
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	msg.AppendNetworkDataTLV(data)

	payload := msg.Payload()
	if payload[1] != TLVNetworkData {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVNetworkData)
	}
	if payload[2] != 5 {
		t.Errorf("TLV length = %d, want 5", payload[2])
	}
}

func TestAppendSupervisionIntervalTLV(t *testing.T) {
	msg := NewMessage(CommandChildUpdateResponse)
	msg.AppendSupervisionIntervalTLV(190)

	payload := msg.Payload()
	if payload[1] != TLVSupervisionInterval {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVSupervisionInterval)
	}
	if payload[2] != 2 {
		t.Errorf("TLV length = %d, want 2", payload[2])
	}
	// 190 big-endian = 0x00BE.
	if payload[3] != 0x00 || payload[4] != 0xBE {
		t.Errorf("interval = %02X%02X, want 00BE", payload[3], payload[4])
	}
}

func TestAppendActiveTimestampTLV(t *testing.T) {
	msg := NewMessage(CommandDataResponse)
	ts := &meshcop.Timestamp{}
	ts.SetSeconds(12345)
	ts.SetTicks(100)
	ts.SetAuthoritative(true)

	if err := msg.AppendActiveTimestampTLV(ts); err != nil {
		t.Fatalf("AppendActiveTimestampTLV: %v", err)
	}

	payload := msg.Payload()
	if payload[1] != TLVActiveTimestamp {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVActiveTimestamp)
	}
	if payload[2] != 8 {
		t.Errorf("TLV length = %d, want 8", payload[2])
	}
}

func TestAppendRoute64TLV(t *testing.T) {
	var mask RouterIDSet
	mask.Add(0)
	mask.Add(5)

	entries := []Route64Entry{
		{LinkQualityOut: 3, LinkQualityIn: 2, Cost: 1},
		{LinkQualityOut: 1, LinkQualityIn: 1, Cost: 5},
	}

	msg := NewMessage(CommandAdvertisement)
	msg.AppendRoute64TLV(42, mask, entries)

	payload := msg.Payload()
	if payload[1] != TLVRoute64 {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVRoute64)
	}
	// 1 (seq) + 8 (mask) + 2 (entries) = 11
	if payload[2] != 11 {
		t.Errorf("TLV length = %d, want 11", payload[2])
	}
	if payload[3] != 42 {
		t.Errorf("routerIDSequence = %d, want 42", payload[3])
	}

	// First entry: LQout=3<<6 | LQin=2<<4 | cost=1 = 0xC0|0x20|0x01 = 0xE1
	entryOffset := 3 + 1 + 8 // command + seq + mask
	if payload[entryOffset] != 0xE1 {
		t.Errorf("entry[0] = 0x%02X, want 0xE1", payload[entryOffset])
	}
	// Second entry: LQout=1<<6 | LQin=1<<4 | cost=5 = 0x40|0x10|0x05 = 0x55
	if payload[entryOffset+1] != 0x55 {
		t.Errorf("entry[1] = 0x%02X, want 0x55", payload[entryOffset+1])
	}
}

func TestAppendConnectivityTLV(t *testing.T) {
	msg := NewMessage(CommandParentResponse)
	c := ConnectivityTLV{
		Flags:         0x40,
		LinkQuality3:  3,
		LinkQuality2:  5,
		LinkQuality1:  10,
		LeaderCost:    2,
		IDSequence:    8,
		ActiveRouters: 15,
	}
	msg.AppendConnectivityTLV(c)

	payload := msg.Payload()
	if payload[1] != TLVConnectivity {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVConnectivity)
	}
	if payload[2] != ConnectivityTLVMinSize {
		t.Errorf("TLV length = %d, want %d", payload[2], ConnectivityTLVMinSize)
	}

	// With SED fields.
	msg2 := NewMessage(CommandParentResponse)
	c.SEDBufferSize = 1024
	c.SEDDatagramCount = 5
	msg2.AppendConnectivityTLV(c)

	payload2 := msg2.Payload()
	if payload2[2] != ConnectivityTLVMaxSize {
		t.Errorf("TLV length with SED = %d, want %d", payload2[2], ConnectivityTLVMaxSize)
	}
}

func TestAppendAddressRegistrationTLV(t *testing.T) {
	var addr ip6.Address
	for i := range addr {
		addr[i] = byte(i + 0x10)
	}

	entries := []AddressRegistrationEntry{
		{
			Compressed: true,
			ContextID:  0,
			IID:        [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		},
		{
			Compressed: false,
			Address:    addr,
		},
	}

	msg := NewMessage(CommandChildIDRequest)
	msg.AppendAddressRegistrationTLV(entries)

	payload := msg.Payload()
	if payload[1] != TLVAddressRegistration {
		t.Errorf("TLV type = %d, want %d", payload[1], TLVAddressRegistration)
	}
	// Compressed: 1 (control) + 8 (IID) = 9. Full: 1 (control) + 16 (addr) = 17. Total = 26.
	if payload[2] != 26 {
		t.Errorf("TLV length = %d, want 26", payload[2])
	}

	// Compressed entry control byte.
	if payload[3] != 0x80 {
		t.Errorf("compressed control = 0x%02X, want 0x80", payload[3])
	}

	// Full entry control byte.
	if payload[3+9] != 0x00 {
		t.Errorf("full control = 0x%02X, want 0x00", payload[3+9])
	}
}

// --- TLV parsing tests ---

func TestParseTLVs(t *testing.T) {
	// Build: type=0 len=2 val=0C01, type=18 len=2 val=0004
	data := []byte{
		0x00, 0x02, 0x0C, 0x01,
		0x12, 0x02, 0x00, 0x04,
	}

	tlvs, err := ParseTLVs(data)
	if err != nil {
		t.Fatalf("ParseTLVs: %v", err)
	}
	if len(tlvs) != 2 {
		t.Fatalf("got %d TLVs, want 2", len(tlvs))
	}

	if tlvs[0].Type != TLVSourceAddress {
		t.Errorf("tlvs[0].Type = %d, want %d", tlvs[0].Type, TLVSourceAddress)
	}
	if tlvs[1].Type != TLVVersion {
		t.Errorf("tlvs[1].Type = %d, want %d", tlvs[1].Type, TLVVersion)
	}
}

func TestParseTLVsErrors(t *testing.T) {
	// Truncated header.
	if _, err := ParseTLVs([]byte{0x00}); err == nil {
		t.Error("expected error for truncated header")
	}

	// Length exceeds buffer.
	if _, err := ParseTLVs([]byte{0x00, 0x05, 0x01}); err == nil {
		t.Error("expected error for length exceeding buffer")
	}
}

func TestFindTLV(t *testing.T) {
	data := []byte{
		0x00, 0x02, 0x0C, 0x01,
		0x12, 0x02, 0x00, 0x04,
	}
	tlvs, _ := ParseTLVs(data)

	val, ok := FindTLV(tlvs, TLVVersion)
	if !ok {
		t.Fatal("FindTLV: Version TLV not found")
	}
	if len(val) != 2 || val[0] != 0x00 || val[1] != 0x04 {
		t.Errorf("Version value = %X, want 0004", val)
	}

	_, ok = FindTLV(tlvs, TLVTimeout)
	if ok {
		t.Error("FindTLV: found Timeout TLV that doesn't exist")
	}
}

// --- TLV read helper tests ---

func TestReadSourceAddressTLV(t *testing.T) {
	v, err := ReadSourceAddressTLV([]byte{0x0C, 0x01})
	if err != nil {
		t.Fatalf("ReadSourceAddressTLV: %v", err)
	}
	if v != 0x0C01 {
		t.Errorf("RLOC16 = 0x%04X, want 0x0C01", v)
	}

	_, err = ReadSourceAddressTLV([]byte{0x01})
	if err == nil {
		t.Error("expected error for short value")
	}
}

func TestReadModeTLV(t *testing.T) {
	m, err := ReadModeTLV([]byte{ModeRxOnWhenIdle | ModeFullThreadDevice | ModeFullNetworkData})
	if err != nil {
		t.Fatalf("ReadModeTLV: %v", err)
	}
	if !m.IsFullThreadDevice() {
		t.Error("expected FTD")
	}
	if !m.IsRxOnWhenIdle() {
		t.Error("expected RxOnWhenIdle")
	}

	_, err = ReadModeTLV(nil)
	if err == nil {
		t.Error("expected error for empty value")
	}
}

func TestReadTimeoutTLV(t *testing.T) {
	v, err := ReadTimeoutTLV([]byte{0x00, 0x00, 0x00, 0xF0})
	if err != nil {
		t.Fatalf("ReadTimeoutTLV: %v", err)
	}
	if v != 240 {
		t.Errorf("timeout = %d, want 240", v)
	}
}

func TestReadChallengeTLV(t *testing.T) {
	c, err := ReadChallengeTLV([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatalf("ReadChallengeTLV: %v", err)
	}
	if c != (Challenge{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Errorf("challenge = %v, want [1..8]", c)
	}

	_, err = ReadChallengeTLV([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for short challenge")
	}
}

func TestReadFrameCounterTLVs(t *testing.T) {
	v, err := ReadLinkFrameCounterTLV([]byte{0x00, 0x00, 0x03, 0xE8})
	if err != nil {
		t.Fatalf("ReadLinkFrameCounterTLV: %v", err)
	}
	if v != 1000 {
		t.Errorf("link frame counter = %d, want 1000", v)
	}

	v, err = ReadMleFrameCounterTLV([]byte{0x00, 0x00, 0x07, 0xD0})
	if err != nil {
		t.Fatalf("ReadMleFrameCounterTLV: %v", err)
	}
	if v != 2000 {
		t.Errorf("MLE frame counter = %d, want 2000", v)
	}
}

func TestReadAddress16TLV(t *testing.T) {
	v, err := ReadAddress16TLV([]byte{0x0C, 0x01})
	if err != nil {
		t.Fatalf("ReadAddress16TLV: %v", err)
	}
	if v != 0x0C01 {
		t.Errorf("Address16 = 0x%04X, want 0x0C01", v)
	}
}

func TestReadLeaderDataTLV(t *testing.T) {
	data := []byte{0x12, 0x34, 0x56, 0x78, 64, 10, 5, 1}
	ld, err := ReadLeaderDataTLV(data)
	if err != nil {
		t.Fatalf("ReadLeaderDataTLV: %v", err)
	}
	if ld.PartitionID != 0x12345678 {
		t.Errorf("PartitionID = 0x%08X, want 0x12345678", ld.PartitionID)
	}
	if ld.Weighting != 64 {
		t.Errorf("Weighting = %d, want 64", ld.Weighting)
	}
	if ld.DataVersion != 10 {
		t.Errorf("DataVersion = %d, want 10", ld.DataVersion)
	}
	if ld.StableDataVersion != 5 {
		t.Errorf("StableDataVersion = %d, want 5", ld.StableDataVersion)
	}
	if ld.LeaderRouterID != 1 {
		t.Errorf("LeaderRouterID = %d, want 1", ld.LeaderRouterID)
	}

	_, err = ReadLeaderDataTLV([]byte{1, 2})
	if err == nil {
		t.Error("expected error for short leader data")
	}
}

func TestReadVersionTLV(t *testing.T) {
	v, err := ReadVersionTLV([]byte{0x00, 0x04})
	if err != nil {
		t.Fatalf("ReadVersionTLV: %v", err)
	}
	if v != 4 {
		t.Errorf("version = %d, want 4", v)
	}
}

func TestReadChannelTLV(t *testing.T) {
	page, ch, err := ReadChannelTLV([]byte{0, 0x00, 0x0F})
	if err != nil {
		t.Fatalf("ReadChannelTLV: %v", err)
	}
	if page != 0 {
		t.Errorf("page = %d, want 0", page)
	}
	if ch != 15 {
		t.Errorf("channel = %d, want 15", ch)
	}
}

func TestReadPanIDTLV(t *testing.T) {
	v, err := ReadPanIDTLV([]byte{0xAB, 0xCD})
	if err != nil {
		t.Fatalf("ReadPanIDTLV: %v", err)
	}
	if v != 0xABCD {
		t.Errorf("PAN ID = 0x%04X, want 0xABCD", v)
	}
}

func TestReadActiveTimestampTLV(t *testing.T) {
	ts := &meshcop.Timestamp{}
	ts.SetSeconds(12345)
	ts.SetTicks(100)
	ts.SetAuthoritative(true)

	data, _ := ts.MarshalBinary()
	parsed, err := ReadActiveTimestampTLV(data)
	if err != nil {
		t.Fatalf("ReadActiveTimestampTLV: %v", err)
	}
	if parsed.Seconds() != 12345 {
		t.Errorf("seconds = %d, want 12345", parsed.Seconds())
	}
	if parsed.Ticks() != 100 {
		t.Errorf("ticks = %d, want 100", parsed.Ticks())
	}
	if !parsed.Authoritative() {
		t.Error("expected authoritative")
	}
}

func TestReadRoute64TLV(t *testing.T) {
	var mask RouterIDSet
	mask.Add(0)
	mask.Add(5)

	val := make([]byte, 0, 11)
	val = append(val, 42)         // sequence
	val = append(val, mask[:]...) // mask
	val = append(val, 0xE1)       // LQout=3, LQin=2, cost=1
	val = append(val, 0x55)       // LQout=1, LQin=1, cost=5

	seq, parsedMask, entries, err := ReadRoute64TLV(val)
	if err != nil {
		t.Fatalf("ReadRoute64TLV: %v", err)
	}
	if seq != 42 {
		t.Errorf("sequence = %d, want 42", seq)
	}
	if parsedMask != mask {
		t.Errorf("mask mismatch")
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if entries[0].LinkQualityOut != 3 || entries[0].LinkQualityIn != 2 || entries[0].Cost != 1 {
		t.Errorf("entry[0] = %+v", entries[0])
	}
	if entries[1].LinkQualityOut != 1 || entries[1].LinkQualityIn != 1 || entries[1].Cost != 5 {
		t.Errorf("entry[1] = %+v", entries[1])
	}
}

func TestReadConnectivityTLV(t *testing.T) {
	// Without SED.
	val := []byte{0x40, 3, 5, 10, 2, 8, 15}
	c, err := ReadConnectivityTLV(val)
	if err != nil {
		t.Fatalf("ReadConnectivityTLV: %v", err)
	}
	if c.Flags != 0x40 {
		t.Errorf("Flags = 0x%02X, want 0x40", c.Flags)
	}
	if c.LinkQuality3 != 3 || c.LinkQuality2 != 5 || c.LinkQuality1 != 10 {
		t.Error("link quality mismatch")
	}
	if c.LeaderCost != 2 {
		t.Errorf("LeaderCost = %d, want 2", c.LeaderCost)
	}
	if c.SEDBufferSize != 0 {
		t.Errorf("SEDBufferSize = %d, want 0", c.SEDBufferSize)
	}

	// With SED.
	val = []byte{0x40, 3, 5, 10, 2, 8, 15, 0x04, 0x00, 5}
	c, err = ReadConnectivityTLV(val)
	if err != nil {
		t.Fatalf("ReadConnectivityTLV with SED: %v", err)
	}
	if c.SEDBufferSize != 1024 {
		t.Errorf("SEDBufferSize = %d, want 1024", c.SEDBufferSize)
	}
	if c.SEDDatagramCount != 5 {
		t.Errorf("SEDDatagramCount = %d, want 5", c.SEDDatagramCount)
	}
}

func TestReadAddressRegistrationTLV(t *testing.T) {
	var addr ip6.Address
	for i := range addr {
		addr[i] = byte(i + 0x10)
	}

	// Build: compressed(contextID=0, IID) + full(addr)
	val := []byte{0x80}
	val = append(val, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08) // IID
	val = append(val, 0x00)                                           // full
	val = append(val, addr[:]...)

	entries, err := ReadAddressRegistrationTLV(val)
	if err != nil {
		t.Fatalf("ReadAddressRegistrationTLV: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}

	if !entries[0].Compressed {
		t.Error("entry[0]: expected compressed")
	}
	if entries[0].ContextID != 0 {
		t.Errorf("entry[0].ContextID = %d, want 0", entries[0].ContextID)
	}
	if entries[0].IID[0] != 0x01 {
		t.Errorf("entry[0].IID[0] = 0x%02X, want 0x01", entries[0].IID[0])
	}

	if entries[1].Compressed {
		t.Error("entry[1]: expected full")
	}
	if entries[1].Address != addr {
		t.Error("entry[1].Address mismatch")
	}
}

func TestReadAddressRegistrationTLVErrors(t *testing.T) {
	// Truncated compressed entry.
	_, err := ReadAddressRegistrationTLV([]byte{0x80, 0x01, 0x02})
	if err == nil {
		t.Error("expected error for truncated compressed entry")
	}

	// Truncated full entry.
	_, err = ReadAddressRegistrationTLV([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Error("expected error for truncated full entry")
	}
}

func TestReadLinkMarginTLV(t *testing.T) {
	v, err := ReadLinkMarginTLV([]byte{42})
	if err != nil {
		t.Fatalf("ReadLinkMarginTLV: %v", err)
	}
	if v != 42 {
		t.Errorf("link margin = %d, want 42", v)
	}
}

func TestReadStatusTLV(t *testing.T) {
	v, err := ReadStatusTLV([]byte{StatusDuplicate})
	if err != nil {
		t.Fatalf("ReadStatusTLV: %v", err)
	}
	if v != StatusDuplicate {
		t.Errorf("status = %d, want %d", v, StatusDuplicate)
	}
}

func TestReadScanMaskTLV(t *testing.T) {
	v, err := ReadScanMaskTLV([]byte{0xC0})
	if err != nil {
		t.Fatalf("ReadScanMaskTLV: %v", err)
	}
	if v != 0xC0 {
		t.Errorf("scan mask = 0x%02X, want 0xC0", v)
	}
}

func TestReadSupervisionIntervalTLV(t *testing.T) {
	v, err := ReadSupervisionIntervalTLV([]byte{0x00, 0xBE})
	if err != nil {
		t.Fatalf("ReadSupervisionIntervalTLV: %v", err)
	}
	if v != 190 {
		t.Errorf("interval = %d, want 190", v)
	}
}

// --- ParseMessage tests ---

func TestParseMessageSecured(t *testing.T) {
	// Build a minimal secured message: suite(1) + secHdr(10) + cmd(1) + mic(4)
	secHdr := NewSecurityHeader(1, 100)
	hdr := secHdr.Marshal()

	data := make([]byte, 0, 16)
	data = append(data, SecuritySuiteEncMic32)
	data = append(data, hdr[:]...)
	data = append(data, byte(CommandParentRequest)) // command (will be "ciphertext" in real use)
	data = append(data, 0xAA, 0xBB, 0xCC, 0xDD)     // fake MIC

	pm, err := ParseMessage(data)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if pm.SecuritySuite != SecuritySuiteEncMic32 {
		t.Errorf("SecuritySuite = %d, want %d", pm.SecuritySuite, SecuritySuiteEncMic32)
	}
	if pm.SecHeader.FrameCounter != 100 {
		t.Errorf("FrameCounter = %d, want 100", pm.SecHeader.FrameCounter)
	}
	if pm.SecHeader.KeySource != 1 {
		t.Errorf("KeySource = %d, want 1", pm.SecHeader.KeySource)
	}
	if len(pm.Payload) != 1 {
		t.Errorf("payload length = %d, want 1", len(pm.Payload))
	}
	if pm.Tag != [4]byte{0xAA, 0xBB, 0xCC, 0xDD} {
		t.Errorf("tag = %X, want AABBCCDD", pm.Tag)
	}
}

func TestParseMessageUnsecured(t *testing.T) {
	data := []byte{SecuritySuiteNone, byte(CommandDiscoveryRequest), 0x01, 0x02}

	pm, err := ParseMessage(data)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if pm.SecuritySuite != SecuritySuiteNone {
		t.Errorf("SecuritySuite = %d, want %d", pm.SecuritySuite, SecuritySuiteNone)
	}
	// Payload = command + rest.
	if len(pm.Payload) != 3 {
		t.Errorf("payload length = %d, want 3", len(pm.Payload))
	}
}

func TestParseMessageErrors(t *testing.T) {
	// Empty.
	if _, err := ParseMessage(nil); err == nil {
		t.Error("expected error for empty data")
	}

	// Secured too short.
	if _, err := ParseMessage([]byte{0x00, 0x01}); err == nil {
		t.Error("expected error for short secured message")
	}

	// Unsecured too short.
	if _, err := ParseMessage([]byte{0xFF}); err == nil {
		t.Error("expected error for short unsecured message")
	}

	// Unknown suite.
	if _, err := ParseMessage([]byte{0x42, 0x01}); err == nil {
		t.Error("expected error for unknown security suite")
	}
}

// --- Finalize and full round-trip test ---

func TestFinalizeAndRoundTrip(t *testing.T) {
	// Create a message.
	msg := NewMessage(CommandParentRequest)
	challenge := Challenge{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	msg.AppendChallengeTLV(challenge)
	msg.AppendVersionTLV(4)
	msg.AppendScanMaskTLV(ScanMaskRouterFlag)

	// Set up security parameters.
	var mleKey [16]byte
	for i := range mleKey {
		mleKey[i] = byte(i + 0xA0)
	}
	var srcAddr [8]byte
	for i := range srcAddr {
		srcAddr[i] = byte(i + 1)
	}
	var srcIP, dstIP ip6.Address
	for i := range srcIP {
		srcIP[i] = byte(i)
	}
	for i := range dstIP {
		dstIP[i] = byte(i + 0x20)
	}

	secHdr := NewSecurityHeader(1, 42)

	// Finalize (encrypt).
	err := msg.Finalize(secHdr, mleKey, srcAddr, srcIP, dstIP)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	wire := msg.Bytes()

	// Parse the wire bytes.
	pm, err := ParseMessage(wire)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}

	if pm.SecuritySuite != SecuritySuiteEncMic32 {
		t.Errorf("SecuritySuite = %d, want %d", pm.SecuritySuite, SecuritySuiteEncMic32)
	}
	if pm.SecHeader.FrameCounter != 42 {
		t.Errorf("FrameCounter = %d, want 42", pm.SecHeader.FrameCounter)
	}
	if pm.SecHeader.KeySource != 1 {
		t.Errorf("KeySource = %d, want 1", pm.SecHeader.KeySource)
	}

	// Decrypt.
	hdrBytes := pm.SecHeader.Marshal()
	plaintext, err := pm.DecryptPayload(mleKey, srcAddr, srcIP, dstIP, hdrBytes)
	if err != nil {
		t.Fatalf("DecryptPayload: %v", err)
	}

	// First byte should be the command.
	if Command(plaintext[0]) != CommandParentRequest {
		t.Errorf("decrypted command = %d, want %d", plaintext[0], CommandParentRequest)
	}

	// Parse TLVs from the rest.
	tlvs, err := ParseTLVs(plaintext[1:])
	if err != nil {
		t.Fatalf("ParseTLVs: %v", err)
	}

	// Find challenge.
	val, ok := FindTLV(tlvs, TLVChallenge)
	if !ok {
		t.Fatal("Challenge TLV not found after decrypt")
	}
	c, err := ReadChallengeTLV(val)
	if err != nil {
		t.Fatalf("ReadChallengeTLV: %v", err)
	}
	if c != challenge {
		t.Errorf("challenge = %v, want %v", c, challenge)
	}

	// Find version.
	val, ok = FindTLV(tlvs, TLVVersion)
	if !ok {
		t.Fatal("Version TLV not found after decrypt")
	}
	ver, err := ReadVersionTLV(val)
	if err != nil {
		t.Fatalf("ReadVersionTLV: %v", err)
	}
	if ver != 4 {
		t.Errorf("version = %d, want 4", ver)
	}

	// Find scan mask.
	val, ok = FindTLV(tlvs, TLVScanMask)
	if !ok {
		t.Fatal("ScanMask TLV not found after decrypt")
	}
	sm, err := ReadScanMaskTLV(val)
	if err != nil {
		t.Fatalf("ReadScanMaskTLV: %v", err)
	}
	if sm != ScanMaskRouterFlag {
		t.Errorf("scan mask = 0x%02X, want 0x%02X", sm, ScanMaskRouterFlag)
	}
}

func TestFinalizeUnsecuredError(t *testing.T) {
	msg := NewUnsecuredMessage(CommandDiscoveryRequest)
	err := msg.Finalize(SecurityHeader{}, [16]byte{}, [8]byte{}, ip6.Address{}, ip6.Address{})
	if err == nil {
		t.Error("expected error when finalizing unsecured message")
	}
}
