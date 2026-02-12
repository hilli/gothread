// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"testing"
	"time"

	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/net/ip6"
)

// --- test infrastructure ---

// parentExtAddr is a well-known extended address used for the parent in tests.
var parentExtAddr = types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}

// parentRLOC16 is the parent's RLOC16 (Router ID 1, child ID 0).
const parentRLOC16 uint16 = 0x0400

// childRLOC16 is our child RLOC16 under parent with Router ID 1.
const childRLOC16 uint16 = 0x0401

func makeLeaderDataTLVValue(ld LeaderData) []byte {
	buf := make([]byte, LeaderDataTLVSize)
	encoding.BigEndianWriteUint32(ld.PartitionID, buf[0:4])
	buf[4] = ld.Weighting
	buf[5] = ld.DataVersion
	buf[6] = ld.StableDataVersion
	buf[7] = ld.LeaderRouterID
	return buf
}

func makeSourceAddressTLVValue(rloc16 uint16) []byte {
	val := make([]byte, 2)
	encoding.BigEndianWriteUint16(rloc16, val)
	return val
}

// mockChildDatasetProvider implements DatasetProvider for testing.
type mockChildDatasetProvider struct {
	activeTimestamp  meshcop.Timestamp
	pendingTimestamp meshcop.Timestamp
	activeDataset    []byte
	pendingDataset   []byte
}

func (m *mockChildDatasetProvider) GetActiveTimestamp() meshcop.Timestamp  { return m.activeTimestamp }
func (m *mockChildDatasetProvider) GetPendingTimestamp() meshcop.Timestamp { return m.pendingTimestamp }
func (m *mockChildDatasetProvider) ReadActiveDataset() []byte              { return m.activeDataset }
func (m *mockChildDatasetProvider) ReadPendingDataset() []byte             { return m.pendingDataset }

// mockChildNetworkDataProvider implements NetworkDataProvider for testing.
type mockChildNetworkDataProvider struct {
	data []byte
}

func (m *mockChildNetworkDataProvider) GetNetworkData(_ bool) []byte { return m.data }

// newChildHandlersTestSetupWithProviders creates a ChildHandlers instance
// wired to the given DatasetProvider and NetworkDataProvider.
func newChildHandlersTestSetupWithProviders(
	datasets DatasetProvider,
	networkData NetworkDataProvider,
) (*ChildHandlers, *Mle, *mockTransport, *mockKeyProvider) {
	mle := NewMle()
	_ = mle.Enable()

	transport := &mockTransport{
		extAddr: types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		linkLocal: ip6.Address{
			0xfe, 0x80, 0, 0, 0, 0, 0, 0,
			0x03, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		},
	}

	keyMgr := &mockKeyProvider{
		currentSeq:      1,
		mleFrameCounter: 100,
		macFrameCounter: 200,
	}

	d := NewDispatcher(mle, keyMgr, transport)

	_ = mle.SetStateChild(childRLOC16)
	mle.SetLeaderData(defaultLeaderData)

	parent := mle.GetParent()
	parent.MacAddr = parentExtAddr
	parent.RLOC16 = parentRLOC16
	parent.State = StateValid
	parent.LastHeard = time.Now().Add(-1 * time.Minute)

	ch := NewChildHandlers(mle, d, datasets, networkData)
	return ch, mle, transport, keyMgr
}

// --- SendDataRequest with DatasetProvider tests ---

func TestSendDataRequest_WithDatasets_AppendsTimestamps(t *testing.T) {
	t.Parallel()

	var activeTS meshcop.Timestamp
	activeTS.SetSeconds(1000)
	activeTS.SetTicks(10)

	var pendingTS meshcop.Timestamp
	pendingTS.SetSeconds(2000)
	pendingTS.SetTicks(20)

	datasets := &mockChildDatasetProvider{
		activeTimestamp:  activeTS,
		pendingTimestamp: pendingTS,
	}

	ch, _, transport, _ := newChildHandlersTestSetupWithProviders(datasets, nil)

	err := ch.SendDataRequest()
	if err != nil {
		t.Fatalf("SendDataRequest error: %v", err)
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
	}

	// The message was sent — verify it's non-empty (the timestamps are
	// inside the encrypted MLE payload, so we just verify the message
	// was constructed and sent successfully).
	if len(transport.sentMessages[0].data) == 0 {
		t.Error("sent message should not be empty")
	}
}

func TestSendDataRequest_NilDatasets_NoTimestampAppended(t *testing.T) {
	t.Parallel()

	ch, _, transport, _ := newChildHandlersTestSetupWithProviders(nil, nil)

	err := ch.SendDataRequest()
	if err != nil {
		t.Fatalf("SendDataRequest error: %v", err)
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
	}
}

// --- appendRequestedTLV with new TLV types tests ---

func TestAppendRequestedTLV_NetworkData(t *testing.T) {
	t.Parallel()

	networkData := &mockChildNetworkDataProvider{data: []byte{0xAA, 0xBB, 0xCC}}
	ch, _, _, _ := newChildHandlersTestSetupWithProviders(nil, networkData)

	msg := NewMessage(CommandChildUpdateResponse)
	initialLen := len(msg.buf)
	ch.appendRequestedTLV(msg, TLVNetworkData)

	if len(msg.buf) <= initialLen {
		t.Error("appendRequestedTLV(TLVNetworkData) did not append anything")
	}
}

func TestAppendRequestedTLV_NetworkData_NilProvider(t *testing.T) {
	t.Parallel()

	ch, _, _, _ := newChildHandlersTestSetupWithProviders(nil, nil)

	msg := NewMessage(CommandChildUpdateResponse)
	initialLen := len(msg.buf)
	ch.appendRequestedTLV(msg, TLVNetworkData)

	if len(msg.buf) != initialLen {
		t.Error("appendRequestedTLV(TLVNetworkData) should not append when provider is nil")
	}
}

func TestAppendRequestedTLV_ActiveTimestamp(t *testing.T) {
	t.Parallel()

	var activeTS meshcop.Timestamp
	activeTS.SetSeconds(500)

	datasets := &mockChildDatasetProvider{activeTimestamp: activeTS}
	ch, _, _, _ := newChildHandlersTestSetupWithProviders(datasets, nil)

	msg := NewMessage(CommandChildUpdateResponse)
	initialLen := len(msg.buf)
	ch.appendRequestedTLV(msg, TLVActiveTimestamp)

	if len(msg.buf) <= initialLen {
		t.Error("appendRequestedTLV(TLVActiveTimestamp) did not append anything")
	}
}

func TestAppendRequestedTLV_ActiveTimestamp_NilProvider(t *testing.T) {
	t.Parallel()

	ch, _, _, _ := newChildHandlersTestSetupWithProviders(nil, nil)

	msg := NewMessage(CommandChildUpdateResponse)
	initialLen := len(msg.buf)
	ch.appendRequestedTLV(msg, TLVActiveTimestamp)

	if len(msg.buf) == initialLen {
		// With nil provider, nothing should be appended.
	}
	// Verify no panic and no data appended.
	if len(msg.buf) != initialLen {
		t.Error("appendRequestedTLV(TLVActiveTimestamp) should not append when datasets is nil")
	}
}

func TestAppendRequestedTLV_PendingTimestamp(t *testing.T) {
	t.Parallel()

	var pendingTS meshcop.Timestamp
	pendingTS.SetSeconds(700)

	datasets := &mockChildDatasetProvider{pendingTimestamp: pendingTS}
	ch, _, _, _ := newChildHandlersTestSetupWithProviders(datasets, nil)

	msg := NewMessage(CommandChildUpdateResponse)
	initialLen := len(msg.buf)
	ch.appendRequestedTLV(msg, TLVPendingTimestamp)

	if len(msg.buf) <= initialLen {
		t.Error("appendRequestedTLV(TLVPendingTimestamp) did not append anything")
	}
}

func TestAppendRequestedTLV_PendingTimestamp_NilProvider(t *testing.T) {
	t.Parallel()

	ch, _, _, _ := newChildHandlersTestSetupWithProviders(nil, nil)

	msg := NewMessage(CommandChildUpdateResponse)
	initialLen := len(msg.buf)
	ch.appendRequestedTLV(msg, TLVPendingTimestamp)

	if len(msg.buf) != initialLen {
		t.Error("appendRequestedTLV(TLVPendingTimestamp) should not append when datasets is nil")
	}
}

func makeModeTLVValue(mode DeviceMode) []byte {
	return []byte{mode.Get()}
}

func makeTimeoutTLVValue(timeout uint32) []byte {
	val := make([]byte, 4)
	encoding.BigEndianWriteUint32(timeout, val)
	return val
}

func makeStatusTLVValue(status uint8) []byte {
	return []byte{status}
}

func makeLinkMarginTLVValue(margin uint8) []byte {
	return []byte{margin}
}

// defaultLeaderData is the leader data used to set up the Mle state machine.
var defaultLeaderData = LeaderData{
	PartitionID:       0x00001000,
	Weighting:         64,
	DataVersion:       10,
	StableDataVersion: 5,
	LeaderRouterID:    1,
}

// newChildHandlersTestSetup creates a ChildHandlers instance with a fully
// initialized Mle (child state, parent set up) and Dispatcher mocks.
// Returns the ChildHandlers, Mle, mockTransport, and mockKeyProvider.
func newChildHandlersTestSetup() (*ChildHandlers, *Mle, *mockTransport, *mockKeyProvider) {
	mle := NewMle()
	_ = mle.Enable()

	transport := &mockTransport{
		extAddr: types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		linkLocal: ip6.Address{
			0xfe, 0x80, 0, 0, 0, 0, 0, 0,
			0x03, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		},
	}

	keyMgr := &mockKeyProvider{
		currentSeq:      1,
		mleFrameCounter: 100,
		macFrameCounter: 200,
	}

	d := NewDispatcher(mle, keyMgr, transport)

	// Transition to Child state.
	_ = mle.SetStateChild(childRLOC16)

	// Set up leader data.
	mle.SetLeaderData(defaultLeaderData)

	// Set up the parent.
	parent := mle.GetParent()
	parent.MacAddr = parentExtAddr
	parent.RLOC16 = parentRLOC16
	parent.State = StateValid
	parent.LastHeard = time.Now().Add(-1 * time.Minute)

	ch := NewChildHandlers(mle, d, nil, nil)
	return ch, mle, transport, keyMgr
}

// rxInfoFromParent creates an RxInfo that appears to come from the parent.
func rxInfoFromParent(mle *Mle, tlvs []TLV) *RxInfo {
	parentIP := parentLinkLocalIP(parentExtAddr)
	return &RxInfo{
		SrcAddr:  parentExtAddr,
		SrcIP:    parentIP,
		Neighbor: &mle.GetParent().Neighbor,
		TLVs:     tlvs,
	}
}

// rxInfoFromStranger creates an RxInfo from an unknown neighbor.
func rxInfoFromStranger(tlvs []TLV) *RxInfo {
	strangerAddr := types.ExtAddress{0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22}
	strangerIP := parentLinkLocalIP(strangerAddr)
	stranger := &Neighbor{
		MacAddr: strangerAddr,
		RLOC16:  0x0800,
		State:   StateValid,
	}
	return &RxInfo{
		SrcAddr:  strangerAddr,
		SrcIP:    strangerIP,
		Neighbor: stranger,
		TLVs:     tlvs,
	}
}

// --- HandleAdvertisement tests ---

func TestHandleAdvertisement_NormalFromParent(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	beforeLastHeard := mle.GetParent().LastHeard

	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
		{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(defaultLeaderData)},
	})

	err := ch.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("HandleAdvertisement error: %v", err)
	}

	// LastHeard should be updated.
	if !mle.GetParent().LastHeard.After(beforeLastHeard) {
		t.Error("parent LastHeard was not updated")
	}

	// No network data request should be pending (same leader data).
	if mle.NeedsNewNetworkData() {
		t.Error("should not need new network data for identical leader data")
	}
}

func TestHandleAdvertisement_FromNonParent(t *testing.T) {
	t.Parallel()
	ch, _, _, _ := newChildHandlersTestSetup()

	rxInfo := rxInfoFromStranger([]TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(0x0800)},
		{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(defaultLeaderData)},
	})

	err := ch.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("HandleAdvertisement should silently ignore non-parent: %v", err)
	}
}

func TestHandleAdvertisement_PartitionChange(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	newLD := defaultLeaderData
	newLD.PartitionID = 0x00002000 // Different partition

	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
		{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(newLD)},
	})

	err := ch.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("HandleAdvertisement error: %v", err)
	}

	if !mle.NeedsNewNetworkData() {
		t.Error("should need new network data after partition change")
	}
	if !mle.IsDataRequestPending() {
		t.Error("data request should be pending after partition change")
	}
}

func TestHandleAdvertisement_LeaderChange(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	newLD := defaultLeaderData
	newLD.LeaderRouterID = 5 // Different leader

	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
		{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(newLD)},
	})

	err := ch.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("HandleAdvertisement error: %v", err)
	}

	if !mle.NeedsNewNetworkData() {
		t.Error("should need new network data after leader change")
	}
}

func TestHandleAdvertisement_DataVersionChange(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	newLD := defaultLeaderData
	newLD.DataVersion = defaultLeaderData.DataVersion + 1

	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
		{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(newLD)},
	})

	err := ch.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("HandleAdvertisement error: %v", err)
	}

	if !mle.NeedsNewNetworkData() {
		t.Error("should need new network data after data version change")
	}
	if !mle.IsDataRequestPending() {
		t.Error("data request should be pending")
	}
}

func TestHandleAdvertisement_RLOC16Mismatch_Detaches(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	// Advertise a different RLOC16 than the parent's actual RLOC16.
	mismatchedRLOC := uint16(0x0C00)
	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(mismatchedRLOC)},
		{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(defaultLeaderData)},
	})

	err := ch.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("HandleAdvertisement error: %v", err)
	}

	if !mle.IsDetached() {
		t.Errorf("device should be detached after RLOC16 mismatch, got role %s", mle.Role())
	}
}

func TestHandleAdvertisement_NotAttached_ReturnsError(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	_ = mle.BecomeDetached()

	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
		{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(defaultLeaderData)},
	})

	err := ch.HandleAdvertisement(rxInfo)
	if err == nil {
		t.Fatal("HandleAdvertisement should return error when not attached")
	}
}

func TestHandleAdvertisement_MissingSourceAddress_ReturnsError(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(defaultLeaderData)},
	})

	err := ch.HandleAdvertisement(rxInfo)
	if err == nil {
		t.Fatal("HandleAdvertisement should return error when SourceAddress TLV is missing")
	}
}

func TestHandleAdvertisement_MissingLeaderData_ReturnsError(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
	})

	err := ch.HandleAdvertisement(rxInfo)
	if err == nil {
		t.Fatal("HandleAdvertisement should return error when LeaderData TLV is missing")
	}
}

func TestHandleAdvertisement_NilNeighbor_SilentlyIgnored(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
		{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(defaultLeaderData)},
	})
	rxInfo.Neighbor = nil // Unknown sender

	err := ch.HandleAdvertisement(rxInfo)
	if err != nil {
		t.Fatalf("HandleAdvertisement should silently ignore nil neighbor: %v", err)
	}
}

// --- HandleDataResponse tests ---

func TestHandleDataResponse_WithNetworkData(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	// Set up: need new network data.
	mle.SetRetrieveNewNetworkData(true)
	mle.SetDataRequestPending(true)

	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(defaultLeaderData)},
		{Type: TLVNetworkData, Value: []byte{0x01, 0x02, 0x03}},
	})

	err := ch.HandleDataResponse(rxInfo)
	if err != nil {
		t.Fatalf("HandleDataResponse error: %v", err)
	}

	if mle.NeedsNewNetworkData() {
		t.Error("retrieveNewNetworkData should be cleared after receiving NetworkData")
	}
	if mle.IsDataRequestPending() {
		t.Error("dataRequestPending should be cleared after receiving NetworkData")
	}
}

func TestHandleDataResponse_WithoutNetworkData_SchedulesAnotherRequest(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	// Set up: need new network data.
	mle.SetRetrieveNewNetworkData(true)

	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(defaultLeaderData)},
		// No NetworkData TLV
	})

	err := ch.HandleDataResponse(rxInfo)
	if err != nil {
		t.Fatalf("HandleDataResponse error: %v", err)
	}

	if mle.IsDataRequestPending() != true {
		t.Error("dataRequestPending should be set when NetworkData is absent but needed")
	}
}

func TestHandleDataResponse_PartitionChange_FlagsNewData(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	newLD := defaultLeaderData
	newLD.PartitionID = 0x00009999

	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(newLD)},
	})

	err := ch.HandleDataResponse(rxInfo)
	if err != nil {
		t.Fatalf("HandleDataResponse error: %v", err)
	}

	if !mle.NeedsNewNetworkData() {
		t.Error("should need new network data after partition change in data response")
	}
}

func TestHandleDataResponse_InvalidNeighbor_ReturnsError(t *testing.T) {
	t.Parallel()
	ch, _, _, _ := newChildHandlersTestSetup()

	rxInfo := &RxInfo{
		Neighbor: nil,
		TLVs: []TLV{
			{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(defaultLeaderData)},
		},
	}

	err := ch.HandleDataResponse(rxInfo)
	if err == nil {
		t.Fatal("HandleDataResponse should return error for nil neighbor")
	}
}

func TestHandleDataResponse_NotAttached_ReturnsError(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()
	_ = mle.BecomeDetached()

	rxInfo := &RxInfo{
		Neighbor: &Neighbor{State: StateValid},
		TLVs: []TLV{
			{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(defaultLeaderData)},
		},
	}

	err := ch.HandleDataResponse(rxInfo)
	if err == nil {
		t.Fatal("HandleDataResponse should return error when not attached")
	}
}

func TestHandleDataResponse_MissingLeaderData_ReturnsError(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVNetworkData, Value: []byte{0x01}},
		// No LeaderData
	})

	err := ch.HandleDataResponse(rxInfo)
	if err == nil {
		t.Fatal("HandleDataResponse should return error when LeaderData TLV is missing")
	}
}

// --- HandleChildUpdateRequest tests ---

func TestHandleChildUpdateRequest_NormalFromParent(t *testing.T) {
	t.Parallel()
	ch, mle, transport, _ := newChildHandlersTestSetup()

	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
	})

	err := ch.HandleChildUpdateRequest(rxInfo)
	if err != nil {
		t.Fatalf("HandleChildUpdateRequest error: %v", err)
	}

	// Should have sent a Child Update Response.
	if len(transport.sentMessages) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
	}
}

func TestHandleChildUpdateRequest_WithChallenge_IncludesResponseTLV(t *testing.T) {
	t.Parallel()
	ch, mle, transport, _ := newChildHandlersTestSetup()

	challenge := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
		{Type: TLVChallenge, Value: challenge},
	})

	err := ch.HandleChildUpdateRequest(rxInfo)
	if err != nil {
		t.Fatalf("HandleChildUpdateRequest error: %v", err)
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
	}

	// Verify that the sent message is a secured message and contains data.
	// The exact TLV verification is limited since the message is encrypted,
	// but we confirm a response was sent.
	if len(transport.sentMessages[0].data) == 0 {
		t.Error("sent message should not be empty")
	}
}

func TestHandleChildUpdateRequest_StatusError_Detaches(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
		{Type: TLVStatus, Value: makeStatusTLVValue(StatusError)},
	})

	err := ch.HandleChildUpdateRequest(rxInfo)
	if err != nil {
		t.Fatalf("HandleChildUpdateRequest error: %v", err)
	}

	if !mle.IsDetached() {
		t.Errorf("device should be detached after Status=Error, got role %s", mle.Role())
	}
}

func TestHandleChildUpdateRequest_RLOC16Mismatch_Detaches(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(0x0C00)}, // Wrong RLOC16
	})

	err := ch.HandleChildUpdateRequest(rxInfo)
	if err != nil {
		t.Fatalf("HandleChildUpdateRequest error: %v", err)
	}

	if !mle.IsDetached() {
		t.Errorf("device should be detached after RLOC16 mismatch, got role %s", mle.Role())
	}
}

func TestHandleChildUpdateRequest_FromNonParent_SendsReject(t *testing.T) {
	t.Parallel()
	ch, _, transport, _ := newChildHandlersTestSetup()

	rxInfo := rxInfoFromStranger([]TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(0x0800)},
	})

	err := ch.HandleChildUpdateRequest(rxInfo)
	if err != nil {
		t.Fatalf("HandleChildUpdateRequest error: %v", err)
	}

	// Should have sent a reject response.
	if len(transport.sentMessages) != 1 {
		t.Fatalf("expected 1 reject message, got %d", len(transport.sentMessages))
	}
}

func TestHandleChildUpdateRequest_WithLeaderData(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	newLD := defaultLeaderData
	newLD.DataVersion = defaultLeaderData.DataVersion + 1

	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
		{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(newLD)},
	})

	err := ch.HandleChildUpdateRequest(rxInfo)
	if err != nil {
		t.Fatalf("HandleChildUpdateRequest error: %v", err)
	}

	// Leader data should be updated.
	ld := mle.GetLeaderData()
	if ld.DataVersion != newLD.DataVersion {
		t.Errorf("leader data version not updated: got %d, want %d",
			ld.DataVersion, newLD.DataVersion)
	}
}

func TestHandleChildUpdateRequest_WithLinkMargin(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
		{Type: TLVLinkMargin, Value: makeLinkMarginTLVValue(25)}, // 25 dB -> quality 3
	})

	err := ch.HandleChildUpdateRequest(rxInfo)
	if err != nil {
		t.Fatalf("HandleChildUpdateRequest error: %v", err)
	}

	// The parent's link quality out should be updated.
	parent := mle.GetParent()
	qualityOut := parent.LinkInfo.GetQualityOut()
	if qualityOut != 3 {
		t.Errorf("parent link quality out = %d, want 3", qualityOut)
	}
}

func TestHandleChildUpdateRequest_WithTlvRequest(t *testing.T) {
	t.Parallel()
	ch, mle, transport, _ := newChildHandlersTestSetup()

	// Parent requests Mode and Version TLVs.
	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
		{Type: TLVTLVRequest, Value: []byte{TLVMode, TLVVersion}},
	})

	err := ch.HandleChildUpdateRequest(rxInfo)
	if err != nil {
		t.Fatalf("HandleChildUpdateRequest error: %v", err)
	}

	// Verify a response was sent.
	if len(transport.sentMessages) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
	}
}

func TestHandleChildUpdateRequest_NotAttached_ReturnsError(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()
	_ = mle.BecomeDetached()

	rxInfo := &RxInfo{
		TLVs: []TLV{
			{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
		},
	}

	err := ch.HandleChildUpdateRequest(rxInfo)
	if err == nil {
		t.Fatal("HandleChildUpdateRequest should return error when not attached")
	}
}

func TestHandleChildUpdateRequest_MissingSourceAddress_ReturnsError(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	rxInfo := rxInfoFromParent(mle, []TLV{
		// No SourceAddress
	})

	err := ch.HandleChildUpdateRequest(rxInfo)
	if err == nil {
		t.Fatal("HandleChildUpdateRequest should return error when SourceAddress is missing")
	}
}

// --- HandleChildUpdateResponse tests ---

func TestHandleChildUpdateResponse_Normal(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	mode := mle.GetDeviceMode()
	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVMode, Value: makeModeTLVValue(mode)},
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
	})

	err := ch.HandleChildUpdateResponse(rxInfo)
	if err != nil {
		t.Fatalf("HandleChildUpdateResponse error: %v", err)
	}
}

func TestHandleChildUpdateResponse_WithChallengeVerification(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	// Set up pending challenge.
	var challenge Challenge
	copy(challenge[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	ch.pendingChallenge = challenge
	ch.hasPendingChallenge = true

	mode := mle.GetDeviceMode()
	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVResponse, Value: challenge[:]},
		{Type: TLVMode, Value: makeModeTLVValue(mode)},
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
	})

	err := ch.HandleChildUpdateResponse(rxInfo)
	if err != nil {
		t.Fatalf("HandleChildUpdateResponse error: %v", err)
	}

	// Pending challenge should be cleared.
	if ch.hasPendingChallenge {
		t.Error("pending challenge should be cleared after successful verification")
	}
}

func TestHandleChildUpdateResponse_ChallengeResponseMismatch(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	var challenge Challenge
	copy(challenge[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	ch.pendingChallenge = challenge
	ch.hasPendingChallenge = true

	mode := mle.GetDeviceMode()
	wrongResponse := []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8}
	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVResponse, Value: wrongResponse},
		{Type: TLVMode, Value: makeModeTLVValue(mode)},
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
	})

	err := ch.HandleChildUpdateResponse(rxInfo)
	if err == nil {
		t.Fatal("HandleChildUpdateResponse should return error on challenge mismatch")
	}
}

func TestHandleChildUpdateResponse_WithStatus_Detaches(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	mode := mle.GetDeviceMode()
	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVStatus, Value: makeStatusTLVValue(StatusError)},
		{Type: TLVMode, Value: makeModeTLVValue(mode)},
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
	})

	err := ch.HandleChildUpdateResponse(rxInfo)
	if err != nil {
		t.Fatalf("HandleChildUpdateResponse error: %v", err)
	}

	if !mle.IsDetached() {
		t.Errorf("device should be detached after receiving Status TLV, got role %s", mle.Role())
	}
}

func TestHandleChildUpdateResponse_ModeMismatch(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	// Use a different mode than ours.
	wrongMode := NewDeviceMode(0) // MTD mode
	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVMode, Value: makeModeTLVValue(wrongMode)},
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
	})

	err := ch.HandleChildUpdateResponse(rxInfo)
	if err == nil {
		t.Fatal("HandleChildUpdateResponse should return error on mode mismatch")
	}
}

func TestHandleChildUpdateResponse_SourceAddressRouterIDMismatch(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	mode := mle.GetDeviceMode()
	// Source address with a different router ID.
	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVMode, Value: makeModeTLVValue(mode)},
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(0x0C00)}, // Router ID 3
	})

	err := ch.HandleChildUpdateResponse(rxInfo)
	if err == nil {
		t.Fatal("HandleChildUpdateResponse should return error on router ID mismatch")
	}
}

func TestHandleChildUpdateResponse_WithTimeout(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	mode := mle.GetDeviceMode()
	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVMode, Value: makeModeTLVValue(mode)},
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
		{Type: TLVTimeout, Value: makeTimeoutTLVValue(300)},
	})

	err := ch.HandleChildUpdateResponse(rxInfo)
	if err != nil {
		t.Fatalf("HandleChildUpdateResponse error: %v", err)
	}

	if mle.GetChildTimeout() != 300 {
		t.Errorf("child timeout = %d, want 300", mle.GetChildTimeout())
	}
}

func TestHandleChildUpdateResponse_WithLinkMargin(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	mode := mle.GetDeviceMode()
	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVMode, Value: makeModeTLVValue(mode)},
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
		{Type: TLVLinkMargin, Value: makeLinkMarginTLVValue(15)}, // 15 dB -> quality 2
	})

	err := ch.HandleChildUpdateResponse(rxInfo)
	if err != nil {
		t.Fatalf("HandleChildUpdateResponse error: %v", err)
	}

	parent := mle.GetParent()
	qualityOut := parent.LinkInfo.GetQualityOut()
	if qualityOut != 2 {
		t.Errorf("parent link quality out = %d, want 2", qualityOut)
	}
}

func TestHandleChildUpdateResponse_NotChild_ReturnsError(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()
	_ = mle.BecomeDetached()

	rxInfo := &RxInfo{
		TLVs: []TLV{
			{Type: TLVMode, Value: makeModeTLVValue(NewDeviceMode(ModeRxOnWhenIdle | ModeFullThreadDevice))},
			{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
		},
	}

	err := ch.HandleChildUpdateResponse(rxInfo)
	if err == nil {
		t.Fatal("HandleChildUpdateResponse should return error when not a child")
	}
}

func TestHandleChildUpdateResponse_NotFromParent_ReturnsError(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	mode := mle.GetDeviceMode()
	rxInfo := rxInfoFromStranger([]TLV{
		{Type: TLVMode, Value: makeModeTLVValue(mode)},
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(0x0800)},
	})

	err := ch.HandleChildUpdateResponse(rxInfo)
	if err == nil {
		t.Fatal("HandleChildUpdateResponse should return error when not from parent")
	}
}

func TestHandleChildUpdateResponse_MissingMode_ReturnsError(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	rxInfo := rxInfoFromParent(mle, []TLV{
		// No Mode TLV.
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
	})

	err := ch.HandleChildUpdateResponse(rxInfo)
	if err == nil {
		t.Fatal("HandleChildUpdateResponse should return error when Mode TLV is missing")
	}
}

func TestHandleChildUpdateResponse_MissingSourceAddress_ReturnsError(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	mode := mle.GetDeviceMode()
	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVMode, Value: makeModeTLVValue(mode)},
		// No SourceAddress.
	})

	err := ch.HandleChildUpdateResponse(rxInfo)
	if err == nil {
		t.Fatal("HandleChildUpdateResponse should return error when SourceAddress is missing")
	}
}

func TestHandleChildUpdateResponse_WithLeaderData(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	mode := mle.GetDeviceMode()
	newLD := defaultLeaderData
	newLD.DataVersion = defaultLeaderData.DataVersion + 3

	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVMode, Value: makeModeTLVValue(mode)},
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
		{Type: TLVLeaderData, Value: makeLeaderDataTLVValue(newLD)},
		{Type: TLVNetworkData, Value: []byte{0xAA}},
	})

	err := ch.HandleChildUpdateResponse(rxInfo)
	if err != nil {
		t.Fatalf("HandleChildUpdateResponse error: %v", err)
	}

	ld := mle.GetLeaderData()
	if ld.DataVersion != newLD.DataVersion {
		t.Errorf("leader data version not updated: got %d, want %d",
			ld.DataVersion, newLD.DataVersion)
	}
}

func TestHandleChildUpdateResponse_ParentInvalidState_ReturnsError(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	// Make parent invalid.
	parent := mle.GetParent()
	parent.State = StateInvalid

	mode := mle.GetDeviceMode()
	rxInfo := rxInfoFromParent(mle, []TLV{
		{Type: TLVMode, Value: makeModeTLVValue(mode)},
		{Type: TLVSourceAddress, Value: makeSourceAddressTLVValue(parentRLOC16)},
	})

	err := ch.HandleChildUpdateResponse(rxInfo)
	if err == nil {
		t.Fatal("HandleChildUpdateResponse should return error when parent is in invalid state")
	}
}

// --- SendDataRequest tests ---

func TestSendDataRequest_Normal(t *testing.T) {
	t.Parallel()
	ch, _, transport, _ := newChildHandlersTestSetup()

	err := ch.SendDataRequest()
	if err != nil {
		t.Fatalf("SendDataRequest error: %v", err)
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
	}

	// Verify destination is parent's link-local IP.
	expectedDst := parentLinkLocalIP(parentExtAddr)
	if transport.sentMessages[0].dst != expectedDst {
		t.Errorf("sent to wrong destination: got %v, want %v",
			transport.sentMessages[0].dst, expectedDst)
	}
}

func TestSendDataRequest_NotAttached_ReturnsError(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()
	_ = mle.BecomeDetached()

	err := ch.SendDataRequest()
	if err == nil {
		t.Fatal("SendDataRequest should return error when not attached")
	}
}

func TestSendDataRequest_ParentNotValid_ReturnsError(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()

	parent := mle.GetParent()
	parent.State = StateInvalid

	err := ch.SendDataRequest()
	if err == nil {
		t.Fatal("SendDataRequest should return error when parent is not valid")
	}
}

// --- SendChildUpdateRequest tests ---

func TestSendChildUpdateRequest_NormalMode(t *testing.T) {
	t.Parallel()
	ch, _, transport, _ := newChildHandlersTestSetup()

	err := ch.SendChildUpdateRequest(ChildUpdateNormal)
	if err != nil {
		t.Fatalf("SendChildUpdateRequest error: %v", err)
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
	}

	// Destination should be parent's link-local IP.
	expectedDst := parentLinkLocalIP(parentExtAddr)
	if transport.sentMessages[0].dst != expectedDst {
		t.Errorf("sent to wrong destination")
	}
}

func TestSendChildUpdateRequest_ChallengeMode(t *testing.T) {
	t.Parallel()
	ch, _, transport, _ := newChildHandlersTestSetup()

	err := ch.SendChildUpdateRequest(ChildUpdateAppendChallenge)
	if err != nil {
		t.Fatalf("SendChildUpdateRequest error: %v", err)
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
	}

	// Pending challenge should be set.
	if !ch.hasPendingChallenge {
		t.Error("pending challenge should be set after ChildUpdateAppendChallenge")
	}

	// The challenge should be non-zero (it's random).
	allZero := true
	for _, b := range ch.pendingChallenge {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("pending challenge should not be all zeros")
	}
}

func TestSendChildUpdateRequest_ZeroTimeoutMode(t *testing.T) {
	t.Parallel()
	ch, _, transport, _ := newChildHandlersTestSetup()

	err := ch.SendChildUpdateRequest(ChildUpdateAppendZeroTimeout)
	if err != nil {
		t.Fatalf("SendChildUpdateRequest error: %v", err)
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
	}
}

func TestSendChildUpdateRequest_NotChild_NormalMode_ReturnsError(t *testing.T) {
	t.Parallel()
	ch, mle, _, _ := newChildHandlersTestSetup()
	_ = mle.BecomeDetached()

	err := ch.SendChildUpdateRequest(ChildUpdateNormal)
	if err == nil {
		t.Fatal("SendChildUpdateRequest(Normal) should return error when not a child")
	}
}

func TestSendChildUpdateRequest_NotChild_ChallengeMode_Allowed(t *testing.T) {
	t.Parallel()
	ch, mle, transport, _ := newChildHandlersTestSetup()
	_ = mle.BecomeDetached()

	// Challenge mode is allowed when not a child (used during re-establish).
	err := ch.SendChildUpdateRequest(ChildUpdateAppendChallenge)
	if err != nil {
		t.Fatalf("SendChildUpdateRequest(Challenge) should be allowed when detached: %v", err)
	}

	if len(transport.sentMessages) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
	}
}

// --- NewChildHandlers registration tests ---

func TestNewChildHandlers_RegistersAllHandlers(t *testing.T) {
	t.Parallel()
	_, mle, _, _ := newChildHandlersTestSetup()

	// The newChildHandlersTestSetup calls NewChildHandlers which registers handlers.
	// Access the dispatcher to verify.
	d, _, _ := newTestDispatcher()
	_ = NewChildHandlers(mle, d, nil, nil)

	expectedCommands := []Command{
		CommandDataResponse,
		CommandChildUpdateRequest,
		CommandChildUpdateResponse,
	}

	for _, cmd := range expectedCommands {
		if _, ok := d.handlers[cmd]; !ok {
			t.Errorf("handler for command %d not registered", cmd)
		}
	}
}

// --- parentLinkLocalIP tests ---

func TestParentLinkLocalIP(t *testing.T) {
	t.Parallel()

	mac := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	ip := parentLinkLocalIP(mac)

	// fe80::0302:0304:0506:0708 (with U/L bit toggled on byte[8])
	expected := [16]byte{
		0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		0x03, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // 0x01 ^ 0x02 = 0x03
	}

	if ip != expected {
		t.Errorf("parentLinkLocalIP(%v) = %v, want %v", mac, ip, expected)
	}
}

// --- appendRequestedTLV tests ---

func TestAppendRequestedTLV_KnownTypes(t *testing.T) {
	t.Parallel()
	ch, _, _, _ := newChildHandlersTestSetup()

	// Test that known TLV types don't panic and produce output.
	knownTypes := []uint8{TLVMode, TLVTimeout, TLVVersion, TLVSourceAddress,
		TLVLeaderData, TLVLinkFrameCounter, TLVMleFrameCounter}

	for _, tlvType := range knownTypes {
		msg := NewMessage(CommandChildUpdateResponse)
		initialLen := len(msg.buf)
		ch.appendRequestedTLV(msg, tlvType)
		if len(msg.buf) <= initialLen {
			t.Errorf("appendRequestedTLV(%d) did not append anything", tlvType)
		}
	}
}

func TestAppendRequestedTLV_UnknownType(t *testing.T) {
	t.Parallel()
	ch, _, _, _ := newChildHandlersTestSetup()

	msg := NewMessage(CommandChildUpdateResponse)
	initialLen := len(msg.buf)
	ch.appendRequestedTLV(msg, 200) // Unknown type
	if len(msg.buf) != initialLen {
		t.Error("appendRequestedTLV should not append anything for unknown TLV type")
	}
}

// --- MleMaxResponseDelay test ---

func TestMleMaxResponseDelay(t *testing.T) {
	t.Parallel()

	if MleMaxResponseDelay != 1000*time.Millisecond {
		t.Errorf("MleMaxResponseDelay = %v, want 1000ms", MleMaxResponseDelay)
	}
}
