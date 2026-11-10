package instance

import (
	"bytes"
	"context"
	"crypto/hmac"
	stdsha256 "crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/lowpan"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
)

func ownedDataset() *meshcop.Dataset {
	info := &meshcop.Info{
		NetworkName: "OwnedThread", NetworkKey: [16]byte{1, 2, 3, 4, 5},
		ExtendedPanID:   [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		MeshLocalPrefix: [8]byte{0xfd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
		PanID:           0xface, Channel: 20, ChannelMask: meshcop.Page0ThreadChannelMask,
		Components: meshcop.Components{
			ActiveTimestamp: true, NetworkKey: true, NetworkName: true, ExtendedPanID: true,
			MeshLocalPrefix: true, PanID: true, Channel: true, ChannelMask: true, PSKc: true, SecurityPolicy: true,
		},
	}
	info.ActiveTimestamp.SetSeconds(1)
	info.SecurityPolicy.SetToDefault()
	return meshcop.InfoToDataset(info)
}

type ownedAttachFixture struct {
	node    *fragmentEndpoint
	store   *srpSettings
	now     time.Time
	eid     ip6.Address
	attempt *ThreadAttachAttempt
}

func newOwnedAttachFixture(t *testing.T, assign bool) *ownedAttachFixture {
	return newOwnedAttachFixtureWithSettings(t, assign, nil)
}

func newOwnedAttachFixtureWithSettings(t *testing.T, assign bool, provided platform.Settings) *ownedAttachFixture {
	return newOwnedAttachFixtureWithRadio(t, assign, provided, nil)
}

func newOwnedAttachFixtureWithRadio(t *testing.T, assign bool, provided platform.Settings, wrap func(*fragmentRadio) radio.Radio) *ownedAttachFixture {
	t.Helper()
	store := newSRPSettings()
	var storage platform.Settings = store
	if provided != nil {
		storage = provided
	}
	driver := &fragmentRadio{
		boundedUDPRadio: &boundedUDPRadio{captures: make(chan udpRadioCapture, 2), settings: storage},
		identity:        fragmentSource,
		caps:            radio.CapCsmaBackoff | radio.CapTransmitRetries | radio.CapAckTimeout,
	}
	fixture := &ownedAttachFixture{
		node: &fragmentEndpoint{driver: driver}, store: store, now: time.Now(),
		eid: ip6.Address{0xfd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 8: 0x61, 15: 0x27},
	}
	var actualRadio radio.Radio = driver
	if wrap != nil {
		actualRadio = wrap(driver)
	}
	fixture.node.inst = New(Config{Radio: actualRadio, Settings: storage, Entropy: &ownedTestEntropy{}})
	if err := fixture.node.inst.StageOperationalDatasets(DatasetRecord{Present: true, TLVs: ownedDataset().Bytes()}, DatasetRecord{}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.node.inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fixture.node.inst.Stop)
	mustSRPLoop(t, fixture.node.inst, func() error {
		fixture.node.inst.timers.now = func() time.Time { return fixture.now }
		fixture.node.inst.mleService.Mle().SetDeviceMode(mle.NewDeviceMode(mle.ModeRxOnWhenIdle))
		fixture.node.inst.mac.SetRxOnWhenIdle(true)
		if assign {
			if err := fixture.node.inst.netif.AddExternalUnicastAddress(&ip6.UnicastAddress{
				Address: fixture.eid, PrefixLength: 64, Valid: true, Preferred: true, MeshLocal: true,
			}); err != nil {
				return err
			}
		}
		return fixture.node.inst.IfConfigUp()
	})
	return fixture
}

func (fixture *ownedAttachFixture) begin(t *testing.T) {
	fixture.beginProfile(t, ThreadAttachAwakeMTD)
}

func (fixture *ownedAttachFixture) beginProfile(t *testing.T, profile ThreadAttachProfile) {
	t.Helper()
	mustSRPLoop(t, fixture.node.inst, func() error {
		var err error
		fixture.attempt, err = fixture.node.inst.BeginThreadAttachWithConfig(ThreadAttachConfig{Timeout: 30 * time.Second, Profile: profile})
		fixture.node.macKey = fixture.node.inst.keyManager.GetCurrentMacKey()
		return err
	})
}

func TestOwnedFTDChildEntropyFailureFailsBeforeAdmission(t *testing.T) {
	store := &datasetWriteFault{SimSettings: simulation.NewSimSettings()}
	fixture := newOwnedAttachFixtureWithSettings(t, true, store)
	before := observeInitialParent(t, fixture, store)
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		mode, role, eligible := inst.mleService.Mle().GetDeviceMode(), inst.mleService.Mle().Role(), inst.mleService.Mle().IsRouterEligible()
		inst.entropy.(*ownedTestEntropy).source.fail = true // A challenge read would fail/latch.
		attempt, err := inst.BeginThreadAttachWithConfig(ThreadAttachConfig{Timeout: time.Second, Profile: ThreadAttachAwakeFTDChild})
		if attempt != nil || !errors.Is(err, errSRPEntropy) {
			return fmt.Errorf("FTD profile lost checked entropy failure: %v", err)
		}
		if inst.threadEnabled || inst.threadAttach != nil || !errors.Is(inst.SecurityError(), errSRPEntropy) ||
			inst.mleService.Mle().Role() != role || inst.mleService.Mle().GetDeviceMode() != mode ||
			inst.mleService.Mle().IsRouterEligible() != eligible {
			return fmt.Errorf("failed FTD entropy changed mode/role/eligibility or lost its cause")
		}
		return nil
	})
	after := observeInitialParent(t, fixture, store)
	if !bytes.Equal(before.record, after.record) || before.writes != after.writes ||
		before.mac != after.mac || before.mle != after.mle || before.addresses != after.addresses ||
		len(fixture.node.driver.captures) != 0 {
		t.Fatal("failed FTD entropy changed persistence/counters/addresses or emitted traffic")
	}
}

func (fixture *ownedAttachFixture) fireProtocolTimer(t *testing.T) {
	t.Helper()
	mustSRPLoop(t, fixture.node.inst, func() error {
		delay := fixture.node.inst.mleService.Attacher.NextTimerDelay
		if delay <= 0 {
			return fmt.Errorf("no actual attach timer")
		}
		fixture.now = fixture.now.Add(delay)
		fixture.node.inst.timers.processExpired()
		return nil
	})
}

func ownedSentMLE(t *testing.T, node *fragmentEndpoint, capture udpRadioCapture) (mle.Command, []mle.TLV) {
	t.Helper()
	var packet []byte
	var sourceEUI types.ExtAddress
	for frames := 0; frames < 20; frames++ {
		ctx, offset, err := mesh.NewFramer().ParseFrameHeader(capture.frame.PSDU)
		if err != nil || capture.frame.TxInfo.SubmissionID == 0 {
			t.Fatal("actual owned MLE frame missing")
		}
		sourceEUI = ctx.SrcExtAddr
		adaptation := capture.frame.PSDU[offset:]
		if ctx.SecurityEnabled {
			adaptation, err = mesh.DecryptFramePayload(capture.frame.PSDU, offset, ctx, node.macKey, sourceEUI)
			if err != nil {
				t.Fatal(err)
			}
		}
		addresses := lowpan.AddressContext{
			SrcExtAddr: ctx.SrcExtAddr, DstExtAddr: ctx.DstExtAddr,
			SrcShort: types.ShortAddress(ctx.SrcShortAddr), DstShort: types.ShortAddress(ctx.DstShortAddr),
			SrcShortValid: ctx.UseSrcShort, DstShortValid: ctx.UseDstShort,
		}
		last := true
		if lowpan.IsFragment(adaptation) {
			header, n, err := lowpan.ParseFragmentHeader(adaptation)
			if err != nil {
				t.Fatal(err)
			}
			body := adaptation[n:]
			if header.IsFirst {
				packet = make([]byte, header.DatagramSize)
				body, err = lowpan.DecompressDatagram(body, addresses, header.DatagramSize)
				if err != nil {
					t.Fatal(err)
				}
			}
			if packet == nil || int(header.DatagramOffset)+len(body) > len(packet) {
				t.Fatal("invalid original fragment coordinates")
			}
			copy(packet[int(header.DatagramOffset):], body)
			last = int(header.DatagramOffset)+len(body) == len(packet)
		} else {
			packet, err = lowpan.DecompressDatagram(adaptation, addresses, 0)
			if err != nil {
				t.Fatal(err)
			}
		}
		completeNativeFrame(t, node, capture, nil)
		if last {
			break
		}
		capture = captureUDP(t, node.driver.boundedUDPRadio)
	}
	if packet == nil {
		t.Fatal("no complete actual MLE packet")
	}
	var source, destination ip6.Address
	copy(source[:], packet[8:24])
	copy(destination[:], packet[24:40])
	message, err := mle.ParseMessage(packet[48:])
	if err != nil || message.SecuritySuite != mle.SecuritySuiteEncMic32 {
		t.Fatal("real MLE encryption missing")
	}
	// Independent software-peer derivation from the FULL wire source, not a
	// client-field inspection or its current/adjacent resolver.
	hash := hmac.New(stdsha256.New, []byte{1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	var sequence [4]byte
	binary.BigEndian.PutUint32(sequence[:], message.SecHeader.KeySource)
	_, _ = hash.Write(sequence[:])
	_, _ = hash.Write([]byte("Thread"))
	var peerKey [16]byte
	copy(peerKey[:], hash.Sum(nil)[:16])
	plaintext, err := message.DecryptPayload(peerKey, sourceEUI, source, destination, message.SecHeader.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	tlvs, err := mle.ParseTLVs(plaintext[1:])
	if err != nil {
		t.Fatal(err)
	}
	return mle.Command(plaintext[0]), tlvs
}

// The parent fixture emits independent real MLE messages over its production
// secured forwarder/radio. It never sets the client role/RLOC/neighbor state.
func sendParentAttachMessage(t *testing.T, parent *fragmentEndpoint, child *ownedAttachFixture, message *mle.Message, counter uint32) {
	sendParentAttachMessageWithMutation(t, parent, child, message, counter, nil)
}

func sendParentAttachMessageWithMutation(t *testing.T, parent *fragmentEndpoint, child *ownedAttachFixture, message *mle.Message, counter uint32, mutate func([]byte)) {
	t.Helper()
	for _, capture := range captureParentAttachMessage(t, parent, child, message, counter, mutate) {
		deliverNativeFrame(t, child.node, capture)
	}
	mustSRPLoop(t, child.node.inst, func() error { return nil })
}

func captureParentAttachMessage(t *testing.T, parent *fragmentEndpoint, child *ownedAttachFixture, message *mle.Message, counter uint32, mutate func([]byte)) []udpRadioCapture {
	t.Helper()
	mustSRPLoop(t, parent.inst, func() error {
		source, destination := parent.inst.GetLinkLocalAddress(), child.node.inst.GetLinkLocalAddress()
		if message.IsSecured() {
			if err := message.Finalize(mle.NewSecurityHeader(parent.inst.keyManager.GetCurrentKeySequence(), counter),
				parent.inst.keyManager.GetCurrentMleKey(), parent.inst.GetExtAddress(), source, destination); err != nil {
				return err
			}
			if mutate != nil {
				mutate(message.Bytes())
			}
		}
		tx := parent.inst.newUDPMessage(message.Bytes(), ip6.MessageInfo{
			SockAddr: source, PeerAddr: destination, SockPort: mle.UDPPort, PeerPort: mle.UDPPort, HopLimit: mle.ControlHopLimit,
		})
		tx.Metadata.UseSrcShort = false
		tx.Metadata.UseDstShort = false
		tx.Metadata.SecurityEnabled = false // Reference normal MLE is inner-EncMIC protected, not MAC encrypted.
		tx.Metadata.DstExtAddr = child.node.driver.identity
		tx.MeshDest = 0x0801
		return parent.inst.sendViaForwarder(tx)
	})
	var captures []udpRadioCapture
	var fragmentTag, fragmentSize uint16
	for frames := 0; frames < 20; frames++ {
		capture := captureUDP(t, parent.driver.boundedUDPRadio)
		ctx, offset, err := mesh.NewFramer().ParseFrameHeader(capture.frame.PSDU)
		if err != nil || ctx.SecurityEnabled || capture.frame.TxInfo.SubmissionID == 0 {
			t.Fatal("normal parent MLE must carry inner authentication without outer link security")
		}
		last := true
		payload := capture.frame.PSDU[offset:]
		if lowpan.IsFragment(payload) {
			header, n, err := lowpan.ParseFragmentHeader(payload)
			if err != nil {
				t.Fatal(err)
			}
			if frames == 0 {
				if !header.IsFirst {
					t.Fatal("actual parent sender did not start its datagram with FRAG1")
				}
				fragmentTag, fragmentSize = header.DatagramTag, header.DatagramSize
			}
			if header.DatagramTag != fragmentTag || header.DatagramSize != fragmentSize {
				t.Fatal("parent capture crossed actual datagram identity")
			}
			last = !header.IsFirst && int(header.DatagramOffset)+len(payload[n:]) == int(header.DatagramSize)
		} else if frames != 0 {
			t.Fatal("parent capture ended a fragmented datagram with unrelated wire")
		}
		captures = append(captures, capture)
		completeNativeFrame(t, parent, capture, nil)
		// pendingTxMsg is cleared after EACH frame, before the next zero-delay
		// MAC request. Only actual FRAGN coverage proves datagram completion.
		if last {
			break
		}
		if frames == 19 {
			t.Fatal("unbounded parent MLE fragments")
		}
	}
	return captures
}

func parentResponse(challenge []byte) *mle.Message {
	return parentResponseMessage(challenge, true)
}

func parentResponseMessage(challenge []byte, secured bool) *mle.Message {
	message := mle.NewMessage(mle.CommandParentResponse)
	if !secured {
		message = mle.NewUnsecuredMessage(mle.CommandParentResponse)
	}
	message.AppendSourceAddressTLV(0x0800)
	message.AppendVersionTLV(3)
	message.AppendResponseTLV(challenge)
	message.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 1, Weighting: 64, LeaderRouterID: 2})
	message.AppendLinkMarginTLV(50)
	message.AppendConnectivityTLV(mle.ConnectivityTLV{LinkQuality3: 1, LeaderCost: 0, ActiveRouters: 1, SEDBufferSize: 1280, SEDDatagramCount: 1})
	message.AppendLinkFrameCounterTLV(10)
	message.AppendMleFrameCounterTLV(10)
	message.AppendChallengeTLV(mle.Challenge{1, 2, 3, 4, 5, 6, 7, 8})
	return message
}

func awaitOwnedAttach(t *testing.T, attempt *ThreadAttachAttempt) ThreadAttachResult {
	t.Helper()
	select {
	case result, ok := <-attempt.Result():
		if !ok {
			t.Fatal("missing terminal attach result")
		}
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("owned attach result did not complete")
		return ThreadAttachResult{}
	}
}

func childIDResponse(rloc uint16) *mle.Message {
	return childIDResponseWithNetworkData(rloc, nil)
}

func childIDResponseWithNetworkData(rloc uint16, data []byte) *mle.Message {
	message := mle.NewMessage(mle.CommandChildIDResponse)
	message.AppendSourceAddressTLV(0x0800)
	message.AppendAddress16TLV(rloc)
	message.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 1, Weighting: 64, LeaderRouterID: 2})
	message.AppendNetworkDataTLV(data)
	return message
}

func TestOwnedAttachActualAuthenticatedRadioExchange(t *testing.T) {
	fixture := newOwnedAttachFixture(t, true)
	parent := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
	fixture.begin(t)
	select {
	case <-fixture.attempt.Result():
		t.Fatal("admission falsely completed attach")
	default:
	}
	fixture.fireProtocolTimer(t)
	request := captureUDP(t, fixture.node.driver.boundedUDPRadio)
	ctx, _, err := mesh.NewFramer().ParseFrameHeader(request.frame.PSDU)
	if err != nil || ctx.SecurityEnabled || !ctx.UseDstShort || ctx.DstShortAddr != 0xffff || ctx.AckRequest {
		t.Fatal("actual Parent Request not standard short broadcast/no-ACK")
	}
	command, records := ownedSentMLE(t, fixture.node, request)
	if command != mle.CommandParentRequest {
		t.Fatal("not a real Parent Request")
	}
	challenge, ok := mle.FindTLV(records, mle.TLVChallenge)
	if !ok {
		t.Fatal("missing fresh challenge")
	}
	sendParentAttachMessage(t, parent, fixture, parentResponse(challenge), 11)
	fixture.fireProtocolTimer(t)
	request = captureUDP(t, fixture.node.driver.boundedUDPRadio)
	command, records = ownedSentMLE(t, fixture.node, request)
	if command != mle.CommandChildIDRequest {
		t.Fatal("real selected-parent Child ID Request missing")
	}
	registration, ok := mle.FindTLV(records, mle.TLVAddressRegistration)
	if !ok {
		t.Fatal("actual caller EID was not registered")
	}
	entries, err := mle.ReadAddressRegistrationTLV(registration)
	if err != nil || len(entries) != 1 || entries[0].Address != fixture.eid {
		t.Fatal("actual wire request did not own/register exact caller EID")
	}
	sendParentAttachMessage(t, parent, fixture, childIDResponse(0x0801), 12)
	result := awaitOwnedAttach(t, fixture.attempt)
	if result.Err != nil || result.Role != mle.RoleChild || result.RLOC16 != 0x0801 ||
		result.ParentVersion != 3 || result.ParentExtAddress != udpPeerExt {
		t.Fatalf("actual authenticated result incorrect: %v", result.Err)
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		if fixture.node.inst.RLOC16() != result.RLOC16 ||
			fixture.node.inst.mleService.Mle().RLOC16() != result.RLOC16 ||
			fixture.node.inst.mac.GetShortAddress() != types.ShortAddress(result.RLOC16) ||
			!fixture.node.inst.netif.HasUnicastAddress(fixture.eid) ||
			!fixture.node.inst.netif.HasUnicastAddress(fixture.node.inst.GetMeshLocalAddress()) {
			return fmt.Errorf("actual response did not establish identity/address coherence")
		}
		return nil
	})
	result.Addresses[0].Address[15] ^= 1
	mustSRPLoop(t, fixture.node.inst, func() error {
		if !fixture.node.inst.netif.HasUnicastAddress(fixture.eid) {
			return fmt.Errorf("result borrowed live address")
		}
		return nil
	})
}

func TestOwnedAttachMissingEIDAndCancelGeneration(t *testing.T) {
	missing := newOwnedAttachFixture(t, false)
	mustSRPLoop(t, missing.node.inst, func() error {
		_, err := missing.node.inst.BeginThreadAttach(time.Second)
		if !errors.Is(err, goterrors.ErrInvalidSourceAddress) || len(missing.node.driver.captures) != 0 {
			return fmt.Errorf("missing EID admitted traffic: %v", err)
		}
		return nil
	})
	fixture := newOwnedAttachFixture(t, true)
	fixture.begin(t)
	old := fixture.attempt
	mustSRPLoop(t, fixture.node.inst, old.Cancel)
	if result := awaitOwnedAttach(t, old); !errors.Is(result.Err, context.Canceled) {
		t.Fatal("explicit cancellation cause lost")
	}
	fixture.begin(t)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if err := old.Cancel(); err != nil {
			return err
		}
		select {
		case <-fixture.attempt.Result():
			return fmt.Errorf("old cancellation completed new generation")
		default:
		}
		fixture.now = fixture.now.Add(time.Minute)
		fixture.node.inst.timers.processExpired()
		return nil
	})
	result := awaitOwnedAttach(t, fixture.attempt)
	if !errors.Is(result.Err, context.DeadlineExceeded) {
		t.Fatalf("missing actual deadline: %v", result.Err)
	}
}

func TestOwnedDatasetSnapshotDoesNotRestoreSecurityState(t *testing.T) {
	fixture := newOwnedAttachFixture(t, true)
	var snapshot OperationalDatasetSnapshot
	var signing []byte
	mustSRPLoop(t, fixture.node.inst, func() error {
		var err error
		snapshot, err = fixture.node.inst.ReadOperationalDatasets()
		if err != nil {
			return err
		}
		if _, err = fixture.node.inst.loadSRPKey(); err != nil {
			return err
		}
		signing, err = fixture.store.Get(platform.SettingsKeySRPECDSAKey, 0)
		return err
	})
	fixture.begin(t)
	fixture.fireProtocolTimer(t)
	frame := captureUDP(t, fixture.node.driver.boundedUDPRadio)
	completeNativeFrame(t, fixture.node, frame, nil)
	mustSRPLoop(t, fixture.node.inst, fixture.attempt.Cancel)
	before, err := fixture.store.Get(platform.SettingsKeyNetworkInfo, 0)
	if err != nil {
		t.Fatal(err)
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		return fixture.node.inst.StageOperationalDatasets(snapshot.Active, snapshot.Pending)
	})
	after, _ := fixture.store.Get(platform.SettingsKeyNetworkInfo, 0)
	keyAfter, _ := fixture.store.Get(platform.SettingsKeySRPECDSAKey, 0)
	if binary.BigEndian.Uint32(after[37:41]) < binary.BigEndian.Uint32(before[37:41]) ||
		binary.BigEndian.Uint32(after[41:45]) < binary.BigEndian.Uint32(before[41:45]) || !bytes.Equal(signing, keyAfter) {
		t.Fatal("dataset-only rollback rewound counter reservations or signing identity")
	}
}
