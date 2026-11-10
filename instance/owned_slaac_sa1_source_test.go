package instance

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
)

// This file uses APIs/helpers already present in exact1a2. Identical bytes
// accompany unchanged1a2 and the correction; no execution is claimed here.
type sa1StoppedEpisode struct {
	fixture         *ownedAttachFixture
	parent          *fragmentEndpoint
	source          ip6.Address
	oldAttempt      *ThreadAttachAttempt
	oldObservation  ThreadAttachmentObservation
	oldFrameCheck   func() error
	stoppedCounters phase2AdmissionCounters
}

func sa1StopBeforeAcceptedData(t *testing.T) *sa1StoppedEpisode {
	t.Helper()
	fixture, parent, _ := publicFTDWireFixture(t, ownedPrefixWire(true))
	episode := &sa1StoppedEpisode{fixture: fixture, parent: parent,
		source: actualOwnedSlaacAddress(t, fixture), oldAttempt: fixture.attempt}
	destination := ip6.Address{0x20, 1, 0x0d, 0xb8, 0, 2, 15: 0x71}
	mustSRPLoop(t, fixture.node.inst, func() error {
		var err error
		episode.oldObservation, err = fixture.attempt.ObserveAttachment(episode.source)
		if err != nil {
			return err
		}
		return fixture.node.inst.SendUDP([]byte("sa1-old-episode"), ip6.MessageInfo{
			SockAddr: episode.source, PeerAddr: destination, SockPort: 5540, PeerPort: 5540,
		})
	})
	oldPacket := captureSitePacket(t, fixture.node, func(context *mesh.FrameContext) {
		if !context.SecurityEnabled || context.DstExtAddr != udpPeerExt {
			t.Error("initial real source send did not use secured parent MAC handoff")
		}
		mustSRPLoop(t, fixture.node.inst, func() error {
			message := fixture.node.inst.pendingTxMsg
			if message == nil || message.ValidateFrame == nil {
				return fmt.Errorf("actual admitted source packet has no retained frame proof")
			}
			episode.oldFrameCheck = message.ValidateFrame
			return nil
		})
	})
	if !bytes.Equal(oldPacket[8:24], episode.source[:]) || string(oldPacket[48:]) != "sa1-old-episode" {
		t.Fatal("initial authenticated source never traversed actual ordinary TX")
	}
	transition := mle.NewMessage(mle.CommandDataResponse)
	transition.AppendSourceAddressTLV(0x0800)
	transition.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 2, Weighting: 64, LeaderRouterID: 2, DataVersion: 1})
	// Deliberately no Network Data: no second accepted DataResponse follows.
	sendParentAttachMessage(t, parent, fixture, transition, 70)
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		if !inst.mleService.Mle().NeedsNewNetworkData() || inst.netif.HasUnicastAddress(episode.source) {
			return fmt.Errorf("actual changed-partition response did not establish the retrieval/source fence")
		}
		if _, err := episode.oldAttempt.ObserveAttachment(episode.source); !errors.Is(err, goterrors.ErrInvalidSourceAddress) {
			return fmt.Errorf("old source survived the actual unaccepted leader-data transition: %v", err)
		}
		if err := episode.oldFrameCheck(); err == nil {
			return fmt.Errorf("old admitted packet proof survived real source retirement")
		}
		if err := inst.ThreadStop(); err != nil {
			return err
		}
		if !inst.mleService.Mle().NeedsNewNetworkData() {
			return fmt.Errorf("Stop indiscriminately cleared the unaccepted-data fence")
		}
		episode.stoppedCounters = phase2AdmissionSnapshot(inst)
		return nil
	})
	return episode
}

func sa1FreshPublicParentExchange(t *testing.T, episode *sa1StoppedEpisode) {
	t.Helper()
	fixture := episode.fixture
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		before := inst.entropy.(*ownedTestEntropy).source.calls
		var err error
		fixture.attempt, err = inst.BeginThreadAttachWithConfig(ThreadAttachConfig{
			Timeout: 30 * time.Second, Profile: ThreadAttachAwakeFTDChild,
		})
		if err != nil {
			return err
		}
		if fixture.attempt == episode.oldAttempt || inst.entropy.(*ownedTestEntropy).source.calls <= before ||
			!inst.mleService.Mle().NeedsNewNetworkData() || inst.mleService.Mle().Role() != mle.RoleDetached {
			return fmt.Errorf("fresh public Begin reused identity/nonce or cleared the old fence before wire acceptance")
		}
		fixture.node.macKey = inst.keyManager.GetCurrentMacKey()
		return nil
	})
	fixture.fireProtocolTimer(t)
	command, records := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	challenge, present := mle.FindTLV(records, mle.TLVChallenge)
	rawMode, _ := mle.FindTLV(records, mle.TLVMode)
	mode, err := mle.ReadModeTLV(rawMode)
	if command != mle.CommandParentRequest || !present || len(challenge) != 8 || err != nil ||
		!mode.IsRxOnWhenIdle() || !mode.IsFullThreadDevice() || !mode.IsFullNetworkData() {
		t.Fatal("same Instance did not emit a real fresh public full-data Parent Request")
	}
	sendParentAttachMessage(t, episode.parent, fixture, parentResponse(challenge), 80)
	fixture.fireProtocolTimer(t)
	command, records = ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if command != mle.CommandChildIDRequest {
		t.Fatal("fresh authenticated parent did not produce actual CID Request")
	}
	if _, present := mle.FindTLV(records, mle.TLVAddressRegistration); present {
		t.Fatal("fresh FTD child used MTD address registration")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		if !fixture.node.inst.mleService.Mle().NeedsNewNetworkData() {
			return fmt.Errorf("fresh Parent/CID request cleared the old fence before accepted full data")
		}
		return nil
	})
}

func sa1AcceptFullCIDAndSend(t *testing.T, episode *sa1StoppedEpisode, counter uint32) {
	t.Helper()
	fixture := episode.fixture
	data := ownedPrefixWire(true)
	response := childIDResponseWithNetworkData(0x0801, data)
	var mask mle.RouterIDSet
	mask.Add(2)
	mask.Add(3)
	response.AppendRoute64TLV(1, mask, []mle.Route64Entry{{Cost: 0}, {Cost: 1}})
	sendParentAttachMessage(t, episode.parent, fixture, response, counter)
	result := awaitOwnedAttach(t, fixture.attempt)
	if result.Err != nil || result.Role != mle.RoleChild || !bytes.Equal(result.NetworkData, data) {
		t.Fatal("fresh authenticated full-data CID did not complete its real public attachment")
	}
	source := actualOwnedSlaacAddress(t, fixture)
	destination := ip6.Address{0x20, 1, 0x0d, 0xb8, 0, 2, 15: 0x72}
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		current, err := fixture.attempt.ObserveAttachment(source)
		if err != nil {
			return fmt.Errorf("SA1 fresh authenticated CID retained previous-episode data fence at actual Observe: %w", err)
		}
		if source != episode.source || current.Epoch == episode.oldObservation.Epoch ||
			current == episode.oldObservation || inst.mleService.Mle().NeedsNewNetworkData() {
			return fmt.Errorf("fresh CID did not reconcile only the new episode's accepted source")
		}
		if _, err := episode.oldAttempt.ObserveAttachment(source); !errors.Is(err, goterrors.ErrInvalidState) {
			return fmt.Errorf("old opaque attempt acquired the new episode's source: %v", err)
		}
		if err := episode.oldFrameCheck(); err == nil {
			return fmt.Errorf("old admitted source proof acquired fresh same-address authority")
		}
		counters := phase2AdmissionSnapshot(inst)
		if counters.mac < episode.stoppedCounters.mac || counters.mle < episode.stoppedCounters.mle {
			return fmt.Errorf("same-Instance fresh attach reset security counters")
		}
		return inst.SendUDP([]byte("sa1-fresh-episode"), ip6.MessageInfo{
			SockAddr: source, PeerAddr: destination, SockPort: 5540, PeerPort: 5540,
		})
	})
	packet := captureSitePacket(t, fixture.node, func(context *mesh.FrameContext) {
		if !context.SecurityEnabled || context.SrcExtAddr != fragmentSource || context.DstExtAddr != udpPeerExt {
			t.Error("fresh source did not traverse actual secured parent MAC TX")
		}
	})
	if !bytes.Equal(packet[8:24], source[:]) || !bytes.Equal(packet[24:40], destination[:]) ||
		string(packet[48:]) != "sa1-fresh-episode" {
		t.Fatal("fresh current source did not retain actual ordinary TX IPv6 tuple/payload")
	}
}

func TestOwnedSlaacSA1FreshAuthenticatedCIDReconcilesPreviousEpisodeRetrieval(t *testing.T) {
	episode := sa1StopBeforeAcceptedData(t)
	sa1FreshPublicParentExchange(t, episode)
	sa1AcceptFullCIDAndSend(t, episode, 81)
}

func TestOwnedSlaacSA1RejectedFreshCIDCannotClearPreviousEpisodeFence(t *testing.T) {
	for _, kind := range []string{"missing-network-data", "malformed-network-data", "wrong-parent-source"} {
		t.Run(kind, func(t *testing.T) {
			episode := sa1StopBeforeAcceptedData(t)
			sa1FreshPublicParentExchange(t, episode)
			fixture := episode.fixture
			rejected := mle.NewMessage(mle.CommandChildIDResponse)
			source := uint16(0x0800)
			if kind == "wrong-parent-source" {
				source = 0x0c00
			}
			rejected.AppendSourceAddressTLV(source)
			rejected.AppendAddress16TLV(0x0801)
			rejected.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 1, Weighting: 64, LeaderRouterID: 2})
			if kind != "missing-network-data" {
				data := ownedPrefixWire(true)
				if kind == "malformed-network-data" {
					data = data[:len(data)-1]
				}
				rejected.AppendNetworkDataTLV(data)
			}
			sendParentAttachMessage(t, episode.parent, fixture, rejected, 81)
			mustSRPLoop(t, fixture.node.inst, func() error {
				inst := fixture.node.inst
				if !inst.mleService.Mle().NeedsNewNetworkData() || inst.mleService.Mle().IsChild() ||
					inst.netif.HasUnicastAddress(episode.source) {
					return fmt.Errorf("rejected fresh CID cleared retrieval/created source or Child success")
				}
				select {
				case <-fixture.attempt.Result():
					return fmt.Errorf("rejected CID completed the pending public attempt")
				default:
				}
				if _, err := fixture.attempt.ObserveAttachment(episode.source); !errors.Is(err, goterrors.ErrInvalidState) {
					return fmt.Errorf("unaccepted fresh CID became observable source authority: %v", err)
				}
				return nil
			})
			sa1AcceptFullCIDAndSend(t, episode, 82)
		})
	}
}
