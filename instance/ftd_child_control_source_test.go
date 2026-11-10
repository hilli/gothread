package instance

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/thread/mle"
)

var controlPeerExt = types.ExtAddress{0x26, 1, 2, 3, 4, 5, 6, 7}

// Retains private-engine boundary coverage through authenticated attach wire.
// Separate public-entry oracles do not turn either fixture into native readiness.
func dormantFTDControlFixture(t *testing.T) (*ownedAttachFixture, *fragmentEndpoint) {
	fixture, _, peer := dormantFTDControlWithData(t, nil)
	return fixture, peer
}

func dormantFTDControlWithData(t *testing.T, data []byte, stores ...platform.Settings) (fixture *ownedAttachFixture, parent, peer *fragmentEndpoint) {
	t.Helper()
	if len(stores) == 0 {
		fixture = newOwnedAttachFixture(t, true)
	} else {
		if len(stores) != 1 {
			t.Fatal("one explicit Settings backend required")
		}
		fixture = newOwnedAttachFixtureWithSettings(t, true, stores[0])
	}
	parent = newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
	mustSRPLoop(t, fixture.node.inst, func() error {
		var err error
		fixture.attempt, err = fixture.node.inst.beginThreadAttach(ThreadAttachConfig{Timeout: 30 * time.Second, Profile: ThreadAttachAwakeFTDChild})
		return err
	})
	fixture.fireProtocolTimer(t)
	command, records := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if command != mle.CommandParentRequest {
		t.Fatal("no real FTD Parent Request")
	}
	raw, _ := mle.FindTLV(records, mle.TLVMode)
	mode, err := mle.ReadModeTLV(raw)
	if err != nil || !mode.IsFullThreadDevice() || !mode.IsFullNetworkData() || !mode.IsRxOnWhenIdle() {
		t.Fatal("wrong FTD wire mode")
	}
	challenge, _ := mle.FindTLV(records, mle.TLVChallenge)
	sendParentAttachMessage(t, parent, fixture, parentResponse(challenge), 60)
	fixture.fireProtocolTimer(t)
	command, records = ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if command != mle.CommandChildIDRequest {
		t.Fatal("no real FTD CID Request")
	}
	if _, present := mle.FindTLV(records, mle.TLVAddressRegistration); present {
		t.Fatal("FTD used MTD registration")
	}
	var mask mle.RouterIDSet
	mask.Add(2)
	mask.Add(3)
	reply := childIDResponseWithNetworkData(0x0801, data)
	reply.AppendRoute64TLV(1, mask, []mle.Route64Entry{{Cost: 0}, {Cost: 1}})
	sendParentAttachMessage(t, parent, fixture, reply, 61)
	if result := awaitOwnedAttach(t, fixture.attempt); result.Err != nil || result.Role != mle.RoleChild || result.ParentExtAddress != udpPeerExt {
		t.Fatal("no actual authenticated FTD child")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		if fixture.node.inst.mleService.Mle().IsRouterEligible() {
			return fmt.Errorf("router eligibility changed")
		}
		return nil
	})
	peer = newFragmentEndpoint(t, controlPeerExt, fragmentSource, 0x0c00, 0x0801, simulation.NewSimSettings())
	return fixture, parent, peer
}

func controlAdvertisement() *mle.Message {
	message := mle.NewMessage(mle.CommandAdvertisement)
	message.AppendSourceAddressTLV(0x0c00)
	message.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 1, Weighting: 64, LeaderRouterID: 2})
	var mask mle.RouterIDSet
	mask.Add(2)
	mask.Add(3)
	message.AppendRoute64TLV(1, mask, []mle.Route64Entry{{Cost: 1}, {Cost: 0}})
	return message
}

func startOwnedControlRequest(t *testing.T, fixture *ownedAttachFixture, peer *fragmentEndpoint) []byte {
	t.Helper()
	sendParentAttachMessage(t, peer, fixture, controlAdvertisement(), 70)
	mustSRPLoop(t, fixture.node.inst, func() error {
		fixture.now = fixture.now.Add(mle.MaxLinkRequestDelayOnChild)
		fixture.node.inst.timers.processExpired()
		return nil
	})
	command, records := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if command != mle.CommandLinkRequest {
		t.Fatal("no actual nonparent Link Request")
	}
	challenge, present := mle.FindTLV(records, mle.TLVChallenge)
	if !present || len(challenge) != 8 {
		t.Fatal("missing actual checked nonce")
	}
	return append([]byte(nil), challenge...)
}

func controlLinkAccept(challenge []byte, andRequest bool) *mle.Message {
	command := mle.CommandLinkAccept
	if andRequest {
		command = mle.CommandLinkAcceptAndRequest
	}
	message := mle.NewMessage(command)
	message.AppendSourceAddressTLV(0x0c00)
	message.AppendVersionTLV(3)
	message.AppendResponseTLV(challenge)
	message.AppendLinkFrameCounterTLV(50)
	message.AppendMleFrameCounterTLV(71)
	message.AppendLinkMarginTLV(50)
	message.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 1, Weighting: 64, LeaderRouterID: 2})
	if andRequest {
		message.AppendChallengeTLV(mle.Challenge{8, 7, 6, 5, 4, 3, 2, 1})
		message.AppendTLVRequestTLV([]uint8{mle.TLVLinkMargin})
	}
	return message
}

func TestDormantFTDActualNonparentControlDoesNotAdmitApplicationData(t *testing.T) {
	fixture, peer := dormantFTDControlFixture(t)
	challenge := startOwnedControlRequest(t, fixture, peer)
	wrong := append([]byte(nil), challenge...)
	wrong[0] ^= 1
	sendParentAttachMessage(t, peer, fixture, controlLinkAccept(wrong, false), 71)
	mustSRPLoop(t, fixture.node.inst, func() error {
		record := fixture.node.inst.ownedPeerByAddress(controlPeerExt)
		if record == nil || !record.awaiting || record.router.IsStateValid() {
			return fmt.Errorf("wrong challenge changed control state")
		}
		return nil
	})
	sendParentAttachMessage(t, peer, fixture, controlLinkAccept(challenge, false), 72)
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		record := inst.ownedPeerByAddress(controlPeerExt)
		if record == nil || record.awaiting || record.expected != nil || !record.router.IsStateValid() {
			return fmt.Errorf("actual Link Accept did not commit stable control state")
		}
		err := inst.SendUDP([]byte("not-a-data-route"), ip6.MessageInfo{
			SockAddr: inst.GetLinkLocalAddress(), PeerAddr: linkLocalAddress(controlPeerExt), SockPort: 1234, PeerPort: 1234,
		})
		if !errors.Is(err, goterrors.ErrNoRoute) {
			return fmt.Errorf("control link admitted app data: %v", err)
		}
		return nil
	})
	unsolicited := mle.NewMessage(mle.CommandLinkRequest)
	unsolicited.AppendSourceAddressTLV(0x0c00)
	unsolicited.AppendVersionTLV(3)
	unsolicited.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 1, Weighting: 64, LeaderRouterID: 2})
	unsolicited.AppendChallengeTLV(mle.Challenge{1, 1, 1, 1, 1, 1, 1, 1})
	sendParentAttachMessage(t, peer, fixture, unsolicited, 73)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if len(fixture.node.driver.captures) != 0 {
			return fmt.Errorf("child became generic Link Request responder")
		}
		return nil
	})
}

func TestDormantFTDExpectedFragmentedLinkReplyUsesSharedQuarantine(t *testing.T) {
	fixture, peer := dormantFTDControlFixture(t)
	challenge := startOwnedControlRequest(t, fixture, peer)
	message := controlLinkAccept(challenge, true)
	var packet []byte
	mustSRPLoop(t, peer.inst, func() error {
		src, dst := peer.inst.GetLinkLocalAddress(), fixture.node.inst.GetLinkLocalAddress()
		if err := message.Finalize(mle.NewSecurityHeader(peer.inst.keyManager.GetCurrentKeySequence(), 71),
			peer.inst.keyManager.GetCurrentMleKey(), peer.inst.GetExtAddress(), src, dst); err != nil {
			return err
		}
		ipv6 := ip6.NewHeader(src, dst, ip6.ProtoUDP, 255, uint16(8+len(message.Bytes())))
		header := ipv6.Bytes()
		udp := fixtureUDPHeader(src, dst, mle.UDPPort, mle.UDPPort, message.Bytes())
		packet = append(header[:], udp[:]...)
		packet = append(packet, message.Bytes()...)
		return nil
	})
	if len(packet)+1 != 121 {
		t.Fatal("not the literal uncompressed 121>104 link form")
	}
	frames := literalParentFragments(t, packet, controlPeerExt, fragmentSource, 0x7531)
	deliverAttachCaptures(t, fixture, frames[:1])
	mustSRPLoop(t, fixture.node.inst, func() error {
		candidate := fixture.node.inst.initialMLEFragment
		if candidate == nil || candidate.expected == nil || candidate.expected.peer == nil {
			return fmt.Errorf("no shared expected-link quarantine")
		}
		return nil
	})
	deliverAttachCaptures(t, fixture, frames[1:])
	command, records := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	response, _ := mle.FindTLV(records, mle.TLVResponse)
	if command != mle.CommandLinkAccept || !bytes.Equal(response, []byte{8, 7, 6, 5, 4, 3, 2, 1}) {
		t.Fatal("no authenticated actual AcceptAndRequest reply")
	}
}
