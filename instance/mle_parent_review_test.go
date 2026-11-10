package instance

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/mle"
)

// This oracle uses only APIs/helpers already present in exact43ca, so the
// identical file can be compiled there before its old/fixed assertion run.
func TestOwnedAttachedParentControlRequiresInnerAuthentication(t *testing.T) {
	fixture, parent := ownedAttachedMTD(t)
	var before []byte
	var macCounter, mleCounter uint32
	attachment := fixture.node.inst.ownedAttachment
	mustSRPLoop(t, fixture.node.inst, func() error {
		var err error
		before, err = fixture.store.Get(platform.SettingsKeyNetworkInfo, 0)
		before = append([]byte(nil), before...)
		macCounter = fixture.node.inst.keyManager.GetMacFrameCounter()
		mleCounter = fixture.node.inst.keyManager.GetMleFrameCounter()
		return err
	})
	forged := mle.NewUnsecuredMessage(mle.CommandChildUpdateRequest)
	forged.AppendSourceAddressTLV(0x0800)
	forged.AppendStatusTLV(mle.StatusError)
	sendParentAttachMessage(t, parent, fixture, forged, 80)
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		after, err := fixture.store.Get(platform.SettingsKeyNetworkInfo, 0)
		if err != nil {
			return err
		}
		if !inst.mleService.Mle().IsChild() || inst.ownedAttachment != attachment ||
			!inst.mleService.Mle().GetParent().IsStateValid() ||
			inst.mleService.Mle().GetParent().MacAddr != udpPeerExt || inst.SecurityError() != nil ||
			!bytes.Equal(before, after) || inst.keyManager.GetMacFrameCounter() != macCounter ||
			inst.keyManager.GetMleFrameCounter() != mleCounter || len(fixture.node.driver.captures) != 0 {
			return fmt.Errorf("MAC-plain/INNER-unsecured spoof changed owned attachment/security/traffic")
		}
		return nil
	})
	seenDiscovery := false
	mustSRPLoop(t, fixture.node.inst, func() error {
		original := fixture.node.inst.mleService.DiscoveryHandler.HandleDiscoveryRequest
		fixture.node.inst.mleService.Dispatcher().RegisterHandler(mle.CommandDiscoveryRequest, func(info *mle.RxInfo) error {
			seenDiscovery = true
			return original(info)
		})
		return nil
	})
	discovery := mle.NewUnsecuredMessage(mle.CommandDiscoveryRequest)
	discovery.AppendDiscoveryTLV([]byte{128, 2, 0x40, 0})
	sendParentAttachMessage(t, parent, fixture, discovery, 80)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if !seenDiscovery || !fixture.node.inst.mleService.Mle().IsChild() ||
			fixture.node.inst.ownedAttachment != attachment || fixture.node.inst.SecurityError() != nil ||
			fixture.node.inst.keyManager.GetMleFrameCounter() != mleCounter || len(fixture.node.driver.captures) != 0 {
			return fmt.Errorf("stateless discovery was blocked or caused parent/security/TX effects")
		}
		return nil
	})
	authenticated := mle.NewMessage(mle.CommandChildUpdateRequest)
	authenticated.AppendSourceAddressTLV(0x0800)
	authenticated.AppendStatusTLV(mle.StatusError)
	sendParentAttachMessage(t, parent, fixture, authenticated, 81)
	waitUDPCondition(t, fixture.node.inst, func() bool {
		return !fixture.node.inst.mleService.Mle().IsChild() && fixture.node.inst.ownedAttachment == nil
	})
}

func parentAdvertisement(version uint8) *mle.Message {
	message := mle.NewMessage(mle.CommandAdvertisement)
	message.AppendSourceAddressTLV(0x0800)
	message.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 1, Weighting: 64, LeaderRouterID: 2, DataVersion: version})
	return message
}

func TestOwnedParentAuthenticatedRotationReconcilesFragmentWindows(t *testing.T) {
	fixture, parent := ownedAttachedMTD(t)
	// A real S request and partially received S response own the old window.
	mustSRPLoop(t, fixture.node.inst, fixture.node.inst.mleService.ChildHandlers.SendDataRequest)
	command, _ := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if command != mle.CommandDataRequest {
		t.Fatal("missing real pre-rotation request")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		return fixture.node.inst.mleService.ChildHandlers.SendChildUpdateRequest(mle.ChildUpdateAppendChallenge)
	})
	oldChildCommand, _ := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if oldChildCommand != mle.CommandChildUpdateRequest {
		t.Fatal("missing real pre-rotation child update")
	}
	oldResponse := captureParentAttachMessage(t, parent, fixture, expectedDataResponse(), 90, nil)
	deliverAttachCaptures(t, fixture, oldResponse[:1])
	// Retain a genuinely authenticated old-sequence advertisement for the
	// later downgrade check; never set the client's sequence or window.
	oldAdvertisement := captureParentAttachMessage(t, parent, fixture, parentAdvertisement(2), 100, nil)
	var before []byte
	mustSRPLoop(t, fixture.node.inst, func() error {
		var err error
		before, err = fixture.store.Get(platform.SettingsKeyNetworkInfo, 0)
		before = append([]byte(nil), before...)
		if fixture.node.inst.initialMLEFragment == nil || fixture.node.inst.expectedMLE[0] == nil || fixture.node.inst.expectedMLE[1] == nil {
			return fmt.Errorf("no old actual fragment/window")
		}
		return err
	})
	mustSRPLoop(t, parent.inst, func() error {
		parent.inst.SetCurrentKeySequence(1, key.ForceUpdate|key.ResetGuardTimer)
		return parent.inst.PersistenceError()
	})
	// Small, authenticated S+1 wire traffic performs legitimate adoption.
	sendParentAttachMessage(t, parent, fixture, parentAdvertisement(0), 2)
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		after, err := fixture.store.Get(platform.SettingsKeyNetworkInfo, 0)
		if err != nil {
			return err
		}
		if inst.keyManager.GetCurrentKeySequence() != 1 || inst.mleService.Mle().GetParent().KeySequence != 1 ||
			inst.expectedMLE[0] != nil || inst.expectedMLE[1] != nil || inst.initialMLEFragment != nil {
			return fmt.Errorf("authenticated rotation left stale parent sequence/window/candidate")
		}
		if binary.BigEndian.Uint32(after[37:41]) < binary.BigEndian.Uint32(before[37:41]) ||
			binary.BigEndian.Uint32(after[41:45]) < binary.BigEndian.Uint32(before[41:45]) {
			return fmt.Errorf("rotation lowered global persistent high-waters")
		}
		return nil
	})
	deliverAttachCaptures(t, fixture, oldResponse[1:])
	sendParentAttachMessage(t, parent, fixture, parentAdvertisement(1), 3)
	command, _ = ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if command != mle.CommandDataRequest {
		t.Fatal("changed Network Data did not trigger actual current-sequence request")
	}
	reply := captureParentAttachMessage(t, parent, fixture, expectedDataResponse(), 4, nil)
	if len(reply) < 2 {
		t.Fatal("response was not actually fragmented")
	}
	deliverAttachCaptures(t, fixture, reply)
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		if !inst.mleService.Mle().IsChild() || inst.mleService.Mle().GetParent().KeySequence != 1 ||
			inst.expectedMLE[0] != nil || inst.initialMLEFragment != nil ||
			!bytes.Equal(inst.ownedAttachment.networkData, largeBootstrapNetworkData()) {
			return fmt.Errorf("current authenticated fragmented response failed after real rotation")
		}
		return nil
	})
	mustSRPLoop(t, fixture.node.inst, func() error {
		return fixture.node.inst.mleService.ChildHandlers.SendChildUpdateRequest(mle.ChildUpdateAppendChallenge)
	})
	childCommand, records := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if childCommand != mle.CommandChildUpdateRequest {
		t.Fatal("no real post-rotation child update")
	}
	challenge, ok := mle.FindTLV(records, mle.TLVChallenge)
	if !ok {
		t.Fatal("missing actual post-rotation challenge")
	}
	childReply := mle.NewMessage(mle.CommandChildUpdateResponse)
	childReply.AppendSourceAddressTLV(0x0800)
	childReply.AppendModeTLV(mle.NewDeviceMode(mle.ModeRxOnWhenIdle))
	childReply.AppendResponseTLV(challenge)
	childReply.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 1, Weighting: 64, LeaderRouterID: 2, DataVersion: 1})
	childReply.AppendNetworkDataTLV(largeBootstrapNetworkData())
	childFrames := captureParentAttachMessage(t, parent, fixture, childReply, 5, nil)
	if len(childFrames) < 2 {
		t.Fatalf("child response was not actually fragmented: first wire=%x", childFrames[0].frame.PSDU)
	}
	deliverAttachCaptures(t, fixture, childFrames)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if fixture.node.inst.expectedMLE[1] != nil || fixture.node.inst.initialMLEFragment != nil ||
			fixture.node.inst.mleService.Mle().GetParent().Counters.MleFrameCounter != 5 {
			return fmt.Errorf("new actual Child Update window did not follow authenticated parent sequence")
		}
		return nil
	})
	deliverAttachCaptures(t, fixture, oldAdvertisement)
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		if inst.keyManager.GetCurrentKeySequence() != 1 || inst.mleService.Mle().GetParent().KeySequence != 1 ||
			inst.mleService.Mle().GetParent().Counters.MleFrameCounter != 5 ||
			inst.expectedMLE[0] != nil || len(fixture.node.driver.captures) != 0 {
			return fmt.Errorf("old authenticated key sequence downgraded parent/replay state or triggered stale work")
		}
		return nil
	})
}
