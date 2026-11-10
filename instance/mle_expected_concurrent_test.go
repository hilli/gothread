package instance

import (
	"fmt"
	"testing"

	"github.com/hilli/gothread/thread/mle"
)

func TestOwnedKnownParentConcurrentResponseCommandOwnership(t *testing.T) {
	fixture, parent := ownedAttachedMTD(t)
	mustSRPLoop(t, fixture.node.inst, fixture.node.inst.mleService.ChildHandlers.SendDataRequest)
	ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	mustSRPLoop(t, fixture.node.inst, func() error {
		return fixture.node.inst.mleService.ChildHandlers.SendChildUpdateRequest(mle.ChildUpdateAppendChallenge)
	})
	_, records := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	challenge, _ := mle.FindTLV(records, mle.TLVChallenge)
	reply := mle.NewMessage(mle.CommandChildUpdateResponse)
	reply.AppendSourceAddressTLV(0x0800)
	reply.AppendModeTLV(mle.NewDeviceMode(mle.ModeRxOnWhenIdle))
	reply.AppendResponseTLV(challenge)
	reply.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 1, Weighting: 64, LeaderRouterID: 2, DataVersion: 1})
	reply.AppendNetworkDataTLV(largeBootstrapNetworkData())
	frames := captureParentAttachMessage(t, parent, fixture, reply, 62, nil)
	deliverAttachCaptures(t, fixture, frames)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if fixture.node.inst.expectedMLE[0] == nil || fixture.node.inst.expectedMLE[1] != nil ||
			len(fixture.node.inst.ownedAttachment.networkData) == 0 {
			return fmt.Errorf("encrypted command consumed/matched wrong pending exchange")
		}
		return nil
	})
}
