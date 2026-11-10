package instance

import (
	"fmt"
	"testing"
	"time"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/routing"
)

func TestOwnedParentSequenceDoesNotFollowUnrelatedAuthenticatedRouter(t *testing.T) {
	fixture, parent := ownedAttachedMTD(t)
	foreignExt := types.ExtAddress{0x26, 1, 2, 3, 4, 5, 6, 7}
	foreign := newFragmentEndpoint(t, foreignExt, fragmentSource, 0x0c00, 0x0801, simulation.NewSimSettings())
	// A preconfigured direct-neighbor fixture, not evidence of its enrollment.
	// Client role/parent/key/window still come from real attach/request/RX.
	mustSRPLoop(t, fixture.node.inst, func() error {
		neighbor, err := fixture.node.inst.routerTable.AllocateWithID(3)
		if err != nil {
			return err
		}
		neighbor.ExtAddress, neighbor.RLOC16, neighbor.State = foreignExt, 0x0c00, routing.StateValid
		neighbor.LastHeard = uint32(time.Now().UnixMilli())
		neighbor.Mode = mle.NewDeviceMode(mle.ModeRxOnWhenIdle | mle.ModeFullThreadDevice | mle.ModeFullNetworkData)
		return fixture.node.inst.mleService.ChildHandlers.SendDataRequest()
	})
	ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	var window *ownedMLEResponse
	mustSRPLoop(t, fixture.node.inst, func() error {
		window = fixture.node.inst.expectedMLE[0]
		if window == nil {
			return fmt.Errorf("no actual parent response window")
		}
		return nil
	})
	mustSRPLoop(t, foreign.inst, func() error {
		foreign.inst.SetCurrentKeySequence(1, key.ForceUpdate|key.ResetGuardTimer)
		return foreign.inst.PersistenceError()
	})
	advertisement := mle.NewMessage(mle.CommandAdvertisement)
	advertisement.AppendSourceAddressTLV(0x0c00)
	advertisement.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 1, Weighting: 64, LeaderRouterID: 2})
	sendParentAttachMessage(t, foreign, fixture, advertisement, 2)
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		if inst.keyManager.GetCurrentKeySequence() != 1 {
			return fmt.Errorf("unrelated authenticated wire did not exercise real global adoption")
		}
		if inst.mleService.Mle().GetParent().KeySequence != 0 || inst.expectedMLE[0] != window ||
			inst.mleService.Mle().GetParent().Counters.MleFrameCounter != 61 {
			return fmt.Errorf("unrelated global adoption rewrote parent evidence/window/replay state")
		}
		return nil
	})
	reply := captureParentAttachMessage(t, parent, fixture, expectedDataResponse(), 62, nil)
	deliverAttachCaptures(t, fixture, reply)
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		if inst.expectedMLE[0] != nil || len(inst.ownedAttachment.networkData) == 0 ||
			inst.mleService.Mle().GetParent().KeySequence != 0 || inst.keyManager.GetCurrentKeySequence() != 1 {
			return fmt.Errorf("real parent window stopped working after unrelated global rotation")
		}
		return nil
	})
	mustSRPLoop(t, parent.inst, func() error {
		parent.inst.SetCurrentKeySequence(1, key.ForceUpdate|key.ResetGuardTimer)
		return parent.inst.PersistenceError()
	})
	// Global is already S+1, but this parent's new-key counter legitimately
	// starts below its old-key62. Replay qualification must use its own key.
	sendParentAttachMessage(t, parent, fixture, parentAdvertisement(2), 1)
	command, _ := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if command != mle.CommandDataRequest {
		t.Fatal("parent's later genuine key rotation was mistaken for a replay")
	}
	newReply := mle.NewMessage(mle.CommandDataResponse)
	newReply.AppendSourceAddressTLV(0x0800)
	newReply.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 1, Weighting: 64, LeaderRouterID: 2, DataVersion: 2})
	newReply.AppendNetworkDataTLV(largeBootstrapNetworkData())
	deliverAttachCaptures(t, fixture, captureParentAttachMessage(t, parent, fixture, newReply, 2, nil))
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		if inst.mleService.Mle().GetParent().KeySequence != 1 ||
			inst.mleService.Mle().GetParent().Counters.MleFrameCounter != 2 ||
			inst.expectedMLE[0] != nil || inst.initialMLEFragment != nil {
			return fmt.Errorf("parent replay/window state did not follow its own authenticated rotation")
		}
		return nil
	})
}
