package instance

import (
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/mle"
)

func TestOwnedParentRotationPersistenceFailureRetiresOwnedWork(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprint(commit), func(t *testing.T) {
			store := &datasetWriteFault{SimSettings: simulation.NewSimSettings()}
			fixture := newOwnedAttachFixtureWithSettings(t, true, store)
			parent := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
			fixture.begin(t)
			fixture.fireProtocolTimer(t)
			_, records := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
			challenge, _ := mle.FindTLV(records, mle.TLVChallenge)
			sendParentAttachMessage(t, parent, fixture, parentResponse(challenge), 60)
			fixture.fireProtocolTimer(t)
			ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
			sendParentAttachMessage(t, parent, fixture, childIDResponse(0x0801), 61)
			if result := awaitOwnedAttach(t, fixture.attempt); result.Err != nil {
				t.Fatal(result.Err)
			}
			mustSRPLoop(t, fixture.node.inst, fixture.node.inst.mleService.ChildHandlers.SendDataRequest)
			ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
			oldResponse := captureParentAttachMessage(t, parent, fixture, expectedDataResponse(), 90, nil)
			deliverAttachCaptures(t, fixture, oldResponse[:1])
			before := observeInitialParent(t, fixture, store)
			mustSRPLoop(t, parent.inst, func() error {
				parent.inst.SetCurrentKeySequence(1, key.ForceUpdate|key.ResetGuardTimer)
				return parent.inst.PersistenceError()
			})
			mustSRPLoop(t, fixture.node.inst, func() error {
				store.fail, store.commit = platform.SettingsKeyNetworkInfo, commit
				return nil
			})
			sendParentAttachMessage(t, parent, fixture, parentAdvertisement(1), 2)
			deliverAttachCaptures(t, fixture, oldResponse[1:])
			after := observeInitialParent(t, fixture, store)
			mustSRPLoop(t, fixture.node.inst, func() error {
				inst := fixture.node.inst
				if !errors.Is(inst.PersistenceError(), errOwnedDatasetWrite) || inst.SecurityError() != nil ||
					inst.threadEnabled || inst.ownedAttachment != nil || inst.expectedMLE[0] != nil ||
					inst.initialMLEFragment != nil || inst.mleService.Mle().IsChild() ||
					len(fixture.node.driver.captures) != 0 {
					return fmt.Errorf("rotation persistence fault lost cause or retained/admitted owned work")
				}
				if inst.keyManager.GetMacFrameCounter() < before.mac || inst.keyManager.GetMleFrameCounter() < before.mle {
					return fmt.Errorf("fault rolled back already admitted counters")
				}
				return nil
			})
			if binary.BigEndian.Uint32(after.record[37:41]) < binary.BigEndian.Uint32(before.record[37:41]) ||
				binary.BigEndian.Uint32(after.record[41:45]) < binary.BigEndian.Uint32(before.record[41:45]) {
				t.Fatal("ambiguous rotation write lowered persistent reservation high-waters")
			}
		})
	}
}
