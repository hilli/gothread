package instance

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/thread/key"
)

func TestDormantOwnAddressAmbiguousPersistenceFailureFencesQueryAndRetry(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprint(commit), func(t *testing.T) {
			store := &datasetWriteFault{SimSettings: simulation.NewSimSettings()}
			fixture, parent, _ := dormantFTDControlWithData(t, nil, store)
			mustSRPLoop(t, fixture.node.inst, func() error {
				fixture.node.macKey = fixture.node.inst.keyManager.GetCurrentMacKey()
				return nil
			})
			origin := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0c00)
			sendOwnQueryPacket(t, parent, fixture, ownQueryPacket(t, fixture, origin, fixture.eid, 0x7701, 1, nil), true)
			captureSitePacket(t, fixture.node)
			control := fixture.node.inst.ownedTMF
			var counters [3]uint32
			mustSRPLoop(t, fixture.node.inst, func() error {
				inst := fixture.node.inst
				store.fail, store.commit = platform.SettingsKeyNetworkInfo, commit
				inst.SetCurrentKeySequence(inst.keyManager.GetCurrentKeySequence()+1, key.ForceUpdate|key.ResetGuardTimer)
				if !errors.Is(inst.PersistenceError(), errOwnedDatasetWrite) || inst.SecurityError() != nil {
					return fmt.Errorf("actual Settings failure lost its distinct exact cause")
				}
				counters = [3]uint32{inst.keyManager.GetMacFrameCounter(), inst.keyManager.GetMleFrameCounter(),
					uint32(inst.entropy.(*ownedTestEntropy).source.calls)}
				return nil
			})
			// Old MAC-key grace is not permission to answer with failed persistence.
			sendOwnQueryPacket(t, parent, fixture, ownQueryPacket(t, fixture, origin, fixture.eid, 0x7702, 2, nil), true)
			mustSRPLoop(t, fixture.node.inst, func() error {
				inst := fixture.node.inst
				fixture.now = fixture.now.Add(4 * time.Second)
				inst.timers.processExpired()
				after := [3]uint32{inst.keyManager.GetMacFrameCounter(), inst.keyManager.GetMleFrameCounter(),
					uint32(inst.entropy.(*ownedTestEntropy).source.calls)}
				for _, pending := range control.ownNotifications {
					if pending != nil {
						return fmt.Errorf("persistence failure retained retry ownership")
					}
				}
				if after != counters || len(fixture.node.driver.captures) != 0 ||
					!errors.Is(inst.PersistenceError(), errOwnedDatasetWrite) {
					return fmt.Errorf("failed persistence consumed response/nonce/counter or lost latch")
				}
				return nil
			})
		})
	}
}
