package instance

import (
	"errors"
	"fmt"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
)

func TestOwnedSlaacObservationAndNormalSendsFailClosedOnEpisodeInvalidation(t *testing.T) {
	for _, kind := range []string{"health", "role", "stop", "persist"} {
		t.Run(kind, func(t *testing.T) {
			store := &datasetWriteFault{SimSettings: simulation.NewSimSettings()}
			fixture, _, _ := publicFTDWireFixture(t, ownedPrefixWire(true), store)
			source := actualOwnedSlaacAddress(t, fixture)
			mustSRPLoop(t, fixture.node.inst, func() error {
				inst := fixture.node.inst
				switch kind {
				case "health":
					inst.entropy.(*ownedTestEntropy).latch(errSRPEntropy)
				case "role":
					if err := inst.mleService.Mle().BecomeDetached(); err != nil {
						return err
					}
				case "stop":
					if err := inst.ThreadStop(); err != nil {
						return err
					}
				case "persist":
					store.fail = platform.SettingsKeyActiveDataset
					if err := inst.StageOperationalDatasets(DatasetRecord{Present: true, TLVs: ownedDataset().Bytes()}, DatasetRecord{}); !errors.Is(err, errOwnedDatasetWrite) {
						return fmt.Errorf("actual Settings failure not established")
					}
				}
				before, writes := phase2AdmissionSnapshot(inst), store.writes
				failure, fence := inst.securityFailure.Load(), inst.securityFenceRequested.Load()
				if _, err := fixture.attempt.ObserveAttachment(source); err == nil {
					return fmt.Errorf("invalidated owned SLAAC source was observed as authenticated")
				} else if kind == "health" && !errors.Is(err, errSRPEntropy) {
					return fmt.Errorf("readonly source observation lost exact health cause")
				}
				if phase2AdmissionSnapshot(inst) != before || store.writes != writes ||
					inst.securityFailure.Load() != failure || inst.securityFenceRequested.Load() != fence {
					return fmt.Errorf("source observation mutated health/NV/counters")
				}
				if err := inst.SendUDP([]byte("invalid"), ip6.MessageInfo{
					SockAddr: source, PeerAddr: ip6.Address{0x20, 1, 0x0d, 0xb8, 0, 2, 15: 1}, SockPort: 5540, PeerPort: 5540,
				}); err == nil || errors.Is(err, goterrors.ErrNoBufs) {
					return fmt.Errorf("invalidated source reached ordinary packet admission")
				}
				if len(fixture.node.driver.captures) != 0 {
					return fmt.Errorf("invalidated source emitted actual native radio work")
				}
				return nil
			})
		})
	}
}
