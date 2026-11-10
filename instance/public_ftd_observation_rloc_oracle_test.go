package instance

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
)

// Both versions already expose these APIs. Keep this file identical on exact
// old0d and the fix for later compile-first, real-wire old/fixed assertions.
func requirePublicObservationRejectsRLOCDrift(t *testing.T, macShort bool) {
	t.Helper()
	store := &datasetWriteFault{SimSettings: simulation.NewSimSettings()}
	fixture, _, _ := publicFTDWireFixture(t, nil, store)
	owner := fixture.attempt
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		valid, err := owner.ObserveAttachment(fixture.eid)
		if err != nil || valid.RLOC16 != 0x0801 || inst.RLOC16() != 0x0801 ||
			inst.SubMac().GetShortAddress() != types.ShortAddress(0x0801) {
			return fmt.Errorf("no actual coherent public authenticated0801 attachment before injection")
		}
		if macShort {
			inst.Mac().SetShortAddress(types.ShortAddress(0x0802))
		} else {
			inst.SetRLOC16(0x0802)
		}
		if inst.mleService.Mle().RLOC16() != 0x0801 || inst.ownedAttachment.rloc != 0x0801 ||
			inst.threadEpoch != valid.Epoch || !inst.netif.HasUnicastAddress(fixture.eid) {
			return fmt.Errorf("injection did not isolate live Instance/MAC drift from authenticated MLE/owner identity")
		}
		record, err := store.Get(platform.SettingsKeyNetworkInfo, 0)
		if err != nil {
			return err
		}
		record = append([]byte(nil), record...)
		counters, writes := phase2AdmissionSnapshot(inst), store.writes
		addresses := append([]ip6.UnicastAddress(nil), inst.netif.GetUnicastAddresses()...)
		instanceRLOC, short := inst.RLOC16(), inst.SubMac().GetShortAddress()
		failure, fence := inst.securityFailure.Load(), inst.securityFenceRequested.Load()
		attachment, epoch := inst.ownedAttachment, inst.threadEpoch
		observed, err := owner.ObserveAttachment(fixture.eid)
		if !errors.Is(err, goterrors.ErrInvalidState) || observed != (ThreadAttachmentObservation{}) {
			return fmt.Errorf("incoherent live RLOC tuple was reported as authenticated0801: %+v %v", observed, err)
		}
		after, err := store.Get(platform.SettingsKeyNetworkInfo, 0)
		if err != nil {
			return err
		}
		if phase2AdmissionSnapshot(inst) != counters || store.writes != writes || !bytes.Equal(record, after) ||
			inst.RLOC16() != instanceRLOC || inst.SubMac().GetShortAddress() != short ||
			inst.mleService.Mle().RLOC16() != 0x0801 || inst.ownedAttachment != attachment || inst.threadEpoch != epoch ||
			inst.securityFailure.Load() != failure || inst.securityFenceRequested.Load() != fence ||
			!reflect.DeepEqual(inst.netif.GetUnicastAddresses(), addresses) || len(fixture.node.driver.captures) != 0 {
			return fmt.Errorf("read-only rejection changed the injected tuple, addresses, health, entropy, NV or counters")
		}
		// Repair is an explicit caller mutation, never an observer side effect.
		if macShort {
			inst.Mac().SetShortAddress(types.ShortAddress(0x0801))
		} else {
			inst.SetRLOC16(0x0801)
		}
		restored, err := owner.ObserveAttachment(fixture.eid)
		if err != nil || restored != valid {
			return fmt.Errorf("restored coherent tuple lost its unchanged authenticated lifetime")
		}
		if err := inst.ThreadStop(); err != nil {
			return err
		}
		if _, err := owner.ObserveAttachment(fixture.eid); !errors.Is(err, goterrors.ErrInvalidState) {
			return fmt.Errorf("retained opaque owner survived real Stop after tuple repair")
		}
		return nil
	})
}

func TestPublicObservationRejectsInstanceRLOCDriftAfterActualAttach(t *testing.T) {
	requirePublicObservationRejectsRLOCDrift(t, false)
}

func TestPublicObservationRejectsMACShortDriftAfterActualAttach(t *testing.T) {
	requirePublicObservationRejectsRLOCDrift(t, true)
}
