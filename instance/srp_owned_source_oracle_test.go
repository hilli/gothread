package instance

import (
	"errors"
	"fmt"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/srp"
)

// All APIs/helpers used here exist in accepted5aee. These are authored source
// oracles, not an old compile/failure or runtime pass claim.
func TestOwnedSRPSameAddressNewGenerationCannotTransferLocalOrAnyAdvertisedAuthority(t *testing.T) {
	for _, action := range []string{"timer", "mutation"} {
		for _, surface := range []string{"local", "advert0", "advert1", "advert2", "advert3", "both"} {
			t.Run(action+"-"+surface, func(t *testing.T) {
				localGenerated := surface == "local" || surface == "both"
				advertiseAll := surface != "local"
				index := 0
				switch surface {
				case "advert1":
					index = 1
				case "advert2":
					index = 2
				case "advert3":
					index = 3
				}
				fixture := newSRPOwnedProofFixture(t, localGenerated, advertiseAll)
				registerOwnedSRPControl(t, fixture, 5540)
				registerOwnedSRPControl(t, fixture, 5541) // Actual mutation/timer/ACK control before withdrawal.
				replaceOwnedSRPSourceGeneration(t, fixture, index)
				before := phase2AdmissionCounters{}
				mustSRPLoop(t, fixture.thread.node.inst, func() error {
					before = phase2AdmissionSnapshot(fixture.thread.node.inst)
					return nil
				})
				if action == "timer" {
					driveOwnedSRPTimers(t, fixture)
				} else {
					mustSRPLoop(t, fixture.thread.node.inst, func() error {
						_, err := fixture.binding.UpsertService(nativeService("must-not-transfer"))
						if !errors.Is(err, goterrors.ErrNoRoute) {
							return fmt.Errorf("SRP retained binding mutation transferred G1 authority to same-address G2: %v", err)
						}
						return nil
					})
				}
				mustSRPLoop(t, fixture.thread.node.inst, func() error {
					inst := fixture.thread.node.inst
					if !errors.Is(fixture.binding.Err(), goterrors.ErrNoRoute) || !fixture.binding.closed {
						return fmt.Errorf("SRP internal timer reused old Local/advertised G1 lifetime after authenticated same-epoch G2 readdition")
					}
					if len(fixture.thread.node.driver.captures) != 0 ||
						phase2AdmissionSnapshot(inst) != before || inst.udpManager.IsPortInUse(fixture.config.Local.Port) ||
						inst.forwarder.GetBufferUsage().TxDatagrams != 0 {
						return fmt.Errorf("stale SRP proof emitted fresh G2 wire/counter or retained port/queue")
					}
					return nil
				})
				old := fixture.binding
				mustSRPLoop(t, fixture.thread.node.inst, func() error {
					var err error
					fixture.binding, err = fixture.thread.node.inst.StartSRP(fixture.config)
					return err
				})
				if fixture.binding == old {
					t.Fatal("new binding reused retired opaque lifetime")
				}
				registerOwnedSRPControl(t, fixture, 5542)
			})
		}
	}
}

func TestOwnedSRPDeferredRealACKCannotHealRetiredSourceGeneration(t *testing.T) {
	for _, localOnly := range []bool{false, true} {
		t.Run(fmt.Sprint(localOnly), func(t *testing.T) {
			fixture := newSRPOwnedProofFixture(t, localOnly, !localOnly)
			mustSRPLoop(t, fixture.thread.node.inst, func() error {
				_, err := fixture.binding.UpsertService(nativeService("pending-real-ack"))
				return err
			})
			driveOwnedSRPTimers(t, fixture)
			request := captureOwnedSRPUpdate(t, fixture)
			response := makeOwnedSRPReply(t, fixture, request)
			index := 3
			if localOnly {
				index = 0
			}
			replaceOwnedSRPSourceGeneration(t, fixture, index)
			deliverOwnedSRPReply(t, fixture, response)
			mustSRPLoop(t, fixture.thread.node.inst, func() error {
				if !errors.Is(fixture.binding.Err(), goterrors.ErrNoRoute) || !fixture.binding.closed {
					return fmt.Errorf("old real ACK acquired replacement G2 Local/advertised source authority")
				}
				select {
				case notice, open := <-fixture.binding.Notices():
					if open && notice.Err == nil {
						return fmt.Errorf("stale generation published successful server acknowledgement")
					}
				default:
					return fmt.Errorf("retired receive proof did not close outcome delivery")
				}
				return nil
			})
		})
	}
}

func TestOwnedSRPWithdrawDeprecatedAndRoleLossRemainExplicitFences(t *testing.T) {
	for _, kind := range []string{"withdraw-local", "withdraw-advert", "deprecated-local", "deprecated-advert", "role"} {
		t.Run(kind, func(t *testing.T) {
			local := kind == "withdraw-local" || kind == "deprecated-local" || kind == "role"
			fixture := newSRPOwnedProofFixture(t, local, !local)
			registerOwnedSRPControl(t, fixture, 5540)
			all := [4]bool{true, true, true, true}
			present, preferred := all, all
			index := 3
			if local {
				index = 0
			}
			switch kind {
			case "withdraw-local", "withdraw-advert":
				present[index] = false
			case "deprecated-local", "deprecated-advert":
				preferred[index] = false
			}
			if kind == "role" {
				mustSRPLoop(t, fixture.thread.node.inst, fixture.thread.node.inst.mleService.Mle().BecomeDetached)
			} else {
				sendOwnedPrefixUpdate(t, fixture.thread, fixture.parent, srpProofPrefixData(present, preferred), 1, 70, true)
			}
			driveOwnedSRPTimers(t, fixture)
			mustSRPLoop(t, fixture.thread.node.inst, func() error {
				if fixture.binding.Err() == nil || !fixture.binding.closed || len(fixture.thread.node.driver.captures) != 0 {
					return fmt.Errorf("withdraw/deprecate/role loss retained SRP lifetime or emitted stale wire")
				}
				return nil
			})
		})
	}
}

func TestOwnedSRPUnchangedPrefixKeyPrimaryRefreshAndMeshLocalGenerationZeroRemainValid(t *testing.T) {
	for _, kind := range []string{"refresh", "key", "mesh-local"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newSRPOwnedProofFixture(t, kind != "mesh-local", true)
			registerOwnedSRPControl(t, fixture, 5540)
			var before ThreadAttachmentObservation
			mustSRPLoop(t, fixture.thread.node.inst, func() error {
				var err error
				before, err = fixture.thread.attempt.ObserveAttachment(fixture.config.Local.Address)
				return err
			})
			if kind == "key" {
				for _, frame := range phase2ParentRotationFrames(t, fixture.thread, fixture.parent) {
					deliverNativeFrame(t, fixture.thread.node, frame)
				}
				mustSRPLoop(t, fixture.thread.node.inst, func() error {
					fixture.thread.node.macKey = fixture.thread.node.inst.keyManager.GetCurrentMacKey()
					return nil
				})
			} else {
				all := [4]bool{true, true, true, true}
				sendOwnedPrefixUpdate(t, fixture.thread, fixture.parent, srpProofPrefixData(all, all), 1, 70, true)
			}
			mustSRPLoop(t, fixture.thread.node.inst, func() error {
				current, err := fixture.thread.attempt.ObserveAttachment(fixture.config.Local.Address)
				if err != nil || current != before || fixture.binding.Err() != nil {
					return fmt.Errorf("unrelated key/Primary/prefix refresh rotated source or invalidated SRP")
				}
				if kind == "mesh-local" && current.SourceGeneration != 0 {
					return fmt.Errorf("caller ML source lost generation0 contract")
				}
				return nil
			})
			driveOwnedSRPTimers(t, fixture)
			packet := captureOwnedSRPUpdate(t, fixture)
			deliverOwnedSRPReply(t, fixture, makeOwnedSRPReply(t, fixture, packet))
			notice := nextSRPNotice(t, fixture.binding)
			if notice.Err != nil || fixture.binding.client.GetState() != srp.StateUpdated {
				t.Fatal("legitimate refresh/native internal renewal did not retain actual ACK behavior")
			}
		})
	}
}
