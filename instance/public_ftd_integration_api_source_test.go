package instance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/mle"
)

// These are genuinely NEW-API source oracles. They are not included in the
// old-DFF existing-API comparison, where absent symbols are not behavior proof.
func TestPublicProfileResourcesArePureImplementationBounds(t *testing.T) {
	mtd, err := ThreadAttachAwakeMTD.Resources()
	if err != nil || mtd.MaxOrdinaryMulticastAddresses != 8 || mtd.MaxUnicastPayload != 1232 ||
		mtd.MaxSiteMulticastReferences != 0 || mtd.MaxSiteMulticastAddresses != 0 || mtd.MaxSiteMulticastPayload != 0 {
		t.Fatal("MTD resource query changed default8 or invented site membership")
	}
	ftd, err := ThreadAttachAwakeFTDChild.Resources()
	expected := ThreadProfileResources{
		MaxUnicastPayload: 1232, MaxOrdinaryMulticastAddresses: 8,
		MaxSiteMulticastReferences: len(ownedSiteGroups{}.handles),
		MaxSiteMulticastAddresses:  len(ownedSiteGroups{}.entries), MaxSiteMulticastPayload: MaxSiteMulticastPayload,
	}
	if err != nil || ftd != expected {
		t.Fatal("FTD bounds were not the actual arrays/reservation/wire capacities")
	}
	for _, bound := range []struct{ actual, required int }{
		{ftd.MaxSiteMulticastReferences, 80}, {ftd.MaxSiteMulticastAddresses, 80},
		{ip6.MaxReservedExternalMulticastAddresses, 80}, {ftd.MaxSiteMulticastPayload, 1184},
	} {
		if bound.actual != bound.required {
			t.Fatal("actual bounded FTD profile changed its required capacity")
		}
	}
	if _, err := ThreadAttachProfile(255).Resources(); !errors.Is(err, goterrors.ErrInvalidArgs) {
		t.Fatal("resource query invented an unsupported public profile")
	}
	store := &datasetWriteFault{SimSettings: simulation.NewSimSettings()}
	fixture := newOwnedAttachFixtureWithSettings(t, true, store)
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		before, writes := phase2AdmissionSnapshot(inst), store.writes
		for i := 0; i < 10; i++ {
			if _, err := ThreadAttachAwakeFTDChild.Resources(); err != nil {
				return err
			}
		}
		if phase2AdmissionSnapshot(inst) != before || store.writes != writes || inst.threadEnabled ||
			inst.siteGroups != nil || inst.ownedAttachment != nil || len(fixture.node.driver.captures) != 0 {
			return fmt.Errorf("cold capacity query admitted, allocated or manufactured an attachment")
		}
		return nil
	})
}

func TestPublicAttemptObservationRejectsColdPendingAndCanceledOwners(t *testing.T) {
	var cold *ThreadAttachAttempt
	if _, err := cold.ObserveAttachment(ip6.Address{}); !errors.Is(err, goterrors.ErrInvalidState) {
		t.Fatal("nil opaque owner looked authenticated")
	}
	var zero ThreadAttachAttempt
	if _, err := zero.ObserveAttachment(ip6.Address{}); !errors.Is(err, goterrors.ErrInvalidState) {
		t.Fatal("freely constructed zero attempt looked authenticated")
	}
	fixture := newOwnedAttachFixture(t, true)
	fixture.beginProfile(t, ThreadAttachAwakeFTDChild)
	pending := fixture.attempt
	mustSRPLoop(t, fixture.node.inst, func() error {
		if _, err := pending.ObserveAttachment(fixture.eid); !errors.Is(err, goterrors.ErrInvalidState) {
			return fmt.Errorf("admitted attempt became authenticated before actual CID")
		}
		return pending.Cancel()
	})
	awaitOwnedAttach(t, pending)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if _, err := pending.ObserveAttachment(fixture.eid); !errors.Is(err, goterrors.ErrInvalidState) {
			return fmt.Errorf("canceled opaque attempt acquired attachment authority")
		}
		return nil
	})
	fixture.beginProfile(t, ThreadAttachAwakeFTDChild)
	failed := fixture.attempt
	mustSRPLoop(t, fixture.node.inst, func() error {
		fixture.now = fixture.now.Add(time.Minute)
		fixture.node.inst.timers.processExpired()
		return nil
	})
	if result := awaitOwnedAttach(t, failed); !errors.Is(result.Err, context.DeadlineExceeded) {
		t.Fatal("actual admitted failure did not retain its timeout cause")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		if _, err := failed.ObserveAttachment(fixture.eid); !errors.Is(err, goterrors.ErrInvalidState) {
			return fmt.Errorf("failed opaque attempt acquired attachment authority")
		}
		return nil
	})
}

func TestPublicAttemptObservationIsPureAndSurvivesActualKeyPrimaryRefresh(t *testing.T) {
	store := &datasetWriteFault{SimSettings: simulation.NewSimSettings()}
	data := publicFTDPrimaryData()
	fixture, parent, _ := publicFTDWireFixture(t, data, store)
	var before ThreadAttachmentObservation
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		var err error
		before, err = fixture.attempt.ObserveAttachment(fixture.eid)
		if err != nil {
			return err
		}
		if before.Profile != ThreadAttachAwakeFTDChild || before.Role != mle.RoleChild || before.Source != fixture.eid ||
			before.RLOC16 != 0x0801 || before.ParentRLOC16 != 0x0800 || before.ParentExtAddress != udpPeerExt ||
			before.LocalExtAddress != fragmentSource || before.Epoch == 0 {
			return fmt.Errorf("observation did not describe the actual authenticated owned attachment")
		}
		record, err := store.Get(platform.SettingsKeyNetworkInfo, 0)
		if err != nil {
			return err
		}
		record = append([]byte(nil), record...)
		counters, writes := phase2AdmissionSnapshot(inst), store.writes
		for i := 0; i < 10; i++ {
			current, err := fixture.attempt.ObserveAttachment(fixture.eid)
			if err != nil || current != before {
				return fmt.Errorf("read-only observation changed its actual binding")
			}
		}
		after, err := store.Get(platform.SettingsKeyNetworkInfo, 0)
		if err != nil {
			return err
		}
		if phase2AdmissionSnapshot(inst) != counters || store.writes != writes || !bytes.Equal(record, after) ||
			len(fixture.node.driver.captures) != 0 {
			return fmt.Errorf("observation changed entropy/NV/counters/radio state")
		}
		return nil
	})
	rotation := phase2ParentRotationFrames(t, fixture, parent)
	for _, frame := range rotation {
		deliverNativeFrame(t, fixture.node, frame)
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		current, err := fixture.attempt.ObserveAttachment(fixture.eid)
		if err != nil || current != before || fixture.node.inst.keyManager.GetCurrentKeySequence() != 1 {
			return fmt.Errorf("normal actual key rotation invalidated stable attachment identity")
		}
		return fixture.node.inst.mleService.ChildHandlers.SendDataRequest()
	})
	command, _ := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if command != mle.CommandDataRequest {
		t.Fatal("no actual request before Primary Network Data refresh")
	}
	response := mle.NewMessage(mle.CommandDataResponse)
	response.AppendSourceAddressTLV(0x0800)
	response.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 1, Weighting: 64, LeaderRouterID: 2, DataVersion: 1})
	response.AppendNetworkDataTLV(data)
	sendParentAttachMessage(t, parent, fixture, response, 3)
	mustSRPLoop(t, fixture.node.inst, func() error {
		current, err := fixture.attempt.ObserveAttachment(fixture.eid)
		if err != nil || current != before {
			return fmt.Errorf("normal actual Primary refresh became a terminal attachment change")
		}
		return nil
	})
}

func TestPublicAttemptObservationRejectsActualInvalidationWithoutMutatingHealth(t *testing.T) {
	for _, kind := range []string{"source", "rebind", "mode", "eligibility", "role", "pan", "channel", "key", "eui",
		"rloc-address", "health", "persist", "dataset", "parent", "stop"} {
		t.Run(kind, func(t *testing.T) {
			store := &datasetWriteFault{SimSettings: simulation.NewSimSettings()}
			fixture, parent, _ := publicFTDWireFixture(t, nil, store)
			owner := fixture.attempt
			if kind == "parent" {
				message := mle.NewMessage(mle.CommandChildUpdateRequest)
				message.AppendSourceAddressTLV(0x0800)
				message.AppendStatusTLV(mle.StatusError)
				sendParentAttachMessage(t, parent, fixture, message, 80)
				waitUDPCondition(t, fixture.node.inst, func() bool { return fixture.node.inst.ownedAttachment == nil })
			}
			mustSRPLoop(t, fixture.node.inst, func() error {
				inst := fixture.node.inst
				source := fixture.eid
				switch kind {
				case "source", "rebind":
					if err := inst.netif.RemoveExternalUnicastAddress(source); err != nil {
						return err
					}
					if kind == "rebind" {
						source[15] ^= 0x40
						if err := inst.netif.AddExternalUnicastAddress(&ip6.UnicastAddress{
							Address: source, PrefixLength: 64, Valid: true, Preferred: true, MeshLocal: true,
						}); err != nil {
							return err
						}
					}
				case "mode":
					inst.mleService.Mle().SetDeviceMode(mle.NewDeviceMode(mle.ModeRxOnWhenIdle))
				case "eligibility":
					inst.mleService.Mle().SetRouterEligible(true)
				case "role":
					if err := inst.mleService.Mle().BecomeDetached(); err != nil {
						return err
					}
				case "pan":
					inst.Mac().SetPanID(0xfacf)
				case "channel":
					inst.Mac().SetPanChannel(21)
				case "key":
					inst.KeyManager().SetNetworkKey(key.NetworkKey{9, 8, 7, 6})
				case "eui":
					identity := fragmentSource
					identity[7] ^= 1
					inst.Mac().SetExtAddress(identity)
				case "rloc-address":
					for _, address := range inst.netif.GetUnicastAddresses() {
						if address.Address == meshLocator(inst.meshLocalPrefix, 0x0801) {
							inst.netif.RemoveUnicastAddress(&address)
							break
						}
					}
				case "health":
					inst.entropy.(*ownedTestEntropy).latch(errSRPEntropy)
				case "persist":
					store.fail = platform.SettingsKeyActiveDataset
					if err := inst.StageOperationalDatasets(DatasetRecord{Present: true, TLVs: ownedDataset().Bytes()}, DatasetRecord{}); !errors.Is(err, errOwnedDatasetWrite) {
						return fmt.Errorf("actual Settings failure was not established: %v", err)
					}
				case "dataset":
					if err := inst.StageOperationalDatasets(DatasetRecord{Present: true, TLVs: ownedDataset().Bytes()}, DatasetRecord{}); err != nil {
						return err
					}
				case "stop":
					if err := inst.ThreadStop(); err != nil {
						return err
					}
				}
				counters, writes := phase2AdmissionSnapshot(inst), store.writes
				failure, fence := inst.securityFailure.Load(), inst.securityFenceRequested.Load()
				if _, err := owner.ObserveAttachment(source); err == nil {
					return fmt.Errorf("invalidated opaque attempt still observed an authenticated source")
				} else if kind == "health" && !errors.Is(err, errSRPEntropy) {
					return fmt.Errorf("read-only health observation lost its exact cause")
				}
				if phase2AdmissionSnapshot(inst) != counters || store.writes != writes ||
					inst.securityFailure.Load() != failure || inst.securityFenceRequested.Load() != fence {
					return fmt.Errorf("read-only observation latched/fenced or changed provider/counter/NV state")
				}
				return nil
			})
		})
	}
}

func TestPublicAttemptObservationRejectsOldEpochWithSameAssignedAddresses(t *testing.T) {
	fixture, parent, _ := publicFTDWireFixture(t, nil)
	old := fixture.attempt
	var oldInfo ThreadAttachmentObservation
	mustSRPLoop(t, fixture.node.inst, func() error {
		var err error
		oldInfo, err = old.ObserveAttachment(fixture.eid)
		if err != nil {
			return err
		}
		if err := fixture.node.inst.ThreadStop(); err != nil {
			return err
		}
		fixture.attempt, err = fixture.node.inst.BeginThreadAttachWithConfig(ThreadAttachConfig{
			Timeout: 30 * time.Second, Profile: ThreadAttachAwakeFTDChild,
		})
		return err
	})
	fixture.fireProtocolTimer(t)
	command, records := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	challenge, _ := mle.FindTLV(records, mle.TLVChallenge)
	if command != mle.CommandParentRequest {
		t.Fatal("reattach did not use a new public Parent Request")
	}
	sendParentAttachMessage(t, parent, fixture, parentResponse(challenge), 100)
	fixture.fireProtocolTimer(t)
	command, _ = ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if command != mle.CommandChildIDRequest {
		t.Fatal("reattach did not use actual public CID")
	}
	sendParentAttachMessage(t, parent, fixture, childIDResponseWithNetworkData(0x0801, nil), 101)
	if result := awaitOwnedAttach(t, fixture.attempt); result.Err != nil {
		t.Fatal(result.Err)
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		if _, err := old.ObserveAttachment(fixture.eid); !errors.Is(err, goterrors.ErrInvalidState) {
			return fmt.Errorf("old opaque attempt rebound to a new same-address attachment")
		}
		current, err := fixture.attempt.ObserveAttachment(fixture.eid)
		if err != nil || current.Source != oldInfo.Source || current.RLOC16 != oldInfo.RLOC16 || current.Epoch == oldInfo.Epoch {
			return fmt.Errorf("actual reattach lost source or reused owned epoch")
		}
		return nil
	})
}
