package instance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/mle"
)

func TestPublicFTDAdmissionRejectsBeforeModeOrCounterEffects(t *testing.T) {
	for _, kind := range []string{"profile", "timeout-zero", "timeout-negative", "interface", "mle-state",
		"sleepy", "missing-eid", "rloc-eid", "identity", "dataset", "health", "entropy", "persistence"} {
		t.Run(kind, func(t *testing.T) {
			store := &datasetWriteFault{SimSettings: simulation.NewSimSettings()}
			fixture := newOwnedAttachFixtureWithSettings(t, kind != "missing-eid" && kind != "rloc-eid", store)
			config := ThreadAttachConfig{Timeout: time.Second, Profile: ThreadAttachAwakeFTDChild}
			var expected error
			mustSRPLoop(t, fixture.node.inst, func() error {
				inst := fixture.node.inst
				switch kind {
				case "profile":
					config.Profile, expected = ThreadAttachProfile(255), goterrors.ErrInvalidArgs
				case "timeout-zero":
					config.Timeout, expected = 0, goterrors.ErrInvalidArgs
				case "timeout-negative":
					config.Timeout, expected = -time.Second, goterrors.ErrInvalidArgs
				case "interface":
					if err := inst.IfConfigDown(); err != nil {
						return err
					}
					expected = goterrors.ErrInvalidState
				case "mle-state":
					if err := inst.mleService.Mle().Enable(); err != nil {
						return err
					}
					expected = goterrors.ErrInvalidState
				case "sleepy":
					inst.mac.SetRxOnWhenIdle(false)
					expected = goterrors.ErrNotCapable
				case "missing-eid":
					expected = goterrors.ErrInvalidSourceAddress
				case "rloc-eid":
					if err := inst.netif.AddExternalUnicastAddress(&ip6.UnicastAddress{
						Address:      meshLocator(ownedDataset().ConvertToInfo().MeshLocalPrefix, 0x0801),
						PrefixLength: 64, Valid: true, Preferred: true,
					}); err != nil {
						return err
					}
					expected = goterrors.ErrInvalidSourceAddress
				case "identity":
					inst.mac.SetExtAddress(types.ExtAddress{})
					expected = goterrors.ErrSecurity
				case "dataset":
					invalid := ownedDataset()
					invalid.RemoveTLV(meshcop.TLVNetworkKey)
					if err := inst.ActiveDataset().SaveLocal(invalid); err != nil {
						return err
					}
					expected = goterrors.ErrInvalidArgs
				case "health":
					inst.entropy.(*ownedTestEntropy).latch(errSRPEntropy)
					expected = errSRPEntropy
				case "entropy":
					inst.entropy.(*ownedTestEntropy).source.fail = true
					expected = errSRPEntropy
				case "persistence":
					store.fail = platform.SettingsKeyNetworkInfo
					inst.SetCurrentKeySequence(1, key.ForceUpdate|key.ResetGuardTimer)
					if !errors.Is(inst.PersistenceError(), errOwnedDatasetWrite) {
						return fmt.Errorf("real Settings failure did not latch before public entry")
					}
					expected = errOwnedDatasetWrite
				}
				return nil
			})
			before := observeInitialParent(t, fixture, store)
			mustSRPLoop(t, fixture.node.inst, func() error {
				inst := fixture.node.inst
				mode, role, eligible := inst.mleService.Mle().GetDeviceMode(), inst.mleService.Mle().Role(), inst.mleService.Mle().IsRouterEligible()
				calls := inst.entropy.(*ownedTestEntropy).source.calls
				attempt, err := inst.BeginThreadAttachWithConfig(config)
				if attempt != nil || !errors.Is(err, expected) {
					return fmt.Errorf("public %s cause/admission: got %v want %v", kind, err, expected)
				}
				if inst.threadEnabled || inst.threadAttach != nil || inst.mleService.Mle().GetDeviceMode() != mode ||
					inst.mleService.Mle().Role() != role || inst.mleService.Mle().IsRouterEligible() != eligible {
					return fmt.Errorf("rejected public entry changed mode/role/eligibility")
				}
				afterCalls := inst.entropy.(*ownedTestEntropy).source.calls
				if kind == "entropy" {
					if afterCalls != calls+1 || !errors.Is(inst.SecurityError(), errSRPEntropy) {
						return fmt.Errorf("checked challenge failure did not preserve its exact cause")
					}
				} else if afterCalls != calls {
					return fmt.Errorf("invalid public prerequisites consumed challenge entropy")
				}
				return nil
			})
			after := observeInitialParent(t, fixture, store)
			if !bytes.Equal(before.record, after.record) || before.writes != after.writes ||
				before.mac != after.mac || before.mle != after.mle || before.addresses != after.addresses ||
				len(fixture.node.driver.captures) != 0 {
				t.Fatal("rejected public prerequisites consumed storage/counter/address/radio effects")
			}
		})
	}
}

func TestPublicFTDRequiresActualSettingsAndEntropyHealth(t *testing.T) {
	for _, kind := range []string{"settings", "health", "entropy"} {
		t.Run(kind, func(t *testing.T) {
			var store platform.Settings = simulation.NewSimSettings()
			var entropy platform.Entropy = &ownedTestEntropy{}
			expected := goterrors.ErrNotCapable
			switch kind {
			case "settings":
				store, expected = nil, goterrors.ErrInvalidState
			case "health":
				entropy = &srpEntropy{}
			case "entropy":
				entropy = nil
			}
			driver := &fragmentRadio{
				boundedUDPRadio: &boundedUDPRadio{captures: make(chan udpRadioCapture, 2), settings: store},
				identity:        fragmentSource, caps: radio.CapCsmaBackoff | radio.CapTransmitRetries | radio.CapAckTimeout,
			}
			inst := New(Config{Radio: driver, Settings: store, Entropy: entropy})
			if err := inst.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(inst.Stop)
			mustSRPLoop(t, inst, func() error {
				inst.mleService.Mle().SetDeviceMode(mle.NewDeviceMode(mle.ModeRxOnWhenIdle))
				inst.mac.SetRxOnWhenIdle(true)
				if err := inst.IfConfigUp(); err != nil {
					return err
				}
				attempt, err := inst.BeginThreadAttachWithConfig(ThreadAttachConfig{
					Timeout: time.Second, Profile: ThreadAttachAwakeFTDChild,
				})
				if attempt != nil || !errors.Is(err, expected) || inst.threadEnabled || len(driver.captures) != 0 {
					return fmt.Errorf("missing actual provider accepted or lost cause: %v", err)
				}
				return nil
			})
		})
	}
}

func TestPublicFTDCancelOverlapDatasetAndDeadlineOwnership(t *testing.T) {
	fixture := newOwnedAttachFixture(t, true)
	fixture.beginProfile(t, ThreadAttachAwakeFTDChild)
	old := fixture.attempt
	mustSRPLoop(t, fixture.node.inst, func() error {
		other, err := fixture.node.inst.BeginThreadAttachWithConfig(ThreadAttachConfig{
			Timeout: time.Second, Profile: ThreadAttachAwakeFTDChild,
		})
		if other != nil || !errors.Is(err, goterrors.ErrInvalidState) {
			return fmt.Errorf("public overlap lost owner/cause: %v", err)
		}
		return old.Cancel()
	})
	if result := awaitOwnedAttach(t, old); !errors.Is(result.Err, context.Canceled) || result.Role == mle.RoleChild {
		t.Fatal("public FTD cancellation fabricated success or lost cause")
	}
	fixture.beginProfile(t, ThreadAttachAwakeFTDChild)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if err := old.Cancel(); err != nil {
			return err
		}
		select {
		case <-fixture.attempt.Result():
			return fmt.Errorf("old public cancellation terminated the new generation")
		default:
		}
		fixture.now = fixture.now.Add(time.Minute)
		fixture.node.inst.timers.processExpired()
		return nil
	})
	if result := awaitOwnedAttach(t, fixture.attempt); !errors.Is(result.Err, context.DeadlineExceeded) || result.Role == mle.RoleChild {
		t.Fatal("public FTD deadline fabricated success or lost cause")
	}
	changed := newOwnedAttachFixture(t, true)
	changed.beginProfile(t, ThreadAttachAwakeFTDChild)
	mustSRPLoop(t, changed.node.inst, func() error {
		next := ownedDataset()
		if err := next.WriteTLV(meshcop.TLVNetworkName, []byte("ChangedPublic")); err != nil {
			return err
		}
		return changed.node.inst.StageOperationalDatasets(DatasetRecord{Present: true, TLVs: next.Bytes()}, DatasetRecord{})
	})
	if result := awaitOwnedAttach(t, changed.attempt); result.Err == nil || result.Role == mle.RoleChild {
		t.Fatal("dataset change falsely completed the old public FTD generation")
	}
}

func TestPublicFTDStoppedInstanceCannotAdmit(t *testing.T) {
	fixture := newOwnedAttachFixture(t, true)
	fixture.node.inst.Stop()
	calls := fixture.node.inst.entropy.(*ownedTestEntropy).source.calls
	// No event loop exists after Stop; this tests rejection, not an off-loop
	// mutation or an attempt to restart protocol work without an owner.
	attempt, err := fixture.node.inst.BeginThreadAttachWithConfig(ThreadAttachConfig{
		Timeout: time.Second, Profile: ThreadAttachAwakeFTDChild,
	})
	if attempt != nil || !errors.Is(err, goterrors.ErrInvalidState) ||
		fixture.node.inst.entropy.(*ownedTestEntropy).source.calls != calls || len(fixture.node.driver.captures) != 0 {
		t.Fatal("stopped public instance admitted work or changed its rejection cause")
	}
}
