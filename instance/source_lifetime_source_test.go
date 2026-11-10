package instance

import (
	"errors"
	"fmt"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/thread/mle"
)

func TestSourceLifetimePublicAuthenticatedWithdrawalDeprecationAndSameAddressReuse(t *testing.T) {
	for _, deprecate := range []bool{false, true} {
		t.Run(fmt.Sprint(deprecate), func(t *testing.T) {
			fixture, parent, source, lease := lifetimePublicFixture(t)
			current := observeLifetime(t, fixture, lease)
			if current.State != ThreadSourceCurrent || current.Source != source || current.SourceGeneration == 0 {
				t.Fatal("G1 not actually acquired while current")
			}
			var data []byte
			reason := ThreadSourceAuthenticatedWithdrawal
			if deprecate {
				data, reason = lifetimePrefixData(1, false), ThreadSourceAuthenticatedDeprecation
			}
			sendOwnedPrefixUpdate(t, fixture, parent, data, 1, 70, true)
			retired := observeLifetime(t, fixture, lease)
			if retired.State != ThreadSourceRetired || retired.Retirement != reason || retired.Cause != nil ||
				retired.SourceGeneration != current.SourceGeneration || retired.Epoch != current.Epoch {
				t.Fatal("actual accepted Network Data did not retain the exact G1 retirement")
			}
			sendOwnedPrefixUpdate(t, fixture, parent, lifetimePrefixData(1, true), 2, 71, true)
			var next ThreadSourceLifetime
			mustSRPLoop(t, fixture.node.inst, func() error {
				info, err := fixture.attempt.ObserveAttachment(source)
				if err != nil || info.Epoch != current.Epoch || info.SourceGeneration == current.SourceGeneration {
					return fmt.Errorf("actual same-address G2/epoch control absent")
				}
				next, err = fixture.attempt.AcquireSourceLifetime(source)
				return err
			})
			if old := observeLifetime(t, fixture, lease); old.State != ThreadSourceRetired || old.SourceGeneration != current.SourceGeneration {
				t.Fatal("G2 current tuple rewrote or revived old G1")
			}
			if fresh := observeLifetime(t, fixture, next); fresh.State != ThreadSourceCurrent || fresh.SourceGeneration == current.SourceGeneration {
				t.Fatal("new G2 proof failed actual acquisition")
			}
		})
	}
}

func TestSourceLifetimeManualRoleStopAndInvalidatedDataCannotBeCleanRetirement(t *testing.T) {
	for _, kind := range []string{"manual", "role", "stop", "unaccepted-data"} {
		t.Run(kind, func(t *testing.T) {
			fixture, parent, source, lease := lifetimePublicFixture(t)
			reason := ThreadSourceManualRemoval
			mustSRPLoop(t, fixture.node.inst, func() error {
				switch kind {
				case "manual":
					fixture.node.inst.netif.RemoveUnicastAddress(&ip6.UnicastAddress{Address: source})
				case "role":
					reason = ThreadSourceRoleLost
					return fixture.node.inst.mleService.Mle().BecomeDetached()
				case "stop":
					reason = ThreadSourceStopped
					return fixture.node.inst.ThreadStop()
				}
				return nil
			})
			if kind == "unaccepted-data" {
				reason = ThreadSourceNetworkDataInvalidated
				response := mle.NewMessage(mle.CommandDataResponse)
				response.AppendSourceAddressTLV(0x0800)
				response.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 2, Weighting: 64, LeaderRouterID: 2, DataVersion: 1})
				sendParentAttachMessage(t, parent, fixture, response, 70)
			}
			failed := observeLifetime(t, fixture, lease)
			if failed.State != ThreadSourceFailed || failed.Failure != reason || failed.Cause == nil ||
				failed.Retirement != ThreadSourceNoRetirement {
				t.Fatal("genuine non-clean source end was labeled authenticated retirement")
			}
			if kind == "manual" {
				// A later genuine accepted empty data set cannot erase the
				// earlier manual event, even though no current slot remains.
				sendOwnedPrefixUpdate(t, fixture, parent, nil, 1, 70, true)
				if later := observeLifetime(t, fixture, lease); later.Failure != ThreadSourceManualRemoval || later.State != ThreadSourceFailed {
					t.Fatal("later authenticated data turned earlier genuine manual failure benign")
				}
			}
		})
	}
}

func TestSourceLifetimeHeldReasonSurvivesManagerSlotReuseAndForeignAttempts(t *testing.T) {
	fixture, parent, source, lease := lifetimePublicFixture(t)
	before := observeLifetime(t, fixture, lease)
	sendOwnedPrefixUpdate(t, fixture, parent, lifetimePrefixData(5, true), 1, 70, true)
	old := observeLifetime(t, fixture, lease)
	if old.State != ThreadSourceRetired || old.Retirement != ThreadSourceAuthenticatedWithdrawal {
		t.Fatal("slot reuse lost old G1 retirement")
	}
	sendOwnedPrefixUpdate(t, fixture, parent, lifetimePrefixData(1, true), 2, 71, true)
	if now := observeLifetime(t, fixture, lease); now.Source != source || now.SourceGeneration != before.SourceGeneration || now.State != ThreadSourceRetired {
		t.Fatal("same address readdition overwrote leased G1 slot history")
	}
	other, _, _, _ := lifetimePublicFixture(t)
	mustSRPLoop(t, other.node.inst, func() error {
		if _, err := other.attempt.ObserveSourceLifetime(lease); !errors.Is(err, goterrors.ErrInvalidState) {
			return fmt.Errorf("foreign instance/attempt accepted G1 lease")
		}
		if err := other.attempt.ReleaseSourceLifetime(lease); !errors.Is(err, goterrors.ErrInvalidState) {
			return fmt.Errorf("foreign owner released lease")
		}
		return nil
	})
}

func TestSourceLifetimeLateHealthPersistenceAndStopDominateRetiredDisposition(t *testing.T) {
	for _, kind := range []string{"health", "persistence", "stop"} {
		t.Run(kind, func(t *testing.T) {
			store := &datasetWriteFault{SimSettings: simulation.NewSimSettings()}
			fixture, parent, _, lease := lifetimePublicFixture(t, store)
			sendOwnedPrefixUpdate(t, fixture, parent, nil, 1, 70, true)
			if observeLifetime(t, fixture, lease).State != ThreadSourceRetired {
				t.Fatal("clean control retirement missing")
			}
			cause := errors.New("actual latched provider failure")
			mustSRPLoop(t, fixture.node.inst, func() error {
				inst := fixture.node.inst
				switch kind {
				case "health":
					inst.entropy.(*ownedTestEntropy).latch(cause)
				case "persistence":
					store.fail = platform.SettingsKeyActiveDataset
					if err := inst.StageOperationalDatasets(DatasetRecord{Present: true, TLVs: ownedDataset().Bytes()}, DatasetRecord{}); !errors.Is(err, errOwnedDatasetWrite) {
						return fmt.Errorf("actual dataset failure absent")
					}
				case "stop":
					return inst.ThreadStop()
				}
				return nil
			})
			failed := observeLifetime(t, fixture, lease)
			if failed.State != ThreadSourceFailed || failed.Retirement != ThreadSourceAuthenticatedWithdrawal || failed.Cause == nil {
				t.Fatal("late genuine fault was masked by prior authenticated retirement")
			}
			if kind == "health" && !errors.Is(failed.HealthError, cause) {
				t.Fatal("exact late health cause lost")
			}
			if kind == "persistence" && !errors.Is(failed.PersistenceError, errOwnedDatasetWrite) {
				t.Fatal("exact late backend cause lost")
			}
			if kind == "stop" && failed.Failure != ThreadSourceStopped {
				t.Fatal("actual Stop reason lost")
			}
		})
	}
}

func TestSourceLifetimeBoundedAcquireReleaseAliasesAndIDExhaustion(t *testing.T) {
	fixture, _, source, first := lifetimePublicFixture(t)
	var leases [SourceLifetimeCapacity]ThreadSourceLifetime
	leases[0] = first
	mustSRPLoop(t, fixture.node.inst, func() error {
		for i := 1; i < len(leases); i++ {
			var err error
			leases[i], err = fixture.attempt.AcquireSourceLifetime(source)
			if err != nil {
				return err
			}
		}
		if _, err := fixture.attempt.AcquireSourceLifetime(source); !errors.Is(err, goterrors.ErrNoBufs) {
			return fmt.Errorf("lease capacity unbounded or silently reused")
		}
		if !fixture.node.inst.netif.HasUnicastAddress(source) || len(fixture.node.inst.slaacManager.GetAddresses()) != 1 {
			return fmt.Errorf("proof exhaustion reduced address capacity/authority")
		}
		if err := fixture.attempt.ReleaseSourceLifetime(first); err != nil {
			return err
		}
		replacement, err := fixture.attempt.AcquireSourceLifetime(source)
		if err != nil {
			return err
		}
		if _, err := fixture.attempt.ObserveSourceLifetime(first); !errors.Is(err, goterrors.ErrInvalidState) {
			return fmt.Errorf("released alias revived on slot reuse")
		}
		if err := fixture.attempt.ReleaseSourceLifetime(first); !errors.Is(err, goterrors.ErrInvalidState) {
			return fmt.Errorf("stale release affected replacement")
		}
		if err := fixture.attempt.ReleaseSourceLifetime(replacement); err != nil {
			return err
		}
		for i := 1; i < len(leases); i++ {
			if err := fixture.attempt.ReleaseSourceLifetime(leases[i]); err != nil {
				return err
			}
		}
		for range 64 {
			lease, err := fixture.attempt.AcquireSourceLifetime(source)
			if err != nil {
				return err
			}
			if err := fixture.attempt.ReleaseSourceLifetime(lease); err != nil {
				return err
			}
		}
		fixture.node.inst.sourceLifetimeNext = ^uint64(0) // New API fixed-only exhaustion seam.
		if _, err := fixture.attempt.AcquireSourceLifetime(source); !errors.Is(err, goterrors.ErrNoBufs) {
			return fmt.Errorf("opaque lease identity wrapped/revived")
		}
		return nil
	})
}
