package instance

import (
	"context"
	"errors"
	"fmt"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
)

type lifetimeHOSTSettings struct {
	*simulation.SimSettings
	calls [4]int
}

func (store *lifetimeHOSTSettings) Get(key platform.SettingsKey, index int) ([]byte, error) {
	store.calls[0]++
	return store.SimSettings.Get(key, index)
}
func (store *lifetimeHOSTSettings) Set(key platform.SettingsKey, data []byte) error {
	store.calls[1]++
	return store.SimSettings.Set(key, data)
}
func (store *lifetimeHOSTSettings) Add(key platform.SettingsKey, data []byte) error {
	store.calls[2]++
	return store.SimSettings.Add(key, data)
}
func (store *lifetimeHOSTSettings) Delete(key platform.SettingsKey, index int) error {
	store.calls[3]++
	return store.SimSettings.Delete(key, index)
}

func TestSourceLifetimeHOSTReleaseReturnsCapacityWithoutRevivingAlias(t *testing.T) {
	fixture, _, source, first := lifetimePublicFixture(t)
	mustSRPLoop(t, fixture.node.inst, func() error {
		for i := 1; i < SourceLifetimeCapacity; i++ {
			if _, err := fixture.attempt.AcquireSourceLifetime(source); err != nil {
				return err
			}
		}
		if err := fixture.attempt.ReleaseSourceLifetime(first); err != nil {
			return err
		}
		if _, err := fixture.attempt.AcquireSourceLifetime(source); err != nil {
			return fmt.Errorf("released actual lease did not return bounded capacity: %w", err)
		}
		if _, err := fixture.attempt.ObserveSourceLifetime(first); !errors.Is(err, goterrors.ErrInvalidState) {
			return fmt.Errorf("released alias revived on actual slot reuse")
		}
		return nil
	})
}

func TestSourceLifetimeHOSTFirstFailureLateHealthAndStoppedReadPurity(t *testing.T) {
	store := &lifetimeHOSTSettings{SimSettings: simulation.NewSimSettings()}
	fixture, _, source, lease := lifetimePublicFixture(t, store)
	inst := fixture.node.inst
	mustSRPLoop(t, inst, func() error {
		before := store.calls
		if _, err := fixture.attempt.ObserveSourceLifetime(lease); err != nil {
			return err
		}
		if store.calls != before {
			return fmt.Errorf("actual current observation performed Settings I/O")
		}
		inst.netif.RemoveUnicastAddress(&ip6.UnicastAddress{Address: source})
		return nil
	})
	first := observeLifetime(t, fixture, lease)
	late := errors.New("HOST late actual entropy health cause")
	mustSRPLoop(t, inst, func() error {
		inst.entropy.(*ownedTestEntropy).latch(late)
		return inst.ThreadStop()
	})
	inst.Stop()
	if err := inst.Start(); !errors.Is(err, late) {
		t.Fatalf("normal Start did not retain actual failed health: %v", err)
	}
	if err := inst.Do(context.Background(), func() error { return nil }); !errors.Is(err, goterrors.ErrInvalidState) {
		t.Fatal("normal Do admitted a stopped failed instance")
	}
	beforeIO, beforeCounters, beforeState := store.calls, phase2AdmissionSnapshot(inst), fixture.node.driver.GetState()
	beforeRecords, beforeLatch := inst.sourceLifetimes, inst.securityFailure.Load()
	after, err := fixture.attempt.ObserveSourceLifetime(lease)
	if err != nil || after.State != ThreadSourceFailed || after.Failure != ThreadSourceManualRemoval ||
		!errors.Is(after.Cause, first.Cause) || !errors.Is(after.HealthError, late) {
		t.Fatal("first genuine failure or exact late health was overwritten after actual Stop")
	}
	if inst.sourceLifetimes != beforeRecords || inst.securityFailure.Load() != beforeLatch {
		t.Fatal("stopped metadata observation mutated retained records/health")
	}
	if err := fixture.attempt.ReleaseSourceLifetime(lease); err != nil {
		t.Fatal(err)
	}
	if store.calls != beforeIO || phase2AdmissionSnapshot(inst) != beforeCounters ||
		fixture.node.driver.GetState() != beforeState || inst.IsRunning() {
		t.Fatal("stopped metadata query/release performed Settings/Fill/counter/hardware work")
	}
}
