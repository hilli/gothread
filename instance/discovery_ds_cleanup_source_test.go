package instance

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/key"
)

// NEW CleanupStopped API only: not installed on oldad918 and never counted as
// an absent-method/compiler/panic/timeout regression counterexample.
func TestDiscoveryDS3StoppedCleanupUnderFailedLatchesRunsNoOrdinaryWork(t *testing.T) {
	for _, kind := range []string{"health", "persistence", "both"} {
		t.Run(kind, func(t *testing.T) {
			store := &datasetWriteFault{SimSettings: simulation.NewSimSettings()}
			fixture, driver := discoveryDSFixture(t, store, false)
			inst := fixture.node.inst
			attempt := beginSourceDiscovery(t, fixture, 1<<15)
			assertActualDiscoveryRequest(t, fixture, 15)
			health := errors.New("DS3 latched actual entropy-provider failure")
			restore := errors.New("DS3 retained home receive failure")
			mustSRPLoop(t, inst, func() error {
				driver.failChannel, driver.receiveErr = 20, restore
				if kind == "persistence" || kind == "both" {
					store.fail = platform.SettingsKeyNetworkInfo
					sequence := inst.GetCurrentKeySequence()
					inst.SetCurrentKeySequence(sequence+1, key.ForceUpdate)
					if err := inst.PersistenceError(); !errors.Is(err, errOwnedDatasetWrite) ||
						inst.GetCurrentKeySequence() != sequence {
						return fmt.Errorf("actual persistence failure not established without key change: %v", err)
					}
				}
				if kind == "health" || kind == "both" {
					inst.entropy.(*ownedTestEntropy).latch(health)
				}
				fixture.now = fixture.now.Add(10 * time.Millisecond)
				inst.timers.processExpired()
				inst.mac.RequestBeaconTransmission()
				return nil
			})
			result := awaitDiscoveryOutcome(t, attempt)
			if !errors.Is(result.Err, restore) {
				t.Fatal("initial terminal lost restoration failure")
			}
			if kind != "persistence" && !errors.Is(result.Err, health) {
				t.Fatal("health terminal cause lost")
			}
			if err := attempt.CleanupStopped(); !errors.Is(err, goterrors.ErrInvalidState) {
				t.Fatal("external cleanup-only API accepted a still-running loop")
			}
			inst.Stop()
			pendingMAC := inst.mac.GetPendingOperations()
			if pendingMAC == 0 {
				t.Fatal("actual ordinary MAC operation was not retained behind the failed radio lease")
			}
			expectedStart := errOwnedDatasetWrite
			if kind != "persistence" {
				expectedStart = health
			}
			if err := inst.Start(); !errors.Is(err, expectedStart) {
				t.Fatalf("ordinary Start bypassed failed latch: %v", err)
			}
			ordinary := 0
			if err := inst.Do(context.Background(), func() error { ordinary++; return nil }); !errors.Is(err, goterrors.ErrInvalidState) {
				t.Fatal("ordinary Do admitted a stopped failed instance")
			}
			// A queued ordinary operation must not be drained by restoration.
			select {
			case inst.taskCh <- loopTask{fn: func() { ordinary++ }}:
			default:
				t.Fatal("model queue unexpectedly full")
			}
			queued := len(inst.taskCh)
			beforeTX := driver.txCalls
			beforeCounters, beforeWrites := phase2AdmissionSnapshot(inst), store.writes
			beforeSecurity := inst.securityFailure.Load()
			beforeFence := inst.securityFenceRequested.Load()
			beforeKey, beforeSequence := inst.keyManager.GetNetworkKey(), inst.keyManager.GetCurrentKeySequence()
			foreign := &ThreadDiscoveryAttempt{inst: inst, owner: &nativeDiscovery{}, id: attempt.id, done: true}
			if err := foreign.CleanupStopped(); !errors.Is(err, goterrors.ErrInvalidState) {
				t.Fatal("foreign owner acquired cleanup privilege")
			}
			if err := attempt.CleanupStopped(); !errors.Is(err, restore) {
				t.Fatalf("failed stopped cleanup did not report actual restore cause: %v", err)
			}
			if inst.nativeDiscovery == nil || inst.discoveryCleanupOnly {
				t.Fatal("failed stopped cleanup lost owner/barrier")
			}
			var reentry error
			driver.receiveHook = func() {
				if err := inst.Start(); !errors.Is(err, goterrors.ErrBusy) {
					reentry = fmt.Errorf("Start overlapped cleanup: %v", err)
				}
				if err := attempt.CleanupStopped(); !errors.Is(err, goterrors.ErrBusy) {
					reentry = fmt.Errorf("recursive cleanup was not serialized: %v", err)
				}
				if err := inst.Do(context.Background(), func() error { ordinary++; return nil }); !errors.Is(err, goterrors.ErrInvalidState) {
					reentry = fmt.Errorf("cleanup-only barrier admitted ordinary work: %v", err)
				}
			}
			// Repair ONLY the radio fault; no entropy/persistence/key reset.
			driver.receiveErr = nil
			if err := attempt.CleanupStopped(); err != nil {
				t.Fatalf("supported stopped cleanup failed: %v", err)
			}
			driver.receiveHook = nil
			if reentry != nil {
				t.Fatal(reentry)
			}
			if ordinary != 0 || len(inst.taskCh) != queued || driver.txCalls != beforeTX ||
				inst.mac.GetPendingOperations() != pendingMAC || inst.IsRunning() || inst.nativeDiscovery != nil ||
				inst.discoveryScanner.IsScanning() || inst.discoveryCleanupOnly ||
				driver.channel != 20 || driver.pan != 0xface || driver.state != radio.StateReceive {
				t.Fatal("DS3 cleanup ran ordinary work/loop or failed actual home restoration/release")
			}
			if phase2AdmissionSnapshot(inst) != beforeCounters || store.writes != beforeWrites ||
				inst.securityFailure.Load() != beforeSecurity || inst.keyManager.GetNetworkKey() != beforeKey ||
				inst.keyManager.GetCurrentKeySequence() != beforeSequence || inst.securityFenceRequested.Load() != beforeFence {
				t.Fatal("DS3 cleanup changed counters/NV/health latch/key identity")
			}
			if kind != "persistence" && !errors.Is(inst.SecurityError(), health) {
				t.Fatal("health latch cleared")
			}
			if kind != "health" && !errors.Is(inst.PersistenceError(), errOwnedDatasetWrite) {
				t.Fatal("persistence latch cleared")
			}
			if err := inst.Start(); !errors.Is(err, expectedStart) {
				t.Fatal("normal Start became enabled after cleanup")
			}
			select {
			case _, open := <-attempt.Result():
				if open {
					t.Fatal("cleanup emitted another terminal")
				}
			default:
				t.Fatal("terminal not closed")
			}
			if err := attempt.CleanupStopped(); !errors.Is(err, goterrors.ErrInvalidState) {
				t.Fatal("released attempt retained cleanup privilege")
			}
		})
	}
}
