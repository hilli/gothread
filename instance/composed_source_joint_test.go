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

// NEW composed ThreadBackend MODEL source oracles: UNPARSED/UNCOMPILED/UNRUN.
// Neither the real producer callbacks nor model server ACKs are RF evidence.
type jointSourceSettings struct {
	*datasetWriteFault
	calls [4]int
}

func (store *jointSourceSettings) Get(setting platform.SettingsKey, index int) ([]byte, error) {
	store.calls[0]++
	return store.datasetWriteFault.Get(setting, index)
}
func (store *jointSourceSettings) Set(setting platform.SettingsKey, value []byte) error {
	store.calls[1]++
	return store.datasetWriteFault.Set(setting, value)
}
func (store *jointSourceSettings) Add(setting platform.SettingsKey, value []byte) error {
	store.calls[2]++
	return store.datasetWriteFault.Add(setting, value)
}
func (store *jointSourceSettings) Delete(setting platform.SettingsKey, index int) error {
	store.calls[3]++
	return store.datasetWriteFault.Delete(setting, index)
}

func newJointSourceFixture(t *testing.T) (*srpOwnedProofFixture, *discoveryDSRadio, *jointSourceSettings) {
	t.Helper()
	store := &jointSourceSettings{datasetWriteFault: &datasetWriteFault{SimSettings: simulation.NewSimSettings()}}
	var driver *discoveryDSRadio
	thread := newOwnedAttachFixtureWithRadio(t, true, store, func(base *fragmentRadio) radio.Radio {
		driver = &discoveryDSRadio{discoveryProbeRadio: &discoveryProbeRadio{fragmentRadio: base}}
		return driver
	})
	// Only the capture helper's optional per-frame NV snapshot is disabled,
	// exactly as in the tested discovery fixture. Instance Settings stay real.
	thread.node.driver.settings = nil
	all := [4]bool{true, true, true, true}
	thread, parent, _ := publicFTDWireFixtureFor(t, thread, srpProofPrefixData(all, all))
	return newSRPOwnedProofFixtureFor(t, thread, parent, true, true), driver, store
}

func acquireJointSource(t *testing.T, fixture *srpOwnedProofFixture) ThreadSourceLifetime {
	t.Helper()
	var lease ThreadSourceLifetime
	mustSRPLoop(t, fixture.thread.node.inst, func() error {
		var err error
		lease, err = fixture.thread.attempt.AcquireSourceLifetime(fixture.config.Local.Address)
		return err
	})
	return lease
}

func TestComposedSourceDiscoveryRestoresG1BeforeSRPAndLifetimeG2Fences(t *testing.T) {
	for _, action := range []string{"timer", "matching-old-ack"} {
		t.Run(action, func(t *testing.T) {
			fixture, driver, store := newJointSourceFixture(t)
			thread, inst := fixture.thread, fixture.thread.node.inst
			registerOwnedSRPControl(t, fixture, 5540)
			lease := acquireJointSource(t, fixture)
			g1 := observeLifetime(t, thread, lease)
			var attachment ThreadAttachmentObservation
			var counters phase2AdmissionCounters
			var networkKey key.NetworkKey
			var sequence uint32
			var ioBefore [4]int
			mustSRPLoop(t, inst, func() error {
				var err error
				attachment, err = thread.attempt.ObserveAttachment(fixture.config.Local.Address)
				counters, networkKey, sequence = phase2AdmissionSnapshot(inst), inst.keyManager.GetNetworkKey(), inst.GetCurrentKeySequence()
				ioBefore = store.calls
				return err
			})
			scan := beginSourceDiscovery(t, thread, 1<<15)
			assertActualDiscoveryRequest(t, thread, 15)
			response := discoveryPeerFrame(t, thread, 15, 0x1234)
			deliverNativeFrame(t, thread.node, udpRadioCapture{frame: response})
			mustSRPLoop(t, inst, func() error {
				thread.now = thread.now.Add(10 * time.Millisecond)
				inst.timers.processExpired()
				return nil
			})
			outcome := awaitDiscoveryOutcome(t, scan)
			if outcome.Err != nil || len(outcome.Results) != 1 || outcome.Results[0].Channel != 15 {
				t.Fatal("joint actual typed discovery did not complete its own response/restoration")
			}
			mustSRPLoop(t, inst, func() error {
				current, err := thread.attempt.ObserveAttachment(fixture.config.Local.Address)
				if err != nil || current != attachment || phase2AdmissionSnapshot(inst) != counters ||
					inst.keyManager.GetNetworkKey() != networkKey || inst.GetCurrentKeySequence() != sequence ||
					store.calls != ioBefore || fixture.binding.closed || fixture.binding.Err() != nil ||
					inst.nativeDiscovery != nil || driver.channel != 20 || driver.pan != 0xface ||
					driver.state != radio.StateReceive || inst.mac.GetPanChannelSnapshot() != 20 {
					return fmt.Errorf("joint plain scan changed G1/parent/key/NV/counters or failed checked home release")
				}
				return nil
			})
			if current := observeLifetime(t, thread, lease); current != g1 || current.State != ThreadSourceCurrent {
				t.Fatal("joint discovery changed the actual G1 lifetime proof")
			}
			var oldReply []byte
			if action == "matching-old-ack" {
				mustSRPLoop(t, inst, func() error {
					_, err := fixture.binding.UpsertService(nativeService("joint-pending-old-ack"))
					return err
				})
				driveOwnedSRPTimers(t, fixture)
				oldReply = makeOwnedSRPReply(t, fixture, captureOwnedSRPUpdate(t, fixture))
			}
			replaceOwnedSRPSourceGeneration(t, fixture, 0)
			retired := observeLifetime(t, thread, lease)
			if retired.State != ThreadSourceRetired || retired.Retirement != ThreadSourceAuthenticatedWithdrawal ||
				retired.Source != g1.Source || retired.SourceGeneration != g1.SourceGeneration ||
				retired.Epoch != g1.Epoch || retired.Cause != nil {
				t.Fatal("joint same-Epoch G2 overwrote old authenticated G1 retirement")
			}
			mustSRPLoop(t, inst, func() error {
				current, err := thread.attempt.ObserveAttachment(g1.Source)
				if err != nil || current.Epoch != g1.Epoch || current.Source != g1.Source ||
					current.SourceGeneration == g1.SourceGeneration {
					return fmt.Errorf("joint authentic same-address G2 control absent")
				}
				counters = phase2AdmissionSnapshot(inst)
				return nil
			})
			if action == "timer" {
				driveOwnedSRPTimers(t, fixture)
			} else {
				deliverOwnedSRPReply(t, fixture, oldReply)
			}
			mustSRPLoop(t, inst, func() error {
				binding := fixture.binding
				if !binding.closed || !errors.Is(binding.Err(), goterrors.ErrNoRoute) ||
					inst.srpBinding != nil || inst.udpManager.IsPortInUse(fixture.config.Local.Port) ||
					binding.timer != nil && binding.timer.active || len(driver.captures) != 0 ||
					inst.forwarder.GetBufferUsage().TxDatagrams != 0 || phase2AdmissionSnapshot(inst) != counters {
					return fmt.Errorf("joint stale SRP G1 timer/ACK accepted G2 or retained socket/timer/queue/new TX")
				}
				select {
				case notice, open := <-binding.Notices():
					if open && notice.Err == nil {
						return fmt.Errorf("joint old G1 ACK became successful G2 authority")
					}
				default:
					return fmt.Errorf("joint stale SRP closure did not close notice delivery")
				}
				return nil
			})
			old := fixture.binding
			mustSRPLoop(t, inst, func() error {
				var err error
				fixture.binding, err = inst.StartSRP(fixture.config)
				return err
			})
			if fixture.binding == old {
				t.Fatal("joint new binding reused old G1 SRP lifetime")
			}
			registerOwnedSRPControl(t, fixture, 5541)
			mustSRPLoop(t, inst, func() error { return thread.attempt.ReleaseSourceLifetime(lease) })
		})
	}
}

func TestComposedSourceFaultsRetainScanOwnerSRPAndLifetimeThroughStoppedCleanup(t *testing.T) {
	for _, kind := range []string{"health", "persistence", "both"} {
		t.Run(kind, func(t *testing.T) {
			fixture, driver, store := newJointSourceFixture(t)
			thread, inst := fixture.thread, fixture.thread.node.inst
			registerOwnedSRPControl(t, fixture, 5540)
			lease := acquireJointSource(t, fixture)
			scan := beginSourceDiscovery(t, thread, 1<<15)
			assertActualDiscoveryRequest(t, thread, 15)
			restore := errors.New("joint actual home Receive fault")
			mustSRPLoop(t, inst, func() error {
				driver.failChannel, driver.receiveErr = 20, restore
				if err := scan.Cancel(); err != nil {
					return err
				}
				inst.mac.RequestBeaconTransmission()
				return nil
			})
			outcome := awaitDiscoveryOutcome(t, scan)
			if !errors.Is(outcome.Err, context.Canceled) || !errors.Is(outcome.Err, restore) {
				t.Fatal("joint cancellation lost actual independent home restore cause")
			}
			mustSRPLoop(t, inst, func() error {
				if inst.nativeDiscovery == nil || fixture.binding.closed || inst.subMac.IsTransmittingOrScanning() {
					return fmt.Errorf("joint fault fixture has no active SRP and genuinely quiescent retained scan owner")
				}
				return nil
			})
			if kind != "persistence" {
				fillsBefore := 0
				mustSRPLoop(t, inst, func() error {
					// Configure failure in the already-used entropy BACKEND.
					// Real native SIG(0) Fill, not a health/latch setter, must
					// discover it and deliver the exact provider cause.
					entropy := inst.entropy.(*ownedTestEntropy)
					fillsBefore = entropy.source.calls
					entropy.source.fail = true
					_, err := fixture.binding.UpsertService(nativeService("joint-provider-fault"))
					return err
				})
				driveOwnedSRPTimers(t, fixture)
				mustSRPLoop(t, inst, func() error {
					if inst.entropy.(*ownedTestEntropy).source.calls <= fillsBefore ||
						!errors.Is(fixture.binding.Err(), errSRPEntropy) {
						return fmt.Errorf("joint real SRP signing Fill did not retain actual entropy backend error")
					}
					return nil
				})
			}
			if kind != "health" {
				mustSRPLoop(t, inst, func() error {
					store.fail = platform.SettingsKeyNetworkInfo
					sequence := inst.GetCurrentKeySequence()
					inst.SetCurrentKeySequence(sequence+1, key.ForceUpdate)
					if !errors.Is(inst.PersistenceError(), errOwnedDatasetWrite) || inst.GetCurrentKeySequence() != sequence {
						return fmt.Errorf("joint public failed sequence write changed keys or failed to latch genuine backend error")
					}
					return nil
				})
				if kind == "persistence" {
					driveOwnedSRPTimers(t, fixture)
					if !errors.Is(fixture.binding.Err(), errOwnedDatasetWrite) {
						t.Fatal("joint SRP internal timer lost exact persistence failure")
					}
				}
			}
			inst.Stop()
			if !fixture.binding.closed || inst.srpBinding != nil || fixture.binding.timer != nil && fixture.binding.timer.active ||
				inst.udpManager.IsPortInUse(fixture.config.Local.Port) || len(driver.captures) != 0 {
				t.Fatal("joint actual Stop failed to close SRP timer/socket without fresh wire")
			}
			expectedStart := errSRPEntropy
			if kind == "persistence" {
				expectedStart = errOwnedDatasetWrite
			}
			if err := inst.Start(); !errors.Is(err, expectedStart) {
				t.Fatalf("joint normal Start bypassed failed cause: %v", err)
			}
			if err := inst.Do(context.Background(), func() error { return nil }); !errors.Is(err, goterrors.ErrInvalidState) {
				t.Fatal("joint ordinary Do admitted the actual stopped generation")
			}
			beforeIO, beforeCounters, beforeTX := store.calls, phase2AdmissionSnapshot(inst), driver.txCalls
			beforeKey, beforeSequence := inst.keyManager.GetNetworkKey(), inst.GetCurrentKeySequence()
			beforeLatch, beforeFence := inst.securityFailure.Load(), inst.securityFenceRequested.Load()
			beforeRecords := inst.sourceLifetimes
			metadata, err := thread.attempt.ObserveSourceLifetime(lease)
			if err != nil || metadata.State != ThreadSourceFailed || metadata.Cause == nil {
				t.Fatal("joint stopped source metadata falsely reported clean/current")
			}
			if kind != "persistence" && !errors.Is(metadata.HealthError, errSRPEntropy) {
				t.Fatal("joint exact health metadata cause lost")
			}
			if kind != "health" && !errors.Is(metadata.PersistenceError, errOwnedDatasetWrite) {
				t.Fatal("joint exact persistence metadata cause lost")
			}
			if inst.sourceLifetimes != beforeRecords {
				t.Fatal("joint stopped Observe mutated source lifetime records")
			}
			if err := scan.CleanupStopped(); !errors.Is(err, restore) {
				t.Fatal("joint failed stopped cleanup lost exact radio restore cause")
			}
			ordinary := 0
			select {
			case inst.taskCh <- loopTask{fn: func() { ordinary++ }}:
			default:
				t.Fatal("joint stopped task queue unexpectedly full")
			}
			queued, pendingMAC := len(inst.taskCh), inst.mac.GetPendingOperations()
			if pendingMAC == 0 {
				t.Fatal("joint real pending MAC operation was not retained behind scan lease")
			}
			driver.receiveErr = nil // Repair ONLY the model radio restoration fault.
			if err := scan.CleanupStopped(); err != nil {
				t.Fatalf("joint named stopped cleanup failed: %v", err)
			}
			if ordinary != 0 || len(inst.taskCh) != queued || driver.txCalls != beforeTX ||
				inst.mac.GetPendingOperations() != pendingMAC || inst.nativeDiscovery != nil ||
				inst.discoveryScanner.IsScanning() || inst.discoveryCleanupOnly || inst.IsRunning() ||
				driver.channel != 20 || driver.pan != 0xface || driver.state != radio.StateReceive {
				t.Fatal("joint stopped cleanup rescheduled ordinary work or did not restore/release home owner")
			}
			if err := thread.attempt.ReleaseSourceLifetime(lease); err != nil {
				t.Fatal(err)
			}
			if _, err := thread.attempt.ObserveSourceLifetime(lease); !errors.Is(err, goterrors.ErrInvalidState) {
				t.Fatal("joint released stopped source alias retained authority")
			}
			if store.calls != beforeIO || phase2AdmissionSnapshot(inst) != beforeCounters ||
				inst.keyManager.GetNetworkKey() != beforeKey || inst.GetCurrentKeySequence() != beforeSequence ||
				inst.securityFailure.Load() != beforeLatch || inst.securityFenceRequested.Load() != beforeFence {
				t.Fatal("joint stopped metadata/cleanup changed NV/Fill/counters/keys or health fences")
			}
			if err := scan.CleanupStopped(); !errors.Is(err, goterrors.ErrInvalidState) {
				t.Fatal("joint released scan owner retained cleanup privilege")
			}
			select {
			case _, open := <-scan.Result():
				if open {
					t.Fatal("joint cleanup emitted another scan terminal")
				}
			default:
				t.Fatal("joint scan terminal did not stay closed")
			}
		})
	}
}
