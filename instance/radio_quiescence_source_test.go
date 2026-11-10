package instance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/submac"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/key"
)

// NEW API SOURCE oracles ONLY; UNPARSED/UNCOMPILED/UNRUN. Radio/hardware and
// logger are MODEL backends. Task dispatch/Stop/maintenance are the actual SDK.
func awaitRadioBridgeSource(t *testing.T, condition func() bool) {
	t.Helper()
	until := time.Now().Add(2 * time.Second)
	for !condition() {
		if !time.Now().Before(until) {
			t.Fatal("radio bridge source oracle did not reach its actual causal condition")
		}
		time.Sleep(time.Millisecond)
	}
}

func joinRadioBridgeSource(t *testing.T, inst *Instance) {
	t.Helper()
	awaitRadioBridgeSource(t, func() bool {
		err := inst.JoinRadioCallbacks()
		if err != nil && !errors.Is(err, goterrors.ErrBusy) {
			t.Fatalf("join actual operation error: %v", err)
		}
		return err == nil
	})
}

func waitRadioBridgeSource(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("radio bridge source oracle did not observe its actual channel milestone")
	}
}

func stopRadioBridgeSource(t *testing.T, inst *Instance) {
	t.Helper()
	awaitRadioBridgeSource(t, func() bool {
		err := inst.StopRadioQuiescent()
		if err != nil && !errors.Is(err, goterrors.ErrBusy) {
			t.Fatalf("stop actual operation error: %v", err)
		}
		return err == nil
	})
	select {
	case <-inst.doneCh:
	default:
		t.Fatal("nil stopped milestone preceded actual loop completion")
	}
}

func TestSDKRadioBridgePublicationBeforeBlockedEnqueueAndRealOuterReturn(t *testing.T) {
	fixture, _ := discoveryDSFixture(t, nil, false)
	inst := fixture.node.inst
	entered, releaseLoop := make(chan struct{}), make(chan struct{})
	var loopOnce sync.Once
	unblockLoop := func() { loopOnce.Do(func() { close(releaseLoop) }) }
	t.Cleanup(unblockLoop)
	opDone := make(chan error, 1)
	go func() {
		opDone <- inst.Do(context.Background(), func() error { close(entered); <-releaseLoop; return nil })
	}()
	waitRadioBridgeSource(t, entered)
	for range cap(inst.taskCh) {
		inst.PostTask(func() {})
	}
	ack, returnGate, posted := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var returnOnce sync.Once
	releaseReturn := func() { returnOnce.Do(func() { close(returnGate) }) }
	t.Cleanup(releaseReturn)
	go func() {
		inst.PostRadioCallback(func() {
			// A real driver acknowledgement can occur inside its deferred
			// epilogue BEFORE the function has returned to the SDK runner.
			defer func() { close(ack); <-returnGate }()
		})
		close(posted)
	}()
	awaitRadioBridgeSource(t, func() bool {
		inst.radioOwner.mu.Lock()
		defer inst.radioOwner.mu.Unlock()
		return inst.radioOwner.pending == 1
	})
	select {
	case <-posted:
		t.Fatal("driver publication unexpectedly fit the actually full existing queue")
	default:
	}
	if err := inst.JoinRadioCallbacks(); !errors.Is(err, goterrors.ErrBusy) {
		t.Fatal("blocked BEFORE-enqueue publication was invisible to genuine join")
	}
	unblockLoop()
	if err := <-opDone; err != nil {
		t.Fatal(err)
	}
	waitRadioBridgeSource(t, posted)
	waitRadioBridgeSource(t, ack)
	if err := inst.JoinRadioCallbacks(); !errors.Is(err, goterrors.ErrBusy) {
		t.Fatal("driver-owned ack was incorrectly accepted as actual outer return")
	}
	releaseReturn()
	joinRadioBridgeSource(t, inst)
}

type radioBridgeLogGate struct {
	cause            string
	entered, release chan struct{}
	once             sync.Once
}

func (logger *radioBridgeLogGate) Log(_ platform.LogLevel, _ platform.LogRegion, message string) {
	if strings.Contains(message, logger.cause) {
		logger.once.Do(func() { close(logger.entered) })
		<-logger.release
	}
}

func TestSDKRadioBridgeJoinsActualDiscoveryCompletionMaintenanceAfterDriverReturn(t *testing.T) {
	fixture, driver := discoveryDSFixture(t, nil, false)
	inst := fixture.node.inst
	scan := beginSourceDiscovery(t, fixture, 1<<15)
	actual := captureUDP(t, fixture.node.driver.boundedUDPRadio)
	mustSRPLoop(t, inst, func() error { return scan.Cancel() })
	if result := awaitDiscoveryOutcome(t, scan); !errors.Is(result.Err, goterrors.ErrBusy) {
		t.Fatal("actual accepted in-flight discovery did not retain ownership")
	}
	cause := errors.New("bridge genuine late accepted completion")
	logger := &radioBridgeLogGate{cause: cause.Error(), entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(logger.release) }) }
	t.Cleanup(unblock)
	mustSRPLoop(t, inst, func() error { inst.logger = logger; return nil })
	returned := make(chan struct{})
	inst.PostRadioCallback(func() {
		defer close(returned)
		// Legal on-loop completion maintenance must not enqueue behind
		// this genuinely full ordinary queue and wait for its own runner.
		for len(inst.taskCh) < cap(inst.taskCh) {
			inst.PostTask(func() {})
		}
		inst.SubMac().HandleTransmitDone(&actual.frame, nil, cause)
	})
	waitRadioBridgeSource(t, returned)
	waitRadioBridgeSource(t, logger.entered) // Actual native completion is now in SDK logger.
	if err := inst.JoinRadioCallbacks(); !errors.Is(err, goterrors.ErrBusy) {
		t.Fatal("join returned before actual completion-derived SDK maintenance returned")
	}
	unblock()
	joinRadioBridgeSource(t, inst)
	mustSRPLoop(t, inst, func() error {
		if inst.nativeDiscovery == nil || inst.nativeDiscovery.transmitting ||
			inst.subMac.IsTransmittingOrScanning() || !inst.subMac.IsCurrentTransmitCompletion(&actual.frame) {
			return fmt.Errorf("actual accepted-ID completion was lost or cleanup invented quiescence")
		}
		return nil
	})
	stopRadioBridgeSource(t, inst)
	restorer := &radioBridgeModelRestorer{inst: inst, driver: driver}
	if err := inst.RestoreRadioQuiescent(restorer); err != nil {
		t.Fatal(err)
	}
	if inst.nativeDiscovery != nil || inst.discoveryScanner.IsScanning() {
		t.Fatal("whole named discovery metadata did not release")
	}
}

type radioBridgeModelRestorer struct {
	inst                *Instance
	driver              *discoveryDSRadio
	panError, modeError error
	calls               []string
	duringMode          func()
}

func (restorer *radioBridgeModelRestorer) RestorePanID(pan uint16) error {
	restorer.calls = append(restorer.calls, "PAN")
	if restorer.panError != nil {
		return restorer.panError
	}
	restorer.driver.SetPanID(pan)
	return nil
}
func (restorer *radioBridgeModelRestorer) RestoreReceive(channel uint8) error {
	restorer.calls = append(restorer.calls, "RX")
	if restorer.modeError != nil {
		return restorer.modeError
	}
	if err := restorer.driver.Receive(channel); err != nil {
		return err
	}
	if restorer.duringMode != nil {
		restorer.duringMode()
	}
	return nil
}
func (restorer *radioBridgeModelRestorer) RestoreSleep() error {
	restorer.calls = append(restorer.calls, "SLEEP")
	if restorer.modeError != nil {
		return restorer.modeError
	}
	if err := restorer.driver.Sleep(); err != nil {
		return err
	}
	if restorer.duringMode != nil {
		restorer.duringMode()
	}
	return nil
}

func TestSDKRadioBridgeRetainedSleepRestorationIsWholeIdentityCheckedAndRetryable(t *testing.T) {
	fixture, driver := discoveryDSFixture(t, nil, false)
	inst := fixture.node.inst
	mustSRPLoop(t, inst, func() error { inst.mac.SetRxOnWhenIdle(false); return nil })
	scan := beginSourceDiscovery(t, fixture, 1<<15)
	assertActualDiscoveryRequest(t, fixture, 15)
	restoreError := errors.New("actual retained home sleep error")
	mustSRPLoop(t, inst, func() error {
		driver.sleepErr = restoreError
		if err := scan.Cancel(); err != nil {
			return err
		}
		inst.mac.RequestBeaconTransmission()
		return nil
	})
	if result := awaitDiscoveryOutcome(t, scan); !errors.Is(result.Err, restoreError) {
		t.Fatal("actual restore fault absent")
	}
	joinRadioBridgeSource(t, inst)
	stopRadioBridgeSource(t, inst)
	pendingMAC := inst.mac.GetPendingOperations()
	if pendingMAC == 0 {
		t.Fatal("no genuine pending ordinary MAC operation behind retained owner")
	}
	retained := inst.nativeDiscovery
	panError, modeError := errors.New("PAN command failed"), errors.New("sleep command failed")
	restorer := &radioBridgeModelRestorer{inst: inst, driver: driver, panError: panError}
	if err := inst.RestoreRadioQuiescent(restorer); !errors.Is(err, panError) {
		t.Fatal("PAN failure became cleanup success")
	}
	if len(restorer.calls) != 1 || inst.nativeDiscovery != retained || retained.lease == nil ||
		inst.subMac.GetState() != submac.StateReceive {
		t.Fatal("PAN-only partial restoration released/mutated SDK owner")
	}
	restorer.panError, restorer.modeError = nil, modeError
	if err := inst.RestoreRadioQuiescent(restorer); !errors.Is(err, modeError) {
		t.Fatal("mode failure became cleanup success")
	}
	if inst.nativeDiscovery != retained || retained.lease == nil || inst.subMac.GetState() != submac.StateReceive {
		t.Fatal("failed actual mode changed SubMac or lost retained owner")
	}
	restorer.modeError, driver.sleepErr = nil, nil
	restorer.duringMode = func() {
		if inst.nativeDiscovery != retained || retained.lease == nil || inst.subMac.GetState() != submac.StateReceive {
			t.Error("SubMac/MAC/native metadata released before actual mode command returned")
		}
		if err := inst.Start(); !errors.Is(err, goterrors.ErrBusy) {
			t.Error("recursive Start bypassed stopped cleanup barrier")
		}
		if err := inst.RestoreRadioQuiescent(restorer); !errors.Is(err, goterrors.ErrBusy) {
			t.Error("recursive whole restoration bypassed same-owner serialization")
		}
	}
	if err := inst.RestoreRadioQuiescent(restorer); err != nil {
		t.Fatal(err)
	}
	if inst.nativeDiscovery != nil || retained.lease != nil || inst.radioOwner.lease != nil ||
		inst.subMac.GetState() != submac.StateSleep || driver.state != radio.StateSleep ||
		inst.mac.GetPendingOperations() != pendingMAC ||
		strings.Join(restorer.calls, ",") != "PAN,PAN,SLEEP,PAN,SLEEP" {
		t.Fatal("whole ordered PAN->mode->SubMac->MAC/native release did not finish")
	}

	if err := inst.Start(); !errors.Is(err, goterrors.ErrInvalidState) {
		t.Fatal("irreversible bridge stop reopened ordinary admission")
	}
}

func TestSDKRadioBridgeRejectsChangedActualHomeIdentityBeforeAnyHardwareRestore(t *testing.T) {
	fixture, driver := discoveryDSFixture(t, nil, false)
	inst := fixture.node.inst
	joinRadioBridgeSource(t, inst)
	stopRadioBridgeSource(t, inst)
	// MODEL low-level identity invalidation through the actual existing MAC
	// setter, not a trusted proof/ready/owner field or synthetic cleanup token.
	inst.Mac().SetPanID(0xbeef)
	restorer := &radioBridgeModelRestorer{inst: inst, driver: driver}
	if err := inst.RestoreRadioQuiescent(restorer); !errors.Is(err, goterrors.ErrInvalidState) {
		t.Fatal("changed real MAC identity acquired old stopped-owner authority")
	}
	if len(restorer.calls) != 0 || inst.radioOwner.lease == nil || inst.radioOwner.restored {
		t.Fatal("identity failure performed hardware cleanup or released owner")
	}
}

func TestSDKRadioBridgeHealthyNoScanAndCallsOnActualLoopRemainBounded(t *testing.T) {
	fixture, driver := discoveryDSFixture(t, nil, false)
	inst := fixture.node.inst
	completed := make(chan struct{})
	inst.PostRadioCallback(func() {
		if err := inst.JoinRadioCallbacks(); !errors.Is(err, goterrors.ErrBusy) {
			t.Error("actual active callback joined itself")
		}
		if err := inst.StopRadioQuiescent(); !errors.Is(err, goterrors.ErrBusy) {
			t.Error("actual active callback stopped/waited on itself")
		}
		if err := inst.RestoreRadioQuiescent(&radioBridgeModelRestorer{inst: inst, driver: driver}); !errors.Is(err, goterrors.ErrInvalidState) {
			t.Error("actual running loop admitted stopped restoration")
		}
		close(completed)
	})
	waitRadioBridgeSource(t, completed)
	joinRadioBridgeSource(t, inst)
	stopRadioBridgeSource(t, inst)
	if inst.radioOwner.discovery != nil || inst.radioOwner.lease == nil {
		t.Fatal("healthy no-scan path has no genuine named MAC home owner")
	}
	restorer := &radioBridgeModelRestorer{inst: inst, driver: driver}
	if err := inst.RestoreRadioQuiescent(restorer); err != nil {
		t.Fatal(err)
	}
	if strings.Join(restorer.calls, ",") != "PAN,RX" || !inst.radioOwner.restored || inst.radioOwner.lease != nil {
		t.Fatal("healthy canceled/no-retained-scan path skipped named home restoration")
	}
	ran := false
	inst.PostTask(func() { ran = true })
	if err := inst.Do(context.Background(), func() error { ran = true; return nil }); !errors.Is(err, goterrors.ErrInvalidState) {
		t.Fatal("ordinary Do admission reopened after resource milestone success")
	}
	if ran {
		t.Fatal("ordinary task ran after permanent stop")
	}
}

func TestSDKRadioBridgeStickyHealthAndLatePersistenceDoNotMasqueradeAsFailedResourceMilestones(t *testing.T) {
	for _, persistenceFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "health-first", true: "persistence-first"}[persistenceFirst], func(t *testing.T) {
			fixture, driver, store := newJointSourceFixture(t)
			thread, inst := fixture.thread, fixture.thread.node.inst
			registerOwnedSRPControl(t, fixture, 5540)
			lease := acquireJointSource(t, fixture)
			mustSRPLoop(t, inst, fixture.binding.Stop)
			callbackReturned := make(chan struct{})
			inst.PostRadioCallback(func() {
				defer close(callbackReturned)
				persist := func() {
					store.fail = platform.SettingsKeyNetworkInfo
					before := inst.GetCurrentKeySequence()
					inst.SetCurrentKeySequence(before+1, key.ForceUpdate)
					if !errors.Is(inst.PersistenceError(), errOwnedDatasetWrite) || inst.GetCurrentKeySequence() != before {
						t.Error("actual persistence cause lost or key sequence changed")
					}
				}
				if persistenceFirst {
					persist()
				}
				inst.entropy.(*ownedTestEntropy).source.fail = true // MODEL backend, not an SDK latch setter.
				if persistenceFirst {
					// A persisted write failure correctly blocks new networking.
					// The configured independent provider can still expose its first
					// later health error through its real public Fill/Err path.
					var data [1]byte
					if err := inst.Entropy().Fill(data[:]); !errors.Is(err, errSRPEntropy) {
						t.Error("later provider Fill failure absent")
					}
				} else if _, err := inst.StartSRP(fixture.config); !errors.Is(err, errSRPEntropy) {
					t.Error("actual public producer did not consume failed Fill")
				}
				if !errors.Is(inst.SecurityError(), errSRPEntropy) {
					t.Error("actual provider failure not retained by SDK")
				}
				if !persistenceFirst {
					persist()
				}
			})
			waitRadioBridgeSource(t, callbackReturned)
			joinRadioBridgeSource(t, inst)
			stopRadioBridgeSource(t, inst)
			beforeIO, beforeCounters := store.calls, phase2AdmissionSnapshot(inst)
			beforeKey, beforeLatch := inst.keyManager.GetNetworkKey(), inst.securityFailure.Load()
			if err := inst.RestoreRadioQuiescent(&radioBridgeModelRestorer{inst: inst, driver: driver}); err != nil {
				t.Fatalf("completed resource restoration was made permanently uncloseable by historical health: %v", err)
			}
			if !errors.Is(inst.SecurityError(), errSRPEntropy) || !errors.Is(inst.PersistenceError(), errOwnedDatasetWrite) ||
				inst.securityFailure.Load() != beforeLatch || inst.keyManager.GetNetworkKey() != beforeKey {
				t.Fatal("resource milestone success discarded exact first/late genuine SDK causes")
			}
			status, err := thread.attempt.ObserveSourceLifetime(lease)
			if err != nil || status.State != ThreadSourceFailed || !errors.Is(status.HealthError, errSRPEntropy) ||
				!errors.Is(status.PersistenceError, errOwnedDatasetWrite) {
				t.Fatal("stopped life metadata lost genuine causes")
			}
			if err := thread.attempt.ReleaseSourceLifetime(lease); err != nil {
				t.Fatal(err)
			}
			if store.calls != beforeIO || phase2AdmissionSnapshot(inst) != beforeCounters {
				t.Fatal("stopped cleanup/query/release performed NV/Fill/counter work")
			}
			if err := inst.Start(); !errors.Is(err, goterrors.ErrInvalidState) {
				t.Fatal("nil resource stages were treated as healthy restart")
			}
		})
	}
}

func TestSDKRadioBridgeBusyStopRetainsRealAcceptedCompletionAndRejectsRacingOrdinaryAdmission(t *testing.T) {
	fixture, driver := discoveryDSFixture(t, nil, false)
	inst := fixture.node.inst
	scan := beginSourceDiscovery(t, fixture, 1<<15)
	actual := captureUDP(t, fixture.node.driver.boundedUDPRadio)
	if err := inst.StopRadioQuiescent(); !errors.Is(err, goterrors.ErrBusy) {
		t.Fatal("premature stop claimed actual accepted TX quiescence")
	}
	awaitRadioBridgeSource(t, func() bool {
		inst.radioOwner.mu.Lock()
		defer inst.radioOwner.mu.Unlock()
		return errors.Is(inst.radioOwner.stopError, goterrors.ErrBusy)
	})
	if err := inst.Do(context.Background(), func() error { t.Error("racing ordinary request executed"); return nil }); !errors.Is(err, goterrors.ErrInvalidState) {
		t.Fatal("irreversible ordinary admission fence missing after stop attempt")
	}
	select {
	case <-inst.doneCh:
		t.Fatal("failed busy stop joined loop without real completion")
	default:
	}
	inst.PostRadioCallback(func() { inst.SubMac().HandleTransmitDone(&actual.frame, nil, nil) })
	joinRadioBridgeSource(t, inst)
	stopRadioBridgeSource(t, inst)
	result := awaitDiscoveryOutcome(t, scan)
	if result.Err == nil {
		t.Fatal("scan operation failure was hidden by successful loop-stop milestone")
	}
	if !inst.subMac.IsCurrentTransmitCompletion(&actual.frame) {
		t.Fatal("stop fence dropped accepted TX completion")
	}
	if err := inst.RestoreRadioQuiescent(&radioBridgeModelRestorer{inst: inst, driver: driver}); err != nil {
		t.Fatal(err)
	}
}

func TestSDKRadioBridgeOrdinaryStopDoesNotSealBeforeAcceptedCallbackPublication(t *testing.T) {
	fixture, driver := discoveryDSFixture(t, nil, false)
	inst := fixture.node.inst
	scan := beginSourceDiscovery(t, fixture, 1<<15)
	actual := captureUDP(t, fixture.node.driver.boundedUDPRadio)
	joinRadioBridgeSource(t, inst) // Opt in while an actual radio submission still exists.
	stopped := make(chan struct{})
	go func() { inst.Stop(); close(stopped) }()
	awaitRadioBridgeSource(t, func() bool {
		inst.runningMu.Lock()
		defer inst.runningMu.Unlock()
		return inst.stopping
	})
	select {
	case <-stopped:
		t.Fatal("ordinary opt-in Stop sealed before the still-accepted callback could publish")
	default:
	}
	inst.PostRadioCallback(func() { inst.SubMac().HandleTransmitDone(&actual.frame, nil, nil) })
	waitRadioBridgeSource(t, stopped)
	if !inst.subMac.IsCurrentTransmitCompletion(&actual.frame) {
		t.Fatal("ordinary Stop lost accepted callback identity")
	}
	if result := awaitDiscoveryOutcome(t, scan); result.Err == nil {
		t.Fatal("stopped scan operation falsely succeeded")
	}
	if err := inst.StopRadioQuiescent(); err != nil {
		t.Fatal(err)
	}
	if err := inst.RestoreRadioQuiescent(&radioBridgeModelRestorer{inst: inst, driver: driver}); err != nil {
		t.Fatal(err)
	}
}

func TestSDKRadioBridgeFirstJoinIncludesActualMaintenanceBeforeFirstDriverPublication(t *testing.T) {
	fixture, driver := discoveryDSFixture(t, nil, false)
	inst := fixture.node.inst
	scan := beginSourceDiscovery(t, fixture, 1<<15)
	actual := captureUDP(t, fixture.node.driver.boundedUDPRadio)
	mustSRPLoop(t, inst, func() error { return scan.Cancel() })
	_ = awaitDiscoveryOutcome(t, scan)
	cause := errors.New("pre-publication actual completion maintenance")
	logger := &radioBridgeLogGate{cause: cause.Error(), entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(logger.release) }) }
	t.Cleanup(unblock)
	mustSRPLoop(t, inst, func() error { inst.logger = logger; return nil })
	// Actual existing callback path on the SDK loop, as used by synchronous
	// radio errors: no PostRadioCallback or Join has enabled the bridge yet.
	// Do not call completeNativeFrame here: its subsequent loop observation
	// would wait behind the logger that this test must release externally.
	inst.PostTask(func() { inst.SubMac().HandleTransmitDone(&actual.frame, nil, cause) })
	waitRadioBridgeSource(t, logger.entered)
	inst.radioOwner.mu.Lock()
	enabled, pending := inst.radioOwner.enabled, inst.radioOwner.pending
	inst.radioOwner.mu.Unlock()
	if enabled || pending == 0 {
		t.Fatal("actual earlier maintenance was not independently accounted before opt-in")
	}
	if err := inst.JoinRadioCallbacks(); !errors.Is(err, goterrors.ErrBusy) {
		t.Fatal("first Join ignored actual earlier completion maintenance")
	}
	unblock()
	joinRadioBridgeSource(t, inst)
	mustSRPLoop(t, inst, func() error {
		if !inst.subMac.IsCurrentTransmitCompletion(&actual.frame) || inst.subMac.IsTransmittingOrScanning() ||
			inst.nativeDiscovery == nil || inst.nativeDiscovery.transmitting {
			return fmt.Errorf("actual pre-first-publication completion was lost or falsely quiescent")
		}
		return nil
	})
	stopRadioBridgeSource(t, inst)
	if err := inst.RestoreRadioQuiescent(&radioBridgeModelRestorer{inst: inst, driver: driver}); err != nil {
		t.Fatal(err)
	}
}
