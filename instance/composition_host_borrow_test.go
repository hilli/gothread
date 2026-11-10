package instance

import (
	"errors"
	"fmt"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/srp"
	"github.com/hilli/gothread/radio"
)

func endCompositionHOSTScan(t *testing.T, fixture *srpOwnedProofFixture, scan *ThreadDiscoveryAttempt) {
	t.Helper()
	mustSRPLoop(t, fixture.thread.node.inst, func() error {
		fixture.thread.now = fixture.thread.now.Add(10 * time.Millisecond)
		fixture.thread.node.inst.timers.processExpired()
		return nil
	})
	if outcome := awaitDiscoveryOutcome(t, scan); outcome.Err != nil {
		t.Fatalf("actual checked home restoration failed: %v", outcome.Err)
	}
}

func requireCompositionHOSTG2Fence(t *testing.T, fixture *srpOwnedProofFixture, lease ThreadSourceLifetime) {
	t.Helper()
	before := observeLifetime(t, fixture.thread, lease)
	replaceOwnedSRPSourceGeneration(t, fixture, 0)
	driveOwnedSRPTimers(t, fixture)
	mustSRPLoop(t, fixture.thread.node.inst, func() error {
		if !fixture.binding.closed || !errors.Is(fixture.binding.Err(), goterrors.ErrNoRoute) ||
			len(fixture.thread.node.driver.captures) != 0 {
			return fmt.Errorf("borrowed current-G1 activity transferred old SRP authority to same-address G2")
		}
		return nil
	})
	retired := observeLifetime(t, fixture.thread, lease)
	if retired.State != ThreadSourceRetired || retired.Retirement != ThreadSourceAuthenticatedWithdrawal ||
		retired.SourceGeneration != before.SourceGeneration || retired.Epoch != before.Epoch {
		t.Fatal("borrowed G1 activity changed old-generation authenticated retirement")
	}
	mustSRPLoop(t, fixture.thread.node.inst, func() error {
		var err error
		fixture.binding, err = fixture.thread.node.inst.StartSRP(fixture.config)
		return err
	})
	registerOwnedSRPControl(t, fixture, 5542)
}

func TestCompositionHOSTInternalSRPTimerQueuesDuringActualDiscoveryLease(t *testing.T) {
	fixture, driver, _ := newJointSourceFixture(t)
	inst := fixture.thread.node.inst
	registerOwnedSRPControl(t, fixture, 5540)
	lease := acquireJointSource(t, fixture)
	g1 := observeLifetime(t, fixture.thread, lease)
	scan := beginSourceDiscovery(t, fixture.thread, 1<<15)
	assertActualDiscoveryRequest(t, fixture.thread, 15)
	var scanTX int
	mustSRPLoop(t, inst, func() error {
		scanTX = driver.txCalls
		service := nativeService("owned-generation")
		service.Port = 5541
		_, err := fixture.binding.UpsertService(service)
		return err
	})
	// Actual native client timer, not direct Send/Ready/state manipulation.
	fireSRPTimer(t, fixture.binding)
	mustSRPLoop(t, inst, func() error {
		if inst.nativeDiscovery == nil || inst.nativeDiscovery.lease == nil ||
			inst.nativeDiscovery.terminal || fixture.binding.closed || fixture.binding.Err() != nil ||
			fixture.binding.client.GetState() != srp.StateUpdating ||
			inst.forwarder.GetBufferUsage().TxDatagrams != 1 {
			return fmt.Errorf("actual SRP internal timer did not queue current-G1 update while discovery owns the MAC lease")
		}
		if driver.txCalls != scanTX || len(driver.captures) != 0 {
			return fmt.Errorf("queued current-G1 SRP escaped onto the borrowed discovery channel")
		}
		return nil
	})
	if current := observeLifetime(t, fixture.thread, lease); current != g1 || current.State != ThreadSourceCurrent {
		t.Fatal("actual borrowed SRP timer invalidated a legitimate G1 lifetime")
	}
	endCompositionHOSTScan(t, fixture, scan)
	packet := captureOwnedSRPUpdate(t, fixture)
	deliverOwnedSRPReply(t, fixture, makeOwnedSRPReply(t, fixture, packet))
	notice := nextSRPNotice(t, fixture.binding)
	if notice.Err != nil || len(notice.Services) != 1 || notice.Services[0].Port != 5541 {
		t.Fatal("checked home restore did not resume queued native SRP with a real matching server ACK")
	}
	mustSRPLoop(t, inst, func() error {
		if inst.nativeDiscovery != nil || driver.channel != 20 || driver.pan != 0xface ||
			driver.state != radio.StateReceive || fixture.binding.Err() != nil {
			return fmt.Errorf("queued SRP completion lacked genuine checked home release")
		}
		return nil
	})
	requireCompositionHOSTG2Fence(t, fixture, lease)
}

func TestCompositionHOSTMatchingCurrentG1ACKIsAcceptedDuringDiscoveryLease(t *testing.T) {
	fixture, driver, _ := newJointSourceFixture(t)
	inst := fixture.thread.node.inst
	registerOwnedSRPControl(t, fixture, 5540)
	lease := acquireJointSource(t, fixture)
	g1 := observeLifetime(t, fixture.thread, lease)
	mustSRPLoop(t, inst, func() error {
		service := nativeService("owned-generation")
		service.Port = 5541
		_, err := fixture.binding.UpsertService(service)
		return err
	})
	driveOwnedSRPTimers(t, fixture)
	request := captureOwnedSRPUpdate(t, fixture)
	response := makeOwnedSRPReply(t, fixture, request)
	frames := captureOwnQueryPacket(t, fixture.parent, fixture.thread, response, true)
	var scan *ThreadDiscoveryAttempt
	var scanTX int
	mustSRPLoop(t, inst, func() error {
		// Genuine authenticated home-channel RX arrives before the borrow.
		// Its actual SDK ACK processing remains queued when the lease is
		// acquired, so acceptance runs DURING the borrow without pretending
		// a real radio could receive home-channel RF while tuned elsewhere.
		for _, capture := range frames {
			frame := capture.frame
			frame.PSDU = append([]byte(nil), frame.PSDU...)
			frame.RxInfo = &radio.RxInfo{RSSI: -37, LQI: 90}
			inst.SubMac().HandleReceiveDone(&frame, nil)
			clear(frame.PSDU)
		}
		if fixture.binding.queuedRX == 0 {
			return fmt.Errorf("actual matching G1 ACK did not reach deferred SDK receive")
		}
		var err error
		scan, err = inst.BeginThreadDiscovery(ThreadDiscoveryConfig{
			ChannelMask: 1 << 15, ChannelDuration: 10 * time.Millisecond, Timeout: time.Second,
		})
		scanTX = driver.txCalls
		return err
	})
	// The real ACK task was enqueued before this normal Do turn. Let the
	// genuine FIFO runner execute it before reading the nonblocking notice.
	mustSRPLoop(t, inst, func() error { return nil })
	notice := nextSRPNotice(t, fixture.binding)
	if notice.Err != nil || len(notice.Services) != 1 || notice.Services[0].Port != 5541 {
		t.Fatal("actual matching current-G1 ACK was falsely rejected during discovery borrow")
	}
	mustSRPLoop(t, inst, func() error {
		if inst.nativeDiscovery == nil || inst.nativeDiscovery.lease == nil || inst.nativeDiscovery.terminal ||
			fixture.binding.Err() != nil || fixture.binding.closed ||
			fixture.binding.client.GetState() != srp.StateUpdated || driver.txCalls != scanTX {
			return fmt.Errorf("matching current-G1 ACK did not remain legitimately live under actual discovery ownership")
		}
		return nil
	})
	if current := observeLifetime(t, fixture.thread, lease); current != g1 || current.State != ThreadSourceCurrent {
		t.Fatal("matching current-G1 ACK forged withdrawal/failure during the borrow")
	}
	assertActualDiscoveryRequest(t, fixture.thread, 15)
	endCompositionHOSTScan(t, fixture, scan)
	requireCompositionHOSTG2Fence(t, fixture, lease)
}

func TestCompositionHOSTIfDownFailureKeepsActualLeaseAndPriorLifetimeCause(t *testing.T) {
	fixture, driver, _ := newJointSourceFixture(t)
	inst := fixture.thread.node.inst
	registerOwnedSRPControl(t, fixture, 5540)
	lease := acquireJointSource(t, fixture)
	scan := beginSourceDiscovery(t, fixture.thread, 1<<15)
	assertActualDiscoveryRequest(t, fixture.thread, 15)
	cause := errors.New("composition actual home RX restore failure")
	mustSRPLoop(t, inst, func() error {
		driver.failChannel, driver.receiveErr = 20, cause
		if err := inst.ThreadStop(); !errors.Is(err, cause) {
			return fmt.Errorf("ThreadStop lost actual restore failure: %v", err)
		}
		if err := inst.IfConfigDown(); !errors.Is(err, cause) {
			return fmt.Errorf("IfConfigDown bypassed retained restore failure: %v", err)
		}
		if !inst.ifConfigUp || inst.nativeDiscovery == nil || inst.nativeDiscovery.lease == nil {
			return fmt.Errorf("failed IfConfigDown falsely completed interface or lease teardown")
		}
		status, err := fixture.thread.attempt.ObserveSourceLifetime(lease)
		if err != nil || status.Failure != ThreadSourceStopped {
			return fmt.Errorf("failed IfConfigDown changed the real earlier source-stop cause")
		}
		driver.receiveErr = nil
		if err := scan.RetryCleanup(); err != nil {
			return err
		}
		return inst.IfConfigDown()
	})
}

func TestCompositionHOSTLoopStopRecordsLifetimeBeforeFallibleCleanup(t *testing.T) {
	fixture, driver, _ := newJointSourceFixture(t)
	inst := fixture.thread.node.inst
	registerOwnedSRPControl(t, fixture, 5540)
	lease := acquireJointSource(t, fixture)
	scan := beginSourceDiscovery(t, fixture.thread, 1<<15)
	assertActualDiscoveryRequest(t, fixture.thread, 15)
	cause := errors.New("composition Stop restore failed")
	called := false
	var observed error
	mustSRPLoop(t, inst, func() error {
		driver.failChannel, driver.receiveErr = 20, cause
		driver.receiveHook = func() {
			called = true
			status, err := fixture.thread.attempt.ObserveSourceLifetime(lease)
			if err != nil || status.State != ThreadSourceFailed || status.Failure != ThreadSourceStopped {
				observed = fmt.Errorf("actual loop shutdown called fallible restoration before recording source Stop")
			}
		}
		return nil
	})
	inst.Stop()
	driver.receiveHook = nil
	if !called || observed != nil {
		t.Fatalf("Stop-before-cleanup source ordering not observed: called=%v error=%v", called, observed)
	}
	if result := awaitDiscoveryOutcome(t, scan); !errors.Is(result.Err, cause) {
		t.Fatal("actual Stop lost cleanup cause")
	}
	driver.receiveErr = nil
	if err := scan.CleanupStopped(); err != nil {
		t.Fatal(err)
	}
}

func TestCompositionHOSTEarlierHealthCauseSurvivesActualStopAndCleanup(t *testing.T) {
	fixture, driver, _ := newJointSourceFixture(t)
	inst := fixture.thread.node.inst
	registerOwnedSRPControl(t, fixture, 5540)
	lease := acquireJointSource(t, fixture)
	scan := beginSourceDiscovery(t, fixture.thread, 1<<15)
	assertActualDiscoveryRequest(t, fixture.thread, 15)
	restore := errors.New("composition independent retained restore failure")
	mustSRPLoop(t, inst, func() error {
		driver.failChannel, driver.receiveErr = 20, restore
		inst.entropy.(*ownedTestEntropy).source.fail = true // Configured MODEL backend only.
		var data [1]byte
		if err := inst.Entropy().Fill(data[:]); !errors.Is(err, errSRPEntropy) {
			return fmt.Errorf("genuine provider Fill error absent")
		}
		if !errors.Is(inst.SecurityError(), errSRPEntropy) {
			return fmt.Errorf("actual SDK health latch absent")
		}
		return nil
	})
	inst.Stop()
	status, err := fixture.thread.attempt.ObserveSourceLifetime(lease)
	if err != nil || status.State != ThreadSourceFailed || status.Failure != ThreadSourceHealthFailure ||
		!errors.Is(status.Cause, errSRPEntropy) || !errors.Is(status.HealthError, errSRPEntropy) {
		t.Fatal("actual later loop Stop/cleanup overwrote the earlier genuine health lifetime cause")
	}
	if fixture.binding.Err() == nil || !fixture.binding.closed {
		t.Fatal("actual health fence/Stop retained SRP socket")
	}
	outcome := awaitDiscoveryOutcome(t, scan)
	if !errors.Is(outcome.Err, restore) {
		t.Fatal("health Stop discarded independent restore error")
	}
	driver.receiveErr = nil
	if err := scan.CleanupStopped(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(inst.SecurityError(), errSRPEntropy) {
		t.Fatal("cleanup reset genuine SDK health")
	}
}
