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
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/mesh"
)

func TestThreadDiscoveryActualWireRestoresAttachedTupleAndRetainsOrdinaryTX(t *testing.T) {
	fixture, driver := discoverySourceFixture(t, true)
	source := actualOwnedSlaacAddress(t, fixture)
	var before ThreadAttachmentObservation
	var counters phase2AdmissionCounters
	mustSRPLoop(t, fixture.node.inst, func() error {
		var err error
		before, err = fixture.attempt.ObserveAttachment(source)
		counters = phase2AdmissionSnapshot(fixture.node.inst)
		return err
	})
	attempt := beginSourceDiscovery(t, fixture, 1<<15)
	assertActualDiscoveryRequest(t, fixture, 15)
	response := discoveryPeerFrame(t, fixture, 15, 0x1234)
	destination := ip6.Address{0x20, 1, 0x0d, 0xb8, 0, 2, 15: 0x79}
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		inst.subMac.HandleReceiveDone(&response, nil)
		clear(response.PSDU)
		current, err := fixture.attempt.ObserveAttachment(source)
		if err != nil || current != before || driver.channel != 15 || driver.pan != 0xffff ||
			inst.mac.GetPanChannelSnapshot() != 20 || inst.subMac.GetPanID() != 0xface {
			return fmt.Errorf("scan mutated configured/authenticated attachment identity")
		}
		if phase2AdmissionSnapshot(inst) != counters {
			return fmt.Errorf("plain scan consumed counters/entropy")
		}
		if err := inst.SendUDP([]byte("queued-home-source"), ip6.MessageInfo{
			SockAddr: source, PeerAddr: destination, SockPort: 5540, PeerPort: 5540,
		}); err != nil {
			return err
		}
		if len(driver.captures) != 0 {
			return fmt.Errorf("ordinary TX escaped onto scan channel")
		}
		return nil
	})
	mustSRPLoop(t, fixture.node.inst, func() error {
		fixture.now = fixture.now.Add(10 * time.Millisecond)
		fixture.node.inst.timers.processExpired()
		return nil
	})
	outcome := awaitDiscoveryOutcome(t, attempt)
	if outcome.Err != nil || len(outcome.Results) != 1 || outcome.Results[0].NetworkName != "actual-scan" ||
		outcome.Results[0].Channel != 15 || outcome.Results[0].PanID != 0x1234 ||
		outcome.Results[0].ExtAddress != [8]byte(udpPeerExt) || outcome.Results[0].RSSI != -41 || outcome.Results[0].LQI != 99 {
		t.Fatal("real response tuple/copy/terminal does not describe the actual catalogue")
	}
	packet := captureSitePacket(t, fixture.node, func(context *mesh.FrameContext) {
		if !context.SecurityEnabled {
			t.Error("ordinary home traffic lost MAC security")
		}
	})
	if !bytes.Equal(packet[8:24], source[:]) || string(packet[48:]) != "queued-home-source" {
		t.Fatal("normal source changed after scan")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		current, err := fixture.attempt.ObserveAttachment(source)
		if err != nil || current != before || driver.channel != 20 || driver.pan != 0xface ||
			driver.state != radio.StateReceive || fixture.node.inst.nativeDiscovery != nil {
			return fmt.Errorf("actual driver/home restoration did not preserve authenticated source")
		}
		return nil
	})
}

func TestThreadDiscoveryRestorationFailureRetainsOwnerUntilActualRetry(t *testing.T) {
	fixture, driver := discoverySourceFixture(t, false)
	attempt := beginSourceDiscovery(t, fixture, 1<<15)
	assertActualDiscoveryRequest(t, fixture, 15)
	cause := errors.New("home receive restore failed")
	mustSRPLoop(t, fixture.node.inst, func() error {
		driver.failChannel, driver.receiveErr = 20, cause
		return attempt.Cancel()
	})
	outcome := awaitDiscoveryOutcome(t, attempt)
	if !errors.Is(outcome.Err, cause) || !errors.Is(outcome.Err, context.Canceled) {
		t.Fatal("cancel/cleanup cause lost")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		if next, err := fixture.node.inst.BeginThreadDiscovery(ThreadDiscoveryConfig{ChannelMask: 1 << 15}); next != nil || !errors.Is(err, goterrors.ErrBusy) {
			return fmt.Errorf("terminal callback released failed-restoration ownership")
		}
		if err := attempt.RetryCleanup(); !errors.Is(err, cause) {
			return fmt.Errorf("retry lost exact cause")
		}
		driver.receiveErr = nil
		if err := attempt.RetryCleanup(); err != nil {
			return err
		}
		if driver.channel != 20 || driver.pan != 0xface || fixture.node.inst.nativeDiscovery != nil {
			return fmt.Errorf("retry did not restore/release")
		}
		select {
		case _, open := <-attempt.Result():
			if open {
				return fmt.Errorf("cleanup repeated terminal")
			}
		default:
			return fmt.Errorf("terminal not closed")
		}
		return nil
	})
}

func TestThreadDiscoveryRealFailuresStopExpiryAndHealthReachTerminalWithRestoration(t *testing.T) {
	for _, kind := range []string{"first-receive", "later-receive", "transmit", "driver-receive", "deadline", "health", "stop"} {
		t.Run(kind, func(t *testing.T) {
			fixture, driver := discoverySourceFixture(t, false)
			cause := errors.New("actual discovery backend failure")
			mustSRPLoop(t, fixture.node.inst, func() error {
				if kind == "first-receive" {
					driver.failChannel, driver.receiveErr = 11, cause
				}
				if kind == "transmit" {
					driver.txErr = cause
				}
				return nil
			})
			timeout := time.Second
			if kind == "deadline" {
				timeout = 5 * time.Millisecond
			}
			attempt := beginSourceDiscoveryTimeout(t, fixture, 1<<11|1<<12, timeout)
			if kind != "first-receive" && kind != "transmit" {
				assertActualDiscoveryRequest(t, fixture, 11)
				mustSRPLoop(t, fixture.node.inst, func() error {
					inst := fixture.node.inst
					switch kind {
					case "later-receive":
						driver.failChannel, driver.receiveErr = 12, cause
						fixture.now = fixture.now.Add(10 * time.Millisecond)
						inst.timers.processExpired()
					case "driver-receive":
						inst.subMac.HandleReceiveDone(nil, cause)
					case "deadline":
						fixture.now = fixture.now.Add(5 * time.Millisecond)
						inst.timers.processExpired()
					case "health":
						inst.entropy.(*ownedTestEntropy).latch(cause)
						fixture.now = fixture.now.Add(10 * time.Millisecond)
						inst.timers.processExpired()
					}
					return nil
				})
				if kind == "stop" {
					fixture.node.inst.Stop()
				}
			}
			outcome := awaitDiscoveryOutcome(t, attempt)
			expected := cause
			if kind == "deadline" {
				expected = context.DeadlineExceeded
			}
			if kind == "stop" {
				expected = goterrors.ErrInvalidState
			}
			if !errors.Is(outcome.Err, expected) {
				t.Fatalf("lost %s cause: %v", kind, outcome.Err)
			}
			if driver.channel != 20 || driver.pan != 0xface {
				t.Fatal("failure did not restore prior tuple")
			}
			select {
			case _, open := <-attempt.Result():
				if open {
					t.Fatal("second terminal")
				}
			default:
				t.Fatal("terminal not closed")
			}
		})
	}
}

func TestThreadDiscoveryQueuedResponseAndAcceptedLateCompletionCannotFinishNewScan(t *testing.T) {
	fixture, _ := discoverySourceFixture(t, false)
	first := beginSourceDiscovery(t, fixture, 1<<15)
	oldTX := assertActualDiscoveryRequest(t, fixture, 15)
	response := discoveryPeerFrame(t, fixture, 15, 0x1234)
	var second *ThreadDiscoveryAttempt
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		inst.subMac.HandleReceiveDone(&response, nil)
		if err := first.Cancel(); err != nil {
			return err
		}
		var err error
		second, err = inst.BeginThreadDiscovery(ThreadDiscoveryConfig{ChannelMask: 1 << 15, ChannelDuration: 10 * time.Millisecond})
		return err
	})
	if result := awaitDiscoveryOutcome(t, first); !errors.Is(result.Err, context.Canceled) {
		t.Fatal("old cancellation lost")
	}
	newTX := captureUDP(t, fixture.node.driver.boundedUDPRadio)
	if newTX.frame.TxInfo.SubmissionID == oldTX.frame.TxInfo.SubmissionID {
		t.Fatal("submission origin reused")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		inst.subMac.HandleTransmitDone(&oldTX.frame, nil, nil)
		inst.discoveryScanner.HandleTimerFor(first.id)
		if !inst.subMac.IsTransmittingOrScanning() || inst.nativeDiscovery == nil ||
			inst.nativeDiscovery.submissionID != newTX.frame.TxInfo.SubmissionID || len(inst.discoveryScanner.Results()) != 0 {
			return fmt.Errorf("old response/timer/submission touched new scan")
		}
		select {
		case <-second.Result():
			return fmt.Errorf("old callback completed new scan")
		default:
		}
		return nil
	})
	completeNativeFrame(t, fixture.node, newTX, nil)
	mustSRPLoop(t, fixture.node.inst, func() error { return second.Cancel() })
	if result := awaitDiscoveryOutcome(t, second); !errors.Is(result.Err, context.Canceled) {
		t.Fatal("new cancellation lost")
	}
}

func TestThreadDiscoveryCancellationDuringActualTXRetainsCleanupUntilCompletionAndRetry(t *testing.T) {
	fixture, driver := discoverySourceFixture(t, false)
	attempt := beginSourceDiscovery(t, fixture, 1<<15)
	inflight := captureUDP(t, fixture.node.driver.boundedUDPRadio)
	mustSRPLoop(t, fixture.node.inst, func() error { return attempt.Cancel() })
	outcome := awaitDiscoveryOutcome(t, attempt)
	if !errors.Is(outcome.Err, context.Canceled) || !errors.Is(outcome.Err, goterrors.ErrBusy) {
		t.Fatal("in-flight cancellation falsely claimed restoration")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		if next, err := fixture.node.inst.BeginThreadDiscovery(ThreadDiscoveryConfig{ChannelMask: 1 << 15}); next != nil || !errors.Is(err, goterrors.ErrBusy) {
			return fmt.Errorf("uncompleted submission released owner")
		}
		return nil
	})
	completeNativeFrame(t, fixture.node, inflight, nil)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if err := attempt.RetryCleanup(); err != nil {
			return err
		}
		if driver.channel != 20 || driver.pan != 0xface || fixture.node.inst.nativeDiscovery != nil {
			return fmt.Errorf("completion/retry did not restore")
		}
		return nil
	})
}

func TestThreadDiscoveryReceiveSleepStateAndSupportedMaskRestoration(t *testing.T) {
	fixture, driver := discoverySourceFixture(t, false)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if attempt, err := fixture.node.inst.BeginThreadDiscovery(ThreadDiscoveryConfig{ChannelMask: 1 << 3}); attempt != nil || !errors.Is(err, goterrors.ErrInvalidArgs) {
			return fmt.Errorf("unsupported actual channel mask silently changed")
		}
		fixture.node.inst.mac.SetRxOnWhenIdle(false)
		return nil
	})
	attempt := beginSourceDiscovery(t, fixture, 1<<15)
	assertActualDiscoveryRequest(t, fixture, 15)
	mustSRPLoop(t, fixture.node.inst, func() error { return attempt.Cancel() })
	if result := awaitDiscoveryOutcome(t, attempt); !errors.Is(result.Err, context.Canceled) {
		t.Fatal(result.Err)
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		if driver.state != radio.StateSleep || driver.pan != 0xface || fixture.node.inst.mac.GetRxOnWhenIdle() {
			return fmt.Errorf("prior sleep/RX-on-idle not restored")
		}
		return nil
	})
}

func TestThreadDiscoveryActualWireDuplicateUniqueAndQueuedOverflowAreExplicit(t *testing.T) {
	for _, queued := range []bool{false, true} {
		t.Run(fmt.Sprint(queued), func(t *testing.T) {
			fixture, driver := discoverySourceFixture(t, false)
			attempt := beginSourceDiscovery(t, fixture, 1<<15)
			assertActualDiscoveryRequest(t, fixture, 15)
			first := discoveryPeerFrame(t, fixture, 15, 0x1234)
			for count := 0; count < 20; count++ {
				deliverNativeFrame(t, fixture.node, udpRadioCapture{frame: first})
			}
			mustSRPLoop(t, fixture.node.inst, func() error {
				if len(fixture.node.inst.discoveryScanner.Results()) != 1 {
					return fmt.Errorf("repeated response grew catalogue")
				}
				return nil
			})
			if queued {
				second := discoveryPeerFrameFrom(t, fixture, 15, 0x1234, types.ExtAddress{2, 0, 0, 0, 0, 0, 0, 2})
				mustSRPLoop(t, fixture.node.inst, func() error {
					for count := 0; count < 3; count++ {
						fixture.node.inst.subMac.HandleReceiveDone(&second, nil)
					}
					return nil
				})
			} else {
				for index := byte(2); index <= 17; index++ {
					frame := discoveryPeerFrameFrom(t, fixture, 15, 0x1234, types.ExtAddress{2, 0, 0, 0, 0, 0, 0, index})
					deliverNativeFrame(t, fixture.node, udpRadioCapture{frame: frame})
					mustSRPLoop(t, fixture.node.inst, func() error { return nil })
				}
			}
			outcome := awaitDiscoveryOutcome(t, attempt)
			expected := 16
			if queued {
				expected = 1
			}
			if !errors.Is(outcome.Err, goterrors.ErrNoBufs) || len(outcome.Results) != expected || driver.channel != 20 || driver.pan != 0xface {
				t.Fatal("actual result/queue overflow silently truncated or failed restoration")
			}
		})
	}
}

func TestThreadDiscoveryStopDeadlineOverflowKeepRestorationFailureExplicit(t *testing.T) {
	for _, kind := range []string{"stop", "deadline", "overflow"} {
		t.Run(kind, func(t *testing.T) {
			fixture, driver := discoverySourceFixture(t, false)
			timeout := time.Second
			if kind == "deadline" {
				timeout = 5 * time.Millisecond
			}
			attempt := beginSourceDiscoveryTimeout(t, fixture, 1<<15, timeout)
			assertActualDiscoveryRequest(t, fixture, 15)
			restore := errors.New("retained actual home RX failure")
			mustSRPLoop(t, fixture.node.inst, func() error {
				driver.failChannel, driver.receiveErr = 20, restore
				if kind == "deadline" {
					fixture.now = fixture.now.Add(5 * time.Millisecond)
					fixture.node.inst.timers.processExpired()
				}
				return nil
			})
			if kind == "overflow" {
				for index := byte(1); index <= 17; index++ {
					frame := discoveryPeerFrameFrom(t, fixture, 15, 0x1234, types.ExtAddress{2, 0, 0, 0, 0, 0, 0, index})
					deliverNativeFrame(t, fixture.node, udpRadioCapture{frame: frame})
					mustSRPLoop(t, fixture.node.inst, func() error { return nil })
				}
			}
			if kind == "stop" {
				fixture.node.inst.Stop()
			}
			outcome := awaitDiscoveryOutcome(t, attempt)
			if !errors.Is(outcome.Err, restore) {
				t.Fatal("cleanup failure erased")
			}
			if kind == "deadline" && !errors.Is(outcome.Err, context.DeadlineExceeded) {
				t.Fatal("deadline cause erased")
			}
			if kind == "overflow" && !errors.Is(outcome.Err, goterrors.ErrNoBufs) {
				t.Fatal("overflow cause erased")
			}
			if kind == "stop" {
				if err := fixture.node.inst.Start(); err != nil {
					t.Fatal(err)
				}
			}
			mustSRPLoop(t, fixture.node.inst, func() error {
				if next, err := fixture.node.inst.BeginThreadDiscovery(ThreadDiscoveryConfig{ChannelMask: 1 << 15}); next != nil || !errors.Is(err, goterrors.ErrBusy) {
					return fmt.Errorf("terminal path lost failed cleanup ownership")
				}
				driver.receiveErr = nil
				if err := attempt.RetryCleanup(); err != nil {
					return err
				}
				if driver.channel != 20 || driver.pan != 0xface {
					return fmt.Errorf("retry did not restore")
				}
				return nil
			})
		})
	}
}
