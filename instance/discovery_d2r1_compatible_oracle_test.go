package instance

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/submac"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/mesh"
)

// Existinga395 APIs/helpers only. Identical bytes accompany unchangeda395 for
// a later compile-first assertion comparison; no source is executed here.
type discoveryD2Radio struct {
	*discoveryDSRadio
	sleepCalls, failSleepCall int
	sleepCause                error
}

func (driver *discoveryD2Radio) Sleep() error {
	driver.sleepCalls++
	if driver.sleepCalls == driver.failSleepCall {
		return driver.sleepCause
	}
	return driver.discoveryDSRadio.Sleep()
}

func discoveryD2Fixture(t *testing.T, sleep bool) (*ownedAttachFixture, *discoveryD2Radio) {
	t.Helper()
	var driver *discoveryD2Radio
	fixture := newOwnedAttachFixtureWithRadio(t, true, nil, func(base *fragmentRadio) radio.Radio {
		base.caps = radio.CapNone // Actual SubMac caches software-CSMA capability at construction.
		driver = &discoveryD2Radio{discoveryDSRadio: &discoveryDSRadio{
			discoveryProbeRadio: &discoveryProbeRadio{fragmentRadio: base},
		}}
		return driver
	})
	fixture.node.driver.settings = nil
	mustSRPLoop(t, fixture.node.inst, func() error {
		fixture.node.inst.mac.SetPanID(0xface)
		fixture.node.inst.mac.SetPanChannel(20)
		if sleep {
			fixture.node.inst.mac.SetRxOnWhenIdle(false)
		}
		return nil
	})
	return fixture, driver
}

func discoveryD2FirstAccepted(t *testing.T, fixture *ownedAttachFixture) udpRadioCapture {
	t.Helper()
	mustSRPLoop(t, fixture.node.inst, func() error {
		// Initial BE3 software backoff is at most7*320us. This bounded
		// model advance remains before the actual10ms discovery dwell.
		fixture.now = fixture.now.Add(3 * time.Millisecond)
		fixture.node.inst.timers.processExpired()
		return nil
	})
	first := captureUDP(t, fixture.node.driver.boundedUDPRadio)
	wireContext, _, err := mesh.NewFramer().ParseFrameHeader(first.frame.PSDU)
	if err != nil || wireContext.SecurityEnabled || first.frame.TxInfo == nil ||
		first.frame.TxInfo.SubmissionID == 0 || first.frame.Channel != 15 {
		t.Fatal("D2R1 fixture did not produce actual first accepted discovery submission N")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		if !inst.subMac.IsTransmittingOrScanning() || inst.nativeDiscovery == nil ||
			inst.nativeDiscovery.submissionID != first.frame.TxInfo.SubmissionID ||
			inst.subMac.GetTransmitFrame().TxInfo.SubmissionID != 0 {
			return fmt.Errorf("D2R1 accepted origin was not distinct from mutable staging")
		}
		return nil
	})
	return first
}

func TestDiscoveryD2R1SoftwareRetryPreparationKeepsActualAcceptedIdentity(t *testing.T) {
	for _, kind := range []string{"receive", "sleep", "receive-and-restore", "retry-begin-receive", "retry-validator"} {
		t.Run(kind, func(t *testing.T) {
			sleep := kind == "sleep"
			fixture, driver := discoveryD2Fixture(t, sleep)
			attempt := beginSourceDiscovery(t, fixture, 1<<15)
			first := discoveryD2FirstAccepted(t, fixture)
			cause, restore := errors.New("D2R1 actual retry preparation failed"), errors.New("D2R1 actual home restore failed")
			mustSRPLoop(t, fixture.node.inst, func() error {
				if sleep {
					driver.failSleepCall, driver.sleepCause = driver.sleepCalls+1, cause
				} else if kind != "retry-validator" {
					driver.failReceiveCall, driver.receiveCause = driver.receiveCalls+1, cause
					if kind == "retry-begin-receive" {
						driver.failReceiveCall++
					}
				}
				if kind == "receive-and-restore" {
					driver.failChannel, driver.receiveErr = 20, restore
				}
				return nil
			})
			// Complete the ACTUAL accepted N with channel-access failure.
			// The production software-CSMA retry then calls the faulting
			// Receive/Sleep before any second Radio.Transmit.
			if kind == "retry-validator" {
				mustSRPLoop(t, fixture.node.inst, func() error {
					fixture.node.inst.subMac.HandleTransmitDone(&first.frame, nil, submac.ErrChannelAccessFailure)
					fixture.node.inst.entropy.(*ownedTestEntropy).latch(cause)
					return nil
				})
			} else {
				completeNativeFrame(t, fixture.node, first, submac.ErrChannelAccessFailure)
			}
			mustSRPLoop(t, fixture.node.inst, func() error {
				// Retry BE4 is at most15*320us. Total model time is8ms,
				// still before the actual10ms discovery dwell.
				fixture.now = fixture.now.Add(5 * time.Millisecond)
				fixture.node.inst.timers.processExpired()
				return nil
			})
			// A separate normal loop turn permits the actual deferred upper
			// completion to run; it does not mutate or waive its ID check.
			mustSRPLoop(t, fixture.node.inst, func() error {
				inst := fixture.node.inst
				if inst.subMac.IsTransmittingOrScanning() {
					return fmt.Errorf("D2R1 retry preparation did not reach actual SubMac quiescence")
				}
				if inst.nativeDiscovery != nil && inst.nativeDiscovery.transmitting {
					return fmt.Errorf("D2R1 quiescent SubMac retained false in-flight owner after accepted retry preparation failure")
				}
				if !inst.subMac.IsCurrentTransmitCompletion(&first.frame) ||
					inst.subMac.GetTransmitFrame().TxInfo.SubmissionID != 0 {
					return fmt.Errorf("D2R1 actual accepted completion lost or staging was stamped")
				}
				return nil
			})
			// OLD must fail the literal false-inflight assertion above,
			// never a missing method, panic, timeout or hung worker.
			result := awaitDiscoveryOutcome(t, attempt)
			if !errors.Is(result.Err, cause) || driver.txCalls != 1 || len(driver.captures) != 0 {
				t.Fatal("D2R1 exact preparation cause was lost or a second actual TX occurred")
			}
			mustSRPLoop(t, fixture.node.inst, func() error {
				inst := fixture.node.inst
				if kind == "receive-and-restore" {
					if !errors.Is(result.Err, restore) || inst.nativeDiscovery == nil {
						return fmt.Errorf("D2R1 actual independent restore cause/retained owner lost")
					}
					driver.receiveErr = nil
					if err := attempt.RetryCleanup(); err != nil {
						return err
					}
				}
				expectedState := radio.StateReceive
				if sleep {
					expectedState = radio.StateSleep
				}
				if inst.nativeDiscovery != nil || inst.discoveryScanner.IsScanning() ||
					(!sleep && driver.channel != 20) || driver.pan != 0xface || driver.state != expectedState ||
					inst.mac.GetPanChannelSnapshot() != 20 {
					return fmt.Errorf("D2R1 truthful checked home restoration did not release lease")
				}
				// Actual scheduler-lease admission proves no permanent Busy,
				// without submitting an unrelated extra discovery packet.
				lease, err := inst.mac.AcquireDiscoveryRadio()
				if err != nil {
					return fmt.Errorf("D2R1 quiescent restored owner remained Busy: %w", err)
				}
				if err := lease.Restore(); err != nil {
					return err
				}
				select {
				case _, open := <-attempt.Result():
					if open {
						return fmt.Errorf("D2R1 repeated terminal")
					}
				default:
					return fmt.Errorf("D2R1 terminal not closed")
				}
				return nil
			})
		})
	}
}

func TestDiscoveryD2R1GenuineAcceptedInFlightRemainsBusyUntilActualCompletion(t *testing.T) {
	fixture, driver := discoveryD2Fixture(t, false)
	attempt := beginSourceDiscovery(t, fixture, 1<<15)
	first := discoveryD2FirstAccepted(t, fixture)
	mustSRPLoop(t, fixture.node.inst, func() error { return attempt.Cancel() })
	result := awaitDiscoveryOutcome(t, attempt)
	if !errors.Is(result.Err, context.Canceled) || !errors.Is(result.Err, goterrors.ErrBusy) {
		t.Fatal("D2R1 genuine still-in-flight cancellation falsely claimed cleanup")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		if !inst.subMac.IsTransmittingOrScanning() || inst.nativeDiscovery == nil ||
			inst.nativeDiscovery.submissionID != first.frame.TxInfo.SubmissionID {
			return fmt.Errorf("D2R1 genuine actual accepted operation was fabricated quiescent")
		}
		if err := attempt.RetryCleanup(); !errors.Is(err, goterrors.ErrBusy) {
			return fmt.Errorf("D2R1 genuine operation released before completion: %v", err)
		}
		return nil
	})
	completeNativeFrame(t, fixture.node, first, nil)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if err := attempt.RetryCleanup(); err != nil {
			return err
		}
		if fixture.node.inst.nativeDiscovery != nil || driver.channel != 20 || driver.pan != 0xface {
			return fmt.Errorf("D2R1 genuine completion did not permit checked cleanup")
		}
		return nil
	})
}
