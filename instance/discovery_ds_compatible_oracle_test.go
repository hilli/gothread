package instance

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/lowpan"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
)

// APIs/helpers already present in frozenad918. Identical bytes can accompany
// unchangedad918 for later compile-first assertions; none have been run here.
type discoveryDSRadio struct {
	*discoveryProbeRadio
	receiveCalls, failReceiveCall int
	receiveCause                  error
	txCalls                       int
	receiveHook                   func()
}

func (driver *discoveryDSRadio) Receive(channel uint8) error {
	driver.receiveCalls++
	if driver.receiveHook != nil {
		driver.receiveHook()
	}
	if driver.receiveCalls == driver.failReceiveCall {
		return driver.receiveCause
	}
	return driver.discoveryProbeRadio.Receive(channel)
}
func (driver *discoveryDSRadio) Transmit(frame *radio.Frame) error {
	driver.txCalls++
	return driver.discoveryProbeRadio.Transmit(frame)
}

func discoveryDSFixture(t *testing.T, settings platform.Settings, attached bool) (*ownedAttachFixture, *discoveryDSRadio) {
	t.Helper()
	var driver *discoveryDSRadio
	fixture := newOwnedAttachFixtureWithRadio(t, true, settings, func(base *fragmentRadio) radio.Radio {
		driver = &discoveryDSRadio{discoveryProbeRadio: &discoveryProbeRadio{fragmentRadio: base}}
		return driver
	})
	fixture.node.driver.settings = nil
	if attached {
		fixture, _, _ = publicFTDWireFixtureFor(t, fixture, ownedPrefixWire(true))
	} else {
		mustSRPLoop(t, fixture.node.inst, func() error {
			fixture.node.inst.mac.SetPanID(0xface)
			fixture.node.inst.mac.SetPanChannel(20)
			return nil
		})
	}
	return fixture, driver
}

func TestDiscoveryDS1OldChannelResponseCannotAbortCurrentNativeChannel(t *testing.T) {
	fixture, driver := discoveryDSFixture(t, nil, true)
	attempt := beginSourceDiscovery(t, fixture, 1<<15|1<<16)
	assertActualDiscoveryRequest(t, fixture, 15)
	old := discoveryPeerFrame(t, fixture, 15, 0x1234)
	mustSRPLoop(t, fixture.node.inst, func() error {
		fixture.now = fixture.now.Add(10 * time.Millisecond)
		fixture.node.inst.timers.processExpired()
		return nil
	})
	assertActualDiscoveryRequest(t, fixture, 16)
	deliverNativeFrame(t, fixture.node, udpRadioCapture{frame: old})
	mustSRPLoop(t, fixture.node.inst, func() error {
		if !fixture.node.inst.discoveryScanner.IsScanning() || fixture.node.inst.discoveryScanner.CurrentChannel() != 16 {
			return fmt.Errorf("DS1 late actual channel15 DiscoveryResponse aborted current channel16")
		}
		select {
		case <-attempt.Result():
			return fmt.Errorf("DS1 wrong-channel fallback emitted terminal")
		default:
		}
		return nil
	})
	current := discoveryPeerFrame(t, fixture, 16, 0x1234)
	deliverNativeFrame(t, fixture.node, udpRadioCapture{frame: current})
	mustSRPLoop(t, fixture.node.inst, func() error {
		fixture.now = fixture.now.Add(10 * time.Millisecond)
		fixture.node.inst.timers.processExpired()
		return nil
	})
	result := awaitDiscoveryOutcome(t, attempt)
	if result.Err != nil || len(result.Results) != 1 || result.Results[0].Channel != 16 ||
		driver.channel != 20 || driver.pan != 0xface {
		t.Fatal("DS1 genuine current-channel discovery or exact home restoration failed")
	}
}

func TestDiscoveryDS2ActualPreparationReceiveCauseSurvivesLaterSuccess(t *testing.T) {
	for _, withRestoreFailure := range []bool{false, true} {
		t.Run(fmt.Sprint(withRestoreFailure), func(t *testing.T) {
			fixture, driver := discoveryDSFixture(t, nil, false)
			cause, restore := errors.New("DS2 actual preparation Receive failed"), errors.New("DS2 home restore failed")
			mustSRPLoop(t, fixture.node.inst, func() error {
				// Call1 is successful acquisition RX; call2 is PRE-TX RX.
				// Post-TX RX succeeds. Home restore is an independent fault.
				driver.receiveCalls, driver.txCalls = 0, 0
				driver.failReceiveCall, driver.receiveCause = 2, cause
				if withRestoreFailure {
					driver.failChannel, driver.receiveErr = 20, restore
				}
				return nil
			})
			attempt := beginSourceDiscovery(t, fixture, 1<<15)
			// Complete any incorrectly submitted OLD frame, reaching a literal
			// outcome assertion instead of a timeout or hung worker.
			select {
			case capture := <-driver.captures:
				completeNativeFrame(t, fixture.node, capture, nil)
			default:
			}
			mustSRPLoop(t, fixture.node.inst, func() error {
				fixture.now = fixture.now.Add(10 * time.Millisecond)
				fixture.node.inst.timers.processExpired()
				return nil
			})
			result := awaitDiscoveryOutcome(t, attempt)
			if !errors.Is(result.Err, cause) {
				t.Fatalf("DS2 PRE-TX Receive cause ignored despite later successful RX: %v", result.Err)
			}
			if driver.txCalls != 0 || driver.receiveCalls < 3 {
				t.Fatal("DS2 preparation failure submitted TX")
			}
			mustSRPLoop(t, fixture.node.inst, func() error {
				if withRestoreFailure {
					if !errors.Is(result.Err, restore) || fixture.node.inst.nativeDiscovery == nil {
						return fmt.Errorf("DS2 restore cause/retained owner lost")
					}
					driver.receiveErr = nil
					if err := attempt.RetryCleanup(); err != nil {
						return err
					}
				}
				if driver.channel != 20 || driver.pan != 0xface {
					return fmt.Errorf("DS2 actual home state not restored")
				}
				return nil
			})
		})
	}
}

func TestDiscoveryDS2ImmediateActualTransmitCauseIsNotChannelAccessReplacement(t *testing.T) {
	fixture, driver := discoveryDSFixture(t, nil, false)
	cause := errors.New("DS2 immediate actual Transmit sentinel")
	mustSRPLoop(t, fixture.node.inst, func() error { driver.txErr = cause; driver.txCalls = 0; return nil })
	attempt := beginSourceDiscovery(t, fixture, 1<<15)
	result := awaitDiscoveryOutcome(t, attempt)
	if !errors.Is(result.Err, cause) {
		t.Fatalf("DS2 actual immediate Transmit error replaced its original cause: %v", result.Err)
	}
	if driver.txCalls != 1 || driver.channel != 20 || driver.pan != 0xface || len(driver.captures) != 0 {
		t.Fatal("DS2 immediate rejection was not one real attempt with exact home cleanup")
	}
}

func TestDiscoveryDS1LegacyMetadataFreeHookCannotAbortBoundNativeScan(t *testing.T) {
	fixture, _ := discoveryDSFixture(t, nil, true)
	attempt := beginSourceDiscovery(t, fixture, 1<<15)
	assertActualDiscoveryRequest(t, fixture, 15)
	frame := discoveryPeerFrame(t, fixture, 15, 0x1234)
	context, offset, err := mesh.NewFramer().ParseFrameHeader(frame.PSDU)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := lowpan.DecompressDatagram(frame.PSDU[offset:], lowpan.AddressContext{
		SrcExtAddr: context.SrcExtAddr, DstExtAddr: context.DstExtAddr,
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	message, err := mle.ParseMessage(packet[48:])
	if err != nil {
		t.Fatal(err)
	}
	records, err := mle.ParseTLVs(message.Payload[1:])
	if err != nil {
		t.Fatal(err)
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		if err := inst.mleService.DiscoveryHandler.HandleDiscoveryResponse(&mle.RxInfo{
			SrcAddr: udpPeerExt, Command: mle.CommandDiscoveryResponse, TLVs: records,
		}); err != nil {
			return err
		}
		if !inst.discoveryScanner.IsScanning() || len(inst.discoveryScanner.Results()) != 0 {
			return fmt.Errorf("DS1 metadata-free legacy hook aborted or authorized typed native delivery")
		}
		return nil
	})
	// Only the actual native tuple path may admit the same encoded response.
	deliverNativeFrame(t, fixture.node, udpRadioCapture{frame: frame})
	mustSRPLoop(t, fixture.node.inst, func() error {
		fixture.now = fixture.now.Add(10 * time.Millisecond)
		fixture.node.inst.timers.processExpired()
		return nil
	})
	result := awaitDiscoveryOutcome(t, attempt)
	if result.Err != nil || len(result.Results) != 1 {
		t.Fatal("DS1 native qualified response was blanket-refused")
	}
}
