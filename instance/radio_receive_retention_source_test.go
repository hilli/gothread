package instance

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/submac"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/mesh"
)

// NEW getter-only SOURCE oracles; UNPARSED/UNCOMPILED/UNRUN. This MODEL Receive
// gate mirrors reviewed Radio.Receive: all ordinary calls fail while fenced.
// The actual SDK SubMac/bridge/MAC/forwarder/loop execute the accepted callback.
type postTXReceiveModelRadio struct {
	*discoveryDSRadio
	fenced          bool
	fenceCause      error
	receiveFailures int
}

func (driver *postTXReceiveModelRadio) Receive(channel uint8) error {
	if driver.fenced {
		driver.receiveFailures++
		return driver.fenceCause
	}
	return driver.discoveryDSRadio.Receive(channel)
}

func postTXReceiveFixture(t *testing.T) (*ownedAttachFixture, *postTXReceiveModelRadio, *jointSourceSettings) {
	t.Helper()
	store := &jointSourceSettings{datasetWriteFault: &datasetWriteFault{SimSettings: simulation.NewSimSettings()}}
	var driver *postTXReceiveModelRadio
	thread := newOwnedAttachFixtureWithRadio(t, true, store, func(base *fragmentRadio) radio.Radio {
		driver = &postTXReceiveModelRadio{discoveryDSRadio: &discoveryDSRadio{
			discoveryProbeRadio: &discoveryProbeRadio{fragmentRadio: base},
		}}
		return driver
	})
	thread.node.driver.settings = nil // Capture snapshots only; real Instance settings are unchanged.
	thread, _, _ = publicFTDWireFixtureFor(t, thread, append(publicFTDPrimaryData(), ownedPrefixWire(true)...))
	return thread, driver, store
}

func acceptedPostTXOrdinary(t *testing.T, thread *ownedAttachFixture) udpRadioCapture {
	t.Helper()
	source := actualOwnedSlaacAddress(t, thread)
	mustSRPLoop(t, thread.node.inst, func() error {
		return thread.node.inst.SendUDP([]byte("actual-sent-once"), ip6.MessageInfo{
			SockAddr: source, PeerAddr: ip6.Address{0x20, 1, 0x0d, 0xb8, 0, 2, 15: 0x79},
			SockPort: 5540, PeerPort: 5540,
		})
	})
	capture := captureUDP(t, thread.node.driver.boundedUDPRadio)
	wire, _, err := mesh.NewFramer().ParseFrameHeader(capture.frame.PSDU)
	if err != nil || !wire.SecurityEnabled || capture.frame.TxInfo == nil ||
		capture.frame.TxInfo.SubmissionID == 0 {
		t.Fatal("fixture produced no actual accepted ordinary secured TX")
	}
	return capture
}

func TestSDKRadioReceiveRetentionPreservesSuccessfulTXAndSeparateOwnedCleanupCause(t *testing.T) {
	for _, kind := range []string{"fenced-busy", "hardware-fault"} {
		t.Run(kind, func(t *testing.T) {
			thread, driver, store := postTXReceiveFixture(t)
			inst := thread.node.inst
			var totalBefore, successBefore, retriesBefore, noAckBefore uint32
			var directBefore, droppedBefore uint32
			mustSRPLoop(t, inst, func() error {
				totalBefore, successBefore, retriesBefore, noAckBefore, _, _ = inst.Mac().GetCounters()
				counters := inst.Forwarder().GetCounters()
				directBefore, droppedBefore = counters.TxDirect, counters.TxDropped
				return nil
			})
			actual := acceptedPostTXOrdinary(t, thread)
			acceptedBytes := append([]byte(nil), actual.frame.PSDU...)
			acceptedCalls := 0
			receiveCause := errors.New("MODEL actual post-TX hardware RX failure")
			if kind == "fenced-busy" {
				receiveCause = goterrors.ErrBusy
			}
			mustSRPLoop(t, inst, func() error {
				// MODEL producer fence, not a purported SDK authority flag.
				driver.fenced, driver.fenceCause = true, receiveCause
				acceptedCalls = driver.txCalls
				return nil
			})
			ack, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			inst.PostRadioCallback(func() {
				inst.SubMac().HandleTransmitDone(&actual.frame, nil, nil)
				if !errors.Is(inst.RadioReceiveRestorationError(), receiveCause) ||
					driver.receiveFailures == 0 {
					t.Error("actual ordinary post-TX Receive error disappeared at the producer callback")
				}
				if inst.pendingTxMsg == nil {
					t.Error("fixture skipped the real deferred MAC packet completion")
				}
				defer func() { close(ack); <-release }()
			})
			waitRadioBridgeSource(t, ack)
			if err := inst.JoinRadioCallbacks(); !errors.Is(err, goterrors.ErrBusy) {
				t.Fatal("join used driver acknowledgement before actual outer return/maintenance")
			}
			unblock()
			joinRadioBridgeSource(t, inst)
			mustSRPLoop(t, inst, func() error {
				total, success, retries, noAck, _, _ := inst.Mac().GetCounters()
				counters := inst.Forwarder().GetCounters()
				if total != totalBefore+1 || success != successBefore+1 ||
					retries != retriesBefore || noAck != noAckBefore ||
					counters.TxDirect != directBefore+1 || counters.TxDropped != droppedBefore ||
					inst.pendingTxMsg != nil || inst.forwarder.GetBufferUsage().TxDatagrams != 0 ||
					len(driver.captures) != 0 || driver.txCalls != acceptedCalls ||
					!bytes.Equal(actual.frame.PSDU, acceptedBytes) ||
					!inst.subMac.IsCurrentTransmitCompletion(&actual.frame) {
					return fmt.Errorf("RX error changed actual successful TX outcome/retry/accounting or produced another TX")
				}
				if !errors.Is(inst.RadioReceiveRestorationError(), receiveCause) {
					return fmt.Errorf("join cleared the independently retained actual RX cause")
				}
				// Later FIRST health and persistence are genuine independent
				// class failures after successful packet accounting, not RX
				// classification or an SDK latch/source/ready setter.
				inst.entropy.(*ownedTestEntropy).source.fail = true
				var random [1]byte
				if err := inst.Entropy().Fill(random[:]); !errors.Is(err, errSRPEntropy) {
					return fmt.Errorf("actual later provider failure absent")
				}
				if !errors.Is(inst.SecurityError(), errSRPEntropy) {
					return fmt.Errorf("later security cause lost")
				}
				store.fail = platform.SettingsKeyNetworkInfo
				sequence := inst.GetCurrentKeySequence()
				inst.SetCurrentKeySequence(sequence+1, key.ForceUpdate)
				if !errors.Is(inst.PersistenceError(), errOwnedDatasetWrite) || inst.GetCurrentKeySequence() != sequence {
					return fmt.Errorf("later persistence cause absent or keys changed")
				}
				return nil
			})
			joinRadioBridgeSource(t, inst)
			stopRadioBridgeSource(t, inst)
			if !errors.Is(inst.RadioReceiveRestorationError(), receiveCause) ||
				!errors.Is(inst.SecurityError(), errSRPEntropy) ||
				!errors.Is(inst.PersistenceError(), errOwnedDatasetWrite) {
				t.Fatal("actual stopped cleanup owner lost RX/late-class cause identity")
			}
			modeCause := errors.New("MODEL separate late stopped mode restoration failure")
			// Named restoration bypasses only this MODEL ordinary fence,
			// matching Radio's separate scoped RestoreReceive command.
			restorer := &radioBridgeModelRestorer{inst: inst, driver: driver.discoveryDSRadio, modeError: modeCause}
			if err := inst.RestoreRadioQuiescent(restorer); !errors.Is(err, modeCause) {
				t.Fatal("independent late mode error was confused with RX Busy or hidden")
			}
			if inst.radioOwner.lease == nil || inst.radioOwner.restored ||
				!errors.Is(inst.RadioReceiveRestorationError(), receiveCause) {
				t.Fatal("failed mode restoration released owner or overwrote the original RX cause")
			}
			restorer.modeError = nil
			if err := inst.RestoreRadioQuiescent(restorer); err != nil {
				t.Fatalf("historical RX error made completed whole restoration permanently uncloseable: %v", err)
			}
			if inst.radioOwner.lease != nil || !inst.radioOwner.restored ||
				!errors.Is(inst.RadioReceiveRestorationError(), receiveCause) ||
				!errors.Is(inst.SecurityError(), errSRPEntropy) ||
				!errors.Is(inst.PersistenceError(), errOwnedDatasetWrite) ||
				len(driver.captures) != 0 || driver.txCalls != acceptedCalls ||
				!bytes.Equal(actual.frame.PSDU, acceptedBytes) || inst.subMac.GetState() != submac.StateReceive {
				t.Fatal("whole restoration lost independent causes, recreated networking or skipped SDK release")
			}
		})
	}
}

func TestSDKRadioReceiveRetentionLeavesLegacyAndCheckedDiscoveryOutcomesUnchanged(t *testing.T) {
	t.Run("legacy-no-opt-in", func(t *testing.T) {
		thread, driver, _ := postTXReceiveFixture(t)
		inst := thread.node.inst
		var successBefore, retriesBefore, noAckBefore, directBefore, droppedBefore uint32
		mustSRPLoop(t, inst, func() error {
			_, successBefore, retriesBefore, noAckBefore, _, _ = inst.Mac().GetCounters()
			counters := inst.Forwarder().GetCounters()
			directBefore, droppedBefore = counters.TxDirect, counters.TxDropped
			return nil
		})
		actual := acceptedPostTXOrdinary(t, thread)
		receiveCause := errors.New("MODEL legacy post-TX RX failure")
		mustSRPLoop(t, inst, func() error {
			driver.fenced, driver.fenceCause = true, receiveCause
			inst.SubMac().HandleTransmitDone(&actual.frame, nil, nil)
			return nil
		})
		mustSRPLoop(t, inst, func() error {
			_, success, retries, noAck, _, _ := inst.Mac().GetCounters()
			counters := inst.Forwarder().GetCounters()
			if driver.receiveFailures == 0 || inst.radioOwner.enabled ||
				inst.RadioReceiveRestorationError() != nil || inst.pendingTxMsg != nil ||
				inst.Forwarder().GetBufferUsage().TxDatagrams != 0 || len(driver.captures) != 0 ||
				success != successBefore+1 || retries != retriesBefore || noAck != noAckBefore ||
				counters.TxDirect != directBefore+1 || counters.TxDropped != droppedBefore {
				return fmt.Errorf("legacy ordinary outcome/reporting changed outside explicit callback opt-in")
			}
			// MODEL backend repair for ordinary fixture teardown, not a
			// clear of any SDK retained cause.
			driver.fenced = false
			return nil
		})
	})
	t.Run("discovery-checked", func(t *testing.T) {
		thread, driver, _ := postTXReceiveFixture(t)
		inst := thread.node.inst
		scan := beginSourceDiscovery(t, thread, 1<<15)
		actual := captureUDP(t, thread.node.driver.boundedUDPRadio)
		receiveCause := errors.New("MODEL checked discovery post-TX Receive failure")
		mustSRPLoop(t, inst, func() error { driver.fenced, driver.fenceCause = true, receiveCause; return nil })
		inst.PostRadioCallback(func() { inst.SubMac().HandleTransmitDone(&actual.frame, nil, nil) })
		joinRadioBridgeSource(t, inst)
		outcome := awaitDiscoveryOutcome(t, scan)
		if !errors.Is(outcome.Err, receiveCause) || inst.RadioReceiveRestorationError() != nil {
			t.Fatal("checked discovery cause was lost or reclassified as ordinary TX/RX retention")
		}
		stopRadioBridgeSource(t, inst)
		if err := inst.RestoreRadioQuiescent(&radioBridgeModelRestorer{inst: inst, driver: driver.discoveryDSRadio}); err != nil {
			t.Fatal(err)
		}
		if inst.nativeDiscovery != nil || inst.RadioReceiveRestorationError() != nil || len(driver.captures) != 0 {
			t.Fatal("checked discovery owner/result semantics changed")
		}
	})
}
