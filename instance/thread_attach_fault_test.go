package instance

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
)

func TestOwnedAttachRejectsUnauthenticatedStaleAndUnselectedResponses(t *testing.T) {
	fixture := newOwnedAttachFixture(t, true)
	parent := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
	fixture.begin(t)
	fixture.fireProtocolTimer(t)
	command, records := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if command != mle.CommandParentRequest {
		t.Fatal("missing production Parent Request")
	}
	challenge, _ := mle.FindTLV(records, mle.TLVChallenge)
	sendParentAttachMessage(t, parent, fixture, parentResponseMessage(challenge, false), 9)
	wrong := append([]byte(nil), challenge...)
	wrong[0] ^= 1
	sendParentAttachMessage(t, parent, fixture, parentResponse(wrong), 10)
	sendParentAttachMessage(t, parent, fixture, childIDResponse(0x0801), 11)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if fixture.node.inst.mleService.Mle().IsChild() {
			return fmt.Errorf("unselected/unauthenticated input became Child")
		}
		select {
		case <-fixture.attempt.Result():
			return fmt.Errorf("invalid input completed attach")
		default:
		}
		return nil
	})
	sendParentAttachMessage(t, parent, fixture, parentResponse(challenge), 20)
	fixture.fireProtocolTimer(t)
	command, _ = ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if command != mle.CommandChildIDRequest {
		t.Fatal("valid parent not selected")
	}
	sendParentAttachMessage(t, parent, fixture, childIDResponse(0x0801), 19) // Authenticated but older than the current challenge exchange.
	sendParentAttachMessage(t, parent, fixture, childIDResponse(0x0800), 21) // Router address, not assigned child.
	mustSRPLoop(t, fixture.node.inst, func() error {
		select {
		case <-fixture.attempt.Result():
			return fmt.Errorf("stale/invalid assigned RLOC completed attach")
		default:
		}
		return nil
	})
	sendParentAttachMessage(t, parent, fixture, childIDResponse(0x0801), 22)
	if result := awaitOwnedAttach(t, fixture.attempt); result.Err != nil || result.RLOC16 != 0x0801 {
		t.Fatal("only the current authenticated response should finish")
	}
}

func TestOwnedAttachLifecycleAndActualAdmissionFailure(t *testing.T) {
	for _, mode := range []string{"thread-stop", "interface-down", "instance-stop", "send-admission"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newOwnedAttachFixture(t, true)
			fixture.begin(t)
			if mode == "instance-stop" {
				fixture.node.inst.Stop()
			} else {
				mustSRPLoop(t, fixture.node.inst, func() error {
					switch mode {
					case "thread-stop":
						return fixture.node.inst.ThreadStop()
					case "interface-down":
						if err := fixture.node.inst.ThreadStop(); err != nil {
							return err
						}
						return fixture.node.inst.IfConfigDown()
					case "send-admission":
						fixture.node.inst.forwarder.SetEnabled(false)
						fixture.now = fixture.now.Add(fixture.node.inst.mleService.Attacher.NextTimerDelay)
						fixture.node.inst.timers.processExpired()
					}
					return nil
				})
			}
			result := awaitOwnedAttach(t, fixture.attempt)
			if result.Err == nil || result.Role == mle.RoleChild {
				t.Fatal("lifecycle/send failure looked connected")
			}
			if mode == "send-admission" && !errors.Is(result.Err, mesh.ErrForwarderDisabled) {
				t.Fatalf("actual send-admission cause lost: %v", result.Err)
			}
		})
	}
}

var errOwnedDatasetWrite = errors.New("dataset write failure")

type datasetWriteFault struct {
	*simulation.SimSettings
	fail   platform.SettingsKey
	commit bool
	writes int
}

func (store *datasetWriteFault) Set(key platform.SettingsKey, value []byte) error {
	store.writes++
	if key == store.fail {
		if store.commit {
			if err := store.SimSettings.Set(key, value); err != nil {
				return err
			}
		}
		return errOwnedDatasetWrite
	}
	return store.SimSettings.Set(key, value)
}

func TestOwnedDatasetValidateBeforeWriteAndAmbiguousFailureLatches(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprint(commit), func(t *testing.T) {
			store := &datasetWriteFault{SimSettings: simulation.NewSimSettings()}
			fixture := newOwnedAttachFixtureWithSettings(t, true, store)
			mustSRPLoop(t, fixture.node.inst, func() error {
				before := store.writes
				invalid := ownedDataset()
				invalid.RemoveTLV(meshcop.TLVNetworkKey)
				if err := fixture.node.inst.StageOperationalDatasets(DatasetRecord{Present: true, TLVs: invalid.Bytes()}, DatasetRecord{}); err == nil {
					return fmt.Errorf("incomplete dataset accepted")
				}
				if store.writes != before {
					return fmt.Errorf("validation failure wrote storage")
				}
				store.fail, store.commit = platform.SettingsKeyActiveDataset, commit
				valid := ownedDataset()
				if err := valid.WriteTLV(meshcop.TLVNetworkName, []byte("Changed")); err != nil {
					return err
				}
				err := fixture.node.inst.StageOperationalDatasets(DatasetRecord{Present: true, TLVs: valid.Bytes()}, DatasetRecord{})
				if !errors.Is(err, errOwnedDatasetWrite) || !errors.Is(fixture.node.inst.PersistenceError(), errOwnedDatasetWrite) {
					return fmt.Errorf("ambiguous write failure not latched: %v", err)
				}
				failedWrites := store.writes
				if err := fixture.node.inst.StageOperationalDatasets(DatasetRecord{Present: true, TLVs: ownedDataset().Bytes()}, DatasetRecord{}); !errors.Is(err, errOwnedDatasetWrite) {
					return fmt.Errorf("snapshot restore cleared failure")
				}
				if store.writes != failedWrites {
					return fmt.Errorf("latched failure retried live writes")
				}
				read, err := store.Get(platform.SettingsKeyActiveDataset, 0)
				if err != nil {
					return err
				}
				if bytes.Equal(read, valid.Bytes()) != commit {
					return fmt.Errorf("fixture ambiguous-commit path did not occur")
				}
				if len(fixture.node.driver.captures) != 0 {
					return fmt.Errorf("staging failure transmitted")
				}
				return nil
			})
		})
	}
}
