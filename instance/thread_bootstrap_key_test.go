package instance

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/mle"
)

func TestOwnedBootstrapAuthenticatesFarSequenceBeforePersisting(t *testing.T) {
	fixture := newOwnedAttachFixture(t, true)
	parent := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
	const far uint32 = 0x1234
	mustSRPLoop(t, parent.inst, func() error {
		parent.inst.SetCurrentKeySequence(far, key.ForceUpdate|key.ResetGuardTimer)
		return parent.inst.PersistenceError()
	})
	fixture.begin(t)
	fixture.fireProtocolTimer(t)
	_, records := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	challenge, _ := mle.FindTLV(records, mle.TLVChallenge)
	before, err := fixture.store.Get(platform.SettingsKeyNetworkInfo, 0)
	if err != nil {
		t.Fatal(err)
	}
	wrong := append([]byte(nil), challenge...)
	wrong[0] ^= 1
	sendParentAttachMessage(t, parent, fixture, parentResponse(wrong), 40)
	sendParentAttachMessageWithMutation(t, parent, fixture, parentResponse(challenge), 41, func(wire []byte) {
		binary.BigEndian.PutUint32(wire[6:10], 0x5678)
		wire[10] = mle.KeyIndexFromSequence(0x5678) // Coherent forged header, invalid MIC.
	})
	sendParentAttachMessageWithMutation(t, parent, fixture, parentResponse(challenge), 42, func(wire []byte) {
		wire[10] ^= 1 // Index alone is never permission to derive/adopt a full sequence.
	})
	after, _ := fixture.store.Get(platform.SettingsKeyNetworkInfo, 0)
	if !bytes.Equal(before, after) {
		t.Fatal("unmatched or unauthenticated candidate persisted identity/counters")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		if fixture.node.inst.keyManager.GetCurrentKeySequence() != 0 || fixture.node.inst.mleService.Mle().IsChild() {
			return fmt.Errorf("forged/unmatched candidate changed protocol state")
		}
		return nil
	})
	sendParentAttachMessage(t, parent, fixture, parentResponse(challenge), 43)
	adopted, _ := fixture.store.Get(platform.SettingsKeyNetworkInfo, 0)
	if binary.BigEndian.Uint32(adopted[33:37]) != far ||
		binary.BigEndian.Uint32(adopted[37:41]) < binary.BigEndian.Uint32(before[37:41]) ||
		binary.BigEndian.Uint32(adopted[41:45]) < binary.BigEndian.Uint32(before[41:45]) {
		t.Fatal("legitimate authenticated adoption did not preserve durable reservation high-waters")
	}
	fixture.fireProtocolTimer(t)
	command, _ := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if command != mle.CommandChildIDRequest {
		t.Fatal("adopted identity did not produce actual Child ID Request")
	}
	sendParentAttachMessage(t, parent, fixture, childIDResponse(0x0801), 44)
	result := awaitOwnedAttach(t, fixture.attempt)
	if result.Err != nil || result.KeySequence != far {
		t.Fatalf("far-sequence authenticated bootstrap failed: %v", result.Err)
	}
}

func TestOwnedBootstrapAdoptionWriteFailureIsClosed(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprint(commit), func(t *testing.T) {
			store := &datasetWriteFault{SimSettings: simulation.NewSimSettings()}
			fixture := newOwnedAttachFixtureWithSettings(t, true, store)
			parent := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
			mustSRPLoop(t, parent.inst, func() error {
				parent.inst.SetCurrentKeySequence(0x1234, key.ForceUpdate)
				return parent.inst.PersistenceError()
			})
			fixture.begin(t)
			fixture.fireProtocolTimer(t)
			_, records := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
			challenge, _ := mle.FindTLV(records, mle.TLVChallenge)
			before, err := store.Get(platform.SettingsKeyNetworkInfo, 0)
			if err != nil {
				t.Fatal(err)
			}
			mustSRPLoop(t, fixture.node.inst, func() error {
				store.fail, store.commit = platform.SettingsKeyNetworkInfo, commit
				return nil
			})
			sendParentAttachMessage(t, parent, fixture, parentResponse(challenge), 50)
			result := awaitOwnedAttach(t, fixture.attempt)
			if !errors.Is(result.Err, errOwnedDatasetWrite) || !errors.Is(fixture.node.inst.PersistenceError(), errOwnedDatasetWrite) {
				t.Fatal("legitimate adoption store failure did not retain original latch/cause")
			}
			after, _ := store.Get(platform.SettingsKeyNetworkInfo, 0)
			if binary.BigEndian.Uint32(after[37:41]) < binary.BigEndian.Uint32(before[37:41]) ||
				binary.BigEndian.Uint32(after[41:45]) < binary.BigEndian.Uint32(before[41:45]) ||
				len(fixture.node.driver.captures) != 0 {
				t.Fatal("failed adoption rewound bounds or emitted Child ID TX")
			}
		})
	}
}
