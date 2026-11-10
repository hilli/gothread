package instance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
)

func ownedCIDPending(t *testing.T) (*ownedAttachFixture, *fragmentEndpoint) {
	t.Helper()
	fixture := newOwnedAttachFixture(t, true)
	parent := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
	fixture.begin(t)
	fixture.fireProtocolTimer(t)
	_, records := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	challenge, _ := mle.FindTLV(records, mle.TLVChallenge)
	sendParentAttachMessage(t, parent, fixture, parentResponse(challenge), 60)
	fixture.fireProtocolTimer(t)
	command, _ := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if command != mle.CommandChildIDRequest {
		t.Fatal("no real outstanding Child ID exchange")
	}
	return fixture, parent
}

func largeBootstrapNetworkData() []byte {
	// A structurally bounded Thread Network Data CommissioningData container.
	return append([]byte{8, 200}, make([]byte, 200)...)
}

func deliverAttachCaptures(t *testing.T, fixture *ownedAttachFixture, captures []udpRadioCapture) {
	t.Helper()
	for _, capture := range captures {
		deliverNativeFrame(t, fixture.node, capture)
	}
	mustSRPLoop(t, fixture.node.inst, func() error { return nil })
}

func TestOwnedCIDQuarantineActualUnsecuredFragmentsAndOrder(t *testing.T) {
	fixture, parent := ownedCIDPending(t)
	data := largeBootstrapNetworkData()
	captures := captureParentAttachMessage(t, parent, fixture, childIDResponseWithNetworkData(0x0801, data), 61, nil)
	if len(captures) < 2 {
		t.Fatal("fixture did not exercise real MAC-unsecured fragmentation")
	}
	deliverAttachCaptures(t, fixture, captures[1:2]) // FRAGN before any owned FRAG1: no tuple/header yet.
	mustSRPLoop(t, fixture.node.inst, func() error {
		select {
		case <-fixture.attempt.Result():
			return fmt.Errorf("unowned FRAGN completed attach")
		default:
		}
		return nil
	})
	deliverAttachCaptures(t, fixture, captures[:1])
	deliverAttachCaptures(t, fixture, captures[:1]) // Exact duplicate is harmless.
	deliverAttachCaptures(t, fixture, captures[1:])
	result := awaitOwnedAttach(t, fixture.attempt)
	if result.Err != nil || result.Role != mle.RoleChild || !bytes.Equal(result.NetworkData, data) {
		t.Fatal("only complete inner-authenticated CID should publish received Network Data/Child")
	}
}

func TestOwnedCIDQuarantineCorruptMICRetiresWithoutProgress(t *testing.T) {
	fixture, parent := ownedCIDPending(t)
	data := largeBootstrapNetworkData()
	bad := captureParentAttachMessage(t, parent, fixture, childIDResponseWithNetworkData(0x0801, data), 61, func(wire []byte) {
		wire[len(wire)-1] ^= 1 // UDP checksum is subsequently generated correctly over corrupted MLE.
	})
	deliverAttachCaptures(t, fixture, bad)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if fixture.node.inst.mleService.Mle().IsChild() || fixture.node.inst.initialMLEFragment != nil {
			return fmt.Errorf("bad inner MIC progressed/retained candidate")
		}
		select {
		case <-fixture.attempt.Result():
			return fmt.Errorf("bad MIC completed attach")
		default:
		}
		return nil
	})
	good := captureParentAttachMessage(t, parent, fixture, childIDResponseWithNetworkData(0x0801, data), 62, nil)
	deliverAttachCaptures(t, fixture, good)
	if result := awaitOwnedAttach(t, fixture.attempt); result.Err != nil {
		t.Fatal(result.Err)
	}
}

func TestOwnedCIDQuarantineCancelFencesRemainingFrames(t *testing.T) {
	fixture, parent := ownedCIDPending(t)
	captures := captureParentAttachMessage(t, parent, fixture, childIDResponseWithNetworkData(0x0801, largeBootstrapNetworkData()), 61, nil)
	deliverAttachCaptures(t, fixture, captures[:1])
	mustSRPLoop(t, fixture.node.inst, fixture.attempt.Cancel)
	if result := awaitOwnedAttach(t, fixture.attempt); !errors.Is(result.Err, context.Canceled) {
		t.Fatal("cancel cause lost")
	}
	deliverAttachCaptures(t, fixture, captures[1:])
	mustSRPLoop(t, fixture.node.inst, func() error {
		if fixture.node.inst.mleService.Mle().IsChild() || fixture.node.inst.initialMLEFragment != nil {
			return fmt.Errorf("stopped fragments revived Child/context")
		}
		return nil
	})
}

func TestOwnedCIDQuarantineSharesExistingPoolPressure(t *testing.T) {
	fixture, parent := ownedCIDPending(t)
	var keys []mesh.FragmentKey
	mustSRPLoop(t, fixture.node.inst, func() error {
		for i := byte(1); i <= 2; i++ {
			k := mesh.FragmentKey{Scope: mesh.FragmentScope{
				Source: [8]byte{0x20, i}, Destination: [8]byte{0x22, 9}, PanID: 0xface, Channel: 20, Secured: true,
			}, Tag: uint16(i), Size: 1280}
			if _, err := fixture.node.inst.forwarder.HandleScopedFragment(k, 0, make([]byte, 48)); err != nil {
				return err
			}
			keys = append(keys, k)
		}
		return nil
	})
	captures := captureParentAttachMessage(t, parent, fixture, childIDResponseWithNetworkData(0x0801, largeBootstrapNetworkData()), 61, nil)
	deliverAttachCaptures(t, fixture, captures)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if fixture.node.inst.initialMLEFragment != nil || fixture.node.inst.mleService.Mle().IsChild() {
			return fmt.Errorf("pressure bypassed shared pool or progressed")
		}
		for _, k := range keys {
			fixture.node.inst.forwarder.RejectFragment(k)
		}
		return nil
	})
	retry := captureParentAttachMessage(t, parent, fixture, childIDResponseWithNetworkData(0x0801, largeBootstrapNetworkData()), 62, nil)
	deliverAttachCaptures(t, fixture, retry)
	if result := awaitOwnedAttach(t, fixture.attempt); result.Err != nil {
		t.Fatal(result.Err)
	}
}
