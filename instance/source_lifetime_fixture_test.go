package instance

import (
	"fmt"
	"testing"

	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/thread/netdata"
)

// NEW lifetime API source oracles only: not installed on old5aee and not a
// missing-method/compile-error behavioral proof.
func lifetimePrefixData(index byte, preferred bool) []byte {
	prefix := modelOwnedPrefix
	prefix[5] = index
	border := netdata.AppendBorderRouterEntry(nil, netdata.BorderRouterEntry{
		RLOC16: 0x0800, OnMesh: true, SLAAC: true, Preferred: preferred,
	})
	value := netdata.AppendPrefixValue(nil, netdata.PrefixTLVInfo{
		Prefix:      ip6.NewPrefix([16]byte(prefix), 64),
		SubTLVsData: netdata.AppendTLV(nil, netdata.TLVTypeBorderRouter, true, border),
	})
	return netdata.AppendTLV(nil, netdata.TLVTypePrefix, true, value)
}

func lifetimePublicFixture(t *testing.T, stores ...platform.Settings) (*ownedAttachFixture, *fragmentEndpoint, ip6.Address, ThreadSourceLifetime) {
	t.Helper()
	fixture, parent, _ := publicFTDWireFixture(t, lifetimePrefixData(1, true), stores...)
	source := actualOwnedSlaacAddress(t, fixture)
	var lease ThreadSourceLifetime
	mustSRPLoop(t, fixture.node.inst, func() error {
		var err error
		lease, err = fixture.attempt.AcquireSourceLifetime(source)
		return err
	})
	return fixture, parent, source, lease
}

func observeLifetime(t *testing.T, fixture *ownedAttachFixture, lease ThreadSourceLifetime) ThreadSourceDisposition {
	t.Helper()
	var result ThreadSourceDisposition
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		before := phase2AdmissionSnapshot(inst)
		records := inst.sourceLifetimes
		failure, fence := inst.securityFailure.Load(), inst.securityFenceRequested.Load()
		var err error
		result, err = fixture.attempt.ObserveSourceLifetime(lease)
		if err != nil {
			return err
		}
		if records != inst.sourceLifetimes || before != phase2AdmissionSnapshot(inst) ||
			inst.securityFailure.Load() != failure || inst.securityFenceRequested.Load() != fence {
			return fmt.Errorf("lifetime observation changed record/counter/entropy/health fence")
		}
		return nil
	})
	return result
}
