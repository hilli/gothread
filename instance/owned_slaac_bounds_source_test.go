package instance

import (
	"errors"
	"fmt"
	"testing"

	csettings "github.com/hilli/gothread/common/settings"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/slaac"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/thread/netdata"
)

func TestOwnedSlaacActualParentFourPrefixLimitDoesNotConsumeFifth(t *testing.T) {
	fixture, parent, _ := publicFTDWireFixture(t, nil)
	var four, five []byte
	for i := byte(1); i <= 5; i++ {
		prefix := modelOwnedPrefix
		prefix[5] = i
		border := netdata.AppendBorderRouterEntry(nil, netdata.BorderRouterEntry{
			RLOC16: 0x0800, OnMesh: true, SLAAC: true, Preferred: true,
		})
		value := netdata.AppendPrefixValue(nil, netdata.PrefixTLVInfo{
			Prefix:      ip6.NewPrefix([16]byte(prefix), 64),
			SubTLVsData: netdata.AppendTLV(nil, netdata.TLVTypeBorderRouter, true, border),
		})
		five = netdata.AppendTLV(five, netdata.TLVTypePrefix, true, value)
		if i == 4 {
			four = append([]byte(nil), five...)
		}
	}
	sendOwnedPrefixUpdate(t, fixture, parent, four, 1, 70, true)
	var before phase2AdmissionCounters
	mustSRPLoop(t, fixture.node.inst, func() error {
		count := 0
		for _, address := range fixture.node.inst.netif.GetUnicastAddresses() {
			if address.Origin == ip6.OriginSLAAC {
				if _, err := fixture.attempt.ObserveAttachment(address.Address); err != nil {
					return err
				}
				count++
			}
		}
		if count != 4 {
			return fmt.Errorf("actual parent prefix path changed existing four-address limit")
		}
		before = phase2AdmissionSnapshot(fixture.node.inst)
		return nil
	})
	sendOwnedPrefixUpdate(t, fixture, parent, five, 2, 71, false)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if len(fixture.node.inst.slaacManager.GetAddresses()) != 4 ||
			phase2AdmissionSnapshot(fixture.node.inst) != before || len(fixture.node.driver.captures) != 0 {
			return fmt.Errorf("fifth authenticated prefix changed capacity or consumed unsafe fallback effects")
		}
		return nil
	})
}

func TestOwnedSlaacActualGeneratedCollisionDoesNotStealCallerAddress(t *testing.T) {
	fixture, parent, _ := publicFTDWireFixture(t, nil)
	var caller ip6.Address
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		value, err := fixture.store.Get(platform.SettingsKey(csettings.KeySlaacIidSecretKey), 0)
		if err != nil {
			return err
		}
		if len(value) != 32 {
			return fmt.Errorf("missing actual persisted IID secret")
		}
		var secret [32]byte
		copy(secret[:], value)
		generator := slaac.NewDefaultIIDGenerator(secret, [8]byte(inst.GetExtAddress()))
		iid, err := generator.GenerateIID([16]byte(modelOwnedPrefix), 64, 0)
		if err != nil {
			return err
		}
		caller = modelOwnedPrefix
		copy(caller[8:], iid[:])
		return inst.netif.AddExternalUnicastAddress(&ip6.UnicastAddress{
			Address: caller, PrefixLength: 64, Origin: ip6.OriginManual, Valid: true, Preferred: true,
		})
	})
	sendOwnedPrefixUpdate(t, fixture, parent, ownedPrefixWire(true), 1, 70, true)
	generated := actualOwnedSlaacAddress(t, fixture)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if generated == caller || !fixture.node.inst.netif.IsUnicastAddressExternal(caller) {
			return fmt.Errorf("generated IID collision stole the preexisting caller entry")
		}
		if _, err := fixture.attempt.ObserveAttachment(caller); err == nil {
			return fmt.Errorf("caller collision became authenticated generated provenance")
		}
		if err := fixture.node.inst.ThreadStop(); err != nil {
			return err
		}
		if !fixture.node.inst.netif.IsUnicastAddressExternal(caller) {
			return fmt.Errorf("Stop removed caller collision")
		}
		return nil
	})
}

var errOwnedSlaacIID = errors.New("owned SLAAC IID source failed")

type ownedSlaacIIDFault struct {
	reserved bool
	calls    int
}

func (generator *ownedSlaacIIDFault) GenerateIID(_ [16]byte, _, _ uint8) ([8]byte, error) {
	generator.calls++
	if generator.reserved {
		return [8]byte{}, nil
	}
	return [8]byte{}, errOwnedSlaacIID
}

func TestOwnedSlaacActualParentGenerationFailureAndReservedIIDExhaustionHaveNoFallback(t *testing.T) {
	for _, reserved := range []bool{false, true} {
		t.Run(fmt.Sprint(reserved), func(t *testing.T) {
			fixture, parent, _ := publicFTDWireFixture(t, nil)
			generator := &ownedSlaacIIDFault{reserved: reserved}
			mustSRPLoop(t, fixture.node.inst, func() error {
				// Replace only the generator of the existing actual manager.
				slaac.WithIIDGenerator(generator)(fixture.node.inst.slaacManager)
				return nil
			})
			sendOwnedPrefixUpdate(t, fixture, parent, ownedPrefixWire(true), 1, 70, true)
			mustSRPLoop(t, fixture.node.inst, func() error {
				expected := 1
				if reserved {
					expected = slaac.MaxDADCounter + 1
				}
				if generator.calls != expected || fixture.node.inst.threadEnabled || len(fixture.node.driver.captures) != 0 {
					return fmt.Errorf("actual bounded IID failure did not fail closed without random fallback")
				}
				for _, address := range fixture.node.inst.netif.GetUnicastAddresses() {
					if address.Origin == ip6.OriginSLAAC {
						return fmt.Errorf("failed IID minted a live source")
					}
				}
				return nil
			})
		})
	}
}
