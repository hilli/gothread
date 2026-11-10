package instance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/netdata"
)

// Only existing DFF APIs/helpers are used, so identical oracle bytes can be
// compiled on the old public-NoCap tree before a later old/candidate comparison.
func publicFTDWireFixture(t *testing.T, data []byte, stores ...platform.Settings) (fixture *ownedAttachFixture, parent *fragmentEndpoint, result ThreadAttachResult) {
	t.Helper()
	if len(stores) == 0 {
		fixture = newOwnedAttachFixture(t, true)
	} else {
		if len(stores) != 1 {
			t.Fatal("one explicit Settings backend required")
		}
		fixture = newOwnedAttachFixtureWithSettings(t, true, stores[0])
	}
	return publicFTDWireFixtureFor(t, fixture, data)
}

func publicFTDWireFixtureFor(t *testing.T, fixture *ownedAttachFixture, data []byte) (*ownedAttachFixture, *fragmentEndpoint, ThreadAttachResult) {
	t.Helper()
	var result ThreadAttachResult
	parent := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		before := inst.entropy.(*ownedTestEntropy).source.calls
		var err error
		fixture.attempt, err = inst.BeginThreadAttachWithConfig(ThreadAttachConfig{
			Timeout: 30 * time.Second, Profile: ThreadAttachAwakeFTDChild,
		})
		if err != nil {
			return fmt.Errorf("explicit public FTD-child entry rejected: %w", err)
		}
		if fixture.attempt == nil || inst.entropy.(*ownedTestEntropy).source.calls <= before ||
			inst.mleService.Mle().Role() != mle.RoleDetached || inst.mleService.Mle().IsRouterEligible() {
			return fmt.Errorf("public admission skipped checked nonce or fabricated attached/eligible role")
		}
		select {
		case <-fixture.attempt.Result():
			return fmt.Errorf("public Begin completed before any authenticated parent wire")
		default:
		}
		fixture.node.macKey = inst.keyManager.GetCurrentMacKey()
		return nil
	})
	fixture.fireProtocolTimer(t)
	command, records := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if command != mle.CommandParentRequest {
		t.Fatal("public FTD entry produced no actual Parent Request")
	}
	rawMode, _ := mle.FindTLV(records, mle.TLVMode)
	mode, err := mle.ReadModeTLV(rawMode)
	challenge, hasChallenge := mle.FindTLV(records, mle.TLVChallenge)
	if err != nil || !mode.IsRxOnWhenIdle() || !mode.IsFullThreadDevice() || !mode.IsFullNetworkData() ||
		!hasChallenge || len(challenge) != 8 || bytes.Equal(challenge, make([]byte, 8)) {
		t.Fatal("public Parent Request lost actual awake/full-data mode or checked challenge")
	}
	sendParentAttachMessage(t, parent, fixture, parentResponse(challenge), 60)
	fixture.fireProtocolTimer(t)
	command, records = ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if command != mle.CommandChildIDRequest {
		t.Fatal("public selected parent did not produce actual CID Request")
	}
	if _, exists := mle.FindTLV(records, mle.TLVAddressRegistration); exists {
		t.Fatal("public FTD child used MTD address registration")
	}
	rawMode, _ = mle.FindTLV(records, mle.TLVMode)
	mode, err = mle.ReadModeTLV(rawMode)
	if err != nil || !mode.IsFullThreadDevice() || !mode.IsFullNetworkData() {
		t.Fatal("public CID Request lost its full-data child mode")
	}
	var mask mle.RouterIDSet
	mask.Add(2)
	mask.Add(3)
	response := childIDResponseWithNetworkData(0x0801, data)
	response.AppendRoute64TLV(1, mask, []mle.Route64Entry{{Cost: 0}, {Cost: 1}})
	sendParentAttachMessage(t, parent, fixture, response, 61)
	result = awaitOwnedAttach(t, fixture.attempt)
	if result.Err != nil || result.Profile != ThreadAttachAwakeFTDChild || result.Role != mle.RoleChild ||
		result.RLOC16 != 0x0801 || result.ParentRLOC16 != 0x0800 || result.ParentExtAddress != udpPeerExt ||
		!bytes.Equal(result.NetworkData, data) {
		t.Fatal("public result was not the actual authenticated full-data child observation")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		if inst.mleService.Mle().IsRouterEligible() || !inst.mleService.Mle().IsChild() ||
			inst.SecurityError() != nil || inst.PersistenceError() != nil ||
			!inst.netif.HasUnicastAddress(fixture.eid) || !inst.hasOwnedRLOCAddress() {
			return fmt.Errorf("public attachment lacks actual owned EID/RLOC or changed eligibility")
		}
		return nil
	})
	if _, open := <-fixture.attempt.Result(); open {
		t.Fatal("public attempt emitted more than one terminal result")
	}
	return fixture, parent, result
}

func publicFTDPrimaryData() []byte {
	server := netdata.AppendServerValue(nil, netdata.ServerEntry{
		Server16: 0x0800, ServerData: []byte{7, 0, 5, 0, 0, 1, 0x2c},
	})
	sub := netdata.AppendTLV(nil, netdata.TLVTypeServer, true, server)
	service := netdata.AppendServiceValue(nil, netdata.ServiceTLVInfo{
		ServiceID: 4, EnterpriseNumber: netdata.ThreadEnterpriseNumber, ServiceData: []byte{1}, SubTLVsData: sub,
	})
	return netdata.AppendTLV(nil, netdata.TLVTypeService, true, service)
}

func TestPublicFTDChildActualAttachIsNotMembershipOrReturnPathReadiness(t *testing.T) {
	fixture, _, result := publicFTDWireFixture(t, nil)
	if len(result.Addresses) < 2 {
		t.Fatal("public result omitted the real caller EID or assigned RLOC")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		handle, err := fixture.node.inst.JoinMulticast(siteTestAddress(1))
		if handle != nil || !errors.Is(err, goterrors.ErrNotFound) {
			return fmt.Errorf("Child result fabricated a qualified Primary or membership: %v", err)
		}
		return nil
	})
}

func TestPublicDefaultBeginStillUsesMTDWireAndCancel(t *testing.T) {
	fixture := newOwnedAttachFixture(t, true)
	mustSRPLoop(t, fixture.node.inst, func() error {
		var err error
		fixture.attempt, err = fixture.node.inst.BeginThreadAttach(30 * time.Second)
		return err
	})
	fixture.fireProtocolTimer(t)
	command, records := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	raw, _ := mle.FindTLV(records, mle.TLVMode)
	mode, err := mle.ReadModeTLV(raw)
	if command != mle.CommandParentRequest || err != nil || !mode.IsMinimalEndDevice() || !mode.IsRxOnWhenIdle() {
		t.Fatal("default public Begin no longer emits the existing awake MTD mode")
	}
	mustSRPLoop(t, fixture.node.inst, fixture.attempt.Cancel)
	if result := awaitOwnedAttach(t, fixture.attempt); !errors.Is(result.Err, context.Canceled) || result.Profile != ThreadAttachAwakeMTD {
		t.Fatal("default MTD cancellation/profile changed")
	}
}

func TestPublicFTDParentLossUsesAuthenticatedOwnedLifecycle(t *testing.T) {
	fixture, parent, _ := publicFTDWireFixture(t, nil)
	plain := mle.NewUnsecuredMessage(mle.CommandChildUpdateRequest)
	plain.AppendSourceAddressTLV(0x0800)
	plain.AppendStatusTLV(mle.StatusError)
	sendParentAttachMessage(t, parent, fixture, plain, 80)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if !fixture.node.inst.mleService.Mle().IsChild() || fixture.node.inst.ownedAttachment == nil {
			return fmt.Errorf("public FTD lifetime accepted inner-unsecured parent control")
		}
		return nil
	})
	authenticated := mle.NewMessage(mle.CommandChildUpdateRequest)
	authenticated.AppendSourceAddressTLV(0x0800)
	authenticated.AppendStatusTLV(mle.StatusError)
	sendParentAttachMessage(t, parent, fixture, authenticated, 81)
	waitUDPCondition(t, fixture.node.inst, func() bool {
		return !fixture.node.inst.mleService.Mle().IsChild() && fixture.node.inst.ownedAttachment == nil
	})
	mustSRPLoop(t, fixture.node.inst, func() error {
		if fixture.node.inst.ownedTMF != nil || fixture.node.inst.netif.IsMulticastSubscribed(ip6.MulticastRealmLocalAllRouters) {
			return fmt.Errorf("actual parent loss retained owned role/TMF state")
		}
		return nil
	})
}
