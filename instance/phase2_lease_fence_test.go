package instance

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/netdata"
)

func phase2LeaseFaultFixture(t *testing.T, store platform.Settings) (fixture *ownedAttachFixture, parent *fragmentEndpoint) {
	t.Helper()
	server := netdata.AppendServerValue(nil, netdata.ServerEntry{
		Server16: 0x0800, ServerData: []byte{7, 0, 5, 0, 0, 1, 0x2c},
	})
	sub := netdata.AppendTLV(nil, netdata.TLVTypeServer, true, server)
	service := netdata.AppendServiceValue(nil, netdata.ServiceTLVInfo{
		ServiceID: 4, EnterpriseNumber: netdata.ThreadEnterpriseNumber, ServiceData: []byte{1}, SubTLVsData: sub,
	})
	fixture, parent, _ = dormantFTDControlWithData(t, netdata.AppendTLV(nil, netdata.TLVTypeService, true, service), store)
	mustSRPLoop(t, fixture.node.inst, func() error {
		fixture.node.macKey = fixture.node.inst.keyManager.GetCurrentMacKey()
		return nil
	})
	return fixture, parent
}

func TestPhase2ExpiredRenewalCannotReviveAfterAuthorityFailure(t *testing.T) {
	for _, kind := range []string{"primary", "health", "persist-before", "persist-after"} {
		t.Run(kind, func(t *testing.T) {
			store := &datasetWriteFault{SimSettings: simulation.NewSimSettings()}
			fixture, parent := phase2LeaseFaultFixture(t, store)
			var handle *MulticastMembership
			mustSRPLoop(t, fixture.node.inst, func() error {
				var err error
				handle, err = fixture.node.inst.JoinMulticast(siteTestAddress(1))
				return err
			})
			first := phase2LeaseRequest(t, fixture, 1)
			sendSiteCoapResponse(t, parent, fixture, first, 0, nil)
			mustSRPLoop(t, fixture.node.inst, func() error {
				fixture.now = fixture.now.Add(301 * time.Second)
				fixture.node.inst.timers.processExpired()
				return nil
			})
			renewal := phase2LeaseRequest(t, fixture, 1)
			switch kind {
			case "primary":
				mustSRPLoop(t, fixture.node.inst, fixture.node.inst.mleService.ChildHandlers.SendDataRequest)
				command, _ := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
				if command != mle.CommandDataRequest {
					t.Fatal("no real parent Network Data request")
				}
				response := mle.NewMessage(mle.CommandDataResponse)
				response.AppendSourceAddressTLV(0x0800)
				response.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 1, Weighting: 64, LeaderRouterID: 2, DataVersion: 1})
				response.AppendNetworkDataTLV(nil)
				sendParentAttachMessage(t, parent, fixture, response, 80)
			case "health":
				mustSRPLoop(t, fixture.node.inst, func() error {
					fixture.node.inst.entropy.(*ownedTestEntropy).latch(errSRPEntropy)
					return nil
				})
			default:
				mustSRPLoop(t, fixture.node.inst, func() error {
					store.fail, store.commit = platform.SettingsKeyNetworkInfo, kind == "persist-after"
					return nil
				})
				rotation := phase2ParentRotationFrames(t, fixture, parent)
				for _, frame := range rotation {
					deliverNativeFrame(t, fixture.node, frame)
				}
				mustSRPLoop(t, fixture.node.inst, func() error {
					if !errors.Is(fixture.node.inst.PersistenceError(), errOwnedDatasetWrite) {
						return fmt.Errorf("actual parent rotation did not retain the exact Settings failure")
					}
					return nil
				})
			}
			sendSiteCoapResponse(t, parent, fixture, renewal, 0, nil)
			mustSRPLoop(t, fixture.node.inst, func() error {
				if handle.Status().State == MulticastReady || len(fixture.node.driver.captures) != 0 {
					return fmt.Errorf("stale renewal response revived failed/removed authority")
				}
				return nil
			})
		})
	}
}
