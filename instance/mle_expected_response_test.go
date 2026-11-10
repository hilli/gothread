package instance

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/hilli/gothread/thread/mle"
)

func ownedAttachedMTD(t *testing.T) (*ownedAttachFixture, *fragmentEndpoint) {
	t.Helper()
	fixture, parent := ownedCIDPending(t)
	sendParentAttachMessage(t, parent, fixture, childIDResponse(0x0801), 61)
	if result := awaitOwnedAttach(t, fixture.attempt); result.Err != nil {
		t.Fatal(result.Err)
	}
	return fixture, parent
}

func expectedDataResponse() *mle.Message {
	reply := mle.NewMessage(mle.CommandDataResponse)
	reply.AppendSourceAddressTLV(0x0800)
	reply.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 1, Weighting: 64, LeaderRouterID: 2, DataVersion: 1})
	reply.AppendNetworkDataTLV(largeBootstrapNetworkData())
	return reply
}

func TestOwnedKnownParentFragmentRequiresActualPendingDataRequest(t *testing.T) {
	fixture, parent := ownedAttachedMTD(t)
	unsolicited := captureParentAttachMessage(t, parent, fixture, expectedDataResponse(), 62, nil)
	deliverAttachCaptures(t, fixture, unsolicited)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if len(fixture.node.inst.ownedAttachment.networkData) != 0 || fixture.node.inst.initialMLEFragment != nil {
			return fmt.Errorf("unsolicited fragmented data advanced network state")
		}
		return fixture.node.inst.mleService.ChildHandlers.SendDataRequest()
	})
	command, _ := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if command != mle.CommandDataRequest {
		t.Fatal("no real pending data exchange")
	}
	bad := captureParentAttachMessage(t, parent, fixture, expectedDataResponse(), 63, func(wire []byte) { wire[len(wire)-1] ^= 1 })
	deliverAttachCaptures(t, fixture, bad)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if len(fixture.node.inst.ownedAttachment.networkData) != 0 || fixture.node.inst.initialMLEFragment != nil {
			return fmt.Errorf("bad MIC advanced/retained known-peer candidate")
		}
		return nil
	})
	good := captureParentAttachMessage(t, parent, fixture, expectedDataResponse(), 64, nil)
	deliverAttachCaptures(t, fixture, good)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if !bytes.Equal(fixture.node.inst.ownedAttachment.networkData, largeBootstrapNetworkData()) ||
			fixture.node.inst.expectedMLE[0] != nil || fixture.node.inst.initialMLEFragment != nil {
			return fmt.Errorf("authenticated expected data did not complete/release")
		}
		return nil
	})
}

func TestOwnedKnownParentFragmentChildChallengeAndExpiry(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		t.Run(fmt.Sprint(expiry), func(t *testing.T) {
			fixture, parent := ownedAttachedMTD(t)
			mustSRPLoop(t, fixture.node.inst, func() error {
				return fixture.node.inst.mleService.ChildHandlers.SendChildUpdateRequest(mle.ChildUpdateAppendChallenge)
			})
			command, records := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
			if command != mle.CommandChildUpdateRequest {
				t.Fatal("no actual child update")
			}
			challenge, _ := mle.FindTLV(records, mle.TLVChallenge)
			response := func(echo []byte) *mle.Message {
				reply := mle.NewMessage(mle.CommandChildUpdateResponse)
				reply.AppendSourceAddressTLV(0x0800)
				reply.AppendModeTLV(mle.NewDeviceMode(mle.ModeRxOnWhenIdle))
				reply.AppendResponseTLV(echo)
				reply.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 1, Weighting: 64, LeaderRouterID: 2, DataVersion: 1})
				reply.AppendNetworkDataTLV(largeBootstrapNetworkData())
				return reply
			}
			wrong := append([]byte(nil), challenge...)
			wrong[0] ^= 1
			bad := captureParentAttachMessage(t, parent, fixture, response(wrong), 62, nil)
			deliverAttachCaptures(t, fixture, bad)
			mustSRPLoop(t, fixture.node.inst, func() error {
				if len(fixture.node.inst.ownedAttachment.networkData) != 0 || fixture.node.inst.expectedMLE[1] == nil {
					return fmt.Errorf("wrong challenge changed or consumed exchange")
				}
				return nil
			})
			good := captureParentAttachMessage(t, parent, fixture, response(challenge), 63, nil)
			if expiry {
				deliverAttachCaptures(t, fixture, good[:1])
				mustSRPLoop(t, fixture.node.inst, func() error {
					fixture.now = fixture.now.Add(ownedMLEResponseWindow + time.Nanosecond)
					fixture.node.inst.timers.processExpired()
					return nil
				})
				deliverAttachCaptures(t, fixture, good[1:])
			} else {
				deliverAttachCaptures(t, fixture, good)
			}
			mustSRPLoop(t, fixture.node.inst, func() error {
				if fixture.node.inst.initialMLEFragment != nil || fixture.node.inst.expectedMLE[1] != nil {
					return fmt.Errorf("response/expiry retained ownership")
				}
				if got := len(fixture.node.inst.ownedAttachment.networkData) > 0; got == expiry {
					return fmt.Errorf("unexpected network-data progress after response/expiry")
				}
				return nil
			})
		})
	}
}
