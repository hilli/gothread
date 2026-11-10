package instance

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/hilli/gothread/net/coap"
)

func phase2LeaseRequest(t *testing.T, fixture *ownedAttachFixture, count int) *coap.Message {
	t.Helper()
	packet := captureSitePacket(t, fixture.node)
	source := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0801)
	peer := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0800)
	if !bytes.Equal(packet[8:24], source[:]) || !bytes.Equal(packet[24:40], peer[:]) {
		t.Fatal("renewal did not use the real captured RLOC control peer/source")
	}
	request, err := coap.ParseMessage(packet[48:])
	if err != nil {
		t.Fatal(err)
	}
	payload := request.GetPayload()
	if request.GetType() != coap.TypeConfirmable || request.GetCode() != coap.CodePost ||
		len(request.GetToken()) != 8 || len(payload) != 2+16*count || payload[0] != 14 || int(payload[1]) != 16*count {
		t.Fatal("not a real bounded address-only default-lease MLR request")
	}
	return request
}

func TestPhase2ExpiredRetainedIntentRequeuesAfterMissedRenewalTick(t *testing.T) {
	fixture, parent := siteNativeFixture(t)
	var handles []*MulticastMembership
	mustSRPLoop(t, fixture.node.inst, func() error {
		for i := byte(1); i <= 16; i++ {
			handle, err := fixture.node.inst.JoinMulticast(siteTestAddress(i))
			if err != nil {
				return err
			}
			handles = append(handles, handle)
		}
		return nil
	})
	first := phase2LeaseRequest(t, fixture, 15)
	sendSiteCoapResponse(t, parent, fixture, first, 0, nil)
	second := phase2LeaseRequest(t, fixture, 1)
	sendSiteCoapResponse(t, parent, fixture, second, 0, nil)
	mustSRPLoop(t, fixture.node.inst, func() error {
		for _, handle := range handles {
			if status := handle.Status(); status.State != MulticastReady || status.Err != nil {
				return fmt.Errorf("actual initial MLR default lease was not Ready")
			}
		}
		// No intermediate ticks: the first renewal opportunity has already
		// passed when the owner loop next processes its actual timers.
		fixture.now = fixture.now.Add(301 * time.Second)
		for _, handle := range handles {
			if status := handle.Status(); status.State != MulticastPending || !status.RemoteLeaseUnknown {
				return fmt.Errorf("expired reference manufactured Ready before a new response")
			}
		}
		fixture.node.inst.timers.processExpired()
		if fixture.node.inst.siteGroups.client.pending == nil {
			return fmt.Errorf("overdue timer did not admit any new MLR transaction for expired live intent")
		}
		return nil
	})
	renewal := phase2LeaseRequest(t, fixture, 15)
	if renewal.GetMessageID() == first.GetMessageID() || bytes.Equal(renewal.GetToken(), first.GetToken()) {
		t.Fatal("expired intent replayed an old transaction instead of fresh registration")
	}
	// A genuine late response to the expired transaction cannot ready refs.
	sendSiteCoapResponse(t, parent, fixture, first, 0, nil)
	mustSRPLoop(t, fixture.node.inst, func() error {
		for _, handle := range handles {
			if handle.Status().State != MulticastPending {
				return fmt.Errorf("old expired response revived a retained reference")
			}
		}
		return nil
	})
	sendSiteCoapResponse(t, parent, fixture, renewal, 4, [][16]byte{[16]byte(siteTestAddress(2))})
	mustSRPLoop(t, fixture.node.inst, func() error {
		for i, handle := range handles {
			status := handle.Status()
			if i == 1 || i == 15 {
				if status.State != MulticastPending {
					return fmt.Errorf("nonaccepted expired subset became Ready")
				}
			} else if status.State != MulticastReady || status.Err != nil {
				return fmt.Errorf("new actual accepted subset did not become Ready")
			}
		}
		fixture.now = fixture.now.Add(5 * time.Second)
		fixture.node.inst.timers.processExpired()
		return nil
	})
	last := phase2LeaseRequest(t, fixture, 2)
	sendSiteCoapResponse(t, parent, fixture, last, 0, nil)
	mustSRPLoop(t, fixture.node.inst, func() error {
		for _, handle := range handles {
			if status := handle.Status(); status.State != MulticastReady || status.Err != nil {
				return fmt.Errorf("fresh accepted retry failed to ready the retained reference")
			}
		}
		return nil
	})
}

func TestPhase2ExpiredLeaseDoesNotReplaceActualInflightRenewal(t *testing.T) {
	fixture, parent := siteNativeFixture(t)
	var handle *MulticastMembership
	mustSRPLoop(t, fixture.node.inst, func() error {
		var err error
		handle, err = fixture.node.inst.JoinMulticast(siteTestAddress(1))
		return err
	})
	first := phase2LeaseRequest(t, fixture, 1)
	sendSiteCoapResponse(t, parent, fixture, first, 0, nil)
	mustSRPLoop(t, fixture.node.inst, func() error {
		fixture.now = fixture.now.Add(226 * time.Second)
		fixture.node.inst.timers.processExpired()
		return nil
	})
	renewal := phase2LeaseRequest(t, fixture, 1)
	mustSRPLoop(t, fixture.node.inst, func() error {
		fixture.now = fixture.now.Add(75 * time.Second)
		fixture.node.inst.timers.processExpired()
		if handle.Status().State != MulticastPending {
			return fmt.Errorf("expired in-flight lease stayed Ready")
		}
		return nil
	})
	retry := phase2LeaseRequest(t, fixture, 1)
	if retry.GetMessageID() != renewal.GetMessageID() || !bytes.Equal(retry.GetToken(), renewal.GetToken()) {
		t.Fatal("expiry duplicated/replaced the actual in-flight registration")
	}
	sendSiteCoapResponse(t, parent, fixture, renewal, 0, nil)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if status := handle.Status(); status.State != MulticastReady || status.Err != nil {
			return fmt.Errorf("expiry reset Registering state of the actual pending batch")
		}
		return nil
	})
}

func TestPhase2ExpiredIntentCannotReviveAfterLastLeaveOrStop(t *testing.T) {
	for _, kind := range []string{"leave", "stop"} {
		t.Run(kind, func(t *testing.T) {
			fixture, parent := siteNativeFixture(t)
			var handle *MulticastMembership
			mustSRPLoop(t, fixture.node.inst, func() error {
				var err error
				handle, err = fixture.node.inst.JoinMulticast(siteTestAddress(1))
				return err
			})
			request := phase2LeaseRequest(t, fixture, 1)
			sendSiteCoapResponse(t, parent, fixture, request, 0, nil)
			mustSRPLoop(t, fixture.node.inst, func() error {
				fixture.now = fixture.now.Add(301 * time.Second)
				if kind == "leave" {
					if err := handle.Leave(); err != nil {
						return err
					}
				} else if err := fixture.node.inst.ThreadStop(); err != nil {
					return err
				}
				fixture.node.inst.timers.processExpired()
				if handle.Status().State != MulticastLocalLeft || fixture.node.inst.siteGroups != nil ||
					len(fixture.node.driver.captures) != 0 {
					return fmt.Errorf("expired stale owner revived after last Leave/Stop")
				}
				return nil
			})
			sendSiteCoapResponse(t, parent, fixture, request, 0, nil)
			mustSRPLoop(t, fixture.node.inst, func() error {
				if handle.Status().State != MulticastLocalLeft || fixture.node.inst.siteGroups != nil {
					return fmt.Errorf("old-epoch response revived a removed reference")
				}
				return nil
			})
		})
	}
}
