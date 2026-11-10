package instance

import (
	"fmt"
	"testing"
	"time"

	"github.com/hilli/gothread/net/coap"
)

func TestDormantAuthenticatedNotPrimaryRevokesPriorLocalReadyLease(t *testing.T) {
	fixture, parent := siteNativeFixture(t)
	var membership *MulticastMembership
	mustSRPLoop(t, fixture.node.inst, func() error {
		var err error
		membership, err = fixture.node.inst.JoinMulticast(siteTestAddress(1))
		return err
	})
	packet := captureSitePacket(t, fixture.node)
	request, err := coap.ParseMessage(packet[48:])
	if err != nil {
		t.Fatal(err)
	}
	sendSiteCoapResponse(t, parent, fixture, request, 0, nil)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if membership.Status().State != MulticastReady {
			return fmt.Errorf("actual default lease missing")
		}
		fixture.now = fixture.now.Add(225 * time.Second)
		fixture.node.inst.timers.processExpired()
		return nil
	})
	renewal := captureSitePacket(t, fixture.node)
	next, err := coap.ParseMessage(renewal[48:])
	if err != nil {
		t.Fatal(err)
	}
	sendSiteCoapResponse(t, parent, fixture, next, 5, nil)
	mustSRPLoop(t, fixture.node.inst, func() error {
		status := membership.Status()
		if status.State != MulticastPending || !status.RemoteLeaseUnknown || status.Err == nil ||
			fixture.node.inst.siteGroups.readyAddress(siteTestAddress(1)) {
			return fmt.Errorf("authenticated NotPrimary left stale RX/TX permission")
		}
		return membership.Leave()
	})
}
