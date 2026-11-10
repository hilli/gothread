package instance

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/hilli/gothread/net/coap"
)

func TestDormantSiteActualSubsetRejectsPlainAckAndCannotReviveRejoinedReference(t *testing.T) {
	fixture, parent := siteNativeFixture(t)
	var handles []*MulticastMembership
	mustSRPLoop(t, fixture.node.inst, func() error {
		for i := byte(1); i <= 3; i++ {
			handle, err := fixture.node.inst.JoinMulticast(siteTestAddress(i))
			if err != nil {
				return err
			}
			handles = append(handles, handle)
		}
		return nil
	})
	packet := captureSitePacket(t, fixture.node)
	request, err := coap.ParseMessage(packet[48:])
	if err != nil {
		t.Fatal(err)
	}
	sendSiteCoapResponseSecurity(t, parent, fixture, request, 0, nil, false)
	mustSRPLoop(t, fixture.node.inst, func() error {
		for _, handle := range handles {
			if handle.Status().State != MulticastPending {
				return fmt.Errorf("MAC-unsecured ACK manufactured ready")
			}
		}
		if err := handles[0].Leave(); err != nil {
			return err
		}
		handle, err := fixture.node.inst.JoinMulticast(siteTestAddress(1))
		if err != nil {
			return err
		}
		handles = append(handles, handle)
		return nil
	})
	sendSiteCoapResponse(t, parent, fixture, request, 4, [][16]byte{[16]byte(siteTestAddress(3))})
	mustSRPLoop(t, fixture.node.inst, func() error {
		if handles[0].Status().State != MulticastLocalLeft || handles[1].Status().State != MulticastReady ||
			handles[1].Status().Err != nil || handles[2].Status().State != MulticastPending ||
			handles[3].Status().State != MulticastPending {
			return fmt.Errorf("current failed subset or old-address generation was flattened")
		}
		if err := handles[2].Leave(); err != nil {
			return err
		}
		fixture.now = fixture.now.Add(5 * time.Second)
		fixture.node.inst.timers.processExpired()
		return nil
	})
	packet = captureSitePacket(t, fixture.node)
	next, err := coap.ParseMessage(packet[48:])
	if err != nil {
		t.Fatal(err)
	}
	payload := next.GetPayload()
	want := siteTestAddress(1)
	if len(payload) != 18 || payload[0] != 14 || payload[1] != 16 || !bytes.Equal(payload[2:], want[:]) {
		t.Fatal("retry renewed a locally left address or omitted rejoined reference")
	}
	sendSiteCoapResponse(t, parent, fixture, next, 0, nil)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if handles[3].Status().State != MulticastReady {
			return fmt.Errorf("new actual registration did not ready current reference")
		}
		for _, index := range []int{1, 3} {
			if err := handles[index].Leave(); err != nil {
				return err
			}
		}
		if fixture.node.inst.siteGroups != nil || len(fixture.node.driver.captures) != 0 {
			return fmt.Errorf("last leave retained renewal/prune work")
		}
		return nil
	})
}
