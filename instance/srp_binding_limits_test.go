package instance

import (
	"fmt"
	"strings"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/dns"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/srp"
)

func TestBoundSRPCoalescedInputAndInflightAdmission(t *testing.T) {
	pair := newSRPPair(t, true)
	first, latest := nativeService("coalesced"), nativeService("coalesced")
	latest.Port = 5555
	var oldToken, latestToken uint64
	mustSRPLoop(t, pair.client.inst, func() error {
		var err error
		oldToken, err = pair.binding.UpsertService(first)
		if err != nil {
			return err
		}
		latestToken, err = pair.binding.UpsertService(latest)
		return err
	})
	fireSRPTimer(t, pair.binding)
	mustSRPLoop(t, pair.client.inst, func() error {
		if _, err := pair.binding.UpsertService(nativeService("not-admitted")); err != goterrors.ErrInvalidState {
			return fmt.Errorf("in-flight mutation admitted: %v", err)
		}
		return nil
	})
	forwardSRPDatagram(t, pair.client, pair.server)
	forwardSRPDatagram(t, pair.server, pair.client)
	mustSRPLoop(t, pair.client.inst, func() error { return nil })
	notice := nextSRPNotice(t, pair.binding)
	if notice.Err != nil || notice.Revision != latestToken || oldToken == latestToken ||
		len(notice.Services) != 1 || notice.Services[0].Port != 5555 ||
		len(pair.binding.notices) != 0 {
		t.Fatal("coalesced token falsely completed superseded content or latest state was stamped onto old response")
	}
	mustSRPLoop(t, pair.client.inst, func() error {
		if _, err := pair.binding.WithdrawService(latest.Name, latest.InstanceName); err != nil {
			return err
		}
		latest.Port++
		_, err := pair.binding.UpsertService(latest)
		return err
	})
	replaced := exchangeSRP(t, pair)
	if replaced.Err != nil || len(replaced.RemovedServices) != 0 || len(replaced.Services) != 1 ||
		replaced.Services[0].Port != latest.Port {
		t.Fatal("per-service withdrawal/replacement coalescing was confused with global host withdrawal")
	}
}

func TestBoundSRPServiceAndWireCapacityNeverTruncate(t *testing.T) {
	pair := newSRPPair(t, true)
	mustSRPLoop(t, pair.client.inst, func() error {
		for i := range SRPServiceCapacity {
			if _, err := pair.binding.UpsertService(nativeService(fmt.Sprintf("service%d", i))); err != nil {
				return err
			}
		}
		revision := pair.binding.revision
		for _, invalid := range []srp.Service{
			nativeService("ninth"),
			{Name: "_matter._tcp", InstanceName: "oversub", Port: 1, SubTypeLabels: []string{"a", "b", "c", "d", "e", "f"}},
			{Name: "_matter._tcp", InstanceName: "overtxt", Port: 1, TxtEntries: []dns.TxtEntry{{Value: make([]byte, 513)}}},
		} {
			if _, err := pair.binding.UpsertService(invalid); err != goterrors.ErrNoBufs {
				return fmt.Errorf("capacity not explicit: %v", err)
			}
		}
		badRaw := nativeService("invalid-raw")
		badRaw.TxtEntries = []dns.TxtEntry{{Value: []byte{5, 'x'}}}
		if _, err := pair.binding.UpsertService(badRaw); err != goterrors.ErrInvalidArgs {
			return fmt.Errorf("malformed raw TXT accepted: %v", err)
		}
		if len(pair.binding.client.GetServices()) != 8 || pair.binding.revision != revision ||
			pair.store.keyWrites != 1 {
			return fmt.Errorf("failed admission changed service/key ownership")
		}
		return nil
	})
}

func TestBoundSRPActualEncoderRejectsOverBudgetService(t *testing.T) {
	pair := newSRPPair(t, false)
	mustSRPLoop(t, pair.client.inst, func() error {
		config := pair.config
		config.DomainName = strings.Repeat("d", 63) + "."
		config.HostName = strings.Repeat("h", 63)
		config.Addresses = nil
		for i := range 4 {
			addr := pair.config.Addresses[0]
			addr[15] += byte(i + 1)
			pair.client.inst.netif.AddUnicastAddress(&ip6.UnicastAddress{Address: addr, PrefixLength: 64, Valid: true})
			config.Addresses = append(config.Addresses, addr)
		}
		var err error
		pair.binding, err = pair.client.inst.StartSRP(config)
		if err != nil {
			return err
		}
		service := nativeService(strings.Repeat("i", 63))
		service.SubTypeLabels = []string{
			strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63),
			strings.Repeat("d", 63), strings.Repeat("e", 63),
		}
		service.TxtEntries = []dns.TxtEntry{{Key: "x", Value: make([]byte, 252)}, {Key: "y", Value: make([]byte, 252)}}
		size, err := pair.binding.client.ServiceUpdateSize(service)
		if err != nil {
			return err
		}
		if size <= 1232 {
			return fmt.Errorf("fixture does not cross actual encoded 1232-byte threshold: %d", size)
		}
		if _, err := pair.binding.UpsertService(service); err != goterrors.ErrNoBufs {
			return fmt.Errorf("actual oversized signed update admitted/truncated: %v", err)
		}
		if len(pair.binding.client.GetServices()) != 0 || pair.binding.revision != 0 {
			return fmt.Errorf("oversized input changed owned registration")
		}
		return nil
	})
}
