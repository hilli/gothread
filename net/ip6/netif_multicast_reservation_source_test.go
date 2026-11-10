package ip6

import (
	"errors"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
)

func siteCapacityAddress(index byte) Address   { return Address{0xff, 0x35, 0, 0x40, 4: 0xfd, 15: index} }
func manualCapacityAddress(index byte) Address { return Address{0xff, 0x05, 14: 2, 15: index} }

func TestNetifExplicit80ExternalReservationPreservesDefaultAcrossLifetime(t *testing.T) {
	var netif Netif
	for i := byte(1); i <= 8; i++ {
		if err := netif.SubscribeExternalMulticast(manualCapacityAddress(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := netif.SubscribeExternalMulticast(manualCapacityAddress(9)); !errors.Is(err, goterrors.ErrNoBufs) {
		t.Fatal("zero-value default pool changed from8")
	}
	reservation, err := netif.ReserveExternalMulticast(80)
	if err != nil {
		t.Fatal(err)
	}
	for i := byte(1); i <= 80; i++ {
		if err := reservation.Subscribe(siteCapacityAddress(i)); err != nil {
			t.Fatalf("actual reserved external admission%d: %v", i, err)
		}
	}
	if err := reservation.Subscribe(siteCapacityAddress(81)); !errors.Is(err, goterrors.ErrNoBufs) {
		t.Fatal("reserved pool exceeded80")
	}
	if err := netif.SubscribeExternalMulticast(manualCapacityAddress(9)); !errors.Is(err, goterrors.ErrNoBufs) {
		t.Fatal("reservation raised ordinary/default quota")
	}
	if err := netif.UnsubscribeExternalMulticast(siteCapacityAddress(1)); !errors.Is(err, goterrors.ErrRejected) {
		t.Fatal("ordinary API stole protocol-owned subscription")
	}
	for i := byte(1); i <= 64; i++ {
		netif.SubscribeMulticast(Address{0xff, 0x05, 14: 1, 15: i})
	}
	for i := byte(1); i <= 80; i++ {
		address := siteCapacityAddress(i)
		if !netif.IsMulticastAddressExternal(address) {
			t.Fatalf("reserved external ownership lost%d", i)
		}
		if err := reservation.Unsubscribe(address); err != nil {
			t.Fatalf("actual reserved removal%d: %v", i, err)
		}
	}
	if err := reservation.Release(); err != nil {
		t.Fatal(err)
	}
	if err := reservation.Release(); err != nil {
		t.Fatal("release was not idempotent")
	}
	for i := byte(1); i <= 8; i++ {
		if !netif.IsMulticastAddressExternal(manualCapacityAddress(i)) {
			t.Fatal("reservation release damaged preexisting default8")
		}
	}
	for i := byte(1); i <= 64; i++ {
		if !netif.IsMulticastSubscribed(Address{0xff, 0x05, 14: 1, 15: i}) {
			t.Fatal("external removal damaged internal subscription")
		}
	}
	if err := netif.SubscribeExternalMulticast(manualCapacityAddress(9)); !errors.Is(err, goterrors.ErrNoBufs) {
		t.Fatal("ordinary quota remained enlarged after profile release")
	}
	if err := netif.UnsubscribeExternalMulticast(manualCapacityAddress(1)); err != nil {
		t.Fatal(err)
	}
	if err := netif.SubscribeExternalMulticast(manualCapacityAddress(9)); err != nil {
		t.Fatal("default slot was not usable after reservation release")
	}
	for i := byte(2); i <= 9; i++ {
		if err := netif.UnsubscribeExternalMulticast(manualCapacityAddress(i)); err != nil {
			t.Fatal(err)
		}
	}
	for i := byte(1); i <= 8; i++ {
		if err := netif.SubscribeExternalMulticast(manualCapacityAddress(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := netif.SubscribeExternalMulticast(manualCapacityAddress(9)); !errors.Is(err, goterrors.ErrNoBufs) {
		t.Fatal("next lifecycle changed default8/9 boundary")
	}
}

func TestNetifReservationBoundsDoNotMutateDefault(t *testing.T) {
	netif := NewNetif()
	for _, capacity := range []int{0, -1, 81} {
		if reservation, err := netif.ReserveExternalMulticast(capacity); reservation != nil || !errors.Is(err, goterrors.ErrInvalidArgs) {
			t.Fatal("invalid reservation accepted")
		}
	}
	reservation, err := netif.ReserveExternalMulticast(80)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := netif.ReserveExternalMulticast(80); other != nil || !errors.Is(err, goterrors.ErrBusy) {
		t.Fatal("second owner grew an unbounded pool")
	}
	if err := reservation.Release(); err != nil {
		t.Fatal(err)
	}
	for i := byte(1); i <= 8; i++ {
		if err := netif.SubscribeExternalMulticast(manualCapacityAddress(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := netif.SubscribeExternalMulticast(manualCapacityAddress(9)); !errors.Is(err, goterrors.ErrNoBufs) {
		t.Fatal("reserve/release mutated default pool")
	}
}
