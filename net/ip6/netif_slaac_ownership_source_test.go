package ip6

import (
	"errors"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
)

func TestInternalSlaacMovementPreservesActualExternalUnicastOwners(t *testing.T) {
	netif := NewNetif()
	var first UnicastAddress
	first.InitAsSLAACOrigin(64, true)
	first.Address = Address{0x20, 1, 0x0d, 0xb8, 0, 8, 15: 1}
	netif.AddUnicastAddress(&first)
	for i := byte(1); i <= 8; i++ {
		if err := netif.AddExternalUnicastAddress(&UnicastAddress{
			Address: Address{0x20, 1, 0x0d, 0xb8, 0, 7, 15: i}, Valid: true, Preferred: true, PrefixLength: 64,
		}); err != nil {
			t.Fatal(err)
		}
	}
	for i := byte(2); i <= 4; i++ {
		var address UnicastAddress
		address.InitAsSLAACOrigin(64, true)
		address.Address = Address{0x20, 1, 0x0d, 0xb8, 0, 8, 15: i}
		netif.AddUnicastAddress(&address)
	}
	for i := byte(1); i <= 4; i++ {
		netif.RemoveUnicastAddress(&UnicastAddress{Address: Address{0x20, 1, 0x0d, 0xb8, 0, 8, 15: i}})
	}
	for i := byte(1); i <= 8; i++ {
		address := Address{0x20, 1, 0x0d, 0xb8, 0, 7, 15: i}
		if !netif.IsUnicastAddressExternal(address) {
			t.Fatal("internal SLAAC growth/compaction stole external ownership")
		}
	}
	if err := netif.AddExternalUnicastAddress(&UnicastAddress{
		Address: Address{0x20, 1, 0x0d, 0xb8, 0, 7, 15: 9}, Valid: true,
	}); !errors.Is(err, goterrors.ErrNoBufs) {
		t.Fatal("SLAAC internal lifecycle enlarged external8 capacity")
	}
	for i := byte(1); i <= 8; i++ {
		if err := netif.RemoveExternalUnicastAddress(Address{0x20, 1, 0x0d, 0xb8, 0, 7, 15: i}); err != nil {
			t.Fatal("external pointer removal lost identity after compaction")
		}
	}
}
