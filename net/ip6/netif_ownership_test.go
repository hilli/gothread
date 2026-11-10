package ip6

import "testing"

func TestNetifExternalMulticastRemovalPreservesRemainingOwners(t *testing.T) {
	netif := NewNetif()
	addresses := []Address{
		{0xff, 5, 15: 11}, {0xff, 5, 15: 12}, {0xff, 5, 15: 13}, {0xff, 5, 15: 14},
		{0xff, 5, 15: 15}, {0xff, 5, 15: 16}, {0xff, 5, 15: 17}, {0xff, 5, 15: 18},
	}
	for _, address := range addresses {
		if err := netif.SubscribeExternalMulticast(address); err != nil {
			t.Fatal(err)
		}
	}
	if err := netif.UnsubscribeExternalMulticast(addresses[0]); err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses[1:] {
		if !netif.IsMulticastAddressExternal(address) {
			t.Fatal("slice compaction lost remaining external owner")
		}
	}
	netif.SubscribeAllNodesMulticast()
	netif.SubscribeAllRoutersMulticast()
	netif.UnsubscribeAllRoutersMulticast()
	netif.UnsubscribeAllNodesMulticast()
	for _, address := range addresses[1:] {
		if !netif.IsMulticastAddressExternal(address) {
			t.Fatal("slice compaction lost remaining external owner")
		}
		if err := netif.UnsubscribeExternalMulticast(address); err != nil {
			t.Fatal(err)
		}
	}
}
