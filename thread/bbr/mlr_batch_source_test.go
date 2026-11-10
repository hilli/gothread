package bbr

import (
	"testing"

	"github.com/hilli/gothread/net/ip6"
)

func TestMlrAutomatic80RetainedSixLiteralWireBatches(t *testing.T) {
	manager := NewMlrManager(WithMaxEntries(80), WithMlrLeaderProvider(testLeader()))
	for i := 0; i < 80; i++ {
		address := ip6.Address{0xff, 0x35, 3: 0x40, 4: 0xfd, 15: byte(i + 1)}
		if err := manager.AddAddress([16]byte(address)); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []int{15, 15, 15, 15, 15, 5} {
		batch := manager.UpdateRegistration()
		if len(batch) != want {
			t.Fatalf("actual automatic batch=%d want%d", len(batch), want)
		}
		if len(manager.GetEntries()) != 80 {
			t.Fatal("wire batching shrank retained capacity")
		}
		manager.HandleMlrResponse(MlrStatusSuccess, nil)
	}
	if got := len(manager.GetRegisteredAddresses()); got != 80 {
		t.Fatalf("accepted actual subsets=%d", got)
	}
	if pending := manager.UpdateRegistration(); len(pending) != 0 {
		t.Fatal("registered entries were resubmitted")
	}
}

func TestMlrAutomaticFailedSubsetAcceptsOnlyUnlistedCurrentAddresses(t *testing.T) {
	manager := NewMlrManager(WithMaxEntries(80), WithMlrLeaderProvider(testLeader()))
	for i := byte(1); i <= 15; i++ {
		if err := manager.AddAddress([16]byte{0xff, 0x35, 4: 0xfd, 15: i}); err != nil {
			t.Fatal(err)
		}
	}
	batch := manager.UpdateRegistration()
	manager.HandleMlrResponse(MlrStatusNoResources, [][16]byte{batch[3], batch[8]})
	if got := len(manager.GetRegisteredAddresses()); got != 13 {
		t.Fatalf("accepted subset=%d want13", got)
	}
	retry := manager.UpdateRegistration()
	if len(retry) != 2 || retry[0] != batch[3] || retry[1] != batch[8] {
		t.Fatal("retry is not exact failed subset")
	}
	manager.HandleMlrResponse(MlrStatusGeneralFailure, nil)
	if got := len(manager.GetRegisteredAddresses()); got != 13 {
		t.Fatal("failure without list accepted current batch")
	}
}
