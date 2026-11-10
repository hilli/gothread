package instance

import (
	"fmt"
	"testing"

	"github.com/hilli/gothread/net/srp"
)

func TestBoundSRPPauseObservableAndResumeRequiresEveryFreshACK(t *testing.T) {
	pair := newSRPPair(t, true)
	mustSRPLoop(t, pair.client.inst, func() error {
		for _, name := range []string{"B", "A"} {
			if _, err := pair.binding.UpsertService(nativeService(name)); err != nil {
				return err
			}
		}
		return nil
	})
	exchangeSRP(t, pair)
	exchangeSRP(t, pair)
	mustSRPLoop(t, pair.client.inst, pair.binding.Pause)
	paused := nextSRPNotice(t, pair.binding)
	if paused.State != srp.StatePaused || paused.Err != nil || len(paused.Services) != 0 ||
		len(paused.RemovedServices) != 0 || pair.binding.Err() != nil {
		t.Fatal("pause did not emit owned nonterminal invalidation without a fake ACK/error")
	}
	paused.Host.Addresses[0][15] ^= 0x7f
	mustSRPLoop(t, pair.client.inst, func() error {
		if pair.binding.client.GetHostInfo().Addresses[0] != pair.config.Addresses[0] {
			return fmt.Errorf("paused notice borrowed host input")
		}
		return pair.binding.Resume()
	})
	healthy := map[string]bool{}
	first := exchangeSRP(t, pair)
	if len(first.Services) != 1 || first.Services[0].InstanceName != "B" {
		t.Fatal("resume did not send a real B-only fresh update")
	}
	healthy["B"] = true
	if healthy["A"] {
		t.Fatal("B-only resume response healed A's old registration")
	}
	second := exchangeSRP(t, pair)
	if len(second.Services) != 1 || second.Services[0].InstanceName != "A" {
		t.Fatal("A never received an independent fresh resume ACK")
	}
}
