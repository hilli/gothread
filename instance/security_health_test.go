package instance

import (
	"bytes"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/radio"
)

type ownedHealthFailure struct{ cause error }

type ownedTestEntropy struct {
	source  srpEntropy
	failure atomic.Pointer[ownedHealthFailure]
}

func TestOwnedAttachRequiresExplicitHealthGuard(t *testing.T) {
	store := newSRPSettings()
	driver := &fragmentRadio{
		boundedUDPRadio: &boundedUDPRadio{captures: make(chan udpRadioCapture, 2), settings: store},
		identity:        fragmentSource, caps: radio.CapCsmaBackoff | radio.CapTransmitRetries | radio.CapAckTimeout,
	}
	inst := New(Config{Radio: driver, Settings: store, Entropy: &srpEntropy{}})
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inst.Stop)
	before, err := store.Get(platform.SettingsKeyNetworkInfo, 0)
	if err != nil {
		t.Fatal(err)
	}
	mustSRPLoop(t, inst, func() error {
		attempt, err := inst.BeginThreadAttach(time.Second)
		if attempt != nil || !errors.Is(err, goterrors.ErrNotCapable) {
			return fmt.Errorf("missing health guard admitted native attempt: %v", err)
		}
		return nil
	})
	after, _ := store.Get(platform.SettingsKeyNetworkInfo, 0)
	if !bytes.Equal(before, after) || len(driver.captures) != 0 || store.keyWrites != 0 {
		t.Fatal("missing guard caused traffic/reservation/key mutation")
	}
}

func (entropy *ownedTestEntropy) Err() error {
	if failure := entropy.failure.Load(); failure != nil {
		return failure.cause
	}
	return nil
}

func (entropy *ownedTestEntropy) latch(err error) {
	entropy.failure.CompareAndSwap(nil, &ownedHealthFailure{cause: err})
}

func (entropy *ownedTestEntropy) Fill(destination []byte) error {
	if err := entropy.Err(); err != nil {
		return err
	}
	if err := entropy.source.Fill(destination); err != nil {
		entropy.latch(err)
		return err
	}
	return nil
}

func TestOwnedEntropyFailureBeforeAttachChangesNoReservationsOrIdentity(t *testing.T) {
	fixture := newOwnedAttachFixture(t, true)
	entropy := fixture.node.inst.entropy.(*ownedTestEntropy)
	before, err := fixture.store.Get(platform.SettingsKeyNetworkInfo, 0)
	if err != nil {
		t.Fatal(err)
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		entropy.source.fail = true // Failure after initial constructor seed succeeded.
		attempt, err := fixture.node.inst.BeginThreadAttach(time.Second)
		if attempt != nil || !errors.Is(err, errSRPEntropy) || !errors.Is(fixture.node.inst.SecurityError(), errSRPEntropy) {
			return fmt.Errorf("checked challenge failure lost cause: %v", err)
		}
		return nil
	})
	after, _ := fixture.store.Get(platform.SettingsKeyNetworkInfo, 0)
	if !bytes.Equal(before, after) || len(fixture.node.driver.captures) != 0 || fixture.store.keyWrites != 0 {
		t.Fatal("failed challenge consumed reservations/transmitted/regenerated signing identity")
	}
	if fixture.node.inst.PersistenceError() != nil {
		t.Fatal("entropy health and storage failures were conflated")
	}
}

func TestOwnedHealthLatchFencesPendingFrameAndCannotRecoverLive(t *testing.T) {
	fixture := newOwnedAttachFixture(t, true)
	entropy := fixture.node.inst.entropy.(*ownedTestEntropy)
	fixture.begin(t)
	fixture.fireProtocolTimer(t)
	accepted := captureUDP(t, fixture.node.driver.boundedUDPRadio)
	before, _ := fixture.store.Get(platform.SettingsKeyNetworkInfo, 0)
	entropy.latch(errSRPEntropy) // Already accepted hardware frame cannot be retracted.
	mustSRPLoop(t, fixture.node.inst, func() error {
		if !errors.Is(fixture.node.inst.SecurityError(), errSRPEntropy) {
			return fmt.Errorf("latched health disappeared")
		}
		fixture.node.inst.subMac.HandleTransmitDone(&accepted.frame, nil, nil)
		return nil
	})
	result := awaitOwnedAttach(t, fixture.attempt)
	if !errors.Is(result.Err, errSRPEntropy) {
		t.Fatalf("pending operation health cause lost: %v", result.Err)
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		if _, err := fixture.node.inst.BeginThreadAttach(time.Second); !errors.Is(err, errSRPEntropy) {
			return fmt.Errorf("retry revived failed generator")
		}
		if err := fixture.node.inst.SendUDP(nil, ip6.MessageInfo{}); !errors.Is(err, errSRPEntropy) {
			return fmt.Errorf("producer admitted work after health latch")
		}
		if err := fixture.node.inst.StageOperationalDatasets(DatasetRecord{Present: true, TLVs: ownedDataset().Bytes()}, DatasetRecord{}); !errors.Is(err, errSRPEntropy) {
			return fmt.Errorf("dataset restore cleared security health")
		}
		return nil
	})
	after, _ := fixture.store.Get(platform.SettingsKeyNetworkInfo, 0)
	if !bytes.Equal(before, after) || len(fixture.node.driver.captures) != 0 {
		t.Fatal("late callback/producer consumed new counters or transmitted")
	}
}
