package instance

import (
	"errors"
	"fmt"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/slaac"
	"github.com/hilli/gothread/thread/mle"
)

func TestSourceLifetimeActualManagerFailureRetainsCauseNotAuthenticatedRetirement(t *testing.T) {
	fixture, parent, _, lease := lifetimePublicFixture(t)
	mustSRPLoop(t, fixture.node.inst, func() error {
		slaac.WithIIDGenerator(&ownedSlaacIIDFault{})(fixture.node.inst.slaacManager)
		return nil
	})
	sendOwnedPrefixUpdate(t, fixture, parent, lifetimePrefixData(5, true), 1, 70, true)
	result := observeLifetime(t, fixture, lease)
	if result.State != ThreadSourceFailed || result.Failure != ThreadSourceBackendFailure ||
		!errors.Is(result.Cause, errOwnedSlaacIID) || result.Retirement != ThreadSourceNoRetirement {
		t.Fatal("actual generation/backend error became clean or lost exact failure cause")
	}
}

func TestSourceLifetimeKeyPrimaryRefreshAndOrdinaryMeshSourceDoNotMintRetirement(t *testing.T) {
	fixture, parent, _, lease := lifetimePublicFixture(t)
	before := observeLifetime(t, fixture, lease)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if _, err := fixture.attempt.AcquireSourceLifetime(fixture.eid); !errors.Is(err, goterrors.ErrNotCapable) {
			return fmt.Errorf("generation0 caller mesh source was turned into generated-source authority")
		}
		return nil
	})
	sendOwnedPrefixUpdate(t, fixture, parent, lifetimePrefixData(1, true), 1, 70, true)
	for _, frame := range phase2ParentRotationFrames(t, fixture, parent) {
		deliverNativeFrame(t, fixture.node, frame)
	}
	after := observeLifetime(t, fixture, lease)
	if after.State != ThreadSourceCurrent || after.SourceGeneration != before.SourceGeneration ||
		after.Epoch != before.Epoch || after.Retirement != ThreadSourceNoRetirement {
		t.Fatal("unchanged prefix/key/metadata refresh forged retirement or rotated source lifetime")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		ordinary, err := fixture.attempt.ObserveAttachment(fixture.eid)
		if err != nil || ordinary.SourceGeneration != 0 {
			return fmt.Errorf("ordinary mesh-local contract changed")
		}
		return nil
	})
}

func lifetimeReattachPublic(t *testing.T, fixture *ownedAttachFixture, parent *fragmentEndpoint) {
	t.Helper()
	mustSRPLoop(t, fixture.node.inst, func() error {
		var err error
		fixture.attempt, err = fixture.node.inst.BeginThreadAttachWithConfig(ThreadAttachConfig{
			Timeout: 30 * time.Second, Profile: ThreadAttachAwakeFTDChild,
		})
		fixture.node.macKey = fixture.node.inst.keyManager.GetCurrentMacKey()
		return err
	})
	fixture.fireProtocolTimer(t)
	command, records := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	challenge, ok := mle.FindTLV(records, mle.TLVChallenge)
	if command != mle.CommandParentRequest || !ok || len(challenge) != 8 {
		t.Fatal("no real fresh Parent Request")
	}
	sendParentAttachMessage(t, parent, fixture, parentResponse(challenge), 80)
	fixture.fireProtocolTimer(t)
	command, _ = ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if command != mle.CommandChildIDRequest {
		t.Fatal("no actual fresh CID Request")
	}
	response := childIDResponseWithNetworkData(0x0801, lifetimePrefixData(1, true))
	var mask mle.RouterIDSet
	mask.Add(2)
	response.AppendRoute64TLV(1, mask, []mle.Route64Entry{{Cost: 0}})
	sendParentAttachMessage(t, parent, fixture, response, 81)
	if result := awaitOwnedAttach(t, fixture.attempt); result.Err != nil || result.Role != mle.RoleChild {
		t.Fatal("fresh public wire attachment failed")
	}
}

func TestSourceLifetimeOldAttemptEpochCannotBecomeFreshSameAddressAuthority(t *testing.T) {
	fixture, parent, source, lease := lifetimePublicFixture(t)
	oldAttempt := fixture.attempt
	before := observeLifetime(t, fixture, lease)
	mustSRPLoop(t, fixture.node.inst, fixture.node.inst.ThreadStop)
	lifetimeReattachPublic(t, fixture, parent)
	mustSRPLoop(t, fixture.node.inst, func() error {
		current, err := fixture.attempt.ObserveAttachment(source)
		if err != nil || current.Epoch == before.Epoch {
			return fmt.Errorf("same-address new episode control absent")
		}
		if _, err := fixture.attempt.ObserveSourceLifetime(lease); !errors.Is(err, goterrors.ErrInvalidState) {
			return fmt.Errorf("new attempt adopted old epoch lease")
		}
		old, err := oldAttempt.ObserveSourceLifetime(lease)
		if err != nil || old.State != ThreadSourceFailed || old.Failure != ThreadSourceStopped ||
			old.Epoch != before.Epoch || old.Source != source {
			return fmt.Errorf("old episode proof revived or history lost")
		}
		return oldAttempt.ReleaseSourceLifetime(lease)
	})
}

func TestSourceLifetimeStoppedStatusAndReleaseRequireNoFailedLoopRestart(t *testing.T) {
	fixture, _, _, lease := lifetimePublicFixture(t)
	fixture.node.inst.Stop()
	result, err := fixture.attempt.ObserveSourceLifetime(lease)
	if err != nil || result.State != ThreadSourceFailed || result.Failure != ThreadSourceStopped {
		t.Fatal("actual Instance.Stop did not retain terminal lifetime cause")
	}
	before := fixture.node.inst.securityFailure.Load()
	if err := fixture.attempt.ReleaseSourceLifetime(lease); err != nil {
		t.Fatal(err)
	}
	if fixture.node.inst.IsRunning() || fixture.node.inst.securityFailure.Load() != before {
		t.Fatal("stopped metadata release ran protocol or changed health")
	}
	if _, err := fixture.attempt.ObserveSourceLifetime(lease); !errors.Is(err, goterrors.ErrInvalidState) {
		t.Fatal("released stopped token revived")
	}
}

func TestSourceLifetimeNoRetrospectiveAcquireFromMissingSourceOrPublicFlags(t *testing.T) {
	fixture, parent, source, lease := lifetimePublicFixture(t)
	sendOwnedPrefixUpdate(t, fixture, parent, nil, 1, 70, true)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if _, err := fixture.attempt.AcquireSourceLifetime(source); !errors.Is(err, goterrors.ErrInvalidSourceAddress) {
			return fmt.Errorf("absence sentinel reconstructed old G1 authority")
		}
		manual := source
		manual[15] ^= 0x55
		if err := fixture.node.inst.netif.AddExternalUnicastAddress(&ip6.UnicastAddress{
			Address: manual, PrefixLength: 64, Valid: true, Preferred: true, Origin: ip6.OriginSLAAC,
		}); err != nil {
			return err
		}
		if _, err := fixture.attempt.AcquireSourceLifetime(manual); !errors.Is(err, goterrors.ErrInvalidSourceAddress) {
			return fmt.Errorf("public Origin flag minted authenticated lifetime proof")
		}
		return nil
	})
	if result := observeLifetime(t, fixture, lease); result.State != ThreadSourceRetired {
		t.Fatal("failed retrospective acquire rewrote actual retained G1 event")
	}
}

func TestSourceLifetimeRetiredLeaseCapacityCannotBeReusedUntilExplicitRelease(t *testing.T) {
	fixture, parent, source, first := lifetimePublicFixture(t)
	var held [SourceLifetimeCapacity]ThreadSourceLifetime
	held[0] = first
	mustSRPLoop(t, fixture.node.inst, func() error {
		for i := 1; i < len(held); i++ {
			var err error
			held[i], err = fixture.attempt.AcquireSourceLifetime(source)
			if err != nil {
				return err
			}
		}
		return nil
	})
	sendOwnedPrefixUpdate(t, fixture, parent, nil, 1, 70, true)
	sendOwnedPrefixUpdate(t, fixture, parent, lifetimePrefixData(1, true), 2, 71, true)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if _, err := fixture.attempt.ObserveAttachment(source); err != nil {
			return err
		}
		if _, err := fixture.attempt.AcquireSourceLifetime(source); !errors.Is(err, goterrors.ErrNoBufs) {
			return fmt.Errorf("current G2 borrowed still-held retired G1 lease capacity")
		}
		for _, lease := range held {
			result, err := fixture.attempt.ObserveSourceLifetime(lease)
			if err != nil || result.State != ThreadSourceRetired {
				return fmt.Errorf("capacity pressure overwrote old G1 disposition")
			}
		}
		if err := fixture.attempt.ReleaseSourceLifetime(held[0]); err != nil {
			return err
		}
		fresh, err := fixture.attempt.AcquireSourceLifetime(source)
		if err != nil {
			return err
		}
		result, err := fixture.attempt.ObserveSourceLifetime(fresh)
		if err != nil || result.State != ThreadSourceCurrent {
			return fmt.Errorf("actual released slot could not acquire genuine G2")
		}
		return nil
	})
}
