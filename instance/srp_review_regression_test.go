package instance

import (
	"fmt"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/srp"
	"github.com/hilli/gothread/thread/mle"
)

func TestBoundSRPHostWithdrawalCannotACKUnencodedAddition(t *testing.T) {
	pair := newSRPPair(t, true)
	mustSRPLoop(t, pair.client.inst, func() error { _, err := pair.binding.UpsertService(nativeService("A")); return err })
	exchangeSRP(t, pair)
	var additionErr error
	mustSRPLoop(t, pair.client.inst, func() error {
		if _, err := pair.binding.WithdrawHost(false); err != nil {
			return err
		}
		_, additionErr = pair.binding.UpsertService(nativeService("B-never-encoded"))
		return nil
	})
	notice := exchangeSRP(t, pair)
	if notice.Err != nil || len(notice.Services) != 0 || len(notice.RemovedServices) != 1 ||
		notice.RemovedServices[0].State != srp.ItemStateRemoved || additionErr != goterrors.ErrInvalidState {
		t.Fatalf("host lease-zero response falsely ACKed unencoded addition: admittedErr=%v err=%v addACKs=%d removeACKs=%d",
			additionErr, notice.Err, len(notice.Services), len(notice.RemovedServices))
	}
}

func TestBoundSRPHostWithdrawalCannotDiscardRejectedReplacement(t *testing.T) {
	pair := newSRPPair(t, true)
	original := nativeService("A")
	mustSRPLoop(t, pair.client.inst, func() error { _, err := pair.binding.UpsertService(original); return err })
	exchangeSRP(t, pair)
	mustSRPLoop(t, pair.client.inst, func() error {
		if _, err := pair.binding.WithdrawHost(false); err != nil {
			return err
		}
		replacement := original
		replacement.Port++
		if _, err := pair.binding.UpsertService(replacement); err != goterrors.ErrInvalidState {
			return fmt.Errorf("replacement admitted during global withdrawal: %v", err)
		}
		return nil
	})
	notice := exchangeSRP(t, pair)
	if notice.Err != nil || len(notice.Services) != 0 || len(notice.RemovedServices) != 1 ||
		notice.RemovedServices[0].Port != original.Port {
		t.Fatal("rejected replacement silently discarded original removal ownership")
	}
}

func TestBoundSRPMLEPortRejectedBeforeCredentialSideEffects(t *testing.T) {
	pair := newSRPPair(t, false)
	mustSRPLoop(t, pair.client.inst, func() error {
		config := pair.config
		config.Local.Port = mle.UDPPort
		binding, err := pair.client.inst.StartSRP(config)
		if binding != nil || err != goterrors.ErrInvalidArgs || pair.store.keyWrites != 0 ||
			pair.client.inst.udpManager.IsPortInUse(mle.UDPPort) {
			return fmt.Errorf("MLE-intercepted port admitted/unusable or changed credentials: err=%v writes=%d", err, pair.store.keyWrites)
		}
		var startErr error
		pair.binding, startErr = pair.client.inst.StartSRP(pair.config)
		return startErr
	})
}
