package slaac

import (
	"errors"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
)

func TestCheckedSlaacPreservesExistingCapacityAndGenerationFailure(t *testing.T) {
	generator := NewDefaultIIDGenerator([32]byte{1, 2, 3}, [8]byte{4, 5, 6})
	manager := NewManager(generator)
	if err := manager.UpdateChecked(nil); !errors.Is(err, goterrors.ErrInvalidState) {
		t.Fatal("disabled checked manager looked active")
	}
	manager.Enable()
	var prefixes []Prefix
	for i := byte(1); i <= DefaultMaxAddresses+1; i++ {
		prefixes = append(prefixes, Prefix{Prefix: [16]byte{0x20, 1, 0x0d, 0xb8, 0, i}, Length: 64, Flags: FlagOnMesh | FlagSlaac})
	}
	if err := manager.UpdateChecked(prefixes); !errors.Is(err, goterrors.ErrNoBufs) {
		t.Fatal("checked path silently hid existing four-address pressure")
	}
	if len(manager.GetAddresses()) != DefaultMaxAddresses {
		t.Fatal("checked path changed actual manager capacity")
	}
	old := manager.GetAddresses()[0]
	prefixes[0].Flags |= FlagPreferred
	if err := manager.UpdateChecked(prefixes[:DefaultMaxAddresses]); err != nil {
		t.Fatal(err)
	}
	current := manager.GetAddresses()[0]
	if current.Address != old.Address || current.DadCounter != old.DadCounter || !current.Prefix.HasFlag(FlagPreferred) {
		t.Fatal("checked refresh lost current prefix semantics or rotated stable IID")
	}
	failing := NewManager(&failingIIDGenerator{})
	failing.Enable()
	if err := failing.UpdateChecked(prefixes[:1]); !errors.Is(err, goterrors.ErrFailed) || len(failing.GetAddresses()) != 0 {
		t.Fatal("checked path manufactured an address after actual IID failure")
	}
}
