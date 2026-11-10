package instance

import (
	"errors"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
)

func TestOwnedMlrResponseRequiresCurrentExplicitStatusSubset(t *testing.T) {
	pending := [][16]byte{[16]byte(siteTestAddress(1)), [16]byte(siteTestAddress(2)), [16]byte(siteTestAddress(3))}
	partial := []byte{4, 1, 4, 14, 16}
	partial = append(partial, pending[1][:]...)
	status, failed, err := parseOwnedMlrResponse(partial, pending)
	if err != nil || status != 4 || len(failed) != 1 || failed[0] != pending[1] {
		t.Fatal("valid current failed subset not retained")
	}
	unknown := append([]byte(nil), partial...)
	unknown[len(unknown)-1] = 99
	duplicate := []byte{4, 1, 4, 14, 32}
	duplicate = append(duplicate, pending[1][:]...)
	duplicate = append(duplicate, pending[1][:]...)
	for _, bad := range [][]byte{
		nil, {4}, {4, 0}, {4, 1, 0, 4, 1, 0}, {4, 1, 255}, {4, 1, 4, 14, 0},
		{4, 1, 4, 14, 15}, unknown, duplicate,
	} {
		if _, _, err := parseOwnedMlrResponse(bad, pending); !errors.Is(err, goterrors.ErrParse) {
			t.Fatal("malformed/foreign/duplicate/status-less response accepted")
		}
	}
}
