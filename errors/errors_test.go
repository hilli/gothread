package errors //nolint:revive // package name intentionally matches stdlib for domain clarity

import (
	"errors"
	"fmt"
	"testing"
)

// allErrors returns every exported sentinel error in declaration order.
func allErrors() []*Error {
	return []*Error{
		ErrFailed,
		ErrDrop,
		ErrNoBufs,
		ErrNoRoute,
		ErrBusy,
		ErrParse,
		ErrInvalidArgs,
		ErrSecurity,
		ErrAddressQuery,
		ErrNoAddress,
		ErrAbort,
		ErrNotImplemented,
		ErrInvalidState,
		ErrNoAck,
		ErrChannelAccessFailure,
		ErrDetached,
		ErrFcs,
		ErrNoFrameReceived,
		ErrUnknownNeighbor,
		ErrInvalidSourceAddress,
		ErrAddressFiltered,
		ErrDestinationAddressFiltered,
		ErrNotFound,
		ErrAlready,
		ErrIP6AddressCreationFailure,
		ErrNotCapable,
		ErrResponseTimeout,
		ErrDuplicated,
		ErrReassemblyTimeout,
		ErrNotTmf,
		ErrNotLowpanDataFrame,
		ErrLinkMarginLow,
		ErrInvalidCommand,
		ErrPending,
		ErrRejected,
		ErrGeneric,
	}
}

// expectedMessages maps each sentinel to its expected Error() string.
// These match the descriptions from OpenThread's error.h.
var expectedMessages = map[*Error]string{
	ErrFailed:                     "operation failed",
	ErrDrop:                       "message was dropped",
	ErrNoBufs:                     "insufficient buffers",
	ErrNoRoute:                    "no route available",
	ErrBusy:                       "service is busy",
	ErrParse:                      "failed to parse message",
	ErrInvalidArgs:                "invalid arguments",
	ErrSecurity:                   "security checks failed",
	ErrAddressQuery:               "address resolution requires an address query operation",
	ErrNoAddress:                  "address is not in the source match table",
	ErrAbort:                      "operation was aborted",
	ErrNotImplemented:             "function or method is not implemented",
	ErrInvalidState:               "cannot complete due to invalid state",
	ErrNoAck:                      "no acknowledgment was received",
	ErrChannelAccessFailure:       "transmission failed due to activity on the channel",
	ErrDetached:                   "not currently attached to a Thread Partition",
	ErrFcs:                        "FCS check failure while receiving",
	ErrNoFrameReceived:            "no frame received",
	ErrUnknownNeighbor:            "received a frame from an unknown neighbor",
	ErrInvalidSourceAddress:       "received a frame from an invalid source address",
	ErrAddressFiltered:            "received a frame filtered by the address filter",
	ErrDestinationAddressFiltered: "received a frame filtered by the destination address check",
	ErrNotFound:                   "the requested item could not be found",
	ErrAlready:                    "the operation is already in progress",
	ErrIP6AddressCreationFailure:  "the creation of IPv6 address failed",
	ErrNotCapable:                 "operation prevented by mode flags",
	ErrResponseTimeout:            "response not received",
	ErrDuplicated:                 "received a duplicated frame",
	ErrReassemblyTimeout:          "message is being dropped from reassembly list due to timeout",
	ErrNotTmf:                     "message is not a TMF message",
	ErrNotLowpanDataFrame:         "received a non-lowpan data frame",
	ErrLinkMarginLow:              "the link margin was too low",
	ErrInvalidCommand:             "input command is invalid",
	ErrPending:                    "status is pending and not yet known",
	ErrRejected:                   "request rejected",
	ErrGeneric:                    "generic error",
}

func TestAllErrorsHaveNonEmptyString(t *testing.T) {
	for _, e := range allErrors() {
		if e.Error() == "" {
			t.Errorf("Code %d: Error() returned empty string", e.Code)
		}
	}
}

func TestErrorMessagesMatchExpected(t *testing.T) {
	for e, want := range expectedMessages {
		got := e.Error()
		if got != want {
			t.Errorf("Code %d: got %q, want %q", e.Code, got, want)
		}
	}
}

func TestAllExpectedErrorsCovered(t *testing.T) {
	all := allErrors()
	if len(all) != len(expectedMessages) {
		t.Fatalf("allErrors() has %d entries, expectedMessages has %d", len(all), len(expectedMessages))
	}
	for _, e := range all {
		if _, ok := expectedMessages[e]; !ok {
			t.Errorf("Code %d (%v) missing from expectedMessages", e.Code, e)
		}
	}
}

func TestErrorsAreDistinct(t *testing.T) {
	all := allErrors()
	seen := make(map[Code]bool)
	for _, e := range all {
		if seen[e.Code] {
			t.Errorf("duplicate error code: %d", e.Code)
		}
		seen[e.Code] = true
	}

	// Also verify distinct message strings.
	msgs := make(map[string]Code)
	for _, e := range all {
		msg := e.Error()
		if prev, ok := msgs[msg]; ok {
			t.Errorf("duplicate message %q: codes %d and %d", msg, prev, e.Code)
		}
		msgs[msg] = e.Code
	}
}

func TestErrorsIs(t *testing.T) {
	// A sentinel should match itself.
	if !errors.Is(ErrFailed, ErrFailed) {
		t.Error("ErrFailed should match itself via errors.Is")
	}

	// Two different sentinels should not match.
	if errors.Is(ErrFailed, ErrDrop) {
		t.Error("ErrFailed should not match ErrDrop via errors.Is")
	}

	// A wrapped sentinel should still match the original.
	wrapped := fmt.Errorf("context: %w", ErrNoBufs)
	if !errors.Is(wrapped, ErrNoBufs) {
		t.Error("wrapped ErrNoBufs should match ErrNoBufs via errors.Is")
	}
	if errors.Is(wrapped, ErrBusy) {
		t.Error("wrapped ErrNoBufs should not match ErrBusy via errors.Is")
	}
}

func TestErrorsAs(t *testing.T) {
	wrapped := fmt.Errorf("context: %w", ErrSecurity)
	var target *Error
	if !errors.As(wrapped, &target) {
		t.Fatal("errors.As should unwrap to *Error")
	}
	if target.Code != ErrSecurity.Code {
		t.Errorf("got code %d, want %d", target.Code, ErrSecurity.Code)
	}
}

func TestNilErrorCase(t *testing.T) {
	// The success case: no error. A function returning error should return nil
	// for OT_ERROR_NONE. Verify that our sentinel list does not include a nil
	// or zero-code entry — success is represented by Go's nil error.
	for _, e := range allErrors() {
		if e.Code == 0 {
			t.Error("no sentinel should have Code 0; success is nil")
		}
	}

	// Verify a nil *Error doesn't panic on Error().
	var nilErr *Error
	if nilErr.Error() != "no error" {
		t.Errorf("nil *Error should return %q, got %q", "no error", nilErr.Error())
	}
}

func TestCodeConstants(t *testing.T) {
	// Spot-check a few code values against the OpenThread header.
	checks := []struct {
		err  *Error
		code Code
	}{
		{ErrFailed, 1},
		{ErrDrop, 2},
		{ErrNoBufs, 3},
		{ErrInvalidArgs, 7},
		{ErrNotFound, 23},
		{ErrAlready, 24},
		{ErrIP6AddressCreationFailure, 26}, // Note: code 25 is skipped in OpenThread.
		{ErrNotLowpanDataFrame, 32},
		{ErrLinkMarginLow, 34}, // Note: code 33 is skipped in OpenThread.
		{ErrRejected, 37},
		{ErrGeneric, 255},
	}
	for _, c := range checks {
		if c.err.Code != c.code {
			t.Errorf("%v: got code %d, want %d", c.err, c.err.Code, c.code)
		}
	}
}

func TestErrorCount(t *testing.T) {
	// We expect exactly 36 sentinel errors (all named codes except OT_ERROR_NONE).
	all := allErrors()
	if len(all) != 36 {
		t.Errorf("expected 36 sentinel errors, got %d", len(all))
	}
}
