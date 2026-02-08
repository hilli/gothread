// Package errors defines the error codes used throughout gothread.
//
// Each sentinel error corresponds to an otError value from OpenThread's
// error.h. The success case (OT_ERROR_NONE = 0) is represented by a nil
// error in Go, so there is no sentinel for it.
//
// Reference: openthread/include/openthread/error.h
package errors //nolint:revive // package name intentionally matches stdlib for domain clarity

// Code is the numeric error code matching OpenThread's otError enum.
type Code uint8

// Error represents an OpenThread error with a numeric code and description.
type Error struct {
	Code Code
	msg  string
}

// Error returns a human-readable description of the error.
func (e *Error) Error() string {
	if e == nil {
		return "no error"
	}
	return e.msg
}

// newError creates a sentinel error with the given code and message.
func newError(code Code, msg string) *Error {
	return &Error{Code: code, msg: msg}
}

// Sentinel errors corresponding to OpenThread's otError codes.
var (
	ErrFailed                     = newError(1, "operation failed")
	ErrDrop                       = newError(2, "message was dropped")
	ErrNoBufs                     = newError(3, "insufficient buffers")
	ErrNoRoute                    = newError(4, "no route available")
	ErrBusy                       = newError(5, "service is busy")
	ErrParse                      = newError(6, "failed to parse message")
	ErrInvalidArgs                = newError(7, "invalid arguments")
	ErrSecurity                   = newError(8, "security checks failed")
	ErrAddressQuery               = newError(9, "address resolution requires an address query operation")
	ErrNoAddress                  = newError(10, "address is not in the source match table")
	ErrAbort                      = newError(11, "operation was aborted")
	ErrNotImplemented             = newError(12, "function or method is not implemented")
	ErrInvalidState               = newError(13, "cannot complete due to invalid state")
	ErrNoAck                      = newError(14, "no acknowledgment was received")
	ErrChannelAccessFailure       = newError(15, "transmission failed due to activity on the channel")
	ErrDetached                   = newError(16, "not currently attached to a Thread Partition")
	ErrFcs                        = newError(17, "FCS check failure while receiving")
	ErrNoFrameReceived            = newError(18, "no frame received")
	ErrUnknownNeighbor            = newError(19, "received a frame from an unknown neighbor")
	ErrInvalidSourceAddress       = newError(20, "received a frame from an invalid source address")
	ErrAddressFiltered            = newError(21, "received a frame filtered by the address filter")
	ErrDestinationAddressFiltered = newError(22, "received a frame filtered by the destination address check")
	ErrNotFound                   = newError(23, "the requested item could not be found")
	ErrAlready                    = newError(24, "the operation is already in progress")
	// Code 25 is not defined in OpenThread.
	ErrIP6AddressCreationFailure = newError(26, "the creation of IPv6 address failed")
	ErrNotCapable                = newError(27, "operation prevented by mode flags")
	ErrResponseTimeout           = newError(28, "response not received")
	ErrDuplicated                = newError(29, "received a duplicated frame")
	ErrReassemblyTimeout         = newError(30, "message is being dropped from reassembly list due to timeout")
	ErrNotTmf                    = newError(31, "message is not a TMF message")
	ErrNotLowpanDataFrame        = newError(32, "received a non-lowpan data frame")
	// Code 33 is not defined in OpenThread.
	ErrLinkMarginLow  = newError(34, "the link margin was too low")
	ErrInvalidCommand = newError(35, "input command is invalid")
	ErrPending        = newError(36, "status is pending and not yet known")
	ErrRejected       = newError(37, "request rejected")
	ErrGeneric        = newError(255, "generic error")
)
