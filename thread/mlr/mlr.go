// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package mlr defines the Multicast Listener Registration (MLR) status codes
// and state types used in Thread BBR multicast forwarding.
//
// This is a Go port of OpenThread's src/core/thread/mlr_types.hpp.
package mlr

// MlrStatus represents the result of an MLR.req message.
type MlrStatus uint8

const (
	// StatusSuccess indicates the MLR request succeeded.
	StatusSuccess MlrStatus = 0
	// StatusInvalid indicates the request contained invalid parameters.
	StatusInvalid MlrStatus = 2
	// StatusNoPersistent indicates persistent registrations are not supported.
	StatusNoPersistent MlrStatus = 3
	// StatusNoResources indicates the BBR has no resources for the request.
	StatusNoResources MlrStatus = 4
	// StatusNotPrimary indicates the responder is not the Primary BBR.
	StatusNotPrimary MlrStatus = 5
	// StatusGeneralFailure indicates a general/unspecified failure.
	StatusGeneralFailure MlrStatus = 6
)

// String returns the human-readable name of an MlrStatus.
func (s MlrStatus) String() string {
	switch s {
	case StatusSuccess:
		return "Success"
	case StatusInvalid:
		return "Invalid"
	case StatusNoPersistent:
		return "NoPersistent"
	case StatusNoResources:
		return "NoResources"
	case StatusNotPrimary:
		return "NotPrimary"
	case StatusGeneralFailure:
		return "GeneralFailure"
	default:
		return "Unknown"
	}
}

// MaxAddresses is the maximum number of multicast addresses in a single
// MLR.req message.
const MaxAddresses = 15

// MlrState represents the MLR registration state for a multicast address.
type MlrState uint8

const (
	// StateToRegister indicates the address needs to be registered.
	StateToRegister MlrState = iota
	// StateRegistering indicates an MLR.req is in progress for this address.
	StateRegistering
	// StateRegistered indicates the address has been successfully registered.
	StateRegistered
)

// String returns the human-readable name of an MlrState.
func (s MlrState) String() string {
	switch s {
	case StateToRegister:
		return "ToRegister"
	case StateRegistering:
		return "Registering"
	case StateRegistered:
		return "Registered"
	default:
		return "Unknown"
	}
}
