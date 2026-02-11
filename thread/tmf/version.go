// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tmf

// Thread protocol version constants.
//
// Each version is represented by its wire-format numeric value as defined in
// the Thread specification and the OpenThread C++ header
// (src/core/thread/version.hpp, include/openthread/thread.h).

const (
	// ThreadVersion1p1 is the Thread 1.1 protocol version (wire value 2).
	ThreadVersion1p1 uint16 = 2

	// ThreadVersion1p2 is the Thread 1.2 protocol version (wire value 3).
	ThreadVersion1p2 uint16 = 3

	// ThreadVersion1p3 is the Thread 1.3 protocol version (wire value 4).
	ThreadVersion1p3 uint16 = 4

	// ThreadVersion1p3p1 is the Thread 1.3.1 protocol version (wire value 5).
	// This is a legacy alias for Thread 1.4.
	ThreadVersion1p3p1 uint16 = 5

	// ThreadVersion1p4 is the Thread 1.4 protocol version (wire value 5).
	ThreadVersion1p4 uint16 = 5
)

// ThreadVersionCurrent is the latest Thread version supported by this
// implementation. It mirrors the default OPENTHREAD_CONFIG_THREAD_VERSION
// value in the OpenThread C++ core configuration.
const ThreadVersionCurrent = ThreadVersion1p4

// ThreadVersionMin is the minimum Thread version accepted by this
// implementation.
const ThreadVersionMin = ThreadVersion1p1

// IsVersionSupported reports whether the given Thread protocol version
// falls within the supported range [ThreadVersionMin, ThreadVersionCurrent].
func IsVersionSupported(version uint16) bool {
	return version >= ThreadVersionMin && version <= ThreadVersionCurrent
}
