// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tcp

import "testing"

func TestNew(t *testing.T) {
	mgr := New()
	if mgr == nil {
		t.Fatal("New() returned nil")
	}
	if mgr.ephemeralPort != DynamicPortMin {
		t.Errorf("ephemeralPort = %d, want %d", mgr.ephemeralPort, DynamicPortMin)
	}
}

func TestEndpointIsClosed(t *testing.T) {
	var ep Endpoint
	if !ep.IsClosed() {
		t.Error("Endpoint.IsClosed() = false, want true")
	}
}

func TestListenerIsClosed(t *testing.T) {
	var ln Listener
	if !ln.IsClosed() {
		t.Error("Listener.IsClosed() = false, want true")
	}
}

func TestConstants(t *testing.T) {
	if DynamicPortMin != 49152 {
		t.Errorf("DynamicPortMin = %d, want 49152", DynamicPortMin)
	}
	if DynamicPortMax != 65535 {
		t.Errorf("DynamicPortMax = %d, want 65535", DynamicPortMax)
	}
}
