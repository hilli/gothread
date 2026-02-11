// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mlr

import "testing"

func TestMlrStatusString(t *testing.T) {
	tests := []struct {
		status MlrStatus
		want   string
	}{
		{StatusSuccess, "Success"},
		{StatusInvalid, "Invalid"},
		{StatusNoPersistent, "NoPersistent"},
		{StatusNoResources, "NoResources"},
		{StatusNotPrimary, "NotPrimary"},
		{StatusGeneralFailure, "GeneralFailure"},
		{MlrStatus(99), "Unknown"},
	}
	for _, tc := range tests {
		if got := tc.status.String(); got != tc.want {
			t.Errorf("MlrStatus(%d).String() = %q, want %q", tc.status, got, tc.want)
		}
	}
}

func TestMlrStatusValues(t *testing.T) {
	// Verify the numeric values match the Thread spec.
	if StatusSuccess != 0 {
		t.Errorf("StatusSuccess = %d, want 0", StatusSuccess)
	}
	if StatusInvalid != 2 {
		t.Errorf("StatusInvalid = %d, want 2", StatusInvalid)
	}
	if StatusNoPersistent != 3 {
		t.Errorf("StatusNoPersistent = %d, want 3", StatusNoPersistent)
	}
	if StatusNoResources != 4 {
		t.Errorf("StatusNoResources = %d, want 4", StatusNoResources)
	}
	if StatusNotPrimary != 5 {
		t.Errorf("StatusNotPrimary = %d, want 5", StatusNotPrimary)
	}
	if StatusGeneralFailure != 6 {
		t.Errorf("StatusGeneralFailure = %d, want 6", StatusGeneralFailure)
	}
}

func TestMlrStateString(t *testing.T) {
	tests := []struct {
		state MlrState
		want  string
	}{
		{StateToRegister, "ToRegister"},
		{StateRegistering, "Registering"},
		{StateRegistered, "Registered"},
		{MlrState(99), "Unknown"},
	}
	for _, tc := range tests {
		if got := tc.state.String(); got != tc.want {
			t.Errorf("MlrState(%d).String() = %q, want %q", tc.state, got, tc.want)
		}
	}
}

func TestMaxAddresses(t *testing.T) {
	if MaxAddresses != 15 {
		t.Errorf("MaxAddresses = %d, want 15", MaxAddresses)
	}
}
